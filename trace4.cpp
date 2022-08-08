/****************************************************************************
   Program:     $Id: trace.cpp 39 2015-12-30 20:28:36Z rbeverly $
   Date:        $Date: 2015-12-30 12:28:36 -0800 (Wed, 30 Dec 2015) $
   Description: traceroute class
****************************************************************************/
#include "yarrp.h"

Traceroute4::Traceroute4(YarrpConfig *_config, Stats *_stats) : Traceroute(_config, _stats)
{
    if (config->testing) return;
    memset(&source, 0, sizeof(struct sockaddr_in)); 
    if (config->probesrc) {
        source.sin_family = AF_INET;
        if (inet_pton(AF_INET, config->probesrc, &source.sin_addr) != 1)
          fatal("** Bad source address.");
        cout << ">> Using IP source: " << config->probesrc << endl;
    } else {
        infer_my_ip(&source);
    }
    inet_ntop(AF_INET, &source.sin_addr, addrstr, INET_ADDRSTRLEN);
    config->set("SourceIP", addrstr, true);
    payloadlen = 0;
    outip = (struct ip *)calloc(1, PKTSIZE);
    outip->ip_v = IPVERSION;
    outip->ip_hl = sizeof(struct ip) >> 2;
    outip->ip_src.s_addr = source.sin_addr.s_addr;
    sndsock = raw_sock(&source);
    if (config->probe and config->receive) {
        lock();   /* grab mutex; make listener thread block. */
        pthread_create(&recv_thread, NULL, listener, this);
    }
}

Traceroute4::~Traceroute4() {
    if (outip)
        free(outip);
}

void Traceroute4::probePrint(struct in_addr *targ, int ttl) {
    uint32_t diff = elapsed();
    if (config->probesrc)
        cout << inet_ntoa(source.sin_addr) << " -> ";
    cout << inet_ntoa(*targ) << " ttl: ";
    cout << ttl;
    if (config->instance)
        cout << " i=" << (int) config->instance;
    cout << " t=" << diff;
    (config->coarse) ? cout << "ms" << endl : cout << "us" << endl;
}

void
Traceroute4::probe(const char *targ, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    inet_aton(targ, &(target.sin_addr));
    probe(&target, ttl);
}

void
Traceroute4::probe(uint32_t addr, int ttl) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    target.sin_addr.s_addr = addr;
    probe(&target, ttl);
}

void
Traceroute4::probe(struct sockaddr_in *target, int ttl) {
    outip->ip_ttl = ttl;
    outip->ip_id = htons(ttl + (config->instance << 8));
    outip->ip_off = 0; // htons(IP_DF);
    outip->ip_dst.s_addr = (target->sin_addr).s_addr;
    outip->ip_sum = 0;
    if (TR_UDP == config->type) {
        probeUDP(target, ttl);
    } else if ( (TR_ICMP == config->type) || (TR_ICMP_REPLY == config->type) ) {
        probeICMP(target, ttl);
    } else if ( (TR_TCP_SYN == config->type) || (TR_TCP_ACK == config->type) ) {
        probeTCP(target, ttl);
    } else {
        cerr << "** bad trace type:" << config->type << endl;
        assert(false);
    }
}

void
Traceroute4::probeUDP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));

    uint32_t diff = elapsed();
    payloadlen = 2;
    /* encode MSB of timestamp in UDP payload length */ 
    if (diff >> 16)
        payloadlen += (diff>>16);
    if (verbosity > HIGH) {
        cout << ">> UDP probe: ";
        probePrint(&target->sin_addr, ttl);
    }

    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(dport);
    udp->uh_dport = htons(dstport);
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute UDP checksum */
    memset(data, 0, 2);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    /* encode LSB of timestamp in checksum */
    uint16_t crafted_cksum = diff & 0xFFFF;
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

#define TESTCODE 201u

void
Traceroute4::probeUDPFieldTest(struct sockaddr_in *target, int ttl, uint32_t round) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));

    unsigned int lbid = round%10;
    payloadlen = 2 + lbid;
    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
    outip->ip_id = ((TESTCODE & 0xFF) << 8) + TESTCODE;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* encode destination IPv4 address as cksum(ipdst) */
    udp->uh_sport = htons(33434 + lbid);     // fixed bytes
    udp->uh_dport = htons(33434 + lbid);     // LBID
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;


    /* compute UDP checksum */
    memset(data, 0, payloadlen);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    uint16_t crafted_cksum = ((TESTCODE & 0xFF) << 8) + TESTCODE;
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << endl;
    } 
    // else {
    //     printf("ip_id:%u ; ip_sum:%u ; uh_sport:%u ; uh_dport:%u ; uh_ulen:%u ; uh_cksum:%u ;\n", outip->ip_id, outip->ip_sum, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen), udp->uh_sum);
    // }
}

void
Traceroute4::probeUDPRound(struct sockaddr_in *target, int ttl, uint32_t round) {
    unsigned char *ptr = (unsigned char *)outip;
    struct udphdr *udp = (struct udphdr *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + sizeof(struct udphdr));

    uint32_t diff = elapsed();
    payloadlen = 2;
    if (verbosity > HIGH) {
        cout << ">> UDP probe: ";
        probePrint(&target->sin_addr, ttl);
    }

    packlen = sizeof(struct ip) + sizeof(struct udphdr) + payloadlen;

    outip->ip_p = IPPROTO_UDP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = IP_DF;
#else
    outip->ip_len = htons(packlen);
    outip->ip_off = ntohs(IP_DF);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    udp->uh_sport = htons(config->instance << 8 + (dport & 0xFF));     // fixed bytes
    udp->uh_dport = htons(33434 + round%3);     // LBID
    udp->uh_ulen = htons(sizeof(struct udphdr) + payloadlen);
    udp->uh_sum = 0;

    outip->ip_id = htons(diff & 0xFFFF);
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute UDP checksum */
    memset(data, 0, 2);
    u_short len = sizeof(struct udphdr) + payloadlen;
    udp->uh_sum = p_cksum(outip, (u_short *) udp, len);

    /* encode LSB of timestamp in checksum */
    uint16_t crafted_cksum = ~((udp->uh_dport) + ttl);
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(udp->uh_sum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    udp->uh_sum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> UDP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
    //  else {
        // cout << ">> src ip: " << inet_ntoa(target->sin_addr) << " ttl: ";
        // cout << ttl << " ; " << static_cast<uint16_t>((~udp->uh_sum) + (~udp->uh_dport) + 1) << endl;
        // cout << "lbid: " << ntohs(udp->uh_dport) - 33434 << "; pld: " << crafted_data << endl;
    // }
}

void
Traceroute4::probeTCP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct tcphdr *tcp = (struct tcphdr *)(ptr + (outip->ip_hl << 2));

    packlen = sizeof(struct ip) + sizeof(struct tcphdr) + payloadlen;
    outip->ip_p = IPPROTO_TCP;
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode destination IPv4 address as cksum(ipdst) */
    uint16_t dport = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    tcp->th_sport = htons(dport);
    tcp->th_dport = htons(dstport);
    /* encode send time into seq no as elapsed milliseconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> TCP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    tcp->th_seq = htonl(diff);
    tcp->th_off = 5;
    tcp->th_win = htons(0xFFFE);
    tcp->th_sum = 0;
    /* don't want to set SYN, lest we be tagged as SYN flood. */
    if (TR_TCP_SYN == config->type) {
        tcp->th_flags |= TH_SYN;
    } else {
        tcp->th_flags |= TH_ACK;
        tcp->th_ack = htonl(target->sin_addr.s_addr);
    }
    /*
     * explicitly computing cksum probably not required on most machines
     * these days as offloaded by OS or NIC.  but we'll be safe.
     */
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));
    /*
     * bsd rawsock requires host ordered len and offset; rewrite here as
     * chksum must be over htons() versions
     */
    u_short len = sizeof(struct tcphdr) + payloadlen;
    tcp->th_sum = p_cksum(outip, (u_short *) tcp, len);
    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> TCP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeICMP(struct sockaddr_in *target, int ttl) {
    unsigned char *ptr = (unsigned char *)outip;
    struct icmp *icmp = (struct icmp *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + ICMP_MINLEN);

    payloadlen = 2;
    packlen = sizeof(struct ip) + ICMP_MINLEN + payloadlen;
    outip->ip_p = IPPROTO_ICMP;
    outip->ip_len = htons(packlen);
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode send time into icmp id and seq as elapsed milli/micro seconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> ICMP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    icmp->icmp_type = ICMP_ECHO;
    if (TR_ICMP_REPLY == config->type)
        icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = htons(diff & 0xFFFF);
    icmp->icmp_seq = htons((diff >> 16) & 0xFFFF);
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute ICMP checksum */
    memset(data, 0, 2);
    u_short len = ICMP_MINLEN + payloadlen;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    /* encode cksum(ipdst) into checksum */
    uint16_t crafted_cksum = in_cksum((unsigned short *)&(outip->ip_dst), 4);
    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(icmp->icmp_cksum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    icmp->icmp_cksum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> ICMP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}

void
Traceroute4::probeRound(uint32_t addr, int ttl, uint32_t round) {
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
#ifdef _BSD
    target.sin_len = sizeof(target);
#endif
    target.sin_addr.s_addr = addr;
    probeRound(&target, ttl, round);
}

void
Traceroute4::probeRound(struct sockaddr_in *target, int ttl, uint32_t round) {
    outip->ip_ttl = ttl;
    outip->ip_id = 0;
    outip->ip_off = 0; // htons(IP_DF);
    outip->ip_dst.s_addr = (target->sin_addr).s_addr;
    outip->ip_sum = 0;
    if (TR_UDP == config->type) {
        // probeUDPRound(target, ttl, round);
        probeUDPFieldTest(target, ttl, round);
    } else if ( (TR_ICMP == config->type) || (TR_ICMP_REPLY == config->type) ) {
        probeICMPRound(target, ttl, round);
    } else if ( (TR_TCP_SYN == config->type) || (TR_TCP_ACK == config->type) ) {
        probeTCP(target, ttl);
    } else {
        cerr << "** bad trace type:" << config->type << endl;
        assert(false);
    }
}


void
Traceroute4::probeICMPRound(struct sockaddr_in *target, int ttl, uint32_t round) {
    unsigned char *ptr = (unsigned char *)outip;
    struct icmp *icmp = (struct icmp *)(ptr + (outip->ip_hl << 2));
    unsigned char *data = (unsigned char *)(ptr + (outip->ip_hl << 2) + ICMP_MINLEN);

    payloadlen = 2;
    packlen = sizeof(struct ip) + ICMP_MINLEN + payloadlen;
    outip->ip_p = IPPROTO_ICMP;
    outip->ip_len = htons(packlen);
#if defined(_BSD) && !defined(_NEW_FBSD)
    outip->ip_len = packlen;
    outip->ip_off = 0; //IP_DF;
#else
    outip->ip_len = htons(packlen);
#endif
    /* encode send time into icmp id as elapsed milli/micro seconds */
    uint32_t diff = elapsed();
    if (verbosity > HIGH) {
        cout << ">> ICMP probe: ";
        probePrint(&target->sin_addr, ttl);
    }
    icmp->icmp_type = ICMP_ECHO;
    if (TR_ICMP_REPLY == config->type)
        icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = htons(diff & 0xFFFF);
    /* encode round info into icmp sequence number */
    icmp->icmp_seq = htons(static_cast<uint16_t>(round));
    outip->ip_sum = htons(in_cksum((unsigned short *)outip, 20));

    /* compute ICMP checksum */
    memset(data, 0, 2);
    u_short len = ICMP_MINLEN + payloadlen;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

    /* encode LB identifiers into checksum */
    // uint16_t crafted_cksum = 0xFFF1;        // fixed LB identifiers
    uint16_t crafted_cksum = 0xFF00 + static_cast<uint16_t>(round % 3);        // ranging LB identifiers

    /* craft payload such that the new cksum is correct */
    uint16_t crafted_data = compute_data(icmp->icmp_cksum, crafted_cksum);
    memcpy(data, &crafted_data, 2);
    if (crafted_cksum == 0x0000)
        crafted_cksum = 0xFFFF;
    icmp->icmp_cksum = crafted_cksum;

    if (sendto(sndsock, (char *)outip, packlen, 0, (struct sockaddr *)target, sizeof(*target)) < 0) {
        cout << __func__ << "(): error: " << strerror(errno) << endl;
        cout << ">> ICMP probe: " << inet_ntoa(target->sin_addr) << " ttl: ";
        cout << ttl << " t=" << diff << endl;
    }
}