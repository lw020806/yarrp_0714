#include "yarrp.h"
#include "random_list.h"

IPList::IPList(uint8_t _maxttl, bool _rand, bool _entire) : seeded(false) {
  perm = NULL;
  permsize = 0;
  maxttl = _maxttl;
  ttlbits = intlog(maxttl);
  ttlmask = 0xffffffff >> (32 - ttlbits);
  ttlprefix = ttlmask ^ 0xff;
  rand = _rand;
  entire = _entire;
  if (entire) 
    permsize = UINT32_MAX;
  memset(key, 0, KEYLEN);
}

void IPList::setkey(int seed) {
    debug(HIGH, ">> Seed: " << seed);
    permseed(key, seed);
}

IPList4::~IPList4() {
  targets.clear();
  cperm_destroy(perm);
}

IPList6::~IPList6() {
  targets.clear();
  cperm_destroy(perm);
}

/* seed */
void IPList4::seed() {
  PermMode mode = PERM_MODE_CYCLE;
  if (not entire) {
    assert(targets.size() > 0);
    permsize = targets.size() * maxttl;
    if (permsize < 1000000) 
      mode = PERM_MODE_PREFIX;
  } 
  perm = cperm_create(permsize, mode, PERM_CIPHER_RC5, key, 16);
  assert(perm);
  seeded = true;
}

void IPList6::seed() {
  PermMode mode = PERM_MODE_PREFIX;
  assert(targets.size() > 0);
  permsize = targets.size() * maxttl;
  if (permsize > 5000000) {
    mode = PERM_MODE_CYCLE;
    std::cout << ">> Warning: reduced IPv6 performance with this many targets" <<  std::endl;
    std::cout << ">>          use fewer targets, or lower max TTL (-m)" <<  std::endl;
  }
  perm = cperm_create(permsize, mode, PERM_CIPHER_SPECK, key, 8);
  assert(perm);
  seeded = true;
}

/* Read list of input IPs */
void IPList::read(char *in) {
  if (*in == '-') {
    read(std::cin);
  } else {
    std::ifstream ifile(in);
    if (ifile.good() == false)
      fatal("Bad input file: %s", in);
    read(ifile);
  }
}

/* Read list of input IPs */
void IPList4::read(std::istream& inlist) {
  std::string line;
  struct in_addr addr;
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    if (inet_aton(line.c_str(), &addr) != 1)
      fatal("Couldn't parse IPv4 address: %s", line.c_str());
    targets.push_back(addr.s_addr);
  }
  debug(LOW, ">> IPv4 targets: " << targets.size());
}

/* Read list of input IPs */
void IPList6::read(std::istream& inlist) {
  std::string line;
  struct in6_addr addr;
  while (getline(inlist, line)) {
    if (!line.empty() && line[line.size() - 1] == '\r')
      line.erase( std::remove(line.begin(), line.end(), '\r'), line.end() );
    if (inet_pton(AF_INET6, line.c_str(), &addr) != 1)
      fatal("Couldn't parse IPv6 address: %s", line.c_str());
    targets.push_back(addr);
  }  
  debug(LOW, ">> IPv6 targets: " << targets.size());
}

uint32_t IPList4::next_address(struct in_addr *in, uint8_t * ttl) {
  if (entire)
    return next_address_entire(in, ttl);
  else if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList4::next_address_seq(struct in_addr *in, uint8_t * ttl) {
  static std::vector<uint32_t>::iterator iter = targets.begin();
  static uint32_t last_addr = *iter;
  static uint8_t  last_ttl = 0;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  *ttl = last_ttl;
  last_ttl+=1;
  in->s_addr = last_addr;
  return 1;
}

/* random next address */
uint32_t IPList4::next_address_rand(struct in_addr *in, uint8_t * ttl) {
  static uint64_t next = 0;
  static uint32_t next32 = 0;
  static uint32_t round = 30;             // TOCHANGE: round info

  if (not seeded)
    seed();

  while (PERM_END == cperm_next(perm, &next)) {
    round --;
    if (round == 0) 
      return 0;
    else 
      next = 0;
      next32 = 0;
      cperm_reset(perm);
  }
  next32 = next % 0xffffffff;
  in->s_addr = targets[next32 >> ttlbits];
  if (ttlbits == 0)
    *ttl = 0;
  else
    *ttl = (next32 & ttlmask);
  return round;
}
/*
uint32_t IPList4::next_address_rand(struct in_addr *in, uint8_t * ttl) {
  static uint64_t next = 0;
  static uint32_t next32 = 0;

  if (not seeded)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;
  next32 = next % 0xffffffff;
  in->s_addr = targets[next32 >> ttlbits];
  if (ttlbits == 0)
    *ttl = 0;
  else
    *ttl = (next32 & ttlmask);
  return 1;
}
*/

/* Internet-wide scanning mode */
uint32_t IPList4::next_address_entire(struct in_addr *in, uint8_t * ttl) {
  static uint64_t next = 0;
  static uint32_t next32 = 0;
  static uint32_t host;
  static char *p;

  if (not seeded)
    seed();

  p = (char *) &next;
  while (PERM_END != cperm_next(perm, &next)) {
    next32 = next % 0xffffffff;
    *ttl = next32 >> 24;            // use remaining 8 bits of perm as ttl
    if ( (*ttl & ttlprefix) != 0x0) { // fast check: ttls in [0,31]
      continue;
    }
    in->s_addr = next32 & 0x00FFFFFF;    // pick out 24 bits of network
    host = (p[0] + p[1] + p[2]) & 0xFF;
    in->s_addr += (host << 24);
    return 1;
  }
  return 0;
}

uint32_t IPList6::next_address(struct in6_addr *in, uint8_t * ttl) {
  if (rand) 
    return next_address_rand(in, ttl);
  else
    return next_address_seq(in, ttl);
}

/* sequential next address */
uint32_t IPList6::next_address_seq(struct in6_addr *in, uint8_t * ttl) {
  static std::vector<struct in6_addr>::iterator iter = targets.begin();
  static struct in6_addr last_addr = *iter;
  static uint8_t  last_ttl = 0;
  int i;

  if (last_ttl + 1 > maxttl) {
    iter++;
    if (iter == targets.end())
      return 0;
    last_ttl = 0;
    last_addr = *(iter);
  }
  *ttl = last_ttl;
  for(i = 0; i < 16; i++)
    in->s6_addr[i] = last_addr.s6_addr[i];
  last_ttl+=1;
  return 1;
}

/* random next address */
uint32_t IPList6::next_address_rand(struct in6_addr *in, uint8_t * ttl) {
  static uint64_t next = 0;

  if (not seeded)
    seed();

  if (PERM_END == cperm_next(perm, &next))
    return 0;

  *in = targets[next >> ttlbits];
  *ttl = (next & ttlmask);
  return 1;
}
