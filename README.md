Yarrp (Yelling at Random Routers Progressively)
=========

Yarrp is a next-generation active network topology discovery technique and tool
designed for rapid mapping at Internet scales. As with traditional traceroute,
Yarrp discovers router interfaces and the links between them. However, Yarrp
can probe at over 100Kpps and has been shown to discover >200K router
interfaces in less than 5 minutes. Yarrp supports TCP, UDP-paris, and
ICMP-paris probing over both IPv4 and IPv6. Yarrp is written in C++, runs on
Linux and BSD systems, and is open-sourced with a BSD license.

## Build

```shell
./bootstrap
./configure
make
```

## Technical details

* See https://www.cmand.org/yarrp

## Customized packet structure
### Sent UDP packet
* Probed ttl info : second byte of ip identification field 
* LB identifier: udp dport
* Send timestamp: udp cksum
* Makeup bytes: udp sport
* IP header
	| Byte1 | Byte2 | Byte3 | Byte4 |
	| :---: | :---: | :---: | :---: |
	| version + IHL | TOS | length | length |
	| id(instance) | id(**ttl**) | ... | ... |
	| ttl | protcol | hdr cksum | hdr cksum |
	| src IP | src IP | src IP | src IP |
	| dst IP | dst IP | dst IP | dst IP |
* UDP header (two-byte empty payload)
	| Byte1 | Byte2 | Byte3 | Byte4 |
	| :---: | :---: | :---: | :---: |
	| sport(**Makeup**) | sport(**Makeup**) | dport(**LBID**) | dport(**LBID**) |
	| length | length | cksum(**timestamp**) | cksum(**timestamp**) |

### Received ICMP packet
* cksum field is fixed for each (dst, ttl) even with different LB identifiers
* ICMP header
	| Byte1 | Byte2 | Byte3 | Byte4 |
	| :---: | :---: | :---: | :---: |
	| Type(11) | Code(0) | Cksum | Cksum |
