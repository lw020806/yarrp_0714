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
	| id(**timestamp**) | id(**timestamp**) | ... | ... |
	| ttl | protcol | hdr cksum | hdr cksum |
	| src IP | src IP | src IP | src IP |
	| dst IP | dst IP | dst IP | dst IP |
* UDP header (2-byte makeup payload)
	| Byte1 | Byte2 | Byte3 | Byte4 |
	| :---: | :---: | :---: | :---: |
	| sport(**instance**) | sport(ip_dst encoded) | dport(0) | dport(**LBID**) |
	| length | length | cksum(**ttl**) | cksum(**LBID Makeup**) |

### Received ICMP packet
* cksum field is fixed for each (dst, ttl) even with different LB identifiers
* ICMP header
	| Byte1 | Byte2 | Byte3 | Byte4 |
	| :---: | :---: | :---: | :---: |
	| Type(11) | Code(0) | Cksum | Cksum |

## Branch Purpose
* Objective: filter out routers with bad behaviors who modify fields of original probed packets when responsing
* Fields of interest:
	1. IP header (original probed packet)
		* Identifier (timestamp)
	2. UDP header (original probed packet)
		* sport (LBID)
		* dport (LBID)
		* cksum (ttl)
	3. ICMP header (response packet)
		* cksum (return LBID)
		* id -> cksum
		* seq -> cksum
* Method:
	1. IP header
		| Byte1 | Byte2 | Byte3 | Byte4 |
		| :---: | :---: | :---: | :---: |
		| version + IHL | TOS | length | length |
		| id(**instance**) | id(**instance**) | ... | ... |
		| ttl | protcol | hdr cksum | hdr cksum |
		| src IP | src IP | src IP | src IP |
		| dst IP | dst IP | dst IP | dst IP |
	2. UDP header (2-byte makeup payload)
		| Byte1 | Byte2 | Byte3 | Byte4 |
		| :---: | :---: | :---: | :---: |
		| sport(**instance**) | sport(**instance**) | dport(**instance**) | dport(**LBID**) |
		| length | length | cksum(**instance**) | cksum(**instance**) |
	3. to observe
		* ICMP:
			* cksum(fixed for all dst, ttl, lbid)
			* id (= 0)
			* seq (= 0)
		* inner IP:
			* id (= instance + instance)
		* inner UDP:
			* sport (= 33434 + lbid)
			* dport (= 33434 + lbid) (*lbid* as much as possible)
			* len (= 2 + lbid)
			* cksum (= ~(sport + dport + 0))
	4. instance value(8bit): 201 or 0b11001001

