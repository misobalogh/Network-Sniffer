# Implementation of network sniffer
## IPK - Project 2 
Variant ZETA - Network Sniffer

This project's assignment was to create network sniffer, that would be able to capture packets that suit specified filter on specified interface.

## 1. Table of contents
- [Implementation of network sniffer](#implementation-of-network-sniffer)
    * [1. Table of contents](#1-table-of-contents)
    * [2. How to run it](#2-how-to-run-it)
        - [Makefile targets:](#makefile-targets-)
    * [3. Basic theory for understanding the program](#3-basic-theory-for-understanding-the-program)
    * [4. Program structure](#4-program-structure)
    * [5. Testing](#5-testing)
    * [6. Bibliography](#6-bibliography)

## 2. How to run it
The project can be build with prepared [Makefile](Makefile). The default Makefile target will create executable file `./ipk-sniffer` that can be started from command line as shown below:\
```
./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
```
#### Makefile targets:
```
make        - default target, will build the executable file
make utest  - builds unit tests, and run them
make help   - prints help message of the program
make clean  - cleans binary files
```

## 3. Basic theory for understanding the program
A network sniffer is a program that captures and analyze packets transmitted over network. 
Here are some basic concepts to understanding the program:

**Packet** is formatted unit of bits carried by a packet-switched network. Packet consists of control information and user data (payload).

**Interface** is the connecting point between a computer and a private or public network. A network interface is generally a network interface card, but does not have to always have a physical form. It can also be implemented in software. (e.g. loopback interface)

**Network protocols and protocol subsets** defines how data are formatted, transmitted, received, and interpreted by network devices. 

## 4. Program structure
The structure of the program is shown in the class diagram below:
![classDiagram](img/classDiagram.svg)

## 5. Testing

## 6. Bibliography
[SharpPcap Tutorial] Tutorial for SharpPcap [online]. [cited 2024-04-21]. Available at: https://github.com/dotpcap/sharppcap/tree/master/Tutorial

[SharpPcap Examples] Examples of SharpPcap [online]. [cited 2024-04-21]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples

[Ndp] Wireshark/ICMPv6 NDP [online]. [cited 2024-04-21]. Available at: https://en.wikiversity.org/wiki/Wireshark/ICMPv6_NDP

[Tcpdump] Tcpdump Manual Pages [online]. [cited 2024-04-21]. Available at: https://www.tcpdump.org/manpages/pcap-filter.7.html

[Stallings] Stallings, William (2001). "Glossary". *Business Data Communication* (4th ed.). Upper Saddle River, New Jersey, USA: Prentice-Hall, Inc. p. 632. ISBN 0-13-088263-1. Available at: https://archive.org/details/businessdatacomm00stal/page/632

[Network Interface] Oracle Java Tutorials: Network Interface [online]. [cited 2024-04-21]. Available at: https://docs.oracle.com/javase/tutorial/networking/nifs/definition.html

[RFC792] Postel, J. _INTERNET CONTROL MESSAGE PROTOCOL_ [online]. September 1981. [cited 2024-04-21]. Updates: RFCs 777, 760. Updates: IENs 109, 128. Available at: https://datatracker.ietf.org/doc/html/rfc792

[RFC826] Plummer, D.C. _An Ethernet Address Resolution Protocol_ [online].  November 1982. [cited 2024-04-21]. Available at: https://datatracker.ietf.org/doc/html/rfc826

[RFC5952] Kawamura, S. and Kawashima, M. _A Recommendation for IPv6 Address Text Representation_ [online]. August 2010. [cited 2024-04-21]. Available at: https://datatracker.ietf.org/doc/html/rfc5952

[RFC3339] Klyne, G. and Newman, C. _Date and Time on the Internet: Timestamps_ [online]. July 2002.  [cited 2024-04-21]. Available at: https://datatracker.ietf.org/doc/html/rfc3339

[Wikipedia, the free encyclopedia.] _Neighbor Discovery Protocol_ [online]. [cited 2024-04-21]. Available at: https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
