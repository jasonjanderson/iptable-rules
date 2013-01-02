#!/bin/sh

LOG_LEVEL="6"

## Flush out all iptables rules
iptables -t filter --flush
iptables -t nat --flush
iptables -t mangle --flush
iptables --delete-chain

## Drop by default (could accept by default due to everything being logged and dropped at the end)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

## Chain for invalid packets
## Source: http://www.linuxhelp.net/guides/iptables/
iptables -N INVALID
iptables -A INVALID -m limit --limit 15/minute -j LOG --log-level ${LOG_LEVEL} --log-prefix "Invalid Packet: "
iptables -A INVALID -j DROP

## Chain for spoofed packets
iptables -N SPOOF 
iptables -A INVALID -m limit --limit 15/minute -j LOG --log-level ${LOG_LEVEL} --log-prefix "Spoofed Packet: "
iptables -A SPOOF -j DROP


## Log and drop invalid packets
iptables -A INPUT -m state --state INVALID -j INVALID
iptables -A FORWARD -m state --state INVALID -j INVALID
iptables -A OUTPUT -m state --state INVALID -j INVALID

## Log and drop bad TCP flag combinations. (May be removed for simplicity/performance sake)
## Source: http://www.pantz.org/software/iptables/laptopiptables.html
## Source: http://pikt.org/pikt/samples/iptables_tcp_flags_programs.cfg.html
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j INVALID 
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j INVALID 
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j INVALID 
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,FIN FIN -j INVALID 
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j INVALID 

iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,PSH PSH -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL ALL -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,FIN,PSH,URG -j INVALID
iptables -A INPUT -p tcp -m tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j INVALID

## Drop NEW TCP packets that don't have the syn flag
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j INVALID

## Allow all loopback traffic
iptables -A INPUT -i lo -s 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -o lo -d 127.0.0.1 -j ACCEPT

## Accept TCP/UDP packets from ESTABLISHED and RELATED connections
iptables -A INPUT -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

## Allow packets to be sent (or just use a default ACCEPT policy for OUTPUT)
iptables -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

## Allow ICMP in from internal network
iptables -A INPUT -p icmp -s 192.168.0.0/16 --icmp-type any -j ACCEPT

## Allow ICMP out and back in if ESTABLISHED
## Source: http://www.pantz.org/software/iptables/laptopiptables.html
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT

## Drop broadcast and multicast packets
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -m pkttype --pkt-type multicast -j DROP

## Reject packets from RFC1918 class networks (spoofed)
## Source: http://www.newartisans.com/2007/09/neat-tricks-with-iptables.html
iptables -A INPUT -s 10.0.0.0/8 -j SPOOF
iptables -A INPUT -s 169.254.0.0/16 -j SPOOF
iptables -A INPUT -s 172.16.0.0/12 -j SPOOF
iptables -A INPUT -s 127.0.0.0/8 -j SPOOF
iptables -A INPUT -s 224.0.0.0/4 -j SPOOF
iptables -A INPUT -d 224.0.0.0/4 -j SPOOF
iptables -A INPUT -s 240.0.0.0/5 -j SPOOF
iptables -A INPUT -d 240.0.0.0/5 -j SPOOF
iptables -A INPUT -s 0.0.0.0/8 -j SPOOF
iptables -A INPUT -d 0.0.0.0/8 -j SPOOF
iptables -A INPUT -d 239.255.255.0/24 -j SPOOF
iptables -A INPUT -d 255.255.255.255 -j SPOOF

## SSH (Port 22)
iptables -A INPUT -m state --state NEW -m tcp -p tcp -s 192.168.0.0/16 --dport 22 -j ACCEPT


## Log and drop the rest
iptables -A INPUT -m limit --limit 15/minute -j LOG --log-prefix "Input Dropped: "
iptables -A INPUT -j DROP

iptables -A OUTPUT -m limit --limit 15/minute -j LOG --log-prefix "Output Dropped: "
iptables -A OUTPUT -j DROP

iptables -A FORWARD -m limit --limit 15/minute -j LOG --log-prefix "Forward Dropped: "
iptables -A FORWARD -j DROP

