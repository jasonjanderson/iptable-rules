#!/bin/sh

## Flush out all iptables rules
iptables -t filter --flush
iptables -t nat --flush
iptables -t mangle --flush
iptables --delete-chain

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

