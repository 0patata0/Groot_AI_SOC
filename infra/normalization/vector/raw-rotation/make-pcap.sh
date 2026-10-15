#!/bin/bash
# Fixed synthetic, offline Ethernet/IPv4/UDP capture. Never transmits a packet.
set -euo pipefail
[[ $# == 2 && $1 =~ ^4100[1-7]$ && $2 == /* ]] || exit 64
port=$1 output=$2
[[ ! -e $output && ! -L $output ]] || exit 65
# PCAP little-endian header; a single 46-byte Ethernet frame. IPv4 checksum is
# deliberately zero: the private Suricata process uses -k none. UDP checksum 0
# is permitted for IPv4. The marker is the source port, not a real address.
printf -v port_hex '%04x' "$port"
hex="d4c3b2a1020004000000000000000000ffff00000100000001000000000000002e0000002e0000000200000000020200000000010800450000200001000040110000c6120001c6120002${port_hex}238c000c000054455354"
[[ ${#hex} == 172 ]]
for ((i=0; i<${#hex}; i+=2)); do printf '%b' "\\x${hex:i:2}"; done > "$output"
(( $(wc -c < "$output") == 86 ))
