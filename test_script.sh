#!/bin/bash



if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi

echo "Packet Analysis Result:"

####### ARP flood or Network Scan ########

allARP="$(tcpdump -r $1 -X 2>/dev/null | grep "ARP" | grep "tell" | cut -d ' ' -f 7 | uniq -cd | sed 's/^\s*//' | sed 's/,//' | sed 's/\s/-/')" #| cut -d ' ' -f 1
#tshark -r captured/nmap_scan.pcapng -O arp -Y "arp" -x
#tshark -t ad -r captured/nmap_scan.pcapng -Y "arp"
#tshark -t ad -r captured/nmap_scan.pcapng -Y "arp and arp.opcode==2"

#echo $allARP

for i in $allARP
do

count="$(echo $i | cut -d '-' -f 1)"
source="$(echo $i | cut -d '-' -f 2)"

if [[ $count -gt 10 ]]
then
	echo "Possible Network Scan from $source"
fi

done

