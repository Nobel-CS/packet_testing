#!/bin/bash



if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi

#echo "Packet Analysis Result:"

####### Packets ########

zip_stream_list="$(tshark -r $1 -Y "(http.request or ssl.handshake.type == 1) 
				and !(ssdp) 
				and http.request.uri contains "zip"" -O tcp,http -l| grep "Stream index" | awk 'match($0, /([0-9]+)/, matches) {print matches[1]}')"
				# 
# Export http objects
#tshark -2 -r $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x --export-object "http,malware_export"
# [Make sure there is no space between http,malware_export or there will be issues.]
					
for stream_num in $zip_stream_list
do
zip_stream="$(tshark -2 -r $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x)"
echo "$zip_stream"
done

#-z follow,http,ascii,7
#-O tcp -S "###" 
#-Y "(http.request or ssl.handshake.type == 1) and !(ssdp)" 
#-T fields -e ip.addr udp
#and http.host==www.dchristjan.com
#captured/2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap 

#echo "$zip_stream"


#### list of filters and regular expressions

#General filter:	-Y "(http.request or ssl.handshake.type == 1) and !(ssdp)"
#URL filter:		-Y "http.request.uri contains "/google/""
#tcp conv show:		-z conv,tcp
#Output view:		-O tcp,http
#Output pkt separator:	-S "###" 
#Output fields(!view):	-T fields -e ip.addr
#











#tshark -r captured/nmap_scan.pcapng -O arp -Y "arp" -x
#tshark -t ad -r captured/nmap_scan.pcapng -Y "arp"
#tshark -t ad -r captured/nmap_scan.pcapng -Y "arp and arp.opcode==2"

#echo $allARP


