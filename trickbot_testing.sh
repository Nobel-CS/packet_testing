#!/bin/bash



if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi

#echo "Packet Analysis Result:"

####### Pre-Infection Analysis ########

# Get tcp stream index (that contains zip in GET request)
zip_stream_list="$(tshark -r $1 -Y "(http.request or ssl.handshake.type == 1) 
				and !(ssdp) 
				and http.request.uri contains "zip"" -O tcp,http -l| grep "Stream index" | awk 'match($0, /([0-9]+)/, matches) {print matches[1]}')"
				# 
# Export http objects
(tshark -2 -r $1 --export-object "http,malware_check")
#tshark -2 -r $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x --export-object "http,malware_export"
# [Make sure there is no space between http,malware_export or there will be issues.]

# Show tcp streams					
for stream_num in $zip_stream_list
do


zip_stream="$(tshark -2 -r $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x)"


malware_file="malware_export/dd05ce3a-a9c9-4018-8252-d579eed1e670.zip"

zip_directory='malware_check/'
zip_file="$zip_directory$(echo "$zip_stream" | grep -oP '(?<=GET /).*(?=HTTP)')"

hash_1="$(sha512sum $malware_file | awk -F" " '{print $1}')"
hash_2="$(sha512sum $zip_file | awk -F" " '{print $1}')"

if [[ $hash_1 -eq $hash_2 ]]
then
echo
echo "<<<<<<<<<<< Malware Infected Zip file found. >>>>>>>>>>>"
fi

done





####### Post-Infection Analysis ########



#grep -oP '(?<=GET /).*(?=HTTP)'
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



