#!/bin/bash



if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi



####### Pre-Infection Analysis ########

echo "Pre-Infection Checks:" > report.txt #Start New Report (>> will append , > creates/overwrites)
echo >>report.txt

#_#_#_#_#_#_#_#_#_ Hash Check START_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#

# Get tcp stream index (that contains zip in GET request)
zip_stream_list="$(tshark -nr $1 -Y "(http.request or ssl.handshake.type == 1) 
				and !(ssdp) 
				and http.request.uri contains "zip"" -O tcp,http -l | grep "Stream index" | awk 'match($0, /([0-9]+)/) {matches = substr($0, RSTART, RLENGTH); print matches}')"
				# -T fields -e tcp.stream

# Export http objects
if [[ -d "malware_check" ]]; then
	if [[ "$(ls -A malware_check)" ]]; then
	rm malware_check/* -r
	fi
fi
tshark -2 -r $1 --export-object "http,malware_check" >> /dev/null
#sleep 1s
# [Make sure there is no space between http,malware_check or there will be issues with directory name.]

# Check tcp streams for zip file requests
echo "Hash Check:" >> report.txt

for stream_num in $zip_stream_list
do

zip_stream="$(tshark -2 -nr $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x)"
zip_directory='malware_check/'
zip_file="$zip_directory$(echo "$zip_stream" | grep -oP '(?<=GET /).*(?=HTTP)')"

object_hash="$(sha256sum $zip_file | awk -F" " '{print $1}')"

echo "******************************************" >> report.txt
echo "Exported Object: $zip_file - Hash (SHA256): $object_hash" >> report.txt
## the next command executes early for some reason ##
vt_result="$(vt file $object_hash)"
echo "$vt_result" > vt_result
echo "Virustotal - detection: $(echo "$vt_result" | grep "malicious:" | awk 'match($0, /([0-9]+)/) {matches = substr($0, RSTART, RLENGTH); print matches}' | awk '{ sum += $1 } END { print sum }') sources detected malware presence in file." >> report.txt
echo "Detailed report in - vt_result" >> report.txt
echo "******************************************" >> report.txt
echo >> report.txt
echo >> report.txt

done

#_#_#_#_#_#_#_#_#_ Hash Check DONE_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#













#_#_#_#_#_#_#_#_#_ Host Check START_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#
malicious_requests="$(tshark -nr $1 -Y "(http.request or ssl.handshake.type == 1) 
				and !(ssdp) 
				and (http.host==144.91.69.195 or http.host==www.dchristjan.com)" -O http -l -T fields -e http.host)"
malicious_request_count="$(echo "$malicious_requests" |wc -l)"
				
if [[ $malicious_request_count -gt 0 ]]
then
echo >> report.txt
echo "Host check:" >> report.txt
echo "******************************************" >> report.txt
echo "No. of requests to malicious site: $malicious_request_count" >> report.txt
echo $malicious_requests >> report.txt
echo "******************************************" >> report.txt
echo >> report.txt
echo >> report.txt
fi
#_#_#_#_#_#_#_#_#_ Host Check DONE_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#_#










########### EXTRAS ###########

#grep -oP '(?<=GET /).*(?=HTTP)'
#-z follow,http,ascii,7
#-O tcp -S "###" 
#-Y "(http.request or ssl.handshake.type == 1) and !(ssdp)" 
#-T fields -e ip.addr udp
#and http.host==www.dchristjan.com
#captured/2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap 

#echo "$zip_stream"


#### list of filters and regular expressions

#Two pass:		-2
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

(cat report.txt)

