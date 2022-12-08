#!/bin/bash

if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi

###### Post-Infection Analysis ########

<<COMPLETED_BLOCK

#################### Checking certificate ###############################

malicious_cert="$( tshark -nr $1 -2 -R "ssl.handshake.certificates and frame contains "State""  -T fields -e x509sat.uTF8String )"
echo "Irregular Digital Certificate : "
echo "$malicious_cert" | uniq

#########################################################################
#    api.ip.sb
#    checkip.amazonaws.com
#    icanhazip.com
#    ident.me
#    ip.anysrc.net
#    ipecho.net
#    ipinfo.io
#    myexternalip.com
#   wtfismyip.com
#########################################################################



################### Checking File type variation ########################

echo 
mal="$( tshark -nr $1 -2 -R "http.request.method contains GET and http.request.uri contains ".png" and frame contains ".exe" " -T fields -e ip.src )"
echo "Malicious File Download from : (exe as png)"
echo "$mal" | uniq

COMPLETED_BLOCK

































##<<TEST_BLOCK
#################### TESTING ######################
#This program cannot be run in DOS mode.#

##### 
#### matches function requires '' closure and is case insensitive
echo "$(tshark -n -r $1 -Y 'http.request.method matches "(get|post)"')"


#########################################################################

mal_stream_list="$(tshark -nr $1 -Y '(http.request or ssl.handshake.type == 1) and !(ssdp) and http.request.method matches "(get|post)" and http.request.uri contains ".png"' -O http,tcp -l -T fields -e tcp.stream)"
for stream_num in $mal_stream_list
do
echo "******************************************" 

mal_stream="$(tshark -2 -nr $1 -Y "tcp.stream eq $stream_num" -z follow,tcp,ascii,$stream_num -x)"
mal_stream_info="$(echo "$mal_stream" | grep "Follow" -A28)"
echo "Malicious Stream Info:" 
echo "$mal_stream_info" 



echo "******************************************"
done
##TEST_BLOCK
