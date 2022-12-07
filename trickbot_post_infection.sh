#!/bin/bash

if [[ $# -ne 1 ]]
then
	echo "Invalid input."
	exit 1
fi

###### Post-Infection Analysis ########


malicious_port_act="$(tshark -r $1 -Y "(ssl.handshake.type == 11 and x509sat.uTF8String=="Some-State")" -O tcp,http -l -x)"

echo "$malicious_port_act"
