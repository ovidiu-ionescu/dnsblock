#!/bin/bash

declare -A DOSIP

# make a hash with all the addresses already blocked
while read -r l
do
    if [[ $l =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
        # BASH_REMATCH contains the matches from the previous regex match
        ip=${BASH_REMATCH[0]}
        DOSIP[${ip}]="aha"
    fi
done < <(iptables -S 0_1)

# This displays the content of the hash
#for K in "${!DOSIP[@]}"; do echo $K; done

tail -f /var/log/named/dnsquery.log | while read -r l
#tail -f ./bad.log | while read -r l
do
# if the request is an external DNS request, we don't want those
# IN ANY +E
if [[ $l =~  IN[[:blank:]]ANY[[:blank:]]\+E ]]; then
#if [[ $l =~ :[[:blank:]]usgs.gov[[:blank:]]IN ]]; then
    # extract the IP address to block
    [[ $l =~ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]
    ip=${BASH_REMATCH[0]}
    if [ ! ${DOSIP[${ip}]+_} ]; then
        # The address is not already in our cache, block it
        DOSIP[${ip}]="aha"
        iptables -A 0_1 -s $ip -j DROP
        echo "Blocked ${ip}"
#        else
#        echo "already blocked"
    fi
fi
done
