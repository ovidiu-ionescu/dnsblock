#!/bin/bash
# Fetches lists of servers to block. Initially the list was the same as used by PiHole

# break on errors
set -e
# break on errors in pipes, e.g. a | b | c
set -o pipefail

if [[ "$1" == "debug" ]]
then
    echo "Debug mode, will fetch each source in separate files."
else
    OUT=domains.blocked
    rm -f $OUT
    echo "Building $OUT"
fi

function proc {
    if [[ -z "$OUT" ]]
    then
	# we are in debug mode, remove previous text output file
	rm -f "$3"
    fi

    echo "Fetching: $1"    
    curl --insecure --fail --max-time 10 --retry 10 --retry-delay 0 "$1" | awk "$2" >> "${OUT:-$3}"
}

# site url, awk script to filter, output file for debug
sites=(\
'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' '/^0\.0\.0\.0/ { if(!match($2, /0\.0\.0\.0/)) print $2 }' 'stevenblack.txt' \
'https://mirror1.malwaredomains.com/files/justdomains' '{ print $1 }' 'malwaredomains.com.txt' \
'http://sysctl.org/cameleon/hosts' '/^127\.0\.0\.1/{ if(!match($2, /^localhost$/)) print $2 }' 'cameleon.txt' \
'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist' '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' 'zeustracker.txt' \
'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt' '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' 'disconnect.me.simple_tracking.txt' \
'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt' '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' 'disconnect.me.simple_ad.txt' \
'https://hosts-file.net/ad_servers.txt' '/^127\.0\.0\.1/ { if(!match($2, /^localhost$/)) print $2 }' 'ad_servers.txt' \
'https://adaway.org/hosts.txt' '/^127\.0\.0\.1/{ if(!match($2, /^localhost$/)) print $2 }' 'adaway.txt' \
'http://someonewhocares.org/hosts/hosts' '/^127\.0\.0\.1/{ if(!match($2, /^localhost$/)) print $2 }' 'someonewhocares.txt' \
'https://mirror.cedia.org.ec/malwaredomains/immortal_domains.txt' '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' 'immortal_domains.txt' \
'https://www.malwaredomainlist.com/hostslist/hosts.txt' '/^127\.0\.0\.1/{ if(!match($2, /^localhost$/)) print $2 }' 'malwaredomainslist.txt' \
'https://mirror.cedia.org.ec/malwaredomains/justdomains' '{ print $1 }' 'justdomains.txt' \
'http://winhelp2002.mvps.org/hosts.txt' '/^0\.0\.0\.0/ { if(!match($2, /0\.0\.0\.0/)) print $2 }' 'winhelp2002.txt' \
'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext' '/^127\.0\.0\.1/ { print $2 }' 'yoyo.txt' \
)

# all elements in array, there's three per file
total=${#sites[*]}

for (( i=0; i<=$(( $total - 1)); i+=3))
do
    proc  "${sites[$i]}" "${sites[(($i+1))]}" "${sites[(($i+2))]}"
done

if [[ ! -z "$OUT" ]]
then
    dos2unix $OUT
    wc -l $OUT
fi


