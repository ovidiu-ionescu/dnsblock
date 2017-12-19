#!/bin/bash
# Fetches lists of servers to block. Initially the list was the same as used by PiHole


OUT=domains.blocked

wget -O - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | awk '/^0\.0\.0\.0/ { if(!match($2, /0\.0\.0\.0/)) print $2 }' > $OUT
wget -O - https://mirror1.malwaredomains.com/files/justdomains >> $OUT
wget -O - http://sysctl.org/cameleon/hosts  | awk '/127\.0\.0\.1/{ if(!match($2, /^localhost$/)) print $2 }' >> $OUT
wget -O - https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist | awk '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' >> $OUT
wget -O - https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt | awk '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' >> $OUT
wget -O - https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt | awk '{ if(!match($1, /^#/) && length($1) > 0) print $1 }' >> $OUT
wget -O - https://hosts-file.net/ad_servers.txt |  awk '/127\.0\.0\.1/ { if(!match($2, /^localhost$/)) print $2 }' >> $OUT

dos2unix $OUT

