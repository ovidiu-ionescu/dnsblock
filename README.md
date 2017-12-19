# dnsblock

Scripts to manage a zone file for Bind in order to block advertisment and tracking servers.

There are two sources of info for the domains to block:

* Obtained from lists maintained on the internet and consolidated in domains.block

* A personally maintained list, kept in hosts_blocked.txt

The script can produce a zones file for bind9 that links all domains to the same zone record, db.adblock

Several shell scripts are included to ease common case usage of the main script:

**add_host.sh** to quickly add a host to the hosts blocked; will warn and skip if host is already blocked. 

Can supply one or more domains as arguments

**makezone.sh** creates a bind zone file and restarts bind

**getlists.sh** fetches several tracker and ad server lists from the web and consolidates them into domains.blocked
