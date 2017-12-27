#!/bin/bash

node dnsblock.js hosts_blocked.txt domains.blocked domains.whitelisted generatezone
service bind9 restart

