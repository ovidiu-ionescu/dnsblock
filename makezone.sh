#!/bin/bash

node dnsblock.js hosts_blocked.txt domains.blocked generatezone
service bind9 restart

