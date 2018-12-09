#!/bin/bash

node dnsblock.js hosts_blocked.txt domains.blocked domains.whitelisted generateRpz
