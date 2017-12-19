#!/bin/bash

node dnsblock.js add $*
wc -l hosts_blocked.txt

