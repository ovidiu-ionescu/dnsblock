#!/bin/bash

tail -f /var/log/named/dnsquery.log | ./dnsblock.js domains.blocked filter
