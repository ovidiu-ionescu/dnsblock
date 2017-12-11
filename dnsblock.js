#!/usr/local/bin/node

const readline = require('readline');
const fs = require('fs');

var verbose = false;


function log(text) {
    if(verbose) {
        console.log(text);
    }
}

class AdCache {
    constructor() {
        this.resetCache();
    }

    resetCache() {
        this.cache = {};
    }

    blockDomain(domain) {
        let p = this.cache;
        let tailKey;
        let tailHash = this.cache;
        let path = [];
        for(const key of domain.toLowerCase().split('.').reverse()) {
            tailKey = key;
            path.unshift(key);
            tailHash = p;
            if(p[key]) {
                if('*' === p[key]) {
                    log(`Domain ${domain} already blocked by ${path.join('.')}`);
                    return false;
                }
            } else {
                p[key] = {};
            }
            p = p[key];
        }
        return tailKey && (tailHash[tailKey] = '*');
     }

    isBlocked(domain) {
        var p = this.cache;
        for(const key of domain.toLowerCase().split('.').reverse()) {
            p = p[key];
            if(p) {
                if('*' === p) {
                    return true;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    _traverseCache(cache, path, result) {
        Object.keys(cache).sort().filter(v => cache[v] !== '*').forEach((key) => {
            path.unshift(key);
            this._traverseCache(cache[key], path, result);
            path.shift();
        });
        Object.keys(cache).sort().filter(v => cache[v] === '*').forEach((key) => result.push(key + '.' + path.join('.')));
    }

    serializeBlockedDomains() {
        let result = []
        this._traverseCache(this.cache, [], result);
        return result;
    }

    generateZone(filename) {
        let blockedDomains = this.serializeBlockedDomains();
        let zoneInfo = blockedDomains.reduce((accumulator, domain) => accumulator += `zone "${domain}" { type master; file "/etc/bind/ionescu/adblock/db.adblock"; };\n`, '');
        fs.writeFile(filename, zoneInfo, (err) => err && console.error('Error is: ', err));
    }
}

const domainCache = new AdCache();

function processHostsBlocked(cache, filename, continuation) {
    const rl = readline.createInterface({ input: fs.createReadStream(filename) });
    rl.on('line', (line) => cache.blockDomain(line));
    rl.on('close', continuation);
}

//processHostsBlocked('domains.blocked');


module.exports = { domainCache: domainCache, processHostsBlocked: processHostsBlocked };
