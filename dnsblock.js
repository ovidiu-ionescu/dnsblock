#!/usr/local/bin/node

const readline = require('readline');
const fs = require('fs');

const verbose = false;

function log(text) {
    if(verbose) {
        console.log(text);
    }
}

const VALID_DOMAIN_REGEX = /^([a-z0-9-_]+\.)+[a-z0-9-_]+$/;
const DOMAIN_REGEX =       /(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+(([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-])*[A-Za-z0-9])/;
const EXTRACT_DOMAIN_REGEX = /query:\s(${DOMAIN_REGEX})\sIN\sA/;
const EXTRACT_IP = /^(.+)\sclient\s(\d+\.0\.0\.\d+)#\d+.+query:\s(.+)\sIN A.+/;
const REMOVE_END_DOT = /^(.+)\.$/;
const EXTRACT_DOMAIN_FROM_ZONE = /"(.+?)"/;
const COMMENT_REGEX = /^\s*#/;



class AdCache {
    constructor() {
        this.resetCache();
    }

    resetCache() {
        this.cache = {};
    }

    blockDomain(domain, comment) {
        comment = comment || '*';
        let p = this.cache;
        let tailKey;
        let tailHash;
        let path = [];
        for(const key of domain.toLowerCase().split('.').reverse()) {
            tailKey = key;
            path.unshift(key);
            tailHash = p;
            if(p[key]) {
                if(typeof p[key] === 'string') {
                    log(`Domain ${domain} already blocked by ${path.join('.')}`);
                    return false;
                }
            } else {
                p[key] = {};
            }
            p = p[key];
        }
        return tailKey && (tailHash[tailKey] = comment);
     }

    isBlocked(domain) {
        let p = this.cache;
        for(const key of domain.toLowerCase().split('.').reverse()) {
            p = p[key];
            if(p) {
                if(typeof p === 'string') {
                    return true;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    _traverseCache(cache, path, result) {
        Object.keys(cache).sort().filter(v => typeof cache[v] !== 'string').forEach((key) => {
            path.unshift(key);
            this._traverseCache(cache[key], path, result);
            path.shift();
        });
        Object.keys(cache).sort().filter(v => typeof cache[v] === 'string').forEach((key) => result.push(key + '.' + path.join('.')));
    }

    serializeBlockedDomains() {
        let result = [];
        this._traverseCache(this.cache, [], result);
        return result;
    }
}

const domainCache = new AdCache();
const ignoredDomains = {};

function processHostsBlocked(cache, filename) {
    const rl = readline.createInterface({ input: fs.createReadStream(filename) });
    rl.on('line', (line) => {
        let parts = line.trim().split(' ');
        let domain = parts[0].toLowerCase();
        let comment = parts[1];
        if(domain.match(VALID_DOMAIN_REGEX)) {
            cache.blockDomain(domain, comment);
        } else {
            console.error(`${domain} is not a valid domain`);
        }
    });

    return new Promise(function(resolve) {
        rl.on('close', () => resolve() );
    });
}

function listBlockedDomains(cache, filename) {
    let listDomains = cache.serializeBlockedDomains();
    let out = fs.createWriteStream(filename);
    listDomains.forEach((domain) => out.write(`${domain}\n`));
    out.close();
}

function generateZone(cache, filename) {
    let blockedDomains = cache.serializeBlockedDomains();
    let zoneInfo = blockedDomains.reduce((accumulator, domain) => accumulator + `zone "${domain}" { type master; file "/etc/bind/ionescu/adblock/db.adblock"; };\n`, '');
    fs.writeFile(filename, zoneInfo, (err) => err && console.error('Error is: ', err));
}

function loadIgnoredDomains(filename) {
    const rl = readline.createInterface({ input: fs.createReadStream(filename) });
    rl.on('line', (line) => {

    });
    return new Promise(function(resolve) {
        rl.on('close', () => resolve() );
    });
}

function processCommandLine(commandLineParameters) {

    let params = {
        hostsBlocked: "hosts_blocked.txt",
        domainsBlocked: null,
        zonesFile: "zones.adblock",
        dnsQueryLog: "",
        domainsIgnoreFile: "zones.searchads",
        command: null,
        commandParams: []
    };

    const conditions = { hostsBlocked: /\.txt$/i, domainsBlocked: /\.blocked$/i, dnsQueryLog: /\.log$/i, zonesFile: /\.adblock/ };

    commandLineParameters.slice(2).forEach((param) => {
        if (!params.command) {
            -1 === Object.keys(conditions).findIndex((key) => param.match(conditions[key]) && (params[key] = param)) && (params.command = param);
        } else {
            params.commandParams.push(param);
        }
    });

    return params;
}

function help() {
    console.error( `
    Usage:
${process.argv[1]} <blocked_hosts_file.txt> <domains.blocked> <dnsquery.log> <zones.adblock> help|simplify|processlog|add|generatezone|addgen

    Files are identified by extension.";
    The first non file parameter is the command. All following parameters are command parameters.
`);
}

async function main() {
    let params = processCommandLine(process.argv);
    await processHostsBlocked(domainCache, params.hostsBlocked);
    params.domainsBlocked && await processHostsBlocked(domainCache, params.domainsBlocked);

    params.command = params.command || help;

    switch(params.command) {
        case 'simplify':
            listBlockedDomains(domainCache, params.hostsBlocked);
            break;

        case 'add':
            params.commandParams.forEach((domain) => domainCache.blockDomain(domain));
            listBlockedDomains(domainCache, params.hostsBlocked);
            break;

        case 'generatezone':
            // load_ignored_domains $domains_ignore_file;
            generateZone(domainCache, params.zonesFile);
            break;

        case 'addgen':
            params.commandParams.forEach((domain) => domainCache.blockDomain(domain));
            // listBlockedDomains(domainCache, params.hostsBlocked);
            // generate_zone $zones_file;
            break;

        case 'filter':
            // filter @params;
            break;

        case 'ignore':
            break;

        case 'processlog':
            // process_dns_query_log $dns_query_log, @params;
            break;

        case 'help':
        case '?':
        default:
            help();
    }
}

main();

module.exports = { domainCache: domainCache, processHostsBlocked: processHostsBlocked, main: main, processCommandLine: processCommandLine, generateZone: generateZone };
