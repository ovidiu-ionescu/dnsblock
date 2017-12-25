#!/usr/local/bin/node

const readline = require('readline');
const fs = require('fs');
const dns = require('dns');

const verbose = false;

function log(text) {
    if (verbose) {
        console.log(text);
    }
}

const DOMAIN = '([a-z0-9-_]+\\.)+[a-z0-9-_]+';

const VALID_DOMAIN_REGEX = new RegExp(`^${DOMAIN}$`);
const EXTRACT_DOMAIN_REGEX = new RegExp(`query:\\s(${DOMAIN})\\sIN\\sA`);
const EXTRACT_IP = /^(.+)\sclient\s(\d+\.0\.0\.\d+)#\d+.+query:\s(.+)\sIN A.+/;
const REMOVE_END_DOT = /^(.+)\.$/;
const EXTRACT_DOMAIN_FROM_ZONE = /"(.+?)"/;
const COMMENT_REGEX = /^\s*#/;

class BlockedDomain {
    constructor(domain, comment) {
        this.domain = domain;
        this.comment = comment || '#';
    }

    serialize() {
        return this.comment === '#' ? this.domain : `${this.domain}${this.comment}`;
    }
}

class DomainIndex {
    constructor() {
        this.resetCache();
    }

    resetCache() {
        this.cache = {};
    }


    _traverseCache(cache, path, result) {
        Object.keys(cache).sort().filter(v => typeof cache[v] !== 'string').forEach((key) => {
            path.unshift(key);
            this._traverseCache(cache[key], path, result);
            path.shift();
        });
        Object.keys(cache).sort().filter(key => typeof cache[key] === 'string').forEach((key) => result.push(new BlockedDomain(key + '.' + path.join('.'), cache[key])));
    }

    serializeBlockedDomains() {
        let result = [];
        this._traverseCache(this.cache, [], result);
        return result;
    }
}

class BlockedDomainIndex extends DomainIndex {
    // shorter domain will replace longer sub domain
    blockDomain(domain, comment) {
        comment = comment || '#';
        let p = this.cache;
        let tailKey;
        let tailHash;
        let path = [];
        for (const key of domain.toLowerCase().split('.').reverse()) {
            tailKey = key;
            path.unshift(key);
            tailHash = p;
            if (typeof p[key] === 'string') {
                log(`Domain ${domain} already blocked by ${path.join('.')}`);
                return false;
            }
            p[key] = p[key] || {};
            p = p[key];
        }
        return tailKey && (tailHash[tailKey] = comment);
    }

    isBlocked(domain) {
        let p = this.cache;
        for (const key of domain.toLowerCase().split('.').reverse()) {
            p = p[key];
            if (p) {
                if (typeof p === 'string') {
                    return true;
                }
            } else {
                return false;
            }
        }
        return false;
    }

}

class WhitelistedDomainIndex extends DomainIndex {
    // longer sub domain will replace the domain
    whitelistDomain(domain, comment) {
        comment = comment || '#';
        let p = this.cache;
        let tailKey;
        let tailHash;
        let path = [];
        for (const key of domain.toLowerCase().split('.').reverse()) {
            tailKey = key;
            path.unshift(key);
            tailHash = p;
            p[key] = p[key] || {};
            p = p[key];
        }
        if(!Object.keys(tailHash[tailKey]).length) {
            return (tailHash[tailKey] = comment);
        } else {
            return false;
        }
    }

    isWhitelisted(domain) {
        let p = this.cache;
        for (const key of domain.toLowerCase().split('.').reverse()) {
            p = p[key];
            if (!p) {
                return false;
            }
        }
        return true;
    }

}

const blockedDomains = new BlockedDomainIndex();
const whitelistedDomains = new WhitelistedDomainIndex();
const localNameCache = { '127.0.0.1': 'localhost' };

function processHostsLine(line) {
    line = line.toLowerCase().trim();
    let spaceIndex = line.indexOf(' ');
    let domain = line;
    let comment = '';
    if (spaceIndex !== -1) {
        domain = line.substring(0, spaceIndex);
        comment = line.substring(spaceIndex);
    }
    if (!domain.match(VALID_DOMAIN_REGEX)) {
        throw `${domain} is not a valid domain`;
    }
    return new BlockedDomain(domain, comment);
}

function processHostsWhitelisted(cache, filename) {
    const rl = readline.createInterface({ input: fs.createReadStream(filename) });

    rl.on('line', (line) => {
        try {
            let whitelistedDomain = processHostsLine(line);
            cache.whitelistDomain(whitelistedDomain.domain, whitelistedDomain.comment);
        } catch(e) {
            console.error(e);
        }
    });

    return new Promise(function (resolve) {
        rl.on('close', () => resolve());
    });
}

function processHostsBlocked(cache, filename) {
    const rl = readline.createInterface({input: fs.createReadStream(filename)});
    rl.on('line', (line) => {
        try {
            let blockedDomain = processHostsLine(line);
            if(whitelistedDomains.isWhitelisted(blockedDomain.domain)) {
                console.log(`Domain ${blockedDomain.domain} is whitelisted`);
            } else {
                cache.blockDomain(blockedDomain.domain, blockedDomain.comment);
            }
        } catch (e) {
            console.error(e);
        }
    });

    return new Promise(function (resolve) {
        rl.on('close', () => resolve());
    });
}

function listBlockedDomains(cache, filename) {
    let listDomains = cache.serializeBlockedDomains();
    let out = fs.createWriteStream(filename);
    listDomains.forEach((domain) => out.write(`${domain.serialize()}\n`));
    out.close();
}

function generateZone(cache, filename) {
    let blockedDomains = cache.serializeBlockedDomains();
    let zoneInfo = blockedDomains.reduce((accumulator, blockedDomain) => accumulator + `zone "${blockedDomain.domain}" { type master; file "/etc/bind/ionescu/adblock/db.adblock"; };\n`, '');
    fs.writeFile(filename, zoneInfo, (err) => err && console.error('Error is: ', err));
}

function processCommandLine(commandLineParameters) {

    let params = {
        hostsBlocked: 'hosts_blocked.txt',
        hostsWhitelisted: '',
        domainsBlocked: null,
        zonesFile: 'zones.adblock',
        dnsQueryLog: '',
        command: null,
        commandParams: []
    };

    const conditions = {
        hostsBlocked: /\.txt$/i,
        hostsWhitelisted: /\.whitelisted/,
        domainsBlocked: /\.blocked$/i,
        dnsQueryLog: /\.log$/i,
        zonesFile: /\.adblock/
    };

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
    console.error(`
    Usage:
${process.argv[1]} <blocked_hosts_file.txt> <hosts.whitelisted> <domains.blocked> <dnsquery.log> <zones.adblock> help|simplify|processlog|add|generatezone|addgen <extra-parameters>...

    Files are identified by extension.";
    The first non file parameter is the command. All following parameters are command parameters.
`);
}

function addBlockedDomains(domains, filename) {
    domains.forEach((domain) => {
        if(!whitelistedDomains.isWhitelisted(domain)) {
            blockedDomains.blockDomain(domain);
        } else {
            console.warn(`Domain ${domain} is whitelisted`);
        }
    });
    filename && listBlockedDomains(blockedDomains, filename);
}

function reverseDNS(ip) {
    return new Promise(function (resolve) {
        dns.reverse(ip, (err, hostnames) => {
            let result = err ? `${ip} ${err.code}` : hostnames[0];
            resolve(result);
        });
    });
}

async function filterLine(line) {
    let dom = EXTRACT_DOMAIN_REGEX.exec(line);
    if(!dom) return;
    let domain = dom[1];
    if(blockedDomains.isBlocked(domain)) {
        return `blocked: ${domain}`;
    }
    let parts = EXTRACT_IP.exec(line);
    let time = parts[1];
    let ip = parts[2];
    let remoteHost = parts[3];
    let localName = localNameCache[ip];

    if(!localName) {
        localName = await reverseDNS(ip);
    }
    return `${time} client: ${localName}, query: ${domain}`;
}

function filter() {
    var rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        terminal: false
    });

    rl.on('line', async (line) => {
        let filteredLine = await filterLine(line);
        filteredLine && console.log(filteredLine);
    })
}

async function main() {
    let params = processCommandLine(process.argv);
    await processHostsBlocked(blockedDomains, params.hostsBlocked);
    params.domainsBlocked && await processHostsBlocked(blockedDomains, params.domainsBlocked);
    params.hostsWhitelisted && await processHostsWhitelisted(whitelistedDomains, params.hostsWhitelisted);

    params.command = params.command || help;

    switch (params.command) {
        case 'simplify':
            listBlockedDomains(blockedDomains, params.hostsBlocked);
            break;

        case 'add':
            addBlockedDomains(params.commandParams, params.hostsBlocked);
            break;

        case 'generatezone':
            // load_ignored_domains $domains_ignore_file;
            generateZone(blockedDomains, params.zonesFile);
            break;

        case 'addgen':
            params.commandParams.forEach((domain) => blockedDomains.blockDomain(domain));
            // listBlockedDomains(domainCache, params.hostsBlocked);
            // generate_zone $zones_file;
            break;

        case 'filter':
            filter();
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

module.exports = {
    blockedDomains: blockedDomains,
    whitelistedDomains: whitelistedDomains,
    processHostsLine: processHostsLine,
    processHostsBlocked: processHostsBlocked,
    main: main,
    processCommandLine: processCommandLine,
    generateZone: generateZone,
    BlockedDomain: BlockedDomain,
    filterLine: filterLine,
    reverseDNS: reverseDNS
};
