#!/usr/local/bin/node

const readline = require('readline');
const fs = require('fs');
const dns = require('dns');
const util = require('util');

const resolver = new dns.Resolver();
resolver.setServers(['8.8.8.8']);

const resolve = util.promisify(resolver.resolveAny.bind(resolver));

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
const NUMERIC_IPV4 = /^[0-9\.]+$/;

class BlockedDomain {
    constructor(domain, comment) {
        this.domain = domain;
        this.comment = comment || '#';
    }

    get normalizedComment() {
        return this.comment === '#' ? '' : this.comment;
    }

    serialize() {
        return this.normalizedComment ? `${this.domain}${this.comment}` : this.domain;
    }

    toString() {
        const concat = this.normalizedComment ? this.domain + ' : ' + this.comment : this.domain;
        return '[' + concat + ']';
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
        if(typeof cache === 'string') {
            result.push(new BlockedDomain(path.join('.'), cache));
            return;
        }
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

    /**
     * Visits all nodes in the cache tree recursively
     * @param cache Cache tree node from where to start exploring
     * @param path The path to the current node, array of strings
     * @param accumulator Accumulator object
     * @param processor Processor function, gets invoked for every node
     * processor(node, path, accumulator)
     * @private
     */
    _visitCache(cache, path, accumulator, processor) {
        Object.keys(cache).sort().filter(v => typeof cache[v] !== 'string').forEach((key) => {
            path.unshift(key);
            this._visitCache(cache[key], path, accumulator, processor);
            path.shift();
        });
        return processor(cache, path, accumulator);
    }

    visit(processor, accumulator) {
        return this._visitCache(this.cache, [], accumulator, processor);
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

    // @return the rule that blocks the domain or false
    isBlocked(domain) {
        let p = this.cache;
        const blocker = [];
        for (const key of domain.toLowerCase().split('.').reverse()) {
            blocker.unshift(key);
            p = p[key];
            if (p) {
                if (typeof p === 'string') {
                    return blocker.join('.');
                }
            } else {
                return false;
            }
        }
        return false;
    }

}

/**
 * Whitelisting works in reverse compared to blocking, i.e. in order to 
 * whitelist a domain we must make sure none of it's ancestors is blocked
 * So www.wikipedia.org automatically whitelists wikipedia.org
 */
class WhitelistedDomainIndex extends DomainIndex {
    // longer subdomain will replace the domain
    whitelistDomain(domain, comment) {
        console.log(`Whitelisting: ${domain} on behalf of ${comment}`);
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

    /**
     * @return the subtree that blocks the domain
     */
    isWhitelisted(domain) {
        let p = this.cache;
        // we go down the whitelist tree, all domain parts must be in full in the tree
        for (const key of domain.toLowerCase().split('.').reverse()) {
            p = p[key];
            if (!p) {
                return false;
            }
        }
        const result = [];
        this._traverseCache(p, domain.toLowerCase().split('.'), result);
        return result;
    }

}

const blockedDomains = new BlockedDomainIndex();
const whitelistedDomains = new WhitelistedDomainIndex();
const localNameCache = { '127.0.0.1': 'localhost' };

/**
 * Goes through a line from the whiteliste file and extracts the name and the
 * comment, then resolves all the cnames
 * @param {string} line 
 */
function processHostsLine(line) {
    line = line.toLowerCase().trim();
    let spaceIndex = line.indexOf(' ');
    let domain = line;
    let comment = '';
    if (spaceIndex !== -1) {
        domain = line.substring(0, spaceIndex);
        comment = line.substring(spaceIndex);
    }
    if (!domain.match(VALID_DOMAIN_REGEX) || domain.match(NUMERIC_IPV4) || domain === 'localhost' || domain === 'localhost.localdomain') {
        throw `[${domain}] is not a valid domain, comment: [${comment}]`;
    }
    return new BlockedDomain(domain, comment);
}

async function digList(domain) {
    let cname = domain;
    const result = [];
    while(cname) {
        result.push(cname)
        const addresses = await resolve(cname);
        const a = addresses.find(e => e.type === 'A');
        if(a) return result;
        const c = addresses.find(e => e.type === 'CNAME');
        if(!c) return result;
        cname = c.value;
    }
}

function collectHostsWhitelisted(filename) {
    const rl = readline.createInterface({ input: fs.createReadStream(filename) });

    const result = [];
    rl.on('line', (line) => {
        try {
            result.unshift(processHostsLine(line));
        } catch(e) {
            console.error(e);
        }
    });

    return new Promise(function (resolve) {
        rl.on('close', () => resolve(result));
    });
}

async function processHostsWhitelisted(cache, filename) {
    const whitelistedDomains = await collectHostsWhitelisted(filename);

    whitelistedDomains.forEach(async whitelistedDomain => {
        const cnameList = await digList(whitelistedDomain.domain);
        cnameList.map(cname =>
            cache.whitelistDomain(cname, `${whitelistedDomain.serialize()}`))
        });
}

function processHostsBlocked(cache, filename) {
    const rl = readline.createInterface({input: fs.createReadStream(filename)});
    rl.on('line', (line) => {
        try {
            let blockedDomain = processHostsLine(line);
            const whitelistedBy = whitelistedDomains.isWhitelisted(blockedDomain.domain);
            if(whitelistedBy) {
                console.log(`Domain ${blockedDomain.domain} is whitelisted by ${whitelistedBy}`);
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

const generateRpz = (cache, filename) => {
    const blockedDomains = cache.serializeBlockedDomains();
    const prefix = 
`$TTL 60
@   IN    SOA  localhost. root.localhost.  (
        2   ; serial 
        3H  ; refresh 
        1H  ; retry 
        1W  ; expiry 
        1H) ; minimum 
    IN    NS    localhost.
`;
    const rpz = blockedDomains.reduce((accumulator, blockedDomain) => accumulator + 
`${blockedDomain.domain} CNAME .
*.${blockedDomain.domain} CNAME .
`, prefix);

fs.writeFile(filename, rpz, (err) => err && console.error('Error is: ', err));

}

async function whitelist(cache, domain, whitelistCache) {
    console.log(`Whitelisting ${domain}`)
    const cnameList = await digList(domain);
    console.log(cnameList);
    cnameList.forEach(cname => {
        const blocker = cache.isBlocked(cname);
        if(blocker) {
            console.log(`${blocker} # ${cname}`);
        } else {
            if(whitelistCache.isWhitelisted(cname)) {
                console.log(`# ${domain} is whitelisted`);
            }
        }
    });
}

function processCommandLine(commandLineParameters) {

    let params = {
        hostsBlocked: 'hosts_blocked.txt',
        hostsWhitelisted: '',
        domainsBlocked: null,
        zonesFile: 'zones.adblock',
        rpzFile: 'rpz.db',
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
${process.argv[1]} <blocked_hosts_file.txt> <hosts.whitelisted> <domains.blocked> <dnsquery.log> <zones.adblock> help|simplify|simplifyDomains|processlog|add|generatezone|whitelist|addgen|advise <extra-parameters>...

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
    if(!parts) return line;
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


/**
 * Iterates the blocked domains cache and signals common suffixes in level 3
 * @param cache The blocked domains cache
 */
function advise(cache) {
    let stats = cache.visit((node, path, accumulator) => {
        if(path.length > 1) {
            let count = Object.keys(node).length;
            if( count > 4) {
                accumulator.unshift({ count: count, path: path.join('.') });
                //console.log(count + ' ' + path.join('.'));
            }
        }
        return accumulator;
    }, []);

    // stats.sort((a, b) => a.count - b.count).forEach((e) => console.log(`${e.count} ${e.path}`));
    stats.forEach((e) => console.log(`${e.count} ${e.path}`));
}

async function main() {
    let params = processCommandLine(process.argv);
    params.hostsWhitelisted && await processHostsWhitelisted(whitelistedDomains, params.hostsWhitelisted);
    await processHostsBlocked(blockedDomains, params.hostsBlocked);
    params.domainsBlocked && await processHostsBlocked(blockedDomains, params.domainsBlocked);

    params.command = params.command || help;

    switch (params.command) {
        case 'simplify':
            listBlockedDomains(blockedDomains, params.hostsBlocked);
            break;

        case 'simplifyDomains':
            listBlockedDomains(blockedDomains, params.domainsBlocked);
            break;

        case 'add':
            addBlockedDomains(params.commandParams, params.hostsBlocked);
            break;

        case 'generatezone':
            // load_ignored_domains $domains_ignore_file;
            generateZone(blockedDomains, params.zonesFile);
            break;

        case 'generateRpz':
            generateRpz(blockedDomains, params.rpzFile);
            break;

        case 'addgen':
            params.commandParams.forEach((domain) => blockedDomains.blockDomain(domain));
            // listBlockedDomains(domainCache, params.hostsBlocked);
            // generate_zone $zones_file;
            break;

        case 'whitelist':
            whitelist(blockedDomains, params.commandParams[0], whitelistedDomains);
            break;

        case 'filter':
            filter();
            break;

        case 'ignore':
            break;

        case 'processlog':
            // process_dns_query_log $dns_query_log, @params;
            break;

        case 'advise':
            advise(blockedDomains);
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
