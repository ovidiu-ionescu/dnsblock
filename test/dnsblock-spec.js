'use strict';

const expect = require('chai').expect;
const dnsblock = require('../dnsblock.js');
const crypto = require('crypto');
const fs = require('fs');

const ADSERVER = 'adserver.net';
const WWWADSERVER = 'www.adserver.net';
const WIKIPEDIA = 'www.wikipedia.org';
const REALADSERVER = 'neptune.appads.com';

function shuffle(b) {
    let a = b.slice();
    let j, x, i;
    for (i = a.length - 1; i > 0; i--) {
        j = Math.floor(Math.random() * (i + 1));
        x = a[i];
        a[i] = a[j];
        a[j] = x;
    }
    return a;
}

function checksum (str, algorithm, encoding) {
    return crypto
        .createHash(algorithm || 'md5')
        .update(str, 'utf8')
        .digest(encoding || 'hex');
}

describe('Testing core functionality', () => {
    describe('Testing the domain cache', () => {
        it(`should accept domain ${ADSERVER} to block`, () => {
            expect(!!dnsblock.blockedDomains.blockDomain(ADSERVER)).to.be.true;
        });
        it(`should detect domain ${WWWADSERVER} as already blocked`, () => {
            expect(dnsblock.blockedDomains.blockDomain(WWWADSERVER)).to.be.false;
        });
        it(`should detect ${ADSERVER} as blocked`, () => {
            expect(dnsblock.blockedDomains.isBlocked(ADSERVER)).to.be.true;
        });
        it(`should detect ${WIKIPEDIA} as not blocked`, () => {
            expect(dnsblock.blockedDomains.isBlocked(WIKIPEDIA)).to.be.false;
        });
    });
    describe('Testing the whitelisting', () => {
        it(`should accept domain ${WIKIPEDIA} to whitelist`, () => {
            expect(!!dnsblock.whitelistedDomains.whitelistDomain(WIKIPEDIA, 'dictionary')).to.be.true;
        });
        it(`should detect ${WIKIPEDIA} as whitelisted`, () => {
            expect(dnsblock.whitelistedDomains.isWhitelisted(WIKIPEDIA)).to.be.true;
        });
        it(`should detect domain wikipedia.org as whitelisted`, () => {
            expect(dnsblock.whitelistedDomains.isWhitelisted('wikipedia.org')).to.be.true;
        });
        it(`should detect domain ${'ftp.' + WIKIPEDIA} as not whitelisted`, () => {
            expect(dnsblock.whitelistedDomains.isWhitelisted('ftp.' + WIKIPEDIA)).to.be.false;
        });
        it(`should detect domain ${ADSERVER} as not whitelisted`, () => {
            expect(dnsblock.whitelistedDomains.isWhitelisted(ADSERVER)).to.be.false;
        });
    });
    describe('Testing whitelisting and blocking together', () => {
        it('should not block whitelisted domain', () => {

        });
    });

    describe('Test line parsing', () => {
        it('should parse a domain and a comment', () => {
            expect(dnsblock.processHostsLine(' bad.adspammer.com # this is my comment   ')).to.deep.equal({
                domain: 'bad.adspammer.com',
                comment: ' # this is my comment'
            });
        });
        it('should throw an exception when domain is invalid', () => {
            let badDomain = 'bad_domain@';
            expect(() => dnsblock.processHostsLine(badDomain)).to.throw(`${badDomain} is not a valid domain`);
        });
    });
    describe('Test the BlockedDomain class', () => {
        it('should handle no comment', () => {
            expect(new dnsblock.BlockedDomain(WIKIPEDIA).serialize()).to.equal(WIKIPEDIA);
        });
    });
});

describe('Testing file processing', () => {
    describe('Test processing the hosts blocked file', () => {
        dnsblock.blockedDomains.resetCache();
        it(`should process the blocked hosts file`, () => {
            return dnsblock.processHostsBlocked(dnsblock.blockedDomains, 'domains.blocked');
        });
        it(`domain ${REALADSERVER} should now be blocked`, () => {
           expect(dnsblock.blockedDomains.isBlocked(REALADSERVER)).to.be.true;
        });
        it(`domain ${WIKIPEDIA} should not be blocked`, () => {
            expect(dnsblock.blockedDomains.isBlocked(WIKIPEDIA)).to.be.false;
        });
    });
});

describe('Testing output', () => {
    const zoneFileName = 'zoneinfo-test.txt';
    before(() => {try {fs.unlinkSync(zoneFileName) } catch(e){}});
    // after(() => fs.unlinkSync(zoneFileName));
    describe('Testing serialization', () => {
        const domains = ['promotie.ads', 'publicitate.ads', 'reclame.ads', 'neptune.appads.com', 'adserver.net' ];

        it('should produce a sorted list of domains', () => {
            dnsblock.blockedDomains.resetCache();
            shuffle(domains).forEach( (domain) => dnsblock.blockedDomains.blockDomain(domain) );
            let result = dnsblock.blockedDomains.serializeBlockedDomains();

            result.forEach((blockedDomain, index) => expect(blockedDomain.domain).to.be.equal(domains[index]) );
        });
        let zoneChecksum;
        it('should write a zone file', (done) => {
            dnsblock.generateZone(dnsblock.blockedDomains, zoneFileName);
            fs.readFile(zoneFileName, (err, data) => {
                zoneChecksum = checksum(data);
                done(err);
            });
        });
        it('checksum of the file should be', () => {
                expect(zoneChecksum).to.equal('56ce8d73435a693cf160a0a2ee6d7dc7');
        });
    });
});

describe('Test command line', () => {
    describe('Parse the command line parameters', () => {
        it('should interpret correctly the names of the files', () => {
            let commandLineParams = ['node', 'dnsblock.js', 'myhost.txt', 'mydom.blocked', 'myquery.log', 'myzones.adblock', 'unu', 'doi', 'trei' ];
            let params = dnsblock.processCommandLine(commandLineParams);
            expect(params).to.deep.equal({
                hostsBlocked: 'myhost.txt',
                hostsWhitelisted: '',
                domainsBlocked: 'mydom.blocked',
                zonesFile: 'myzones.adblock',
                dnsQueryLog: 'myquery.log',
                command: 'unu',
                commandParams: ['doi', 'trei']

            });
        });
    });
});

describe('Test filtering', () => {
    describe('Parse query log', () => {
        beforeEach(() => dnsblock.blockedDomains.resetCache());
        it('should parse a query for a blocked domain', () => {

        });
        it('should parse a query for a whitelisted domain', () => {

        });
        it('should resolve a query client', async () => {
            let line = '22-Dec-2017 21:09:28.799 client 127.0.0.1#55983 (shavar.prod.mozaws.net): view internal: query: shavar.prod.mozaws.net IN A +ED (127.0.0.1)';
            let parsedLine = await dnsblock.filterLine(line);
            expect(parsedLine).to.be.equal('22-Dec-2017 21:09:28.799 client: localhost, query: shavar.prod.mozaws.net');
        });
    });

    describe('Test reverse DNS', () => {
        let msIp = '184.24.199.187';
        let msAkamai = 'a184-24-199-187.deploy.static.akamaitechnologies.com';
        it(`should translate ${msIp} to ${msAkamai}`, async () => {
            const hostname = await dnsblock.reverseDNS(msIp);
            expect(hostname).to.equal(msAkamai);
        });
    });
});

