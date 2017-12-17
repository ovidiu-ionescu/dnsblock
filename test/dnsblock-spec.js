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
            expect(!!dnsblock.domainCache.blockDomain(ADSERVER)).to.be.true;
        });
        it(`should detect domain ${WWWADSERVER} as already blocked`, () => {
            expect(dnsblock.domainCache.blockDomain(WWWADSERVER)).to.be.false;
        });
        it(`should detect ${ADSERVER} as blocked`, () => {
            expect(dnsblock.domainCache.isBlocked(ADSERVER)).to.be.true;
        });
        it(`should detect ${WIKIPEDIA} as not blocked`, () => {
            expect(dnsblock.domainCache.isBlocked(WIKIPEDIA)).to.be.false;
        });
    })
});

describe('Testing file processing', () => {
    describe('Test processing the hosts blocked file', ()=> {
        dnsblock.domainCache.resetCache();
        it(`should process the blocked hosts file`, () => {
            return dnsblock.processHostsBlocked(dnsblock.domainCache, 'domains.blocked');
        });
        it(`domain ${REALADSERVER} should now be blocked`, () => {
           expect(dnsblock.domainCache.isBlocked(REALADSERVER)).to.be.true;
        });
        it(`domain ${WIKIPEDIA} should not be blocked`, () => {
            expect(dnsblock.domainCache.isBlocked(WIKIPEDIA)).to.be.false;
        });
    });
});

describe('Testing output', () => {
    const zoneFileName = 'zoneinfo-test.txt';
    before(() => {try {fs.unlinkSync(zoneFileName) } catch(e){}});
    after(() => fs.unlinkSync(zoneFileName));
    describe('Testing serialization', () => {
        const domains = ['promotie.ads', 'publicitate.ads', 'reclame.ads', 'neptune.appads.com', 'adserver.net' ];

        it('should produce a sorted list of domains', () => {
            dnsblock.domainCache.resetCache();
            shuffle(domains).forEach( (domain) => dnsblock.domainCache.blockDomain(domain) );
            let result = dnsblock.domainCache.serializeBlockedDomains();

            result.forEach((domain, index) => expect(domain).to.be.equal(domains[index]) );
        });
        let zoneChecksum;
        it('should write a zone file', (done) => {
            dnsblock.generateZone(dnsblock.domainCache, zoneFileName);
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
                domainsBlocked: 'mydom.blocked',
                zonesFile: 'myzones.adblock',
                dnsQueryLog: 'myquery.log',
                domainsIgnoreFile: 'zones.searchads',
                command: 'unu',
                commandParams: ['doi', 'trei']

            });
        });
    });
});

