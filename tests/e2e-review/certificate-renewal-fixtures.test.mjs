import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {certificateRenewalFixture,certificateRenewalCaseName,certificateRenewalDisclosure,requireCertificateRenewalEvidence} from './certificate-renewal-browser.mjs';
test('renewal metadata fixtures distinguish valid, blocked and expired authority',()=>{
 for(const status of ['healthy','blocked','expired']){const d=certificateRenewalFixture(status);assert.equal(d.renewal.currentNotAfter,d.expiresAt);assert.equal(d.renewal.status,status);assert.equal(Date.parse(d.expiresAt)<=Date.parse(d.checkedAt),status==='expired');assert.equal(d.renewal.enabled,status!=='blocked');}
 assert.throws(()=>certificateRenewalFixture('unsupported'));assert.match(certificateRenewalDisclosure,/No certificate issuance/);
});
test('all twelve source-bound renewal screenshots are mandatory',()=>{
 const sha='a'.repeat(40),rows=[];
 for(const status of ['healthy','blocked','expired'])for(const locale of ['en','de'])for(const width of [1440,390])rows.push({test:certificateRenewalCaseName,file:`synthetic-certificate-renewal-${status}-${width}-${locale}.png`,sourceSha:sha,fixtureDisclosure:certificateRenewalDisclosure,publicSafe:true,fullPage:false,locale,viewport:{width,height:width===390?844:1000}});
 requireCertificateRenewalEvidence(rows,sha);assert.throws(()=>requireCertificateRenewalEvidence(rows.slice(1),sha));assert.throws(()=>requireCertificateRenewalEvidence([...rows.slice(1),rows[1]],sha));assert.throws(()=>requireCertificateRenewalEvidence(rows,'b'.repeat(40)));
});

test('renewal case is mandatory in the existing hosted runner',()=>{
 const runner=fs.readFileSync(new URL('./lan-browser.mjs',import.meta.url),'utf8');
 assert.equal((runner.match(/await check\(/g)||[]).length,27);
 assert.equal((runner.match(/await check\(certificateRenewalCaseName/g)||[]).length,1);
 assert.match(runner,/if\(name===certificateRenewalCaseName\)requireCertificateRenewalEvidence\(screenshots,sourceSha\);results.push\(\{name,status:'PASS'/);
});
