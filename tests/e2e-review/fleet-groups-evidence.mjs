/** Canonical capture contract shared by the producer and every evidence validator. */
import assert from 'node:assert/strict';
export const fleetGroupsCaseName='Manual Windows monitoring policies for exact devices';
export const fleetGroupsDisclosure='Production UI and real disposable loopback login with intercepted invented group membership and policy writes. Hosted browser fixture evidence only; no live group write, endpoint collection, native action, AI, notification or deployment.';
export const fleetGroupsScenes=Object.freeze(['groups','draft','review','results','inheritance-unchecked','inheritance-review','inheritance-status','inheritance-stop']);
export const fleetGroupsCaptureMatrix=Object.freeze(fleetGroupsScenes.flatMap(scene=>['en','de'].flatMap(locale=>[1440,390].map(width=>Object.freeze({scene,locale,width,height:width===390?844:1000,name:`synthetic-fleet-groups-${scene}-${width}-${locale}`,file:`synthetic-fleet-groups-${scene}-${width}-${locale}.png`})))));
export function fleetGroupsCaptureName(scene,width,locale){const row=fleetGroupsCaptureMatrix.find(row=>row.scene===scene&&row.width===width&&row.locale===locale);assert.ok(row,'Capture is outside the canonical fleet group matrix');return row.name;}
export function requireFleetGroupsEvidence(rows,sourceSha){
 assert.match(sourceSha??'',/^[a-f0-9]{40}$/);assert.equal(rows.length,fleetGroupsCaptureMatrix.length);
 for(const expected of fleetGroupsCaptureMatrix){
  const matches=rows.filter(row=>row.file===expected.file);assert.equal(matches.length,1);const row=matches[0];assert.equal(row.sourceSha,sourceSha);assert.equal(row.test,fleetGroupsCaseName);assert.equal(row.locale,expected.locale);assert.equal(row.viewport?.width,expected.width);assert.equal(row.viewport?.height,expected.height);assert.equal(row.fullPage,false);assert.equal(row.publicSafe,true);assert.equal(row.fixtureDisclosure,fleetGroupsDisclosure);
 }
 return Object.fromEntries(fleetGroupsScenes.map(scene=>[scene,fleetGroupsCaptureMatrix.filter(row=>row.scene===scene).length]));
}
