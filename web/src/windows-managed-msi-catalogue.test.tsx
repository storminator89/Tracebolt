import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AUTH_REQUIRED_EVENT, mutateRaw, request } from './api';
import { useOperator } from './auth';
import { setLocale } from './i18n';
import { WindowsFleetManagedMSIWorklist } from './windows-fleet-managed-msi';
import { managedCataloguePath, managedCatalogueVersion, validManagedCatalogue, type ManagedCatalogueView } from './windows-managed-msi-catalogue-types';
import { validManagedArtifact, type ManagedArtifactView } from './windows-managed-msi-types';
import { catalogueWorklistVersion, validWorklistsView, worklistBindingDigest, worklistPath, worklistVersion, type WorklistsView, type WorklistView } from './windows-managed-msi-worklist-types';
import { ManagedMSIWorklistResource } from './windows-managed-msi-worklist-resource';
import { savedMSIFixture } from './windows-managed-msi-worklists-fixture';
import type { Device } from './types';

vi.mock('./api',async original=>({...await original<typeof import('./api')>(),request:vi.fn(),mutateRaw:vi.fn()}));
vi.mock('./auth',async original=>({...await original<typeof import('./auth')>(),useOperator:vi.fn()}));
const seconds=savedMSIFixture.artifact.serverNow,now=new Date(seconds*1000).toISOString();
const devices=savedMSIFixture.devices as unknown as Device[],digest=(s:string)=>`sha256:${s.repeat(64)}`;
let actor:string,catalogue:ManagedCatalogueView,lists:WorklistsView;
const session=()=>({...savedMSIFixture.session,actorId:actor});
function entry(occurrence:string,name:string):ManagedArtifactView{return {...structuredClone(savedMSIFixture.artifact) as ManagedArtifactView,artifactId:digest(occurrence),package:{...savedMSIFixture.artifact.package,name,architecture:'amd64' as const},retiredCount:occurrence,recent:[]}}
function list(artifact:ManagedArtifactView):WorklistView{
 const w=structuredClone(savedMSIFixture.worklist) as WorklistView;
 Object.assign(w,{id:`worklist_${artifact.retiredCount!.repeat(32)}`,name:`Worklist ${artifact.package!.name}`,artifactId:artifact.artifactId,artifactRetiredCount:artifact.retiredCount,package:artifact.package});
 for(const row of w.rows)if(row.view)Object.assign(row.view,{artifactId:artifact.artifactId,artifactRetiredCount:artifact.retiredCount,package:artifact.package});
 return w;
}
const review=(a:ManagedArtifactView)=>({package:a.package,nativeAcceptanceDigest:a.nativeAcceptanceDigest,publisherStatus:a.publisherStatus,publisherEvidenceDigest:a.publisherEvidenceDigest});
const flush=()=>act(async()=>{});
const choose=async(name='Package A',occurrence='1')=>{fireEvent.click(screen.getByRole('button',{name:`Select package: ${name} 1.2.3 · ${occurrence}`}));await flush()};
const mount=async()=>{const ui=render(<WindowsFleetManagedMSIWorklist devices={devices}/>);fireEvent.click(screen.getByRole('button',{name:'Windows MSI worklist'}));await flush();return ui};
const loadReview=async(a:ManagedArtifactView)=>{const f=new File(['fixture'],'review.json');Object.defineProperty(f,'text',{value:async()=>JSON.stringify(review(a))});fireEvent.change(screen.getByLabelText('New package review JSON'),{target:{files:[f]}});await flush()};
beforeEach(()=>{
 actor=`operator_${crypto.randomUUID().replaceAll('-','')}`;const entries=[entry('1','Package A'),entry('2','Package B')];
 catalogue={version:managedCatalogueVersion,enabled:true,serverNow:seconds,revision:'1',maxEntries:4,maxRetainedPayloadBytes:134217728,reservedBytes:2*1048576,entries};lists={version:catalogueWorklistVersion,enabled:true,serverNow:seconds,worklists:entries.map(list)};
 vi.useFakeTimers();vi.setSystemTime(now);setLocale('en',false);vi.mocked(useOperator).mockReturnValue({...session(),theme:'light',logout:vi.fn(),setTheme:vi.fn()} as never);
 vi.mocked(request).mockReset().mockImplementation(async path=>{
  if(path==='/auth/session')return structuredClone(session()) as never;
  if(path===managedCataloguePath)return structuredClone(catalogue) as never;
  if(path===worklistPath)return structuredClone(lists) as never;
  const occurrence=path.split('?artifactRetiredCount=')[1];
  if(path.startsWith('/windows-managed-msi/artifact?'))return structuredClone(catalogue.entries.find(e=>e.retiredCount===occurrence)) as never;
  if(path.startsWith('/devices/')&&occurrence)return structuredClone(lists.worklists.find(w=>w.artifactRetiredCount===occurrence)?.rows.find(row=>path.includes(row.deviceId))?.view) as never;
  throw Error(`Unexpected GET ${path}`);
 });vi.mocked(mutateRaw).mockReset();
});
afterEach(()=>{cleanup();vi.useRealTimers();vi.restoreAllMocks()});

it('validates explicit catalogue context without weakening singleton history or storage bounds',()=>{
 expect(validManagedCatalogue(catalogue)).toBe(true);expect(validManagedArtifact(catalogue.entries[0])).toBe(false);expect(validManagedArtifact(catalogue.entries[0],true)).toBe(true);
 for(const patch of [{reservedBytes:0},{maxEntries:5},{revision:'0'},{enabled:false},{entries:[catalogue.entries[0],catalogue.entries[0]]},{entries:[{...catalogue.entries[0],retiredCount:'0'},catalogue.entries[1]]},{entries:[{...catalogue.entries[0],recent:[{}]},catalogue.entries[1]]},{entries:[{...catalogue.entries[0],serverNow:seconds+1},catalogue.entries[1]]},{extra:true}])expect(validManagedCatalogue({...catalogue,...patch})).toBe(false);
 const retired={...catalogue.entries[0],state:'retired' as const,canRetire:false,retirementBlocked:'not_ready' as const};expect(validManagedCatalogue({...catalogue,entries:[retired,catalogue.entries[1]],reservedBytes:1048576})).toBe(true);
});
it('accepts one active worklist per occurrence only in v2',()=>{
 expect(validWorklistsView(lists)).toBe(true);expect(validWorklistsView({...lists,version:worklistVersion})).toBe(false);
 const duplicate=list(catalogue.entries[0]);duplicate.id=`worklist_${'3'.repeat(32)}`;expect(validWorklistsView({...lists,worklists:[lists.worklists[0],duplicate]})).toBe(false);
 duplicate.archivedAt=seconds;duplicate.rows=duplicate.rows.map(r=>({deviceId:r.deviceId,available:false,state:'unavailable'}));expect(validWorklistsView({...lists,worklists:[lists.worklists[0],duplicate]})).toBe(true);
});
it.each(['en','de'] as const)('requires exact package selection and reads no device on opening in %s',async locale=>{
 setLocale(locale,false);render(<WindowsFleetManagedMSIWorklist devices={devices}/>);fireEvent.click(screen.getByRole('button',{name:locale==='de'?'Windows-MSI-Arbeitsliste':'Windows MSI worklist'}));await flush();
 expect(screen.getByRole('progressbar',{name:locale==='de'?'Reservierter Manager-Speicher':'Reserved manager storage'})).toHaveAttribute('value','2097152');expect(screen.queryByRole('region',{name:'Saved MSI worklists'})).toBeNull();expect(screen.queryByRole('checkbox')).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();expect(vi.mocked(request).mock.calls.map(([p])=>p)).toEqual(['/auth/session',managedCataloguePath]);
});
it('selects retained B and older A independently, filters worklists, and pins device GETs',async()=>{
 await mount();await choose('Package B','2');expect(screen.getByText('Worklist Package B')).toBeVisible();expect(screen.queryByText('Worklist Package A')).toBeNull();expect(vi.mocked(request).mock.calls.some(([p])=>p==='/windows-managed-msi/artifact?artifactRetiredCount=2')).toBe(true);
 fireEvent.click(screen.getByRole('button',{name:`Open device: ${devices[0].name}`}));await flush();expect(vi.mocked(request).mock.calls.some(([p])=>p===`/devices/${devices[0].id}/windows-managed-msi?artifactRetiredCount=2`)).toBe(true);
 await choose();expect(screen.getByText('Worklist Package A')).toBeVisible();expect(screen.queryByText('Worklist Package B')).toBeNull();expect(screen.queryByRole('button',{name:'Read saved status'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('clears an unchecked stage preview when another package is selected',async()=>{
 vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{const w=lists.worklists.find(w=>path.includes(w.id))!;expect(path.endsWith('/preview')).toBe(true);return {worklistId:w.id,revision:w.revision,kind:JSON.parse(raw).kind,items:[],excluded:w.targets.map(t=>({deviceId:t.binding.deviceId,reason:'unavailable'}))} as never});
 await mount();await choose();fireEvent.click(screen.getByRole('button',{name:'Deliver selected devices'}));await flush();expect(screen.getByRole('checkbox')).not.toBeChecked();fireEvent.click(screen.getByRole('checkbox'));await choose('Package B','2');expect(screen.queryByRole('button',{name:'Confirm exact requests'})).toBeNull();expect(vi.mocked(mutateRaw).mock.calls).toHaveLength(1);
});
it('reserves a new exact review once with the displayed revision and keeps upload explicit',async()=>{
 const fresh={...entry('3','Package C'),state:'upload_incomplete' as const,uploadOffset:0,canRetire:false,retirementBlocked:'not_ready' as const};
 vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{expect(path).toBe(`${managedCataloguePath}/reserve`);expect(JSON.parse(raw)).toEqual({revision:'1',...review(fresh)});catalogue={...catalogue,revision:'2',reservedBytes:3*1048576,entries:[...catalogue.entries,fresh]};return structuredClone(catalogue) as never});
 await mount();await loadReview(fresh);const button=screen.getByRole('button',{name:'Reserve reviewed package'});fireEvent.click(button);fireEvent.click(button);await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('region',{name:'Selected MSI package'})).toHaveTextContent('Package C');expect(screen.getByRole('button',{name:'Continue exact upload'})).toBeDisabled();expect(screen.queryByRole('checkbox')).toBeNull();
});
it('reconciles a lost reserve with GET only across remount and never auto uploads',async()=>{
 const fresh={...entry('3','Package C'),state:'upload_incomplete' as const,uploadOffset:0,canRetire:false,retirementBlocked:'not_ready' as const};vi.mocked(mutateRaw).mockRejectedValueOnce(Error('lost response'));
 const ui=await mount();await loadReview(fresh);fireEvent.click(screen.getByRole('button',{name:'Reserve reviewed package'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('unconfirmed');ui.unmount();await mount();expect(screen.getByRole('button',{name:'Reserve reviewed package'})).toBeDisabled();expect(mutateRaw).toHaveBeenCalledTimes(1);
 catalogue={...catalogue,revision:'2',reservedBytes:3*1048576,entries:[...catalogue.entries,fresh]};fireEvent.click(screen.getByRole('button',{name:'Read package catalogue'}));await flush();expect(screen.queryByRole('alert')).toBeNull();expect(screen.getByRole('region',{name:'Selected MSI package'})).toHaveTextContent('Package C');expect(mutateRaw).toHaveBeenCalledTimes(1);
});
it('rejects a wrong occurrence response before exposing its worklist',async()=>{
 const original=vi.mocked(request).getMockImplementation()!;vi.mocked(request).mockImplementation(async(path,...rest)=>path.startsWith('/windows-managed-msi/artifact?')?structuredClone(catalogue.entries[1]) as never:original(path,...rest));await mount();await choose();expect(screen.getByRole('alert')).toBeVisible();expect(screen.queryByRole('button',{name:'Deliver selected devices'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it.each(['blur','pagehide','popstate','hashchange',AUTH_REQUIRED_EVENT])('stops reserve before dispatch on %s',async event=>{
 await mount();await loadReview(entry('3','Package C'));let resolve!:(v:unknown)=>void;vi.mocked(request).mockImplementationOnce(()=>new Promise(r=>{resolve=r}) as never);fireEvent.click(screen.getByRole('button',{name:'Reserve reviewed package'}));act(()=>window.dispatchEvent(new Event(event)));await act(async()=>resolve(session()));expect(mutateRaw).not.toHaveBeenCalled();expect(screen.getByRole('button',{name:'Reserve reviewed package'})).toBeDisabled();
});
it('fails closed on an unavailable catalogue without probing singleton custody',async()=>{
 vi.mocked(request).mockImplementation(async path=>{if(path==='/auth/session')return session() as never;throw Error('unavailable')});await mount();expect(screen.getByRole('alert')).toBeVisible();expect(vi.mocked(request).mock.calls.some(([p])=>p.includes('/artifact'))).toBe(false);expect(mutateRaw).not.toHaveBeenCalled();
});
it('uploads only the selected occurrence using existing chunk and completion bodies',async()=>{
 const raw=new Uint8Array(1024),hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),n=>n.toString(16).padStart(2,'0')).join('');
 catalogue.entries[0]={...catalogue.entries[0],state:'upload_incomplete',package:{...catalogue.entries[0].package!,size:1024,sha256:`sha256:${hash}`},uploadOffset:0};catalogue.reservedBytes=1048576+1024;lists.worklists=lists.worklists.slice(1);
 vi.mocked(mutateRaw).mockImplementation(async(path,body)=>{const value=JSON.parse(body);expect(value.retiredCount).toBe('1');if(path.endsWith('/upload')){expect(value.index).toBe(0);expect(value.packageDigest).toBe(`sha256:${hash}`);catalogue.entries[0]={...catalogue.entries[0],uploadOffset:1024}}else if(path.endsWith('/complete')){expect(value).toEqual({retiredCount:'1'});catalogue.entries[0]={...catalogue.entries[0],state:'uploaded'}}else throw Error('unexpected mutation');return structuredClone(catalogue.entries[0]) as never});
 await mount();await choose();const file=new File([raw],'inert.msi');Object.defineProperty(file,'arrayBuffer',{value:async()=>raw.slice().buffer});Object.defineProperty(file,'slice',{value:(start:number,end:number)=>({arrayBuffer:async()=>raw.slice(start,end).buffer})});const reviewed=new File(['fixture'],'review.json');Object.defineProperty(reviewed,'text',{value:async()=>JSON.stringify(review(catalogue.entries[0]))});fireEvent.change(screen.getByLabelText('Exact x64 machine MSI'),{target:{files:[file]}});fireEvent.change(screen.getByLabelText('Package review JSON'),{target:{files:[reviewed]}});await flush();fireEvent.click(screen.getByRole('button',{name:'Continue exact upload'}));
 await act(async()=>{await vi.waitFor(()=>expect(mutateRaw).toHaveBeenCalledTimes(2),{timeout:3000,interval:10})});await flush();expect(vi.mocked(mutateRaw).mock.calls.map(([p])=>p)).toEqual(['/windows-managed-msi/artifact/upload','/windows-managed-msi/artifact/complete']);expect(screen.getByRole('button',{name:'Save worklist'})).toBeDisabled();expect(vi.mocked(mutateRaw).mock.calls.some(([p])=>p.startsWith('/devices/'))).toBe(false);
});
it('retirement remains unchecked, exact-entry only, and updates aggregate storage by GET',async()=>{
 catalogue.entries[0]={...catalogue.entries[0],canRetire:true,retirementBlocked:''};vi.mocked(mutateRaw).mockImplementation(async(path,body)=>{expect(path).toBe('/windows-managed-msi/artifact/retire');expect(JSON.parse(body)).toEqual({artifactId:catalogue.entries[0].artifactId,acknowledged:true,retiredCount:'1'});catalogue.entries[0]={...catalogue.entries[0],state:'retired',canRetire:false,retirementBlocked:'not_ready'};catalogue.reservedBytes=1048576;catalogue.revision='2';return structuredClone(catalogue.entries[0]) as never});
 await mount();await choose();const box=screen.getByRole('checkbox',{name:/All assigned device jobs/});expect(box).not.toBeChecked();expect(screen.getByRole('button',{name:'Retire shared payload'})).toBeDisabled();fireEvent.click(box);fireEvent.click(screen.getByRole('button',{name:'Retire shared payload'}));await flush();expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.getByRole('progressbar',{name:'Reserved manager storage'})).toHaveAttribute('value','1048576');expect(catalogue.entries[1].state).toBe('uploaded');expect(screen.getByRole('button',{name:'Archive worklist'})).toBeEnabled();expect(screen.queryByRole('button',{name:'Upload exact package'})).toBeNull();
});
it('rejects a replacement catalogue occurrence rather than reusing a stale selection',async()=>{
 await mount();await choose();catalogue={...catalogue,revision:'2',entries:[{...catalogue.entries[0],retiredCount:'3'},catalogue.entries[1]]};fireEvent.click(screen.getByRole('button',{name:'Read package catalogue'}));await flush();expect(screen.queryByRole('region',{name:'Selected MSI package'})).toBeNull();expect(screen.queryByRole('button',{name:'Deliver selected devices'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('saves only explicitly selected A devices while an independent B worklist remains active',async()=>{
 const saved=list(catalogue.entries[0]);saved.targets=saved.targets.slice(0,1);saved.rows=saved.rows.slice(0,1);saved.group={id:'',name:'',revision:0};const binding=await worklistBindingDigest(saved.targets[0].binding);catalogue.entries[0].targets[0].bindingDigest=binding;saved.rows[0].view!.bindingDigest=binding;lists.worklists=lists.worklists.slice(1);
 vi.mocked(mutateRaw).mockImplementation(async(path,raw)=>{expect(path).toBe(`${worklistPath}/save`);const body=JSON.parse(raw);expect(body.artifactRetiredCount).toBe('1');expect(body.targets).toEqual([{deviceId:devices[0].id,name:devices[0].name,bindingDigest:binding}]);saved.name=body.name;lists.worklists.push(saved);return structuredClone(saved) as never});
 await mount();await choose();expect(screen.getByRole('button',{name:'Save worklist'})).toBeDisabled();fireEvent.click(screen.getByRole('checkbox',{name:new RegExp(devices[0].name)}));fireEvent.click(screen.getByRole('button',{name:'Save worklist'}));await act(async()=>{await vi.waitFor(()=>expect(lists.worklists).toHaveLength(2),{timeout:3000,interval:10})});expect(lists.worklists.filter(w=>!w.archivedAt)).toHaveLength(2);expect(mutateRaw).toHaveBeenCalledTimes(1);expect(screen.queryByText('Worklist Package B')).toBeNull();
});
it('scopes resource writes to the selected occurrence independently of UI filtering',async()=>{
 const resource=new ManagedMSIWorklistResource({actor,expires:savedMSIFixture.session.expiresAt,occurrence:'1',allowed:()=>true,onChange:()=>{}});await resource.read();await resource.preview(lists.worklists[1].id,'deliver');expect(mutateRaw).not.toHaveBeenCalled();expect(resource.state.error).toBe('invalid');resource.dispose();
});
it('shows conflicting saved references as blocked rather than offering a duplicate worklist',async()=>{
 lists.worklists[0].nativeAcceptanceDigest=digest('f');for(const row of lists.worklists[0].rows)if(row.view)row.view.nativeAcceptanceDigest=digest('f');await mount();await choose();expect(screen.getByText('Worklist Package A')).toBeVisible();expect(screen.getByRole('button',{name:'Deliver selected devices'})).toBeDisabled();expect(screen.queryByRole('button',{name:'Save worklist'})).toBeNull();expect(mutateRaw).not.toHaveBeenCalled();
});
it('keeps original archived outcomes inspectable after the payload occurrence is replaced',async()=>{
 const archived=list(entry('3','Replaced package'));archived.archivedAt=seconds;archived.targets[0].transferId=`transfer_${'9'.repeat(32)}`;archived.targets[0].jobSequence='1';archived.rows=archived.rows.map((row,i)=>({deviceId:row.deviceId,available:false,state:'unavailable',...(i===0?{historicalResult:{jobId:`software_${'9'.repeat(32)}`,envelopeDigest:digest('8'),attempted:true,returnCodeKnown:true,returnCode:3010,outcome:'restart_required' as const,registrationVerified:'unknown' as const,completedAt:seconds-10}}:{})}));lists.worklists.push(archived);await mount();await choose();const history=screen.getByText('Archived package worklists (1)').closest('details')!;expect(history).not.toHaveAttribute('open');fireEvent.click(history.querySelector('summary')!);fireEvent.click(within(history).getByText('Worklist Replaced package · 1.2.3 · Payload generation 3'));expect(within(history).getByText('3010: Restart required')).toBeVisible();expect(within(history).getByText('Return code: 3010 · Exact registration: Unknown')).toBeVisible();expect(within(history).queryByRole('button')).toBeNull();expect(within(history).queryByRole('checkbox')).toBeNull();expect(screen.getByRole('button',{name:'Deliver selected devices'})).toBeEnabled();expect(mutateRaw).not.toHaveBeenCalled();
});
it('requires explicit worklist archive before reserving into a retired occupied slot',async()=>{
 catalogue.entries.push(entry('3','Package C'),entry('4','Package D'));catalogue.entries[0]={...catalogue.entries[0],state:'retired',canRetire:false,retirementBlocked:'not_ready'};catalogue.reservedBytes=3*1048576;lists.worklists.push(...catalogue.entries.slice(2).map(list));await mount();await loadReview(entry('5','Package E'));fireEvent.click(screen.getByRole('button',{name:'Reserve reviewed package'}));await flush();expect(screen.getByRole('alert')).toHaveTextContent('Archive a retired package');expect(mutateRaw).not.toHaveBeenCalled();expect(vi.mocked(request).mock.calls.some(([path])=>path===worklistPath)).toBe(true);await choose();expect(screen.getByRole('button',{name:'Archive worklist'})).toBeEnabled();
});
