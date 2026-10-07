import { useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests, AUTH_REQUIRED_EVENT } from './api';
import { InvestigationsPage } from './investigations';
import { useInvestigations } from './investigations-resource';
import { ageInvestigations, INVESTIGATIONS_BYTES, validInvestigationsView } from './investigations-types';
import type { InvestigationScope, InvestigationsView } from './investigations-types';
import { setLocale } from './i18n';
const id='agent_00000000000000000000000000000001', now='2026-10-06T12:00:00Z';
function fixture(scope: InvestigationScope = 'open', offset=0): InvestigationsView {
 const incident={id:'health_0000000000000001',key:'filesystem:root',kind:'filesystem' as const,target:'/',openedAt:'2026-10-06T11:57:00Z',lastObservedAt:now,resolvedAt:null,acknowledgedAt:null};
 return {schemaVersion:'tracebolt.investigations.v1',serverNow:now,scope,offset,total:1,counts:{open:1,recovered:0,closed:0,all:1},devices:[{schemaVersion:'tracebolt.health-view.v1',deviceId:id,serverNow:now,evaluatedAt:now,status:'attention',maintenanceUntil:null,monitoredServices:[],checks:[{key:'offline:contact',kind:'offline',target:'agent',state:'ok',observedAt:now,value:null},{key:'filesystem:root',kind:'filesystem',target:'/',state:'open',observedAt:now,value:95}],incidents:[]}],items:[{deviceId:id,incident}]};
}
function pagedFixture(scope: InvestigationScope, offset: number, total = 51): InvestigationsView {
 const value=fixture(scope,offset); value.counts={open:1,recovered:total-1,closed:0,all:total};value.total=value.counts[scope];
 const all=Array.from({length:total},(_,i)=>({deviceId:id,incident:{...fixture().items[0].incident,id:`health_${(i+1).toString(16).padStart(16,'0')}`,...(i>0?{resolvedAt:now,closedReason:'recovered' as const}:{})}}));
 const selected=scope==='all'?all:scope==='open'?all.slice(0,1):scope==='recovered'?all.slice(1):[];value.items=selected.slice(offset,offset+50);return value;
}
const response=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status});
function Harness({enabled=true,route='cases'}:{enabled?:boolean;route?:string}) {
 const [scope,setScope]=useState<InvestigationScope>('open'),[offset,setOffset]=useState(0),resource=useInvestigations(enabled,'session-a',route,scope,offset);
 return <InvestigationsPage resource={resource} devices={[]} scope={scope} offset={offset} onScope={next=>{setScope(next);setOffset(0);}} onPage={setOffset}/>;
}
const refresh=()=>fireEvent.click(screen.getByRole('button',{name:'Refresh investigations'}));
beforeEach(()=>{setLocale('en',false);sessionStorage.clear();localStorage.clear();});
afterEach(()=>{cleanup();abortProtectedRequests();vi.useRealTimers();vi.unstubAllGlobals();vi.restoreAllMocks();});
describe('read-only health investigations',()=>{
 it('validates the bounded real health contract, exact counts, scope and membership',()=>{
  expect(validInvestigationsView(fixture(),'open',0)).toBe(true);
  for(const value of [{...fixture(),extra:true},{...fixture(),counts:{open:0,recovered:0,closed:0,all:0}},{...fixture(),devices:[]},{...fixture(),items:[...fixture().items,...fixture().items]},{...fixture(),scope:'all'},{...fixture(),serverNow:'2026-02-31T00:00:00Z'}]) expect(validInvestigationsView(value,'open',0)).toBe(false);
  const malformed=fixture();malformed.items[0].incident.resolvedAt=now as never;expect(validInvestigationsView(malformed,'open',0)).toBe(false);
 });
 it('renders evidence with an undetermined cause and links only to real device views',async()=>{
  const fetch=vi.fn().mockResolvedValue(response(fixture()));vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('Root filesystem nearly full');
  fireEvent.click(screen.getByText('Evidence & next check'));expect(screen.getByText(/Cause undetermined/)).toBeVisible();expect(screen.getByText('95.0 %')).toBeVisible();
  expect(screen.getByRole('link',{name:'Check Health'})).toHaveAttribute('href',`#/devices/${id}/health`);expect(screen.getByRole('link',{name:'Device details'})).toHaveAttribute('href',`#/devices/${id}/details`);
  expect(screen.queryByRole('button',{name:/Resolve|Analyze|Acknowledge|Restart/})).not.toBeInTheDocument();expect(fetch).toHaveBeenCalledTimes(1);expect(fetch.mock.calls[0][0]).toBe('/api/investigations?scope=open&offset=0');expect(fetch.mock.calls[0][1]).toMatchObject({credentials:'same-origin'});expect(fetch.mock.calls[0][1].method).toBeUndefined();expect(fetch.mock.calls[0][1].body).toBeUndefined();
 });
 it('keeps acknowledgement separate from recovery and stopped monitoring',async()=>{
  const value=fixture('all');value.items[0].incident.acknowledgedAt=now as never;expect(validInvestigationsView(value,'all',0)).toBe(true);
  const fetch=vi.fn().mockImplementation((url:string)=>{const scope=new URL(url,'https://localhost').searchParams.get('scope') as InvestigationScope;const next=fixture(scope);if(scope==='closed'){next.counts={open:0,recovered:0,closed:1,all:1};next.items[0].incident={...next.items[0].incident,resolvedAt:now,closedReason:'monitoring_stopped'};}return Promise.resolve(response(next));});vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('Root filesystem nearly full');fireEvent.click(screen.getByRole('button',{name:'Monitoring stopped 0'}));await screen.findByText('Root filesystem nearly full');fireEvent.click(screen.getByText('Evidence & next check'));expect(screen.getByText('Monitoring was stopped. This does not confirm recovery.')).toBeVisible();expect(screen.getByRole('button',{name:'Recovered 0'})).toBeVisible();
 });
 it('paginates without sending names or evidence in URLs, and resets page on scope change',async()=>{
  const fetch=vi.fn().mockImplementation((url:string)=>{const params=new URL(url,'https://localhost').searchParams;return Promise.resolve(response(pagedFixture(params.get('scope') as InvestigationScope,Number(params.get('offset')))));});vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('Root filesystem nearly full');fireEvent.click(screen.getByRole('button',{name:'All cases 51'}));await screen.findByText('1–50 / 51');fireEvent.click(screen.getByRole('button',{name:'Next'}));await screen.findByText('51–51 / 51');expect(screen.getByRole('button',{name:'Next'})).toBeDisabled();fireEvent.click(screen.getByRole('button',{name:'Monitoring stopped 0'}));await screen.findByText('No cases in this view');expect(fetch.mock.calls.map(x=>x[0])).toEqual(['/api/investigations?scope=open&offset=0','/api/investigations?scope=all&offset=0','/api/investigations?scope=all&offset=50','/api/investigations?scope=closed&offset=0']);
 });
 it('distinguishes an empty retained history from missing or revoked data',async()=>{
  const value=fixture();value.items=[];value.devices=[];value.counts={open:0,recovered:0,closed:0,all:0};value.total=0;
  const fetch=vi.fn().mockResolvedValueOnce(response(value)).mockResolvedValueOnce(response({},503));vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('No cases in this view');expect(screen.getByText(/This does not confirm device health/)).toBeVisible();refresh();await screen.findByRole('alert');expect(screen.queryByText('No cases in this view')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Open —'})).toBeVisible();
 });
 it('ages current evidence without resolving a stored incident or inventing historical values',async()=>{
  vi.useFakeTimers();const value=fixture();value.devices[0].checks[1].observedAt='2026-10-06T11:58:01Z';vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response(value)));render(<Harness/>);await act(async()=>{await vi.advanceTimersByTimeAsync(0);});fireEvent.click(screen.getByText('Evidence & next check'));expect(screen.getByText('95.0 %')).toBeVisible();await act(async()=>{await vi.advanceTimersByTimeAsync(2100);});expect(screen.queryByText('95.0 %')).not.toBeInTheDocument();expect(screen.getByText('Unknown: current evidence is missing or stale')).toBeVisible();expect(screen.getByRole('button',{name:'Open 1'})).toBeVisible();
  expect(ageInvestigations(value,121000).items[0].incident.resolvedAt).toBeNull();
 });
 it('clears a failed refresh and late response after session revocation',async()=>{
  let finish!:(value:Response)=>void;const fetch=vi.fn().mockResolvedValueOnce(response(fixture())).mockResolvedValueOnce(response({},503)).mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;}));vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('Root filesystem nearly full');refresh();await screen.findByRole('alert');expect(screen.queryByText('Root filesystem nearly full')).not.toBeInTheDocument();refresh();await waitFor(()=>expect(finish).toBeDefined());act(()=>{abortProtectedRequests();window.dispatchEvent(new Event(AUTH_REQUIRED_EVENT));});await act(async()=>finish(response(fixture())));expect(screen.queryByText('Root filesystem nearly full')).not.toBeInTheDocument();expect(screen.getByRole('button',{name:'Refresh investigations'})).toBeDisabled();expect(screen.getByRole('alert')).toHaveTextContent('Session ended');act(()=>window.dispatchEvent(new Event('focus')));expect(fetch).toHaveBeenCalledTimes(3);
 });
 it('clears on hide and older routes, requiring a fresh read after focus',async()=>{
  const fetch=vi.fn().mockImplementation(()=>Promise.resolve(response(fixture())));vi.stubGlobal('fetch',fetch);const{rerender}=render(<Harness/>);await screen.findByText('Root filesystem nearly full');act(()=>window.dispatchEvent(new Event('blur')));expect(screen.queryByText('Root filesystem nearly full')).not.toBeInTheDocument();act(()=>window.dispatchEvent(new Event('focus')));await screen.findByText('Root filesystem nearly full');rerender(<Harness enabled={false} route="devices"/>);expect(screen.queryByText('Root filesystem nearly full')).not.toBeInTheDocument();expect(fetch).toHaveBeenCalledTimes(2);
 });
 it('rejects oversized bytes and handles real unauthorized responses',async()=>{
  let canceled=false;const stream=new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(' '.repeat(INVESTIGATIONS_BYTES+1)));},cancel(){canceled=true;}});const fetch=vi.fn().mockResolvedValueOnce(new Response(stream)).mockResolvedValueOnce(response({},401));vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByRole('alert');expect(canceled).toBe(true);refresh();await waitFor(()=>expect(screen.getByRole('button',{name:'Refresh investigations'})).toBeDisabled());expect(screen.getByRole('alert')).toHaveTextContent('Session ended');
 });
 it('bounds stalled requests and invalidates a changed clock',async()=>{
  vi.useFakeTimers();const fetch=vi.fn().mockImplementationOnce(()=>new Promise(()=>{})).mockResolvedValueOnce(response(fixture()));vi.stubGlobal('fetch',fetch);render(<Harness/>);await act(async()=>{await vi.advanceTimersByTimeAsync(10001);});expect(screen.getByRole('alert')).toHaveTextContent('timed out');refresh();await act(async()=>{await vi.advanceTimersByTimeAsync(0);});expect(screen.getByText('Root filesystem nearly full')).toBeVisible();vi.setSystemTime(Date.now()+10000);await act(async()=>{await vi.advanceTimersByTimeAsync(1000);});expect(screen.queryByText('Root filesystem nearly full')).not.toBeInTheDocument();expect(screen.getByRole('alert')).toHaveTextContent('Time reference changed');
 });
});

it('does not offer an exact-unit journal link when the journal API rejects that Health unit',async()=>{
 const value=fixture();value.devices[0].monitoredServices=['foo:bar.service'];value.devices[0].checks.push({key:'service:foo:bar.service',kind:'service',target:'foo:bar.service',state:'open',observedAt:now,value:null});value.items[0].incident={...value.items[0].incident,key:'service:foo:bar.service',kind:'service',target:'foo:bar.service'};vi.stubGlobal('fetch',vi.fn().mockResolvedValue(response(value)));render(<Harness/>);await screen.findByText('foo:bar.service: service inactive');fireEvent.click(screen.getByText('Evidence & next check'));expect(screen.queryByRole('link',{name:'Service logs'})).not.toBeInTheDocument();expect(screen.getByText(/A journal link is unavailable for this unit name/)).toBeVisible();
});
it('distinguishes a live page that shrank from an empty incident history',async()=>{
 const fetch=vi.fn().mockImplementation((url:string)=>{const params=new URL(url,'https://localhost').searchParams,offset=Number(params.get('offset'));return Promise.resolve(response(pagedFixture(params.get('scope') as InvestigationScope,offset,offset?49:51)));});vi.stubGlobal('fetch',fetch);render(<Harness/>);await screen.findByText('Root filesystem nearly full');fireEvent.click(screen.getByRole('button',{name:'All cases 51'}));await screen.findByText('1–50 / 51');fireEvent.click(screen.getByRole('button',{name:'Next'}));await screen.findByText('This page has changed');expect(screen.queryByText('No cases in this view')).not.toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Go to first page'}));await screen.findByText('1–50 / 51');
});
it('rejects impossible history counts and duplicate open incidents for the same check',()=>{
 const empty=fixture();empty.devices=[];empty.items=[];empty.counts={open:0,recovered:2500,closed:0,all:2500};empty.total=0;expect(validInvestigationsView(empty,'open',0)).toBe(false);
 const duplicate=fixture();duplicate.items.push({...duplicate.items[0],incident:{...duplicate.items[0].incident,id:'health_0000000000000002'}});duplicate.counts.open=duplicate.counts.all=duplicate.total=2;expect(validInvestigationsView(duplicate,'open',0)).toBe(false);
});

it('shows the next destination before evidence and omits repeated page headings', async () => {
 const fetch=vi.fn().mockResolvedValue(response(fixture()));vi.stubGlobal('fetch',fetch);render(<Harness/>);
 const link=await screen.findByRole('link',{name:'Check Health'});expect(link).toBeVisible();
 expect(screen.getByText('Evidence & next check').closest('details')).not.toHaveAttribute('open');
 expect(screen.queryByRole('heading',{name:'Open'})).not.toBeInTheDocument();
 expect(screen.queryByText('Review stored health warnings and find the next check.')).not.toBeInTheDocument();
 expect(fetch).toHaveBeenCalledTimes(1);expect(fetch.mock.calls[0][1].method).toBeUndefined();
});
