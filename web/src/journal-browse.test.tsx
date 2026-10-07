import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent } from './journal';
import { journalNow, journalPage, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
import type { JournalResource } from './journal-resource';
import type { JournalPage, JournalView } from './journal-types';

function view(state:'awaiting'|'accepted'='awaiting'):JournalView{
 const v=journalView(state);v.schemaVersion='tracebolt.journal-view.v2';v.generation={schemaVersion:'tracebolt.journal-generation-view.v3',browsingContract:'tracebolt.journal-browse.v1',policyGeneration:{revision:'1',generation:'a'.repeat(64),policyDigest:`sha256:${'b'.repeat(64)}`},sequence:'1',observedAt:journalNow,receivedAt:journalNow,expiresAt:'2026-10-04T12:05:00Z',fresh:true,policyEnabled:true,serviceAuthorization:'all-system-services',allowedUnits:[]};
 if(v.request)v.request.description={...v.request.description,schemaVersion:'tracebolt.journal-request.v3',policyGeneration:v.generation.policyGeneration,query:{unit:'fixture.service',start:'1970-01-01T00:00:00Z',end:journalNow,maxPriority:7,browseMode:'retained-v1'}};return v;
}
function resource(extra:Partial<JournalResource>={}):JournalResource{return {view:view(),page:null,busy:false,paused:false,failure:null,uncertain:false,reset:0,refresh:vi.fn(),refreshWindow:vi.fn(async()=>journalNow),create:vi.fn(async()=>{}),cancelRequest:vi.fn(),search:vi.fn(),next:vi.fn(),previous:vi.fn(),canPrevious:false,...extra}}
beforeEach(()=>setLocale('en',false));afterEach(cleanup);
describe('scoped retained journal browser',()=>{
 it('opens an explicitly selected service immediately without another consent modal',async()=>{const r=resource();render(<JournalContent resource={r} insecureTestMode initialUnit="fixture.service"/>);await waitFor(()=>expect(r.create).toHaveBeenCalledTimes(1));expect(r.create).toHaveBeenCalledWith({unit:'fixture.service',start:'1970-01-01T00:00:00Z',end:journalNow,maxPriority:7,browseMode:'retained-v1'},false,false);expect(screen.queryByRole('dialog')).not.toBeInTheDocument();expect(screen.queryByText(/I understand/)).not.toBeInTheDocument()});
 it('does not treat stale, disabled or previous grants as retained browsing permission',()=>{for(const change of [{fresh:false},{policyEnabled:false}]){const v=view();Object.assign(v.generation!,change);const r=resource({view:v});const mounted=render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);expect(r.create).not.toHaveBeenCalled();expect(screen.getByRole('button',{name:'Search logs'})).toBeDisabled();mounted.unmount()}const v=view();v.generation!.schemaVersion='tracebolt.journal-generation-view.v2';delete v.generation!.browsingContract;const r=resource({view:v});render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);expect(r.create).not.toHaveBeenCalled();expect(screen.getByRole('button',{name:'Fetch logs'})).toBeVisible()});
 it('continues an empty sparse page with the original exact filters and replaces source pages',async()=>{const v=view('accepted');v.request!.description.query.search='rare';const p:JournalPage={...journalPage([]),schemaVersion:'tracebolt.journal-page.v2',query:v.request!.description.query,searchScope:'retained_source_page',coverage:'partial',reason:'item_limit',countExact:false,nextCursor:'s=fixture;i=9'};const r=resource({view:v,page:p});render(<JournalContent resource={r} insecureTestMode={false}/>);fireEvent.change(screen.getByLabelText('Exact service unit'),{target:{value:'fixture.service'}});expect(screen.getByText(/No matching messages in this source page/)).toBeVisible();fireEvent.click(screen.getByRole('button',{name:'Continue searching older logs'}));await waitFor(()=>expect(r.create).toHaveBeenCalledWith({...v.request!.description.query,cursor:'s=fixture;i=9'},false,false));expect(r.search).not.toHaveBeenCalled()});
 it('source search starts a new retained query and never pretends to search only loaded messages',async()=>{const r=resource();render(<JournalContent resource={r} insecureTestMode={false}/>);fireEvent.change(screen.getByLabelText('Exact service unit'),{target:{value:'fixture.service'}});fireEvent.change(screen.getByLabelText('Search retained messages'),{target:{value:'literal failure'}});fireEvent.click(screen.getByRole('button',{name:'Search logs'}));await waitFor(()=>expect(r.create).toHaveBeenCalledWith(expect.objectContaining({browseMode:'retained-v1',search:'literal failure',start:'1970-01-01T00:00:00Z'}),false,false));expect(r.search).not.toHaveBeenCalled()});
 it('does not replay an initial read after pause or a later status refresh',async()=>{const r=resource();const mounted=render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);await waitFor(()=>expect(r.create).toHaveBeenCalledTimes(1));mounted.rerender(<JournalContent resource={{...r,view:null,paused:true,reset:1}} insecureTestMode={false} initialUnit="fixture.service"/>);mounted.rerender(<JournalContent resource={{...r,reset:2}} insecureTestMode={false} initialUnit="fixture.service"/>);expect(r.create).toHaveBeenCalledTimes(1)});
});

it('uses the same microsecond end for rendered validity and submission with nanosecond manager time',async()=>{
 const v=view();v.serverNow='2026-10-04T12:00:00.123456789Z';
 const r=resource({view:v,refreshWindow:vi.fn(async()=>v.serverNow)});
 render(<JournalContent resource={r} insecureTestMode={false}/>);
 fireEvent.change(screen.getByLabelText('Exact service unit'),{target:{value:'fixture.service'}});
 const search=screen.getByRole('button',{name:'Search logs'});
 expect(search).toBeEnabled();
 fireEvent.click(search);
 await waitFor(()=>expect(r.create).toHaveBeenCalledWith(expect.objectContaining({end:'2026-10-04T12:00:00.123456Z',browseMode:'retained-v1'}),false,false));
});

it.each(['expired','canceled','accepted'] as const)('fresh service navigation starts one new bounded read after same-unit %s content loss',async(state)=>{
 const v=view('accepted');v.request!.state=state;v.request!.contentStatus='unavailable';v.contentStatus='unavailable';
 if(state==='expired'){
  v.request!.description.createdAt='2026-10-04T11:45:00Z';v.request!.description.expiresAt=journalNow;v.request!.description.query.end='2026-10-04T11:45:00Z';
  v.request!.receipt!.acceptedAt='2026-10-04T11:45:00Z';v.request!.receipt!.expiresAt=journalNow;
 }
 const r=resource({view:v}),mounted=render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);
 await waitFor(()=>expect(r.create).toHaveBeenCalledTimes(1));
 expect(r.create).toHaveBeenCalledWith({unit:'fixture.service',start:'1970-01-01T00:00:00Z',end:journalNow,maxPriority:7,browseMode:'retained-v1'},false,false);
 expect(r.cancelRequest).not.toHaveBeenCalled();
 mounted.rerender(<JournalContent resource={{...r,reset:1}} insecureTestMode={false} initialUnit="fixture.service"/>);
 expect(r.create).toHaveBeenCalledTimes(1);
});

it.each(['pending','claimed','accepted'] as const)('keeps same-unit %s work that can still supply its page',state=>{
 const v=view('accepted');v.request!.state=state;
 if(state!=='accepted'){v.request!.receipt=null;v.request!.contentStatus='unavailable';v.contentStatus='unavailable'}
 const r=resource({view:v});render(<JournalContent resource={r} insecureTestMode={false} initialUnit="fixture.service"/>);
 expect(r.create).not.toHaveBeenCalled();expect(r.cancelRequest).not.toHaveBeenCalled();
});
