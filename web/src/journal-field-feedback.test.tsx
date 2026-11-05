import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { JournalContent } from './journal';
import { journalNow, journalView } from './journal-fixtures';
import { setLocale } from './i18n';
import type { JournalResource } from './journal-resource';
import type { JournalView } from './journal-types';

function view(state:'awaiting'|'accepted'='awaiting'):JournalView{
 const v=journalView(state);v.schemaVersion='tracebolt.journal-view.v2';v.generation={schemaVersion:'tracebolt.journal-generation-view.v3',browsingContract:'tracebolt.journal-browse.v1',policyGeneration:{revision:'1',generation:'a'.repeat(64),policyDigest:`sha256:${'b'.repeat(64)}`},sequence:'1',observedAt:journalNow,receivedAt:journalNow,expiresAt:'2026-10-04T12:05:00Z',fresh:true,policyEnabled:true,serviceAuthorization:'all-system-services',allowedUnits:[]};
 if(v.request)v.request.description={...v.request.description,schemaVersion:'tracebolt.journal-request.v3',policyGeneration:v.generation.policyGeneration,query:{unit:'fixture.service',start:'1970-01-01T00:00:00Z',end:journalNow,maxPriority:7,browseMode:'retained-v1'}};return v;
}
function resource(extra:Partial<JournalResource>={}):JournalResource{return {view:view(),page:null,busy:false,paused:false,failure:null,uncertain:false,reset:0,refresh:vi.fn(),refreshWindow:vi.fn(async()=>journalNow),create:vi.fn(async()=>{}),cancelRequest:vi.fn(),search:vi.fn(),next:vi.fn(),previous:vi.fn(),canPrevious:false,...extra}}
beforeEach(()=>setLocale('en',false));afterEach(cleanup);
describe('retained journal field feedback',()=>{
 it.each(['en','de'] as const)('associates UTF-8 search errors and clears them on repair (%s)',locale=>{
  setLocale(locale,false);const r=resource();render(<JournalContent resource={r} insecureTestMode={false}/>);
  const input=screen.getByLabelText(locale==='de'?'Aufbewahrte Nachrichten durchsuchen':'Search retained messages');
  fireEvent.change(screen.getByLabelText(locale==='de'?'Exakte Service-Unit':'Exact service unit'),{target:{value:'fixture.service'}});
  fireEvent.change(input,{target:{value:'ü'.repeat(100)}});expect(input).toHaveAttribute('aria-invalid','false');
  expect(screen.getByRole('button',{name:locale==='de'?'Logs durchsuchen':'Search logs'})).toBeEnabled();
  fireEvent.change(input,{target:{value:'ü'.repeat(100)+'a'}});expect(input).toHaveValue('ü'.repeat(100)+'a');expect(input).toHaveAttribute('aria-invalid','true');expect(input).toHaveAccessibleDescription(new RegExp('201 / 200'));
  expect(screen.getByRole('button',{name:locale==='de'?'Logs durchsuchen':'Search logs'})).toBeDisabled();
  fireEvent.change(input,{target:{value:'fixed'}});expect(input).toHaveAttribute('aria-invalid','false');expect(input).not.toHaveAttribute('aria-describedby');
  expect(r.create).not.toHaveBeenCalled();expect(r.refreshWindow).not.toHaveBeenCalled();expect(r.refresh).not.toHaveBeenCalled();
 });
 it.each(['en','de'] as const)('marks only malformed service and search fields (%s)',locale=>{
  setLocale(locale,false);const r=resource();render(<JournalContent resource={r} insecureTestMode={false}/>);
  const unit=screen.getByLabelText(locale==='de'?'Exakte Service-Unit':'Exact service unit'),search=screen.getByLabelText(locale==='de'?'Aufbewahrte Nachrichten durchsuchen':'Search retained messages');
  expect(unit).toHaveAttribute('aria-invalid','false');fireEvent.change(unit,{target:{value:'not a service'}});expect(unit).toHaveAttribute('aria-invalid','true');expect(unit).toHaveAccessibleDescription(/example.service/);expect(search).toHaveAttribute('aria-invalid','false');
  fireEvent.change(unit,{target:{value:'fixture.service'}});expect(unit).not.toHaveAttribute('aria-describedby');fireEvent.change(search,{target:{value:'a\u007fb'}});expect(search).toHaveAttribute('aria-invalid','true');expect(search).toHaveAccessibleDescription(locale==='de'?/Steuerzeichen/:/control characters/);expect(r.create).not.toHaveBeenCalled();
 });
 it.each(['en','de'] as const)('links UTC order and future errors to the affected date fields (%s)',locale=>{
  setLocale(locale,false);const r=resource();render(<JournalContent resource={r} insecureTestMode={false}/>);
  const fromName=locale==='de'?'Von (UTC)':'From (UTC)',toName=locale==='de'?'Bis (UTC)':'To (UTC)';
  fireEvent.click(screen.getByLabelText(locale==='de'?'Alle aufbewahrten Logs':'All retained'));
  const from=screen.getByLabelText(fromName),to=screen.getByLabelText(toName);
  fireEvent.change(from,{target:{value:'2026-10-04T12:00:00'}});expect(from).toHaveAttribute('aria-invalid','true');expect(to).toHaveAttribute('aria-invalid','true');expect(from).toHaveAccessibleDescription(locale==='de'?/muss vor/:/must be earlier/);
  fireEvent.change(from,{target:{value:'2026-10-04T11:00:00'}});expect(from).toHaveAttribute('aria-invalid','false');expect(to).toHaveAttribute('aria-invalid','false');
  fireEvent.change(to,{target:{value:'2026-10-04T12:01'}});expect(to).toHaveAttribute('aria-invalid','true');expect(from).toHaveAttribute('aria-invalid','false');expect(to).toHaveAccessibleDescription(locale==='de'?/Manager-Zeit/:/manager’s current time/);
  fireEvent.change(to,{target:{value:'2026-10-04T12:00:00'}});expect(to).not.toHaveAttribute('aria-describedby');
  fireEvent.change(from,{target:{value:''}});expect(from).toHaveAccessibleDescription(/UTC/);expect(to).toHaveAttribute('aria-invalid','false');
  fireEvent.change(from,{target:{value:'1969-12-31T23:59:59'}});expect(from).toHaveAttribute('aria-invalid','true');
  fireEvent.click(screen.getByLabelText(locale==='de'?'Alle aufbewahrten Logs':'All retained'));expect(screen.queryByLabelText(fromName)).toBeNull();expect(screen.queryByText(locale==='de'?/gültiges UTC-Datum/:/valid UTC date/)).toBeNull();
  expect(r.create).not.toHaveBeenCalled();expect(r.refreshWindow).not.toHaveBeenCalled();
 });
 it('removes descriptions when the source becomes unavailable while retaining its original warning',()=>{
  const r=resource(),mounted=render(<JournalContent resource={r} insecureTestMode={false}/>);fireEvent.change(screen.getByLabelText('Exact service unit'),{target:{value:'bad'}});expect(screen.getByLabelText('Exact service unit')).toHaveAttribute('aria-invalid','true');
  mounted.rerender(<JournalContent resource={{...r,view:null,paused:true,reset:1}} insecureTestMode={false}/>);expect(screen.getByLabelText('Exact service unit')).toHaveAttribute('aria-invalid','false');expect(screen.getByLabelText('Exact service unit')).not.toHaveAttribute('aria-describedby');expect(screen.getByText('Reading is paused. Refresh status to recheck access.')).toBeVisible();expect(r.create).not.toHaveBeenCalled();
 });
});
