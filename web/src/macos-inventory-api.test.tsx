import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { MacInventoryWorkspace } from './macos-inventory';
import { macInventoryDeviceId, macInventoryFixtureClock } from './macos-inventory-fixture';
import { setLocale } from './i18n';
const response = (value:unknown, status=200) => new Response(JSON.stringify(value), {status,headers:{'Content-Type':'application/json'}});
const props = { deviceId: macInventoryDeviceId, enabled: true, configured: true, sessionKey: '2026-10-13T10:30:00Z', identityKey: 'identity' };
let macInventoryFixture: ReturnType<typeof macInventoryFixtureClock>;
beforeEach(() => { macInventoryFixture = macInventoryFixtureClock(); setLocale('en',false); abortProtectedRequests(); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('real bounded Mac private-read client', () => {
 it('uses same-origin CSRF POSTs and never puts generation, offset or rows in URLs', async () => {
  const calls:{url:string;init:RequestInit|undefined}[]=[]; vi.stubGlobal('fetch',vi.fn(async (url:string,init?:RequestInit)=>{calls.push({url,init});return url==='/api/session'?response({csrfToken:'synthetic-csrf'}):response(macInventoryFixture(JSON.parse(String(init?.body))));}));
  render(<MacInventoryWorkspace {...props}/>); await screen.findByText('Mac14,12');
  expect(calls).toHaveLength(4); fireEvent.click(screen.getByRole('tab', { name: 'Package receipts' })); await screen.findByText('com.example.fixture.helper'); fireEvent.change(screen.getByRole('textbox'), { target: { value: 'EDITOR' } }); fireEvent.click(screen.getByRole('button', { name: 'Apply' })); await screen.findByText('com.example.fixture.editor'); expect(screen.queryByText('com.example.fixture.helper')).not.toBeInTheDocument(); expect(JSON.parse(String(calls.at(-1)!.init?.body))).toMatchObject({ schemaVersion: 'tracebolt.macos-read-inventory-query.v2', section: 'receipts', search: 'editor', offset: 0, limit: 50 }); for(const {url,init} of calls.filter(row=>row.url!=='/api/session')) { expect(url).toBe(`/api/devices/${macInventoryDeviceId}/macos-inventory/query`); expect(init?.method).toBe('POST'); expect(init?.credentials).toBe('same-origin'); expect(init?.headers).toMatchObject({'X-CSRF-Token':'synthetic-csrf','Content-Type':'application/json'}); }
 });
 it('rejects oversized response streams before accepting any private data', async () => {
  vi.stubGlobal('fetch',vi.fn(async(url:string)=>url==='/api/session'?response({csrfToken:'synthetic-csrf'}):new Response(' '.repeat(32769),{headers:{'Content-Type':'application/json'}}))); render(<MacInventoryWorkspace {...props}/>); await screen.findByRole('alert'); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
 it('does not send a page after current session changes during CSRF acquisition', async () => {
  let finish!:(value:Response)=>void; const fetcher=vi.fn(async()=>new Promise<Response>(resolve=>{finish=resolve;})); vi.stubGlobal('fetch',fetcher); render(<MacInventoryWorkspace {...props}/>); await waitFor(()=>expect(finish).toBeDefined()); abortProtectedRequests(); finish(response({csrfToken:'old-token'})); await screen.findByRole('alert'); expect(fetcher).toHaveBeenCalledTimes(1); expect(screen.queryByText('Mac14,12')).not.toBeInTheDocument();
 });
});
