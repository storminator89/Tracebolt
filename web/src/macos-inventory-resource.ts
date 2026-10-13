import { useCallback, useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw } from './api';
import { MAC_INVENTORY_PAGE_BYTES, MAC_INVENTORY_PAGE_ROWS, isMacLookupSection, normalizeMacInventorySearch, macInventoryVisible, sameMacInventoryGeneration, validMacDeviceId, validMacInventoryPage } from './macos-inventory-types';
import type { MacInventoryPage, MacInventoryQuery, MacInventorySection } from './macos-inventory-types';

type Failure = 'invalid' | 'unavailable' | 'session' | 'expired' | 'changed' | 'timeout' | 'clock';
type Anchor = { wall: number; mono: number };
const capture = (): Anchor => ({ wall: Date.now(), mono: performance.now() });
function elapsed(a: Anchor): number {
 const mono = performance.now() - a.mono, wall = Date.now() - a.wall;
 return Number.isFinite(mono) && mono >= 0 && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type State = { summary: MacInventoryPage | null; page: MacInventoryPage | null; error: Failure | null; draft: string; search: string; searchInvalid: boolean };
const empty = (): State => ({ summary: null, page: null, error: null, draft: '', search: '', searchInvalid: false });
type ReadOptions = { offset?: number; index?: number; deliberate?: boolean };
/** Private, bounded current page only. No persistence, global search or AI input.
 * Every page revalidates the original generation and current server authority.
 * UI refresh preserves the section and scroll container; access changes erase rows. */
export function useMacInventory(deviceId: string, enabled: boolean, sessionKey: string | null, identityKey: string, section: MacInventorySection) {
 const key = JSON.stringify([deviceId, enabled, sessionKey, identityKey]);
 const [state, setState] = useState<State & { key: string; section: MacInventorySection }>({ ...empty(), key, section }), [loading, setLoading] = useState(false), [age, setAge] = useState(0);
 const latest = useRef<State>(empty()), alive = useRef(false), locked = useRef(false), suspended = useRef(false), revision = useRef(0), anchor = useRef<Anchor | null>(null), generationChanged = useRef(false), serverFloor = useRef<{ time: number; anchor: Anchor } | null>(null);
 const selection = useRef(section), positions = useRef([0]), index = useRef(0), pending = useRef<{ controller: AbortController; timer: number } | null>(null);
 selection.current = section;
 const install = useCallback((value: State) => { latest.current = value; if (alive.current) setState({ ...value, key, section: selection.current }); }, [key]);
 const cancel = useCallback(() => { revision.current++; pending.current?.controller.abort(); window.clearTimeout(pending.current?.timer); pending.current = null; if (alive.current) setLoading(false); }, []);
 const clear = useCallback((error: Failure | null = null, forgetSearch = false) => { cancel(); anchor.current = null; positions.current = [0]; index.current = 0; install({ ...empty(), ...(!forgetSearch ? { draft: latest.current.draft, search: latest.current.search, searchInvalid: latest.current.searchInvalid } : {}), error }); }, [cancel, install]);
 const read = useCallback(async (options: ReadOptions = {}) => {
  if (generationChanged.current && !options.deliberate) return;
  if (!alive.current || !enabled || locked.current || suspended.current || document.visibilityState === 'hidden' || !validMacDeviceId(deviceId)) return;
  cancel(); const rev = revision.current, accessEpoch = getProtectedRequestEpoch(), controller = new AbortController(), started = capture(), selected = selection.current;
  const prior = latest.current.summary, search = latest.current.search;
  if (options.deliberate) { generationChanged.current = false; positions.current = [0]; index.current = 0; }
  setLoading(true);
  pending.current = { controller, timer: window.setTimeout(() => { if (revision.current === rev) clear('timeout'); }, 10000) };
  const current = () => alive.current && !controller.signal.aborted && revision.current === rev && accessEpoch === getProtectedRequestEpoch() && !locked.current && !suspended.current && selection.current === selected && latest.current.search === search;
  const query = async (input: MacInventoryQuery): Promise<MacInventoryPage> => {
   const value: unknown = await mutateRaw(`/devices/${encodeURIComponent(deviceId)}/macos-inventory/query`, JSON.stringify(input), {}, controller.signal, MAC_INVENTORY_PAGE_BYTES, current);
   if (!current()) throw new DOMException('Canceled', 'AbortError');
   if (!Number.isFinite(elapsed(started))) throw new Error('clock');
   if (!validMacInventoryPage(value, deviceId, input)) throw new Error('invalid');
   const previous = serverFloor.current, now = Date.parse(value.serverNow);
   if (previous && (now < previous.time || now + 1500 < previous.time + elapsed(previous.anchor))) throw new Error('clock');
   serverFloor.current = { time: now, anchor: capture() };
   if (!macInventoryVisible(value, elapsed(started))) throw new Error('expired');
   return value;
  };
  try {
   const summary = await query({ section: 'summary', generationId: '', offset: 0, limit: MAC_INVENTORY_PAGE_ROWS });
   if (!current()) return;
   if (summary.status !== 'fresh' && summary.status !== 'stale') {
    positions.current = [0]; index.current = 0; anchor.current = started; install({ ...empty(), summary }); setAge(elapsed(started)); return;
   }
   const same = prior && sameMacInventoryGeneration(prior, summary);
   if (!same && (options.offset !== undefined || prior && isMacLookupSection(selected)) && !options.deliberate) throw new Error('changed');
   const offset = options.deliberate ? 0 : same ? options.offset ?? positions.current[index.current] ?? 0 : 0;
   const input = { section: selected, generationId: summary.generationId, offset, limit: MAC_INVENTORY_PAGE_ROWS };
   const page = await query(isMacLookupSection(selected) ? { ...input, schemaVersion: 'tracebolt.macos-read-inventory-query.v2', section: selected, search } : input);
   if (!current()) return;
   if (!sameMacInventoryGeneration(summary, page) || page.status !== 'fresh' && page.status !== 'stale') throw new Error('changed');
   if (!same) { positions.current = [0]; index.current = 0; }
   if (options.index !== undefined) index.current = options.index;
   if (page.nextOffset !== null) positions.current[index.current + 1] = page.nextOffset;
   positions.current.length = index.current + (page.nextOffset === null ? 1 : 2);
   anchor.current = started; install({ ...latest.current, summary: { ...summary, serverNow: page.serverNow, authorityUntil: page.authorityUntil, status: page.status }, page, error: null }); setAge(elapsed(started));
  } catch (error) {
   if (!current()) return;
   if (error instanceof APIError && error.status === 401) { locked.current = true; clear('session', true); }
   else {
    const failure = error instanceof APIError ? error.status === 409 ? 'changed' : error.status === 410 ? 'expired' : 'unavailable' : error instanceof Error && ['invalid', 'clock', 'expired', 'changed'].includes(error.message) ? error.message as Failure : 'unavailable';
    if (failure === 'changed') generationChanged.current = true;
    clear(failure, failure === 'expired' || failure === 'clock' || error instanceof APIError && (error.status === 403 || error.status === 404));
   }
  } finally {
   if (revision.current === rev) { window.clearTimeout(pending.current?.timer); pending.current = null; if (alive.current) setLoading(false); }
  }
 }, [cancel, clear, deviceId, enabled, install]);
 useEffect(() => {
  alive.current = true; locked.current = false; suspended.current = document.visibilityState === 'hidden'; serverFloor.current = null; generationChanged.current = false; clear(null, true);
  const accessEpoch = getProtectedRequestEpoch();
  const lock = () => { locked.current = true; clear('session', true); };
  const suspend = () => { suspended.current = true; generationChanged.current = false; clear(null, true); };
  const restore = () => { if (locked.current || !suspended.current || document.visibilityState === 'hidden') return; suspended.current = false; void read(); };
  const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
  const timer = window.setInterval(() => {
   if (accessEpoch !== getProtectedRequestEpoch()) { lock(); return; }
   const value = latest.current.summary;
   if (!anchor.current || !value) return;
   const duration = elapsed(anchor.current);
   if (!Number.isFinite(duration)) { clear('clock', true); return; }
   if (!macInventoryVisible(value, duration)) { clear('expired', true); return; }
   setAge(duration);
  }, 250);
  // Read-only revalidation catches terminal local disable/current-grant changes.
  const refresh = window.setInterval(() => { if (!pending.current) void read(); }, 15000);
  window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', suspend); window.addEventListener('blur', suspend); window.addEventListener('pageshow', restore); window.addEventListener('focus', restore); document.addEventListener('visibilitychange', visibility);
  void read();
  return () => { alive.current = false; clear(null, true); window.clearInterval(timer); window.clearInterval(refresh); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', suspend); window.removeEventListener('blur', suspend); window.removeEventListener('pageshow', restore); window.removeEventListener('focus', restore); document.removeEventListener('visibilitychange', visibility); };
 }, [key, enabled, clear, read]);
 const previousSection = useRef(section);
 useEffect(() => { if (previousSection.current === section) return; previousSection.current = section; generationChanged.current = false; clear(null, true); void read(); }, [section, clear, read]);
 const admitted = enabled && state.key === key && state.section === section;
 const page = admitted && state.page?.section === section ? state.page : null;
 return { ...(admitted ? state : empty()), page, loading: enabled && loading, age,
  setDraft: (draft: string) => { if (admitted && !locked.current && !suspended.current) install({ ...latest.current, draft, searchInvalid: false }); },
  applySearch: (value = latest.current.draft) => {
   if (!admitted || !isMacLookupSection(section) || locked.current || suspended.current) return;
   const search = normalizeMacInventorySearch(value);
   if (search === null) { install({ ...latest.current, searchInvalid: true }); return; }
   // Cancel before changing the pin; late rows from either stage cannot return.
   clear(); install({ ...latest.current, draft: search, search, searchInvalid: false }); void read({ deliberate: true });
  },
  refresh: () => { if (isMacLookupSection(section)) { clear(); void read({ deliberate: true }); } else { generationChanged.current = false; void read(); } }, previous: () => { if (index.current > 0) void read({ offset: positions.current[index.current - 1], index: index.current - 1 }); },
  next: () => { if (page?.nextOffset !== null && page?.nextOffset !== undefined) void read({ offset: page.nextOffset, index: index.current + 1 }); },
 };
}
