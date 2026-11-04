import { useEffect, useRef, useState } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutate, request } from './api';
import { hasLogoutIntent } from './auth';
import { MOUNT_BYTES, mountBody, mountConfirmed, validMountView } from './linux-mount-watch-types';
import type { MountCommand, MountView } from './linux-mount-watch-types';
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
const elapsed = (a: Anchor) => { const m = performance.now() - a.mono, w = Date.now() - a.wall; return m >= 0 && w >= 0 && Math.abs(m - w) <= 1500 ? Math.max(m, w) : Infinity; };
// A wall-clock adjustment cannot erase positive monotonic elapsed age. A reset
// or unavailable monotonic clock falls back to nonnegative wall elapsed.
const elapsedLowerBound = (a: Anchor) => { const mono = performance.now() - a.mono, wall = Date.now() - a.wall; return Number.isFinite(mono) && mono >= 0 ? mono : Number.isFinite(wall) && wall >= 0 ? wall : Infinity; };
let retainedEpoch = -1;
const uncertain = new Map<string, MountCommand>();
const superseded = new Set<string>();
const clocks = new Map<string, { server: number; latestServer: number; anchor: Anchor; revision: bigint }>();
const empty = { refresh: () => {}, change: async (_c: MountCommand) => false };
export function useMountWatch(deviceId: string, sessionKey: string | null, enabled: boolean) {
 const key = JSON.stringify([deviceId, sessionKey]);
 const [supersededAttempt, setSupersededAttempt] = useState(false);
 const [snapshot, setSnapshot] = useState<{ key: string; view: MountView } | null>(null), [pending, setPending] = useState(false), [error, setError] = useState<string | null>(null), [attempt, setAttempt] = useState<MountCommand | null>(null);
 const actions = useRef(empty);
 useEffect(() => {
  const epoch = getProtectedRequestEpoch(); if (retainedEpoch !== epoch) { uncertain.clear(); clocks.clear(); superseded.clear(); retainedEpoch = epoch; }
  let alive = true, locked = false, suspended = document.visibilityState === 'hidden', serial = 0, accepted: MountView | null = null;
  let operation: { controller: AbortController; timer: number } | null = null;
  const validScope = () => alive && !locked && !suspended && !hasLogoutIntent() && epoch === getProtectedRequestEpoch() && document.visibilityState !== 'hidden';
  const currentTime = () => { const a = clocks.get(key); return a ? a.server + elapsed(a.anchor) : Infinity; };
  const activeView = () => accepted !== null && currentTime() < Date.parse(accepted.expiresAt) && (sessionKey === null || currentTime() < Date.parse(sessionKey));
  const clear = (message: string | null) => { serial++; operation?.controller.abort(); window.clearTimeout(operation?.timer); operation = null; accepted = null; if (alive) { setSnapshot(null); setPending(false); setError(message); } };
  const run = async (command?: MountCommand) => {
   if (!validScope() || operation || command && (!activeView() || !accepted?.canManage || uncertain.has(key) || command.expectedRevision !== accepted.revision || command.sourceToken !== accepted.sourceToken)) return false;
   if (!enabled || !/^agent_[a-f0-9]{32}$/.test(deviceId)) return false;
   if (command && uncertain.size >= 128 || !clocks.has(key) && clocks.size >= 128) { clear('unavailable'); return false; }
   if (command) { uncertain.set(key, command); setAttempt(command); }
   const controller = new AbortController(), started = capture(), version = ++serial;
   accepted = null; setSnapshot(null); setPending(true); setError(null);
   operation = { controller, timer: window.setTimeout(() => { if (version === serial) clear(command ? 'uncertain' : 'unavailable'); }, command ? 15000 : 10000) };
   let diagnostic: string | null = null;
   try {
    const path = `/devices/${encodeURIComponent(deviceId)}/mount-watch`;
    const value = command ? await mutate<unknown>(path, mountBody(command), controller.signal) : await request<unknown>(path, { signal: controller.signal }, MOUNT_BYTES);
    if (!validScope() || version !== serial || controller.signal.aborted) return false;
    if (!validMountView(value, deviceId)) throw new Error('Invalid mount watch');
    // Preserve the read-only reason even when existing clock/revision floors
    // reject the response. Never accept its evidence or relax those floors.
    if (!value.canManage && (value.sourceStatus === 'identity_changed' || value.sourceStatus === 'clock_uncertain')) diagnostic = value.sourceStatus;
    const server = Date.parse(value.serverNow), prior = clocks.get(key), requestAge = elapsed(started);
    if (!Number.isFinite(requestAge) || prior && (server < prior.latestServer || BigInt(value.revision) < prior.revision)) throw new Error('Clock or revision regression');
    const retainedAge = prior ? elapsed(prior.anchor) : 0;
    // A clock discontinuity removes display confidence. Only a new GET with
    // strictly advancing manager time can re-anchor; old revision/server floors
    // and each observation's original expiry remain unchanged.
    if (!Number.isFinite(retainedAge) && (command || !prior || server <= prior.latestServer)) throw new Error('Fresh manager time required');
    const bound = prior ? Number.isFinite(retainedAge) ? retainedAge : elapsedLowerBound(prior.anchor) : 0;
    if (!Number.isFinite(bound)) throw new Error('Clock remains unavailable');
    const floor = prior ? prior.server + bound : server;
    const now = Math.max(server + requestAge, floor); clocks.set(key, { server: now, latestServer: server, anchor: capture(), revision: BigInt(value.revision) });
    if (now >= Date.parse(value.expiresAt) || sessionKey !== null && now >= Date.parse(sessionKey)) throw new Error('Expired');
    const old = uncertain.get(key); if (old && mountConfirmed(value, old)) uncertain.delete(key); else if (old && !command && BigInt(value.revision) > BigInt(old.expectedRevision)) { uncertain.delete(key); superseded.add(key); setSupersededAttempt(true); }
    if (command && !mountConfirmed(value, command)) throw new Error('Unconfirmed write');
    accepted = value; setSnapshot({ key, view: value }); setAttempt(uncertain.get(key) ?? null); return true;
   } catch (e) {
    if (validScope() && version === serial) { if (command && e instanceof APIError && [400, 403, 409].includes(e.status ?? 0)) { uncertain.delete(key); setAttempt(null); }
     if (e instanceof APIError && e.status === 401) { locked = true; clear('session'); } else clear(uncertain.has(key) ? 'uncertain' : diagnostic ?? 'unavailable'); }
    return false;
   } finally { if (alive && version === serial) { window.clearTimeout(operation?.timer); operation = null; setPending(false); } }
  };
  const end = () => { locked = true; clear('session'); }, suspend = () => { suspended = true; clear('interrupted'); }, resume = () => { if (!locked) suspended = document.visibilityState === 'hidden'; }, visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
  actions.current = { refresh: () => { void run(); }, change: run }; setAttempt(uncertain.get(key) ?? null); setSupersededAttempt(superseded.has(key)); clear(null);
  if (enabled) { window.addEventListener(AUTH_REQUIRED_EVENT, end); window.addEventListener('blur', suspend); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', end); window.addEventListener('popstate', end); window.addEventListener('focus', resume); document.addEventListener('visibilitychange', visibility); void run(); }
  const timer = window.setInterval(() => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) end(); else if (accepted && !activeView()) clear('expired'); }, 1000);
  return () => { alive = false; clear(null); window.clearInterval(timer); actions.current = empty; window.removeEventListener(AUTH_REQUIRED_EVENT, end); window.removeEventListener('blur', suspend); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', end); window.removeEventListener('popstate', end); window.removeEventListener('focus', resume); document.removeEventListener('visibilitychange', visibility); };
 }, [key, deviceId, sessionKey, enabled]);
 return { view: snapshot?.key === key ? snapshot.view : null, pending, error, attempt, supersededAttempt, refresh: () => actions.current.refresh(), change: (c: MountCommand) => actions.current.change(c) };
}
