import { getProtectedRequestEpoch } from './api';
import { inventoryAge } from './complete-packages-types';

type Anchor = { mono: number; wall: number };
type Clock = { anchor: Anchor; elapsed: number; server: string };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
// Timing only: never retain a receipt, metric, private row or access decision.
const clocks = new Map<string, Clock>();
let clockEpoch = -1;
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
export function acceptWindowsContactClock(key: string, epoch: number, server: string, requestAge: number): boolean {
    if (epoch !== getProtectedRequestEpoch()) return false;
    if (clockEpoch !== epoch) { clocks.clear(); clockEpoch = epoch; }
    const previous = clocks.get(key), anchor = capture();
    if (!Number.isFinite(Date.parse(server)) || !Number.isFinite(requestAge) || requestAge < 0 || previous && inventoryAge(server, previous.server) < 0 || !previous && clocks.size >= 128) return false;
    // Across a remount/blur reject clock divergence and retain the elapsed lower bound. Never
    // evict a live key to make room: capacity exhaustion must withhold readings.
    const gap = previous ? elapsed(previous.anchor) : 0;
    if (!Number.isFinite(gap)) return false;
    // Keep raw manager time plus a relative offset: absolute Date.parse numbers
    // would lose sub-millisecond rollback and strict age-boundary precision.
    clocks.set(key, { anchor, elapsed: Math.max(requestAge, previous ? inventoryAge(previous.server, server) + previous.elapsed + gap : 0), server });
    return true;
}
export function windowsContactElapsed(key: string, epoch: number, server: string, requestAge: number): number {
    const clock = epoch === getProtectedRequestEpoch() && clockEpoch === epoch ? clocks.get(key) : undefined;
    return clock && Number.isFinite(requestAge) && requestAge >= 0 ? Math.max(requestAge, inventoryAge(clock.server, server) + clock.elapsed + elapsed(clock.anchor)) : Infinity;
}
