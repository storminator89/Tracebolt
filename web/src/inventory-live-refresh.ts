import { inventoryAge } from './complete-packages-types';

/** Local scheduling only; it never captures telemetry or owns an API request. */
export class InventoryPollClock {
    private dueAt = Infinity;
    private failures = 0;
    private stopped = false;
    begin() { this.dueAt = Infinity; this.stopped = false; }
    finish(failed = false) {
        this.failures = failed ? Math.min(this.failures + 1, 3) : 0;
        this.dueAt = performance.now() + Math.min(120000, 15000 * 2 ** this.failures);
    }
    stop() { this.dueAt = Infinity; this.stopped = true; }
    due() { return performance.now() >= this.dueAt; }
    state(paused: boolean): 'active' | 'paused' | 'retrying' {
        return paused || this.stopped ? 'paused' : this.failures ? 'retrying' : 'active';
    }
}

/** Compare only already-validated generation evidence, independent of JSON key order. */
function sameEvidence(a: unknown, b: unknown): boolean {
    if (a === b) return true;
    if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
    const left = a as Record<string, unknown>, right = b as Record<string, unknown>;
    const keys = Object.keys(left);
    return keys.length === Object.keys(right).length && keys.every(key => Object.hasOwn(right, key) && sameEvidence(left[key], right[key]));
}
export function inventoryGenerationChange(previous: { id: string; sequence: string; evidence: unknown } | null, next: { id: string; sequence: string; evidence: unknown }): 'same' | 'new' | 'invalid' {
    if (!previous) return 'new';
    if (previous.id === next.id) return previous.sequence === next.sequence && sameEvidence(previous.evidence, next.evidence) ? 'same' : 'invalid';
    return BigInt(next.sequence) > BigInt(previous.sequence) ? 'new' : 'invalid';
}

/** Replayed or slowly advancing server clocks cannot make retained observations younger. */
export function preserveInventoryAge(previous: { mono: number; wall: number } | null, previousServerNow: string | undefined, serverNow: string, started: { mono: number; wall: number }) {
    if (!previous || !previousServerNow) return started;
    const floor = Math.max(0, started.mono - previous.mono - inventoryAge(serverNow, previousServerNow));
    return { mono: started.mono - floor, wall: started.wall - floor };
}
