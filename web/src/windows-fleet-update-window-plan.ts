import { updateID } from './windows-update-jobs-types';
import type { UpdateScheduleWindow } from './windows-update-jobs';

export type FleetUpdateWindowPlan = Readonly<{
    entries: readonly Readonly<{ deviceId: string; wave: number; window: UpdateScheduleWindow }>[];
    waveCount: number;
}>;

/** Pure local planning. Windows limit dispatch, not completion or concurrency.
 * Every target still needs its independent exact readiness and approval. */
export function planFleetUpdateWindows(ids: readonly string[], first: UpdateScheduleWindow | null, perWave: string, gapMinutes: string, now: number): FleetUpdateWindowPlan | null {
    if (!first || !Number.isFinite(now) || now < 0 || !ids.length || ids.length > 50 || new Set(ids).size !== ids.length || ids.some(id => !updateID(id, 'agent_'))) return null;
    if (!/^[1-9][0-9]*$/.test(perWave) || !/^(0|[1-9][0-9]*)$/.test(gapMinutes)) return null;
    const size = Number(perWave), gap = Number(gapMinutes), duration = first.endAt - first.startAt;
    if (!Number.isSafeInteger(size) || size > 50 || !Number.isSafeInteger(gap) || gap > 1440 || !Number.isSafeInteger(first.startAt) || !Number.isSafeInteger(first.endAt) || duration < 60 || duration > 3600) return null;
    const entries = ids.map((deviceId, index) => {
        const wave = Math.floor(index / size), startAt = first.startAt + wave * (duration + gap * 60), endAt = startAt + duration;
        return Object.freeze({ deviceId, wave: wave + 1, window: Object.freeze({ startAt, endAt }) });
    });
    if (entries.some(({ window }) => !Number.isSafeInteger(window.endAt) || window.endAt > 253402300799 || window.startAt <= now || window.startAt - now > 86400)) return null;
    return Object.freeze({ entries: Object.freeze(entries), waveCount: entries.at(-1)!.wave });
}
