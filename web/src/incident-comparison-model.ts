import type { InvestigationsView } from './investigations-types';
import type { QueueRow } from './incident-work-queue-model';
import { incidentTimeline } from './incident-timeline-model';
import type { IncidentTimelineModel, TimelineCheckpoint } from './incident-timeline-model';

export const MAX_COMPARISON_EPISODES = 4;
export interface ComparisonEpisode {
    identity: string; platform: QueueRow['platform']; source: QueueRow['source'];
    model: IncidentTimelineModel; readAt: string | null;
}
export interface ComparisonCheckpoint extends TimelineCheckpoint { identity: string; episodeIndex: number }

/** Retain identities only while the exact episode is still visible. Never
 * cache a private row, join domains by a local ID, or silently replace a choice. */
export function comparisonSelection(selected: readonly string[], rows: readonly QueueRow[]): string[] {
    const available = new Set(rows.map(row => row.identity));
    return [...new Set(selected)].filter(identity => available.has(identity)).slice(0, MAX_COMPARISON_EPISODES);
}

export function toggleComparison(selected: readonly string[], rows: readonly QueueRow[], identity: string): string[] {
    const current = comparisonSelection(selected, rows);
    if (current.includes(identity)) return current.filter(value => value !== identity);
    return rows.some(row => row.identity === identity) && current.length < MAX_COMPARISON_EPISODES ? [...current, identity] : current;
}

/** Read the same live, already-authorized pages as the queue. The comparison
 * is not a pinned snapshot and does not infer correlation or common cause. */
export function comparisonEpisodes(selected: readonly string[], rows: readonly QueueRow[], linux: InvestigationsView | null, windowsNow: string | null, windowsAge: number): ComparisonEpisode[] {
    const byIdentity = new Map(rows.map(row => [row.identity, row]));
    return comparisonSelection(selected, rows).map(identity => {
        const row = byIdentity.get(identity)!;
        return { identity, platform: row.platform, source: row.source, model: incidentTimeline(row, linux, windowsNow, windowsAge), readAt: row.platform === 'linux' ? linux?.serverNow ?? null : windowsNow };
    });
}

/** Preserve nanosecond UTC ordering and every equal-time checkpoint. Source
 * clocks are not proven synchronized, so ordering is presentation only. */
export function comparisonCheckpoints(episodes: readonly ComparisonEpisode[]): ComparisonCheckpoint[] {
    const key = (at: string) => at.slice(0, 19) + (at.match(/\.(\d+)Z$/)?.[1] ?? '').padEnd(9, '0');
    return episodes.flatMap((episode, episodeIndex) => episode.model.episode.map((checkpoint, checkpointIndex) => ({ ...checkpoint, identity: episode.identity, episodeIndex, checkpointIndex })))
        .sort((a, b) => key(a.at).localeCompare(key(b.at)) || a.episodeIndex - b.episodeIndex || a.checkpointIndex - b.checkpointIndex)
        .map(({ checkpointIndex: _index, ...checkpoint }) => checkpoint);
}
