import type { QueueRow } from './incident-work-queue-model';
import type { InvestigationsView } from './investigations-types';
import { incidentTimeline } from './incident-timeline-model';

export type QueueCurrentCheck = 'all' | 'unknown' | 'attention' | 'pending' | 'inactive';

/** Filter only the already-loaded episodes by their existing, separately aged
 * current-check projection. Never infer recovery or create rows for lost sources. */
export function filterQueueCurrentCheck(rows: QueueRow[], filter: QueueCurrentCheck, linux: InvestigationsView | null, windowsNow: string | null, windowsAge: number): QueueRow[] {
    if (filter === 'all') return rows;
    return rows.filter(row => {
        const state = incidentTimeline(row, linux, windowsNow, windowsAge).current.state;
        return filter === 'inactive' ? state === 'disabled' || state === 'not-monitored' : state === filter;
    });
}
