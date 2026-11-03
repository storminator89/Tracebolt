import type { InvestigationItem, InvestigationsView } from './investigations-types';
import type { WindowsInboxItem, WindowsInboxView } from './windows-complete-incident-inbox-types';
import { incidentLifecycle } from './incident-timeline-model';
import type { IncidentLifecycle } from './incident-timeline-model';

export type QueuePlatform = 'all' | 'linux' | 'windows';
export type QueueSource = 'all' | 'linux-health' | 'windows-assessment' | 'windows-full-services';
export type QueueSeen = 'all' | 'seen' | 'unseen';
export type QueueScope = 'active' | 'all';
export type QueueLifecycle = 'all' | IncidentLifecycle;
export const QUEUE_SEARCH_LIMIT = 160;
export type QueueRow =
    | { identity: string; platform: 'linux'; source: 'linux-health'; openedAt: string; seenAt: string | null; item: InvestigationItem }
    | { identity: string; platform: 'windows'; source: 'windows-assessment' | 'windows-full-services'; openedAt: string; seenAt: string | null; item: WindowsInboxItem };

/** The lifecycle contracts differ. Only these two scopes have an exact mapping. */
export function queueSourceScopes(scope: QueueScope) {
    return { linux: scope === 'active' ? 'open' as const : 'all' as const, windows: scope };
}

/** Merge bounded current source pages. Never join by device name or local
 * incident ID, and never turn this page view into a global filtered total. */
export function incidentQueueRows(linux: InvestigationsView | null, windows: WindowsInboxView | null): QueueRow[] {
    const rows: QueueRow[] = [];
    for (const item of linux?.items ?? []) rows.push({ identity: JSON.stringify(['linux-health', item.deviceId, item.incident.id, item.incident.key, item.incident.openedAt]), platform: 'linux', source: 'linux-health', openedAt: item.incident.openedAt, seenAt: item.incident.acknowledgedAt, item });
    for (const item of windows?.items ?? []) {
        const complete = 'sourceKind' in item && item.sourceKind === 'windows_full_services';
        const source = complete ? 'windows-full-services' : 'windows-assessment';
        rows.push({ identity: JSON.stringify(['windows', source, item.domain, item.key]), platform: 'windows', source, openedAt: item.openedAt, seenAt: item.acknowledgedAt, item });
    }
    return rows.sort((a, b) => Date.parse(b.openedAt) - Date.parse(a.openedAt) || a.identity.localeCompare(b.identity));
}

/** Search only explicit identity/name/target fields from the loaded source pages.
 * Never search model prose or log content, and never compile user input as a pattern. */
export function filterIncidentQueue(rows: QueueRow[], platform: QueuePlatform, source: QueueSource, seen: QueueSeen, lifecycle: QueueLifecycle = 'all', query = '', names: ReadonlyMap<string, string> = new Map()) {
    const search = query.slice(0, QUEUE_SEARCH_LIMIT).trim().toLowerCase();
    return rows.filter(row => {
        if ((platform !== 'all' && row.platform !== platform) || (source !== 'all' && row.source !== source) || (seen !== 'all' && (seen === 'seen') !== (row.seenAt !== null)) || (lifecycle !== 'all' && incidentLifecycle(row) !== lifecycle)) return false;
        if (!search) return true;
        const fields = row.platform === 'linux' ? [row.item.incident.id, row.item.incident.key, row.item.incident.target, row.item.incident.kind] : [row.item.incidentId, row.item.key, row.item.serviceName, row.item.domain];
        return [row.item.deviceId, names.get(`${row.platform}:${row.item.deviceId}`) ?? '', row.platform, row.source, ...fields].some(value => value.toLowerCase().includes(search));
    });
}

/** Page-local categories, not new source totals or lifecycle state. */
export function incidentQueueLifecycleCounts(rows: QueueRow[]): Record<IncidentLifecycle, number> {
    const counts = { open: 0, recovered: 0, stopped: 0 };
    for (const row of rows) counts[incidentLifecycle(row)]++;
    return counts;
}
