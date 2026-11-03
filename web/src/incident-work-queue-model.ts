import type { InvestigationItem, InvestigationsView } from './investigations-types';
import type { WindowsInboxItem, WindowsInboxView } from './windows-complete-incident-inbox-types';

export type QueuePlatform = 'all' | 'linux' | 'windows';
export type QueueSource = 'all' | 'linux-health' | 'windows-assessment' | 'windows-full-services';
export type QueueSeen = 'all' | 'seen' | 'unseen';
export type QueueScope = 'active' | 'all';
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

export function filterIncidentQueue(rows: QueueRow[], platform: QueuePlatform, source: QueueSource, seen: QueueSeen) {
    return rows.filter(row => (platform === 'all' || row.platform === platform) && (source === 'all' || row.source === source) && (seen === 'all' || (seen === 'seen') === (row.seenAt !== null)));
}
