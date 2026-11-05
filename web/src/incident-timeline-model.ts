import type { QueueRow } from './incident-work-queue-model';
import type { InvestigationsView } from './investigations-types';
import type { WindowsServiceHealthSource } from './windows-service-health-complete-types';
import { windowsInboxSourceStatus } from './windows-complete-incident-inbox-types';
import { validJournalUnit } from './journal-types';

export type IncidentLifecycle = 'open' | 'recovered' | 'stopped';
export type TimelineKind = 'opened' | 'linux-contact-evaluated' | 'last-observed' | 'last-confirmed' | 'bad-captured' | 'bad-received'
    | 'contact-received' | 'opening-captured' | 'opening-finished' | 'opening-received' | 'bad-finished'
    | 'recovery-captured' | 'recovery-finished' | 'recovery-received'
    | 'recovered' | 'reports-resumed' | 'policy-changed' | 'monitoring-stopped' | 'seen';
export interface TimelineCheckpoint { kind: TimelineKind; at: string }
export type TimelineSourceRole = 'opening' | 'last-bad' | 'recovery';
export interface TimelineSource { role: TimelineSourceRole; source: WindowsServiceHealthSource }
export type TimelineCurrentState = 'unknown' | 'not-monitored' | 'disabled' | 'pending' | 'attention' | 'within-policy' | 'recent' | 'running';
export interface IncidentTimelineModel {
    lifecycle: IncidentLifecycle; deviceId: string; incidentId: string; sourceKey: string; target: string;
    episode: TimelineCheckpoint[]; sources: TimelineSource[]; contact: 'linux' | 'windows' | null;
    current: { state: TimelineCurrentState; evaluatedAt: string | null; observedAt: string | null; validUntil: string | null; source: WindowsServiceHealthSource | null };
    healthHref: string; logsHref: string | null;
}

/** Shared presentation categories only. Administrative closure never earns recovery. */
export function incidentLifecycle(row: QueueRow): IncidentLifecycle {
    if (row.platform === 'linux') return row.item.incident.resolvedAt === null ? 'open' : row.item.incident.closedReason === 'recovered' ? 'recovered' : 'stopped';
    return row.item.resolvedAt === null ? 'open' : row.item.closedReason === 'policy-changed' ? 'stopped' : 'recovered';
}

// Validated source timestamps are UTC with at most nine fractional digits. Keep
// sub-millisecond ordering: Date.parse alone would reorder distinct checkpoints.
function timeKey(at: string): string { return at.slice(0, 19) + (at.match(/\.(\d+)Z$/)?.[1] ?? '').padEnd(9, '0'); }
function chronological(events: TimelineCheckpoint[]): TimelineCheckpoint[] {
    return events.map((event, index) => ({ event, index })).sort((a, b) => timeKey(a.event.at).localeCompare(timeKey(b.event.at)) || a.index - b.index).map(({ event }) => event);
}

/** Project validated, already-authorized source rows only. No storage, fetch,
 * analysis prose, inferred samples or incident mutation is part of a timeline.
 * Current checks are a separate context, never evidence of an old episode. */
export function incidentTimeline(row: QueueRow, linux: InvestigationsView | null, windowsNow: string | null, windowsAge: number): IncidentTimelineModel {
    const episode: TimelineCheckpoint[] = [], sources: TimelineSource[] = [];
    const add = (kind: TimelineKind, at: string | null) => { if (at !== null) episode.push({ kind, at }); };
    const deviceId = row.item.deviceId, healthHref = `#/devices/${encodeURIComponent(deviceId)}/health`;
    if (row.platform === 'linux') {
        const incident = row.item.incident, device = linux?.devices.find(value => value.deviceId === deviceId), check = device?.checks.find(value => value.key === incident.key);
        add('opened', incident.openedAt); add(incident.kind === 'offline' ? 'linux-contact-evaluated' : 'last-observed', incident.lastObservedAt);
        if (incident.resolvedAt) add(incident.closedReason === 'recovered' ? 'recovered' : 'monitoring-stopped', incident.resolvedAt);
        add('seen', incident.acknowledgedAt);
        const state: TimelineCurrentState = !device ? 'unknown' : !check ? 'not-monitored' : device.evaluatedAt === null || check.state === 'unknown' ? 'unknown' : check.state === 'open' ? 'attention' : check.state === 'ok' ? 'within-policy' : 'pending';
        return {
            lifecycle: incidentLifecycle(row), deviceId, incidentId: incident.id, sourceKey: incident.key, target: incident.target,
            episode: chronological(episode), sources, contact: incident.kind === 'offline' ? 'linux' : null,
            current: { state, evaluatedAt: device?.evaluatedAt ?? null, observedAt: check?.observedAt ?? null, validUntil: null, source: null },
            healthHref, logsHref: incident.kind === 'service' && validJournalUnit(incident.target) ? `#/devices/${encodeURIComponent(deviceId)}/logs/${encodeURIComponent(incident.target)}` : null,
        };
    }
    const item = row.item;
    add('opened', item.openedAt); add('last-confirmed', item.lastConfirmedAt);
    add('bad-captured', item.collectedAt); add(item.domain === 'contact' ? 'contact-received' : 'bad-received', item.receivedAt);
    add('recovery-captured', item.recoveryCollectedAt); add('recovery-received', item.recoveryReceivedAt);
    if (item.resolvedAt) add(item.closedReason === 'policy-changed' ? 'policy-changed' : item.closedReason === 'reports-resumed' ? 'reports-resumed' : 'recovered', item.resolvedAt);
    add('seen', item.acknowledgedAt);
    const status = windowsNow === null ? 'unknown' : windowsInboxSourceStatus(item, windowsNow, windowsAge);
    const state: TimelineCurrentState = status === 'pressure' || status === 'overdue' ? 'attention' : status;
    let currentSource: WindowsServiceHealthSource | null = null;
    if ('sourceKind' in item && item.sourceKind === 'windows_full_services') {
        sources.push({ role: 'opening', source: item.openingSource }, { role: 'last-bad', source: item.lastBadSource });
        add('opening-captured', item.openingSource.capturedAt); add('opening-finished', item.openingSource.captureFinishedAt); add('opening-received', item.openingSource.receivedAt);
        add('bad-finished', item.lastBadSource.captureFinishedAt);
        if (item.recoverySource) { sources.push({ role: 'recovery', source: item.recoverySource }); add('recovery-finished', item.recoverySource.captureFinishedAt); }
        // A retained reference cannot keep a current generation qualified after
        // its existing source deadline. Do not join it to historical bindings.
        if (status !== 'unknown' && status !== 'disabled') currentSource = item.currentSource;
    }
    return {
        lifecycle: incidentLifecycle(row), deviceId, incidentId: item.incidentId, sourceKey: item.key, target: item.serviceName || item.domain,
        episode: chronological(episode), sources, contact: item.domain === 'contact' ? 'windows' : null,
        current: { state, evaluatedAt: item.evaluatedAt, observedAt: currentSource?.capturedAt ?? null, validUntil: state === 'unknown' || state === 'disabled' ? null : item.statusValidUntil, source: currentSource },
        healthHref, logsHref: null,
    };
}
