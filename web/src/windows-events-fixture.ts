import type { WindowsEvents } from './windows-events-types';
import { windowsView } from './windows-inventory-fixture';
/** Invented headers only; never a native log read. */
export function windowsEventsFixture(): WindowsEvents {
    return { schemaVersion: 'tracebolt.windows-event-metadata.v1', scope: 'windows-application-system-event-headers-v1', grantId: 'e'.repeat(32), generationId: windowsView().snapshot!.generationId, collectedAt: '2026-10-07T12:00:02Z', channels: (['Application', 'System'] as const).map((channel, c) => ({ channel, quality: 'bounded', reason: '', complete: false, truncated: true, observedCount: 12, rows: Array.from({ length: 12 }, (_, i) => ({ recordId: `${18446744073709551615n - BigInt(i)}`, eventId: c * 100 + i, level: i % 7, provider: i % 2 ? 'Fixture Provider B' : 'Fixture Provider A', timestamp: `2026-10-06T10:${String(30 - i * 2 - c).padStart(2, '0')}:00Z` })) })) };
}
export function windowsEventsView() { return { ...windowsView(), events: windowsEventsFixture() }; }
