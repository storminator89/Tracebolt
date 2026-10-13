/** Synthetic adapters use the Go-generated closed health DTO and the existing
 * Go-generated complete-service generation. No host data or collection occurs. */
import wire from './windows-complete-service-health-go-fixture.json';
import { fullServiceRows, fullServicesComplete, fullServicesDevice, fullServicesNow, fullServicesPage } from './windows-full-services-fixtures';
import { completeServiceHealthSource } from './windows-service-health-complete-types';
import type { WindowsServiceHealthCompletePolicy, WindowsServiceHealthCompleteView } from './windows-service-health-complete-types';
export const completeHealthSession = '2026-10-11T07:00:00Z';
export function completeHealthView(policy: WindowsServiceHealthCompletePolicy = { enabled: false, services: [], revision: 0 }): WindowsServiceHealthCompleteView {
    const view = structuredClone(wire.disabled) as WindowsServiceHealthCompleteView, complete = fullServicesComplete(), source = completeServiceHealthSource(complete), rows = fullServiceRows();
    view.deviceId = fullServicesDevice; view.serverNow = fullServicesNow; view.certificateExpiresAt = fullServicesPage().authorityUntil!; view.policy = structuredClone(policy); view.status = policy.enabled ? 'unknown' : 'disabled';
    view.checks = policy.services.map(name => ({ name, status: 'unknown', observation: null }));
    view.inventory = { ...view.inventory!, collectedAt: source.capturedAt, receivedAt: source.receivedAt, sequence: source.sequence, observedCount: source.rowCount, source, services: rows.filter(row => policy.services.includes(row.name)).map(row => ({ name: row.name, displayName: row.displayName ?? '', state: row.state ?? 'unknown' })) };
    return view;
}
