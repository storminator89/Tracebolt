import { windowsSection, windowsView } from './windows-inventory-fixture';
import { windowsServicesDigest, type WindowsServiceStartup, type WindowsServiceStartupRow } from './windows-service-startup-types';
import type { WindowsInventorySnapshot, WindowsInventoryView } from './windows-inventory-types';

const modes: Omit<WindowsServiceStartupRow, 'serviceIndex'>[] = [
    { startupMode: 'automatic', startupQuality: 'observed', delayedAutoStart: true, delayedAutoQuality: 'observed' },
    { startupMode: 'automatic', startupQuality: 'observed', delayedAutoStart: false, delayedAutoQuality: 'observed' },
    { startupMode: 'manual', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'not-applicable' },
    { startupMode: 'disabled', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'not-applicable' },
    { startupMode: null, startupQuality: 'denied', delayedAutoStart: null, delayedAutoQuality: 'denied' },
    { startupMode: null, startupQuality: 'unavailable', delayedAutoStart: null, delayedAutoQuality: 'unavailable' },
    { startupMode: null, startupQuality: 'unknown', delayedAutoStart: null, delayedAutoQuality: 'unknown' },
    { startupMode: 'automatic', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'denied' },
    { startupMode: 'automatic', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'unavailable' },
    { startupMode: 'automatic', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'unknown' },
];
export function windowsServiceStartup(snapshot: WindowsInventorySnapshot): WindowsServiceStartup {
    return { schemaVersion: 'tracebolt.windows-service-startup.v1', scope: 'windows-service-startup-v1', grantId: 'c'.repeat(32), generationId: snapshot.generationId, servicesSHA256: windowsServicesDigest(snapshot.services.rows), collectedAt: snapshot.collectedAt, requestedCount: snapshot.services.rows.length, truncated: false, rows: snapshot.services.rows.map((_, serviceIndex) => ({ serviceIndex, ...modes[serviceIndex % modes.length] })) };
}
export function windowsServiceStartupView(count = 10): WindowsInventoryView & { serviceStartup: WindowsServiceStartup } {
    const view = windowsView();
    view.snapshot!.services = windowsSection(Array.from({ length: count }, (_, i) => ({ name: `Service-${String(i + 1).padStart(3, '0')}`, displayName: `Synthetic display ${i + 1}`, state: i % 2 ? 'stopped' as const : 'running' as const, pid: i % 2 ? 0 : i + 1 })));
    return { ...view, serviceStartup: windowsServiceStartup(view.snapshot!) };
}
