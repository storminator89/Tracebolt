/** Synthetic manager metadata only; no host, browser or native acceptance evidence. */
import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { WINDOWS_MAINTENANCE_DOMAINS } from './windows-maintenance-types';
import type { WindowsMaintenanceDomain, WindowsMaintenanceTarget, WindowsMaintenanceView, WindowsMaintenanceWindow } from './windows-maintenance-types';

export function windowsMaintenanceWindow(patch: Partial<WindowsMaintenanceWindow> = {}): WindowsMaintenanceWindow {
    return { id: 1, startedAt: '2026-10-07T11:59:10Z', endsAt: '2026-10-07T12:29:10Z', endedAt: null, intent: 'planned-work', ...patch };
}
export function windowsMaintenanceTarget(domain: WindowsMaintenanceDomain, windows: WindowsMaintenanceWindow[] = [], patch: Partial<WindowsMaintenanceTarget> = {}): WindowsMaintenanceTarget {
    const latest = windows[0];
    return { key: (WINDOWS_MAINTENANCE_DOMAINS.indexOf(domain) + 1).toString(16).padStart(64, '0'), deviceId: windowsDeviceId, domain, revision: latest ? latest.id + (latest.endedAt === null ? 0 : 1) : 0, changedAt: latest ? latest.endedAt ?? latest.startedAt : null, windows, ...patch };
}
export function windowsMaintenanceView(targets: WindowsMaintenanceTarget[] = WINDOWS_MAINTENANCE_DOMAINS.map(domain => windowsMaintenanceTarget(domain)), patch: Partial<WindowsMaintenanceView> = {}): WindowsMaintenanceView {
    return { schemaVersion: 'tracebolt.windows-maintenance.v1', serverNow: windowsNow, authorityExpiresAt: '2026-10-07T12:30:00Z', targets, ...patch };
}
