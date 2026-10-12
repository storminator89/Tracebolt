import { windowsDeviceId, windowsNow } from './windows-inventory-fixture';
import { WINDOWS_NOTIFICATION_DOMAINS } from './windows-notifications-types';
import type { WindowsNotificationView } from './windows-notifications-types';
export function windowsNotificationView(): WindowsNotificationView {
    return { schemaVersion: 'tracebolt.windows-notifications.v1', serverNow: windowsNow, authorityExpiresAt: '2026-10-07T12:02:10Z', destinationHost: 'receiver.example.test', destinationBinding: 'a'.repeat(64), deliveryEnabled: true, targets: WINDOWS_NOTIFICATION_DOMAINS.map((domain, index) => ({ key: (index + 1).toString(16).padStart(64, '0'), deviceId: windowsDeviceId, domain, revision: 0, enabled: false, effective: false, changedAt: null, maintenanceUntil: null })), counts: { schemaVersion: 'tracebolt.alarm-status.v1', enabled: true, queued: 0, inFlight: 0, providerAccepted: 0, failed: 0, uncertain: 0, suppressed: 0, dropped: 0 } };
}
