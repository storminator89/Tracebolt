import { windowsNotificationView } from './windows-notifications-fixture';
import type { WindowsCompleteNotificationView } from './windows-complete-notifications-types';
export function windowsCompleteNotificationView(): WindowsCompleteNotificationView {
    const preview = windowsNotificationView();
    return { ...preview, schemaVersion: 'tracebolt.windows-complete-notifications.v1', targets: [{ key: 'c'.repeat(64), deviceId: preview.targets[0].deviceId, domain: 'service-complete', revision: 0, enabled: false, effective: false, changedAt: null, maintenanceUntil: null, healthPolicyRevision: 1, grantId: 'b'.repeat(32), grantRevision: 1, services: ['Exact Complete Service', 'Service beyond preview 2049'], actionable: true }] };
}
