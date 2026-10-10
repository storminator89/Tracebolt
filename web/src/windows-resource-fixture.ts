/** Invented independent manager policies only; no endpoint or native data. */
import { windowsCapacityView } from './windows-capacity-fixture';
import type { WindowsCapacityStatus, WindowsResourceMetric, WindowsResourceView } from './windows-capacity-types';
export function windowsResourceView(metric: WindowsResourceMetric, status: WindowsCapacityStatus = 'disabled'): WindowsResourceView {
    return { ...windowsCapacityView(status), schemaVersion: 'tracebolt.windows-resource-view.v1', metric };
}
