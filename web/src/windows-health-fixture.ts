import { windowsDevice } from './windows-inventory-fixture';
import type { Device } from './types';

/** Invented manager-projected DTO, not a grant. Production Devices appends this
 * capability for an activated identity; the bare inventory fixture omits it. */
export function windowsHealthDevice(authority: 'activated' | 'missing-identity' = 'activated'): Device {
    const device: Device = { ...windowsDevice(), status: 'unknown' };
    return authority === 'missing-identity' ? device : { ...device, capabilities: [{ id: 'agent_identity', name: 'Enrolled agent identity', status: 'supported', detail: 'Synthetic activated identity fixture; no native enrollment or permission change' }] };
}
