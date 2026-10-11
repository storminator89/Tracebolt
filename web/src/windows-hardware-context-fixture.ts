import { windowsView } from './windows-inventory-fixture';
import type { WindowsHardwareContext } from './windows-hardware-context-types';
export function windowsHardwareContext(): WindowsHardwareContext {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-hardware-context.v1', scope: 'windows-hardware-context-v1', grantId: '6'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        system: { quality: 'observed', reason: '', manufacturer: { value: 'Fixture Devices', quality: 'observed' }, model: { value: 'Example Laptop 14', quality: 'observed' } },
        firmware: { quality: 'partial', reason: 'windows_hardware_context_partial_result', source: 'Win32_BIOS', vendor: { value: 'Fixture Firmware', quality: 'observed' }, version: { value: 'F.42', quality: 'observed' }, releaseDate: { value: '20260815000000.000000+000', quality: 'observed' }, serialNumber: { value: null, quality: 'denied' } },
        chassis: { quality: 'observed', reason: '', source: 'Win32_SystemEnclosure', serialNumber: { value: 'FIXTURE-CHASSIS-0042', quality: 'observed' } },
        power: { quality: 'observed', reason: '', source: 'GetSystemPowerStatus', acLineStatus: 'online', batteryPresence: 'present', charging: 'yes', batteryPercent: 74, estimatedSeconds: null },
    };
}
export const windowsHardwareContextView = () => ({ ...windowsView(), hardwareContext: windowsHardwareContext() });
