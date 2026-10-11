import { windowsView } from './windows-inventory-fixture';
import type { WindowsResourceContext } from './windows-resource-context-types';
export function windowsResourceContext(): WindowsResourceContext {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-resource-context.v1', scope: 'windows-resource-context-v1', grantId: 'b'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        processors: { quality: 'observed', reason: '', source: 'Win32_Processor', rows: [{ name: { value: 'Fixture CPU 12-Core', quality: 'observed' }, architecture: { value: 'x64', quality: 'observed' }, cores: { value: 12, quality: 'observed' }, logicalProcessors: { value: 24, quality: 'observed' } }], totalCores: 12, totalLogicalProcessors: 24 },
        installedMemory: { quality: 'observed', reason: '', source: 'GetPhysicallyInstalledSystemMemory', installedBytes: '34359738368' },
        memory: { quality: 'observed', reason: '', source: 'K32GetPerformanceInfo', commitTotalBytes: '12884901888', commitLimitBytes: '42949672960', physicalTotalBytes: '33285996544', physicalAvailableBytes: '16106127360', pageSizeBytes: '4096' },
        pagefiles: { quality: 'observed', reason: '', source: 'EnumPageFilesW', count: 1, totalBytes: '10737418240', totalInUseBytes: '1073741824' },
    };
}
export const windowsResourceContextView = () => ({ ...windowsView(), resourceContext: windowsResourceContext() });
export function unavailableWindowsResourceContext(): WindowsResourceContext {
    const v = windowsResourceContext();
    for (const source of Object.values(v).filter(value => value && typeof value === 'object')) { source.quality = 'unavailable'; source.reason = 'windows_resource_context_budget_exhausted'; }
    v.processors.rows = []; v.processors.totalCores = v.processors.totalLogicalProcessors = null;
    v.installedMemory.installedBytes = null;
    Object.assign(v.memory, { commitTotalBytes: null, commitLimitBytes: null, physicalTotalBytes: null, physicalAvailableBytes: null, pageSizeBytes: null });
    Object.assign(v.pagefiles, { count: null, totalBytes: null, totalInUseBytes: null });
    return v;
}
