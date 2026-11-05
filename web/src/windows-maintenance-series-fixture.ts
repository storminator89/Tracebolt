import { windowsMaintenanceView } from './windows-maintenance-fixture';
import { windowsNow } from './windows-inventory-fixture';
import type { WindowsMaintenanceSeriesView, WindowsMaintenanceSeriesReview } from './windows-maintenance-series-types';
export function windowsMaintenanceSeriesView():WindowsMaintenanceSeriesView {
    const legacy=windowsMaintenanceView();
    return {schemaVersion:'tracebolt.windows-maintenance-series.v1',serverNow:windowsNow,authorityExpiresAt:legacy.authorityExpiresAt,targets:legacy.targets.map(t=>({key:t.key,deviceId:t.deviceId,domain:t.domain,revision:t.revision,changedAt:t.changedAt,remainingSlots:16,retiredOccurrences:0,immediateActive:false,legacyReserved:false,occurrences:[]}))};
}
export function seriesReceipt(r:WindowsMaintenanceSeriesReview) {
    return {schemaVersion:'tracebolt.windows-maintenance-series-receipt.v1',operationId:r.operationId,key:r.key,action:r.action,revision:r.revision+1,occurrenceIds:r.action==='create'?r.occurrences.map((_,i)=>i+1):[r.occurrenceId],committedAt:windowsNow,expiresAt:'2026-10-08T12:00:10Z'};
}
