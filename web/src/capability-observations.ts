import type { Capability, Device } from './types';
import type { SystemView, SystemSection } from './system-inventory-types';
import type { OverviewView, OverviewSection } from './complete-overview-types';
import type { CompletePackageView } from './complete-packages-types';
import type { JournalView } from './journal-types';
import { inventoryAge } from './complete-packages-types';

export type CapabilityState = 'supported' | 'available' | 'scope' | 'unsupported' | 'denied' | 'failed' | 'not_configured' | 'stale' | 'unknown' | 'pending' | 'partial' | 'configured';
export interface CapabilityObservation { state: CapabilityState; at?: string; reason?: string }
export const capabilityFailure = (reason: string): CapabilityObservation => ({ state: reason === 'permission_denied' ? 'denied' : reason === 'not_supported' ? 'unsupported' : reason === 'not_collected' ? 'unknown' : 'failed', reason });
const age = (now: string, at: string, elapsed: number) => inventoryAge(now, at) + elapsed;
const fresh = (now: string, at: string, elapsed: number, limit: number) => Number.isFinite(elapsed) && elapsed >= 0 && age(now, at, elapsed) >= 0 && age(now, at, elapsed) <= limit;

export function systemCapability(view: SystemView, section: SystemSection, elapsed: number): CapabilityObservation {
    if (view.status === 'not_configured') return { state: 'not_configured' };
    if (view.status === 'revoked') return { state: 'denied', reason: 'revoked' };
    if (view.status === 'expired') return { state: 'stale' };
    if (view.status === 'unknown' || !view.latest) return { state: 'unknown' };
    const meta = view.latest[section];
    // A retained successful generation never conceals a newer failed attempt.
    if (meta.coverage === 'failed') return { ...capabilityFailure(meta.reason), at: meta.observedAt };
    if (view.status === 'stale' || !fresh(view.serverNow, meta.observedAt, elapsed, 120000)) return { state: 'stale', at: meta.observedAt };
    return { state: 'available', at: meta.observedAt };
}

export function socketOwnerCapability(view: SystemView, elapsed: number): CapabilityObservation {
    const collected = systemCapability(view, 'sockets', elapsed);
    if (collected.state !== 'available') return collected;
    const source = view.latest?.socketOwnerProvenance;
    return source ? { state: 'available', at: source.finishedAt } : { state: 'unknown', reason: 'socket_owner_source_unconfirmed', at: collected.at };
}

export function overviewCapability(view: OverviewView, section: OverviewSection, elapsed: number): CapabilityObservation {
    const value = view[section], complete = value.complete;
    if (value.status === 'not_configured') return { state: 'not_configured' };
    if (value.failure && (!complete || BigInt(value.failure.sequence) > BigInt(complete.binding.sequence))) return { ...capabilityFailure(value.failure.reason), at: value.failure.attemptedAt };
    if (value.transfer && (!complete || BigInt(value.transfer.binding.sequence) > BigInt(complete.binding.sequence)) && ['failed', 'expired'].includes(value.transfer.state)) return { state: 'failed', reason: 'transfer_' + value.transfer.state, at: value.transfer.collectedAt };
    if (!complete) return { state: value.transfer?.state === 'pending' ? 'pending' : 'unknown' };
    const at = complete.manifest.collectedAt;
    if (value.status !== 'available' || complete.state !== 'complete' || !fresh(view.serverNow, at, elapsed, 120000) || inventoryAge(complete.retainedUntil, view.serverNow) <= elapsed) return { state: 'stale', at };
    const fields = complete.manifest[section].fieldCoverage;
    if (fields.denied > 0) return { state: 'denied', reason: 'permission_denied', at };
    if (fields.invalid > 0 || fields.unavailable > 0) return { state: 'partial', reason: 'missing_fields', at };
    // Exited processes and filesystems without capacity are expected outcomes.
    // Unsupported/not-applicable field counts remain in the inventory details.
    return { state: 'available', at };
}

export function packageCapability(view: CompletePackageView, elapsed: number): CapabilityObservation {
    if (view.status === 'not_configured') return { state: 'not_configured' };
    if (view.status === 'revoked') return { state: 'denied', reason: 'revoked' };
    const complete = view.complete;
    if (view.failure && (!complete || BigInt(view.failure.sequence) > BigInt(complete.binding.sequence))) return { ...capabilityFailure(view.failure.reason), at: view.failure.attemptedAt };
    if (view.transfer && (!complete || BigInt(view.transfer.binding.sequence) > BigInt(complete.binding.sequence)) && ['failed', 'expired'].includes(view.transfer.state)) return { state: 'failed', reason: 'transfer_' + view.transfer.state, at: view.transfer.collectedAt };
    if (!complete) return { state: view.transfer?.state === 'pending' ? 'pending' : 'unknown' };
    const at = complete.manifest.collectedAt;
    // Full dpkg captures run every six hours; retention is not freshness.
    if (view.status !== 'available' || complete.state !== 'complete' || !fresh(view.serverNow, at, elapsed, 6 * 3600000 + 120000) || inventoryAge(complete.retainedUntil, view.serverNow) <= elapsed) return { state: 'stale', at };
    return { state: 'available', at };
}

export function journalCapability(view: JournalView, elapsed: number): CapabilityObservation {
    if (view.localStatus === 'denied') return { state: 'denied', reason: 'permission_denied' };
    if (!view.configured || view.localStatus === 'disabled' || view.generation?.policyEnabled === false) return { state: 'not_configured' };
    if (view.localStatus === 'helper_unavailable' || view.localStatus === 'result_lost') return { state: 'failed', reason: view.localStatus };
    const generation = view.generation;
    if (!generation) return { state: view.localStatus === 'checking' ? 'pending' : 'unknown' };
    if (!Number.isFinite(elapsed) || elapsed < 0 || !generation.fresh || inventoryAge(generation.expiresAt, view.serverNow) <= elapsed) return { state: 'stale', at: generation.observedAt };
    // A fresh enabled policy proves configuration, not a successful content read.
    return { state: generation.policyEnabled === true ? 'configured' : 'unknown', at: generation.observedAt };
}

export function basicCapability(capability: Capability, device: Device): CapabilityObservation {
    if (capability.status === 'denied') return { state: 'denied', reason: 'permission_denied' };
    if (['cpu', 'memory', 'disk'].includes(capability.id)) {
        const metric = device[capability.id as 'cpu' | 'memory' | 'disk'];
        if (metric.quality === 'denied') return { state: 'denied', reason: 'permission_denied', at: metric.collectedAt };
        if (metric.quality === 'stale') return { state: 'stale', at: metric.collectedAt };
        if (metric.value === null || metric.quality !== 'healthy') return { state: 'unknown' };
    }
    // These fixed collector rows describe attribution/acceptance, never a failed read.
    if (capability.status === 'limited' && ['host_inventory', 'native_verification', 'local_transport'].includes(capability.id)) return { state: 'scope' };
    return { state: capability.status === 'limited' ? 'unknown' : capability.status };
}
