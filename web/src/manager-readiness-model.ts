import { inventoryAge } from './complete-packages-types';

export const MANAGER_READINESS_VIEW_BYTES = 32768;
// A read is a short-lived snapshot, not a continuing claim about the manager.
export const MANAGER_READINESS_MAX_AGE_MS = 5000;
export const MANAGER_READINESS_COMPONENTS = [
    'state_boundary', 'operator_store', 'trust_store', 'linux_enrollment_store',
    'windows_enrollment_store', 'macos_basic_store', 'macos_inventory_store',
    'server_certificate', 'enrollment_issuer', 'linux_inventory_step',
    'windows_inventory_step', 'macos_inventory_step', 'linux_health_worker', 'windows_health_worker',
] as const;
export const MANAGER_READINESS_UNASSESSED = [
    'full_store_integrity', 'write_capacity_and_durability', 'complete_maintenance_sweep',
    'optional_provider_workers', 'native_and_release_acceptance',
] as const;
export const MANAGER_CERTIFICATE_ROLES = ['server_chain', 'enrollment_issuer', 'enrollment_root'] as const;
export type ManagerComponentName = typeof MANAGER_READINESS_COMPONENTS[number] | 'runtime' | 'probe';
export type ManagerComponentState = 'ready' | 'succeeded' | 'not_configured' | 'unknown' | 'starting' | 'stopped' | 'stale' | 'failed' | 'busy' | 'timeout';
export interface ManagerReadinessComponent { component: ManagerComponentName; state: ManagerComponentState; checkedAt?: string }
export type ManagerCertificateState = 'valid' | 'within_30_days' | 'within_7_days' | 'expired' | 'not_yet_valid' | 'not_configured' | 'unavailable';
export interface ManagerCertificateLifetime { role: typeof MANAGER_CERTIFICATE_ROLES[number]; state: ManagerCertificateState; validFrom?: string; validUntil?: string }
export interface ManagerReadinessView {
    schemaVersion: 'tracebolt.manager-readiness.v1';
    scope: 'core_reads_and_last_worker_steps';
    status: 'ready' | 'unavailable';
    serverNow: string;
    components: ManagerReadinessComponent[];
    unassessed: typeof MANAGER_READINESS_UNASSESSED[number][];
    certificateLifetimes?: ManagerCertificateLifetime[];
}

function exact(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
        && required.every(key => Object.hasOwn(value, key))
        && Object.keys(value).every(key => required.includes(key) || optional.includes(key));
}
const member = (value: unknown, values: readonly string[]): value is string => typeof value === 'string' && values.includes(value);
/** Go emits UTC RFC3339Nano. Keep its original text and sub-millisecond order. */
export function validManagerReadinessTimestamp(value: unknown, certificateDate = false): value is string {
    return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value)
        && Number(value.slice(0, 4)) >= (certificateDate ? 1 : 1970)
        && Number.isFinite(Date.parse(value))
        && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
function workerAge(name: ManagerComponentName): number | null {
    if (name === 'linux_inventory_step' || name === 'windows_inventory_step') return 5000;
    if (name === 'macos_inventory_step') return 120000;
    if (name === 'linux_health_worker' || name === 'windows_health_worker') return 90000;
    return null;
}
function component(value: unknown, serverNow: string): value is ManagerReadinessComponent {
    if (!exact(value, ['component', 'state'], ['checkedAt']) || !member(value.component, [...MANAGER_READINESS_COMPONENTS, 'runtime', 'probe'])) return false;
    if (value.component === 'runtime') return value.state === 'unknown' && !Object.hasOwn(value, 'checkedAt');
    if (value.component === 'probe') return member(value.state, ['busy', 'timeout']) && !Object.hasOwn(value, 'checkedAt');
    const name = value.component as ManagerComponentName, maximum = workerAge(name);
    const states = maximum !== null
        ? [name.endsWith('_step') ? 'succeeded' : 'ready', 'not_configured', 'stopped', 'starting', 'stale', 'failed']
        : name === 'server_certificate' || name === 'enrollment_issuer'
            ? ['ready', 'failed', 'not_configured']
            : ['ready', 'failed', 'timeout', 'unknown', ...(['state_boundary', 'operator_store', 'trust_store'].includes(name) ? [] : ['not_configured'])];
    if (!member(value.state, states)) return false;
    if (member(value.state, ['not_configured', 'starting', 'unknown'])) return !Object.hasOwn(value, 'checkedAt');
    if (value.state === 'stopped' && !Object.hasOwn(value, 'checkedAt')) return true;
    if (!validManagerReadinessTimestamp(value.checkedAt)) return false;
    const age = inventoryAge(serverNow, value.checkedAt);
    if (maximum !== null && value.state !== 'stopped') {
        if (value.state === 'stale') return age < 0 || age > maximum;
        return age >= 0 && age <= maximum;
    }
    return value.state !== 'ready' || age >= 0;
}
function certificateState(from: string, until: string, serverNow: string, elapsedMS = 0): ManagerCertificateState {
    if (inventoryAge(serverNow, from) + elapsedMS < 0) return 'not_yet_valid';
    const remaining = inventoryAge(until, serverNow) - elapsedMS;
    if (remaining <= 0) return 'expired';
    if (remaining <= 7 * 86400000) return 'within_7_days';
    if (remaining <= 30 * 86400000) return 'within_30_days';
    return 'valid';
}
function certificate(value: unknown, serverNow: string): value is ManagerCertificateLifetime {
    if (!exact(value, ['role', 'state'], ['validFrom', 'validUntil']) || !member(value.role, MANAGER_CERTIFICATE_ROLES)) return false;
    if (value.state === 'not_configured' || value.state === 'unavailable') return !Object.hasOwn(value, 'validFrom') && !Object.hasOwn(value, 'validUntil');
    return validManagerReadinessTimestamp(value.validFrom, true) && validManagerReadinessTimestamp(value.validUntil, true)
        && inventoryAge(value.validUntil, value.validFrom) > 0
        && value.state === certificateState(value.validFrom, value.validUntil, serverNow);
}

/** Closed operator-only contract. A 503 carries useful evidence, not an error envelope. */
export function validManagerReadinessView(value: unknown, httpStatus?: number): value is ManagerReadinessView {
    if (!exact(value, ['schemaVersion', 'scope', 'status', 'serverNow', 'components', 'unassessed'], ['certificateLifetimes'])
        || value.schemaVersion !== 'tracebolt.manager-readiness.v1' || value.scope !== 'core_reads_and_last_worker_steps'
        || !member(value.status, ['ready', 'unavailable']) || !validManagerReadinessTimestamp(value.serverNow)
        || httpStatus !== undefined && httpStatus !== (value.status === 'ready' ? 200 : 503)
        || !Array.isArray(value.components) || value.components.length > MANAGER_READINESS_COMPONENTS.length + 1
        || !Array.from(value.components).every(row => component(row, value.serverNow as string))
        || new Set(value.components.map(row => row.component)).size !== value.components.length
        || !Array.isArray(value.unassessed) || value.unassessed.length !== MANAGER_READINESS_UNASSESSED.length
        || !Array.from(value.unassessed).every(item => member(item, MANAGER_READINESS_UNASSESSED))
        || new Set(value.unassessed).size !== MANAGER_READINESS_UNASSESSED.length) return false;
    const rows = value.components as ManagerReadinessComponent[];
    // Empty/fallback evidence is explicitly unavailable; a partial roster is never green.
    const fallback = rows.length === 0 || rows.length === 1 && (rows[0].component === 'runtime' || rows[0].component === 'probe' && rows[0].state === 'busy');
    if (fallback) {
        if (value.status !== 'unavailable' || Object.hasOwn(value, 'certificateLifetimes')) return false;
    } else {
        if (!MANAGER_READINESS_COMPONENTS.every(name => rows.some(row => row.component === name))
            || rows.some(row => row.component === 'runtime' || row.component === 'probe' && row.state !== 'timeout')) return false;
        const ready = rows.every(row => member(row.state, ['ready', 'succeeded', 'not_configured']));
        if ((value.status === 'ready') !== ready) return false;
    }
    if (Object.hasOwn(value, 'certificateLifetimes')) {
        if (!Array.isArray(value.certificateLifetimes) || value.certificateLifetimes.length !== MANAGER_CERTIFICATE_ROLES.length
            || !Array.from(value.certificateLifetimes).every(row => certificate(row, value.serverNow as string))
            || new Set(value.certificateLifetimes.map(row => row.role)).size !== MANAGER_CERTIFICATE_ROLES.length) return false;
        for (const lifetime of value.certificateLifetimes as ManagerCertificateLifetime[]) {
            const authority = rows.find(row => row.component === (lifetime.role === 'server_chain' ? 'server_certificate' : 'enrollment_issuer'));
            // Both projections use the same configuration flag and loaded
            // material. Dates may not contradict a successful validity check;
            // valid dates still cannot establish trust or override a failure.
            if (!authority || (lifetime.state === 'not_configured') !== (authority.state === 'not_configured')
                || authority.state === 'ready' && member(lifetime.state, ['expired', 'not_yet_valid'])) return false;
        }
    }
    return new TextEncoder().encode(JSON.stringify(value)).byteLength <= MANAGER_READINESS_VIEW_BYTES;
}

const validElapsed = (elapsedMS: number) => Number.isFinite(elapsedMS) && elapsedMS >= 0;
/** Age only withholds confidence. It never changes failed/stopped into success. */
export function managerComponentState(row: ManagerReadinessComponent, serverNow: string, elapsedMS: number): ManagerComponentState {
    if (!validElapsed(elapsedMS)) return 'unknown';
    if (row.state !== 'ready' && row.state !== 'succeeded') return row.state;
    if (!validManagerReadinessTimestamp(serverNow) || !validManagerReadinessTimestamp(row.checkedAt)) return 'unknown';
    const age = inventoryAge(serverNow, row.checkedAt);
    return age < 0 || elapsedMS > MANAGER_READINESS_MAX_AGE_MS || age + elapsedMS > (workerAge(row.component) ?? MANAGER_READINESS_MAX_AGE_MS) ? 'stale' : row.state;
}
/** Loaded dates are not trust. Passage of time may worsen, never grant, validity. */
export function managerCertificateState(row: ManagerCertificateLifetime, serverNow: string, elapsedMS: number): ManagerCertificateState | 'unknown' {
    if (!validElapsed(elapsedMS) || elapsedMS > MANAGER_READINESS_MAX_AGE_MS) return 'unknown';
    if (row.state === 'not_configured' || row.state === 'unavailable' || row.state === 'not_yet_valid' || row.state === 'expired') return row.state;
    if (!validManagerReadinessTimestamp(serverNow) || !validManagerReadinessTimestamp(row.validFrom, true) || !validManagerReadinessTimestamp(row.validUntil, true)) return 'unknown';
    return certificateState(row.validFrom, row.validUntil, serverNow, elapsedMS);
}
export function managerReadinessStatus(view: ManagerReadinessView, elapsedMS: number): 'ready' | 'unavailable' | 'stale' | 'unknown' {
    if (!validElapsed(elapsedMS)) return 'unknown';
    if (elapsedMS > MANAGER_READINESS_MAX_AGE_MS) return 'stale';
    if (view.status === 'unavailable') return 'unavailable';
    if (view.components.some(row => managerComponentState(row, view.serverNow, elapsedMS) === 'stale')) return 'stale';
    if (view.components.some(row => managerComponentState(row, view.serverNow, elapsedMS) === 'unknown')) return 'unknown';
    // A loaded certificate reaching expiry withholds the old success; it cannot
    // assert that a replacement was loaded or that a fresh authority check failed.
    if (view.certificateLifetimes?.some(row => member(row.state, ['valid', 'within_30_days', 'within_7_days']) && managerCertificateState(row, view.serverNow, elapsedMS) === 'expired')) return 'stale';
    return 'ready';
}
