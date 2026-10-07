/** Package inventory is not a plan. Only the independent preparation adapter
 * supplies immutable versions and provenance in this workflow contract. */
export interface PackageIdentity { name: string; architecture: string }
export interface PackageUpdateItem extends PackageIdentity {
    fromVersion: string; toVersion: string; sourcePackage: string; sourceVersion: string;
    sourceLabel: string; suite: string; component: string; archiveSHA256: string;
}
export interface PackageUpdatePreview {
    requestId: string; digest: string; actorId: string; expiresAt: string;
    transportProfile: 'production-tls' | 'disposable-http-test';
    conffilePolicy: 'preserve-modified-dpkg-conffiles'; totalBytes: number; items: PackageUpdateItem[];
}
export type PackageUpdateState = 'preparing' | 'preview_ready' | 'approved' | 'delivery_unknown' | 'expired' | 'revoked' | 'preparation_failed' | 'applying' | 'verifying' | 'succeeded' | 'needs_intervention';
export interface PackageUpdateResult {
    phase: 'applying' | 'verifying' | 'succeeded' | 'needs_intervention'; observedAt: string;
    packages: (PackageIdentity & { expectedVersion: string; observedVersion: string | null; outcome: 'verified' | 'mismatch' | 'unknown' })[];
    reboot: { state: 'required' | 'not_reported' | 'unknown'; source: 'simulation' | 'native'; observedAt: string }; reason: string;
}
export interface PackageUpdateJob { requestId: string; state: PackageUpdateState; createdAt: string; updatedAt: string; approvedAt: string | null; result: PackageUpdateResult | null }
export interface PackageUpdateView {
    schemaVersion: 'tracebolt.package-update-workflow.v2'; deviceId: string; serverNow: string;
    executionMode: 'unavailable' | 'simulation' | 'native'; available: boolean;
    reason: 'native_adapter_unavailable' | 'ready' | 'simulation_only' | 'operation_in_progress' | 'needs_intervention';
    preview: PackageUpdatePreview | null; job: PackageUpdateJob | null;
}
export const PACKAGE_UPDATE_VIEW_BYTES = 512 * 1024;
export const canonicalPackageSelection = (items: PackageIdentity[]): PackageIdentity[] => items.map(({ name, architecture }) => ({ name, architecture })).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : a.architecture < b.architecture ? -1 : a.architecture > b.architecture ? 1 : 0);
export const packageIdentityKey = (value: PackageIdentity) => `${value.name}:${value.architecture}`;
export const validPackageIdentity = (value: unknown): value is PackageIdentity => exact(value, ['name', 'architecture']) && packageName(value.name) && typeof value.architecture === 'string' && value.architecture.length <= 64 && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(value.architecture) && value.architecture !== 'source' && !value.architecture.split('-').includes('any');
export const validPackageUpdateID = (value: unknown, prefix: 'agent_' | 'operator_' | 'update_'): value is string => typeof value === 'string' && new RegExp(`^${prefix}[a-f0-9]{32}$`).test(value) && value !== `${prefix}${'0'.repeat(32)}`;
export const packageUpdateReady = (view: PackageUpdateView | null): boolean => !!view && (view.executionMode === 'native' && view.reason === 'ready' || view.executionMode === 'simulation' && view.reason === 'simulation_only');
export const packageUpdateBlocksNew = (job: PackageUpdateJob | null) => !!job && !['expired', 'revoked', 'preparation_failed', 'succeeded'].includes(job.state);
export const packageUpdatePending = (job: PackageUpdateJob | null) => !!job && ['preparing', 'approved', 'delivery_unknown', 'applying', 'verifying'].includes(job.state);
const packageName = (value: unknown): value is string => typeof value === 'string' && /^[a-z0-9][a-z0-9+.-]{1,255}$/.test(value);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const text = (value: unknown, limit = 256): value is string => typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\x00-\x1f\x7f]/.test(value);
const member = (value: unknown, values: readonly string[]) => typeof value === 'string' && values.includes(value);
const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) && value !== '0'.repeat(64);
const digest = (value: unknown): value is string => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value) && hash(value.slice(7));
export function packageUpdateTime(value: unknown): value is string {
    return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value)
        && Number.isFinite(Date.parse(value)) && Date.parse(value) >= 1000
        && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
export function validPackageUpdatePreview(value: unknown): value is PackageUpdatePreview {
    if (!exact(value, ['requestId', 'digest', 'actorId', 'expiresAt', 'transportProfile', 'conffilePolicy', 'totalBytes', 'items'])
        || !validPackageUpdateID(value.requestId, 'update_') || !digest(value.digest) || !validPackageUpdateID(value.actorId, 'operator_') || !packageUpdateTime(value.expiresAt)
        || !member(value.transportProfile, ['production-tls', 'disposable-http-test']) || value.conffilePolicy !== 'preserve-modified-dpkg-conffiles'
        || !Number.isSafeInteger(value.totalBytes) || (value.totalBytes as number) < 0 || !Array.isArray(value.items) || value.items.length < 1 || value.items.length > 32) return false;
    const seen = new Set<string>();
    return value.items.every(item => {
        if (!exact(item, ['name', 'architecture', 'fromVersion', 'toVersion', 'sourcePackage', 'sourceVersion', 'sourceLabel', 'suite', 'component', 'archiveSHA256'])
            || !validPackageIdentity({ name: item.name, architecture: item.architecture }) || !packageName(item.sourcePackage)
            || ![item.fromVersion, item.toVersion, item.sourceVersion].every(value => text(value, 1024)) || ![item.sourceLabel, item.suite, item.component].every(value => text(value)) || !digest(item.archiveSHA256)) return false;
        const key = `${item.name}:${item.architecture}`; if (seen.has(key)) return false; seen.add(key); return true;
    });
}
function validResult(value: unknown, job: PackageUpdateJob, preview: PackageUpdatePreview | null, serverNow: string, mode: PackageUpdateView['executionMode']): value is PackageUpdateResult {
    if (!exact(value, ['phase', 'observedAt', 'packages', 'reboot', 'reason']) || !member(value.phase, ['applying', 'verifying', 'succeeded', 'needs_intervention']) || value.phase !== job.state
        || !packageUpdateTime(value.observedAt) || Date.parse(value.observedAt) > Date.parse(serverNow) || Date.parse(value.observedAt) > Date.parse(job.updatedAt) || !member(value.reason, [mode === 'native' ? 'native_running' : 'simulated_running', mode === 'native' ? 'native_verified' : 'simulated_verified', 'runner_state_unknown', 'verification_mismatch'])
        || !Array.isArray(value.packages) || value.packages.length < 1 || value.packages.length > 32
        || !exact(value.reboot, ['state', 'source', 'observedAt']) || !member(value.reboot.state, ['required', 'not_reported', 'unknown'])
        || !member(value.reboot.source, ['simulation', 'native']) || value.reboot.source !== mode
        || !packageUpdateTime(value.reboot.observedAt) || Date.parse(value.reboot.observedAt) > Date.parse(serverNow)) return false;
    if (!preview || value.packages.length !== preview.items.length || value.reboot.observedAt !== value.observedAt || Date.parse(value.observedAt) < Date.parse(job.approvedAt ?? job.createdAt)) return false;
    if (['applying', 'verifying'].includes(value.phase as string) && (value.reason !== (mode === 'native' ? 'native_running' : 'simulated_running') || value.reboot.state !== 'unknown')) return false;
    if (value.phase === 'needs_intervention' && !['runner_state_unknown', 'verification_mismatch'].includes(value.reason as string)) return false;
    const seen = new Set<string>();
    if (!value.packages.every(row => {
        if (!exact(row, ['name', 'architecture', 'expectedVersion', 'observedVersion', 'outcome']) || !validPackageIdentity({ name: row.name, architecture: row.architecture })
            || !text(row.expectedVersion, 1024) || !(row.observedVersion === null || text(row.observedVersion, 1024)) || !member(row.outcome, ['verified', 'mismatch', 'unknown'])) return false;
        const key = `${row.name}:${row.architecture}`; if (seen.has(key)) return false; seen.add(key);
        if (row.outcome === 'unknown' && row.observedVersion !== null) return false;
        if (row.outcome === 'verified' && row.observedVersion !== row.expectedVersion || row.outcome === 'mismatch' && (row.observedVersion === null || row.observedVersion === row.expectedVersion)) return false;
        if (preview && !preview.items.some(item => packageIdentityKey(item) === key && item.toVersion === row.expectedVersion)) return false;
        return true;
    })) return false;
    return value.phase !== 'succeeded' || value.reason === (mode === 'native' ? 'native_verified' : 'simulated_verified') && !!preview && value.packages.length === preview.items.length && value.packages.every(row => row.outcome === 'verified');
}
/** Strict protocol validation: no fabricated success, unknown fields, cross-device
 * replies or silent conversion of inventory into installation evidence. */
export function validPackageUpdateView(value: unknown, deviceId: string): value is PackageUpdateView {
    if (!validPackageUpdateID(deviceId, 'agent_') || !exact(value, ['schemaVersion', 'deviceId', 'serverNow', 'executionMode', 'available', 'reason', 'preview', 'job'])
        || value.schemaVersion !== 'tracebolt.package-update-workflow.v2' || value.deviceId !== deviceId || !packageUpdateTime(value.serverNow)
        || !member(value.executionMode, ['unavailable', 'simulation', 'native']) || typeof value.available !== 'boolean'
        || !member(value.reason, ['native_adapter_unavailable', 'ready', 'simulation_only', 'operation_in_progress', 'needs_intervention'])) return false;
    if (value.executionMode === 'unavailable') return value.available === false && value.reason === 'native_adapter_unavailable' && value.preview === null && value.job === null;
    const readyReason = value.executionMode === 'native' ? 'ready' : 'simulation_only';
    if (value.reason === (value.executionMode === 'native' ? 'simulation_only' : 'ready') || value.reason === 'native_adapter_unavailable' && (value.executionMode !== 'native' || value.available)) return false;
    if (value.preview !== null && !validPackageUpdatePreview(value.preview)) return false;
    const preview = value.preview as PackageUpdatePreview | null;
    if (value.job === null) return preview === null && (value.reason === readyReason || value.reason === 'native_adapter_unavailable');
    if (!exact(value.job, ['requestId', 'state', 'createdAt', 'updatedAt', 'approvedAt', 'result'])) return false;
    const job = value.job as unknown as PackageUpdateJob;
    if (!validPackageUpdateID(job.requestId, 'update_') || !member(job.state, ['preparing', 'preview_ready', 'approved', 'delivery_unknown', 'expired', 'revoked', 'preparation_failed', 'applying', 'verifying', 'succeeded', 'needs_intervention'])
        || !packageUpdateTime(job.createdAt) || !packageUpdateTime(job.updatedAt) || Date.parse(job.createdAt) > Date.parse(job.updatedAt) || Date.parse(job.updatedAt) > Date.parse(value.serverNow)
        || !(job.approvedAt === null || packageUpdateTime(job.approvedAt) && Date.parse(job.approvedAt) >= Date.parse(job.createdAt) && Date.parse(job.approvedAt) <= Date.parse(job.updatedAt))) return false;
    if (preview && preview.requestId !== job.requestId || ['preview_ready', 'approved', 'delivery_unknown', 'applying', 'verifying', 'succeeded'].includes(job.state) && !preview) return false;
    if (['approved', 'delivery_unknown', 'applying', 'verifying', 'succeeded'].includes(job.state) && job.approvedAt === null) return false;
    if (job.state === 'succeeded' && job.result === null || job.state === 'preview_ready' && job.approvedAt !== null) return false;
    if (job.result !== null && !validResult(job.result, job, preview, value.serverNow, value.executionMode as PackageUpdateView['executionMode'])) return false;
    if (value.reason === 'native_adapter_unavailable') return !value.available;
    if (job.state === 'needs_intervention' || job.state === 'delivery_unknown') return value.reason === 'needs_intervention' && !value.available;
    if (!packageUpdateBlocksNew(job)) return !value.available || value.reason === readyReason;
    return !value.available && value.reason === (packageUpdatePending(job) ? 'operation_in_progress' : readyReason);
}
export function parsePackageUpdateView(value: unknown, deviceId: string): PackageUpdateView {
    if (!validPackageUpdateView(value, deviceId)) throw new TypeError('Invalid package-update view');
    return value;
}
