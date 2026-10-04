import { inventoryAge, inventorySequence } from './complete-packages-types';

/** Operator-only DTO. Completion comes from the manager's atomic ledger, never
 * from the number of rows loaded into a page. No cross-session row cache. */
export type OverviewSection = 'processes' | 'volumes';
export const OVERVIEW_STATUS_BYTES = 32768, OVERVIEW_PAGE_BYTES = 262144, OVERVIEW_PAGE_ROWS = 100, OVERVIEW_SCAN_ROWS = 2048;
export const overviewOutcomes = ['observed', 'denied', 'exited', 'invalid', 'unsupported', 'unavailable', 'notApplicable'] as const;
export type FieldCoverage = Record<typeof overviewOutcomes[number], number>;
export type ObservationStatus = 'observed' | 'denied' | 'exited' | 'invalid' | 'unsupported' | 'unavailable' | 'not_applicable';
export interface Observation { status: ObservationStatus; reason: string }
export interface ProcessRow { pid: number; parentPid: number | null; name: string | null; state: string | null; rssBytes: number | null; cpuTimeSeconds: number | null; threads: number | null; observation: Observation }
export interface VolumeRow { id: string; mountPoint: string; filesystem: string; kind: 'local' | 'memory' | 'remote' | 'unknown' | 'virtual'; filesystemGroup: string; capacityScope: 'agent-mount-namespace'; totalBytes: number | null; availableBytes: number | null; usedPercent: number | null; measurement: Observation }
export interface OverviewRow { process: ProcessRow | null; volume: VolumeRow | null }
export interface OverviewMeta { generationId: string; coverage: 'complete' | 'failed'; reason: string; observedCount: number | null; countExact: boolean; fieldCoverage: FieldCoverage }
export interface OverviewManifest {
    schemaVersion: 'tracebolt.complete-overview-generation.v1'; scope: 'agent-visible-linux-namespaces'; generationId: string; captureGenerationId: string; section: OverviewSection;
    captureStartedAt: string; captureFinishedAt: string; collectedAt: string; processes: OverviewMeta; volumes: OverviewMeta; observedCount: number; chunkCount: number; canonicalRowBytes: number; canonicalSnapshotBytes: number; canonicalSectionBytes: number; rowsSha256: string;
}
export interface OverviewBinding { section: OverviewSection; sequence: string; generationId: string; manifestHash: string }
export interface OverviewComplete { binding: OverviewBinding; manifest: OverviewManifest; state: 'complete' | 'expired'; completedAt: string; retainedUntil: string }
export interface OverviewSectionView {
    status: 'not_configured' | 'awaiting' | 'available' | 'expired'; complete: OverviewComplete | null;
    transfer: null | { binding: OverviewBinding; manifest: OverviewManifest; state: 'pending' | 'complete' | 'expired' | 'failed'; declaredRows: number; acceptedRows: number; expectedChunks: number; acceptedChunks: number; collectedAt: string; startedAt: string; expiresAt: string };
    failure: null | { sequence: string; generationId: string; attemptedAt: string; receivedAt: string; reason: string };
}
export interface OverviewView { schemaVersion: 'tracebolt.complete-overview-view.v1'; deviceId: string; serverNow: string; collectionProfile: '' | 'managed-operations-v3'; status: OverviewSectionView['status']; processes: OverviewSectionView; volumes: OverviewSectionView }
export interface OverviewPage {
    schemaVersion: 'tracebolt.complete-overview-page.v1'; deviceId: string; serverNow: string; section: OverviewSection; binding: OverviewBinding; manifest: OverviewManifest; collectedAt: string; completedAt: string; retainedUntil: string;
    totalRows: number; items: OverviewRow[]; scannedRows: number; exhausted: boolean; searchIncomplete: boolean; nextCursor: string; cursorExpiresAt: string;
}
const record = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const number = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= max;
const member = (v: unknown, list: readonly string[]): boolean => typeof v === 'string' && list.includes(v);
const generation = (v: unknown): v is string => typeof v === 'string' && /^sample_[a-f0-9]{32}$/.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const safeText = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).byteLength <= max && !/[\p{Cc}\p{Cf}\uFFFD\uD800-\uDFFF\u2028\u2029]/u.test(v);
function timestamp(v: unknown): v is string { return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19); }
const failureReasons = ['source_missing', 'permission_denied', 'not_supported', 'timeout', 'invalid_source', 'read_failed', 'item_limit', 'byte_limit', 'collector_busy', 'not_collected', 'mount_changed'];
function validMeta(v: unknown, section: OverviewSection, captureId: string): v is OverviewMeta {
    if (!record(v, ['generationId', 'coverage', 'reason', 'observedCount', 'countExact', 'fieldCoverage']) || v.generationId !== captureId || !record(v.fieldCoverage, overviewOutcomes) || !Object.values(v.fieldCoverage).every(n => integer(n, section === 'processes' ? 32768 : 16384))) return false;
    const count = Object.values(v.fieldCoverage).reduce<number>((sum, n) => sum + (n as number), 0);
    return v.coverage === 'complete' ? v.reason === 'none' && v.countExact === true && integer(v.observedCount, section === 'processes' ? 32768 : 16384) && count === v.observedCount : v.coverage === 'failed' && member(v.reason, failureReasons) && v.countExact === false && v.observedCount === null && count === 0;
}
export function validOverviewManifest(v: unknown, section: OverviewSection): v is OverviewManifest {
    if (!record(v, ['schemaVersion', 'scope', 'generationId', 'captureGenerationId', 'section', 'captureStartedAt', 'captureFinishedAt', 'collectedAt', 'processes', 'volumes', 'observedCount', 'chunkCount', 'canonicalRowBytes', 'canonicalSnapshotBytes', 'canonicalSectionBytes', 'rowsSha256']) || v.schemaVersion !== 'tracebolt.complete-overview-generation.v1' || v.scope !== 'agent-visible-linux-namespaces' || v.section !== section || !generation(v.generationId) || !generation(v.captureGenerationId) || !timestamp(v.captureStartedAt) || !timestamp(v.captureFinishedAt) || !timestamp(v.collectedAt) || inventoryAge(v.collectedAt, v.captureStartedAt) !== 0 || inventoryAge(v.captureFinishedAt, v.captureStartedAt) < 0 || !validMeta(v.processes, 'processes', v.captureGenerationId) || !validMeta(v.volumes, 'volumes', v.captureGenerationId) || !integer(v.observedCount, section === 'processes' ? 32768 : 16384) || !integer(v.chunkCount, 1024) || !integer(v.canonicalRowBytes, (16 << 20) + 32 * 32768) || !integer(v.canonicalSectionBytes, 16 << 20) || !integer(v.canonicalSnapshotBytes, 24 << 20) || v.canonicalSectionBytes > v.canonicalSnapshotBytes || !digest(v.rowsSha256)) return false;
    const selected = v[section] as OverviewMeta;
    if (selected.coverage !== 'complete' || selected.observedCount !== v.observedCount) return false;
    return v.observedCount === 0 ? v.chunkCount === 0 && v.canonicalRowBytes === 0 : v.chunkCount > 0 && v.chunkCount <= v.observedCount && v.observedCount <= v.chunkCount * 128 && v.canonicalRowBytes >= v.observedCount && v.canonicalRowBytes <= v.chunkCount * 65536;
}
function binding(v: unknown, section: OverviewSection): v is OverviewBinding { return record(v, ['section', 'sequence', 'generationId', 'manifestHash']) && v.section === section && inventorySequence(v.sequence) && generation(v.generationId) && digest(v.manifestHash); }
function same(a: unknown, b: unknown): boolean { return a === b || a !== null && b !== null && typeof a === 'object' && typeof b === 'object' && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(k => Object.hasOwn(b, k) && same((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k])); }
function validSection(v: unknown, section: OverviewSection, now: string): v is OverviewSectionView {
    if (!record(v, ['status', 'complete', 'transfer', 'failure'])) return false;
    const c = v.complete, t = v.transfer, f = v.failure;
    if (c !== null && (!record(c, ['binding', 'manifest', 'state', 'completedAt', 'retainedUntil']) || !binding(c.binding, section) || !validOverviewManifest(c.manifest, section) || c.binding.generationId !== c.manifest.generationId || !member(c.state, ['complete', 'expired']) || !timestamp(c.completedAt) || !timestamp(c.retainedUntil) || inventoryAge(c.completedAt, c.manifest.captureFinishedAt) < 0 || inventoryAge(now, c.completedAt) < 0 || inventoryAge(c.retainedUntil, c.manifest.collectedAt) !== 86400000 || (c.state === 'complete') !== (inventoryAge(c.retainedUntil, now) > 0))) return false;
    if (t !== null) {
        if (!record(t, ['binding', 'manifest', 'state', 'declaredRows', 'acceptedRows', 'expectedChunks', 'acceptedChunks', 'collectedAt', 'startedAt', 'expiresAt']) || !binding(t.binding, section) || !validOverviewManifest(t.manifest, section) || t.binding.generationId !== t.manifest.generationId || !member(t.state, ['pending', 'complete', 'expired', 'failed']) || t.declaredRows !== t.manifest.observedCount || !integer(t.acceptedRows, t.manifest.observedCount) || t.expectedChunks !== t.manifest.chunkCount || !integer(t.acceptedChunks, t.manifest.chunkCount) || t.collectedAt !== t.manifest.collectedAt || !timestamp(t.startedAt) || !timestamp(t.expiresAt) || inventoryAge(t.startedAt, t.manifest.captureFinishedAt) < 0 || inventoryAge(now, t.startedAt) < 0) return false;
        // A capture uploaded after its observation TTL can already be expired at
        // promotion. Its original retention deadline must not move to upload time.
        if (inventoryAge(t.expiresAt, t.startedAt) < 0 && !(t.state === 'expired' && t.acceptedRows === t.declaredRows && t.acceptedChunks === t.expectedChunks && inventoryAge(t.expiresAt, t.manifest.collectedAt) === 86400000)) return false;
        if (t.state === 'complete' && (t.acceptedRows !== t.declaredRows || t.acceptedChunks !== t.expectedChunks) || t.state === 'pending' && inventoryAge(t.expiresAt, now) <= 0 || c !== null && BigInt(t.binding.sequence) < BigInt((c as unknown as OverviewComplete).binding.sequence)) return false;
    }
    if (f !== null && (!record(f, ['sequence', 'generationId', 'attemptedAt', 'receivedAt', 'reason']) || !inventorySequence(f.sequence) || !generation(f.generationId) || !timestamp(f.attemptedAt) || !timestamp(f.receivedAt) || inventoryAge(f.receivedAt, f.attemptedAt) < 0 || inventoryAge(now, f.receivedAt) < 0 || !member(f.reason, [...failureReasons, 'source_invalid', 'source_changed', 'resource_limit', 'collection_failed']))) return false;
    if (v.status === 'not_configured') return c === null && t === null && f === null;
    return v.status === (c === null ? 'awaiting' : (c as unknown as OverviewComplete).state === 'complete' ? 'available' : 'expired');
}
export function validOverviewView(v: unknown, deviceId: string): v is OverviewView {
    if (!record(v, ['schemaVersion', 'deviceId', 'serverNow', 'collectionProfile', 'status', 'processes', 'volumes']) || v.schemaVersion !== 'tracebolt.complete-overview-view.v1' || v.deviceId !== deviceId || !/^agent_[a-f0-9]{32}$/.test(deviceId) || !timestamp(v.serverNow) || !member(v.collectionProfile, ['', 'managed-operations-v3']) || !validSection(v.processes, 'processes', v.serverNow) || !validSection(v.volumes, 'volumes', v.serverNow)) return false;
    if (v.collectionProfile === '') return v.status === 'not_configured' && v.processes.status === 'not_configured' && v.volumes.status === 'not_configured';
    if (v.processes.status === 'not_configured' || v.volumes.status === 'not_configured') return false;
    return v.status === ([v.processes.status, v.volumes.status].includes('available') ? 'available' : [v.processes.status, v.volumes.status].includes('expired') ? 'expired' : 'awaiting');
}
function validMissing(v: unknown, process: boolean): boolean {
    if (!record(v, ['status', 'reason'])) return false;
    return v.status === 'denied' ? v.reason === 'permission_denied' : v.status === 'exited' ? process && v.reason === 'process_gone' : v.status === 'invalid' ? v.reason === 'invalid_source' || !process && v.reason === 'mount_changed' : v.status === 'unsupported' ? v.reason === 'not_supported' || !process && v.reason === 'remote_filesystem_skipped' : v.status === 'unavailable' ? member(v.reason, ['read_failed', 'source_missing']) : !process && v.status === 'not_applicable' && v.reason === 'not_applicable';
}
export function validOverviewProcess(v: unknown): v is ProcessRow {
    if (!record(v, ['pid', 'parentPid', 'name', 'state', 'rssBytes', 'cpuTimeSeconds', 'threads', 'observation']) || !integer(v.pid, 2147483647) || v.pid === 0 || !record(v.observation, ['status', 'reason'])) return false;
    if (v.observation.status !== 'observed') return ['parentPid', 'name', 'state', 'rssBytes', 'cpuTimeSeconds', 'threads'].every(k => v[k] === null) && validMissing(v.observation, true);
    return v.observation.reason === 'none' && integer(v.parentPid, 2147483647) && safeText(v.name, 64) && !/[\\/]/.test(v.name) && member(v.state, ['running', 'sleeping', 'disk_sleep', 'stopped', 'tracing_stop', 'zombie', 'dead', 'idle', 'parked']) && integer(v.rssBytes) && number(v.cpuTimeSeconds) && integer(v.threads, 2147483647) && v.threads > 0;
}
function filesystemKind(fs: string): VolumeRow['kind'] {
    if (['ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'jfs', 'reiserfs', 'vfat', 'exfat', 'ntfs3', 'zfs', 'bcachefs', 'erofs', 'squashfs'].includes(fs)) return 'local';
    if (['tmpfs', 'devtmpfs', 'hugetlbfs', 'ramfs'].includes(fs)) return 'memory';
    if (['proc', 'sysfs', 'devpts', 'cgroup', 'cgroup2', 'overlay', 'nsfs', 'mqueue', 'securityfs', 'debugfs', 'tracefs', 'pstore', 'configfs', 'efivarfs', 'autofs', 'binfmt_misc', 'fusectl'].includes(fs)) return 'virtual';
    return fs.startsWith('fuse') || ['nfs', 'nfs4', 'cifs', 'smb3', '9p', 'ceph', 'afs', 'coda', 'glusterfs'].includes(fs) ? 'remote' : 'unknown';
}
export function validOverviewVolume(v: unknown): v is VolumeRow {
    if (!record(v, ['id', 'mountPoint', 'filesystem', 'kind', 'filesystemGroup', 'capacityScope', 'totalBytes', 'availableBytes', 'usedPercent', 'measurement']) || typeof v.id !== 'string' || !/^mount_[1-9]\d{0,9}$/.test(v.id) || Number(v.id.slice(6)) > 4294967295 || !safeText(v.mountPoint, 4096) || !v.mountPoint.startsWith('/') || v.mountPoint !== '/' && (v.mountPoint.endsWith('/') || v.mountPoint.split('/').slice(1).some(p => !p || p === '.' || p === '..')) || ['/home/', '/run/user/'].some(prefix => (v.mountPoint as string).startsWith(prefix) && !(v.mountPoint as string).slice(prefix.length).match(/^\[redacted\](\/|$)/)) || typeof v.filesystem !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(v.filesystem) || v.kind !== filesystemKind(v.filesystem) || typeof v.filesystemGroup !== 'string' || !/^fs_(0|[1-9]\d{0,9})_(0|[1-9]\d{0,9})$/.test(v.filesystemGroup) || v.filesystemGroup.split('_').slice(1).some(n => Number(n) > 4294967295) || v.capacityScope !== 'agent-mount-namespace' || !record(v.measurement, ['status', 'reason'])) return false;
    const m = v.measurement;
    if (m.status !== 'observed') return v.totalBytes === null && v.availableBytes === null && v.usedPercent === null && validMissing(m, false) && (v.kind === 'virtual' ? m.status === 'not_applicable' : v.kind === 'remote' ? m.reason === 'remote_filesystem_skipped' : v.kind === 'unknown' ? m.reason === 'not_supported' : m.status !== 'not_applicable');
    return member(v.kind, ['local', 'memory']) && m.reason === 'none' && integer(v.totalBytes) && integer(v.availableBytes, v.totalBytes) && (v.totalBytes === 0 ? v.usedPercent === null : number(v.usedPercent, 100) && Math.abs(v.usedPercent - (v.totalBytes - v.availableBytes) * 100 / v.totalBytes) < 1e-9);
}
export function volumeGroup(v: VolumeRow): number { return v.kind === 'local' ? v.measurement.status === 'observed' ? 0 : 1 : v.kind === 'memory' ? 2 : v.kind === 'remote' ? 3 : v.kind === 'unknown' ? 4 : 5; }
function byteCompare(a: string, b: string): number { const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b); for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i]; return x.length - y.length; }
export function compareOverviewRows(a: OverviewRow, b: OverviewRow): number {
    if (a.process && b.process) return a.process.pid - b.process.pid;
    if (!a.volume || !b.volume) return 0;
    const x = a.volume, y = b.volume;
    return volumeGroup(x) - volumeGroup(y) || Number(y.mountPoint === '/') - Number(x.mountPoint === '/') || byteCompare(x.mountPoint, y.mountPoint) || byteCompare(x.id, y.id);
}
export function overviewSearchText(row: OverviewRow): string { return row.process ? `${row.process.pid}${row.process.name === null ? '' : ` ${row.process.name}`}` : row.volume ? `${row.volume.id} ${row.volume.mountPoint} ${row.volume.filesystem} ${row.volume.kind}` : ''; }
// Go strings.ToLower uses context-free Unicode simple lowercase. ECMAScript's
// whole-string lowercase can expand U+0130 or apply contextual final sigma.
// The server accepts printable ASCII queries only; preserve its match semantics.
export function overviewSearchLower(value: string): string { return Array.from(value, point => point === '\u0130' ? 'i' : point.toLowerCase()).join(''); }
export function validOverviewSearch(value: string): boolean { return value.length <= 128 && !/[^\x20-\x7e]/.test(value); }
export function validOverviewPage(v: unknown, deviceId: string, section: OverviewSection, selected: OverviewComplete, search: string, cursor: string): v is OverviewPage {
    if (!record(v, ['schemaVersion', 'deviceId', 'serverNow', 'section', 'binding', 'manifest', 'collectedAt', 'completedAt', 'retainedUntil', 'totalRows', 'items', 'scannedRows', 'exhausted', 'searchIncomplete', 'nextCursor', 'cursorExpiresAt']) || v.schemaVersion !== 'tracebolt.complete-overview-page.v1' || v.deviceId !== deviceId || v.section !== section || !timestamp(v.serverNow) || !binding(v.binding, section) || !same(v.binding, selected.binding) || !validOverviewManifest(v.manifest, section) || !same(v.manifest, selected.manifest) || v.collectedAt !== selected.manifest.collectedAt || v.completedAt !== selected.completedAt || v.retainedUntil !== selected.retainedUntil || v.totalRows !== selected.manifest.observedCount || !timestamp(v.cursorExpiresAt) || inventoryAge(v.serverNow, selected.completedAt) < 0 || inventoryAge(selected.retainedUntil, v.serverNow) <= 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) <= 0 || inventoryAge(selected.retainedUntil, v.cursorExpiresAt) < 0 || inventoryAge(v.cursorExpiresAt, v.serverNow) > 900000 || !Array.isArray(v.items) || v.items.length > OVERVIEW_PAGE_ROWS || !integer(v.scannedRows, Math.min(OVERVIEW_SCAN_ROWS, selected.manifest.observedCount)) || v.scannedRows < v.items.length || typeof v.exhausted !== 'boolean' || v.searchIncomplete !== (search.trim() !== '' && !v.exhausted) || typeof v.nextCursor !== 'string' || new TextEncoder().encode(v.nextCursor).byteLength > 1024 || (v.exhausted ? v.nextCursor !== '' : v.nextCursor === '' || v.nextCursor === cursor || v.scannedRows === 0)) return false;
    if (!search.trim() && v.items.length !== v.scannedRows) return false;
    let previous: OverviewRow | null = null; const ids = new Set<string | number>();
    for (const r of v.items) {
        if (!record(r, ['process', 'volume']) || !(section === 'processes' ? r.volume === null && validOverviewProcess(r.process) : r.process === null && validOverviewVolume(r.volume))) return false;
        const row = r as unknown as OverviewRow, id = row.process?.pid ?? row.volume!.id;
        if (ids.has(id) || previous && compareOverviewRows(previous, row) >= 0 || search.trim() && !overviewSearchLower(overviewSearchText(row)).includes(search.trim().toLowerCase())) return false;
        ids.add(id); previous = row;
    }
    return true;
}
export function overviewSectionVisible(view: OverviewView, section: OverviewSection, elapsed: number): boolean {
    const selected = view[section]; return Number.isFinite(elapsed) && elapsed >= 0 && selected.status === 'available' && selected.complete?.state === 'complete' && inventoryAge(selected.complete.retainedUntil, view.serverNow) > elapsed;
}
