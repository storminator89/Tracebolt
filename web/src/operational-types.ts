/** Bounded read-only DTOs for docs/operational/contract.md. No AI evidence inputs. */
export const OPERATIONAL_PROFILE = 'managed-operations-v1' as const;
export const OPERATIONAL_SCHEMA = 'tracebolt.linux-operational.v1' as const;
export const SECTION_LIMITS = { volumes: 32, network: 32, services: 128, processes: 64, software: 256, events: 64 } as const;
export const SECTION_NAMES = ['volumes', 'network', 'services', 'processes', 'software', 'events'] as const;
export type OperationalSectionName = typeof SECTION_NAMES[number];
export type OperationalQuality = 'healthy' | 'unknown' | 'denied' | 'stale';
export type OperationalReason = 'none' | 'source_missing' | 'permission_denied' | 'not_supported' | 'timeout' | 'invalid_source' | 'read_failed' | 'item_limit' | 'byte_limit' | 'remote_filesystem_skipped' | 'tool_unavailable' | 'not_implemented';
export interface OperationalMeta {
    quality: OperationalQuality; reason: OperationalReason; observedAt: string; generationId: string;
    complete: boolean; truncated: boolean; observedCount: number; countExact: boolean; itemLimit: number;
}
export interface OperationalSection<T> { meta: OperationalMeta; items: T[] }
export interface OperationalVolume {
    id: string; mountPoint: string; filesystem: string; kind: 'local' | 'remote' | 'virtual' | 'unknown';
    totalBytes: number | null; availableBytes: number | null; usedPercent: number | null;
    measurementQuality: OperationalQuality; measurementReason: OperationalReason;
}
export interface OperationalNetwork {
    name: string; state: 'up' | 'down' | 'unknown'; mtu: number | null;
    rxBytes: number | null; txBytes: number | null; rxErrors: number | null; txErrors: number | null;
    ipv4Count: number | null; ipv6Count: number | null;
}
export interface OperationalService {
    name: string; loadState: 'loaded' | 'not_found' | 'masked' | 'unknown';
    activeState: 'active' | 'inactive' | 'failed' | 'activating' | 'deactivating' | 'reloading' | 'unknown';
    subState: 'running' | 'exited' | 'dead' | 'failed' | 'other' | 'unknown';
}
export interface OperationalProcess {
    pid: number; parentPid: number | null; name: string; state: 'running' | 'sleeping' | 'stopped' | 'zombie' | 'idle' | 'unknown';
    rssBytes: number | null; cpuTimeSeconds: number | null; threads: number | null;
}
export interface OperationalSoftware { name: string; version: string; architecture: string; manager: 'dpkg' }
export interface OperationalEvent {
    source: 'systemd-journal' | 'agent'; unit: string; priority: number; messageId: string;
    count: number; firstSeen: string; lastSeen: string;
}
export interface OperationalItems {
    volumes: OperationalVolume; network: OperationalNetwork; services: OperationalService;
    processes: OperationalProcess; software: OperationalSoftware; events: OperationalEvent;
}
export type OperationalSections = { [K in OperationalSectionName]: OperationalSection<OperationalItems[K]> };
export interface OperationalSnapshot {
    schemaVersion: typeof OPERATIONAL_SCHEMA; collectionProfile: typeof OPERATIONAL_PROFILE;
    generationId: string; collectedAt: string; durationMs: number; sections: OperationalSections;
}
export type OperationalStatus = 'not_configured' | 'awaiting' | 'fresh' | 'stale' | 'revoked' | 'unavailable';
export interface OperationalView {
    schemaVersion: 'tracebolt.operational-view.v1'; deviceId: string; status: OperationalStatus;
    serverNow: string; receivedAt: string | null; sequence: number | null; maxAgeSeconds: number;
    snapshot: OperationalSnapshot | null;
    lastGood: { [K in OperationalSectionName]: OperationalSections[K] | null };
    assessments: { updates: { quality: 'unknown'; reason: 'not_implemented' }; vulnerabilities: { quality: 'unknown'; reason: 'not_implemented' } };
}

const qualities = ['healthy', 'unknown', 'denied', 'stale'];
const reasons = ['none', 'source_missing', 'permission_denied', 'not_supported', 'timeout', 'invalid_source', 'read_failed', 'item_limit', 'byte_limit', 'remote_filesystem_skipped', 'tool_unavailable', 'not_implemented'];
const encoder = new TextEncoder();
type RecordValue = Record<string, unknown>;
function record(value: unknown, keys: readonly string[]): value is RecordValue {
    return value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function text(value: unknown, limit: number, empty = false): value is string {
    // Reject lone surrogate code units rather than silently replacing invalid UTF-8.
    return typeof value === 'string' && (empty || value.length > 0) && value.length <= limit && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value) && encoder.encode(value).byteLength <= limit;
}
function member(value: unknown, choices: readonly string[]): boolean { return typeof value === 'string' && choices.includes(value); }
function number(value: unknown, integer = true): value is number { return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER && (!integer || Number.isSafeInteger(value)); }
function nullableNumber(value: unknown, integer = true): boolean { return value === null || number(value, integer); }
function timestamp(value: unknown): value is string {
    if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) || !Number.isFinite(Date.parse(value))) return false;
    return Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
}
function validMeta(value: unknown, section: OperationalSectionName, length: number): value is OperationalMeta {
    if (!record(value, ['quality', 'reason', 'observedAt', 'generationId', 'complete', 'truncated', 'observedCount', 'countExact', 'itemLimit'])) return false;
    if (!member(value.quality, qualities) || !member(value.reason, reasons) || !timestamp(value.observedAt) || typeof value.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(value.generationId) || typeof value.complete !== 'boolean' || typeof value.truncated !== 'boolean' || !number(value.observedCount) || typeof value.countExact !== 'boolean' || value.itemLimit !== SECTION_LIMITS[section]) return false;
    if (value.observedCount < length || (value.truncated && value.complete)) return false;
    if (value.complete && (!value.countExact || (section !== 'events' && value.observedCount !== length) || value.reason !== 'none')) return false;
    if ((!value.complete && value.reason === 'none') || (value.quality === 'denied' && value.reason !== 'permission_denied') || (['item_limit', 'byte_limit'].includes(value.reason as string) && !value.truncated)) return false;
    if ((value.quality === 'healthy' || value.quality === 'stale') && length === 0 && !value.complete) return false;
    if ((value.quality === 'unknown' || value.quality === 'denied') && (length !== 0 || value.complete || value.reason === 'none')) return false;
    return true;
}
const serviceUnit = /^[A-Za-z0-9:_.@\\-]+\.service$/;
const eventUnit = /^[A-Za-z0-9:_.@\\-]+\.(?:service|scope|socket|target|mount|automount|slice|timer|path|device|swap)$/;
function mountKind(filesystem: string): OperationalVolume['kind'] {
    if (['ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'f2fs', 'jfs', 'reiserfs', 'vfat', 'exfat', 'ntfs3', 'zfs', 'bcachefs', 'erofs', 'squashfs'].includes(filesystem)) return 'local';
    if (['nfs', 'nfs4', 'cifs', 'smb3', '9p', 'ceph', 'afs', 'coda', 'glusterfs'].includes(filesystem)) return 'remote';
    if (['proc', 'sysfs', 'tmpfs', 'devtmpfs', 'devpts', 'cgroup', 'cgroup2', 'overlay', 'nsfs', 'mqueue', 'hugetlbfs', 'securityfs', 'debugfs', 'tracefs', 'pstore', 'configfs', 'efivarfs', 'ramfs', 'autofs', 'binfmt_misc', 'fusectl'].includes(filesystem)) return 'virtual';
    return filesystem.startsWith('fuse') ? 'remote' : 'unknown';
}
function canonicalMount(path: string): boolean {
    return path === '/' || (path.startsWith('/') && path.split('/').slice(1).every(part => part !== '' && part !== '.' && part !== '..'));
}
/** Same Debian-policy grammar as the collector's assessment.ValidDebianVersion. */
function debianVersion(version: string): boolean {
    let remainder = version;
    const colon = remainder.indexOf(':');
    if (colon !== -1) {
        if (!/^[0-9]+$/.test(remainder.slice(0, colon))) return false;
        remainder = remainder.slice(colon + 1);
    }
    if (!/^[0-9]/.test(remainder)) return false;
    const hyphen = remainder.lastIndexOf('-');
    if (hyphen !== -1) {
        if (!/^[A-Za-z0-9.+~]+$/.test(remainder.slice(hyphen + 1))) return false;
        remainder = remainder.slice(0, hyphen);
    }
    return /^[A-Za-z0-9.+~:-]+$/.test(remainder);
}
/** Reconstruct original-quality sizes, including encoding/json's HTML/line escapes. */
function encodedBytes(value: unknown): number {
    const json = JSON.stringify(value, (key, field) => key === 'quality' && field === 'stale' ? 'healthy' : field).replace(/[<>&\u2028\u2029]/g, character => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`);
    return encoder.encode(json).byteLength;
}
const validators: { [K in OperationalSectionName]: (value: unknown) => boolean } = {
    volumes(value) {
        if (!record(value, ['id', 'mountPoint', 'filesystem', 'kind', 'totalBytes', 'availableBytes', 'usedPercent', 'measurementQuality', 'measurementReason']) || !text(value.id, 40) || !/^mount_[1-9][0-9]{0,9}$/.test(value.id) || Number(value.id.slice(6)) > 4294967295 || !text(value.mountPoint, 160) || !canonicalMount(value.mountPoint) || /^\/(?:home|run\/user)\/(?!\[redacted\](?:\/|$))/.test(value.mountPoint) || !text(value.filesystem, 32) || value.kind !== mountKind(value.filesystem) || !nullableNumber(value.totalBytes) || !nullableNumber(value.availableBytes) || !(value.usedPercent === null || (number(value.usedPercent, false) && value.usedPercent <= 100)) || !member(value.measurementQuality, ['healthy', 'unknown', 'denied']) || !member(value.measurementReason, reasons)) return false;
        if (value.measurementQuality === 'healthy') {
            if (value.measurementReason !== 'none' || value.kind !== 'local' || !number(value.totalBytes) || !number(value.availableBytes) || value.availableBytes > value.totalBytes) return false;
            return value.totalBytes === 0 ? value.usedPercent === null : typeof value.usedPercent === 'number' && Math.abs(value.usedPercent - (value.totalBytes - value.availableBytes) * 100 / value.totalBytes) <= 0.000001;
        }
        return value.measurementReason !== 'none' && value.totalBytes === null && value.availableBytes === null && value.usedPercent === null && (value.measurementQuality !== 'denied' || value.measurementReason === 'permission_denied');
    },
    network(value) {
        return record(value, ['name', 'state', 'mtu', 'rxBytes', 'txBytes', 'rxErrors', 'txErrors', 'ipv4Count', 'ipv6Count']) && text(value.name, 64) && /^[A-Za-z0-9_.:-]+$/.test(value.name) && value.name !== '.' && value.name !== '..' && member(value.state, ['up', 'down', 'unknown']) && ['mtu', 'rxBytes', 'txBytes', 'rxErrors', 'txErrors', 'ipv4Count', 'ipv6Count'].every(key => nullableNumber(value[key]));
    },
    services(value) {
        return record(value, ['name', 'loadState', 'activeState', 'subState']) && text(value.name, 128) && serviceUnit.test(value.name) && member(value.loadState, ['loaded', 'not_found', 'masked', 'unknown']) && member(value.activeState, ['active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'unknown']) && member(value.subState, ['running', 'exited', 'dead', 'failed', 'other', 'unknown']);
    },
    processes(value) {
        return record(value, ['pid', 'parentPid', 'name', 'state', 'rssBytes', 'cpuTimeSeconds', 'threads']) && number(value.pid) && value.pid > 0 && nullableNumber(value.parentPid) && text(value.name, 64) && !/[\/\\]/.test(value.name) && member(value.state, ['running', 'sleeping', 'stopped', 'zombie', 'idle', 'unknown']) && nullableNumber(value.rssBytes) && nullableNumber(value.cpuTimeSeconds, false) && nullableNumber(value.threads);
    },
    software(value) {
        return record(value, ['name', 'version', 'architecture', 'manager']) && text(value.name, 128) && /^[a-z0-9][a-z0-9+.-]*$/.test(value.name) && text(value.version, 192) && debianVersion(value.version) && text(value.architecture, 32) && /^[a-z0-9][a-z0-9-]*$/.test(value.architecture) && value.manager === 'dpkg';
    },
    events(value) {
        return record(value, ['source', 'unit', 'priority', 'messageId', 'count', 'firstSeen', 'lastSeen']) && member(value.source, ['systemd-journal', 'agent']) && text(value.unit, 128, true) && (value.unit === '' || eventUnit.test(value.unit)) && number(value.priority) && value.priority <= 7 && typeof value.messageId === 'string' && /^(?:[a-f0-9]{32})?$/.test(value.messageId) && number(value.count) && value.count > 0 && timestamp(value.firstSeen) && timestamp(value.lastSeen) && Date.parse(value.lastSeen) >= Date.parse(value.firstSeen) && Date.parse(value.lastSeen) - Date.parse(value.firstSeen) <= 15 * 60 * 1000;
    },
};
function validSection(value: unknown, name: OperationalSectionName): boolean {
    if (!record(value, ['meta', 'items']) || !Array.isArray(value.items) || value.items.length > SECTION_LIMITS[name] || !validMeta(value.meta, name, value.items.length) || !value.items.every(validators[name])) return false;
    const seen = new Set<string>();
    let eventCount = 0;
    for (const item of value.items as RecordValue[]) {
        const identity = name === 'volumes' ? item.id : name === 'processes' ? item.pid : name === 'software' ? JSON.stringify([item.name, item.architecture]) : name === 'events' ? JSON.stringify([item.source, item.unit, item.priority, item.messageId]) : item.name;
        if (seen.has(String(identity))) return false;
        seen.add(String(identity));
        if (value.meta.complete) {
            if (name === 'volumes' && item.measurementQuality !== 'healthy') return false;
            if (name === 'network' && (item.state === 'unknown' || ['mtu', 'rxBytes', 'txBytes', 'rxErrors', 'txErrors', 'ipv4Count', 'ipv6Count'].some(key => item[key] === null))) return false;
            if (name === 'services' && ['loadState', 'activeState', 'subState'].some(key => item[key] === 'unknown')) return false;
            if (name === 'processes' && (item.state === 'unknown' || ['parentPid', 'rssBytes', 'cpuTimeSeconds', 'threads'].some(key => item[key] === null))) return false;
        }
        if (name === 'events') {
            if (Date.parse(item.lastSeen as string) > Date.parse(value.meta.observedAt) || Date.parse(item.firstSeen as string) < Date.parse(value.meta.observedAt) - 15 * 60 * 1000) return false;
            eventCount += item.count as number;
            if (!Number.isSafeInteger(eventCount)) return false;
        }
    }
    if (name === 'events' && (eventCount > value.meta.observedCount || (value.meta.complete && eventCount !== value.meta.observedCount))) return false;
    return encodedBytes(value) <= 48 * 1024;
}
function validSnapshot(value: unknown): value is OperationalSnapshot {
    if (!record(value, ['schemaVersion', 'collectionProfile', 'generationId', 'collectedAt', 'durationMs', 'sections']) || value.schemaVersion !== OPERATIONAL_SCHEMA || value.collectionProfile !== OPERATIONAL_PROFILE || typeof value.generationId !== 'string' || !/^sample_[a-f0-9]{32}$/.test(value.generationId) || !timestamp(value.collectedAt) || !number(value.durationMs) || !record(value.sections, SECTION_NAMES)) return false;
    if (!SECTION_NAMES.every(name => validSection((value.sections as RecordValue)[name], name))) return false;
    const snapshot = value as unknown as OperationalSnapshot;
    if (!SECTION_NAMES.every(name => snapshot.sections[name].meta.observedAt === snapshot.collectedAt && snapshot.sections[name].meta.generationId === snapshot.generationId)) return false;
    return encodedBytes(value) <= 48 * 1024;
}
/** Fail closed: never expose partially validated, cross-device or expanded response data. */
export function validOperationalView(value: unknown, expectedDeviceId: string): value is OperationalView {
    if (!record(value, ['schemaVersion', 'deviceId', 'status', 'serverNow', 'receivedAt', 'sequence', 'maxAgeSeconds', 'snapshot', 'lastGood', 'assessments']) || value.schemaVersion !== 'tracebolt.operational-view.v1' || !text(value.deviceId, 128) || value.deviceId !== expectedDeviceId || !member(value.status, ['not_configured', 'awaiting', 'fresh', 'stale', 'revoked', 'unavailable']) || !timestamp(value.serverNow) || (value.receivedAt !== null && !timestamp(value.receivedAt)) || !nullableNumber(value.sequence) || value.sequence === 0 || !number(value.maxAgeSeconds) || value.maxAgeSeconds === 0 || (value.snapshot !== null && !validSnapshot(value.snapshot)) || !record(value.lastGood, SECTION_NAMES) || !record(value.assessments, ['updates', 'vulnerabilities'])) return false;
    if (!['updates', 'vulnerabilities'].every(key => {
        const assessment = (value.assessments as RecordValue)[key];
        return record(assessment, ['quality', 'reason']) && assessment.quality === 'unknown' && assessment.reason === 'not_implemented';
    })) return false;
    if (!SECTION_NAMES.every(name => {
        const section = (value.lastGood as RecordValue)[name];
        return section === null || (validSection(section, name) && ['healthy', 'stale'].includes((section as OperationalSections[typeof name]).meta.quality));
    })) return false;
    const view = value as unknown as OperationalView;
    if (view.snapshot && SECTION_NAMES.some(name => view.lastGood[name] !== null && Date.parse(view.lastGood[name]!.meta.observedAt) > Date.parse(view.snapshot!.collectedAt))) return false;
    if (view.status === 'fresh' && (!view.snapshot || !view.receivedAt || view.sequence === null)) return false;
    // Mirror the known per-device logical record, not the larger API envelope.
    // Global quota and any pruned/hidden original snapshot remain server-owned.
    if ((view.snapshot ? encodedBytes(view.snapshot) : 0) + encodedBytes({ lastGood: view.lastGood }) > 128 * 1024) return false;
    return true;
}
/** Elapsed time comes only from performance.now(); browser wall-clock changes are irrelevant. */
export function operationalNow(view: OperationalView, elapsedMs: number): number {
    return Date.parse(view.serverNow) + (Number.isFinite(elapsedMs) ? Math.max(0, elapsedMs) : 0);
}
export function effectiveOperationalStatus(view: OperationalView, elapsedMs: number): OperationalStatus {
    if (view.status !== 'fresh') return view.status;
    const now = operationalNow(view, elapsedMs);
    return !view.snapshot || !view.receivedAt || Date.parse(view.snapshot.collectedAt) > Date.parse(view.serverNow) || Date.parse(view.receivedAt) > Date.parse(view.serverNow) || now - Date.parse(view.snapshot.collectedAt) > view.maxAgeSeconds * 1000 || now - Date.parse(view.receivedAt) > view.maxAgeSeconds * 1000 ? 'stale' : 'fresh';
}
