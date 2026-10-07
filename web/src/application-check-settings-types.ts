/** Strict, bounded admin-only destination settings. Never use the public status schema here. */
export const APPLICATION_CHECK_SETTINGS_BYTES = 32768;
export const APPLICATION_CHECK_MAX_TARGETS = 8;
export type ApplicationTarget = {
    kind: 'http'; id: string; url: string; allowedAddresses: string[]; allowPrivateLAN: boolean; plaintextHTTPAcknowledged: boolean;
} | {
    kind: 'dns'; id: string; host: string; allowedAddresses: string[]; allowPrivateLAN: boolean;
} | {
    kind: 'tcp'; id: string; host: string; port: number; allowedAddresses: string[]; allowPrivateLAN: boolean;
};
export interface ApplicationCheckSettings {
    schemaVersion: 'tracebolt.application-check-settings.v1';
    mode: 'managed' | 'external' | 'unavailable';
    revision: string;
    configured: boolean;
    enabled: boolean;
    blocked: boolean;
    intervalSeconds: number;
    targets: ApplicationTarget[];
}
export type ApplicationCheckSettingsChange = { expectedRevision: string } & (
    { operation: 'save'; intervalSeconds: number; targets: ApplicationTarget[] } |
    { operation: 'enable'; checksFromManagerAcknowledged: true; destinationsAcknowledged: true; plaintextAcknowledged?: true } |
    { operation: 'disable' }
);
const exact = (value: unknown, keys: string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const integer = (value: unknown, min: number, max: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= min && value <= max;

/** Only canonical literals, with no ports, ranges, zones, mapped IPv4 or hostnames. */
export function exactApplicationIP(value: unknown): boolean {
    if (typeof value !== 'string' || value.length > 39) return false;
    if (/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) return value.split('.').every(part => Number(part) <= 255);
    if (!value.includes(':') || !/^[0-9a-f:]+$/.test(value)) return false;
    try {
        const host = new URL(`http://[${value}]/`).hostname;
        if (host !== `[${value}]` || value.startsWith('::ffff:')) return false;
        return true;
    } catch { return false; }
}
const ipv4 = (value: string) => value.split('.').reduce((number, part) => (number << 8) + Number(part), 0) >>> 0;
const inV4 = (value: string, prefix: string, bits: number) => (ipv4(value) >>> (32 - bits)) === (ipv4(prefix) >>> (32 - bits));
export function privateApplicationIP(value: string): boolean {
    return value.includes(':') ? /^(fc|fd)[0-9a-f]{2}:/.test(value) : inV4(value, '10.0.0.0', 8) || inV4(value, '172.16.0.0', 12) || inV4(value, '192.168.0.0', 16);
}
/** Mirrors the conservative destination exclusions; the server remains authoritative. */
function allowedIP(value: string, privateLAN: boolean): boolean {
    if (!exactApplicationIP(value)) return false;
    if (value.includes(':')) {
        if (value === 'fd00:ec2::254' || value === 'fd20:ce::254') return false;
        if (privateApplicationIP(value)) return privateLAN;
        const first = parseInt(value.split(':')[0], 16), second = parseInt(value.split(':')[1] || '0', 16);
        return first >= 0x2000 && first <= 0x3fff && !(first === 0x2001 && second <= 0x1ff) && !value.startsWith('2001:db8:') && first !== 0x2002 && !value.startsWith('2620:4f:8000:') && !(first === 0x3fff && second < 0x1000);
    }
    const excluded: [string, number][] = [['0.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['192.0.0.0',24],['192.0.2.0',24],['192.31.196.0',24],['192.52.193.0',24],['192.88.99.0',24],['192.175.48.0',24],['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4],['168.63.129.16',32]];
    return !excluded.some(([prefix, bits]) => inV4(value, prefix, bits)) && (!privateApplicationIP(value) || privateLAN);
}
export function validApplicationHost(value: unknown, literal: boolean): value is string {
    if (typeof value !== 'string' || value.length === 0 || value.length > 253) return false;
    if (exactApplicationIP(value)) return literal;
    return value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
export function validApplicationURL(value: unknown, plaintext: boolean): value is string {
    if (typeof value !== 'string' || !value || value.length > 1024 || /[^\x21-\x7e]|[\\%?#]/.test(value)) return false;
    const match = /^(https?):\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)(?::([0-9]+))?(\/.*)?$/.exec(value);
    if (!match || (match[1] === 'http') !== plaintext || !validApplicationHost(match[2].replace(/^\[|\]$/g, ''), true) || match[3] && (!/^[1-9][0-9]{0,4}$/.test(match[3]) || Number(match[3]) > 65535)) return false;
    const path = match[4] || '';
    return !/[<>"`{}|^]/.test(path) && !path.includes('//') && !path.split('/').some(part => part === '.' || part === '..');
}
export function validApplicationTarget(value: unknown): value is ApplicationTarget {
    if (!value || typeof value !== 'object' || !('kind' in value)) return false;
    const candidate = value as Record<string, unknown>;
    const keys = ['kind', 'id', 'allowedAddresses', 'allowPrivateLAN'];
    if (!exact(candidate, [...keys, ...(candidate.kind === 'http' ? ['url', 'plaintextHTTPAcknowledged'] : candidate.kind === 'dns' ? ['host'] : candidate.kind === 'tcp' ? ['host', 'port'] : ['unsupported'])])) return false;
    if (typeof candidate.id !== 'string' || !/^[a-z0-9_-]{1,48}$/.test(candidate.id) || typeof candidate.allowPrivateLAN !== 'boolean' || !Array.isArray(candidate.allowedAddresses) || candidate.allowedAddresses.length < 1 || candidate.allowedAddresses.length > 16 || new Set(candidate.allowedAddresses).size !== candidate.allowedAddresses.length || !candidate.allowedAddresses.every(ip => typeof ip === 'string' && allowedIP(ip, candidate.allowPrivateLAN as boolean))) return false;
    let host: string;
    if (candidate.kind === 'http') {
        if (typeof candidate.plaintextHTTPAcknowledged !== 'boolean' || !validApplicationURL(candidate.url, candidate.plaintextHTTPAcknowledged)) return false;
        // Preserve the exact Go-validated hostname; WHATWG URL rewrites numeric labels.
        host = /^https?:\/\/(\[[0-9a-f:]+\]|[a-z0-9.-]+)/.exec(candidate.url)![1].replace(/^\[|\]$/g, '');
    } else {
        if (!validApplicationHost(candidate.host, candidate.kind === 'tcp') || candidate.kind === 'tcp' && !integer(candidate.port, 1, 65535)) return false;
        host = candidate.host;
    }
    return !exactApplicationIP(host) || candidate.allowedAddresses.includes(host);
}
export function validApplicationCheckSettings(value: unknown): value is ApplicationCheckSettings {
    if (!exact(value, ['schemaVersion', 'mode', 'revision', 'configured', 'enabled', 'blocked', 'intervalSeconds', 'targets']) || value.schemaVersion !== 'tracebolt.application-check-settings.v1' || !['managed', 'external', 'unavailable'].includes(String(value.mode)) || typeof value.revision !== 'string' || (value.mode === 'managed' ? !/^[0-9a-f]{32}$/.test(value.revision) : value.revision !== '' && !/^[0-9a-f]{32}$/.test(value.revision))) return false;
    if (typeof value.configured !== 'boolean' || typeof value.enabled !== 'boolean' || typeof value.blocked !== 'boolean' || value.blocked && value.enabled || !integer(value.intervalSeconds, 60, 3600) || !Array.isArray(value.targets) || value.targets.length > APPLICATION_CHECK_MAX_TARGETS || !value.targets.every(validApplicationTarget) || new Set(value.targets.map(target => target.id)).size !== value.targets.length) return false;
    if (value.configured !== (value.targets.length > 0) || !value.configured && (value.enabled || value.intervalSeconds !== 60)) return false;
    return value.mode !== 'unavailable' || !value.configured && !value.enabled && !value.blocked;
}
export const sameApplicationTargets = (first: ApplicationTarget[], second: ApplicationTarget[]) => first.length === second.length && first.every((target, index) => {
    const other = second[index];
    return target.kind === other.kind && target.id === other.id && target.allowPrivateLAN === other.allowPrivateLAN && target.allowedAddresses.length === other.allowedAddresses.length && target.allowedAddresses.every((ip, i) => ip === other.allowedAddresses[i]) && (target.kind === 'http' && other.kind === 'http' ? target.url === other.url && target.plaintextHTTPAcknowledged === other.plaintextHTTPAcknowledged : target.kind === 'dns' && other.kind === 'dns' ? target.host === other.host : target.kind === 'tcp' && other.kind === 'tcp' && target.host === other.host && target.port === other.port);
});
