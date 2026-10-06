/** Sanitized settings only. Destination credentials and complete URLs are never read back. */
export const ALARM_SETTINGS_BYTES = 4096;
export const ALARM_ENDPOINT_MAX = 4096;
export type AlarmTestState = 'queued' | 'in_flight' | 'provider_accepted' | 'failed' | 'uncertain' | 'suppressed';
export interface AlarmSettings {
    schemaVersion: 'tracebolt.alarm-settings.v1';
    mode: 'managed' | 'external' | 'unavailable';
    revision: string;
    configured: boolean;
    enabled: boolean;
    destinationHost: string;
    test: null | { eventId: string; state: AlarmTestState; createdAt: string };
    blocked: boolean;
}
export type AlarmSettingsChange = {
    expectedRevision: string;
    operation: 'replace' | 'enable' | 'disable';
    endpoint: string;
    payloadSharingAcknowledged: boolean;
    plaintextAcknowledged: boolean;
};
export type AlarmTestRequest = { expectedRevision: string; requestId: string; testAcknowledged: true };
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const host = (value: unknown): value is string => typeof value === 'string' && value.length <= 253 && (/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(value) || /^(?:\[[0-9a-fA-F:]{2,45}\]|[0-9a-fA-F]*:[0-9a-fA-F:]{1,44})$/.test(value));
export function validAlarmSettings(value: unknown): value is AlarmSettings {
    if (!object(value) || Object.keys(value).length !== 8 || value.schemaVersion !== 'tracebolt.alarm-settings.v1' || !['managed', 'external', 'unavailable'].includes(String(value.mode)) || (value.mode === 'managed' ? typeof value.revision !== 'string' || !/^[0-9a-f]{32}$/.test(value.revision) : value.revision !== '')) return false;
    if (typeof value.configured !== 'boolean' || typeof value.enabled !== 'boolean' || typeof value.blocked !== 'boolean') return false;
    if (value.configured ? !host(value.destinationHost) : value.destinationHost !== '' || value.enabled || value.test !== null) return false;
    if (value.blocked && value.enabled) return false;
    if (value.mode === 'unavailable' && (value.configured || value.enabled || value.blocked || value.test !== null)) return false;
    if (value.test === null) return true;
    if (!object(value.test) || Object.keys(value.test).length !== 3 || typeof value.test.eventId !== 'string' || !/^[0-9a-f]{64}$/.test(value.test.eventId) || !['queued', 'in_flight', 'provider_accepted', 'failed', 'uncertain', 'suppressed'].includes(String(value.test.state))) return false;
    return typeof value.test.createdAt === 'string' && value.test.createdAt.length <= 40 && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value.test.createdAt) && Number.isFinite(Date.parse(value.test.createdAt));
}
/** Preliminary syntax check only; public-address policy is enforced by the manager. */
export function validAlarmEndpoint(value: string): boolean {
    if (!value || value.length > ALARM_ENDPOINT_MAX || /[^\x21-\x7e]|[\\#]/.test(value)) return false;
    try {
        const url = new URL(value);
        const authority = /^https:\/\/([^/?#]+)/.exec(value)?.[1];
        return !!authority && authority === authority.toLowerCase() && !authority.includes('@') && !authority.endsWith(':') && url.protocol === 'https:' && !!url.hostname && !url.username && !url.password && !value.includes('#') && (url.port === '' || url.port === '443');
    } catch { return false; }
}
export function createAlarmTestRequestId(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
