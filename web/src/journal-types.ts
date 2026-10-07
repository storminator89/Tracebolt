/** The journal is one bounded, immutable capture. These DTOs grant no local permission. */
export const JOURNAL_VIEW_BYTES = 16384;
export const JOURNAL_PAGE_BYTES = 65536;
export const JOURNAL_SEARCH_BYTES = 128;
export const JOURNAL_WARNING = 'Best-effort masking only. Messages may still contain credentials, personal data or other secrets; this output is not safe or anonymous.';
export interface JournalQuery { unit: string; start: string; end: string; maxPriority: number }
export interface JournalIdentity { id: string; sequence: string; queryDigest: string }
export interface JournalPolicyGeneration { revision: string; generation: string; policyDigest: string }
export interface JournalGenerationView { schemaVersion: 'tracebolt.journal-generation-view.v1' | 'tracebolt.journal-generation-view.v2'; policyEnabled?: boolean; serviceAuthorization?: 'exact-units' | 'all-system-services'; allowedUnits?: string[]; policyGeneration: JournalPolicyGeneration; sequence: string; observedAt: string; receivedAt: string; expiresAt: string; fresh: boolean }
export interface JournalDescription {
    schemaVersion: 'tracebolt.journal-request.v1' | 'tracebolt.journal-request.v2'; policyGeneration?: JournalPolicyGeneration; identity: JournalIdentity; deviceId: string; certificateHash: string;
    query: JournalQuery; budgets: { maxRows: number; maxSnapshotBytes: number; maxMessageBytes: number; maxRawBytes: number; maxLineBytes: number; maxScannedRows: number; timeoutMs: number };
    createdAt: string; expiresAt: string;
}
export interface JournalReceipt { identity: JournalIdentity; policyDigest: string; resultDigest: string; acceptedAt: string; expiresAt: string }
export interface JournalRequest { description: JournalDescription; state: 'pending' | 'claimed' | 'accepted' | 'canceled' | 'expired'; contentStatus: 'available' | 'unavailable'; receipt: JournalReceipt | null }
export interface JournalView {
    schemaVersion: 'tracebolt.journal-view.v1' | 'tracebolt.journal-view.v2'; generation?: JournalGenerationView; deviceId: string; serverNow: string; configured: boolean; expectedFloor: string;
    request: JournalRequest | null; localStatus: 'unknown' | 'checking' | 'disabled' | 'denied' | 'helper_unavailable' | 'result_lost'; contentStatus: 'available' | 'unavailable';
}
export interface JournalRow { timestamp: string; unit: string; priority: number; message: string }
export interface JournalPage {
    schemaVersion: 'tracebolt.journal-page.v1'; deviceId: string; serverNow: string; expiresAt: string; identity: JournalIdentity;
    snapshotDigest: string; scope: 'agent-visible-system-journal-service-and-manager'; query: JournalQuery; observedAt: string;
    coverage: 'complete' | 'partial' | 'failed'; reason: typeof journalReasons[number]; rows: JournalRow[]; observedCount: number; countExact: boolean;
    redactionApplied: boolean; redactionWarning: typeof JOURNAL_WARNING; totalCapturedRows: number; matchedRows: number;
    search: string; searchScope: 'captured_snapshot_only'; offset: number; nextOffset: number | null;
}
export const journalReasons = ['none', 'permission_denied', 'source_missing', 'invalid_source', 'read_failed', 'timeout', 'item_limit', 'byte_limit', 'visibility_restricted', 'not_supported', 'collector_busy'] as const;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const integer = (v: unknown, max = Number.MAX_SAFE_INTEGER): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max;
const member = (v: unknown, values: readonly string[]) => typeof v === 'string' && values.includes(v);
// Go strings.ToLower uses simple per-codepoint mapping, including dotted capital I.
export const journalFold = (v: string) => Array.from(v, ch => ch === '\u0130' ? 'i' : ch.toLowerCase()).join('');
export const journalBytes = (v: string) => new TextEncoder().encode(v).byteLength;
export function journalTime(v: unknown): v is string {
    return typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v)) && Number(v.slice(0, 4)) >= 1970 && new Date(Date.parse(v)).toISOString().slice(0, 19) === v.slice(0, 19);
}
// Keep the server's sub-millisecond ordering at expiry boundaries.
export function journalAge(now: string, then: string): number {
    const fraction = (s: string) => Number((s.includes('.') ? s.slice(20, -1) : '').padEnd(9, '0')) / 1e6;
    return Date.parse(now.slice(0, 19) + 'Z') - Date.parse(then.slice(0, 19) + 'Z') + fraction(now) - fraction(then);
}
export const validJournalDevice = (v: string) => /^agent_[A-Za-z0-9_-]{1,120}$/.test(v);
export function validJournalUnit(v: unknown): v is string {
    if (typeof v !== 'string' || journalBytes(v) > 255 || !/^[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service$/.test(v)) return false;
    const stem = v.slice(0, -8); return !stem.includes('..') && !stem.endsWith('@') && (stem.match(/@/g)?.length ?? 0) <= 1;
}
export function validJournalQuery(v: unknown, now: string): v is JournalQuery {
    if (!exact(v, ['unit', 'start', 'end', 'maxPriority']) || !validJournalUnit(v.unit) || !journalTime(v.start) || !journalTime(v.end) || !integer(v.maxPriority, 7)) return false;
    const micro = (s: string) => !s.includes('.') || s.slice(20, -1).padEnd(9, '0').endsWith('000');
    return micro(v.start) && micro(v.end) && journalAge(v.end, v.start) > 0 && journalAge(v.end, v.start) <= 3600000 && journalAge(now, v.end) >= 0 && journalAge(now, v.start) <= 86400000;
}
const digest = (v: unknown): v is string => typeof v === 'string' && /^sha256:[a-f0-9]{64}$/.test(v);
const sequence = (v: unknown): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
export function validJournalGeneration(v: unknown): v is JournalPolicyGeneration {
    return exact(v, ['revision', 'generation', 'policyDigest']) && sequence(v.revision) && v.revision !== '0' && typeof v.generation === 'string' && /^[a-f0-9]{64}$/.test(v.generation) && v.generation !== '0'.repeat(64) && digest(v.policyDigest) && v.policyDigest !== `sha256:${'0'.repeat(64)}`;
}
export const sameJournalGeneration = (a: JournalPolicyGeneration, b: JournalPolicyGeneration) => a.revision === b.revision && a.generation === b.generation && a.policyDigest === b.policyDigest;
export function sameJournalAuthorization(a: JournalGenerationView, b: JournalGenerationView): boolean {
    return a.schemaVersion === b.schemaVersion && a.policyEnabled === b.policyEnabled && a.serviceAuthorization === b.serviceAuthorization && JSON.stringify(a.allowedUnits) === JSON.stringify(b.allowedUnits);
}
export function validJournalGenerationView(v: unknown, now: string): v is JournalGenerationView {
    const v2 = record(v) && v.schemaVersion === 'tracebolt.journal-generation-view.v2';
    if (!exact(v, ['schemaVersion', 'policyGeneration', 'sequence', 'observedAt', 'receivedAt', 'expiresAt', 'fresh', ...(v2 ? ['policyEnabled', 'serviceAuthorization', 'allowedUnits'] : [])]) || !v2 && v.schemaVersion !== 'tracebolt.journal-generation-view.v1' || !validJournalGeneration(v.policyGeneration) || !sequence(v.sequence) || v.sequence === '0' || !journalTime(v.observedAt) || !journalTime(v.receivedAt) || !journalTime(v.expiresAt) || journalAge(v.receivedAt, v.observedAt) < 0 || journalAge(v.receivedAt, v.observedAt) >= 300000 || journalAge(now, v.receivedAt) < 0 || journalAge(v.expiresAt, v.observedAt) !== 300000 || typeof v.fresh !== 'boolean' || v.fresh && journalAge(v.expiresAt, now) <= 0) return false;
    if (!v2) return true;
    if (typeof v.policyEnabled !== 'boolean' || !Array.isArray(v.allowedUnits) || v.allowedUnits.length > 32) return false;
    if (v.serviceAuthorization === 'all-system-services') return v.allowedUnits.length === 0;
    return v.serviceAuthorization === 'exact-units' && v.allowedUnits.length > 0 && v.allowedUnits.every((unit: unknown, index: number, units: unknown[]) => validJournalUnit(unit) && (index === 0 || typeof units[index - 1] === 'string' && (units[index - 1] as string) < unit));
}
function identity(v: unknown): v is JournalIdentity { return exact(v, ['id', 'sequence', 'queryDigest']) && typeof v.id === 'string' && /^journal_[A-Za-z0-9_-]{1,120}$/.test(v.id) && sequence(v.sequence) && v.sequence !== '0' && digest(v.queryDigest); }
export const sameJournalIdentity = (a: JournalIdentity, b: JournalIdentity) => a.id === b.id && a.sequence === b.sequence && a.queryDigest === b.queryDigest;
const sameQuery = (a: JournalQuery, b: JournalQuery) => a.unit === b.unit && a.start === b.start && a.end === b.end && a.maxPriority === b.maxPriority;
function description(v: unknown, deviceId: string, now: string): v is JournalDescription {
    const v2 = record(v) && v.schemaVersion === 'tracebolt.journal-request.v2';
    if (!exact(v, ['schemaVersion', 'identity', 'deviceId', 'certificateHash', 'query', 'budgets', 'createdAt', 'expiresAt', ...(v2 ? ['policyGeneration'] : [])]) || (!v2 && v.schemaVersion !== 'tracebolt.journal-request.v1') || v2 && !validJournalGeneration(v.policyGeneration) || !identity(v.identity) || v.deviceId !== deviceId || typeof v.certificateHash !== 'string' || !/^[a-f0-9]{64}$/.test(v.certificateHash) || !journalTime(v.createdAt) || !journalTime(v.expiresAt) || journalAge(now, v.createdAt) < 0 || journalAge(v.expiresAt, v.createdAt) !== 900000 || !validJournalQuery(v.query, v.createdAt)) return false;
    const limits = { maxRows: 500, maxSnapshotBytes: 524288, maxMessageBytes: 4096, maxRawBytes: 8388608, maxLineBytes: 65536, maxScannedRows: 4096, timeoutMs: 4000 };
    return exact(v.budgets, Object.keys(limits)) && Object.entries(limits).every(([key, n]) => (v.budgets as Record<string, unknown>)[key] === n);
}
export function validJournalView(v: unknown, deviceId: string): v is JournalView {
    const v2 = record(v) && v.schemaVersion === 'tracebolt.journal-view.v2';
    if (!exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'configured', 'expectedFloor', 'request', 'localStatus', 'contentStatus', ...(v2 ? ['generation'] : [])]) || (!v2 && v.schemaVersion !== 'tracebolt.journal-view.v1') || !validJournalDevice(deviceId) || v.deviceId !== deviceId || !journalTime(v.serverNow) || typeof v.configured !== 'boolean' || !sequence(v.expectedFloor) || !member(v.localStatus, ['unknown', 'checking', 'disabled', 'denied', 'helper_unavailable', 'result_lost']) || !member(v.contentStatus, ['available', 'unavailable'])) return false;
    if (v2 && (!v.configured || !validJournalGenerationView(v.generation, v.serverNow))) return false;
    if (v.request === null) return v.contentStatus === 'unavailable' && v.expectedFloor === '0';
    if (!v.configured) return false;
    const r = v.request;
    if (!exact(r, ['description', 'state', 'contentStatus', 'receipt']) || !description(r.description, deviceId, v.serverNow) || r.description.identity.sequence !== v.expectedFloor || !member(r.state, ['pending', 'claimed', 'accepted', 'canceled', 'expired']) || r.contentStatus !== v.contentStatus) return false;
    if (!v2 && r.description.schemaVersion !== 'tracebolt.journal-request.v1') return false;
    if (v2 && r.description.policyGeneration && (BigInt(r.description.policyGeneration.revision) > BigInt((v.generation as JournalGenerationView).policyGeneration.revision) || r.description.policyGeneration.revision === (v.generation as JournalGenerationView).policyGeneration.revision && !sameJournalGeneration(r.description.policyGeneration, (v.generation as JournalGenerationView).policyGeneration))) return false;
    if (v2 && (r.state === 'pending' || r.state === 'claimed') && (!r.description.policyGeneration || !sameJournalGeneration(r.description.policyGeneration, (v.generation as JournalGenerationView).policyGeneration))) return false;
    if (r.receipt !== null) {
        const p = r.receipt;
        if (!exact(p, ['identity', 'policyDigest', 'resultDigest', 'acceptedAt', 'expiresAt']) || !identity(p.identity) || !sameJournalIdentity(p.identity, r.description.identity) || !digest(p.policyDigest) || !digest(p.resultDigest) || !journalTime(p.acceptedAt) || p.expiresAt !== r.description.expiresAt || journalAge(p.acceptedAt, r.description.createdAt) < 0 || journalAge(v.serverNow, p.acceptedAt) < 0 || journalAge(r.description.expiresAt, p.acceptedAt) <= 0) return false;
        if (r.description.policyGeneration && p.policyDigest !== r.description.policyGeneration.policyDigest) return false;
    }
    if (r.state === 'accepted' && r.receipt === null || (r.state === 'pending' || r.state === 'claimed') && r.receipt !== null) return false;
    if (v.contentStatus === 'available' && (!v.configured || r.state !== 'accepted' || r.receipt === null || journalAge(r.description.expiresAt, v.serverNow) <= 0)) return false;
    return !(r.state === 'pending' || r.state === 'claimed' || r.state === 'accepted') || journalAge(r.description.expiresAt, v.serverNow) > 0;
}
export function validJournalPage(v: unknown, view: JournalView, search: string, offset: number): v is JournalPage {
    const r = view.request;
    if (!r?.receipt || r.state !== 'accepted' || view.contentStatus !== 'available' || !exact(v, ['schemaVersion', 'deviceId', 'serverNow', 'expiresAt', 'identity', 'snapshotDigest', 'scope', 'query', 'observedAt', 'coverage', 'reason', 'rows', 'observedCount', 'countExact', 'redactionApplied', 'redactionWarning', 'totalCapturedRows', 'matchedRows', 'search', 'searchScope', 'offset', 'nextOffset']) || v.schemaVersion !== 'tracebolt.journal-page.v1' || v.deviceId !== view.deviceId || !journalTime(v.serverNow) || journalAge(v.serverNow, view.serverNow) < 0 || v.expiresAt !== r.description.expiresAt || journalAge(v.expiresAt, v.serverNow) <= 0 || !identity(v.identity) || !sameJournalIdentity(v.identity, r.description.identity) || v.snapshotDigest !== r.receipt.resultDigest || v.scope !== 'agent-visible-system-journal-service-and-manager' || !validJournalQuery(v.query, r.description.createdAt) || !sameQuery(v.query, r.description.query) || !journalTime(v.observedAt) || journalAge(v.serverNow, v.observedAt) < 0 || !member(v.coverage, ['complete', 'partial', 'failed']) || !member(v.reason, journalReasons) || !integer(v.observedCount, 4096) || typeof v.countExact !== 'boolean' || typeof v.redactionApplied !== 'boolean' || v.redactionWarning !== JOURNAL_WARNING || !integer(v.totalCapturedRows, 500) || !integer(v.matchedRows, v.totalCapturedRows) || v.observedCount < v.totalCapturedRows || v.search !== search || journalBytes(search) > JOURNAL_SEARCH_BYTES || v.searchScope !== 'captured_snapshot_only' || v.offset !== offset || !integer(v.offset, v.matchedRows) || !Array.isArray(v.rows) || v.rows.length > 100 || v.rows.length > v.matchedRows - offset) return false;
    if (!search && v.matchedRows !== v.totalCapturedRows || offset === v.matchedRows && offset !== 0) return false;
    const end = offset + v.rows.length;
    if (end < v.matchedRows ? v.rows.length === 0 || v.nextOffset !== end : v.nextOffset !== null) return false;
    if (v.coverage === 'complete' ? v.reason !== 'none' || !v.countExact || v.observedCount !== v.totalCapturedRows : v.reason === 'none' || v.countExact) return false;
    if (v.coverage === 'failed' && (v.totalCapturedRows !== 0 || v.observedCount !== 0 || v.redactionApplied)) return false;
    return v.rows.every(row => exact(row, ['timestamp', 'unit', 'priority', 'message']) && journalTime(row.timestamp) && journalAge(row.timestamp, r.description.query.start) >= 0 && journalAge(r.description.query.end, row.timestamp) >= 0 && row.unit === r.description.query.unit && integer(row.priority, r.description.query.maxPriority) && typeof row.message === 'string' && journalBytes(row.message) <= 4096);
}
