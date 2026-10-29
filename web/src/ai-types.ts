import { t } from './i18n';
import type { Evidence } from './types';
export interface AIConfig {
    revision: string;
    configured: boolean;
    provider: string;
    baseURL: string;
    endpointOrigin: string;
    model: string;
    keyConfigured: boolean;
    useLegacyMaxTokens: boolean;
    allowRemoteEvidence: boolean;
    /** Present only for an active, explicitly approved process-memory-only LAN destination. */
    lanMode?: boolean;
    /** Public fingerprint of the active process-memory private LAN CA, if any. */
    lanPrivateCaSha256?: string;
    storage: 'memory-only' | 'protected-file';
    /** Absent on older managers: never infer permission to persist. */
    persistenceAvailable?: boolean;
    persistentKeyAllowed?: boolean;
    resetsOnRestart: boolean;
    busy: boolean;
    limitations: string[];
}
/** Reject ambiguous storage/capability readbacks before offering a write. */
export function validAIConfig(value: unknown): value is AIConfig {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const config = value as Record<string, unknown>;
    if (typeof config.revision !== 'string' || !config.revision || typeof config.baseURL !== 'string' || typeof config.model !== 'string' || typeof config.configured !== 'boolean') return false;
    if (['keyConfigured', 'useLegacyMaxTokens', 'allowRemoteEvidence', 'busy'].some(key => typeof config[key] !== 'boolean')) return false;
    if (config.lanMode !== undefined && config.lanMode !== true) return false;
    if (config.lanPrivateCaSha256 !== undefined && (config.lanMode !== true || typeof config.lanPrivateCaSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(config.lanPrivateCaSha256) || 'caPem' in config || 'apiKey' in config)) return false;
    if (config.lanMode === true && (config.configured !== true || config.storage !== 'memory-only' || config.allowRemoteEvidence !== true || typeof config.endpointOrigin !== 'string' || !endpointInfo(config.baseURL as string).lan || endpointInfo(config.baseURL as string).origin !== config.endpointOrigin)) return false;
    if (config.persistenceAvailable !== undefined && typeof config.persistenceAvailable !== 'boolean' || config.persistentKeyAllowed !== undefined && typeof config.persistentKeyAllowed !== 'boolean') return false;
    if (config.persistentKeyAllowed === true && config.persistenceAvailable !== true) return false;
    if (config.storage === 'memory-only') return config.resetsOnRestart === true;
    return config.storage === 'protected-file' && config.resetsOnRestart === false && config.configured === true && config.persistenceAvailable === true;
}
export interface Provenance {
    method: string;
    provider: string;
    model: string;
    promptVersion: string;
    runbookVersion: string;
    ruleId: string;
    packetSHA256: string;
    destination: string;
    endpointOrigin: string;
}
export interface Claim {
    statement: string;
    evidenceIDs: string[];
}
export interface Findings {
    observedEvidenceIDs: string[];
    hypotheses: Claim[];
    counterevidence: Claim[];
    missingData: string[];
    nextCheck: string;
}
export interface AnalysisResult {
    schemaVersion: string;
    id: string;
    fingerprint: string;
    generatedAt: string;
    configRevision: string;
    superseded: boolean;
    packet: {
        case: {
            id: string;
            title: string;
            summary: string;
            synthetic: boolean;
        };
        evidence: Evidence[];
        missingEvidenceIDs: string[];
        observationWindow: {
            from: string | null;
            to: string | null;
        };
        gaps: {
            code: string;
            evidenceIDs: string[];
            detail: string;
        }[];
    };
    baseline: {
        summary: string;
        evidenceIDs: string[];
        nextCheck: string;
        nextSteps: string[];
        provenance: Provenance;
    };
    ai: {
        status: 'not_configured' | 'completed' | 'canceled' | 'timeout' | 'busy' | 'invalid_response' | 'unavailable';
        reason: string;
        findings: Findings | null;
        nextSteps: string[];
        provenance: Provenance;
    };
    rootCauseConfirmed: false;
    limitations: string[];
}
export interface EndpointInfo {
    valid: boolean;
    origin: string;
    local: boolean;
    lan: boolean;
    error: string;
}
/** UX validation only. The server independently validates origin, DNS and transport. */
export function endpointInfo(value: string): EndpointInfo {
    const fail = (error: string): EndpointInfo => ({ valid: false, origin: '', local: false, lan: false, error });
    try {
        if (!value || value.length > 512 || value.trim() !== value || /[\\%\r\n\t?#]/.test(value))
            return fail(t("Eine vollst\u00E4ndige Basis-URL ohne Abfrage oder Fragment eingeben."));
        const url = new URL(value);
        const prefix = value.match(/^(https?):\/\/([^/]+)/);
        if (!prefix || url.username || url.password || !url.hostname || prefix[2] !== prefix[2].toLowerCase())
            return fail(t("Eine g\u00FCltige http- oder https-URL ohne Zugangsdaten eingeben."));
        const local = /^(127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(prefix[2]);
        const literal = prefix[2].match(/^(\d+\.\d+\.\d+\.\d+)(?::(\d*))?$/);
        const octets = literal?.[1].split('.').map(Number);
        const privateIPv4 = !!octets && octets.length === 4 && (octets[0] === 10 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31 || octets[0] === 192 && octets[1] === 168);
        let lan = false;
        if (privateIPv4) {
            const parts = literal![1].split('.');
            const port = literal![2];
            if (url.protocol !== 'https:' || !port || !/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535 || parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255))
                return fail(t('Für ein privates LAN-Ziel sind HTTPS, eine eindeutige IPv4-Adresse und ein expliziter Port erforderlich.'));
            lan = true;
        }
        if (!local && url.protocol !== 'https:')
            return fail(t("HTTP ist nur f\u00FCr 127.0.0.1 oder [::1] erlaubt. Andere Anbieter ben\u00F6tigen HTTPS."));
        if (!local && !url.hostname.includes('.'))
            return fail(t("Lokale Anbieter als 127.0.0.1 oder [::1] angeben."));
        return { valid: true, origin: `${prefix[1]}://${prefix[2]}`, local, lan, error: '' };
    }
    catch {
        return fail(t("Eine g\u00FCltige Basis-URL eingeben."));
    }
}
export function safeAIError(error: unknown, secret = ''): string { const message = error instanceof Error ? error.message : t("Die Anfrage konnte nicht abgeschlossen werden."); return secret ? message.split(secret).join(t("[Schl\u00FCssel entfernt]")) : message; }
