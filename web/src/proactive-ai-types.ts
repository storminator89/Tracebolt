import { endpointInfo } from './ai-types';

export const PROACTIVE_SETTINGS_BYTES = 16384;
export interface ProactiveAISettings {
    schemaVersion: 'tracebolt.proactive-ai-settings.v1';
    revision: string;
    enabled: boolean;
    configRevision: string;
    providerConfigured: boolean;
    baseURL: string;
    model: string;
    deviceIds: string[];
    availableDevices: { id: string }[];
    dataScope: 'health-summary-v1';
    logsAllowed: false;
    resetsOnRestart: boolean;
    maxAnalysesPerHour: 6;
    cooldownMinutes: 30;
    minIntervalSeconds: 60;
    reason: string;
}
export interface ProactiveAIChange {
    expectedRevision: string;
    configRevision: string;
    enabled: boolean;
    deviceIds: string[];
    approvedBaseURL: string;
    approvedModel: string;
    dataScope: 'health-summary-v1';
    acknowledgeData: boolean;
}
const object = (value: unknown): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value);
const deviceID = (value: unknown): value is string => typeof value === 'string' && /^agent_[a-f0-9]{32}$/.test(value);
const revision = (value: unknown): value is string => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(value);
export function validProactiveAISettings(value: unknown): value is ProactiveAISettings {
    const keys = ['schemaVersion', 'revision', 'enabled', 'configRevision', 'providerConfigured', 'baseURL', 'model', 'deviceIds', 'availableDevices', 'dataScope', 'logsAllowed', 'resetsOnRestart', 'maxAnalysesPerHour', 'cooldownMinutes', 'minIntervalSeconds', 'reason'];
    if (!object(value) || Object.keys(value).length !== keys.length || !keys.every(key => Object.hasOwn(value, key)) || value.schemaVersion !== 'tracebolt.proactive-ai-settings.v1' || !revision(value.revision) || !revision(value.configRevision)) return false;
    if (typeof value.enabled !== 'boolean' || typeof value.providerConfigured !== 'boolean' || typeof value.baseURL !== 'string' || value.baseURL.length > 512 || typeof value.model !== 'string' || value.model.length > 128) return false;
    if (value.providerConfigured && (!endpointInfo(value.baseURL).valid || !/^[\x21-\x7e]+$/.test(value.model))) return false;
    if (value.dataScope !== 'health-summary-v1' || value.logsAllowed !== false || typeof value.resetsOnRestart !== 'boolean' || value.maxAnalysesPerHour !== 6 || value.cooldownMinutes !== 30 || value.minIntervalSeconds !== 60 || typeof value.reason !== 'string' || value.reason.length > 512) return false;
    if (!Array.isArray(value.deviceIds) || value.deviceIds.length > 25 || !value.deviceIds.every(deviceID) || new Set(value.deviceIds).size !== value.deviceIds.length) return false;
    if (!Array.isArray(value.availableDevices) || value.availableDevices.length > 25 || !value.availableDevices.every(item => object(item) && Object.keys(item).length === 1 && deviceID(item.id))) return false;
    const available = new Set(value.availableDevices.map(item => item.id));
    return available.size === value.availableDevices.length && (!value.enabled || value.providerConfigured && value.deviceIds.length > 0);
}
