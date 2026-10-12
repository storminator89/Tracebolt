import { validWindowsCapacityDeviceId, validWindowsCapacityThreshold, validWindowsCapacityTimestamp } from './windows-capacity-types';
import type { WindowsCapacityPolicy, WindowsPercentageMetric } from './windows-capacity-types';
import type { GroupHealthSetting } from './fleet-groups-workflow';

export type GroupMonitoringTarget = {
    deviceId: string; name: string; metric: WindowsPercentageMetric; assignmentRevision: number;
    policy: WindowsCapacityPolicy; desired: Omit<GroupHealthSetting, 'metric'> | null;
    status: 'manual' | 'pending' | 'inherited' | 'manual-override' | 'stopped' | 'conflict';
    owned: boolean; certificateExpiresAt: string;
};
export type GroupMonitoringView = {
    schemaVersion: 'tracebolt.fleet-group-monitoring.v1'; serverNow: string; groupId: string;
    groupRevision: number; revision: number; definitions: GroupHealthSetting[];
    targets: GroupMonitoringTarget[]; unavailableAssignments: number;
};
export type GroupMonitoringWrite = {
    expectedGroupRevision: number; expectedRevision: number; consent: boolean;
    definitions: GroupHealthSetting[];
    assignments: { deviceId: string; metric: WindowsPercentageMetric; expectedRevision: number; expectedPolicyRevision: number; inherit: boolean }[];
};
export type GroupMonitoringIO = { active: () => boolean; get: () => Promise<GroupMonitoringView>; post: (body: GroupMonitoringWrite) => Promise<GroupMonitoringView> };
export const groupMonitoringMetrics: WindowsPercentageMetric[] = ['disk', 'cpu', 'memory'];
export const groupMonitoringKey = (target: Pick<GroupMonitoringTarget, 'deviceId' | 'metric'>) => `${target.deviceId}:${target.metric}`;
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const revision = (v: unknown, minimum = 0): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= minimum;
const setting = (v: unknown): boolean => exact(v, ['enabled', 'thresholdPercent']) && typeof v.enabled === 'boolean' && validWindowsCapacityThreshold(v.thresholdPercent);
export function validGroupMonitoringView(v: unknown, groupId: string): v is GroupMonitoringView {
    if (!exact(v, ['schemaVersion', 'serverNow', 'groupId', 'groupRevision', 'revision', 'definitions', 'targets', 'unavailableAssignments']) || v.schemaVersion !== 'tracebolt.fleet-group-monitoring.v1' || v.groupId !== groupId || !/^group_[a-f0-9]{32}$/.test(groupId) || groupId === `group_${'0'.repeat(32)}` || !validWindowsCapacityTimestamp(v.serverNow) || !revision(v.groupRevision, 1) || !revision(v.revision) || !revision(v.unavailableAssignments) || v.unavailableAssignments > 75 || !Array.isArray(v.definitions) || v.definitions.length > 3 || !Array.isArray(v.targets) || v.targets.length > 75) return false;
    if (!v.definitions.every(d => exact(d, ['metric', 'enabled', 'thresholdPercent']) && groupMonitoringMetrics.includes(d.metric as WindowsPercentageMetric) && typeof d.enabled === 'boolean' && validWindowsCapacityThreshold(d.thresholdPercent)) || new Set(v.definitions.map(d => d.metric)).size !== v.definitions.length) return false;
    if (!v.targets.every(t => exact(t, ['deviceId', 'name', 'metric', 'assignmentRevision', 'policy', 'desired', 'status', 'owned', 'certificateExpiresAt']) && typeof t.deviceId === 'string' && validWindowsCapacityDeviceId(t.deviceId) && typeof t.name === 'string' && t.name.length > 0 && new TextEncoder().encode(t.name).length <= 256 && groupMonitoringMetrics.includes(t.metric as WindowsPercentageMetric) && revision(t.assignmentRevision) && exact(t.policy, ['enabled', 'thresholdPercent', 'revision']) && typeof t.policy.enabled === 'boolean' && validWindowsCapacityThreshold(t.policy.thresholdPercent) && revision(t.policy.revision) && (t.desired === null || setting(t.desired)) && typeof t.status === 'string' && ['manual', 'pending', 'inherited', 'manual-override', 'stopped', 'conflict'].includes(t.status) && typeof t.owned === 'boolean' && validWindowsCapacityTimestamp(t.certificateExpiresAt) && Date.parse(t.certificateExpiresAt) > Date.parse(v.serverNow as string))) return false;
    const targets = v.targets as GroupMonitoringTarget[];
    if (new Set(targets.map(groupMonitoringKey)).size !== targets.length) return false;
    const ids = new Set(targets.map(t => t.deviceId));
    return [...ids].every(id => { const rows = targets.filter(t => t.deviceId === id); return rows.length === 3 && rows.every(t => t.name === rows[0].name && t.certificateExpiresAt === rows[0].certificateExpiresAt); });
}
