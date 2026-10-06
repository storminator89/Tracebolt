/** Local notification only; listeners re-read status and never trust event data. */
export const ALARM_DELIVERY_CHANGED_EVENT = 'tracebolt:alarm-delivery-changed';
/** The existing read-only aggregate contract; no event or destination data. */
export const ALARM_STATUS_BYTES = 4096;
const counts = ['queued', 'inFlight', 'providerAccepted', 'failed', 'uncertain', 'suppressed', 'dropped'] as const;
export type AlarmStatus = {
    schemaVersion: 'tracebolt.alarm-status.v1';
    enabled: boolean;
} & Record<typeof counts[number], number>;
export function validAlarmStatus(value: unknown): value is AlarmStatus {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const data = value as Record<string, unknown>;
    if (Object.keys(data).length !== 9 || data.schemaVersion !== 'tracebolt.alarm-status.v1' || typeof data.enabled !== 'boolean') return false;
    if (!counts.every(key => typeof data[key] === 'number' && Number.isSafeInteger(data[key]) && (data[key] as number) >= 0)) return false;
    const status = data as AlarmStatus;
    // Dropped is a separate durable gap counter, not a retained outbox state.
    return status.queued + status.inFlight <= 500 && counts.filter(key => key !== 'dropped').reduce((sum, key) => sum + status[key], 0) <= 1000;
}
