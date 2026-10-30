/** Go recorder bytes with one uniform display-clock translation. Source-only evidence. */
import wire from './windows-complete-service-review-go-fixture.json';
import { validWindowsCompleteServiceIncidentReview } from './windows-complete-service-incident-review-types';
import type { WindowsCompleteServiceIncidentReviewView } from './windows-complete-service-incident-review-types';
export type CompleteServiceReviewScene = keyof typeof wire;
export const completeServiceReviewNow = wire.matched.serverNow;
export function completeServiceReviewFixture(scene: CompleteServiceReviewScene = 'matched', now?: string): WindowsCompleteServiceIncidentReviewView {
    const original = wire[scene];
    const delta = now === undefined ? 0 : Date.parse(now) - Date.parse(original.serverNow);
    if (!Number.isFinite(delta)) throw new Error('Invalid fixture display clock');
    const shift = (value: unknown): unknown => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(value) && now !== undefined ? new Date(Date.parse(value) + delta).toISOString() : Array.isArray(value) ? value.map(shift) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, shift(item)])) : value;
    const value = shift(structuredClone(original));
    if (!validWindowsCompleteServiceIncidentReview(value, original.incident.key, original.incident.deviceId, original.incident.serviceName)) throw new Error('Invalid Go complete-service review fixture');
    return value;
}
