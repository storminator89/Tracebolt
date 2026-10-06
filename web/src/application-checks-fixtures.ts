import type { ApplicationCheck, ApplicationChecksView } from './application-checks-types';
// Invented retained API data. These identifiers are never destinations or probes.
export const applicationNow = '2026-10-06T12:00:00Z';
export function applicationRow(patch: Partial<ApplicationCheck> = {}): ApplicationCheck {
    return { id: 'fixture-app', targetScheme: 'https', state: 'ok', reason: 'http_2xx', observedAt: applicationNow, httpStatus: 204, tls: { state: 'expiring', expiresAt: '2026-10-10T12:00:00Z' }, ...patch };
}
export function applicationView(items = [applicationRow()]): ApplicationChecksView {
    return { schemaVersion: 'tracebolt.application-checks.v1', enabled: true, vantage: 'management_server', serverNow: applicationNow, intervalSeconds: 60, maxAgeSeconds: 60 + (items.length + 1) * 5, items };
}
export function disabledApplicationView(): ApplicationChecksView { return { ...applicationView([]), enabled: false, intervalSeconds: 0, maxAgeSeconds: 0 }; }
