import type { ApplicationCheck, ApplicationCheckV2, ApplicationChecksViewV2, DNSApplicationCheck, TCPApplicationCheck } from './application-checks-types';
import { applicationNow, applicationRow } from './application-checks-fixtures';

// Invented retained observations only. No hostname, address, port or target controls.
export function applicationHTTPRow(patch: Partial<ApplicationCheck> = {}): ApplicationCheck & { kind: 'http' } {
    return { ...applicationRow(patch), kind: 'http' };
}
export function applicationDNSRow(): Extract<DNSApplicationCheck, { state: 'ok' }> {
    return { kind: 'dns', id: 'fixture-dns', state: 'ok', reason: 'dns_resolved', observedAt: applicationNow };
}
export function applicationTCPRow(): Extract<TCPApplicationCheck, { state: 'ok' }> {
    return { kind: 'tcp', id: 'fixture-tcp', state: 'ok', reason: 'tcp_connected', observedAt: applicationNow };
}
export function applicationViewV2(items: ApplicationCheckV2[] = [applicationHTTPRow(), applicationDNSRow(), applicationTCPRow()]): ApplicationChecksViewV2 {
    return { schemaVersion: 'tracebolt.application-checks.v2', enabled: true, vantage: 'management_server', serverNow: applicationNow, intervalSeconds: 60, maxAgeSeconds: 60 + (items.length + 1) * 5, items };
}
export function disabledApplicationViewV2(): ApplicationChecksViewV2 {
    return { ...applicationViewV2([]), enabled: false, intervalSeconds: 0, maxAgeSeconds: 0 };
}
