import { certificateExpiry } from './agent-certificate';
import { noReportTimestamp, reportTimestamp } from './report-time';
import type { CapabilityObservation, CapabilityState } from './capability-observations';
import type { Device } from './types';

export type ReportReadiness = 'unavailable' | 'not_collected' | 'unknown' | 'recent' | 'stale';
export type CertificateReadiness = 'unknown' | 'current' | 'expiring' | 'expired' | 'revoked';
export interface DeviceReadinessFacts {
    report: ReportReadiness;
    reportAgeSeconds: number | null;
    certificate: CertificateReadiness;
    checkedAt: string | null;
    counts: Partial<Record<CapabilityState, number>>;
}

/** Describes existing evidence, never readiness, permission or live reachability.
 * lastSeen is the accepted report's capture time, not its manager receipt time. */
export function deviceReadinessFacts(device: Device, observations: CapabilityObservation[], elapsed: number, available: boolean): DeviceReadinessFacts {
    const counts: DeviceReadinessFacts['counts'] = {};
    for (const { state } of observations) counts[state] = (counts[state] ?? 0) + 1;
    const result: DeviceReadinessFacts = { report: 'unavailable', reportAgeSeconds: null, certificate: 'unknown', checkedAt: null, counts };
    if (!available || device.source !== 'lan' || device.synthetic) return result;
    const cert = certificateExpiry(device.agentCertificate);
    const checked = cert.certificate?.checkedAt;
    const now = checked && Number.isFinite(elapsed) && elapsed >= 0 ? Date.parse(checked) + elapsed : NaN;
    if (Number.isFinite(now) && checked) {
        result.checkedAt = checked;
        const expiry = cert.certificate?.expiresAt;
        if (cert.certificate?.renewal?.status === 'revoked') result.certificate = 'revoked';
        else if (expiry) {
            const remaining = Date.parse(expiry) - now;
            result.certificate = remaining <= 0 ? 'expired' : remaining <= 48 * 3600000 ? 'expiring' : 'current';
        }
    }
    if (noReportTimestamp(device.lastSeen)) result.report = 'not_collected';
    else {
        const age = reportTimestamp(device.lastSeen) ? now - Date.parse(device.lastSeen) : NaN;
        if (!Number.isFinite(age) || age < 0) result.report = 'unknown';
        else {
            result.report = age <= 120000 ? 'recent' : 'stale';
            result.reportAgeSeconds = Math.floor(age / 1000);
        }
    }
    return result;
}
