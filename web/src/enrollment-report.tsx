import type { Device } from './types';
import type { EnrollmentSnapshot } from './enrollment-types';
import { deadlinePassed, terminal } from './enrollment-types';
import { certificateExpiry } from './agent-certificate';
import { ReportTime, noReportTimestamp, reportTimestamp } from './report-time';
import { useLocale } from './i18n';

export function matchingReportDevice(devices: Device[] | undefined, id: string): Device | undefined {
    const matches = devices?.filter(device => device.id === id);
    return matches?.length === 1 ? matches[0] : undefined;
}

/** Read-only display evidence. Never use this to authorize an enrollment action. */
export function enrollmentReportIdentity(item: EnrollmentSnapshot, device: Device | undefined, now: number | null) {
    const matching = device?.id === item.approval.deviceID && device.source === 'lan' && !device.synthetic ? device : undefined;
    const identity = Array.isArray(matching?.capabilities) ? matching.capabilities.filter(capability => capability?.id === 'agent_identity') : [];
    const certificate = certificateExpiry(matching?.agentCertificate);
    const value = certificate.certificate;
    const checked = value?.source === 'guided-enrollment' && now !== null && Number.isFinite(now) && Date.parse(value.checkedAt) <= now;
    const currentExpiry = value?.expiresAt ? Date.parse(value.expiresAt) : null;
    const anchorExpiry = item.intent.notAfter > 0 ? item.intent.notAfter * 1000 : null;
    // The activated snapshot retains its original identity anchor. A later leaf
    // needs validated renewal/generation evidence; an arbitrary later date is not renewal.
    const renewed = item.state === 'activated' && value?.renewal && value.renewal.credentialGeneration >= 2 && anchorExpiry !== null && currentExpiry !== null && currentExpiry > anchorExpiry;
    const currentLeaf = Boolean(checked && currentExpiry !== null && (currentExpiry === anchorExpiry || renewed));
    const expired = item.state === 'expired' || item.state !== 'activated' && deadlinePassed(item, now) || currentLeaf && now !== null && currentExpiry !== null && currentExpiry <= now;
    const denied = terminal(item.state) || identity.some(capability => capability.status === 'denied') || checked && value?.renewal?.status === 'revoked';
    const admitted = Boolean(matching && identity.length === 1 && identity[0].status === 'supported' && currentLeaf && !expired && !denied && value?.renewal?.status !== 'expired' && (certificate.state === 'current' || certificate.state === 'expiring'));
    return { matching, currentLeaf, currentExpiry: currentLeaf ? value!.expiresAt : null, expired: Boolean(expired), denied: Boolean(denied), admitted };
}

export function activatedEnrollmentDisplay(item: EnrollmentSnapshot, device: Device | undefined, now: number | null, available: boolean): 'activated' | 'expired' | 'denied' | 'unavailable' {
    const identity = enrollmentReportIdentity(item, device, now);
    return !available || now === null || !Number.isFinite(now) ? 'unavailable' : identity.expired ? 'expired' : identity.denied ? 'denied' : identity.admitted ? 'activated' : 'unavailable';
}

export function EnrollmentReport({ item, device, now, available }: { item: EnrollmentSnapshot; device?: Device; now: number | null; available: boolean }) {
    const [locale] = useLocale();
    if (!item.approval.deviceID) return null;
    const c = locale === 'de' ? { title: 'Meldung', unknown: 'Meldungsstatus nicht verfügbar', expired: 'Identität abgelaufen', denied: 'Identität nicht zugelassen', pending: 'Aktivierung ausstehend', waiting: 'Warte auf erste Meldung', recorded: 'Letzte Meldung', scope: 'Erfasste Meldungen bestätigen keine aktuelle Erreichbarkeit. Fehlende Messwerte sind kein Beleg für eine fehlende Meldung.' } : { title: 'Report', unknown: 'Report status unavailable', expired: 'Identity expired', denied: 'Identity not admitted', pending: 'Activation pending', waiting: 'Waiting for first report', recorded: 'Last report', scope: 'Recorded reports do not confirm current reachability. Missing measurements do not prove that no report was received.' };
    const { matching, expired, denied, admitted } = enrollmentReportIdentity(item, device, now);
    const recorded = matching && reportTimestamp(matching.lastSeen);
    const zero = matching && noReportTimestamp(matching.lastSeen);
    // Missing, foreign and duplicate device matches are unavailable, not a zero
    // timestamp. Historical timestamps remain visible independently of admission.
    const status = !available || now === null || !Number.isFinite(now) ? c.unknown
        : expired ? c.expired
        : denied ? c.denied
        : !matching || !recorded && !zero ? c.unknown
        : recorded ? c.recorded
        : ['approved', 'issuance_intent', 'issued'].includes(item.state) ? c.pending
        : item.state === 'activated' && zero && admitted ? c.waiting
        : c.unknown;
    return <div className="enrollment-message" role="status" aria-label={c.title}><div><strong>{status}</strong>{recorded && <> · <ReportTime device={matching} full/></>}<details><summary>{locale === 'de' ? 'Hinweise zur Meldung' : 'About this report'}</summary>{c.scope}</details></div></div>;
}
