import type { ReactNode } from 'react';
import { ArrowRight, Clock3, Download, HardDrive, Info, MemoryStick, Radio, ShieldAlert, Terminal } from 'lucide-react';
import { useLocale } from './i18n';
import { MetricValue } from './components';
import { certificateExpiry } from './agent-certificate';
import { useHealth } from './health';
import { useCompleteUpdates } from './complete-updates-resource';
import { completeUpdatesGenerationVisible, completeUpdatesTransferExpired } from './complete-updates-types';
import { inventoryAge } from './complete-packages-types';
import { fullDate, relativeTime } from './utils';
import type { Device } from './types';
import './device-essentials.css';

const copy = {
    en: { contact: 'Last report', contactScope: 'Last accepted report', contactLimit: 'Live reachability is not checked.', interpretation: 'About these values', warningScope: 'Warnings cover the selected checks only. Unknown checks are not a healthy result.', updateScope: 'Candidates come from the existing APT cache. They are not a live update check, an installability assessment or a security assessment.', warnings: 'Warnings', updates: 'Updates', unknown: 'Unknown', reading: 'Checking…', scope: 'Selected checks', open: 'open', pending: 'pending', unknownChecks: 'unknown', maintenance: 'Maintenance active', review: 'Review checks', candidates: 'cached candidates', partial: 'Partial comparison', unknownComparisons: 'comparisons unknown', held: 'held', stale: 'Cache is stale', freshness: 'Cache freshness unknown', age: 'Observed', minutes: 'min ago', unavailable: 'No current report', expired: 'Report expired', revoked: 'Device revoked', transferFailed: 'Newer transfer failed', failed: 'Latest collection failed', transfer: 'Newer transfer incomplete', transferExpired: 'Newer transfer expired', viewUpdates: 'View updates', details: 'Device details', resources: 'Resources', memory: 'Memory', disk: 'Disk', sources: 'Sources & details', certificate: 'Certificate', expiryUnknown: 'Expiry unknown', expiring: 'Expires within 48 hours', expiredCertificate: 'Expired', certificateCheck: 'At manager check' },
    de: { contact: 'Letzte Meldung', contactScope: 'Letzte akzeptierte Meldung', contactLimit: 'Aktuelle Erreichbarkeit wird nicht geprüft.', interpretation: 'Hinweise zu den Werten', warningScope: 'Warnungen beziehen sich nur auf die ausgewählten Prüfungen. Unbekannte Prüfungen bedeuten keinen gesunden Zustand.', updateScope: 'Kandidaten stammen aus dem vorhandenen APT-Cache. Sie sind weder eine aktuelle Updateprüfung noch eine Installierbarkeits- oder Sicherheitsbewertung.', warnings: 'Warnungen', updates: 'Updates', unknown: 'Unbekannt', reading: 'Wird geprüft …', scope: 'Ausgewählte Prüfungen', open: 'offen', pending: 'ausstehend', unknownChecks: 'unbekannt', maintenance: 'Wartung aktiv', review: 'Prüfungen öffnen', candidates: 'Cache-Kandidaten', partial: 'Teilweise verglichen', unknownComparisons: 'Vergleiche unbekannt', held: 'zurückgehalten', stale: 'Cache ist veraltet', freshness: 'Cache-Aktualität unbekannt', age: 'Erfasst vor', minutes: 'Min.', unavailable: 'Kein aktueller Bericht', expired: 'Bericht abgelaufen', revoked: 'Gerät widerrufen', transferFailed: 'Neuere Übertragung fehlgeschlagen', failed: 'Letzte Erfassung fehlgeschlagen', transfer: 'Neuere Übertragung unvollständig', transferExpired: 'Neuere Übertragung abgelaufen', viewUpdates: 'Updates öffnen', details: 'Gerätedetails', resources: 'Ressourcen', memory: 'Arbeitsspeicher', disk: 'Datenträger', sources: 'Quellen & Details', certificate: 'Zertifikat', expiryUnknown: 'Ablauf unbekannt', expiring: 'Läuft innerhalb von 48 Stunden ab', expiredCertificate: 'Abgelaufen', certificateCheck: 'Bei Managerprüfung' },
};
function Card({ title, icon: Icon, children, action, onOpen, busy = false }: { title: string; icon: typeof Radio; children: ReactNode; action?: string; onOpen?: () => void; busy?: boolean }) {
    return <section className="device-essential-card" aria-label={title} aria-busy={busy}><h2><Icon size={17} aria-hidden="true"/>{title}</h2>{children}{onOpen && <button type="button" className="text-button" onClick={onOpen}>{action}<ArrowRight size={13} aria-hidden="true"/></button>}</section>;
}
function WarningSummary({ deviceId, sessionKey, onOpen }: { deviceId: string; sessionKey: string | null; onOpen: () => void }) {
    const [locale] = useLocale(), c = copy[locale], { view, pending, failure } = useHealth(deviceId, sessionKey, false);
    const open = view?.checks.filter(check => check.state === 'open').length ?? 0, waiting = view?.checks.filter(check => check.state === 'pending').length ?? 0, unknown = view?.checks.filter(check => check.state === 'unknown').length ?? 0;
    return <Card title={c.warnings} icon={ShieldAlert} action={c.review} onOpen={onOpen} busy={pending || !view && !failure}>
        <strong className={`device-essential-value ${open || waiting ? 'caution' : ''}`}>{!view ? pending ? c.reading : c.unknown : open ? `${open} ${c.open}` : waiting ? `${waiting} ${c.pending}` : unknown || view.status === 'unknown' ? c.unknown : `0 ${c.open}`}</strong>
        <p>{c.scope}</p>{view && <>{open > 0 && waiting > 0 && <p className="caution">{waiting} {c.pending}</p>}{unknown > 0 && <p className="caution">{unknown} {c.unknownChecks}</p>}{view.status === 'maintenance' && <p className="caution">{c.maintenance}</p>}{view.evaluatedAt && <time dateTime={view.evaluatedAt} title={fullDate(view.evaluatedAt)}>{relativeTime(view.evaluatedAt)}</time>}</>}
    </Card>;
}
/** One metadata-only read after identity settles. Health follows it, never beside
 * it. These overview readers do not resume or poll on their own; the identity
 * boundary remounts them after a fresh visible-session read. */
function StatusSummaries({ deviceId, sessionKey, onWarnings, onUpdates }: { deviceId: string; sessionKey: string | null; onWarnings?: () => void; onUpdates: () => void }) {
    const [locale] = useLocale(), c = copy[locale], resource = useCompleteUpdates(deviceId, true, false), { view } = resource;
    const visible = Boolean(view && completeUpdatesGenerationVisible(view, resource.elapsed)), manifest = visible ? view?.complete?.manifest : null;
    const settled = !resource.loading && Boolean(view || resource.error), number = (value: number) => new Intl.NumberFormat(locale).format(value);
    return <>
        {settled && resource.error !== 'session' && onWarnings ? <WarningSummary deviceId={deviceId} sessionKey={sessionKey} onOpen={onWarnings}/> : <Card title={c.warnings} icon={ShieldAlert} action={c.review} onOpen={onWarnings} busy={Boolean(onWarnings && !settled)}><strong className="device-essential-value">{c.unknown}</strong><p>{c.scope}</p></Card>}
        <Card title={c.updates} icon={Download} action={c.viewUpdates} onOpen={onUpdates} busy={resource.loading || !view && !resource.error}>
            <strong className={`device-essential-value ${manifest?.candidateCount || manifest?.unknownCount ? 'caution' : ''}`}>{manifest ? `${number(manifest.candidateCount)}${manifest.unknownCount ? '+' : ''}` : resource.loading ? c.reading : c.unknown}</strong>
            <p>{c.candidates}</p>
            {manifest && view ? <>{manifest.unknownCount > 0 && <p className="caution">{c.partial} · {number(manifest.unknownCount)} {c.unknownComparisons}</p>}{manifest.heldCount > 0 && <p>{number(manifest.heldCount)} {c.held}</p>}<p className={manifest.metadata.freshness === 'stale' ? 'caution' : undefined}>{manifest.metadata.freshness === 'stale' ? c.stale : c.freshness}</p><time dateTime={manifest.collectedAt} title={fullDate(manifest.collectedAt)}>{c.age} {number(Math.floor((inventoryAge(view.serverNow, manifest.collectedAt) + resource.elapsed) / 60000))} {c.minutes}</time></> : !resource.loading && <p>{view?.status === 'revoked' ? c.revoked : view?.status === 'available' && view.complete ? c.expired : c.unavailable}</p>}
            {view?.failure && <p className="caution">{c.failed}</p>}
            {view?.transfer && view.transfer.state !== 'complete' && <p className="caution">{view.transfer.state === 'failed' ? c.transferFailed : view.transfer.state === 'expired' || completeUpdatesTransferExpired(view, resource.elapsed) ? c.transferExpired : c.transfer}</p>}
        </Card>
    </>;
}
export function DeviceEssentials({ device, sessionKey, readReady, onWarnings, onUpdates, onDetails }: { device: Device; sessionKey: string | null; readReady: boolean; onWarnings?: () => void; onUpdates?: () => void; onDetails: () => void }) {
    const [locale] = useLocale(), c = copy[locale], certificate = certificateExpiry(device.agentCertificate);
    return <div className="device-essentials">
        <div className="device-essentials-status">
            <Card title={c.contact} icon={Radio} action={c.details} onOpen={onDetails}><strong className="device-essential-value detail-time">{relativeTime(device.lastSeen)}</strong></Card>
            {onUpdates && readReady ? <StatusSummaries key={`${device.id}:${sessionKey ?? ''}`} deviceId={device.id} sessionKey={sessionKey} onWarnings={onWarnings} onUpdates={onUpdates}/> : <><Card title={c.warnings} icon={ShieldAlert} action={c.review} onOpen={onWarnings} busy={Boolean(onWarnings && onUpdates)}><strong className="device-essential-value">{c.unknown}</strong><p>{c.scope}</p></Card><Card title={c.updates} icon={Download} action={c.viewUpdates} onOpen={onUpdates} busy={Boolean(onUpdates)}><strong className="device-essential-value">{c.unknown}</strong><p>{c.candidates}</p></Card></>}
        </div>
        <section aria-label={c.resources} className="device-essential-resources"><div className="device-metrics">{[{ label: 'CPU', metric: device.cpu, icon: Terminal }, { label: c.memory, metric: device.memory, icon: MemoryStick }, { label: c.disk, metric: device.disk, icon: HardDrive }].map(({ label, metric, icon: Icon }) => <div className="device-metric-card" key={label}><span className="device-metric-label"><Icon size={16} aria-hidden="true"/>{label}</span><MetricValue metric={metric} precision={1}/><time className="device-metric-time" dateTime={metric.collectedAt} title={fullDate(metric.collectedAt)}>{locale === 'de' ? 'Messung' : 'Measured'} · {fullDate(metric.collectedAt)}</time></div>)}</div><button type="button" className="text-button" onClick={onDetails}>{c.sources}<ArrowRight size={13} aria-hidden="true"/></button></section>
        {!device.synthetic && device.source === 'lan' && certificate.state !== 'current' && <button type="button" className={`device-certificate-notice ${certificate.state}`} onClick={onDetails}><Clock3 size={15} aria-hidden="true"/><span>{c.certificate}: {certificate.state === 'unknown' ? c.expiryUnknown : certificate.state === 'expired' ? c.expiredCertificate : c.expiring}{certificate.certificate && <> · {c.certificateCheck} <time dateTime={certificate.certificate.checkedAt}>{fullDate(certificate.certificate.checkedAt)}</time></>}</span><ArrowRight size={13} aria-hidden="true"/></button>}
    </div>;
}

/** Optional interpretation stays within the existing Details surface. No reads. */
export function DeviceObservationNotes() {
    const [locale] = useLocale(), c = copy[locale];
    return <details className="device-observation-notes"><summary><Info size={15} aria-hidden="true"/>{c.interpretation}</summary><dl>
        <div><dt>{c.contact}</dt><dd>{c.contactScope}. {c.contactLimit}</dd></div>
        <div><dt>{c.warnings}</dt><dd>{c.warningScope}</dd></div>
        <div><dt>{c.updates}</dt><dd>{c.updateScope}</dd></div>
    </dl></details>;
}
