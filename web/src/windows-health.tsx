import { useLayoutEffect, useState } from 'react';
import { HardDrive, Radio } from 'lucide-react';
import { getProtectedRequestEpoch } from './api';
import { hasLogoutIntent } from './auth';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { Device } from './types';
import './windows-health.css';

type Reason = 'available' | 'loading' | 'unavailable' | 'awaiting' | 'authority' | 'clock';
type Reading = { state: 'current' | 'stale' | 'denied' | 'missing' | 'unknown'; value: number | null; at: string | null; source: string | null };
const emptyReading = (): Reading => ({ state: 'unknown', value: null, at: null, source: null });
const timestamp = (value: unknown): value is string => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Number(value.slice(0, 4)) >= 1970 && new Date(Date.parse(value)).toISOString().slice(0, 19) === value.slice(0, 19);
/** Operator-only display adapter. No durable evaluation, thresholds or AI input. */
export function windowsHealthSummary(device: Device | undefined, resource: WindowsInventoryResource, elapsed: number, metadataReady: boolean) {
    let reason: Reason = 'available';
    const view = resource.view, certificate = device?.agentCertificate;
    const identities = device?.capabilities?.filter(item => item.id === 'agent_identity') ?? [];
    if (resource.loading) reason = 'loading';
    else if (resource.error || !view) reason = 'unavailable';
    else if (resource.status === 'awaiting') reason = 'awaiting';
    else if (!device || device.id !== view.deviceId || device.platform !== 'windows' || device.source !== 'lan' || device.synthetic || identities.length !== 1 || identities[0].status !== 'supported' || view.collectionProfile !== 'windows-inventory-v1' || !['fresh', 'stale'].includes(resource.status ?? '') || !resource.snapshot || !certificate || certificate.source !== 'guided-enrollment') reason = 'authority';
    else if (!Number.isFinite(elapsed) || elapsed < 0) reason = 'clock';
    else if (!timestamp(certificate.checkedAt) || !timestamp(certificate.expiresAt) || inventoryAge(view.serverNow, certificate.checkedAt) + elapsed < 0 || inventoryAge(view.serverNow, certificate.checkedAt) + elapsed > 120000 || inventoryAge(certificate.expiresAt, view.serverNow) <= elapsed) reason = 'authority';
    if (reason !== 'available' || !view || !device) return { reason, contact: 'unknown' as const, receivedAt: null, disk: emptyReading() };
    const receiptAge = view.receivedAt ? inventoryAge(view.serverNow, view.receivedAt) + elapsed : Infinity;
    const contact = !Number.isFinite(receiptAge) || receiptAge < 0 ? 'unknown' : receiptAge > 120000 ? 'stale' : 'recent';
    const disk = emptyReading(), metric = device.disk;
    if (!metadataReady || !metric) return { reason, contact, receivedAt: contact === 'unknown' ? null : view.receivedAt, disk };
    const age = timestamp(metric.collectedAt) ? inventoryAge(view.serverNow, metric.collectedAt) + elapsed : Infinity;
    if (metric.quality === 'denied') disk.state = 'denied';
    else if (metric.quality === 'stale' || Number.isFinite(age) && age > 120000) disk.state = 'stale';
    else if (metric.quality !== 'healthy' || !Number.isFinite(age) || age < 0 || inventoryAge(view.serverNow, metric.collectedAt) < 0 || !certificate || inventoryAge(certificate.checkedAt, metric.collectedAt) < 0 || metric.value === null || !Number.isFinite(metric.value) || metric.value < 0 || metric.value > 100 || metric.unit !== '%' || !timestamp(device.lastSeen) || inventoryAge(device.lastSeen, metric.collectedAt) < 0 || inventoryAge(view.serverNow, device.lastSeen) + elapsed < 0 || typeof metric.source !== 'string' || !metric.source.trim() || metric.source.length > 512) disk.state = 'missing';
    else { disk.state = 'current'; disk.value = metric.value; }
    if (timestamp(metric.collectedAt) && age >= 0 && age < 86400000) { disk.at = metric.collectedAt; disk.source = typeof metric.source === 'string' && metric.source.length <= 512 ? metric.source : null; }
    return { reason, contact, receivedAt: contact === 'unknown' ? null : view.receivedAt, disk };
}
const copy = {
    en: { title: 'Windows health observations', scope: 'Accepted contact and system-volume readings. Overall health remains unassessed.', contact: 'Agent contact', recent: 'Recent report', staleContact: 'Report is stale', unknown: 'Unknown', receipt: 'Accepted by manager', contactNote: 'Report age only. Live reachability is not checked.', disk: 'System volume', current: 'Current reading', stale: 'Stale reading', denied: 'Access denied', missing: 'No usable reading', captured: 'Measured', storage: 'Inspect storage', details: 'Sources & assessment limits', diskScope: 'Caller-visible, quota-aware usage of the Windows system volume. It does not describe all volumes or physical-disk condition. No Windows disk alarm threshold or durable incident history is configured here.', source: 'Source', available: '', loading: 'Refreshing observations…', unavailable: 'Observations unavailable. Current state is unknown.', awaiting: 'Waiting for the first accepted report.', authority: 'Current device access could not be verified. Readings are hidden.', clock: 'Observation age could not be verified. Readings are hidden.', metadata: 'Device metadata is being refreshed or could not be read.' },
    de: { title: 'Windows-Health-Beobachtungen', scope: 'Akzeptierter Kontakt und Systemvolume-Messungen. Der Gesamtzustand bleibt unbewertet.', contact: 'Agent-Kontakt', recent: 'Aktuelle Meldung', staleContact: 'Meldung veraltet', unknown: 'Unbekannt', receipt: 'Vom Manager akzeptiert', contactNote: 'Nur das Meldungsalter. Die aktuelle Erreichbarkeit wird nicht geprüft.', disk: 'Systemvolume', current: 'Aktuelle Messung', stale: 'Messung veraltet', denied: 'Zugriff verweigert', missing: 'Keine verwertbare Messung', captured: 'Gemessen', storage: 'Speicher ansehen', details: 'Quellen & Bewertungsgrenzen', diskScope: 'Für den Aufrufer sichtbare, kontingentabhängige Belegung des Windows-Systemvolumes. Sie beschreibt weder alle Volumes noch den Zustand physischer Datenträger. Hier sind keine Windows-Speicheralarmgrenzen oder dauerhaften Vorfallsverläufe eingerichtet.', source: 'Quelle', available: '', loading: 'Beobachtungen werden aktualisiert …', unavailable: 'Beobachtungen nicht verfügbar. Der aktuelle Zustand ist unbekannt.', awaiting: 'Die erste akzeptierte Meldung steht aus.', authority: 'Die aktuelle Gerätefreigabe konnte nicht bestätigt werden. Messungen sind ausgeblendet.', clock: 'Das Beobachtungsalter konnte nicht bestätigt werden. Messungen sind ausgeblendet.', metadata: 'Gerätemetadaten werden aktualisiert oder konnten nicht gelesen werden.' },
};
export function WindowsHealthSummary({ device, resource, sessionKey, metadataReady, onOpenStorage }: { device: Device; resource: WindowsInventoryResource; sessionKey: string | null; metadataReady: boolean; onOpenStorage: () => void }) {
    const [locale] = useLocale(), c = copy[locale], epoch = getProtectedRequestEpoch();
    const key = JSON.stringify([device.id, sessionKey]), view = resource.view;
    const [accepted, setAccepted] = useState<{ key: string; epoch: number; view: typeof view } | null>(null);
    useLayoutEffect(() => {
        if (!view || resource.error || resource.loading || hasLogoutIntent()) { setAccepted(null); return; }
        const ok = acceptWindowsHealthClock(key, epoch, view.serverNow, resource.elapsedMS);
        setAccepted(ok ? { key, epoch, view } : null);
    }, [key, epoch, view, resource.error, resource.loading]); // elapsedMS advances; only a new response accepts a clock.
    const elapsed = accepted?.key === key && accepted.epoch === epoch && accepted.view === view && view && !hasLogoutIntent() ? windowsHealthElapsed(key, epoch, view.serverNow, resource.elapsedMS) : Infinity;
    const summary = windowsHealthSummary(device, resource, elapsed, metadataReady), disk = summary.disk;
    return <section className="windows-health-summary" aria-label={c.title}>
        <h2>{c.title}</h2><p className="windows-health-scope">{c.scope}</p>
        {summary.reason !== 'available' && <p role="status" className="windows-health-note">{c[summary.reason]}</p>}
        <div className="windows-health-cards">
            <section aria-label={c.contact}><h3><Radio size={16} aria-hidden="true"/>{c.contact}</h3><strong>{summary.contact === 'recent' ? c.recent : summary.contact === 'stale' ? c.staleContact : c.unknown}</strong>{summary.receivedAt && <p>{c.receipt} · <time dateTime={summary.receivedAt}>{fullDate(summary.receivedAt)}</time></p>}<p>{c.contactNote}</p></section>
            <section aria-label={c.disk}><h3><HardDrive size={16} aria-hidden="true"/>{c.disk}</h3><strong>{disk.value === null ? '—' : `${new Intl.NumberFormat(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(disk.value)} %`}</strong><span>{c[disk.state]}</span>{disk.at && <p>{c.captured} · <time dateTime={disk.at}>{fullDate(disk.at)}</time></p>}{summary.reason === 'available' && !metadataReady && <p>{c.metadata}</p>}<button type="button" className="text-button" onClick={onOpenStorage}>{c.storage}</button></section>
        </div>
        <details className="windows-inventory-scope"><summary>{c.details}</summary><p>{c.diskScope}</p>{disk.source && <p>{c.source}: {disk.source}</p>}</details>
    </section>;
}
