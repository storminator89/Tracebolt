import { useId, useRef } from 'react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { capabilityLabels } from './capability-guidance';
import type { CapabilityObservation, CapabilityState } from './capability-observations';
import { deviceReadinessFacts } from './device-readiness-model';
import type { Device } from './types';
import './device-readiness.css';

const copy = {
    en: {
        title: 'Readiness facts', unavailable: 'Current evidence unavailable', report: 'Accepted report capture', recent: 'Recent capture', stale: 'Stale capture', not_collected: 'No report recorded yet', unknown: 'Age unknown', age: 'Capture age', seconds: 's', checked: 'Manager time reference',
        version: 'Reported agent version', missing: 'Not supplied', profiles: 'Profiles from validated source status', counts: 'Capability status rows', empty: 'No capability status supplied', scopes: 'Advertised profile scopes',
        certificate: 'Certificate validity', current: 'More than 48 hours remaining', expiring: 'Expires within 48 hours', expired: 'Expired', revoked: 'Revoked', certificateUnknown: 'Unknown',
        limit: 'No readiness score. Profile support, local approval and collected data remain separate. Counts below match the capability rows, not the number of devices or inventory records.',
        artifact: 'An agent version is not a verified artifact. Exact artifact, native acceptance and release gates are not established by these reads.',
        time: 'Capture age uses the recorded manager time and elapsed time in this view. It is not receipt age, live connectivity or a health verdict.',
    },
    de: {
        title: 'Nachweise zur Betriebsbereitschaft', unavailable: 'Aktuelle Nachweise nicht verfügbar', report: 'Erfassung der akzeptierten Meldung', recent: 'Aktuelle Erfassung', stale: 'Veraltete Erfassung', not_collected: 'Noch keine Meldung erfasst', unknown: 'Alter unbekannt', age: 'Erfassungsalter', seconds: 's', checked: 'Zeitreferenz des Managers',
        version: 'Gemeldete Agentversion', missing: 'Nicht geliefert', profiles: 'Profile aus geprüftem Quellstatus', counts: 'Fähigkeitsstatus-Zeilen', empty: 'Kein Fähigkeitsstatus geliefert', scopes: 'Im Profil vorgesehene Umfänge',
        certificate: 'Zertifikatsgültigkeit', current: 'Mehr als 48 Stunden verbleibend', expiring: 'Läuft innerhalb von 48 Stunden ab', expired: 'Abgelaufen', revoked: 'Widerrufen', certificateUnknown: 'Unbekannt',
        limit: 'Keine Bereitschaftspunktzahl. Profilunterstützung, lokale Freigabe und erfasste Daten bleiben getrennt. Die Zahlen entsprechen den Fähigkeitszeilen, nicht Geräte- oder Inventarzahlen.',
        artifact: 'Eine Agentversion ist kein verifiziertes Artefakt. Exaktes Artefakt, native Abnahme und Release-Gates werden durch diese Lesezugriffe nicht belegt.',
        time: 'Das Erfassungsalter nutzt die erfasste Managerzeit und die verstrichene Zeit dieser Ansicht. Es ist weder Empfangsalter noch Live-Verbindung oder Zustandsurteil.',
    },
};

type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsedSince(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return mono >= 0 && Number.isFinite(mono) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}

/** Reuses its parent's validated status reads and render tick. No requests,
 * persistence, collection, export, grant or action is introduced here. */
export function DeviceReadiness({ device, observations, profiles, available, metadataElapsed }: { device: Device; observations: CapabilityObservation[]; profiles: string[]; available: boolean; metadataElapsed: number }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const checkedAt = device.agentCertificate?.checkedAt;
    const metadataAge = Number.isFinite(metadataElapsed) && metadataElapsed >= 0 ? metadataElapsed : Infinity;
    const clock = useRef({ deviceId: device.id, checkedAt, anchor: capture(), offset: metadataAge });
    const prior = clock.current;
    if (prior.deviceId !== device.id) clock.current = { deviceId: device.id, checkedAt, anchor: capture(), offset: metadataAge };
    else if (prior.checkedAt !== checkedAt) {
        const before = Date.parse(prior.checkedAt ?? ''), advance = Date.parse(checkedAt ?? '') - before;
        // A stalled/slow manager clock cannot renew unchanged capture age.
        // Backward manager or browser time makes this view's age unknown.
        const offset = !Number.isFinite(before) ? metadataAge : advance < 0 || !Number.isFinite(advance) ? Infinity : Math.max(metadataAge, elapsedSince(prior.anchor) + prior.offset - advance);
        clock.current = { deviceId: device.id, checkedAt, anchor: capture(), offset };
    }
    else clock.current.offset = Math.max(clock.current.offset, metadataAge - elapsedSince(clock.current.anchor));
    const elapsed = elapsedSince(clock.current.anchor) + clock.current.offset;
    const facts = deviceReadinessFacts(device, observations, elapsed, available);
    const sourceProfiles = [...new Set(profiles.filter(Boolean))].sort();
    const states = (Object.keys(capabilityLabels[locale]) as CapabilityState[]).filter(state => facts.counts[state]);
    return <section className="device-readiness" aria-labelledby={id}>
        <h3 id={id}>{c.title}</h3>
        {!available ? <p>{c.unavailable}</p> : <>
            <dl className="device-readiness-facts">
                <div><dt>{c.report}</dt><dd data-report-state={facts.report}>{c[facts.report]}{facts.reportAgeSeconds !== null && <span> · {c.age}: {facts.reportAgeSeconds.toLocaleString(locale)} {c.seconds}</span>}{['recent', 'stale'].includes(facts.report) && <time dateTime={device.lastSeen}>{fullDate(device.lastSeen)}</time>}</dd></div>
                <div><dt>{c.certificate}</dt><dd data-certificate-state={facts.certificate}>{facts.certificate === 'unknown' ? c.certificateUnknown : c[facts.certificate]}{facts.checkedAt && <span>{c.checked}: <time dateTime={facts.checkedAt}>{fullDate(facts.checkedAt)}</time></span>}</dd></div>
                <div><dt>{c.version}</dt><dd>{device.agentVersion && device.agentVersion !== 'unknown' ? device.agentVersion : c.missing}</dd></div>
                <div><dt>{c.profiles}</dt><dd>{sourceProfiles.length ? sourceProfiles.join(', ') : c.missing}</dd></div>
            </dl>
            <div className="device-readiness-counts"><p>{c.counts}: <strong>{observations.length}</strong> · {c.scopes}: <strong>{device.capabilities.filter(item => item.status === 'scope').length}</strong></p>{states.length ? <ul aria-label={c.counts}>{states.map(state => <li key={state} data-readiness-state={state}><strong>{facts.counts[state]}</strong> {capabilityLabels[locale][state]}</li>)}</ul> : <p>{c.empty}</p>}</div>
        </>}
        <details><summary>{locale === 'de' ? 'Grenzen dieser Nachweise' : 'Limits of this evidence'}</summary><p>{c.limit}</p><p>{c.time}</p><p>{c.artifact}</p></details>
    </section>;
}
