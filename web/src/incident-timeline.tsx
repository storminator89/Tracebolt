import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { IncidentTimelineModel, TimelineKind, TimelineCurrentState, TimelineSourceRole } from './incident-timeline-model';
import type { WindowsServiceHealthSource } from './windows-service-health-complete-types';

const copy = {
    en: {
        title: 'Incident timeline', history: 'Retained episode checkpoints', current: 'Current check, separate from this episode', sources: 'Complete-service evidence references',
        opening: 'Opening evidence', 'last-bad': 'Last-bad evidence', recovery: 'Recovery evidence',
        device: 'Device identity', incident: 'Incident identity', target: 'Check target', key: 'Exact source key', unavailable: 'Not retained or unavailable',
        'opened': 'Incident opened', 'linux-contact-evaluated': 'Last retained contact evaluation by manager', 'last-observed': 'Last retained incident evidence', 'last-confirmed': 'Last incident confirmation',
        'contact-received': 'Last accepted report for the contact incident', 'bad-captured': 'Last-bad evidence captured', 'bad-received': 'Last-bad evidence accepted',
        'opening-captured': 'Opening generation capture began', 'opening-finished': 'Opening generation capture completed', 'opening-received': 'Opening generation accepted', 'bad-finished': 'Last-bad generation capture completed',
        'recovery-captured': 'Recovery evidence captured', 'recovery-finished': 'Recovery generation capture completed', 'recovery-received': 'Recovery evidence accepted',
        recovered: 'Selected check recovery confirmed', 'reports-resumed': 'Accepted reports resumed', 'policy-changed': 'Closed after policy change; no recovery established', 'monitoring-stopped': 'Monitoring stopped; no recovery established', seen: 'Operator marked seen; episode state unchanged',
        unknown: 'Unknown: current evidence is missing or stale', 'not-monitored': 'This check is no longer monitored', disabled: 'Policy disabled', pending: 'Confirmation pending', attention: 'Selected check needs attention', 'within-policy': 'Within the selected check policy', recent: 'Accepted reports are recent', running: 'Selected service is running',
        evaluation: 'Original manager evaluation', observation: 'Original current observation', validUntil: 'Current confidence ends no later than', source: 'Qualified current generation',
        kind: 'Source kind', grant: 'Exact grant identity', expires: 'Original generation expiry', contactEvaluation: 'Linux contact history records manager evaluation times. The separate current accepted-report receipt is not an incident evaluation or a capture time.', contactReceipt: 'Original current accepted-report receipt', generation: 'Generation', sequence: 'Sequence', grantRevision: 'Grant revision', manifest: 'Manifest SHA256', capture: 'Capture began', finished: 'Capture completed', receipt: 'Accepted', rowCount: 'Complete generation row count',
        partial: 'These are retained checkpoints, not a continuous event log. Intermediate samples, earlier raw values and missed manager evaluations are not reconstructed. A gap between checkpoints does not prove uninterrupted failure.',
        context: 'The current check can belong to a later episode or policy. It cannot rewrite this episode or prove that an earlier cause was repaired. Seen is independent of recovery.',
        linuxGap: 'Linux history does not retain separate opening or recovery raw samples. Opening and closure are manager confirmation times; the last incident evidence time keeps its original source meaning.',
        windowsGap: 'Capture, acceptance and manager confirmation are different times. A received report is not proof that the host or all services are healthy.',
        contact: 'Contact uses accepted-report timing. No capture timestamp is invented for contact evidence.',
        maintenance: 'Maintenance is not an incident event here. Its source-specific rules remain in Health.',
        health: 'Open exact device Health', logs: 'Open exact service logs', readOnly: 'Expanding this timeline starts no request. Following Health or Logs uses the existing view permissions and may start an already-authorized retained-log search. No new collection, acknowledgement, action preview or execution is authorized.',
    },
    de: {
        title: 'Vorfall-Zeitverlauf', history: 'Gespeicherte Eckpunkte der Episode', current: 'Aktuelle Prüfung, getrennt von dieser Episode', sources: 'Belegreferenzen des vollständigen Dienstinventars',
        opening: 'Eröffnungsbeleg', 'last-bad': 'Letzter Auffälligkeitsbeleg', recovery: 'Erholungsbeleg',
        device: 'Geräteidentität', incident: 'Vorfallidentität', target: 'Prüfziel', key: 'Exakter Quellschlüssel', unavailable: 'Nicht gespeichert oder nicht verfügbar',
        'opened': 'Vorfall eröffnet', 'linux-contact-evaluated': 'Letzte gespeicherte Kontaktauswertung durch Manager', 'last-observed': 'Letzter gespeicherter Vorfallbeleg', 'last-confirmed': 'Letzte Vorfallbestätigung',
        'contact-received': 'Letzter akzeptierter Bericht zum Kontaktvorfall', 'bad-captured': 'Letzter Auffälligkeitsbeleg erfasst', 'bad-received': 'Letzter Auffälligkeitsbeleg akzeptiert',
        'opening-captured': 'Erfassung der Eröffnungsgeneration begonnen', 'opening-finished': 'Erfassung der Eröffnungsgeneration beendet', 'opening-received': 'Eröffnungsgeneration akzeptiert', 'bad-finished': 'Erfassung der letzten auffälligen Generation beendet',
        'recovery-captured': 'Erholungsbeleg erfasst', 'recovery-finished': 'Erfassung der Erholungsgeneration beendet', 'recovery-received': 'Erholungsbeleg akzeptiert',
        recovered: 'Erholung der ausgewählten Prüfung bestätigt', 'reports-resumed': 'Akzeptierte Berichte wieder eingegangen', 'policy-changed': 'Nach Richtlinienänderung geschlossen; keine Erholung belegt', 'monitoring-stopped': 'Überwachung beendet; keine Erholung belegt', seen: 'Kenntnisnahme durch Operator; Episodenstatus unverändert',
        unknown: 'Unbekannt: aktuelle Belege fehlen oder sind veraltet', 'not-monitored': 'Diese Prüfung wird nicht mehr überwacht', disabled: 'Richtlinie deaktiviert', pending: 'Bestätigung ausstehend', attention: 'Ausgewählte Prüfung benötigt Aufmerksamkeit', 'within-policy': 'Innerhalb der ausgewählten Prüfrichtlinie', recent: 'Akzeptierte Berichte sind aktuell', running: 'Ausgewählter Dienst läuft',
        evaluation: 'Ursprüngliche Managerauswertung', observation: 'Ursprüngliche aktuelle Beobachtung', validUntil: 'Aktuelle Aussagekraft endet spätestens', source: 'Aktuell gültige Generation',
        kind: 'Quellenart', grant: 'Exakte Freigabeidentität', expires: 'Ursprünglicher Generationsablauf', contactEvaluation: 'Die Linux-Kontakthistorie speichert Manager-Auswertungszeiten. Der getrennte aktuelle Zeitpunkt des akzeptierten Berichts ist keine Vorfallauswertung und keine Erfassungszeit.', contactReceipt: 'Ursprüngliche aktuelle Berichtsakzeptanz', generation: 'Generation', sequence: 'Sequenz', grantRevision: 'Freigaberevision', manifest: 'Manifest-SHA256', capture: 'Erfassung begonnen', finished: 'Erfassung beendet', receipt: 'Akzeptiert', rowCount: 'Zeilenanzahl der vollständigen Generation',
        partial: 'Dies sind gespeicherte Eckpunkte, kein lückenloses Ereignisprotokoll. Zwischenwerte, frühere Rohwerte und verpasste Managerauswertungen werden nicht rekonstruiert. Eine Lücke zwischen Eckpunkten belegt keinen durchgehenden Fehlerzustand.',
        context: 'Die aktuelle Prüfung kann zu einer späteren Episode oder Richtlinie gehören. Sie schreibt diese Episode nicht um und belegt keine Behebung einer früheren Ursache. Kenntnisnahme ist von Erholung unabhängig.',
        linuxGap: 'Die Linux-Historie speichert keine getrennten Rohwerte zur Eröffnung oder Erholung. Eröffnung und Abschluss sind Manager-Bestätigungszeiten; die letzte Vorfallbelegzeit behält ihre ursprüngliche Quellenbedeutung.',
        windowsGap: 'Erfassung, Akzeptanz und Managerbestätigung sind verschiedene Zeitpunkte. Ein eingegangener Bericht belegt nicht, dass das Gerät oder alle Dienste gesund sind.',
        contact: 'Kontakt nutzt den Zeitpunkt akzeptierter Berichte. Für Kontaktbelege wird keine Erfassungszeit erfunden.',
        maintenance: 'Wartung ist hier kein Vorfallereignis. Ihre quellenspezifischen Regeln bleiben in Health.',
        health: 'Health der exakten Geräteidentität öffnen', logs: 'Logs des exakten Dienstes öffnen', readOnly: 'Das Aufklappen dieses Zeitverlaufs startet keine Abfrage. Health- und Log-Links nutzen die bestehenden Ansichtsrechte und können eine bereits freigegebene Suche in gespeicherten Logs starten. Keine neue Erfassung, Kenntnisnahme, Aktionsvorschau oder Ausführung wird freigegeben.',
    },
};
type Copy = typeof copy.en | typeof copy.de;
export function timelineCheckpointLabel(kind: TimelineKind, locale: 'en' | 'de'): string { return copy[locale][kind]; }
export function timelineCurrentLabel(state: TimelineCurrentState, locale: 'en' | 'de'): string { return copy[locale][state]; }
function Time({ at, c }: { at: string | null; c: Copy }) { return at ? <time dateTime={at} title={at}>{fullDate(at)} <span className="incident-timeline-exact">{at}</span></time> : <span>{c.unavailable}</span>; }
function Source({ source, label, c }: { source: WindowsServiceHealthSource; label: string; c: Copy }) {
    return <details className="incident-timeline-source"><summary>{label}</summary><dl>
        <div><dt>{c.kind}</dt><dd>{source.kind}</dd></div><div><dt>{c.grant}</dt><dd>{source.grantId}</dd></div><div><dt>{c.expires}</dt><dd><Time at={source.expiresAt} c={c}/></dd></div><div><dt>{c.generation}</dt><dd>{source.generationId}</dd></div><div><dt>{c.sequence}</dt><dd>{source.sequence}</dd></div><div><dt>{c.grantRevision}</dt><dd>{source.grantRevision}</dd></div><div><dt>{c.manifest}</dt><dd>{source.manifestSha256}</dd></div>
        <div><dt>{c.capture}</dt><dd><Time at={source.capturedAt} c={c}/></dd></div><div><dt>{c.finished}</dt><dd><Time at={source.captureFinishedAt} c={c}/></dd></div><div><dt>{c.receipt}</dt><dd><Time at={source.receivedAt} c={c}/></dd></div><div><dt>{c.rowCount}</dt><dd>{source.rowCount}</dd></div>
    </dl></details>;
}

/** Literal, read-only rendering of the exact row's bounded source projection. */
export function IncidentTimeline({ model, platform }: { model: IncidentTimelineModel; platform: 'linux' | 'windows' }) {
    const [locale] = useLocale(), c = copy[locale];
    return <details className="incident-timeline"><summary>{c.title}</summary>
        <p>{c.partial}</p>
        <dl className="incident-timeline-identities"><div><dt>{c.device}</dt><dd>{model.deviceId}</dd></div><div><dt>{c.incident}</dt><dd>{model.incidentId}</dd></div><div><dt>{c.target}</dt><dd>{model.target}</dd></div><div><dt>{c.key}</dt><dd>{model.sourceKey}</dd></div></dl>
        <h4>{c.history}</h4><ol className="incident-timeline-events">{model.episode.map((event, index) => <li key={`${event.kind}:${index}`}><strong>{c[event.kind as TimelineKind]}</strong><Time at={event.at} c={c}/></li>)}</ol>
        <p>{platform === 'linux' ? c.linuxGap : c.windowsGap}</p>{model.contact && <p>{model.contact === 'linux' ? c.contactEvaluation : c.contact}</p>}
        {model.sources.length > 0 && <section aria-label={c.sources}><h4>{c.sources}</h4>{model.sources.map(value => <Source key={value.role} source={value.source} label={c[value.role as TimelineSourceRole]} c={c}/>)}</section>}
        <section aria-label={c.current}><h4>{c.current}</h4><p>{c[model.current.state as TimelineCurrentState]}</p><p>{c.context}</p><dl>
            <div><dt>{c.evaluation}</dt><dd><Time at={model.current.evaluatedAt} c={c}/></dd></div><div><dt>{model.contact === 'linux' ? c.contactReceipt : c.observation}</dt><dd><Time at={model.current.observedAt} c={c}/></dd></div>
            {model.current.validUntil && <div><dt>{c.validUntil}</dt><dd><Time at={model.current.validUntil} c={c}/></dd></div>}
        </dl>{model.current.source && <Source source={model.current.source} label={c.source} c={c}/>}</section>
        <p>{c.maintenance}</p><div className="investigation-links"><a href={model.healthHref}>{c.health}</a>{model.logsHref && <a href={model.logsHref}>{c.logs}</a>}</div><p>{c.readOnly}</p>
    </details>;
}
