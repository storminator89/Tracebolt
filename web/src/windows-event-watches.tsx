import { useId, useState } from 'react';
import { ChevronDown, Radio, RefreshCw } from 'lucide-react';
import { getProtectedRequestEpoch } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { useWindowsEventWatches } from './windows-event-watches-resource';
import { eventWatchDeviceId, eventWatchRequestId, selectorKey } from './windows-event-watches-types';
import type { EventWatchRequest, EventWatchSelector, EventWatchesView } from './windows-event-watches-types';
import './windows-event-watches.css';
export const eventWatchCopy = {
    en: {
        history: 'Recorded observations', disableHelp: 'Disabling removes saved selectors, not recorded observations.', timing: 'Capture & receipt times', retentionTitle: 'History & retention', limit: '4 selected · Deselect one to choose another', title: 'Watch sampled events', boundary: 'Sampled events only: events may be missed. No match does not mean healthy. No automatic recovery, notifications or remediation.',
        refresh: 'Refresh saved watches', empty: 'Open this panel to check saved watches. Nothing is enabled automatically.', unavailable: 'Private watch data is unavailable or expired. Refresh to check again.', loading: 'Checking saved watches…', uncertain: 'The last change is unconfirmed. Refresh to check saved state; the change will not be sent again.',
        choose: 'Choose up to 4 exact observed event types', noChoices: 'No fresh observed choices are available. Refresh after a new header sample arrives.', selected: 'Selected', level: 'level', consent: 'I agree to save these private exact selectors and local duplicate-tracking counters while enabled and retain derived counts and capture/receipt times for up to 7 days after the latest match. No messages, extended raw-event retention or notifications.',
        enable: 'Enable watch', replace: 'Replace / re-arm watch', disable: 'Disable watch', review: 'Mark reviewed', reviewed: 'Reviewed', open: 'Not reviewed', count: 'At least', matches: 'sampled matches', first: 'First capture', last: 'Latest capture', received: 'Latest receipt', firstReceived: 'First receipt', choiceCapture: 'Choice sample captured', current: 'Saved exact selectors', disabled: 'Disabled', unknown: 'Observation unknown', baselining: 'Waiting for a new sample', watching: 'Watching sampled events', matched: 'Sampled match recorded', 'continuity-unknown': 'Sample continuity unknown', 'history-full': 'Watch history full', retention: 'Event observations expire after 7 days from their latest match receipt, even if not reviewed. Expiration is not recovery. Disabling clears saved selectors, not existing observations.', readOnly: 'Read-only access', noIncidents: 'No retained matches. This does not establish a healthy system.',
    },
    de: {
        history: 'Gespeicherte Beobachtungen', disableHelp: 'Deaktivieren entfernt die Auswahlwerte, nicht die gespeicherten Beobachtungen.', timing: 'Erfassungs- & Empfangszeiten', retentionTitle: 'Verlauf & Aufbewahrung', limit: '4 ausgewählt · Für eine andere Auswahl einen Eintrag abwählen', title: 'Ereignisstichproben beobachten', boundary: 'Nur Ereignisstichproben: Ereignisse können fehlen. Kein Treffer bedeutet nicht fehlerfrei. Keine automatische Entwarnung, Benachrichtigung oder Behebung.',
        refresh: 'Gespeicherte Beobachtung aktualisieren', empty: 'Panel öffnen, um gespeicherte Beobachtungen zu prüfen. Nichts wird automatisch aktiviert.', unavailable: 'Private Beobachtungsdaten sind nicht verfügbar oder abgelaufen. Zum Prüfen aktualisieren.', loading: 'Gespeicherte Beobachtung wird geprüft …', uncertain: 'Die letzte Änderung ist unbestätigt. Gespeicherten Zustand durch Aktualisieren prüfen; die Änderung wird nicht erneut gesendet.',
        choose: 'Bis zu 4 exakt beobachtete Ereignistypen auswählen', noChoices: 'Keine frischen beobachteten Auswahlwerte verfügbar. Nach einer neuen Kopfstichprobe aktualisieren.', selected: 'Ausgewählt', level: 'Stufe', consent: 'Ich stimme zu, diese privaten exakten Auswahlwerte und lokale Zähler zur Duplikaterkennung während der Aktivierung zu speichern und abgeleitete Zähler sowie Erfassungs-/Empfangszeiten bis zu 7 Tage nach dem letzten Treffer aufzubewahren. Keine Nachrichten, verlängerte Rohereignis-Aufbewahrung oder Benachrichtigungen.',
        enable: 'Beobachtung aktivieren', replace: 'Beobachtung ersetzen / neu starten', disable: 'Beobachtung deaktivieren', review: 'Als geprüft markieren', reviewed: 'Geprüft', open: 'Nicht geprüft', count: 'Mindestens', matches: 'Stichprobentreffer', first: 'Erste Erfassung', last: 'Letzte Erfassung', received: 'Letzter Empfang', firstReceived: 'Erster Empfang', choiceCapture: 'Auswahlstichprobe erfasst', current: 'Gespeicherte exakte Auswahl', disabled: 'Deaktiviert', unknown: 'Beobachtung unbekannt', baselining: 'Warten auf neue Stichprobe', watching: 'Ereignisstichproben werden beobachtet', matched: 'Stichprobentreffer erfasst', 'continuity-unknown': 'Stichprobenkontinuität unbekannt', 'history-full': 'Beobachtungsspeicher voll', retention: 'Beobachtungen verfallen 7 Tage nach dem letzten Trefferempfang, auch ungeprüfte. Ablauf bedeutet keine Entwarnung. Deaktivieren löscht gespeicherte Auswahlwerte, nicht bestehende Beobachtungen.', readOnly: 'Nur Lesezugriff', noIncidents: 'Keine aufbewahrten Treffer. Das belegt keinen fehlerfreien Zustand.',
    },
};
const label = (s: EventWatchSelector, level: string) => `${s.channel} · ${s.provider} · ID ${s.eventId} · ${level} ${s.level}`;
function SelectorLabel({ selector, level }: { selector: EventWatchSelector; level: string }) {
    return <span className="windows-event-watches-selector"><strong><bdi>{selector.provider}</bdi></strong><span><bdi>{selector.channel}</bdi> · ID {selector.eventId} · {level} {selector.level}</span></span>;
}
function WatchTime({ value, locale }: { value: string; locale: 'en' | 'de' }) {
    return <time dateTime={value} title={value}>{new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value))} UTC</time>;
}
export function WindowsEventWatches({ deviceId }: { deviceId: string }) {
    const operator = useOperator();
    if (!operator || operator.mode !== 'lan' || !operator.authenticated || operator.checkingAccess || !eventWatchDeviceId(deviceId)) return null;
    const scope = JSON.stringify([operator.actorId, operator.loginMode, operator.capabilities, operator.expiresAt]);
    return <WindowsEventWatchPanel key={JSON.stringify([deviceId, scope, getProtectedRequestEpoch()])} deviceId={deviceId} scope={scope} sessionEnd={operator.expiresAt}/>;
}
export function WindowsEventWatchPanel({ deviceId, scope, sessionEnd }: { deviceId: string; scope: string; sessionEnd: string | null }) {
    const [locale] = useLocale(), c = eventWatchCopy[locale], [open, setOpen] = useState(false), id = useId();
    const resource = useWindowsEventWatches(open, deviceId, scope, sessionEnd);
    return <section className="windows-event-watches" aria-label={c.title}>
        <button className="windows-event-watches-toggle" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(v => !v)}><Radio size={18} aria-hidden="true"/><span>{c.title}</span><ChevronDown size={18} aria-hidden="true"/></button>
        {open && <div id={id} className="windows-event-watches-body">
            <p className="windows-event-watches-boundary">{c.boundary}</p>
            <button type="button" className="button small" disabled={resource.busy} onClick={resource.refresh}><RefreshCw size={14} aria-hidden="true"/>{c.refresh}</button>
            {resource.busy && <p role="status">{c.loading}</p>}
            {resource.uncertain && <p role="status">{c.uncertain}</p>}
            {!resource.view && !resource.busy && <p role="status">{c.unavailable}</p>}
            {resource.view && <EventWatchEditor key={`${resource.view.revision}:${resource.view.source.token}:${resource.view.serverNow}`} view={resource.view} disabled={resource.uncertain || resource.busy} locale={locale} write={resource.write}/>}
        </div>}
    </section>;
}
/** Remount on every accepted view; hiding/expiry removes all drafts and consent. */
export function EventWatchEditor({ view, disabled, locale, write }: { view: EventWatchesView; disabled: boolean; locale: 'en' | 'de'; write: (request: EventWatchRequest) => void }) {
    const c = eventWatchCopy[locale], [selected, setSelected] = useState<string[]>([]), [consent, setConsent] = useState(false);
    const editable = view.canManage && !disabled && view.revision < Number.MAX_SAFE_INTEGER;
    const chosen = view.source.choices.filter(s => selected.includes(selectorKey(s)));
    const common = () => ({ requestId: eventWatchRequestId(), expectedRevision: view.revision, sourceToken: view.source.token });
    const save = (enabled: boolean) => {
        if (!editable || enabled && (!view.source.available || !consent || chosen.length < 1 || chosen.length > 4)) return;
        setConsent(false); setSelected([]);
        write({ operation: 'policy', body: { ...common(), enabled, selectors: enabled ? chosen : [], retentionAcknowledged: enabled } });
    };
    return <div>
        <p role="status" className="windows-event-watches-status"><strong>{c[view.status]}</strong>{!view.canManage && ` · ${c.readOnly}`}</p>
        {view.policy.selectors.length > 0 && <><h3>{c.current}</h3><ul>{view.policy.selectors.map(s => <li key={selectorKey(s)}><bdi>{label(s, c.level)}</bdi></li>)}</ul></>}
        {view.canManage && <form onSubmit={e => { e.preventDefault(); save(true); }}>
            {view.source.collectedAt && <p>{c.choiceCapture}: <WatchTime value={view.source.collectedAt} locale={locale}/></p>}
            <fieldset disabled={!editable || !view.source.available}><legend>{c.choose}</legend>
                {view.source.choices.length === 0 && <p>{c.noChoices}</p>}
                {view.source.choices.map(s => { const key = selectorKey(s), checked = selected.includes(key); return <label className={`windows-event-watches-choice windows-event-watches-option${checked ? ' is-selected' : ''}`} key={key}><input type="checkbox" checked={checked} disabled={!checked && selected.length >= 4} onChange={() => { setConsent(false); setSelected(old => checked ? old.filter(k => k !== key) : [...old, key]); }}/><SelectorLabel selector={s} level={c.level}/></label>; })}
                <p className="windows-event-watches-selection" role="status">{chosen.length === 4 ? c.limit : `${c.selected}: ${chosen.length} / 4`}</p>
                <label className="windows-event-watches-choice"><input type="checkbox" checked={consent} disabled={!chosen.length} onChange={e => setConsent(e.target.checked)}/><span>{c.consent}</span></label>
                <button type="submit" className="button small" disabled={!consent || chosen.length === 0}>{view.policy.enabled ? c.replace : c.enable}</button>
            </fieldset>
        </form>}
        {view.policy.enabled && view.canManage && <div className="windows-event-watches-disable"><p>{c.disableHelp}</p><button type="button" className="button small" disabled={!editable} onClick={() => save(false)}>{c.disable}</button></div>}
        <details className="windows-event-watches-retention"><summary>{c.retentionTitle}</summary><p>{c.retention}</p></details>
        <h3>{c.history} <span className="windows-event-watches-count">{view.incidents.length}</span></h3>
        {view.incidents.length === 0 && <p>{c.noIncidents}</p>}
        <ul className="windows-event-watches-incidents" role="list">{view.incidents.map(i => <li key={i.id}>
            <SelectorLabel selector={i.selector} level={c.level}/>
            <p>{c.count} {i.countLowerBound} {c.matches} · {i.reviewedAt ? c.reviewed : c.open}</p>
            <p>{c.last} · <WatchTime value={i.lastObservedAt} locale={locale}/></p>
            <details><summary>{c.timing}</summary><dl>{[[c.first, i.firstObservedAt], [c.last, i.lastObservedAt], [c.firstReceived, i.firstReceivedAt], [c.received, i.lastReceivedAt], ...(i.reviewedAt ? [[c.reviewed, i.reviewedAt]] : [])].map(([name, value]) => <div key={name}><dt>{name}</dt><dd><WatchTime value={value} locale={locale}/></dd></div>)}</dl></details>
            {i.reviewedAt === null && view.canManage && <button type="button" className="button small" disabled={!editable} onClick={() => { if (editable) write({ operation: 'review', body: { ...common(), incidentId: i.id } }); }}>{c.review}</button>}
        </li>)}</ul>
    </div>;
}
