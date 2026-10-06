import { useId } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import type { JournalView } from './journal-types';
import { validJournalUnit } from './journal-types';
import { journalReportedAccess, journalServiceLabel, journalServiceSearches } from './journal-sources';
import { useSystemInventory } from './system-inventory-resource';
import { systemAgeStatus, systemSectionVisible, validSystemSearch } from './system-inventory-types';
import './journal-service-picker.css';

const copy = {
    en: {
        title: 'Observed services', close: 'Close service picker', access: 'Authenticated LAN operator access is required.',
        permission: 'Observed inventory does not confirm local journal allowlist membership or grant access. Selecting a service only fills the exact-unit field; it does not capture logs.',
        manual: 'You can close this picker and enter an exact service unit manually.',
        search: 'Search observed services', searchButton: 'Search services', searchHint: 'Search retained service names and states, not journal content. Each request returns at most 100 rows and scans at most 2,048 rows.',
        loading: 'Reading observed services…', refresh: 'Refresh service list', retry: 'Retry service read',
        not_configured: 'Service inventory is not configured.', unknown: 'Service inventory is unavailable for this identity.', awaiting: 'Awaiting observed services.', revoked: 'Device identity revoked.', expired: 'Service observations or identity expired.',
        noComplete: 'No retained complete service inventory is available. This does not mean the device has no services.',
        fresh: 'Within the observation window', stale: 'Stale / historical service observations',
        prior: 'Showing the last complete service inventory. The newer failed attempt does not refresh its original observation time.', failed: 'The latest service inventory attempt failed.',
        observed: 'Original observation time', whole: 'Whole retained service inventory', scanned: 'Rows scanned so far', matches: 'Matches found so far', shown: 'Rows on this page',
        suggestions: 'Find a service by purpose', suggestionsHint: 'Shortcuts search observed service names. They do not prove that a service is installed or permitted, and do not cover every Linux distribution.', all: 'All services', observedOnly: 'Permission unknown', reported_allowed: 'In reported grant', reported_disabled: 'Policy disabled', outside_reported_scope: 'Outside reported grant',
        select: 'Use', unsupported: 'This observed name is not supported by the exact service-unit syntax for log capture.',
        next: 'Next service page', continue: 'Continue search', emptyWindow: 'No matches in this scan window. More rows remain; continue searching.',
        zero: 'The complete service inventory contained zero services.', noMatches: 'No matches in the complete service inventory.', noMore: 'No further matches; earlier pages contained matches.', finished: 'The whole retained service inventory has been scanned.',
        loadError: 'Observed services could not be read. Retry or refresh.', invalid: 'The manager returned inconsistent or unsupported service inventory. Rows were cleared.', timeout: 'The service read timed out. Retry or refresh.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Retry in a moment.', restart: 'The service generation or paging session changed or expired. Refresh to restart; previous rows were cleared.', searchInvalid: 'Use at most 128 UTF-8 bytes without control or formatting characters.',
    },
    de: {
        title: 'Beobachtete Dienste', close: 'Dienstauswahl schließen', access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.',
        permission: 'Das beobachtete Inventar bestätigt weder die lokale Journal-Freigabeliste noch gewährt es Zugriff. Die Auswahl trägt nur die exakte Unit ein; sie erfasst keine Logs.',
        manual: 'Die Auswahl lässt sich schließen, um eine exakte Service-Unit manuell einzugeben.',
        search: 'Beobachtete Dienste durchsuchen', searchButton: 'Dienste suchen', searchHint: 'Gespeicherte Dienstnamen und Zustände durchsuchen, keine Journal-Inhalte. Jede Anfrage liefert höchstens 100 Zeilen und prüft höchstens 2.048 Zeilen.',
        loading: 'Beobachtete Dienste werden gelesen…', refresh: 'Dienstliste aktualisieren', retry: 'Dienstabfrage wiederholen',
        not_configured: 'Dienstinventar ist nicht eingerichtet.', unknown: 'Dienstinventar ist für diese Identität nicht verfügbar.', awaiting: 'Beobachtete Dienste stehen aus.', revoked: 'Geräteidentität widerrufen.', expired: 'Dienstbeobachtungen oder Identität abgelaufen.',
        noComplete: 'Kein vollständiges gespeichertes Dienstinventar verfügbar. Das bedeutet nicht, dass das Gerät keine Dienste hat.',
        fresh: 'Im Beobachtungszeitfenster', stale: 'Veraltete / historische Dienstbeobachtungen',
        prior: 'Das letzte vollständige Dienstinventar wird angezeigt. Der neuere fehlgeschlagene Versuch erneuert den ursprünglichen Beobachtungszeitpunkt nicht.', failed: 'Die neueste Dienstinventar-Erfassung ist fehlgeschlagen.',
        observed: 'Ursprünglicher Beobachtungszeitpunkt', whole: 'Gesamtes gespeichertes Dienstinventar', scanned: 'Bisher geprüfte Zeilen', matches: 'Bisher gefundene Treffer', shown: 'Zeilen auf dieser Seite',
        suggestions: 'Dienste nach Aufgabe finden', suggestionsHint: 'Kurzsuchen durchsuchen beobachtete Dienstnamen. Sie belegen weder Installation noch Freigabe und decken nicht jede Linux-Distribution ab.', all: 'Alle Dienste', observedOnly: 'Freigabe unbekannt', reported_allowed: 'In gemeldeter Freigabe', reported_disabled: 'Richtlinie deaktiviert', outside_reported_scope: 'Außerhalb gemeldeter Freigabe',
        select: 'Übernehmen', unsupported: 'Dieser beobachtete Name wird von der exakten Service-Unit-Syntax für die Log-Erfassung nicht unterstützt.',
        next: 'Nächste Dienstseite', continue: 'Suche fortsetzen', emptyWindow: 'Keine Treffer in diesem Suchabschnitt. Weitere Zeilen stehen aus; Suche fortsetzen.',
        zero: 'Das vollständige Dienstinventar enthielt keine Dienste.', noMatches: 'Keine Treffer im vollständigen Dienstinventar.', noMore: 'Keine weiteren Treffer; frühere Seiten enthielten Treffer.', finished: 'Das gesamte gespeicherte Dienstinventar wurde durchsucht.',
        loadError: 'Beobachtete Dienste konnten nicht gelesen werden. Wiederholen oder aktualisieren.', invalid: 'Der Manager lieferte widersprüchliches oder nicht unterstütztes Dienstinventar. Zeilen wurden entfernt.', timeout: 'Die Dienstabfrage hat das Zeitlimit überschritten. Wiederholen oder aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.', restart: 'Dienstgeneration oder Seitensitzung geändert oder abgelaufen. Zum Neubeginn aktualisieren; vorherige Zeilen wurden entfernt.', searchInvalid: 'Höchstens 128 UTF-8-Bytes ohne Steuer- oder Formatierungszeichen verwenden.',
    },
};

type JournalServicePickerProps = { deviceId: string; sessionKey: string | null; journalView?: JournalView | null; onSelect: (unit: string) => void; onClose: () => void };

/** Read-only inventory picker: selecting a name never requests journal content. */
export function JournalServicePicker({ deviceId, sessionKey, journalView = null, onSelect, onClose }: JournalServicePickerProps) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale], id = useId();
    return <section className="journal-service-picker" aria-labelledby={id} onKeyDown={event => {
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onClose(); }
    }}>
        <header><h4 id={id}>{c.title}</h4><button autoFocus type="button" className="button small" onClick={onClose}>{c.close}</button></header>

        {operator?.mode === 'lan' && operator.authenticated
            ? <ObservedServices key={JSON.stringify([deviceId, sessionKey, operator.expiresAt])} deviceId={deviceId} journalView={journalView} onSelect={onSelect}/>
            : <p role="status">{c.access}</p>}
        <details className="journal-picker-details"><summary>{locale === 'de' ? 'Auswahl & Freigabe' : 'Selection & permission'}</summary><p className="journal-picker-note">{c.permission}</p><p className="journal-picker-note">{c.manual}</p></details>
    </section>;
}

function ObservedServices({ deviceId, journalView = null, onSelect }: Pick<JournalServicePickerProps, 'deviceId' | 'journalView' | 'onSelect'>) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useSystemInventory(deviceId, 'services');
    const { view, page } = resource, complete = view?.lastComplete.services;
    const visible = !!view && systemSectionVisible(view, 'services', resource.elapsed), searchValid = validSystemSearch(resource.search);
    const number = (n: number) => new Intl.NumberFormat(locale).format(n);
    const fact = (label: string, value: string) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    return <div aria-busy={resource.loading}>
        <button type="button" className="button small" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh}>{c.refresh}</button>
        {resource.loading && <p role="status">{c.loading}</p>}
        {resource.error && <p role="alert" className="journal-picker-warning">{c[resource.error]}</p>}
        {['busy', 'timeout', 'loadError'].includes(resource.error ?? '') && <button type="button" className="button small" disabled={resource.loading} onClick={resource.retry}>{c.retry}</button>}
        {view && <>
            {!visible && <><p role="status">{view.status === 'fresh' || view.status === 'stale' ? complete ? c.expired : c.failed : c[view.status]}</p><p>{c.noComplete}</p></>}
            {complete && visible && <>
                {view.latest?.services.coverage === 'failed' && <p className="journal-picker-warning">{c.failed} {c.prior}</p>}
                <p className="journal-picker-note">{systemAgeStatus(view.serverNow, complete.meta.observedAt, resource.elapsed) === 'fresh' ? c.fresh : c.stale}</p>
                <details className="journal-picker-details"><summary>{locale === 'de' ? 'Inventardetails' : 'Inventory details'}</summary><dl className="journal-picker-facts">{fact(c.observed, complete.meta.observedAt)}{fact(c.whole, number(complete.meta.observedCount!))}</dl><p className="journal-picker-note">{c.searchHint}</p><p className="journal-picker-note">{c.suggestionsHint}</p></details>
                <div className="journal-picker-shortcuts" role="group" aria-label={c.suggestions}>
                    <strong>{c.suggestions}</strong><div>{journalServiceSearches.map(shortcut => <button key={shortcut.term} type="button" className="button small" disabled={resource.loading} onClick={() => { resource.changeSearch(shortcut.term); resource.startSearch(); }}>{shortcut.label[locale]}</button>)}<button type="button" className="button small" disabled={resource.loading} onClick={() => { resource.changeSearch(''); resource.startSearch(); }}>{c.all}</button></div>
                    </div>
                <div className="journal-picker-search">
                    <label htmlFor={`${id}-search`}>{c.search}</label>
                    <div><input id={`${id}-search`} type="search" value={resource.search} onChange={event => resource.changeSearch(event.target.value)} onKeyDown={event => {
                        if (event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); if (!event.nativeEvent.isComposing && !resource.loading && searchValid) resource.startSearch(); }
                    }} maxLength={128} autoComplete="off" spellCheck={false} aria-describedby={`${id}-hint${searchValid ? '' : ` ${id}-invalid`}`} aria-invalid={!searchValid}/>
                        <button type="button" className="button small" disabled={resource.loading || !searchValid} onClick={resource.startSearch}>{c.searchButton}</button></div>
                    <p id={`${id}-hint`} className="journal-picker-note">{locale === 'de' ? 'Dienstnamen und Zustände' : 'Service names and states'}</p>
                    {!searchValid && <p id={`${id}-invalid`} role="alert" className="journal-picker-warning">{c.searchInvalid}</p>}
                </div>
                {page && <>
                    <p className="journal-picker-count">{number(page.returnedCount)} {locale === 'de' ? 'angezeigt' : 'shown'} · {number(resource.scanned)} / {number(page.totalRows)} {locale === 'de' ? 'geprüft' : 'scanned'} · {number(resource.matches)} {locale === 'de' ? 'Treffer bisher' : 'matches so far'}</p>
                    {page.returnedCount > 0 ? <ul className="journal-picker-rows" aria-label={c.title}>
                        {page.services.map((row, index) => {
                            const access = journalReportedAccess(journalView, row.name), supported = validJournalUnit(row.name), label = journalServiceLabel(row.name, locale), reasonId = `${id}-unsupported-${index}`;
                            return <li key={row.name}><div>{label && <strong className="journal-picker-label">{label}</strong>}<span className="journal-picker-unit">{row.name}</span><span className="journal-picker-access">{access === 'unknown' ? c.observedOnly : c[access]}</span></div><button type="button" className="button small" disabled={!supported} aria-label={`${c.select} ${row.name}`} aria-describedby={supported ? undefined : reasonId} onClick={() => { if (validJournalUnit(row.name)) onSelect(row.name); }}>{c.select}</button>{!supported && <p id={reasonId} className="journal-picker-warning">{c.unsupported}</p>}</li>;
                        })}
                    </ul> : <p role="status">{!page.exhausted ? c.emptyWindow : page.totalRows === 0 ? c.zero : resource.matches === 0 ? c.noMatches : c.noMore}</p>}
                    {page.exhausted ? <p className="journal-picker-note">{c.finished}</p> : <button type="button" className="button small" disabled={resource.loading} onClick={resource.next}>{resource.search.trim() ? c.continue : c.next}</button>}
                </>}
            </>}
        </>}
    </div>;
}
