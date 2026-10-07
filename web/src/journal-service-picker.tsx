import { useEffect, useId, useRef } from 'react';
import type { KeyboardEvent } from 'react';
import { ArrowRight, Check, LoaderCircle, RefreshCw, Search } from 'lucide-react';
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
        title: 'Observed services', close: 'Close service picker', cancel: 'Cancel', placeholder: 'Search service names…', quick: 'Quick filters', keyboard: '↑ ↓ to browse · Enter on a service to select', selectionHint: 'Selection grants no access. Logs need separate approval.', selected: 'Selected', access: 'Authenticated LAN operator access is required.',
        permission: 'Observed inventory does not confirm local journal allowlist membership or grant access. Selecting a service only fills the exact-unit field; it does not capture logs.',
        manual: 'You can close this picker and enter an exact service unit manually.',
        search: 'Search observed services', searchButton: 'Search services', searchHint: 'Search retained service names and states, not journal content. Each request returns at most 100 rows and scans at most 2,048 rows.',
        loading: 'Reading observed services…', refresh: 'Refresh service list', retry: 'Retry service read',
        not_configured: 'Service inventory is not configured.', unknown: 'Service inventory is unavailable for this identity.', awaiting: 'Awaiting observed services.', revoked: 'Device identity revoked.', expired: 'Service observations or identity expired.',
        noComplete: 'No retained complete service inventory is available. This does not mean the device has no services.',
        fresh: 'Within the observation window', stale: 'Stale / historical service observations',
        prior: 'Showing the last complete inventory with its original time.', failed: 'The latest service inventory attempt failed.',
        observed: 'Original observation time', whole: 'Whole retained service inventory', scanned: 'Rows scanned so far', matches: 'Matches found so far', shown: 'Rows on this page',
        suggestions: 'Find a service by purpose', suggestionsHint: 'Shortcuts search observed service names. They do not prove that a service is installed or permitted, and do not cover every Linux distribution.', all: 'All services', observedOnly: 'Permission unknown', reported_allowed: 'In reported grant', reported_disabled: 'Policy disabled', outside_reported_scope: 'Outside reported grant',
        alias: 'Reported alias · target unavailable', aliasHint: 'Alias targets are not included in this inventory. Choose the unit used by the journal; selecting an alias does not include its target.', select: 'Use', unsupported: 'Unsupported service-unit name.',
        next: 'Next service page', continue: 'Continue search', emptyWindow: 'No matches in this scan window. More rows remain; continue searching.',
        zero: 'The complete service inventory contained zero services.', noMatches: 'No matches in the complete service inventory.', noMore: 'No further matches; earlier pages contained matches.', finished: 'The whole retained service inventory has been scanned.',
        loadError: 'Observed services could not be read. Retry or refresh.', invalid: 'The manager returned inconsistent or unsupported service inventory. Rows were cleared.', timeout: 'The service read timed out. Retry or refresh.', session: 'Your session has ended. Sign in again.', clock: 'The time anchor is no longer reliable. Refresh before continuing.', busy: 'The manager is busy. Retry in a moment.', restart: 'The service generation or paging session changed or expired. Refresh to restart; previous rows were cleared.', searchInvalid: 'Use at most 128 UTF-8 bytes without control or formatting characters.',
    },
    de: {
        title: 'Beobachtete Dienste', close: 'Dienstauswahl schließen', cancel: 'Abbrechen', placeholder: 'Dienstnamen suchen…', quick: 'Schnellfilter', keyboard: '↑ ↓ zum Navigieren · Enter auf einem Dienst zum Auswählen', selectionHint: 'Auswahl gewährt keinen Zugriff. Logs separat freigeben.', selected: 'Ausgewählt', access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.',
        permission: 'Das beobachtete Inventar bestätigt weder die lokale Journal-Freigabeliste noch gewährt es Zugriff. Die Auswahl trägt nur die exakte Unit ein; sie erfasst keine Logs.',
        manual: 'Die Auswahl lässt sich schließen, um eine exakte Service-Unit manuell einzugeben.',
        search: 'Beobachtete Dienste durchsuchen', searchButton: 'Dienste suchen', searchHint: 'Gespeicherte Dienstnamen und Zustände durchsuchen, keine Journal-Inhalte. Jede Anfrage liefert höchstens 100 Zeilen und prüft höchstens 2.048 Zeilen.',
        loading: 'Beobachtete Dienste werden gelesen…', refresh: 'Dienstliste aktualisieren', retry: 'Dienstabfrage wiederholen',
        not_configured: 'Dienstinventar ist nicht eingerichtet.', unknown: 'Dienstinventar ist für diese Identität nicht verfügbar.', awaiting: 'Beobachtete Dienste stehen aus.', revoked: 'Geräteidentität widerrufen.', expired: 'Dienstbeobachtungen oder Identität abgelaufen.',
        noComplete: 'Kein vollständiges gespeichertes Dienstinventar verfügbar. Das bedeutet nicht, dass das Gerät keine Dienste hat.',
        fresh: 'Im Beobachtungszeitfenster', stale: 'Veraltete / historische Dienstbeobachtungen',
        prior: 'Letztes vollständiges Inventar mit ursprünglichem Zeitpunkt.', failed: 'Die neueste Dienstinventar-Erfassung ist fehlgeschlagen.',
        observed: 'Ursprünglicher Beobachtungszeitpunkt', whole: 'Gesamtes gespeichertes Dienstinventar', scanned: 'Bisher geprüfte Zeilen', matches: 'Bisher gefundene Treffer', shown: 'Zeilen auf dieser Seite',
        suggestions: 'Dienste nach Aufgabe finden', suggestionsHint: 'Kurzsuchen durchsuchen beobachtete Dienstnamen. Sie belegen weder Installation noch Freigabe und decken nicht jede Linux-Distribution ab.', all: 'Alle Dienste', observedOnly: 'Freigabe unbekannt', reported_allowed: 'In gemeldeter Freigabe', reported_disabled: 'Richtlinie deaktiviert', outside_reported_scope: 'Außerhalb gemeldeter Freigabe',
        alias: 'Gemeldeter Alias · Ziel unbekannt', aliasHint: 'Alias-Ziele sind nicht in diesem Inventar enthalten. Die im Journal verwendete Unit wählen; die Auswahl eines Alias umfasst sein Ziel nicht.', select: 'Übernehmen', unsupported: 'Nicht unterstützter Service-Unit-Name.',
        next: 'Nächste Dienstseite', continue: 'Suche fortsetzen', emptyWindow: 'Keine Treffer in diesem Suchabschnitt. Weitere Zeilen stehen aus; Suche fortsetzen.',
        zero: 'Das vollständige Dienstinventar enthielt keine Dienste.', noMatches: 'Keine Treffer im vollständigen Dienstinventar.', noMore: 'Keine weiteren Treffer; frühere Seiten enthielten Treffer.', finished: 'Das gesamte gespeicherte Dienstinventar wurde durchsucht.',
        loadError: 'Beobachtete Dienste konnten nicht gelesen werden. Wiederholen oder aktualisieren.', invalid: 'Der Manager lieferte widersprüchliches oder nicht unterstütztes Dienstinventar. Zeilen wurden entfernt.', timeout: 'Die Dienstabfrage hat das Zeitlimit überschritten. Wiederholen oder aktualisieren.', session: 'Die Sitzung ist beendet. Erneut anmelden.', clock: 'Der Zeitanker ist nicht mehr verlässlich. Vor dem Fortfahren aktualisieren.', busy: 'Der Manager ist ausgelastet. Gleich erneut versuchen.', restart: 'Dienstgeneration oder Seitensitzung geändert oder abgelaufen. Zum Neubeginn aktualisieren; vorherige Zeilen wurden entfernt.', searchInvalid: 'Höchstens 128 UTF-8-Bytes ohne Steuer- oder Formatierungszeichen verwenden.',
    },
};

type JournalServicePickerProps = { deviceId: string; sessionKey: string | null; journalView?: JournalView | null; selectedUnit?: string; onSelect: (unit: string) => void; onClose: () => void };

/** Read-only inventory picker: selecting a name never requests journal content. */
export function JournalServicePicker({ deviceId, sessionKey, journalView = null, selectedUnit = '', onSelect, onClose }: JournalServicePickerProps) {
    const operator = useOperator(), [locale] = useLocale(), c = copy[locale], id = useId();
    return <section className="journal-service-picker" aria-labelledby={id} onKeyDown={event => {
        if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); onClose(); }
    }}>
        <header><h4 id={id}>{c.title}</h4></header>
        {operator?.mode === 'lan' && operator.authenticated
            ? <ObservedServices key={JSON.stringify([deviceId, sessionKey, operator.expiresAt])} deviceId={deviceId} journalView={journalView} selectedUnit={selectedUnit} onSelect={onSelect}/>
            : <p role="status">{c.access}</p>}
        <footer className="journal-picker-footer"><span>{c.selectionHint}</span><button type="button" className="button" aria-label={c.close} onClick={onClose}>{c.cancel}</button></footer>
    </section>;
}

function ObservedServices({ deviceId, journalView = null, selectedUnit = '', onSelect }: Pick<JournalServicePickerProps, 'deviceId' | 'journalView' | 'selectedUnit' | 'onSelect'>) {
    const [locale] = useLocale(), c = copy[locale], id = useId(), resource = useSystemInventory(deviceId, 'services');
    const searchInput = useRef<HTMLInputElement>(null), list = useRef<HTMLUListElement>(null), searchTimer = useRef<number | undefined>(undefined), composing = useRef(false);
    const cancelSearch = () => { window.clearTimeout(searchTimer.current); searchTimer.current = undefined; };
    useEffect(() => {
        // Wait for the dialog's own initial focus, without stealing focus after
        // the user has already moved to another control.
        const frame = window.requestAnimationFrame(() => {
            const input = searchInput.current, active = document.activeElement;
            if (input && (active === document.body || active === input.closest('[role="dialog"]'))) input.focus();
        });
        const cancel = () => { window.clearTimeout(searchTimer.current); searchTimer.current = undefined; };
        const visibility = () => { if (document.visibilityState === 'hidden') cancel(); };
        window.addEventListener('blur', cancel); window.addEventListener('pagehide', cancel); window.addEventListener('hashchange', cancel); document.addEventListener('visibilitychange', visibility);
        return () => { window.cancelAnimationFrame(frame); cancel(); window.removeEventListener('blur', cancel); window.removeEventListener('pagehide', cancel); window.removeEventListener('hashchange', cancel); document.removeEventListener('visibilitychange', visibility); };
    }, []);
    const search = () => { cancelSearch(); if (!composing.current && validSystemSearch(resource.search)) resource.startSearch(); };
    const changeSearch = (value: string) => {
        cancelSearch(); resource.changeSearch(value);
        // One bounded inventory search after typing settles. This never reads
        // journal content and is canceled by explicit submit or dismissal.
        if (!composing.current && validSystemSearch(value)) searchTimer.current = window.setTimeout(() => { searchTimer.current = undefined; resource.startSearch(); }, 250);
    };
    const chooseShortcut = (value: string) => { cancelSearch(); resource.changeSearch(value); resource.startSearch(); };
    const move = (event: KeyboardEvent<HTMLElement>, fromSearch = false) => {
        if (event.nativeEvent.isComposing || composing.current || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key) || fromSearch && !['ArrowDown', 'ArrowUp'].includes(event.key)) return;
        const buttons = Array.from(list.current?.querySelectorAll<HTMLButtonElement>('button[data-journal-unit]:not(:disabled)') ?? []);
        if (!buttons.length) return;
        event.preventDefault(); event.stopPropagation();
        const index = buttons.indexOf(event.currentTarget as HTMLButtonElement);
        if (!fromSearch && event.key === 'ArrowUp' && index === 0) { searchInput.current?.focus(); return; }
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : fromSearch ? event.key === 'ArrowUp' ? buttons.length - 1 : 0 : Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
        buttons[next]?.focus();
    };
    const { view, page } = resource, complete = view?.lastComplete.services;
    const visible = !!view && systemSectionVisible(view, 'services', resource.elapsed), searchValid = validSystemSearch(resource.search);
    const number = (n: number) => new Intl.NumberFormat(locale).format(n);
    const fact = (label: string, value: string) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    return <div aria-busy={resource.loading}>
        <div className="journal-picker-search">
            <label htmlFor={`${id}-search`}>{c.search}</label>
            <div><Search size={18} aria-hidden="true"/><input ref={searchInput} id={`${id}-search`} type="search" value={resource.search} placeholder={c.placeholder} disabled={resource.error === 'session'} onChange={event => changeSearch(event.target.value)} onCompositionStart={() => { composing.current = true; cancelSearch(); }} onCompositionEnd={event => { composing.current = false; changeSearch(event.currentTarget.value); }} onKeyDown={event => {
                if (event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); if (!event.nativeEvent.isComposing && !resource.loading && searchValid) search(); }
                else move(event, true);
            }} maxLength={128} autoComplete="off" spellCheck={false} aria-describedby={`${id}-hint${searchValid ? '' : ` ${id}-invalid`}`} aria-invalid={!searchValid}/>
                <button type="button" className="icon-button" disabled={resource.loading || !searchValid || resource.error === 'session'} onClick={search} aria-label={c.searchButton}><ArrowRight size={18}/></button></div>
            <p id={`${id}-hint`} className="sr-only">{c.searchHint} {c.keyboard}</p>
            {!searchValid && <p id={`${id}-invalid`} role="alert" className="journal-picker-warning">{c.searchInvalid}</p>}
        </div>
        <div className="journal-picker-toolbar"><details className="journal-picker-shortcuts"><summary>{c.quick}</summary><div role="group" aria-label={c.suggestions}>{journalServiceSearches.map(shortcut => <button key={shortcut.term} type="button" className="button small" disabled={resource.loading} onClick={() => chooseShortcut(shortcut.term)}>{shortcut.label[locale]}</button>)}<button type="button" className="button small" disabled={resource.loading} onClick={() => chooseShortcut('')}>{c.all}</button></div></details><button type="button" className="icon-button" disabled={resource.loading || resource.error === 'session'} onClick={() => { cancelSearch(); resource.refresh(); }} aria-label={c.refresh} title={c.refresh}><RefreshCw size={15}/></button></div>
        {resource.loading && <p role="status" className="journal-picker-note"><LoaderCircle size={14} className="spin" aria-hidden="true"/> {c.loading}</p>}
        {resource.error && <p role="alert" className="journal-picker-warning">{c[resource.error]}</p>}
        {['busy', 'timeout', 'loadError'].includes(resource.error ?? '') && <button type="button" className="button small" disabled={resource.loading} onClick={resource.retry}>{c.retry}</button>}
        {view && <>
            {!visible && <><p role="status">{view.status === 'fresh' || view.status === 'stale' ? complete ? c.expired : c.failed : c[view.status]}</p><p>{c.noComplete}</p></>}
            {complete && visible && <>
                {view.latest?.services.coverage === 'failed' && <p className="journal-picker-warning">{c.failed} {c.prior}</p>}
                {systemAgeStatus(view.serverNow, complete.meta.observedAt, resource.elapsed) !== 'fresh' && <p className="journal-picker-warning">{c.stale}</p>}
                {page && <>
                    <div className="journal-picker-list-heading"><span>{number(page.returnedCount)} {locale === 'de' ? 'angezeigt' : 'shown'}</span><span>{c.keyboard}</span></div>
                    {page.returnedCount > 0 ? <ul ref={list} className="journal-picker-rows" aria-label={c.title}>
                        {page.services.map((row, index) => {
                            const access = journalReportedAccess(journalView, row.name), supported = validJournalUnit(row.name), label = journalServiceLabel(row.name, locale), reasonId = `${id}-unsupported-${index}`, selected = selectedUnit === row.name;
                            return <li key={row.name}><button type="button" className="journal-picker-row" data-journal-unit={row.name} disabled={!supported || resource.loading} aria-label={`${c.select} ${row.name}`} aria-current={selected ? 'true' : undefined} aria-describedby={supported ? undefined : reasonId} onKeyDown={event => move(event)} onClick={() => { if (validJournalUnit(row.name)) { cancelSearch(); onSelect(row.name); } }}><span className="journal-picker-row-copy"><strong className="journal-picker-unit">{row.name}</strong>{label && <span className="journal-picker-label">{label}</span>}{row.enablement === 'alias' && <span className="journal-picker-alias" title={c.aliasHint}>{c.alias}</span>}<span className={`journal-picker-access journal-picker-access-${access}`}>{access === 'unknown' ? c.observedOnly : c[access]}</span></span>{selected ? <Check size={18} aria-label={c.selected}/> : <ArrowRight size={16} aria-hidden="true"/>}</button>{!supported && <p id={reasonId} className="journal-picker-warning">{c.unsupported}</p>}</li>;
                        })}
                    </ul> : <p role="status">{!page.exhausted ? c.emptyWindow : page.totalRows === 0 ? c.zero : resource.matches === 0 ? c.noMatches : c.noMore}</p>}
                    {!page.exhausted && <button type="button" className="button journal-picker-next" disabled={resource.loading} onClick={resource.next}>{resource.search.trim() ? c.continue : c.next}<ArrowRight size={14}/></button>}
                </>}
                <details className="journal-picker-details"><summary>{locale === 'de' ? 'Inventardetails' : 'Inventory details'}</summary>{systemAgeStatus(view.serverNow, complete.meta.observedAt, resource.elapsed) === 'fresh' && <p className="journal-picker-note">{c.fresh}</p>}<dl className="journal-picker-facts">{fact(c.observed, complete.meta.observedAt)}{fact(c.whole, number(complete.meta.observedCount!))}</dl>{page && <p className="journal-picker-count">{number(page.returnedCount)} {locale === 'de' ? 'angezeigt' : 'shown'} · {number(resource.scanned)} / {number(page.totalRows)} {locale === 'de' ? 'geprüft' : 'scanned'} · {number(resource.matches)} {locale === 'de' ? 'Treffer bisher' : 'matches so far'}</p>}{page?.exhausted && <p className="journal-picker-note">{c.finished}</p>}<p className="journal-picker-note">{c.searchHint}</p><p className="journal-picker-note">{c.suggestionsHint}</p></details>
            </>}
        </>}
    </div>;
}
