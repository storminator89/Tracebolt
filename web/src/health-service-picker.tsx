import { useId, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { useOperator } from './auth';
import { validHealthService } from './health-types';
import { t, useLocale } from './i18n';
import { useSystemInventory } from './system-inventory-resource';
import { systemAgeStatus, systemSectionVisible, validSystemSearch } from './system-inventory-types';
import './health-service-picker.css';

type Props = { deviceId: string; sessionKey: string | null; selected: string[]; disabled: boolean; onChange: (services: string[]) => void };
/** Read retained inventory only. Selection changes a draft; its parent owns Save. */
export function HealthServicePicker(props: Props) {
    const operator = useOperator();
    useLocale();
    return operator?.mode === 'lan' && operator.authenticated
        ? <ServiceChoices key={JSON.stringify([props.deviceId, props.sessionKey, operator.expiresAt])} {...props}/>
        : <p className="health-note">{t('Ein authentifizierter LAN-Operator-Zugang ist erforderlich.')}</p>;
}
function ServiceChoices({ deviceId, selected, disabled, onChange }: Props) {
    const [locale] = useLocale(), id = useId(), resource = useSystemInventory(deviceId, 'services');
    const [manual, setManual] = useState('');
    const { view, page } = resource, complete = view?.lastComplete.services;
    const visible = !!view && systemSectionVisible(view, 'services', resource.elapsed);
    const searchValid = validSystemSearch(resource.search), manualUnit = manual.trim();
    const capped = selected.length >= 8, locked = disabled || resource.error === 'session';
    const canAdd = (unit: string) => !locked && !capped && validHealthService(unit) && !selected.includes(unit);
    const add = (unit: string) => { if (canAdd(unit)) onChange([...selected, unit].sort()); };
    const remove = (unit: string) => { if (!locked) onChange(selected.filter(value => value !== unit)); };
    const enter = (event: KeyboardEvent<HTMLInputElement>, action: () => void) => {
        if (event.key === 'Enter') { event.preventDefault(); event.stopPropagation(); if (!event.nativeEvent.isComposing) action(); }
    };
    const number = (value: number) => new Intl.NumberFormat(locale).format(value);
    // A completed empty inventory or an empty search is not an inventory failure.
    const unavailable = !resource.loading && (view ? !visible || !!resource.error : !!resource.error);
    if (resource.error === 'session') return <p role="alert" className="health-failure">{t('Die Sitzung ist abgelaufen. Bitte erneut anmelden.')}</p>;
    return <div className="health-service-picker" aria-busy={resource.loading}>
        <p className="health-note" id={`${id}-selection-note`}>{t('Bis zu 8 Dienste; danach speichern. Keine zusätzliche Erfassung oder Logs.')}</p>
        <p className="health-note" role="status">{t('{0} von 8 Diensten ausgewählt', { 0: selected.length })}{capped && <> · {t('Zum Hinzufügen zuerst einen Dienst entfernen.')}</>}</p>
        {selected.length > 0 ? <ul className="health-service-chips" aria-label={t('Ausgewählte Dienste')}>
            {selected.map(unit => <li key={unit}><span>{unit}</span><button type="button" disabled={locked} onClick={() => remove(unit)} aria-label={t('Dienst entfernen: {0}', { 0: unit })}>×</button></li>)}
        </ul> : <p className="health-note">{t('Keine Auswahl. Speichern beendet bestehende Dienstprüfungen.')}</p>}
        <button className="button small" type="button" disabled={locked || resource.loading} onClick={resource.refresh}>{t('Dienstliste aktualisieren')}</button>
        {resource.loading && <p role="status" className="health-note">{t('Beobachtete Dienste werden gelesen …')}</p>}
        {resource.error && <p role="alert" className="health-failure">{resource.error === 'restart' ? t('Dienstgeneration oder Seitensitzung geändert oder abgelaufen. Dienste aktualisieren.') : resource.error === 'clock' ? t('Zeitbezug des Dienstinventars geändert. Dienste aktualisieren.') : t('Dienstinventar konnte nicht verlässlich gelesen werden. Dienste aktualisieren.')}</p>}
        {unavailable && <p className="health-note" role="status">{t('Dienstinventar fehlt, nicht die Dienste. Manuelle Auswahl bleibt bis zur Beobachtung unbekannt.')}</p>}
        {complete && visible && <>
            <p className="health-note">{systemAgeStatus(view!.serverNow, complete.meta.observedAt, resource.elapsed) === 'fresh' ? t('Dienste im Beobachtungszeitfenster') : t('Veraltete / historische Dienstbeobachtungen')}<br/>{t('Ursprünglich beobachtet:')} <time dateTime={complete.meta.observedAt}>{complete.meta.observedAt}</time><br/>{t('Gespeicherte Dienste insgesamt: {0}', { 0: number(complete.meta.observedCount!) })}</p>
            {view!.latest?.services.coverage === 'failed' && <p className="health-note">{t('Die neuere Erfassung ist fehlgeschlagen. Der ursprüngliche Beobachtungszeitpunkt bleibt unverändert.')}</p>}
            <label htmlFor={`${id}-search`}>{t('Beobachtete Dienste durchsuchen')}</label>
            <div className="health-service-search"><input id={`${id}-search`} type="search" value={resource.search} disabled={locked} maxLength={128} autoComplete="off" spellCheck={false} aria-invalid={!searchValid} aria-describedby={`${id}-search-note`} onChange={event => resource.changeSearch(event.target.value)} onKeyDown={event => enter(event, () => { if (!locked && !resource.loading && searchValid) resource.startSearch(); })}/><button className="button small" type="button" disabled={locked || resource.loading || !searchValid} onClick={resource.startSearch}>{t('Dienste suchen')}</button></div>
            <p className="health-note" id={`${id}-search-note`}>{t('Namen und Zustände: bis zu 100 Treffer aus 2.048 Zeilen je Anfrage.')}</p>
            {!searchValid && <p className="health-failure" role="alert">{t('Höchstens 128 UTF-8-Bytes ohne Steuer- oder Formatierungszeichen verwenden.')}</p>}
            {page && <>
                <p className="health-note">{t('Geprüft: {0} / {1} · Treffer bisher: {2}', { 0: number(resource.scanned), 1: number(page.totalRows), 2: number(resource.matches) })}</p>
                {page.services.length > 0 ? <ul className="health-service-options" aria-label={t('Beobachtete Dienste')}>
                    {page.services.map((row, index) => <li key={row.name}><label><input type="checkbox" checked={selected.includes(row.name)} disabled={locked || !validHealthService(row.name) || capped && !selected.includes(row.name)} aria-describedby={validHealthService(row.name) ? undefined : `${id}-unsupported-${index}`} onChange={() => selected.includes(row.name) ? remove(row.name) : add(row.name)}/><span>{row.name}</span></label><small>{t('Beobachteter Zustand:')} {row.runtime?.activeState ?? t('Unbekannt')}</small>{!validHealthService(row.name) && <p className="health-note" id={`${id}-unsupported-${index}`}>{t('Dieser beobachtete Name wird von Health-Prüfungen nicht unterstützt.')}</p>}</li>)}
                </ul> : <p role="status" className="health-note">{!page.exhausted ? t('Keine Treffer in diesem Suchabschnitt. Weitere Zeilen stehen aus.') : page.totalRows === 0 ? t('Das vollständige Dienstinventar enthielt keine Dienste.') : resource.matches === 0 ? t('Keine Treffer im vollständigen Dienstinventar.') : t('Keine weiteren Treffer. Frühere Seiten enthielten Treffer.')}</p>}
                {!page.exhausted && <button className="button small" type="button" disabled={locked || resource.loading} onClick={resource.next}>{resource.search.trim() ? t('Dienstsuche fortsetzen') : t('Nächste Dienstseite')}</button>}
            </>}
        </>}
        {unavailable && <div className="health-service-manual"><label htmlFor={`${id}-manual`}>{t('Dienst manuell hinzufügen')}</label><div className="health-service-search"><input id={`${id}-manual`} value={manual} maxLength={127} disabled={locked || capped} autoComplete="off" spellCheck={false} aria-invalid={!!manualUnit && !validHealthService(manualUnit)} aria-describedby={`${id}-manual-note`} onChange={event => setManual(event.target.value)} onKeyDown={event => enter(event, () => { if (canAdd(manualUnit)) { add(manualUnit); setManual(''); } })}/><button className="button small" type="button" disabled={!canAdd(manualUnit)} onClick={() => { add(manualUnit); setManual(''); }}>{t('Dienst hinzufügen')}</button></div><p className="health-note" id={`${id}-manual-note`}>{t('Exakter .service-Name, keine Platzhalter. Danach Auswahl speichern.')}</p></div>}
    </div>;
}
