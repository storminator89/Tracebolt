import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsPatchOSField } from './windows-patch-context-types';
import './windows-patch-context.css';

const copy = {
    en: {
        title: 'Patch context', release: 'Release', build: 'Build', edition: 'Edition', revision: 'Revision', captured: 'Captured',
        reboot: 'Reboot indicators', pending: 'Pending', clear: 'None reported', clearSummary: 'No checked indicator set', unknown: 'Unknown', denied: 'Access denied', unavailable: 'Unavailable', absent: 'Not reported', observed: 'Observed', partial: 'Partial',
        windowsUpdate: 'Windows Update', servicing: 'Servicing', fileOperations: 'File operations', details: 'Details', history: 'Retained update history',
        count: (shown: number, total: number, exact: boolean) => `${shown} shown · ${exact ? '' : 'at least '}${total} retained events`,
        empty: 'No retained events returned. Installed updates and patch coverage remain unknown.', missing: 'History unavailable; installed updates and patch coverage remain unknown.',
        note: 'Retained events, not current installed inventory or patch coverage. Reboot indicators describe only the checked sources. Pending file operations alone do not imply an urgent reboot.',
        omitted: 'Some history rows were omitted.', stale: 'Stale context; values describe the original capture.', expired: 'Patch context expired after 24 hours.', ahead: 'Patch context is hidden until its capture time can be verified.',
        rowTitle: 'Update', occurred: 'Recorded at', operation: 'Operation', result: 'Result', installation: 'Installation', uninstallation: 'Uninstallation',
        'not-started': 'Not started', 'in-progress': 'In progress', succeeded: 'Succeeded', 'succeeded-with-errors': 'Succeeded with errors', failed: 'Failed', aborted: 'Aborted', shortened: 'Title shortened',
        reasons: { windows_patch_context_access_denied: 'History access denied.', windows_patch_context_unavailable: 'History source unavailable.', windows_patch_context_unsupported_platform: 'History source unsupported.', windows_patch_context_invalid_metadata: 'Some history metadata was invalid.', windows_patch_context_bounds: 'History collection limit reached.', windows_patch_context_offline_not_verified: 'Offline-only history access could not be verified.', windows_patch_context_partial_result: 'Partial history result.', windows_patch_context_budget_exhausted: 'History collection budget exhausted.' },
    },
    de: {
        title: 'Patch-Kontext', release: 'Version', build: 'Build', edition: 'Edition', revision: 'Revision', captured: 'Erfasst',
        reboot: 'Neustartindikatoren', pending: 'Ausstehend', clear: 'Keine gemeldet', clearSummary: 'Keiner der geprüften Indikatoren gesetzt', unknown: 'Unbekannt', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', absent: 'Nicht gemeldet', observed: 'Beobachtet', partial: 'Teilweise',
        windowsUpdate: 'Windows Update', servicing: 'Wartung', fileOperations: 'Dateioperationen', details: 'Details', history: 'Gespeicherter Updateverlauf',
        count: (shown: number, total: number, exact: boolean) => `${shown} angezeigt · ${exact ? '' : 'mindestens '}${total} gespeicherte Ereignisse`,
        empty: 'Keine gespeicherten Ereignisse zurückgegeben. Installierte Updates und Patch-Abdeckung bleiben unbekannt.', missing: 'Verlauf nicht verfügbar; installierte Updates und Patch-Abdeckung bleiben unbekannt.',
        note: 'Gespeicherte Ereignisse, kein aktueller Installationsbestand oder Nachweis der Patch-Abdeckung. Neustartindikatoren gelten nur für die geprüften Quellen. Ausstehende Dateioperationen allein belegen keinen dringenden Neustartbedarf.',
        omitted: 'Einige Verlaufszeilen wurden ausgelassen.', stale: 'Veralteter Kontext; Werte gelten für die ursprüngliche Erfassung.', expired: 'Patch-Kontext nach 24 Stunden abgelaufen.', ahead: 'Patch-Kontext bleibt ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        rowTitle: 'Update', occurred: 'Aufgezeichnet am', operation: 'Vorgang', result: 'Ergebnis', installation: 'Installation', uninstallation: 'Deinstallation',
        'not-started': 'Nicht gestartet', 'in-progress': 'Läuft', succeeded: 'Erfolgreich', 'succeeded-with-errors': 'Mit Fehlern abgeschlossen', failed: 'Fehlgeschlagen', aborted: 'Abgebrochen', shortened: 'Titel gekürzt',
        reasons: { windows_patch_context_access_denied: 'Zugriff auf Verlauf verweigert.', windows_patch_context_unavailable: 'Verlaufsquelle nicht verfügbar.', windows_patch_context_unsupported_platform: 'Verlaufsquelle nicht unterstützt.', windows_patch_context_invalid_metadata: 'Einige Verlaufsmetadaten waren ungültig.', windows_patch_context_bounds: 'Erfassungsgrenze für Verlauf erreicht.', windows_patch_context_offline_not_verified: 'Rein lokaler Verlaufszugriff konnte nicht bestätigt werden.', windows_patch_context_partial_result: 'Teilweises Verlaufsergebnis.', windows_patch_context_budget_exhausted: 'Zeitbudget für Verlauf erschöpft.' },
    },
};
export function WindowsPatchContextPanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], context = resource.patchContext;
    if (!context) return resource.patchContextExpired || resource.patchContextAhead ? <p role="status" className="windows-inventory-empty">{resource.patchContextExpired ? c.expired : c.ahead}</p> : null;
    const { os, reboot, history } = context;
    const display = (field: WindowsPatchOSField) => field.quality === 'observed' ? field.value : c[field.quality];
    const states = Object.values(reboot), rebootState = states.includes('pending') ? 'pending' : states.every(state => state === 'clear') ? 'clear' : 'unknown';
    const headers = [c.rowTitle, c.occurred, c.operation, c.result];
    return <section className="windows-patch-context" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={context.collectedAt}>{fullDate(context.collectedAt)}</time></span></div>
        <p className="windows-patch-os">{os.edition.quality === 'observed' ? display(os.edition) : `${c.edition} ${display(os.edition)}`} · {c.release} {display(os.release)} · {c.build} {display(os.build)}{os.build.quality === 'observed' && os.revision.quality === 'observed' ? `.${os.revision.value}` : ` · ${c.revision} ${display(os.revision)}`}</p>
        <p className="windows-patch-reboot">{c.reboot}: <strong>{rebootState === 'clear' ? c.clearSummary : c[rebootState]}</strong></p>
        {resource.patchContextStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <details className="windows-patch-details" key={`${context.grantId}:${context.generationId}:${context.collectedAt}`}>
            <summary>{c.details} · {c.history}: {history.quality === 'partial' && `${c.partial} · `}{history.quality === 'observed' || history.quality === 'partial' ? c.count(history.rows.length, history.totalCount, history.countExact) : c[history.quality]}</summary>
            <dl className="windows-patch-sources">{(['windowsUpdate', 'servicing', 'fileOperations'] as const).map(key => <div key={key}><dt>{c[key]}</dt><dd>{c[reboot[key]]}</dd></div>)}</dl>
            <p className="windows-inventory-exclusions">{c.note}</p>
            {history.reason && <p className="windows-inventory-caution">{c.reasons[history.reason]}</p>}
            {history.truncated && <p className="windows-inventory-caution">{c.omitted}</p>}
            {history.rows.length ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-patch-history-table"><caption className="sr-only">{c.history}</caption><thead><tr>{headers.map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{history.rows.map(row => <tr key={row.index}>
                <td data-label={c.rowTitle}><div>{row.title}{row.metadataTruncated && <small>{c.shortened}</small>}<details className="windows-patch-row-details"><summary>{c.details}</summary><span>{row.updateId} · {c.revision} {row.revision}</span></details></div></td>
                <td data-label={c.occurred}><time dateTime={row.occurredAt}>{fullDate(row.occurredAt)}</time></td><td data-label={c.operation}>{c[row.operation]}</td><td data-label={c.result}><div>{c[row.result]}<small>HRESULT: {row.hresult}</small></div></td>
            </tr>)}</tbody></table></div> : <p className="windows-inventory-empty">{history.quality === 'observed' && history.totalCount === 0 ? c.empty : c.missing}</p>}
        </details>
    </section>;
}
