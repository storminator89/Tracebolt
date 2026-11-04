import { useId, useState } from 'react';
import { useLocale } from './i18n';
import { compareNetworkObservations } from './network-interval-model';
import type { NetworkIntervalRow, NetworkObservation } from './network-interval-model';
import './network-interval.css';

const copy = {
    en: {
        title: 'Network counter interval', intro: 'Choose a baseline, then refresh existing observations after a later agent report. Only two bounded observations, fresh at selection, from the visible namespace are compared. Partial coverage stays partial. No extra collection starts.',
        set: 'Use current network observation as baseline', replace: 'Replace network baseline', clear: 'Clear network baseline', noBaseline: 'No network baseline selected.', unavailable: 'A fresh network observation with collected rows and unique interface names is required. Retained, denied, stale and unavailable observations cannot be used.',
        baseline: 'Baseline original observation', current: 'Current original observation', received: 'Accepted', generation: 'Generation', sequence: 'Sequence', seconds: 'Original observation interval (seconds)',
        waiting: 'Waiting for a different original observation. Refreshing unchanged counters or timestamps does not create an interval.', too_short: 'The original observations are less than one second apart. Rates are withheld.', changed: 'Source identity, sequence or original time changed inconsistently. Choose a new baseline.', expired: 'The original observations are more than one hour apart. Choose a new baseline.', cleared: 'The previous baseline was cleared because its source was lost, changed or exceeded the comparison window.', refreshing: 'Reading the existing source. Comparison is withheld while it is unavailable.',
        limits: 'Names are the only interface match key. Reboots, counter resets, renamed or replaced interfaces cannot be excluded, even when counters increase. Values below are arithmetic counter changes, not verified traffic throughput, bandwidth utilization, continuous activity or packet-loss rates. State describes each endpoint observation only. Rates use source snapshot timestamps, not individual interface-read times, and are rounded to six significant digits.',
        coverage: 'Source coverage', complete: 'Complete visible namespace', partial: 'Partial coverage', truncated: 'Truncated rows', exact: 'Exact discovered count', atLeast: 'At least', receivedRows: 'Received rows', cap: 'Row cap', reason: 'Original source reason', addressNote: 'Address counts are not used for differences. The current native source deliberately leaves them unknown.',
        endpoints: 'Original counter values', counterRx: 'Received bytes', counterTx: 'Sent bytes', counterRxErrors: 'RX errors', counterTxErrors: 'TX errors',
        filter: 'Filter compared interface names', matched: 'Matched names', onlyBefore: 'Baseline only', onlyAfter: 'Current only', withheld: 'Matched names with withheld differences', unknown: 'Unknown', name: 'Interface name', context: 'Observation context', outcome: 'Comparison', rx: 'Received byte change', tx: 'Sent byte change', rxRate: 'Received change / second', txRate: 'Sent change / second', rxErrors: 'RX error change', txErrors: 'TX error change',
        baseline_only: 'Only in baseline observation; not proof of removal', current_only: 'Only in current observation; not proof of addition', decreased: 'A counter decreased; all differences withheld', context_changed: 'MTU context changed; all differences withheld', matchedRow: 'Name matched; identity continuity unverified', empty: 'No interface names match this filter.', zero: 'Both bounded observations contained zero received interface rows; this does not establish absence.', up: 'Up', down: 'Down', before: 'Baseline', after: 'Current',
    },
    de: {
        title: 'Netzwerkzähler-Intervall', intro: 'Einen Ausgangsstand wählen und die vorhandenen Beobachtungen nach einer späteren Agent-Meldung aktualisieren. Verglichen werden nur zwei begrenzte, bei Auswahl frische Beobachtungen des sichtbaren Namensraums. Teilweise Erfassung bleibt teilweise. Es startet keine zusätzliche Erfassung.',
        set: 'Aktuelle Netzwerkbeobachtung als Ausgangsstand verwenden', replace: 'Netzwerk-Ausgangsstand ersetzen', clear: 'Netzwerk-Ausgangsstand löschen', noBaseline: 'Kein Netzwerk-Ausgangsstand gewählt.', unavailable: 'Eine frische Netzwerkbeobachtung mit erfassten Zeilen und eindeutigen Schnittstellennamen ist erforderlich. Aufbewahrte, verweigerte, veraltete und nicht verfügbare Beobachtungen sind nicht verwendbar.',
        baseline: 'Ursprüngliche Ausgangsbeobachtung', current: 'Ursprüngliche aktuelle Beobachtung', received: 'Akzeptiert', generation: 'Generation', sequence: 'Sequenz', seconds: 'Intervall der Originalbeobachtungen (Sekunden)',
        waiting: 'Eine andere Originalbeobachtung steht aus. Unveränderte Zähler oder Zeitstempel erzeugen beim Aktualisieren kein Intervall.', too_short: 'Die Originalbeobachtungen liegen weniger als eine Sekunde auseinander. Raten werden nicht ausgewiesen.', changed: 'Quellidentität, Sequenz oder Originalzeit hat sich widersprüchlich geändert. Einen neuen Ausgangsstand wählen.', expired: 'Die Originalbeobachtungen liegen mehr als eine Stunde auseinander. Einen neuen Ausgangsstand wählen.', cleared: 'Der vorherige Ausgangsstand wurde gelöscht, weil seine Quelle verloren ging, sich änderte oder das Vergleichsfenster überschritten wurde.', refreshing: 'Die vorhandene Quelle wird gelesen. Solange sie nicht verfügbar ist, wird kein Vergleich ausgewiesen.',
        limits: 'Schnittstellen werden nur über ihren Namen zugeordnet. Neustarts, Zählerrücksetzungen sowie umbenannte oder ersetzte Schnittstellen sind auch bei steigenden Zählern nicht auszuschließen. Die Werte sind rechnerische Zähleränderungen, kein verifizierter Datendurchsatz, keine Bandbreitenauslastung, kontinuierliche Aktivität oder Paketverlustrate. Der Zustand gilt nur für die jeweilige Einzelbeobachtung. Raten verwenden die Zeitstempel der Quellbeobachtungen, keine einzelnen Schnittstellen-Lesezeiten, und werden auf sechs signifikante Stellen gerundet.',
        coverage: 'Quellabdeckung', complete: 'Vollständig sichtbarer Namensraum', partial: 'Teilweise erfasst', truncated: 'Begrenzte Zeilen', exact: 'Exakte gefundene Anzahl', atLeast: 'Mindestens', receivedRows: 'Empfangene Zeilen', cap: 'Zeilenlimit', reason: 'Ursprünglicher Quellgrund', addressNote: 'Adressanzahlen werden nicht für Differenzen verwendet. Die aktuelle native Quelle lässt sie bewusst unbekannt.',
        endpoints: 'Ursprüngliche Zählerwerte', counterRx: 'Empfangene Bytes', counterTx: 'Gesendete Bytes', counterRxErrors: 'RX-Fehler', counterTxErrors: 'TX-Fehler',
        filter: 'Verglichene Schnittstellennamen filtern', matched: 'Übereinstimmende Namen', onlyBefore: 'Nur im Ausgangsstand', onlyAfter: 'Nur im aktuellen Stand', withheld: 'Übereinstimmende Namen ohne ausgewiesene Differenzen', unknown: 'Unbekannt', name: 'Schnittstellenname', context: 'Beobachtungskontext', outcome: 'Vergleich', rx: 'Änderung empfangener Bytes', tx: 'Änderung gesendeter Bytes', rxRate: 'Empfangsänderung / Sekunde', txRate: 'Sendeänderung / Sekunde', rxErrors: 'Änderung RX-Fehler', txErrors: 'Änderung TX-Fehler',
        baseline_only: 'Nur in der Ausgangsbeobachtung; kein Beleg für Entfernung', current_only: 'Nur in der aktuellen Beobachtung; kein Beleg für Hinzufügung', decreased: 'Ein Zähler sank; keine Differenzen ausgewiesen', context_changed: 'MTU-Kontext geändert; keine Differenzen ausgewiesen', matchedRow: 'Name zugeordnet; Identitätskontinuität ungeprüft', empty: 'Keine Schnittstellennamen entsprechen diesem Filter.', zero: 'Beide begrenzten Beobachtungen enthielten keine empfangenen Schnittstellenzeilen; dies belegt keine Abwesenheit.', up: 'Aktiv', down: 'Inaktiv', before: 'Ausgangsstand', after: 'Aktuell',
    },
} as const;

function NetworkIntervalTableRow({ row, seconds }: { row: NetworkIntervalRow; seconds: number }) {
    const [locale] = useLocale(), c = copy[locale];
    const number = (value: number | null, rate = false) => value === null ? c.unknown : value.toLocaleString(locale, rate ? { maximumSignificantDigits: 6 } : { maximumFractionDigits: 0 });
    const observations = [['before', row.before], ['after', row.after]] as const;
    const counters = [['counterRx', 'rxBytes'], ['counterTx', 'txBytes'], ['counterRxErrors', 'rxErrors'], ['counterTxErrors', 'txErrors']] as const;
    return <tr>
        <th scope="row">{row.name}</th>
        <td>
            {observations.map(([label, source]) => <div key={label}>{c[label]}: {source ? `${c[source.state]} · MTU ${number(source.mtu)}` : c.unknown}</div>)}
            <details>
                <summary>{c.endpoints}</summary>
                {observations.map(([label, source]) => <div key={label}>
                    <strong>{c[label]}</strong>
                    <dl>{counters.map(([caption, key]) => <div key={key}><dt>{c[caption]}</dt><dd>{number(source?.[key] ?? null)}</dd></div>)}</dl>
                </div>)}
            </details>
        </td>
        <td>{row.status === 'matched' ? c.matchedRow : c[row.status]}</td>
        <td>{number(row.differences.rxBytes)}</td>
        <td>{number(row.differences.rxBytes === null ? null : row.differences.rxBytes / seconds, true)}</td>
        <td>{number(row.differences.txBytes)}</td>
        <td>{number(row.differences.txBytes === null ? null : row.differences.txBytes / seconds, true)}</td>
        <td>{number(row.differences.rxErrors)}</td>
        <td>{number(row.differences.txErrors)}</td>
    </tr>;
}

export function NetworkInterval({ baseline, current, pending, cleared, onSet, onClear }: {
    baseline: NetworkObservation | null; current: NetworkObservation | null; pending: boolean; cleared: boolean;
    onSet: () => void; onClear: () => void;
}) {
    const [locale] = useLocale(), c = copy[locale], filterId = useId();
    const [filter, setFilter] = useState('');
    const result = baseline && current ? compareNetworkObservations(baseline, current) : null;
    const observation = (label: string, source: NetworkObservation) => <div>
        <dt>{label}</dt>
        <dd>
            <time dateTime={source.observedAt}>{source.observedAt}</time><br/>
            {c.received}: <time dateTime={source.receivedAt}>{source.receivedAt}</time><br/>
            {c.generation}: <span>{source.generationId}</span><br/>
            {c.sequence}: {source.sequence}<br/>
            {c.coverage}: <span>{source.coverage.complete ? c.complete : c.partial}</span>{source.coverage.truncated && <> · {c.truncated}</>}<br/>
            {source.coverage.countExact ? c.exact : c.atLeast}: {source.coverage.observedCount} · {c.receivedRows}: {source.rows.length} · {c.cap}: {source.coverage.itemLimit}<br/>
            {c.reason}: <span>{source.coverage.reason}</span>
        </dd>
    </div>;
    const counts = result ? [
        [c.matched, result.rows.filter(row => row.before && row.after).length],
        [c.onlyBefore, result.rows.filter(row => row.status === 'baseline_only').length],
        [c.onlyAfter, result.rows.filter(row => row.status === 'current_only').length],
        [c.withheld, result.rows.filter(row => row.status === 'decreased' || row.status === 'context_changed' || row.status === 'matched' && Object.values(row.differences).some(value => value === null)).length],
    ] as const : [];
    const rows = result?.rows.filter(row => row.name.toLowerCase().includes(filter.slice(0, 160).trim().toLowerCase())) ?? [];
    return <section className="network-interval" aria-label={c.title}>
        <h3>{c.title}</h3>
        <p>{c.intro}</p>
        <div className="network-interval-controls">
            <button type="button" className="button small" disabled={!current || pending} onClick={onSet}>{baseline ? c.replace : c.set}</button>
            {baseline && <button type="button" className="button small" onClick={() => { setFilter(''); onClear(); }}>{c.clear}</button>}
        </div>
        {!baseline && <p role="status">{cleared ? c.cleared : c.noBaseline}</p>}
        {!current && <p role="status">{pending ? c.refreshing : c.unavailable}</p>}
        <p className="network-interval-limits">{c.limits}</p>
        <p>{c.addressNote}</p>
        <dl className="network-interval-provenance">
            {baseline && observation(c.baseline, baseline)}
            {current && observation(c.current, current)}
            {result?.seconds !== null && result?.seconds !== undefined && <div><dt>{c.seconds}</dt><dd>{result.seconds.toLocaleString(locale, { maximumFractionDigits: 9 })}</dd></div>}
        </dl>
        {result && result.status !== 'advanced' && <p role="status">{c[result.status]}</p>}
        {result?.status === 'advanced' && <>
            <dl className="network-interval-counts">{counts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
            <label className="network-interval-filter" htmlFor={filterId}>
                {c.filter}<input id={filterId} type="search" maxLength={160} value={filter} onChange={event => setFilter(event.target.value)} autoComplete="off" spellCheck={false}/>
            </label>
            {rows.length ? <div className="network-interval-scroll" role="region" aria-label={`${c.title}: ${c.name}`} tabIndex={0}>
                <table>
                    <caption className="sr-only">{c.title}</caption>
                    <thead><tr>{[c.name, c.context, c.outcome, c.rx, c.rxRate, c.tx, c.txRate, c.rxErrors, c.txErrors].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
                    <tbody>{rows.map(row => <NetworkIntervalTableRow key={row.name} row={row} seconds={result.seconds!}/>)}</tbody>
                </table>
            </div> : <p role="status">{result.rows.length ? c.empty : c.zero}</p>}
        </>}
    </section>;
}
