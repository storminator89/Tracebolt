import { ArrowLeftRight, CircleMinus, CirclePlus, History, Info, ListOrdered, PencilLine } from 'lucide-react';
import { inventoryAge } from './complete-packages-types';
import { fullDate } from './utils';
import type { FullSoftwareRow } from './windows-full-software-types';
import type { SoftwareHistoryChange, SoftwareHistoryPage } from './windows-software-history-types';
import './windows-software-registration-trails.css';

const copy = {
    en: {
        title: 'History by registration',
        shortScope: 'Loaded page only. Gaps are possible; current state is not established.',
        about: 'How to read this history', steps: 'Changes on this page', pair: 'Before and after observations',
        scope: 'Only registrations with multiple changes on this loaded page are grouped, by exact registration ID and registry view. Search and other pages may hide earlier, later or intervening evidence. Names can repeat or change; these are not application identities.',
        meaning: 'Each entry keeps its own before/after observations. The first and last shown values are not a complete lifetime, installation or uninstall times, or proof of the current state. Gaps, omissions and expired evidence remain possible.',
        entries: 'changes shown', id: 'Registration ID', evidence: 'First and last shown observations',
        first: 'First shown before', last: 'Last shown after', before: 'Before observation', after: 'After observation',
        field: 'Field', name: 'Name', version: 'Version', publisher: 'Publisher', absent: 'Not in this capture', unknown: 'Unavailable', empty: 'Empty value',
        added: 'Registration added', removed: 'Registration removed', changed: 'Metadata changed', fields: 'Observed changed fields', expires: 'Evidence expires',
        chronology: 'Original observation pairs, oldest later observation first',
    },
    de: {
        title: 'Verlauf je Registrierung',
        shortScope: 'Nur die geladene Seite. Lücken sind möglich; der aktuelle Zustand ist nicht belegt.',
        about: 'Diesen Verlauf richtig lesen', steps: 'Änderungen auf dieser Seite', pair: 'Vorher- und Nachher-Beobachtungen',
        scope: 'Gruppiert werden nur Registrierungen mit mehreren Änderungen auf dieser geladenen Seite, nach exakter Registrierungs-ID und Registry-Ansicht. Suche und andere Seiten können frühere, spätere oder dazwischenliegende Belege ausblenden. Namen können mehrfach vorkommen oder wechseln; dies sind keine Programmidentitäten.',
        meaning: 'Jeder Eintrag behält seine eigenen Vorher-/Nachher-Beobachtungen. Die ersten und letzten angezeigten Werte sind weder ein vollständiger Lebenslauf noch Installations- oder Deinstallationszeiten oder ein Beleg des aktuellen Zustands. Lücken, ausgelassene und abgelaufene Belege bleiben möglich.',
        entries: 'angezeigte Änderungen', id: 'Registrierungs-ID', evidence: 'Erste und letzte angezeigte Beobachtung',
        first: 'Erste angezeigte Vorher-Beobachtung', last: 'Letzte angezeigte Nachher-Beobachtung', before: 'Vorher-Beobachtung', after: 'Nachher-Beobachtung',
        field: 'Feld', name: 'Name', version: 'Version', publisher: 'Herausgeber', absent: 'Nicht in dieser Erfassung', unknown: 'Nicht verfügbar', empty: 'Leerer Wert',
        added: 'Registrierung hinzugefügt', removed: 'Registrierung entfernt', changed: 'Metadaten geändert', fields: 'Beobachtete geänderte Felder', expires: 'Beleg läuft ab',
        chronology: 'Ursprüngliche Beobachtungspaare, nach späterer Beobachtung aufsteigend',
    },
};
type Locale = 'en' | 'de';
function Stamp({ value }: { value: string }) {
    return <time dateTime={value}>{fullDate(value)}<small className="windows-registration-exact-time">{value}</small></time>;
}

/** No cross-page cache or name-based join. The caller supplies only its currently
 * admitted page; every source/query/page replacement resets native disclosures. */
export function WindowsSoftwareRegistrationTrails({ page, locale }: { page: SoftwareHistoryPage; locale: Locale }) {
    const groups = new Map<string, SoftwareHistoryChange[]>();
    for (const row of page.rows) {
        const key = `${row.registrationId}:${row.registryView}`;
        const group = groups.get(key) ?? []; group.push(row); groups.set(key, group);
    }
    const repeated = [...groups.entries()].filter(([, rows]) => rows.length > 1);
    if (repeated.length === 0) return null;
    const c = copy[locale], key = JSON.stringify([page.deviceId, page.grantId, page.grantRevision, page.historyDigest, page.search, page.offset]);
    return <details key={key} className="windows-registration-trails">
        <summary><span className="windows-registration-label"><History size={16} aria-hidden="true" focusable="false"/>{c.title} ({repeated.length})</span></summary>
        <p className="windows-registration-scope">{c.shortScope}</p>
        <details className="windows-registration-help"><summary><span className="windows-registration-label"><Info size={14} aria-hidden="true" focusable="false"/>{c.about}</span></summary><p>{c.scope}</p><p>{c.meaning}</p></details>
        {repeated.map(([identity, rows]) => <Trail key={identity} rows={rows} locale={locale}/>)}
    </details>;
}
function Values({ before, after, beforeAt, afterAt, firstLast = false, locale }: {
    before: FullSoftwareRow | null; after: FullSoftwareRow | null; beforeAt: string; afterAt: string; firstLast?: boolean; locale: Locale;
}) {
    const c = copy[locale], value = (row: FullSoftwareRow | null, field: 'name' | 'version' | 'publisher') => row === null ? c.absent : row[field] === null ? c.unknown : row[field] === '' ? c.empty : <bdi>{row[field]}</bdi>;
    return <div><dl className="windows-registration-observations"><div><dt>{firstLast ? c.first : c.before}</dt><dd><Stamp value={beforeAt}/></dd></div><div><dt>{firstLast ? c.last : c.after}</dt><dd><Stamp value={afterAt}/></dd></div></dl><div className="windows-inventory-table-wrap"><table className="windows-inventory-table">
        <caption className={firstLast ? 'sr-only' : undefined}>{firstLast ? c.evidence : c.pair}</caption>
        <thead><tr><th scope="col">{c.field}</th><th scope="col">{firstLast ? c.first : c.before}</th><th scope="col">{firstLast ? c.last : c.after}</th></tr></thead>
        <tbody>{(['name', 'version', 'publisher'] as const).map(field => <tr key={field}><th scope="row">{c[field]}</th><td data-label={firstLast ? c.first : c.before}>{value(before, field)}</td><td data-label={firstLast ? c.last : c.after}>{value(after, field)}</td></tr>)}</tbody>
    </table></div></div>;
}
function Trail({ rows, locale }: { rows: SoftwareHistoryChange[]; locale: Locale }) {
    // Stable ordering preserves response ties, including sub-millisecond times.
    const ordered = [...rows].sort((a, b) => inventoryAge(a.afterObservedAt, b.afterObservedAt));
    const first = ordered[0], last = ordered[ordered.length - 1], latest = last.after ?? last.before!, c = copy[locale];
    const name = latest.name === null ? c.unknown : latest.name === '' ? c.empty : latest.name;
    const kind = (row: SoftwareHistoryChange) => row.kind === 'registration_added' ? c.added : row.kind === 'registration_removed' ? c.removed : c.changed;
    return <details className="windows-registration-trail" data-registration-trail={`${first.registrationId}:${first.registryView}`}>
        <summary aria-label={`${name} · HKLM ${first.registryView} · ${rows.length} ${c.entries} · ${c.id}: ${first.registrationId}`}><bdi>{name}</bdi><small>HKLM {first.registryView} · {rows.length} {c.entries}</small></summary>
        <p className="windows-registration-identity">{c.id}: <code>{first.registrationId}</code></p>
        <section className="windows-registration-section" aria-label={c.evidence}>
            <h4><ArrowLeftRight size={16} aria-hidden="true" focusable="false"/>{c.evidence}</h4>
            <Values before={first.before} after={last.after} beforeAt={first.beforeObservedAt} afterAt={last.afterObservedAt} firstLast locale={locale}/>
        </section>
        <section className="windows-registration-section" aria-label={c.steps}>
        <h4><ListOrdered size={16} aria-hidden="true" focusable="false"/>{c.steps}</h4>
        <ol aria-label={c.chronology}>{ordered.map(row => {
            const Icon = row.kind === 'registration_added' ? CirclePlus : row.kind === 'registration_removed' ? CircleMinus : PencilLine;
            return <li key={row.id} data-trail-change={row.id}><details>
            <summary><span className="windows-registration-label"><Icon size={15} aria-hidden="true" focusable="false"/>{kind(row)}</span><Stamp value={row.afterObservedAt}/></summary>
            {row.changedFields.length > 0 && <p>{c.fields}: {row.changedFields.map(field => c[field]).join(', ')}</p>}
            <Values before={row.before} after={row.after} beforeAt={row.beforeObservedAt} afterAt={row.afterObservedAt} locale={locale}/>
            <p>{c.expires}: <Stamp value={row.expiresAt}/></p>
        </details></li>; })}</ol>
        </section>
    </details>;
}
