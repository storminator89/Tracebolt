import { useId, useState } from 'react';
import type { ReactNode } from 'react';
import { CircleHelp, DatabaseZap, ListFilter, SearchCheck, SearchX } from 'lucide-react';
import { useLocale } from './i18n';
import type { FleetSoftwareItem, FleetSoftwarePage } from './windows-fleet-software-types';
import './windows-fleet-software-coverage.css';

type Coverage = 'matches' | 'unclear' | 'noMatch' | 'noCapture';
const categories = ['matches', 'unclear', 'noMatch', 'noCapture'] as const;
const icons = { all: ListFilter, matches: SearchCheck, unclear: CircleHelp, noMatch: SearchX, noCapture: DatabaseZap };
const copy = {
    en: {
        title: 'Search coverage', all: 'All', matches: 'With matches', unclear: 'Unclear', noMatch: 'No reported match', noCapture: 'No complete capture',
        scope: 'Devices on this page only. No match does not prove absence.', details: 'How to read this',
        explanation: 'Each device appears in one group. With matches means at least one reported match, even if other queried fields are unavailable. Unclear means no reported match and some queried fields are unavailable. Counts use retained captures, not current installation or compliance. Original capture ages and software scope exclusions still apply.',
        shown: 'Devices shown', of: 'of', empty: 'No devices in this group on this page.',
    },
    de: {
        title: 'Suchabdeckung', all: 'Alle', matches: 'Mit Treffern', unclear: 'Unklar', noMatch: 'Kein gemeldeter Treffer', noCapture: 'Keine vollständige Erfassung',
        scope: 'Nur Geräte dieser Seite. Kein Treffer belegt nicht, dass Software fehlt.', details: 'Hinweise zur Einordnung',
        explanation: 'Jedes Gerät gehört zu einer Gruppe. Mit Treffern bedeutet mindestens einen gemeldeten Treffer, auch wenn andere Suchfelder nicht verfügbar sind. Unklar bedeutet keinen gemeldeten Treffer bei teilweise nicht verfügbaren Suchfeldern. Die Zahlen beziehen sich auf gespeicherte Erfassungen, nicht auf aktuelle Installation oder Richtlinienkonformität. Ursprüngliches Erfassungsalter und ausgeschlossene Softwarequellen gelten weiterhin.',
        shown: 'Angezeigte Geräte', of: 'von', empty: 'Keine Geräte dieser Gruppe auf dieser Seite.',
    },
};

function coverage(item: FleetSoftwareItem): Coverage {
    if (item.status !== 'ready' || !item.complete) return 'noCapture';
    if (item.matchingCount > 0) return 'matches';
    return item.unknownCount > 0 ? 'unclear' : 'noMatch';
}

/** Purely local triage of one admitted page. Never retain pages or query again. */
export function WindowsFleetSoftwareCoverage({ page, children }: { page: FleetSoftwarePage; children: (items: FleetSoftwareItem[]) => ReactNode }) {
    // Mount a fresh selection for each original page/source. No prior page is stored.
    const identity = JSON.stringify([page.mode, page.name, page.version, page.offset, page.serverNow, page.cursorExpiresAt, page.items]);
    return <CoveragePage key={identity} page={page}>{children}</CoveragePage>;
}

function CoveragePage({ page, children }: { page: FleetSoftwarePage; children: (items: FleetSoftwareItem[]) => ReactNode }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [selected, setSelected] = useState<Coverage | 'all'>('all');
    if (page.mode !== 'fleet' || page.status !== 'ready' || !page.items.length) return children(page.items);
    const counts = { all: page.items.length, matches: 0, unclear: 0, noMatch: 0, noCapture: 0 };
    for (const item of page.items) counts[coverage(item)]++;
    const shown = selected === 'all' ? page.items : page.items.filter(item => coverage(item) === selected);
    return <>
        <section className="software-coverage" aria-labelledby={`${id}-title`}>
            <h3 id={`${id}-title`}>{c.title}</h3>
            <p className="software-coverage-scope" id={`${id}-scope`}>{c.scope}</p>
            <div className="software-coverage-options" role="group" aria-label={c.title} aria-describedby={`${id}-scope`}>
                {(['all', ...categories] as const).map(kind => {
                    const Icon = icons[kind];
                    return <button key={kind} type="button" aria-label={`${c[kind]} ${counts[kind]}`} aria-pressed={selected === kind} aria-controls={`${id}-results`} onClick={() => setSelected(kind)}>
                        <Icon size={16} aria-hidden="true"/><span>{c[kind]}</span><strong>{counts[kind]}</strong>
                    </button>;
                })}
            </div>
            <div className="software-coverage-footer">
                <span role="status">{c.shown}: {shown.length} {c.of} {page.items.length}</span>
                <details><summary>{c.details}</summary><p>{c.explanation}</p></details>
            </div>
        </section>
        <div id={`${id}-results`}>
            {!shown.length && <p className="software-coverage-empty">{c.empty}</p>}
            {children(shown)}
        </div>
    </>;
}
