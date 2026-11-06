import { useState } from 'react';
import { Boxes, GitBranch, PackageCheck, PackageMinus } from 'lucide-react';
import type { CompletePackagePage } from './complete-packages-types';
import type { PackageRow } from './package-observations-types';
import './complete-package-source-groups.css';

export interface PackageSourceGroup { key: string; name: string; version: string; rows: PackageRow[] }
/** Exact source labels only. Each binary name + architecture remains a separate row. */
export function packageSourceGroups(rows: readonly PackageRow[]): PackageSourceGroup[] {
    const groups = new Map<string, PackageSourceGroup>();
    for (const row of rows) {
        const key = JSON.stringify([row.sourcePackage, row.sourceVersion]);
        let group = groups.get(key);
        if (!group) { group = { key, name: row.sourcePackage, version: row.sourceVersion, rows: [] }; groups.set(key, group); }
        group.rows.push(row);
    }
    return [...groups.values()].filter(group => group.rows.length > 1);
}

const copy = {
    en: {
        title: 'Shared source packages', page: 'Loaded page only', scope: 'Same reported source package + version. Other pages may contain more related rows.',
        empty: 'No shared source pair on this page.', rows: 'Package rows', installed: 'Installed', incomplete: 'Incomplete',
        binary: 'Binary package', version: 'Binary version', architecture: 'Architecture', explicit: 'Explicit Source field', fallback: 'Binary default',
        help: 'What this shows', explanation: 'Groups use exact captured source names and versions, with no version comparison or suffix removal. A binary default means the Source field was absent and dpkg used the binary name and version. This is not verified vendor origin, a dependency tree, a complete source-package inventory or an update/CVE assessment. Original capture age and inventory scope still apply.',
    },
    de: {
        title: 'Gemeinsame Quellpakete', page: 'Nur geladene Seite', scope: 'Gleiches gemeldetes Quellpaket + Quellversion. Weitere zugehörige Zeilen können auf anderen Seiten liegen.',
        empty: 'Kein gemeinsames Quellpaket mit gleicher Version auf dieser Seite.', rows: 'Paketzeilen', installed: 'Installiert', incomplete: 'Unvollständig',
        binary: 'Binärpaket', version: 'Binärversion', architecture: 'Architektur', explicit: 'Ausdrückliches Source-Feld', fallback: 'Binärvorgabe',
        help: 'Was die Ansicht zeigt', explanation: 'Gruppiert werden exakt erfasste Quellnamen und Quellversionen, ohne Versionsvergleich oder Entfernen von Zusätzen. Binärvorgabe bedeutet: Das Source-Feld fehlte, daher wurden Binärname und Binärversion verwendet. Dies belegt weder Herstellerherkunft noch Abhängigkeiten, vollständigen Quellpaketbestand oder Update-/CVE-Status. Ursprüngliches Erfassungsalter und Inventarumfang gelten weiterhin.',
    },
};

export function CompletePackageSourceGroups({ page, locale, search }: { page: CompletePackagePage; locale: 'en' | 'de'; search: string }) {
    if (!page.items.length) return null;
    const identity = JSON.stringify([page.deviceId, page.binding, page.collectedAt, page.completedAt, page.retainedUntil, page.cursorExpiresAt, page.nextCursor, search, page.items]);
    return <SourceGroupsPage key={identity} page={page} locale={locale}/>;
}

function SourceGroupsPage({ page, locale }: { page: CompletePackagePage; locale: 'en' | 'de' }) {
    const [open, setOpen] = useState(false), c = copy[locale], groups = packageSourceGroups(page.items);
    return <details className="package-source-groups" onToggle={event => setOpen(event.currentTarget.open)}>
        <summary><GitBranch size={16} aria-hidden="true"/> <strong>{c.title}</strong><span>{c.page}</span></summary>
        {open && <div className="package-source-content">
            <p>{c.scope}</p>
            {!groups.length ? <p>{c.empty}</p> : <ul className="package-source-list">{groups.map(group => {
                const installed = group.rows.filter(row => row.installState === 'installed').length;
                return <li key={group.key}><details className="package-source-group">
                    <summary><span className="package-source-name"><Boxes size={16} aria-hidden="true"/> {group.name}</span><span className="package-source-version">{group.version}</span><span className="package-source-count">{c.rows}: {group.rows.length}</span></summary>
                    <p className="package-source-states"><span><PackageCheck size={14} aria-hidden="true"/> {c.installed}: {installed}</span><span><PackageMinus size={14} aria-hidden="true"/> {c.incomplete}: {group.rows.length - installed}</span></p>
                    <ul className="package-source-binaries">{group.rows.map(row => <li key={JSON.stringify([row.name, row.architecture])}>
                        <strong>{row.name}</strong><dl><div><dt>{c.architecture}</dt><dd>{row.architecture}</dd></div><div><dt>{c.version}</dt><dd>{row.version}</dd></div></dl>
                        <div className="package-source-row-state"><span>{row.installState === 'installed' ? c.installed : c.incomplete}</span><span>{row.sourceMapping === 'source-field' ? c.explicit : c.fallback}</span></div>
                    </li>)}</ul>
                </details></li>;
            })}</ul>}
            <details className="package-source-help"><summary>{c.help}</summary><p>{c.explanation}</p></details>
        </div>}
    </details>;
}
