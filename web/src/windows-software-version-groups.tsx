import { useState } from 'react';
import { Layers3, List, Tag } from 'lucide-react';
import type { FullSoftwarePage, FullSoftwareRow } from './windows-full-software-types';
import './windows-software-version-groups.css';

export interface SoftwareVersionGroup {
    key: string;
    name: string;
    publisher: string;
    rows: FullSoftwareRow[];
    versions: { value: string | null; rows: FullSoftwareRow[] }[];
}

/** Exact observed labels are an investigation grouping, never application identity. */
export function softwareVersionGroups(rows: readonly FullSoftwareRow[]): SoftwareVersionGroup[] {
    const groups = new Map<string, SoftwareVersionGroup>();
    for (const row of rows) {
        if (row.nameQuality !== 'observed' || row.publisherQuality !== 'observed' || !row.name || !row.publisher) continue;
        const key = JSON.stringify([row.name, row.publisher]);
        let group = groups.get(key);
        if (!group) {
            group = { key, name: row.name, publisher: row.publisher, rows: [], versions: [] };
            groups.set(key, group);
        }
        group.rows.push(row);
        const value = row.versionQuality === 'observed' ? row.version : null;
        let version = group.versions.find(candidate => candidate.value === value);
        if (!version) { version = { value, rows: [] }; group.versions.push(version); }
        version.rows.push(row);
    }
    return [...groups.values()].filter(group => group.rows.length > 1);
}

const copy = {
    en: {
        title: 'Version groups', page: 'Loaded page only', groups: 'Repeated name + publisher groups', rows: 'Registrations',
        scope: 'Only this loaded page. Matching labels do not prove the same application or an upgrade need.',
        empty: 'No repeated nonempty name + publisher pair on this page. Other pages and unavailable labels are not compared.',
        help: 'How groups are formed', explanation: 'Names and publishers must both be observed, nonempty and exactly equal, including case and whitespace. Versions are exact reported text, not upgrade order. Empty and unavailable versions stay separate. Each registration retains its ID and registry view. Search and paging can split a group. This does not establish current installation, duplicate installations, health or compliance.',
        versions: 'Reported nonempty versions', unavailable: 'Version unavailable', emptyVersion: 'Empty reported version',
        registrations: 'Inspect registrations', id: 'Registration ID', view: 'Registry view', publisher: 'Publisher',
    },
    de: {
        title: 'Versionsgruppen', page: 'Nur geladene Seite', groups: 'Wiederholte Gruppen aus Name + Herausgeber', rows: 'Registrierungen',
        scope: 'Nur diese geladene Seite. Gleiche Angaben belegen weder dieselbe Anwendung noch Aktualisierungsbedarf.',
        empty: 'Kein wiederholtes, nicht leeres Paar aus Name + Herausgeber auf dieser Seite. Andere Seiten und nicht verfügbare Angaben werden nicht verglichen.',
        help: 'So entstehen die Gruppen', explanation: 'Name und Herausgeber müssen beide erfasst, nicht leer und exakt gleich sein, einschließlich Großschreibung und Leerzeichen. Versionen sind exakt gemeldeter Text, keine Aktualitätsreihenfolge. Leere und nicht verfügbare Versionen bleiben getrennt. Jede Registrierung behält ihre ID und Registrierungsansicht. Suche und Seitenwechsel können Gruppen aufteilen. Daraus folgen keine Aussagen zu aktueller Installation, doppelten Installationen, Zustand oder Richtlinienkonformität.',
        versions: 'Gemeldete nicht leere Versionen', unavailable: 'Version nicht verfügbar', emptyVersion: 'Leer gemeldete Version',
        registrations: 'Registrierungen prüfen', id: 'Registrierungs-ID', view: 'Registrierungsansicht', publisher: 'Herausgeber',
    },
};

export function WindowsSoftwareVersionGroups({ page, locale }: { page: FullSoftwarePage; locale: 'en' | 'de' }) {
    if (page.status !== 'ready' || !page.complete || !page.rows.length) return null;
    // No source cache: replacement page/query/authority starts with closed disclosures.
    const identity = JSON.stringify([page.deviceId, page.grantId, page.grantRevision, page.complete, page.search, page.sort, page.limit, page.offset, page.cursorExpiresAt, page.rows]);
    return <VersionGroupsPage key={identity} page={page} locale={locale}/>;
}

function VersionGroupsPage({ page, locale }: { page: FullSoftwarePage; locale: 'en' | 'de' }) {
    const [open, setOpen] = useState(false), c = copy[locale], groups = softwareVersionGroups(page.rows);
    return <details className="software-version-groups" onToggle={event => setOpen(event.currentTarget.open)}>
        <summary><Layers3 size={16} aria-hidden="true"/> <strong>{c.title}</strong><span>{c.page}</span></summary>
        {open && <div className="software-version-content">
            <p>{c.scope}</p>
            {groups.length ? <>
                <dl className="software-version-counts"><div><dt>{c.groups}</dt><dd>{groups.length}</dd></div><div><dt>{c.rows}</dt><dd>{groups.reduce((count, group) => count + group.rows.length, 0)} / {page.rows.length}</dd></div></dl>
                <ul className="software-version-list">{groups.map(group => <li key={group.key}>
                    <div className="software-version-heading"><strong className="software-version-value">{group.name}</strong><span>{c.versions}: {group.versions.filter(version => version.value !== null && version.value !== '').length}</span></div>
                    <p className="software-version-publisher">{c.publisher}: <span className="software-version-value">{group.publisher}</span></p>
                    <ul className="software-version-variants">{group.versions.map(version => <li key={JSON.stringify(version.value)}>
                        <div className="software-version-variant"><Tag size={14} aria-hidden="true"/><span className="software-version-value">{version.value === null ? c.unavailable : version.value === '' ? c.emptyVersion : version.value}</span><span>{c.rows}: {version.rows.length}</span></div>
                        <div className="software-version-bar" aria-hidden="true"><span style={{ width: `${version.rows.length / group.rows.length * 100}%` }}/></div>
                        <details><summary><List size={14} aria-hidden="true"/> {c.registrations} ({version.rows.length})</summary><ul>{version.rows.map(row => <li key={row.registrationId}><span>{c.view}: HKLM {row.registryView}</span><span>{c.id}: <code>{row.registrationId}</code></span></li>)}</ul></details>
                    </li>)}</ul>
                </li>)}</ul>
            </> : <p>{c.empty}</p>}
            <details className="software-version-help"><summary>{c.help}</summary><p>{c.explanation}</p></details>
        </div>}
    </details>;
}
