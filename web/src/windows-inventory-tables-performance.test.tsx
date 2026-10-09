import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { capturedInventoryTableRows, WindowsInventoryTable, type WindowsInventoryTableKind, type WindowsInventoryTableSort } from './windows-inventory-tables';
import { windowsSnapshot } from './windows-inventory-fixture';
import type { WindowsInventorySnapshot } from './windows-inventory-types';
import { windowsServiceStartup } from './windows-service-startup-fixture';
import type { WindowsServiceStartup, WindowsServiceStartupRow } from './windows-service-startup-types';

type Locale = 'en' | 'de';
const states = {
    en: { stopped: 'Stopped', start_pending: 'Starting', stop_pending: 'Stopping', running: 'Running', continue_pending: 'Resuming', pause_pending: 'Pausing', paused: 'Paused' },
    de: { stopped: 'Gestoppt', start_pending: 'Wird gestartet', stop_pending: 'Wird gestoppt', running: 'Läuft', continue_pending: 'Wird fortgesetzt', pause_pending: 'Wird pausiert', paused: 'Pausiert' },
};
// Frozen ee602981 comparator and four original cells, extended with the
// reviewed PR #4 startup column. This reference deliberately retains the old
// localeCompare call and independently freezes the startup display vocabulary.
const startupCopy = {
    en: { automatic: 'Automatic', manual: 'Manual', disabled: 'Disabled', denied: 'Access denied', unavailable: 'Unavailable', unknown: 'Unknown', absent: 'Not configured or not captured', trimmed: 'Not captured (trimmed)', delayed: 'delayed', notDelayed: 'not delayed', delayedStatus: 'delayed status', partial: 'partial' },
    de: { automatic: 'Automatisch', manual: 'Manuell', disabled: 'Deaktiviert', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar', unknown: 'Unbekannt', absent: 'Nicht eingerichtet oder nicht erfasst', trimmed: 'Nicht erfasst (gekürzt)', delayed: 'verzögert', notDelayed: 'nicht verzögert', delayedStatus: 'Verzögerungsstatus', partial: 'teilweise' },
};
function baselineStartupCell(row: WindowsServiceStartupRow | undefined, startup: WindowsServiceStartup | null, locale: Locale) {
    const c = startupCopy[locale];
    if (!startup) return c.absent;
    if (!row) return c.trimmed;
    if (row.startupQuality !== 'observed') return c[row.startupQuality];
    if (row.startupMode === 'manual' || row.startupMode === 'disabled') return c[row.startupMode];
    if (row.startupMode !== 'automatic') return c.unknown;
    if (row.delayedAutoQuality === 'observed' && row.delayedAutoStart !== null) return `${c.automatic} (${row.delayedAutoStart ? c.delayed : c.notDelayed})`;
    const quality = row.delayedAutoQuality;
    return `${c.automatic} · ${c.delayedStatus}: ${quality === 'denied' || quality === 'unavailable' ? c[quality] : c.unknown} (${c.partial})`;
}
function baselineRows(snapshot: WindowsInventorySnapshot, kind: WindowsInventoryTableKind, query: string, sort: WindowsInventoryTableSort, locale: Locale, startup: WindowsServiceStartup | null = null) {
    const c = states[locale], unknown = (value: string) => value || (locale === 'en' ? 'Not reported' : 'Nicht gemeldet');
    const filter = query.trim().toLocaleLowerCase(locale), descending = sort.endsWith('-desc');
    const literalCompare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
    const startupRows = new Map(startup?.rows.map(row => [row.serviceIndex, row]));
    const rows = kind === 'services' ? snapshot.services.rows.map((row, index) => {
        const captured = startupRows.get(index), startupText = baselineStartupCell(captured, startup, locale);
        const startupMode = captured?.startupQuality === 'observed' && captured.startupMode ? startupCopy[locale][captured.startupMode] : '';
        return {
            cells: [row.name, unknown(row.displayName), c[row.state], String(row.pid), startupText],
            order: sort.startsWith('pid-') ? row.pid : sort.startsWith('state-') ? c[row.state] : sort.startsWith('startup-') ? startupMode : row.name,
            tie: JSON.stringify([row.name, row.displayName, row.state, row.pid]), index,
            search: [row.name, row.displayName, row.state, c[row.state], String(row.pid), startupText, captured?.startupMode ?? '', captured?.startupQuality ?? '', captured?.delayedAutoQuality ?? ''],
        };
    }) : snapshot.software.rows.map((row, index) => ({
        cells: [row.name, unknown(row.version), unknown(row.publisher), `${row.registryView}-bit`],
        order: sort.startsWith('version-') ? row.version : sort.startsWith('publisher-') ? row.publisher : row.name,
        tie: JSON.stringify([row.name, row.version, row.publisher, row.registryView]), index,
        search: [row.name, row.version, row.publisher, row.registryView, `${row.registryView}-bit`],
    }));
    return rows.filter(row => row.search.some(value => value.toLocaleLowerCase(locale).includes(filter))).sort((a, b) => {
        if (a.order === '' || b.order === '') return a.order === b.order ? literalCompare(a.tie, b.tie) || a.index - b.index : a.order === '' ? 1 : -1;
        const order = typeof a.order === 'number' && typeof b.order === 'number' ? a.order - b.order : String(a.order).localeCompare(String(b.order), locale, { numeric: false });
        return order * (descending ? -1 : 1) || literalCompare(a.tie, b.tie) || a.index - b.index;
    });
}
function mixedSnapshot() {
    const snapshot = windowsSnapshot(), labels = ['Ähre', 'a', 'Z', 'é', 'ss', 'ß', 'Öl', 'Éclair', '10', '2', 'zebra', 'ALPHA', 'öl', 'alpha', 'omega', 'β'];
    snapshot.services.rows = Array.from({ length: 128 }, (_, i) => {
        const j = i * 73 % 128;
        return { name: `${labels[j % 16]} fixture ${j}`, displayName: j % 11 ? `${labels[(j + 3) % 16]} ${j}` : '', state: (['running', 'stopped', 'paused'] as const)[j % 3], pid: j };
    });
    snapshot.software.rows = snapshot.services.rows.map((row, i) => ({ name: row.name, version: i % 9 ? `1.${i}` : '', publisher: i % 10 ? labels[(i + 5) % 16] : '', registryView: i % 2 ? '64' as const : '32' as const }));
    // Full duplicates, locale-equivalent names and distinct ties all stay rows.
    snapshot.services.rows[127] = { ...snapshot.services.rows[126] };
    snapshot.software.rows[127] = { ...snapshot.software.rows[126] };
    return snapshot;
}
const cases: { locale: Locale; kind: WindowsInventoryTableKind; sort: WindowsInventoryTableSort; query: string }[] = [];
for (const locale of ['en', 'de'] as const) for (const kind of ['services', 'software'] as const) {
    const sorts: WindowsInventoryTableSort[] = kind === 'services' ? ['name-asc', 'name-desc', 'pid-asc', 'pid-desc', 'state-asc', 'state-desc'] : ['name-asc', 'name-desc', 'version-asc', 'version-desc', 'publisher-asc', 'publisher-desc'];
    for (const sort of sorts) for (const query of ['', 'a', 'ß', 'not-present']) cases.push({ locale, kind, sort, query });
}
const startupCases: { locale: Locale; sort: WindowsInventoryTableSort; query: string; trimmed: boolean }[] = [];
for (const locale of ['en', 'de'] as const) for (const sort of ['name-asc', 'name-desc', 'pid-asc', 'pid-desc', 'state-asc', 'state-desc', 'startup-asc', 'startup-desc'] as const) {
    for (const query of ['', 'automatic', 'denied', locale === 'en' ? 'partial' : 'teilweise', locale === 'en' ? 'trimmed' : 'gekürzt']) for (const trimmed of [false, true]) startupCases.push({ locale, sort, query, trimmed });
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('captured table collation parity', () => {
    it.each(cases)('matches the frozen comparator: $locale $kind $sort filter="$query"', ({ locale, kind, sort, query }) => {
        const snapshot = mixedSnapshot(), before = JSON.stringify(snapshot);
        expect(capturedInventoryTableRows(snapshot, kind, query, sort, locale)).toEqual(baselineRows(snapshot, kind, query, sort, locale));
        expect(JSON.stringify(snapshot)).toBe(before);
    });
    it.each(startupCases)('preserves all five cells with startup metadata: $locale $sort filter="$query" trimmed=$trimmed', ({ locale, sort, query, trimmed }) => {
        const snapshot = mixedSnapshot(), startup = windowsServiceStartup(snapshot);
        if (trimmed) { startup.rows = startup.rows.filter(row => row.serviceIndex % 3 === 1); startup.truncated = true; }
        const before = JSON.stringify({ snapshot, startup });
        expect(capturedInventoryTableRows(snapshot, 'services', query, sort, locale, startup)).toEqual(baselineRows(snapshot, 'services', query, sort, locale, startup));
        expect(JSON.stringify({ snapshot, startup })).toBe(before);
    });
    it('constructs one locale-correct collator per transform rather than per comparison', () => {
        const snapshot = mixedSnapshot(), OriginalCollator = Intl.Collator;
        const collators = vi.spyOn(Intl, 'Collator').mockImplementation(function (locales, options) { return new OriginalCollator(locales, options); });
        capturedInventoryTableRows(snapshot, 'services', '', 'name-asc', 'de');
        expect(collators).toHaveBeenCalledExactlyOnceWith('de', { numeric: false });
    });
});

describe('component-local captured row reuse', () => {
    it('reuses transforms across age renders and page changes, and recomputes every sort/filter/locale/kind input', () => {
        const snapshot = mixedSnapshot(), services = vi.spyOn(snapshot.services.rows, 'map'), software = vi.spyOn(snapshot.software.rows, 'map');
        const initial = { query: '', sort: 'name-asc' as const, page: 0 }, onChange = vi.fn();
        const ui = render(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={initial} onChange={onChange}/>);
        expect(services).toHaveBeenCalledTimes(1);
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={{ ...initial }} onChange={vi.fn()}/>);
        expect(services).toHaveBeenCalledTimes(1);
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={{ ...initial, page: 1 }} onChange={onChange}/>);
        expect(services).toHaveBeenCalledTimes(1); expect(screen.getByText('Page 2 of 6')).toBeVisible();
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={{ ...initial, query: 'ß' }} onChange={onChange}/>);
        expect(services).toHaveBeenCalledTimes(2);
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={{ ...initial, query: 'ß', sort: 'name-desc' }} onChange={onChange}/>);
        expect(services).toHaveBeenCalledTimes(3);
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="services" locale="de" controls={{ ...initial, query: 'ß', sort: 'name-desc' }} onChange={onChange}/>);
        expect(services).toHaveBeenCalledTimes(4);
        ui.rerender(<WindowsInventoryTable snapshot={snapshot} kind="software" locale="de" controls={{ ...initial, query: 'ß', sort: 'name-desc' }} onChange={onChange}/>);
        expect(software).toHaveBeenCalledTimes(1);
    });
    it('recomputes and reorders on a startup-only replacement while reusing the same inventory snapshot', () => {
        const snapshot = mixedSnapshot(), startup = windowsServiceStartup(snapshot), changed = windowsServiceStartup(snapshot);
        changed.rows = changed.rows.map(row => ({ ...row, startupMode: 'manual', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'not-applicable' }));
        const controls = { query: '', sort: 'startup-asc' as const, page: 0 }, onChange = vi.fn();
        const firstRows = baselineRows(snapshot, 'services', '', controls.sort, 'en', startup).slice(0, 25).map(row => row.cells);
        const changedRows = baselineRows(snapshot, 'services', '', controls.sort, 'en', changed).slice(0, 25).map(row => row.cells);
        const mapped = vi.spyOn(snapshot.services.rows, 'map');
        const table = (serviceStartup: WindowsServiceStartup | null) => <WindowsInventoryTable snapshot={snapshot} serviceStartup={serviceStartup} kind="services" locale="en" controls={controls} onChange={onChange}/>;
        const visibleRows = () => within(screen.getByRole('table')).getAllByRole('row').slice(1).map(row => within(row).getAllByRole('cell').map(cell => cell.textContent));
        const ui = render(table(startup)); expect(mapped).toHaveBeenCalledTimes(1);
        expect(visibleRows()).toEqual(firstRows);
        ui.rerender(table(changed)); expect(mapped).toHaveBeenCalledTimes(2);
        expect(visibleRows()).toEqual(changedRows);
        expect(visibleRows().every(row => row[4] === 'Manual')).toBe(true);
    });
    it('drops startup-only values and restores them after scope loss without replacing base rows', () => {
        const snapshot = windowsSnapshot(), startup = windowsServiceStartup(snapshot), mapped = vi.spyOn(snapshot.services.rows, 'map');
        const controls = { query: '', sort: 'name-asc' as const, page: 0 }, onChange = vi.fn();
        const table = (serviceStartup: WindowsServiceStartup | null) => <WindowsInventoryTable snapshot={snapshot} serviceStartup={serviceStartup} kind="services" locale="en" controls={controls} onChange={onChange}/>;
        const ui = render(table(startup)); expect(mapped).toHaveBeenCalledTimes(1); expect(screen.getByText('Automatic (delayed)')).toBeVisible();
        ui.rerender(table(null)); expect(mapped).toHaveBeenCalledTimes(2); expect(screen.queryByText('Automatic (delayed)')).toBeNull(); expect(screen.getByText('Not configured or not captured')).toBeVisible(); expect(screen.getByText('FixtureService')).toBeVisible();
        ui.rerender(table(startup)); expect(mapped).toHaveBeenCalledTimes(3); expect(screen.getByText('Automatic (delayed)')).toBeVisible(); expect(screen.queryByText('Not configured or not captured')).toBeNull();
    });
    it('reapplies a startup-only filter through update, loss and recovery', () => {
        const snapshot = windowsSnapshot(), startup = windowsServiceStartup(snapshot), changed = windowsServiceStartup(snapshot);
        changed.rows[0] = { serviceIndex: 0, startupMode: 'manual', startupQuality: 'observed', delayedAutoStart: null, delayedAutoQuality: 'not-applicable' };
        const controls = { query: 'manual', sort: 'startup-desc' as const, page: 0 }, onChange = vi.fn();
        const table = (serviceStartup: WindowsServiceStartup | null) => <WindowsInventoryTable snapshot={snapshot} serviceStartup={serviceStartup} kind="services" locale="en" controls={controls} onChange={onChange}/>;
        const ui = render(table(startup)); expect(screen.queryByRole('table')).toBeNull();
        ui.rerender(table(changed)); expect(screen.getByText('Manual')).toBeVisible(); expect(screen.getByText('FixtureService')).toBeVisible();
        ui.rerender(table(null)); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('Manual');
        ui.rerender(table(changed)); expect(screen.getByText('Manual')).toBeVisible();
    });
    it('uses a replacement snapshot object even when the generation and capture labels match', () => {
        const first = windowsSnapshot(), replacement = windowsSnapshot(), onChange = vi.fn(), controls = { query: '', sort: 'name-asc' as const, page: 0 };
        replacement.services.rows[0].name = 'Replacement private service';
        const ui = render(<WindowsInventoryTable snapshot={first} kind="services" locale="en" controls={controls} onChange={onChange}/>);
        expect(screen.getByText('FixtureService')).toBeVisible();
        ui.rerender(<WindowsInventoryTable snapshot={replacement} kind="services" locale="en" controls={controls} onChange={onChange}/>);
        expect(screen.queryByText('FixtureService')).toBeNull(); expect(screen.getByText('Replacement private service')).toBeVisible();
        expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(2);
    });
    it('drops its memoized rows on unmount and recomputes when the same snapshot is later admitted again', () => {
        const snapshot = windowsSnapshot(), rows = vi.spyOn(snapshot.services.rows, 'map'), controls = { query: '', sort: 'name-asc' as const, page: 0 }, onChange = vi.fn();
        const table = () => <WindowsInventoryTable snapshot={snapshot} kind="services" locale="en" controls={controls} onChange={onChange}/>;
        const ui = render(table()); expect(rows).toHaveBeenCalledTimes(1);
        ui.rerender(<div/>); expect(screen.queryByRole('table')).toBeNull(); expect(document.body).not.toHaveTextContent('FixtureService');
        ui.rerender(table()); expect(rows).toHaveBeenCalledTimes(2); expect(screen.getByText('FixtureService')).toBeVisible();
    });
});
