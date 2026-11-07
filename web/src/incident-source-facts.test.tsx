import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import legacyWire from '../../tests/fixtures/windows-incident-inbox-view.json';
import healthWire from './health-go-fixture.json';
import type { HealthView } from './health-types';
import type { InvestigationsView } from './investigations-types';
import type { InvestigationsResource } from './investigations-resource';
import { IncidentWorkQueue } from './incident-work-queue';
import { useWindowsIncidentInbox } from './windows-incident-inbox-resource';
import { setLocale } from './i18n';
vi.mock('./windows-incident-inbox-resource', () => ({ useWindowsIncidentInbox: vi.fn() }));
vi.mock('./manager-readiness-panel', () => ({ ManagerReadinessPanel: () => null }));
vi.mock('./application-incidents', () => ({ ApplicationIncidentWorkspace: () => null }));
const linux = () => {
    const health = structuredClone(healthWire) as HealthView;
    const view: InvestigationsView = { schemaVersion: 'tracebolt.investigations.v1', serverNow: health.serverNow, scope: 'all', offset: 0, total: health.incidents.length, counts: { open: health.incidents.length, recovered: 0, closed: 0, all: health.incidents.length }, items: health.incidents.map(incident => ({ deviceId: health.deviceId, incident })), devices: [{ ...health, incidents: [] }] };
    return { view, counts: view.counts, readiness: 'unknown', pending: false, failure: null, locked: false, refresh: vi.fn() } as InvestigationsResource;
};
let windows: ReturnType<typeof useWindowsIncidentInbox>;
beforeEach(() => {
    setLocale('en', false);
    windows = { view: structuredClone(legacyWire.active) as ReturnType<typeof useWindowsIncidentInbox>['view'], age: 0, loading: false, writing: false, error: false, notice: null, refresh: vi.fn(), acknowledge: vi.fn(), isUncertain: () => false };
    vi.mocked(useWindowsIncidentInbox).mockImplementation(() => windows);
});
afterEach(cleanup);
const draw = (resource = linux()) => render(<IncidentWorkQueue devices={[]} sessionKey="fixture" linux={resource} scope="all" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>);
function count(region: HTMLElement, label: string, value: number) {
    const term = within(region).getByText(label, { selector: 'dt', exact: true });
    expect(term.nextElementSibling?.tagName).toBe('DD');
    expect(term.nextElementSibling).toHaveTextContent(String(value));
}
it.each(['en', 'de'] as const)('labels source-specific counts without equating seen and recovered (%s)', locale => {
    setLocale(locale, false); const resource = linux(); draw(resource);
    const l = screen.getByRole('region', { name: 'Linux Health' }), w = screen.getByRole('region', { name: locale === 'en' ? 'Windows incidents' : 'Windows-Vorfälle' });
    count(l, locale === 'en' ? 'retained' : 'gespeichert', resource.view!.counts.all);
    count(l, locale === 'en' ? 'recovered' : 'erholt', 0);
    count(l, locale === 'en' ? 'monitoring stopped' : 'Überwachung beendet', 0);
    count(w, locale === 'en' ? 'closed' : 'geschlossen', windows.view!.counts.resolved);
    count(w, locale === 'en' ? 'Seen' : 'Gesehen', windows.view!.counts.acknowledged);
    count(w, locale === 'en' ? 'unknown checks' : 'unbekannte Prüfungen', windows.view!.coverage.unknownChecks);
    expect(w.querySelectorAll('dl.incident-source-facts')).toHaveLength(2);
    expect(w.querySelector('dl')).toHaveAccessibleName(locale === 'en' ? 'Retained incident counts' : 'Gespeicherte Vorfallzahlen');
});
it('removes unavailable source facts instead of showing zero or retaining old totals', () => {
    const resource = linux(); const rendered = draw(resource);
    windows = { ...windows, view: null, error: true };
    resource.view = null; resource.counts = null;
    rendered.rerender(<IncidentWorkQueue devices={[]} sessionKey="fixture" linux={resource} scope="all" onScope={vi.fn()} linuxOffset={0} onLinuxPage={vi.fn()}/>);
    expect(document.querySelectorAll('.incident-source-facts')).toHaveLength(0);
    expect(screen.getByText(/Source coverage is incomplete/)).toBeVisible();
    expect(screen.getByText(/Windows incidents unavailable or expired/)).toBeVisible();
});
