import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mutateRaw, request } from './api';
import { setLocale } from './i18n';
import { journalServiceLabel, journalServiceSearches, journalSourceAccess } from './journal-sources';
import { JournalSourceOptions, JournalSelectedSource } from './journal-source-options';
import { JournalServicePicker } from './journal-service-picker';
import { JournalContent } from './journal';
import { journalView } from './journal-fixtures';
import type { JournalResource } from './journal-resource';
import { serviceRows, systemDevice, systemPage, systemView } from './system-inventory-fixtures';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutateRaw: vi.fn() }));
vi.mock('./auth', () => ({ useOperator: () => ({ mode: 'lan', authenticated: true, expiresAt: '2026-10-04T01:00:00Z' }) }));
const names = ['apt-daily.service', 'containerd.service', 'docker.service', 'networking.service', 'ssh.service', 'sshd.service', 'systemd-journald.service', 'systemd-resolved.service', 'tracebolt-agent.service'];
const services = names.map(name => ({ ...serviceRows(1)[0], name }));
const view = systemView(names.length), select = vi.fn();
beforeEach(() => {
    setLocale('en', false); select.mockReset();
    vi.mocked(request).mockReset().mockImplementation(async () => view);
    vi.mocked(mutateRaw).mockReset().mockImplementation(async (_path, raw) => systemPage(view, services, [], raw));
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const picker = () => <JournalServicePicker deviceId={systemDevice} sessionKey="source-test" onSelect={select} onClose={vi.fn()}/>;

describe('Linux log source guidance is discovery, never authority', () => {
    it('labels only exact recognized supported units and never rewrites aliases or wildcard input', () => {
        expect(journalServiceLabel('ssh.service', 'en')).toBe('SSH remote login');
        expect(journalServiceLabel('sshd.service', 'de')).toBe('SSH-Fernzugriff');
        expect(journalServiceLabel('systemd-journald.service', 'en')).toBe('Journal daemon diagnostics');
        for (const unit of ['SSH.service', 'ssh@host.service', '*.service', 'ssh.service\n', 'kernel', 'ssh.socket', '__proto__', 'constructor', '<img>.service']) expect(journalServiceLabel(unit, 'en')).toBeNull();
    });
    it('does not treat a configured endpoint or past capture as an authorized allowlist', () => {
        expect(journalSourceAccess(journalView('awaiting'), 'ssh.service')).toBe('unknown');
        const accepted = journalView();
        expect(journalSourceAccess(accepted, accepted.request!.description.query.unit)).toBe('unknown');
        expect(journalSourceAccess({ ...accepted, configured: false }, 'ssh.service')).toBe('not_configured');
        expect(journalSourceAccess(null, 'ssh.service')).toBe('unknown');
    });
    it.each(['denied', 'disabled', 'helper_unavailable'] as const)('attributes %s only to the selected service’s historical request', status => {
        const current = journalView(); current.localStatus = status;
        const unit = current.request!.description.query.unit;
        expect(journalSourceAccess(current, unit)).toBe(status);
        expect(journalSourceAccess(current, 'other.service')).toBe('unknown');
        const rendered = render(<JournalSelectedSource unit={unit} view={current}/>);
        expect(screen.getByText(/The last request for this service/)).toBeVisible();
        rendered.rerender(<JournalSelectedSource unit="other.service" view={current}/>);
        expect(screen.queryByText(/The last request for this service/)).not.toBeInTheDocument();
        expect(screen.getByText(/Permission not verified/)).toBeVisible();
    });
    it('keeps broader sources explicitly unsupported, with no requests or selectable collector fallback', () => {
        render(<JournalSourceOptions/>);
        for (const name of ['Kernel & hardware', 'Whole system journal', 'System-wide authentication']) expect(screen.getByText(name)).toBeVisible();
        expect(screen.getByText(/Not supported by this collector/)).toBeVisible();
        expect(screen.getByText(/Journal-daemon logs are not the whole journal/)).toBeVisible();
        expect(screen.getByText(/SSH logs cover SSH only/)).toBeVisible();
        expect(screen.queryByRole('button')).not.toBeInTheDocument(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        expect(request).not.toHaveBeenCalled(); expect(mutateRaw).not.toHaveBeenCalled();
    });
    it('discovers known service labels only for observed rows and sends their unchanged exact names', async () => {
        render(picker()); await screen.findByText('ssh.service');
        expect(screen.getAllByText('SSH remote login')).toHaveLength(2);
        expect(screen.getByText('Docker daemon')).toBeVisible();
        expect(screen.queryByText('Nginx web server')).not.toBeInTheDocument();
        expect(screen.getAllByText('Permission unknown')).toHaveLength(names.length);
        fireEvent.click(screen.getByRole('button', { name: 'Use sshd.service' }));
        expect(select).toHaveBeenCalledExactlyOnceWith('sshd.service');
        expect(mutateRaw).toHaveBeenCalledTimes(1);
    });
    it.each(journalServiceSearches)('the $term shortcut is only a visible literal inventory search', async shortcut => {
        render(picker()); await screen.findByText('ssh.service');
        fireEvent.click(screen.getByText('Quick filters', { selector: 'summary' }));
        fireEvent.click(screen.getByRole('button', { name: shortcut.label.en }));
        expect(screen.getByLabelText('Search observed services')).toHaveValue(shortcut.term);
        const last = vi.mocked(mutateRaw).mock.calls.at(-1)!;
        expect(last[0]).toBe(`/devices/${systemDevice}/inventory/system/query`);
        expect(JSON.parse(last[1])).toMatchObject({ section: 'services', search: shortcut.term, cursor: '', limit: 100, filter: 'all' });
        expect(select).not.toHaveBeenCalled();
        await screen.findByText('The whole retained service inventory has been scanned.');
        fireEvent.click(screen.getByRole('button', { name: 'All services' }));
        await screen.findByText('ssh.service'); expect(screen.getByLabelText('Search observed services')).toHaveValue('');
    });
    it('shortcut selection inside a ready capture form does not submit or acknowledge a new source', async () => {
        const resource: JournalResource = { view: { ...journalView('awaiting'), deviceId: systemDevice }, page: null, busy: false, paused: false, failure: null, uncertain: false, reset: 0, refresh: vi.fn(), refreshWindow: vi.fn(async () => null), create: vi.fn(async () => undefined), cancelRequest: vi.fn(), search: vi.fn(), next: vi.fn(), previous: vi.fn(), canPrevious: false };
        render(<JournalContent resource={resource} insecureTestMode={false} sessionKey="source-form"/>);
        openAdvanced(); fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'manual.service' } });
        expect(screen.getByRole('button', { name: 'Fetch logs' })).toBeEnabled(); expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
        fireEvent.click(screen.getByRole('button', { name: 'Choose observed service' })); await screen.findByText('ssh.service');
        fireEvent.click(screen.getByText('Quick filters', { selector: 'summary' }));
        fireEvent.click(screen.getByRole('button', { name: 'SSH logins' })); await screen.findByText('sshd.service');
        expect(screen.getByLabelText('Exact service unit')).toHaveValue('manual.service');
        expect(resource.create).not.toHaveBeenCalled(); expect(resource.cancelRequest).not.toHaveBeenCalled();
        expect(within(screen.getByRole('region', { name: 'Observed services' })).queryByText('docker.service')).not.toBeInTheDocument();
    });
    it('offers German discovery and explicit unknown access', async () => {
        setLocale('de', false); render(picker()); await screen.findByText('ssh.service');
        expect(screen.getAllByText('SSH-Fernzugriff')).toHaveLength(2);
        fireEvent.click(screen.getByText('Schnellfilter', { selector: 'summary' }));
        fireEvent.click(screen.getByRole('button', { name: 'SSH-Anmeldungen' })); await screen.findByText('sshd.service');
        expect(screen.getByLabelText('Beobachtete Dienste durchsuchen')).toHaveValue('ssh');
        expect(screen.getAllByText('Freigabe unbekannt')).toHaveLength(2);
    });
});

it('labels observed inventory separately from the reported exact grant and loses permission on stale reports', async () => {
    const permission = journalView('awaiting'); permission.schemaVersion = 'tracebolt.journal-view.v2';
    permission.generation = { schemaVersion: 'tracebolt.journal-generation-view.v2', policyGeneration: { revision: '1', generation: 'a'.repeat(64), policyDigest: `sha256:${'b'.repeat(64)}` }, sequence: '1', observedAt: permission.serverNow, receivedAt: permission.serverNow, expiresAt: '2026-10-04T12:05:00Z', fresh: true, policyEnabled: true, serviceAuthorization: 'exact-units', allowedUnits: ['ssh.service'] };
    const pickerWithGrant = () => <JournalServicePicker deviceId={systemDevice} sessionKey="reported-source" journalView={permission} onSelect={select} onClose={vi.fn()}/>;
    const rendered = render(pickerWithGrant()); await screen.findByText('ssh.service');
    expect(screen.getByText('In reported grant')).toBeVisible();
    expect(screen.getAllByText('Outside reported grant')).toHaveLength(names.length - 1);
    expect(select).not.toHaveBeenCalled();
    permission.generation = { ...permission.generation, fresh: false };
    rendered.rerender(pickerWithGrant());
    expect(screen.getAllByText('Permission unknown')).toHaveLength(names.length);
    expect(screen.queryByText('In reported grant')).not.toBeInTheDocument();
});

function openAdvanced() {
    const summary = screen.getByText(/^(Advanced|Erweitert)$/, { selector: 'summary' });
    if (!summary.closest('details')!.open) fireEvent.click(summary);
}
