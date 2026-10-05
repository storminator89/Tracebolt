import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { abortProtectedRequests } from './api';
import { setLocale } from './i18n';
import { JournalPanel } from './journal';
import { journalDevice, journalNow, journalSession, journalSessionExpiry, journalView } from './journal-fixtures';
import type { JournalView } from './journal-types';
const root = `/api/devices/${journalDevice}/journal`;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
function generationView(revision = '1'): JournalView {
    const v = journalView('awaiting'); v.schemaVersion = 'tracebolt.journal-view.v2';
    v.generation = { schemaVersion: 'tracebolt.journal-generation-view.v1', policyGeneration: { revision, generation: (revision === '1' ? 'a' : 'b').repeat(64), policyDigest: `sha256:${(revision === '1' ? 'd' : 'e').repeat(64)}` }, sequence: revision, observedAt: revision === '1' ? journalNow : '2026-10-04T12:00:01Z', receivedAt: revision === '1' ? journalNow : '2026-10-04T12:00:01Z', expiresAt: revision === '1' ? '2026-10-04T12:05:00Z' : '2026-10-04T12:05:01Z', fresh: true };
    v.serverNow = v.generation.receivedAt; return v;
}
function server(read: () => JournalView, create?: (body: Record<string, unknown>) => Response) {
    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
        if (url === '/api/auth/session') return json(journalSession);
        if (url === '/api/session') return json({ csrfToken: 'synthetic-csrf' });
        if (url === root) return json(read());
        if (url === `${root}/create` && create) return create(JSON.parse(String(init?.body)));
        throw new Error('Unexpected synthetic route');
    }); vi.stubGlobal('fetch', fetch); return fetch;
}
function open() { render(<JournalPanel deviceId={journalDevice} insecureTestMode={false} sessionKey={journalSessionExpiry}/>); }
beforeEach(() => { setLocale('en', false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); abortProtectedRequests(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });
describe('generation-aware explicit capture', () => {
    it('attaches the exact validated expected tuple and never retries a CAS conflict', async () => {
        let view = generationView();
        const fetch = server(() => view, body => { expect(body.expectedPolicyGeneration).toEqual(view.generation!.policyGeneration); view = generationView('2'); return json({ error: { code: 'journal_conflict', message: 'Refresh before continuing.' } }, 409); });
        open(); await screen.findByText('Awaiting a request');
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(screen.getByRole('button', { name: 'Capture logs' }));
        await waitFor(() => expect(fetch.mock.calls.filter(([url]) => url === `${root}/create`)).toHaveLength(1));
        await screen.findByText('Awaiting a request');
        expect(screen.getByRole('checkbox')).not.toBeChecked();
        expect(fetch.mock.calls.filter(([url]) => url === `${root}/create`)).toHaveLength(1);
    });
    it('clears acknowledgements on a changed tuple and refuses a downgrade on refresh', async () => {
        let view = generationView(); const fetch = server(() => view); open(); await screen.findByText('Awaiting a request');
        fireEvent.click(screen.getByRole('checkbox')); expect(screen.getByRole('checkbox')).toBeChecked();
        view = generationView('2'); fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
        await waitFor(() => expect(screen.getByRole('checkbox')).not.toBeChecked());
        await screen.findByText('Awaiting a request');
        view = journalView('awaiting'); fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
        await screen.findByRole('alert'); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
        expect(fetch.mock.calls.some(([url]) => url === `${root}/create`)).toBe(false);
    });
    it('keeps a stale report visible but never sends a capture', async () => {
        const view = generationView(); view.serverNow = '2026-10-04T12:05:00Z'; view.generation!.fresh = false;
        const fetch = server(() => view); open(); await screen.findByText('Awaiting a request');
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'fixture.service' } });
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByText(/endpoint policy report is stale/)).toBeVisible(); expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
        await act(async () => { fireEvent.submit(screen.getByRole('button', { name: 'Capture logs' }).closest('form')!); });
        expect(fetch.mock.calls.some(([url]) => url === `${root}/create`)).toBe(false);
    });
});

function scopeView(scope: 'exact-units' | 'all-system-services' = 'all-system-services'): JournalView {
    const view = generationView();
    view.generation = { ...view.generation!, schemaVersion: 'tracebolt.journal-generation-view.v2', policyEnabled: true, serviceAuthorization: scope, allowedUnits: scope === 'exact-units' ? ['fixture.service'] : [] };
    return view;
}
describe('reported local service grant', () => {
    it('shows the broad grant without inventory or automatic capture and retains explicit consent', async () => {
        const view = scopeView(), fetch = server(() => view); open(); await screen.findByText('Awaiting a request');
        expect(screen.getByText(/All current and future system services/)).toBeVisible();
        expect(screen.queryByRole('list')).not.toBeInTheDocument();
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: 'future.service' } });
        expect(screen.getByText('Included in the last reported local grant.')).toBeVisible();
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeEnabled();
        expect(fetch.mock.calls.some(([url]) => url === `${root}/create`)).toBe(false);
    });
    it.each(['disabled', 'outside', 'stale'] as const)('does not capture a %s reported grant', async kind => {
        const view = scopeView('exact-units');
        if (kind === 'disabled') view.generation!.policyEnabled = false;
        if (kind === 'stale') { view.generation!.fresh = false; view.serverNow = '2026-10-04T12:05:00Z'; }
        const fetch = server(() => view); open(); await screen.findByText('Awaiting a request');
        fireEvent.change(screen.getByLabelText('Exact service unit'), { target: { value: kind === 'outside' ? 'other.service' : 'fixture.service' } });
        fireEvent.click(screen.getByRole('checkbox'));
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
        await act(async () => { fireEvent.submit(screen.getByRole('button', { name: 'Capture logs' }).closest('form')!); });
        expect(fetch.mock.calls.some(([url]) => url === `${root}/create`)).toBe(false);
        if (kind === 'stale') { expect(screen.getByText(/Stale · current permission unknown/)).toBeVisible(); expect(screen.queryByText('Included in the last reported local grant.')).not.toBeInTheDocument(); }
    });
    it.each(['changed-summary', 'same-tuple-enrichment', 'downgrade'] as const)('rejects %s on refresh', async kind => {
        let view = kind === 'same-tuple-enrichment' ? generationView() : scopeView();
        server(() => view); open(); await screen.findByText('Awaiting a request');
        view = kind === 'same-tuple-enrichment' ? scopeView() : structuredClone(view);
        view.serverNow = '2026-10-04T12:00:01Z'; view.generation!.sequence = '2'; view.generation!.observedAt = view.serverNow; view.generation!.receivedAt = view.serverNow; view.generation!.expiresAt = '2026-10-04T12:05:01Z';
        if (kind === 'changed-summary') view.generation!.policyEnabled = false;
        if (kind === 'downgrade') { view = generationView('2'); }
        fireEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
        await screen.findByRole('alert');
        expect(screen.getByRole('button', { name: 'Capture logs' })).toBeDisabled();
    });
});
