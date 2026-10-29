import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { APIError, mutate } from './api';
import { ApplicationNetworkAI } from './application-network-ai';
import { applicationDNSRow } from './application-checks-v2-fixtures';
import { setLocale } from './i18n';
import { useState } from 'react';
import { NetworkReviewHistoryView } from './application-network-ai';
import type { NetworkReviewHistory } from './application-network-ai';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn() }));
const row = applicationDNSRow();
const p = { schemaVersion: 'tracebolt.ai-network-review-preview.v1', checkId: row.id, kind: row.kind, state: row.state, reason: row.reason, observedAt: row.observedAt, validUntil: '2026-10-06T12:01:00Z', snapshotToken: 'opaque', configRevision: 'rev', baseURL: 'https://10.6.1.75:8443/v1', model: 'fixture-model' };
const response = { schemaVersion: 'tracebolt.ai-network-review-result.v1', checkId: row.id, snapshotToken: p.snapshotToken, configRevision: p.configRevision, result: { schemaVersion: 'tracebolt.analysis.v1', rootCauseConfirmed: false, ai: { status: 'completed', findings: { hypotheses: [{ statement: 'A possible cause' }], counterevidence: [], missingData: ['Other observations'] }, nextSteps: ['Review existing data'] } } };
beforeEach(() => { setLocale('en', false); vi.mocked(mutate).mockReset(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function prepare() { fireEvent.click(screen.getByRole('button', { name: 'Review AI analysis' })); return screen.findByRole('checkbox', { name: /I approve sending this observation/ }); }
function Fixture() { const [history, setHistory] = useState<NetworkReviewHistory | null>(null); return <><ApplicationNetworkAI row={row} onCompleted={setHistory}/>{history && <NetworkReviewHistoryView history={history} onDismiss={() => setHistory(null)}/>}</>; }
it('reviews the exact saved observation and provider before a single explicitly approved call', async () => {
    vi.mocked(mutate).mockResolvedValueOnce(p).mockResolvedValueOnce(response); render(<Fixture/>);
    expect(mutate).not.toHaveBeenCalled(); const check = await prepare();
    const dialog = screen.getByRole('dialog'); expect(dialog).toHaveTextContent(p.baseURL); expect(dialog).toHaveTextContent(p.model);
    for (const v of [p.kind.toUpperCase(), p.state, p.reason, p.observedAt]) expect(dialog).toHaveTextContent(v);
    expect(dialog).toHaveTextContent('fixed explanatory text and a fixed evidence ID'); expect(dialog).toHaveTextContent('No check ID, hostname, IP address, port, target URL or free text');
    expect(check).not.toBeChecked(); expect(within(dialog).getByRole('button', { name: 'Analyze now' })).toBeDisabled();
    expect(mutate).toHaveBeenCalledTimes(1); expect(mutate).toHaveBeenCalledWith('/ai/network-review/preview', { checkId: row.id }, expect.any(AbortSignal));
    fireEvent.click(check); fireEvent.click(within(dialog).getByRole('button', { name: 'Analyze now' }));
    expect(await screen.findByText('A possible cause')).toBeVisible(); expect(screen.getByText(/cause not confirmed/)).toBeVisible(); expect(screen.getByText(/No action was performed/)).toBeVisible(); expect(screen.getByText(row.observedAt)).toHaveAttribute('datetime', row.observedAt);
    expect(mutate).toHaveBeenLastCalledWith('/ai/network-review/run', { checkId: row.id, snapshotToken: 'opaque', configRevision: 'rev', acknowledge: true }, expect.any(AbortSignal)); expect(mutate).toHaveBeenCalledTimes(2);
});
it('rejects a changed or malformed preview without an analysis call', async () => {
    vi.mocked(mutate).mockResolvedValue({ ...p, reason: 'tcp_connected' }); render(<Fixture/>);
    fireEvent.click(screen.getByRole('button', { name: 'Review AI analysis' })); expect(await screen.findByRole('alert')).toHaveTextContent('preview is invalid');
    expect(screen.queryByRole('checkbox')).toBeNull(); expect(mutate).toHaveBeenCalledTimes(1);
});
it('treats an unrecognized result as uncertain and does not retry', async () => {
    vi.mocked(mutate).mockResolvedValueOnce(p).mockResolvedValueOnce({ ...response, snapshotToken: 'other' }); render(<Fixture/>);
    fireEvent.click(await prepare()); fireEvent.click(screen.getByRole('button', { name: 'Analyze now' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('outcome is uncertain'); expect(screen.queryByText('A possible cause')).toBeNull(); expect(mutate).toHaveBeenCalledTimes(2);
});
it('handles a source conflict without implying an analysis result', async () => {
    vi.mocked(mutate).mockRejectedValue(new APIError('ignored', 409)); render(<Fixture/>);
    fireEvent.click(screen.getByRole('button', { name: 'Review AI analysis' })); expect(await screen.findByRole('alert')).toHaveTextContent('observation or provider changed'); expect(mutate).toHaveBeenCalledTimes(1);
});
it('shows uncertainty after cancel and ignores a late response', async () => {
    let finish!: (x: unknown) => void; vi.mocked(mutate).mockResolvedValueOnce(p).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })); render(<Fixture/>);
    fireEvent.click(await prepare()); fireEvent.click(screen.getByRole('button', { name: 'Analyze now' })); fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await act(async () => finish(response)); expect(screen.getByRole('alert')).toHaveTextContent('outcome is uncertain'); expect(screen.queryByText('A possible cause')).toBeNull(); expect(mutate).toHaveBeenCalledTimes(2);
});
it('renders German consent and keeps it unchecked', async () => {
    setLocale('de', false); vi.mocked(mutate).mockResolvedValue(p); render(<Fixture/>); fireEvent.click(screen.getByRole('button', { name: 'KI-Analyse prüfen' }));
    const check = await screen.findByRole('checkbox', { name: /Ich bestätige die einmalige Übertragung/ }); expect(check).not.toBeChecked(); expect(screen.getByRole('button', { name: 'Jetzt analysieren' })).toBeDisabled(); expect(mutate).toHaveBeenCalledTimes(1);
});
