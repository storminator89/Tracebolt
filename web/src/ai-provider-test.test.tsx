import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { APIError, mutate } from './api';
import type { AIConfig } from './ai-types';
import { AIProviderTest } from './ai-provider-test';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn() }));
const config: AIConfig = { revision:'revision-a',configured:true,provider:'openai-compatible',baseURL:'https://10.6.1.75:8443/v1',endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:true,lanMode:true,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[] };
const result = (status: string, revision = config.revision) => ({schemaVersion:'tracebolt.ai-provider-test.v1', configRevision:revision, status});
const changed = vi.fn();
const refresh = vi.fn(async () => config);
beforeEach(() => { vi.mocked(mutate).mockReset(); changed.mockClear(); refresh.mockClear(); setLocale('en',false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
function show(c = config) { return render(<AIProviderTest config={c} disabled={false} onBusy={changed} onRefresh={refresh}/>); }
function open() { fireEvent.click(screen.getByRole('button',{name:'Test saved provider'})); }
function acknowledge() { fireEvent.click(screen.getByRole('checkbox',{name:/I approve this one-time test/})); }

it('requires an unchecked explicit review and sends only the displayed revision', async () => {
    show(); open();
    expect(screen.getByText(config.baseURL)).toBeVisible(); expect(screen.getByText(config.model)).toBeVisible();
    expect(screen.getByText(/Case evidence and logs are not sent/)).toBeVisible();
    expect(screen.getByText(/not model quality or local inference/)).toBeVisible();
    expect(screen.getByRole('checkbox',{name:/I approve this one-time test/})).not.toBeChecked();
    expect(screen.getByRole('button',{name:'Run test now'})).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    acknowledge(); vi.mocked(mutate).mockResolvedValue(result('passed')); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(await screen.findByText(/Provider test passed: connectivity and structured response format/)).toBeVisible();
    expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/test',{configRevision:'revision-a',acknowledgeTest:true},expect.any(AbortSignal));
    expect(changed).toHaveBeenCalledWith(true); expect(changed).toHaveBeenLastCalledWith(false);
});

it.each([['unavailable','The provider was unavailable'],['timeout','The provider test timed out'],['invalid_response','did not have the expected structured format'],['canceled','Data already sent cannot be recalled']])('renders %s without repeating',async (status, message) => {
    show(); open(); acknowledge(); vi.mocked(mutate).mockResolvedValue(result(status)); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(await screen.findByText(new RegExp(message))).toBeVisible(); expect(mutate).toHaveBeenCalledTimes(1);
});

it.each([result('passed','other-revision'),{...result('passed'), extra:'untrusted'},result('unknown')])('treats unexpected response as uncertain and does not render untrusted text',async response => {
    show(); open(); acknowledge(); vi.mocked(mutate).mockResolvedValue(response); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(await screen.findByText(/outcome is uncertain/)).toBeVisible(); expect(screen.queryByText('untrusted')).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledTimes(1);
});

it('reports busy/conflict as a fresh-read requirement',async () => {
    show(); open(); acknowledge(); vi.mocked(mutate).mockRejectedValue(new APIError('private provider detail',409)); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(await screen.findByText(/Another analysis is running or the provider configuration changed/)).toBeVisible();
    expect(screen.queryByText('private provider detail')).not.toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Read status again'})).toBeVisible(); expect(screen.getByRole('button',{name:'Test saved provider'})).toBeDisabled(); expect(mutate).toHaveBeenCalledTimes(1);
});

it('shows a read-only refresh when the loaded provider is busy', () => {
    show({...config,busy:true});
    expect(screen.getByRole('button',{name:'Test saved provider'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'Read status again'})).toBeVisible();
    expect(mutate).not.toHaveBeenCalled();
});

it('accepts HTTP 200 busy as a known state and never retries automatically', async () => {
    show(); open(); acknowledge(); vi.mocked(mutate).mockResolvedValue(result('busy'));
    fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(await screen.findByText('Another analysis is running.')).toBeVisible();
    expect(screen.getByRole('button',{name:'Test saved provider'})).toBeDisabled();
    expect(screen.getByRole('button',{name:'Read status again'})).toBeVisible();
    expect(screen.queryByText(/outcome is uncertain/)).not.toBeInTheDocument();
    expect(mutate).toHaveBeenCalledTimes(1);
});

it('cancels once and ignores a late success',async () => {
    let finish!: (v: unknown) => void;
    vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
    show(); open(); acknowledge(); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    const signal = vi.mocked(mutate).mock.calls[0][2]!;
    fireEvent.click(screen.getByRole('button',{name:'Cancel'})); expect(signal.aborted).toBe(true);
    await act(async () => finish(result('passed')));
    expect(screen.getByText(/outcome is uncertain/)).toBeVisible(); expect(screen.queryByText(/Provider test passed/)).not.toBeInTheDocument(); expect(mutate).toHaveBeenCalledTimes(1);
});

it('discards a late result when the configuration revision changes',async () => {
    let finish!: (v: unknown) => void;
    vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
    const view=show(); open(); acknowledge(); fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    const signal=vi.mocked(mutate).mock.calls[0][2]!;
    view.rerender(<AIProviderTest config={{...config,revision:'revision-b'}} disabled={false} onBusy={changed} onRefresh={refresh}/>);
    expect(signal.aborted).toBe(true); await act(async () => finish(result('passed')));
    expect(screen.queryByText(/Provider test passed/)).not.toBeInTheDocument();
});

it('closes and marks the view stale after a configuration change event',async () => {
    show(); open(); act(() => window.dispatchEvent(new Event('tracebolt-ai-config-changed')));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); expect(screen.getByRole('button',{name:'Test saved provider'})).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'Read status again'})); await act(async()=>{});
    expect(refresh).toHaveBeenCalledOnce();
});

it('shows the confirmation and limits in German', () => {
    setLocale('de',false); show(); fireEvent.click(screen.getByRole('button',{name:'Gespeicherten Anbieter testen'}));
    expect(screen.getByText(/Fallbelege und Logs werden nicht gesendet/)).toBeVisible();
    expect(screen.getByRole('checkbox',{name:/Ich bestätige diesen einmaligen Test/})).not.toBeChecked();
    expect(screen.getByRole('button',{name:'Test jetzt ausführen'})).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
});
