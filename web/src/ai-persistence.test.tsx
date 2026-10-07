import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import { validAIConfig } from './ai-types';
import type { AIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const memory: AIConfig = { revision: 'config-one', configured: true, provider: 'openai-compatible', baseURL: 'http://127.0.0.1:11434/v1', endpointOrigin: 'http://127.0.0.1:11434', model: 'fixture-model', keyConfigured: false, useLegacyMaxTokens: false, allowRemoteEvidence: false, storage: 'memory-only', resetsOnRestart: true, busy: false, limitations: [], persistenceAvailable: true, persistentKeyAllowed: true };
const persisted: AIConfig = { ...memory, revision: 'config-saved', storage: 'protected-file', resetsOnRestart: false };
const remember = () => screen.getByRole('checkbox', { name: 'Keep provider configuration on this manager after restart' });
const keyConsent = () => screen.getByRole('checkbox', { name: 'Save this key on this manager' });
const save = () => screen.getByRole('button', { name: 'Save configuration' });
const enterKey = (value = 'SYNTHETIC_KEY_NEVER_REAL') => fireEvent.change(screen.getByLabelText('AI API key'), { target: { value } });
const flush = () => act(async () => {});
async function start(config: AIConfig = memory) { vi.mocked(request).mockResolvedValue(config); render(<AIProviderSettings/>); await screen.findByLabelText('AI model'); }
const change = (config = memory, apiKey = '') => ({ expectedRevision: config.revision, baseURL: config.baseURL, model: config.model, apiKey, approvedOrigin: config.endpointOrigin, allowRemoteEvidence: false, useLegacyMaxTokens: false });
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('provider persistence contract', () => {
    it('accepts legacy memory-only and explicit protected-file readbacks', () => {
        expect(validAIConfig({ ...memory, persistenceAvailable: undefined, persistentKeyAllowed: undefined })).toBe(true);
        expect(validAIConfig(persisted)).toBe(true);
    });
    it.each([{ ...memory, persistenceAvailable: 'true' }, { ...memory, persistentKeyAllowed: 1 }, { ...memory, storage: 'encrypted' }, { ...memory, resetsOnRestart: false }, { ...persisted, resetsOnRestart: true }, { ...persisted, persistenceAvailable: false }, { ...persisted, configured: false }, { ...memory, persistenceAvailable: false, persistentKeyAllowed: true }])('fails closed for contradictory capabilities/storage %j', value => expect(validAIConfig(value)).toBe(false));
    it('hides persistence choices for old managers without migrating or saving', async () => {
        await start({ ...memory, persistenceAvailable: undefined, persistentKeyAllowed: undefined });
        expect(screen.queryByRole('checkbox', { name: /Keep provider/ })).not.toBeInTheDocument();
        expect(mutate).not.toHaveBeenCalled();
    });
    it('starts unchecked and preserves the exact seven-field memory-only request', async () => {
        await start(); expect(remember()).not.toBeChecked(); vi.mocked(mutate).mockResolvedValue({ ...memory, revision: 'config-next' });
        fireEvent.click(save()); await flush();
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config', change(), expect.any(AbortSignal));
    });
    it('uses the persistent endpoint for explicit keyless approval with no key acknowledgment', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'), changed = vi.fn(); window.addEventListener('tracebolt-ai-config-changed', changed);
        try {
            await start({ ...memory, persistentKeyAllowed: false }); fireEvent.click(remember());
            expect(screen.queryByRole('checkbox', { name: /Save this key/ })).not.toBeInTheDocument();
            vi.mocked(mutate).mockResolvedValue({ ...persisted, persistentKeyAllowed: false }); fireEvent.click(save()); await flush();
            expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/persistent', { ...change(), acknowledgeKeyStorage: false }, expect.any(AbortSignal));
            expect(changed).toHaveBeenCalledOnce(); expect(storage).not.toHaveBeenCalled();
            expect(screen.getByText('Saved on this manager')).toBeVisible(); expect(remember()).not.toBeChecked();
            expect(screen.queryByText('For this manager session only')).not.toBeInTheDocument();
        } finally { window.removeEventListener('tracebolt-ai-config-changed', changed); }
    });
    it('requires specific key consent and never reads or stores the key in the browser', async () => {
        const storage = vi.spyOn(Storage.prototype, 'setItem'); await start(); fireEvent.click(remember()); enterKey();
        expect(save()).toBeDisabled(); expect(keyConsent()).not.toBeChecked();
        fireEvent.submit(save().closest('form')!); expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(keyConsent()); expect(save()).toBeEnabled();
        vi.mocked(mutate).mockResolvedValue({ ...persisted, keyConfigured: true }); fireEvent.click(save()); await flush();
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/persistent', { ...change(memory, 'SYNTHETIC_KEY_NEVER_REAL'), acknowledgeKeyStorage: true }, expect.any(AbortSignal));
        expect(screen.getByLabelText('AI API key')).toHaveValue(''); expect(storage).not.toHaveBeenCalled();
        expect(screen.getByText('Configured · untested')).toBeVisible();
    });
    it('blocks keyed HTTP-test persistence regardless of the browser origin and allows explicit memory-only save', async () => {
        await start({ ...memory, persistentKeyAllowed: false }); fireEvent.click(remember()); enterKey();
        expect(save()).toBeDisabled(); expect(keyConsent()).toBeDisabled();
        expect(screen.getByText(/HTTP-test mode only supports a keyless loopback/)).toBeVisible();
        fireEvent.click(keyConsent()); fireEvent.submit(save().closest('form')!); expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(remember()); expect(save()).toBeEnabled(); vi.mocked(mutate).mockResolvedValue({ ...memory, persistentKeyAllowed: false, revision: 'config-next', keyConfigured: true });
        fireEvent.click(save()); await flush(); expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config', change(memory, 'SYNTHETIC_KEY_NEVER_REAL'), expect.any(AbortSignal));
    });
    it('requires new consent when the key changes or persistence is toggled', async () => {
        await start(); fireEvent.click(remember()); enterKey(); fireEvent.click(keyConsent());
        enterKey('SYNTHETIC_REPLACEMENT'); expect(keyConsent()).not.toBeChecked(); expect(save()).toBeDisabled();
        fireEvent.click(keyConsent()); fireEvent.click(remember()); fireEvent.click(remember()); expect(keyConsent()).not.toBeChecked(); expect(save()).toBeDisabled();
    });
    it.each(['AI base URL', 'AI model'])('clears key and its approval when %s changes', async name => {
        await start(); fireEvent.click(remember()); enterKey(); fireEvent.click(keyConsent());
        fireEvent.change(screen.getByLabelText(name), { target: { value: name === 'AI model' ? 'replacement-model' : 'http://127.0.0.1:11435/v1' } });
        expect(screen.getByLabelText('AI API key')).toHaveValue(''); enterKey(); expect(keyConsent()).not.toBeChecked(); expect(save()).toBeDisabled();
    });
    it('does not opt in or reuse a saved key on readback; unchecked saving explicitly replaces persisted mode', async () => {
        await start({ ...persisted, keyConfigured: true }); expect(remember()).not.toBeChecked(); expect(screen.getByLabelText('AI API key')).toHaveValue('');
        expect(screen.getByText(/Saving removes any previously saved configuration and proactive approval/)).toBeVisible();
        expect(screen.queryByText(/After a restart, the provider/)).not.toBeInTheDocument();
        vi.mocked(mutate).mockResolvedValue({ ...memory, revision: 'config-next' }); fireEvent.click(save()); await flush();
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config', change(persisted), expect.any(AbortSignal));
    });
    it('explicitly clears persisted provider, key and scope, then notifies scope listeners', async () => {
        const changed = vi.fn(); window.addEventListener('tracebolt-ai-config-changed', changed);
        try {
            await start(persisted); fireEvent.click(screen.getByRole('button', { name: 'Remove AI provider' }));
            expect(screen.getByText(/The saved configuration, key and proactive approval will be removed/)).toBeVisible(); expect(mutate).not.toHaveBeenCalled();
            vi.mocked(mutate).mockResolvedValue({ ...memory, revision: 'config-clear', configured: false, model: '' }); fireEvent.click(screen.getByRole('button', { name: 'Remove provider' })); await flush();
            expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/clear', { expectedRevision: persisted.revision }, expect.any(AbortSignal));
            expect(screen.getByText('Provider, key and saved proactive approval removed.')).toBeVisible(); expect(changed).toHaveBeenCalledOnce();
        } finally { window.removeEventListener('tracebolt-ai-config-changed', changed); }
    });
    it.each(['failure', 'malformed', 'wrong-mode'])('locks after an uncertain %s write until an explicit read, with no replay', async mode => {
        await start(); fireEvent.click(remember());
        if (mode === 'failure') vi.mocked(mutate).mockRejectedValue(new Error('private provider data'));
        else vi.mocked(mutate).mockResolvedValue(mode === 'malformed' ? { ...persisted, persistentKeyAllowed: 'true' } : memory);
        fireEvent.click(save()); await flush();
        expect(screen.getByRole('alert')).toHaveTextContent('may already have taken effect'); expect(screen.queryByLabelText('AI model')).not.toBeInTheDocument();
        expect(screen.queryByText('private provider data')).not.toBeInTheDocument(); expect(request).toHaveBeenCalledTimes(1);
        fireEvent.click(screen.getByRole('button', { name: 'Try again' })); await flush();
        expect(remember()).not.toBeChecked(); expect(mutate).toHaveBeenCalledTimes(1);
    });
    it('serializes repeated submissions and discards late saves after unmount', async () => {
        vi.mocked(request).mockResolvedValue(memory); const mounted = render(<AIProviderSettings/>); await screen.findByLabelText('AI model'); fireEvent.click(remember());
        let resolve!: (value: AIConfig) => void; vi.mocked(mutate).mockReturnValue(new Promise<AIConfig>(done => { resolve = done; }));
        const form = save().closest('form')!; act(() => { fireEvent.submit(form); fireEvent.submit(form); });
        expect(mutate).toHaveBeenCalledTimes(1); const signal = vi.mocked(mutate).mock.calls[0][2]!; mounted.unmount(); expect(signal.aborted).toBe(true);
        const changed = vi.fn(); window.addEventListener('tracebolt-ai-config-changed', changed);
        try { await act(async () => resolve(persisted)); expect(changed).not.toHaveBeenCalled(); } finally { window.removeEventListener('tracebolt-ai-config-changed', changed); }
    });
    it('keeps invalid reads noneditable and never auto-saves', async () => {
        vi.mocked(request).mockResolvedValue({ ...persisted, persistenceAvailable: 'true' }); render(<AIProviderSettings/>); await flush();
        expect(screen.getByRole('alert')).toBeVisible(); expect(screen.queryByLabelText('AI model')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
    });
});
