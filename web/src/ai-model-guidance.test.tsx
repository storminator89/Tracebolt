import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import type { AIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const memory: AIConfig = { revision: 'config-one', configured: true, provider: 'openai-compatible', baseURL: 'http://127.0.0.1:11434/v1', endpointOrigin: 'http://127.0.0.1:11434', model: 'fixture-model', keyConfigured: false, useLegacyMaxTokens: false, allowRemoteEvidence: false, storage: 'memory-only', resetsOnRestart: true, busy: false, limitations: [], persistenceAvailable: true, persistentKeyAllowed: true };

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); vi.mocked(request).mockResolvedValue(memory); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function start() { render(<AIProviderSettings/>); return screen.findByLabelText('AI model'); }
describe('accessible model format guidance', () => {
    it('explains an empty model without changing the configuration or consent', async () => {
        const model = await start();
        expect(model).toHaveAttribute('aria-invalid', 'false');
        expect(model).toHaveAccessibleDescription(/1–128 ASCII characters/);
        fireEvent.change(model, { target: { value: '' } });
        expect(model).toHaveAttribute('aria-invalid', 'true');
        expect(model).toHaveAccessibleDescription(/Enter a model ID to save the configuration/);
        expect(screen.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
        expect(screen.getAllByRole('checkbox').every(box => !(box as HTMLInputElement).checked)).toBe(true);
        expect(mutate).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it.each(['model with space', 'mödél', 'model\tname'])('links invalid format guidance and recovers after correcting %s', async invalid => {
        const model = await start(); fireEvent.change(model, { target: { value: invalid } });
        expect(model).toHaveAttribute('aria-invalid', 'true');
        expect(model).toHaveAccessibleDescription(/ASCII characters/);
        expect(screen.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
        fireEvent.change(model, { target: { value: 'provider/model-1:latest' } });
        expect(model).toHaveAttribute('aria-invalid', 'false');
        expect(screen.getByRole('button', { name: 'Save configuration' })).toBeEnabled();
        expect(mutate).not.toHaveBeenCalled();
    });
    it.each([
        ['128 ASCII characters', 'a'.repeat(128), true],
        ['129 ASCII characters', 'a'.repeat(129), false],
        ['ASCII DEL', 'model' + String.fromCharCode(127), false],
    ] as const)('preserves the existing boundary for %s', async (_label, value, valid) => {
        const model = await start();
        expect(model).toHaveAttribute('maxlength', '128');
        // Programmatic change also exercises the existing validator beyond the browser limit.
        fireEvent.change(model, { target: { value } });
        expect(model).toHaveValue(value);
        expect(model).toHaveAttribute('aria-invalid', String(!valid));
        expect(model).toHaveAccessibleDescription(/1–128 ASCII characters/);
        const save = screen.getByRole('button', { name: 'Save configuration' });
        if (valid) expect(save).toBeEnabled(); else expect(save).toBeDisabled();
        expect(mutate).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
    });
    it('localizes the empty state in place without fetching or changing the draft', async () => {
        const model = await start(); fireEvent.change(model, { target: { value: '' } });
        act(() => setLocale('de', false));
        expect(model).toHaveAccessibleDescription(/1–128 ASCII-Zeichen/);
        expect(model).toHaveAccessibleDescription(/Eine Modellkennung eingeben/);
        expect(model).toHaveValue(''); expect(request).toHaveBeenCalledTimes(1); expect(mutate).not.toHaveBeenCalled();
    });
});
