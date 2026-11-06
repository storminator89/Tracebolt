import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { mutate, request } from './api';
import type { AIConfig } from './ai-types';
import { AIProviderTest } from './ai-provider-test';
import { AIProviderSettings } from './ai';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), mutate: vi.fn(), request: vi.fn() }));
const config: AIConfig = { revision:'revision-a',configured:true,provider:'openai-compatible',baseURL:'https://10.6.1.75:8443/v1',endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:true,lanMode:true,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[] };
const changed = vi.fn();
const refresh = vi.fn(async () => config);
beforeEach(() => { vi.mocked(mutate).mockReset(); vi.mocked(request).mockReset(); changed.mockClear(); refresh.mockClear(); setLocale('en',false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
function show(c = config, disabled = false) { return render(<AIProviderTest config={c} disabled={disabled} onBusy={changed} onRefresh={refresh}/>); }
function open() { fireEvent.click(screen.getByRole('button',{name:'Test saved provider'})); }
function acknowledge() { fireEvent.click(screen.getByRole('checkbox',{name:/I approve this one-time test/})); }

it('explains missing configuration without starting a test or preselecting consent', () => {
    show({ ...config, configured: false });
    const button = screen.getByRole('button', { name: 'Test saved provider' });
    expect(button).toBeDisabled();
    expect(button).toHaveAccessibleDescription('Save a provider configuration first. Saving does not start a test.');
    fireEvent.click(button); expect(screen.queryByRole('dialog')).toBeNull();
    expect(mutate).not.toHaveBeenCalled(); expect(refresh).not.toHaveBeenCalled();
});
it('explains pending edits and removes guidance once testing becomes available', () => {
    const mounted = show(config, true);
    let button = screen.getByRole('button', { name: 'Test saved provider' });
    expect(button).toHaveAccessibleDescription(/Save pending changes first/); expect(button).toBeDisabled();
    mounted.rerender(<AIProviderTest config={config} disabled={false} onBusy={changed} onRefresh={refresh}/>);
    button = screen.getByRole('button', { name: 'Test saved provider' });
    expect(button).toBeEnabled(); expect(button).not.toHaveAttribute('aria-describedby');
    open(); expect(screen.getByRole('checkbox')).not.toBeChecked();
    expect(screen.getByRole('button', { name: 'Run test now' })).toBeDisabled();
    expect(mutate).not.toHaveBeenCalled();
});
it('keeps existing busy and stale recovery instructions instead of save guidance', () => {
    const mounted = show({ ...config, busy: true }, true);
    expect(screen.queryByText(/Save pending changes/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Read status again' })).toBeVisible();
    mounted.rerender(<AIProviderTest config={config} disabled onBusy={changed} onRefresh={refresh}/>);
    act(() => window.dispatchEvent(new Event('tracebolt-ai-config-changed')));
    expect(screen.queryByText(/Save pending changes/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Read status again' })).toBeVisible();
    expect(mutate).not.toHaveBeenCalled(); expect(refresh).not.toHaveBeenCalled();
});
it('does not tell users to save changes while a confirmed test is running', () => {
    vi.mocked(mutate).mockReturnValue(new Promise(() => {})); show(); open(); acknowledge();
    fireEvent.click(screen.getByRole('button', { name: 'Run test now' }));
    expect(screen.queryByText(/Save pending changes/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Test saved provider' })).not.toHaveAttribute('aria-describedby');
    expect(mutate).toHaveBeenCalledTimes(1);
});
it('localizes missing-configuration guidance in place', () => {
    show({ ...config, configured: false }); act(() => setLocale('de', false));
    expect(screen.getByRole('button', { name: 'Gespeicherten Anbieter testen' })).toHaveAccessibleDescription('Zuerst eine Anbieterkonfiguration speichern. Speichern startet keinen Funktionstest.');
    expect(mutate).not.toHaveBeenCalled(); expect(refresh).not.toHaveBeenCalled();
});


it.each(['en', 'de'] as const)('gives achievable instructions after edits to an active private-CA provider (%s)', async locale => {
    setLocale(locale, false);
    vi.mocked(request).mockResolvedValue({ ...config, lanPrivateCaSha256: 'a'.repeat(64) });
    render(<AIProviderSettings/>);
    const model = await screen.findByLabelText(locale === 'de' ? 'KI Modell' : 'AI model');
    const test = screen.getByRole('button', { name: locale === 'de' ? 'Gespeicherten Anbieter testen' : 'Test saved provider' });
    const save = screen.getByRole('button', { name: locale === 'de' ? 'Konfiguration speichern' : 'Save configuration' });
    expect(test).toBeEnabled(); expect(save).toBeDisabled();
    fireEvent.change(model, { target: { value: 'other-model' } });
    expect(test).toBeDisabled(); expect(save).toBeDisabled();
    expect(test).toHaveAccessibleDescription(locale === 'de'
        ? 'Der Test verwendet die gespeicherte Konfiguration. Entwurfsänderungen zum Testen zurücknehmen. Für Änderungen bei aktiver privater CA zuerst den Anbieter ausdrücklich entfernen.'
        : 'The test uses the saved configuration. Revert draft changes to test it. To change a provider with an active private CA, explicitly remove the provider first.');
    expect(screen.queryByText(/Save pending changes first|Ausstehende Änderungen zuerst speichern/)).toBeNull();
    expect(mutate).not.toHaveBeenCalled();
    fireEvent.change(model, { target: { value: config.model } });
    expect(test).toBeEnabled(); expect(test).not.toHaveAttribute('aria-describedby'); expect(save).toBeDisabled();
    fireEvent.click(test); expect(screen.getByRole('checkbox', { name: locale === 'de' ? /Ich bestätige diesen einmaligen/ : /I approve this one-time test/ })).not.toBeChecked();
    expect(screen.getByRole('button', { name: locale === 'de' ? 'Test jetzt ausführen' : 'Run test now' })).toBeDisabled();
    expect(mutate).not.toHaveBeenCalled();
});
