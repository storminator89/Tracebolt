// @vitest-environment-options {"url":"http://localhost/"}
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import type { AIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const initial: AIConfig = { revision:'old',configured:false,provider:'openai-compatible',baseURL:'http://127.0.0.1:11434/v1',endpointOrigin:'http://127.0.0.1:11434',model:'',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[] };
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(request).mockResolvedValue(initial); setLocale('en', false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('blocks LAN key entry on an HTTP operator surface while allowing keyless settings', async () => {
    expect(window.location.protocol).toBe('http:');
    render(<AIProviderSettings/>);
    await screen.findByLabelText('AI model');
    // A previously typed key is cleared when changing to a LAN destination.
    fireEvent.change(screen.getByLabelText('AI API key'),{target:{value:'SYNTHETIC_ONLY'}});
    fireEvent.change(screen.getByLabelText('AI base URL'),{target:{value:'https://10.6.1.75:8443/v1'}});
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'fixture-model'}});
    expect(screen.getByLabelText('AI API key')).toBeDisabled();
    expect(screen.getByLabelText('AI API key')).toHaveValue('');
    expect(screen.getByText(/LAN API key can only be entered through an HTTPS connection to the manager/)).toBeVisible();
    expect(screen.queryByRole('checkbox',{name:'Use a private CA for this LAN destination'})).not.toBeInTheDocument();
    expect(screen.getByText(/private CA requires a secure HTTPS connection/)).toBeVisible();
    expect(mutate).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('checkbox',{name:/I confirm the private LAN destination/}));
    fireEvent.click(screen.getByRole('checkbox',{name:/Allow case evidence to be sent to/}));
    expect(screen.getByRole('button',{name:'Save configuration'})).toBeEnabled();
    const next: AIConfig = { ...initial,revision:'new',configured:true,baseURL:'https://10.6.1.75:8443/v1',endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',allowRemoteEvidence:true,lanMode:true };
    vi.mocked(mutate).mockResolvedValue(next);
    fireEvent.click(screen.getByRole('button',{name:'Save configuration'}));
    await screen.findByText('Configuration saved. The provider has not been contacted.');
    expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/lan',expect.objectContaining({apiKey:'',acknowledgeLanDestination:true}),expect.any(AbortSignal));
});

it('explains the blocked key field in German without a write', async () => {
    setLocale('de', false);
    render(<AIProviderSettings/>);
    await screen.findByLabelText('KI Modell');
    fireEvent.change(screen.getByLabelText('KI Basis-URL'),{target:{value:'https://10.6.1.75:8443/v1'}});
    expect(screen.getByLabelText('KI API-Schlüssel')).toBeDisabled();
    expect(screen.getByText(/LAN-API-Schlüssel kann nur über einen HTTPS-Zugang zum Manager/)).toBeVisible();
    expect(mutate).not.toHaveBeenCalled();
});
