import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import type { AIConfig } from './ai-types';
import { publicCAFingerprint } from './ai-ca';
import { validAIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const pem = '-----BEGIN CERTIFICATE-----\nAQIDBA==\n-----END CERTIFICATE-----\n';
const fingerprint = '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a';
const digest = vi.fn(async (_algorithm: string, data: Uint8Array) => {
    if (Array.from(data).join(',') !== '1,2,3,4') throw new Error('unexpected DER');
    return Uint8Array.from(fingerprint.match(/../g)!.map(value => parseInt(value,16))).buffer;
});
const base = 'https://10.6.1.75:8443/v1';
const initial: AIConfig = { revision:'old',configured:false,provider:'openai-compatible',baseURL:'http://127.0.0.1:11434/v1',endpointOrigin:'http://127.0.0.1:11434',model:'',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[] };
const active: AIConfig = { ...initial, revision:'new',configured:true,baseURL:base,endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',allowRemoteEvidence:true,lanMode:true,lanPrivateCaSha256:fingerprint };

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); digest.mockClear(); vi.mocked(request).mockResolvedValue(initial); vi.stubGlobal('isSecureContext',true); vi.stubGlobal('crypto',{subtle:{digest}}); setLocale('en',false); localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function setup() {
    render(<AIProviderSettings/>); await screen.findByLabelText('AI model');
    fireEvent.change(screen.getByLabelText('AI base URL'),{target:{value:base}});
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'fixture-model'}});
}
const caMode = () => screen.getByRole('checkbox',{name:'Use a private CA for this LAN destination'});
const fingerprintInput = () => screen.getByLabelText('Independently expected CA fingerprint');
const caConsent = () => screen.getByRole('checkbox',{name:'I independently verified this CA fingerprint.'});
const save = () => screen.getByRole('button',{name:'Save configuration'});

it('computes a bounded public DER hash without accepting ambiguous PEM', async () => {
    expect(await publicCAFingerprint(pem)).toBe(fingerprint);
    expect(digest).toHaveBeenCalledWith('SHA-256',expect.any(Uint8Array));
    for (const value of ['',pem+pem,pem.replace('CERTIFICATE','PRIVATE KEY'),pem.replace('AQIDBA==','AQIDBA='),pem+' '.repeat(4096)]) await expect(publicCAFingerprint(value)).rejects.toThrow();
});

it('requires independently entered matching hash, its unchecked confirmation and both separate LAN approvals', async () => {
    const storage=vi.spyOn(Storage.prototype,'setItem'); await setup();
    expect(caMode()).not.toBeChecked(); fireEvent.click(caMode());
    fireEvent.change(screen.getByLabelText('Public CA certificate (PEM)'),{target:{value:pem}});
    expect(await screen.findByText(fingerprint)).toBeVisible();
    expect(fingerprintInput()).toHaveValue(''); expect(caConsent()).not.toBeChecked(); expect(save()).toBeDisabled();
    fireEvent.change(fingerprintInput(),{target:{value:'a'.repeat(64)}}); fireEvent.click(caConsent());
    fireEvent.click(screen.getByRole('checkbox',{name:/I confirm the private LAN destination/}));
    fireEvent.click(screen.getByRole('checkbox',{name:/Allow case evidence to be sent to/}));
    expect(save()).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    fireEvent.change(fingerprintInput(),{target:{value:fingerprint}}); expect(caConsent()).not.toBeChecked();
    fireEvent.click(caConsent()); expect(save()).toBeEnabled();
    vi.mocked(mutate).mockResolvedValue(active); fireEvent.click(save());
    await screen.findByText('Configuration saved. The provider has not been contacted.');
    expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/lan-private-ca',expect.objectContaining({caPem:pem,expectedCaSha256:fingerprint,acknowledgeCaFingerprint:true,acknowledgeLanDestination:true,allowRemoteEvidence:true,apiKey:''}),expect.any(AbortSignal));
    expect(screen.getByText('Active private CA fingerprint')).toBeVisible(); expect(screen.getByText(fingerprint)).toBeVisible();
    expect(screen.queryByLabelText('Public CA certificate (PEM)')).not.toBeInTheDocument(); expect(storage).not.toHaveBeenCalled();
});

it('requires explicit provider removal before any replacement of an active pin', async () => {
    vi.mocked(request).mockResolvedValue(active); render(<AIProviderSettings/>); await screen.findByLabelText('AI model');
    expect(screen.getByText('Active private CA fingerprint')).toBeVisible(); expect(screen.getByText(fingerprint)).toBeVisible();
    expect(screen.getByText(/explicitly remove the provider first/)).toBeVisible();
    expect(save()).toBeDisabled();
    fireEvent.change(screen.getByLabelText('AI base URL'),{target:{value:'http://127.0.0.1:11434/v1'}});
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'other-model'}});
    expect(save()).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    expect(screen.getByRole('button',{name:'Remove AI provider'})).toBeVisible();
});

it('marks a private-CA choice as an unsaved draft even when the saved LAN destination is unchanged', async () => {
    vi.mocked(request).mockResolvedValue({ ...active, lanPrivateCaSha256:undefined });
    render(<AIProviderSettings/>); await screen.findByLabelText('AI model');
    expect(screen.getByText('Until the manager restarts')).toBeVisible();
    expect(screen.queryByText('LAN draft · not saved yet')).not.toBeInTheDocument();
    fireEvent.click(caMode());
    expect(screen.getByText('LAN draft · not saved yet')).toBeVisible();
    expect(screen.queryByText('Until the manager restarts')).not.toBeInTheDocument();
    expect(mutate).not.toHaveBeenCalled();
});

it('rejects invalid private CA readbacks', () => {
    expect(validAIConfig(active)).toBe(true);
    expect(validAIConfig({...active,lanPrivateCaSha256:'BAD'})).toBe(false);
    expect(validAIConfig({...active,lanMode:undefined})).toBe(false);
    expect(validAIConfig({...active,storage:'protected-file',resetsOnRestart:false,persistenceAvailable:true})).toBe(false);
    expect(validAIConfig({...active,caPem:pem})).toBe(false);
    expect(validAIConfig({...active,apiKey:'SYNTHETIC_ONLY'})).toBe(false);
});

it('never offers or computes private CA trust without a secure browser context', async () => {
    vi.stubGlobal('isSecureContext',false); await setup();
    expect(screen.queryByRole('checkbox',{name:'Use a private CA for this LAN destination'})).not.toBeInTheDocument();
    expect(screen.getByText(/private CA requires a secure HTTPS connection/)).toBeVisible();
    expect(screen.queryByLabelText('Public CA certificate (PEM)')).not.toBeInTheDocument(); expect(mutate).not.toHaveBeenCalled();
});

it.each(['pem', 'mode', 'unmount'])('discards a delayed fingerprint after %s change without a request', async change => {
    let finish!: (value: ArrayBuffer) => void;
    digest.mockImplementationOnce(() => new Promise<ArrayBuffer>(resolve => { finish = resolve; }));
    const view = render(<AIProviderSettings/>);
    await screen.findByLabelText('AI model');
    fireEvent.change(screen.getByLabelText('AI base URL'),{target:{value:base}});
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'fixture-model'}});
    fireEvent.click(caMode());
    fireEvent.change(screen.getByLabelText('Public CA certificate (PEM)'),{target:{value:pem}});
    await waitFor(() => expect(finish).toBeDefined());
    if (change === 'pem') fireEvent.change(screen.getByLabelText('Public CA certificate (PEM)'),{target:{value:'invalid'}});
    else if (change === 'mode') fireEvent.click(caMode());
    else view.unmount();
    const delayed = Uint8Array.from(fingerprint.match(/../g)!.map(value => parseInt(value,16))).buffer;
    await act(async () => finish(delayed));
    expect(screen.queryByText(fingerprint)).not.toBeInTheDocument();
    if (change === 'pem') { expect(fingerprintInput()).toHaveValue(''); expect(caConsent()).not.toBeChecked(); expect(save()).toBeDisabled(); }
    expect(mutate).not.toHaveBeenCalled();
});

it('shows the separate private CA fingerprint review in German without a network request', async () => {
    setLocale('de',false); render(<AIProviderSettings/>); await screen.findByLabelText('KI Modell');
    fireEvent.change(screen.getByLabelText('KI Basis-URL'),{target:{value:base}});
    fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'fixture-model'}});
    fireEvent.click(screen.getByRole('checkbox',{name:'Private CA für dieses LAN-Ziel verwenden'}));
    fireEvent.change(screen.getByLabelText('Öffentliches CA-Zertifikat (PEM)'),{target:{value:pem}});
    expect(await screen.findByText(fingerprint)).toBeVisible();
    expect(screen.getByLabelText('Unabhängig erwarteter CA-Fingerabdruck')).toHaveValue('');
    expect(screen.getByRole('checkbox',{name:'Ich habe diesen CA-Fingerabdruck unabhängig geprüft.'})).not.toBeChecked();
    expect(screen.getByRole('button',{name:'Konfiguration speichern'})).toBeDisabled();
    expect(mutate).not.toHaveBeenCalled();
});
