import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import { endpointInfo, validAIConfig } from './ai-types';
import type { AIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const initial: AIConfig = { revision:'old',configured:false,provider:'openai-compatible',baseURL:'http://127.0.0.1:11434/v1',endpointOrigin:'http://127.0.0.1:11434',model:'',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[],persistenceAvailable:true,persistentKeyAllowed:true };
const base = 'https://10.6.1.75:8443/v1';
const active: AIConfig = { ...initial,revision:'new',configured:true,baseURL:base,endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',allowRemoteEvidence:true,lanMode:true };

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(request).mockResolvedValue(initial); localStorage.clear(); sessionStorage.clear(); setLocale('en', false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

async function setup() {
    render(<AIProviderSettings/>);
    await screen.findByLabelText('AI model');
    fireEvent.change(screen.getByLabelText('AI base URL'), { target:{value:base} });
    fireEvent.change(screen.getByLabelText('AI model'), { target:{value:'fixture-model'} });
}
const lanConsent = () => screen.getByRole('checkbox', { name:/I confirm the private LAN destination/ });
const evidenceConsent = () => screen.getByRole('checkbox', { name:/Allow case evidence to be sent to/ });
const save = () => screen.getByRole('button', { name:'Save configuration' });

describe('explicit private LAN provider', () => {
    it.each(['https://10.6.1.75:8443/v1','https://172.16.0.1:1/v1','https://172.31.255.254:65535/v1','https://192.168.0.1:443/v1'])( 'recognizes exact RFC1918 endpoint %s', url => {
        expect(endpointInfo(url)).toMatchObject({valid:true,lan:true,local:false});
    });
    it.each(['http://10.6.1.75:8443/v1','https://10.6.1.75/v1','https://10.6.1.75:/v1','https://10.6.1.75:0/v1','https://10.6.1.75:65536/v1','https://10.06.1.75:8443/v1','https://10.6.1.75:8443/v1?x=1'])('rejects invalid private endpoint %s', url => expect(endpointInfo(url).valid).toBe(false));
    it('requires both unchecked acknowledgements and sends only session-mode request with optional empty key', async () => {
        const storage = vi.spyOn(Storage.prototype,'setItem');
        await setup();
        expect(lanConsent()).not.toBeChecked(); expect(evidenceConsent()).not.toBeChecked();
        expect(screen.getByText(/certificate must be valid for the exact IP address/i)).toBeVisible();
        expect(screen.queryByRole('checkbox',{name:/Keep provider/})).not.toBeInTheDocument();
        expect(save()).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(lanConsent()); expect(save()).toBeDisabled();
        fireEvent.click(evidenceConsent()); expect(save()).toBeEnabled();
        vi.mocked(mutate).mockResolvedValue(active); fireEvent.click(save());
        await screen.findByText('Configuration saved. The provider has not been contacted.');
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/lan', { expectedRevision:'old',baseURL:base,model:'fixture-model',apiKey:'',approvedOrigin:'https://10.6.1.75:8443',allowRemoteEvidence:true,useLegacyMaxTokens:false,acknowledgeLanDestination:true }, expect.any(AbortSignal));
        expect(storage).not.toHaveBeenCalled();
    });
    it('distinguishes an unsaved LAN draft from the active process-memory configuration', async () => {
        await setup();
        expect(screen.getByText('LAN draft · not saved yet')).toBeVisible();
        expect(screen.getByText(/After saving, the LAN destination remains configured until the manager restarts/)).toBeVisible();
        expect(screen.queryByText('Until the manager restarts')).not.toBeInTheDocument();
        expect(mutate).not.toHaveBeenCalled();
        fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        vi.mocked(mutate).mockResolvedValue(active); fireEvent.click(save());
        await screen.findByText('Configuration saved. The provider has not been contacted.');
        expect(screen.queryByText('LAN draft · not saved yet')).not.toBeInTheDocument();
        expect(screen.getByText('Until the manager restarts')).toBeVisible();
    });
    it('clears both approvals when the exact destination changes', async () => {
        await setup(); fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        fireEvent.change(screen.getByLabelText('AI base URL'),{target:{value:'https://10.6.1.76:8443/v1'}});
        expect(lanConsent()).not.toBeChecked(); expect(evidenceConsent()).not.toBeChecked(); expect(save()).toBeDisabled();
    });
    it('warns before LAN save removes the previously persisted provider, key and proactive approval', async () => {
        vi.mocked(request).mockResolvedValue({ ...initial, configured:true, model:'old-model', keyConfigured:true, storage:'protected-file', resetsOnRestart:false });
        await setup();
        expect(screen.getByRole('note')).toHaveTextContent('Saving removes the previously saved provider configuration, its key and the proactive approval from this manager.');
        expect(mutate).not.toHaveBeenCalled();
    });
    it('shows unchecked destination and evidence approvals in German without contacting any provider', async () => {
        setLocale('de', false);
        render(<AIProviderSettings/>);
        await screen.findByLabelText('KI Modell');
        fireEvent.change(screen.getByLabelText('KI Basis-URL'), { target:{value:base} });
        fireEvent.change(screen.getByLabelText('KI Modell'), { target:{value:'fixture-model'} });
        expect(screen.getByRole('checkbox',{name:/Ich bestätige das private LAN-Ziel.*bis zum Manager-Neustart/})).not.toBeChecked();
        expect(screen.getByRole('checkbox',{name:/Fallbelege für manuelle Analysen/})).not.toBeChecked();
        expect(screen.getByText(/Zertifikat muss für die exakte IP-Adresse gültig sein/)).toBeVisible();
        expect(mutate).not.toHaveBeenCalled();
    });
    it('clears approvals after model or secret changes', async () => {
        await setup(); fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'other-model'}});
        expect(lanConsent()).not.toBeChecked(); expect(evidenceConsent()).not.toBeChecked();
        fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        fireEvent.change(screen.getByLabelText('AI API key'),{target:{value:'SYNTHETIC_ONLY'}});
        expect(lanConsent()).not.toBeChecked(); expect(evidenceConsent()).not.toBeChecked();
    });
    it('uses a fresh optional key only in the LAN configuration request', async () => {
        const storage = vi.spyOn(Storage.prototype,'setItem');
        await setup();
        fireEvent.change(screen.getByLabelText('AI API key'),{target:{value:'SYNTHETIC_ONLY'}});
        fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        vi.mocked(mutate).mockResolvedValue({...active,keyConfigured:true});
        fireEvent.click(save());
        await screen.findByText('Configuration saved. The provider has not been contacted.');
        expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/config/lan', expect.objectContaining({apiKey:'SYNTHETIC_ONLY',acknowledgeLanDestination:true,allowRemoteEvidence:true}), expect.any(AbortSignal));
        expect(screen.getByLabelText('AI API key')).toHaveValue('');
        expect(storage).not.toHaveBeenCalled();
    });
    it('rejects contradictory readback and requires an explicit read after an uncertain write', async () => {
        expect(validAIConfig({...active, storage:'protected-file', resetsOnRestart:false})).toBe(false);
        expect(validAIConfig({...active, allowRemoteEvidence:false})).toBe(false);
        expect(validAIConfig({...active, endpointOrigin:'https://10.6.1.76:8443'})).toBe(false);
        expect(validAIConfig({...active, lanMode:false})).toBe(false);
        await setup(); fireEvent.click(lanConsent()); fireEvent.click(evidenceConsent());
        vi.mocked(mutate).mockResolvedValue({...active, lanMode:undefined}); fireEvent.click(save());
        await act(async () => {});
        expect(screen.getByRole('alert')).toHaveTextContent('may already have taken effect');
        expect(screen.queryByLabelText('AI model')).not.toBeInTheDocument();
        expect(mutate).toHaveBeenCalledTimes(1);
    });
});
