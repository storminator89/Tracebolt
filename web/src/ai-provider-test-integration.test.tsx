import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import type { AIConfig } from './ai-types';
import { mutate, request } from './api';
import { setLocale } from './i18n';

vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const config: AIConfig = { revision:'revision-a',configured:true,provider:'openai-compatible',baseURL:'https://10.6.1.75:8443/v1',endpointOrigin:'https://10.6.1.75:8443',model:'fixture-model',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:true,lanMode:true,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[] };
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(request).mockResolvedValue(config); setLocale('en',false); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('tests the saved settings only and prevents edits or saves during the in-flight test',async () => {
    render(<AIProviderSettings/>);
    await screen.findByLabelText('AI model');
    const testButton=screen.getByRole('button',{name:'Test saved provider'});
    expect(testButton).toBeEnabled();
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:'other-model'}});
    expect(testButton).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText('AI model'),{target:{value:config.model}});
    expect(testButton).toBeEnabled(); fireEvent.click(testButton);
    expect(screen.getByRole('dialog')).toHaveTextContent(config.baseURL); expect(screen.getByRole('dialog')).toHaveTextContent(config.model);
    fireEvent.click(screen.getByRole('checkbox',{name:/I approve this one-time test/}));
    let finish!: (value: unknown) => void;
    vi.mocked(mutate).mockImplementation(() => new Promise(resolve => {finish=resolve;}));
    fireEvent.click(screen.getByRole('button',{name:'Run test now'}));
    expect(screen.getByLabelText('AI model')).toBeDisabled(); expect(screen.getByLabelText('AI base URL')).toBeDisabled(); expect(screen.getByRole('button',{name:'Save configuration'})).toBeDisabled();
    await act(async () => finish({schemaVersion:'tracebolt.ai-provider-test.v1',configRevision:'revision-a',status:'passed'}));
    expect(await screen.findByText(/Provider test passed/)).toBeVisible();
    expect(mutate).toHaveBeenCalledExactlyOnceWith('/ai/test',{configRevision:'revision-a',acknowledgeTest:true},expect.any(AbortSignal));
});
