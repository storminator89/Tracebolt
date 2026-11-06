import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { AIProviderSettings } from './ai';
import { mutate, request } from './api';
import type { AIConfig } from './ai-types';
import { setLocale } from './i18n';
vi.mock('./api', async original => ({ ...await original<typeof import('./api')>(), request: vi.fn(), mutate: vi.fn() }));
const config: AIConfig = { revision:'cfg-synthetic', configured:false, provider:'openai-compatible', baseURL:'http://127.0.0.1:11434/v1', endpointOrigin:'http://127.0.0.1:11434', model:'synthetic-model', keyConfigured:false, useLegacyMaxTokens:false, allowRemoteEvidence:false, storage:'memory-only', resetsOnRestart:true, busy:false, limitations:[] };
beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(request).mockResolvedValue(config); });
afterEach(() => { cleanup(); setLocale('de',false); vi.restoreAllMocks(); });
it.each(['en','de'] as const)('links only the visible existing validation message and clears on repair (%s)', async locale => {
 setLocale(locale,false); render(<AIProviderSettings/>);
 const input = await screen.findByLabelText(locale === 'de' ? 'KI API-Schlüssel' : 'AI API key');
 expect(input).toHaveAttribute('type','password'); expect(input).toHaveAttribute('aria-invalid','false'); expect(input).not.toHaveAttribute('aria-describedby');
 const save = screen.getByRole('button',{name: locale === 'de' ? 'Konfiguration speichern' : 'Save configuration'});
 for (const value of ['SYNTHETIC INVALID', 'SYNTHETIC\u007fINVALID']) {
  fireEvent.change(input,{target:{value}});
  expect(input).toHaveAttribute('aria-invalid','true'); expect(input).toHaveAccessibleDescription(locale === 'de' ? 'Schlüssel ohne Leer- oder Steuerzeichen eingeben.' : 'Use a key without spaces or control characters.');
  const id = input.getAttribute('aria-describedby'); expect(id).toBeTruthy(); expect(document.getElementById(id!)).toBeVisible(); expect(save).toBeDisabled();
 }
 fireEvent.change(input,{target:{value:'SYNTHETIC_NOT_A_REAL_KEY'}});
 expect(input).toHaveAttribute('aria-invalid','false'); expect(input).not.toHaveAttribute('aria-describedby'); expect(save).toBeEnabled();
 fireEvent.change(input,{target:{value:''}}); expect(input).toHaveAttribute('aria-invalid','false'); expect(input).not.toHaveAttribute('aria-describedby');
 expect(mutate).not.toHaveBeenCalled(); expect(request).toHaveBeenCalledTimes(1);
});
it('marks an empty required external key invalid without a dangling description', async () => {
 vi.mocked(request).mockResolvedValue({...config,baseURL:'https://provider.example/v1',endpointOrigin:'https://provider.example',allowRemoteEvidence:true});
 setLocale('en',false); render(<AIProviderSettings/>);
 const input=await screen.findByLabelText('AI API key'); expect(input).toHaveAttribute('aria-invalid','true'); expect(input).not.toHaveAttribute('aria-describedby');
 expect(screen.getByRole('button',{name:'Save configuration'})).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
});
