import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIAnalysisPanel, AIProviderSettings } from './ai';
import { endpointInfo, safeAIError } from './ai-types';
import type { AIConfig, AnalysisResult } from './ai-types';
import type { Case } from './types';
import { APIError, mutate, request } from './api';
import { setLocale } from './i18n';
vi.mock('./api',async importOriginal=>{const original=await importOriginal<typeof import('./api')>();return {...original,request:vi.fn(),mutate:vi.fn()};});
const config:AIConfig={revision:'cfg-one',configured:false,provider:'openai-compatible',baseURL:'http://127.0.0.1:11434/v1',endpointOrigin:'http://127.0.0.1:11434',model:'',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[]};
const configured:AIConfig={...config,configured:true,model:'local-test-model'};
const item:Case={id:'case-test',title:'DNS-Dienst gestoppt',deviceId:'demo-test',deviceName:'DEMO',severity:'critical',status:'open',category:'service',summary:'Regelbefund',ruleId:'service.test',confidence:'evidence-backed',createdAt:'2026-10-03T12:00:00Z',updatedAt:'2026-10-03T12:00:00Z',evidenceIds:['e-1'],evidence:[{id:'e-1',title:'Dienstzustand',source:'fixture',quality:'healthy',collectedAt:'2026-10-03T12:00:00Z',detail:'synthetisch',value:'stopped',synthetic:true}],runbookId:'service',nextSteps:['Lesend prüfen'],timeline:[],notes:[],synthetic:true};
const provenance={method:'ai-suggestion',provider:'openai-compatible',model:'local-test-model',promptVersion:'v1',runbookVersion:'v1',ruleId:'service.test',packetSHA256:'abc',destination:config.baseURL,endpointOrigin:config.endpointOrigin};
const result:AnalysisResult={schemaVersion:'tracebolt.analysis.v1',id:'analysis-test',fingerprint:'test',generatedAt:'2026-10-03T12:00:00Z',configRevision:'cfg-one',superseded:false,packet:{case:{id:item.id,title:item.title,summary:item.summary,synthetic:true},evidence:item.evidence,missingEvidenceIDs:[],observationWindow:{from:null,to:null},gaps:[]},baseline:{summary:'Regelbefund',evidenceIDs:['e-1'],nextCheck:'service',nextSteps:['Lesend prüfen'],provenance},ai:{status:'completed',reason:'',findings:{observedEvidenceIDs:['e-1'],hypotheses:[{statement:'Der Dienst könnte manuell gestoppt worden sein.',evidenceIDs:['e-1']}],counterevidence:[],missingData:['Ereignisprotokoll fehlt'],nextCheck:'service'},nextSteps:['Dienstzustand lesend prüfen'],provenance},rootCauseConfirmed:false,limitations:['Keine bestätigte Ursache']};

beforeEach(() => { vi.mocked(request).mockReset(); vi.mocked(mutate).mockReset(); vi.mocked(request).mockResolvedValue(configured); });
afterEach(() => { cleanup(); setLocale('de', false); vi.restoreAllMocks(); });
async function start(locale: 'en' | 'de') {
 setLocale(locale, false); render(<AIAnalysisPanel item={item} onSettings={() => {}}/>);
 fireEvent.click(await screen.findByRole('button', {name: locale === 'de' ? 'KI-Analyse prüfen' : 'Review AI analysis'}));
 await screen.findByRole('dialog');
 const send = screen.getByRole('button', {name: locale === 'de' ? 'Jetzt analysieren' : 'Analyze now'});
 expect(send).toBeDisabled(); expect(mutate).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole('checkbox')); fireEvent.click(send);
}
const message = (locale: 'en'|'de') => locale === 'de'
 ? 'Antwort auf die Analyseanfrage erhalten. Die aktuelle Anbieter-Konfiguration konnte nicht geprüft werden; das Ergebnis wird nicht angezeigt.'
 : 'A response to the analysis request was received. The current provider configuration could not be checked; the result is not shown.';
it.each(['en','de'] as const)('explains follow-up read failure without provider success (%s)', async locale => {
 vi.mocked(mutate).mockResolvedValue({...result, ai: {...result.ai, status:'unavailable', findings:null}});
 vi.mocked(request).mockResolvedValueOnce(configured).mockResolvedValueOnce(configured).mockRejectedValueOnce(new Error('Synthetic read failure'));
 await start(locale); expect(await screen.findByRole('alert')).toHaveTextContent(message(locale));
 expect(screen.getByRole('alert')).toHaveTextContent('Synthetic read failure');
 expect(screen.queryByText(result.ai.findings!.hypotheses[0].statement)).toBeNull();
 expect(mutate).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(3);
});
it.each(['en','de'] as const)('does not mislabel preflight or mutation failure (%s)', async locale => {
 vi.mocked(mutate).mockRejectedValue(new Error('Synthetic preflight failure'));
 await start(locale); expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic preflight failure');
 expect(screen.getByRole('alert')).not.toHaveTextContent(message(locale));
 expect(mutate).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(2);
});
it.each([401,403])('preserves access failure %i', async status => {
 vi.mocked(mutate).mockResolvedValue(result);
 vi.mocked(request).mockResolvedValueOnce(configured).mockResolvedValueOnce(configured).mockRejectedValueOnce(new APIError('Synthetic access failure',status));
 await start('de'); expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic access failure');
 expect(screen.getByRole('alert')).not.toHaveTextContent(message('de')); expect(mutate).toHaveBeenCalledTimes(1);
});

it('does not mislabel an invalid analysis response after a successful configuration check', async () => {
 vi.mocked(mutate).mockResolvedValue(null);
 await start('de'); await screen.findByRole('alert');
 expect(screen.getByRole('alert')).not.toHaveTextContent(message('de'));
 expect(mutate).toHaveBeenCalledTimes(1); expect(request).toHaveBeenCalledTimes(3);
});
