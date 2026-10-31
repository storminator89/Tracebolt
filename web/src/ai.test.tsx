import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIAnalysisPanel, AIProviderSettings } from './ai';
import { endpointInfo, safeAIError } from './ai-types';
import type { AIConfig, AnalysisResult } from './ai-types';
import type { Case } from './types';
import { mutate, request } from './api';
import { setLocale } from './i18n';
vi.mock('./api',async importOriginal=>{const original=await importOriginal<typeof import('./api')>();return {...original,request:vi.fn(),mutate:vi.fn()};});
const config:AIConfig={revision:'cfg-one',configured:false,provider:'openai-compatible',baseURL:'http://127.0.0.1:11434/v1',endpointOrigin:'http://127.0.0.1:11434',model:'',keyConfigured:false,useLegacyMaxTokens:false,allowRemoteEvidence:false,storage:'memory-only',resetsOnRestart:true,busy:false,limitations:[]};
const configured:AIConfig={...config,configured:true,model:'local-test-model'};
const item:Case={id:'case-test',title:'DNS-Dienst gestoppt',deviceId:'demo-test',deviceName:'DEMO',severity:'critical',status:'open',category:'service',summary:'Regelbefund',ruleId:'service.test',confidence:'evidence-backed',createdAt:'2026-10-03T12:00:00Z',updatedAt:'2026-10-03T12:00:00Z',evidenceIds:['e-1'],evidence:[{id:'e-1',title:'Dienstzustand',source:'fixture',quality:'healthy',collectedAt:'2026-10-03T12:00:00Z',detail:'synthetisch',value:'stopped',synthetic:true}],runbookId:'service',nextSteps:['Lesend prüfen'],timeline:[],notes:[],synthetic:true};
const provenance={method:'ai-suggestion',provider:'openai-compatible',model:'local-test-model',promptVersion:'v1',runbookVersion:'v1',ruleId:'service.test',packetSHA256:'a'.repeat(64),destination:config.baseURL,endpointOrigin:config.endpointOrigin};
const packet = {schemaVersion:'tracebolt.evidence-packet.v1',case:{id:item.id,title:item.title,summary:item.summary,category:item.category,ruleId:item.ruleId,runbookId:item.runbookId,createdAt:item.createdAt,updatedAt:item.updatedAt,synthetic:true},evidence:item.evidence,missingEvidenceIDs:[],observationWindow:{from:null,to:null},gaps:[]};
const result:AnalysisResult & {previewToken:string}={previewToken:'b'.repeat(64),schemaVersion:'tracebolt.analysis.v1',id:'analysis-test',fingerprint:'test',generatedAt:'2026-10-03T12:00:00Z',configRevision:'cfg-one',superseded:false,packet,baseline:{summary:'Regelbefund',evidenceIDs:['e-1'],nextCheck:'service',nextSteps:['Lesend prüfen'],provenance},ai:{status:'completed',reason:'',findings:{observedEvidenceIDs:['e-1'],hypotheses:[{statement:'Der Dienst könnte manuell gestoppt worden sein.',evidenceIDs:['e-1']}],counterevidence:[],missingData:['Ereignisprotokoll fehlt'],nextCheck:'service'},nextSteps:['Dienstzustand lesend prüfen'],provenance},rootCauseConfirmed:false,limitations:['Keine bestätigte Ursache']};
beforeEach(()=>{vi.mocked(request).mockReset();vi.mocked(mutate).mockReset();vi.mocked(request).mockResolvedValue(config);localStorage.clear();sessionStorage.clear();});
afterEach(()=>{cleanup();vi.restoreAllMocks();});
async function readyProviderForm(){await screen.findByLabelText('KI Modell');await waitFor(()=>expect(screen.getByLabelText('KI Basis-URL')).toHaveValue(config.baseURL));}
describe('endpoint and secret handling',()=>{
  it.each(['http://127.0.0.1:11434/v1','http://[::1]:11434/v1'])('recognizes literal loopback %s',url=>expect(endpointInfo(url)).toMatchObject({valid:true,local:true}));
  it('preserves explicit default port in the exact approved origin',()=>expect(endpointInfo('https://api.example.com:443/v1').origin).toBe('https://api.example.com:443'));
  it.each(['http://localhost:11434/v1','http://api.example.com/v1','https://user:secret@api.example.com/v1','https://api.example.com/v1?key=secret','https://api.example.com/v1#secret'])('rejects unsafe or ambiguous URL %s',url=>expect(endpointInfo(url).valid).toBe(false));
  it('redacts a known secret from displayed errors',()=>expect(safeAIError(new Error('Rejected TEST_FAKE_KEY'),'TEST_FAKE_KEY')).toBe('Rejected [Schlüssel entfernt]'));
});
describe('provider settings',()=>{
  it('does not contact a provider or claim connectivity on load',async()=>{render(<AIProviderSettings/>);await readyProviderForm();expect(mutate).not.toHaveBeenCalled();expect(screen.getByText('Nicht eingerichtet')).toBeVisible();expect(screen.getByText('Nur für diese Manager-Sitzung')).toBeVisible();});
  it('saves a local provider, clears password, and never stores credentials in browser storage',async()=>{const storage=vi.spyOn(Storage.prototype,'setItem');vi.mocked(mutate).mockResolvedValue({...configured,revision:'cfg-two',keyConfigured:true});render(<AIProviderSettings/>);await readyProviderForm();fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'local-test-model'}});fireEvent.change(screen.getByLabelText('KI API-Schlüssel'),{target:{value:'TEST_FAKE_KEY_NEVER_REAL'}});fireEvent.click(screen.getByRole('button',{name:'Konfiguration speichern'}));await screen.findByText('Konfiguration gespeichert. Der Anbieter wurde noch nicht kontaktiert.');expect(screen.getByLabelText('KI API-Schlüssel')).toHaveValue('');expect(mutate).toHaveBeenCalledWith('/ai/config',expect.objectContaining({expectedRevision:'cfg-one',apiKey:'TEST_FAKE_KEY_NEVER_REAL',approvedOrigin:'http://127.0.0.1:11434',allowRemoteEvidence:false}),expect.any(AbortSignal));expect(storage).not.toHaveBeenCalled();expect(screen.getByText('Konfiguriert · ungetestet')).toBeVisible();});
  it('requires fresh key plus explicit remote opt-in for HTTPS',async()=>{render(<AIProviderSettings/>);await readyProviderForm();fireEvent.change(screen.getByLabelText('KI Basis-URL'),{target:{value:'https://api.example.com/v1'}});fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'test-model'}});const save=screen.getByRole('button',{name:'Konfiguration speichern'});expect(save).toBeDisabled();fireEvent.change(screen.getByLabelText('KI API-Schlüssel'),{target:{value:'TEST_FAKE_KEY'}});expect(save).toBeDisabled();fireEvent.click(screen.getByRole('checkbox',{name:/Fallbelege für manuelle/}));expect(save).toBeEnabled();expect(mutate).not.toHaveBeenCalled();});
  it('clears entered key and remote consent when destination changes',async()=>{render(<AIProviderSettings/>);await readyProviderForm();fireEvent.change(screen.getByLabelText('KI Basis-URL'),{target:{value:'https://api.example.com/v1'}});fireEvent.change(screen.getByLabelText('KI API-Schlüssel'),{target:{value:'TEST_FAKE_KEY'}});fireEvent.click(screen.getByRole('checkbox',{name:/Fallbelege für manuelle/}));fireEvent.change(screen.getByLabelText('KI Basis-URL'),{target:{value:'https://other.example.com/v1'}});expect(screen.getByLabelText('KI API-Schlüssel')).toHaveValue('');expect(screen.getByRole('checkbox',{name:/Fallbelege für manuelle/})).not.toBeChecked();});
  it('never reads a configured secret back into the field',async()=>{vi.mocked(request).mockResolvedValue({...configured,keyConfigured:true});render(<AIProviderSettings/>);await screen.findByText('Schlüssel gesetzt');expect(screen.getByLabelText('KI API-Schlüssel')).toHaveValue('');});
  it('requires confirmation before clearing memory configuration',async()=>{vi.mocked(request).mockResolvedValue(configured);vi.mocked(mutate).mockResolvedValue({...config,revision:'cfg-two'});render(<AIProviderSettings/>);await screen.findByRole('button',{name:'KI-Anbieter entfernen'});fireEvent.click(screen.getByRole('button',{name:'KI-Anbieter entfernen'}));expect(mutate).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Anbieter entfernen'}));await screen.findByText('Anbieter und Schlüssel aus dem Arbeitsspeicher entfernt.');expect(mutate).toHaveBeenCalledWith('/ai/config/clear',{expectedRevision:'cfg-one'},expect.any(AbortSignal));});
});
function previewFor(value: AnalysisResult = result) { return {schemaVersion:'tracebolt.case-analysis-preview.v1',caseId:item.id,configRevision:configured.revision,baseURL:configured.baseURL,endpointOrigin:configured.endpointOrigin,model:configured.model,packetJSON:JSON.stringify(value.packet),packetSHA256:provenance.packetSHA256,serverNow:new Date(Date.now()).toISOString(),validUntil:new Date(Date.now()+90_000).toISOString(),previewToken:result.previewToken}; }
function mockAnalysis(value: AnalysisResult = result) { vi.mocked(mutate).mockImplementation(async path => path.endsWith('/analyze-preview') ? previewFor(value) : value); }
async function confirmAnalysis(){fireEvent.click(screen.getByRole('button',{name:'KI-Analyse prüfen'}));await screen.findByRole('dialog',{name:'Fallbelege zur KI-Analyse senden'});fireEvent.click(screen.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}));fireEvent.click(screen.getByRole('button',{name:'Jetzt analysieren'}));}
describe('evidence-scoped analysis',()=>{
  it('shows a real settings action while unconfigured, without fake analysis',async()=>{const onSettings=vi.fn();render(<AIAnalysisPanel item={item} onSettings={onSettings}/>);await screen.findByText('Noch kein Anbieter eingerichtet');fireEvent.click(screen.getByRole('button',{name:'Einrichten'}));expect(onSettings).toHaveBeenCalledOnce();expect(mutate).not.toHaveBeenCalled();});
  it('requires data-and-destination review before any provider request',async()=>{mockAnalysis();vi.mocked(request).mockResolvedValue(configured);render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});fireEvent.click(screen.getByRole('button',{name:'KI-Analyse prüfen'}));await screen.findByRole('dialog');expect(screen.getByRole('button',{name:'Jetzt analysieren'})).toBeDisabled();expect(screen.getByText(/ohne automatische Geheimnisfilterung/)).toBeVisible();expect(mutate).toHaveBeenCalledExactlyOnceWith('/cases/case-test/analyze-preview',{},expect.any(AbortSignal));fireEvent.click(screen.getByRole('button',{name:'Abbrechen'}));expect(screen.queryByRole('dialog')).not.toBeInTheDocument();expect(mutate).toHaveBeenCalledTimes(1);});
  it('renders hypotheses as unconfirmed suggestions and keeps markup inert',async()=>{vi.mocked(request).mockResolvedValue(configured);const attack='<img src=x onerror=alert(1)><script>alert(1)</script>';mockAnalysis({...result,ai:{...result.ai,findings:{...result.ai.findings!,hypotheses:[{statement:attack,evidenceIDs:['e-1']}]}}});const {container}=render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText('Ursache nicht bestätigt');expect(screen.getByText(attack)).toBeVisible();expect(container.querySelector('img')).toBeNull();expect(container.querySelector('script')).toBeNull();expect(mutate).toHaveBeenCalledWith('/cases/case-test/analyze',{configRevision:'cfg-one',previewToken:result.previewToken,packetSHA256:provenance.packetSHA256,acknowledge:true},expect.any(AbortSignal));});
  it('ignores superseded configuration results',async()=>{vi.mocked(request).mockResolvedValue(configured);mockAnalysis({...result,superseded:true});render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText(/überholte Ergebnis/);expect(screen.queryByText('KI-Hypothesen')).not.toBeInTheDocument();});
  it('ignores a result when the live configuration changed during request',async()=>{vi.mocked(request).mockResolvedValueOnce(configured).mockResolvedValueOnce(configured).mockResolvedValue({...configured,revision:'cfg-two'});mockAnalysis(result);render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText(/überholte Ergebnis/);expect(screen.queryByText('KI-Hypothesen')).not.toBeInTheDocument();});
  it('reports invalid model output without claiming a diagnosis',async()=>{vi.mocked(request).mockResolvedValue(configured);mockAnalysis({...result,ai:{...result.ai,status:'invalid_response',findings:null,reason:'Antwortschema ungültig'}});render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText('Antwort nicht verwendbar');expect(screen.queryByText('KI-Hypothesen')).not.toBeInTheDocument();});
  it('labels unavailable results without falsely claiming the provider was unreachable',async()=>{setLocale('de',false);vi.mocked(request).mockResolvedValue(configured);mockAnalysis({...result,ai:{...result.ai,status:'unavailable',findings:null,reason:'The configured model could not produce a usable response.'}});render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();expect(await screen.findByText('Anbieterantwort nicht verfügbar')).toBeVisible();expect(screen.queryByText('Anbieter nicht erreichbar')).toBeNull();act(()=>setLocale('en',false));expect(screen.getByText('Provider response unavailable')).toBeVisible();act(()=>setLocale('de',false));});
  it('never revives an analysis result after local cancellation',async()=>{vi.mocked(request).mockResolvedValue(configured);let resolve!:(value:AnalysisResult)=>void;vi.mocked(mutate).mockImplementation(path=>path.endsWith('/analyze-preview')?Promise.resolve(previewFor()):new Promise<AnalysisResult>(done=>{resolve=done;}));render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText('Fallbelege werden analysiert …');fireEvent.click(screen.getByRole('button',{name:'Abbrechen'}));await act(async()=>{resolve(result);});await waitFor(()=>expect(screen.queryByText('KI-Hypothesen')).not.toBeInTheDocument());expect(screen.getByText(/Bereits übertragene Daten/)).toBeVisible();});
});
describe('immutable references and strict input validation',()=>{
  it('opens the analyzed evidence snapshot rather than a later same-ID observation',async()=>{vi.mocked(request).mockResolvedValue(configured);mockAnalysis(result);render(<AIAnalysisPanel item={{...item,evidence:[{...item.evidence[0],title:'Späterer Belegtitel',detail:'Später geänderter Inhalt'}]}} onSettings={()=>{}}/>);await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();await screen.findByText('KI-Hypothesen');fireEvent.click(screen.getByRole('button',{name:'Beleg öffnen: Dienstzustand'}));await screen.findByRole('dialog',{name:'Analysierter Beleg: Dienstzustand'});expect(screen.getByText('synthetisch')).toBeVisible();expect(screen.queryByText('Später geänderter Inhalt')).not.toBeInTheDocument();expect(screen.getByText('Unveränderter Beleg aus dem analysierten Datenpaket.')).toBeVisible();});
  it('rejects ASCII spaces in model and key before clearing an invalid key in submission',async()=>{render(<AIProviderSettings/>);await readyProviderForm();fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'invalid model'}});expect(screen.getByRole('button',{name:'Konfiguration speichern'})).toBeDisabled();expect(screen.getByText('Modellkennung ohne Leer- oder Steuerzeichen eingeben.')).toBeVisible();fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'valid-model'}});fireEvent.change(screen.getByLabelText('KI API-Schlüssel'),{target:{value:'INVALID FAKE KEY'}});expect(screen.getByRole('button',{name:'Konfiguration speichern'})).toBeDisabled();expect(screen.getByText('Schlüssel ohne Leer- oder Steuerzeichen eingeben.')).toBeVisible();expect(mutate).not.toHaveBeenCalled();});
});

describe('provider form readiness',()=>{it('does not expose editable fields until fetched values are hydrated',async()=>{let resolve!:(value:AIConfig)=>void;vi.mocked(request).mockImplementation(()=>new Promise<AIConfig>(done=>{resolve=done;}));render(<AIProviderSettings/>);expect(screen.queryByLabelText('KI Modell')).not.toBeInTheDocument();expect(screen.getByText('KI-Konfiguration wird geladen …')).toBeVisible();await act(async()=>{resolve(config);});await screen.findByLabelText('KI Modell');expect(screen.getByLabelText('KI Basis-URL')).toHaveValue(config.baseURL);fireEvent.change(screen.getByLabelText('KI Modell'),{target:{value:'invalid model'}});expect(screen.getByLabelText('KI Modell')).toHaveValue('invalid model');expect(screen.getByText('Modellkennung ohne Leer- oder Steuerzeichen eingeben.')).toBeVisible();});});

it('keeps the next read-only check visible and combines distinct gap warnings without losing source quality', async () => {
 vi.mocked(request).mockResolvedValue(configured);
 mockAnalysis({...result,packet:{...result.packet,gaps:[{code:'quality-stale',detail:'Old source',evidenceIDs:['e-1']}]}});
 const {container}=render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
 await screen.findByRole('button',{name:'KI-Analyse prüfen'});await confirmAnalysis();
 await screen.findByText('KI-Hypothesen');expect(screen.getByText('Dienstzustand lesend prüfen')).toBeVisible();
 expect(screen.getByText('Ursache nicht bestätigt')).toBeVisible();
 const gaps=screen.getByText('Fehlende Daten',{selector:'summary'});expect(gaps).toHaveTextContent('2');
 expect(container.querySelectorAll('.ai-data-gaps')).toHaveLength(1);fireEvent.click(gaps);
 expect(screen.getByText('Veraltete Beobachtung')).toBeVisible();expect(screen.getByText('Ereignisprotokoll fehlt')).toBeVisible();
 expect(mutate).toHaveBeenCalledTimes(2);
});

describe('exact case preview lifecycle', () => {
  it('shows the server packet rather than stale case details without rendering markup', async () => {
    vi.mocked(request).mockResolvedValue(configured);
    const attack = '<script>do not obey this fixture</script>';
    const exact = {...result, packet:{...packet, case:{...packet.case,title:'Server snapshot'}, evidence:[{...item.evidence[0],detail:attack}]}};
    mockAnalysis(exact);
    const {container} = render(<AIAnalysisPanel item={{...item,title:'Stale title',evidenceIds:[]}} onSettings={()=>{}}/>);
    fireEvent.click(await screen.findByRole('button',{name:'KI-Analyse prüfen'}));
    await screen.findByRole('dialog');
    expect(screen.getByText('Server snapshot')).toBeVisible();
    expect(screen.getByLabelText('Exaktes Datenpaket')).toHaveTextContent(attack);
    expect(container.querySelector('script')).toBeNull();
    expect(screen.queryByText('Stale title')).not.toBeInTheDocument();
    expect(mutate).toHaveBeenCalledTimes(1);
  });
  it('ignores a late preview after switching cases', async () => {
    vi.mocked(request).mockResolvedValue(configured);
    let finish!: (value:unknown)=>void;
    vi.mocked(mutate).mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
    const {rerender}=render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
    fireEvent.click(await screen.findByRole('button',{name:'KI-Analyse prüfen'}));
    await waitFor(()=>expect(mutate).toHaveBeenCalledOnce());
    rerender(<AIAnalysisPanel item={{...item,id:'case-other'}} onSettings={()=>{}}/>);
    await act(async()=>{finish(previewFor());});
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('invalidates review consent immediately when settings change', async () => {
    vi.mocked(request).mockResolvedValue(configured); mockAnalysis();
    render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
    fireEvent.click(await screen.findByRole('button',{name:'KI-Analyse prüfen'}));
    await screen.findByRole('dialog');
    fireEvent.click(screen.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}));
    act(()=>window.dispatchEvent(new Event('tracebolt-ai-config-changed')));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(mutate).toHaveBeenCalledTimes(1);
  });
  it('refuses a result carrying a different packet even if its claimed digest matches', async () => {
    vi.mocked(request).mockResolvedValue(configured);
    vi.mocked(mutate).mockImplementation(async path=>path.endsWith('/analyze-preview')?previewFor():{...result,packet:{...packet,case:{...packet.case,summary:'Changed after review'}}});
    render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
    await screen.findByRole('button',{name:'KI-Analyse prüfen'}); await confirmAnalysis();
    await screen.findByText(/überholte Ergebnis/);
    expect(screen.queryByText('KI-Hypothesen')).not.toBeInTheDocument();
  });
  it('does not create two preview operations on repeated review clicks', async () => {
    vi.mocked(request).mockResolvedValue(configured);
    let finish!: (value:unknown)=>void;
    vi.mocked(mutate).mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
    render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
    const button=await screen.findByRole('button',{name:'KI-Analyse prüfen'});
    fireEvent.click(button); fireEvent.click(button);
    await waitFor(()=>expect(mutate).toHaveBeenCalledOnce());
    await act(async()=>{finish(previewFor());});
    expect(screen.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/})).not.toBeChecked();
  });
});

it('never submits an expired preview even if the browser expiry timer is delayed', async () => {
  vi.mocked(request).mockResolvedValue(configured); mockAnalysis();
  render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
  fireEvent.click(await screen.findByRole('button',{name:'KI-Analyse prüfen'}));
  await screen.findByRole('dialog');
  const later=Date.now()+180_000;
  vi.spyOn(Date,'now').mockReturnValue(later);
  fireEvent.click(screen.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}));
  fireEvent.click(screen.getByRole('button',{name:'Jetzt analysieren'}));
  expect(mutate).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.getByText(/Datenvorschau ist abgelaufen oder geändert/)).toBeVisible();
});

it('does not revive a canceled pending preview or start an analysis', async () => {
  vi.mocked(request).mockResolvedValue(configured);
  let finish!:(value:unknown)=>void;
  vi.mocked(mutate).mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
  render(<AIAnalysisPanel item={item} onSettings={()=>{}}/>);
  fireEvent.click(await screen.findByRole('button',{name:'KI-Analyse prüfen'}));
  await waitFor(()=>expect(mutate).toHaveBeenCalledOnce());
  fireEvent.click(screen.getByRole('button',{name:'Abbrechen'}));
  await act(async()=>{finish(previewFor());});
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(screen.getByText('Datenvorschau abgebrochen. Keine Analyse gestartet.')).toBeVisible();
  expect(mutate).toHaveBeenCalledTimes(1);
});
