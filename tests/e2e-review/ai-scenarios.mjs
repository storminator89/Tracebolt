/** Optional AI browser checks. Real manager + deterministic loopback fixture provider.
 * Never calls a real model or sends real telemetry. Enabled only by
 * TRACEBOLT_REVIEW_AI=1 for the coherent AI source checkpoint.
 */
import http from 'node:http';
export async function runAIReview({test,pageAt,loaded,shot,base,data,expect,restartManager}) {
 const item=data.cases.find(c=>c.deviceId==='demo-linux-01');
 const citedEvidence=item.evidence.find(e=>e.id===item.evidenceIds[0]);
 const durableCase=data.cases.find(c=>c.deviceId==='demo-win-01');
 const fixtureLabel='Testanbieter-keine-reale-Modellanalyse';
 const fixtureKey='TRACEBOLT_REVIEW_SYNTHETIC_KEY_NOT_A_CREDENTIAL';
 const statement='Testanbieter / keine reale Modellanalyse. Die Kapazität könnte knapp sein; die Ursache bleibt unbestätigt.';
 let mode='valid'; const requests=[]; const pending=[];
 const provider=http.createServer(async(req,res)=>{
  let raw=''; for await (const chunk of req) {raw+=chunk;if(raw.length>65536){res.writeHead(413).end();return;}}
  let body;try{body=JSON.parse(raw);}catch{res.writeHead(400).end();return;}
  requests.push({path:req.url,method:req.method,body});
  const findings={observedEvidenceIDs:[item.evidenceIds[0]],hypotheses:[{statement,evidenceIDs:[item.evidenceIds[0]]}],counterevidence:[],missingData:['Keine echte Modellinferenz: kontrollierte Testantwort.'],nextCheck:'storage'};
  const respond=()=>{if(res.destroyed)return;res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({id:'review-fixture-completion',model:fixtureLabel,choices:[{index:0,finish_reason:'stop',message:{role:'assistant',content:JSON.stringify(mode==='invalid'?{...findings,observedEvidenceIDs:['unknown-review-evidence']}:findings)}}]}));};
  if(mode==='hold')pending.push(respond);else respond();
 });
 await new Promise((resolve,reject)=>{provider.once('error',reject);provider.listen(0,'127.0.0.1',resolve);});
 const endpoint=`http://127.0.0.1:${provider.address().port}/v1`;
 async function getConfig(){const response=await fetch(`${base}/api/ai/config`);expect(response.status).toBe(200);return response.json();}
 async function mutate(path,body){const session=await (await fetch(`${base}/api/session`)).json();const response=await fetch(`${base}/api${path}`,{method:'POST',headers:{Origin:base,'Content-Type':'application/json','X-CSRF-Token':session.csrfToken},body:JSON.stringify(body)});expect(response.ok,`${path}: HTTP ${response.status}`).toBe(true);return response.json();}
 async function openReview(page){await page.getByRole('button',{name:'Belege prüfen & analysieren'}).click();await expect(page.getByRole('dialog',{name:'Fallbelege zur KI-Analyse senden'})).toBeVisible();}
 async function submitReview(page){await openReview(page);await page.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}).check();await page.getByRole('button',{name:'Jetzt analysieren'}).click();}
 try {
  await test('AI unconfigured: deterministic finding remains, no generated suggestions or provider calls',async()=>{
   const config=await getConfig();expect(config.configured).toBe(false);
   const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('heading',{name:'Noch kein Anbieter eingerichtet'})).toBeVisible();await expect(page.locator('.finding-summary')).toHaveText(item.summary);expect(requests).toHaveLength(0);
   await expect(page.getByText('Modellvorschläge',{exact:true})).toHaveCount(0);await page.getByRole('button',{name:'Einrichten',exact:true}).click();await expect(page.getByRole('textbox',{name:'KI Modell'})).toBeVisible();
  });
  await test('AI local settings save is memory-only, clears synthetic key, and makes zero provider calls',async()=>{
   const page=await pageAt('/settings');await loaded(page);await expect(page.getByRole('textbox',{name:'KI Modell'})).toBeVisible();await page.getByLabel('KI Basis-URL').fill(endpoint);await page.getByLabel('KI Modell').fill(fixtureLabel);await page.getByLabel('KI API-Schlüssel').fill(fixtureKey);await page.getByRole('button',{name:'Konfiguration speichern'}).click();
   await expect(page.getByRole('status')).toContainText('noch nicht kontaktiert');await expect(page.getByLabel('KI API-Schlüssel')).toHaveValue('');expect(requests).toHaveLength(0);
   const storage=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage}}));expect(storage).not.toContain(fixtureKey);const config=await getConfig();expect(config.keyConfigured).toBe(true);expect(JSON.stringify(config)).not.toContain(fixtureKey);await shot(page,'synthetic-ai-fixture-settings-desktop-light');
   await page.reload();await expect(page.getByLabel('KI API-Schlüssel')).toHaveValue('');await expect(page.getByText('Schlüssel gesetzt')).toBeVisible();
  });
  await test('AI consent dialog shows exact destination; cancel and Escape send no evidence',async()=>{
   const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();const before=requests.length;await openReview(page);await expect(page.getByRole('dialog')).toContainText(endpoint);await expect(page.getByRole('button',{name:'Jetzt analysieren'})).toBeDisabled();await page.getByRole('button',{name:'Abbrechen',exact:true}).click();await expect(page.getByRole('dialog')).toHaveCount(0);expect(requests).toHaveLength(before);
   await openReview(page);await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).toHaveCount(0);expect(requests).toHaveLength(before);
  });
  await test('AI completed fixture response is unconfirmed, cited, and excludes notes and unrelated telemetry',async()=>{
   const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();const before=requests.length;mode='valid';await submitReview(page);await expect(page.getByText('Ursache nicht bestätigt',{exact:true})).toBeVisible();await expect(page.getByText(statement,{exact:true})).toBeVisible();expect(requests).toHaveLength(before+1);
   const sent=requests.at(-1);expect(sent.method).toBe('POST');expect(sent.path).toBe('/v1/chat/completions');expect(sent.body.model).toBe(fixtureLabel);expect(sent.body.stream).toBe(false);expect(sent.body.store).toBe(false);expect(sent.body.messages).toHaveLength(2);
   const packet=JSON.parse(sent.body.messages[1].content);expect(packet.evidence.every(e=>e.synthetic===true)).toBe(true);const raw=sent.body.messages[1].content;for(const forbidden of ['notes','deviceName','192.0.2.22','Review: literal evidence','Delayed save review note', 'FRA-APP-02'])expect(raw).not.toContain(forbidden);
   await page.getByRole('button',{name:`Beleg öffnen: ${citedEvidence.title}`}).first().click();await expect(page.getByRole('dialog',{name:`Analysierter Beleg: ${citedEvidence.title}`})).toBeVisible();await expect(page.getByRole('dialog')).toContainText(citedEvidence.value);await page.getByRole('button',{name:'Schließen',exact:true}).click();await shot(page,'synthetic-ai-fixture-case-desktop-light');
   await page.getByRole('button',{name:'Dunkles Design aktivieren'}).click();await shot(page,'synthetic-ai-fixture-case-desktop-dark');await page.reload();await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();await expect(page.getByText(statement,{exact:true})).toHaveCount(0);
  });
  await test('AI invalid provider output never becomes a diagnosis; baseline stays visible',async()=>{
   mode='invalid';const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();await submitReview(page);await expect(page.getByText('Antwort nicht verwendbar',{exact:true})).toBeVisible();await expect(page.getByText('Modellvorschläge',{exact:true})).toHaveCount(0);await expect(page.locator('.finding-summary')).toHaveText(item.summary);mode='valid';
  });
  await test('AI repeated approval sends once; local cancellation never revives delayed result',async()=>{
   mode='hold';const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();const before=requests.length;await openReview(page);await page.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}).check();await page.getByRole('button',{name:'Jetzt analysieren'}).dblclick();await expect.poll(()=>requests.length).toBe(before+1);await expect(page.locator('.ai-progress')).toContainText('Begrenzte Fallbelege werden analysiert');
   await page.getByRole('button',{name:'Abbrechen',exact:true}).click();await expect(page.getByRole('alert')).toContainText('Bereits übertragene Daten');mode='valid';pending.splice(0).forEach(f=>f());await expect.poll(async()=>(await getConfig()).busy).toBe(false);await expect(page.getByText(statement,{exact:true})).toHaveCount(0);expect(requests).toHaveLength(before+1);
  });
  await test('AI mobile consent and completed fixture keep readable bounded layout',async()=>{
   mode='valid';const page=await pageAt(`/cases/${item.id}`,{width:390,height:844},{isMobile:true,hasTouch:true});await expect(page.getByRole('button',{name:'Belege prüfen & analysieren'})).toBeVisible();await openReview(page);await shot(page,'synthetic-ai-fixture-consent-mobile-light');await page.getByRole('checkbox',{name:/Ich habe Belege und Ziel geprüft/}).check();await page.getByRole('button',{name:'Jetzt analysieren'}).click();await expect(page.getByText('Ursache nicht bestätigt',{exact:true})).toBeVisible();expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);await shot(page,'synthetic-ai-fixture-case-mobile-light');
  });
  await test('AI manager restart clears provider and synthetic key without changing durable case notes',async()=>{
   expect((await getConfig()).configured).toBe(true);await restartManager();const config=await getConfig();expect(config.configured).toBe(false);expect(config.keyConfigured).toBe(false);const page=await pageAt(`/cases/${item.id}`);await expect(page.getByRole('heading',{name:'Noch kein Anbieter eingerichtet'})).toBeVisible();const persisted=await (await fetch(`${base}/api/cases/${durableCase.id}`)).json();expect(persisted.notes.some(n=>n.text.includes('Review: literal evidence'))).toBe(true);
  });
 } finally {mode='valid';pending.splice(0).forEach(f=>f());provider.closeAllConnections();await new Promise(resolve=>provider.close(resolve));}
}
