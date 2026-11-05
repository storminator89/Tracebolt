import { useEffect, useId, useState } from 'react';
import { useLocale } from './i18n';
import { useMountWatch } from './linux-mount-watch-resource';
import type { MountCommand } from './linux-mount-watch-types';
export function LinuxMountWatch({ deviceId, sessionKey }: { deviceId: string; sessionKey: string | null }) {
 const [locale] = useLocale(), t = (en: string, de: string) => locale === 'de' ? de : en, uid = useId();
 const [open, setOpen] = useState(false), [selected, setSelected] = useState(''), [threshold, setThreshold] = useState(90), [recovery, setRecovery] = useState(80), [consent, setConsent] = useState(false);
 const [editingKey, setEditingKey] = useState<string | null>(null);
 const r = useMountWatch(deviceId, sessionKey, open), v = r.view;
 const savedChoice = v?.policy.target && v.options.find(o => o.mountPoint === v.policy.target!.mountPoint && o.filesystem === v.policy.target!.filesystem && o.filesystemGroup === v.policy.target!.filesystemGroup);
 const formKey = v ? JSON.stringify([deviceId, sessionKey, v.sourceToken, v.revision, v.policy, savedChoice ?? null]) : null;
 useEffect(() => { setOpen(false); setSelected(''); setThreshold(90); setRecovery(80); setConsent(false); setEditingKey(null); }, [deviceId, sessionKey]);
 useEffect(() => {
  if (!v || formKey === null || editingKey === formKey) return;
  setSelected(savedChoice ? JSON.stringify(savedChoice) : ''); setThreshold(v.policy.enabled ? v.policy.threshold : 90); setRecovery(v.policy.enabled ? v.policy.recovery : 80); setConsent(false); setEditingKey(formKey);
 }, [v, formKey, editingKey, savedChoice]);
 const chosen = v?.options.find(o => JSON.stringify(o) === selected);
 useEffect(() => { if (v && selected && !chosen) setConsent(false); }, [v, selected, chosen]);
 const changed = Boolean(chosen && (!v?.policy.enabled || chosen.mountPoint !== v.policy.target?.mountPoint || chosen.filesystem !== v.policy.target?.filesystem || chosen.filesystemGroup !== v.policy.target?.filesystemGroup || threshold !== v.policy.threshold || recovery !== v.policy.recovery));
 const blocked = r.pending || Boolean(r.attempt) || !v?.canManage || editingKey !== formKey;
 const canSave = !blocked && consent && changed && Number.isInteger(threshold) && threshold >= 50 && threshold <= 99 && Number.isInteger(recovery) && recovery >= 0 && recovery < threshold;
 const send = (operation: MountCommand['operation'], incidentId = '') => {
  if (!v || blocked) return; const target = operation === 'enable' ? chosen : null;
  if (operation === 'enable' && !canSave) return;
  const c: MountCommand = { requestId: `mountrequest_${[...crypto.getRandomValues(new Uint8Array(16))].map(x => x.toString(16).padStart(2, '0')).join('')}`, expectedRevision: v.revision, sourceToken: v.sourceToken, operation, target: target ?? null, threshold: operation === 'enable' ? threshold : 0, recovery: operation === 'enable' ? recovery : 0, retentionAcknowledged: operation === 'enable', incidentId };
  void r.change(c).then(ok => { if (ok) setConsent(false); });
 };
 return <section className="health-panel" aria-label={t('Selected mount capacity', 'Kapazität eines gewählten Mounts')}>
  <button className="button" aria-expanded={open} onClick={() => { setOpen(!open); setConsent(false); }}>{t('Selected mount capacity', 'Kapazität eines gewählten Mounts')}</button>
  {open && <div>
   <p>{t('Watch one non-root local mounted filesystem in the agent’s namespace. Two fresh, advancing generations confirm a warning or recovery. This does not measure physical disk health.', 'Ein lokales Dateisystem außerhalb von / im Namespace des Agenten überwachen. Zwei frische, fortschreitende Generationen bestätigen Warnung oder Erholung. Dies bewertet keinen physischen Datenträgerzustand.')}</p>
   <p>{t('Local incidents only. No notifications, AI, repair or host changes. Existing Linux Health maintenance does not pause this separate watch.', 'Nur lokale Vorfälle. Keine Benachrichtigungen, KI, Reparatur oder Geräteänderungen. Bestehende Linux-Health-Wartung pausiert diese separate Überwachung nicht.')}</p>
   <button className="button" disabled={r.pending} onClick={r.refresh}>{t('Refresh mount watch', 'Mount-Überwachung aktualisieren')}</button>
   {r.pending && <p role="status">{t('Reading or saving mount watch…', 'Mount-Überwachung wird gelesen oder gespeichert …')}</p>}
   {r.error && <p role="alert">{r.error === 'uncertain' ? t('Write outcome is uncertain. Refresh saved status; do not repeat the write.', 'Das Speicherergebnis ist unklar. Gespeicherten Status aktualisieren; nicht erneut senden.') : r.error === 'identity_changed' ? t('The enrolled device identity changed. The previous mount watch does not apply to this identity; changes are blocked.', 'Die registrierte Geräteidentität hat sich geändert. Die bisherige Mount-Überwachung gilt nicht für diese Identität; Änderungen sind gesperrt.') : r.error === 'clock_uncertain' ? t('Manager time is earlier than stored watch history. Evidence is unknown and changes are blocked until time catches up. Existing incidents are not resolved.', 'Die Managerzeit liegt vor dem gespeicherten Überwachungsverlauf. Belege sind unbekannt und Änderungen gesperrt, bis die Zeit aufgeholt hat. Bestehende Vorfälle sind nicht gelöst.') : t('Mount watch evidence is unavailable or expired. Refresh to check again.', 'Belege der Mount-Überwachung sind nicht verfügbar oder abgelaufen. Zum Prüfen aktualisieren.')}</p>}
   {r.attempt && <p role="status">{t('An earlier change is unconfirmed. Further writes are blocked until status resolves it.', 'Eine frühere Änderung ist unbestätigt. Weitere Änderungen sind bis zur Statusklärung gesperrt.')}</p>}
   {r.supersededAttempt && <p role="status">{t('A newer saved revision prevents replay. The outcome of an earlier unconfirmed write remains unknown.', 'Eine neuere gespeicherte Version verhindert Wiederholung. Das Ergebnis einer früheren unbestätigten Änderung bleibt unbekannt.')}</p>}
   {v && <>
    <p>{v.policy.enabled ? `${t('Watching', 'Überwacht')}: ${v.policy.target!.mountPoint} · ${v.policy.threshold}% / ${v.policy.recovery}%` : t('No mount watch is enabled.', 'Keine Mount-Überwachung aktiviert.')}</p>
    <p>{t('Current evidence', 'Aktueller Beleg')}: {({ unknown: t('Unknown', 'Unbekannt'), clear: t('Below warning threshold', 'Unter Warnschwelle'), pending: t('Warning awaiting confirmation', 'Warnung wartet auf Bestätigung'), open: t('Warning', 'Warnung'), recovering: t('Recovery awaiting confirmation', 'Erholung wartet auf Bestätigung') })[v.check.condition]}{v.check.usedPercent !== null && ` · ${v.check.usedPercent.toFixed(1)}%`}</p>
    {v.check.observedAt && <p>{t('Original observation', 'Ursprüngliche Beobachtung')}: {v.check.observedAt}</p>}
    {v.sourceStatus === 'identity_changed' ? <p>{t('The enrolled device identity changed. The previous mount watch does not apply to this identity; changes are blocked.', 'Die registrierte Geräteidentität hat sich geändert. Die bisherige Mount-Überwachung gilt nicht für diese Identität; Änderungen sind gesperrt.')}</p> : v.sourceStatus === 'clock_uncertain' ? <p>{t('Manager time is earlier than stored watch history. Evidence is unknown and changes are blocked until time catches up. Existing incidents are not resolved.', 'Die Managerzeit liegt vor dem gespeicherten Überwachungsverlauf. Belege sind unbekannt und Änderungen gesperrt, bis die Zeit aufgeholt hat. Bestehende Vorfälle sind nicht gelöst.')}</p> : v.sourceStatus !== 'none' && <p>{t('Fresh complete mount evidence is unavailable. Existing open incidents remain unresolved.', 'Frische vollständige Mount-Belege fehlen. Bestehende offene Vorfälle bleiben ungelöst.')}</p>}
    {!v.canManage && v.sourceStatus !== 'identity_changed' && v.sourceStatus !== 'clock_uncertain' && <p>{t('Read-only. Shared administrator access is required for changes.', 'Nur lesend. Änderungen erfordern den gemeinsamen Administratorzugang.')}</p>}
    {v.canManage && <fieldset disabled={blocked}>
     <legend>{t('Configure one mount watch', 'Eine Mount-Überwachung einrichten')}</legend>
     <label htmlFor={`${uid}-target`}>{t('Mount location', 'Mount-Pfad')}</label><select id={`${uid}-target`} value={selected} onChange={e => { setSelected(e.target.value); setConsent(false); }}><option value="">{t('Choose a measured local mount', 'Gemessenen lokalen Mount wählen')}</option>{v.options.map(o => <option key={o.mountPoint} value={JSON.stringify(o)}>{o.mountPoint} · {o.filesystem} · {o.filesystemGroup}</option>)}</select>
     {v.moreOptions && <p>{t('This bounded list shows up to 64 eligible mount locations. More locations exist.', 'Diese begrenzte Liste zeigt bis zu 64 geeignete Mount-Pfade. Weitere Pfade existieren.')}</p>}
     <label htmlFor={`${uid}-high`}>{t('Warn at usage (%)', 'Warnen ab Belegung (%)')}</label><input id={`${uid}-high`} type="number" min={50} max={99} value={threshold} onChange={e => { setThreshold(Number(e.target.value)); setConsent(false); }}/>
     <label htmlFor={`${uid}-low`}>{t('Recover at usage (%)', 'Erholung bis Belegung (%)')}</label><input id={`${uid}-low`} type="number" min={0} max={98} value={recovery} onChange={e => { setRecovery(Number(e.target.value)); setConsent(false); }}/>
     {v.policy.enabled && <p>{t('Current setting', 'Bisherige Einstellung')}: {v.policy.target!.mountPoint} · {v.policy.target!.filesystem} · {v.policy.target!.filesystemGroup} · {t('warn', 'Warnung')} {v.policy.threshold}% / {t('recover', 'Erholung')} {v.policy.recovery}%</p>}
     {chosen && <p>{t('Proposed setting', 'Vorgeschlagene Einstellung')}: {chosen.mountPoint} · {chosen.filesystem} · {chosen.filesystemGroup} · {t('warn', 'Warnung')} {threshold}% / {t('recover', 'Erholung')} {recovery}%</p>}
     {v.policy.enabled && <p>{t('Saving a change starts a new monitoring period. Two new observations must confirm a warning or recovery. Existing open incidents close as monitoring stopped, not recovered.', 'Eine Änderung startet einen neuen Überwachungszeitraum. Zwei neue Beobachtungen müssen Warnung oder Erholung bestätigen. Bestehende offene Vorfälle werden als Überwachung gestoppt geschlossen, nicht als erholt.')}</p>}
     {v.policy.enabled && !changed && <p>{t('Change a setting to save a new watch. Unchanged settings do not restart monitoring.', 'Zum Speichern eine Einstellung ändern. Unveränderte Einstellungen starten die Überwachung nicht neu.')}</p>}
     <label><input type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)}/>{t('Enable this selected watch and retain its mount path and local incidents with a 30-day closed-history window and up to 100 recent incidents. Unresolved incidents may remain longer.', 'Diese gewählte Überwachung aktivieren und Mount-Pfad sowie lokale Vorfälle mit einem 30-Tage-Fenster für abgeschlossene und bis zu 100 aktuelle Vorfälle speichern. Ungelöste Vorfälle können länger bestehen bleiben.')}</label>
     <button className="button" disabled={!canSave} onClick={() => send('enable')}>{t('Save selected mount watch', 'Gewählte Mount-Überwachung speichern')}</button>
     {v.policy.enabled && <button className="button" onClick={() => send('disable')}>{t('Stop this watch', 'Diese Überwachung stoppen')}</button>}
    </fieldset>}
    <h4>{t('Local mount incidents', 'Lokale Mount-Vorfälle')}</h4>
    {v.incidents.length === 0 && <p>{t('No retained incidents. This does not prove current capacity is healthy.', 'Keine gespeicherten Vorfälle. Dies belegt keine aktuell unauffällige Kapazität.')}</p>}
    <ul>{v.incidents.map(i => <li key={i.id}><strong>{i.target.mountPoint}</strong> · {({ open: t('Open', 'Offen'), recovered: t('Recovered', 'Erholt'), monitoring_stopped: t('Monitoring stopped, not recovered', 'Überwachung gestoppt, nicht erholt') })[i.state]}<p>{t('Opened', 'Eröffnet')}: {i.openedAt} · {t('Latest evidence', 'Letzter Beleg')}: {i.lastObservedAt}</p>{i.acknowledgedAt ? <p>{t('Seen, not resolved', 'Gesehen, nicht gelöst')}: {i.acknowledgedAt}</p> : v.canManage && <button className="button" disabled={blocked} onClick={() => send('acknowledge', i.id)}>{t('Mark seen', 'Als gesehen markieren')}</button>}</li>)}</ul>
    {v.earlierOmitted > 0 && <p>{v.earlierOmitted} {t('earlier incidents omitted by retention limits.', 'frühere Vorfälle wegen Speichergrenzen ausgelassen.')}</p>}
   </>}
  </div>}
 </section>;
}
