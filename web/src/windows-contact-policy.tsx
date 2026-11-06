import { useEffect, useId, useRef, useState } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutateRaw } from './api';
import { hasLogoutIntent, useOperator } from './auth';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { validContactGrace, validWindowsContactView, WINDOWS_CONTACT_VIEW_BYTES } from './windows-contact-types';
import type { WindowsContactView } from './windows-contact-types';

const copy = {
 en: { title: 'Report delay settings', label: 'Wait before confirming a new overdue report', current: 'Saved wait', default: 'default', rules: 'Reports are recent for 2 minutes. This setting only delays new overdue incidents; the manager then confirms continuously for 60 seconds. Recovery still needs recent reports for 60 seconds.', reset: 'Saving resets pending confirmation and recovery progress. Existing incidents stay open. A new fresh accepted report is needed before another incident can open. No notifications are enabled.', consent: 'I have reviewed this wait and the reset of confirmation progress for this device.', save: 'Save wait', saving: 'Saving…', saved: 'Wait saved.', uncertain: 'Save result is unconfirmed. Check the saved setting before making another change. The save will not be repeated automatically.', refresh: 'Check saved setting', newReview: 'Start a new review', superseded: 'The current setting has been checked. The earlier save remains unconfirmed. Start a new review to discard this local attempt and review a separate change.', awaiting: 'Waiting for a new fresh accepted report after the setting change.', readOnly: 'A shared administrator can change this setting.', unavailable: 'Refresh contact history to review this setting.', discard: 'Discard draft' },
 de: { title: 'Wartezeit für Meldungen', label: 'Wartezeit vor der Bestätigung einer neuen überfälligen Meldung', current: 'Gespeicherte Wartezeit', default: 'Standard', rules: 'Meldungen gelten 2 Minuten lang als aktuell. Diese Einstellung verzögert nur neue Überfälligkeitsvorfälle; danach bestätigt der Manager 60 Sekunden lang fortlaufend. Für die Erholung sind weiterhin 60 Sekunden lang aktuelle Meldungen nötig.', reset: 'Speichern setzt die laufende Bestätigung und den Erholungsfortschritt zurück. Bestehende Vorfälle bleiben offen. Vor einem weiteren Vorfall ist eine neue, aktuelle akzeptierte Meldung nötig. Benachrichtigungen werden nicht aktiviert.', consent: 'Ich habe diese Wartezeit und das Zurücksetzen des Bestätigungsfortschritts für dieses Gerät geprüft.', save: 'Wartezeit speichern', saving: 'Wird gespeichert …', saved: 'Wartezeit gespeichert.', uncertain: 'Speicherergebnis unbestätigt. Vor einer weiteren Änderung die gespeicherte Einstellung prüfen. Das Speichern wird nicht automatisch wiederholt.', refresh: 'Gespeicherte Einstellung prüfen', newReview: 'Neu prüfen', superseded: 'Die aktuelle Einstellung wurde geprüft. Das frühere Speicherergebnis bleibt unbestätigt. Mit einer neuen Prüfung wird dieser lokale Versuch verworfen und eine separate Änderung geprüft.', awaiting: 'Nach der Änderung wird auf eine neue, aktuelle akzeptierte Meldung gewartet.', readOnly: 'Ein gemeinsamer Administrator kann diese Einstellung ändern.', unavailable: 'Den Meldungsverlauf aktualisieren, um diese Einstellung zu prüfen.', discard: 'Entwurf verwerfen' },
};
type Props = { device: Device; view: WindowsContactView | null; elapsedMS: number; sessionKey: string | null; loading: boolean; refresh: () => void };
type Attempt = { requestId: string; expectedRevision: number; graceSeconds: number };
export function WindowsContactPolicySettings(props: Props) {
 const [locale] = useLocale(), c = copy[locale], op = useOperator(), id = useId();
 const { view, loading, refresh } = props;
 const [choice, setChoice] = useState(view?.policy?.graceSeconds ?? 120), [dirty, setDirty] = useState(false), [review, setReview] = useState<string | null>(null), [busy, setBusy] = useState(false), [notice, setNotice] = useState<'saved' | 'uncertain' | null>(null);
 const [readbackReady, setReadbackReady] = useState(false);
 const excludedViews = useRef(new WeakSet<object>()), readbackRequested = useRef(false);
 const latest = useRef({ props, op, mono: performance.now(), wall: Date.now() }); latest.current = { props, op, mono: performance.now(), wall: Date.now() };
 const epoch = useRef(getProtectedRequestEpoch()), alive = useRef(true), suspended = useRef(false), serial = useRef(0), pending = useRef<AbortController | null>(null), attempt = useRef<Attempt | null>(null), revision = useRef<number | null>(null);
 const reviewKey = `${view?.policy?.revision ?? 0}:${choice}`;
 const admin = op?.mode === 'lan' && op.authenticated && op.loginMode === 'shared';
 const permitted = () => {
  const l = latest.current, p = l.props, v = p.view, mono = performance.now() - l.mono, wall = Date.now() - l.wall, age = p.elapsedMS + mono;
  return alive.current && !suspended.current && document.visibilityState !== 'hidden' && !hasLogoutIntent() && epoch.current === getProtectedRequestEpoch() && l.op?.mode === 'lan' && l.op.authenticated && l.op.loginMode === 'shared' && l.op.expiresAt === p.sessionKey && !!v && !p.loading && Number.isFinite(age) && mono >= 0 && Math.abs(mono - wall) <= 1500 && !!p.sessionKey && inventoryAge(p.sessionKey, v.serverNow) > age && inventoryAge(v.certificateExpiresAt, v.serverNow) > age && !!p.device.agentCertificate?.expiresAt && inventoryAge(p.device.agentCertificate.expiresAt, v.serverNow) > age && inventoryAge(v.serverNow, p.device.agentCertificate.checkedAt) + age <= 120000;
 };
 useEffect(() => {
  alive.current = true;
  const invalidate = () => { suspended.current = true; readbackRequested.current = false; setReadbackReady(false); serial.current++; pending.current?.abort(); if (latest.current.props.view) excludedViews.current.add(latest.current.props.view); pending.current = null; setBusy(false); setReview(null); if (attempt.current) setNotice('uncertain'); };
  const resume = () => { suspended.current = false; setReview(null); };
  const visibility = () => document.visibilityState === 'hidden' ? invalidate() : resume();
  window.addEventListener('blur', invalidate); window.addEventListener('pagehide', invalidate); window.addEventListener('hashchange', invalidate); window.addEventListener('popstate', invalidate); window.addEventListener(AUTH_REQUIRED_EVENT, invalidate); window.addEventListener('focus', resume); document.addEventListener('visibilitychange', visibility);
  const timer = window.setInterval(() => { if (!permitted() && !latest.current.props.loading) setReview(null); }, 500);
  return () => { alive.current = false; serial.current++; pending.current?.abort(); window.clearInterval(timer); window.removeEventListener('blur', invalidate); window.removeEventListener('pagehide', invalidate); window.removeEventListener('hashchange', invalidate); window.removeEventListener('popstate', invalidate); window.removeEventListener(AUTH_REQUIRED_EVENT, invalidate); window.removeEventListener('focus', resume); document.removeEventListener('visibilitychange', visibility); };
 }, []);
 useEffect(() => { setReview(null); }, [op?.authenticated, op?.loginMode, op?.expiresAt]);
 useEffect(() => {
  if (!view) { setReadbackReady(false); if (!loading) setReview(null); return; }
  if (pending.current) excludedViews.current.add(view);
  else if (attempt.current && readbackRequested.current && !excludedViews.current.has(view) && permitted()) setReadbackReady(true);
  const next = view.policy?.revision ?? 0;
  if (revision.current !== next) { revision.current = next; if (!attempt.current) setNotice(null); setReview(null); setChoice(view.policy?.graceSeconds ?? 120); setDirty(false); }
  const a = attempt.current;
  if (a && !pending.current && permitted() && view.policy?.lastRequestId === a.requestId && view.policy.revision === a.expectedRevision + 1 && view.policy.graceSeconds === a.graceSeconds) { attempt.current = null; setNotice('saved'); setDirty(false); setChoice(a.graceSeconds); }
 }, [view, loading]);
 const checkSaved = () => {
  if (pending.current) return;
  if (latest.current.props.view) excludedViews.current.add(latest.current.props.view);
  readbackRequested.current = true; setReadbackReady(false); refresh();
 };
 const canStartReview = () => !!attempt.current && !pending.current && permitted() && readbackReady;
 const startReview = () => {
  if (!canStartReview()) return;
  attempt.current = null; setReadbackReady(false); setReview(null); setNotice(null); setChoice(latest.current.props.view?.policy?.graceSeconds ?? 120); setDirty(false);
 };
 const save = async () => {
  const v = latest.current.props.view;
  if (!v || !permitted() || pending.current || attempt.current || review !== `${v.policy?.revision ?? 0}:${choice}` || !dirty || !validContactGrace(choice)) return;
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const requestId = Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); if (/^0+$/.test(requestId)) return;
  const a = { requestId, expectedRevision: v.policy?.revision ?? 0, graceSeconds: choice }, controller = new AbortController(), version = ++serial.current, mono = performance.now(), wall = Date.now();
  readbackRequested.current = false; excludedViews.current = new WeakSet([v]); setReadbackReady(false); pending.current = controller; attempt.current = a; setBusy(true); setNotice(null);
  const active = () => alive.current && version === serial.current && !controller.signal.aborted && permitted() && performance.now() - mono < 10000 && Math.abs((Date.now() - wall) - (performance.now() - mono)) <= 1500;
  const timer = window.setTimeout(() => { if (version !== serial.current) return; controller.abort(); if (latest.current.props.view) excludedViews.current.add(latest.current.props.view); pending.current = null; serial.current++; setBusy(false); setReview(null); setNotice('uncertain'); }, 10000);
  try {
   const result: unknown = await mutateRaw(`/devices/${encodeURIComponent(v.deviceId)}/windows-contact/policy`, JSON.stringify({ ...a, acknowledged: true }), {}, controller.signal, WINDOWS_CONTACT_VIEW_BYTES, () => active() && latest.current.props.view === v);
   if (!active()) return;
   if (!validWindowsContactView(result, v.deviceId) || inventoryAge(result.serverNow, v.serverNow) < 0 || result.policy?.lastRequestId !== a.requestId || result.policy.revision !== a.expectedRevision + 1 || result.policy.graceSeconds !== a.graceSeconds) throw new Error('unconfirmed');
   // Reconcile through the existing clock- and authority-checked GET, not POST data.
   setNotice('uncertain');
  } catch { if (alive.current && version === serial.current) setNotice('uncertain'); }
  finally { window.clearTimeout(timer); if (alive.current && version === serial.current) { if (latest.current.props.view) excludedViews.current.add(latest.current.props.view); pending.current = null; setBusy(false); setReview(null); setNotice('uncertain'); checkSaved(); } }
 };
 return <details className="windows-contact-policy" hidden={!view}><summary>{c.title}</summary><p>{c.rules}</p><p>{c.reset}</p>{view && <p>{c.current}: <strong>{(view.policy?.graceSeconds ?? 120) / 60} min</strong>{!view.policy && ` (${c.default})`}</p>}{view?.policy?.awaitingFreshReport && <p role="status">{c.awaiting}</p>}{notice && <p role="status">{c[notice]}</p>}{attempt.current && <button type="button" className="text-button" disabled={loading || busy} onClick={checkSaved}>{c.refresh}</button>}
  {canStartReview() && <div><p>{c.superseded}</p><button type="button" className="text-button" onClick={startReview}>{c.newReview}</button></div>}
  {admin ? <fieldset disabled={!view || loading || busy || !!attempt.current}><label htmlFor={id}>{c.label}</label><select id={id} value={choice} onChange={event => { setChoice(Number(event.target.value)); setDirty(true); setReview(null); setNotice(null); }}>{[120, 300, 900, 3600].map(seconds => <option key={seconds} value={seconds}>{seconds / 60} min{seconds === 120 ? ` (${c.default})` : ''}</option>)}</select><label className="windows-contact-policy-consent"><input type="checkbox" checked={review === reviewKey} onChange={event => setReview(event.target.checked && permitted() ? reviewKey : null)}/>{c.consent}</label><button type="button" className="button small" disabled={!dirty || review !== reviewKey || !permitted()} onClick={() => void save()}>{busy ? c.saving : c.save}</button>{dirty && <button type="button" className="text-button" onClick={() => { setChoice(view?.policy?.graceSeconds ?? 120); setDirty(false); setReview(null); }}>{c.discard}</button>}</fieldset> : <p>{c.readOnly}</p>}
 </details>;
}
