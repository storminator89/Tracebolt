import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutate, request } from './api';
import { validFleetGroupName } from './fleet-groups-types';
import { useLocale } from './i18n';
import { CustomerOrganizationNotice } from './customer-organization-notice';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsCapacityTimestamp } from './windows-capacity-types';
import { inventoryAge } from './complete-packages-types';
import './customer-devices.css';

interface Customer { id: string; name: string; revision: number }
interface Device { deviceId: string; identity: string; customerId: string }
interface View { schemaVersion: 'tracebolt.customer-windows-assignments.v1'; serverNow: string; validUntil: string; customers: Customer[]; devices: Device[]; unavailableAssignments: number }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const id = (v: unknown, prefix: string) => typeof v === 'string' && new RegExp(`^${prefix}[0-9a-f]{32}$`).test(v) && v !== prefix + '0'.repeat(32);
const digest = (v: unknown) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) && v !== '0'.repeat(64);
// An absent row after an uncertain POST does not prove that a delayed request
// cannot still commit. Retain a conservative fence for this page session.
const uncertainSessions = new Map<string, { deviceId:string; identity:string }>();
export function validCustomerDeviceView(v: unknown): v is View {
    if (!exact(v, ['schemaVersion','serverNow','validUntil','customers','devices','unavailableAssignments']) || v.schemaVersion !== 'tracebolt.customer-windows-assignments.v1' || !validWindowsCapacityTimestamp(v.serverNow) || !validWindowsCapacityTimestamp(v.validUntil) || inventoryAge(v.validUntil, v.serverNow) <= 0 || inventoryAge(v.validUntil, v.serverNow) > 30000 || !Array.isArray(v.customers) || v.customers.length > 25 || !Array.isArray(v.devices) || v.devices.length > 25 || !Number.isSafeInteger(v.unavailableAssignments) || Number(v.unavailableAssignments) < 0 || Number(v.unavailableAssignments) > 100) return false;
    if (!v.customers.every(c => exact(c, ['id','name','revision']) && id(c.id, 'customer_') && validFleetGroupName(c.name) && Number.isSafeInteger(c.revision) && Number(c.revision) > 0) || new Set(v.customers.map(c => c.id)).size !== v.customers.length) return false;
    const customers = new Set(v.customers.map(c => c.id));
    return v.devices.every(d => exact(d, ['deviceId','identity','customerId']) && id(d.deviceId, 'agent_') && digest(d.identity) && typeof d.customerId === 'string' && (d.customerId === '' || customers.has(d.customerId))) && new Set(v.devices.map(d => d.deviceId)).size === v.devices.length && new Set(v.devices.map(d => d.identity)).size === v.devices.length;
}

const copy = {
    en: { title:'Assign Windows devices to customers', scope:'Organizational assignment of already activated Windows identities. This grants no enrollment, collection or customer access isolation. The assignment cannot be changed here.', refresh:'Refresh assignments', loading:'Checking customer and device identities…', error:'Assignments cannot be confirmed. Refresh before continuing.', expired:'This session or view is no longer available. Refresh after access is confirmed.', uncertain:'The assignment could not be confirmed and may have been saved. Refresh and review; it will not be retried automatically.', fenced:'A previous assignment is unconfirmed. New assignments are blocked in this page session until its identity is observed assigned. An empty result does not prove the earlier request failed.', noneCustomers:'Create a customer first.', noneDevices:'No currently admitted Windows identities.', unavailable:'Previously recorded assignments unavailable:', unassigned:'Not assigned', recorded:'Recorded assignments', device:'Windows identity', customer:'Customer', chooseDevice:'Select a Windows identity', chooseCustomer:'Select a customer', choose:'Choose…', identity:'Identity binding', acknowledge:'I reviewed this exact customer and Windows identity for this permanent organizational assignment.', assign:'Assign reviewed identity', saving:'Saving…', asOf:'Manager snapshot', pending:'This does not approve a pending device.' },
    de: { title:'Windows-Geräte Kunden zuordnen', scope:'Organisatorische Zuordnung bereits aktivierter Windows-Identitäten. Sie erteilt keine Enrollment- oder Erfassungsfreigabe und trennt keine Kundenzugriffe. Die Zuordnung kann hier nicht geändert werden.', refresh:'Zuordnungen aktualisieren', loading:'Kunden und Geräteidentitäten werden geprüft …', error:'Zuordnungen können nicht bestätigt werden. Vor dem Fortfahren aktualisieren.', expired:'Sitzung oder Ansicht ist nicht mehr verfügbar. Nach bestätigtem Zugriff aktualisieren.', uncertain:'Die Zuordnung konnte nicht bestätigt werden und wurde möglicherweise gespeichert. Aktualisieren und prüfen; sie wird nicht automatisch wiederholt.', fenced:'Eine frühere Zuordnung ist unbestätigt. Weitere Zuordnungen sind in dieser Seitensitzung gesperrt, bis ihre Identität als zugeordnet erscheint. Ein leeres Ergebnis belegt keinen Fehlschlag der früheren Anfrage.', noneCustomers:'Zuerst einen Kunden anlegen.', noneDevices:'Keine aktuell zugelassenen Windows-Identitäten.', unavailable:'Zuvor gespeicherte Zuordnungen nicht verfügbar:', unassigned:'Nicht zugeordnet', recorded:'Gespeicherte Zuordnungen', device:'Windows-Identität', customer:'Kunde', chooseDevice:'Windows-Identität auswählen', chooseCustomer:'Kunden auswählen', choose:'Bitte wählen …', identity:'Identitätsbindung', acknowledge:'Ich habe diesen Kunden und die vollständige Windows-Identität für diese dauerhafte organisatorische Zuordnung geprüft.', assign:'Geprüfte Identität zuordnen', saving:'Wird gespeichert …', asOf:'Manager-Abfrage', pending:'Eine ausstehende Gerätefreigabe wird dadurch nicht erteilt.' },
} as const;

/** The backend revalidates current identity, customer revision and session at commit. */
export function CustomerDevices({ sessionExpiresAt }: { sessionExpiresAt: string }) {
    const [locale] = useLocale(), c = copy[locale];
    const [view, setView] = useState<View | null>(null);
    const [state, setState] = useState<'loading' | 'ready' | 'error' | 'expired' | 'uncertain'>('loading');
    const [deviceId, setDeviceId] = useState(''), [customerId, setCustomerId] = useState(''), [acknowledged, setAcknowledged] = useState(false), [busy, setBusy] = useState(false), [fenced, setFenced] = useState(() => uncertainSessions.has(sessionExpiresAt));
    const active = useRef<AbortController | null>(null), generation = useRef(0), writing = useRef(false), writeTarget = useRef<{deviceId:string;identity:string} | null>(null);
    const deadline = Date.parse(sessionExpiresAt);
    const clockKey = `customer-devices:${sessionExpiresAt}`;
    const clock = useRef<{epoch:number;requestAge:number;serverNow:string;validUntil:string} | null>(null);
    const live = useCallback(() => Number.isFinite(deadline) && !document.hidden, [deadline]);
    const fresh = useCallback(() => {
        const v = clock.current;
        if (!live() || !v || v.epoch !== getProtectedRequestEpoch()) return false;
        const allowed = Math.min(inventoryAge(v.validUntil, v.serverNow), inventoryAge(new Date(deadline).toISOString(), v.serverNow));
        return Number.isFinite(allowed) && allowed > 0 && windowsHealthElapsed(clockKey, v.epoch, v.serverNow, v.requestAge) < allowed;
    }, [clockKey, deadline, live]);
    const resetSelection = () => { setDeviceId(''); setCustomerId(''); setAcknowledged(false); };
    const invalidate = useCallback(() => {
        const uncertain = writing.current;
        if (uncertain && writeTarget.current) { uncertainSessions.set(sessionExpiresAt, writeTarget.current); setFenced(true); }
        generation.current++; active.current?.abort(); active.current = null; writing.current = false; clock.current = null;
        setView(null); setDeviceId(''); setCustomerId(''); setAcknowledged(false); setBusy(false); setState(uncertain ? 'uncertain' : 'expired');
    }, [sessionExpiresAt]);
    const refresh = useCallback(async () => {
        if (!live() || writing.current) { if (!live()) invalidate(); return; }
        active.current?.abort(); const controller = new AbortController(), run = ++generation.current, epoch = getProtectedRequestEpoch(), startMono = performance.now(), startWall = Date.now(); active.current = controller; clock.current = null;
        setView(null); setDeviceId(''); setCustomerId(''); setAcknowledged(false); setState('loading');
        try {
            const result = await request<unknown>('/customer-windows-assignments', { signal: controller.signal });
            if (controller.signal.aborted || run !== generation.current || epoch !== getProtectedRequestEpoch() || !live()) return;
            if (!validCustomerDeviceView(result)) throw new Error('invalid response');
            const age = performance.now() - startMono, wallAge = Date.now() - startWall;
            if (!Number.isFinite(age) || age < 0 || !Number.isFinite(wallAge) || Math.abs(age-wallAge) > 1500 || !acceptWindowsHealthClock(clockKey, epoch, result.serverNow, age)) throw new Error('invalid clock');
            clock.current = {epoch, requestAge:age, serverNow:result.serverNow, validUntil:result.validUntil};
            if (!fresh()) { clock.current = null; throw new Error('expired snapshot'); }
            const pending = uncertainSessions.get(sessionExpiresAt);
            // A durable create-only assignment to any customer makes a later
            // conflicting request unable to change this exact original identity.
            if (pending && result.devices.some(d => d.deviceId === pending.deviceId && d.identity === pending.identity && d.customerId !== '')) { uncertainSessions.delete(sessionExpiresAt); setFenced(false); }
            setView(result); setState('ready');
        } catch {
            if (!controller.signal.aborted && run === generation.current && epoch === getProtectedRequestEpoch() && live()) setState('error');
        } finally { if (active.current === controller) active.current = null; }
    }, [clockKey, fresh, invalidate, live, sessionExpiresAt]);
    useEffect(() => {
        void refresh();
        const visibility = () => { if (document.hidden) invalidate(); };
        document.addEventListener('visibilitychange', visibility); window.addEventListener('pagehide', invalidate); window.addEventListener('hashchange', invalidate); window.addEventListener(AUTH_REQUIRED_EVENT, invalidate);
        const timer = window.setInterval(() => { if (clock.current && !fresh()) invalidate(); }, 100);
        return () => { if (writing.current && writeTarget.current) uncertainSessions.set(sessionExpiresAt, writeTarget.current); generation.current++; active.current?.abort(); active.current = null; clock.current = null; window.clearInterval(timer); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('pagehide', invalidate); window.removeEventListener('hashchange', invalidate); window.removeEventListener(AUTH_REQUIRED_EVENT, invalidate); };
    }, [fresh, invalidate, refresh, sessionExpiresAt]);
    const device = view?.devices.find(d => d.deviceId === deviceId && d.customerId === ''), customer = view?.customers.find(c => c.id === customerId);
    const save = async (event: FormEvent) => {
        event.preventDefault();
        if (writing.current || uncertainSessions.has(sessionExpiresAt) || state !== 'ready' || !view || !device || !customer || !acknowledged || !fresh()) return;
        writing.current = true; setBusy(true);
        const controller = new AbortController(), run = ++generation.current, epoch = getProtectedRequestEpoch(), selectedDevice = device, selectedCustomer = customer, startMono = performance.now(), startWall = Date.now(); active.current = controller; writeTarget.current = {deviceId:device.deviceId, identity:device.identity};
        try {
            const result = await mutate<unknown>('/customer-windows-assignments', { customerId:selectedCustomer.id, customerRevision:selectedCustomer.revision, deviceId:selectedDevice.deviceId, identity:selectedDevice.identity, acknowledged:true }, controller.signal);
            if (controller.signal.aborted || run !== generation.current || epoch !== getProtectedRequestEpoch() || !fresh()) {
                if (writeTarget.current) uncertainSessions.set(sessionExpiresAt, writeTarget.current);
                if (run === generation.current) { setView(null); resetSelection(); setFenced(true); setState('uncertain'); }
                return;
            }
            if (!validCustomerDeviceView(result) || !result.devices.some(d => d.deviceId === selectedDevice.deviceId && d.identity === selectedDevice.identity && d.customerId === selectedCustomer.id)) throw new Error('unconfirmed response');
            const age = performance.now() - startMono, wallAge = Date.now() - startWall;
            if (!Number.isFinite(age) || age < 0 || !Number.isFinite(wallAge) || Math.abs(age-wallAge) > 1500 || !acceptWindowsHealthClock(clockKey, epoch, result.serverNow, age)) throw new Error('invalid clock');
            clock.current = {epoch, requestAge:age, serverNow:result.serverNow, validUntil:result.validUntil};
            if (!fresh()) throw new Error('expired snapshot');
            setView(result); resetSelection(); setState('ready');
        } catch {
            if (writeTarget.current) uncertainSessions.set(sessionExpiresAt, writeTarget.current);
            if (!controller.signal.aborted && run === generation.current && epoch === getProtectedRequestEpoch() && live()) { setView(null); resetSelection(); setFenced(true); setState('uncertain'); }
        } finally { if (active.current === controller) { active.current = null; writing.current = false; writeTarget.current = null; setBusy(false); } }
    };
    return <section className="panel customer-devices-panel" aria-label={c.title}>
        <div className="customer-devices-heading"><h3>{c.title}</h3><button className="button" type="button" disabled={busy} onClick={() => void refresh()}>{c.refresh}</button></div>
        <p>{c.scope}</p><CustomerOrganizationNotice/><p>{c.pending} {locale === 'de' ? 'Der Prüfstand kann sich jederzeit ändern; der Manager prüft beim Speichern erneut.' : 'The snapshot can change at any time; the manager checks again when saving.'}</p>
        {state === 'loading' && <p role="status">{c.loading}</p>}
        {state !== 'loading' && state !== 'ready' && <p role="alert">{c[state]}</p>}
        {state === 'ready' && view && <>
            <p>{c.asOf}: <time dateTime={view.serverNow}>{new Date(view.serverNow).toLocaleString(locale)}</time></p>
            {fenced && <p role="alert">{c.fenced}</p>}
            {view.unavailableAssignments > 0 && <p role="status">{c.unavailable} {view.unavailableAssignments}</p>}
            {view.customers.length === 0 && <p>{c.noneCustomers}</p>}
            {view.devices.length === 0 ? <p>{c.noneDevices}</p> : <ul className="customer-devices-list" aria-label={c.recorded}>{view.devices.map(item => <li key={item.deviceId}><span><strong>{item.deviceId}</strong><br/>{c.identity}: <code>{item.identity}</code></span><span>{view.customers.find(x => x.id === item.customerId)?.name ?? c.unassigned}</span></li>)}</ul>}
            {!fenced && view.customers.length > 0 && view.devices.some(d => d.customerId === '') && <form className="customer-devices-form" onSubmit={event => void save(event)}>
                <label>{c.chooseDevice}<select value={deviceId} disabled={busy} onChange={event => { setDeviceId(event.target.value); setAcknowledged(false); }}><option value="">{c.choose}</option>{view.devices.filter(d => d.customerId === '').map(d => <option value={d.deviceId} key={d.deviceId}>{d.deviceId}</option>)}</select></label>
                <label>{c.chooseCustomer}<select value={customerId} disabled={busy} onChange={event => { setCustomerId(event.target.value); setAcknowledged(false); }}><option value="">{c.choose}</option>{view.customers.map(x => <option value={x.id} key={x.id}>{x.name} ({x.id})</option>)}</select></label>
                {device && customer && <><p>{c.device}: <strong>{device.deviceId}</strong><br/>{c.identity}: <code>{device.identity}</code><br/>{c.customer}: <strong>{customer.name}</strong> ({customer.id})</p><label className="customer-devices-confirm"><input type="checkbox" checked={acknowledged} disabled={busy} onChange={event => setAcknowledged(event.target.checked)}/>{c.acknowledge}</label></>}
                <button className="button primary" type="submit" disabled={busy || !device || !customer || !acknowledged}>{busy ? c.saving : c.assign}</button>
            </form>}
        </>}
    </section>;
}
