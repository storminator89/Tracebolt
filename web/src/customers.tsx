import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, mutate, request } from './api';
import { validFleetGroupName } from './fleet-groups-types';
import { useLocale } from './i18n';
import './customers.css';

interface Customer { id: string; name: string; revision: number }
interface Catalog { schemaVersion: 'tracebolt.customers.v1'; customers: Customer[] }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
export function validCustomerCatalog(v: unknown): v is Catalog {
    if (!exact(v, ['schemaVersion', 'customers']) || v.schemaVersion !== 'tracebolt.customers.v1' || !Array.isArray(v.customers) || v.customers.length > 25) return false;
    return v.customers.every(c => exact(c, ['id', 'name', 'revision']) && typeof c.id === 'string' && /^customer_[a-f0-9]{32}$/.test(c.id) && c.id !== `customer_${'0'.repeat(32)}` && validFleetGroupName(c.name) && Number.isSafeInteger(c.revision) && Number(c.revision) > 0) && new Set(v.customers.map(c => c.id)).size === v.customers.length;
}
const copy = {
    en: { title: 'Customers', scope: 'Organizational customer records only. They do not isolate access or assign devices or installers.', loading: 'Loading customers…', empty: 'No customers yet.', error: 'Customers are unavailable. Refresh before making changes.', conflict: 'The customer changed. Refresh and review before editing again.', uncertain: 'The change could not be confirmed and may have been saved. Refresh before another change; it will not be retried automatically.', refresh: 'Refresh customers', name: 'Customer name', create: 'Create customer', edit: 'Edit', save: 'Save name', cancel: 'Cancel', saving: 'Saving…', limit: 'The 25-customer limit has been reached.', invalid: 'Enter a name of 1–80 UTF-8 bytes without leading or trailing spaces or control characters.', expired: 'Customer data is no longer available in this session. Refresh after access is confirmed.' },
    de: { title: 'Kunden', scope: 'Nur organisatorische Kundenstammdaten. Sie trennen keine Zugriffe und ordnen weder Geräte noch Installer zu.', loading: 'Kunden werden geladen …', empty: 'Noch keine Kunden vorhanden.', error: 'Kunden sind nicht verfügbar. Vor Änderungen aktualisieren.', conflict: 'Der Kunde wurde geändert. Vor einer weiteren Bearbeitung aktualisieren und erneut prüfen.', uncertain: 'Die Änderung konnte nicht bestätigt werden und wurde möglicherweise gespeichert. Vor einer weiteren Änderung aktualisieren; sie wird nicht automatisch wiederholt.', refresh: 'Kunden aktualisieren', name: 'Kundenname', create: 'Kunde erstellen', edit: 'Bearbeiten', save: 'Name speichern', cancel: 'Abbrechen', saving: 'Wird gespeichert …', limit: 'Das Limit von 25 Kunden ist erreicht.', invalid: 'Einen Namen mit 1–80 UTF-8-Bytes ohne äußere Leerzeichen oder Steuerzeichen eingeben.', expired: 'Kundendaten sind in dieser Sitzung nicht mehr verfügbar. Nach bestätigtem Zugriff aktualisieren.' },
} as const;

/** Shared-admin-only organizational records; never selects or authorizes enrollment. */
export function Customers({ sessionExpiresAt }: { sessionExpiresAt: string }) {
    const [locale] = useLocale(), c = copy[locale];
    const [catalog, setCatalog] = useState<Catalog | null>(null);
    const [state, setState] = useState<'loading' | 'ready' | 'error' | 'conflict' | 'uncertain' | 'expired'>('loading');
    const [name, setName] = useState(''), [editing, setEditing] = useState<Customer | null>(null), [busy, setBusy] = useState(false);
    const active = useRef<AbortController | null>(null), generation = useRef(0), writing = useRef(false);
    const deadline = Date.parse(sessionExpiresAt);
    const live = useCallback(() => Number.isFinite(deadline) && Date.now() < deadline && !document.hidden, [deadline]);
    const invalidate = useCallback(() => {
        const interruptedWrite = writing.current;
        generation.current++; active.current?.abort(); active.current = null; writing.current = false;
        setCatalog(null); setName(''); setEditing(null); setBusy(false); setState(interruptedWrite ? 'uncertain' : 'expired');
    }, []);
    const refresh = useCallback(async () => {
        if (!live() || writing.current) { if (!live()) invalidate(); return; }
        active.current?.abort();
        const controller = new AbortController(), run = ++generation.current, epoch = getProtectedRequestEpoch(); active.current = controller;
        setCatalog(null); setEditing(null); setName(''); setState('loading');
        try {
            const value = await request<unknown>('/customers', { signal: controller.signal });
            if (controller.signal.aborted || generation.current !== run || epoch !== getProtectedRequestEpoch() || !live()) return;
            if (!validCustomerCatalog(value)) throw new Error('invalid response');
            setCatalog(value); setState('ready');
        } catch {
            if (!controller.signal.aborted && generation.current === run && epoch === getProtectedRequestEpoch() && live()) setState('error');
        } finally { if (active.current === controller) active.current = null; }
    }, [invalidate, live]);
    useEffect(() => {
        void refresh();
        const visibility = () => { if (document.hidden) invalidate(); };
        document.addEventListener('visibilitychange', visibility);
        window.addEventListener('hashchange', invalidate);
        window.addEventListener(AUTH_REQUIRED_EVENT, invalidate);
        const timer = window.setTimeout(invalidate, Math.max(0, Math.min(2147483647, deadline - Date.now())));
        return () => { generation.current++; active.current?.abort(); active.current = null; window.clearTimeout(timer); document.removeEventListener('visibilitychange', visibility); window.removeEventListener('hashchange', invalidate); window.removeEventListener(AUTH_REQUIRED_EVENT, invalidate); };
    }, [deadline, invalidate, refresh]);
    const save = async (event: FormEvent) => {
        event.preventDefault();
        if (writing.current || state !== 'ready' || !catalog || !validFleetGroupName(name) || !live() || (!editing && catalog.customers.length >= 25)) return;
        writing.current = true; setBusy(true);
        const controller = new AbortController(), run = ++generation.current, epoch = getProtectedRequestEpoch(), selected = editing; active.current = controller;
        try {
            const value = await mutate<unknown>(selected ? `/customers/${selected.id}` : '/customers', { name, expectedRevision: selected?.revision ?? 0 }, controller.signal);
            if (controller.signal.aborted || generation.current !== run || epoch !== getProtectedRequestEpoch() || !live()) return;
            if (!validCustomerCatalog(value)) throw new Error('unconfirmed response');
            if (selected) {
                if (!value.customers.some(customer => customer.id === selected.id && customer.name === name && customer.revision === selected.revision + 1)) throw new Error('unconfirmed response');
            } else {
                const known = new Set(catalog.customers.map(customer => customer.id));
                if (value.customers.filter(customer => !known.has(customer.id) && customer.name === name && customer.revision === 1).length !== 1) throw new Error('unconfirmed response');
            }
            setCatalog(value); setName(''); setEditing(null); setState('ready');
        } catch (error) {
            if (!controller.signal.aborted && generation.current === run && epoch === getProtectedRequestEpoch() && live()) {
                setCatalog(null); setName(''); setEditing(null); setState(error instanceof APIError && error.status === 409 ? 'conflict' : 'uncertain');
            }
        } finally { if (active.current === controller) { active.current = null; writing.current = false; setBusy(false); } }
    };
    return <section className="panel customers-panel" aria-label={c.title}>
        <div className="customers-heading"><h3>{c.title}</h3><button className="button" type="button" disabled={busy} onClick={() => void refresh()}>{c.refresh}</button></div>
        <p>{c.scope}</p>
        {state === 'loading' && <p role="status">{c.loading}</p>}
        {state !== 'loading' && state !== 'ready' && <p role="alert">{c[state]}</p>}
        {state === 'ready' && catalog && <>
            {catalog.customers.length === 0 ? <p>{c.empty}</p> : <ul className="customers-list">{catalog.customers.map(customer => <li key={customer.id}><span>{customer.name}</span><button className="button" type="button" disabled={busy} onClick={() => { setEditing(customer); setName(customer.name); }}>{c.edit} {customer.name}</button></li>)}</ul>}
            {!editing && catalog.customers.length >= 25 && <p role="status">{c.limit}</p>}
            {(editing || catalog.customers.length < 25) && <form className="customers-form" onSubmit={event => void save(event)}>
                <label><span>{c.name}</span><input value={name} onChange={event => setName(event.target.value)} disabled={busy} maxLength={80}/></label>
                {name && !validFleetGroupName(name) && <p role="status">{c.invalid}</p>}
                <button className="button primary" type="submit" disabled={busy || !validFleetGroupName(name)}>{busy ? c.saving : editing ? c.save : c.create}</button>
                {editing && <button className="button" type="button" disabled={busy} onClick={() => { setEditing(null); setName(''); }}>{c.cancel}</button>}
            </form>}
        </>}
    </section>;
}
