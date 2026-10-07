import { createContext, useContext, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { APIError, AUTH_REQUIRED_EVENT, getProtectedRequestEpoch } from './api';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { approvePackageUpdates, PackageUpdateNotReady, preparePackageUpdates, readPackageUpdateRetryGate, readPackageUpdates } from './package-update-api';
import type { PackageUpdateAccess } from './package-update-api';
import { canonicalPackageSelection, packageIdentityKey, packageUpdateBlocksNew, packageUpdatePending, packageUpdateReady, validPackageIdentity, validPackageUpdateID } from './package-update-types';
import type { PackageIdentity, PackageUpdateState, PackageUpdateView } from './package-update-types';
import './package-updates.css';

const copy = {
    en: {
        title: 'Selected package updates', unavailableTitle: 'Selected package updates · unavailable', unavailable: 'Native package updates are not ready on this device.', inventory: 'Cached candidates are inventory only, not a verified installation plan.',
        native: 'Updates run on this device. No automatic reboot.', nativePrepare: 'Prepare selected updates', nativeApprove: 'Install these exact updates', nativeResult: 'Endpoint-reported verification', notReady: 'Update readiness changed. Refresh the saved status before continuing.', simulation: 'SIMULATION ONLY · Synthetic package evidence. No host updates are executed.', select: 'Select', selected: 'Selected identities', selectionHint: 'Select up to 32 detected name + architecture identities in the list below. Preparation independently resolves exact versions and sources.', none: 'No packages selected.', remove: 'Remove', prepare: 'Prepare selected updates (simulation)', preparing: 'Preparing…', read: 'Refresh saved update status', reading: 'Reading saved update status…', access: 'A named operator with plan_updates is required to prepare. execute_updates is separately required to confirm.', readError: 'Update status could not be verified. Refresh the saved status before continuing.', invalid: 'Inconsistent update evidence was rejected. Check the saved status before continuing.', session: 'Your session or update access changed. Sign in again before continuing.',
        review: 'Immutable preparation review', request: 'Request ID', digest: 'Preview digest', actor: 'Preparing operator', expiry: 'Approval expires', transport: 'Transport profile', bytes: 'Total download bytes', conffile: 'Configuration policy', policy: 'Preserve modified dpkg configuration files', source: 'Source', version: 'Version', archive: 'Archive SHA-256', risk: 'I have reviewed these exact versions and sources. Package scripts may restart services. No automatic reboot or guaranteed rollback.', approve: 'Confirm this exact update (simulation)', approving: 'Saving confirmation…', expired: 'This preview has expired or its clock is unreliable. Refresh the saved status; a new preparation is required.', owner: 'Only the preparing operator can confirm this preview.',
        saved: 'Saved operation', result: 'Verification evidence (simulation)', expected: 'Expected version', observed: 'Observed version', unknown: 'Unknown', verified: 'Verified', mismatch: 'Mismatch', reboot: 'Reboot observation', required: 'Required', not_reported: 'Not reported', evidenceTime: 'Evidence time', reason: 'Result reason', unknownWrite: 'The write response was lost or could not be verified. Its outcome is unknown. Recover this same request; do not start a new operation.', recover: 'Recover same request status', notRecorded: 'This exact request is not recorded yet. Current access and update availability were checked. Only an explicit retry of the same request is allowed.', retry: 'Retry the same request', failedRecovery: 'The saved status does not establish this request’s outcome. Keep this request ID for recovery.', acknowledged: 'Confirmation saved', held: 'Held candidate; preparation may refuse it.',
    },
    de: {
        title: 'Ausgewählte Paketupdates', unavailableTitle: 'Ausgewählte Paketupdates · nicht verfügbar', unavailable: 'Native Paketupdates sind auf diesem Gerät nicht bereit.', inventory: 'Cache-Kandidaten sind nur Inventardaten, kein geprüfter Installationsplan.',
        native: 'Updates werden auf diesem Gerät ausgeführt. Kein automatischer Neustart.', nativePrepare: 'Ausgewählte Updates vorbereiten', nativeApprove: 'Diese genauen Updates installieren', nativeResult: 'Vom Endpunkt gemeldete Verifikation', notReady: 'Updatebereitschaft geändert. Vor dem Fortfahren den gespeicherten Status aktualisieren.', simulation: 'NUR SIMULATION · Synthetische Paketnachweise. Es werden keine Hostupdates ausgeführt.', select: 'Auswählen', selected: 'Ausgewählte Identitäten', selectionHint: 'Bis zu 32 erkannte Namen + Architekturen in der Liste unten auswählen. Die Vorbereitung ermittelt genaue Versionen und Quellen unabhängig neu.', none: 'Keine Pakete ausgewählt.', remove: 'Entfernen', prepare: 'Ausgewählte Updates vorbereiten (Simulation)', preparing: 'Vorbereitung läuft…', read: 'Gespeicherten Updatestatus aktualisieren', reading: 'Gespeicherter Updatestatus wird gelesen…', access: 'Zur Vorbereitung ist ein benannter Operator mit plan_updates nötig. Für die Bestätigung ist unabhängig execute_updates erforderlich.', readError: 'Der Updatestatus konnte nicht geprüft werden. Vor dem Fortfahren den gespeicherten Status aktualisieren.', invalid: 'Widersprüchliche Updatenachweise wurden abgewiesen. Vor dem Fortfahren den gespeicherten Status prüfen.', session: 'Sitzung oder Updateberechtigung geändert. Vor dem Fortfahren erneut anmelden.',
        review: 'Unveränderliche Vorbereitung prüfen', request: 'Anfrage-ID', digest: 'Vorschau-Digest', actor: 'Vorbereitender Operator', expiry: 'Freigabe gültig bis', transport: 'Transportprofil', bytes: 'Gesamte Downloadbytes', conffile: 'Konfigurationsrichtlinie', policy: 'Geänderte dpkg-Konfigurationsdateien beibehalten', source: 'Quelle', version: 'Version', archive: 'Archiv-SHA-256', risk: 'Ich habe diese genauen Versionen und Quellen geprüft. Paketskripte können Dienste neu starten. Kein automatischer Neustart und kein garantiertes Rollback.', approve: 'Dieses genaue Update bestätigen (Simulation)', approving: 'Bestätigung wird gespeichert…', expired: 'Diese Vorschau ist abgelaufen oder ihre Zeitbasis unzuverlässig. Gespeicherten Status aktualisieren; eine neue Vorbereitung ist erforderlich.', owner: 'Nur der vorbereitende Operator kann diese Vorschau bestätigen.',
        saved: 'Gespeicherter Vorgang', result: 'Verifikationsnachweise (Simulation)', expected: 'Erwartete Version', observed: 'Beobachtete Version', unknown: 'Unbekannt', verified: 'Verifiziert', mismatch: 'Abweichung', reboot: 'Neustartbeobachtung', required: 'Erforderlich', not_reported: 'Nicht gemeldet', evidenceTime: 'Nachweiszeit', reason: 'Ergebnisgrund', unknownWrite: 'Die Schreibantwort ging verloren oder konnte nicht geprüft werden. Der Ausgang ist unbekannt. Dieselbe Anfrage wiederherstellen; keinen neuen Vorgang starten.', recover: 'Status derselben Anfrage wiederherstellen', notRecorded: 'Diese genaue Anfrage ist noch nicht gespeichert. Aktueller Zugang und Updateverfügbarkeit wurden geprüft. Nur ein ausdrücklicher Wiederholungsversuch derselben Anfrage ist erlaubt.', retry: 'Dieselbe Anfrage erneut senden', failedRecovery: 'Der gespeicherte Status klärt den Ausgang dieser Anfrage nicht. Diese Anfrage-ID zur Wiederherstellung aufbewahren.', acknowledged: 'Bestätigung gespeichert', held: 'Zurückgehaltener Kandidat; Vorbereitung kann ihn ablehnen.',
    },
};
const states: Record<'en' | 'de', Record<PackageUpdateState, string>> = {
    en: { preparing: 'Preparing', preview_ready: 'Ready for review', approved: 'Approved; awaiting execution evidence', delivery_unknown: 'Delivery outcome unknown', expired: 'Expired', revoked: 'Revoked', preparation_failed: 'Preparation failed', applying: 'Applying (simulation)', verifying: 'Verifying (simulation)', succeeded: 'All approved versions verified (simulation)', needs_intervention: 'Needs intervention; outcome not verified' },
    de: { preparing: 'Vorbereitung läuft', preview_ready: 'Zur Prüfung bereit', approved: 'Bestätigt; Ausführungsnachweis ausstehend', delivery_unknown: 'Zustellausgang unbekannt', expired: 'Abgelaufen', revoked: 'Widerrufen', preparation_failed: 'Vorbereitung fehlgeschlagen', applying: 'Anwenden (Simulation)', verifying: 'Verifizieren (Simulation)', succeeded: 'Alle freigegebenen Versionen verifiziert (Simulation)', needs_intervention: 'Eingriff nötig; Ausgang nicht verifiziert' },
};
interface Selection { selected: PackageIdentity[]; disabled: boolean; toggle: (identity: PackageIdentity) => void }
const SelectionContext = createContext<Selection | null>(null);
/** Outside the Updates workflow, inventory remains a read-only table. */
export function PackageUpdateSelectionHeader() {
    const selection = useContext(SelectionContext), [locale] = useLocale();
    return selection ? <th scope="col">{copy[locale].select}</th> : null;
}
export function PackageUpdateSelectionCell({ name, architecture, held = false }: PackageIdentity & { held?: boolean }) {
    const selection = useContext(SelectionContext), [locale] = useLocale();
    if (!selection) return null;
    const checked = selection.selected.some(item => packageIdentityKey(item) === `${name}:${architecture}`);
    return <td><input type="checkbox" aria-label={`${copy[locale].select} ${name}:${architecture}`} title={held ? copy[locale].held : undefined} checked={checked} disabled={selection.disabled || !checked && selection.selected.length >= 32} onChange={() => selection.toggle({ name, architecture })}/></td>;
}
export function PackageUpdatesUnavailable() {
    const [locale] = useLocale(), id = useId(), labels = copy[locale];
    return <section className="package-update-unavailable" aria-labelledby={id}><h4 id={id}>{labels.unavailableTitle}</h4><p>{labels.unavailable}</p><p>{labels.inventory}</p></section>;
}
/** Device, source and explicit access scope are remounted together. Late private
 * responses cannot restore a previous device/session's selection or preview. */
export function PackageUpdatesWorkspace({ deviceId, sessionKey, source, children }: { deviceId: string; sessionKey: string | null; source: string; children: ReactNode }) {
    const operator = useOperator();
    const key = JSON.stringify([deviceId, source, sessionKey, operator?.authenticated, operator?.loginMode, operator?.actorId, operator?.capabilities, operator?.hasExplicitMetadata, operator?.insecureTestMode]);
    return <Workflow key={key} deviceId={deviceId} sessionKey={sessionKey}>{children}</Workflow>;
}
type Intent = { mode: 'simulation' | 'native' } & ({ kind: 'prepare'; requestId: string; packages: PackageIdentity[] } | { kind: 'approve'; requestId: string; previewDigest: string });
type Anchor = { mono: number; wall: number };
type RetryGate = { requestId: string; executionMode: 'unavailable' | 'simulation' | 'native'; available: boolean; started: Anchor };
const anchorNow = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor) {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return mono >= 0 && Number.isFinite(mono) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
function newRequestID() {
    const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
    const id = `update_${Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('')}`;
    if (!validPackageUpdateID(id, 'update_')) throw new TypeError('Invalid request ID');
    return id;
}
function Workflow({ deviceId, sessionKey, children }: { deviceId: string; sessionKey: string | null; children: ReactNode }) {
    const operator = useOperator(), [locale] = useLocale(), labels = copy[locale], id = useId();
    const [selection, setSelection] = useState<PackageIdentity[]>([]), [view, setView] = useState<PackageUpdateView | null>(null), [loading, setLoading] = useState<'read' | 'prepare' | 'approve' | null>(null);
    const [error, setError] = useState<'readError' | 'invalid' | 'session' | 'notReady' | null>(null), [uncertain, setUncertain] = useState<Intent | null>(null), [ack, setAck] = useState(false), [, tick] = useState(0);
    const [retryGate, setRetryGate] = useState<RetryGate | null>(null);
    const alive = useRef(false), locked = useRef(false), suspended = useRef(false), pending = useRef<AbortController | null>(null), current = useRef<PackageUpdateView | null>(null), clock = useRef<Anchor | null>(null), uncertainRef = useRef<Intent | null>(null), frozen = useRef(new Map<string, string>());
    const authenticated = operator?.mode === 'lan' && operator.authenticated;
    const named = authenticated && operator.hasExplicitMetadata === true && operator.loginMode === 'named' && validPackageUpdateID(operator.actorId, 'operator_') && !!sessionKey;
    const canPlan = !!named && operator.capabilities?.includes('plan_updates') === true, canExecute = !!named && operator.capabilities?.includes('execute_updates') === true;
    const storageKey = 'tracebolt.package-update-intent';
    const forgetIntent = () => { if (storageKey) { try { sessionStorage.removeItem(storageKey); } catch { /* Retaining an intent only blocks another operation. */ } } };
    const access: PackageUpdateAccess | null = named ? { actorId: operator.actorId!, sessionKey: sessionKey!, insecureTestMode: operator.insecureTestMode } : null;
    const accept = (next: PackageUpdateView, started: Anchor, intent?: Intent) => {
        if (!Number.isFinite(elapsed(started)) || current.current && Date.parse(next.serverNow) < Date.parse(current.current.serverNow)) throw new TypeError('Unreliable update clock');
        const expected = intent ?? uncertainRef.current;
        if (expected && (next.job?.requestId !== expected.requestId || next.executionMode !== expected.mode)) throw new TypeError('Wrong update request');
        if (intent?.kind === 'approve' && !next.job?.approvedAt) throw new TypeError('Approval not established');
        if (next.preview) {
            const serialized = JSON.stringify([next.executionMode, next.preview]), prior = frozen.current.get(next.preview.requestId);
            if (prior && prior !== serialized) throw new TypeError('Immutable preview changed');
            if (expected && (next.preview.actorId !== access?.actorId || next.preview.transportProfile !== (access?.insecureTestMode ? 'disposable-http-test' : 'production-tls'))) throw new TypeError('Recovery scope changed');
            if (expected?.kind === 'approve' && next.preview.digest !== expected.previewDigest) throw new TypeError('Approved preview digest changed');
            if (expected?.kind === 'prepare' && (next.preview.items.length !== expected.packages.length || !next.preview.items.every(item => expected.packages.some(selected => packageIdentityKey(item) === packageIdentityKey(selected))))) throw new TypeError('Selection changed');
            frozen.current.set(next.preview.requestId, serialized);
        }
        setRetryGate(null);
        if (current.current?.preview?.digest !== next.preview?.digest || current.current?.executionMode !== next.executionMode || !packageUpdateReady(next)) setAck(false);
        clock.current = started; current.current = next; setView(next); setError(null);
        const lost = uncertainRef.current;
        if (lost && next.job?.requestId === lost.requestId && (lost.kind === 'prepare' ? !!next.preview || ['expired', 'revoked', 'preparation_failed'].includes(next.job.state) : !!next.preview && !['preview_ready', 'preparing'].includes(next.job.state))) { uncertainRef.current = null; setUncertain(null); setAck(false); forgetIntent(); }
    };
    const run = async (intent?: Intent) => {
        if (!alive.current || locked.current || suspended.current || pending.current || !authenticated) return;
        if (intent && !access) return;
        const retrying = !!uncertainRef.current;
        if (intent) {
            try { sessionStorage.setItem(storageKey, JSON.stringify({ deviceId, actorId: access!.actorId, sessionKey, intent })); } catch { setError('invalid'); return; }
            uncertainRef.current = intent;
        }
        const controller = new AbortController(), epoch = getProtectedRequestEpoch(), started = anchorNow(); pending.current = controller;
        setLoading(intent?.kind ?? 'read'); setError(null); setRetryGate(null);
        const timeout = window.setTimeout(() => controller.abort(), 10000);
        try {
            const approvalPreview = current.current?.preview;
            if (intent?.kind === 'approve' && (!approvalPreview || approvalPreview.requestId !== intent.requestId || approvalPreview.digest !== intent.previewDigest)) throw new TypeError('Original preview unavailable');
            let next: PackageUpdateView;
            try {
                next = !intent ? await readPackageUpdates(deviceId, controller.signal, uncertainRef.current?.requestId) : intent.kind === 'prepare'
                    ? await preparePackageUpdates(deviceId, intent.requestId, intent.packages, access!, controller.signal, intent.mode)
                    : await approvePackageUpdates(deviceId, approvalPreview!, access!, controller.signal, intent.mode);
            } catch (caught) {
                const lost = uncertainRef.current;
                if (intent || !(caught instanceof APIError) || caught.status !== 404 || caught.code !== 'package_update_not_found' || lost?.kind !== 'prepare' || !access) throw caught;
                // A missing exact ID can mean a lost write never committed. A
                // latest read is admission only, never replacement job evidence.
                const latest = await readPackageUpdateRetryGate(deviceId, access, controller.signal);
                if (!alive.current || pending.current !== controller || suspended.current || epoch !== getProtectedRequestEpoch() || controller.signal.aborted) return;
                if (!Number.isFinite(elapsed(started)) || current.current && Date.parse(latest.serverNow) < Date.parse(current.current.serverNow)) throw new TypeError('Unreliable recovery clock');
                if (latest.executionMode !== lost.mode) throw new TypeError('Recovery execution mode changed');
                if (latest.job?.requestId === lost.requestId) accept(latest, started);
                else {
                    current.current = null; clock.current = null; setView(null); setAck(false);
                    setRetryGate({ requestId: lost.requestId, executionMode: latest.executionMode, available: latest.available && packageUpdateReady(latest), started });
                    setError(null);
                }
                return;
            }
            if (!alive.current || pending.current !== controller || suspended.current || epoch !== getProtectedRequestEpoch() || controller.signal.aborted) return;
            accept(next, started, intent);
            if (intent?.kind === 'approve') setAck(false);
        } catch (caught) {
            if (!alive.current || pending.current !== controller || suspended.current) return;
            if (caught instanceof APIError && caught.status === 401 || epoch !== getProtectedRequestEpoch()) { locked.current = true; forgetIntent(); uncertainRef.current = null; setUncertain(null); setError('session'); current.current = null; setView(null); setSelection([]); setAck(false); }
            else if (caught instanceof PackageUpdateNotReady) {
                if (!retrying) { forgetIntent(); uncertainRef.current = null; setUncertain(null); }
                setAck(false); current.current = null; clock.current = null; setView(null); setError('notReady');
            }
            else if (intent) { uncertainRef.current = intent; setUncertain(intent); setAck(false); }
            else setError(caught instanceof TypeError ? 'invalid' : 'readError');
        } finally { window.clearTimeout(timeout); if (pending.current === controller) { pending.current = null; if (alive.current) setLoading(null); } }
    };
    const runRef = useRef(run); runRef.current = run;
    useEffect(() => {
        alive.current = true;
        try {
            const raw = sessionStorage.getItem(storageKey);
            if (raw && raw.length <= 16384) {
                const stored = JSON.parse(raw), saved = stored?.intent as Intent;
                if (stored.deviceId !== deviceId || stored.actorId !== access?.actorId || stored.sessionKey !== sessionKey) forgetIntent();
                else if (saved && ['simulation', 'native'].includes(saved.mode) && validPackageUpdateID(saved.requestId, 'update_') && (saved.kind === 'prepare' && Array.isArray(saved.packages) && saved.packages.length > 0 && saved.packages.length <= 32 && saved.packages.every(validPackageIdentity) && new Set(saved.packages.map(packageIdentityKey)).size === saved.packages.length || saved.kind === 'approve' && /^sha256:[a-f0-9]{64}$/.test(saved.previewDigest))) { uncertainRef.current = saved; setUncertain(saved); }
                else { locked.current = true; setError('invalid'); }
            } else if (raw) { locked.current = true; setError('invalid'); }
        } catch { locked.current = true; setError('invalid'); }
        const clear = () => { setRetryGate(null); pending.current?.abort(); pending.current = null; current.current = null; clock.current = null; setView(null); setSelection([]); setAck(false); setLoading(null); };
        const lock = () => { locked.current = true; forgetIntent(); uncertainRef.current = null; setUncertain(null); clear(); setError('session'); };
        const suspend = () => { suspended.current = true; clear(); };
        const restore = () => { if (locked.current || document.visibilityState === 'hidden') return; suspended.current = false; void runRef.current(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('pagehide', suspend); window.addEventListener('pageshow', restore); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { tick(value => value + 1); if ((packageUpdatePending(current.current?.job ?? null) || current.current?.executionMode === 'native' && current.current.job?.state === 'preview_ready' || uncertainRef.current) && !pending.current) void runRef.current(); }, 2000);
        void runRef.current();
        return () => { alive.current = false; pending.current?.abort(); pending.current = null; window.clearInterval(timer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('pagehide', suspend); window.removeEventListener('pageshow', restore); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); document.removeEventListener('visibilitychange', visibility); };
    }, []);
    const preview = view?.preview, job = view?.job, simulated = view?.executionMode === 'simulation' || retryGate?.executionMode === 'simulation';
    const native = view?.executionMode === 'native' || retryGate?.executionMode === 'native';
    const ready = packageUpdateReady(view);
    const activeMode = view?.executionMode === 'native' ? 'native' : 'simulation';
    const actionLabels = native ? { prepare: labels.nativePrepare, approve: labels.nativeApprove, result: labels.nativeResult } : labels;
    const stateLabels = native ? { ...states[locale], applying: locale === 'en' ? 'Applying updates' : 'Updates werden angewendet', verifying: locale === 'en' ? 'Verifying installed versions' : 'Installierte Versionen werden geprüft', succeeded: locale === 'en' ? 'Endpoint verified all approved versions' : 'Endpunkt hat alle freigegebenen Versionen verifiziert' } : states[locale];
    const retryPrepareAvailable = ready && !!view?.available || !!retryGate && retryGate.requestId === uncertain?.requestId && retryGate.available && elapsed(retryGate.started) < 10000;
    const age = clock.current ? elapsed(clock.current) : Infinity;
    const expired = !!preview && (!Number.isFinite(age) || Date.parse(preview.expiresAt) <= Date.parse(view!.serverNow) + age);
    const bound = !!preview && preview.actorId === access?.actorId && preview.transportProfile === (access?.insecureTestMode ? 'disposable-http-test' : 'production-tls');
    const disabled = !canPlan || !!loading || !!error || !!uncertain || packageUpdateBlocksNew(job ?? null);
    const toggle = (item: PackageIdentity) => { if (disabled) return; setSelection(previous => previous.some(old => packageIdentityKey(old) === packageIdentityKey(item)) ? previous.filter(old => packageIdentityKey(old) !== packageIdentityKey(item)) : previous.length < 32 ? [...previous, { name: item.name, architecture: item.architecture }] : previous); };
    const field = (label: string, value: ReactNode) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    const prepare = () => { if (disabled || !ready || !view?.available || selection.length === 0) return; try { void run({ kind: 'prepare', mode: activeMode, requestId: newRequestID(), packages: canonicalPackageSelection(selection) }); } catch { setError('invalid'); } };
    const approve = () => { if (!preview || !clock.current || Date.parse(preview.expiresAt) <= Date.parse(view!.serverNow) + elapsed(clock.current) || !canExecute || !bound || expired || !ack || loading || error || uncertain || !ready || job?.state !== 'preview_ready') return; void run({ kind: 'approve', mode: activeMode, requestId: preview.requestId, previewDigest: preview.digest }); };
    return <SelectionContext.Provider value={{ selected: selection, disabled, toggle }}>
        <section className="package-update-workflow" aria-labelledby={id}>
            <header className="package-heading"><h3 id={id}>{labels.title}</h3><button type="button" className="button small" disabled={!!loading || error === 'session'} onClick={() => void run()}>{labels.read}</button></header>
            {simulated && <p className="package-update-simulation" role="note">{labels.simulation}</p>}
            {view?.reason === 'native_adapter_unavailable' && <PackageUpdatesUnavailable/>}{native && <p className="package-note">{labels.native}</p>}
            <p className="package-note">{labels.inventory}</p>
            {loading && <p role="status">{loading === 'read' ? labels.reading : loading === 'prepare' ? labels.preparing : labels.approving}</p>}
            {error && <p role="alert" className="package-error">{labels[error]}</p>}
            {(!canPlan || !canExecute) && <p className="package-note">{labels.access}</p>}
            {uncertain && <div role="alert" className="package-update-uncertain"><p>{labels.unknownWrite}</p>{retryGate && <p>{labels.notRecorded}</p>}<p>{labels.request}: <code>{uncertain.requestId}</code></p><button type="button" className="button" disabled={!!loading || !!error && error === 'session'} onClick={() => void run()}>{labels.recover}</button><button type="button" className="button" disabled={!!loading || !!error || !simulated && !native || uncertain.kind === 'approve' && (!ready || !bound || expired || !canExecute) || uncertain.kind === 'prepare' && (!canPlan || !retryPrepareAvailable)} onClick={() => void run(uncertain)}>{labels.retry}</button>{view?.job?.requestId !== uncertain.requestId && <p>{labels.failedRecovery}</p>}</div>}
            <div className="package-update-selection"><h4>{labels.selected} ({selection.length}/32)</h4><p className="package-note">{labels.selectionHint}</p>{selection.length ? <ul>{selection.map(item => <li key={packageIdentityKey(item)}><code>{packageIdentityKey(item)}</code><button type="button" className="button small" aria-label={`${labels.remove} ${packageIdentityKey(item)}`} disabled={disabled} onClick={() => toggle(item)}>{labels.remove}</button></li>)}</ul> : <p>{labels.none}</p>}<button type="button" className="button" disabled={disabled || !ready || !view?.available || selection.length === 0} onClick={prepare}>{actionLabels.prepare}</button></div>
            {preview && <section className="package-update-review" aria-label={labels.review}><h4>{labels.review}</h4><dl className="package-facts">{field(labels.request, preview.requestId)}{field(labels.digest, preview.digest)}{field(labels.actor, preview.actorId)}{field(labels.expiry, preview.expiresAt)}{field(labels.transport, preview.transportProfile)}{field(labels.bytes, new Intl.NumberFormat(locale).format(preview.totalBytes))}{field(labels.conffile, labels.policy)}</dl><ol>{preview.items.map(item => <li key={packageIdentityKey(item)}><strong>{packageIdentityKey(item)}</strong><dl className="package-facts">{field(labels.version, `${item.fromVersion} → ${item.toVersion}`)}{field(labels.source, `${item.sourcePackage} ${item.sourceVersion} · ${item.sourceLabel} / ${item.suite} / ${item.component}`)}{field(labels.archive, item.archiveSHA256)}</dl></li>)}</ol>{job?.state === 'preview_ready' && <>{expired && <p role="status" className="package-error">{labels.expired}</p>}{!bound && <p>{labels.owner}</p>}<label className="package-update-ack"><input type="checkbox" checked={ack} disabled={!ready || !canExecute || !bound || expired || !!loading || !!error || !!uncertain} onChange={event => setAck(event.target.checked)}/>{labels.risk}</label><button type="button" className="button" disabled={!ready || !canExecute || !bound || expired || !ack || !!loading || !!error || !!uncertain || !ready} onClick={approve}>{actionLabels.approve}</button></>}</section>}
            {job && <section aria-label={labels.saved}><h4>{labels.saved}</h4><p role="status">{stateLabels[job.state]}</p><dl className="package-facts">{field(labels.request, job.requestId)}{field(labels.evidenceTime, job.updatedAt)}{job.approvedAt && field(labels.acknowledged, job.approvedAt)}</dl>{job.result && <section aria-label={actionLabels.result}><h4>{actionLabels.result}</h4><ul>{job.result.packages.map(item => <li key={packageIdentityKey(item)}><strong>{packageIdentityKey(item)}</strong>: {labels[item.outcome]}<br/>{labels.expected}: {item.expectedVersion} · {labels.observed}: {item.observedVersion ?? labels.unknown}</li>)}</ul><dl className="package-facts">{field(labels.evidenceTime, job.result.observedAt)}{field(labels.reason, job.result.reason)}{field(labels.reboot, `${labels[job.result.reboot.state]} · ${job.result.reboot.source} · ${job.result.reboot.observedAt}`)}</dl></section>}</section>}
        </section>
        {children}
    </SelectionContext.Provider>;
}
