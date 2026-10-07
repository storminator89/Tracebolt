import { t, ui, useLocale } from './i18n';
import { LanguageSelector } from './LanguageSelector';
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, Info, LoaderCircle, LockKeyhole, LogOut, Moon, RefreshCw, ShieldCheck, Sun, TriangleAlert } from 'lucide-react';
import { abortProtectedRequests, APIError, AUTH_REQUIRED_EVENT, mutate, request } from './api';
import { Logo } from './components';
import { fullDate, noteBytes, readSaved, saveLocal } from './utils';
export type OperatorLoginMode = 'shared' | 'named';
export type OperatorCapability = 'read' | 'plan_updates' | 'execute_updates' | 'restart_service' | 'manage_alarms' | 'manage_application_checks';
export interface OperatorSession {
    mode: 'development' | 'lan';
    transport: 'http' | 'https';
    insecureTestMode: boolean;
    transportWarning: 'unencrypted_lan_test' | null;
    authenticationRequired: boolean;
    authenticated: boolean;
    csrfToken: string | null;
    serverNow: string;
    expiresAt: string | null;
    expiresInSeconds: number | null;
    // Older managers omit all three fields. Present metadata must be complete.
    loginMode?: OperatorLoginMode;
    actorId?: string | null;
    capabilities?: OperatorCapability[];
}
interface OperatorContextValue {
    insecureTestMode: boolean;
    mode: 'development' | 'lan';
    authenticated: boolean;
    // Display metadata only. The server authorizes every protected request.
    loginMode?: OperatorLoginMode;
    actorId?: string | null;
    capabilities?: readonly OperatorCapability[];
    // Legacy display defaults do not establish explicit administrative authority.
    hasExplicitMetadata?: boolean;
    expiresAt: string | null;
    logout: () => void;
    theme: 'light' | 'dark';
    setTheme: (theme: 'light' | 'dark') => void;
}
const OperatorContext = createContext<OperatorContextValue | null>(null);
export function useOperator() { return useContext(OperatorContext); }
function validOperatorMetadata(s: Partial<OperatorSession>): boolean {
    if (!('loginMode' in s) && !('actorId' in s) && !('capabilities' in s))
        return true;
    if (s.loginMode !== 'shared' && s.loginMode !== 'named')
        return false;
    if (!Array.isArray(s.capabilities) || s.capabilities.length > 6 || new Set(s.capabilities).size !== s.capabilities.length || s.capabilities.some(capability => !['read', 'plan_updates', 'execute_updates', 'restart_service', 'manage_alarms', 'manage_application_checks'].includes(capability)))
        return false;
    if (s.mode === 'development')
        return s.loginMode === 'shared' && s.actorId === null && s.capabilities.length === 0;
    if (!s.authenticated)
        return s.actorId === null && s.capabilities.length === 0;
    if (s.loginMode === 'shared')
        return s.actorId === null && s.capabilities.length === 1 && s.capabilities[0] === 'read';
    return typeof s.actorId === 'string' && /^operator_[0-9a-f]{32}$/.test(s.actorId) && s.actorId !== 'operator_00000000000000000000000000000000' && s.capabilities.includes('read');
}
export function validOperatorSession(value: unknown, browserProtocol = window.location.protocol): value is OperatorSession {
    if (!value || typeof value !== 'object')
        return false;
    const s = value as Partial<OperatorSession>;
    if (!['development', 'lan'].includes(s.mode || '') || typeof s.authenticationRequired !== 'boolean' || typeof s.authenticated !== 'boolean' || typeof s.serverNow !== 'string' || !Number.isFinite(Date.parse(s.serverNow)))
        return false;
    if (typeof s.insecureTestMode !== 'boolean' || !['http','https'].includes(s.transport || '')) return false;
    if (s.insecureTestMode ? s.mode !== 'lan' || s.transport !== 'http' || s.transportWarning !== 'unencrypted_lan_test' : s.transportWarning !== null || (s.mode === 'lan' && s.transport !== 'https')) return false;
    if (s.mode === 'lan' && `${s.transport}:` !== browserProtocol) return false;
    if (!validOperatorMetadata(s)) return false;
    if (s.mode === 'development')
        return s.authenticationRequired === false && s.authenticated === false;
    if (s.authenticationRequired !== true)
        return false;
    if (s.authenticated)
        return typeof s.csrfToken === 'string' && s.csrfToken.length > 0 && typeof s.expiresAt === 'string' && Number.isFinite(Date.parse(s.expiresAt)) && typeof s.expiresInSeconds === 'number' && Number.isFinite(s.expiresInSeconds) && s.expiresInSeconds > 0 && s.expiresInSeconds <= 86400;
    return s.csrfToken === null && s.expiresAt === null && s.expiresInSeconds === null;
}
export const LOGOUT_INTENT_KEY = 'tracebolt.logout-intent';
export function hasLogoutIntent(): boolean {
    try {
        if (localStorage.getItem(LOGOUT_INTENT_KEY) === '1')
            return true;
    }
    catch { }
    try {
        return sessionStorage.getItem(LOGOUT_INTENT_KEY) === '1';
    }
    catch {
        return false;
    }
}
function rememberLogoutIntent(): boolean {
    try {
        localStorage.setItem(LOGOUT_INTENT_KEY, '1');
        try {
            sessionStorage.removeItem(LOGOUT_INTENT_KEY);
        }
        catch { }
        return true;
    }
    catch { }
    try {
        sessionStorage.setItem(LOGOUT_INTENT_KEY, '1');
        return true;
    }
    catch {
        return false;
    }
}
function clearLogoutIntent(): void {
    try {
        localStorage.removeItem(LOGOUT_INTENT_KEY);
    }
    catch { }
    try {
        sessionStorage.removeItem(LOGOUT_INTENT_KEY);
    }
    catch { }
}
type Phase = 'loading' | 'ready' | 'signin' | 'blocked' | 'signingout';
export function AuthBoundary({ children }: {
    children: ReactNode;
}) {
    useLocale();
    const [insecureTestMode,setInsecureTestMode] = useState(false);
    const [checkingAccess, setCheckingAccess] = useState(false);
    const [privateEpoch, setPrivateEpoch] = useState(0);
    const privateView = useRef<HTMLDivElement | null>(null);
    const priorFocus = useRef<HTMLElement | null>(null);
    const [phase, setPhase] = useState<Phase>('loading');
    const [session, setSession] = useState<OperatorSession | null>(null);
    // Retain the validated login mode even when lock paths discard the session.
    const [loginMode, setLoginMode] = useState<OperatorLoginMode>('shared');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [notice, setNotice] = useState('');
    const [error, setError] = useState('');
    const [pending, setPending] = useState(false);
    const [theme, setTheme] = useState<'light' | 'dark'>(() => readSaved<unknown>('local-rmm-theme', 'light') === 'dark' ? 'dark' : 'light');
    const alive = useRef(true);
    const current = useRef<AbortController | null>(null);
    const sessionRef = useRef<OperatorSession | null>(null);
    const signoutUnconfirmed = useRef(false);
    const modeRef = useRef<'development' | 'lan' | null>(null);
    const channelRef = useRef<BroadcastChannel | null>(null);
    const logoutIntentStored = useRef(true);
    useEffect(() => { document.documentElement.dataset.theme = theme; saveLocal('local-rmm-theme', theme); }, [theme]);
    const install = useCallback((next: OperatorSession) => { setInsecureTestMode(next.insecureTestMode); setLoginMode(next.loginMode ?? 'shared'); setUsername(''); setCheckingAccess(false); sessionRef.current = next; modeRef.current = next.mode; setSession(next); setPhase(next.authenticationRequired && !next.authenticated ? 'signin' : 'ready'); }, []);
    const lock = useCallback((message: string) => {
        abortProtectedRequests();
        current.current?.abort();
        setUsername('');
        setPassword('');
        setPending(false);
        setNotice(message);
        setError('');
        signoutUnconfirmed.current = false;
        const wasLAN = modeRef.current === 'lan';
        sessionRef.current = null;
        setSession(null);
        setPhase(wasLAN ? 'signin' : 'blocked');
        if (!wasLAN)
            setError(t("Der Manager hat den Zugriff verweigert. Status erneut pr\u00FCfen."));
    }, []);
    const bootstrap = useCallback(async () => {
        current.current?.abort();
        abortProtectedRequests();
        const controller = new AbortController();
        current.current = controller;
        setPhase('loading');
        setError('');
        setUsername('');
        setPassword('');
        signoutUnconfirmed.current = hasLogoutIntent();
        const timeout = window.setTimeout(() => {
            controller.abort();
            if (alive.current && current.current === controller) {
                sessionRef.current = null;
                setSession(null);
                setPhase('blocked');
                setError(t("Der Manager antwortet nicht. Erneut versuchen."));
            }
        }, 10000);
        try {
            const next = await request<OperatorSession>('/auth/session', { signal: controller.signal });
            if (!alive.current || controller.signal.aborted)
                return;
            if (!validOperatorSession(next))
                throw new APIError(t("Der Manager hat keinen g\u00FCltigen Zugriffsstatus geliefert."));
            setInsecureTestMode(next.insecureTestMode);
            setLoginMode(next.loginMode ?? 'shared');
            if (signoutUnconfirmed.current && next.authenticated) {
                sessionRef.current = next;
                modeRef.current = next.mode;
                setSession(next);
                setPhase('blocked');
                setError(t("Abmeldung noch nicht best\u00E4tigt. Bitte erneut abmelden."));
                return;
            }
            signoutUnconfirmed.current = false;
            clearLogoutIntent();
            install(next);
        }
        catch (err) {
            if (alive.current && current.current === controller) {
                sessionRef.current = null;
                setSession(null);
                setPhase('blocked');
                setError(controller.signal.aborted ? t("Der Manager antwortet nicht. Erneut versuchen.") : err instanceof Error ? err.message : t("Der Zugriffsstatus ist nicht verf\u00FCgbar."));
            }
        }
        finally {
            window.clearTimeout(timeout);
        }
    }, [install]);
    useEffect(() => { alive.current = true; void bootstrap(); return () => { alive.current = false; current.current?.abort(); abortProtectedRequests(); }; }, [bootstrap]);
    const broadcast = useCallback((type: string) => {
        try {
            channelRef.current?.postMessage({ type });
        }
        catch { }
    }, []);
    const lockFromOtherTab = useCallback((logoutPending: boolean) => { if(logoutPending) logoutIntentStored.current = rememberLogoutIntent(); abortProtectedRequests(); current.current?.abort(); setUsername(''); setPassword(''); setPending(false); sessionRef.current = null; setSession(null); signoutUnconfirmed.current = logoutPending; setPhase('blocked'); setNotice(''); setError(logoutPending && !logoutIntentStored.current ? t("Abmeldung unbestätigt; die Browsersperre konnte nicht gespeichert werden. Bitte alle Tabs schließen und erneut abmelden.") : logoutPending ? t("Abmeldung in einem anderen Tab begonnen. Zugriff bleibt gesperrt.") : t("Die Sitzung wurde in einem anderen Tab ge\u00E4ndert. Status erneut pr\u00FCfen.")); }, []);
    useEffect(() => {
        let channel: BroadcastChannel | null = null;
        if (typeof window.BroadcastChannel === 'function') {
            channel = new BroadcastChannel('tracebolt-auth');
            channelRef.current = channel;
            channel.onmessage = event => {
                if (event.data?.type === 'logout-intent')
                    lockFromOtherTab(true);
                else if (event.data?.type === 'session-ended' || event.data?.type === 'session-changed')
                    lockFromOtherTab(false);
            };
        }
        const stored = (event: StorageEvent) => {
            if (event.key === LOGOUT_INTENT_KEY && event.newValue === '1')
                lockFromOtherTab(true);
        };
        window.addEventListener('storage', stored);
        return () => {
            window.removeEventListener('storage', stored);
            channel?.close();
            if (channelRef.current === channel)
                channelRef.current = null;
        };
    }, [lockFromOtherTab]);
    useEffect(() => { const expired = () => { clearLogoutIntent(); lock(t("Sitzung abgelaufen. Bitte erneut anmelden.")); broadcast('session-ended'); }; window.addEventListener(AUTH_REQUIRED_EVENT, expired); return () => window.removeEventListener(AUTH_REQUIRED_EVENT, expired); }, [lock, broadcast]);
    useEffect(() => {
        if (phase !== 'ready' || !session?.authenticationRequired || !session.authenticated || session.expiresInSeconds === null)
            return;
        const timeout = window.setTimeout(() => lock(t("Sitzung abgelaufen. Bitte erneut anmelden.")), session.expiresInSeconds * 1000);
        return () => window.clearTimeout(timeout);
    }, [session, phase, lock]);
    useEffect(() => {
        const conceal = () => {
            const view = privateView.current;
            if (!view)
                return;
            const focused = document.activeElement;
            if (focused instanceof HTMLElement && view.contains(focused)) {
                priorFocus.current = focused;
                focused.blur();
            }
            view.style.visibility = 'hidden';
            view.setAttribute('inert', '');
            view.setAttribute('aria-hidden', 'true');
            setCheckingAccess(true);
        };
        const restore = async () => {
            if (!privateView.current)
                return;
            conceal();
            if (hasLogoutIntent()) {
                lockFromOtherTab(true);
                return;
            }
            current.current?.abort();
            const controller = new AbortController();
            current.current = controller;
            const oldSession = sessionRef.current;
            const timeout = window.setTimeout(() => {
                controller.abort();
                if (alive.current && current.current === controller) {
                    lock('');
                    setPhase('blocked');
                    setError(t("Zugriffsstatus konnte nicht erneut gepr\u00FCft werden."));
                }
            }, 10000);
            try {
                const next = await request<OperatorSession>('/auth/session', { signal: controller.signal });
                if (!alive.current || controller.signal.aborted || current.current !== controller)
                    return;
                if (!validOperatorSession(next))
                    throw new APIError(t("Ung\u00FCltiger Zugriffsstatus."));
                if (next.authenticationRequired && !next.authenticated) {
                    abortProtectedRequests();
                    clearLogoutIntent();
                    install(next);
                    setNotice(t("Sitzung abgelaufen. Bitte erneut anmelden."));
                    return;
                }
                const changed = oldSession?.mode !== next.mode || oldSession?.csrfToken !== next.csrfToken || oldSession?.loginMode !== next.loginMode || oldSession?.actorId !== next.actorId || JSON.stringify(oldSession?.capabilities) !== JSON.stringify(next.capabilities);
                if (changed) {
                    abortProtectedRequests();
                    setPrivateEpoch(value => value + 1);
                }
                install(next);
                setCheckingAccess(false);
                if (!changed) {
                    privateView.current?.style.removeProperty('visibility');
                    privateView.current?.removeAttribute('inert');
                    privateView.current?.removeAttribute('aria-hidden');
                    if (priorFocus.current?.isConnected)
                        priorFocus.current.focus();
                }
            }
            catch {
                if (alive.current && !controller.signal.aborted && current.current === controller) {
                    lock('');
                    setPhase('blocked');
                    setError(t("Zugriffsstatus konnte nicht erneut gepr\u00FCft werden."));
                }
            }
            finally {
                window.clearTimeout(timeout);
            }
        };
        const visibility = () => {
            if (!privateView.current)
                return;
            if (document.visibilityState === 'hidden') {
                conceal();
                current.current?.abort();
            }
            else
                void restore();
        };
        const pagehide = () => { conceal(); current.current?.abort(); setUsername(''); setPassword(''); setPending(false); };
        const pageshow = (event: PageTransitionEvent) => {
            if (event.persisted && !privateView.current)
                void bootstrap();
            else if (event.persisted || privateView.current?.hasAttribute('inert'))
                void restore();
        };
        document.addEventListener('visibilitychange', visibility);
        window.addEventListener('pagehide', pagehide);
        window.addEventListener('pageshow', pageshow);
        return () => { document.removeEventListener('visibilitychange', visibility); window.removeEventListener('pagehide', pagehide); window.removeEventListener('pageshow', pageshow); };
    }, [bootstrap, install, lock, lockFromOtherTab]);
    const login = async (event: React.SubmitEvent<HTMLFormElement>) => {
        event.preventDefault();
        const bytes = noteBytes(password);
        if (pending || bytes < 12 || bytes > 1024 || (loginMode === 'named' && (username.trim().length === 0 || username.length > 64)))
            return;
        const secret = password;
        setPassword('');
        setPending(true);
        setError('');
        setNotice('');
        current.current?.abort();
        const controller = new AbortController();
        current.current = controller;
        const deadline = window.setTimeout(() => {
            controller.abort();
            if (alive.current && current.current === controller) {
                setPending(false);
                setError(t("Die Anmeldung hat das Zeitlimit erreicht. Bitte erneut versuchen."));
            }
        }, 15000);
        try {
            const credentials = loginMode === 'named' ? { username, password: secret } : { password: secret };
            const next = await request<OperatorSession>('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials), signal: controller.signal });
            if (!alive.current || controller.signal.aborted)
                return;
            if (!validOperatorSession(next) || next.mode !== 'lan' || !next.authenticated || (next.loginMode ?? 'shared') !== loginMode)
                throw new APIError(t("Die Anmeldung konnte nicht best\u00E4tigt werden."));
            signoutUnconfirmed.current = false;
            clearLogoutIntent();
            install(next);
            broadcast('session-changed');
        }
        catch (err) {
            if (alive.current && !controller.signal.aborted) {
                const status = err instanceof APIError ? err.status : undefined;
                setError(status === 401 ? loginMode === 'named' ? t("Anmeldung nicht möglich. Benutzername und Passwort prüfen.") : t("Anmeldung nicht m\u00F6glich. Passwort pr\u00FCfen.") : status === 429 ? t("Zu viele Anmeldeversuche. Bitte sp\u00E4ter erneut versuchen.") : status === 403 ? t("Dieser Zugang ist nicht für die Anmeldung freigegeben.") : status === 503 ? t("Anmeldung vor\u00FCbergehend nicht verf\u00FCgbar.") : t("Die Anmeldung konnte nicht best\u00E4tigt werden. Bitte erneut versuchen."));
            }
        }
        finally {
            window.clearTimeout(deadline);
            if (alive.current && !controller.signal.aborted)
                setPending(false);
        }
    };
    const logout = async () => {
        if (pending)
            return;
        abortProtectedRequests();
        current.current?.abort();
        setPhase('signingout');
        setUsername('');
        setPassword('');
        setPending(true);
        setError('');
        setNotice('');
        signoutUnconfirmed.current = true;
        logoutIntentStored.current = rememberLogoutIntent();
        broadcast('logout-intent');
        const controller = new AbortController();
        current.current = controller;
        const deadline = window.setTimeout(() => {
            controller.abort();
            if (alive.current && current.current === controller) {
                setPending(false);
                setPhase('blocked');
                setError(logoutIntentStored.current ? t("Abmeldung konnte nicht best\u00E4tigt werden. Bitte erneut abmelden.") : t("Abmeldung unbest\u00E4tigt; die Browsersperre konnte nicht gespeichert werden. Bitte alle Tabs schlie\u00DFen und erneut abmelden."));
            }
        }, 15000);
        try {
            const next = await mutate<OperatorSession>('/auth/logout', {}, controller.signal);
            if (!alive.current || controller.signal.aborted)
                return;
            if (!validOperatorSession(next) || next.authenticated || next.mode !== 'lan')
                throw new APIError(t("Abmeldung nicht best\u00E4tigt."));
            signoutUnconfirmed.current = false;
            clearLogoutIntent();
            setNotice(t("Abgemeldet."));
            install(next);
            broadcast('session-ended');
        }
        catch (err) {
            if (alive.current && !controller.signal.aborted) {
                if (err instanceof APIError && err.status === 401) {
                    signoutUnconfirmed.current = false;
                    lock(t("Sitzung abgelaufen. Bitte erneut anmelden."));
                }
                else {
                    setPhase('blocked');
                    setError(logoutIntentStored.current ? t("Abmeldung konnte nicht best\u00E4tigt werden. Bitte erneut abmelden.") : t("Abmeldung unbest\u00E4tigt; die Browsersperre konnte nicht gespeichert werden. Bitte alle Tabs schlie\u00DFen und erneut abmelden."));
                }
            }
        }
        finally {
            window.clearTimeout(deadline);
            if (alive.current && !controller.signal.aborted)
                setPending(false);
        }
    };
    if (phase === 'ready' && session && (!session.authenticationRequired || session.authenticated))
        return <OperatorContext.Provider value={{ insecureTestMode, mode: session.mode, authenticated: session.authenticated, loginMode: session.loginMode ?? 'shared', actorId: session.actorId ?? null, capabilities: session.capabilities ?? (session.authenticated ? ['read'] : []), hasExplicitMetadata: session.loginMode !== undefined && session.actorId !== undefined && session.capabilities !== undefined, expiresAt: session.expiresAt, logout: () => void logout(), theme, setTheme }}><div key={privateEpoch} ref={privateView} className="auth-private-view" style={checkingAccess ? { visibility: 'hidden' } : undefined} inert={checkingAccess ? true : undefined} aria-hidden={checkingAccess ? true : undefined}>{children}</div>{checkingAccess && <div className="auth-resume-check" role="status"><LoaderCircle className="spin" size={20}/>{t("Zugriff wird erneut gepr\u00FCft \u2026")}</div>}</OperatorContext.Provider>;
    return <div className="auth-shell"><header className="auth-header"><div className="auth-brand"><Logo /><span>Tracebolt</span></div><div className="auth-header-actions"><LanguageSelector /><button className="icon-button" aria-label={theme === 'light' ? t("Dunkles Design aktivieren") : t("Helles Design aktivieren")} onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>{theme === 'light' ? <Moon size={18}/> : <Sun size={18}/>}</button></div></header>{insecureTestMode && <TransportWarning />}<main className="auth-main"><section className="auth-card"><div className="auth-symbol"><LockKeyhole size={24}/></div><div className="eyebrow">{t("OPERATORZUGANG")}</div><h1>{phase === 'loading' ? t("Zugriff wird gepr\u00FCft") : phase === 'signingout' ? t("Wird abgemeldet") : phase === 'blocked' ? t("Zugriff nicht verf\u00FCgbar") : t("Anmelden")}</h1><p className="auth-address"><ShieldCheck size={14}/>{window.location.host}</p>{(phase === 'loading' || phase === 'signingout') ? <div className="auth-loading" role="status"><LoaderCircle className="spin" size={19}/>{phase === 'loading' ? t("Manager-Status wird geladen \u2026") : t("Sitzung wird beendet \u2026")}</div> : <>{notice && <div className="auth-notice" role="status"><Info size={15}/><span>{ui(notice)}</span></div>}{error && <div className="auth-error" role="alert"><TriangleAlert size={16}/><span>{ui(error)}</span></div>}{phase === 'signin' ? <form onSubmit={event => void login(event)}>{loginMode === 'named' && <label className="form-field"><span>{t("Operator-Benutzername")}</span><input aria-label={t("Operator-Benutzername")} type="text" autoComplete="username" autoCapitalize="none" spellCheck={false} value={username} onChange={event => setUsername(event.target.value)} disabled={pending} maxLength={64} autoFocus/></label>}<label className="form-field"><span>{t("Operator-Passwort")}</span><input aria-label={t("Operator-Passwort")} type="password" autoComplete="off" spellCheck={false} value={password} onChange={event => setPassword(event.target.value)} disabled={pending} maxLength={1024} placeholder={t("Vom Administrator vergeben")} autoFocus={loginMode === 'shared'}/></label>{password && noteBytes(password) < 12 && <p className="auth-field-hint">{t("Passwort ist zu kurz.")}</p>}{noteBytes(password) > 1024 && <p className="auth-field-hint">{t("Maximal 1024 UTF-8-Bytes.")}</p>}<button className="button primary auth-submit" type="submit" disabled={pending || noteBytes(password) < 12 || noteBytes(password) > 1024 || (loginMode === 'named' && (username.trim().length === 0 || username.length > 64))}>{pending ? <LoaderCircle className="spin" size={16}/> : <ArrowRight size={16}/>}{t("Anmelden")}</button></form> : <button className="button auth-retry" onClick={() => signoutUnconfirmed.current ? void logout() : void bootstrap()} disabled={pending}>{signoutUnconfirmed.current ? <LogOut size={15}/> : <RefreshCw size={15}/>} {signoutUnconfirmed.current ? t("Erneut abmelden") : t("Status erneut pr\u00FCfen")}</button>}{phase === 'blocked' && signoutUnconfirmed.current && <><button className="text-button auth-check-session" onClick={() => { setPhase('signin'); setError(''); setNotice(t("Bitte frisch anmelden.")); }}>{t("Neu anmelden")}</button><button className="text-button auth-check-session" onClick={() => void bootstrap()}>{t("Zugriffsstatus pr\u00FCfen")}</button></>}</>}</section><p className="auth-footnote"><LockKeyhole size={13}/>{t("Gesch\u00FCtzte Daten werden erst nach best\u00E4tigtem Zugriff geladen.")}</p></main></div>;
}
export function OperatorAccount() { const operator = useOperator(); return <div className="operator"><div className="operator-avatar">{operator?.mode === 'lan' ? 'OP' : 'LO'}</div><span><strong>{operator?.mode === 'lan' ? t("Operator") : t("Local Operator")}</strong><small title={operator?.expiresAt ? t("Sitzungsende: {0}", { "0": fullDate(operator.expiresAt) }) : undefined}>{operator?.authenticated ? t("LAN \u00B7 Sitzung aktiv") : t("Lokaler Zugriff \u00B7 v0.1.0")}</small></span>{operator?.mode === 'lan' && operator.authenticated ? <button className="icon-button operator-logout" aria-label={t("Abmelden")} title={t("Abmelden")} onClick={operator.logout}><LogOut size={17}/></button> : <ShieldCheck size={17}/>}</div>; }

export function TransportWarning(){return <div className="transport-warning" role="note"><TriangleAlert size={17} aria-hidden="true"/><div><strong>{t("Unverschlüsselter LAN-Test")}</strong><span>{t("Passwörter und Daten sind im Netzwerk mitlesbar. Nur in einer isolierten Testumgebung verwenden.")}</span></div></div>;}
