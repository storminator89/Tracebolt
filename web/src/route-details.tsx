import './route-detail-styles';
import { Component, createContext, lazy, Suspense, useContext, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowLeft, RefreshCw, TriangleAlert } from 'lucide-react';
import { useOperator } from './auth';
import { Loading } from './components';
import { useLocale } from './i18n';

// Stable wrappers share one normal module import. Never cache-bust this URL:
// detail resources include a module-scoped unresolved-action fence.
export const DeviceDetail = lazy(() => import('./details').then(module => ({ default: module.DeviceDetail })));
export const CaseDetail = lazy(() => import('./details').then(module => ({ default: module.CaseDetail })));

// Keep this data-free lifecycle state above AuthBoundary so route, actor and
// private-view replacement cannot forget a suspension during a pending import.
const DetailLifecycleContext = createContext(false);
export function DetailLoadingLifecycle({ children }: { children: ReactNode }) {
    const [suspended, setSuspended] = useState(() => document.visibilityState === 'hidden');
    useLayoutEffect(() => {
        const suspend = () => setSuspended(true);
        const resume = () => { if (document.visibilityState !== 'hidden') setSuspended(false); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : resume();
        window.addEventListener('blur', suspend);
        window.addEventListener('pagehide', suspend);
        window.addEventListener('focus', resume);
        window.addEventListener('pageshow', resume);
        document.addEventListener('visibilitychange', visibility);
        return () => {
            window.removeEventListener('blur', suspend);
            window.removeEventListener('pagehide', suspend);
            window.removeEventListener('focus', resume);
            window.removeEventListener('pageshow', resume);
            document.removeEventListener('visibilitychange', visibility);
        };
    }, []);
    return <DetailLifecycleContext.Provider value={suspended}>{children}</DetailLifecycleContext.Provider>;
}

type BoundaryProps = { children: ReactNode; onBack: () => void; backLabel: string };

function RouteFallback({ onBack, backLabel, failed = false }: Omit<BoundaryProps, 'children'> & { failed?: boolean }) {
    const [locale] = useLocale();
    const back = useRef(onBack);
    back.current = onBack;
    useLayoutEffect(() => {
        const key = (event: KeyboardEvent) => {
            if (event.key === 'Escape' && !event.defaultPrevented && !document.querySelector('[role="dialog"]')) {
                event.preventDefault(); back.current();
            }
        };
        document.addEventListener('keydown', key);
        return () => document.removeEventListener('keydown', key);
    }, []);
    return <>
        <button className="back-link" onClick={onBack}><ArrowLeft size={15}/>{backLabel}</button>
        {failed ? <div className="panel detail-error" role="alert">
            <TriangleAlert size={24}/>
            <h2>{locale === 'de' ? 'Ansicht konnte nicht geladen werden' : 'View could not be loaded'}</h2>
            <p>{locale === 'de' ? 'Die Seite neu laden, um es erneut zu versuchen.' : 'Reload the page to try again.'}</p>
            <button className="button" onClick={() => window.location.reload()}><RefreshCw size={15}/>{locale === 'de' ? 'Seite neu laden' : 'Reload page'}</button>
        </div> : <Loading label={locale === 'de' ? 'Ansicht wird geladen …' : 'Loading view …'}/>}
    </>;
}

class DetailErrorBoundary extends Component<BoundaryProps, { failed: boolean }> {
    state = { failed: false };
    static getDerivedStateFromError() { return { failed: true }; }
    render() {
        // Rejected imports are cached by React/browser. Only a deliberate full
        // page reload retries; route changes never replay an operation.
        return this.state.failed ? <RouteFallback onBack={this.props.onBack} backLabel={this.props.backLabel} failed/> : this.props.children;
    }
}

function DetailCommit({ children, onCommit }: { children: ReactNode; onCommit: () => void }) {
    useLayoutEffect(onCommit, [onCommit]);
    return children;
}

/** Must be keyed by the current route. A pending import cannot mount private
 * readers after a missed suspension or while auth is being revalidated. Once
 * mounted, existing detail resources own their normal clearing/resume lifecycle. */
export function RouteDetailBoundary({ children, onBack, backLabel }: BoundaryProps) {
    const operator = useOperator();
    const suspended = useContext(DetailLifecycleContext);
    const mounted = useRef(false);
    const committed = useRef(() => { mounted.current = true; }).current;
    const fallback = <RouteFallback onBack={onBack} backLabel={backLabel}/>;
    if (!mounted.current && (suspended || operator?.checkingAccess)) return fallback;
    return <DetailErrorBoundary onBack={onBack} backLabel={backLabel}>
        <Suspense fallback={fallback}><DetailCommit onCommit={committed}>{children}</DetailCommit></Suspense>
    </DetailErrorBoundary>;
}
