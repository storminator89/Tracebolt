import { useId } from 'react';
import { ArrowRight, Boxes, RefreshCw } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { completePackageCopy } from './complete-packages';
import { useCompletePackages } from './complete-packages-resource';
import { completeGenerationVisible, inventoryAge } from './complete-packages-types';
import './software-overview.css';

const copy = {
    en: {
        title: 'Software · complete dpkg inventory', rows: 'Complete dpkg rows', incomplete: 'Incomplete rows',
        open: 'Open Packages', refresh: 'Refresh software overview', historical: 'Historical generation details', details: 'Generation details',
        unavailable: 'No currently available complete generation. A bounded sample or declared transfer count is not a complete software total.',
        scope: 'Installed and incomplete dpkg rows in the agent-visible namespace. Snap, Flatpak and other software sources are not included.',
    },
    de: {
        title: 'Software · vollständiges dpkg-Inventar', rows: 'Vollständige dpkg-Zeilen', incomplete: 'Unvollständige Zeilen',
        open: 'Pakete öffnen', refresh: 'Softwareübersicht aktualisieren', historical: 'Historische Generationsdetails', details: 'Generationsdetails',
        unavailable: 'Derzeit keine vollständige Generation verfügbar. Eine begrenzte Stichprobe oder deklarierte Übertragungszahl ist keine vollständige Softwareanzahl.',
        scope: 'Installierte und unvollständige dpkg-Einträge im für den Agent sichtbaren Namensraum. Snap, Flatpak und andere Softwarequellen sind nicht enthalten.',
    },
};

/** The summary reads the validated generation ledger, never the legacy sample
 * or a page length. Each device/operator session owns fresh private state. */
export function SoftwareOverview({ deviceId, onOpenPackages, sessionKey }: { deviceId: string; onOpenPackages: () => void; sessionKey?: string | number }) {
    const operator = useOperator();
    if (operator?.mode !== 'lan' || !operator.authenticated) return null;
    const identity = JSON.stringify([deviceId, sessionKey ?? null, operator.expiresAt ?? null]);
    return <SoftwareOverviewSession key={identity} deviceId={deviceId} onOpenPackages={onOpenPackages}/>;
}

function SoftwareOverviewSession({ deviceId, onOpenPackages }: { deviceId: string; onOpenPackages: () => void }) {
    const [locale] = useLocale(), labels = copy[locale], facts = completePackageCopy[locale], id = useId();
    const resource = useCompletePackages(deviceId, true), { view } = resource;
    const generation = view?.complete, visible = Boolean(view && completeGenerationVisible(view, resource.elapsed));
    const transferState = view?.transfer?.state === 'pending' && inventoryAge(view.transfer.expiresAt, view.serverNow) <= resource.elapsed ? 'expired' : view?.transfer?.state;
    const number = (value: number) => new Intl.NumberFormat(locale).format(value);
    const field = (label: string, value: string) => <div><dt>{label}</dt><dd>{value}</dd></div>;
    const generationFacts = generation && view && <>
        <dl className="package-facts">
            {field(facts.collected, generation.manifest.collectedAt)}
            {Number.isFinite(resource.elapsed) && field(facts.age, number(Math.floor(Math.max(0, inventoryAge(view.serverNow, generation.manifest.collectedAt) + resource.elapsed) / 60000)))}
        </dl>
        <details className="software-generation-details"><summary>{labels.details}</summary>
            <dl className="package-facts">{field(facts.generation, generation.binding.generationId)}{field(facts.sequence, generation.binding.sequence)}{field(facts.retained, generation.retainedUntil)}</dl>
            <p className="package-note">{facts.retention}</p>
        </details>
    </>;
    return <section className="software-overview package-observations" aria-labelledby={id} aria-busy={resource.loading}>
        <header className="package-heading"><h2 id={id}><Boxes size={18}/>{labels.title}</h2><button className="button small" type="button" disabled={resource.loading || resource.error === 'session'} onClick={resource.refresh}><RefreshCw size={14}/>{labels.refresh}</button></header>
        <p className="package-note">{labels.scope}</p>
        {resource.loading && <p role="status">{resource.recovering ? locale === 'de' ? 'Der Speicher ist ausgelastet. Ein automatischer Leseversuch folgt in 2 Sekunden.' : 'Storage is busy. One automatic read retry in 2 seconds.' : facts.loading}</p>}
        {resource.error && <p role="alert" className="package-error">{facts[resource.error]}</p>}
        <dl className="package-counts software-total">{field(labels.rows, visible && generation ? number(generation.manifest.observedCount) : '—')}{visible && generation && <>{field(facts.installed, number(generation.manifest.installedCount))}{field(labels.incomplete, number(generation.manifest.observedCount - generation.manifest.installedCount))}</>}</dl>
        {view && <>
            <p className="package-status">{view.status === 'available' && !visible ? facts.historical : facts[view.status]}</p>
            {!visible && <p className="package-note">{labels.unavailable}</p>}
            {view.status === 'not_configured' && <p className="package-note">{facts.configure}</p>}
            {visible ? generationFacts : generation && <details className="software-historical"><summary>{labels.historical}</summary><p>{view.status === 'revoked' ? facts.revoked : view.status === 'available' ? facts.expired : facts.unavailable}</p><dl className="package-facts">{field(facts.observed, number(generation.manifest.observedCount))}{field(facts.installed, number(generation.manifest.installedCount))}</dl>{generationFacts}</details>}
            {view.transfer && <section aria-label={facts.transfer}><h3>{facts.transfer}</h3><p>{facts[transferState === 'expired' ? 'transferExpired' : transferState!]}</p><dl className="package-facts">{field(facts.generation, view.transfer.binding.generationId)}{field(facts.sequence, view.transfer.binding.sequence)}{field(facts.accepted, `${number(view.transfer.acceptedRows)} / ${number(view.transfer.declaredRows)}`)}{field(facts.collected, view.transfer.collectedAt)}</dl><p className="package-note">{facts.transferNote}</p></section>}
            {view.failure && <section aria-label={facts.failure}><h3>{facts.failure}</h3><p>{facts[view.failure.reason]}</p><dl className="package-facts">{field(facts.generation, view.failure.generationId)}{field(facts.sequence, view.failure.sequence)}{field(facts.attempted, view.failure.attemptedAt)}</dl></section>}
        </>}
        <button type="button" className="button" disabled={resource.error === 'session'} onClick={onOpenPackages}>{labels.open}<ArrowRight size={15}/></button>
    </section>;
}
