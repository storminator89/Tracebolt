import { useId, useState } from 'react';
import { ArrowRight, Boxes, RefreshCw } from 'lucide-react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { LinuxCVEPanel } from './linux-cve';
import { SecurityCoveragePanel } from './security-coverage';
import { PackageObservationsPanel } from './package-observations';
import './device-security.css';

type Source = 'current' | 'legacy-coverage' | 'legacy-packages';
const copy = {
    en: {
        title: 'Security', subtitle: 'Installed packages, cached update candidates and CVE warnings',
        packages: 'Installed packages', packageNote: 'Complete received dpkg inventory, with its capture time and coverage.', openPackages: 'Open Packages',
        updates: 'Cached update candidates', updateNote: 'Known candidates from local APT metadata, with its age and comparison gaps.', openUpdates: 'Open Updates',
        legacy: 'Legacy diagnostics', source: 'Diagnostic source', current: 'Current CVE warnings', coverage: 'Legacy bounded inventory evidence', metadata: 'Legacy v2 source-package metadata',
        legacyNote: 'These older sources have separate coverage and can be unavailable while Packages or CVE warnings work. Their sample counts are not complete inventory totals.',
        access: 'Authenticated LAN operator access is required.',
    },
    de: {
        title: 'Sicherheit', subtitle: 'Installierte Pakete, bekannte Update-Kandidaten und CVE-Warnungen',
        packages: 'Installierte Pakete', packageNote: 'Vollständig empfangenes dpkg-Inventar mit Erfassungszeit und Abdeckung.', openPackages: 'Pakete öffnen',
        updates: 'Bekannte Update-Kandidaten', updateNote: 'Kandidaten aus lokalen APT-Metadaten mit deren Alter und Vergleichslücken.', openUpdates: 'Updates öffnen',
        legacy: 'Ältere Diagnosequellen', source: 'Diagnosequelle', current: 'Aktuelle CVE-Warnungen', coverage: 'Ältere begrenzte Inventarbelege', metadata: 'Ältere v2-Quellpaket-Metadaten',
        legacyNote: 'Diese älteren Quellen haben eine eigene Abdeckung und können fehlen, obwohl Pakete oder CVE-Warnungen verfügbar sind. Ihre Stichprobenzahlen sind keine vollständigen Inventarzahlen.',
        access: 'Ein authentifizierter LAN-Operator-Zugang ist erforderlich.',
    },
};

/** The primary Security and CVE tabs share one authoritative reader. Legacy
 * sources are opt-in and mutually exclusive, never parallel background reads. */
export function DeviceSecurityWorkspace({ deviceId, sessionKey, onOpenPackages, onOpenUpdates }: { deviceId: string; sessionKey?: string | number; onOpenPackages: () => void; onOpenUpdates: () => void }) {
    const operator = useOperator(), [locale] = useLocale();
    if (operator?.mode !== 'lan' || !operator.authenticated) return <p>{copy[locale].access}</p>;
    return <DeviceSecuritySession key={JSON.stringify([deviceId, sessionKey ?? null, operator.expiresAt ?? null])} deviceId={deviceId} sessionKey={sessionKey} onOpenPackages={onOpenPackages} onOpenUpdates={onOpenUpdates}/>;
}

function DeviceSecuritySession({ deviceId, sessionKey, onOpenPackages, onOpenUpdates }: { deviceId: string; sessionKey?: string | number; onOpenPackages: () => void; onOpenUpdates: () => void }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId(), [source, setSource] = useState<Source>('current');
    return <section className="device-security-workspace" aria-labelledby={`${id}-title`}>
        <header className="device-security-heading"><h2 id={`${id}-title`}>{labels.title}</h2><p>{labels.subtitle}</p></header>
        <div className="device-security-sources">
            <article><h3><Boxes size={17}/>{labels.packages}</h3><p>{labels.packageNote}</p><button type="button" className="button" onClick={onOpenPackages}>{labels.openPackages}<ArrowRight size={15}/></button></article>
            <article><h3><RefreshCw size={17}/>{labels.updates}</h3><p>{labels.updateNote}</p><button type="button" className="button" onClick={onOpenUpdates}>{labels.openUpdates}<ArrowRight size={15}/></button></article>
        </div>
        <details className="device-legacy-sources" onToggle={event => { if (!event.currentTarget.open) setSource('current'); }}>
            <summary>{labels.legacy}</summary><p>{labels.legacyNote}</p>
            <label htmlFor={`${id}-source`}>{labels.source}</label><select id={`${id}-source`} value={source} onChange={event => setSource(event.target.value as Source)}>
                <option value="current">{labels.current}</option><option value="legacy-coverage">{labels.coverage}</option><option value="legacy-packages">{labels.metadata}</option>
            </select>
        </details>
        {source === 'current' && <LinuxCVEPanel deviceId={deviceId} sessionKey={sessionKey}/>}
        {source === 'legacy-coverage' && <SecurityCoveragePanel deviceId={deviceId} sessionKey={sessionKey}/>}
        {source === 'legacy-packages' && <PackageObservationsPanel deviceId={deviceId} sessionKey={sessionKey}/>}
    </section>;
}
