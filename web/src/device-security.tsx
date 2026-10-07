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
        title: 'Security', openPackages: 'Open Packages', openUpdates: 'Open Updates',
        legacy: 'Legacy diagnostics', source: 'Diagnostic source', current: 'Current CVE warnings', coverage: 'Legacy bounded inventory evidence', metadata: 'Legacy v2 source-package metadata',
        legacyNote: 'Older samples have separate coverage and may be unavailable. Their counts are not full inventory totals.',
        access: 'Authenticated LAN operator access is required.',
    },
    de: {
        title: 'Sicherheit', openPackages: 'Pakete öffnen', openUpdates: 'Updates öffnen',
        legacy: 'Ältere Diagnosequellen', source: 'Diagnosequelle', current: 'Aktuelle CVE-Warnungen', coverage: 'Ältere begrenzte Inventarbelege', metadata: 'Ältere v2-Quellpaket-Metadaten',
        legacyNote: 'Ältere Stichproben haben eine eigene Abdeckung und können fehlen. Ihre Zahlen sind keine vollständigen Inventarzahlen.',
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
        <h2 className="sr-only" id={`${id}-title`}>{labels.title}</h2>
        <div className="device-security-sources">
            <button type="button" className="button" onClick={onOpenPackages}><Boxes size={17}/>{labels.openPackages}<ArrowRight size={15}/></button>
            <button type="button" className="button" onClick={onOpenUpdates}><RefreshCw size={17}/>{labels.openUpdates}<ArrowRight size={15}/></button>
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
