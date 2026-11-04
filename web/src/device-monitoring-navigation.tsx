import { Activity, ArrowRight, ListChecks } from 'lucide-react';
import { useLocale } from './i18n';
import './device-monitoring-navigation.css';

const copy = {
    en: {
        title: 'Monitoring',
        health: 'Health & history',
        healthDetail: 'Agent contact, storage, selected services and incident history.',
        healthAction: 'Open Health',
        processes: 'Processes & watches',
        processesDetail: 'Complete process snapshots and optional exact-name watches.',
        processesAction: 'Open Processes',
        scope: 'Enabled checks and their current status are shown in each view. Opening a view does not enable monitoring.',
    },
    de: {
        title: 'Überwachung',
        health: 'Health & Verlauf',
        healthDetail: 'Agent-Kontakt, Speicher, ausgewählte Dienste und Vorfallsverlauf.',
        healthAction: 'Health öffnen',
        processes: 'Prozesse & Überwachung',
        processesDetail: 'Vollständige Prozessaufnahmen und optionale Überwachung exakter Namen.',
        processesAction: 'Prozesse öffnen',
        scope: 'Aktivierte Prüfungen und ihr aktueller Status stehen in der jeweiligen Ansicht. Das Öffnen aktiviert keine Überwachung.',
    },
};

/** Navigation only. Do not fetch policy views or infer opt-in, coverage or health
 * from a platform, inventory snapshot or unrelated source's status. */
export function DeviceMonitoringNavigation({ onOpenHealth, onOpenProcesses }: {
    onOpenHealth: () => void;
    onOpenProcesses?: () => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const items = [
        { title: c.health, detail: c.healthDetail, action: c.healthAction, icon: Activity, onOpen: onOpenHealth },
        ...(onOpenProcesses ? [{ title: c.processes, detail: c.processesDetail, action: c.processesAction, icon: ListChecks, onOpen: onOpenProcesses }] : []),
    ];
    return <section className="device-monitoring-navigation" aria-label={c.title}>
        <h2>{c.title}</h2>
        <div className="device-monitoring-links">
            {items.map(({ title, detail, action, icon: Icon, onOpen }) => <button key={title} type="button" className="device-monitoring-link" onClick={onOpen} aria-label={action}>
                <Icon size={18} aria-hidden="true"/>
                <span className="device-monitoring-text"><strong>{title}</strong><span>{detail}</span><span className="device-monitoring-action">{action}<ArrowRight size={13} aria-hidden="true"/></span></span>
            </button>)}
        </div>
        <p>{c.scope}</p>
    </section>;
}
