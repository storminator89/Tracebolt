import { useId } from 'react';
import { ListFilter } from 'lucide-react';
import type { WindowsInventorySnapshot } from './windows-inventory-types';
import type { WindowsServiceStartup } from './windows-service-startup-types';
import './windows-service-triage.css';

const filters = ['all', 'stopped', 'transitioning', 'automatic-stopped', 'startup-unknown'] as const;
export type ServiceTriageFilter = typeof filters[number];
type ServiceTriageCounts = Record<ServiceTriageFilter, Set<number>>;
const copy = {
    en: {
        heading: 'Review captured services', all: 'All captured', stopped: 'Stopped', transitioning: 'In transition',
        'automatic-stopped': 'Automatic + stopped', 'startup-unknown': 'Startup unknown',
        scope: 'Counts cover captured rows before the text filter. Missing services are not searched.',
        automatic: 'Automatic startup and stopped state were captured separately. This is not proof of a fault or failed boot start. Delayed or triggered starts may be normal.',
        unknown: 'Startup mode was not captured or is denied, unavailable or unknown. These rows do not establish manual or disabled startup.',
    },
    de: {
        heading: 'Erfasste Dienste prüfen', all: 'Alle erfassten', stopped: 'Gestoppt', transitioning: 'Im Übergang',
        'automatic-stopped': 'Automatisch + gestoppt', 'startup-unknown': 'Starttyp unbekannt',
        scope: 'Zahlen gelten für erfasste Zeilen vor dem Textfilter. Fehlende Dienste werden nicht durchsucht.',
        automatic: 'Automatischer Starttyp und gestoppter Zustand wurden getrennt erfasst. Das belegt weder einen Fehler noch einen fehlgeschlagenen Systemstart. Verzögerte oder triggerbasierte Starts können normal sein.',
        unknown: 'Der Starttyp wurde nicht erfasst oder ist verweigert, nicht verfügbar oder unbekannt. Diese Zeilen belegen weder einen manuellen noch einen deaktivierten Starttyp.',
    },
};
/** Local review only. Keep original source ordinals, including duplicate names.
 * The existing resource parser validates the exact row digest/order before admission.
 * PID/name matches never bind metadata, and triage never re-admits raw responses. */
export function capturedServiceTriage(snapshot: WindowsInventorySnapshot, startup: WindowsServiceStartup | null): ServiceTriageCounts {
    const result: ServiceTriageCounts = { all: new Set(), stopped: new Set(), transitioning: new Set(), 'automatic-stopped': new Set(), 'startup-unknown': new Set() };
    const bound = startup?.generationId === snapshot.generationId && startup.requestedCount === snapshot.services.rows.length;
    const metadata = new Map(bound ? startup.rows.map(row => [row.serviceIndex, row]) : []);
    snapshot.services.rows.forEach((row, index) => {
        result.all.add(index);
        if (row.state === 'stopped') result.stopped.add(index);
        if (['start_pending', 'stop_pending', 'continue_pending', 'pause_pending'].includes(row.state)) result.transitioning.add(index);
        const mode = metadata.get(index);
        if (!mode || mode.startupQuality !== 'observed' || mode.startupMode === null) result['startup-unknown'].add(index);
        if (row.state === 'stopped' && mode?.startupQuality === 'observed' && mode.startupMode === 'automatic') result['automatic-stopped'].add(index);
    });
    return result;
}
export function WindowsServiceTriage({ counts, selected, locale, onSelect }: { counts: ServiceTriageCounts; selected: ServiceTriageFilter; locale: 'en' | 'de'; onSelect: (filter: ServiceTriageFilter) => void }) {
    const id = useId(), c = copy[locale];
    return <div className="windows-service-triage">
        <div className="windows-service-triage-heading" id={`${id}-heading`}><ListFilter size={15} aria-hidden="true" focusable="false"/>{c.heading}</div>
        <div role="group" aria-labelledby={`${id}-heading`} aria-describedby={`${id}-scope`} className="windows-service-triage-options">
            {filters.map(filter => <button type="button" className="button small" key={filter} aria-pressed={selected === filter} onClick={() => onSelect(filter)}>{c[filter]} ({counts[filter].size})</button>)}
        </div>
        <p id={`${id}-scope`} className="windows-inventory-exclusions">{c.scope}</p>
        {selected === 'automatic-stopped' && <p className="windows-inventory-exclusions">{c.automatic}</p>}
        {selected === 'startup-unknown' && <p className="windows-inventory-exclusions">{c.unknown}</p>}
    </div>;
}
