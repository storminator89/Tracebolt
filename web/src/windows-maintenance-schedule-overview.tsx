import { useLocale } from './i18n';
import { WindowsLocalTime } from './windows-local-time';
import { windowsMaintenanceScheduleState } from './windows-maintenance-schedule-types';
import type { WindowsMaintenanceScheduleTarget, WindowsMaintenanceScheduleView } from './windows-maintenance-schedule-types';

const copy = {
    en: {
        title: 'Upcoming and active schedules',
        scope: 'Fleet-wide scheduled windows only. Immediate maintenance is shown separately. Device search and group filters do not narrow this list.',
        pending: 'Upcoming', active: 'Active', unknown: 'Refresh status',
        empty: 'No upcoming or active scheduled windows in this snapshot.',
        refresh: 'A scheduled start has passed since this read. Refresh schedule to confirm its current state.',
        checked: 'Manager snapshot', starts: 'Starts', ends: 'Ends', view: 'View window',
        all: 'All Windows checks', contact: 'Contact', cpu: 'CPU percentage', disk: 'System-volume capacity', memory: 'Physical RAM percentage', service: 'Selected-service checks',
        uncertain: 'A change is unconfirmed. These are saved values, not confirmation of that change.',
    },
    de: {
        title: 'Bevorstehende und aktive Wartungspläne',
        scope: 'Nur geplante Fenster der gesamten Flotte. Sofortige Wartung wird separat angezeigt. Gerätesuche und Gruppenfilter grenzen diese Liste nicht ein.',
        pending: 'Bevorstehend', active: 'Aktiv', unknown: 'Status aktualisieren',
        empty: 'Keine bevorstehenden oder aktiven geplanten Fenster in diesem Stand.',
        refresh: 'Ein geplanter Start ist seit diesem Abruf verstrichen. Wartungsplan aktualisieren, um den aktuellen Zustand zu bestätigen.',
        checked: 'Manager-Stand', starts: 'Beginn', ends: 'Ende', view: 'Fenster ansehen',
        all: 'Alle Windows-Prüfungen', contact: 'Kontakt', cpu: 'CPU-Prozentwert', disk: 'Kapazität des Systemvolumes', memory: 'Physischer RAM-Prozentwert', service: 'Prüfungen ausgewählter Dienste',
        uncertain: 'Eine Änderung ist unbestätigt. Dies sind gespeicherte Werte, keine Bestätigung dieser Änderung.',
    },
};

// Inputs are the existing validated, currently authorized schedule projection.
// UTC fractional seconds are padded only for ordering, never for presentation.
const timeKey = (time: string) => time.slice(0, 19) + (time.slice(19, -1).replace(/^\./, '')).padEnd(9, '0');
export function scheduledMaintenanceOverviewRows(view: WindowsMaintenanceScheduleView, age: number) {
    return view.targets.flatMap(target => {
        const window = target.windows[0];
        if (!window) return [];
        const state = windowsMaintenanceScheduleState(window, view.serverNow, age);
        return state === 'pending' || state === 'active' || state === 'unknown' ? [{ target, window, state }] : [];
    }).sort((a, b) => {
        const rank = { unknown: 0, active: 1, pending: 2 };
        const order = rank[a.state] - rank[b.state];
        const at = timeKey(a.state === 'active' ? a.window.endsAt : a.window.startsAt);
        const bt = timeKey(b.state === 'active' ? b.window.endsAt : b.window.startsAt);
        return order || (at < bt ? -1 : at > bt ? 1 : a.target.key < b.target.key ? -1 : a.target.key > b.target.key ? 1 : 0);
    });
}

/** Presentation of this panel's response only: no reader, persistence or action. */
export function WindowsMaintenanceScheduleOverview({ view, age, label, isUncertain, disabled, onSelect }: {
    view: WindowsMaintenanceScheduleView;
    age: number;
    label: (deviceId: string) => string;
    isUncertain: (target: WindowsMaintenanceScheduleTarget) => boolean;
    disabled: boolean;
    onSelect: (key: string) => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const rows = scheduledMaintenanceOverviewRows(view, age);
    return <section className="windows-maintenance-schedule-overview" aria-label={c.title}>
        <h3>{c.title}</h3>
        <p>{c.scope}</p>
        <p>{c.checked}: <WindowsLocalTime value={view.serverNow} locale={locale} exact/></p>
        <p className="windows-maintenance-schedule-counts">{(['active', 'pending', 'unknown'] as const).map(state => <span key={state}>{c[state]}: {rows.filter(row => row.state === state).length}</span>)}</p>
        {rows.length === 0 ? <p>{c.empty}</p> : <ul className="windows-maintenance-schedule-list" aria-label={c.title} tabIndex={0}>
            {rows.map(({ target, window, state }) => <li key={`${target.key}:${window.id}`}>
                <div className="windows-maintenance-label"><strong>{label(target.deviceId)}</strong><span className="windows-maintenance-identity">{target.deviceId}</span><span>{c[target.domain]}</span></div>
                <div className="windows-maintenance-label-state">
                    <span className={`windows-maintenance-badge is-${state}`}>{c[state]}</span>
                    <span>{c.starts}: <WindowsLocalTime value={window.startsAt} locale={locale}/></span>
                    <span>{c.ends}: <WindowsLocalTime value={window.endsAt} locale={locale}/></span>
                    {state === 'unknown' && <p>{c.refresh}</p>}
                    {isUncertain(target) && <p>{c.uncertain}</p>}
                    <button type="button" className="text-button" disabled={disabled} aria-label={`${c.view}: ${label(target.deviceId)} · ${target.deviceId} · ${c[target.domain]}`} onClick={() => onSelect(target.key)}>{c.view}</button>
                </div>
            </li>)}
        </ul>}
    </section>;
}
