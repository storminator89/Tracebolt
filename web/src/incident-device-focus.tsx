import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Filter, Monitor, X } from 'lucide-react';
import { AUTH_REQUIRED_EVENT } from './api';
import { useLocale } from './i18n';
import type { QueueRow } from './incident-work-queue-model';
import { incidentQueueLifecycleCounts } from './incident-work-queue-model';
import { incidentLifecycle } from './incident-timeline-model';
import './incident-device-focus.css';

export function incidentDeviceKey(row: QueueRow): string {
    return JSON.stringify([row.platform, row.item.deviceId]);
}

/** Group only admitted rows, preserving distinct source/domain episodes and
 * their existing order. A device name is presentation, never an identity. */
export function incidentDeviceGroups(rows: QueueRow[]) {
    const grouped = new Map<string, QueueRow[]>();
    for (const row of rows) {
        const key = incidentDeviceKey(row);
        const group = grouped.get(key);
        if (group) group.push(row); else grouped.set(key, [row]);
    }
    return [...grouped].map(([key, episodes]) => ({
        key, platform: episodes[0].platform, deviceId: episodes[0].item.deviceId,
        total: episodes.length, outcomes: incidentQueueLifecycleCounts(episodes),
        unseenOpen: episodes.filter(row => row.seenAt === null && incidentLifecycle(row) === 'open').length,
    }));
}

type DeviceGroup = ReturnType<typeof incidentDeviceGroups>[number];

/** Only the exact choice is retained. All private presentation is re-derived
 * from the caller's current guarded rows, including during the reset render. */
export function useIncidentDeviceFocus(rows: QueueRow[], scope: string, locked: boolean) {
    const groups = incidentDeviceGroups(locked ? [] : rows);
    const [choice, setChoice] = useState({ scope, key: '' });
    const selected = choice.scope === scope && !locked ? groups.find(group => group.key === choice.key) ?? null : null;
    const selectedKey = selected?.key ?? '';
    useEffect(() => {
        setChoice(current => current.scope === scope && current.key === selectedKey ? current : { scope, key: selectedKey });
    }, [scope, selectedKey]);
    useEffect(() => {
        const clear = () => setChoice({ scope, key: '' });
        const hidden = () => { if (document.visibilityState !== 'visible') clear(); };
        window.addEventListener('blur', clear);
        window.addEventListener('pagehide', clear);
        window.addEventListener('hashchange', clear);
        window.addEventListener('popstate', clear);
        window.addEventListener(AUTH_REQUIRED_EVENT, clear);
        document.addEventListener('visibilitychange', hidden);
        return () => {
            window.removeEventListener('blur', clear);
            window.removeEventListener('pagehide', clear);
            window.removeEventListener('hashchange', clear);
            window.removeEventListener('popstate', clear);
            window.removeEventListener(AUTH_REQUIRED_EVENT, clear);
            document.removeEventListener('visibilitychange', hidden);
        };
    }, [scope]);
    const select = (key: string) => setChoice({ scope, key: !locked && groups.some(group => group.key === key) ? key : '' });
    return { groups, selected, select, rows: selected ? rows.filter(row => incidentDeviceKey(row) === selected.key) : rows };
}

const copy = {
    en: {
        title: 'Devices on loaded pages', note: 'Counts use the current page filters. Separate episodes stay separate; this is not device health or full history.',
        none: 'No devices in the matching loaded incidents.', episodes: 'Episodes', open: 'Open', recovered: 'Check recovered / reports resumed', stopped: 'Closed without confirmed recovery', unseen: 'Open and not seen',
        focus: 'Focus device', clear: 'Show all matching devices', active: 'Device focus', health: 'Open device Health', unnamed: 'Unnamed device',
    },
    de: {
        title: 'Geräte auf geladenen Seiten', note: 'Die Anzahlen folgen den aktuellen Seitenfiltern. Episoden bleiben getrennt; dies ist weder der Gerätezustand noch die vollständige Historie.',
        none: 'Keine Geräte in den passenden geladenen Vorfällen.', episodes: 'Episoden', open: 'Offen', recovered: 'Prüfung erholt / Berichte fortgesetzt', stopped: 'Ohne bestätigte Erholung geschlossen', unseen: 'Offen und ungesehen',
        focus: 'Gerät eingrenzen', clear: 'Alle passenden Geräte zeigen', active: 'Gerätefokus', health: 'Geräte-Health öffnen', unnamed: 'Unbenanntes Gerät',
    },
};

export function IncidentDeviceFocus({ groups, selected, names, onSelect }: {
    groups: DeviceGroup[]; selected: DeviceGroup | null; names: ReadonlyMap<string, string>; onSelect: (key: string) => void;
}) {
    const [locale] = useLocale(), c = copy[locale], summaryRef = useRef<HTMLElement>(null), detailsRef = useRef<HTMLDetailsElement>(null);
    const name = (group: DeviceGroup) => names.get(`${group.platform}:${group.deviceId}`)?.trim() || c.unnamed;
    const label = (group: DeviceGroup) => `${name(group)} · ${group.platform === 'linux' ? 'Linux' : 'Windows'} · ${group.deviceId}`;
    return <section className="panel incident-device-focus" aria-label={c.title}>
        {selected && <div className="incident-device-focus-active">
            <p aria-live="polite"><Filter size={15} aria-hidden="true"/><strong>{c.active}: {label(selected)}</strong></p>
            <div className="incident-device-focus-actions">
                <button type="button" className="button small" onClick={() => { summaryRef.current?.focus(); onSelect(''); }}><X size={14} aria-hidden="true"/>{c.clear}</button>
                <a className="text-button" href={`#/devices/${encodeURIComponent(selected.deviceId)}/health`}>{c.health}<ArrowRight size={14} aria-hidden="true"/></a>
            </div>
        </div>}
        <details ref={detailsRef}>
            <summary ref={summaryRef}><Monitor size={17} aria-hidden="true"/>{c.title}<span>{groups.length}</span></summary>
            <p className="investigations-note">{c.note}</p>
            {groups.length ? <ul className="incident-device-focus-list">{groups.map(group => <li key={group.key}>
                <h3>{name(group)}</h3><p className="incident-device-focus-identity">{group.platform === 'linux' ? 'Linux' : 'Windows'} · {group.deviceId}</p>
                <p>{c.episodes}: {group.total}</p>
                <dl>{([[c.open, group.outcomes.open], [c.unseen, group.unseenOpen], [c.recovered, group.outcomes.recovered], [c.stopped, group.outcomes.stopped]] as const).map(([title, count]) => <div key={title}><dt>{title}</dt><dd>{count}</dd></div>)}</dl>
                <button type="button" className="button small" aria-pressed={selected?.key === group.key} aria-label={`${c.focus}: ${label(group)}`} onClick={() => { if (detailsRef.current) detailsRef.current.open = false; summaryRef.current?.focus(); onSelect(group.key); }}><Filter size={14} aria-hidden="true"/>{c.focus}</button>
            </li>)}</ul> : <p>{c.none}</p>}
        </details>
    </section>;
}
