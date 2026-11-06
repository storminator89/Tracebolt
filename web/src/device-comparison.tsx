import { useEffect, useId, useRef, useState } from 'react';
import { ArrowUpRight, Columns3, X } from 'lucide-react';
import { AUTH_REQUIRED_EVENT } from './api';
import { MetricValue, Source, Status } from './components';
import { useLocale } from './i18n';
import { ReportTime, reportTimestamp } from './report-time';
import { emptyFleetIdentity, type FleetIdentityMap } from './fleet-identity-types';
import type { Device, Metric } from './types';
import { fullDate } from './utils';
import './device-comparison.css';

const copy = {
    en: { title: 'Compare devices', scope: 'Loaded inventory only. Observations may come from different times.', choose: 'Choose a device…', slot: 'Device', optional: '(optional)', clear: 'Clear comparison', close: 'Close comparison', empty: 'Choose two or three devices from the current inventory filters.', unavailable: 'Refresh the inventory to compare devices.', fact: 'Inventory field', os: 'Operating system', source: 'Source', report: 'Last recorded report', health: 'Overall health', memory: 'Memory', disk: 'Disk', metricSource: 'Measurement source', noTime: 'Collection time unavailable', open: 'Open device', remove: 'Remove from comparison' },
    de: { title: 'Geräte vergleichen', scope: 'Nur geladenes Inventar. Beobachtungen können aus verschiedenen Zeitpunkten stammen.', choose: 'Gerät auswählen …', slot: 'Gerät', optional: '(optional)', clear: 'Vergleich leeren', close: 'Vergleich schließen', empty: 'Zwei oder drei Geräte aus den aktuellen Inventarfiltern auswählen.', unavailable: 'Inventar aktualisieren, um Geräte zu vergleichen.', fact: 'Inventarangabe', os: 'Betriebssystem', source: 'Quelle', report: 'Letzte erfasste Meldung', health: 'Gesamtzustand', memory: 'Arbeitsspeicher', disk: 'Datenträger', metricSource: 'Messquelle', noTime: 'Erfassungszeit nicht verfügbar', open: 'Gerät öffnen', remove: 'Aus Vergleich entfernen' },
} as const;

/** An in-memory display of the current overview rows. This owns no reader,
 * evidence snapshot, storage, export, assessment or operation authority. */
export function DeviceComparison({ devices, available, onOpen, identities = emptyFleetIdentity }: { devices: Device[]; available: boolean; identities?: FleetIdentityMap; onOpen: (device: Device) => void }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [open, setOpen] = useState(false), [hidden, setHidden] = useState(() => document.hidden), [blocked, setBlocked] = useState(false);
    const button = useRef<HTMLButtonElement>(null);
    useEffect(() => {
        const hide = () => { setOpen(false); setBlocked(true); };
        const visibility = () => { setHidden(document.hidden); if (document.hidden) setOpen(false); };
        document.addEventListener('visibilitychange', visibility);
        window.addEventListener(AUTH_REQUIRED_EVENT, hide); window.addEventListener('pagehide', hide); window.addEventListener('hashchange', hide);
        return () => { document.removeEventListener('visibilitychange', visibility); window.removeEventListener(AUTH_REQUIRED_EVENT, hide); window.removeEventListener('pagehide', hide); window.removeEventListener('hashchange', hide); };
    }, []);
    useEffect(() => { if (!available) setOpen(false); }, [available]);
    const active = available && !hidden && !document.hidden && !blocked;
    return <section className="device-comparison" aria-label={c.title}>
        <div className="device-comparison-heading"><button ref={button} type="button" className="text-button" aria-expanded={active && open} aria-controls={`${id}-content`} disabled={!active} onClick={() => { if (active) setOpen(value => !value); }}><Columns3 size={16} aria-hidden="true"/>{c.title}</button>
            {active && open && <button type="button" className="icon-button" title={c.close} aria-label={c.close} onClick={() => { setOpen(false); button.current?.focus(); }}><X size={16} aria-hidden="true"/></button>}
        </div>
        {!active && !hidden && <p role="status">{c.unavailable}</p>}
        <div id={`${id}-content`}>{active && open && <ComparisonContent devices={devices} identities={identities} onOpen={onOpen}/>}</div>
    </section>;
}

function ComparisonContent({ devices, identities, onOpen }: { devices: Device[]; identities: FleetIdentityMap; onOpen: (device: Device) => void }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [selection, setSelection] = useState(['', '', '']);
    const selectors = useRef<(HTMLSelectElement | null)[]>([]);
    // Store only IDs. Removed/filtered rows disappear immediately and cannot
    // silently return selected when the filter later changes.
    const ids = new Set(devices.map(device => device.id));
    const selected = selection.map(value => ids.has(value) ? value : '');
    const roster = JSON.stringify(devices.map(device => device.id));
    useEffect(() => { setSelection(previous => previous.map(value => ids.has(value) ? value : '')); }, [roster]);
    const rows = selected.flatMap((value, index) => { const device = devices.find(item => item.id === value); return device ? [{ device, index }] : []; });
    const name = (device: Device) => device.source === 'lan' && !device.synthetic ? identities.get(device.id)?.hostname ?? device.id : device.name;
    const target = (device: Device) => name(device) === device.id ? device.id : `${name(device)} · ${device.id}`;
    const choose = (index: number, value: string) => {
        if (document.hidden || value && (!ids.has(value) || selected.some((other, slot) => other === value && slot !== index))) return;
        setSelection(previous => previous.map((item, slot) => slot === index ? value : item));
    };
    const metric = (value: Metric) => <><MetricValue metric={value}/><details className="device-comparison-provenance"><summary>{c.metricSource}</summary><span>{value.source}</span>{reportTimestamp(value.collectedAt) ? <time dateTime={value.collectedAt}>{fullDate(value.collectedAt)}</time> : <span>{c.noTime}</span>}</details></>;
    const hostnameStatus = (device: Device) => {
        const identity = identities.get(device.id);
        if (device.source !== 'lan' || device.synthetic || !identity?.hostname) return null;
        return <span className="device-comparison-id">Hostname: {identity.status === 'fresh' ? locale === 'de' ? 'Aktuell' : 'Recent' : locale === 'de' ? 'Veraltet' : 'Stale'}{identity.hostnamePartial ? locale === 'de' ? ' · teilweise erfasst' : ' · partially collected' : ''}</span>;
    };
    const fields: { label: string; render: (device: Device) => React.ReactNode }[] = [
        { label: c.source, render: device => <Source source={device.source} synthetic={device.synthetic}/> },
        { label: c.os, render: device => device.os },
        { label: c.report, render: device => <ReportTime device={device} full/> },
        { label: c.health, render: device => <Status status={device.status} source={device.source} synthetic={device.synthetic}/> },
        { label: 'CPU', render: device => metric(device.cpu) },
        { label: c.memory, render: device => metric(device.memory) },
        { label: c.disk, render: device => metric(device.disk) },
    ];
    return <>
        <p id={`${id}-scope`}>{c.scope}</p>
        <div className="device-comparison-selectors">{selected.map((value, index) => <label key={index} htmlFor={`${id}-${index}`}>{c.slot} {index + 1}{index === 2 ? ` ${c.optional}` : ''}<select ref={node => { selectors.current[index] = node; }} id={`${id}-${index}`} value={value} onChange={event => choose(index, event.target.value)}><option value="">{c.choose}</option>{devices.map(device => <option key={device.id} value={device.id} disabled={selected.some((other, slot) => other === device.id && slot !== index)}>{name(device)}{name(device) !== device.id ? ` · ${device.id}` : ''}</option>)}</select></label>)}</div>
        {rows.length > 0 && <button type="button" className="text-button" onClick={() => { setSelection(['', '', '']); selectors.current[0]?.focus(); }}><X size={14} aria-hidden="true"/>{c.clear}</button>}
        {rows.length < 2 ? <p role="status">{c.empty}</p> : <div className="device-comparison-scroll" role="region" aria-label={c.title} tabIndex={0}>
            <table aria-describedby={`${id}-scope`}><caption className="sr-only">{c.title}</caption><thead><tr><th scope="col">{c.fact}</th>{rows.map(({ device, index }) => <th scope="col" key={device.id}><strong>{name(device)}</strong>{hostnameStatus(device)}{name(device) !== device.id && <span className="device-comparison-id">{device.id}</span>}<div className="device-comparison-actions"><button type="button" className="text-button" aria-label={`${c.open}: ${target(device)}`} onClick={() => { if (!document.hidden) onOpen(device); }}><ArrowUpRight size={14} aria-hidden="true"/>{c.open}</button><button type="button" className="icon-button" title={c.remove} aria-label={`${c.remove}: ${target(device)}`} onClick={() => { choose(index, ''); selectors.current[index]?.focus(); }}><X size={14} aria-hidden="true"/></button></div></th>)}</tr></thead><tbody>{fields.map(field => <tr key={field.label}><th scope="row">{field.label}</th>{rows.map(({ device }) => <td key={device.id}>{field.render(device)}</td>)}</tr>)}</tbody></table>
        </div>}
    </>;
}
