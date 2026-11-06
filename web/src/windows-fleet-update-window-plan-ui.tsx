import { useId } from 'react';
import { useLocale } from './i18n';
import type { FleetUpdateWindowPlan } from './windows-fleet-update-window-plan';
import './windows-fleet-update-window-plan.css';

const copy = {
    en: { stagger: 'Spread devices across successive UTC windows', size: 'Devices per window', gap: 'Gap after each window (minutes)', scope: 'Devices follow the displayed selection order. Each window lasts as long as the first. Every start must be within 24 hours; every device still needs separate fresh review and approval.', limit: 'These are dispatch windows, not a concurrency limit or a pilot success gate. Installations may continue into later windows. No automatic approval, next-device action or stop-on-failure is added.', invalid: 'Choose 1–50 devices per window and a gap of 0–1440 whole minutes. All window starts must remain in the next 24 hours.', preview: 'Review planned device windows', frozen: 'Frozen device windows', wave: 'Window', elapsed: 'This window has started. Read saved outcomes; no new approval can use it.', empty: 'Select devices and a valid first UTC window to review the plan.' },
    de: { stagger: 'Geräte auf aufeinanderfolgende UTC-Zeitfenster verteilen', size: 'Geräte je Zeitfenster', gap: 'Abstand nach jedem Zeitfenster (Minuten)', scope: 'Die angezeigte Geräteauswahl bestimmt die Reihenfolge. Jedes Zeitfenster dauert so lange wie das erste. Jeder Beginn muss innerhalb von 24 Stunden liegen; jedes Gerät braucht weiterhin eine eigene frische Prüfung und Freigabe.', limit: 'Das sind Auslösungsfenster, keine Parallelitätsgrenze oder Pilot-Erfolgsprüfung. Installationen können in spätere Zeitfenster hineinreichen. Keine automatische Freigabe, Folgeaktion oder Unterbrechung bei Fehlern.', invalid: '1–50 Geräte je Zeitfenster und einen Abstand von 0–1440 ganzen Minuten wählen. Alle Zeitfenster müssen innerhalb der nächsten 24 Stunden beginnen.', preview: 'Geplante Gerätezeitfenster prüfen', frozen: 'Festgehaltene Gerätezeitfenster', wave: 'Zeitfenster', elapsed: 'Dieses Zeitfenster hat begonnen. Gespeicherte Ergebnisse lesen; keine neue Freigabe dafür.', empty: 'Geräte und ein gültiges erstes UTC-Zeitfenster auswählen, um den Plan zu prüfen.' },
};
export function FleetUpdateWindowPlanReview({ plan, devices, frozen = false, now }: { plan: FleetUpdateWindowPlan; devices: Array<{ id: string; name: string }>; frozen?: boolean; now: number }) {
    const [locale] = useLocale(), c = copy[locale];
    const at = (value: number) => new Date(value * 1000).toISOString();
    const display = (value: number) => at(value).replace('T', ' ').replace('.000Z', ' UTC');
    return <section className="windows-fleet-update-window-plan" aria-label={frozen ? c.frozen : c.preview}>
        <strong>{frozen ? c.frozen : c.preview} · {plan.waveCount}</strong><p>{c.limit}</p>
        <ol>{Array.from({ length: plan.waveCount }, (_, index) => {
            const entries = plan.entries.filter(entry => entry.wave === index + 1), window = entries[0].window;
            return <li key={index}><strong>{c.wave} {index + 1}</strong><p><time dateTime={at(window.startAt)}>{display(window.startAt)}</time> – <time dateTime={at(window.endAt)}>{display(window.endAt)}</time></p><ul>{entries.map(entry => <li key={entry.deviceId}>{devices.find(device => device.id === entry.deviceId)?.name ?? entry.deviceId}<small>{entry.deviceId}</small></li>)}</ul>{frozen && now >= window.startAt && <p role="status">{c.elapsed}</p>}</li>;
        })}</ol>
    </section>;
}
export function FleetUpdateWindowPlanOptions({ stagger, setStagger, size, setSize, gap, setGap, plan, devices, now, hasFirstWindow }: { stagger: boolean; setStagger: (value: boolean) => void; size: string; setSize: (value: string) => void; gap: string; setGap: (value: string) => void; plan: FleetUpdateWindowPlan | null; devices: Array<{ id: string; name: string }>; now: number; hasFirstWindow: boolean }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    return <div className="windows-fleet-update-window-plan-options">
        <label className="windows-fleet-update-window-choice"><input type="checkbox" checked={stagger} onChange={event => setStagger(event.target.checked)}/>{c.stagger}</label>
        {stagger && <><div className="windows-fleet-update-window-inputs">
            <label>{c.size}<input type="number" min="1" max="50" step="1" value={size} aria-describedby={id} onChange={event => setSize(event.target.value)}/></label>
            <label>{c.gap}<input type="number" min="0" max="1440" step="1" value={gap} aria-describedby={id} onChange={event => setGap(event.target.value)}/></label>
        </div><p id={id}>{c.scope}</p>{plan ? <FleetUpdateWindowPlanReview plan={plan} devices={devices} now={now}/> : <p role="status">{devices.length && hasFirstWindow ? c.invalid : c.empty}</p>}</>}
    </div>;
}
