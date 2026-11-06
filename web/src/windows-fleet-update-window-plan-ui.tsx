import { useId } from 'react';
import { CalendarClock, ClipboardList, Info, LockKeyhole } from 'lucide-react';
import { useLocale } from './i18n';
import type { FleetUpdateWindowPlan } from './windows-fleet-update-window-plan';
import './windows-fleet-update-window-plan.css';

const copy = {
    en: {
        stagger: 'Spread devices across successive UTC windows', size: 'Devices per window', gap: 'Gap after each window (minutes)',
        scope: 'Devices follow the displayed order. Each window lasts as long as the first. Every start must be within 24 hours.',
        limits: 'Window limits', overlap: 'Dispatch windows, not a concurrency limit. Installations may continue into later windows.',
        success: 'Later approved windows do not wait for earlier success or stop automatically after failure.', timing: 'Exact start time is not guaranteed.',
        steps: 'Plan, approve, read results', planStep: 'Plan device windows', planHelp: 'Freeze device IDs and UTC times. Planning and freezing send no requests.',
        approveStep: 'Approve each device', approveHelp: 'Open each device, check fresh readiness and approve its exact update and window separately. No device is approved automatically.',
        resultsStep: 'Read saved results', resultsHelp: 'For unconfirmed writes, read saved status only. An uncertain result is not success. Do not retry uncertain actions.',
        invalid: 'Choose 1–50 devices per window and a gap of 0–1440 whole minutes. All window starts must remain in the next 24 hours.',
        preview: 'Review planned device windows', frozen: 'Frozen device windows', wave: 'Window',
        elapsed: 'This window has started. Read saved outcomes; no new approval can use it.', empty: 'Select devices and a valid first UTC window to review the plan.',
    },
    de: {
        stagger: 'Geräte auf aufeinanderfolgende UTC-Zeitfenster verteilen', size: 'Geräte je Zeitfenster', gap: 'Abstand nach jedem Zeitfenster (Minuten)',
        scope: 'Die angezeigte Geräteauswahl bestimmt die Reihenfolge. Jedes Zeitfenster dauert so lange wie das erste. Jeder Beginn muss innerhalb von 24 Stunden liegen.',
        limits: 'Grenzen der Zeitfenster', overlap: 'Das sind Auslösungsfenster, keine Parallelitätsgrenze. Installationen können in spätere Zeitfenster hineinreichen.',
        success: 'Freigegebene spätere Zeitfenster warten nicht auf vorherigen Erfolg und stoppen bei Fehlern nicht automatisch.', timing: 'Der genaue Startzeitpunkt ist nicht garantiert.',
        steps: 'Planen, freigeben, Ergebnisse lesen', planStep: 'Gerätezeitfenster planen', planHelp: 'Geräte-IDs und UTC-Zeiten festhalten. Beim Planen und Festhalten wird nichts gesendet.',
        approveStep: 'Jedes Gerät freigeben', approveHelp: 'Jedes Gerät öffnen, die Bereitschaft frisch prüfen und das genaue Update mit seinem Zeitfenster separat freigeben. Kein Gerät wird automatisch freigegeben.',
        resultsStep: 'Gespeicherte Ergebnisse lesen', resultsHelp: 'Bei unbestätigten Schreibvorgängen nur den gespeicherten Status lesen. Ein ungewisses Ergebnis ist kein Erfolg. Ungewisse Aktionen nicht erneut ausführen.',
        invalid: '1–50 Geräte je Zeitfenster und einen Abstand von 0–1440 ganzen Minuten wählen. Alle Zeitfenster müssen innerhalb der nächsten 24 Stunden beginnen.',
        preview: 'Geplante Gerätezeitfenster prüfen', frozen: 'Festgehaltene Gerätezeitfenster', wave: 'Zeitfenster',
        elapsed: 'Dieses Zeitfenster hat begonnen. Gespeicherte Ergebnisse lesen; keine neue Freigabe dafür.', empty: 'Geräte und ein gültiges erstes UTC-Zeitfenster auswählen, um den Plan zu prüfen.',
    },
};
/** Static instructions, never a progress indicator or an approval/result state. */
export function FleetUpdateWindowPlanGuide() {
    const [locale] = useLocale(), c = copy[locale];
    return <ol className="windows-fleet-update-window-steps" aria-label={c.steps}>
        <li><strong><CalendarClock size={16} aria-hidden="true" focusable="false"/>{c.planStep}</strong><p>{c.planHelp}</p></li>
        <li><strong><LockKeyhole size={16} aria-hidden="true" focusable="false"/>{c.approveStep}</strong><p>{c.approveHelp}</p></li>
        <li><strong><ClipboardList size={16} aria-hidden="true" focusable="false"/>{c.resultsStep}</strong><p>{c.resultsHelp}</p></li>
    </ol>;
}
export function FleetUpdateWindowPlanReview({ plan, devices, frozen = false, now }: { plan: FleetUpdateWindowPlan; devices: Array<{ id: string; name: string }>; frozen?: boolean; now: number }) {
    const [locale] = useLocale(), c = copy[locale];
    const at = (value: number) => new Date(value * 1000).toISOString();
    const display = (value: number) => at(value).replace('T', ' ').replace('.000Z', ' UTC');
    return <section className="windows-fleet-update-window-plan" aria-label={frozen ? c.frozen : c.preview}>
        <strong>{frozen ? c.frozen : c.preview} · {plan.waveCount}</strong>
        <div className="windows-fleet-update-window-limits"><strong><Info size={16} aria-hidden="true" focusable="false"/>{c.limits}</strong><ul><li>{c.overlap}</li><li>{c.success}</li><li>{c.timing}</li></ul></div>
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
