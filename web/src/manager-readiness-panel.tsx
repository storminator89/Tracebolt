import { useId, useState } from 'react';
import { ChevronDown, RefreshCw } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import { managerCertificateState, managerComponentState, managerReadinessStatus } from './manager-readiness-model';
import { useManagerReadiness } from './manager-readiness-resource';
import './manager-readiness.css';

const copy = {
    en: {
        title: 'Manager status', show: 'Inspect manager checks and certificate dates', hide: 'Close manager status', refresh: 'Refresh manager status', loading: 'Reading manager status…', readAt: 'Original manager read',
        ready: 'Recorded checks passed', unavailable: 'Configured checks unavailable', stale: 'Snapshot is stale', unknown: 'Current evidence unknown',
        failed: 'Manager evidence could not be read or validated. No current status is established.', access: 'Access ended. Sign in again to read manager evidence.', paused: 'Evidence cleared while this view was inactive. Refresh to read it again.', expired: 'The snapshot or session expired, or its clock changed. Refresh to read current evidence.',
        intro: 'Read-only checks of this manager, separate from incident outcomes and endpoint health.', limits: 'What these checks cover', scope: 'Only configured core reads and the last completed worker steps are checked. A successful maintenance step is not a complete sweep or recovery of another domain. This snapshot ages out after five seconds; refresh is manual.',
        exclusions: 'Not assessed', certificates: 'Loaded certificate dates', certificateLimit: 'Dates describe already-loaded public certificates. The server-chain interval is the intersection of its certificates. This is not trust, a TLS handshake, connectivity, key possession or successful renewal.',
        checks: 'Core checks and last worker evidence', component: 'Component', state: 'Evidence', checked: 'Original check or completion time', missing: 'Not supplied', from: 'Valid from', until: 'Valid until', readonly: 'Opening or refreshing runs one bounded GET. No repair, credential reload, scope grant, collection, provider call or external delivery is started.',
        state_boundary: 'Restore-quarantine boundary', operator_store: 'Operator store reads', trust_store: 'Trust store reads', linux_enrollment_store: 'Linux enrollment store reads', windows_enrollment_store: 'Windows enrollment store reads', macos_basic_store: 'macOS Basic store reads', macos_inventory_store: 'macOS inventory store reads', server_certificate: 'Presented server chain validity', enrollment_issuer: 'Enrollment public-authority validation', linux_inventory_step: 'Last Linux inventory step', windows_inventory_step: 'Last Windows inventory step', macos_inventory_step: 'Last macOS inventory step', linux_health_worker: 'Last Linux Health iteration', windows_health_worker: 'Last Windows Health iteration', probe: 'Bounded read admission', runtime: 'Readiness source',
        full_store_integrity: 'Full store integrity', write_capacity_and_durability: 'Write capacity and durability', complete_maintenance_sweep: 'Complete maintenance sweeps', optional_provider_workers: 'Optional provider workers', native_and_release_acceptance: 'Native and release acceptance',
        server_chain: 'Presented server chain', enrollment_root: 'Enrollment root',
        certificateTitles: { server_chain: 'Presented server chain', enrollment_issuer: 'Enrollment issuer', enrollment_root: 'Enrollment root' },
        componentStates: { ready: 'Check passed', succeeded: 'One step succeeded', not_configured: 'Not configured', stopped: 'Stopped', starting: 'Starting', stale: 'Stale evidence', failed: 'Failed', busy: 'Busy', timeout: 'Timed out', unknown: 'Unknown' },
        certificateStates: { valid: 'More than 30 days remaining', within_30_days: 'Expires within 30 days', within_7_days: 'Expires within 7 days', expired: 'Expired', not_yet_valid: 'Not yet valid', not_configured: 'Not configured', unavailable: 'Dates unavailable', unknown: 'Current validity unknown' },
    },
    de: {
        title: 'Managerstatus', show: 'Managerprüfungen und Zertifikatsdaten ansehen', hide: 'Managerstatus schließen', refresh: 'Managerstatus aktualisieren', loading: 'Managerstatus wird gelesen …', readAt: 'Ursprünglicher Managerabruf',
        ready: 'Gespeicherte Prüfungen bestanden', unavailable: 'Konfigurierte Prüfungen nicht verfügbar', stale: 'Momentaufnahme veraltet', unknown: 'Aktuelle Nachweise unbekannt',
        failed: 'Managernachweise konnten nicht gelesen oder geprüft werden. Kein aktueller Status belegt.', access: 'Zugriff beendet. Zum Lesen der Managernachweise erneut anmelden.', paused: 'Nachweise während inaktiver Ansicht entfernt. Zum erneuten Lesen aktualisieren.', expired: 'Momentaufnahme oder Sitzung abgelaufen oder Uhr verändert. Für aktuelle Nachweise aktualisieren.',
        intro: 'Rein lesende Prüfungen dieses Managers, getrennt von Vorfallausgängen und Gerätezustand.', limits: 'Umfang dieser Prüfungen', scope: 'Geprüft werden nur konfigurierte Kern-Lesezugriffe und die letzten abgeschlossenen Arbeitsschritte. Ein erfolgreicher Wartungsschritt ist kein vollständiger Durchlauf und belegt keine Erholung anderer Bereiche. Die Momentaufnahme veraltet nach fünf Sekunden; Aktualisierung erfolgt manuell.',
        exclusions: 'Nicht geprüft', certificates: 'Geladene Zertifikatsdaten', certificateLimit: 'Die Daten beschreiben bereits geladene öffentliche Zertifikate. Das Intervall der Serverkette ist die Schnittmenge ihrer Zertifikate. Es belegt weder Vertrauen, TLS-Handshake, Erreichbarkeit, Schlüsselbesitz noch erfolgreiche Erneuerung.',
        checks: 'Kernprüfungen und letzte Arbeitsnachweise', component: 'Komponente', state: 'Nachweis', checked: 'Ursprüngliche Prüf- oder Abschlusszeit', missing: 'Nicht geliefert', from: 'Gültig ab', until: 'Gültig bis', readonly: 'Öffnen oder Aktualisieren führt einen begrenzten GET aus. Keine Reparatur, kein erneutes Laden von Zugangsdaten, keine Freigabe, Erfassung, Anbieterabfrage oder externe Zustellung wird gestartet.',
        state_boundary: 'Wiederherstellungsquarantäne', operator_store: 'Operator-Datenbank lesen', trust_store: 'Vertrauensdatenbank lesen', linux_enrollment_store: 'Linux-Aufnahmedatenbank lesen', windows_enrollment_store: 'Windows-Aufnahmedatenbank lesen', macos_basic_store: 'macOS-Basic-Datenbank lesen', macos_inventory_store: 'macOS-Inventardatenbank lesen', server_certificate: 'Gültigkeit der präsentierten Serverkette', enrollment_issuer: 'Öffentliche Aufnahmeautorität prüfen', linux_inventory_step: 'Letzter Linux-Inventarschritt', windows_inventory_step: 'Letzter Windows-Inventarschritt', macos_inventory_step: 'Letzter macOS-Inventarschritt', linux_health_worker: 'Letzter Linux-Health-Durchlauf', windows_health_worker: 'Letzter Windows-Health-Durchlauf', probe: 'Zulassung des begrenzten Lesezugriffs', runtime: 'Quelle der Bereitschaftsnachweise',
        full_store_integrity: 'Vollständige Datenintegrität', write_capacity_and_durability: 'Schreibkapazität und dauerhafte Speicherung', complete_maintenance_sweep: 'Vollständige Wartungsdurchläufe', optional_provider_workers: 'Optionale Anbieterprozesse', native_and_release_acceptance: 'Native Abnahme und Release-Abnahme',
        server_chain: 'Präsentierte Serverkette', enrollment_root: 'Aufnahme-Stammzertifikat',
        certificateTitles: { server_chain: 'Präsentierte Serverkette', enrollment_issuer: 'Aufnahme-Ausstellerzertifikat', enrollment_root: 'Aufnahme-Stammzertifikat' },
        componentStates: { ready: 'Prüfung bestanden', succeeded: 'Ein Arbeitsschritt erfolgreich', not_configured: 'Nicht konfiguriert', stopped: 'Gestoppt', starting: 'Startet', stale: 'Nachweis veraltet', failed: 'Fehlgeschlagen', busy: 'Belegt', timeout: 'Zeitüberschreitung', unknown: 'Unbekannt' },
        certificateStates: { valid: 'Mehr als 30 Tage verbleibend', within_30_days: 'Läuft innerhalb von 30 Tagen ab', within_7_days: 'Läuft innerhalb von 7 Tagen ab', expired: 'Abgelaufen', not_yet_valid: 'Noch nicht gültig', not_configured: 'Nicht konfiguriert', unavailable: 'Daten nicht verfügbar', unknown: 'Aktuelle Gültigkeit unbekannt' },
    },
};

function Time({ at, missing }: { at?: string; missing: string }) {
    return at ? <time dateTime={at} title={at}>{fullDate(at)}</time> : <span>{missing}</span>;
}

/** Available only inside the authenticated LAN work queue. Starts collapsed;
 * its isolated reader is destroyed on close, route change and session change. */
export function ManagerReadinessPanel({ sessionKey }: { sessionKey: string | null }) {
    const [locale] = useLocale(), c = copy[locale], id = useId();
    const [open, setOpen] = useState(false);
    const resource = useManagerReadiness(open, sessionKey), view = resource.view;
    const status = view ? managerReadinessStatus(view, resource.age) : null;
    return <section className="panel manager-readiness" aria-label={c.title}>
        <div className="manager-readiness-heading"><div><h2>{c.title}</h2><p>{c.intro}</p></div><button className="button small" type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(value => !value)}><ChevronDown size={14}/>{open ? c.hide : c.show}</button></div>
        {open && <div id={id} className="manager-readiness-body" aria-busy={resource.loading}>
            <div className="manager-readiness-controls"><button className="button small" type="button" disabled={resource.loading || !sessionKey || resource.notice === 'access'} onClick={resource.refresh}><RefreshCw size={14}/>{c.refresh}</button>{resource.loading && <p role="status">{c.loading}</p>}{status && <strong className="manager-readiness-status" data-manager-state={status}>{c[status]}</strong>}</div>
            {resource.notice && <p className="manager-readiness-notice" role="status">{c[resource.notice]}</p>}
            {!view && !resource.loading && !resource.notice && <p role="status">{sessionKey ? c.unknown : c.access}</p>}
            {view && <>
                <p>{c.readAt}: <Time at={view.serverNow} missing={c.missing}/></p>
                <div className="manager-readiness-table"><table><caption>{c.checks}</caption><thead><tr><th scope="col">{c.component}</th><th scope="col">{c.state}</th><th scope="col">{c.checked}</th></tr></thead><tbody>{view.components.map(component => {
                    const state = managerComponentState(component, view.serverNow, resource.age);
                    return <tr key={component.component}><th scope="row">{c[component.component]}</th><td data-component-state={state}>{c.componentStates[state]}</td><td><Time at={component.checkedAt} missing={c.missing}/></td></tr>;
                })}</tbody></table></div>
                <section aria-label={c.certificates} className="manager-readiness-certificates"><h3>{c.certificates}</h3><p>{c.certificateLimit}</p><div>{(['server_chain', 'enrollment_issuer', 'enrollment_root'] as const).map(role => {
                    const lifetime = view.certificateLifetimes?.find(row => row.role === role), state = lifetime ? managerCertificateState(lifetime, view.serverNow, resource.age) : 'unknown';
                    return <article key={role}><h4>{c.certificateTitles[role]}</h4><p data-certificate-state={state}>{c.certificateStates[state]}</p><dl><div><dt>{c.from}</dt><dd><Time at={lifetime?.validFrom} missing={c.missing}/></dd></div><div><dt>{c.until}</dt><dd><Time at={lifetime?.validUntil} missing={c.missing}/></dd></div></dl></article>;
                })}</div></section>
                <details className="manager-readiness-limits"><summary>{c.limits}</summary><p>{c.scope}</p><h3>{c.exclusions}</h3><ul>{view.unassessed.map(item => <li key={item}>{c[item]}</li>)}</ul><p>{c.readonly}</p></details>
            </>}
        </div>}
    </section>;
}
