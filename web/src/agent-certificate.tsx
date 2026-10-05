import { useId } from 'react';
import { Clock3 } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { AgentCertificate } from './types';
import './agent-certificate.css';

const warningWindow = 48 * 60 * 60 * 1000;
type ExpiryState = 'unknown' | 'current' | 'expiring' | 'expired';
const copy = {
    en: {
        title: 'Agent certificate', unknown: 'Expiry unknown', current: 'More than 48 hours remaining', expiring: 'Expires within 48 hours', expired: 'Expired',
        expiry: 'Certificate expires', checked: 'Manager checked', scope: 'Expiry status at the manager check above. Refresh device metadata to check again. Approval, connection and device health are separate.',
        unknownHelp: 'Refresh device metadata. If expiry stays unknown, ask an administrator to check certificate issuance or approval.',
        manual: 'Plan a separately authorized certificate replacement and new manual approval. A new approval receives a new device ID.',
        guided: 'Ask an administrator to plan a separately authorized replacement enrollment. Existing identity and history are not automatically renewed or merged.',
        renewal: 'Automatic renewal is unavailable.',
        atCheck: 'Status at manager check', details: 'Certificate details', nextStep: 'Ask an administrator to plan a separately authorized certificate replacement.',
    },
    de: {
        title: 'Agent-Zertifikat', unknown: 'Ablauf unbekannt', current: 'Mehr als 48 Stunden verbleibend', expiring: 'Läuft innerhalb von 48 Stunden ab', expired: 'Abgelaufen',
        expiry: 'Zertifikat läuft ab', checked: 'Vom Manager geprüft', scope: 'Ablaufstatus zum Prüfzeitpunkt oben. Für eine neue Prüfung die Gerätedaten aktualisieren. Freigabe, Verbindung und Gerätezustand sind unabhängig davon.',
        unknownHelp: 'Gerätedaten aktualisieren. Bleibt der Ablauf unbekannt, die Ausstellung oder Freigabe durch einen Administrator prüfen lassen.',
        manual: 'Separat freigegebenen Zertifikatsaustausch mit neuer manueller Freigabe planen. Eine neue Freigabe erhält eine neue Geräte-ID.',
        guided: 'Eine separat freigegebene Neuanmeldung mit einem Administrator planen. Bestehende Identität und Historie werden nicht automatisch erneuert oder zusammengeführt.',
        renewal: 'Automatische Erneuerung ist nicht verfügbar.',
        atCheck: 'Status bei Managerprüfung', details: 'Zertifikatsdetails', nextStep: 'Einen separat freigegebenen Zertifikatsaustausch mit einem Administrator planen.',
    },
};

function timestamp(value: unknown): value is string {
    return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value)) && Date.parse(value) > 0 && new Date(value).toISOString().slice(0, 19) === value.slice(0, 19);
}

/** Use the manager's explicit check time, never lastSeen, a TTL guess, browser
 * wall time, enrollment deadlines or a successful metadata refresh as renewal. */
export function certificateExpiry(value: unknown): { state: ExpiryState; certificate: AgentCertificate | null } {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { state: 'unknown', certificate: null };
    const item = value as Record<string, unknown>;
    if (Object.keys(item).sort().join(',') !== 'checkedAt,expiresAt,source' || (item.source !== 'manual-approval' && item.source !== 'guided-enrollment') || !timestamp(item.checkedAt) || (item.expiresAt !== null && !timestamp(item.expiresAt))) return { state: 'unknown', certificate: null };
    const certificate = item as unknown as AgentCertificate;
    if (certificate.expiresAt === null) return { state: 'unknown', certificate };
    const remaining = Date.parse(certificate.expiresAt) - Date.parse(certificate.checkedAt);
    return { state: remaining <= 0 ? 'expired' : remaining <= warningWindow ? 'expiring' : 'current', certificate };
}

export function AgentCertificatePanel({ value }: { value: unknown }) {
    const [locale] = useLocale(), labels = copy[locale], id = useId();
    const { state, certificate } = certificateExpiry(value);
    return <section className={`agent-certificate ${state}`} aria-labelledby={id}>
        <header>
            <h2 id={id}><Clock3 size={17}/>{labels.title}</h2>
            <div className="certificate-status-group">
                {certificate && <span>{labels.atCheck}</span>}
                <strong className="certificate-status">{labels[state]}</strong>
            </div>
        </header>
        {certificate && <dl>
            <div><dt>{labels.expiry}</dt><dd>{certificate.expiresAt ? <time dateTime={certificate.expiresAt}>{fullDate(certificate.expiresAt)}</time> : '—'}</dd></div>
            <div><dt>{labels.checked}</dt><dd><time dateTime={certificate.checkedAt}>{fullDate(certificate.checkedAt)}</time></dd></div>
        </dl>}
        <p className="certificate-guidance">{state === 'unknown' ? labels.unknownHelp : state !== 'current' ? labels.nextStep : null} {labels.renewal}</p>
        {certificate && <details className="certificate-details">
            <summary>{labels.details}</summary>
            <p>{labels.scope}</p>
            <p>{certificate.source === 'manual-approval' ? labels.manual : labels.guided}</p>
        </details>}
    </section>;
}
