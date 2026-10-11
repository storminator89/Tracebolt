import { Shield, BrickWall } from 'lucide-react';
import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsSecurityPosture } from './windows-security-posture-types';
import './windows-security-posture.css';

const copy = {
    en: {
        title: 'Security', captured: 'Captured', defender: 'Microsoft Defender', firewall: 'Windows Firewall', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable',
        modes: { normal: 'Normal mode', passive: 'Passive mode', 'edr-block': 'EDR block mode', unknown: 'Unknown mode' },
        on: 'On', off: 'Off', unknown: 'Unknown', active: 'Active', inactive: 'Inactive', realTime: 'Real-time protection', service: 'Defender service', antivirus: 'Antivirus function', signatures: 'Signature version', age: 'Signature age at capture', days: (days: number) => `${days} ${days === 1 ? 'day' : 'days'}`,
        details: 'Source details', profile: 'Profile', domain: 'Domain', private: 'Private', public: 'Public', activity: 'Active profile', configured: 'Configured firewall',
        defenderNote: 'Defender status alone does not describe overall antivirus protection. Other antivirus products are not assessed.',
        firewallNote: 'Local configuration only. Effective policy and network connectivity are not checked.',
        source: 'Source', defenderSource: 'Local Defender status', firewallSource: 'Local firewall profile configuration',
        empty: 'Security observations are unavailable for this capture. Separate local approval is required.',
        stale: 'Stale observation; values describe the original capture.', expired: 'Security observations expired after 24 hours.', ahead: 'Security observations are hidden until their capture time can be verified.',
        checkLocal: 'Check the source status on the device.', checkCapture: 'Check the next capture.',
        reasons: {
            windows_security_posture_access_denied: (source: string) => `${source} access was denied; unreadable values remain Unknown.`,
            windows_security_posture_unavailable: (source: string) => `${source} values could not all be read (Unknown).`,
            windows_security_posture_unsupported_platform: (source: string) => `${source} is unsupported on this platform; unavailable values remain Unknown.`,
            windows_security_posture_invalid_metadata: (source: string) => `${source} returned invalid data; affected values remain Unknown.`,
            windows_security_posture_bounds: (source: string) => `${source} collection limit reached; unread values remain Unknown.`,
            windows_security_posture_partial_result: (source: string) => `Some ${source} values could not be determined (Unknown).`,
            windows_security_posture_budget_exhausted: (source: string) => `${source} read timed out; unread values remain Unknown.`,
        },
    },
    de: {
        title: 'Sicherheit', captured: 'Erfasst', defender: 'Microsoft Defender', firewall: 'Windows-Firewall', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar',
        modes: { normal: 'Normalmodus', passive: 'Passivmodus', 'edr-block': 'EDR-Blockmodus', unknown: 'Modus unbekannt' },
        on: 'Ein', off: 'Aus', unknown: 'Unbekannt', active: 'Aktiv', inactive: 'Inaktiv', realTime: 'Echtzeitschutz', service: 'Defender-Dienst', antivirus: 'Antivirusfunktion', signatures: 'Signaturversion', age: 'Signaturalter bei Erfassung', days: (days: number) => `${days} ${days === 1 ? 'Tag' : 'Tage'}`,
        details: 'Quelldetails', profile: 'Profil', domain: 'Domäne', private: 'Privat', public: 'Öffentlich', activity: 'Aktives Profil', configured: 'Konfigurierte Firewall',
        defenderNote: 'Der Defender-Status allein beschreibt nicht den gesamten Virenschutz. Andere Antivirusprodukte werden nicht geprüft.',
        firewallNote: 'Nur lokale Konfiguration. Wirksame Richtlinien und Netzwerkerreichbarkeit werden nicht geprüft.',
        source: 'Quelle', defenderSource: 'Lokaler Defender-Status', firewallSource: 'Lokale Firewall-Profilkonfiguration',
        empty: 'Für diese Erfassung sind keine Sicherheitsdaten verfügbar. Eine separate lokale Zustimmung ist erforderlich.',
        stale: 'Veraltete Beobachtung; Werte gelten für die ursprüngliche Erfassung.', expired: 'Sicherheitsdaten nach 24 Stunden abgelaufen.', ahead: 'Sicherheitsdaten bleiben ausgeblendet, bis die Erfassungszeit geprüft werden kann.',
        checkLocal: 'Status der Quelle auf dem Gerät prüfen.', checkCapture: 'Die nächste Erfassung prüfen.',
        reasons: {
            windows_security_posture_access_denied: (source: string) => `Zugriff auf ${source} verweigert; nicht lesbare Werte bleiben Unbekannt.`,
            windows_security_posture_unavailable: (source: string) => `Werte für ${source} konnten nicht vollständig gelesen werden (Unbekannt).`,
            windows_security_posture_unsupported_platform: (source: string) => `${source} wird auf dieser Plattform nicht unterstützt; nicht verfügbare Werte bleiben Unbekannt.`,
            windows_security_posture_invalid_metadata: (source: string) => `${source} lieferte ungültige Daten; betroffene Werte bleiben Unbekannt.`,
            windows_security_posture_bounds: (source: string) => `Erfassungsgrenze für ${source} erreicht; nicht gelesene Werte bleiben Unbekannt.`,
            windows_security_posture_partial_result: (source: string) => `Einige Werte für ${source} konnten nicht ermittelt werden (Unbekannt).`,
            windows_security_posture_budget_exhausted: (source: string) => `Zeitlimit beim Lesen von ${source} erreicht; nicht gelesene Werte bleiben Unbekannt.`,
        },
    },
};
export function WindowsSecurityPosturePanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], posture = resource.securityPosture;
    if (!posture) return <p role="status" className="windows-inventory-empty">{resource.securityPostureExpired ? c.expired : resource.securityPostureAhead ? c.ahead : c.empty}</p>;
    const { defender, firewall } = posture, binding = `${posture.grantId}:${posture.generationId}:${posture.collectedAt}`;
    const headers = [c.profile, c.activity, c.configured];
    const sourceSummary = (source: WindowsSecurityPosture['defender'] | WindowsSecurityPosture['firewall'], name: string) => source.reason && <p className="windows-security-note">
        {c.reasons[source.reason](name)}{' '}{['windows_security_posture_invalid_metadata', 'windows_security_posture_bounds', 'windows_security_posture_budget_exhausted'].includes(source.reason) ? c.checkCapture : c.checkLocal}
    </p>;
    return <section className="windows-security-posture" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={posture.collectedAt}>{fullDate(posture.collectedAt)}</time></span></div>
        {resource.securityPostureStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-security-grid">
            <section className="windows-security-card" aria-label={c.defender}>
                <div className="windows-security-card-header"><h4><Shield size={18} aria-hidden="true"/>{c.defender}</h4><span className="windows-security-quality">{c[defender.quality]}</span></div>
                {sourceSummary(defender, c.defender)}
                <p className="windows-security-mode">{c.modes[defender.mode]}</p>
                <dl className="windows-security-fields"><div><dt>{c.realTime}</dt><dd>{c[defender.realTimeProtectionEnabled]}</dd></div></dl>
                <p className="windows-security-note">{c.defenderNote}</p>
                <details className="windows-security-details" key={`defender:${binding}`}><summary>{c.details}</summary>
                    <dl className="windows-security-fields">{[[c.service, c[defender.serviceEnabled]], [c.antivirus, c[defender.antivirusEnabled]], [c.signatures, defender.signatureVersion ?? c.unknown], [c.age, defender.signatureAgeDays === null ? c.unknown : c.days(defender.signatureAgeDays)], [c.source, c.defenderSource]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
                </details>
            </section>
            <section className="windows-security-card" aria-label={c.firewall}>
                <div className="windows-security-card-header"><h4><BrickWall size={18} aria-hidden="true"/>{c.firewall}</h4><span className="windows-security-quality">{c[firewall.quality]}</span></div>
                {sourceSummary(firewall, c.firewall)}
                <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-security-firewall-table"><caption className="sr-only">{c.firewall}</caption><thead><tr>{headers.map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{firewall.profiles.map(profile => <tr key={profile.profile}><td data-label={c.profile}>{c[profile.profile]}</td><td data-label={c.activity}>{profile.active === 'on' ? c.active : profile.active === 'off' ? c.inactive : c.unknown}</td><td data-label={c.configured}>{c[profile.enabled]}</td></tr>)}</tbody></table></div>
                <p className="windows-security-note">{c.firewallNote}</p>
                <details className="windows-security-details" key={`firewall:${binding}`}><summary>{c.details}</summary>
                    <dl className="windows-security-fields"><div><dt>{c.source}</dt><dd>{c.firewallSource}</dd></div></dl>
                </details>
            </section>
        </div>
    </section>;
}
