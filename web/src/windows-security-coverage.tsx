import { useLocale } from './i18n';
import { fullDate } from './utils';
import type { WindowsInventoryResource } from './windows-inventory-resource';
import type { WindowsSecurityCoverage } from './windows-security-coverage-types';
import './windows-security-posture.css';
import './windows-security-coverage.css';

const copy = {
    en: {
        title: 'Antivirus & TPM', captured: 'Captured', antivirus: 'Antivirus registration', tpm: 'TPM', observed: 'Observed', partial: 'Partial', denied: 'Access denied', unavailable: 'Unavailable',
        unknown: 'Unknown', name: 'Product', state: 'Reported state', signature: 'Signature status', on: 'On', off: 'Off', snoozed: 'Snoozed', expired: 'Expired', 'up-to-date': 'Up to date', 'out-of-date': 'Out of date',
        present: 'Present', 'not-found': 'No supported TPM found', presence: 'Supported-device presence', version: 'TPM version', details: 'Source details', source: 'Source', count: 'Products reported', shown: 'Products shown',
        antivirusNote: 'Registration and reported status do not establish overall protection.', tpmNote: 'Presence and version do not establish TPM readiness or BitLocker protection.', notFoundNote: 'The source found no supported TPM; this does not establish hardware absence.',
        emptyRows: 'No products reported by this source.', missingRows: 'No readable product rows.', emptyRowsNote: 'This does not establish that antivirus software is absent.', missingRowsNote: 'Antivirus presence and protection remain unknown.', unreadNote: 'Unread or unavailable values remain unknown.', truncated: 'Some reported products are omitted by collection or transfer limits.',
        empty: 'Antivirus and TPM observations are unavailable for this capture. A separate local scope is required.', stale: 'Stale antivirus and TPM observations; values describe the original capture.', expiredData: 'Antivirus and TPM observations expired after 24 hours.', ahead: 'Antivirus and TPM observations are hidden until their capture time can be verified.', bitlocker: 'BitLocker: unavailable. Not collected under this profile.',
        reasons: { windows_security_coverage_access_denied: 'Source access was denied.', windows_security_coverage_unavailable: 'Source values could not be read.', windows_security_coverage_unsupported_platform: 'This source is unsupported on this platform.', windows_security_coverage_invalid_metadata: 'The source returned invalid data.', windows_security_coverage_bounds: 'Collection limits were reached.', windows_security_coverage_partial_result: 'Some source values could not be determined.', windows_security_coverage_budget_exhausted: 'The source read timed out.' },
        avSource: 'Windows Security Center · IWSCProductList · supported Windows clients only', tpmSource: 'TPM Base Services · Tbsi_GetDeviceInfo',
    },
    de: {
        title: 'Antivirus & TPM', captured: 'Erfasst', antivirus: 'Antivirusregistrierung', tpm: 'TPM', observed: 'Beobachtet', partial: 'Teilweise', denied: 'Zugriff verweigert', unavailable: 'Nicht verfügbar',
        unknown: 'Unbekannt', name: 'Produkt', state: 'Gemeldeter Status', signature: 'Signaturstatus', on: 'Ein', off: 'Aus', snoozed: 'Pausiert', expired: 'Abgelaufen', 'up-to-date': 'Aktuell', 'out-of-date': 'Veraltet',
        present: 'Vorhanden', 'not-found': 'Kein unterstütztes TPM gefunden', presence: 'Unterstütztes Gerät vorhanden', version: 'TPM-Version', details: 'Quelldetails', source: 'Quelle', count: 'Gemeldete Produkte', shown: 'Angezeigte Produkte',
        antivirusNote: 'Registrierung und gemeldeter Status belegen keinen umfassenden Schutz.', tpmNote: 'Vorhandensein und Version belegen weder TPM-Bereitschaft noch BitLocker-Schutz.', notFoundNote: 'Die Quelle fand kein unterstütztes TPM; dies belegt keine fehlende Hardware.',
        emptyRows: 'Diese Quelle meldet keine Produkte.', missingRows: 'Keine lesbaren Produktzeilen.', emptyRowsNote: 'Dies belegt nicht, dass Antivirussoftware fehlt.', missingRowsNote: 'Vorhandensein und Schutz durch Antivirussoftware bleiben unbekannt.', unreadNote: 'Nicht gelesene oder nicht verfügbare Werte bleiben unbekannt.', truncated: 'Einige gemeldete Produkte fehlen aufgrund von Erfassungs- oder Übertragungsgrenzen.',
        empty: 'Für diese Erfassung sind keine Antivirus- und TPM-Daten verfügbar. Ein separater lokaler Erfassungsumfang ist erforderlich.', stale: 'Veraltete Antivirus- und TPM-Beobachtungen; Werte gelten für die ursprüngliche Erfassung.', expiredData: 'Antivirus- und TPM-Daten nach 24 Stunden abgelaufen.', ahead: 'Antivirus- und TPM-Daten bleiben ausgeblendet, bis die Erfassungszeit geprüft werden kann.', bitlocker: 'BitLocker: nicht verfügbar. In diesem Profil nicht erfasst.',
        reasons: { windows_security_coverage_access_denied: 'Zugriff auf die Quelle verweigert.', windows_security_coverage_unavailable: 'Quelldaten konnten nicht gelesen werden.', windows_security_coverage_unsupported_platform: 'Diese Quelle wird auf dieser Plattform nicht unterstützt.', windows_security_coverage_invalid_metadata: 'Die Quelle lieferte ungültige Daten.', windows_security_coverage_bounds: 'Erfassungsgrenzen erreicht.', windows_security_coverage_partial_result: 'Einige Quellwerte konnten nicht ermittelt werden.', windows_security_coverage_budget_exhausted: 'Zeitlimit beim Lesen der Quelle erreicht.' },
        avSource: 'Windows-Sicherheitscenter · IWSCProductList · nur unterstützte Windows-Clients', tpmSource: 'TPM Base Services · Tbsi_GetDeviceInfo',
    },
};
export function WindowsSecurityCoveragePanel({ resource }: { resource: WindowsInventoryResource }) {
    const [locale] = useLocale(), c = copy[locale], coverage = resource.securityCoverage;
    const bitlocker = <p className="windows-security-note windows-coverage-bitlocker">{c.bitlocker}</p>;
    if (!coverage) return <section className="windows-security-coverage" aria-label={c.title}><p role="status" className="windows-inventory-empty">{resource.securityCoverageExpired ? c.expiredData : resource.securityCoverageAhead ? c.ahead : c.empty}</p>{bitlocker}</section>;
    const { antivirus, tpm } = coverage, binding = `${coverage.grantId}:${coverage.generationId}:${coverage.collectedAt}`, headers = [c.name, c.state, c.signature];
    const summary = (source: WindowsSecurityCoverage['antivirus'] | WindowsSecurityCoverage['tpm']) => source.reason && <p className="windows-security-note">{c.reasons[source.reason]}</p>;
    return <section className="windows-security-coverage" aria-label={c.title}>
        <div className="windows-inventory-section-header"><h3>{c.title}</h3><span className="windows-inventory-times">{c.captured} <time dateTime={coverage.collectedAt}>{fullDate(coverage.collectedAt)}</time></span></div>
        {resource.securityCoverageStale && <p role="status" className="windows-inventory-caution">{c.stale}</p>}
        <div className="windows-security-grid">
            <section className="windows-security-card" aria-label={c.antivirus}>
                <div className="windows-security-card-header"><h4>{c.antivirus}</h4><span className="windows-security-quality">{c[antivirus.quality]}</span></div>
                {summary(antivirus)}
                {antivirus.rows.length > 0 ? <div className="windows-inventory-table-wrap"><table className="windows-inventory-table windows-coverage-table"><caption className="sr-only">{c.antivirus}</caption><thead><tr>{headers.map(header => <th scope="col" key={header}>{header}</th>)}</tr></thead><tbody>{antivirus.rows.map(product => <tr key={product.index}><td data-label={c.name}>{product.name ?? c.unknown}</td><td data-label={c.state}>{c[product.state]}</td><td data-label={c.signature}>{c[product.signatureStatus]}</td></tr>)}</tbody></table></div> : <p className="windows-security-note">{antivirus.reportedCount === 0 ? c.emptyRows : c.missingRows}</p>}
                {antivirus.truncated && <p className="windows-inventory-caution">{c.truncated}</p>}
                <details className="windows-security-details windows-coverage-details" key={`antivirus:${binding}`}><summary>{c.details}</summary><dl className="windows-security-fields">{[[c.source, c.avSource], [c.count, antivirus.reportedCount ?? c.unknown], [c.shown, antivirus.rows.length]].map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl><p className="windows-security-note">{c.antivirusNote}</p>{antivirus.rows.length === 0 && <p className="windows-security-note">{antivirus.reportedCount === 0 ? c.emptyRowsNote : c.missingRowsNote}</p>}{antivirus.reason && <p className="windows-security-note">{c.unreadNote}</p>}</details>
            </section>
            <section className="windows-security-card" aria-label={c.tpm}>
                <div className="windows-security-card-header"><h4>{c.tpm}</h4><span className="windows-security-quality">{c[tpm.quality]}</span></div>
                {summary(tpm)}
                <dl className="windows-security-fields"><div><dt>{c.presence}</dt><dd>{c[tpm.presence]}</dd></div><div><dt>{c.version}</dt><dd>{tpm.version === 'unknown' ? c.unknown : tpm.version}</dd></div></dl>
                <details className="windows-security-details windows-coverage-details" key={`tpm:${binding}`}><summary>{c.details}</summary><dl className="windows-security-fields"><div><dt>{c.source}</dt><dd>{c.tpmSource}</dd></div></dl><p className="windows-security-note">{c.tpmNote}</p>{tpm.presence === 'not-found' && <p className="windows-security-note">{c.notFoundNote}</p>}{tpm.reason && <p className="windows-security-note">{c.unreadNote}</p>}</details>
            </section>
        </div>
        {bitlocker}
    </section>;
}
