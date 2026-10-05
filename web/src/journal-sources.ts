import { validJournalUnit } from './journal-types';
import type { JournalView } from './journal-types';

type Label = { en: string; de: string };
/** Presentation metadata only. These names are never an allowlist or a claim
 * that a service exists. The chooser may select only an observed exact unit. */
const serviceLabels: Record<string, Label> = {
    'ssh.service': { en: 'SSH remote login', de: 'SSH-Fernzugriff' },
    'sshd.service': { en: 'SSH remote login', de: 'SSH-Fernzugriff' },
    'docker.service': { en: 'Docker daemon', de: 'Docker-Dienst' },
    'containerd.service': { en: 'Container runtime', de: 'Container-Laufzeit' },
    'tracebolt-agent.service': { en: 'Tracebolt agent', de: 'Tracebolt-Agent' },
    'NetworkManager.service': { en: 'Network connections', de: 'Netzwerkverbindungen' },
    'networking.service': { en: 'Network configuration', de: 'Netzwerkkonfiguration' },
    'systemd-networkd.service': { en: 'Network configuration', de: 'Netzwerkkonfiguration' },
    'systemd-networkd-wait-online.service': { en: 'Network startup', de: 'Netzwerkstart' },
    'systemd-resolved.service': { en: 'DNS resolution', de: 'DNS-Auflösung' },
    'cron.service': { en: 'Scheduled jobs', de: 'Geplante Aufgaben' },
    'crond.service': { en: 'Scheduled jobs', de: 'Geplante Aufgaben' },
    'apt-daily.service': { en: 'APT package metadata', de: 'APT-Paketmetadaten' },
    'apt-daily-upgrade.service': { en: 'APT automatic updates', de: 'Automatische APT-Updates' },
    'unattended-upgrades.service': { en: 'Unattended package updates', de: 'Unbeaufsichtigte Paketupdates' },
    'systemd-logind.service': { en: 'Login sessions', de: 'Anmeldesitzungen' },
    'systemd-journald.service': { en: 'Journal daemon diagnostics', de: 'Diagnose des Journal-Dienstes' },
    'rsyslog.service': { en: 'Syslog daemon diagnostics', de: 'Diagnose des Syslog-Dienstes' },
    'nginx.service': { en: 'Nginx web server', de: 'Nginx-Webserver' },
    'apache2.service': { en: 'Apache web server', de: 'Apache-Webserver' },
    'postgresql.service': { en: 'PostgreSQL database', de: 'PostgreSQL-Datenbank' },
    'mariadb.service': { en: 'MariaDB database', de: 'MariaDB-Datenbank' },
};
export function journalServiceLabel(unit: string, locale: 'en' | 'de'): string | null {
    return validJournalUnit(unit) && Object.hasOwn(serviceLabels, unit) ? serviceLabels[unit][locale] : null;
}
/** These are literal, bounded searches of existing inventory, not source probes.
 * Keep the applied term visible and never silently expand a selected unit. */
export const journalServiceSearches: readonly { term: string; label: Label }[] = [
    { term: 'ssh', label: { en: 'SSH logins', de: 'SSH-Anmeldungen' } },
    { term: 'docker', label: { en: 'Docker', de: 'Docker' } },
    { term: 'containerd', label: { en: 'Container runtime', de: 'Container-Laufzeit' } },
    { term: 'network', label: { en: 'Networking', de: 'Netzwerk' } },
    { term: 'resolved', label: { en: 'DNS', de: 'DNS' } },
    { term: 'cron', label: { en: 'Scheduled jobs', de: 'Geplante Aufgaben' } },
    { term: 'apt', label: { en: 'APT updates', de: 'APT-Updates' } },
    { term: 'tracebolt', label: { en: 'Tracebolt', de: 'Tracebolt' } },
];

export type JournalSourceAccess = 'unknown' | 'not_configured' | 'denied' | 'disabled' | 'helper_unavailable';
/** A request result is historical and query-specific, never reusable authority.
 * Do not attribute an old service's failure to a newly selected unit. */
export function journalSourceAccess(view: JournalView | null, unit: string): JournalSourceAccess {
    if (view?.configured === false) return 'not_configured';
    if (!view?.request || !validJournalUnit(unit) || view.request.description.query.unit !== unit) return 'unknown';
    if (['denied', 'disabled', 'helper_unavailable'].includes(view.localStatus)) return view.localStatus as JournalSourceAccess;
    return 'unknown';
}
