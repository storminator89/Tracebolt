import { t, translatedLabels, dateLocale, getLocale } from './i18n';
import type { Device, DeviceStatus, Platform } from './types';
export const statusLabels = translatedLabels({healthy:'Unauffällig',attention:'Prüfen',critical:'Kritisch',stale:'Veraltet',unknown:'Unbekannt'});
export const platformLabels: Record<Platform, string> = { windows: 'Windows', linux: 'Linux', macos: 'macOS', get unknown(){return t('Unbekannt');} };
export const qualityLabels = translatedLabels({healthy:'Aktuell',stale:'Veraltet',unknown:'Nicht verfügbar',denied:'Zugriff verweigert'});
export const caseStatusLabels = translatedLabels({open:'Offen',investigating:'In Untersuchung',resolved:'Abgeschlossen'});
function operationalTime(date: string): number {
    if (!date)
        return Number.NaN;
    const time = new Date(date).getTime();
    return time === -62135596800000 ? Number.NaN : time;
}
export function relativeTime(date: string, now = Date.now()): string {
    const time = operationalTime(date);
    if (!Number.isFinite(time))
        return t("Zeitpunkt unbekannt");
    const seconds = Math.max(0, Math.floor((now - time) / 1000));
    if (seconds < 60)
        return t("gerade eben");
    if (seconds < 3600)
        return t("vor {0} Min.", { "0": Math.floor(seconds / 60) });
    if (seconds < 86400)
        return t("vor {0} Std.", { "0": Math.floor(seconds / 3600) });
    return seconds < 172800 ? t("vor einem Tag") : t("vor {0} Tagen", { "0": Math.floor(seconds / 86400) });
}
export function fullDate(date: string): string {
    const value = new Date(operationalTime(date));
    return Number.isNaN(value.getTime()) ? t("Zeitpunkt unbekannt") : new Intl.DateTimeFormat(dateLocale(), { dateStyle: 'medium', timeStyle: 'medium' }).format(value);
}
export interface Filters {
    query: string;
    platform: string;
    status: string;
    source: string;
    sort: string;
}
export const defaultFilters: Filters = { query: '', platform: 'all', status: 'all', source: 'all', sort: 'priority' };
export function filterDevices(devices: Device[], filters: Filters): Device[] {
    const priority: Record<DeviceStatus, number> = { critical: 0, attention: 1, stale: 2, unknown: 3, healthy: 4 };
    return devices.filter(d => (filters.platform === 'all' || d.platform === filters.platform) && (filters.status === 'all' || (filters.status === 'needs-attention' ? ['critical', 'attention'].includes(d.status) : d.status === filters.status)) && (filters.source === 'all' || (filters.source === 'local' ? ['sandbox','local'].includes(d.source) : d.source === filters.source)) && `${d.name} ${d.os} ${d.site} ${d.group} ${d.tags.join(' ')} ${d.ip || ''}`.toLocaleLowerCase(getLocale()).includes(filters.query.trim().toLocaleLowerCase(getLocale()))).sort((a, b) => filters.sort === 'name' ? a.name.localeCompare(b.name,getLocale()) : filters.sort === 'seen' ? new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime() : priority[a.status] - priority[b.status] || a.name.localeCompare(b.name,getLocale()));
}
export function readSaved<T>(key: string, fallback: T): T {
    try {
        const saved = localStorage.getItem(key);
        return saved ? JSON.parse(saved) as T : fallback;
    }
    catch {
        return fallback;
    }
}
export function saveLocal(key: string, data: unknown): void {
    try {
        localStorage.setItem(key, JSON.stringify(data));
    }
    catch { /* The app remains usable with storage disabled. */ }
}
export function csvCell(value: unknown): string {
    let text = String(value ?? "");
    if (/^[=+@\-\t\r\n]/.test(text.trimStart()) || /^[\t\r\n]/.test(text))
        text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
}
export function decodeRouteId(id: string | undefined): string | undefined {
    if (!id)
        return undefined;
    try {
        return decodeURIComponent(id);
    }
    catch {
        return undefined;
    }
}
export function noteBytes(value: string): number { return new TextEncoder().encode(value).length; }
/** Browser storage is untrusted and may contain data from earlier app versions. */
export function normalizeFilters(value: unknown): Filters {
    const candidate = value !== null && typeof value === 'object' ? value as Record<string, unknown> : {};
    const oneOf = (key: string, allowed: string[], fallback: string) => typeof candidate[key] === 'string' && allowed.includes(candidate[key] as string) ? candidate[key] as string : fallback;
    return { query: typeof candidate.query === 'string' ? candidate.query : '', platform: oneOf('platform', ['all', 'windows', 'linux', 'macos','unknown'], 'all'), status: oneOf('status', ['all', 'healthy', 'attention', 'needs-attention', 'critical', 'stale', 'unknown'], 'all'), source: oneOf('source', ['all', 'synthetic', 'sandbox', 'local','lan'], 'all'), sort: oneOf('sort', ['priority', 'name', 'seen'], 'priority') };
}
export function savedFilters(): Filters | null { const stored = readSaved<unknown>('local-rmm-saved-view', null); return stored !== null && typeof stored === 'object' ? normalizeFilters(stored) : null; }
