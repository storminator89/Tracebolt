import type { FleetUpdateGroup } from './windows-fleet-update-triage-resource';
import type { WindowsUpdate } from './windows-updates-types';

export type FleetUpdateFilters = {
    query: string;
    severity: 'all' | WindowsUpdate['severity'];
    downloaded: 'all' | 'downloaded' | 'not-downloaded';
    sort: 'identity' | 'severity' | 'reporting';
};
export const emptyFleetUpdateFilters = (): FleetUpdateFilters => ({ query: '', severity: 'all', downloaded: 'all', sort: 'identity' });
const rank = { unspecified: 0, low: 1, moderate: 2, important: 3, critical: 4 };
const identityOrder = (a: FleetUpdateGroup, b: FleetUpdateGroup) => (a.updateId < b.updateId ? -1 : a.updateId > b.updateId ? 1 : 0) || a.revision - b.revision;
const highestSeverity = (group: FleetUpdateGroup) => Math.max(0, ...group.reports.map(({ row }) => rank[row.severity]));

/** Local presentation only. All predicates must match one original device row.
 * Keep the complete group intact: filters never change reporting-device selection,
 * source evidence, cached download flags or the separate readiness workflow. */
export function filterFleetUpdateGroups(groups: readonly FleetUpdateGroup[], filters: FleetUpdateFilters, locale: 'en' | 'de'): FleetUpdateGroup[] {
    const query = filters.query.trim().toLocaleLowerCase(locale);
    return groups.filter(group => group.reports.some(({ row }) =>
        (filters.severity === 'all' || row.severity === filters.severity) &&
        (filters.downloaded === 'all' || row.downloaded === (filters.downloaded === 'downloaded')) &&
        [group.updateId, String(group.revision), row.title, ...row.kbArticleIds, row.severity].join(' ').toLocaleLowerCase(locale).includes(query)
    )).sort((a, b) => (filters.sort === 'severity' ? highestSeverity(b) - highestSeverity(a) : filters.sort === 'reporting' ? b.reports.length - a.reports.length : 0) || identityOrder(a, b));
}
