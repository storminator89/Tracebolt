import { EmptyState } from './components';
import type { FleetGroupsResource } from './fleet-groups';
import { useLocale } from './i18n';
import './fleet-group-inventory.css';

const copy = {
    en: {
        checking: 'Checking group membership…',
        checkingDetail: 'Devices will appear after the selected group has been checked.',
        unavailable: 'Group membership unavailable',
        unavailableDetail: 'The selected group cannot currently be checked. The device count is unknown.',
        missing: 'Selected group unavailable',
        missingDetail: 'The selected group is not in the current group list. Choose another group or clear the group filter.',
        empty: 'No visible group members',
        emptyDetail: 'The selected group has no members.',
        unavailableMembers: (count: number) => `${count} group members are currently unavailable. This does not prove that the devices are absent.`,
        selected: 'Selected group', refresh: 'Refresh group membership', overview: 'Refresh overview', clear: 'Clear group filter',
    },
    de: {
        checking: 'Gruppenmitgliedschaft wird geprüft …',
        checkingDetail: 'Geräte erscheinen, sobald die gewählte Gruppe geprüft wurde.',
        unavailable: 'Gruppenmitgliedschaft nicht verfügbar',
        unavailableDetail: 'Die gewählte Gruppe kann derzeit nicht geprüft werden. Die Gerätezahl ist unbekannt.',
        missing: 'Gewählte Gruppe nicht verfügbar',
        missingDetail: 'Die gewählte Gruppe fehlt in der aktuellen Gruppenliste. Eine andere Gruppe wählen oder den Gruppenfilter entfernen.',
        empty: 'Keine sichtbaren Gruppenmitglieder',
        emptyDetail: 'Die gewählte Gruppe hat keine Mitglieder.',
        unavailableMembers: (count: number) => `${count} Gruppenmitglieder sind derzeit nicht verfügbar. Das belegt nicht, dass die Geräte fehlen.`,
        selected: 'Gewählte Gruppe', refresh: 'Gruppenmitgliedschaft aktualisieren', overview: 'Übersicht aktualisieren', clear: 'Gruppenfilter entfernen',
    },
} as const;

/** Explains the existing closed membership filter without retaining old names
 * or treating an unverified roster as a genuine zero/search result. */
export function FleetGroupInventoryState({ resource, managerAvailable, managerLoading, onRefreshOverview }: {
    resource: FleetGroupsResource;
    managerAvailable: boolean;
    managerLoading: boolean;
    onRefreshOverview: () => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const checking = !resource.selected && (managerLoading || resource.loading);
    const state = checking ? 'checking' : resource.selected ? 'empty' : resource.view ? 'missing' : 'unavailable';
    const detail = state === 'empty' && resource.selected?.unavailableMembers
        ? c.unavailableMembers(resource.selected.unavailableMembers)
        : c[`${state}Detail`];
    return <div className="fleet-group-inventory-state" role="status" data-state={state}>
        <EmptyState title={c[state]} detail={detail} action={<div className="fleet-group-inventory-actions">
            <button type="button" className="button" disabled={checking} onClick={managerAvailable ? resource.refresh : onRefreshOverview}>{managerAvailable ? c.refresh : c.overview}</button>
            <button type="button" className="button" onClick={() => resource.select('')}>{c.clear}</button>
        </div>}/>
        <p className="fleet-group-inventory-selection">{c.selected}: <code>{resource.selectedId}</code></p>
    </div>;
}
