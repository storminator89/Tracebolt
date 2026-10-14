import { ArrowRight } from 'lucide-react';
import { EmptyState, Loading } from './components';
import { useLocale } from './i18n';
import './fleet-empty-state.css';

const copy = {
    en: {
        empty: 'No devices yet',
        setup: 'Review device setup',
        overview: 'Review setup options and existing invitations. After approval, check the latest device report for incoming data.',
        inventory: 'Use device setup above to review available options and existing invitations. Approval alone does not confirm that data is arriving.',
        readOnly: 'Adding devices requires the shared administrator. This account can view devices once they are available.',
        unknown: 'Setup permissions are not confirmed for this session. Ask the administrator to check device setup.',
        refreshing: 'Refreshing device data…',
        unavailable: 'Device list unavailable',
        retry: 'The current device list could not be loaded.',
        localEmpty: 'No devices available',
        localDetail: 'The manager returned no devices. There are no device rows to filter.',
    },
    de: {
        empty: 'Noch keine Geräte',
        setup: 'Geräteeinrichtung prüfen',
        overview: 'Prüfe Einrichtungsoptionen und bestehende Einladungen. Nach der Freigabe zeigt der erste Gerätebericht, ob Daten ankommen.',
        inventory: 'Prüfe oben in der Geräteeinrichtung verfügbare Optionen und bestehende Einladungen. Eine Freigabe allein bestätigt keinen Dateneingang.',
        readOnly: 'Nur der gemeinsame Administrator kann Geräte hinzufügen. Dieses Konto kann Geräte anzeigen, sobald sie verfügbar sind.',
        unknown: 'Die Einrichtungsberechtigung dieser Sitzung ist nicht bestätigt. Bitte den Administrator, die Geräteeinrichtung zu prüfen.',
        refreshing: 'Gerätedaten werden aktualisiert …',
        unavailable: 'Geräteliste nicht verfügbar',
        retry: 'Der aktuelle Gerätestand konnte nicht geladen werden.',
        localEmpty: 'Keine Geräte verfügbar',
        localDetail: 'Der Manager hat keine Geräte zurückgegeben. Es gibt keine Gerätezeilen zum Filtern.',
    },
} as const;

// Call only when the unfiltered source has no device rows. A retained empty
// response during refresh/failure is not current evidence of an empty fleet.
export function FleetEmptyState({ lan, loading, failed, admin, named, onSetup }: {
    lan: boolean;
    loading: boolean;
    failed: boolean;
    admin: boolean;
    named: boolean;
    onSetup?: () => void;
}) {
    const [locale] = useLocale(), c = copy[locale];
    if (loading) return <Loading label={c.refreshing}/>;
    if (failed) return <EmptyState title={c.unavailable} detail={c.retry}/>;
    if (!lan) return <EmptyState title={c.localEmpty} detail={c.localDetail}/>;
    return <EmptyState title={c.empty} detail={admin ? (onSetup ? c.overview : c.inventory) : named ? c.readOnly : c.unknown}
        action={onSetup && <button className="button primary" disabled={!admin} onClick={onSetup}>{c.setup}<ArrowRight size={15} aria-hidden="true"/></button>}/>;
}
