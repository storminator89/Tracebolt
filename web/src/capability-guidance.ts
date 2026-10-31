import type { CapabilityObservation, CapabilityState } from './capability-observations';

/** Presentation only. Neither a supported profile nor a status read grants a
 * local scope. Unknown configuration/access must never become inferred consent. */
export const capabilityLabels: Record<'en' | 'de', Record<CapabilityState, string>> = {
    en: { supported: 'Supported', available: 'Collected', scope: 'Profile scope', unsupported: 'Not supported', denied: 'Permission denied', failed: 'Technical failure', not_configured: 'Not configured', not_granted: 'Not granted locally', not_collected: 'Not yet collected', stale: 'Stale', unknown: 'Unknown', pending: 'Transfer pending', partial: 'Incomplete fields', configured: 'Configured' },
    de: { supported: 'Unterstützt', available: 'Erfasst', scope: 'Profilumfang', unsupported: 'Nicht unterstützt', denied: 'Zugriff verweigert', failed: 'Technisch fehlgeschlagen', not_configured: 'Nicht eingerichtet', not_granted: 'Lokal nicht freigegeben', not_collected: 'Noch nicht erfasst', stale: 'Veraltet', unknown: 'Unbekannt', pending: 'Übertragung ausstehend', partial: 'Unvollständige Felder', configured: 'Eingerichtet' },
};

const steps: Record<'en' | 'de', Partial<Record<CapabilityState, string>>> = {
    en: {
        unsupported: 'Check the supported platform, profile and source. Refreshing or selecting a capability cannot add support.',
        not_granted: 'The reported local scope is disabled. Review only the required new scope on the endpoint; any new approval starts unchecked.',
        not_collected: 'No accepted collection is available yet. Check the existing agent and its next report; do not create another enrollment or repeat a write.',
        stale: 'Check the original capture time and existing agent connectivity. Reading retained data does not make it current.',
        failed: 'Check the source or transfer error in its inventory view, then read status again. A failed read is not an empty or healthy result.',
        denied: 'Check operator access and the reported source permissions separately. Do not infer a missing local grant or widen permissions automatically.',
        not_configured: 'Check the manager profile and endpoint setup separately. Missing configuration does not prove whether local consent exists.',
        unknown: 'Read the source status or sign in again if access ended. The cause is unconfirmed; do not infer support, consent or a healthy result.',
        pending: 'Wait for the existing transfer and read its status. Do not start a replacement operation.',
        partial: 'Open the inventory field coverage. Keep unavailable and denied fields distinct from observed zero values.',
    },
    de: {
        unsupported: 'Unterstütztes Betriebssystem, Profil und Quelle prüfen. Aktualisieren oder Auswählen einer Fähigkeit fügt keine Unterstützung hinzu.',
        not_granted: 'Der gemeldete lokale Umfang ist deaktiviert. Nur den erforderlichen neuen Umfang am Gerät prüfen; jede neue Zustimmung startet ungeprüft.',
        not_collected: 'Noch keine akzeptierte Erfassung verfügbar. Vorhandenen Agenten und seine nächste Meldung prüfen; keine neue Aufnahme oder Schreibwiederholung starten.',
        stale: 'Ursprüngliche Erfassungszeit und Verbindung des vorhandenen Agenten prüfen. Das Lesen gespeicherter Daten macht sie nicht aktuell.',
        failed: 'Quell- oder Übertragungsfehler in der Inventaransicht prüfen, dann den Status erneut lesen. Ein Lesefehler belegt weder leere Daten noch einen gesunden Zustand.',
        denied: 'Operatorzugriff und gemeldete Quellberechtigungen getrennt prüfen. Keine fehlende lokale Freigabe ableiten oder Rechte automatisch erweitern.',
        not_configured: 'Managerprofil und Einrichtung am Gerät getrennt prüfen. Fehlende Konfiguration belegt nicht, ob lokale Zustimmung vorliegt.',
        unknown: 'Quellstatus lesen oder bei beendeter Sitzung erneut anmelden. Ursache unbestätigt; keine Unterstützung, Zustimmung oder Gesundheit ableiten.',
        pending: 'Vorhandene Übertragung abwarten und ihren Status lesen. Keinen Ersatzvorgang starten.',
        partial: 'Feldabdeckung im Inventar öffnen. Nicht verfügbare und verweigerte Felder bleiben von beobachteten Nullwerten getrennt.',
    },
};

export function capabilityNextStep(result: CapabilityObservation, locale: 'en' | 'de'): string | undefined {
    return steps[locale][result.state];
}

// These are explanations, not claims that all five causes occurred on a device.
export const missingDataStates = ['unsupported', 'not_granted', 'not_collected', 'stale', 'failed'] as const;
