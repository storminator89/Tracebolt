import { useLocale } from './i18n';

const copy = {
    en: {
        summary: 'Organization, not tenant isolation',
        scope: 'Customer records, assignments and display filters are organizational only, not access control. They grant no collection or action rights and do not create customer-scoped API or export access.',
        separate: 'For confidential customer separation, use separate manager instances with separate identities, trust, state and backups. A frontend filter is not a security boundary.',
    },
    de: {
        summary: 'Organisation, keine Mandantentrennung',
        scope: 'Kundenstammdaten, Zuordnungen und Anzeigefilter dienen nur der Organisation, nicht der Zugriffskontrolle. Sie erteilen keine Erfassungs- oder Aktionsrechte und schaffen keine kundenspezifischen API- oder Exportrechte.',
        separate: 'Für vertrauliche Kundengrenzen getrennte Manager-Instanzen mit getrennten Identitäten, Vertrauensmaterialien, Zuständen und Backups verwenden. Ein Frontendfilter ist keine Sicherheitsgrenze.',
    },
} as const;

/** Disclosure only: customer selection is never an authorization input here. */
export function CustomerOrganizationNotice() {
    const [locale] = useLocale(), c = copy[locale];
    return <details className="customer-organization-notice">
        <summary>{c.summary}</summary>
        <p>{c.scope}</p>
        <p>{c.separate}</p>
    </details>;
}
