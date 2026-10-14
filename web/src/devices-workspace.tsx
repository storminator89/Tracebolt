import { useRef, useState, type ReactNode } from 'react';
import { ArrowDown } from 'lucide-react';
import { useLocale } from './i18n';
import type { EnrollmentAttention } from './enrollment-attention';
import './devices-workspace.css';

const copy = {
    en: { index: 'Device workspaces', inventory: 'Inventory', setup: 'Setup', tools: 'Fleet tools', selected: 'Selected setup', checking: 'Checking status', unknown: 'Status unknown', unavailable: 'Setup unavailable', manual: 'Manual approval', pending: 'Awaiting review', unconfirmed: 'Action unconfirmed', expired: 'Invitation deadline passed', 'retained-review': 'Review retained invitations', profileUnknown: 'Profile not checked', platformUnknown: 'Platform not checked', local: 'Device setup requires a LAN manager.', toolsUnavailable: 'Fleet tools are unavailable in this context.', toolsScope: 'Each tool keeps its own scope and review controls.', inventoryScope: 'Search, compare and open devices.' },
    de: { index: 'Gerätebereiche', inventory: 'Inventar', setup: 'Einrichten', tools: 'Flottentools', selected: 'Gewählte Einrichtung', checking: 'Status wird geprüft', unknown: 'Status unbekannt', unavailable: 'Einrichtung nicht verfügbar', manual: 'Manuelle Freigabe', pending: 'Prüfung ausstehend', unconfirmed: 'Aktion nicht bestätigt', expired: 'Einladungsfrist abgelaufen', 'retained-review': 'Gespeicherte Einladungen prüfen', profileUnknown: 'Profil nicht geprüft', platformUnknown: 'Betriebssystem nicht geprüft', local: 'Geräteeinrichtung erfordert einen LAN-Manager.', toolsUnavailable: 'Flottentools sind in diesem Kontext nicht verfügbar.', toolsScope: 'Jedes Werkzeug behält seinen eigenen Umfang und seine Prüfkontrollen.', inventoryScope: 'Geräte suchen, vergleichen und öffnen.' },
} as const;
const profiles = {
    en: { 'basic-readonly-v1': 'Basic read-only', 'managed-operations-v1': 'Operational inventory', 'managed-operations-v2': 'Package inventory', 'managed-operations-v3': 'Complete inventory', 'windows-inventory-v1': 'Windows inventory', 'macos-read-inventory-v1': 'macOS inventory' },
    de: { 'basic-readonly-v1': 'Basis, nur lesend', 'managed-operations-v1': 'Betriebsinventar', 'managed-operations-v2': 'Paketinventar', 'managed-operations-v3': 'Vollständiges Inventar', 'windows-inventory-v1': 'Windows-Inventar', 'macos-read-inventory-v1': 'macOS-Inventar' },
} as const;
export function DevicesWorkspace({ inventory, setup, tools, lan, toolsAvailable }: {
    inventory: ReactNode;
    setup: (notify: (value: EnrollmentAttention | null) => void) => ReactNode;
    tools: ReactNode;
    lan: boolean;
    toolsAvailable: boolean;
}) {
    const [locale] = useLocale(), c = copy[locale];
    const [attention, setAttention] = useState<EnrollmentAttention | null>(null);
    const inventoryHeading = useRef<HTMLHeadingElement>(null), setupHeading = useRef<HTMLHeadingElement>(null), toolsHeading = useRef<HTMLHeadingElement>(null);
    const jump = (heading: HTMLHeadingElement | null) => {
        // These are local document jumps, never route changes. All modules and
        // dialogs stay mounted, including active or uncertain tool operations.
        heading?.focus({ preventScroll: true });
        if (!heading) return;
        const main = heading.closest<HTMLElement>('#main-content');
        if (main) {
            const margin = parseFloat(getComputedStyle(heading).scrollMarginBlockStart) || 0;
            main.scrollTop = Math.max(0, main.scrollTop + heading.getBoundingClientRect().top - main.getBoundingClientRect().top - margin);
        } else heading.scrollIntoView({ block: 'start', behavior: 'instant' });
    };
    const sections = [[c.inventory, inventoryHeading, 'devices-inventory-heading'], [c.setup, setupHeading, 'devices-setup-heading'], [c.tools, toolsHeading, 'devices-tools-heading']] as const;
    const status = attention?.state ?? 'checking';
    const label = status === 'pending-review' ? c.pending : c[status];
    return <div className="devices-workspace">
        <nav className="devices-workspace-index" aria-label={c.index}>
            {sections.map(([title, ref, id]) => <button type="button" key={id} aria-controls={id} aria-describedby={lan && id === 'devices-setup-heading' ? 'devices-setup-attention' : undefined} onClick={() => jump(ref.current)}>{title}<ArrowDown size={14} aria-hidden="true"/></button>)}
        </nav>
        {lan && <div id="devices-setup-attention" className="devices-setup-attention" data-state={status}>
            <span>{c.selected}: <strong>{attention?.platform === 'darwin' ? 'macOS' : attention?.platform === 'windows' ? 'Windows' : attention?.platform === 'linux' ? 'Linux' : c.platformUnknown}</strong> · {attention?.profile ? profiles[locale][attention.profile] : c.profileUnknown}</span>
            <span>{label}{status === 'pending-review' && attention?.pendingCount !== null && attention?.pendingCount !== undefined ? ` · ${attention.pendingCount}` : ''}</span>
        </div>}
        <section className="devices-inventory-section" aria-labelledby="devices-inventory-heading">
            <header className="devices-workspace-heading"><h2 ref={inventoryHeading} id="devices-inventory-heading" tabIndex={-1}>{c.inventory}</h2><p>{c.inventoryScope}</p></header>
            {inventory}
        </section>
        <section className="devices-setup-section" aria-labelledby="devices-setup-heading">
            <header className="devices-workspace-heading"><h2 ref={setupHeading} id="devices-setup-heading" tabIndex={-1}>{c.setup}</h2></header>
            {lan ? setup(setAttention) : <p className="devices-workspace-unavailable">{c.local}</p>}
        </section>
        <section className="devices-tools-section" aria-labelledby="devices-tools-heading">
            <header className="devices-workspace-heading"><h2 ref={toolsHeading} id="devices-tools-heading" tabIndex={-1}>{c.tools}</h2><p>{toolsAvailable ? c.toolsScope : c.toolsUnavailable}</p></header>
            {tools}
        </section>
    </div>;
}
