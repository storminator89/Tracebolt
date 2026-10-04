import { useId, useState } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { OperationalInventoryPanel } from './operational';
import { CompletePackagesPanel } from './complete-packages';
import { SystemInventoryPanel } from './system-inventory';
import './complete-packages.css';

/** Only the selected inventory source is mounted. Switching a tab destroys its
 * private request/cursor state instead of stacking multiple partial previews. */
export function DeviceInventoryWorkspace({ deviceId }: { deviceId: string }) {
    const operator = useOperator(), [locale] = useLocale(), [selected, setSelected] = useState('preview'), id = useId();
    const authorized = operator?.mode === 'lan' && operator.authenticated;
    const tabs = [{ key: 'preview', text: locale === 'de' ? 'Begrenzte Vorschau' : 'Bounded preview' }, ...(authorized ? [{ key: 'packages', text: locale === 'de' ? 'Pakete' : 'Packages' }, { key: 'services', text: locale === 'de' ? 'Dienste' : 'Services' }, { key: 'sockets', text: locale === 'de' ? 'Verbindungen' : 'Connections' }] : [])];
    return <div className="inventory-workspace"><div className="inventory-source-tabs" role="tablist" aria-label={locale === 'de' ? 'Inventarquelle' : 'Inventory source'}>{tabs.map((tab, index) => <button key={tab.key} id={`${id}-${tab.key}`} role="tab" aria-selected={selected === tab.key} aria-controls={`${id}-panel`} tabIndex={selected === tab.key ? 0 : -1} onClick={() => setSelected(tab.key)} onKeyDown={event => { const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null; if (next !== null) { event.preventDefault(); setSelected(tabs[next].key); document.getElementById(`${id}-${tabs[next].key}`)?.focus(); } }}>{tab.text}</button>)}</div><div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-${selected}`}>
        {selected === 'preview' && <><p className="package-note inventory-preview-note">{locale === 'de' ? 'Diese ältere Betriebsvorschau enthält begrenzte Ausschnitte. Die separaten Registerkarten zeigen vollständig empfangene Paket-, Dienst- und Socket-Abschnitte mit begrenztem Blättern.' : 'This legacy operational preview contains bounded selections. The separate tabs show complete received package, service and socket sections using bounded pagination.'}</p><OperationalInventoryPanel deviceId={deviceId}/></>}
        {authorized && selected === 'packages' && <CompletePackagesPanel deviceId={deviceId} sessionKey={operator.expiresAt ?? undefined} inline/>}
        {authorized && (selected === 'services' || selected === 'sockets') && <SystemInventoryPanel deviceId={deviceId} section={selected} sessionKey={operator.expiresAt ?? undefined}/>}
    </div></div>;
}
