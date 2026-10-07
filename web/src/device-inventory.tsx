import { useEffect, useId, useState } from 'react';
import { useOperator } from './auth';
import { useLocale } from './i18n';
import { OperationalInventoryPanel } from './operational';
import { CompletePackagesPanel } from './complete-packages';
import { DeviceCachedUpdates } from './cached-updates';
import { CompleteUpdatesPanel } from './complete-updates';
import { SystemInventoryPanel } from './system-inventory';
import { CompleteOverviewPanel } from './complete-overview';
import './complete-packages.css';
import './device-security.css';

/** Only the selected inventory source is mounted. Switching a tab destroys its
 * private request/cursor state instead of stacking multiple partial previews. */
export function DeviceInventoryWorkspace({ deviceId, initialSource, onOpenLogs }: { deviceId: string; initialSource?: 'processes' | 'preview' | 'packages' | 'updates'; onOpenLogs?: (unit: string) => void }) {
    const operator = useOperator(), [locale] = useLocale(), [selected, setSelected] = useState<string>(operator?.mode === 'lan' && operator.authenticated ? initialSource ?? 'packages' : 'preview'), id = useId();
    const authorized = operator?.mode === 'lan' && operator.authenticated;
    useEffect(() => { if (initialSource === 'packages' || initialSource === 'updates') document.getElementById(`${id}-${initialSource}`)?.focus(); }, [id, initialSource]);
    const tabs = authorized ? [{ key: 'processes', text: locale === 'de' ? 'Prozesse' : 'Processes' }, { key: 'volumes', text: locale === 'de' ? 'Mounts' : 'Mounts' },{ key: 'packages', text: locale === 'de' ? 'Pakete' : 'Packages' }, { key: 'updates', text: 'Updates' }, { key: 'services', text: locale === 'de' ? 'Dienste' : 'Services' }, { key: 'sockets', text: locale === 'de' ? 'Verbindungen' : 'Connections' }, ...(selected === 'preview' ? [{ key: 'preview', text: locale === 'de' ? 'Ältere begrenzte Vorschau' : 'Legacy bounded preview' }] : [])] : [{ key: 'preview', text: locale === 'de' ? 'Begrenzte Vorschau' : 'Bounded preview' }];
    return <div className="inventory-workspace"><div className="inventory-source-tabs" role="tablist" aria-label={locale === 'de' ? 'Inventarquelle' : 'Inventory source'}>{tabs.map((tab, index) => <button key={tab.key} id={`${id}-${tab.key}`} role="tab" aria-selected={selected === tab.key} aria-controls={`${id}-panel`} tabIndex={selected === tab.key ? 0 : -1} onClick={() => setSelected(tab.key)} onKeyDown={event => { const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null; if (next !== null) { event.preventDefault(); setSelected(tabs[next].key); document.getElementById(`${id}-${tabs[next].key}`)?.focus(); } }}>{tab.text}</button>)}</div>{authorized && <details className="device-legacy-sources inventory-legacy-source" onToggle={event => { if (!event.currentTarget.open && selected === 'preview') setSelected('packages'); }} open={selected === 'preview' ? true : undefined}><summary>{locale === 'de' ? 'Ältere Inventarquelle' : 'Legacy inventory source'}</summary><button type="button" id={`${id}-open-preview`} className="button small" aria-pressed={selected === 'preview'} onClick={() => setSelected('preview')}>{locale === 'de' ? 'Begrenzte Vorschau öffnen' : 'Open bounded preview'}</button></details>}<div role="tabpanel" id={`${id}-panel`} aria-labelledby={`${id}-${selected}`}>
        {selected === 'preview' && <><div className="inventory-preview-intro"><p>{locale === 'de' ? 'Begrenzte Stichprobe, keine vollständigen Inventarzahlen. Vollständige Prozess- und Mount-Erfassung braucht eine eigene lokale Freigabe.' : 'Bounded sample, not full inventory totals. Complete process and mount collection needs its own local opt-in.'}</p></div><OperationalInventoryPanel deviceId={deviceId}/></>}
        {authorized && (selected === 'processes' || selected === 'volumes') && <CompleteOverviewPanel deviceId={deviceId} section={selected} sessionKey={operator.expiresAt ?? undefined}/>}
        {authorized && selected === 'packages' && <CompletePackagesPanel deviceId={deviceId} sessionKey={operator.expiresAt ?? undefined} inline/>}
        {authorized && selected === 'updates' && <DeviceUpdatesWorkspace key={`${deviceId}:${operator.expiresAt ?? ''}`} deviceId={deviceId} sessionKey={operator.expiresAt ?? null}/>}
        {authorized && (selected === 'services' || selected === 'sockets') && <SystemInventoryPanel deviceId={deviceId} section={selected} sessionKey={operator.expiresAt ?? undefined} onOpenLogs={onOpenLogs}/>}
    </div></div>;
}

/** The separately consented complete generation and older bounded preview share
 * storage admission. Mount only the chosen reader, just as the source tabs do. */
function DeviceUpdatesWorkspace({ deviceId, sessionKey }: { deviceId: string; sessionKey: string | null }) {
    const [source, setSource] = useState('complete'), [locale] = useLocale(), id = useId();
    return <>
        <div className="complete-package-search">
            <label htmlFor={id}>{locale === 'de' ? 'Updateansicht' : 'Update view'}</label>
            <select id={id} value={source} onChange={event => setSource(event.target.value)}>
                <option value="complete">{locale === 'de' ? 'Vollständige Kandidaten' : 'Complete candidates'}</option>
                <option value="preview">{locale === 'de' ? 'Begrenzte Vorschau' : 'Limited preview'}</option>
            </select>
        </div>
        {source === 'complete' ? <CompleteUpdatesPanel deviceId={deviceId} sessionKey={sessionKey ?? undefined}/> : <DeviceCachedUpdates deviceId={deviceId} sessionKey={sessionKey}/>}
    </>;
}
