import { WindowsStorageContextPanel } from './windows-storage-context';
import { WindowsHardwareContextPanel } from './windows-hardware-context';
import { WindowsSessionContextPanel } from './windows-session-context';
import { WindowsSecurityPosturePanel } from './windows-security-posture';
import { WindowsPatchContextPanel } from './windows-patch-context';
import { WindowsUpdatesPanel } from './windows-updates';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { WindowsInventoryResource } from './windows-inventory-resource';

type ContextKind = 'updates' | 'patchContext' | 'securityPosture' | 'sessionContext' | 'hardwareContext' | 'storageContext';
const panels = { storageContext: WindowsStorageContextPanel, hardwareContext: WindowsHardwareContextPanel, updates: WindowsUpdatesPanel, patchContext: WindowsPatchContextPanel, securityPosture: WindowsSecurityPosturePanel, sessionContext: WindowsSessionContextPanel };

/** Never merge generations or replace the latest attempt's source failure. */
export function WindowsContextPanel({ resource, kind }: { resource: WindowsInventoryResource; kind: ContextKind }) {
    const [locale] = useLocale(), Panel = panels[kind], current = resource[kind], old = resource.view?.retainedContext?.[kind];
    const age = old && resource.view ? inventoryAge(resource.view.serverNow, old.collectedAt) + resource.elapsedMS : Infinity;
    const visible = old && current && resource.snapshot && ['fresh', 'stale'].includes(resource.status ?? '') && old.grantId === current.grantId && Number.isFinite(age) && age >= 0 && age < 86400000;
    const previous = visible ? { ...resource, [kind]: old, [`${kind}Stale`]: age > 120000 } : null;
    return <>
        <Panel resource={resource}/>
        {previous && old && <details className="windows-inventory-bounds" key={`${kind}:${old.grantId}:${old.generationId}:${old.collectedAt}`}>
            <summary>{locale === 'de' ? 'Vorherige Erfassung anzeigen' : 'Show previous capture'}</summary>
            <p className="windows-inventory-caution">{locale === 'de' ? 'Der letzte Versuch hat diese frühere Beobachtung nicht ersetzt. Sie behält ihre ursprüngliche Erfassungszeit und belegt keinen aktuellen Zustand.' : 'The latest attempt did not replace this earlier observation. It keeps its original capture time and does not establish current state.'}</p>
            <Panel resource={previous}/>
        </details>}
    </>;
}
