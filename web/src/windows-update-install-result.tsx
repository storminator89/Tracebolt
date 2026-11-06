import { Clock3, FileText, RotateCcw } from 'lucide-react';
import { useLocale } from './i18n';
import type { UpdateResult } from './windows-update-jobs-types';
import './windows-update-install-result.css';

const copy = {
    en: {
        title: 'Installation evidence', attempted: 'Attempt recorded', code: 'Saved result code',
        hresult: 'Saved HRESULT', reboot: 'Restart required', completed: 'Result recorded (UTC)',
        yes: 'Yes', no: 'No', unknown: 'Unknown',
        note: 'Saved executor fields, not current installation status. Codes alone do not establish success.',
        notAttempted: 'No installation attempt was recorded. Stored zero codes do not report success.',
    },
    de: {
        title: 'Installationsnachweis', attempted: 'Versuch vermerkt', code: 'Gespeicherter Ergebniscode',
        hresult: 'Gespeicherter HRESULT', reboot: 'Neustart erforderlich', completed: 'Ergebnis vermerkt (UTC)',
        yes: 'Ja', no: 'Nein', unknown: 'Unbekannt',
        note: 'Gespeicherte Executor-Felder, kein aktueller Installationsstatus. Codes allein belegen keinen Erfolg.',
        notAttempted: 'Kein Installationsversuch wurde vermerkt. Gespeicherte Nullcodes melden keinen Erfolg.',
    },
};

/** Display only the validated saved result. Installation lacks the download
 * contract's per-field known flags, so never decode zero into a success claim. */
export function WindowsUpdateInstallResult({ result }: { result: UpdateResult }) {
    const [locale] = useLocale(), c = copy[locale];
    if (result.purpose === 'download') return null;
    const completed = new Date(result.completedAt * 1000).toISOString();
    const hresult = `0x${(result.hresult >>> 0).toString(16).padStart(8, '0')}`;
    return <details className="windows-inventory-scope windows-update-install-result">
        <summary><FileText size={14} aria-hidden="true"/>{c.title}</summary>
        <dl>
            <div><dt>{c.attempted}</dt><dd>{result.attempted ? c.yes : c.no}</dd></div>
            <div><dt>{c.code}</dt><dd>{result.operationResult}</dd></div>
            <div><dt>{c.hresult}</dt><dd>{hresult} ({result.hresult})</dd></div>
            <div><dt><RotateCcw size={14} aria-hidden="true"/>{c.reboot}</dt><dd>{c[result.rebootRequired]}</dd></div>
            <div><dt><Clock3 size={14} aria-hidden="true"/>{c.completed}</dt><dd><time dateTime={completed}>{completed.replace('T', ' ').replace('.000Z', ' UTC')}</time></dd></div>
        </dl>
        <p className="windows-inventory-exclusions">{result.attempted ? c.note : c.notAttempted}</p>
    </details>;
}
