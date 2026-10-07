import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { useLocale } from './i18n';
export type FleetCopyResult = 'copied' | 'selected' | 'unavailable';

/** User-initiated only. No permission queries, external calls or hidden copy cache. */
export async function copyFleetValue(value: string, element: HTMLElement): Promise<FleetCopyResult> {
    const current = () => element.isConnected && element.textContent === value;
    if (!current()) return 'unavailable';
    if (window.isSecureContext && typeof navigator.clipboard?.writeText === 'function') {
        try { await navigator.clipboard.writeText(value); return 'copied'; } catch { /* Try the selected-text path in this document. */ }
    }
    // A delayed clipboard denial must not copy a disappeared or replaced value.
    if (!current()) return 'unavailable';
    const selection = window.getSelection();
    if (!selection) return 'unavailable';
    const previousFocus = document.activeElement;
    const previousRanges = Array.from({ length: selection.rangeCount }, (_, index) => selection.getRangeAt(index).cloneRange());
    try {
        element.focus({ preventScroll: true });
        const range = document.createRange(); range.selectNodeContents(element);
        selection.removeAllRanges(); selection.addRange(range);
        if (selection.toString() !== value) return 'unavailable';
    } catch { return 'unavailable'; }
    let copied = false;
    try { copied = typeof document.execCommand === 'function' && document.execCommand('copy') === true; } catch { /* Leave real text selected for manual copying. */ }
    if (!copied) return 'selected';
    try {
        if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus({ preventScroll: true });
        selection.removeAllRanges();
        for (const range of previousRanges) if (range.commonAncestorContainer.isConnected) selection.addRange(range);
    } catch { /* Copy succeeded; restoring earlier focus/selection is best effort. */ }
    return 'copied';
}

export function FleetCopyValue({ value, label, hostname = false }: { value: string; label: string; hostname?: boolean }) {
    const [locale] = useLocale(), element = useRef<HTMLSpanElement>(null), generation = useRef(0), timer = useRef<number | undefined>(undefined);
    const [state, setState] = useState<'idle' | 'pending' | FleetCopyResult>('idle');
    useEffect(() => {
        generation.current++; setState('idle');
        return () => { generation.current++; window.clearTimeout(timer.current); };
    }, [value]);
    const copy = async () => {
        if (!element.current || state === 'pending') return;
        const token = generation.current;
        window.clearTimeout(timer.current); setState('pending');
        const result = await copyFleetValue(value, element.current);
        if (generation.current !== token) return;
        setState(result);
        if (result === 'copied') timer.current = window.setTimeout(() => { if (generation.current === token) setState('idle'); }, 2200);
    };
    const message = state === 'copied' ? locale === 'de' ? 'Kopiert' : 'Copied' : state === 'selected' ? locale === 'de' ? 'Text ausgewählt. Manuell kopieren.' : 'Text selected. Copy it manually.' : state === 'unavailable' ? locale === 'de' ? 'Bitte den Text manuell markieren und kopieren.' : 'Please select and copy the text manually.' : '';
    return <div className={`fleet-copy-value ${hostname ? 'fleet-copy-hostname' : ''}`}>
        <div className="fleet-copy-line"><span ref={element} tabIndex={-1} className={`fleet-copy-text ${hostname ? '' : 'mono'}`}>{hostname ? <strong>{value}</strong> : value}</span><button type="button" className="fleet-copy-button" aria-label={label} title={label} disabled={state === 'pending'} aria-busy={state === 'pending'} onClick={event => { event.stopPropagation(); void copy(); }}>{state === 'copied' ? <Check size={14}/> : <Copy size={14}/>}</button></div>
        {message && <span className="fleet-copy-feedback" role="status">{message}</span>}
    </div>;
}
