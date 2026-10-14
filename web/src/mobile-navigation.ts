import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';

// Keep this boundary in sync with the sidebar's responsive CSS.
const mobileQuery = '(max-width: 760px)';

export function useMobileNavigation(routeKey: string, helpOpen: boolean) {
    const [mobile, setMobile] = useState(() => window.matchMedia?.(mobileQuery).matches ?? false);
    const [expanded, setExpanded] = useState(false);
    const sidebarRef = useRef<HTMLElement>(null);
    const triggerRef = useRef<HTMLButtonElement>(null);
    const closeRef = useRef<HTMLButtonElement>(null);
    const helpReturnFocus = useRef<Element | null>(null);
    const lastFocus = useRef<Element | null>(null);
    const open = mobile && expanded;
    const previous = useRef({ mobile, open });
    const close = useCallback(() => setExpanded(false), []);

    useLayoutEffect(() => {
        const query = window.matchMedia?.(mobileQuery);
        if (!query) return;
        const change = () => { setMobile(query.matches); setExpanded(false); };
        // Also reconcile a resize between render and subscription.
        change();
        query.addEventListener('change', change);
        return () => query.removeEventListener('change', change);
    }, []);
    useLayoutEffect(close, [routeKey, close]);
    useLayoutEffect(() => {
        const remember = () => { lastFocus.current = document.activeElement; };
        document.addEventListener('focusin', remember);
        return () => document.removeEventListener('focusin', remember);
    }, []);

    useLayoutEffect(() => {
        const sidebar = sidebarRef.current;
        const before = previous.current;
        // Responsive CSS may hide and blur a navigation control before React
        // handles the media change. Keep that transition's visible replacement.
        const active = before.mobile !== mobile && document.activeElement === document.body && lastFocus.current?.isConnected
            ? lastFocus.current : document.activeElement;
        previous.current = { mobile, open };
        // Do not take focus from another dialog. When Help opens from the
        // drawer, restore the trigger before that dialog captures return focus.
        if ([...document.querySelectorAll('[role="dialog"]')].some(dialog => dialog !== sidebar && dialog.contains(active))) return;
        const selected = sidebar?.querySelector<HTMLElement>('[aria-current="page"]');
        if (open && !before.open) {
            (selected ?? closeRef.current)?.focus();
        } else if (mobile && !open && (before.open || (!before.mobile && sidebar?.contains(active)))) {
            triggerRef.current?.focus({ preventScroll: true });
        } else if (!mobile && before.mobile && (active === triggerRef.current || active === closeRef.current || active?.classList.contains('mobile-scrim'))) {
            selected?.focus();
        }
    }, [mobile, open]);

    useLayoutEffect(() => {
        // Capture after drawer dismissal, before Help's passive focus effect.
        if (helpOpen) helpReturnFocus.current = document.activeElement;
    }, [helpOpen]);
    useEffect(() => {
        if (helpOpen) return;
        const origin = helpReturnFocus.current;
        helpReturnFocus.current = null;
        // Help normally restores its own opener. After a breakpoint change,
        // substitute only a navigation opener that is now hidden. Leave all
        // other dialog/route focus behavior alone.
        if (!mobile && origin === triggerRef.current) {
            sidebarRef.current?.querySelector<HTMLElement>('[aria-current="page"]')?.focus();
        } else if (mobile && !open && origin && sidebarRef.current?.contains(origin)) {
            triggerRef.current?.focus({ preventScroll: true });
        }
    }, [helpOpen, mobile, open]);

    useLayoutEffect(() => {
        if (!open) return;
        const key = (event: KeyboardEvent) => {
            const sidebar = sidebarRef.current;
            if (!sidebar || [...document.querySelectorAll('[role="dialog"]')].some(dialog => dialog !== sidebar)) return;
            if (event.key === 'Escape') {
                event.preventDefault();
                // The drawer owns this Escape, including on device-detail routes.
                event.stopPropagation();
                close();
            } else if (event.key === 'Tab') {
                const items = [...sidebar.querySelectorAll<HTMLElement>('a[href],button,input,select,textarea,summary,[tabindex]')].filter(item =>
                    item.tabIndex >= 0 && !item.matches(':disabled') && !item.closest('[hidden],[inert],[aria-hidden="true"]') && getComputedStyle(item).display !== 'none' && getComputedStyle(item).visibility !== 'hidden');
                const first = items[0], last = items.at(-1), active = document.activeElement;
                if (!items.length || !sidebar.contains(active) || (event.shiftKey ? active === first : active === last)) {
                    event.preventDefault();
                    (event.shiftKey ? last : first)?.focus();
                }
            }
        };
        window.addEventListener('keydown', key, true);
        return () => window.removeEventListener('keydown', key, true);
    }, [open, close]);

    return { mobile, open, close, toggle: () => setExpanded(value => !value), sidebarRef, triggerRef, closeRef };
}
