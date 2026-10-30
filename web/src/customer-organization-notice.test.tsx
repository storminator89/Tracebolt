import type {} from 'vitest/jsdom';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CustomerOrganizationNotice } from './customer-organization-notice';
import { setLocale } from './i18n';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); setLocale('en', false); });
describe('customer organization disclosure, not authorization', () => {
    it.each([
        ['en', 'Organization, not tenant isolation', /not access control/, /no collection or action rights/, /customer-scoped API or export access/, /separate identities, trust, state and backups/],
        ['de', 'Organisation, keine Mandantentrennung', /nicht der Zugriffskontrolle/, /keine Erfassungs- oder Aktionsrechte/, /kundenspezifischen API- oder Exportrechte/, /getrennten Identitäten, Vertrauensmaterialien, Zuständen und Backups/],
    ] as const)('exposes the same boundary in %s without requesting or granting anything', (locale, summary, control, rights, exports, separate) => {
        setLocale(locale, false);
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        const { container } = render(<CustomerOrganizationNotice/>);
        const disclosure = container.querySelector('details')!;
        expect(screen.getByText(summary)).toBeVisible();
        expect(disclosure).not.toHaveAttribute('open');
        fireEvent.click(screen.getByText(summary));
        expect(disclosure).toHaveAttribute('open');
        for (const text of [control, rights, exports, separate]) expect(screen.getByText(text)).toBeVisible();
        expect(container.querySelector('button,input,select,form,a')).toBeNull();
        expect(fetch).not.toHaveBeenCalled();
    });
});
