import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setLocale } from './i18n';
import { PackageUpdatesUnavailable } from './package-updates';

beforeEach(() => { setLocale('en', false); });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe('package-update unavailable notice', () => {
    it('explains the version limit without network access, package selection or action controls', () => {
        const fetch = vi.fn(); vi.stubGlobal('fetch', fetch);
        const { container } = render(<PackageUpdatesUnavailable/>);
        expect(screen.getByRole('region', { name: 'Selected package updates · unavailable' })).toBeVisible();
        expect(screen.getByText('Native package updates are not ready on this device.')).toBeVisible();
        expect(screen.getByText('Cached candidates are inventory only, not a verified installation plan.')).toBeVisible();
        expect(container.querySelectorAll('button, input, select, textarea, a, [tabindex]')).toHaveLength(0);
        expect(fetch).not.toHaveBeenCalled();
    });

    it('updates the short unavailable notice when the language changes', () => {
        render(<PackageUpdatesUnavailable/>);
        act(() => setLocale('de', false));
        expect(screen.getByRole('region', { name: 'Ausgewählte Paketupdates · nicht verfügbar' })).toBeVisible();
        expect(screen.getByText('Native Paketupdates sind auf diesem Gerät nicht bereit.')).toBeVisible();
        expect(screen.getByText('Cache-Kandidaten sind nur Inventardaten, kein geprüfter Installationsplan.')).toBeVisible();
        expect(screen.queryByRole('button')).not.toBeInTheDocument();
    });
});
