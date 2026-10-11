import { windowsView } from './windows-inventory-fixture';
import type { WindowsSessionContext } from './windows-session-context-types';
export function windowsSessionContext(): WindowsSessionContext {
    const snapshot = windowsView().snapshot!;
    return { schemaVersion: 'tracebolt.windows-session-context.v1', scope: 'windows-session-context-v1', grantId: '5'.repeat(32), generationId: snapshot.generationId, collectedAt: snapshot.collectedAt,
        sessions: { quality: 'partial', reason: 'windows_session_context_partial_result', observedCount: 3, retainedCount: 3, truncatedCount: 0, rows: [
            { sessionId: 0, userName: null, userQuality: 'empty', domainName: null, domainQuality: 'empty', state: 'disconnected', protocol: 'console' },
            { sessionId: 1, userName: 'fixture-alex', userQuality: 'observed', domainName: 'FIXTURE', domainQuality: 'observed', state: 'active', protocol: 'console' },
            { sessionId: 4, userName: null, userQuality: 'denied', domainName: null, domainQuality: 'unavailable', state: 'disconnected', protocol: 'rdp' },
        ] },
        join: { quality: 'observed', reason: '', status: 'workgroup', name: 'FIXTURE-WORKGROUP' },
    };
}
export const windowsSessionContextView = () => ({ ...windowsView(), sessionContext: windowsSessionContext() });
