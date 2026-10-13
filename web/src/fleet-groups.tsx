import { useEffect, useRef, useState } from 'react';
import { Folder, RefreshCw, Settings2 } from 'lucide-react';
import { AUTH_REQUIRED_EVENT, getProtectedRequestEpoch, request } from './api';
import { hasLogoutIntent, validOperatorSession } from './auth';
import { Dialog } from './components';
import { inventoryAge } from './complete-packages-types';
import { useLocale } from './i18n';
import type { Device } from './types';
import { acceptWindowsHealthClock, windowsHealthElapsed } from './windows-health-clock';
import { validWindowsCapacityTimestamp, WINDOWS_CAPACITY_VIEW_BYTES, windowsCapacityDeviceEligible } from './windows-capacity-types';
import type { WindowsPercentageMetric, WindowsPercentageView } from './windows-capacity-types';
import { validFleetGroupName, validFleetGroupsView } from './fleet-groups-types';
import type { FleetGroup, FleetGroupDevice, FleetGroupsView } from './fleet-groups-types';
import { applyGroupHealth, percentagePath, reviewGroupHealth } from './fleet-groups-workflow';
import type { GroupHealthIO, GroupHealthResult, GroupHealthReview, GroupHealthSetting } from './fleet-groups-workflow';
import { GroupMonitoring } from './fleet-group-monitoring';
import { validGroupMonitoringView } from './fleet-group-monitoring-types';
import type { GroupMonitoringIO, GroupMonitoringView } from './fleet-group-monitoring-types';
import { GroupMaintenance } from './fleet-group-maintenance';
import { GroupMaintenanceEnd } from './fleet-group-maintenance-end';
import type { GroupMaintenanceEndIO } from './fleet-group-maintenance-end-workflow';
import { validGroupMaintenanceView } from './fleet-group-maintenance-workflow';
import type { GroupMaintenanceIO, GroupMaintenanceView } from './fleet-group-maintenance-workflow';
import './fleet-groups.css';

const copy = {
    en: {
        groups: 'Fleet groups', all: 'All groups', unavailable: 'Group membership is unavailable. Refresh before continuing.', loading: 'Checking groups…', refresh: 'Refresh groups', manage: 'Manage groups', create: 'Create group', edit: 'Edit group', name: 'Group name', members: 'Exact members', organizational: 'Manual groups organize devices only. They grant no access or health policy. The existing device Group label is separate.', limits: 'Up to 25 groups and 50 admitted members per group.', readOnly: 'Only the shared administrator can change groups or apply health settings. Your access is read-only.', empty: 'No groups yet.', none: 'No members selected.', reviewChanges: 'Review group changes', save: 'Save reviewed group', delete: 'Delete group', confirmDelete: 'Confirm group deletion', deleteScope: 'Only this group is deleted. Devices and their health policies stay as they are.', cancel: 'Cancel', back: 'Back to edit', revision: 'Group revision', unavailableMembers: 'Unavailable members', omitted: 'Unavailable members have no visible identity. They are retained unless you explicitly choose removal.', removeUnavailable: 'Remove unavailable members', retainedUnavailable: 'Unavailable members will be retained.', removingUnavailable: 'Unavailable members will be removed.', uncertainGroup: 'The group write could not be confirmed. Refresh and review the current group before making another change. It is never retried automatically.', saved: 'Group saved.', deleted: 'Group deleted.', health: 'Apply monitoring policies', healthTitle: 'Apply Windows monitoring policies', windowsOnly: 'Select 1–25 current Windows devices. Linux and unavailable members are excluded. New members are never included automatically.', metric: 'One setting', disk: 'System-volume capacity', cpu: 'CPU percentage', memory: 'Physical RAM percentage', enabled: 'Enable this policy', threshold: 'Threshold (%)', choose: 'Select Windows devices', review: 'Review exact changes', reviewing: 'Reading current policies…', apply: 'Apply reviewed policies', applying: 'Applying sequentially…', stop: 'Stop remaining writes', stopped: 'Stopped. An interrupted write may already have reached the manager. Start a fresh review before another apply.', fresh: 'Start fresh review', reviewFailed: 'Review could not be verified. Refresh and start a fresh review.', settingScope: 'Only selected manager policies are changed. This grants no collection, service action, AI analysis or notification.', diskScope: 'Disk: caller-visible, quota-aware allocation of the Windows system volume.', cpuScope: 'CPU: sampled interval usage of the observed processor group, not all processor groups.', memoryScope: 'RAM: physical memory not immediately available, not process working sets, commit or pagefile use.', rules: 'Opening and recovery each need advancing observations spanning 60 seconds plus continuous manager confirmation. Recovery is 5 percentage points below the threshold. Unknown evidence never records recovery.', changes: 'Changing or disabling a policy closes an open incident as policy-changed, without claiming recovery. Each policy is independent and off by default.', frozen: 'This review freezes the selected group revision if used, exact names and IDs, selected settings and each device policy revision. Apply stops at the first conflict or uncertain result. There is no rollback or automatic retry.', healthSummary: 'Choose policies and exact devices, then review once.', policies: 'Policies to apply', devices: 'Windows devices', include: 'Include', unchanged: 'Not selected · unchanged', selectedPolicies: 'Selected policies', selectedDevices: 'Selected devices', contactServices: 'Contact stays read-only here. Choose exact service checks separately on each device.', policyDetails: 'Scope and policy details', applySafety: 'Stops on conflict or uncertainty. No rollback or automatic retry.', device: 'Device / exact ID', before: 'Reviewed policy', outcome: 'Outcome', policyRevision: 'Policy revision', on: 'Enabled', off: 'Disabled', invalid: 'Use a whole-number threshold from 50 to 99.', 'changed': 'Changed · confirmed response', 'currently-matching': 'Currently matching · no write', 'conflict': 'Conflict · review again', 'not-attempted': 'Not attempted', 'unconfirmed': 'Unconfirmed · write may have happened', matching: 'Current policy matches, but this does not prove our write succeeded.', noWindows: 'No available Windows devices in this selection.', busy: 'Saving…', selectedMissing: 'Selected group unavailable', results: 'Per-device results', explicit: 'Choose a new review to make any further change.', groupReview: 'Review exact group changes', healthBound: 'A reviewed batch is temporary and stops on navigation, blur, access loss or expiry.',
    },
    de: {
        groups: 'Flottengruppen', all: 'Alle Gruppen', unavailable: 'Die Gruppenmitgliedschaft ist nicht verfügbar. Vor dem Fortfahren aktualisieren.', loading: 'Gruppen werden geprüft …', refresh: 'Gruppen aktualisieren', manage: 'Gruppen verwalten', create: 'Gruppe erstellen', edit: 'Gruppe bearbeiten', name: 'Gruppenname', members: 'Exakte Mitglieder', organizational: 'Manuelle Gruppen ordnen nur Geräte. Sie erteilen weder Zugriff noch eine Health-Richtlinie. Das vorhandene Gerätefeld Gruppe ist davon unabhängig.', limits: 'Bis zu 25 Gruppen und 50 zugelassene Mitglieder je Gruppe.', readOnly: 'Nur der gemeinsame Administrator kann Gruppen ändern oder Health-Einstellungen anwenden. Dein Zugriff ist nur lesend.', empty: 'Noch keine Gruppen.', none: 'Keine Mitglieder ausgewählt.', reviewChanges: 'Gruppenänderungen prüfen', save: 'Geprüfte Gruppe speichern', delete: 'Gruppe löschen', confirmDelete: 'Löschen der Gruppe bestätigen', deleteScope: 'Nur diese Gruppe wird gelöscht. Geräte und ihre Health-Richtlinien bleiben bestehen.', cancel: 'Abbrechen', back: 'Zurück zur Bearbeitung', revision: 'Gruppenversion', unavailableMembers: 'Nicht verfügbare Mitglieder', omitted: 'Nicht verfügbare Mitglieder haben keine sichtbare Identität. Sie bleiben erhalten, sofern du sie nicht ausdrücklich entfernst.', removeUnavailable: 'Nicht verfügbare Mitglieder entfernen', retainedUnavailable: 'Nicht verfügbare Mitglieder bleiben erhalten.', removingUnavailable: 'Nicht verfügbare Mitglieder werden entfernt.', uncertainGroup: 'Das Speichern der Gruppe konnte nicht bestätigt werden. Aktualisiere und prüfe die aktuelle Gruppe vor einer weiteren Änderung. Es wird nie automatisch wiederholt.', saved: 'Gruppe gespeichert.', deleted: 'Gruppe gelöscht.', health: 'Monitoring-Richtlinien anwenden', healthTitle: 'Windows-Monitoring-Richtlinien anwenden', windowsOnly: 'Wähle 1–25 aktuelle Windows-Geräte. Linux und nicht verfügbare Mitglieder sind ausgeschlossen. Neue Mitglieder werden nie automatisch einbezogen.', metric: 'Eine Einstellung', disk: 'Kapazität des Systemvolumes', cpu: 'CPU-Prozentwert', memory: 'Physischer RAM-Prozentwert', enabled: 'Diese Richtlinie aktivieren', threshold: 'Schwellenwert (%)', choose: 'Windows-Geräte wählen', review: 'Exakte Änderungen prüfen', reviewing: 'Aktuelle Richtlinien werden gelesen …', apply: 'Geprüfte Richtlinien anwenden', applying: 'Wird nacheinander angewendet …', stop: 'Weitere Schreibvorgänge stoppen', stopped: 'Gestoppt. Ein unterbrochener Schreibvorgang kann den Manager bereits erreicht haben. Vor einer weiteren Anwendung neu prüfen.', fresh: 'Neu prüfen', reviewFailed: 'Die Prüfung konnte nicht bestätigt werden. Aktualisiere und beginne eine neue Prüfung.', settingScope: 'Nur ausgewählte Manager-Richtlinien werden geändert. Es werden keine Erfassung, Dienstaktion, KI-Analyse oder Benachrichtigung freigegeben.', diskScope: 'Datenträger: für den Aufrufer sichtbare, quotenabhängige Belegung des Windows-Systemvolumes.', cpuScope: 'CPU: gemessene Intervallnutzung der beobachteten Prozessorgruppe, nicht aller Prozessorgruppen.', memoryScope: 'RAM: nicht sofort verfügbarer physischer Speicher, weder Prozess-Arbeitssätze noch Commit oder Auslagerungsdateinutzung.', rules: 'Öffnen und Erholung benötigen jeweils fortschreitende Beobachtungen über 60 Sekunden sowie fortlaufende Manager-Bestätigung. Die Erholungsschwelle liegt 5 Prozentpunkte niedriger. Unbekannte Evidenz belegt keine Erholung.', changes: 'Ändern oder Deaktivieren einer Richtlinie schließt einen offenen Vorfall wegen Richtlinienänderung, ohne Erholung zu behaupten. Jede Richtlinie ist unabhängig und standardmäßig aus.', frozen: 'Diese Prüfung bindet die gewählte Gruppenversion, exakte Namen und IDs, ausgewählte Einstellungen und jede Geräte-Richtlinienversion. Die Anwendung stoppt beim ersten Konflikt oder unklaren Ergebnis. Kein Rollback und keine automatische Wiederholung.', healthSummary: 'Richtlinien und exakte Geräte auswählen, dann gemeinsam prüfen.', policies: 'Anzuwendende Richtlinien', devices: 'Windows-Geräte', include: 'Einbeziehen', unchanged: 'Nicht gewählt · unverändert', selectedPolicies: 'Gewählte Richtlinien', selectedDevices: 'Gewählte Geräte', contactServices: 'Kontakt bleibt hier nur lesbar. Exakte Dienstprüfungen werden je Gerät separat gewählt.', policyDetails: 'Umfang und Richtliniendetails', applySafety: 'Stopp bei Konflikt oder unklarem Ergebnis. Kein Rollback, keine automatische Wiederholung.', device: 'Gerät / exakte ID', before: 'Geprüfte Richtlinie', outcome: 'Ergebnis', policyRevision: 'Richtlinienversion', on: 'Aktiviert', off: 'Deaktiviert', invalid: 'Verwende einen ganzzahligen Schwellenwert von 50 bis 99.', 'changed': 'Geändert · bestätigte Antwort', 'currently-matching': 'Entspricht bereits · nicht geschrieben', 'conflict': 'Konflikt · erneut prüfen', 'not-attempted': 'Nicht versucht', 'unconfirmed': 'Unbestätigt · Änderung eventuell erfolgt', matching: 'Die aktuelle Richtlinie entspricht der Auswahl. Das beweist nicht, dass unser Schreibvorgang erfolgreich war.', noWindows: 'Keine verfügbaren Windows-Geräte in dieser Auswahl.', busy: 'Wird gespeichert …', selectedMissing: 'Gewählte Gruppe nicht verfügbar', results: 'Ergebnisse je Gerät', explicit: 'Jede weitere Änderung erfordert eine neue Prüfung.', groupReview: 'Exakte Gruppenänderungen prüfen', healthBound: 'Eine geprüfte Anwendung ist vorübergehend und stoppt bei Navigation, Fokusverlust, Zugriffsverlust oder Ablauf.',
    },
};
type Copy = typeof copy.en;
type Anchor = { mono: number; wall: number };
const capture = (): Anchor => ({ mono: performance.now(), wall: Date.now() });
function elapsed(anchor: Anchor): number {
    const mono = performance.now() - anchor.mono, wall = Date.now() - anchor.wall;
    return Number.isFinite(mono) && mono >= 0 && Number.isFinite(wall) && Math.abs(wall - mono) <= 1500 ? mono : Infinity;
}
type GroupSnapshot = { view: FleetGroupsView; started: Anchor; epoch: number; key: string };
type PolicyLease = { view: WindowsPercentageView; started: Anchor; clockKey: string; metadata: Device };
type GroupIntent = { groupId?: string; name: string; memberIds: string[]; expectedRevision: number; remove?: boolean; removeUnavailableMembers?: boolean };
type MaintenanceLease = { view: GroupMaintenanceView; started: Anchor; clockKey: string };
type MonitoringLease = { view: GroupMonitoringView; started: Anchor; clockKey: string };
type Commands = { refresh: () => void; hold: (value: boolean) => void; cancel: () => void; save: (intent: GroupIntent) => Promise<boolean>; io: (fresh: boolean) => GroupHealthIO; monitoringIO: (groupId: string, fresh: boolean) => GroupMonitoringIO; maintenanceIO: (groupId: string, fresh: boolean) => GroupMaintenanceIO & GroupMaintenanceEndIO };
const unavailableIO = (): GroupHealthIO => ({ get: async () => { throw new Error('Inactive'); }, post: async () => { throw new Error('Inactive'); }, active: () => false, accept: () => false });

const unavailableMonitoringIO = (): GroupMonitoringIO => ({ active: () => false, get: async () => { throw new Error('Inactive'); }, post: async () => { throw new Error('Inactive'); } });

const unavailableMaintenanceIO = (): GroupMaintenanceIO & GroupMaintenanceEndIO => ({ end: async () => { throw new Error('Inactive'); }, active: () => false, get: async () => { throw new Error('Inactive'); }, post: async () => { throw new Error('Inactive'); } });

/** A group selection fails closed while its membership is being checked. No group is an authority grant. */
export function useFleetGroups(available: boolean, sessionKey: string | null, admin: boolean) {
    const [activated, setActivated] = useState(false), enabled = available && activated;
    const [snapshot, setSnapshot] = useState<GroupSnapshot | null>(null), [selectedId, setSelectedId] = useState('');
    const [loading, setLoading] = useState(false), [saving, setSaving] = useState(false), [error, setError] = useState(false), [notice, setNotice] = useState<'saved' | 'deleted' | 'uncertainGroup' | null>(null), [generation, setGeneration] = useState(0);
    const key = JSON.stringify(['fleet-groups', sessionKey]), live = useRef({ enabled, sessionKey, admin });
    live.current = { enabled, sessionKey, admin };
    const commands = useRef<Commands>({ refresh: () => {}, hold: () => {}, cancel: () => {}, save: async () => false, io: unavailableIO, monitoringIO: unavailableMonitoringIO, maintenanceIO: unavailableMaintenanceIO });
    useEffect(() => {
        let alive = true, suspended = document.visibilityState === 'hidden', locked = false, held = false, operation = 0, reading = false, writing = false;
        let accepted: GroupSnapshot | null = null, monitoring: MonitoringLease | null = null, maintenance: MaintenanceLease | null = null;
        const epoch = getProtectedRequestEpoch(), pending = new Set<AbortController>(), policies = new Map<string, PolicyLease>();
        const abort = () => { operation++; for (const controller of pending) controller.abort(); pending.clear(); };
        const clear = (failure = false) => { abort(); accepted = null; policies.clear(); monitoring = null; maintenance = null; reading = false; writing = false; held = false; if (alive) { setSnapshot(null); setLoading(false); setSaving(false); setError(failure); setGeneration(n => n + 1); } };
        const baseActive = () => alive && enabled && live.current.enabled && live.current.sessionKey === sessionKey && live.current.admin === admin && !suspended && !locked && document.visibilityState !== 'hidden' && epoch === getProtectedRequestEpoch() && !hasLogoutIntent();
        const groupActive = () => {
            if (!baseActive() || !accepted || !validWindowsCapacityTimestamp(sessionKey)) return false;
            const age = windowsHealthElapsed(key, epoch, accepted.view.serverNow, elapsed(accepted.started));
            return Number.isFinite(age) && age < 120000 && inventoryAge(sessionKey, accepted.view.serverNow) > age;
        };
        const policyActive = (lease: PolicyLease) => {
            const age = windowsHealthElapsed(lease.clockKey, epoch, lease.view.serverNow, elapsed(lease.started)), cert = lease.metadata.agentCertificate;
            return groupActive() && cert && Number.isFinite(age) && inventoryAge(sessionKey!, lease.view.serverNow) > age && inventoryAge(lease.view.certificateExpiresAt, lease.view.serverNow) > age && inventoryAge(cert.expiresAt!, lease.view.serverNow) > age && inventoryAge(lease.view.serverNow, cert.checkedAt) + age >= 0 && inventoryAge(lease.view.serverNow, cert.checkedAt) + age <= 120000;
        };
        const monitoringActive = (lease: MonitoringLease) => {
            const age = windowsHealthElapsed(lease.clockKey, epoch, lease.view.serverNow, elapsed(lease.started));
            return groupActive() && Number.isFinite(age) && age < 120000 && inventoryAge(sessionKey!, lease.view.serverNow) > age && lease.view.targets.every(t => inventoryAge(t.certificateExpiresAt, lease.view.serverNow) > age);
        };
        const maintenanceActive = (lease: MaintenanceLease) => {
            const age = windowsHealthElapsed(lease.clockKey, epoch, lease.view.serverNow, elapsed(lease.started));
            return groupActive() && Number.isFinite(age) && age < 120000 && inventoryAge(sessionKey!, lease.view.serverNow) > age && inventoryAge(lease.view.authorityExpiresAt, lease.view.serverNow) > age;
        };
        const allActive = () => groupActive() && [...policies.values()].every(policyActive) && (!monitoring || monitoringActive(monitoring)) && (!maintenance || maintenanceActive(maintenance));
        const fetchValue = async (path: string, active: () => boolean, body?: unknown, cap?: number): Promise<{ value: unknown; started: Anchor }> => {
            if (!active()) throw new Error('Inactive');
            const controller = new AbortController(), started = capture(); pending.add(controller);
            const timer = window.setTimeout(() => controller.abort(), 10000);
            const current = () => active() && !controller.signal.aborted && elapsed(started) < 10000;
            try {
                let options: RequestInit = { signal: controller.signal };
                if (body !== undefined) {
                    const session = await request<unknown>('/auth/session', options, 32768);
                    // Check every live metadata lease again after waiting for CSRF.
                    if (!current() || !admin || !validOperatorSession(session) || session.mode !== 'lan' || !session.authenticated || session.loginMode !== 'shared' || session.expiresAt !== sessionKey || typeof session.csrfToken !== 'string' || session.csrfToken.length < 1 || session.csrfToken.length > 256 || inventoryAge(sessionKey!, session.serverNow) <= elapsed(started)) throw new Error('Inactive session');
                    options = { ...options, method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': session.csrfToken }, body: JSON.stringify(body) };
                }
                if (!current()) throw new Error('Inactive');
                const value = await request<unknown>(path, options, cap);
                if (!current()) throw new Error('Inactive');
                return { value, started };
            } finally { window.clearTimeout(timer); pending.delete(controller); }
        };
        const acceptGroups = (value: unknown, started: Anchor): value is FleetGroupsView => {
            if (!validFleetGroupsView(value) || !validWindowsCapacityTimestamp(sessionKey) || !acceptWindowsHealthClock(key, epoch, value.serverNow, elapsed(started))) return false;
            const age = windowsHealthElapsed(key, epoch, value.serverNow, elapsed(started));
            return age < 120000 && inventoryAge(sessionKey, value.serverNow) > age;
        };
        const read = async () => {
            if (!baseActive() || reading || writing || held) return;
            clear(); const run = operation; reading = true; setLoading(true);
            try {
                const { value, started } = await fetchValue('/fleet/groups', () => baseActive() && run === operation, undefined, 262144);
                if (!acceptGroups(value, started)) throw new Error('Invalid groups');
                accepted = { view: value, started, epoch, key }; setSnapshot(accepted); setError(false);
            } catch { if (run === operation && alive) clear(true); }
            finally { if (run === operation && alive) { reading = false; setLoading(false); } }
        };
        const save = async (intent: GroupIntent) => {
            if (!allActive() || !admin || writing || reading || !accepted) return false;
            const original = intent.groupId ? accepted.view.groups.find(g => g.id === intent.groupId) : undefined;
            if (intent.groupId && (!original || original.revision !== intent.expectedRevision) || !intent.groupId && intent.expectedRevision !== 0 || !intent.remove && (!validFleetGroupName(intent.name) || intent.memberIds.length > 50 || new Set(intent.memberIds).size !== intent.memberIds.length || intent.memberIds.some(id => !accepted!.view.devices.some(d => d.id === id)))) return false;
            const run = operation; writing = true; setSaving(true); setNotice(null);
            try {
                const path = intent.groupId ? `/fleet/groups/${intent.groupId}${intent.remove ? '/delete' : ''}` : '/fleet/groups';
                const body = intent.remove ? { expectedRevision: intent.expectedRevision } : { name: intent.name, memberIds: [...intent.memberIds], expectedRevision: intent.expectedRevision, ...(intent.groupId ? { removeUnavailableMembers: intent.removeUnavailableMembers === true } : {}) };
                const { value, started } = await fetchValue(path, () => run === operation && allActive(), body, 262144);
                if (!acceptGroups(value, started)) throw new Error('Invalid groups');
                accepted = { view: value, started, epoch, key }; setSnapshot(accepted); setNotice(intent.remove ? 'deleted' : 'saved');
                if (intent.remove) setSelectedId('');
                return true;
            } catch { if (alive && run === operation) { setNotice('uncertainGroup'); clear(true); } return false; }
            finally { if (alive && run === operation) { writing = false; setSaving(false); } }
        };
        const io = (fresh: boolean): GroupHealthIO => {
            if (fresh) { abort(); policies.clear(); monitoring = null; maintenance = null; }
            const run = operation;
            let candidate: { started: Anchor; metadata: Device } | null = null;
            const active = () => run === operation && admin && allActive();
            return {
                active,
                get: async path => {
                    if (path === '/fleet/groups' || path.startsWith('/fleet/groups/')) {
                        const response = await fetchValue(path, active, undefined, 262144);
                        if (!acceptGroups(response.value, response.started)) throw new Error('Invalid groups');
                        return response.value;
                    }
                    const id = path.split('/')[2];
                    const metadata = await fetchValue(`/devices/${id}`, active, undefined, 262144);
                    if (!metadata.value || typeof metadata.value !== 'object' || !windowsCapacityDeviceEligible(metadata.value as Device, id)) throw new Error('Invalid metadata');
                    const value = await fetchValue(path, active, undefined, WINDOWS_CAPACITY_VIEW_BYTES);
                    candidate = { started: metadata.started, metadata: metadata.value as Device };
                    return value.value;
                },
                post: async (path, body) => {
                    const lease = policies.get(path.replace(/\/policy$/, ''));
                    if (!lease) throw new Error('No reviewed lease');
                    const value = await fetchValue(path, active, body, WINDOWS_CAPACITY_VIEW_BYTES);
                    candidate = { started: value.started, metadata: lease.metadata };
                    return value.value;
                },
                accept: view => {
                    if (!active() || !candidate) return false;
                    const metric = view.schemaVersion === 'tracebolt.windows-capacity-view.v1' ? 'disk' : view.metric;
                    const clockKey = JSON.stringify(['windows-capacity', metric, view.deviceId, sessionKey]);
                    if (!acceptWindowsHealthClock(clockKey, epoch, view.serverNow, elapsed(candidate.started))) return false;
                    const next = { view, started: candidate.started, metadata: candidate.metadata, clockKey };
                    candidate = null;
                    if (!policyActive(next)) return false;
                    policies.set(percentagePath(view.deviceId, metric), next);
                    return true;
                },
            };
        };
        // Reuse the group resource's private lifetime, request aborts, clock and
        // final post-CSRF session/certificate guards. No independent write lane.
        const monitoringIO = (groupId: string, fresh: boolean): GroupMonitoringIO => {
            if (fresh) { abort(); policies.clear(); monitoring = null; maintenance = null; }
            const run = operation;
            const group = accepted?.view.groups.find(g => g.id === groupId);
            const active = () => run === operation && !!group && allActive();
            const accept = (value: unknown, started: Anchor): GroupMonitoringView => {
                if (!active() || !group || !validGroupMonitoringView(value, groupId) || value.groupRevision !== group.revision) throw new Error('Invalid group monitoring');
                const members = accepted!.view.devices.filter(d => d.platform === 'windows' && group.memberIds.includes(d.id));
                if (value.targets.some(t => !members.some(d => d.id === t.deviceId && d.name === t.name))) throw new Error('Group membership changed');
                const clockKey = JSON.stringify(['fleet-group-monitoring', groupId, sessionKey]);
                if (!acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed(started))) throw new Error('Invalid monitoring clock');
                const next = { view: value, started, clockKey };
                if (!monitoringActive(next)) throw new Error('Expired monitoring');
                monitoring = next;
                return value;
            };
            return {
                active,
                get: async () => { const result = await fetchValue(`/fleet/groups/${groupId}/monitoring`, active, undefined, 262144); return accept(result.value, result.started); },
                post: async body => {
                    if (!admin || !monitoring || body.expectedGroupRevision !== group?.revision || body.expectedRevision !== monitoring.view.revision || body.assignments.some(a => !monitoring!.view.targets.some(t => t.deviceId === a.deviceId && t.metric === a.metric && t.assignmentRevision === a.expectedRevision && t.policy.revision === a.expectedPolicyRevision))) throw new Error('No reviewed monitoring lease');
                    const result = await fetchValue(`/fleet/groups/${groupId}/monitoring`, () => admin && active(), body, 262144);
                    return accept(result.value, result.started);
                },
            };
        };
        const maintenanceIO = (groupId: string, fresh: boolean): GroupMaintenanceIO & GroupMaintenanceEndIO => {
            if (fresh) { abort(); policies.clear(); monitoring = null; maintenance = null; }
            const run = operation, group = accepted?.view.groups.find(g => g.id === groupId);
            const active = () => run === operation && admin && !!group && allActive();
            const accept = (value: unknown, started: Anchor): GroupMaintenanceView => {
                if (!active() || !group || !validGroupMaintenanceView(value, groupId) || value.groupRevision !== group.revision || value.groupName !== group.name) throw new Error('Group maintenance changed');
                const clockKey = JSON.stringify(['fleet-group-maintenance', groupId, sessionKey]);
                if (!acceptWindowsHealthClock(clockKey, epoch, value.serverNow, elapsed(started))) throw new Error('Invalid maintenance clock');
                const next = { view: value, started, clockKey };
                if (!maintenanceActive(next)) throw new Error('Expired maintenance');
                // Keep the first projection lease throughout the review/sequence.
                // Refresh reads can tighten it, but cannot extend its original end.
                if (!maintenance || inventoryAge(value.authorityExpiresAt, maintenance.view.authorityExpiresAt) < 0) maintenance = next;
                return value;
            };
            return {
                active,
                get: async () => { const response = await fetchValue(`/fleet/groups/${groupId}/maintenance`, active, undefined, 262144); return accept(response.value, response.started); },
                post: async body => {
                    if (!maintenance || body.groupRevision !== group?.revision || !maintenance.view.members.some(m => m.targets.some(t => t.key === body.key && t.revision === body.revision))) throw new Error('No reviewed maintenance lease');
                    const response = await fetchValue(`/fleet/groups/${groupId}/maintenance/start`, active, body, 262144);
                    return accept(response.value, response.started);
                },
                end: async body => {
                    if (!maintenance || body.groupRevision !== group?.revision || !maintenance.view.members.some(m => m.targets.some(t => t.key === body.key && t.revision === body.revision && t.windows[0]?.id === body.windowId && t.windows[0].endedAt === null))) throw new Error('No reviewed early-end lease');
                    const response = await fetchValue(`/fleet/groups/${groupId}/maintenance/end`, active, body, 262144);
                    return accept(response.value, response.started);
                },
            };
        };
        const lock = () => { locked = true; clear(); }, suspend = () => { suspended = true; clear(); };
        const restore = () => { if (!alive || locked || document.visibilityState === 'hidden') return; suspended = false; void read(); };
        const visibility = () => document.visibilityState === 'hidden' ? suspend() : restore();
        commands.current = { refresh: () => { held = false; void read(); }, hold: value => { held = value; }, cancel: () => { if (writing) { setNotice('uncertainGroup'); clear(true); } else if (reading) clear(); else { abort(); policies.clear(); monitoring = null; maintenance = null; } }, save, io, monitoringIO, maintenanceIO };
        clear(); setNotice(null);
        if (!enabled) { commands.current = { refresh: () => {}, hold: () => {}, cancel: () => {}, save: async () => false, io: unavailableIO, monitoringIO: unavailableMonitoringIO, maintenanceIO: unavailableMaintenanceIO }; return () => { alive = false; abort(); }; }
        if (validWindowsCapacityTimestamp(sessionKey)) void read();
        window.addEventListener(AUTH_REQUIRED_EVENT, lock); window.addEventListener('blur', suspend); window.addEventListener('focus', restore); window.addEventListener('pagehide', suspend); window.addEventListener('hashchange', suspend); document.addEventListener('visibilitychange', visibility);
        const timer = window.setInterval(() => { if (epoch !== getProtectedRequestEpoch() || hasLogoutIntent()) lock(); else if (accepted && !allActive()) clear(true); }, 250);
        const refreshTimer = window.setInterval(() => { if (!held) void read(); }, 15000);
        return () => { alive = false; abort(); accepted = null; policies.clear(); monitoring = null; maintenance = null; window.clearInterval(timer); window.clearInterval(refreshTimer); window.removeEventListener(AUTH_REQUIRED_EVENT, lock); window.removeEventListener('blur', suspend); window.removeEventListener('focus', restore); window.removeEventListener('pagehide', suspend); window.removeEventListener('hashchange', suspend); document.removeEventListener('visibilitychange', visibility); };
    }, [enabled, key, sessionKey, admin]);
    const age = snapshot ? windowsHealthElapsed(key, snapshot.epoch, snapshot.view.serverNow, elapsed(snapshot.started)) : Infinity;
    const view = enabled && snapshot?.key === key && snapshot.epoch === getProtectedRequestEpoch() && !hasLogoutIntent() && age < 120000 && validWindowsCapacityTimestamp(sessionKey) && inventoryAge(sessionKey, snapshot.view.serverNow) > age ? snapshot.view : null;
    const selected = view?.groups.find(group => group.id === selectedId) ?? null;
    return { requested: activated, activate: () => setActivated(true), view, selected, selectedId, select: (id: string) => { commands.current.cancel(); setSelectedId(id); }, memberIds: selectedId ? new Set(selected?.memberIds ?? []) : null, loading, saving, error, notice, generation, admin, refresh: () => commands.current.refresh(), hold: (value: boolean) => commands.current.hold(value), cancel: () => commands.current.cancel(), save: (intent: GroupIntent) => commands.current.save(intent), io: (fresh = false) => commands.current.io(fresh), monitoringIO: (groupId: string, fresh = false) => commands.current.monitoringIO(groupId, fresh), maintenanceIO: (groupId: string, fresh = false) => commands.current.maintenanceIO(groupId, fresh) };
}
export type FleetGroupsResource = ReturnType<typeof useFleetGroups>;

function MemberList({ members, c }: { members: FleetGroupDevice[]; c: Copy }) {
    return members.length ? <ul className="fleet-group-members">{members.map(member => <li key={member.id}><strong>{member.name}</strong><span>{member.platform === 'windows' ? 'Windows' : 'Linux'}</span><code>{member.id}</code></li>)}</ul> : <p>{c.none}</p>;
}
function GroupEditor({ resource, initial, c, onClose }: { resource: FleetGroupsResource; initial: FleetGroup | null; c: Copy; onClose: () => void }) {
    const [name, setName] = useState(initial?.name ?? ''), [ids, setIds] = useState(initial?.memberIds ?? []), [step, setStep] = useState<'edit' | 'review' | 'delete'>('edit'), [removeUnavailable, setRemoveUnavailable] = useState(false);
    const view = resource.view;
    if (!view) return null;
    const editable = resource.admin && !resource.saving, valid = validFleetGroupName(name) && ids.length + (removeUnavailable ? 0 : initial?.unavailableMembers ?? 0) <= 50;
    const selected = view.devices.filter(d => ids.includes(d.id));
    const save = async (remove = false) => { if (await resource.save({ groupId: initial?.id, name, memberIds: [...ids], expectedRevision: initial?.revision ?? 0, remove, removeUnavailableMembers: removeUnavailable })) onClose(); };
    return <Dialog title={step === 'delete' ? c.confirmDelete : step === 'review' ? c.groupReview : initial ? c.edit : c.create} onClose={onClose} className="fleet-group-dialog"><h2>{step === 'delete' ? c.confirmDelete : step === 'review' ? c.groupReview : initial ? c.edit : c.create}</h2><p>{c.organizational}</p>
        {!resource.admin && <p role="status">{c.readOnly}</p>}
        {step === 'edit' ? <><label className="fleet-group-field">{c.name}<input value={name} maxLength={80} disabled={!editable} onChange={event => setName(event.target.value)}/></label><fieldset disabled={!editable} className="fleet-group-choices"><legend>{c.members}</legend>{view.devices.map(member => <label key={member.id}><input type="checkbox" aria-label={`${member.name} ${member.platform === 'windows' ? 'Windows' : 'Linux'} · ${member.id}`} checked={ids.includes(member.id)} onChange={event => setIds(previous => event.target.checked ? [...previous, member.id] : previous.filter(id => id !== member.id))}/><span><strong>{member.name}</strong><small>{member.platform === 'windows' ? 'Windows' : 'Linux'} · {member.id}</small></span></label>)}</fieldset><p>{ids.length}/50 · {c.limits}</p></> : <><h3>{name}</h3><p>{c.revision}: {initial?.revision ?? 0}</p>{step === 'delete' ? <p>{c.deleteScope}</p> : <MemberList members={selected} c={c}/>}</>}
        {!!initial?.unavailableMembers && <><p>{c.unavailableMembers}: {initial.unavailableMembers}. {c.omitted}</p>{step === 'edit' ? <label className="fleet-group-enable"><input type="checkbox" checked={removeUnavailable} disabled={!editable} onChange={event => setRemoveUnavailable(event.target.checked)}/>{c.removeUnavailable} ({initial.unavailableMembers})</label> : step === 'review' && <p>{removeUnavailable ? c.removingUnavailable : c.retainedUnavailable} ({initial.unavailableMembers})</p>}</>}
        <div className="fleet-group-actions">{editable && step === 'edit' && <button className="button" disabled={!valid} onClick={() => setStep('review')}>{c.reviewChanges}</button>}{editable && step === 'review' && <button className="button" onClick={() => void save()}>{c.save}</button>}{editable && step === 'delete' && <button className="button" onClick={() => void save(true)}>{c.confirmDelete}</button>}{resource.saving && <span role="status">{c.busy}</span>}{editable && step !== 'edit' && <button className="text-button" onClick={() => setStep('edit')}>{c.back}</button>}{editable && initial && step === 'edit' && <button className="text-button" onClick={() => setStep('delete')}>{c.delete}</button>}<button className="text-button" onClick={onClose}>{c.cancel}</button></div>
    </Dialog>;
}

const monitoringMetrics: WindowsPercentageMetric[] = ['disk', 'cpu', 'memory'];
type PolicyDraft = { metric: WindowsPercentageMetric; selected: boolean; enabled: boolean; threshold: string };
const initialPolicyDrafts = (): PolicyDraft[] => monitoringMetrics.map(metric => ({ metric, selected: false, enabled: false, threshold: '90' }));
function HealthEditor({ resource, group, c, onClose }: { resource: FleetGroupsResource; group: FleetGroup | null; c: Copy; onClose: () => void }) {
    const [drafts, setDrafts] = useState(initialPolicyDrafts), [ids, setIds] = useState<string[]>([]);
    const [review, setReview] = useState<GroupHealthReview | null>(null), [results, setResults] = useState<GroupHealthResult[] | null>(null), [phase, setPhase] = useState<'draft' | 'reviewing' | 'reviewed' | 'applying' | 'done' | 'failed' | 'stopped'>('draft');
    const alive = useRef(true), run = useRef(0), inFlight = useRef(false);
    useEffect(() => { alive.current = true; return () => { alive.current = false; run.current++; }; }, []);
    const view = resource.view;
    if (!view) return null;
    const members = view.devices.filter(d => d.platform === 'windows' && (!group || group.memberIds.includes(d.id)));
    const selected = drafts.filter(d => d.selected);
    const valid = selected.every(d => /^\d{2}$/.test(d.threshold) && Number(d.threshold) >= 50 && Number(d.threshold) <= 99);
    const settings: GroupHealthSetting[] = review?.settings ?? selected.map(d => ({ metric: d.metric, enabled: d.enabled, thresholdPercent: Number(d.threshold) }));
    const edit = (metric: WindowsPercentageMetric, patch: Partial<PolicyDraft>) => setDrafts(previous => previous.map(d => d.metric === metric ? { ...d, ...patch } : d));
    const prepare = async () => {
        if (inFlight.current || phase !== 'draft' || !valid || !settings.length || ids.length < 1 || ids.length > 25 || !resource.admin) return;
        inFlight.current = true;
        const current = ++run.current; setPhase('reviewing'); setReview(null); setResults(null);
        try {
            const next = await reviewGroupHealth(group, view, [...ids], settings, resource.io(true));
            if (alive.current && current === run.current) { setReview(next); setPhase('reviewed'); }
        } catch { if (alive.current && current === run.current) { resource.cancel(); setPhase(previous => previous === 'stopped' ? previous : 'failed'); } }
        finally { if (current === run.current) inFlight.current = false; }
    };
    const apply = async () => {
        if (inFlight.current || !review || phase !== 'reviewed' || !resource.admin) return;
        inFlight.current = true;
        const current = ++run.current; setPhase('applying');
        try {
            await applyGroupHealth(review, resource.io(), rows => { if (alive.current && current === run.current) setResults(rows); });
            if (alive.current && current === run.current) { setReview(null); setPhase(previous => previous === 'stopped' ? previous : 'done'); }
        } catch { if (alive.current && current === run.current) setPhase(previous => previous === 'stopped' ? previous : 'failed'); }
        finally { if (current === run.current) inFlight.current = false; }
    };
    const stop = () => { resource.cancel(); setReview(null); setPhase('stopped'); };
    const fresh = () => { run.current++; inFlight.current = false; resource.cancel(); setReview(null); setResults(null); setIds([]); setDrafts(initialPolicyDrafts()); setPhase('draft'); };
    const rows: (GroupHealthReview['members'][number] & Partial<Pick<GroupHealthResult, 'status' | 'matchingAfterUnconfirmed'>>)[] | undefined = results ?? review?.members;
    const reviewedDevices = rows ? [...new Map(rows.map(row => [row.id, row])).values()] : [];
    return <Dialog title={c.healthTitle} onClose={onClose} className="fleet-group-dialog"><h2>{c.healthTitle}</h2>
        <p>{group ? <><strong>{group.name}</strong> · {c.revision}: {group.revision}</> : <strong>{c.devices}</strong>}</p>
        <p>{c.healthSummary}</p><p className="fleet-monitoring-counts">{c.selectedPolicies}: {settings.length} · {c.selectedDevices}: {rows ? reviewedDevices.length : ids.length}</p>
        <details className="fleet-group-limits"><summary>{c.policyDetails}</summary><p>{c.settingScope}</p><p>{c.windowsOnly}</p><p>{c.frozen}</p><p>{c.diskScope}</p><p>{c.cpuScope}</p><p>{c.memoryScope}</p><p>{c.rules}</p><p>{c.changes}</p><p>{c.healthBound}</p><p>{c.contactServices}</p></details>
        {phase === 'draft' && <>
            <fieldset className="fleet-monitoring-settings"><legend>{c.policies}</legend>{drafts.map(d => <div key={d.metric} className="fleet-monitoring-setting">
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.include} ${c[d.metric]}`} checked={d.selected} onChange={event => edit(d.metric, { selected: event.target.checked })}/><span>{c[d.metric]}{!d.selected && <small>{c.unchanged}</small>}</span></label>
                <label className="fleet-group-enable"><input type="checkbox" aria-label={`${c.enabled} · ${c[d.metric]}`} checked={d.enabled} disabled={!d.selected} onChange={event => edit(d.metric, { enabled: event.target.checked })}/>{c.enabled}</label>
                <label className="fleet-group-field">{c.threshold}<input aria-label={`${c.threshold} · ${c[d.metric]}`} type="number" min="50" max="99" step="1" value={d.threshold} disabled={!d.selected} onChange={event => edit(d.metric, { threshold: event.target.value })}/></label>
            </div>)}</fieldset>
            <fieldset className="fleet-group-choices"><legend>{c.choose} ({ids.length}/25)</legend>{members.map(member => <label key={member.id}><input type="checkbox" aria-label={`${member.name} ${member.id}`} checked={ids.includes(member.id)} disabled={!ids.includes(member.id) && ids.length >= 25} onChange={event => setIds(previous => event.target.checked ? [...previous, member.id] : previous.filter(id => id !== member.id))}/><span><strong>{member.name}</strong><small>{member.id}</small></span></label>)}</fieldset>
            {!members.length && <p>{c.noWindows}</p>}{!valid && <p role="status">{c.invalid}</p>}
        </>}
        {phase === 'reviewing' && <p role="status">{c.reviewing}</p>}{phase === 'failed' && <p role="alert">{c.reviewFailed}</p>}
        {rows && <>
            <ul className="fleet-monitoring-summary">{settings.map(setting => <li key={setting.metric}><strong>{c[setting.metric]}</strong> · {setting.enabled ? c.on : c.off} · {setting.thresholdPercent}%</li>)}</ul><p>{c.applySafety}</p>
            <div className="fleet-group-table-wrap"><table className="fleet-group-table" role="table">
                <caption>{results ? c.results : c.review}</caption>
                <thead role="rowgroup"><tr role="row"><th role="columnheader" scope="col">{c.device}</th><th role="columnheader" scope="col">{c.before}</th>{results && <th role="columnheader" scope="col">{c.outcome}</th>}</tr></thead>
                <tbody role="rowgroup">{reviewedDevices.map(member => <tr key={member.id} role="row">
                    <td role="cell"><strong>{member.name}</strong><code>{member.id}</code></td>
                    <td role="cell" data-label={c.before}>{rows.filter(row => row.id === member.id).map(row => <div className="fleet-monitoring-policy-result" key={row.metric}><strong>{c[row.metric]}</strong><span>{row.policy.enabled ? c.on : c.off} · {row.policy.thresholdPercent}%</span><small>{c.policyRevision}: {row.policy.revision}</small></div>)}</td>
                    {results && <td role="cell" data-label={c.outcome}>{rows.filter(row => row.id === member.id).map(row => <div className="fleet-monitoring-policy-result" key={row.metric}><strong>{c[row.metric]}</strong><span>{row.status && c[row.status]}</span>{row.matchingAfterUnconfirmed && <small>{c.matching}</small>}</div>)}</td>}
                </tr>)}</tbody>
            </table></div>
        </>}
        {phase === 'applying' && <p role="status">{c.applying}</p>}{phase === 'stopped' && <p role="status">{c.stopped}</p>}{phase === 'done' && <p role="status">{c.explicit}</p>}
        <div className="fleet-group-actions">{phase === 'draft' && <button className="button" disabled={!valid || !settings.length || !ids.length || !resource.admin} onClick={() => void prepare()}>{c.review}</button>}{phase === 'reviewed' && <button className="button" onClick={() => void apply()}>{c.apply}</button>}{(phase === 'applying' || phase === 'reviewing') && <button className="button" onClick={stop}>{c.stop}</button>}{['done', 'failed', 'stopped', 'reviewed'].includes(phase) && <button className="button" onClick={fresh}>{c.fresh}</button>}<button className="text-button" onClick={onClose}>{c.cancel}</button></div>
    </Dialog>;
}

export function FleetGroupsControls({ resource }: { resource: FleetGroupsResource }) {
    const [locale] = useLocale(), c = copy[locale];
    const [inheritance, setInheritance] = useState(false);
    const [dialog, setDialog] = useState<'manage' | 'new' | 'edit' | 'health' | 'maintenance' | 'maintenance-end' | null>(null), [editingId, setEditingId] = useState('');
    const close = () => { resource.cancel(); resource.hold(false); setDialog(null); setInheritance(false); };
    const open = (next: typeof dialog) => { resource.cancel(); setInheritance(false); resource.hold(true); setDialog(next); };
    const group = resource.view?.groups.find(g => g.id === editingId) ?? resource.selected;
    if (!resource.requested) return <div className="fleet-groups"><button className="text-button" onClick={resource.activate}><Folder size={15} aria-hidden="true"/>{c.groups}</button></div>;
    return <div className="fleet-groups"><div className="fleet-group-toolbar"><label className="fleet-group-select"><Folder size={15} aria-hidden="true"/><span>{c.groups}</span><select aria-label={c.groups} value={resource.selectedId} disabled={resource.loading || resource.saving} onChange={event => { close(); resource.select(event.target.value); }}><option value="">{c.all}</option>{resource.selectedId && !resource.selected && <option value={resource.selectedId}>{c.selectedMissing}</option>}{resource.view?.groups.map(item => <option key={item.id} value={item.id}>{item.name} ({item.memberIds.length})</option>)}</select></label><button className="text-button" disabled={!resource.view} onClick={() => open('manage')}><Settings2 size={14} aria-hidden="true"/>{c.manage}</button>{resource.admin && resource.view && (!resource.selectedId || resource.selected) && <button className="text-button" onClick={() => open('health')}>{c.health}</button>}{resource.admin && resource.view && resource.selected && <button className="text-button" onClick={() => open('maintenance')}>{locale === 'de' ? 'Gruppenwartung starten' : 'Start group maintenance'}</button>}{resource.admin && resource.view && resource.selected && <button className="text-button" onClick={() => open('maintenance-end')}>{locale === 'de' ? 'Gruppenwartung beenden' : 'End group maintenance'}</button>}{resource.view && resource.selected && <button className="text-button" aria-expanded={inheritance} onClick={() => { if (inheritance) close(); else { resource.cancel(); setDialog(null); resource.hold(true); setInheritance(true); } }}>{locale === 'de' ? 'Gruppen-Monitoring' : 'Group monitoring'}</button>}<button className="text-button" disabled={resource.loading || resource.saving} onClick={() => { close(); resource.refresh(); }}><RefreshCw size={14} aria-hidden="true"/>{c.refresh}</button></div>
        {inheritance && resource.view && resource.selected && <GroupMonitoring key={resource.selected.id} resource={resource} group={resource.selected} onClose={close}/>}
        {resource.loading && <p role="status">{c.loading}</p>}{resource.error && <p role="status">{c.unavailable}</p>}{resource.notice && <p role="status">{c[resource.notice]}</p>}
        {dialog === 'manage' && resource.view && <Dialog title={c.manage} onClose={close} className="fleet-group-dialog"><h2>{c.manage}</h2><p>{c.organizational}</p><p>{c.limits}</p>{!resource.admin && <p>{c.readOnly}</p>}<ul className="fleet-group-list">{resource.view.groups.map(item => <li key={item.id}><button className="text-button" onClick={() => { setEditingId(item.id); open('edit'); }}>{item.name}</button><span>{item.memberIds.length}/50 · {c.revision}: {item.revision}{item.unavailableMembers > 0 && <> · {c.unavailableMembers}: {item.unavailableMembers}</>}</span></li>)}</ul>{!resource.view.groups.length && <p>{c.empty}</p>}{resource.admin && <button className="button" disabled={resource.view.groups.length >= 25} onClick={() => open('new')}>{c.create}</button>}</Dialog>}
        {(dialog === 'new' || dialog === 'edit' && group) && <GroupEditor key={dialog === 'new' ? 'new' : group!.id} resource={resource} initial={dialog === 'new' ? null : group} c={c} onClose={close}/>}
        {dialog === 'maintenance' && resource.view && resource.selected && <GroupMaintenance resource={resource} group={resource.selected} onClose={close}/>}
        {dialog === 'maintenance-end' && resource.view && resource.selected && <GroupMaintenanceEnd resource={resource} group={resource.selected} onClose={close}/>}
        {dialog === 'health' && resource.view && (!resource.selectedId || resource.selected) && <HealthEditor resource={resource} group={resource.selected} c={c} onClose={close}/>}
    </div>;
}
