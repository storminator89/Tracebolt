export interface DeviceNote { id: string; text: string; createdAt: string; archived: boolean; changedAt: string }
export interface NoteOperation { id: string; action: 'add' | 'archive' | 'restore'; noteId: string; revision: number }
export interface DeviceNotesView { schemaVersion: 'tracebolt.device-notes.v1'; deviceId: string; identityKey: string; binding: string; serverNow: string; validUntil: string; revision: number; canWrite: boolean; notes: DeviceNote[]; operations: NoteOperation[]; limits: { notes: 25; operations: 250; textBytes: 2000 } }
const exact = (v: unknown, keys: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === keys.sort().join();
const utc = (v: unknown): v is string => typeof v === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(v) && Number.isFinite(Date.parse(v));
export const noteBytes = (text: string) => new TextEncoder().encode(text).length;
export function validDeviceNotes(v: unknown, id: string): v is DeviceNotesView {
    if (!exact(v, ['schemaVersion','deviceId','identityKey','binding','serverNow','validUntil','revision','canWrite','notes','operations','limits']) || v.schemaVersion !== 'tracebolt.device-notes.v1' || v.deviceId !== id || typeof v.identityKey !== 'string' || !/^[a-f0-9]{64}$/.test(v.identityKey) || typeof v.binding !== 'string' || !/^[a-f0-9]{64}$/.test(v.binding) || !utc(v.serverNow) || !utc(v.validUntil) || Date.parse(v.validUntil) <= Date.parse(v.serverNow) || Date.parse(v.validUntil) - Date.parse(v.serverNow) > 60000 || !Number.isInteger(v.revision) || (v.revision as number) < 0 || (v.revision as number) > 250 || typeof v.canWrite !== 'boolean' || !exact(v.limits, ['notes','operations','textBytes']) || v.limits.notes !== 25 || v.limits.operations !== 250 || v.limits.textBytes !== 2000 || !Array.isArray(v.notes) || v.notes.length > 25 || !Array.isArray(v.operations) || v.operations.length !== v.revision) return false;
    const notes = v.notes;
    if (!notes.every(n => exact(n,['id','text','createdAt','archived','changedAt']) && typeof n.id === 'string' && /^note_[a-f0-9]{32}$/.test(n.id) && typeof n.text === 'string' && n.text.trim() === n.text && noteBytes(n.text) > 0 && noteBytes(n.text) <= 2000 && typeof n.archived === 'boolean' && utc(n.createdAt) && utc(n.changedAt) && Date.parse(n.createdAt) <= Date.parse(n.changedAt) && Date.parse(n.changedAt) <= Date.parse(v.serverNow as string)) || new Set(notes.map(n => n.id)).size !== notes.length) return false;
    if (!v.operations.every((o, i) => exact(o,['id','action','noteId','revision']) && typeof o.id === 'string' && /^noteop_[a-f0-9]{32}$/.test(o.id) && ['add','archive','restore'].includes(o.action as string) && notes.some(n => n.id === o.noteId) && Number.isInteger(o.revision) && (o.revision as number) >= 1 && (o.revision as number) <= (v.revision as number) && v.operations instanceof Array && !v.operations.slice(0,i).some(p => p.id === o.id || p.revision === o.revision))) return false;
    const states = new Map<string, boolean>();
    for (const op of [...v.operations].sort((a, b) => a.revision - b.revision)) {
        if (op.action === 'add') {
            if (states.has(op.noteId) || op.noteId.slice(5) !== op.id.slice(7)) return false;
            states.set(op.noteId, false);
        } else {
            if (!states.has(op.noteId) || states.get(op.noteId) !== (op.action === 'restore')) return false;
            states.set(op.noteId, op.action === 'archive');
        }
    }
    return notes.every(n => states.has(n.id) && states.get(n.id) === n.archived);
}
