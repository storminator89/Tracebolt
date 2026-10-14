/** Passive failure coordinates only. Raw errors and case names never enter the
 * report, and this collector cannot change an assertion or retry a request. */
import contract from './shell-browser-cases.json' with { type: 'json' };
export const shellFailureCategories = Object.freeze(['assertion', 'timeout', 'other']);
const caseIDs = new Map(contract.cases.map((name, index) => [name, index + 1]));
function category(error) {
    try {
        if (error?.name === 'TimeoutError') return 'timeout';
        if (error?.matcherResult && typeof error.matcherResult === 'object') return 'assertion';
        return 'other';
    } catch { return 'other'; }
}
export function createShellFailureDiagnostic() {
    const failures = new Map(), runtimeCases = new Set();
    let unknownCase = false;
    return {
        failure(name, error) {
            const id = caseIDs.get(name);
            if (id === undefined) { unknownCase = true; return; }
            failures.set(id, category(error));
        },
        runtime(name) {
            const id = caseIDs.get(name);
            if (id === undefined) { unknownCase = true; return; }
            runtimeCases.add(id);
        },
        report(sourceSha) {
            return { schema: 1, sourceSha,
                failures: [...failures].sort(([a], [b]) => a - b).map(([id, category]) => ({ case: id, category })),
                runtimeCases: [...runtimeCases].sort((a, b) => a - b), unknownCase };
        },
    };
}
