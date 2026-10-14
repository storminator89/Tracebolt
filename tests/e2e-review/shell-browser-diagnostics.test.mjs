/** Inert source/diagnostic tests; no browser, listener or manager execution. */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
import contract from './shell-browser-cases.json' with { type: 'json' };
import { createShellFailureDiagnostic, shellFailureCategories } from './shell-browser-diagnostics.mjs';
import { routeLoadingDevelopmentCaseName } from './route-loading-browser.mjs';
const require = createRequire(new URL('../../web/package.json', import.meta.url)), ts = require('typescript');
const sourceFile = file => ts.createSourceFile(file, fs.readFileSync(new URL(file, import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);

// Read only literal loop domains and test-name expressions; never execute a
// callback, setup function, import side effect or arbitrary source expression.
function namesIn(source) {
    const names = [];
    function value(node, bindings) {
        if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
        if (ts.isIdentifier(node) && Object.hasOwn(bindings, node.text)) return bindings[node.text];
        if (ts.isTemplateExpression(node)) return node.head.text + node.templateSpans.map(span => value(span.expression, bindings) + span.literal.text).join('');
        throw new Error('Unreviewed test-name expression');
    }
    function scan(node, bindings) {
        if (ts.isForOfStatement(node)) {
            // Only loops containing registered test calls affect case IDs.
            let contains = false;
            function find(n) { if (ts.isCallExpression(n) && n.expression.getText(source) === 'test') contains = true; ts.forEachChild(n, find); }
            find(node.statement); if (!contains) return;
            assert.ok(ts.isArrayLiteralExpression(node.expression));
            const binding = node.initializer.declarations[0].name;
            for (const item of node.expression.elements) {
                const next = { ...bindings };
                if (ts.isIdentifier(binding)) next[binding.text] = value(item, bindings);
                else {
                    assert.ok(ts.isArrayBindingPattern(binding) && ts.isArrayLiteralExpression(item));
                    // Only literal label fields are consumed by case names.
                    binding.elements.forEach((element, i) => { if (ts.isStringLiteral(item.elements[i])) next[element.name.text] = item.elements[i].text; });
                }
                scan(node.statement, next);
            }
            return;
        }
        if (ts.isCallExpression(node) && node.expression.getText(source) === 'test') { names.push(value(node.arguments[0], bindings)); return; }
        ts.forEachChild(node, child => scan(child, bindings));
    }
    scan(source, { routeLoadingDevelopmentCaseName });
    return names;
}

test('numeric registry binds the exact ordered source cases including literal loop variants and AI', () => {
    assert.deepEqual(Object.keys(contract), ['schema', 'cases']); assert.equal(contract.schema, 1);
    assert.equal(contract.cases.length, 45); assert.equal(new Set(contract.cases).size, 45);
    const names = ['run.mjs', 'concise-shell-gallery.mjs', 'shell-scenarios.mjs', 'ai-scenarios.mjs'].flatMap(file => namesIn(sourceFile(file)));
    assert.deepEqual(contract.cases, names);
    assert.deepEqual(shellFailureCategories, ['assertion', 'timeout', 'other']);
    assert.ok(Object.isFrozen(shellFailureCategories));
});

test('failure projection emits only source IDs and closed categories, never error or name strings', () => {
    const diagnostic = createShellFailureDiagnostic(), marker = 'private-dynamic-marker';
    diagnostic.failure(contract.cases[3], { name: 'TimeoutError', message: marker });
    diagnostic.failure(contract.cases[1], { matcherResult: { actual: marker, expected: marker }, message: marker });
    diagnostic.failure(contract.cases[4], { name: marker, message: marker });
    diagnostic.failure(marker, new Error(marker));
    assert.deepEqual(diagnostic.report('a'.repeat(40)), { schema: 1, sourceSha: 'a'.repeat(40), failures: [
        { case: 2, category: 'assertion' }, { case: 4, category: 'timeout' }, { case: 5, category: 'other' },
    ], runtimeCases: [], unknownCase: true });
    const serialized = JSON.stringify(diagnostic.report('a'.repeat(40)));
    assert.equal(serialized.includes(marker), false);
    for (const name of contract.cases) assert.equal(serialized.includes(name), false);
});

test('runtime coordinates deduplicate and sort known IDs while withholding unknown names', () => {
    const diagnostic = createShellFailureDiagnostic();
    for (const name of [contract.cases[44], contract.cases[0], contract.cases[44], 'unregistered-private-marker']) diagnostic.runtime(name);
    assert.deepEqual(diagnostic.report('a'.repeat(40)).runtimeCases, [1, 45]);
    assert.equal(diagnostic.report('a'.repeat(40)).unknownCase, true);
});

test('diagnostic classification cannot replace an original failure even with hostile error getters', () => {
    const diagnostic = createShellFailureDiagnostic();
    diagnostic.failure(contract.cases[0], { get name() { throw new Error('private-marker'); } });
    assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [{ case: 1, category: 'other' }]);
});

test('actual shell test wrapper keeps failed results and cleanup after passive recording', async () => {
    const source = sourceFile('run.mjs'), wrapper = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'test');
    const diagnostic = createShellFailureDiagnostic(), closed = [], disposed = [];
    const globals = { currentTest: '', Date, results: [], console: { log() {} }, sanitize: value => value,
        shellDiagnostic: diagnostic, allPages: new Set([{ close: async () => closed.push(true) }]),
        transportDiagnostics: new Map([[1, { dispose: () => disposed.push(true) }]]) };
    const run = vm.runInNewContext('(' + wrapper.getText(source) + ')', globals);
    await run(contract.cases[1], async () => { throw Object.assign(new Error('inert-marker'), { matcherResult: {} }); });
    assert.equal(globals.results.length, 1); assert.equal(globals.results[0].status, 'FAIL');
    assert.equal(globals.results[0].error, 'inert-marker'); assert.equal(closed.length, 1); assert.equal(disposed.length, 1);
    assert.equal(globals.allPages.size, 0); assert.equal(globals.transportDiagnostics.size, 0);
    assert.deepEqual(diagnostic.report('a'.repeat(40)).failures, [{ case: 2, category: 'assertion' }]);
});
