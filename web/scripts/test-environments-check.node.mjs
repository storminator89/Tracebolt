import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolve } from 'node:path';
import { validateManifest, verifyDiscovery } from './check-test-environments.mjs';

const root = resolve('synthetic-test-root');
const manifest = () => ({ schemaVersion: 1, nodeFiles: ['src/contract.test.ts'] });
const baseline = () => ['src/contract.test.ts', 'src/component.test.tsx'].map(file => ({ file: resolve(root, file) }));
const projects = () => baseline().map((row, i) => ({ ...row, projectName: i === 0 ? 'node-contracts' : 'browser-interactions' }));

test('preserves the complete default discovery exactly once', () => {
    assert.deepEqual(verifyDiscovery(manifest(), baseline(), projects(), root), { files: 2, nodeFiles: 1, browserFiles: 1 });
});
test('new default-discovered interaction tests remain covered in jsdom', () => {
    const next = { file: resolve(root, 'src/new-feature.test.tsx') };
    assert.deepEqual(verifyDiscovery(manifest(), [...baseline(), next], [...projects(), { ...next, projectName: 'browser-interactions' }], root), { files: 3, nodeFiles: 1, browserFiles: 2 });
});
for (const [name, mutate] of [
    ['missing file', value => value.pop()],
    ['duplicate file across projects', value => value.push({ ...value[0], projectName: 'browser-interactions' })],
    ['same-project duplicate', value => value.push({ ...value[0] })],
    ['wrong Node environment', value => { value[0].projectName = 'browser-interactions'; }],
    ['wrong browser environment', value => { value[1].projectName = 'node-contracts'; }],
    ['unknown project', value => { value[1].projectName = 'unknown'; }],
    ['unexpected file', value => value.push({ file: resolve(root, 'src/extra.test.ts'), projectName: 'browser-interactions' })],
    ['outside-root file', value => { value[1].file = resolve(root, '..', 'private.test.ts'); }],
    ['relative file', value => { value[1].file = 'src/component.test.tsx'; }],
    ['invalid path type', value => { value[1].file = null; }],
]) {
    test(`rejects ${name}`, () => { const value = projects(); mutate(value); assert.throws(() => verifyDiscovery(manifest(), baseline(), value, root)); });
}
for (const [name, value] of [
    ['duplicate manifest paths', { schemaVersion: 1, nodeFiles: ['src/contract.test.ts', 'src/contract.test.ts'] }],
    ['unsorted manifest paths', { schemaVersion: 1, nodeFiles: ['src/z.test.ts', 'src/a.test.ts'] }],
    ['wildcard manifest path', { schemaVersion: 1, nodeFiles: ['src/*.test.ts'] }],
    ['browser component in Node manifest', { schemaVersion: 1, nodeFiles: ['src/component.test.tsx'] }],
    ['traversal manifest path', { schemaVersion: 1, nodeFiles: ['src/../contract.test.ts'] }],
    ['empty manifest', { schemaVersion: 1, nodeFiles: [] }],
    ['unknown manifest field', { ...manifest(), extra: true }],
    ['unknown manifest version', { ...manifest(), schemaVersion: 2 }],
    ['null manifest', null],
]) {
    test(`rejects ${name}`, () => assert.throws(() => validateManifest(value)));
}
test('rejects a deleted or undiscovered listed contract', () => assert.throws(() => verifyDiscovery({ schemaVersion: 1, nodeFiles: ['src/missing.test.ts'] }, baseline(), projects(), root)));
test('rejects empty baseline', () => assert.throws(() => verifyDiscovery(manifest(), [], projects(), root)));
test('rejects duplicate baseline files', () => assert.throws(() => verifyDiscovery(manifest(), [...baseline(), baseline()[0]], projects(), root)));
test('rejects a baseline which still contains projects', () => assert.throws(() => verifyDiscovery(manifest(), projects(), projects(), root)));
