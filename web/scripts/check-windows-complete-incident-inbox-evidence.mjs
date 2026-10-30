/** Hosted exact-source evidence gate; inert tests use the exported validator. */
import assert from 'node:assert/strict';
import path from 'node:path';
import { root, assertHostedSource, validateEvidence } from './windows-complete-incident-inbox-contract.mjs';
assert.equal(process.argv.length, 3);
const sourceTree = await assertHostedSource(process.argv[2]);
const manifest = await validateEvidence(path.join(root, 'artifacts/review'), process.argv[2], sourceTree);
assert.equal(await assertHostedSource(process.argv[2], manifest.sourceInputs), sourceTree);
console.log('PASS: canonical synthetic complete-service incident inbox evidence; not whole-App or native acceptance.');
