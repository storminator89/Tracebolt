/** Hosted exact-source evidence gate; inert tests use the exported validator. */
import assert from 'node:assert/strict';
import path from 'node:path';
import { root, assertHostedSource, validateEvidence } from './windows-complete-service-health-contract.mjs';
assert.equal(process.argv.length, 3);
await assertHostedSource(process.argv[2]);
const manifest = await validateEvidence(path.join(root, 'artifacts/review'), process.argv[2]);
await assertHostedSource(process.argv[2], manifest.sourceInputs);
console.log('PASS: canonical synthetic complete-service component evidence; not whole-App or native acceptance.');
