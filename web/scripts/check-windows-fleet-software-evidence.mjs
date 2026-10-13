/** Separate entry avoids a top-level-await cycle with canonical capture discovery. */
import assert from 'node:assert/strict';
import path from 'node:path';
import { root, validateEvidence } from './windows-fleet-software-contract.mjs';
assert([3, 4].includes(process.argv.length));
await validateEvidence(process.argv[3] ? path.resolve(process.argv[3]) : path.join(root, 'artifacts/review'), process.argv[2]);
console.log('PASS: canonical Windows fleet software lookup evidence.');
