/** Recheck successful hosted evidence without launching a browser or listener. */
import assert from 'node:assert/strict';
import path from 'node:path';
import { root, validateFirstReportEvidence, verifyFirstReportSource } from './first-report-contract.mjs';
try {
    assert.equal(process.argv.length, 3);
    const sourceSha = process.argv[2], sourceTree = verifyFirstReportSource(sourceSha);
    const inputs = await validateFirstReportEvidence(path.join(root, 'artifacts/review'), sourceSha, sourceTree);
    assert.equal(verifyFirstReportSource(sourceSha, inputs), sourceTree);
    console.log('PASS: exact-source synthetic first-report evidence.');
} catch { console.log('FAIL: first-report evidence; raw diagnostics withheld.'); process.exitCode = 1; }
