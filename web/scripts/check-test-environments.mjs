// Compare actual Vitest discovery with the same config before the environment split.
// No test bodies are executed here; the ordinary aggregate still runs every assertion.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const nodeProject = 'node-contracts';
const browserProject = 'browser-interactions';

export function validateManifest(value) {
    if (!value || Array.isArray(value) || typeof value !== 'object'
        || Object.keys(value).sort().join(',') !== 'nodeFiles,schemaVersion'
        || value.schemaVersion !== 1 || !Array.isArray(value.nodeFiles)
        || value.nodeFiles.length === 0 || value.nodeFiles.length > 1024) {
        throw new Error('Invalid test environment manifest.');
    }
    const files = value.nodeFiles;
    for (const file of files) {
        if (typeof file !== 'string' || !/^src\/[a-zA-Z0-9_/-]+\.test\.ts$/.test(file)
            || file.includes('//') || file.split('/').some(part => part === '.' || part === '..')) {
            throw new Error('Node tests must be exact src/*.test.ts paths without patterns.');
        }
    }
    const sorted = [...files].sort();
    if (new Set(files).size !== files.length || files.some((file, index) => file !== sorted[index])) {
        throw new Error('Node test paths must be sorted and unique.');
    }
    return new Set(files);
}

function normalizedFile(file, root) {
    if (typeof file !== 'string' || !isAbsolute(file)) throw new Error('Invalid discovered test path.');
    const value = relative(root, file).split(sep).join('/');
    if (!value || value.startsWith('../') || isAbsolute(value)) throw new Error('Discovered test is outside the web root.');
    return value;
}

export function verifyDiscovery(manifest, baseline, projects, root = webRoot) {
    const nodeFiles = validateManifest(manifest);
    if (!Array.isArray(baseline) || baseline.length === 0 || !Array.isArray(projects)) {
        throw new Error('Missing test discovery evidence.');
    }
    const expected = new Set();
    for (const row of baseline) {
        if (!row || row.projectName !== undefined) throw new Error('Baseline discovery must be unsplit.');
        const file = normalizedFile(row.file, root);
        if (expected.has(file)) throw new Error('Duplicate baseline test file.');
        expected.add(file);
    }
    for (const file of nodeFiles) {
        if (!expected.has(file)) throw new Error('Node manifest contains an undiscovered or deleted test.');
    }
    const seen = new Set();
    for (const row of projects) {
        if (!row) throw new Error('Invalid project discovery.');
        const file = normalizedFile(row.file, root);
        if (!expected.has(file)) throw new Error('Project discovery added an unexpected test.');
        if (seen.has(file)) throw new Error('A test file is selected more than once.');
        const wanted = nodeFiles.has(file) ? nodeProject : browserProject;
        if (row.projectName !== wanted) throw new Error('A test file uses the wrong environment project.');
        seen.add(file);
    }
    if (seen.size !== expected.size) throw new Error('The environment split omitted a test file.');
    return { files: seen.size, nodeFiles: nodeFiles.size, browserFiles: seen.size - nodeFiles.size };
}

function discover(config) {
    const result = spawnSync(process.execPath, [join(webRoot, 'node_modules/vitest/vitest.mjs'), 'list', '--filesOnly', '--json', '--config', config], {
        cwd: webRoot,
        encoding: 'utf8',
        timeout: 60_000,
        maxBuffer: 4 * 1024 * 1024,
        env: { ...process.env, NO_COLOR: '1' },
    });
    if (result.error || result.status !== 0) throw new Error('Vitest file discovery failed; run vitest list --filesOnly --json to diagnose.');
    try { return JSON.parse(result.stdout); } catch { throw new Error('Vitest returned invalid file discovery.'); }
}

export function checkEnvironments() {
    const config = join(webRoot, 'vite.config.ts');
    const manifest = JSON.parse(readFileSync(join(webRoot, 'test-environments.json'), 'utf8'));
    validateManifest(manifest);
    const temporary = mkdtempSync(join(tmpdir(), 'tracebolt-vitest-discovery-'));
    try {
        const baselineConfig = join(temporary, 'baseline.config.mjs');
        // Keep the actual setup/plugins, but independently restore original default
        // include/exclude discovery so a root exclusion cannot weaken both lists.
        writeFileSync(baselineConfig, `import base from ${JSON.stringify(config.split(sep).join('/'))};\nimport {configDefaults} from ${JSON.stringify(join(webRoot, 'node_modules/vitest/dist/config.js').split(sep).join('/'))};\nexport default {...base, root: ${JSON.stringify(webRoot)}, test: {...base.test, projects: undefined, include: configDefaults.include, exclude: configDefaults.exclude}};\n`, { mode: 0o600 });
        return verifyDiscovery(manifest, discover(baselineConfig), discover(config));
    } finally {
        rmSync(temporary, { recursive: true, force: true });
    }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const result = checkEnvironments();
        console.log(`PASS: ${result.files} default-discovered test files selected exactly once (${result.nodeFiles} Node, ${result.browserFiles} jsdom).`);
    } catch (error) {
        console.error(error instanceof Error ? error.message : 'Test environment coverage check failed.');
        process.exitCode = 1;
    }
}
