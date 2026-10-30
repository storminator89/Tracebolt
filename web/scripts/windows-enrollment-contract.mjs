/** Closed synthetic capture contract; no live manager or endpoint authority. */
import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { crc32, inflateSync } from 'node:zlib';
import path from 'node:path';
export const origin = 'https://windows-enrollment.invalid';
export const disclosure = 'Synthetic Windows TLS inventory enrollment DTOs in the actual compiled EnrollmentSection and protected request code, not the whole App. Every browser request is intercepted. One invented creation per viewport; lifecycle events clear the invented invitation before capture. Screenshots are cropped to the unchanged production dialog; background history and its fixed invented identifiers are outside the capture. A separate fifteen-case synthetic visibility-control context takes no screenshots or API actions. Identifier-only closed bodies need finite positive own-parent boxes and native hidden evidence; every secret text match is rejected. A bounded mutation/animation guard and postcheck run before in-memory PNGs are persisted. This static-source, no-CSSOM-mutation harness does not provide general atomic screenshots. No real login, invitation, key, network, endpoint, installation or native acceptance.';
export const viewports = Object.freeze(['en', 'de'].flatMap(locale => [1440, 390].map(width => Object.freeze({ locale, width, height: width === 390 ? 844 : 1100 }))));
export const scenes = Object.freeze(['instructions', 'release']);
export const captureMatrix = Object.freeze(viewports.flatMap(view => scenes.map(scene => Object.freeze({ ...view, scene, file: `windows-enrollment-${scene}-${view.locale}-${view.width}.png` }))));
export const publicSafeFailures = Object.freeze(['public-safe-text', 'public-safe-text-closed-details-native-true', 'public-safe-text-closed-details-native-false', 'public-safe-text-closed-details-native-unavailable', 'public-safe-text-closed-details-native-error', 'public-safe-inputs', 'public-safe-location', 'public-safe-storage']);
// Fixed, source-owned diagnostics for the isolated synthetic controls only.
export const visibilityControlCases = Object.freeze(['clear', 'visible', 'closed-body', 'closed-summary', 'open-body', 'contents', 'closed-secret', 'second-summary', 'outer-body', 'inner-body', 'body-contents', 'closed-then-visible', 'override-body', 'override-contents', 'override-inline']);
export const visibilityControlPrivacyStages = Object.freeze(['public-safe-elements', 'public-safe-inspection', ...publicSafeFailures]);
const controlPrivacyLast = ['none', 'invalid', ...visibilityControlPrivacyStages];
export const visibilityControlPhases = Object.freeze([
 'measure', 'observation-shape', 'range-type', 'box-type', 'box-positive', 'box-empty', 'playwright-visible',
 ...['positive', 'empty'].flatMap(range => [
  `range-${range}`, `playwright-hidden-range-${range}`, `privacy-check-range-${range}`,
  ...['true', 'false', 'invalid'].map(native => `native-${native}-range-${range}`),
  ...controlPrivacyLast.flatMap(last => [
   `privacy-check-${last}-range-${range}`,
   `privacy-accepted-last-${last}-range-${range}`,
   `privacy-rejected-last-${last}-range-${range}`,
   `privacy-sequence-last-${last}-range-${range}`,
  ]),
 ]),
]);
export function visibilityControlStage(name, phase) {
 assert(visibilityControlCases.includes(name) && visibilityControlPhases.includes(phase), 'Unknown synthetic visibility control diagnostic');
 return `visibility-control-${name}-${phase}`;
}
export const stages = Object.freeze(['launch', 'compile', 'visibility-control-context', 'visibility-control-route', 'visibility-control-page', 'visibility-control-blank', 'visibility-control-document', 'visibility-control-runtime-errors', 'visibility-control-route-boundary', ...visibilityControlCases.flatMap(name => visibilityControlPhases.map(phase => visibilityControlStage(name, phase))), ...visibilityControlCases.map(name => `visibility-control-${name}`), 'visibility-control-close', 'prepare-output', 'new-context', 'route', 'new-page', 'navigate', 'initial-status', 'select-windows', 'open-create', 'consent', 'submit-create', 'secret-masked', 'interrupt-clear', 'refresh-restored', 'instructions', 'fonts', 'scroll', 'no-overflow', 'public-safe', 'public-safe-elements', 'public-safe-inspection', ...publicSafeFailures, 'capture-guard', 'capture-guard-pre', 'capture-guard-post', 'public-safe-post', 'persist-image', 'screenshot', 'runtime-errors', 'route-boundary', 'image-hash', 'close-context', 'manifest', 'close-browser', 'evidence']);
export function diagnostic(stage, index = null) {
 assert(stages.includes(stage), 'Unknown Windows enrollment capture stage');
 assert(index === null || Number.isSafeInteger(index) && index >= 0 && index < captureMatrix.length, 'Invalid capture index');
 const row = index === null ? null : captureMatrix[index];
 return { stage, scene: row?.scene ?? null, locale: row?.locale ?? null, width: row?.width ?? null };
}
export function requireHosted() {
 assert(process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'Hosted CI only; use --check for inert local validation.');
}

// Linux-hosted evidence/source reads stay on one regular-file descriptor. Check
// canonical paths before opening and through /proc before reading any bytes.
export async function boundedRegular(file, maximum) {
 assert(Number.isSafeInteger(maximum) && maximum > 0 && maximum <= (16 << 20));
 const absolute = path.resolve(file);
 assert.equal(await realpath(absolute), absolute, 'Symlinked input path');
 const beforePath = await lstat(absolute, { bigint: true });
 assert(beforePath.isFile() && !beforePath.isSymbolicLink());
 const handle = await open(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
 try {
  const before = await handle.stat({ bigint: true });
  assert(before.isFile() && before.size > 0n && before.size <= BigInt(maximum));
  assert.equal(before.dev, beforePath.dev); assert.equal(before.ino, beforePath.ino);
  assert.equal(await realpath(absolute), absolute);
  if (process.platform === 'linux') assert.equal(await realpath(`/proc/self/fd/${handle.fd}`), absolute);
  const chunks = []; let count = 0;
  for (;;) {
   const buffer = Buffer.alloc(Math.min(65536, maximum + 1 - count));
   const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
   if (!bytesRead) break;
   count += bytesRead; assert(count <= maximum, 'Input exceeded bounded read'); chunks.push(buffer.subarray(0, bytesRead));
  }
  const after = await handle.stat({ bigint: true }), afterPath = await lstat(absolute, { bigint: true });
  for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'mode']) assert.equal(after[key], before[key], 'Input changed during read');
  assert.equal(afterPath.dev, before.dev); assert.equal(afterPath.ino, before.ino); assert(afterPath.isFile() && !afterPath.isSymbolicLink());
  assert.equal(await realpath(absolute), absolute); assert.equal(BigInt(count), before.size);
  return Buffer.concat(chunks, count);
 } finally { await handle.close(); }
}

let pngDecoder;
export function validateDialogPNG(png, viewportWidth, viewportHeight) {
 // Only Chromium's bounded 8-bit non-interlaced RGB/RGBA screenshot domain.
 assert(viewports.some(row => row.width === viewportWidth && row.height === viewportHeight));
 assert(Buffer.isBuffer(png) && png.length > 45 && png.length <= (8 << 20));
 assert(png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])));
 const compressed = []; let offset = 8, chunks = 0, width, height, channels, ended = false;
 while (offset < png.length) {
  assert(++chunks <= 4096 && offset + 12 <= png.length && !ended);
  const length = png.readUInt32BE(offset), type = png.toString('latin1', offset + 4, offset + 8);
  assert(length <= png.length - offset - 12);
  const end = offset + length + 12, data = png.subarray(offset + 8, end - 4);
  assert.equal(crc32(png.subarray(offset + 4, end - 4)), png.readUInt32BE(end - 4));
  if (offset === 8) {
   assert.equal(type, 'IHDR'); assert.equal(length, 13);
   width = data.readUInt32BE(0); height = data.readUInt32BE(4);
   assert(width > 0 && width <= viewportWidth && height > 0 && height <= viewportHeight);
   assert.equal(data[8], 8); assert([2, 6].includes(data[9])); assert.deepEqual([...data.subarray(10)], [0, 0, 0]);
   channels = data[9] === 2 ? 3 : 4;
  } else if (type === 'IDAT') { assert(length > 0); compressed.push(data); }
  else { assert.equal(type, 'IEND'); assert.equal(length, 0); assert(compressed.length > 0); assert.equal(end, png.length); ended = true; }
  offset = end;
 }
 assert(ended);
 const bytes = Buffer.concat(compressed), stride = width * channels + 1, expected = stride * height;
 assert(bytes.length > 0 && bytes.length <= (8 << 20) && expected <= (6 << 20) && width * height * 4 <= (6 << 20));
 const inflated = inflateSync(bytes, { maxOutputLength: expected, info: true });
 assert.equal(inflated.engine.bytesWritten, bytes.length); assert.equal(inflated.buffer.length, expected);
 for (let row = 0; row < height; row++) assert(inflated.buffer[row * stride] <= 4);
 if (!pngDecoder) {
  const require = createRequire(new URL('../package.json', import.meta.url));
  assert.equal(require('playwright-core/package.json').version, require('./package.json').devDependencies['@playwright/test']);
  pngDecoder = require(path.join(path.dirname(require.resolve('playwright-core/package.json')), 'lib/utilsBundle.js')).PNG;
 }
 const decoded = pngDecoder.sync.read(png, { checkCRC: true });
 assert.equal(decoded.width, width); assert.equal(decoded.height, height); assert.equal(decoded.data.length, width * height * 4);
 return { width, height };
}
