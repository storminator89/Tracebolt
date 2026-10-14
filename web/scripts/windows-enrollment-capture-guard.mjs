/** Synthetic static-source capture only. This is a persistence guard, not an
 * atomic screenshot API or support for arbitrary hostile/dynamic stylesheets.
 * No production DOM, CSS, fixture bytes or browser visibility state is changed. */
export function createCaptureGuard(root) {
 const fail = () => { throw new Error('Unsupported synthetic capture guard'); };
 if (!root?.isConnected || root.ownerDocument !== document || root.getRootNode() !== document || typeof MutationObserver !== 'function' || typeof document.getAnimations !== 'function' || typeof requestAnimationFrame !== 'function' || typeof cancelAnimationFrame !== 'function') fail();
 const started = performance.now(), maximumMs = 10000, maximumFrames = 600;
 let dirty = false, disposed = false, frame = null, frames = 0, baseline;
 // Observe the whole document: selectors, inheritance and layout can make even
 // mutations outside the crop affect it. Never keep records or raw node values.
 const observer = new MutationObserver(records => { if (records.length) dirty = true; });
 const markDirty = () => { dirty = true; };
 const events = ['animationstart', 'animationiteration', 'animationend', 'animationcancel', 'transitionrun', 'transitionstart', 'transitionend', 'transitioncancel', 'visibilitychange'];
 const sheetState = () => {
  if (document.adoptedStyleSheets.length !== 0 || document.styleSheets.length > 32) fail();
  let characters = 0, rules = 0;
  return [...document.styleSheets].map(sheet => {
   const cssRules = sheet.cssRules, fragments = [];
   if (!Number.isSafeInteger(cssRules.length) || cssRules.length < 0 || (rules += cssRules.length) > 8192) fail();
   for (let index = 0; index < cssRules.length; index++) {
    const text = cssRules[index].cssText;
    if (typeof text !== 'string' || (characters += text.length) > (1 << 20)) fail();
    fragments.push(text);
   }
   const text = fragments.join('\n');
   return { sheet, disabled: sheet.disabled, media: sheet.media.mediaText, text };
  });
 };
 const audit = () => {
  if (disposed) return false;
  try {
   const elapsed = performance.now() - started;
   if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > maximumMs || !root.isConnected || root.ownerDocument !== document || root.getRootNode() !== document || document.visibilityState !== 'visible' || document.fonts.status !== 'loaded') dirty = true;
   const animations = document.getAnimations();
   // Reject all active, paused or pending animations, a conservative superset
   // of visibility animations. Finished nonpending fills are inspected by the
   // ordinary safety check. CSS events and per-frame checks cover the interval.
   if (animations.length > 256 || animations.some(animation => animation.pending !== false || !['finished', 'idle'].includes(animation.playState))) dirty = true;
   const current = sheetState();
   if (current.length !== baseline.length || current.some((sheet, index) => Object.keys(sheet).some(key => sheet[key] !== baseline[index][key]))) dirty = true;
  } catch { dirty = true; }
  if (observer.takeRecords().length) dirty = true;
  return !dirty;
 };
 const tick = () => {
  if (disposed) return;
  if (++frames > maximumFrames) dirty = true;
  if (audit()) frame = requestAnimationFrame(tick);
 };
 const dispose = () => {
  if (disposed) return;
  disposed = true; observer.disconnect();
  if (frame !== null) cancelAnimationFrame(frame);
  for (const event of events) document.removeEventListener(event, markDirty, true);
  window.removeEventListener('pagehide', markDirty, true);
  for (const event of ['loading', 'loadingdone', 'loadingerror']) document.fonts.removeEventListener(event, markDirty);
  baseline = null;
 };
 try {
  observer.observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  for (const event of events) document.addEventListener(event, markDirty, true);
  window.addEventListener('pagehide', markDirty, true);
  for (const event of ['loading', 'loadingdone', 'loadingerror']) document.fonts.addEventListener(event, markDirty);
  baseline = sheetState();
  if (!audit()) fail();
  frame = requestAnimationFrame(tick);
  return { check: audit, dispose };
 } catch { dispose(); fail(); }
}
