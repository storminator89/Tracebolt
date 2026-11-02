//! Static, in-process native view for the existing Go Setup controller.
//! No installation, networking, file selection, invitation or secret reader.
use serde::Deserialize;

pub const VIEW_LIMIT: usize = 512 * 1024;
pub const POLL: u32 = 1000;
pub const RESIZE: u32 = 1001;
pub const CLOSE: u32 = 1002;
pub const PRESENTED: u32 = 1003;

#[unsafe(no_mangle)]
pub extern "C" fn tracebolt_setup_abi() -> u32 {
    1
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Event {
    pub code: u32,
    pub value: u32,
    pub width: i32,
    pub height: i32,
    pub dpi: u32,
    pub owner: usize,
}
pub type Callback = unsafe extern "C" fn(usize, *const Event, *mut u8, usize) -> isize;

#[cfg(any(windows, test))]
struct Bridge {
    handle: usize,
    callback: Callback,
    scratch: Vec<u8>,
}

// Modal host dialogs can pump the Rust window while its State is borrowed.
// Preserve display-change truth outside that borrow; it must be reconciled
// before rendering/acknowledging any newly prepared privileged operation.
#[cfg(any(windows, test))]
#[derive(Default)]
struct ReentryGate {
    in_host: std::cell::Cell<bool>,
    layout_dirty: std::cell::Cell<bool>,
}
#[cfg(any(windows, test))]
impl ReentryGate {
    fn enter(&self) {
        self.in_host.set(true);
    }
    fn geometry(&self) {
        if self.in_host.get() {
            self.layout_dirty.set(true);
        }
    }
    fn leave(&self) -> bool {
        self.in_host.set(false);
        self.layout_dirty.replace(false)
    }
}
#[cfg(any(windows, test))]
impl Bridge {
    fn new(handle: usize, callback: Callback) -> Self {
        Self {
            handle,
            callback,
            scratch: vec![0; VIEW_LIMIT],
        }
    }
    // Every returned String owns its bytes. No view borrows the reusable
    // synchronous scratch buffer or any Go memory after this call returns.
    unsafe fn request(&mut self, event: &Event) -> Result<View, ()> {
        let count =
            unsafe { (self.callback)(self.handle, event, self.scratch.as_mut_ptr(), VIEW_LIMIT) };
        if count <= 0 || count as usize > self.scratch.len() {
            return Err(());
        }
        decode(&self.scratch[..count as usize]).map_err(|_| ())
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub revision: u64,
    pub controls: Vec<Control>,
    pub close: bool,
    pub pending: bool,
    #[serde(rename = "layoutOK")]
    pub layout_ok: bool,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Control {
    pub id: u32,
    pub kind: String,
    pub text: String,
    pub enabled: bool,
    pub checked: bool,
    pub r#box: Rect,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

pub fn decode(bytes: &[u8]) -> Result<View, &'static str> {
    if bytes.is_empty() || bytes.len() > VIEW_LIMIT {
        return Err("invalid view size");
    }
    let view: View = serde_json::from_slice(bytes).map_err(|_| "invalid view")?;
    if view.controls.len() > 32 {
        return Err("too many controls");
    }
    let mut ids = std::collections::HashSet::new();
    for c in &view.controls {
        if !ids.insert(c.id)
            || !matches!(c.kind.as_str(), "label" | "edit" | "button" | "check")
            || c.text.contains('\0')
            || c.text.len() > 256 * 1024
            || c.r#box.x < 0
            || c.r#box.y < 0
            || c.r#box.width < 1
            || c.r#box.height < 1
        {
            return Err("invalid control");
        }
    }
    Ok(view)
}

#[cfg(any(windows, test))]
mod layout;
#[cfg(windows)]
mod native;

/// # Safety
/// The host callback must remain live for this synchronous call, use only the
/// supplied scratch buffer, and never retain pointers. Handle is opaque scalar
/// data. The Go host cancels/joins active hooks before releasing its handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tracebolt_setup_run(handle: usize, callback: Option<Callback>) -> i32 {
    let Some(callback) = callback else { return 1 };
    #[cfg(windows)]
    {
        std::panic::catch_unwind(|| unsafe { native::run(handle, callback) })
            .ok()
            .and_then(Result::ok)
            .map_or(1, |()| 0)
    }
    #[cfg(not(windows))]
    {
        let _ = (handle, callback);
        1 // No non-Windows frontend or command fallback.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn abi_is_fixed_and_views_are_bounded() {
        assert_eq!(tracebolt_setup_abi(), 1);
        assert_eq!(std::mem::offset_of!(Event, owner), 24);
        assert_eq!(std::mem::size_of::<Event>(), 32);
        assert!(decode(&[]).is_err());
        assert!(decode(&vec![b' '; VIEW_LIMIT + 1]).is_err());
        assert!(decode(br#"{"revision":1,"controls":[],"close":false,"pending":false,"layoutOK":true,"secret":"no"}"#).is_err());
    }
    #[test]
    fn no_non_windows_or_null_callback_fallback() {
        assert_eq!(unsafe { tracebolt_setup_run(0, None) }, 1);
    }

    const PUBLIC_VIEW: &[u8] = br#"{"revision":1,"controls":[{"id":204,"kind":"edit","text":"PUBLIC_REVIEW","enabled":true,"checked":false,"box":{"X":12,"Y":12,"Width":600,"Height":100}}],"close":false,"pending":false,"layoutOK":true}"#;
    unsafe extern "C" fn fixture(
        handle: usize,
        event: *const Event,
        out: *mut u8,
        capacity: usize,
    ) -> isize {
        if handle != 17 || event.is_null() || capacity != VIEW_LIMIT {
            return -1;
        }
        unsafe { std::ptr::copy_nonoverlapping(PUBLIC_VIEW.as_ptr(), out, PUBLIC_VIEW.len()) };
        PUBLIC_VIEW.len() as isize
    }
    #[test]
    fn copied_callback_view_outlives_scratch_and_repeated_calls() {
        let mut bridge = Bridge::new(17, fixture);
        let first = unsafe { bridge.request(&Event::default()) }.unwrap();
        bridge.scratch.fill(0);
        assert_eq!(first.controls[0].text, "PUBLIC_REVIEW");
        assert!(!first.controls[0].checked);
        assert!(
            unsafe {
                bridge.request(&Event {
                    code: POLL,
                    ..Event::default()
                })
            }
            .is_ok()
        );
        bridge.handle = 18;
        assert!(unsafe { bridge.request(&Event::default()) }.is_err());
    }
    #[test]
    fn malformed_controls_and_duplicate_ids_fail_closed() {
        for invalid in ["unknown", "button\u{0}"] {
            let value = String::from_utf8(PUBLIC_VIEW.to_vec())
                .unwrap()
                .replace("edit", invalid);
            assert!(decode(value.as_bytes()).is_err());
        }
        let mut value: serde_json::Value = serde_json::from_slice(PUBLIC_VIEW).unwrap();
        let original = value["controls"][0].clone();
        value["controls"].as_array_mut().unwrap().push(original);
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        value["controls"].as_array_mut().unwrap().pop();
        value["controls"][0]["box"]["Width"] = 0.into();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    #[test]
    fn nested_native_event_cannot_alias_window_state() {
        let state = std::cell::RefCell::new(0);
        let mut outer = state.try_borrow_mut().unwrap();
        *outer += 1;
        assert!(state.try_borrow_mut().is_err());
        drop(outer);
        assert_eq!(*state.borrow(), 1);
    }
    #[test]
    fn modal_geometry_change_requires_reconciliation_before_presentation() {
        let gate = ReentryGate::default();
        gate.enter();
        gate.geometry();
        gate.geometry();
        assert!(gate.leave());
        gate.geometry(); // Our own MoveWindow after host return is not modal reentry.
        gate.enter();
        assert!(!gate.leave());
    }
}
