use crate::layout::{Frame, WINDOW_STYLE, clamp_frame, font_height, initial_frame};
use crate::{Bridge, CLOSE, Callback, Event, POLL, PRESENTED, RESIZE, ReentryGate, View};
use std::{cell::RefCell, collections::BTreeMap, mem::size_of, ptr::null_mut, rc::Rc};
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
    Graphics::Gdi::*,
    System::LibraryLoader::GetModuleHandleW,
    UI::{
        HiDpi::*,
        Input::KeyboardAndMouse::{EnableWindow, IsWindowEnabled, SetFocus},
        WindowsAndMessaging::*,
    },
};

const STYLE: u32 = WINDOW_STYLE;
const TIMER: usize = 301;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

struct NativeControl {
    window: HWND,
    kind: String,
    text: String,
}
struct State {
    bridge: Bridge,
    gate: Rc<ReentryGate>,
    window: HWND,
    instance: *mut std::ffi::c_void,
    controls: BTreeMap<u32, NativeControl>,
    revision: Option<u64>,
    font: HFONT,
    dpi: u32,
    failed: bool,
}
struct WindowData {
    state: RefCell<State>,
    gate: Rc<ReentryGate>,
}

impl State {
    unsafe fn dispatch(&mut self, mut event: Event) -> Result<(), ()> {
        event.owner = self.window as usize;
        self.gate.enter();
        let view = unsafe { self.bridge.request(&event) };
        let changed = self.gate.leave();
        let view = view?;
        if changed {
            self.dpi = unsafe { GetDpiForWindow(self.window) };
            unsafe {
                self.update_font()?;
            }
            // A modal Choose/Uninstall dialog observed a display change. Read
            // current OS geometry, then ask Go to recompute it; never acknowledge
            // the pending operation using the stale pre-dialog view.
            return unsafe { self.fit(None) };
        }
        if view.close {
            unsafe { DestroyWindow(self.window) };
            return Ok(());
        }
        let pending = view.pending;
        if self.revision != Some(view.revision) {
            unsafe { self.render(&view)? };
            self.revision = Some(view.revision);
        }
        // This callback is made only after every operation-page control was
        // created/placed successfully, with the completion timer already live.
        if pending && view.layout_ok {
            return unsafe {
                self.dispatch(Event {
                    code: PRESENTED,
                    ..Event::default()
                })
            };
        }
        Ok(())
    }

    unsafe fn resize(&mut self) -> Result<(), ()> {
        let mut area: RECT = unsafe { std::mem::zeroed() };
        if unsafe { GetClientRect(self.window, &mut area) } == 0 {
            return Err(());
        }
        unsafe {
            self.dispatch(Event {
                code: RESIZE,
                width: area.right - area.left,
                height: area.bottom - area.top,
                dpi: self.dpi,
                ..Event::default()
            })
        }
    }

    unsafe fn update_font(&mut self) -> Result<(), ()> {
        let height = font_height(self.dpi).ok_or(())?;
        let font = unsafe {
            CreateFontW(
                height,
                0,
                0,
                0,
                400,
                0,
                0,
                0,
                DEFAULT_CHARSET as u32,
                OUT_DEFAULT_PRECIS as u32,
                CLIP_DEFAULT_PRECIS as u32,
                CLEARTYPE_QUALITY as u32,
                DEFAULT_PITCH as u32,
                wide("Segoe UI").as_ptr(),
            )
        };
        if font.is_null() {
            return Err(());
        }
        for control in self.controls.values() {
            unsafe { SendMessageW(control.window, WM_SETFONT, font as usize, 1) };
        }
        if !self.font.is_null() {
            unsafe { DeleteObject(self.font) };
        }
        self.font = font;
        Ok(())
    }

    unsafe fn render(&mut self, view: &View) -> Result<(), ()> {
        // Keep the last controls and the window's Close action alive while an
        // unavailable geometry stops active work. An empty layout is not an
        // invitation to destroy the view or detach its host operation.
        if !view.layout_ok {
            for (id, c) in &self.controls {
                unsafe { EnableWindow(c.window, i32::from(*id == 2)) };
            }
            return Ok(());
        }
        let page_changed = view
            .controls
            .iter()
            .any(|c| matches!(c.id, 204..=206) && !self.controls.contains_key(&c.id));
        let wanted: std::collections::BTreeSet<u32> = view.controls.iter().map(|c| c.id).collect();
        self.controls.retain(|id, c| {
            if wanted.contains(id) {
                true
            } else {
                unsafe { DestroyWindow(c.window) };
                false
            }
        });
        for spec in &view.controls {
            if let Some(existing) = self.controls.get(&spec.id)
                && existing.kind != spec.kind
            {
                return Err(());
            }
            if !self.controls.contains_key(&spec.id) {
                let (class, extra) = match spec.kind.as_str() {
                    "label" => ("STATIC", 0),
                    "edit" => (
                        "EDIT",
                        ES_MULTILINE as u32
                            | ES_READONLY as u32
                            | ES_AUTOVSCROLL as u32
                            | WS_VSCROLL
                            | WS_BORDER
                            | WS_TABSTOP,
                    ),
                    "check" => (
                        "BUTTON",
                        BS_AUTOCHECKBOX as u32 | BS_MULTILINE as u32 | WS_TABSTOP,
                    ),
                    "button" => (
                        "BUTTON",
                        WS_TABSTOP
                            | if spec.id == 1 {
                                BS_DEFPUSHBUTTON as u32
                            } else {
                                0
                            },
                    ),
                    _ => return Err(()),
                };
                let window = unsafe {
                    CreateWindowExW(
                        0,
                        wide(class).as_ptr(),
                        wide(&spec.text).as_ptr(),
                        WS_CHILD | WS_VISIBLE | extra,
                        0,
                        0,
                        1,
                        1,
                        self.window,
                        spec.id as usize as *mut _,
                        self.instance,
                        null_mut(),
                    )
                };
                if window.is_null() {
                    return Err(());
                }
                unsafe { SendMessageW(window, WM_SETFONT, self.font as usize, 1) };
                self.controls.insert(
                    spec.id,
                    NativeControl {
                        window,
                        kind: spec.kind.clone(),
                        text: spec.text.clone(),
                    },
                );
            }
            let native = self.controls.get_mut(&spec.id).ok_or(())?;
            if native.text != spec.text {
                if unsafe { SetWindowTextW(native.window, wide(&spec.text).as_ptr()) } == 0 {
                    return Err(());
                }
                native.text.clone_from(&spec.text);
            }
            unsafe {
                EnableWindow(native.window, i32::from(spec.enabled));
                if spec.kind == "check" {
                    SendMessageW(native.window, BM_SETCHECK, usize::from(spec.checked), 0);
                }
                let b = &spec.r#box;
                if MoveWindow(native.window, b.x, b.y, b.width, b.height, 1) == 0 {
                    return Err(());
                }
            }
        }
        if page_changed {
            let focus = if self.controls.contains_key(&205) {
                2
            } else if self.controls.contains_key(&204) {
                204
            } else {
                102
            };
            if let Some(control) = self.controls.get(&focus) {
                unsafe { SetFocus(control.window) };
            }
        }
        Ok(())
    }

    unsafe fn fit(&mut self, desired: Option<RECT>) -> Result<(), ()> {
        unsafe { self.place(desired, false) }
    }

    unsafe fn place(&mut self, desired: Option<RECT>, initial: bool) -> Result<(), ()> {
        let monitor = match desired.as_ref() {
            Some(rect) => unsafe { MonitorFromRect(rect, MONITOR_DEFAULTTONEAREST) },
            None => unsafe { MonitorFromWindow(self.window, MONITOR_DEFAULTTONEAREST) },
        };
        let mut info: MONITORINFO = unsafe { std::mem::zeroed() };
        info.cbSize = size_of::<MONITORINFO>() as u32;
        if monitor.is_null() || unsafe { GetMonitorInfoW(monitor, &mut info) } == 0 {
            return Err(());
        }
        let to_frame = |r: RECT| -> Result<Frame, ()> {
            Ok(Frame {
                x: r.left,
                y: r.top,
                width: r.right.checked_sub(r.left).ok_or(())?,
                height: r.bottom.checked_sub(r.top).ok_or(())?,
            })
        };
        let work = to_frame(info.rcWork)?;
        let mut frame: RECT = unsafe { std::mem::zeroed() };
        if unsafe { AdjustWindowRectExForDpi(&mut frame, STYLE, 0, 0, self.dpi) } == 0 {
            return Err(());
        }
        let frame_width = frame.right.checked_sub(frame.left).ok_or(())?;
        let frame_height = frame.bottom.checked_sub(frame.top).ok_or(())?;
        let placement = if initial {
            initial_frame(work, self.dpi, frame_width, frame_height)
        } else {
            let current = match desired {
                Some(rect) => rect,
                None => {
                    let mut rect = unsafe { std::mem::zeroed() };
                    if unsafe { GetWindowRect(self.window, &mut rect) } == 0 {
                        return Err(());
                    }
                    rect
                }
            };
            clamp_frame(
                to_frame(current)?,
                work,
                self.dpi,
                frame_width,
                frame_height,
            )
        }
        .ok_or(())?;
        if unsafe {
            MoveWindow(
                self.window,
                placement.x,
                placement.y,
                placement.width,
                placement.height,
                1,
            )
        } == 0
        {
            return Err(());
        }
        unsafe { self.resize() }
    }
}

unsafe extern "system" fn procedure(window: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // Never unwind through user32's non-unwinding native callback.
    match std::panic::catch_unwind(|| unsafe { procedure_inner(window, message, wp, lp) }) {
        Ok(result) => result,
        Err(_) => {
            unsafe { PostQuitMessage(1) };
            0
        }
    }
}

unsafe fn procedure_inner(window: HWND, message: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let pointer = unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *const WindowData;
    // DestroyWindow sends WM_DESTROY synchronously while dispatch still owns
    // the RefCell borrow. Termination must not depend on borrowing it again.
    if message == WM_DESTROY && !pointer.is_null() {
        unsafe { PostQuitMessage(0) };
        return 0;
    }
    if !pointer.is_null() {
        // Native modal dialogs and control updates can reenter this procedure.
        // A failed borrow ignores nested actions rather than aliasing &mut State
        // or calling the host twice. Paint/default messages remain functional.
        let data = unsafe { &*pointer };
        if let Ok(mut state) = data.state.try_borrow_mut() {
            let result = match message {
                WM_COMMAND if wp >> 16 == BN_CLICKED as usize => {
                    let id = (wp & 0xffff) as u32;
                    if let Some(control) = state.controls.get(&id) {
                        if unsafe { IsWindowEnabled(control.window) } == 0 {
                            return 0;
                        }
                        let checked = if control.kind == "check" {
                            u32::from(
                                unsafe { SendMessageW(control.window, BM_GETCHECK, 0, 0) } == 1,
                            )
                        } else {
                            0
                        };
                        unsafe {
                            state.dispatch(Event {
                                code: id,
                                value: checked,
                                ..Event::default()
                            })
                        }
                    } else {
                        Ok(())
                    }
                }
                WM_TIMER if wp == TIMER => unsafe {
                    state.dispatch(Event {
                        code: POLL,
                        ..Event::default()
                    })
                },
                WM_CLOSE => unsafe {
                    state.dispatch(Event {
                        code: CLOSE,
                        ..Event::default()
                    })
                },
                WM_QUERYENDSESSION => {
                    let _ = unsafe {
                        state.dispatch(Event {
                            code: CLOSE,
                            ..Event::default()
                        })
                    };
                    // Permit shutdown only if the host already allowed close.
                    // Otherwise cancellation keeps the pump/console lifetime.
                    return isize::from(unsafe { IsWindow(window) } == 0);
                }
                WM_SIZE if wp != SIZE_MINIMIZED as usize => unsafe { state.resize() },
                WM_GETMINMAXINFO if lp != 0 => {
                    let mut area = RECT {
                        left: 0,
                        top: 0,
                        right: (600 * state.dpi as i32 + 95) / 96,
                        bottom: (440 * state.dpi as i32 + 95) / 96,
                    };
                    if unsafe { AdjustWindowRectExForDpi(&mut area, STYLE, 0, 0, state.dpi) } == 0 {
                        Err(())
                    } else {
                        let sizes = unsafe { &mut *(lp as *mut MINMAXINFO) };
                        sizes.ptMinTrackSize.x = area.right - area.left;
                        sizes.ptMinTrackSize.y = area.bottom - area.top;
                        Ok(())
                    }
                }
                WM_DPICHANGED => {
                    state.dpi = (wp & 0xffff) as u32;
                    let desired = if lp == 0 {
                        None
                    } else {
                        Some(unsafe { *(lp as *const RECT) })
                    };
                    unsafe { state.update_font().and_then(|()| state.fit(desired)) }
                }
                WM_DISPLAYCHANGE | WM_SETTINGCHANGE => unsafe { state.fit(None) },
                _ => return unsafe { DefWindowProcW(window, message, wp, lp) },
            };
            if result.is_err() {
                state.failed = true;
                // Run returns finite failure; Go then cancels and joins before
                // releasing its callback handle. No child process is detached.
                unsafe { PostQuitMessage(1) };
            }
            return 0;
        }
        if matches!(
            message,
            WM_SIZE | WM_DPICHANGED | WM_DISPLAYCHANGE | WM_SETTINGCHANGE
        ) {
            data.gate.geometry();
        }
        if matches!(
            message,
            WM_COMMAND
                | WM_CLOSE
                | WM_QUERYENDSESSION
                | WM_SIZE
                | WM_TIMER
                | WM_DPICHANGED
                | WM_DISPLAYCHANGE
                | WM_SETTINGCHANGE
        ) {
            return 0;
        }
    }
    unsafe { DefWindowProcW(window, message, wp, lp) }
}

// All Win32 windows, controls, mutable UI state and callback invocations remain
// on this calling thread. The host locks it and owns every worker's lifetime.
pub unsafe fn run(handle: usize, callback: Callback) -> Result<(), ()> {
    let previous =
        unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    if previous.is_null() {
        return Err(());
    }
    struct DpiGuard(DPI_AWARENESS_CONTEXT);
    impl Drop for DpiGuard {
        fn drop(&mut self) {
            unsafe { SetThreadDpiAwarenessContext(self.0) };
        }
    }
    let _restore = DpiGuard(previous);
    unsafe { run_window(handle, callback) }
}

struct WindowGuard {
    window: HWND,
    instance: *mut std::ffi::c_void,
    class_name: Vec<u16>,
    state: *const WindowData,
}
impl Drop for WindowGuard {
    fn drop(&mut self) {
        unsafe {
            KillTimer(self.window, TIMER);
            SetWindowLongPtrW(self.window, GWLP_USERDATA, 0);
            DestroyWindow(self.window);
            if let Ok(state) = (&*self.state).state.try_borrow()
                && !state.font.is_null()
            {
                DeleteObject(state.font);
            }
            UnregisterClassW(self.class_name.as_ptr(), self.instance);
        }
    }
}

unsafe fn run_window(handle: usize, callback: Callback) -> Result<(), ()> {
    let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
    if instance.is_null() {
        return Err(());
    }
    let class_name = wide("TraceboltRustFreshSetupWizard");
    let class = WNDCLASSEXW {
        cbSize: size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(procedure),
        hInstance: instance,
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hbrBackground: (COLOR_BTNFACE + 1) as usize as *mut _,
        lpszClassName: class_name.as_ptr(),
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassExW(&class) } == 0 {
        return Err(());
    }
    let window = unsafe {
        CreateWindowExW(
            0,
            class_name.as_ptr(),
            wide("Tracebolt Setup — experimental Rust frontend").as_ptr(),
            STYLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            860,
            740,
            null_mut(),
            null_mut(),
            instance,
            null_mut(),
        )
    };
    if window.is_null() {
        unsafe { UnregisterClassW(class_name.as_ptr(), instance) };
        return Err(());
    }
    let gate = Rc::new(ReentryGate::default());
    let state = Box::new(WindowData {
        state: RefCell::new(State {
            bridge: Bridge::new(handle, callback),
            gate: gate.clone(),
            window,
            instance,
            controls: BTreeMap::new(),
            revision: None,
            font: null_mut(),
            dpi: unsafe { GetDpiForWindow(window) },
            failed: false,
        }),
        gate,
    });
    unsafe {
        SetWindowLongPtrW(
            window,
            GWLP_USERDATA,
            (&*state as *const WindowData) as isize,
        )
    };
    // Declared after State so cleanup removes userdata/windows before State is
    // dropped, including an unwind caught at the outer C ABI boundary.
    let _cleanup = WindowGuard {
        window,
        instance,
        class_name,
        state: &*state,
    };
    (|| -> Result<(), ()> {
        // Before any rendered view can acknowledge a prepared operation.
        if unsafe { SetTimer(window, TIMER, 250, None) } == 0 {
            return Err(());
        }
        {
            let mut s = state.state.borrow_mut();
            unsafe {
                s.update_font()?;
                s.place(None, true)?;
            }
        }
        unsafe {
            ShowWindow(window, SW_SHOW);
            UpdateWindow(window);
        }
        let mut message: MSG = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if result == -1 {
                return Err(());
            }
            if result == 0 {
                if message.wParam != 0 {
                    return Err(());
                }
                break;
            }
            if unsafe { IsDialogMessageW(window, &message) } == 0 {
                unsafe {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        }
        if state.state.borrow().failed {
            Err(())
        } else {
            Ok(())
        }
    })()
}
