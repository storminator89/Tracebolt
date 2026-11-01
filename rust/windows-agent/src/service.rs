use crate::{
    native,
    runtime::Runtime,
    service_diagnostics::{Diagnostics, Stage},
    service_lifecycle::{Lifecycle, Phase},
};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

pub const NAME: &str = "TraceboltRustAgent";
static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
static HEALTH_ENABLED: OnceLock<bool> = OnceLock::new();
define_windows_service!(ffi_main, service_main);

#[derive(Default)]
struct Reporter {
    lifecycle: Mutex<Lifecycle>,
    handle: OnceLock<ServiceStatusHandle>,
}
impl Reporter {
    fn stopping(&self) -> bool {
        self.lifecycle.lock().map_or(true, |s| s.stopping())
    }

    fn report(&self, phase: Phase, code: u32) -> bool {
        let Ok(mut lifecycle) = self.lifecycle.lock() else {
            return false;
        };
        if !lifecycle.transition(phase) {
            return false;
        }
        // Hold the same lock through SetServiceStatus. Otherwise a concurrent
        // startup could publish Running after the callback published StopPending.
        let state = match phase {
            Phase::StartPending => ServiceState::StartPending,
            Phase::Running => ServiceState::Running,
            Phase::StopPending => ServiceState::StopPending,
            Phase::Stopped => ServiceState::Stopped,
        };
        let pending = matches!(phase, Phase::StartPending | Phase::StopPending);
        self.handle.get().is_some_and(|handle| {
            handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: state,
                    controls_accepted: if phase == Phase::Running {
                        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
                    } else {
                        ServiceControlAccept::empty()
                    },
                    exit_code: ServiceExitCode::Win32(code),
                    checkpoint: u32::from(pending),
                    wait_hint: if pending {
                        Duration::from_secs(30)
                    } else {
                        Duration::ZERO
                    },
                    process_id: None,
                })
                .is_ok()
        })
    }
}

pub fn dispatch(directory: PathBuf) -> windows_service::Result<()> {
    DIRECTORY.get_or_init(|| directory);
    HEALTH_ENABLED.get_or_init(|| true);
    service_dispatcher::start(NAME, ffi_main)
}

pub fn dispatch_without_health(directory: PathBuf) -> windows_service::Result<()> {
    HEALTH_ENABLED.get_or_init(|| false);
    dispatch(directory)
}

fn service_main(_: Vec<OsString>) {
    let (send, receive) = mpsc::channel();
    let reporter = Arc::new(Reporter::default());
    let control_reporter = reporter.clone();
    let Ok(handle) = service_control_handler::register(NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            // Notify SCM immediately, even while a bounded request is finishing.
            // The worker observes this terminal phase before starting more work.
            control_reporter.report(Phase::StopPending, 0);
            let _ = send.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let _ = reporter.handle.set(handle);
    if !reporter.report(Phase::StartPending, 0) {
        reporter.report(Phase::Stopped, 13);
        return;
    }
    let mut diagnostics = Diagnostics::new(*HEALTH_ENABLED.get().unwrap_or(&true));
    // SCM arguments contain only the fixed protected configuration directory.
    let result = DIRECTORY
        .get()
        .ok_or_else(|| anyhow::anyhow!("missing data directory"))
        .and_then(|directory| {
            if *HEALTH_ENABLED.get().unwrap_or(&true) {
                Runtime::open(directory)
            } else {
                Runtime::open_without_health(directory)
            }
        });
    let mut sender = match result {
        Ok(sender) => sender,
        Err(error) => {
            let code = crate::health::classify(&error);
            diagnostics.record(Stage::StartupFailure, code);
            eprintln!("Tracebolt startup: {}. {}", code, code.next_action());
            reporter.report(Phase::Stopped, 13);
            return;
        }
    };
    if !reporter.report(Phase::Running, 0) {
        reporter.report(Phase::Stopped, if reporter.stopping() { 0 } else { 13 });
        return;
    }
    loop {
        if reporter.stopping() || receive.try_recv().is_ok() {
            break;
        }
        // Errors never log payloads, private keys, server bodies or identities.
        // Both success and failure wait, so a disconnected endpoint cannot spin.
        let outcome = sender.cycle_until_stopped(native::collect, || reporter.stopping());
        let unavailable = sender.health_requested() && !sender.health_available();
        let code = if unavailable {
            crate::health::Code::HealthUnavailable
        } else {
            sender.health_code()
        };
        // Record finite transitions including pending and recovery. This never
        // waits for Event Log, and never claims SCM Running is acceptance.
        if diagnostics.record_cycle(code, reporter.stopping(), &outcome)
            && (outcome.is_err() || unavailable)
        {
            eprintln!("Tracebolt diagnostic: {}. {}", code, code.next_action());
        }
        if !matches!(
            receive.recv_timeout(sender.interval()),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            break;
        }
    }
    reporter.report(Phase::StopPending, 0);
    reporter.report(Phase::Stopped, 0);
}
