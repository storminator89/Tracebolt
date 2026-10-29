use crate::{native, runtime::Runtime};
use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{OnceLock, mpsc},
    time::Duration,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

pub const NAME: &str = "TraceboltRustAgent";
static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
define_windows_service!(ffi_main, service_main);

pub fn dispatch(directory: PathBuf) -> windows_service::Result<()> {
    DIRECTORY.get_or_init(|| directory);
    service_dispatcher::start(NAME, ffi_main)
}

fn service_main(_: Vec<OsString>) {
    let (send, receive) = mpsc::channel();
    let Ok(handle) = service_control_handler::register(NAME, move |event| match event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = send.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let status = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(20),
        process_id: None,
    };
    let _ = handle.set_service_status(status(ServiceState::StartPending, 0));
    // SCM arguments contain only the fixed protected configuration directory.
    let result = DIRECTORY
        .get()
        .ok_or_else(|| anyhow::anyhow!("missing data directory"))
        .and_then(|directory| Runtime::open(directory));
    let Ok(mut sender) = result else {
        let _ = handle.set_service_status(status(ServiceState::Stopped, 13));
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    loop {
        if receive.try_recv().is_ok() {
            break;
        }
        // Errors never log payloads, private keys, server bodies or identities.
        // Both success and failure wait, so a disconnected endpoint cannot spin.
        let _ = sender.cycle(native::collect);
        if !matches!(
            receive.recv_timeout(sender.interval()),
            Err(mpsc::RecvTimeoutError::Timeout)
        ) {
            break;
        }
    }
    let _ = handle.set_service_status(status(ServiceState::StopPending, 0));
    let _ = handle.set_service_status(status(ServiceState::Stopped, 0));
}
