//! Best-effort finite Windows service events. Event delivery never blocks a
//! collection/SCM worker and never changes enrollment, sender or health state.
use crate::health::Code;
use std::sync::mpsc::{SyncSender, TrySendError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    StartupFailure,
    Cycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Event {
    stage: Stage,
    code: Code,
}
impl Event {
    fn fields(self) -> [&'static str; 3] {
        [
            match self.stage {
                Stage::StartupFailure => "Tracebolt startup failure",
                Stage::Cycle => "Tracebolt diagnostic transition",
            },
            self.code.as_str(),
            self.code.next_action(),
        ]
    }
}

pub(crate) struct Diagnostics {
    previous: Option<Event>,
    sender: Option<SyncSender<Event>>,
}
impl Diagnostics {
    #[cfg(windows)]
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            previous: None,
            sender: if enabled { native::start() } else { None },
        }
    }

    /// A stop observed at cycle entry returns false without changing the
    /// retained diagnostic. Do not re-emit that old result as a new transition.
    /// A genuinely completed acceptance or failed attempt remains reportable
    /// even when stop arrived while that bounded phase was in progress.
    pub(crate) fn record_cycle(
        &mut self,
        code: Code,
        stopping: bool,
        outcome: &anyhow::Result<bool>,
    ) -> bool {
        if stopping && matches!(outcome, Ok(false)) {
            return false;
        }
        self.record(Stage::Cycle, code)
    }

    /// Returns whether the finite diagnostic changed, not whether Windows
    /// accepted it. A slow/full/failed sink never holds up the runtime or replays
    /// a backlog. Duplicate states are suppressed even after delivery failure.
    pub(crate) fn record(&mut self, stage: Stage, code: Code) -> bool {
        let event = Event { stage, code };
        if self.previous == Some(event) {
            return false;
        }
        self.previous = Some(event);
        if let Some(sender) = &self.sender {
            match sender.try_send(event) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => self.sender = None,
            }
        }
        true
    }
}

#[cfg(windows)]
mod native {
    use super::{Code, Event, Stage, SyncSender};
    use std::{ptr, sync::mpsc, thread};
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
        EVENTLOG_WARNING_TYPE, RegisterEventSourceW, ReportEventW,
    };

    pub(super) fn start() -> Option<SyncSender<Event>> {
        // At most one event in flight plus one queued, for this process. Never
        // join this best-effort worker during SCM stop: local Event Log RPC can
        // itself be unavailable or stalled. Process exit owns its final teardown.
        let (sender, receiver) = mpsc::sync_channel::<Event>(1);
        thread::Builder::new()
            .name("tracebolt-event-log".into())
            .spawn(move || {
                // RegisterEventSource opens a local handle; it does not install
                // a registry source/message DLL. Windows falls back to Application
                // when this source has not separately been registered. EventData
                // strings remain available; formatted descriptions may be absent.
                let source: Vec<u16> = "TraceboltRustAgent".encode_utf16().chain([0]).collect();
                // SAFETY: null selects the local computer; source is terminated
                // UTF-16 and remains live throughout this call.
                let handle = unsafe { RegisterEventSourceW(ptr::null(), source.as_ptr()) };
                if handle.is_null() {
                    eprintln!("Tracebolt Event Log unavailable; event delivery disabled.");
                    return;
                }
                for event in receiver {
                    let fields = event
                        .fields()
                        .map(|s| s.encode_utf16().chain([0]).collect::<Vec<u16>>());
                    let pointers = fields.each_ref().map(|s| s.as_ptr());
                    let kind = match (event.stage, event.code) {
                        (Stage::StartupFailure, _) => EVENTLOG_ERROR_TYPE,
                        (
                            _,
                            Code::Accepted
                            | Code::PendingApproval
                            | Code::RegistrationPending
                            | Code::AttemptInterrupted
                            | Code::NotObserved,
                        ) => EVENTLOG_INFORMATION_TYPE,
                        _ => EVENTLOG_WARNING_TYPE,
                    };
                    let id = match event.stage {
                        Stage::StartupFailure => 1001,
                        Stage::Cycle => 1002,
                    };
                    // SAFETY: handle is owned by this worker; each fixed,
                    // terminated field outlives the synchronous call. There is
                    // no user SID or raw binary payload and exactly three strings.
                    let written = unsafe {
                        ReportEventW(
                            handle,
                            kind,
                            0,
                            id,
                            ptr::null_mut(),
                            3,
                            0,
                            pointers.as_ptr(),
                            ptr::null(),
                        )
                    };
                    if written == 0 {
                        eprintln!("Tracebolt Event Log unavailable; event delivery disabled.");
                        break;
                    }
                }
                // SAFETY: this worker is the sole handle owner; no call is in flight.
                unsafe { DeregisterEventSource(handle) };
            })
            .ok()?;
        Some(sender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::{self, TryRecvError};

    #[test]
    fn repeated_states_are_suppressed_and_recovery_is_a_transition() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut diagnostics = Diagnostics {
            previous: None,
            sender: Some(sender),
        };
        for code in [
            Code::PendingApproval,
            Code::TransportTlsFailed,
            Code::Accepted,
        ] {
            assert!(diagnostics.record(Stage::Cycle, code));
            let event = receiver.try_recv().unwrap();
            assert_eq!(event.code, code);
            for _ in 0..100 {
                assert!(!diagnostics.record(Stage::Cycle, code));
            }
            assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
        }
    }

    #[test]
    fn stop_before_cycle_cannot_publish_retained_acceptance_as_a_new_event() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut diagnostics = Diagnostics {
            previous: None,
            sender: Some(sender),
        };
        // Runtime can return false at its entry guard without changing the
        // previous process's accepted code. SCM stopping is monotonic.
        assert!(!diagnostics.record_cycle(Code::Accepted, true, &Ok(false)));
        assert_eq!(diagnostics.previous, None);
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));

        // A normal pending phase remains visible, and a real completed receipt
        // or error is not discarded merely because stop arrived in flight.
        assert!(diagnostics.record_cycle(Code::PendingApproval, false, &Ok(false)));
        assert_eq!(receiver.try_recv().unwrap().code, Code::PendingApproval);
        assert!(diagnostics.record_cycle(Code::Accepted, true, &Ok(true)));
        assert_eq!(receiver.try_recv().unwrap().code, Code::Accepted);
        let error = Err(anyhow::anyhow!("private-error-sentinel"));
        assert!(diagnostics.record_cycle(Code::TransportTimeout, true, &error));
        assert_eq!(receiver.try_recv().unwrap().code, Code::TransportTimeout);
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
    }

    #[test]
    fn full_or_disconnected_sink_never_retries_or_replays_backlog() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let mut diagnostics = Diagnostics {
            previous: None,
            sender: Some(sender),
        };
        assert!(diagnostics.record(Stage::Cycle, Code::PendingApproval));
        for _ in 0..100 {
            assert!(diagnostics.record(Stage::Cycle, Code::TransportTimeout));
            assert!(diagnostics.record(Stage::Cycle, Code::Accepted));
        }
        assert_eq!(receiver.try_recv().unwrap().code, Code::PendingApproval);
        assert_eq!(receiver.try_recv(), Err(TryRecvError::Empty));
        assert!(!diagnostics.record(Stage::Cycle, Code::Accepted));
        drop(receiver);
        assert!(diagnostics.record(Stage::Cycle, Code::TransportTimeout));
        assert!(diagnostics.sender.is_none());
        assert!(!diagnostics.record(Stage::Cycle, Code::TransportTimeout));
    }

    #[test]
    fn opt_out_keeps_finite_transition_tracking_without_an_event_sink() {
        let mut diagnostics = Diagnostics {
            previous: None,
            sender: None,
        };
        assert!(diagnostics.record(Stage::StartupFailure, Code::StateCorrupt));
        assert!(!diagnostics.record(Stage::StartupFailure, Code::StateCorrupt));
        assert!(diagnostics.sender.is_none());
    }

    #[test]
    fn payload_is_only_fixed_allowlisted_fields_and_never_error_text() {
        let secret = "private-key token cookie raw-telemetry C:\\private\\identity";
        let raw = anyhow::anyhow!(secret);
        let event = Event {
            stage: Stage::StartupFailure,
            code: crate::health::classify(&raw),
        };
        assert_eq!(
            event.fields(),
            [
                "Tracebolt startup failure",
                "unclassified-failure",
                Code::UnclassifiedFailure.next_action()
            ]
        );
        assert!(!event.fields().join(" ").contains(secret));
        for code in [
            Code::StateCorrupt,
            Code::EnrollmentRevoked,
            Code::TransportTlsFailed,
            Code::PendingApproval,
            Code::Accepted,
            Code::HealthUnavailable,
        ] {
            let event = Event {
                stage: Stage::Cycle,
                code,
            };
            for field in event.fields() {
                assert!(!field.contains('\0'));
                assert!(!field.contains('%'));
                assert!(field.encode_utf16().count() < 1024);
            }
        }
    }
}
