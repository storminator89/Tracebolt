use crate::{
    config::{Config, EnrollmentMode},
    enrollment::Enrollment,
    health::{self, Code, Tracker},
    protocol::Sample,
    sender::Sender,
};
use anyhow::{Context, Result};
use std::{path::Path, time::Duration};

pub struct Runtime {
    enrollment: Option<Enrollment>,
    sender: Option<Sender>,
    report_interval: Duration,
    delay: Duration,
    failures: u32,
    last_code: Code,
    health: Option<Tracker>,
    health_requested: bool,
}

enum Outcome {
    Pending,
    Interrupted,
    Accepted(crate::protocol::AcceptedReceipt),
}

impl Runtime {
    pub fn open(directory: &Path) -> Result<Self> {
        Self::open_with_health(directory, true)
    }
    pub fn open_without_health(directory: &Path) -> Result<Self> {
        Self::open_with_health(directory, false)
    }
    fn open_with_health(directory: &Path, health_requested: bool) -> Result<Self> {
        let config = Config::load(directory).context(Code::ConfigurationInvalid)?;
        let mut health = if health_requested {
            Tracker::open_runtime(directory, &config).ok()
        } else {
            None
        };
        let started_at = chrono::Utc::now();
        let opened = if config.enrollment_mode == EnrollmentMode::Preprovided {
            Sender::open(directory, false).map(|sender| (None, Some(sender)))
        } else {
            Enrollment::open(directory, false, None).map(|enrollment| (Some(enrollment), None))
        };
        let (enrollment, sender) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                // Local-open failures with no narrower typed class mean
                // unavailable/invalid retained state, not a network diagnosis.
                let code = match health::classify(&error) {
                    Code::UnclassifiedFailure => Code::StateUnavailable,
                    code => code,
                };
                if let Some(tracker) = health.as_mut().filter(|_| {
                    error
                        .downcast_ref::<crate::state::LockUnavailable>()
                        .is_none()
                }) {
                    let _ = tracker.startup_failure(code, started_at);
                }
                return Err(error.context(code));
            }
        };
        Ok(Self {
            enrollment,
            sender,
            report_interval: Duration::from_secs(config.interval_seconds),
            delay: Duration::from_secs(config.interval_seconds),
            failures: 0,
            last_code: health
                .as_ref()
                .map_or(Code::NotObserved, Tracker::last_code),
            health,
            health_requested,
        })
    }
    pub fn interval(&self) -> Duration {
        self.delay
    }
    /// False means onboarding remains pending, not a delivered observation.
    pub fn cycle(&mut self, collect: impl FnOnce() -> Result<Sample>) -> Result<bool> {
        self.cycle_until_stopped(collect, || false)
    }
    /// Cooperative SCM stop at phase boundaries: skip a cycle if already stopped
    /// and do not append telemetry to enrollment after an observed stop. A phase
    /// already admitted (including collection plus send) finishes normally;
    /// no pending bytes/counters are reset or repaired.
    pub fn cycle_until_stopped(
        &mut self,
        collect: impl FnOnce() -> Result<Sample>,
        stopping: impl Fn() -> bool,
    ) -> Result<bool> {
        if stopping() {
            return Ok(false);
        }
        let at = chrono::Utc::now();
        if self.health.as_mut().is_some_and(|h| h.attempt(at).is_err()) {
            self.health = None;
        }
        let result = self.cycle_inner(collect, stopping);
        let now = chrono::Utc::now();
        let jitter = uuid::Uuid::new_v4().as_bytes()[0] % 31;
        self.last_code = match &result {
            Ok(Outcome::Accepted(_)) => Code::Accepted,
            Ok(Outcome::Interrupted) => Code::AttemptInterrupted,
            Ok(Outcome::Pending) => self
                .enrollment
                .as_ref()
                .and_then(|e| e.public_status().ok())
                .and_then(|s| s["phase"].as_str().map(str::to_owned))
                .map_or(Code::RegistrationPending, |phase| {
                    if phase == "waiting-for-manager-approval" {
                        Code::PendingApproval
                    } else {
                        Code::RegistrationPending
                    }
                }),
            Err(error) => {
                let code = health::classify(error);
                if code == Code::EnrollmentTerminated
                    && matches!(
                        self.last_code,
                        Code::EnrollmentRevoked | Code::EnrollmentExpired
                    )
                {
                    self.last_code
                } else {
                    code
                }
            }
        };
        if result.is_err() {
            self.failures = self.failures.saturating_add(1).min(16);
        } else {
            self.failures = 0;
        }
        let base = if self.sender.is_some() {
            self.report_interval
        } else {
            Duration::from_secs(30)
        };
        self.delay = if result.is_err() {
            health::retry_delay(base, self.failures, jitter)
        } else {
            base
        };
        let certificate = self.sender.as_ref().map(Sender::certificate_not_after);
        if self.health.as_mut().is_some_and(|h| {
            h.complete(
                self.last_code,
                match &result {
                    Ok(Outcome::Accepted(receipt)) => Some(receipt.clone()),
                    _ => None,
                },
                now,
                self.failures,
                self.delay,
                certificate,
            )
            .is_err()
        }) {
            self.health = None;
        }
        result.map(|outcome| matches!(outcome, Outcome::Accepted(_)))
    }
    pub fn health_code(&self) -> Code {
        self.last_code
    }
    pub fn health_requested(&self) -> bool {
        self.health_requested
    }
    pub fn health_available(&self) -> bool {
        self.health.is_some()
    }
    fn cycle_inner(
        &mut self,
        collect: impl FnOnce() -> Result<Sample>,
        stopping: impl Fn() -> bool,
    ) -> Result<Outcome> {
        if self.sender.is_none() {
            let enrollment = self.enrollment.as_mut().unwrap();
            if let Some(material) = enrollment.step(None)? {
                self.sender = Some(Sender::enrolled(&enrollment.state_directory(), material)?);
            } else {
                return Ok(if stopping() {
                    Outcome::Interrupted
                } else {
                    Outcome::Pending
                });
            }
        }
        if stopping() {
            return Ok(Outcome::Interrupted);
        }
        self.sender
            .as_mut()
            .unwrap()
            .report_receipt(collect)
            .map(Outcome::Accepted)
    }
}
