use crate::{
    config::{Config, EnrollmentMode},
    enrollment::Enrollment,
    protocol::Sample,
    sender::Sender,
};
use anyhow::Result;
use std::{path::Path, time::Duration};

pub struct Runtime {
    enrollment: Option<Enrollment>,
    sender: Option<Sender>,
    interval: Duration,
}
impl Runtime {
    pub fn open(directory: &Path) -> Result<Self> {
        let config = Config::load(directory)?;
        let (enrollment, sender) = if config.enrollment_mode == EnrollmentMode::Preprovided {
            (None, Some(Sender::open(directory, false)?))
        } else {
            (Some(Enrollment::open(directory, false, None)?), None)
        };
        Ok(Self {
            enrollment,
            sender,
            interval: Duration::from_secs(config.interval_seconds),
        })
    }
    pub fn interval(&self) -> Duration {
        if self.sender.is_some() {
            self.interval
        } else {
            Duration::from_secs(30)
        }
    }
    /// False means onboarding remains pending, not a delivered observation.
    pub fn cycle(&mut self, collect: impl FnOnce() -> Result<Sample>) -> Result<bool> {
        if self.sender.is_none() {
            let enrollment = self.enrollment.as_mut().unwrap();
            if let Some(material) = enrollment.step(None)? {
                self.sender = Some(Sender::enrolled(&enrollment.state_directory(), material)?);
            } else {
                return Ok(false);
            }
        }
        self.sender.as_mut().unwrap().report(collect)?;
        Ok(true)
    }
}
