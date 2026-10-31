//! Serialized SCM transitions. Stop/shutdown is terminal for this process;
//! startup must not publish Running after a concurrent stop request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

#[derive(Default)]
pub(crate) struct Lifecycle {
    phase: Option<Phase>,
}

impl Lifecycle {
    pub(crate) fn transition(&mut self, next: Phase) -> bool {
        use Phase::*;
        let allowed = match next {
            StartPending => self.phase.is_none(),
            Running => self.phase == Some(StartPending),
            StopPending => !matches!(self.phase, Some(StopPending | Stopped)),
            Stopped => self.phase != Some(Stopped),
        };
        if allowed {
            self.phase = Some(next);
        }
        allowed
    }

    pub(crate) fn stopping(&self) -> bool {
        matches!(self.phase, Some(Phase::StopPending | Phase::Stopped))
    }
}

#[cfg(test)]
mod tests {
    use super::{Lifecycle, Phase::*};

    #[test]
    fn ordinary_start_stop_is_monotonic_and_idempotent() {
        let mut lifecycle = Lifecycle::default();
        assert!(!lifecycle.transition(Running));
        assert!(lifecycle.transition(StartPending));
        assert!(!lifecycle.transition(StartPending));
        assert!(lifecycle.transition(Running));
        assert!(!lifecycle.stopping());
        assert!(lifecycle.transition(StopPending));
        assert!(lifecycle.stopping());
        assert!(!lifecycle.transition(StopPending));
        assert!(lifecycle.transition(Stopped));
        assert!(!lifecycle.transition(Stopped));
        assert!(!lifecycle.transition(Running));
        assert!(!lifecycle.transition(StartPending));
        assert!(!lifecycle.transition(StopPending));
    }

    #[test]
    fn stop_during_startup_never_returns_to_running() {
        for started in [false, true] {
            let mut lifecycle = Lifecycle::default();
            if started {
                assert!(lifecycle.transition(StartPending));
            }
            assert!(lifecycle.transition(StopPending));
            assert!(lifecycle.stopping());
            assert!(!lifecycle.transition(StartPending));
            assert!(!lifecycle.transition(Running));
            assert!(lifecycle.transition(Stopped));
        }
    }

    #[test]
    fn failed_startup_can_finish_without_publishing_running() {
        let mut lifecycle = Lifecycle::default();
        assert!(lifecycle.transition(StartPending));
        assert!(lifecycle.transition(Stopped));
        assert!(lifecycle.stopping());
        assert!(!lifecycle.transition(Running));
    }
}
