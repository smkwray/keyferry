#![forbid(unsafe_code)]

mod input;

pub use input::{
    execute_input_gestures, InputEffect, InputExecutionResult, InputOutcome, InputSimulationError,
    InputTransfer, MixedInputSimulator, NEUTRAL_KEYBOARD, NEUTRAL_MOUSE,
};

use keyferry_layouts::{KeyboardReport, ReportStep};
use std::fmt;

pub const HELD_KEY_WATCHDOG_MS: u32 = 2_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationResult {
    pub reports: Vec<KeyboardReport>,
    pub elapsed_ms: u32,
    pub forced_release: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulationError {
    HeldKeyWatchdog { held_ms: u32 },
}

impl fmt::Display for SimulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldKeyWatchdog { held_ms } => {
                write!(f, "held-key watchdog exceeded after {held_ms} ms")
            }
        }
    }
}

impl std::error::Error for SimulationError {}

#[derive(Clone, Debug)]
pub struct SimulatedEndpoint {
    current: KeyboardReport,
    held_ms: u32,
    elapsed_ms: u32,
    reports: Vec<KeyboardReport>,
}

impl Default for SimulatedEndpoint {
    fn default() -> Self {
        Self {
            current: KeyboardReport::RELEASED,
            held_ms: 0,
            elapsed_ms: 0,
            reports: Vec::new(),
        }
    }
}

impl SimulatedEndpoint {
    pub fn execute(mut self, steps: &[ReportStep]) -> Result<SimulationResult, SimulationError> {
        for step in steps {
            match *step {
                ReportStep::Report(report) => {
                    self.current = report;
                    self.reports.push(report);
                    if report.is_released() {
                        self.held_ms = 0;
                    }
                }
                ReportStep::WaitMs(duration) => {
                    let duration = u32::from(duration);
                    self.elapsed_ms = self.elapsed_ms.saturating_add(duration);
                    if !self.current.is_released() {
                        self.held_ms = self.held_ms.saturating_add(duration);
                        if self.held_ms > HELD_KEY_WATCHDOG_MS {
                            let held_ms = self.held_ms;
                            self.force_release();
                            return Err(SimulationError::HeldKeyWatchdog { held_ms });
                        }
                    }
                }
            }
        }

        let forced_release = if self.current.is_released() {
            false
        } else {
            self.force_release();
            true
        };

        Ok(SimulationResult {
            reports: self.reports,
            elapsed_ms: self.elapsed_ms,
            forced_release,
        })
    }

    fn force_release(&mut self) {
        self.current = KeyboardReport::RELEASED;
        self.reports.push(KeyboardReport::RELEASED);
        self.held_ms = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_layouts::{plan_text_us, TypingTiming, MOD_LEFT_SHIFT};

    #[test]
    fn planned_text_finishes_released() {
        let steps = plan_text_us("hello", TypingTiming::DESKTOP_SAFE).unwrap();
        let result = SimulatedEndpoint::default().execute(&steps).unwrap();
        assert!(!result.forced_release);
        assert_eq!(result.reports.last(), Some(&KeyboardReport::RELEASED));
    }

    #[test]
    fn watchdog_forces_release() {
        let steps = [
            ReportStep::Report(KeyboardReport::single(0, 0x04)),
            ReportStep::WaitMs(2_001),
        ];
        assert!(matches!(
            SimulatedEndpoint::default().execute(&steps),
            Err(SimulationError::HeldKeyWatchdog { .. })
        ));
    }

    #[test]
    fn missing_final_release_is_added_by_simulator() {
        let steps = [ReportStep::Report(KeyboardReport::single(0, 0x04))];
        let result = SimulatedEndpoint::default().execute(&steps).unwrap();
        assert!(result.forced_release);
        assert_eq!(result.reports.last(), Some(&KeyboardReport::RELEASED));
    }

    #[test]
    fn any_prefix_of_a_plan_ends_released() {
        // Cancellation, disconnect, or fault after any step must never leave a
        // key held. Executing every prefix of a valid plan must end released.
        let samples = [
            "a",
            "Hello, World!",
            "The quick brown fox.",
            "x\ty\nz",
            "ALLCAPS",
            "123 (test)",
        ];
        for text in samples {
            let steps = plan_text_us(text, TypingTiming::DESKTOP_SAFE).unwrap();
            for cut in 0..=steps.len() {
                let result = SimulatedEndpoint::default()
                    .execute(&steps[..cut])
                    .expect("desktop-safe waits never trip the watchdog");
                assert_eq!(
                    result
                        .reports
                        .last()
                        .copied()
                        .unwrap_or(KeyboardReport::RELEASED),
                    KeyboardReport::RELEASED,
                    "prefix {cut} of {text:?} left a key held"
                );
            }
        }
    }

    #[test]
    fn cancellation_between_reports_releases_all() {
        // A shifted key held when the command is cancelled (remaining steps never
        // arrive) still ends with an explicit release.
        let steps = [
            ReportStep::Report(KeyboardReport::single(MOD_LEFT_SHIFT, 0x04)),
            ReportStep::WaitMs(12),
        ];
        let result = SimulatedEndpoint::default().execute(&steps).unwrap();
        assert!(result.forced_release);
        assert_eq!(result.reports.last(), Some(&KeyboardReport::RELEASED));
    }
}
