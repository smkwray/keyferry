use keyferry_layouts::{ClickButton, InputGesture, KeyboardReport, MouseDelta};
use std::{collections::BTreeSet, fmt};

pub const NEUTRAL_KEYBOARD: u8 = 0x01;
pub const NEUTRAL_MOUSE: u8 = 0x02;
const NEUTRAL_BOTH: u8 = NEUTRAL_KEYBOARD | NEUTRAL_MOUSE;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputEffect {
    Keyboard(KeyboardReport),
    MouseMove {
        logical_token: u64,
        delta: MouseDelta,
    },
    MouseButtons(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputTransfer {
    pub transfer_token: u64,
    pub attachment_generation: u64,
    pub effect: InputEffect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputOutcome {
    Emitted,
    Aborted,
    Rejected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputSimulationError {
    Busy,
    MovementReplay,
    HeldStateConflict,
    StaleCompletion,
    CompletionMismatch,
    InvalidButtonBitmap,
}

impl fmt::Display for InputSimulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "input.busy",
            Self::MovementReplay => "input.movement_replay",
            Self::HeldStateConflict => "input.held_state_conflict",
            Self::StaleCompletion => "input.stale_completion",
            Self::CompletionMismatch => "input.completion_mismatch",
            Self::InvalidButtonBitmap => "input.invalid_button_bitmap",
        })
    }
}

impl std::error::Error for InputSimulationError {}

#[derive(Clone, Debug)]
pub struct MixedInputSimulator {
    attachment_generation: u64,
    next_transfer_token: u64,
    pending: Option<InputTransfer>,
    keyboard: KeyboardReport,
    mouse_buttons: u8,
    consumed_movements: BTreeSet<u64>,
    possible_effect: bool,
    neutral_mask: u8,
}

impl MixedInputSimulator {
    #[must_use]
    pub fn new(attachment_generation: u64) -> Self {
        Self {
            attachment_generation,
            next_transfer_token: 1,
            pending: None,
            keyboard: KeyboardReport::RELEASED,
            mouse_buttons: 0,
            consumed_movements: BTreeSet::new(),
            possible_effect: false,
            neutral_mask: 0,
        }
    }

    pub fn submit(&mut self, effect: InputEffect) -> Result<InputTransfer, InputSimulationError> {
        if self.pending.is_some() {
            return Err(InputSimulationError::Busy);
        }
        match effect {
            InputEffect::Keyboard(report) => {
                if !report.is_released() && self.mouse_buttons != 0 {
                    return Err(InputSimulationError::HeldStateConflict);
                }
                if !report.is_released() {
                    self.mark_possible_effect();
                }
            }
            InputEffect::MouseMove {
                logical_token,
                delta,
            } => {
                if !self.keyboard.is_released() || self.mouse_buttons != 0 {
                    return Err(InputSimulationError::HeldStateConflict);
                }
                if delta.dx == 0 && delta.dy == 0 {
                    return Err(InputSimulationError::CompletionMismatch);
                }
                if !self.consumed_movements.insert(logical_token) {
                    return Err(InputSimulationError::MovementReplay);
                }
                // Acceptance is the possible-effect boundary. The token is consumed here,
                // independent of whether a completion callback or result is later observed.
                self.mark_possible_effect();
            }
            InputEffect::MouseButtons(buttons) => {
                if buttons & !0x03 != 0 {
                    return Err(InputSimulationError::InvalidButtonBitmap);
                }
                if buttons != 0 && !self.keyboard.is_released() {
                    return Err(InputSimulationError::HeldStateConflict);
                }
                if buttons != 0 {
                    self.mark_possible_effect();
                }
            }
        }

        let transfer = InputTransfer {
            transfer_token: self.next_transfer_token,
            attachment_generation: self.attachment_generation,
            effect,
        };
        self.next_transfer_token = self.next_transfer_token.wrapping_add(1).max(1);
        self.pending = Some(transfer);
        Ok(transfer)
    }

    pub fn complete(&mut self, transfer: InputTransfer) -> Result<(), InputSimulationError> {
        if transfer.attachment_generation != self.attachment_generation {
            return Err(InputSimulationError::StaleCompletion);
        }
        if self.pending != Some(transfer) {
            return Err(InputSimulationError::CompletionMismatch);
        }
        match transfer.effect {
            InputEffect::Keyboard(report) => {
                self.keyboard = report;
                if report.is_released() && self.possible_effect {
                    self.neutral_mask |= NEUTRAL_KEYBOARD;
                }
            }
            InputEffect::MouseMove { .. } => {}
            InputEffect::MouseButtons(buttons) => {
                self.mouse_buttons = buttons;
                if buttons == 0 && self.possible_effect {
                    self.neutral_mask |= NEUTRAL_MOUSE;
                }
            }
        }
        self.pending = None;
        Ok(())
    }

    pub fn reattach(&mut self, attachment_generation: u64) {
        self.attachment_generation = attachment_generation;
        self.pending = None;
        self.keyboard = KeyboardReport::RELEASED;
        self.mouse_buttons = 0;
        // A zero inferred from reattachment cannot prove the old command neutral.
        self.neutral_mask = 0;
    }

    #[must_use]
    pub const fn neutral_mask(&self) -> u8 {
        self.neutral_mask
    }

    #[must_use]
    pub const fn possible_effect(&self) -> bool {
        self.possible_effect
    }

    #[must_use]
    pub const fn terminal_outcome(&self, completed_program: bool, cancelled: bool) -> InputOutcome {
        if !self.possible_effect {
            return InputOutcome::Rejected;
        }
        if self.neutral_mask != NEUTRAL_BOTH {
            return InputOutcome::Unknown;
        }
        if completed_program && !cancelled {
            InputOutcome::Emitted
        } else {
            InputOutcome::Aborted
        }
    }

    fn mark_possible_effect(&mut self) {
        self.possible_effect = true;
        // Any later possible effect invalidates earlier terminal-neutral evidence.
        self.neutral_mask = 0;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputExecutionResult {
    pub transfers: Vec<InputTransfer>,
    pub elapsed_ms: u64,
    pub dx_counts: i64,
    pub dy_counts: i64,
    pub outcome: InputOutcome,
    pub neutral_mask: u8,
}

pub fn execute_input_gestures(
    gestures: &[InputGesture],
    attachment_generation: u64,
) -> Result<InputExecutionResult, InputSimulationError> {
    let mut simulator = MixedInputSimulator::new(attachment_generation);
    let mut transfers = Vec::new();
    let mut elapsed_ms = 0_u64;
    let mut dx_counts = 0_i64;
    let mut dy_counts = 0_i64;
    let mut logical_token = 1_u64;

    let submit_and_complete = |simulator: &mut MixedInputSimulator,
                               transfers: &mut Vec<InputTransfer>,
                               effect: InputEffect|
     -> Result<(), InputSimulationError> {
        let transfer = simulator.submit(effect)?;
        simulator.complete(transfer)?;
        transfers.push(transfer);
        Ok(())
    };

    for gesture in gestures {
        match gesture {
            InputGesture::Keyboard { report, timing } => {
                submit_and_complete(
                    &mut simulator,
                    &mut transfers,
                    InputEffect::Keyboard(*report),
                )?;
                elapsed_ms += u64::from(timing.key_down_ms);
                submit_and_complete(
                    &mut simulator,
                    &mut transfers,
                    InputEffect::Keyboard(KeyboardReport::RELEASED),
                )?;
                elapsed_ms += u64::from(timing.release_gap_ms);
            }
            InputGesture::OrderedChord { reports, timing } => {
                for (index, report) in reports.iter().enumerate() {
                    submit_and_complete(
                        &mut simulator,
                        &mut transfers,
                        InputEffect::Keyboard(*report),
                    )?;
                    elapsed_ms += if index + 1 == reports.len() {
                        u64::from(timing.key_down_ms)
                    } else {
                        u64::from(keyferry_layouts::ORDERED_PRESS_MS)
                    };
                }
                for report in reports[..reports.len() - 1].iter().rev() {
                    submit_and_complete(
                        &mut simulator,
                        &mut transfers,
                        InputEffect::Keyboard(*report),
                    )?;
                    elapsed_ms += u64::from(keyferry_layouts::ORDERED_RELEASE_MS);
                }
                submit_and_complete(
                    &mut simulator,
                    &mut transfers,
                    InputEffect::Keyboard(KeyboardReport::RELEASED),
                )?;
                elapsed_ms += u64::from(timing.release_gap_ms);
            }
            InputGesture::Wait { ms } => elapsed_ms += u64::from(*ms),
            InputGesture::MoveRelative { deltas, .. } => {
                for delta in deltas {
                    submit_and_complete(
                        &mut simulator,
                        &mut transfers,
                        InputEffect::MouseMove {
                            logical_token,
                            delta: *delta,
                        },
                    )?;
                    logical_token += 1;
                    dx_counts += i64::from(delta.dx);
                    dy_counts += i64::from(delta.dy);
                    elapsed_ms += 10;
                }
            }
            InputGesture::Click {
                button,
                hold_ms,
                release_gap_ms,
            } => {
                let bit = match button {
                    ClickButton::Button1 => 0x01,
                    ClickButton::Button2 => 0x02,
                };
                submit_and_complete(
                    &mut simulator,
                    &mut transfers,
                    InputEffect::MouseButtons(bit),
                )?;
                elapsed_ms += u64::from(*hold_ms);
                submit_and_complete(&mut simulator, &mut transfers, InputEffect::MouseButtons(0))?;
                elapsed_ms += u64::from(*release_gap_ms);
            }
        }
    }

    submit_and_complete(
        &mut simulator,
        &mut transfers,
        InputEffect::Keyboard(KeyboardReport::RELEASED),
    )?;
    submit_and_complete(&mut simulator, &mut transfers, InputEffect::MouseButtons(0))?;

    Ok(InputExecutionResult {
        transfers,
        elapsed_ms,
        dx_counts,
        dy_counts,
        outcome: simulator.terminal_outcome(true, false),
        neutral_mask: simulator.neutral_mask(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyferry_layouts::{
        compile_input_sequence, ClickButton, InputAction, InputArmPolicy, InputSequenceV1,
        TypingTiming, INPUT_SEQUENCE_SCHEMA_V1,
    };

    fn complete(simulator: &mut MixedInputSimulator, effect: InputEffect) -> InputTransfer {
        let transfer = simulator.submit(effect).unwrap();
        simulator.complete(transfer).unwrap();
        transfer
    }

    #[test]
    fn movement_is_consumed_at_acceptance_and_never_replayed() {
        let mut simulator = MixedInputSimulator::new(7);
        let effect = InputEffect::MouseMove {
            logical_token: 19,
            delta: MouseDelta { dx: 12, dy: -3 },
        };
        let accepted = simulator.submit(effect).unwrap();
        assert!(simulator.possible_effect());
        assert_eq!(simulator.submit(effect), Err(InputSimulationError::Busy));
        simulator.reattach(8);
        assert_eq!(
            simulator.complete(accepted),
            Err(InputSimulationError::StaleCompletion)
        );
        assert_eq!(
            simulator.submit(effect),
            Err(InputSimulationError::MovementReplay)
        );
        assert_eq!(
            simulator.terminal_outcome(false, true),
            InputOutcome::Unknown
        );
    }

    #[test]
    fn one_writer_forbids_movement_during_keyboard_or_button_hold() {
        let mut simulator = MixedInputSimulator::new(1);
        complete(
            &mut simulator,
            InputEffect::Keyboard(KeyboardReport::single(0, 0x04)),
        );
        assert_eq!(
            simulator.submit(InputEffect::MouseMove {
                logical_token: 1,
                delta: MouseDelta { dx: 1, dy: 0 },
            }),
            Err(InputSimulationError::HeldStateConflict)
        );
        complete(
            &mut simulator,
            InputEffect::Keyboard(KeyboardReport::RELEASED),
        );
        complete(&mut simulator, InputEffect::MouseButtons(1));
        assert_eq!(
            simulator.submit(InputEffect::MouseMove {
                logical_token: 2,
                delta: MouseDelta { dx: 1, dy: 0 },
            }),
            Err(InputSimulationError::HeldStateConflict)
        );
    }

    #[test]
    fn terminal_result_needs_both_post_effect_neutral_completions() {
        let mut simulator = MixedInputSimulator::new(3);
        complete(&mut simulator, InputEffect::MouseButtons(1));
        complete(&mut simulator, InputEffect::MouseButtons(0));
        assert_eq!(simulator.neutral_mask(), NEUTRAL_MOUSE);
        assert_eq!(
            simulator.terminal_outcome(true, false),
            InputOutcome::Unknown
        );
        complete(
            &mut simulator,
            InputEffect::Keyboard(KeyboardReport::RELEASED),
        );
        assert_eq!(simulator.neutral_mask(), NEUTRAL_BOTH);
        assert_eq!(
            simulator.terminal_outcome(true, false),
            InputOutcome::Emitted
        );
        assert_eq!(
            simulator.terminal_outcome(false, true),
            InputOutcome::Aborted
        );
    }

    #[test]
    fn a_later_effect_invalidates_earlier_neutral_evidence() {
        let mut simulator = MixedInputSimulator::new(4);
        complete(&mut simulator, InputEffect::MouseButtons(1));
        complete(&mut simulator, InputEffect::MouseButtons(0));
        complete(
            &mut simulator,
            InputEffect::Keyboard(KeyboardReport::RELEASED),
        );
        assert_eq!(simulator.neutral_mask(), NEUTRAL_BOTH);
        complete(
            &mut simulator,
            InputEffect::MouseMove {
                logical_token: 1,
                delta: MouseDelta { dx: 1, dy: 0 },
            },
        );
        assert_eq!(simulator.neutral_mask(), 0);
        assert_eq!(
            simulator.terminal_outcome(true, false),
            InputOutcome::Unknown
        );
    }

    #[test]
    fn compiled_mixed_plan_preserves_order_totals_and_terminal_neutral() {
        let request = InputSequenceV1 {
            schema: INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: "01995fa0-0000-7000-8000-000000000001".to_owned(),
            keyboard_profile: Some("windows-us".to_owned()),
            arm: InputArmPolicy::CommandScoped,
            start_within_ms: 5000,
            keyboard_timing: None,
            actions: vec![
                InputAction::MoveRelative {
                    dx_counts: 240,
                    dy_counts: -40,
                },
                InputAction::Click {
                    button: ClickButton::Button1,
                    hold_ms: None,
                    release_gap_ms: None,
                },
                InputAction::Tap {
                    key: "ENTER".to_owned(),
                    timing: None,
                },
            ],
        };
        let compiled = compile_input_sequence(&request).unwrap();
        let result = execute_input_gestures(&compiled.gestures, 9).unwrap();
        assert_eq!((result.dx_counts, result.dy_counts), (240, -40));
        assert_eq!(result.elapsed_ms, 152);
        assert_eq!(result.outcome, InputOutcome::Emitted);
        assert_eq!(result.neutral_mask, NEUTRAL_BOTH);
        assert_eq!(
            result
                .transfers
                .iter()
                .map(|item| item.effect)
                .collect::<Vec<_>>(),
            vec![
                InputEffect::MouseMove {
                    logical_token: 1,
                    delta: MouseDelta { dx: 120, dy: -20 },
                },
                InputEffect::MouseMove {
                    logical_token: 2,
                    delta: MouseDelta { dx: 120, dy: -20 },
                },
                InputEffect::MouseButtons(1),
                InputEffect::MouseButtons(0),
                InputEffect::Keyboard(KeyboardReport::single(0, 0x28)),
                InputEffect::Keyboard(KeyboardReport::RELEASED),
                InputEffect::Keyboard(KeyboardReport::RELEASED),
                InputEffect::MouseButtons(0),
            ]
        );
    }

    #[test]
    fn ordered_chord_executes_each_edge_and_finishes_neutral() {
        let prefix = KeyboardReport::from_keys(0, &[0x39]).unwrap();
        let both = KeyboardReport::from_keys(0, &[0x39, 0x14]).unwrap();
        let result = execute_input_gestures(
            &[InputGesture::OrderedChord {
                reports: vec![prefix, both],
                timing: TypingTiming::DESKTOP_SAFE,
            }],
            1,
        )
        .unwrap();
        assert_eq!(result.outcome, InputOutcome::Emitted);
        assert_eq!(result.neutral_mask, NEUTRAL_BOTH);
        let keyboard: Vec<_> = result
            .transfers
            .iter()
            .filter_map(|transfer| match transfer.effect {
                InputEffect::Keyboard(report) => Some(report),
                _ => None,
            })
            .collect();
        assert_eq!(
            keyboard,
            vec![
                prefix,
                both,
                prefix,
                KeyboardReport::RELEASED,
                KeyboardReport::RELEASED
            ]
        );
    }
}
