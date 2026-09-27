#![forbid(unsafe_code)]

pub mod text_stream;

use serde::{Deserialize, Serialize};
use std::fmt;

mod input_sequence;

pub use input_sequence::{
    compile_input_sequence, parse_input_sequence_json, parse_input_sequence_json_with_command_id,
    ClickButton, CompiledInputSequence, InputAction, InputArmPolicy, InputChunk, InputError,
    InputGesture, InputKeyboardTiming, InputLeafAction, InputSequenceV1, MouseDelta,
    INPUT_SEQUENCE_SCHEMA_V1,
};

pub const MOD_LEFT_CTRL: u8 = 0x01;
pub const MOD_LEFT_SHIFT: u8 = 0x02;
pub const MOD_LEFT_ALT: u8 = 0x04;
pub const MOD_LEFT_GUI: u8 = 0x08;
pub const MOD_RIGHT_CTRL: u8 = 0x10;
pub const MOD_RIGHT_SHIFT: u8 = 0x20;
pub const MOD_RIGHT_ALT: u8 = 0x40;
pub const MOD_RIGHT_GUI: u8 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardReport {
    pub modifiers: u8,
    pub keys: [u8; 6],
}

impl KeyboardReport {
    pub const RELEASED: Self = Self {
        modifiers: 0,
        keys: [0; 6],
    };

    #[must_use]
    pub const fn single(modifiers: u8, usage: u8) -> Self {
        Self {
            modifiers,
            keys: [usage, 0, 0, 0, 0, 0],
        }
    }

    pub fn from_keys(modifiers: u8, usages: &[u8]) -> Result<Self, ReportError> {
        if usages.len() > 6 {
            return Err(ReportError::RolloverLimit);
        }
        let mut keys = [0; 6];
        for (index, usage) in usages.iter().copied().enumerate() {
            if usage == 0 {
                return Err(ReportError::ZeroUsage);
            }
            if keys[..index].contains(&usage) {
                return Err(ReportError::DuplicateUsage);
            }
            keys[index] = usage;
        }
        keys[..usages.len()].sort_unstable();
        Ok(Self { modifiers, keys })
    }

    #[must_use]
    pub fn is_released(self) -> bool {
        self.modifiers == 0 && self.keys == [0; 6]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportError {
    RolloverLimit,
    ZeroUsage,
    DuplicateUsage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyClass {
    Modifier,
    NonModifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyPortability {
    BootCommon,
    ReportExtended,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyboardKey {
    pub name: &'static str,
    pub class: KeyClass,
    pub code: u8,
    pub portability: KeyPortability,
}

include!(concat!(env!("OUT_DIR"), "/keyboard_key_registry.rs"));

#[must_use]
pub fn keyboard_key(name: &str) -> Option<KeyboardKey> {
    KEYBOARD_KEYS
        .iter()
        .copied()
        .find(|entry| entry.name == name)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TypingTiming {
    pub key_down_ms: u16,
    pub release_gap_ms: u16,
}

impl TypingTiming {
    pub const DESKTOP_SAFE: Self = Self {
        key_down_ms: 12,
        release_gap_ms: 40,
    };
    pub const COMPATIBILITY: Self = Self {
        key_down_ms: 40,
        release_gap_ms: 40,
    };

    pub fn validate(self) -> Result<Self, LayoutError> {
        if !(5..=100).contains(&self.key_down_ms) {
            return Err(LayoutError::TimingOutOfRange(self.key_down_ms));
        }
        if !(5..=100).contains(&self.release_gap_ms) {
            return Err(LayoutError::TimingOutOfRange(self.release_gap_ms));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Keystroke {
    pub modifiers: u8,
    pub usage: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportStep {
    Report(KeyboardReport),
    WaitMs(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    UnsupportedCharacter(char),
    TimingOutOfRange(u16),
    /// A key name that is not a modifier, a supported named key, or a single
    /// supported character. Carries no payload so the error stays `Copy`.
    UnknownKeyName,
    /// A chord must name exactly one non-modifier key.
    ChordNeedsExactlyOneKey,
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCharacter(_) => write!(f, "unsupported character"),
            Self::TimingOutOfRange(value) => {
                write!(f, "typing delay must be between 5 and 100 ms: {value}")
            }
            Self::UnknownKeyName => write!(f, "unknown key name"),
            Self::ChordNeedsExactlyOneKey => {
                write!(f, "a chord must name exactly one non-modifier key")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

pub const SEQUENCE_SCHEMA_V1: &str = "keyferry.keyboard-sequence.v1";
pub const MAX_SEQUENCE_SOURCE_NODES: usize = 256;
pub const MAX_SEQUENCE_TEXT_CHARACTERS: usize = 4096;
pub const MAX_SEQUENCE_GESTURES: usize = 4096;
pub const MAX_SEQUENCE_REPEAT: u16 = 1000;
pub const MAX_SEQUENCE_WAIT_MS: u16 = 10_000;
pub const MAX_SEQUENCE_PLANNED_MS: u32 = 60_000;
pub const MAX_ORDERED_CHORD_KEYS: usize = 6;
pub const ORDERED_PRESS_MS: u16 = 20;
pub const ORDERED_RELEASE_MS: u16 = 10;

pub(crate) fn ordered_reports(keys: &[KeyboardKey]) -> Result<Vec<KeyboardReport>, ReportError> {
    let mut modifiers = 0_u8;
    let mut usages = Vec::with_capacity(keys.len());
    let mut reports = Vec::with_capacity(keys.len());
    for key in keys {
        match key.class {
            KeyClass::Modifier => modifiers |= key.code,
            KeyClass::NonModifier => usages.push(key.code),
        }
        reports.push(KeyboardReport::from_keys(modifiers, &usages)?);
    }
    Ok(reports)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SequenceArmPolicy {
    CommandScoped,
    RequireExisting,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyboardSequenceV1 {
    pub schema: String,
    pub command_id: String,
    pub profile: String,
    pub arm: SequenceArmPolicy,
    pub start_within_ms: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<TypingTiming>,
    pub actions: Vec<SequenceAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceAction {
    Text {
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Tap {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Chord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    OrderedChord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Wait {
        ms: u16,
    },
    Repeat {
        count: u16,
        actions: Vec<SequenceLeafAction>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceLeafAction {
    Text {
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Tap {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Chord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    OrderedChord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<TypingTiming>,
    },
    Wait {
        ms: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledSequence {
    pub steps: Vec<ReportStep>,
    pub source_nodes: usize,
    pub text_characters: usize,
    pub gestures: usize,
    pub planned_ms: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SequenceError {
    Schema,
    Profile,
    StartDeadline,
    SourceActionCount,
    Timing,
    TextCharacterLimit,
    UnsupportedCharacter,
    UnknownKey,
    KeyOutOfScope,
    DuplicateChordKey,
    ChordSize,
    RolloverLimit,
    Wait,
    Repeat,
    GestureLimit,
    DurationLimit,
    NoKeyEffect,
}

impl SequenceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Schema => "sequence.schema",
            Self::Profile => "sequence.profile",
            Self::StartDeadline => "sequence.start_deadline",
            Self::SourceActionCount => "sequence.source_action_limit",
            Self::Timing => "sequence.timing",
            Self::TextCharacterLimit => "text.character_limit",
            Self::UnsupportedCharacter => "text.unsupported_character",
            Self::UnknownKey => "key.unknown",
            Self::KeyOutOfScope => "key.out_of_scope",
            Self::DuplicateChordKey => "chord.duplicate_key",
            Self::ChordSize => "chord.size",
            Self::RolloverLimit => "chord.rollover_limit",
            Self::Wait => "wait.out_of_range",
            Self::Repeat => "repeat.out_of_range",
            Self::GestureLimit => "sequence.gesture_limit",
            Self::DurationLimit => "sequence.duration_limit",
            Self::NoKeyEffect => "sequence.no_key_effect",
        }
    }
}

impl fmt::Display for SequenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for SequenceError {}

struct CompileState {
    steps: Vec<ReportStep>,
    source_nodes: usize,
    text_characters: usize,
    gestures: usize,
    planned_ms: u32,
}

enum Leaf<'a> {
    Text(&'a str, Option<TypingTiming>),
    Tap(&'a str, Option<TypingTiming>),
    Chord(&'a [String], Option<TypingTiming>),
    OrderedChord(&'a [String], Option<TypingTiming>),
    Wait(u16),
}

pub fn compile_sequence(request: &KeyboardSequenceV1) -> Result<CompiledSequence, SequenceError> {
    if request.schema != SEQUENCE_SCHEMA_V1 {
        return Err(SequenceError::Schema);
    }
    if request.profile != "windows-us" {
        return Err(SequenceError::Profile);
    }
    if !(1..=5000).contains(&request.start_within_ms) {
        return Err(SequenceError::StartDeadline);
    }
    if request.actions.is_empty() {
        return Err(SequenceError::SourceActionCount);
    }
    let default_timing = request.timing.unwrap_or(TypingTiming::DESKTOP_SAFE);
    validate_sequence_timing(default_timing)?;
    let mut state = CompileState {
        steps: Vec::new(),
        source_nodes: request.actions.len(),
        text_characters: 0,
        gestures: 0,
        planned_ms: 0,
    };
    for action in &request.actions {
        match action {
            SequenceAction::Text { value, timing } => {
                compile_leaf(&mut state, Leaf::Text(value, *timing), default_timing)?;
            }
            SequenceAction::Tap { key, timing } => {
                compile_leaf(&mut state, Leaf::Tap(key, *timing), default_timing)?;
            }
            SequenceAction::Chord { keys, timing } => {
                compile_leaf(&mut state, Leaf::Chord(keys, *timing), default_timing)?;
            }
            SequenceAction::OrderedChord { keys, timing } => {
                compile_leaf(
                    &mut state,
                    Leaf::OrderedChord(keys, *timing),
                    default_timing,
                )?;
            }
            SequenceAction::Wait { ms } => {
                compile_leaf(&mut state, Leaf::Wait(*ms), default_timing)?;
            }
            SequenceAction::Repeat { count, actions } => {
                if !(1..=MAX_SEQUENCE_REPEAT).contains(count) || actions.is_empty() {
                    return Err(SequenceError::Repeat);
                }
                state.source_nodes = state.source_nodes.saturating_add(actions.len());
                check_source_nodes(state.source_nodes)?;
                for _ in 0..*count {
                    for action in actions {
                        let leaf = match action {
                            SequenceLeafAction::Text { value, timing } => {
                                Leaf::Text(value, *timing)
                            }
                            SequenceLeafAction::Tap { key, timing } => Leaf::Tap(key, *timing),
                            SequenceLeafAction::Chord { keys, timing } => {
                                Leaf::Chord(keys, *timing)
                            }
                            SequenceLeafAction::OrderedChord { keys, timing } => {
                                Leaf::OrderedChord(keys, *timing)
                            }
                            SequenceLeafAction::Wait { ms } => Leaf::Wait(*ms),
                        };
                        compile_leaf(&mut state, leaf, default_timing)?;
                    }
                }
            }
        }
        check_source_nodes(state.source_nodes)?;
    }
    if state.gestures == 0 {
        return Err(SequenceError::NoKeyEffect);
    }
    Ok(CompiledSequence {
        steps: state.steps,
        source_nodes: state.source_nodes,
        text_characters: state.text_characters,
        gestures: state.gestures,
        planned_ms: state.planned_ms,
    })
}

fn check_source_nodes(count: usize) -> Result<(), SequenceError> {
    if count > MAX_SEQUENCE_SOURCE_NODES {
        return Err(SequenceError::SourceActionCount);
    }
    Ok(())
}

fn validate_sequence_timing(timing: TypingTiming) -> Result<TypingTiming, SequenceError> {
    timing.validate().map_err(|_| SequenceError::Timing)
}

fn compile_leaf(
    state: &mut CompileState,
    action: Leaf<'_>,
    default_timing: TypingTiming,
) -> Result<(), SequenceError> {
    match action {
        Leaf::Text(value, timing) => {
            let characters = value.chars().count();
            state.text_characters = state.text_characters.saturating_add(characters);
            if state.text_characters > MAX_SEQUENCE_TEXT_CHARACTERS {
                return Err(SequenceError::TextCharacterLimit);
            }
            let timing = validate_sequence_timing(timing.unwrap_or(default_timing))?;
            let planned = plan_text_us(value, timing).map_err(|error| match error {
                LayoutError::UnsupportedCharacter(_) => SequenceError::UnsupportedCharacter,
                _ => SequenceError::Timing,
            })?;
            let gestures = planned.len() / 4;
            add_gestures(state, gestures)?;
            add_duration(
                state,
                u32::try_from(gestures)
                    .unwrap_or(u32::MAX)
                    .saturating_mul(u32::from(timing.key_down_ms + timing.release_gap_ms)),
            )?;
            state.steps.extend(planned);
        }
        Leaf::Tap(name, timing) => {
            let timing = validate_sequence_timing(timing.unwrap_or(default_timing))?;
            let key = sequence_key(name)?;
            let report = match key.class {
                KeyClass::Modifier => KeyboardReport::from_keys(key.code, &[]),
                KeyClass::NonModifier => KeyboardReport::from_keys(0, &[key.code]),
            }
            .map_err(|_| SequenceError::RolloverLimit)?;
            emit_gesture(state, report, timing)?;
        }
        Leaf::Chord(names, timing) => {
            let timing = validate_sequence_timing(timing.unwrap_or(default_timing))?;
            if !(2..=14).contains(&names.len()) {
                return Err(SequenceError::ChordSize);
            }
            let mut modifiers = 0u8;
            let mut usages = Vec::with_capacity(6);
            let mut seen = std::collections::HashSet::with_capacity(names.len());
            for name in names {
                if !seen.insert(name.as_str()) {
                    return Err(SequenceError::DuplicateChordKey);
                }
                let key = sequence_key(name)?;
                match key.class {
                    KeyClass::Modifier => modifiers |= key.code,
                    KeyClass::NonModifier => usages.push(key.code),
                }
            }
            let report =
                KeyboardReport::from_keys(modifiers, &usages).map_err(|error| match error {
                    ReportError::RolloverLimit => SequenceError::RolloverLimit,
                    ReportError::DuplicateUsage => SequenceError::DuplicateChordKey,
                    ReportError::ZeroUsage => SequenceError::UnknownKey,
                })?;
            emit_gesture(state, report, timing)?;
        }
        Leaf::OrderedChord(names, timing) => {
            let timing = validate_sequence_timing(timing.unwrap_or(default_timing))?;
            if !(2..=MAX_ORDERED_CHORD_KEYS).contains(&names.len()) {
                return Err(SequenceError::ChordSize);
            }
            let mut seen = std::collections::HashSet::with_capacity(names.len());
            let mut keys = Vec::with_capacity(names.len());
            for name in names {
                if !seen.insert(name.as_str()) {
                    return Err(SequenceError::DuplicateChordKey);
                }
                keys.push(sequence_key(name)?);
            }
            let reports = ordered_reports(&keys).map_err(|_| SequenceError::RolloverLimit)?;
            add_gestures(state, 1)?;
            let prefixes = (reports.len() - 1) as u32;
            add_duration(
                state,
                prefixes * u32::from(ORDERED_PRESS_MS + ORDERED_RELEASE_MS)
                    + u32::from(timing.key_down_ms + timing.release_gap_ms),
            )?;
            for (index, report) in reports.iter().copied().enumerate() {
                state.steps.push(ReportStep::Report(report));
                state
                    .steps
                    .push(ReportStep::WaitMs(if index + 1 == reports.len() {
                        timing.key_down_ms
                    } else {
                        ORDERED_PRESS_MS
                    }));
            }
            for report in reports[..reports.len() - 1].iter().rev().copied() {
                state.steps.push(ReportStep::Report(report));
                state.steps.push(ReportStep::WaitMs(ORDERED_RELEASE_MS));
            }
            state
                .steps
                .push(ReportStep::Report(KeyboardReport::RELEASED));
            state.steps.push(ReportStep::WaitMs(timing.release_gap_ms));
        }
        Leaf::Wait(ms) => {
            if !(1..=MAX_SEQUENCE_WAIT_MS).contains(&ms) {
                return Err(SequenceError::Wait);
            }
            if state.steps.is_empty() {
                state
                    .steps
                    .push(ReportStep::Report(KeyboardReport::RELEASED));
            }
            add_duration(state, u32::from(ms))?;
            let mut remaining = ms;
            while remaining != 0 {
                let part = remaining.min(100);
                state.steps.push(ReportStep::WaitMs(part));
                remaining -= part;
            }
        }
    }
    Ok(())
}

fn sequence_key(name: &str) -> Result<KeyboardKey, SequenceError> {
    if let Some(key) = keyboard_key(name) {
        return Ok(key);
    }
    match name {
        "POWER" | "MUTE" | "VOLUME_UP" | "VOLUME_DOWN" => Err(SequenceError::KeyOutOfScope),
        _ => Err(SequenceError::UnknownKey),
    }
}

fn add_gestures(state: &mut CompileState, count: usize) -> Result<(), SequenceError> {
    state.gestures = state.gestures.saturating_add(count);
    if state.gestures > MAX_SEQUENCE_GESTURES {
        return Err(SequenceError::GestureLimit);
    }
    Ok(())
}

fn add_duration(state: &mut CompileState, milliseconds: u32) -> Result<(), SequenceError> {
    state.planned_ms = state.planned_ms.saturating_add(milliseconds);
    if state.planned_ms > MAX_SEQUENCE_PLANNED_MS {
        return Err(SequenceError::DurationLimit);
    }
    Ok(())
}

fn emit_gesture(
    state: &mut CompileState,
    report: KeyboardReport,
    timing: TypingTiming,
) -> Result<(), SequenceError> {
    add_gestures(state, 1)?;
    add_duration(
        state,
        u32::from(timing.key_down_ms) + u32::from(timing.release_gap_ms),
    )?;
    state.steps.push(ReportStep::Report(report));
    state.steps.push(ReportStep::WaitMs(timing.key_down_ms));
    state
        .steps
        .push(ReportStep::Report(KeyboardReport::RELEASED));
    state.steps.push(ReportStep::WaitMs(timing.release_gap_ms));
    Ok(())
}

pub fn plan_text_us(text: &str, timing: TypingTiming) -> Result<Vec<ReportStep>, LayoutError> {
    let timing = timing.validate()?;
    let mut steps = Vec::with_capacity(text.chars().count() * 4);
    let mut chars = text.chars().peekable();

    while let Some(mut ch) = chars.next() {
        if ch == '\r' {
            if chars.peek().copied() == Some('\n') {
                chars.next();
            }
            ch = '\n';
        }
        let stroke = stroke_for_us_ascii(ch)?;
        steps.push(ReportStep::Report(KeyboardReport::single(
            stroke.modifiers,
            stroke.usage,
        )));
        steps.push(ReportStep::WaitMs(timing.key_down_ms));
        steps.push(ReportStep::Report(KeyboardReport::RELEASED));
        steps.push(ReportStep::WaitMs(timing.release_gap_ms));
    }

    // A trailing wait holds no key, so scan back to the last actual report: the
    // per-character loop already ends each character in a released report.
    let ends_released = steps
        .iter()
        .rev()
        .find_map(|step| match step {
            ReportStep::Report(report) => Some(report.is_released()),
            ReportStep::WaitMs(_) => None,
        })
        .unwrap_or(true);
    if !ends_released {
        steps.push(ReportStep::Report(KeyboardReport::RELEASED));
    }
    Ok(steps)
}

pub fn stroke_for_us_ascii(ch: char) -> Result<Keystroke, LayoutError> {
    let plain = |usage| {
        Ok(Keystroke {
            modifiers: 0,
            usage,
        })
    };
    let shifted = |usage| {
        Ok(Keystroke {
            modifiers: MOD_LEFT_SHIFT,
            usage,
        })
    };

    match ch {
        'a'..='z' => plain(0x04 + (ch as u8 - b'a')),
        'A'..='Z' => shifted(0x04 + (ch as u8 - b'A')),
        '1'..='9' => plain(0x1e + (ch as u8 - b'1')),
        '0' => plain(0x27),
        '\n' => plain(0x28),
        '\u{1b}' => plain(0x29),
        '\u{8}' => plain(0x2a),
        '\t' => plain(0x2b),
        ' ' => plain(0x2c),
        '-' => plain(0x2d),
        '_' => shifted(0x2d),
        '=' => plain(0x2e),
        '+' => shifted(0x2e),
        '[' => plain(0x2f),
        '{' => shifted(0x2f),
        ']' => plain(0x30),
        '}' => shifted(0x30),
        '\\' => plain(0x31),
        '|' => shifted(0x31),
        ';' => plain(0x33),
        ':' => shifted(0x33),
        '\'' => plain(0x34),
        '"' => shifted(0x34),
        '`' => plain(0x35),
        '~' => shifted(0x35),
        ',' => plain(0x36),
        '<' => shifted(0x36),
        '.' => plain(0x37),
        '>' => shifted(0x37),
        '/' => plain(0x38),
        '?' => shifted(0x38),
        '!' => shifted(0x1e),
        '@' => shifted(0x1f),
        '#' => shifted(0x20),
        '$' => shifted(0x21),
        '%' => shifted(0x22),
        '^' => shifted(0x23),
        '&' => shifted(0x24),
        '*' => shifted(0x25),
        '(' => shifted(0x26),
        ')' => shifted(0x27),
        other => Err(LayoutError::UnsupportedCharacter(other)),
    }
}

/// Modifier bit for a modifier key name, or `None` when the name is not one.
fn modifier_for_name(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "CTRL" | "CONTROL" => Some(MOD_LEFT_CTRL),
        "SHIFT" => Some(MOD_LEFT_SHIFT),
        "ALT" | "OPTION" => Some(MOD_LEFT_ALT),
        "GUI" | "META" | "WIN" | "SUPER" | "CMD" => Some(MOD_LEFT_GUI),
        _ => None,
    }
}

/// The version-1 named keys: the typed actions listed in `docs/decisions.md`.
fn named_key(name: &str) -> Option<Keystroke> {
    let plain = |usage| {
        Some(Keystroke {
            modifiers: 0,
            usage,
        })
    };
    match name.to_ascii_uppercase().as_str() {
        "ENTER" | "RETURN" => plain(0x28),
        "ESC" | "ESCAPE" => plain(0x29),
        "BACKSPACE" => plain(0x2a),
        "TAB" => plain(0x2b),
        "SPACE" => plain(0x2c),
        _ => None,
    }
}

/// Resolve a public key *name* to a keystroke. Callers outside the host never
/// supply raw HID usages; this is the only way a client-named key becomes one.
pub fn stroke_for_key_name(name: &str) -> Result<Keystroke, LayoutError> {
    if let Some(stroke) = named_key(name) {
        return Ok(stroke);
    }
    let mut chars = name.chars();
    match (chars.next(), chars.next()) {
        (Some(ch), None) => stroke_for_us_ascii(ch),
        _ => Err(LayoutError::UnknownKeyName),
    }
}

/// Combine modifier names plus exactly one non-modifier key into one chord.
pub fn chord_from_names<S: AsRef<str>>(names: &[S]) -> Result<Keystroke, LayoutError> {
    let mut modifiers = 0u8;
    let mut key: Option<Keystroke> = None;
    for name in names {
        let name = name.as_ref();
        if let Some(bit) = modifier_for_name(name) {
            modifiers |= bit;
            continue;
        }
        if key.is_some() {
            return Err(LayoutError::ChordNeedsExactlyOneKey);
        }
        // In a chord a bare letter names the KEY, not the shifted character, so
        // ["CTRL","L"] is Ctrl+L and never Ctrl+Shift+L. Shift must be named.
        let is_letter = name.len() == 1 && name.starts_with(|c: char| c.is_ascii_alphabetic());
        key = Some(if is_letter {
            stroke_for_key_name(&name.to_ascii_lowercase())?
        } else {
            stroke_for_key_name(name)?
        });
    }
    let key = key.ok_or(LayoutError::ChordNeedsExactlyOneKey)?;
    Ok(Keystroke {
        modifiers: modifiers | key.modifiers,
        usage: key.usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence(actions: Vec<SequenceAction>) -> KeyboardSequenceV1 {
        KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: "019d1234-5678-7abc-8123-456789abcdef".to_owned(),
            profile: "windows-us".to_owned(),
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: 5000,
            timing: None,
            actions,
        }
    }

    #[test]
    fn maps_letters_and_shifted_punctuation() {
        assert_eq!(
            stroke_for_us_ascii('a').unwrap(),
            Keystroke {
                modifiers: 0,
                usage: 0x04
            }
        );
        assert_eq!(
            stroke_for_us_ascii('A').unwrap(),
            Keystroke {
                modifiers: MOD_LEFT_SHIFT,
                usage: 0x04
            }
        );
        assert_eq!(
            stroke_for_us_ascii('!').unwrap(),
            Keystroke {
                modifiers: MOD_LEFT_SHIFT,
                usage: 0x1e
            }
        );
    }

    #[test]
    fn plans_release_after_each_character() {
        let steps = plan_text_us("A!", TypingTiming::DESKTOP_SAFE).unwrap();
        assert_eq!(steps.len(), 8);
        assert_eq!(steps[2], ReportStep::Report(KeyboardReport::RELEASED));
        assert_eq!(steps[6], ReportStep::Report(KeyboardReport::RELEASED));
    }

    #[test]
    fn rejects_unicode_outside_v1_contract() {
        assert_eq!(
            plan_text_us("em—dash", TypingTiming::DESKTOP_SAFE),
            Err(LayoutError::UnsupportedCharacter('—'))
        );
    }

    #[test]
    fn resolves_named_keys_and_single_characters() {
        assert_eq!(stroke_for_key_name("ENTER").unwrap().usage, 0x28);
        assert_eq!(stroke_for_key_name("enter").unwrap().usage, 0x28);
        assert_eq!(stroke_for_key_name("Tab").unwrap().usage, 0x2b);
        assert_eq!(stroke_for_key_name("ESC").unwrap().usage, 0x29);
        // A single character keeps character semantics for a tap.
        assert_eq!(
            stroke_for_key_name("A").unwrap(),
            Keystroke {
                modifiers: MOD_LEFT_SHIFT,
                usage: 0x04
            }
        );
        assert_eq!(
            stroke_for_key_name("NOPE"),
            Err(LayoutError::UnknownKeyName)
        );
    }

    #[test]
    fn chord_uses_the_base_key_and_named_modifiers() {
        // Ctrl+L must not smuggle in an implicit Shift.
        let ctrl_l = chord_from_names(&["CTRL", "L"]).unwrap();
        assert_eq!(ctrl_l.modifiers, MOD_LEFT_CTRL);
        assert_eq!(ctrl_l.usage, 0x0f);

        let ctrl_shift_l = chord_from_names(&["CTRL", "SHIFT", "L"]).unwrap();
        assert_eq!(ctrl_shift_l.modifiers, MOD_LEFT_CTRL | MOD_LEFT_SHIFT);
        assert_eq!(ctrl_shift_l.usage, 0x0f);

        assert_eq!(
            chord_from_names(&["CTRL", "ALT", "DELETE"]),
            Err(LayoutError::UnknownKeyName),
            "DELETE is outside the version-1 key set"
        );
        assert_eq!(
            chord_from_names(&["CTRL"]),
            Err(LayoutError::ChordNeedsExactlyOneKey)
        );
        assert_eq!(
            chord_from_names(&["A", "B"]),
            Err(LayoutError::ChordNeedsExactlyOneKey)
        );
    }

    #[test]
    fn normalizes_crlf_to_one_enter() {
        let steps = plan_text_us("a\r\nb", TypingTiming::DESKTOP_SAFE).unwrap();
        assert_eq!(steps.len(), 12);
    }

    #[test]
    fn registry_is_complete_and_canonical() {
        assert_eq!(KEYBOARD_KEYS.len(), 211);
        for key in KEYBOARD_KEYS {
            assert_eq!(keyboard_key(key.name), Some(*key));
            assert_eq!(key.name, key.name.to_ascii_uppercase());
        }
        assert_eq!(keyboard_key("LEFT_GUI").unwrap().code, MOD_LEFT_GUI);
        assert_eq!(keyboard_key("RIGHT_GUI").unwrap().code, MOD_RIGHT_GUI);
        assert_eq!(keyboard_key("F24").unwrap().code, 0x73);
        assert_eq!(keyboard_key("VOLUME_UP"), None);
        assert_eq!(keyboard_key("left_gui"), None);
    }

    #[test]
    fn full_reports_support_modifier_only_and_six_keys() {
        let modifier = KeyboardReport::from_keys(MOD_RIGHT_ALT, &[]).unwrap();
        assert_eq!(modifier.modifiers, MOD_RIGHT_ALT);
        assert_eq!(modifier.keys, [0; 6]);

        let six = KeyboardReport::from_keys(0xff, &[9, 4, 8, 5, 7, 6]).unwrap();
        assert_eq!(six.keys, [4, 5, 6, 7, 8, 9]);
        assert_eq!(
            KeyboardReport::from_keys(0, &[4, 5, 6, 7, 8, 9, 10]),
            Err(ReportError::RolloverLimit)
        );
        assert_eq!(
            KeyboardReport::from_keys(0, &[4, 4]),
            Err(ReportError::DuplicateUsage)
        );
    }

    #[test]
    fn strict_sequence_json_rejects_irrelevant_fields_and_nested_repeat() {
        let irrelevant = r#"{
            "schema":"keyferry.keyboard-sequence.v1",
            "command_id":"019d1234-5678-7abc-8123-456789abcdef",
            "profile":"windows-us","arm":"command-scoped","start_within_ms":5000,
            "actions":[{"type":"tap","key":"ENTER","value":"secret"}]
        }"#;
        assert!(serde_json::from_str::<KeyboardSequenceV1>(irrelevant).is_err());

        let nested = r#"{
            "schema":"keyferry.keyboard-sequence.v1",
            "command_id":"019d1234-5678-7abc-8123-456789abcdef",
            "profile":"windows-us","arm":"command-scoped","start_within_ms":5000,
            "actions":[{"type":"repeat","count":2,"actions":[
                {"type":"repeat","count":2,"actions":[{"type":"tap","key":"A"}]}
            ]}]
        }"#;
        assert!(serde_json::from_str::<KeyboardSequenceV1>(nested).is_err());
    }

    #[test]
    fn compiles_owner_sequences_and_all_modifier_bits() {
        let request = sequence(vec![
            SequenceAction::Tap {
                key: "LEFT_GUI".to_owned(),
                timing: None,
            },
            SequenceAction::Wait { ms: 250 },
            SequenceAction::Text {
                value: "notepad".to_owned(),
                timing: None,
            },
            SequenceAction::Tap {
                key: "ENTER".to_owned(),
                timing: None,
            },
        ]);
        let compiled = compile_sequence(&request).unwrap();
        assert_eq!(compiled.gestures, 9);
        assert_eq!(compiled.text_characters, 7);
        assert!(compiled.planned_ms > 250);
        assert_eq!(
            compiled.steps[0],
            ReportStep::Report(KeyboardReport::from_keys(MOD_LEFT_GUI, &[]).unwrap())
        );

        for name in [
            "LEFT_CONTROL",
            "LEFT_SHIFT",
            "LEFT_ALT",
            "LEFT_GUI",
            "RIGHT_CONTROL",
            "RIGHT_SHIFT",
            "RIGHT_ALT",
            "RIGHT_GUI",
        ] {
            let compiled = compile_sequence(&sequence(vec![SequenceAction::Tap {
                key: name.to_owned(),
                timing: None,
            }]))
            .unwrap();
            let ReportStep::Report(report) = compiled.steps[0] else {
                panic!("first step must be a report")
            };
            assert_eq!(report.modifiers, keyboard_key(name).unwrap().code);
            assert_eq!(report.keys, [0; 6]);
        }
    }

    #[test]
    fn chord_order_is_canonical_and_rollover_rejects() {
        let chord = |keys: &[&str]| {
            sequence(vec![SequenceAction::Chord {
                keys: keys.iter().map(|key| (*key).to_owned()).collect(),
                timing: None,
            }])
        };
        let first = compile_sequence(&chord(&["RIGHT_ALT", "DELETE", "LEFT_CONTROL"])).unwrap();
        let second = compile_sequence(&chord(&["LEFT_CONTROL", "RIGHT_ALT", "DELETE"])).unwrap();
        assert_eq!(first.steps, second.steps);

        assert_eq!(
            compile_sequence(&chord(&["A", "A"])),
            Err(SequenceError::DuplicateChordKey)
        );
        assert_eq!(
            compile_sequence(&chord(&["A", "B", "C", "D", "E", "F", "G"])),
            Err(SequenceError::RolloverLimit)
        );
    }

    #[test]
    fn ordered_chord_stages_arbitrary_keys_and_releases_in_reverse() {
        let ordered = |keys: &[&str]| {
            sequence(vec![SequenceAction::OrderedChord {
                keys: keys.iter().map(|key| (*key).to_owned()).collect(),
                timing: None,
            }])
        };
        let compiled = compile_sequence(&ordered(&["CAPS_LOCK", "SPACE", "J"])).unwrap();
        let reports: Vec<_> = compiled
            .steps
            .iter()
            .filter_map(|step| match step {
                ReportStep::Report(report) => Some(*report),
                ReportStep::WaitMs(_) => None,
            })
            .collect();
        let caps = keyboard_key("CAPS_LOCK").unwrap().code;
        let space = keyboard_key("SPACE").unwrap().code;
        let j = keyboard_key("J").unwrap().code;
        assert_eq!(
            reports,
            vec![
                KeyboardReport::from_keys(0, &[caps]).unwrap(),
                KeyboardReport::from_keys(0, &[caps, space]).unwrap(),
                KeyboardReport::from_keys(0, &[caps, space, j]).unwrap(),
                KeyboardReport::from_keys(0, &[caps, space]).unwrap(),
                KeyboardReport::from_keys(0, &[caps]).unwrap(),
                KeyboardReport::RELEASED,
            ]
        );
        assert_eq!(compiled.planned_ms, 112);
        assert!(compile_sequence(&ordered(&["SPACE", "Q"])).is_ok());
        assert_eq!(
            compile_sequence(&ordered(&["SPACE", "SPACE"])),
            Err(SequenceError::DuplicateChordKey)
        );
        assert_eq!(
            compile_sequence(&ordered(&["A", "B", "C", "D", "E", "F", "G"])),
            Err(SequenceError::ChordSize)
        );
    }

    #[test]
    fn repeats_waits_and_errors_are_bounded_and_payload_free() {
        let repeated = sequence(vec![SequenceAction::Repeat {
            count: 3,
            actions: vec![
                SequenceLeafAction::Tap {
                    key: "DOWN_ARROW".to_owned(),
                    timing: None,
                },
                SequenceLeafAction::Wait { ms: 250 },
            ],
        }]);
        let compiled = compile_sequence(&repeated).unwrap();
        assert_eq!(compiled.gestures, 3);
        assert_eq!(compiled.planned_ms, 906);
        assert!(compiled
            .steps
            .iter()
            .all(|step| !matches!(step, ReportStep::WaitMs(ms) if *ms > 100)));

        let unsupported = sequence(vec![SequenceAction::Text {
            value: "café".to_owned(),
            timing: None,
        }]);
        let error = compile_sequence(&unsupported).unwrap_err();
        assert_eq!(error, SequenceError::UnsupportedCharacter);
        assert_eq!(error.to_string(), "text.unsupported_character");
        assert!(!error.to_string().contains("café"));

        let volume = sequence(vec![SequenceAction::Tap {
            key: "VOLUME_UP".to_owned(),
            timing: None,
        }]);
        assert_eq!(compile_sequence(&volume), Err(SequenceError::KeyOutOfScope));
        assert_eq!(
            compile_sequence(&sequence(vec![SequenceAction::Wait { ms: 100 }])),
            Err(SequenceError::NoKeyEffect)
        );
    }
}
