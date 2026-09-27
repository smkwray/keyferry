#![forbid(unsafe_code)]

pub mod recipe;
pub mod text_stream;

use serde::{Deserialize, Serialize};
use std::fmt;

mod input_sequence;

pub use input_sequence::{
    canonicalize_input_sequence_keys, compile_input_sequence, parse_input_sequence_json,
    parse_input_sequence_json_with_command_id, ClickButton, CompiledInputSequence, InputAction,
    InputArmPolicy, InputChunk, InputError, InputGesture, InputKeyboardTiming, InputLeafAction,
    InputSequenceV1, MouseDelta, INPUT_SEQUENCE_SCHEMA_V1,
};

/// Wire keyboard-mapping identifier hashed into every command envelope. It names the single
/// US-ASCII HID mapping, valid for a Windows US target and for a Mac identified as ANSI with
/// the U.S. or ABC input source. The value is the legacy v1 string; firmware compares its
/// SHA-256, so it never changes without a firmware release.
pub const LEGACY_WIRE_MAPPING: &str = "windows-us";

#[must_use]
pub fn is_wire_mapping(profile: &str) -> bool {
    profile == LEGACY_WIRE_MAPPING
}

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

/// Exact, case-sensitive canonical registry lookup. Aliases never resolve here.
#[must_use]
pub fn keyboard_key(name: &str) -> Option<KeyboardKey> {
    KEYBOARD_KEYS
        .iter()
        .copied()
        .find(|entry| entry.name == name)
}

/// The only alias table: uppercase alias → canonical registry name. Aliases are never
/// registry rows, and every compiler resolves them to the same key and wire bytes.
pub const KEY_ALIASES: &[(&str, &str)] = &[
    ("COMMAND", "LEFT_GUI"),
    ("CMD", "LEFT_GUI"),
    ("LEFT_COMMAND", "LEFT_GUI"),
    ("LEFT_CMD", "LEFT_GUI"),
    ("RIGHT_COMMAND", "RIGHT_GUI"),
    ("RIGHT_CMD", "RIGHT_GUI"),
    ("OPTION", "LEFT_ALT"),
    ("OPT", "LEFT_ALT"),
    ("LEFT_OPTION", "LEFT_ALT"),
    ("LEFT_OPT", "LEFT_ALT"),
    ("RIGHT_OPTION", "RIGHT_ALT"),
    ("RIGHT_OPT", "RIGHT_ALT"),
    ("CTRL", "LEFT_CONTROL"),
    ("CONTROL", "LEFT_CONTROL"),
    ("SHIFT", "LEFT_SHIFT"),
    ("ALT", "LEFT_ALT"),
    ("WIN", "LEFT_GUI"),
    ("WINDOWS", "LEFT_GUI"),
    ("GUI", "LEFT_GUI"),
    ("META", "LEFT_GUI"),
    ("SUPER", "LEFT_GUI"),
    ("RETURN", "ENTER"),
    ("ESC", "ESCAPE"),
];

/// Case-sensitive lookup of a canonical registry name first, then a listed alias.
#[must_use]
pub fn resolve_key_name(name: &str) -> Option<KeyboardKey> {
    keyboard_key(name).or_else(|| {
        KEY_ALIASES
            .iter()
            .find(|(alias, _)| *alias == name)
            .and_then(|(_, canonical)| keyboard_key(canonical))
    })
}

/// Rewrite an alias to its canonical registry name; other names are left for the compiler.
pub(crate) fn canonicalize_key_name(name: &mut String) {
    if let Some(key) = resolve_key_name(name) {
        if key.name != name {
            *name = key.name.to_owned();
        }
    }
}

/// Rewrite every alias key name in a keyboard sequence, including inside `repeat`, to its
/// canonical registry name. The compiled plan is unchanged; the body stays acceptable to
/// holders that predate aliases.
pub fn canonicalize_sequence_keys(request: &mut KeyboardSequenceV1) {
    for action in &mut request.actions {
        match action {
            SequenceAction::Tap { key, .. } => canonicalize_key_name(key),
            SequenceAction::Chord { keys, .. } | SequenceAction::OrderedChord { keys, .. } => {
                keys.iter_mut().for_each(canonicalize_key_name);
            }
            SequenceAction::Repeat { actions, .. } => {
                for action in actions {
                    match action {
                        SequenceLeafAction::Tap { key, .. } => canonicalize_key_name(key),
                        SequenceLeafAction::Chord { keys, .. }
                        | SequenceLeafAction::OrderedChord { keys, .. } => {
                            keys.iter_mut().for_each(canonicalize_key_name);
                        }
                        SequenceLeafAction::Text { .. } | SequenceLeafAction::Wait { .. } => {}
                    }
                }
            }
            SequenceAction::Text { .. } | SequenceAction::Wait { .. } => {}
        }
    }
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
    if !is_wire_mapping(&request.profile) {
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
            let mut seen = Vec::with_capacity(names.len());
            for name in names {
                let key = sequence_key(name)?;
                if !insert_resolved(&mut seen, key) {
                    return Err(SequenceError::DuplicateChordKey);
                }
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
            let mut keys = Vec::with_capacity(names.len());
            for name in names {
                if !insert_resolved(&mut keys, sequence_key(name)?) {
                    return Err(SequenceError::DuplicateChordKey);
                }
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
    if let Some(key) = resolve_key_name(name) {
        return Ok(key);
    }
    match name {
        "POWER" | "MUTE" | "VOLUME_UP" | "VOLUME_DOWN" => Err(SequenceError::KeyOutOfScope),
        _ => Err(SequenceError::UnknownKey),
    }
}

/// Record a resolved chord key, returning `false` when the same physical key (class and
/// code) was already named, whether canonically or through an alias.
pub(crate) fn insert_resolved(seen: &mut Vec<KeyboardKey>, key: KeyboardKey) -> bool {
    if seen
        .iter()
        .any(|other| other.class == key.class && other.code == key.code)
    {
        return false;
    }
    seen.push(key);
    true
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

/// Modifier bit for a modifier key name, case-insensitive, resolved through the registry
/// and [`KEY_ALIASES`]; `None` when the name is not a modifier.
fn modifier_for_name(name: &str) -> Option<u8> {
    resolve_key_name(&name.to_ascii_uppercase())
        .filter(|key| key.class == KeyClass::Modifier)
        .map(|key| key.code)
}

/// The version-1 named keys: the typed actions listed in `docs/decisions.md`.
const NAMED_KEYS: [&str; 5] = ["ENTER", "ESCAPE", "BACKSPACE", "TAB", "SPACE"];

fn named_key(name: &str) -> Option<Keystroke> {
    resolve_key_name(&name.to_ascii_uppercase())
        .filter(|key| NAMED_KEYS.contains(&key.name))
        .map(|key| Keystroke {
            modifiers: 0,
            usage: key.code,
        })
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
    use std::collections::BTreeSet;

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

    fn input(actions: Vec<InputAction>) -> InputSequenceV1 {
        InputSequenceV1 {
            schema: INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: "019d1234-5678-7abc-8123-456789abcdef".to_owned(),
            keyboard_profile: Some("windows-us".to_owned()),
            arm: InputArmPolicy::CommandScoped,
            start_within_ms: 5000,
            keyboard_timing: None,
            actions,
        }
    }

    fn names(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| (*key).to_owned()).collect()
    }

    #[test]
    fn legacy_wire_mapping_hash_is_pinned_to_firmware() {
        use sha2::{Digest, Sha256};
        const FIRMWARE_PROFILE_HASH: &str =
            "730c3fc2d49f2c092de5917d8f73dcb88c7f32462ac806877f0be1ca7f40bef4";
        let expected: Vec<u8> = (0..FIRMWARE_PROFILE_HASH.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&FIRMWARE_PROFILE_HASH[index..index + 2], 16).unwrap())
            .collect();
        assert_eq!(
            Sha256::digest(LEGACY_WIRE_MAPPING.as_bytes()).as_slice(),
            expected.as_slice()
        );
        // The device compares against this array, so read it rather than a copy of it.
        let firmware = include_str!("../../../firmware/esp32s3/hil_endpoint/main/app_main.cpp");
        let array = firmware
            .split_once("kWindowsUsProfileHash{")
            .and_then(|(_, rest)| rest.split_once("};"))
            .map(|(array, _)| array)
            .expect("firmware declares kWindowsUsProfileHash");
        let firmware_hash: Vec<u8> = array
            .split(',')
            .map(|byte| u8::from_str_radix(byte.trim().trim_start_matches("0x"), 16).unwrap())
            .collect();
        assert_eq!(firmware_hash, expected);
        assert_eq!(LEGACY_WIRE_MAPPING, "windows-us");
        assert!(is_wire_mapping("windows-us"));
        for other in ["us-ascii", "WINDOWS-US", "macos-us", ""] {
            assert!(!is_wire_mapping(other));
            let mut request = sequence(vec![SequenceAction::Tap {
                key: "ENTER".to_owned(),
                timing: None,
            }]);
            request.profile = other.to_owned();
            assert_eq!(compile_sequence(&request), Err(SequenceError::Profile));
        }
    }

    /// US ANSI key legends (unshifted, shifted) in HID usage order, written from the physical
    /// keyboard rather than derived from the mapping under test.
    const US_ANSI_LEGENDS: [(u8, &str); 3] = [
        (
            0x04,
            "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ1!2@3#4$5%6^7&8*9(0)",
        ),
        (0x2d, "-_=+[{]}\\|"),
        (0x33, ";:'\"`~,<.>/?"),
    ];

    #[test]
    fn us_ascii_stroke_table_is_pinned_through_both_compilers() {
        let mut expected = Vec::new();
        for (first, legends) in US_ANSI_LEGENDS {
            let legends: Vec<char> = legends.chars().collect();
            for (offset, pair) in legends.chunks_exact(2).enumerate() {
                let usage = first + u8::try_from(offset).unwrap();
                expected.push((pair[0], 0, usage));
                expected.push((pair[1], MOD_LEFT_SHIFT, usage));
            }
        }
        expected.push((' ', 0, 0x2c));
        let printable: BTreeSet<char> = expected.iter().map(|entry| entry.0).collect();
        assert_eq!(printable.len(), 95);
        assert!(printable.into_iter().eq(' '..='~'));

        let mut text: String = expected.iter().map(|entry| entry.0).collect();
        text.push_str("\t\n\r\n\u{1b}\u{8}");
        expected.extend([
            ('\t', 0, 0x2b),
            ('\n', 0, 0x28),
            ('\n', 0, 0x28),
            ('\u{1b}', 0, 0x29),
            ('\u{8}', 0, 0x2a),
        ]);
        let expected: Vec<KeyboardReport> = expected
            .iter()
            .map(|&(_, modifiers, usage)| KeyboardReport::single(modifiers, usage))
            .collect();

        let compiled = compile_sequence(&sequence(vec![SequenceAction::Text {
            value: text.clone(),
            timing: None,
        }]))
        .unwrap();
        let pressed: Vec<KeyboardReport> = compiled
            .steps
            .chunks_exact(4)
            .map(|steps| match steps {
                [ReportStep::Report(press), _, ReportStep::Report(release), _]
                    if release.is_released() =>
                {
                    *press
                }
                _ => panic!("each character is press, hold, release, gap"),
            })
            .collect();
        assert_eq!(pressed, expected);

        let compiled = compile_input_sequence(&input(vec![InputAction::Text {
            value: text,
            timing: None,
        }]))
        .unwrap();
        let gestures: Vec<KeyboardReport> = compiled
            .gestures
            .iter()
            .map(|gesture| match gesture {
                InputGesture::Keyboard { report, .. } => *report,
                _ => panic!("text compiles to keyboard gestures only"),
            })
            .collect();
        assert_eq!(gestures, expected);

        let usages: BTreeSet<u8> = pressed.iter().map(|report| report.keys[0]).collect();
        assert!(usages.contains(&0x35), "grave/tilde uses GRAVE_ACCENT");
        assert!(usages.contains(&0x31), "backslash/pipe uses BACKSLASH");
        assert!(!usages.contains(&0x32), "NON_US_HASH is never used");
        assert!(!usages.contains(&0x64), "NON_US_BACKSLASH is never used");
        assert!(pressed
            .iter()
            .all(|report| report.modifiers & !MOD_LEFT_SHIFT == 0));
    }

    #[test]
    fn alias_table_targets_registry_names_and_never_shadows_one() {
        let mut aliases = BTreeSet::new();
        for (alias, canonical) in KEY_ALIASES {
            assert!(aliases.insert(*alias), "alias listed twice");
            assert_eq!(*alias, alias.to_ascii_uppercase());
            assert_eq!(
                keyboard_key(alias),
                None,
                "alias must not be a registry name"
            );
            let key = keyboard_key(canonical).expect("alias target must be a registry name");
            assert_eq!(resolve_key_name(alias), Some(key));
            assert_eq!(resolve_key_name(&alias.to_ascii_lowercase()), None);
        }
        assert_eq!(KEYBOARD_KEYS.len(), 211);
        for key in KEYBOARD_KEYS {
            assert_eq!(resolve_key_name(key.name), Some(*key));
        }
        assert_eq!(keyboard_key("CMD"), None);
        assert_eq!(resolve_key_name("COMMAND").unwrap().code, MOD_LEFT_GUI);
        assert_eq!(resolve_key_name("RIGHT_CMD").unwrap().code, MOD_RIGHT_GUI);
        assert_eq!(resolve_key_name("OPT").unwrap().code, MOD_LEFT_ALT);
        assert_eq!(
            resolve_key_name("RIGHT_OPTION").unwrap().code,
            MOD_RIGHT_ALT
        );
        assert_eq!(resolve_key_name("cmd"), None);
    }

    #[test]
    fn protocol_doc_lists_exactly_the_alias_table() {
        let doc = include_str!("../../../protocol/input-sequence-v1.md");
        let section = doc
            .split("## Key names")
            .nth(1)
            .expect("key names section")
            .split("\n## ")
            .next()
            .unwrap();
        let mut listed = BTreeSet::new();
        for row in section.lines().filter(|line| line.starts_with("| `")) {
            let cells: Vec<&str> = row.split('|').map(str::trim).collect();
            let canonical = cells[2].trim_matches('`');
            for alias in cells[1].split(',') {
                listed.insert((alias.trim().trim_matches('`'), canonical));
            }
        }
        let table: BTreeSet<(&str, &str)> = KEY_ALIASES.iter().copied().collect();
        assert_eq!(listed, table);
    }

    #[test]
    fn every_alias_compiles_identically_to_its_canonical_key_in_both_compilers() {
        let keyboard = |key: &str| {
            sequence(vec![
                SequenceAction::Tap {
                    key: key.to_owned(),
                    timing: None,
                },
                SequenceAction::Chord {
                    keys: names(&[key, "F13"]),
                    timing: None,
                },
                SequenceAction::OrderedChord {
                    keys: names(&["F14", key]),
                    timing: None,
                },
            ])
        };
        let mixed = |key: &str| {
            input(vec![
                InputAction::Tap {
                    key: key.to_owned(),
                    timing: None,
                },
                InputAction::Chord {
                    keys: names(&[key, "F13"]),
                    timing: None,
                },
                InputAction::OrderedChord {
                    keys: names(&["F14", key]),
                    timing: None,
                },
            ])
        };
        for (alias, canonical) in KEY_ALIASES {
            assert_eq!(
                compile_sequence(&keyboard(alias)).unwrap(),
                compile_sequence(&keyboard(canonical)).unwrap()
            );
            let aliased = compile_input_sequence(&mixed(alias)).unwrap();
            let expected = compile_input_sequence(&mixed(canonical)).unwrap();
            assert_eq!(aliased.chunks, expected.chunks);
            assert_eq!(aliased.fingerprint, expected.fingerprint);
        }
    }

    #[test]
    fn chords_deduplicate_on_the_resolved_key_in_both_compilers() {
        for keys in [
            ["LEFT_GUI", "COMMAND"],
            ["OPTION", "LEFT_ALT"],
            ["CMD", "WIN"],
            ["RIGHT_OPT", "RIGHT_ALT"],
            ["ESC", "ESCAPE"],
        ] {
            let keys = names(&keys);
            assert_eq!(
                compile_sequence(&sequence(vec![SequenceAction::Chord {
                    keys: keys.clone(),
                    timing: None,
                }])),
                Err(SequenceError::DuplicateChordKey)
            );
            assert_eq!(
                compile_sequence(&sequence(vec![SequenceAction::OrderedChord {
                    keys: keys.clone(),
                    timing: None,
                }])),
                Err(SequenceError::DuplicateChordKey)
            );
            assert_eq!(
                compile_input_sequence(&input(vec![InputAction::Chord {
                    keys: keys.clone(),
                    timing: None,
                }])),
                Err(InputError::DuplicateChordKey)
            );
            assert_eq!(
                compile_input_sequence(&input(vec![InputAction::OrderedChord {
                    keys,
                    timing: None,
                }])),
                Err(InputError::DuplicateChordKey)
            );
        }
        let sides = compile_sequence(&sequence(vec![SequenceAction::Chord {
            keys: names(&["LEFT_CMD", "RIGHT_CMD"]),
            timing: None,
        }]))
        .unwrap();
        assert_eq!(
            sides.steps[0],
            ReportStep::Report(
                KeyboardReport::from_keys(MOD_LEFT_GUI | MOD_RIGHT_GUI, &[]).unwrap()
            )
        );
    }

    #[test]
    fn canonicalizing_aliases_rewrites_names_without_changing_the_plan() {
        let keyboard = |tap: &str, chord: [&str; 3], ordered: [&str; 2], leaf: [&str; 2]| {
            sequence(vec![
                SequenceAction::Tap {
                    key: tap.to_owned(),
                    timing: None,
                },
                SequenceAction::Chord {
                    keys: names(&chord),
                    timing: None,
                },
                SequenceAction::OrderedChord {
                    keys: names(&ordered),
                    timing: None,
                },
                SequenceAction::Repeat {
                    count: 2,
                    actions: vec![
                        SequenceLeafAction::Tap {
                            key: leaf[0].to_owned(),
                            timing: None,
                        },
                        SequenceLeafAction::Chord {
                            keys: names(&[leaf[1], "R"]),
                            timing: None,
                        },
                        SequenceLeafAction::Text {
                            value: "CMD".to_owned(),
                            timing: None,
                        },
                    ],
                },
            ])
        };
        let mut aliased = keyboard(
            "CMD",
            ["COMMAND", "OPT", "SPACE"],
            ["CTRL", "ESC"],
            ["RETURN", "WIN"],
        );
        let canonical = keyboard(
            "LEFT_GUI",
            ["LEFT_GUI", "LEFT_ALT", "SPACE"],
            ["LEFT_CONTROL", "ESCAPE"],
            ["ENTER", "LEFT_GUI"],
        );
        let before = compile_sequence(&aliased).unwrap();
        canonicalize_sequence_keys(&mut aliased);
        assert_eq!(aliased, canonical);
        assert_eq!(compile_sequence(&aliased).unwrap(), before);

        let mixed = |tap: &str, chord: [&str; 2], leaf: &str| {
            input(vec![
                InputAction::Tap {
                    key: tap.to_owned(),
                    timing: None,
                },
                InputAction::OrderedChord {
                    keys: names(&chord),
                    timing: None,
                },
                InputAction::Repeat {
                    count: 2,
                    actions: vec![
                        InputLeafAction::Chord {
                            keys: names(&[leaf, "TAB"]),
                            timing: None,
                        },
                        InputLeafAction::Click {
                            button: ClickButton::Button1,
                            hold_ms: None,
                            release_gap_ms: None,
                        },
                    ],
                },
            ])
        };
        let mut aliased = mixed("OPTION", ["RIGHT_COMMAND", "SHIFT"], "ALT");
        let canonical = mixed("LEFT_ALT", ["RIGHT_GUI", "LEFT_SHIFT"], "LEFT_ALT");
        let before = compile_input_sequence(&aliased).unwrap();
        canonicalize_input_sequence_keys(&mut aliased);
        assert_eq!(aliased, canonical);
        let after = compile_input_sequence(&aliased).unwrap();
        assert_eq!(after.chunks, before.chunks);
        assert_eq!(after.fingerprint, before.fingerprint);

        let mut unknown = sequence(vec![SequenceAction::Tap {
            key: "cmd".to_owned(),
            timing: None,
        }]);
        canonicalize_sequence_keys(&mut unknown);
        assert_eq!(
            unknown.actions,
            vec![SequenceAction::Tap {
                key: "cmd".to_owned(),
                timing: None,
            }]
        );
        assert_eq!(compile_sequence(&unknown), Err(SequenceError::UnknownKey));
    }

    #[test]
    fn legacy_chord_modifiers_derive_from_the_alias_table() {
        for (name, bit) in [
            ("ctrl", MOD_LEFT_CTRL),
            ("CONTROL", MOD_LEFT_CTRL),
            ("shift", MOD_LEFT_SHIFT),
            ("Alt", MOD_LEFT_ALT),
            ("option", MOD_LEFT_ALT),
            ("gui", MOD_LEFT_GUI),
            ("meta", MOD_LEFT_GUI),
            ("win", MOD_LEFT_GUI),
            ("super", MOD_LEFT_GUI),
            ("cmd", MOD_LEFT_GUI),
            ("command", MOD_LEFT_GUI),
            ("opt", MOD_LEFT_ALT),
            ("right_cmd", MOD_RIGHT_GUI),
            ("RIGHT_OPTION", MOD_RIGHT_ALT),
            ("left_shift", MOD_LEFT_SHIFT),
            ("RIGHT_CONTROL", MOD_RIGHT_CTRL),
        ] {
            assert_eq!(
                chord_from_names(&[name, "l"]).unwrap(),
                Keystroke {
                    modifiers: bit,
                    usage: 0x0f
                }
            );
        }
        for (alias, canonical) in KEY_ALIASES {
            let key = keyboard_key(canonical).unwrap();
            if key.class == KeyClass::Modifier {
                assert_eq!(
                    chord_from_names(&[alias.to_ascii_lowercase().as_str(), "l"])
                        .unwrap()
                        .modifiers,
                    key.code
                );
            }
        }
        assert_eq!(stroke_for_key_name("return").unwrap().usage, 0x28);
        assert_eq!(stroke_for_key_name("Esc").unwrap().usage, 0x29);
        assert_eq!(stroke_for_key_name("backspace").unwrap().usage, 0x2a);
        assert_eq!(stroke_for_key_name("space").unwrap().usage, 0x2c);
        assert_eq!(stroke_for_key_name("CMD"), Err(LayoutError::UnknownKeyName));
        assert_eq!(
            chord_from_names(&["cmd"]),
            Err(LayoutError::ChordNeedsExactlyOneKey)
        );
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
