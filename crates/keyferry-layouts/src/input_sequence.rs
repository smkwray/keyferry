use super::{
    keyboard_key, ordered_reports, plan_text_us, KeyClass, KeyboardReport, LayoutError,
    ReportError, ReportStep, TypingTiming, MAX_ORDERED_CHORD_KEYS, ORDERED_PRESS_MS,
    ORDERED_RELEASE_MS,
};
use keyferry_protocol::{action, arm_policy};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt};
use uuid::Version;

pub const INPUT_SEQUENCE_SCHEMA_V1: &str = "keyferry.input-sequence.v1";
pub const MAX_INPUT_BYTES: usize = 65_536;
pub const MAX_INPUT_DEPTH: usize = 8;
pub const MAX_INPUT_SOURCE_NODES: usize = 256;
pub const MAX_INPUT_TEXT_CHARACTERS: usize = 4096;
pub const MAX_INPUT_EFFECTS: usize = 4096;
pub const MAX_INPUT_REPEAT: u64 = 1000;
pub const MAX_INPUT_WAIT_MS: u64 = 10_000;
pub const MAX_INPUT_PLANNED_MS: u64 = 60_000;
pub const MAX_INPUT_CHUNKS: usize = 256;
pub const MAX_INPUT_ACTION_RECORDS: usize = 64;
pub const MAX_INPUT_ACTION_BYTES: usize = 183;
pub const MAX_INPUT_CHUNK_MS: u64 = 500;
const NEUTRAL_RECORD_BYTES: usize = 2;
const NEUTRAL_COST_MS: u64 = 20;
const DEFAULT_CLICK_MS: u64 = 40;
const FINGERPRINT_DOMAIN: &[u8] = b"keyferry.input-sequence.v1\0hid-relative-8-v1\0";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InputArmPolicy {
    CommandScoped,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputKeyboardTiming {
    pub key_down_ms: u64,
    pub release_gap_ms: u64,
}

impl InputKeyboardTiming {
    pub const DESKTOP_SAFE: Self = Self {
        key_down_ms: 12,
        release_gap_ms: 40,
    };

    fn validated(self) -> Result<TypingTiming, InputError> {
        if !(5..=100).contains(&self.key_down_ms) || !(5..=100).contains(&self.release_gap_ms) {
            return Err(InputError::Timing);
        }
        Ok(TypingTiming {
            key_down_ms: self.key_down_ms as u16,
            release_gap_ms: self.release_gap_ms as u16,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClickButton {
    #[serde(rename = "button_1")]
    Button1,
    #[serde(rename = "button_2")]
    Button2,
}

impl ClickButton {
    #[must_use]
    pub const fn usage(self) -> u8 {
        match self {
            Self::Button1 => 1,
            Self::Button2 => 2,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputSequenceV1 {
    pub schema: String,
    pub command_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard_profile: Option<String>,
    pub arm: InputArmPolicy,
    pub start_within_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard_timing: Option<InputKeyboardTiming>,
    pub actions: Vec<InputAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputAction {
    Text {
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Tap {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Chord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    OrderedChord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Wait {
        ms: u64,
    },
    Repeat {
        count: u64,
        actions: Vec<InputLeafAction>,
    },
    MoveRelative {
        dx_counts: i64,
        dy_counts: i64,
    },
    Click {
        button: ClickButton,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hold_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        release_gap_ms: Option<u64>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputLeafAction {
    Text {
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Tap {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Chord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    OrderedChord {
        keys: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timing: Option<InputKeyboardTiming>,
    },
    Wait {
        ms: u64,
    },
    MoveRelative {
        dx_counts: i64,
        dy_counts: i64,
    },
    Click {
        button: ClickButton,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hold_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        release_gap_ms: Option<u64>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MouseDelta {
    pub dx: i8,
    pub dy: i8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InputGesture {
    Keyboard {
        report: KeyboardReport,
        timing: TypingTiming,
    },
    OrderedChord {
        reports: Vec<KeyboardReport>,
        timing: TypingTiming,
    },
    Wait {
        ms: u16,
    },
    MoveRelative {
        dx_counts: i16,
        dy_counts: i16,
        deltas: Vec<MouseDelta>,
    },
    Click {
        button: ClickButton,
        hold_ms: u16,
        release_gap_ms: u16,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputChunk {
    pub index: u16,
    pub count: u16,
    pub body: Vec<u8>,
    pub action_records: usize,
    pub planned_ms: u16,
    pub effectful: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledInputSequence {
    pub gestures: Vec<InputGesture>,
    pub chunks: Vec<InputChunk>,
    pub fingerprint: [u8; 32],
    pub source_nodes: usize,
    pub text_characters: usize,
    pub effectful_gestures: usize,
    pub planned_ms: u64,
    pub has_keyboard: bool,
    pub has_pointer: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    Json,
    DuplicateField,
    UnknownField,
    Schema,
    CommandId,
    IntegerRequired,
    ActionType,
    ArmPolicy,
    KeyboardProfile,
    StartDeadline,
    Limit,
    NoEffect,
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
    PointerRange,
    PointerNoEffect,
    PointerButton,
    PointerTiming,
    PointerOutOfScope,
}

impl InputError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Json => "input.json",
            Self::DuplicateField => "input.duplicate_field",
            Self::UnknownField => "input.unknown_field",
            Self::Schema => "input.schema",
            Self::CommandId => "input.command_id",
            Self::IntegerRequired => "input.integer_required",
            Self::ActionType => "input.action_type",
            Self::ArmPolicy => "input.arm_policy",
            Self::KeyboardProfile => "input.keyboard_profile",
            Self::StartDeadline => "input.start_deadline",
            Self::Limit => "input.limit",
            Self::NoEffect => "input.no_effect",
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
            Self::PointerRange => "pointer.range",
            Self::PointerNoEffect => "pointer.no_effect",
            Self::PointerButton => "pointer.button",
            Self::PointerTiming => "pointer.timing",
            Self::PointerOutOfScope => "pointer.out_of_scope",
        }
    }
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for InputError {}

#[derive(Debug)]
struct UniqueJson(serde_json::Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            values.push(value.0);
        }
        Ok(UniqueJson(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom("duplicate JSON field"));
            }
        }
        Ok(UniqueJson(serde_json::Value::Object(values)))
    }
}

pub fn parse_input_sequence_json(bytes: &[u8]) -> Result<InputSequenceV1, InputError> {
    finish_input_sequence_json(parse_input_sequence_value(bytes)?)
}

pub fn parse_input_sequence_json_with_command_id(
    bytes: &[u8],
    command_id: &str,
) -> Result<InputSequenceV1, InputError> {
    let mut value = parse_input_sequence_value(bytes)?;
    let object = value.as_object_mut().ok_or(InputError::Json)?;
    object
        .entry("command_id")
        .or_insert_with(|| serde_json::Value::String(command_id.to_owned()));
    finish_input_sequence_json(value)
}

fn parse_input_sequence_value(bytes: &[u8]) -> Result<serde_json::Value, InputError> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(InputError::Limit);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJson::deserialize(&mut deserializer).map_err(|error| {
        if error.to_string().contains("duplicate JSON field") {
            InputError::DuplicateField
        } else {
            InputError::Json
        }
    })?;
    deserializer.end().map_err(|_| InputError::Json)?;
    validate_json_tree(&value.0, 1)?;
    Ok(value.0)
}

fn finish_input_sequence_json(value: serde_json::Value) -> Result<InputSequenceV1, InputError> {
    validate_shape(&value)?;
    serde_json::from_value(value).map_err(|_| InputError::Json)
}

fn validate_json_tree(value: &serde_json::Value, depth: usize) -> Result<(), InputError> {
    if depth > MAX_INPUT_DEPTH {
        return Err(InputError::Limit);
    }
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                validate_json_tree(value, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values() {
                validate_json_tree(value, depth + 1)?;
            }
        }
        serde_json::Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            return Err(InputError::IntegerRequired);
        }
        _ => {}
    }
    Ok(())
}

fn validate_shape(value: &serde_json::Value) -> Result<(), InputError> {
    let object = value.as_object().ok_or(InputError::Json)?;
    reject_unknown(
        object,
        &[
            "schema",
            "command_id",
            "keyboard_profile",
            "arm",
            "start_within_ms",
            "keyboard_timing",
            "actions",
        ],
    )?;
    reject_null(object, &["keyboard_profile", "keyboard_timing"])?;
    if object
        .get("arm")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value != "command-scoped")
    {
        return Err(InputError::ArmPolicy);
    }
    if let Some(profile) = object
        .get("keyboard_profile")
        .and_then(serde_json::Value::as_str)
    {
        if profile != "windows-us" {
            return Err(InputError::KeyboardProfile);
        }
    }
    if let Some(timing) = object.get("keyboard_timing") {
        validate_timing_shape(timing)?;
    }
    let actions = object
        .get("actions")
        .and_then(serde_json::Value::as_array)
        .ok_or(InputError::Json)?;
    for action in actions {
        validate_action_shape(action, true)?;
    }
    Ok(())
}

fn validate_timing_shape(value: &serde_json::Value) -> Result<(), InputError> {
    let object = value.as_object().ok_or(InputError::Json)?;
    reject_unknown(object, &["key_down_ms", "release_gap_ms"])
}

fn validate_action_shape(value: &serde_json::Value, allow_repeat: bool) -> Result<(), InputError> {
    let object = value.as_object().ok_or(InputError::Json)?;
    let action_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or(InputError::Json)?;
    match action_type {
        "text" => {
            reject_unknown(object, &["type", "value", "timing"])?;
            reject_null(object, &["timing"])?;
        }
        "tap" => {
            reject_unknown(object, &["type", "key", "timing"])?;
            reject_null(object, &["timing"])?;
        }
        "chord" => {
            reject_unknown(object, &["type", "keys", "timing"])?;
            reject_null(object, &["timing"])?;
        }
        "ordered_chord" => {
            reject_unknown(object, &["type", "keys", "timing"])?;
            reject_null(object, &["timing"])?;
        }
        "wait" => reject_unknown(object, &["type", "ms"])?,
        "move_relative" => reject_unknown(object, &["type", "dx_counts", "dy_counts"])?,
        "click" => {
            reject_unknown(object, &["type", "button", "hold_ms", "release_gap_ms"])?;
            reject_null(object, &["hold_ms", "release_gap_ms"])?;
            if object
                .get("button")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|button| button != "button_1" && button != "button_2")
            {
                return Err(InputError::PointerButton);
            }
        }
        "repeat" if allow_repeat => {
            reject_unknown(object, &["type", "count", "actions"])?;
            let actions = object
                .get("actions")
                .and_then(serde_json::Value::as_array)
                .ok_or(InputError::Json)?;
            for action in actions {
                validate_action_shape(action, false)?;
            }
        }
        "move_absolute" | "double_click" | "scroll" | "drag" | "button_down" | "button_up"
        | "mouse_report" => return Err(InputError::PointerOutOfScope),
        _ => return Err(InputError::ActionType),
    }
    if let Some(timing) = object.get("timing") {
        validate_timing_shape(timing)?;
    }
    Ok(())
}

fn reject_unknown(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
) -> Result<(), InputError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(InputError::UnknownField);
    }
    Ok(())
}

fn reject_null(
    object: &serde_json::Map<String, serde_json::Value>,
    optional: &[&str],
) -> Result<(), InputError> {
    if optional
        .iter()
        .any(|field| object.get(*field).is_some_and(serde_json::Value::is_null))
    {
        return Err(InputError::Json);
    }
    Ok(())
}

struct CompileState {
    gestures: Vec<InputGesture>,
    source_nodes: usize,
    text_characters: usize,
    effectful_gestures: usize,
    has_keyboard: bool,
    has_pointer: bool,
}

enum Leaf<'a> {
    Text(&'a str, Option<InputKeyboardTiming>),
    Tap(&'a str, Option<InputKeyboardTiming>),
    Chord(&'a [String], Option<InputKeyboardTiming>),
    OrderedChord(&'a [String], Option<InputKeyboardTiming>),
    Wait(u64),
    MoveRelative(i64, i64),
    Click(ClickButton, Option<u64>, Option<u64>),
}

pub fn compile_input_sequence(
    request: &InputSequenceV1,
) -> Result<CompiledInputSequence, InputError> {
    if request.schema != INPUT_SEQUENCE_SCHEMA_V1 {
        return Err(InputError::Schema);
    }
    let command_id =
        uuid::Uuid::parse_str(&request.command_id).map_err(|_| InputError::CommandId)?;
    if command_id.get_version() != Some(Version::SortRand)
        || command_id.to_string() != request.command_id
    {
        return Err(InputError::CommandId);
    }
    if request.arm != InputArmPolicy::CommandScoped {
        return Err(InputError::ArmPolicy);
    }
    if !(1..=5000).contains(&request.start_within_ms) {
        return Err(InputError::StartDeadline);
    }
    if request.actions.is_empty() || request.actions.len() > MAX_INPUT_SOURCE_NODES {
        return Err(InputError::Limit);
    }
    let default_timing = request
        .keyboard_timing
        .unwrap_or(InputKeyboardTiming::DESKTOP_SAFE);
    let mut state = CompileState {
        gestures: Vec::new(),
        source_nodes: request.actions.len(),
        text_characters: 0,
        effectful_gestures: 0,
        has_keyboard: false,
        has_pointer: false,
    };
    for action in &request.actions {
        match action {
            InputAction::Text { value, timing } => {
                compile_leaf(&mut state, Leaf::Text(value, *timing), default_timing)?
            }
            InputAction::Tap { key, timing } => {
                compile_leaf(&mut state, Leaf::Tap(key, *timing), default_timing)?
            }
            InputAction::Chord { keys, timing } => {
                compile_leaf(&mut state, Leaf::Chord(keys, *timing), default_timing)?
            }
            InputAction::OrderedChord { keys, timing } => compile_leaf(
                &mut state,
                Leaf::OrderedChord(keys, *timing),
                default_timing,
            )?,
            InputAction::Wait { ms } => compile_leaf(&mut state, Leaf::Wait(*ms), default_timing)?,
            InputAction::MoveRelative {
                dx_counts,
                dy_counts,
            } => compile_leaf(
                &mut state,
                Leaf::MoveRelative(*dx_counts, *dy_counts),
                default_timing,
            )?,
            InputAction::Click {
                button,
                hold_ms,
                release_gap_ms,
            } => compile_leaf(
                &mut state,
                Leaf::Click(*button, *hold_ms, *release_gap_ms),
                default_timing,
            )?,
            InputAction::Repeat { count, actions } => {
                if !(1..=MAX_INPUT_REPEAT).contains(count) || actions.is_empty() {
                    return Err(InputError::Repeat);
                }
                state.source_nodes = state.source_nodes.saturating_add(actions.len());
                if state.source_nodes > MAX_INPUT_SOURCE_NODES {
                    return Err(InputError::Limit);
                }
                for _ in 0..*count {
                    for action in actions {
                        let leaf = match action {
                            InputLeafAction::Text { value, timing } => Leaf::Text(value, *timing),
                            InputLeafAction::Tap { key, timing } => Leaf::Tap(key, *timing),
                            InputLeafAction::Chord { keys, timing } => Leaf::Chord(keys, *timing),
                            InputLeafAction::OrderedChord { keys, timing } => {
                                Leaf::OrderedChord(keys, *timing)
                            }
                            InputLeafAction::Wait { ms } => Leaf::Wait(*ms),
                            InputLeafAction::MoveRelative {
                                dx_counts,
                                dy_counts,
                            } => Leaf::MoveRelative(*dx_counts, *dy_counts),
                            InputLeafAction::Click {
                                button,
                                hold_ms,
                                release_gap_ms,
                            } => Leaf::Click(*button, *hold_ms, *release_gap_ms),
                        };
                        compile_leaf(&mut state, leaf, default_timing)?;
                    }
                }
            }
        }
    }
    if state.effectful_gestures == 0 {
        return Err(InputError::NoEffect);
    }
    match (state.has_keyboard, request.keyboard_profile.as_deref()) {
        (true, Some("windows-us")) => {}
        (true, _) | (false, Some(_)) => return Err(InputError::KeyboardProfile),
        (false, None) => {
            if request.keyboard_timing.is_some() {
                return Err(InputError::KeyboardProfile);
            }
        }
    }
    let (chunks, planned_ms) = packetize(&state.gestures)?;
    let profile = if state.has_keyboard {
        "windows-us"
    } else {
        "none"
    };
    let fingerprint = fingerprint(request.start_within_ms, profile, &chunks);
    Ok(CompiledInputSequence {
        gestures: state.gestures,
        chunks,
        fingerprint,
        source_nodes: state.source_nodes,
        text_characters: state.text_characters,
        effectful_gestures: state.effectful_gestures,
        planned_ms,
        has_keyboard: state.has_keyboard,
        has_pointer: state.has_pointer,
    })
}

fn compile_leaf(
    state: &mut CompileState,
    leaf: Leaf<'_>,
    default_timing: InputKeyboardTiming,
) -> Result<(), InputError> {
    match leaf {
        Leaf::Text(value, timing) => {
            if value.is_empty() {
                return Err(InputError::NoEffect);
            }
            let count = value.chars().count();
            state.text_characters = state.text_characters.saturating_add(count);
            if state.text_characters > MAX_INPUT_TEXT_CHARACTERS {
                return Err(InputError::TextCharacterLimit);
            }
            let timing = timing.unwrap_or(default_timing).validated()?;
            let steps = plan_text_us(value, timing).map_err(|error| match error {
                LayoutError::UnsupportedCharacter(_) => InputError::UnsupportedCharacter,
                _ => InputError::Timing,
            })?;
            for gesture in steps.chunks_exact(4) {
                let ReportStep::Report(report) = gesture[0] else {
                    return Err(InputError::Limit);
                };
                push_effect(
                    state,
                    InputGesture::Keyboard { report, timing },
                    true,
                    false,
                )?;
            }
        }
        Leaf::Tap(name, timing) => {
            let timing = timing.unwrap_or(default_timing).validated()?;
            let key = input_key(name)?;
            let report = match key.class {
                KeyClass::Modifier => KeyboardReport::from_keys(key.code, &[]),
                KeyClass::NonModifier => KeyboardReport::from_keys(0, &[key.code]),
            }
            .map_err(|_| InputError::RolloverLimit)?;
            push_effect(
                state,
                InputGesture::Keyboard { report, timing },
                true,
                false,
            )?;
        }
        Leaf::Chord(names, timing) => {
            if !(2..=14).contains(&names.len()) {
                return Err(InputError::ChordSize);
            }
            let timing = timing.unwrap_or(default_timing).validated()?;
            let mut modifiers = 0_u8;
            let mut usages = Vec::with_capacity(6);
            let mut seen = HashSet::with_capacity(names.len());
            for name in names {
                if !seen.insert(name.as_str()) {
                    return Err(InputError::DuplicateChordKey);
                }
                let key = input_key(name)?;
                match key.class {
                    KeyClass::Modifier => modifiers |= key.code,
                    KeyClass::NonModifier => usages.push(key.code),
                }
            }
            let report =
                KeyboardReport::from_keys(modifiers, &usages).map_err(|error| match error {
                    ReportError::RolloverLimit => InputError::RolloverLimit,
                    ReportError::DuplicateUsage => InputError::DuplicateChordKey,
                    ReportError::ZeroUsage => InputError::UnknownKey,
                })?;
            push_effect(
                state,
                InputGesture::Keyboard { report, timing },
                true,
                false,
            )?;
        }
        Leaf::OrderedChord(names, timing) => {
            if !(2..=MAX_ORDERED_CHORD_KEYS).contains(&names.len()) {
                return Err(InputError::ChordSize);
            }
            let timing = timing.unwrap_or(default_timing).validated()?;
            let mut seen = HashSet::with_capacity(names.len());
            let mut keys = Vec::with_capacity(names.len());
            for name in names {
                if !seen.insert(name.as_str()) {
                    return Err(InputError::DuplicateChordKey);
                }
                keys.push(input_key(name)?);
            }
            let reports = ordered_reports(&keys).map_err(|error| match error {
                ReportError::RolloverLimit => InputError::RolloverLimit,
                ReportError::DuplicateUsage => InputError::DuplicateChordKey,
                ReportError::ZeroUsage => InputError::UnknownKey,
            })?;
            push_effect(
                state,
                InputGesture::OrderedChord { reports, timing },
                true,
                false,
            )?;
        }
        Leaf::Wait(ms) => {
            if !(1..=MAX_INPUT_WAIT_MS).contains(&ms) {
                return Err(InputError::Wait);
            }
            let mut remaining = ms;
            while remaining != 0 {
                let part = remaining.min(100) as u16;
                state.gestures.push(InputGesture::Wait { ms: part });
                remaining -= u64::from(part);
            }
        }
        Leaf::MoveRelative(dx, dy) => {
            if !(-4096..=4096).contains(&dx) || !(-4096..=4096).contains(&dy) {
                return Err(InputError::PointerRange);
            }
            if dx == 0 && dy == 0 {
                return Err(InputError::PointerNoEffect);
            }
            let dx = dx as i16;
            let dy = dy as i16;
            let deltas = split_movement(dx, dy);
            push_effect(
                state,
                InputGesture::MoveRelative {
                    dx_counts: dx,
                    dy_counts: dy,
                    deltas,
                },
                false,
                true,
            )?;
        }
        Leaf::Click(button, hold_ms, release_gap_ms) => {
            let hold_ms = hold_ms.unwrap_or(DEFAULT_CLICK_MS);
            let release_gap_ms = release_gap_ms.unwrap_or(DEFAULT_CLICK_MS);
            if !(10..=100).contains(&hold_ms) || !(10..=100).contains(&release_gap_ms) {
                return Err(InputError::PointerTiming);
            }
            push_effect(
                state,
                InputGesture::Click {
                    button,
                    hold_ms: hold_ms as u16,
                    release_gap_ms: release_gap_ms as u16,
                },
                false,
                true,
            )?;
        }
    }
    Ok(())
}

fn input_key(name: &str) -> Result<super::KeyboardKey, InputError> {
    if let Some(key) = keyboard_key(name) {
        return Ok(key);
    }
    match name {
        "POWER" | "MUTE" | "VOLUME_UP" | "VOLUME_DOWN" => Err(InputError::KeyOutOfScope),
        _ => Err(InputError::UnknownKey),
    }
}

fn push_effect(
    state: &mut CompileState,
    gesture: InputGesture,
    keyboard: bool,
    pointer: bool,
) -> Result<(), InputError> {
    state.effectful_gestures = state.effectful_gestures.saturating_add(1);
    if state.effectful_gestures > MAX_INPUT_EFFECTS {
        return Err(InputError::Limit);
    }
    state.has_keyboard |= keyboard;
    state.has_pointer |= pointer;
    state.gestures.push(gesture);
    Ok(())
}

#[must_use]
pub fn split_movement(dx: i16, dy: i16) -> Vec<MouseDelta> {
    let maximum = i32::from(dx).abs().max(i32::from(dy).abs());
    if maximum == 0 {
        return Vec::new();
    }
    let count = (maximum + 126) / 127;
    (1..=count)
        .map(|index| MouseDelta {
            dx: split_axis(i32::from(dx), index, count),
            dy: split_axis(i32::from(dy), index, count),
        })
        .collect()
}

fn split_axis(value: i32, index: i32, count: i32) -> i8 {
    let magnitude = value.abs();
    let current = index * magnitude / count;
    let previous = (index - 1) * magnitude / count;
    let part = (current - previous) * value.signum();
    i8::try_from(part).expect("movement split is bounded to signed 8-bit reports")
}

struct EncodedUnit {
    records: Vec<Vec<u8>>,
    cost_ms: u64,
    effectful: bool,
}

fn packetize(gestures: &[InputGesture]) -> Result<(Vec<InputChunk>, u64), InputError> {
    let mut units = Vec::with_capacity(gestures.len());
    for gesture in gestures {
        units.push(encode_unit(gesture));
    }
    let mut raw_chunks: Vec<(Vec<Vec<u8>>, u64, bool)> = Vec::new();
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut bytes = 0_usize;
    let mut cost = 0_u64;
    let mut effectful = false;
    for unit in units {
        let unit_bytes = unit.records.iter().map(Vec::len).sum::<usize>();
        let fits = records.len() + unit.records.len() < MAX_INPUT_ACTION_RECORDS
            && bytes + unit_bytes + NEUTRAL_RECORD_BYTES <= MAX_INPUT_ACTION_BYTES
            && cost + unit.cost_ms + NEUTRAL_COST_MS <= MAX_INPUT_CHUNK_MS;
        if !fits && !records.is_empty() {
            raw_chunks.push((std::mem::take(&mut records), cost, effectful));
            bytes = 0;
            cost = 0;
            effectful = false;
        }
        if unit.records.len() >= MAX_INPUT_ACTION_RECORDS
            || unit_bytes + NEUTRAL_RECORD_BYTES > MAX_INPUT_ACTION_BYTES
            || unit.cost_ms + NEUTRAL_COST_MS > MAX_INPUT_CHUNK_MS
        {
            return Err(InputError::Limit);
        }
        bytes += unit_bytes;
        cost += unit.cost_ms;
        effectful |= unit.effectful;
        records.extend(unit.records);
    }
    if !records.is_empty() {
        raw_chunks.push((records, cost, effectful));
    }
    if raw_chunks.is_empty() || raw_chunks.len() > MAX_INPUT_CHUNKS {
        return Err(InputError::Limit);
    }
    let count = raw_chunks.len() as u16;
    let mut chunks = Vec::with_capacity(raw_chunks.len());
    let mut planned_ms = 0_u64;
    for (index, (records, cost, effectful)) in raw_chunks.into_iter().enumerate() {
        let mut body = Vec::new();
        body.extend_from_slice(&(index as u16).to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        for record in &records {
            body.extend_from_slice(record);
        }
        body.extend_from_slice(&[action::NEUTRAL_ALL, 0]);
        let chunk_ms = cost + NEUTRAL_COST_MS;
        planned_ms = planned_ms.saturating_add(chunk_ms);
        chunks.push(InputChunk {
            index: index as u16,
            count,
            body,
            action_records: records.len() + 1,
            planned_ms: chunk_ms as u16,
            effectful,
        });
    }
    if planned_ms > MAX_INPUT_PLANNED_MS {
        return Err(InputError::Limit);
    }
    Ok((chunks, planned_ms))
}

fn encode_unit(gesture: &InputGesture) -> EncodedUnit {
    match gesture {
        InputGesture::Keyboard { report, timing } => {
            let usages: Vec<u8> = report
                .keys
                .iter()
                .copied()
                .filter(|usage| *usage != 0)
                .collect();
            if usages.len() == 1 {
                EncodedUnit {
                    records: vec![record(
                        action::TAP_KEY,
                        &[
                            report.modifiers,
                            usages[0],
                            timing.key_down_ms.to_le_bytes()[0],
                            timing.key_down_ms.to_le_bytes()[1],
                            timing.release_gap_ms.to_le_bytes()[0],
                            timing.release_gap_ms.to_le_bytes()[1],
                        ],
                    )],
                    cost_ms: 20 + u64::from(timing.key_down_ms + timing.release_gap_ms),
                    effectful: true,
                }
            } else {
                let mut payload = Vec::with_capacity(8);
                payload.push(report.modifiers);
                payload.push(0);
                payload.extend_from_slice(&report.keys);
                EncodedUnit {
                    records: vec![
                        record(action::KEY_REPORT, &payload),
                        record(action::WAIT_MS, &timing.key_down_ms.to_le_bytes()),
                        record(action::RELEASE_ALL_ACTION, &[]),
                        record(action::WAIT_MS, &timing.release_gap_ms.to_le_bytes()),
                    ],
                    cost_ms: 20 + u64::from(timing.key_down_ms + timing.release_gap_ms),
                    effectful: true,
                }
            }
        }
        InputGesture::OrderedChord { reports, timing } => {
            let mut records = Vec::with_capacity(reports.len() * 4);
            for (index, report) in reports.iter().enumerate() {
                records.push(key_report_record(report));
                let wait = if index + 1 == reports.len() {
                    timing.key_down_ms
                } else {
                    ORDERED_PRESS_MS
                };
                records.push(record(action::WAIT_MS, &wait.to_le_bytes()));
            }
            for report in reports[..reports.len() - 1].iter().rev() {
                records.push(key_report_record(report));
                records.push(record(action::WAIT_MS, &ORDERED_RELEASE_MS.to_le_bytes()));
            }
            records.push(record(action::RELEASE_ALL_ACTION, &[]));
            records.push(record(
                action::WAIT_MS,
                &timing.release_gap_ms.to_le_bytes(),
            ));
            EncodedUnit {
                records,
                cost_ms: 20
                    + (reports.len() as u64 - 1) * u64::from(ORDERED_PRESS_MS + ORDERED_RELEASE_MS)
                    + u64::from(timing.key_down_ms + timing.release_gap_ms),
                effectful: true,
            }
        }
        InputGesture::Wait { ms } => EncodedUnit {
            records: vec![record(action::WAIT_MS, &ms.to_le_bytes())],
            cost_ms: u64::from(*ms),
            effectful: false,
        },
        InputGesture::MoveRelative {
            dx_counts,
            dy_counts,
            deltas,
        } => {
            let mut payload = Vec::with_capacity(4);
            payload.extend_from_slice(&dx_counts.to_le_bytes());
            payload.extend_from_slice(&dy_counts.to_le_bytes());
            EncodedUnit {
                records: vec![record(action::MOUSE_MOVE_RELATIVE, &payload)],
                cost_ms: 10 * deltas.len() as u64,
                effectful: true,
            }
        }
        InputGesture::Click {
            button,
            hold_ms,
            release_gap_ms,
        } => {
            let mut payload = Vec::with_capacity(5);
            payload.push(button.usage());
            payload.extend_from_slice(&hold_ms.to_le_bytes());
            payload.extend_from_slice(&release_gap_ms.to_le_bytes());
            EncodedUnit {
                records: vec![record(action::MOUSE_CLICK, &payload)],
                cost_ms: 20 + u64::from(*hold_ms + *release_gap_ms),
                effectful: true,
            }
        }
    }
}

fn record(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(payload.len() + 2);
    record.push(tag);
    record.push(payload.len() as u8);
    record.extend_from_slice(payload);
    record
}

fn key_report_record(report: &KeyboardReport) -> Vec<u8> {
    let mut payload = [0_u8; 8];
    payload[0] = report.modifiers;
    payload[2..].copy_from_slice(&report.keys);
    record(action::KEY_REPORT, &payload)
}

fn fingerprint(start_within_ms: u64, profile: &str, chunks: &[InputChunk]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FINGERPRINT_DOMAIN);
    digest.update(Sha256::digest(profile.as_bytes()));
    digest.update((start_within_ms as u32).to_le_bytes());
    digest.update([arm_policy::COMMAND_SCOPED]);
    digest.update((chunks.len() as u16).to_le_bytes());
    for chunk in chunks {
        digest.update((chunk.body.len() as u16).to_le_bytes());
        digest.update(&chunk.body);
    }
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND_ID: &str = "01995fa0-0000-7000-8000-000000000001";

    fn request(actions: Vec<InputAction>, keyboard: bool) -> InputSequenceV1 {
        InputSequenceV1 {
            schema: INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: COMMAND_ID.to_owned(),
            keyboard_profile: keyboard.then(|| "windows-us".to_owned()),
            arm: InputArmPolicy::CommandScoped,
            start_within_ms: 5000,
            keyboard_timing: None,
            actions,
        }
    }

    #[test]
    fn strict_parser_rejects_duplicates_unknown_null_float_and_deferred_actions() {
        let duplicate =
            br#"{"schema":"keyferry.input-sequence.v1","schema":"keyferry.input-sequence.v1"}"#;
        assert_eq!(
            parse_input_sequence_json(duplicate),
            Err(InputError::DuplicateField)
        );

        let unknown = format!(
            r#"{{"schema":"{INPUT_SEQUENCE_SCHEMA_V1}","command_id":"{COMMAND_ID}","arm":"command-scoped","start_within_ms":5000,"actions":[{{"type":"click","button":"button_1","path":"secret"}}]}}"#
        );
        assert_eq!(
            parse_input_sequence_json(unknown.as_bytes()),
            Err(InputError::UnknownField)
        );

        let null = format!(
            r#"{{"schema":"{INPUT_SEQUENCE_SCHEMA_V1}","command_id":"{COMMAND_ID}","arm":"command-scoped","start_within_ms":5000,"actions":[{{"type":"click","button":"button_1","hold_ms":null}}]}}"#
        );
        assert_eq!(
            parse_input_sequence_json(null.as_bytes()),
            Err(InputError::Json)
        );

        let float = format!(
            r#"{{"schema":"{INPUT_SEQUENCE_SCHEMA_V1}","command_id":"{COMMAND_ID}","arm":"command-scoped","start_within_ms":5e3,"actions":[{{"type":"click","button":"button_1"}}]}}"#
        );
        assert_eq!(
            parse_input_sequence_json(float.as_bytes()),
            Err(InputError::IntegerRequired)
        );

        let drag = format!(
            r#"{{"schema":"{INPUT_SEQUENCE_SCHEMA_V1}","command_id":"{COMMAND_ID}","arm":"command-scoped","start_within_ms":5000,"actions":[{{"type":"drag"}}]}}"#
        );
        assert_eq!(
            parse_input_sequence_json(drag.as_bytes()),
            Err(InputError::PointerOutOfScope)
        );

        let generated = COMMAND_ID.to_owned();
        let without_id = br#"{"schema":"keyferry.input-sequence.v1","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"click","button":"button_1"}]}"#;
        assert_eq!(
            parse_input_sequence_json_with_command_id(without_id, &generated)
                .unwrap()
                .command_id,
            generated
        );
    }

    #[test]
    fn movement_splitting_is_exact_bounded_and_keeps_identical_reports() {
        assert_eq!(
            split_movement(240, -40),
            vec![
                MouseDelta { dx: 120, dy: -20 },
                MouseDelta { dx: 120, dy: -20 }
            ]
        );
        for value in [-4096_i16, -128, -127, -1, 1, 127, 128, 4096] {
            let reports = split_movement(value, -value);
            assert_eq!(
                reports
                    .iter()
                    .map(|report| i32::from(report.dx))
                    .sum::<i32>(),
                i32::from(value)
            );
            assert_eq!(
                reports
                    .iter()
                    .map(|report| i32::from(report.dy))
                    .sum::<i32>(),
                -i32::from(value)
            );
            assert!(reports
                .iter()
                .all(|report| report.dx != -128 && report.dy != -128));
        }
    }

    #[test]
    fn canonical_example_matches_the_decision_memo_body_and_cost() {
        let compiled = compile_input_sequence(&request(
            vec![
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
            true,
        ))
        .unwrap();
        assert_eq!(compiled.planned_ms, 212);
        assert_eq!(compiled.chunks.len(), 1);
        assert_eq!(
            compiled.chunks[0].body,
            vec![
                0x00, 0x00, 0x01, 0x00, 0x05, 0x04, 0xF0, 0x00, 0xD8, 0xFF, 0x06, 0x05, 0x01, 0x28,
                0x00, 0x28, 0x00, 0x04, 0x06, 0x00, 0x28, 0x0C, 0x00, 0x28, 0x00, 0x07, 0x00,
            ]
        );
    }

    #[test]
    fn profile_presence_and_pointer_bounds_fail_closed() {
        let pointer = request(
            vec![InputAction::Click {
                button: ClickButton::Button2,
                hold_ms: None,
                release_gap_ms: None,
            }],
            false,
        );
        assert!(compile_input_sequence(&pointer).is_ok());

        let mut wrong = pointer.clone();
        wrong.keyboard_profile = Some("windows-us".to_owned());
        assert_eq!(
            compile_input_sequence(&wrong),
            Err(InputError::KeyboardProfile)
        );

        assert_eq!(
            compile_input_sequence(&request(
                vec![InputAction::MoveRelative {
                    dx_counts: 0,
                    dy_counts: 0
                }],
                false
            )),
            Err(InputError::PointerNoEffect)
        );
        assert_eq!(
            compile_input_sequence(&request(
                vec![InputAction::MoveRelative {
                    dx_counts: 4097,
                    dy_counts: 0
                }],
                false
            )),
            Err(InputError::PointerRange)
        );
    }

    #[test]
    fn ordered_chord_is_one_bounded_neutral_terminated_unit() {
        let compiled = compile_input_sequence(&request(
            vec![InputAction::OrderedChord {
                keys: ["CAPS_LOCK", "SPACE", "J"]
                    .iter()
                    .map(|key| (*key).to_owned())
                    .collect(),
                timing: None,
            }],
            true,
        ))
        .unwrap();
        assert_eq!(compiled.chunks.len(), 1);
        let chunk = &compiled.chunks[0];
        assert!(chunk.action_records <= MAX_INPUT_ACTION_RECORDS);
        assert!(chunk.body.len() <= MAX_INPUT_ACTION_BYTES + 4);
        assert!(u64::from(chunk.planned_ms) <= MAX_INPUT_CHUNK_MS);
        assert!(chunk.body.ends_with(&[action::NEUTRAL_ALL, 0]));
        assert_eq!(chunk.action_records, 13);
    }

    #[test]
    fn repeat_normalization_and_chunk_bounds_are_deterministic() {
        let repeated = request(
            vec![InputAction::Repeat {
                count: 20,
                actions: vec![
                    InputLeafAction::MoveRelative {
                        dx_counts: 1,
                        dy_counts: 0,
                    },
                    InputLeafAction::Wait { ms: 100 },
                ],
            }],
            false,
        );
        let compiled = compile_input_sequence(&repeated).unwrap();
        assert_eq!(compiled.effectful_gestures, 20);
        assert!(compiled.chunks.len() > 1);
        assert!(compiled.chunks.iter().all(|chunk| {
            chunk.action_records <= MAX_INPUT_ACTION_RECORDS
                && chunk.body.len() <= MAX_INPUT_ACTION_BYTES + 4
                && u64::from(chunk.planned_ms) <= MAX_INPUT_CHUNK_MS
                && chunk.body.ends_with(&[action::NEUTRAL_ALL, 0])
        }));
        assert_eq!(
            compile_input_sequence(&repeated).unwrap().fingerprint,
            compiled.fingerprint
        );
    }

    #[test]
    fn payload_free_errors_cover_keyboard_and_click_limits() {
        let unsupported = request(
            vec![InputAction::Text {
                value: "café".to_owned(),
                timing: None,
            }],
            true,
        );
        assert_eq!(
            compile_input_sequence(&unsupported),
            Err(InputError::UnsupportedCharacter)
        );
        assert_eq!(
            InputError::UnsupportedCharacter.to_string(),
            "text.unsupported_character"
        );

        let timing = request(
            vec![InputAction::Click {
                button: ClickButton::Button1,
                hold_ms: Some(9),
                release_gap_ms: None,
            }],
            false,
        );
        assert_eq!(
            compile_input_sequence(&timing),
            Err(InputError::PointerTiming)
        );

        let seven = request(
            vec![InputAction::Chord {
                keys: ["A", "B", "C", "D", "E", "F", "G"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                timing: None,
            }],
            true,
        );
        assert_eq!(
            compile_input_sequence(&seven),
            Err(InputError::RolloverLimit)
        );
    }
}
