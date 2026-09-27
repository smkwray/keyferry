//! `keyferry.recipe.v1`: an explicitly saved, parameterized input plan (`protocol/recipe-v1.md`).
//!
//! Pure: no I/O and no clock. A recipe expands to one ordinary keyboard or input sequence and
//! compiles through the production compilers, so it never gains authority a hand-written
//! sequence lacks. Errors are stable codes with at most a parameter index; they never carry
//! parameter values, action bodies, key arrays, or source JSON.

use crate::input_sequence::{parse_strict_json_value, validate_action_shape, MAX_INPUT_BYTES};
use crate::text_stream::{replace_unsupported_text, UnsupportedTextPolicy};
use crate::{
    canonicalize_input_sequence_keys, canonicalize_sequence_keys, compile_input_sequence,
    compile_sequence, InputAction, InputArmPolicy, InputError, InputKeyboardTiming,
    InputLeafAction, InputSequenceV1, KeyboardSequenceV1, SequenceAction, SequenceArmPolicy,
    SequenceLeafAction, TypingTiming, INPUT_SEQUENCE_SCHEMA_V1, LEGACY_WIRE_MAPPING,
    SEQUENCE_SCHEMA_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::fmt;

pub const RECIPE_SCHEMA_V1: &str = "keyferry.recipe.v1";
pub const MAX_RECIPE_BYTES: usize = MAX_INPUT_BYTES;
pub const MAX_RECIPE_NAME_CHARS: usize = 63;
pub const MAX_DESCRIPTION_CHARS: usize = 200;
pub const MAX_PARAMETERS: usize = 16;
pub const MAX_PARAMETER_NAME_CHARS: usize = 32;
pub const MAX_PARAMETER_CHARS: u64 = 4096;
pub const DEFAULT_PARAMETER_CHARS: u64 = 256;
pub const DEFAULT_START_WITHIN_MS: u64 = 5000;
/// The expanded request body shares the hand-written request cap.
const MAX_EXPANDED_BODY_BYTES: usize = MAX_INPUT_BYTES;
/// Validation's parameter placeholder. Every supported parameter character costs one keystroke,
/// and `"` has the largest JSON encoding among them (two bytes, as do backslash, TAB, LF, and
/// CR), so it is the worst case for every command limit and for the body size at once.
const WORST_CASE_CHARACTER: &str = "\"";
/// Fixed UUIDv7 used only for no-contact validation; a run always supplies a fresh one.
const VALIDATION_COMMAND_ID: &str = "00000000-0000-7000-8000-000000000000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecipeError {
    code: &'static str,
    parameter: Option<usize>,
}

impl RecipeError {
    const fn new(code: &'static str) -> Self {
        Self {
            code,
            parameter: None,
        }
    }

    const fn at(code: &'static str, index: usize) -> Self {
        Self {
            code,
            parameter: Some(index),
        }
    }

    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// Zero-based index into the recipe's `parameters`, when the error concerns one.
    #[must_use]
    pub const fn parameter_index(self) -> Option<usize> {
        self.parameter
    }
}

impl fmt::Display for RecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for RecipeError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterKind {
    Text,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecipeParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ParameterKind,
    #[serde(default)]
    pub max_chars: Option<u64>,
}

impl RecipeParameter {
    #[must_use]
    pub fn max_chars(&self) -> u64 {
        self.max_chars.unwrap_or(DEFAULT_PARAMETER_CHARS)
    }
}

/// A structurally valid recipe. Only [`parse`] constructs one, so its invariants hold.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipeV1 {
    schema: String,
    name: String,
    #[serde(default)]
    revision: Option<u32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    parameters: Vec<RecipeParameter>,
    #[serde(default)]
    timing: Option<InputKeyboardTiming>,
    #[serde(default)]
    start_within_ms: Option<u64>,
    actions: Vec<Value>,
}

impl RecipeV1 {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn revision(&self) -> Option<u32> {
        self.revision
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    #[must_use]
    pub fn parameters(&self) -> &[RecipeParameter] {
        &self.parameters
    }
}

/// Metadata only: the action body may hold saved text and is never formatted.
impl fmt::Debug for RecipeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecipeV1")
            .field("name", &self.name)
            .field("revision", &self.revision)
            .field("parameters", &self.parameters)
            .finish_non_exhaustive()
    }
}

/// Run-time parameter values, parsed from one JSON object. Values are never formatted.
#[derive(Clone, Default)]
pub struct Params(Map<String, Value>);

impl fmt::Debug for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Params")
            .field("count", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// `POST /v1/devices/{id}/sequences`: keyboard-only, valid in every output mode.
    Sequences,
    /// `POST /v1/devices/{id}/input-sequences`: any pointer action; requires `MOUSE_RELATIVE_V1`.
    InputSequences,
}

impl Route {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sequences => "sequences",
            Self::InputSequences => "input-sequences",
        }
    }

    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::Sequences => "/sequences",
            Self::InputSequences => "/input-sequences",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub route: Route,
    /// Input-sequence chunks; `None` on the keyboard route, which the daemon plans itself.
    pub chunks: Option<usize>,
    pub planned_ms: u64,
    /// Parameter characters replaced with `?` under [`UnsupportedTextPolicy::Replace`].
    pub replacements: u64,
}

#[derive(Clone)]
pub enum Request {
    Keyboard(KeyboardSequenceV1),
    Input(InputSequenceV1),
}

#[derive(Clone)]
pub struct Expanded {
    pub request: Request,
    pub summary: Summary,
}

/// Summary only: the expanded request carries parameter values.
impl fmt::Debug for Expanded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Expanded")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

/// `^[a-z0-9][a-z0-9-]{0,62}$`, excluding Windows device names so `<name>.json` is always an
/// ordinary file. Safe to join to a directory: it has no separator, dot, or drive syntax.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=MAX_RECIPE_NAME_CHARS).contains(&bytes.len())
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
        && !is_windows_device_name(name)
}

fn is_windows_device_name(name: &str) -> bool {
    matches!(name, "con" | "prn" | "aux" | "nul")
        || (name.len() == 4
            && (name.starts_with("com") || name.starts_with("lpt"))
            && name.as_bytes()[3].is_ascii_digit())
}

fn is_valid_parameter_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=MAX_PARAMETER_NAME_CHARS).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Strict structural parse: envelope, name, parameters, text sources, and the Input Sequence v1
/// action shapes. Compilation limits are checked by [`validate`].
pub fn parse(bytes: &[u8]) -> Result<RecipeV1, RecipeError> {
    let value = parse_strict_json_value(bytes).map_err(|error| {
        RecipeError::new(match error {
            InputError::DuplicateField => "recipe.duplicate_field",
            InputError::Limit => "recipe.limit",
            InputError::IntegerRequired => "recipe.schema",
            _ => "recipe.json",
        })
    })?;
    if !value.is_object() {
        return Err(RecipeError::new("recipe.json"));
    }
    if contains_null(&value) {
        return Err(RecipeError::new("recipe.schema"));
    }
    let recipe: RecipeV1 =
        serde_json::from_value(value).map_err(|_| RecipeError::new("recipe.schema"))?;
    if recipe.schema != RECIPE_SCHEMA_V1 {
        return Err(RecipeError::new("recipe.schema"));
    }
    if !is_valid_name(&recipe.name) {
        return Err(RecipeError::new("recipe.name"));
    }
    if recipe
        .description
        .as_ref()
        .is_some_and(|description| description.chars().count() > MAX_DESCRIPTION_CHARS)
    {
        return Err(RecipeError::new("recipe.description"));
    }
    if recipe.parameters.len() > MAX_PARAMETERS {
        return Err(RecipeError::new("recipe.parameter_limit"));
    }
    for (index, parameter) in recipe.parameters.iter().enumerate() {
        if !is_valid_parameter_name(&parameter.name) {
            return Err(RecipeError::at("recipe.parameter_name", index));
        }
        if recipe.parameters[..index]
            .iter()
            .any(|other| other.name == parameter.name)
        {
            return Err(RecipeError::at("recipe.parameter_duplicate", index));
        }
        if !(1..=MAX_PARAMETER_CHARS).contains(&parameter.max_chars()) {
            return Err(RecipeError::at("recipe.parameter_max_chars", index));
        }
    }
    let placeholders = vec!["a".to_owned(); recipe.parameters.len()];
    let mut used = vec![false; recipe.parameters.len()];
    build_actions(&recipe, &placeholders, &mut used)?;
    if let Some(index) = used.iter().position(|used| !used) {
        return Err(RecipeError::at("recipe.parameter_unused", index));
    }
    Ok(recipe)
}

/// A library entry is `<name>.json`; the file stem must equal the recipe's own name.
pub fn check_file_stem(recipe: &RecipeV1, stem: &str) -> Result<(), RecipeError> {
    if recipe.name != stem {
        return Err(RecipeError::new("recipe.name_mismatch"));
    }
    Ok(())
}

/// Worst-case compilation: every parameter at its `max_chars` of [`WORST_CASE_CHARACTER`]. A
/// passing recipe cannot exceed a command limit or the body size with any allowed parameter value.
pub fn validate(recipe: &RecipeV1) -> Result<Summary, RecipeError> {
    let values: Vec<String> = recipe
        .parameters
        .iter()
        .map(|parameter| WORST_CASE_CHARACTER.repeat(parameter.max_chars() as usize))
        .collect();
    compile(recipe, &values, VALIDATION_COMMAND_ID, 0).map(|expanded| expanded.summary)
}

pub fn parse_params(bytes: &[u8]) -> Result<Params, RecipeError> {
    let value = parse_strict_json_value(bytes).map_err(|error| {
        RecipeError::new(match error {
            InputError::DuplicateField => "params.duplicate",
            InputError::Limit => "params.limit",
            _ => "params.json",
        })
    })?;
    match value {
        Value::Object(values) => Ok(Params(values)),
        _ => Err(RecipeError::new("params.json")),
    }
}

/// Validates the recipe, substitutes the caller's parameter values, and compiles one
/// command-scoped request under [`LEGACY_WIRE_MAPPING`] with canonical key names. A parameter
/// character outside the text-stream rule (printable ASCII, TAB, LF, CR) is unsupported under
/// both policies: it rejects unless the caller explicitly selects replacement.
pub fn expand(
    recipe: &RecipeV1,
    params: &Params,
    unsupported: UnsupportedTextPolicy,
    command_id: &str,
) -> Result<Expanded, RecipeError> {
    validate(recipe)?;
    if params.0.keys().any(|key| {
        !recipe
            .parameters
            .iter()
            .any(|parameter| &parameter.name == key)
    }) {
        return Err(RecipeError::new("params.unknown"));
    }
    let mut values = Vec::with_capacity(recipe.parameters.len());
    let mut replacements = 0_u64;
    for (index, parameter) in recipe.parameters.iter().enumerate() {
        let value = match params.0.get(&parameter.name) {
            None => return Err(RecipeError::at("params.missing", index)),
            Some(Value::String(value)) => value,
            Some(_) => return Err(RecipeError::at("params.not_string", index)),
        };
        if value.is_empty() {
            return Err(RecipeError::at("params.empty", index));
        }
        if value.chars().count() as u64 > parameter.max_chars() {
            return Err(RecipeError::at("params.too_long", index));
        }
        // One definition of unsupported for both policies: the text-stream replacement rule.
        let (value, count) = replace_unsupported_text(value);
        if count > 0 && unsupported == UnsupportedTextPolicy::Reject {
            return Err(RecipeError::at("text.unsupported_character", index));
        }
        replacements = replacements.saturating_add(count);
        values.push(value);
    }
    compile(recipe, &values, command_id, replacements)
}

fn compile(
    recipe: &RecipeV1,
    values: &[String],
    command_id: &str,
    replacements: u64,
) -> Result<Expanded, RecipeError> {
    let mut used = vec![false; recipe.parameters.len()];
    let actions = build_actions(recipe, values, &mut used)?;
    let start_within_ms = recipe.start_within_ms.unwrap_or(DEFAULT_START_WITHIN_MS);
    // The default timing is bounded on every route, even where no keyboard action uses it.
    if let Some(timing) = recipe.timing {
        keyboard_timing(timing)
            .validate()
            .map_err(|_| RecipeError::new(InputError::Timing.code()))?;
    }
    if let Some(actions) = actions
        .iter()
        .map(keyboard_action)
        .collect::<Option<Vec<_>>>()
    {
        let mut request = KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: command_id.to_owned(),
            profile: LEGACY_WIRE_MAPPING.to_owned(),
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: u32::try_from(start_within_ms).unwrap_or(u32::MAX),
            timing: recipe.timing.map(keyboard_timing),
            actions,
        };
        canonicalize_sequence_keys(&mut request);
        let compiled =
            compile_sequence(&request).map_err(|error| RecipeError::new(error.code()))?;
        check_body_size(&request)?;
        return Ok(Expanded {
            request: Request::Keyboard(request),
            summary: Summary {
                route: Route::Sequences,
                chunks: None,
                planned_ms: u64::from(compiled.planned_ms),
                replacements,
            },
        });
    }
    let has_keyboard = actions.iter().any(|action| match action {
        InputAction::Text { .. }
        | InputAction::Tap { .. }
        | InputAction::Chord { .. }
        | InputAction::OrderedChord { .. } => true,
        InputAction::Repeat { actions, .. } => actions.iter().any(|action| {
            matches!(
                action,
                InputLeafAction::Text { .. }
                    | InputLeafAction::Tap { .. }
                    | InputLeafAction::Chord { .. }
                    | InputLeafAction::OrderedChord { .. }
            )
        }),
        _ => false,
    });
    let mut request = InputSequenceV1 {
        schema: INPUT_SEQUENCE_SCHEMA_V1.to_owned(),
        command_id: command_id.to_owned(),
        keyboard_profile: has_keyboard.then(|| LEGACY_WIRE_MAPPING.to_owned()),
        arm: InputArmPolicy::CommandScoped,
        start_within_ms,
        // Input Sequence v1 forbids keyboard timing without a keyboard action; there it is inert.
        keyboard_timing: recipe.timing.filter(|_| has_keyboard),
        actions,
    };
    canonicalize_input_sequence_keys(&mut request);
    let compiled =
        compile_input_sequence(&request).map_err(|error| RecipeError::new(error.code()))?;
    check_body_size(&request)?;
    Ok(Expanded {
        request: Request::Input(request),
        summary: Summary {
            route: Route::InputSequences,
            chunks: Some(compiled.chunks.len()),
            planned_ms: compiled.planned_ms,
            replacements,
        },
    })
}

/// The serialized request is exactly the body a run posts; it must fit the shared body cap.
fn check_body_size(request: &impl Serialize) -> Result<(), RecipeError> {
    match serde_json::to_vec(request) {
        Ok(body) if body.len() <= MAX_EXPANDED_BODY_BYTES => Ok(()),
        _ => Err(RecipeError::new("recipe.body_limit")),
    }
}

/// Substitutes `param` references and deserializes the Input Sequence v1 action vocabulary, so
/// recipes and input sequences share one strict action contract.
fn build_actions(
    recipe: &RecipeV1,
    values: &[String],
    used: &mut [bool],
) -> Result<Vec<InputAction>, RecipeError> {
    let mut actions = Vec::with_capacity(recipe.actions.len());
    for action in &recipe.actions {
        let mut action = action.clone();
        substitute(&mut action, &recipe.parameters, values, used)?;
        validate_action_shape(&action, true).map_err(|error| RecipeError::new(error.code()))?;
        actions.push(
            serde_json::from_value(action)
                .map_err(|_| RecipeError::new(InputError::Json.code()))?,
        );
    }
    Ok(actions)
}

fn substitute(
    action: &mut Value,
    parameters: &[RecipeParameter],
    values: &[String],
    used: &mut [bool],
) -> Result<(), RecipeError> {
    let Some(object) = action.as_object_mut() else {
        return Ok(());
    };
    match object.get("type").and_then(Value::as_str) {
        Some("text") => match (object.remove("param"), object.get("value")) {
            (Some(Value::String(name)), None) => {
                let index = parameters
                    .iter()
                    .position(|parameter| parameter.name == name)
                    .ok_or(RecipeError::new("recipe.parameter_undeclared"))?;
                used[index] = true;
                object.insert("value".to_owned(), Value::String(values[index].clone()));
            }
            (None, Some(Value::String(value))) if !value.is_empty() => {}
            _ => return Err(RecipeError::new("recipe.text")),
        },
        Some("repeat") => {
            if let Some(Value::Array(actions)) = object.get_mut("actions") {
                for action in actions {
                    substitute(action, parameters, values, used)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn contains_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(values) => values.iter().any(contains_null),
        Value::Object(values) => values.values().any(contains_null),
        _ => false,
    }
}

/// Out-of-range values saturate so the keyboard compiler rejects them with its own code.
fn saturate(value: u64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn keyboard_timing(timing: InputKeyboardTiming) -> TypingTiming {
    TypingTiming {
        key_down_ms: saturate(timing.key_down_ms),
        release_gap_ms: saturate(timing.release_gap_ms),
    }
}

/// The keyboard-sequence form of an action; `None` for pointer actions.
fn keyboard_action(action: &InputAction) -> Option<SequenceAction> {
    Some(match action {
        InputAction::Text { value, timing } => SequenceAction::Text {
            value: value.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputAction::Tap { key, timing } => SequenceAction::Tap {
            key: key.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputAction::Chord { keys, timing } => SequenceAction::Chord {
            keys: keys.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputAction::OrderedChord { keys, timing } => SequenceAction::OrderedChord {
            keys: keys.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputAction::Wait { ms } => SequenceAction::Wait { ms: saturate(*ms) },
        InputAction::Repeat { count, actions } => SequenceAction::Repeat {
            count: saturate(*count),
            actions: actions.iter().map(keyboard_leaf).collect::<Option<_>>()?,
        },
        InputAction::MoveRelative { .. }
        | InputAction::Click { .. }
        | InputAction::DoubleClick { .. } => return None,
    })
}

fn keyboard_leaf(action: &InputLeafAction) -> Option<SequenceLeafAction> {
    Some(match action {
        InputLeafAction::Text { value, timing } => SequenceLeafAction::Text {
            value: value.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputLeafAction::Tap { key, timing } => SequenceLeafAction::Tap {
            key: key.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputLeafAction::Chord { keys, timing } => SequenceLeafAction::Chord {
            keys: keys.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputLeafAction::OrderedChord { keys, timing } => SequenceLeafAction::OrderedChord {
            keys: keys.clone(),
            timing: timing.map(keyboard_timing),
        },
        InputLeafAction::Wait { ms } => SequenceLeafAction::Wait { ms: saturate(*ms) },
        InputLeafAction::MoveRelative { .. }
        | InputLeafAction::Click { .. }
        | InputLeafAction::DoubleClick { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    const COMMAND_ID: &str = "019d1234-5678-7abc-8123-456789abcdef";
    const SECRET: &str = "Hunter2-SECRET";

    fn recipe(value: &Value) -> Result<RecipeV1, RecipeError> {
        parse(value.to_string().as_bytes())
    }

    fn params(value: &Value) -> Params {
        parse_params(value.to_string().as_bytes()).unwrap()
    }

    fn example() -> Value {
        json!({
            "schema": "keyferry.recipe.v1", "name": "open-terminal", "revision": 1,
            "description": "Open a URL",
            "parameters": [{"name": "url", "type": "text", "max_chars": 256}],
            "timing": {"key_down_ms": 12, "release_gap_ms": 40},
            "start_within_ms": 5000,
            "actions": [
                {"type": "chord", "keys": ["COMMAND", "SPACE"]},
                {"type": "text", "param": "url"},
                {"type": "tap", "key": "RETURN"}
            ]
        })
    }

    fn with(mut base: Value, field: &str, value: Value) -> Value {
        base[field] = value;
        base
    }

    fn assert_payload_free(error: RecipeError) {
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(!rendered.contains("COMMAND"), "{rendered}");
    }

    #[test]
    fn spec_example_expands_to_one_canonical_keyboard_sequence() {
        let parsed = recipe(&example()).unwrap();
        assert_eq!(parsed.name(), "open-terminal");
        assert_eq!(parsed.revision(), Some(1));
        assert_eq!(parsed.description(), Some("Open a URL"));
        assert_eq!(parsed.parameters()[0].max_chars(), 256);
        assert_eq!(parsed.parameters()[0].kind, ParameterKind::Text);
        assert_eq!(
            validate(&parsed).unwrap(),
            Summary {
                route: Route::Sequences,
                chunks: None,
                planned_ms: 258 * 52,
                replacements: 0,
            }
        );

        let expanded = expand(
            &parsed,
            &params(&json!({"url": "https://example.test/a"})),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap();
        let expected = KeyboardSequenceV1 {
            schema: SEQUENCE_SCHEMA_V1.to_owned(),
            command_id: COMMAND_ID.to_owned(),
            profile: LEGACY_WIRE_MAPPING.to_owned(),
            arm: SequenceArmPolicy::CommandScoped,
            start_within_ms: 5000,
            timing: Some(TypingTiming::DESKTOP_SAFE),
            actions: vec![
                SequenceAction::Chord {
                    keys: vec!["LEFT_GUI".to_owned(), "SPACE".to_owned()],
                    timing: None,
                },
                SequenceAction::Text {
                    value: "https://example.test/a".to_owned(),
                    timing: None,
                },
                SequenceAction::Tap {
                    key: "ENTER".to_owned(),
                    timing: None,
                },
            ],
        };
        let Request::Keyboard(request) = &expanded.request else {
            panic!("keyboard-only recipes use the keyboard route");
        };
        assert_eq!(request, &expected);
        assert_eq!(
            expanded.summary.planned_ms,
            u64::from(compile_sequence(&expected).unwrap().planned_ms)
        );
        assert_eq!(expanded.summary.route.path(), "/sequences");
        assert_eq!(expanded.summary.replacements, 0);

        let no_parameters = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "lock",
            "actions": [{"type": "chord", "keys": ["CTRL", "CMD", "Q"]}]
        }))
        .unwrap();
        let expanded = expand(
            &no_parameters,
            &Params::default(),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap();
        let Request::Keyboard(request) = &expanded.request else {
            panic!("keyboard route");
        };
        assert_eq!(request.start_within_ms, 5000);
        assert_eq!(request.timing, None);
        assert_eq!(
            request.actions,
            vec![SequenceAction::Chord {
                keys: vec!["LEFT_CONTROL".into(), "LEFT_GUI".into(), "Q".into()],
                timing: None,
            }]
        );
    }

    #[test]
    fn pointer_actions_route_to_one_input_sequence() {
        let parsed = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "open-file",
            "parameters": [{"name": "who", "type": "text", "max_chars": 8}],
            "actions": [
                {"type": "move_relative", "dx_counts": 100, "dy_counts": -20},
                {"type": "double_click", "button": "button_1", "hold_ms": 100, "release_gap_ms": 100},
                {"type": "repeat", "count": 2, "actions": [
                    {"type": "tap", "key": "OPT"},
                    {"type": "text", "param": "who"}
                ]}
            ]
        }))
        .unwrap();
        let expanded = expand(
            &parsed,
            &params(&json!({"who": "me"})),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap();
        let Request::Input(request) = &expanded.request else {
            panic!("pointer recipes use the input route");
        };
        assert_eq!(
            request.keyboard_profile.as_deref(),
            Some(LEGACY_WIRE_MAPPING)
        );
        assert_eq!(request.arm, InputArmPolicy::CommandScoped);
        assert_eq!(request.command_id, COMMAND_ID);
        let InputAction::Repeat { actions, .. } = &request.actions[2] else {
            panic!("repeat is preserved");
        };
        assert_eq!(
            actions,
            &vec![
                InputLeafAction::Tap {
                    key: "LEFT_ALT".to_owned(),
                    timing: None,
                },
                InputLeafAction::Text {
                    value: "me".to_owned(),
                    timing: None,
                },
            ]
        );
        let compiled = compile_input_sequence(request).unwrap();
        assert_eq!(expanded.summary.route, Route::InputSequences);
        assert_eq!(expanded.summary.route.path(), "/input-sequences");
        assert_eq!(expanded.summary.chunks, Some(compiled.chunks.len()));
        assert_eq!(expanded.summary.planned_ms, compiled.planned_ms);
        assert!(compiled
            .gestures
            .iter()
            .any(|gesture| matches!(gesture, crate::InputGesture::DoubleClick { .. })));

        let pointer_only = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "click",
            "actions": [{"type": "repeat", "count": 3, "actions": [{"type": "click", "button": "button_2"}]}]
        }))
        .unwrap();
        let expanded = expand(
            &pointer_only,
            &Params::default(),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap();
        let Request::Input(request) = &expanded.request else {
            panic!("a pointer inside repeat selects the input route");
        };
        assert_eq!(request.keyboard_profile, None);
        assert_eq!(
            validate(&pointer_only).unwrap().route,
            Route::InputSequences
        );

        // A recipe-level default timing is inert without a keyboard action: it stays bounded but
        // is left out, because Input Sequence v1 forbids keyboard timing on a pointer-only body.
        let timed = |timing: Value| {
            recipe(&json!({
                "schema": "keyferry.recipe.v1", "name": "click", "timing": timing,
                "actions": [{"type": "click", "button": "button_1"}]
            }))
            .unwrap()
        };
        let clicked = timed(json!({"key_down_ms": 12, "release_gap_ms": 40}));
        assert_eq!(validate(&clicked).unwrap().route, Route::InputSequences);
        let expanded = expand(
            &clicked,
            &Params::default(),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap();
        let Request::Input(request) = &expanded.request else {
            panic!("pointer route");
        };
        assert_eq!(request.keyboard_profile, None);
        assert_eq!(request.keyboard_timing, None);
        let unbounded = timed(json!({"key_down_ms": 101, "release_gap_ms": 40}));
        assert_eq!(validate(&unbounded).unwrap_err().code(), "sequence.timing");
    }

    #[test]
    fn replacement_is_explicit_counted_and_limited_to_parameter_values() {
        let parsed = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "greet",
            "parameters": [{"name": "who", "type": "text", "max_chars": 16}],
            "actions": [
                {"type": "text", "value": "Hi \u{1b}"},
                {"type": "text", "param": "who"}
            ]
        }))
        .unwrap();
        let values = params(&json!({"who": "caf\u{e9} \u{2014} ok"}));
        let error =
            expand(&parsed, &values, UnsupportedTextPolicy::Reject, COMMAND_ID).unwrap_err();
        assert_eq!(error.code(), "text.unsupported_character");
        assert_eq!(error.parameter_index(), Some(0));

        let expanded =
            expand(&parsed, &values, UnsupportedTextPolicy::Replace, COMMAND_ID).unwrap();
        assert_eq!(expanded.summary.replacements, 2);
        let Request::Keyboard(request) = &expanded.request else {
            panic!("keyboard route");
        };
        assert_eq!(
            request.actions,
            vec![
                SequenceAction::Text {
                    value: "Hi \u{1b}".to_owned(),
                    timing: None,
                },
                SequenceAction::Text {
                    value: "caf? ? ok".to_owned(),
                    timing: None,
                },
            ]
        );

        // ESC and backspace are keys, not parameter text: both policies call them unsupported,
        // so a value cannot inject editing keys and replacement counts only what reject refuses.
        let controls = params(&json!({"who": "x\u{8}\u{8}\u{1b}"}));
        let error = expand(
            &parsed,
            &controls,
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap_err();
        assert_eq!(
            (error.code(), error.parameter_index()),
            ("text.unsupported_character", Some(0))
        );
        let expanded = expand(
            &parsed,
            &controls,
            UnsupportedTextPolicy::Replace,
            COMMAND_ID,
        )
        .unwrap();
        assert_eq!(expanded.summary.replacements, 3);
        let Request::Keyboard(request) = &expanded.request else {
            panic!("keyboard route");
        };
        assert_eq!(
            request.actions[1],
            SequenceAction::Text {
                value: "x???".to_owned(),
                timing: None,
            }
        );
        let plain = params(&json!({"who": "\"a\\b\tc\r\nd~"}));
        for policy in [
            UnsupportedTextPolicy::Reject,
            UnsupportedTextPolicy::Replace,
        ] {
            let expanded = expand(&parsed, &plain, policy, COMMAND_ID).unwrap();
            assert_eq!(expanded.summary.replacements, 0);
        }
    }

    #[test]
    fn validation_compiles_every_parameter_at_its_maximum() {
        let bounded = |max_chars: u64| {
            recipe(&json!({
                "schema": "keyferry.recipe.v1", "name": "long",
                "parameters": [{"name": "body", "type": "text", "max_chars": max_chars}],
                "timing": {"key_down_ms": 25, "release_gap_ms": 25},
                "actions": [{"type": "text", "param": "body"}]
            }))
            .unwrap()
        };
        assert_eq!(validate(&bounded(1200)).unwrap().planned_ms, 60_000);
        let over = bounded(1201);
        assert_eq!(
            validate(&over).unwrap_err().code(),
            "sequence.duration_limit"
        );
        // A short value cannot run a recipe whose declared maximum exceeds a command limit.
        assert_eq!(
            expand(
                &over,
                &params(&json!({"body": "hi"})),
                UnsupportedTextPolicy::Reject,
                COMMAND_ID
            )
            .unwrap_err()
            .code(),
            "sequence.duration_limit"
        );

        let twice = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "twice",
            "parameters": [{"name": "body", "type": "text", "max_chars": 4096}],
            "timing": {"key_down_ms": 5, "release_gap_ms": 5},
            "actions": [{"type": "text", "param": "body"}, {"type": "text", "param": "body"}]
        }))
        .unwrap();
        assert_eq!(validate(&twice).unwrap_err().code(), "text.character_limit");
    }

    #[test]
    fn validation_bounds_the_expanded_body_at_every_parameter_maximum() {
        // Aliases grow to canonical names and a parameter reference grows to its escaped value,
        // so a recipe within its own size cap can expand past the shared body cap.
        let wide = |max_chars: u64| {
            let chord = json!({"type": "chord", "keys": [
                "CTRL", "SHIFT", "ALT", "CMD", "RIGHT_CONTROL", "RIGHT_SHIFT", "RIGHT_OPT",
                "RIGHT_CMD", "KEYPAD_DOUBLE_VERTICAL_BAR", "KEYPAD_RIGHT_PARENTHESIS",
                "KEYPAD_LEFT_PARENTHESIS", "KEYPAD_DOUBLE_AMPERSAND", "KEYPAD_MEMORY_SUBTRACT",
                "KEYPAD_MEMORY_MULTIPLY"
            ]});
            let mut actions = vec![chord; 220];
            actions.push(json!({"type": "text", "param": "body"}));
            let source = json!({
                "schema": "keyferry.recipe.v1", "name": "wide",
                "parameters": [{"name": "body", "type": "text", "max_chars": max_chars}],
                "timing": {"key_down_ms": 5, "release_gap_ms": 5},
                "actions": actions
            })
            .to_string();
            assert!(source.len() < MAX_RECIPE_BYTES);
            parse(source.as_bytes()).unwrap()
        };
        let body = |expanded: &Expanded| match &expanded.request {
            Request::Keyboard(request) => serde_json::to_vec(request).unwrap(),
            Request::Input(request) => serde_json::to_vec(request).unwrap(),
        };

        // At 1,000 characters every command limit passes and plain letters fit, but 1,000
        // two-byte escapes do not: validation must use the escaped worst case.
        let over = wide(1000);
        let letters = compile(&over, &["a".repeat(1000)], VALIDATION_COMMAND_ID, 0).unwrap();
        assert!(body(&letters).len() <= MAX_EXPANDED_BODY_BYTES);
        assert_eq!(validate(&over).unwrap_err().code(), "recipe.body_limit");
        assert_eq!(
            expand(
                &over,
                &params(&json!({"body": "a"})),
                UnsupportedTextPolicy::Reject,
                COMMAND_ID
            )
            .unwrap_err()
            .code(),
            "recipe.body_limit"
        );

        // A recipe that validates fits with every allowed value, under either policy.
        let fits = wide(500);
        validate(&fits).unwrap();
        for (value, policy) in [
            ("\"\\\t\n\r".repeat(100), UnsupportedTextPolicy::Reject),
            ("\u{1b}".repeat(500), UnsupportedTextPolicy::Replace),
        ] {
            let expanded =
                expand(&fits, &params(&json!({"body": value})), policy, COMMAND_ID).unwrap();
            assert!(body(&expanded).len() <= MAX_EXPANDED_BODY_BYTES);
        }
        let doc = include_str!("../../../protocol/recipe-v1.md");
        assert!(doc.contains("`recipe.body_limit`"));
    }

    #[test]
    fn every_error_is_a_stable_payload_free_code() {
        let mut codes = BTreeSet::new();
        let mut expect =
            |result: Result<RecipeV1, RecipeError>, code: &str, index: Option<usize>| {
                let error = result.unwrap_err();
                assert_eq!((error.code(), error.parameter_index()), (code, index));
                assert_payload_free(error);
                codes.insert(error.code());
            };
        let secret = Value::String(SECRET.to_owned());
        let base = example();
        let param = |name: &str, max_chars: u64| json!({"name": name, "type": "text", "max_chars": max_chars});
        let text = |name: &str| json!({"type": "text", "param": name});

        expect(
            parse(format!("not json {SECRET}").as_bytes()),
            "recipe.json",
            None,
        );
        expect(parse(b"[]"), "recipe.json", None);
        expect(
            parse(br#"{"schema":"keyferry.recipe.v1","schema":"keyferry.recipe.v1"}"#),
            "recipe.duplicate_field",
            None,
        );
        expect(
            recipe(&with(
                base.clone(),
                "description",
                json!("a".repeat(MAX_RECIPE_BYTES)),
            )),
            "recipe.limit",
            None,
        );
        expect(
            recipe(&with(base.clone(), "extra", json!([[[[[[[[SECRET]]]]]]]]))),
            "recipe.limit",
            None,
        );
        for (field, value) in [
            ("schema", json!("keyferry.recipe.v2")),
            ("device", secret.clone()),
            ("command_id", json!(COMMAND_ID)),
            ("arm", json!("command-scoped")),
            ("unsupported", json!("replace")),
            ("description", Value::Null),
            ("start_within_ms", json!(1.5)),
            ("revision", json!(-1)),
            ("parameters", json!([{"name": "url", "type": "secret"}])),
        ] {
            expect(
                recipe(&with(base.clone(), field, value)),
                "recipe.schema",
                None,
            );
        }
        for name in [
            "",
            "Open",
            "-open",
            "open.json",
            "../token",
            "a/b",
            "nul",
            "com1",
        ] {
            expect(
                recipe(&with(base.clone(), "name", json!(name))),
                "recipe.name",
                None,
            );
        }
        expect(
            recipe(&with(base.clone(), "name", json!("a".repeat(64)))),
            "recipe.name",
            None,
        );
        expect(
            recipe(&with(base.clone(), "description", json!("d".repeat(201)))),
            "recipe.description",
            None,
        );
        let many: Vec<Value> = (0..17)
            .map(|index| param(&format!("p{index}"), 1))
            .collect();
        expect(
            recipe(&with(base.clone(), "parameters", Value::Array(many))),
            "recipe.parameter_limit",
            None,
        );
        let two = |first: Value, second: Value| {
            let mut value = with(base.clone(), "parameters", json!([first, second]));
            value["actions"] = json!([text("url"), text("second")]);
            recipe(&value)
        };
        expect(
            two(param("url", 8), param("Second", 8)),
            "recipe.parameter_name",
            Some(1),
        );
        expect(
            two(param("url", 8), param("url", 8)),
            "recipe.parameter_duplicate",
            Some(1),
        );
        expect(
            two(param("url", 0), param("second", 8)),
            "recipe.parameter_max_chars",
            Some(0),
        );
        expect(
            two(param("url", 8), param("second", 4097)),
            "recipe.parameter_max_chars",
            Some(1),
        );
        let mut unused = with(
            base.clone(),
            "parameters",
            json!([param("url", 8), param("second", 8)]),
        );
        unused["actions"] = json!([text("url")]);
        expect(recipe(&unused), "recipe.parameter_unused", Some(1));
        for (action, code) in [
            (text("nope"), "recipe.parameter_undeclared"),
            (
                json!({"type": "text", "param": "url", "value": SECRET}),
                "recipe.text",
            ),
            (json!({"type": "text"}), "recipe.text"),
            (json!({"type": "text", "value": ""}), "recipe.text"),
            (json!({"type": "scroll", "dy": 3}), "pointer.out_of_scope"),
            (
                json!({"type": "launch", "app": SECRET}),
                "input.action_type",
            ),
            (
                json!({"type": "tap", "key": "ENTER", "note": SECRET}),
                "input.unknown_field",
            ),
            (
                json!({"type": "click", "button": "button_3"}),
                "pointer.button",
            ),
            (json!({"type": "tap", "key": 7}), "input.json"),
            (
                json!({"type": "repeat", "count": 2, "actions": [{"type": "repeat", "count": 2, "actions": []}]}),
                "input.action_type",
            ),
        ] {
            let value = with(base.clone(), "actions", json!([text("url"), action]));
            expect(recipe(&value), code, None);
        }

        let validated = |action: Value| {
            let parsed =
                recipe(&with(base.clone(), "actions", json!([text("url"), action]))).unwrap();
            validate(&parsed).map(|_| parsed)
        };
        expect(
            validated(json!({"type": "tap", "key": "LAUNCHPAD"})),
            "key.unknown",
            None,
        );
        expect(
            validated(json!({"type": "chord", "keys": ["LEFT_GUI", "COMMAND"]})),
            "chord.duplicate_key",
            None,
        );
        expect(
            validated(json!({"type": "wait", "ms": 70_000})),
            "wait.out_of_range",
            None,
        );
        expect(
            validated(json!({"type": "click", "button": "button_1", "hold_ms": 5})),
            "pointer.timing",
            None,
        );

        let two_params = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "pair",
            "parameters": [param("a", 8), param("b", 8)],
            "actions": [text("a"), text("b")]
        }))
        .unwrap();
        let mut run = |bytes: &[u8], code: &str, index: Option<usize>| {
            let error = parse_params(bytes)
                .and_then(|values| {
                    expand(
                        &two_params,
                        &values,
                        UnsupportedTextPolicy::Reject,
                        COMMAND_ID,
                    )
                })
                .unwrap_err();
            assert_eq!((error.code(), error.parameter_index()), (code, index));
            assert_payload_free(error);
            codes.insert(error.code());
        };
        run(
            format!("{{\"a\":\"{SECRET}\"").as_bytes(),
            "params.json",
            None,
        );
        run(b"[\"a\"]", "params.json", None);
        run(br#"{"a":"x","a":"y","b":"z"}"#, "params.duplicate", None);
        run(
            json!({"a": "x".repeat(MAX_RECIPE_BYTES)})
                .to_string()
                .as_bytes(),
            "params.limit",
            None,
        );
        let values = |value: Value| value.to_string().into_bytes();
        run(
            &values(json!({"a": "x", "b": "y", SECRET: "z"})),
            "params.unknown",
            None,
        );
        run(&values(json!({"a": "x"})), "params.missing", Some(1));
        run(
            &values(json!({"a": 7, "b": "y"})),
            "params.not_string",
            Some(0),
        );
        run(
            &values(json!({"a": null, "b": "y"})),
            "params.not_string",
            Some(0),
        );
        run(&values(json!({"a": "", "b": "y"})), "params.empty", Some(0));
        run(
            &values(json!({"a": SECRET, "b": "y"})),
            "params.too_long",
            Some(0),
        );
        run(
            &values(json!({"a": "ok", "b": "\u{e9}Hunter2"})),
            "text.unsupported_character",
            Some(1),
        );
        let lone = recipe(&json!({
            "schema": "keyferry.recipe.v1", "name": "lone",
            "actions": [{"type": "tap", "key": "ENTER"}]
        }))
        .unwrap();
        let error = expand(
            &lone,
            &params(&json!({"extra": SECRET})),
            UnsupportedTextPolicy::Reject,
            COMMAND_ID,
        )
        .unwrap_err();
        assert_eq!(error.code(), "params.unknown");

        // Compiler codes are documented with their contracts; recipe codes are listed here.
        let doc = include_str!("../../../protocol/recipe-v1.md");
        for code in codes
            .into_iter()
            .filter(|code| code.starts_with("recipe.") || code.starts_with("params."))
        {
            assert!(doc.contains(&format!("`{code}`")), "{code} is undocumented");
        }
    }

    #[test]
    fn metadata_formatting_never_includes_bodies_or_values() {
        let parsed = recipe(&with(
            example(),
            "actions",
            json!([{"type": "text", "value": SECRET}, {"type": "text", "param": "url"}]),
        ))
        .unwrap();
        let values = params(&json!({"url": SECRET}));
        let expanded = expand(&parsed, &values, UnsupportedTextPolicy::Reject, COMMAND_ID).unwrap();
        for rendered in [
            format!("{parsed:?}"),
            format!("{values:?}"),
            format!("{expanded:?}"),
        ] {
            assert!(!rendered.contains(SECRET), "{rendered}");
        }
    }

    #[test]
    fn names_are_plain_file_stems() {
        let longest = "z".repeat(63);
        for name in [
            "a",
            "0",
            "open-terminal",
            "a-",
            "con1",
            "lpt",
            longest.as_str(),
        ] {
            assert!(is_valid_name(name), "{name}");
        }
        let too_long = "z".repeat(64);
        for name in [
            "",
            "-a",
            "A",
            "a_b",
            "a.b",
            "a/b",
            "a\\b",
            "..",
            "c:",
            "aux",
            "prn",
            "lpt9",
            "com0",
            too_long.as_str(),
        ] {
            assert!(!is_valid_name(name), "{name}");
        }
        let parsed = recipe(&example()).unwrap();
        assert!(check_file_stem(&parsed, "open-terminal").is_ok());
        assert_eq!(
            check_file_stem(&parsed, "other").unwrap_err().code(),
            "recipe.name_mismatch"
        );
    }

    #[test]
    fn schema_file_matches_the_expander_bounds_and_action_vocabulary() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../protocol/recipe-v1.schema.json")).unwrap();
        let input: Value = serde_json::from_str(include_str!(
            "../../../protocol/input-sequence-v1.schema.json"
        ))
        .unwrap();
        let properties = &schema["properties"];
        assert_eq!(properties["schema"]["const"], RECIPE_SCHEMA_V1);
        assert_eq!(
            properties["name"]["pattern"],
            format!("^[a-z0-9][a-z0-9-]{{0,{}}}$", MAX_RECIPE_NAME_CHARS - 1)
        );
        assert_eq!(
            properties["name"]["not"]["pattern"],
            "^(con|prn|aux|nul|com[0-9]|lpt[0-9])$"
        );
        assert_eq!(properties["revision"]["maximum"], u64::from(u32::MAX));
        assert_eq!(
            properties["description"]["maxLength"],
            MAX_DESCRIPTION_CHARS
        );
        assert_eq!(properties["parameters"]["maxItems"], MAX_PARAMETERS);
        assert_eq!(
            properties["start_within_ms"]["default"],
            DEFAULT_START_WITHIN_MS
        );
        let parameter = &schema["$defs"]["parameter"]["properties"];
        let name_pattern = format!("^[a-z][a-z0-9_]{{0,{}}}$", MAX_PARAMETER_NAME_CHARS - 1);
        assert_eq!(parameter["name"]["pattern"], name_pattern);
        assert_eq!(
            schema["$defs"]["text_action"]["properties"]["param"]["pattern"],
            name_pattern
        );
        assert_eq!(parameter["type"]["const"], "text");
        assert_eq!(parameter["max_chars"]["maximum"], MAX_PARAMETER_CHARS);
        assert_eq!(parameter["max_chars"]["default"], DEFAULT_PARAMETER_CHARS);

        // Every Input Sequence v1 leaf is reused by reference; only text differs.
        let reused = |refs: &Value, prefix: &str| -> BTreeSet<String> {
            refs.as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["$ref"].as_str().unwrap())
                .filter(|reference| !reference.ends_with("/text_action"))
                .map(|reference| reference.trim_start_matches(prefix).to_owned())
                .collect()
        };
        let recipe_leaves = reused(
            &schema["$defs"]["non_repeat_action"]["oneOf"],
            "input-sequence-v1.schema.json",
        );
        let input_leaves = reused(&input["$defs"]["non_repeat_action"]["oneOf"], "");
        assert_eq!(recipe_leaves, input_leaves);
        assert!(input["$defs"]["keyboard_timing"].is_object());
    }
}
