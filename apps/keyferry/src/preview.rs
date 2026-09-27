use keyferry_layouts::text_stream::replace_unsupported_text;
use keyferry_layouts::{
    compile_sequence, keyboard_key, plan_text_us, KeyboardSequenceV1, LayoutError, SequenceAction,
    SequenceArmPolicy, TypingTiming, KEYBOARD_KEYS, SEQUENCE_SCHEMA_V1,
};
use serde_json::Value;

pub const DEFAULT_PROFILE: &str = "windows-us";
pub const SEQUENCE_EXAMPLE: &str = r#"{
  "schema": "keyferry.keyboard-sequence.v1",
  "profile": "windows-us",
  "arm": "command-scoped",
  "start_within_ms": 5000,
  "actions": [
    {"type": "tap", "key": "LEFT_GUI"},
    {"type": "wait", "ms": 250},
    {"type": "text", "value": "notepad"},
    {"type": "tap", "key": "ENTER"}
  ]
}"#;
pub const SEQUENCE_DRAFT: &str = r#"{
  "schema": "keyferry.keyboard-sequence.v1",
  "profile": "windows-us",
  "arm": "command-scoped",
  "start_within_ms": 5000,
  "actions": []
}"#;
const PREVIEW_COMMAND_ID: &str = "00000000-0000-7000-8000-000000000000";
const MAX_SEQUENCE_BODY: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextPreview {
    pub accepted: bool,
    pub status: String,
    pub normalized_text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequencePreview {
    pub accepted: bool,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSequence {
    pub request: KeyboardSequenceV1,
    pub source_nodes: usize,
    pub gestures: usize,
    pub planned_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceActionSummary {
    pub title: String,
    pub detail: String,
}

fn parse_sequence_request(
    source: &str,
    missing_command_id: &str,
) -> Result<(KeyboardSequenceV1, bool), &'static str> {
    if source.len() > MAX_SEQUENCE_BODY {
        return Err("input.body_limit");
    }
    let mut value: Value = serde_json::from_str(source).map_err(|_| "input.invalid_json")?;
    let object = value.as_object_mut().ok_or("input.not_object")?;
    let command_id_was_missing = !object.contains_key("command_id");
    if command_id_was_missing {
        object.insert(
            "command_id".to_owned(),
            Value::String(missing_command_id.to_owned()),
        );
    }
    let request: KeyboardSequenceV1 = serde_json::from_value(value).map_err(|_| "input.schema")?;
    let command_id = uuid::Uuid::parse_str(&request.command_id).map_err(|_| "input.command_id")?;
    if command_id.get_version_num() != 7 {
        return Err("input.command_id");
    }
    Ok((request, command_id_was_missing))
}

fn validate_sequence(request: KeyboardSequenceV1) -> Result<PreparedSequence, &'static str> {
    let compiled = compile_sequence(&request).map_err(|error| error.code())?;
    if serde_json::to_vec(&request)
        .map_err(|_| "internal.serialization")?
        .len()
        > MAX_SEQUENCE_BODY
    {
        return Err("input.body_limit");
    }
    Ok(PreparedSequence {
        request,
        source_nodes: compiled.source_nodes,
        gestures: compiled.gestures,
        planned_ms: compiled.planned_ms,
    })
}

pub fn prepare_sequence(
    source: &str,
    missing_command_id: &str,
) -> Result<PreparedSequence, &'static str> {
    let (request, _) = parse_sequence_request(source, missing_command_id)?;
    validate_sequence(request)
}

fn edit_sequence(
    source: &str,
    edit: impl FnOnce(&mut Vec<SequenceAction>) -> Result<(), &'static str>,
) -> Result<String, &'static str> {
    let (mut request, command_id_was_missing) = parse_sequence_request(source, PREVIEW_COMMAND_ID)?;
    edit(&mut request.actions)?;
    let prepared = validate_sequence(request)?;
    let mut value = serde_json::to_value(prepared.request).map_err(|_| "internal.serialization")?;
    if command_id_was_missing {
        value
            .as_object_mut()
            .ok_or("internal.serialization")?
            .remove("command_id");
    }
    let output = serde_json::to_string_pretty(&value).map_err(|_| "internal.serialization")?;
    if output.len() > MAX_SEQUENCE_BODY {
        return Err("input.body_limit");
    }
    Ok(output)
}

pub fn append_sequence_action(
    source: &str,
    action: SequenceAction,
) -> Result<String, &'static str> {
    edit_sequence(source, |actions| {
        actions.push(action);
        Ok(())
    })
}

pub fn remove_sequence_action(source: &str, index: usize) -> Result<String, &'static str> {
    edit_sequence(source, |actions| {
        if index >= actions.len() {
            return Err("builder.action_index");
        }
        actions.remove(index);
        Ok(())
    })
}

pub fn move_sequence_action(
    source: &str,
    index: usize,
    offset: i32,
) -> Result<String, &'static str> {
    edit_sequence(source, |actions| {
        let target = (index as i64) + i64::from(offset);
        if index >= actions.len() || target < 0 || target >= actions.len() as i64 {
            return Err("builder.action_index");
        }
        actions.swap(index, target as usize);
        Ok(())
    })
}

pub fn sequence_action_summaries(source: &str) -> Result<Vec<SequenceActionSummary>, &'static str> {
    let prepared = prepare_sequence(source, PREVIEW_COMMAND_ID)?;
    Ok(prepared
        .request
        .actions
        .iter()
        .map(|action| match action {
            SequenceAction::Text { value, .. } => SequenceActionSummary {
                title: "Text".to_owned(),
                detail: format!("{} characters", value.chars().count()),
            },
            SequenceAction::Tap { key, .. } => SequenceActionSummary {
                title: "Tap".to_owned(),
                detail: key.clone(),
            },
            SequenceAction::Chord { keys, .. } => SequenceActionSummary {
                title: "Chord".to_owned(),
                detail: keys.join(" + "),
            },
            SequenceAction::OrderedChord { keys, .. } => SequenceActionSummary {
                title: "Ordered chord".to_owned(),
                detail: keys.join(" → "),
            },
            SequenceAction::Wait { ms } => SequenceActionSummary {
                title: "Wait".to_owned(),
                detail: format!("{ms} ms released"),
            },
            SequenceAction::Repeat { count, actions } => SequenceActionSummary {
                title: "Repeat".to_owned(),
                detail: format!("{count} times · {} actions", actions.len()),
            },
        })
        .collect())
}

/// Resolves one friendly key name ("Ctrl", "CapsLock", "j", "Page Up", "5") to its registry name.
fn canonical_key_name(name: &str) -> Option<String> {
    let mut characters = name.chars();
    if let (Some(character), None) = (characters.next(), characters.next()) {
        let named = match character {
            'a'..='z' | 'A'..='Z' => return Some(character.to_ascii_uppercase().to_string()),
            '0'..='9' => return Some(format!("DIGIT_{character}")),
            '-' => "MINUS",
            '=' => "EQUAL",
            '[' => "LEFT_BRACKET",
            ']' => "RIGHT_BRACKET",
            '\\' => "BACKSLASH",
            ';' => "SEMICOLON",
            '\'' => "APOSTROPHE",
            '`' => "GRAVE",
            ',' => "COMMA",
            '.' => "PERIOD",
            '/' => "SLASH",
            _ => return None,
        };
        return Some(named.to_owned());
    }
    let compact = name
        .chars()
        .filter(|character| !matches!(character, ' ' | '_' | '-'))
        .collect::<String>()
        .to_ascii_uppercase();
    let alias = match compact.as_str() {
        "CTRL" | "CONTROL" => "LEFT_CONTROL",
        "SHIFT" => "LEFT_SHIFT",
        "ALT" | "OPTION" => "LEFT_ALT",
        "WIN" | "WINDOWS" | "GUI" | "META" | "SUPER" | "CMD" | "COMMAND" => "LEFT_GUI",
        "CAPS" => "CAPS_LOCK",
        "ESC" => "ESCAPE",
        "RETURN" => "ENTER",
        "DEL" => "DELETE",
        "INS" => "INSERT",
        "PGUP" => "PAGE_UP",
        "PGDN" => "PAGE_DOWN",
        "UP" => "UP_ARROW",
        "DOWN" => "DOWN_ARROW",
        "LEFT" => "LEFT_ARROW",
        "RIGHT" => "RIGHT_ARROW",
        _ => {
            return KEYBOARD_KEYS
                .iter()
                .find(|entry| entry.name.replace('_', "") == compact)
                .map(|entry| entry.name.to_owned())
        }
    };
    Some(alias.to_owned())
}

/// Parses keys typed in press order and separated by `+` into registry names.
pub fn parse_key_names(input: &str) -> Result<Vec<String>, String> {
    let names = input.split('+').map(str::trim).collect::<Vec<_>>();
    if names.iter().all(|name| name.is_empty()) {
        return Err("Type at least one key.".to_owned());
    }
    names
        .into_iter()
        .enumerate()
        .map(|(index, name)| {
            if name.is_empty() {
                return Err(format!("Key {} is empty.", index + 1));
            }
            canonical_key_name(name)
                .filter(|canonical| keyboard_key(canonical).is_some())
                .ok_or_else(|| {
                    format!(
                        "Key {} is not a known key name. Try Ctrl, Shift, Alt, Win, CapsLock, Enter, F5, PageUp, or a single character.",
                        index + 1
                    )
                })
        })
        .collect()
}

fn hotkey_from_keys(mut keys: Vec<String>) -> SequenceAction {
    if keys.len() == 1 {
        SequenceAction::Tap {
            key: keys.remove(0),
            timing: None,
        }
    } else {
        SequenceAction::OrderedChord { keys, timing: None }
    }
}

/// One key taps it; several keys are held in the typed order and released in reverse.
pub fn hotkey_action(input: &str) -> Result<SequenceAction, String> {
    parse_key_names(input).map(hotkey_from_keys)
}

pub fn preview_hotkey(input: &str) -> SequencePreview {
    let rejected = |status: String| SequencePreview {
        accepted: false,
        status,
    };
    if input.trim().is_empty() {
        return rejected(
            "Type keys in the order you press them, such as Ctrl + L or CapsLock + Space + J."
                .to_owned(),
        );
    }
    let keys = match parse_key_names(input) {
        Ok(keys) => keys,
        Err(status) => return rejected(status),
    };
    let status = if keys.len() == 1 {
        format!("Ready · taps {}.", keys[0])
    } else {
        format!(
            "Ready · presses {} in order, then releases in reverse.",
            keys.join(" → ")
        )
    };
    let request = KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.to_owned(),
        command_id: PREVIEW_COMMAND_ID.to_owned(),
        profile: DEFAULT_PROFILE.to_owned(),
        arm: SequenceArmPolicy::CommandScoped,
        start_within_ms: 5000,
        timing: None,
        actions: vec![hotkey_from_keys(keys)],
    };
    match compile_sequence(&request) {
        Ok(_) => SequencePreview {
            accepted: true,
            status,
        },
        Err(error) => rejected(format!(
            "Not ready · {} · no command will be sent.",
            error.code()
        )),
    }
}

pub fn preview_sequence(source: &str) -> SequencePreview {
    if source.trim().is_empty() {
        return SequencePreview {
            accepted: false,
            status: "Load the example or enter a Sequence v1 JSON object.".to_owned(),
        };
    }
    match prepare_sequence(source, PREVIEW_COMMAND_ID) {
        Ok(prepared) => SequencePreview {
            accepted: true,
            status: format!(
                "Ready · {} source actions · {} gestures · {} ms.",
                prepared.source_nodes, prepared.gestures, prepared.planned_ms
            ),
        },
        Err(code) => SequencePreview {
            accepted: false,
            status: format!("Not ready · {code} · no command will be sent."),
        },
    }
}

pub fn preview_text(
    profile: &str,
    text: &str,
    timing: TypingTiming,
    replace_unsupported: bool,
) -> TextPreview {
    if profile != DEFAULT_PROFILE {
        return TextPreview {
            accepted: false,
            status: format!("Rejected: target profile {profile:?} is not available in API v1."),
            normalized_text: text.to_owned(),
        };
    }
    if text.is_empty() {
        return TextPreview {
            accepted: false,
            status: "Enter text to send.".to_owned(),
            normalized_text: String::new(),
        };
    }
    if text.chars().count() > 4096 {
        return TextPreview {
            accepted: false,
            status: "Rejected: text exceeds the 4096-character API limit.".to_owned(),
            normalized_text: text.to_owned(),
        };
    }
    let (candidate, replacements) = if replace_unsupported {
        replace_unsupported_text(text)
    } else {
        (text.to_owned(), 0)
    };
    match plan_text_us(&candidate, timing) {
        Ok(_) => {
            let normalized_text = candidate.replace("\r\n", "\n");
            let newline_changed = normalized_text != candidate;
            let status = if replacements != 0 && newline_changed {
                format!("Ready · {replacements} unsupported characters become ? · CRLF becomes LF.")
            } else if replacements != 0 {
                format!("Ready · {replacements} unsupported characters become ?.")
            } else if newline_changed {
                "Ready · CRLF becomes LF.".to_owned()
            } else {
                "Ready to send.".to_owned()
            };
            TextPreview {
                accepted: true,
                status,
                normalized_text,
            }
        }
        Err(LayoutError::UnsupportedCharacter(character)) => TextPreview {
            accepted: false,
            status: format!(
                "Rejected: unsupported character U+{:04X}; no command will be sent.",
                character as u32
            ),
            normalized_text: text.to_owned(),
        },
        Err(LayoutError::TimingOutOfRange(_)) => TextPreview {
            accepted: false,
            status: "Rejected: selected typing timing is outside the daemon limits.".to_owned(),
            normalized_text: text.to_owned(),
        },
        // Key-name errors belong to tap/chord resolution and cannot arise from text
        // planning. Named explicitly rather than with a wildcard so a future layout
        // error becomes a compile error here instead of a silently mislabelled one.
        Err(LayoutError::UnknownKeyName | LayoutError::ChordNeedsExactlyOneKey) => TextPreview {
            accepted: false,
            status: "Rejected: this text cannot be mapped for the selected profile.".to_owned(),
            normalized_text: text.to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_rejection_and_crlf_normalization() {
        let rejected = preview_text(DEFAULT_PROFILE, "ok—no", TypingTiming::DESKTOP_SAFE, false);
        assert!(!rejected.accepted);
        assert!(rejected.status.contains("U+2014"));

        let replaced = preview_text(DEFAULT_PROFILE, "ok—no🙂", TypingTiming::DESKTOP_SAFE, true);
        assert!(replaced.accepted);
        assert_eq!(replaced.normalized_text, "ok?no?");
        assert!(replaced
            .status
            .contains("2 unsupported characters become ?"));

        let normalized = preview_text(
            DEFAULT_PROFILE,
            "line\r\nnext",
            TypingTiming::DESKTOP_SAFE,
            false,
        );
        assert!(normalized.accepted);
        assert_eq!(normalized.normalized_text, "line\nnext");
        assert!(normalized.status.contains("CRLF becomes LF"));
    }

    #[test]
    fn sequence_preview_uses_the_shared_compiler_and_injects_uuid_v7() {
        let preview = preview_sequence(SEQUENCE_EXAMPLE);
        assert!(preview.accepted);
        assert_eq!(
            preview.status,
            "Ready · 4 source actions · 9 gestures · 718 ms."
        );
        let prepared =
            prepare_sequence(SEQUENCE_EXAMPLE, "019d1234-5678-7abc-8123-456789abcdef").unwrap();
        assert_eq!(
            prepared.request.command_id,
            "019d1234-5678-7abc-8123-456789abcdef"
        );
        assert_eq!(prepared.gestures, 9);
        assert_eq!(prepared.planned_ms, 718);
    }

    #[test]
    fn sequence_preview_rejects_strict_or_unsafe_input_without_echoing_it() {
        let secret = "must-not-appear";
        let unknown_field = format!(
            r#"{{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{{"type":"tap","key":"A","value":"{secret}"}}]}}"#
        );
        let preview = preview_sequence(&unknown_field);
        assert!(!preview.accepted);
        assert!(preview.status.contains("input.schema"));
        assert!(!preview.status.contains(secret));

        let rollover = r#"{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"chord","keys":["A","B","C","D","E","F","G"]}]}"#;
        let preview = preview_sequence(rollover);
        assert!(!preview.accepted);
        assert!(preview.status.contains("chord.rollover_limit"));
    }

    #[test]
    fn visual_builder_edits_the_canonical_sequence_and_preserves_uuid_omission() {
        let added = append_sequence_action(
            SEQUENCE_EXAMPLE,
            SequenceAction::Chord {
                keys: vec!["LEFT_CONTROL".to_owned(), "L".to_owned()],
                timing: None,
            },
        )
        .unwrap();
        assert!(!added.contains("command_id"));
        let prepared = prepare_sequence(&added, PREVIEW_COMMAND_ID).unwrap();
        assert_eq!(prepared.request.actions.len(), 5);
        assert!(matches!(
            &prepared.request.actions[4],
            SequenceAction::Chord { keys, timing: None }
                if keys == &["LEFT_CONTROL".to_owned(), "L".to_owned()]
        ));

        let moved = move_sequence_action(&added, 4, -1).unwrap();
        let summaries = sequence_action_summaries(&moved).unwrap();
        assert_eq!(summaries[3].title, "Chord");
        assert_eq!(summaries[3].detail, "LEFT_CONTROL + L");

        let removed = remove_sequence_action(&moved, 3).unwrap();
        let prepared = prepare_sequence(&removed, PREVIEW_COMMAND_ID).unwrap();
        assert_eq!(prepared.request.actions.len(), 4);
    }

    #[test]
    fn hotkeys_accept_friendly_names_in_press_order() {
        assert_eq!(
            parse_key_names("CapsLock + Space + j").unwrap(),
            ["CAPS_LOCK", "SPACE", "J"]
        );
        assert_eq!(
            parse_key_names("ctrl+alt+Del").unwrap(),
            ["LEFT_CONTROL", "LEFT_ALT", "DELETE"]
        );
        assert_eq!(
            parse_key_names("Win + page up + F5 + 1 + /").unwrap(),
            ["LEFT_GUI", "PAGE_UP", "F5", "DIGIT_1", "SLASH"]
        );
        assert_eq!(
            parse_key_names("LEFT_CONTROL+up").unwrap(),
            ["LEFT_CONTROL", "UP_ARROW"]
        );

        assert!(matches!(
            hotkey_action("Enter").unwrap(),
            SequenceAction::Tap { key, timing: None } if key == "ENTER"
        ));
        assert!(matches!(
            hotkey_action("CapsLock+J").unwrap(),
            SequenceAction::OrderedChord { keys, timing: None } if keys == ["CAPS_LOCK", "J"]
        ));

        let ready = preview_hotkey("Caps Lock + Space + J");
        assert!(ready.accepted);
        assert_eq!(
            ready.status,
            "Ready · presses CAPS_LOCK → SPACE → J in order, then releases in reverse."
        );
    }

    #[test]
    fn hotkeys_fail_closed_without_echoing_unknown_names() {
        let secret = "must-not-appear";
        let unknown = preview_hotkey(&format!("Ctrl + {secret}"));
        assert!(!unknown.accepted);
        assert!(unknown.status.starts_with("Key 2 is not a known key name"));
        assert!(!unknown.status.contains(secret));

        assert!(!preview_hotkey("").accepted);
        assert!(!preview_hotkey("Ctrl +").accepted);
        assert!(parse_key_names("Ctrl ++ L").is_err());
        assert!(parse_key_names("Mute").is_err());

        let duplicate = preview_hotkey("Ctrl + ctrl");
        assert!(!duplicate.accepted);
        assert!(duplicate.status.contains("no command will be sent"));

        let too_many = preview_hotkey("A+B+C+D+E+F+G");
        assert!(!too_many.accepted);
    }

    #[test]
    fn visual_builder_fails_closed_without_replacing_valid_source() {
        let rollover = SequenceAction::Chord {
            keys: ["A", "B", "C", "D", "E", "F", "G"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            timing: None,
        };
        assert_eq!(
            append_sequence_action(SEQUENCE_EXAMPLE, rollover),
            Err("chord.rollover_limit")
        );
        assert_eq!(
            remove_sequence_action(SEQUENCE_EXAMPLE, 99),
            Err("builder.action_index")
        );
        assert_eq!(
            move_sequence_action(SEQUENCE_EXAMPLE, 0, -1),
            Err("builder.action_index")
        );
    }
}
