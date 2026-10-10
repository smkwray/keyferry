//! Host-side routines in the existing recipe format. No I/O, history or input retries.
use super::*;
use serde_json::json;

pub const MAX_STEPS: usize = 256;
const MAX_ROUTINE_MS: u64 = 180_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TargetOs {
    Macos,
    Windows,
    Linux,
    Any,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Verification {
    Flag(bool),
    Record {
        date: String,
        os_version: String,
        success_count: u32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Region {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Button {
    #[default]
    Left,
    Right,
    Middle,
}
impl Button {
    pub fn wire(self) -> &'static str {
        match self {
            Self::Left => "button_1",
            Self::Right => "button_2",
            Self::Middle => "button_3",
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnFail {
    #[default]
    Stop,
}

// Source strings are never formatted in diagnostics or receipts.
#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    Key {
        keys: Vec<String>,
    },
    TypeText {
        text: String,
    },
    Wait {
        ms: u64,
    },
    Move {
        x: u32,
        y: u32,
    },
    Click {
        x: u32,
        y: u32,
        #[serde(default)]
        button: Button,
        #[serde(default)]
        double: bool,
    },
    Scroll {
        x: u32,
        y: u32,
        dx: i64,
        dy: i64,
    },
    Drag {
        from_x: u32,
        from_y: u32,
        to_x: u32,
        to_y: u32,
        #[serde(default)]
        button: Button,
    },
    Repeat {
        count: u64,
        #[serde(default)]
        delay_ms: u64,
        steps: Vec<Step>,
    },
    ExpectText {
        query: String,
        timeout_ms: u64,
        #[serde(default)]
        region: Option<Region>,
        #[serde(default)]
        on_fail: OnFail,
        #[serde(default)]
        optional: bool,
    },
    ClickText {
        query: String,
        timeout_ms: u64,
        #[serde(default)]
        region: Option<Region>,
        #[serde(default)]
        button: Button,
        #[serde(default)]
        double: bool,
        #[serde(default)]
        on_fail: OnFail,
    },
    WaitForChange {
        timeout_ms: u64,
        #[serde(default)]
        region: Option<Region>,
        #[serde(default)]
        on_fail: OnFail,
    },
    WaitForStable {
        timeout_ms: u64,
        #[serde(default)]
        region: Option<Region>,
        #[serde(default)]
        on_fail: OnFail,
    },
    SecureText {
        #[serde(default)]
        param: Option<String>,
    },
}

impl Step {
    pub fn input_only(&self) -> bool {
        matches!(
            self,
            Self::Key { .. }
                | Self::TypeText { .. }
                | Self::Wait { .. }
                | Self::Move { .. }
                | Self::Click { .. }
                | Self::Scroll { .. }
                | Self::Drag { .. }
                | Self::Repeat { .. }
        )
    }
    pub fn pointer(&self) -> bool {
        match self {
            Self::Move { .. }
            | Self::Click { .. }
            | Self::Scroll { .. }
            | Self::Drag { .. }
            | Self::ClickText { .. } => true,
            Self::Repeat { steps, .. } => steps.iter().any(Self::pointer),
            _ => false,
        }
    }
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Key { .. } => "key",
            Self::TypeText { .. } => "type_text",
            Self::Wait { .. } => "wait",
            Self::Move { .. } => "move",
            Self::Click { .. } => "click",
            Self::Scroll { .. } => "scroll",
            Self::Drag { .. } => "drag",
            Self::Repeat { .. } => "repeat",
            Self::ExpectText { .. } => "expect_text",
            Self::ClickText { .. } => "click_text",
            Self::WaitForChange { .. } => "wait_for_change",
            Self::WaitForStable { .. } => "wait_for_stable",
            Self::SecureText { .. } => "secure_text",
        }
    }
}

/// Convert one input step to the production sequence vocabulary. The supplied mapper is the
/// session's calibrated screenshot mapping; validation uses a neutral placeholder mapping.
pub fn input_actions(
    step: &Step,
    point: &mut impl FnMut(u32, u32) -> Result<[f64; 2], RecipeError>,
) -> Result<Vec<Value>, RecipeError> {
    let move_to = |p: [f64; 2]| json!({"type":"move_absolute","x":p[0],"y":p[1]});
    Ok(match step {
        Step::Key { keys } => vec![if keys.len() == 1 {
            json!({"type":"tap","key":keys[0]})
        } else {
            json!({"type":"chord","keys":keys})
        }],
        Step::TypeText { text } => vec![json!({"type":"text","value":text})],
        Step::Wait { ms } => vec![json!({"type":"wait","ms":ms})],
        Step::Move { x, y } => vec![move_to(point(*x, *y)?)],
        Step::Click {
            x,
            y,
            button,
            double,
        } => vec![
            move_to(point(*x, *y)?),
            json!({"type":if *double {"double_click"} else {"click"},"button":button.wire()}),
        ],
        Step::Scroll { x, y, dx, dy } => vec![
            move_to(point(*x, *y)?),
            json!({"type":"scroll","horizontal":dx,"vertical":dy}),
        ],
        Step::Drag {
            from_x,
            from_y,
            to_x,
            to_y,
            button,
        } => {
            let from = point(*from_x, *from_y)?;
            let to = point(*to_x, *to_y)?;
            vec![
                move_to(from),
                json!({"type":"drag","x":to[0],"y":to[1],"button":button.wire(),"hold_ms":40}),
            ]
        }
        Step::Repeat {
            count,
            delay_ms,
            steps,
        } => {
            let mut body = Vec::new();
            for step in steps {
                body.extend(input_actions(step, point)?);
            }
            let mut result = Vec::new();
            if *count > 1 {
                let mut repeated = body.clone();
                if *delay_ms != 0 {
                    repeated.push(json!({"type":"wait","ms":delay_ms}));
                }
                result.push(json!({"type":"repeat","count":count-1,"actions":repeated}));
            }
            result.extend(body);
            result
        }
        _ => return Err(RecipeError::new("recipe.step")),
    })
}

/// Compile an entire contiguous stretch before any of it can be sent.
pub fn compile_stretch(
    steps: &[Step],
    timing: Option<InputKeyboardTiming>,
    start_within_ms: u64,
    point: &mut impl FnMut(u32, u32) -> Result<[f64; 2], RecipeError>,
) -> Result<(Vec<Value>, bool, u64), RecipeError> {
    let pointer = steps.iter().any(Step::pointer);
    let mut actions = Vec::new();
    for step in steps {
        actions.extend(input_actions(step, point)?);
    }
    let keyboard = actions.iter().any(has_keyboard);
    let mut value = json!({"schema":if pointer {"keyferry.input-sequence.v2"} else {"keyferry.input-sequence.v1"},
        "command_id":VALIDATION_COMMAND_ID,"arm":"command-scoped","start_within_ms":start_within_ms,"actions":actions});
    if keyboard {
        value["keyboard_profile"] = json!(LEGACY_WIRE_MAPPING);
    }
    if let Some(timing) = timing.filter(|_| keyboard) {
        value["keyboard_timing"] = json!(timing);
    }
    let bytes = serde_json::to_vec(&value).map_err(|_| RecipeError::new("recipe.body_limit"))?;
    let request =
        crate::parse_input_sequence_json(&bytes).map_err(|e| RecipeError::new(e.code()))?;
    let compiled = compile_input_sequence(&request).map_err(|e| RecipeError::new(e.code()))?;
    Ok((actions, pointer, compiled.planned_ms))
}

pub fn has_keyboard(v: &Value) -> bool {
    matches!(v["type"].as_str(), Some("text" | "tap" | "chord"))
        || v["actions"]
            .as_array()
            .is_some_and(|a| a.iter().any(has_keyboard))
}

fn pattern(p: &RecipeParameter) -> Result<Option<regex::Regex>, RecipeError> {
    p.pattern
        .as_ref()
        .map(|pattern| {
            if pattern.len() > 256 {
                return Err(RecipeError::new("recipe.parameter_pattern"));
            }
            regex::RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
                .size_limit(65_536)
                .nest_limit(16)
                .build()
                .map_err(|_| RecipeError::new("recipe.parameter_pattern"))
        })
        .transpose()
}
pub(super) fn secret_name(name: &str) -> bool {
    [
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "pwd",
        "otp",
        "secret",
        "token",
        "credential",
        "private_key",
        "recovery",
        "pin",
        "api_key",
    ]
    .iter()
    .any(|word| name.contains(word))
}

pub fn validate_definition(recipe: &RecipeV1) -> Result<Summary, RecipeError> {
    if !recipe.actions.is_empty() || recipe.target_os.is_none() || recipe.steps.len() > MAX_STEPS {
        return Err(RecipeError::new("recipe.schema"));
    }
    if recipe.tags.len() > 16
        || recipe.tags.iter().any(|s| s.is_empty() || s.len() > 32)
        || recipe
            .author
            .as_ref()
            .is_some_and(|s| s.chars().count() > 200)
    {
        return Err(RecipeError::new("recipe.metadata"));
    }
    match &recipe.verified {
        Some(Verification::Flag(true)) => return Err(RecipeError::new("recipe.verification")),
        Some(Verification::Record {
            date,
            os_version,
            success_count,
        }) if *success_count == 0
            || os_version.is_empty()
            || os_version.chars().count() > 200
            || !regex::Regex::new("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
                .expect("static pattern")
                .is_match(date) =>
        {
            return Err(RecipeError::new("recipe.verification"))
        }
        _ => {}
    }
    let mut params = Params::default();
    for (i, p) in recipe.parameters.iter().enumerate() {
        if secret_name(&p.name) && p.kind != ParameterKind::Secure {
            return Err(RecipeError::at("recipe.secret_parameter", i));
        }
        if p.description
            .as_ref()
            .is_some_and(|s| s.chars().count() > 200)
        {
            return Err(RecipeError::at("recipe.metadata", i));
        }
        pattern(p)?;
        match p.kind {
            ParameterKind::Text if p.minimum.is_none() && p.maximum.is_none() => {
                params.0.insert(
                    p.name.clone(),
                    json!(WORST_CASE_CHARACTER.repeat(p.max_chars() as usize)),
                );
            }
            ParameterKind::Integer
                if !p.optional
                    && p.pattern.is_none()
                    && p.minimum
                        .zip(p.maximum)
                        .is_some_and(|(min, max)| min <= max && min >= -127 && max <= 10_000) =>
            {
                params.0.insert(p.name.clone(), json!(p.maximum));
            }
            ParameterKind::Secure
                if p.pattern.is_none()
                    && p.minimum.is_none()
                    && p.maximum.is_none()
                    && p.max_chars.is_none() => {}
            _ => return Err(RecipeError::at("recipe.parameter_bounds", i)),
        }
    }
    let steps = resolve(recipe, &params, true)?;
    let mut planned_ms = 0;
    let mut stretches = 0;
    let mut i = 0;
    while i < steps.len() {
        if steps[i].input_only() {
            let begin = i;
            while i < steps.len() && steps[i].input_only() {
                i += 1;
            }
            let (_, _, ms) = compile_stretch(
                &steps[begin..i],
                recipe.timing,
                recipe.start_within_ms.unwrap_or(5000),
                &mut |_, _| Ok([0.5, 0.5]),
            )?;
            planned_ms += ms;
            stretches += 1;
        } else {
            planned_ms += match &steps[i] {
                Step::ExpectText { timeout_ms, .. }
                | Step::ClickText { timeout_ms, .. }
                | Step::WaitForChange { timeout_ms, .. }
                | Step::WaitForStable { timeout_ms, .. } => *timeout_ms,
                Step::SecureText { .. } => 0,
                _ => unreachable!(),
            };
            i += 1;
        }
    }
    if planned_ms > MAX_ROUTINE_MS {
        return Err(RecipeError::new("recipe.duration_limit"));
    }
    if let Some(timing) = recipe.timing {
        keyboard_timing(timing)
            .validate()
            .map_err(|_| RecipeError::new("timing.out_of_range"))?;
    }
    if !(1..=5000).contains(&recipe.start_within_ms.unwrap_or(5000)) {
        return Err(RecipeError::new("recipe.schema"));
    }
    Ok(Summary {
        route: Route::Routine,
        chunks: Some(stretches),
        planned_ms,
        replacements: 0,
    })
}

pub fn resolve(
    recipe: &RecipeV1,
    params: &Params,
    worst_case: bool,
) -> Result<Vec<Step>, RecipeError> {
    let mut params = params.clone();
    for p in &recipe.parameters {
        if p.optional && p.kind == ParameterKind::Text {
            params.0.entry(p.name.clone()).or_insert(json!(""));
        }
    }
    if params.0.keys().any(|name| {
        !recipe
            .parameters
            .iter()
            .any(|p| &p.name == name && p.kind != ParameterKind::Secure)
    }) {
        return Err(RecipeError::new("params.unknown"));
    }
    for (i, p) in recipe.parameters.iter().enumerate() {
        if p.kind == ParameterKind::Secure {
            continue;
        }
        let value = params
            .0
            .get(&p.name)
            .ok_or(RecipeError::at("params.missing", i))?;
        match p.kind {
            ParameterKind::Text => {
                let text = value
                    .as_str()
                    .ok_or(RecipeError::at("params.not_string", i))?;
                if (text.is_empty() && !p.optional) || text.len() > p.max_chars() as usize {
                    return Err(RecipeError::at("params.too_long", i));
                }
                if replace_unsupported_text(text).1 != 0 {
                    return Err(RecipeError::at("text.unsupported_character", i));
                }
                if !worst_case
                    && !text.is_empty()
                    && pattern(p)?.is_some_and(|regex| !regex.is_match(text))
                {
                    return Err(RecipeError::at("params.pattern", i));
                }
            }
            ParameterKind::Integer => {
                if value
                    .as_i64()
                    .is_none_or(|n| n < p.minimum.unwrap_or(0) || n > p.maximum.unwrap_or(0))
                {
                    return Err(RecipeError::at("params.bounds", i));
                }
            }
            ParameterKind::Secure => unreachable!(),
        }
    }
    let mut used = vec![false; recipe.parameters.len()];
    let mut steps = Vec::new();
    for source in &recipe.steps {
        let mut value = source.clone();
        substitute_step(&mut value, recipe, &params, &mut used)?;
        let step: Step =
            serde_json::from_value(value).map_err(|_| RecipeError::new("recipe.step"))?;
        validate_step(&step, false)?;
        steps.push(step);
    }
    if let Some(i) = used.iter().position(|used| !used) {
        return Err(RecipeError::at("recipe.parameter_unused", i));
    }
    Ok(steps)
}

fn substitute_step(
    value: &mut Value,
    recipe: &RecipeV1,
    params: &Params,
    used: &mut [bool],
) -> Result<(), RecipeError> {
    let object = value
        .as_object_mut()
        .ok_or(RecipeError::new("recipe.step"))?;
    if object.get("type").and_then(Value::as_str) == Some("secure_text") {
        if let Some(name) = object.get("param").and_then(Value::as_str) {
            let i = recipe
                .parameters
                .iter()
                .position(|p| p.name == name && p.kind == ParameterKind::Secure)
                .ok_or(RecipeError::new("recipe.secret_parameter"))?;
            used[i] = true;
        }
        return Ok(());
    }
    for (key, value) in object {
        if key == "steps" {
            for step in value
                .as_array_mut()
                .ok_or(RecipeError::new("recipe.step"))?
            {
                substitute_step(step, recipe, params, used)?;
            }
        } else if let Some(source) = value.as_str().map(str::to_owned) {
            if key == "type" || key == "on_fail" || key == "button" {
                continue;
            }
            let mut output = String::new();
            let mut rest = source.as_str();
            while let Some(start) = rest.find('{') {
                output.push_str(&rest[..start]);
                let tail = &rest[start + 1..];
                let end = tail.find('}').ok_or(RecipeError::new("recipe.template"))?;
                let name = &tail[..end];
                let i = recipe
                    .parameters
                    .iter()
                    .position(|p| p.name == name)
                    .ok_or(RecipeError::new("recipe.parameter_undeclared"))?;
                if recipe.parameters[i].kind == ParameterKind::Secure {
                    return Err(RecipeError::at("recipe.secret_parameter", i));
                }
                used[i] = true;
                let replacement = &params.0[name];
                if key != "text" && key != "query" {
                    if source != format!("{{{name}}}") || !replacement.is_i64() {
                        return Err(RecipeError::new("recipe.template"));
                    }
                    *value = replacement.clone();
                    break;
                }
                output.push_str(
                    replacement
                        .as_str()
                        .ok_or(RecipeError::new("recipe.template"))?,
                );
                rest = &tail[end + 1..];
            }
            if value.is_string() {
                output.push_str(rest);
                *value = json!(output);
            }
        }
    }
    Ok(())
}

fn validate_step(step: &Step, nested: bool) -> Result<(), RecipeError> {
    let pixel = |n: u32| n < 1280;
    let (timeout, region) = match step {
        Step::Repeat {
            count,
            delay_ms,
            steps,
        } => {
            if nested
                || !(1..=1000).contains(count)
                || *delay_ms > 10_000
                || steps.is_empty()
                || steps.len() > 32
                || steps
                    .iter()
                    .any(|s| !s.input_only() || matches!(s, Step::Repeat { .. }))
            {
                return Err(RecipeError::new("repeat.out_of_range"));
            }
            for step in steps {
                validate_step(step, true)?;
            }
            return Ok(());
        }
        Step::Key { keys } if keys.is_empty() || keys.len() > 14 => {
            return Err(RecipeError::new("chord.size"))
        }
        Step::TypeText { text }
            if text.is_empty() || text.len() > 4096 || replace_unsupported_text(text).1 != 0 =>
        {
            return Err(RecipeError::new("text.unsupported_character"))
        }
        Step::Move { x, y } | Step::Click { x, y, .. } if !pixel(*x) || !pixel(*y) => {
            return Err(RecipeError::new("pointer.range"))
        }
        Step::Scroll { x, y, dx, dy }
            if !pixel(*x)
                || !pixel(*y)
                || !(-127..=127).contains(dx)
                || !(-127..=127).contains(dy)
                || (*dx == 0 && *dy == 0) =>
        {
            return Err(RecipeError::new("pointer.range"))
        }
        Step::Drag {
            from_x,
            from_y,
            to_x,
            to_y,
            ..
        } if [*from_x, *from_y, *to_x, *to_y].iter().any(|n| !pixel(*n)) => {
            return Err(RecipeError::new("pointer.range"))
        }
        Step::ExpectText {
            query,
            timeout_ms,
            region,
            ..
        }
        | Step::ClickText {
            query,
            timeout_ms,
            region,
            ..
        } => {
            if (query.is_empty() && !matches!(step, Step::ExpectText { optional: true, .. }))
                || query.len() > 256
                || replace_unsupported_text(query).1 != 0
            {
                return Err(RecipeError::new("recipe.query"));
            }
            (*timeout_ms, *region)
        }
        Step::WaitForChange {
            timeout_ms, region, ..
        }
        | Step::WaitForStable {
            timeout_ms, region, ..
        } => (*timeout_ms, *region),
        _ => return Ok(()),
    };
    if !(1..=30_000).contains(&timeout)
        || region.is_some_and(|r| {
            r.width == 0
                || r.height == 0
                || r.x.saturating_add(r.width) > 1280
                || r.y.saturating_add(r.height) > 1280
        })
    {
        return Err(RecipeError::new("recipe.checkpoint"));
    }
    Ok(())
}

pub fn timing(recipe: &RecipeV1) -> Option<InputKeyboardTiming> {
    recipe.timing
}
pub fn start_within(recipe: &RecipeV1) -> u64 {
    recipe.start_within_ms.unwrap_or(5000)
}
/// Stable error for the calibrated mapper; coordinates never enter errors.
pub fn mapping_error() -> RecipeError {
    RecipeError::new("pointer.calibration_required")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn definition(steps: Value) -> Value {
        json!({"schema":"keyferry.recipe.v1","name":"test-routine","target_os":"any","verified":false,"steps":steps})
    }
    fn parsed(value: &Value) -> Result<RecipeV1, RecipeError> {
        parse(value.to_string().as_bytes())
    }
    fn params(value: Value) -> Params {
        parse_params(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn verification_records_validate_without_unicode_regex_classes() {
        let record = |date: &str| {
            let mut value = definition(json!([{"type":"key","keys":["ESCAPE"]}]));
            value["verified"] = json!({"date":date,"os_version":"macOS 26.3","success_count":1});
            parsed(&value)
        };
        assert!(record("2026-10-10").is_ok());
        assert_eq!(record("2026-1-10").unwrap_err().code(), "recipe.verification");
        let mut flag = definition(json!([{"type":"key","keys":["ESCAPE"]}]));
        flag["verified"] = json!(true);
        assert_eq!(parsed(&flag).unwrap_err().code(), "recipe.verification");
    }

    #[test]
    fn repeats_merge_and_compile_through_real_input_compiler() {
        let mut value = definition(json!([
            {"type":"key","keys":["CMD","SPACE"]},
            {"type":"type_text","text":"prefix-{app}"},
            {"type":"repeat","count":"{count}","delay_ms":800,"steps":[{"type":"key","keys":["ESCAPE"]}]}
        ]));
        value["parameters"] = json!([
            {"name":"app","type":"text","max_chars":20,"pattern":"[a-z]+"},
            {"name":"count","type":"integer","minimum":1,"maximum":10}
        ]);
        let recipe = parsed(&value).unwrap();
        let summary = validate(&recipe).unwrap();
        assert_eq!(summary.chunks, Some(1));
        let steps = resolve(
            &recipe,
            &params(json!({"app":"settings","count":10})),
            false,
        )
        .unwrap();
        let (actions, pointer, planned_ms) =
            compile_stretch(&steps, None, 5000, &mut |_, _| Ok([0.5, 0.5])).unwrap();
        assert!(!pointer);
        assert!(planned_ms > 7200);
        assert_eq!(actions[1]["value"], "prefix-settings");
        assert_eq!(actions[2]["count"], 9);
        assert_eq!(actions[2]["actions"][1]["ms"], 800);
        assert_eq!(
            actions.last().unwrap()["type"],
            "tap",
            "no delay after last repeat"
        );
        assert_eq!(
            resolve(
                &recipe,
                &params(json!({"app":"HAS SPACE","count":10})),
                false
            )
            .err()
            .unwrap()
            .code(),
            "params.pattern"
        );
        assert_eq!(
            resolve(
                &recipe,
                &params(json!({"app":"settings","count":11})),
                false
            )
            .err()
            .unwrap()
            .code(),
            "params.bounds"
        );
        assert_eq!(
            resolve(&recipe, &params(json!({"app":"é","count":10})), false)
                .err()
                .unwrap()
                .code(),
            "text.unsupported_character"
        );
    }

    #[test]
    fn secret_declarations_never_accept_or_expand_values() {
        for name in [
            "password",
            "passphrase",
            "auth_token",
            "recovery_key",
            "pin",
        ] {
            let mut value = definition(json!([{"type":"type_text","text":format!("{{{name}}}")} ]));
            value["parameters"] = json!([{"name":name,"type":"text"}]);
            assert_eq!(
                parsed(&value).unwrap_err().code(),
                "recipe.secret_parameter"
            );
        }
        let mut value = definition(json!([{"type":"secure_text","param":"password"}]));
        value["parameters"] =
            json!([{"name":"password","type":"secure","description":"Owner dialog only"}]);
        let recipe = parsed(&value).unwrap();
        assert!(matches!(
            resolve(&recipe, &Params::default(), false).unwrap()[0],
            Step::SecureText { .. }
        ));
        let error = resolve(
            &recipe,
            &params(json!({"password":"never-echo-this"})),
            false,
        )
        .err()
        .unwrap();
        assert_eq!(error.code(), "params.unknown");
        assert!(!format!("{error:?}").contains("never-echo-this"));
        value["steps"] = json!([{"type":"type_text","text":"{password}"}]);
        assert_eq!(
            parsed(&value).unwrap_err().code(),
            "recipe.secret_parameter"
        );
    }

    #[test]
    fn bounds_unknown_fields_and_checkpoint_fail_policy_are_strict() {
        for steps in [
            json!([{"type":"repeat","count":0,"steps":[{"type":"key","keys":["ESCAPE"]}]}]),
            json!([{"type":"repeat","count":1001,"steps":[{"type":"key","keys":["ESCAPE"]}]}]),
            json!([{"type":"repeat","count":2,"steps":[{"type":"expect_text","query":"ok","timeout_ms":100}]}]),
            json!([{"type":"repeat","count":2,"steps":[{"type":"repeat","count":2,"steps":[{"type":"wait","ms":1}]}]}]),
            json!([{"type":"expect_text","query":"ok","timeout_ms":30001}]),
            json!([{"type":"expect_text","query":"ok","timeout_ms":100,"on_fail":"retry"}]),
            json!([{"type":"secure_text","text":"never-echo-this"}]),
            json!([{"type":"wait","ms":0}]),
            json!([{"type":"move","x":1280,"y":0}]),
        ] {
            assert!(parsed(&definition(steps)).is_err());
        }
        let oversize = definition(
            json!([{"type":"repeat","count":1000,"delay_ms":800,"steps":[{"type":"key","keys":["ESCAPE"]}]}]),
        );
        assert!(
            parsed(&oversize).is_err(),
            "a long stretch rejects; it is not split"
        );
        let mut both = definition(json!([{"type":"key","keys":["ESCAPE"]}]));
        both["actions"] = json!([]);
        assert_eq!(parsed(&both).unwrap_err().code(), "recipe.schema");
        assert_eq!(parse(br#"{"schema":"keyferry.recipe.v1","name":"a","name":"b","target_os":"any","steps":[{"type":"wait","ms":1}]}"#).unwrap_err().code(),"recipe.duplicate_field");
    }

    #[test]
    fn optional_marker_does_not_create_a_secret_value() {
        let mut value = definition(json!([
            {"type":"secure_text"},
            {"type":"expect_text","query":"{marker}","optional":true,"timeout_ms":1000}
        ]));
        value["parameters"] =
            json!([{"name":"marker","type":"text","max_chars":100,"optional":true}]);
        let recipe = parsed(&value).unwrap();
        let steps = resolve(&recipe, &Params::default(), false).unwrap();
        assert!(matches!(&steps[1],Step::ExpectText{query,optional:true,..} if query.is_empty()));
    }
}
