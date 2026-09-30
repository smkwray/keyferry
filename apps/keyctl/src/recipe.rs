//! `keyctl recipe`: this computer's saved-sequence library (`protocol/recipe-v1.md`).
//!
//! `list`, `inspect`, `validate`, and `import` are local and never open Keyferry. `run` expands a
//! recipe here into one ordinary sequence and submits it once through the shared submit engine;
//! it never writes to the library. No output carries an action body or a parameter value.

use super::{
    default_recipe_dir, emit_json_line, emit_sequence_result, prepare_exit, prepare_input_sequence,
    prepare_sequence, sequence_client, submit_prepared_command, SequenceOutcome,
};
use keyferry_layouts::recipe::{self as expander, Params, RecipeError, RecipeV1, Request, Summary};
use keyferry_layouts::text_stream::UnsupportedTextPolicy;
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
};

const HELP: &str = "keyctl recipe <subcommand>  (saved sequences on this computer)\n  list | inspect NAME | validate NAME | validate --input PATH  (local; no device contact)\n  import PATH [--replace]  (validate and save; the only library writer)\n  run DEVICE NAME [--unsupported reject|replace] [--detach]  (parameters: one JSON object on stdin)\n  Run `keyctl recipe --example` for a valid starting recipe.";
const EXAMPLE: &str = r#"{"schema":"keyferry.recipe.v1","name":"type-note","parameters":[{"name":"note","type":"text","max_chars":256}],"actions":[{"type":"text","param":"note"}]}"#;
const LIST_SCHEMA: &str = "keyferry.recipe-list.v1";
const INSPECTION_SCHEMA: &str = "keyferry.recipe-inspection.v1";
const VALIDATION_SCHEMA: &str = "keyferry.recipe-validation.v1";
const IMPORT_SCHEMA: &str = "keyferry.recipe-import.v1";
const REPLACEMENTS_SCHEMA: &str = "keyferry.recipe-replacements.v1";
const CLI_ERROR_SCHEMA: &str = "keyferry.recipe-cli-error.v1";

/// A payload-free failure: a stable code, an optional parameter index, and an exit status.
#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    parameter_index: Option<usize>,
    exit: u8,
}

impl Failure {
    const fn new(code: &'static str, exit: u8) -> Self {
        Self {
            code,
            parameter_index: None,
            exit,
        }
    }

    fn json(self) -> Value {
        let mut error = json!({ "code": self.code });
        if let Some(index) = self.parameter_index {
            error["parameter_index"] = json!(index);
        }
        error
    }
}

impl From<RecipeError> for Failure {
    fn from(error: RecipeError) -> Self {
        Self {
            code: error.code(),
            parameter_index: error.parameter_index(),
            exit: 20,
        }
    }
}

pub(super) fn run(args: &[String], url: &str, token_file: &Path) -> u8 {
    match (args.first().map(String::as_str), args.len()) {
        (Some("--help"), 1) => {
            println!("{HELP}");
            0
        }
        (Some("--example"), 1) => {
            println!("{EXAMPLE}");
            0
        }
        (Some("list"), 1) => list(),
        (Some("inspect"), 2) => inspect(&args[1]),
        (Some("validate"), 3) if args[1] == "--input" => validate(
            read_file(Path::new(&args[2]))
                .and_then(|bytes| expander::parse(&bytes).map_err(Failure::from)),
        ),
        (Some("validate"), 2) => validate(load(&default_recipe_dir(), &args[1])),
        (Some("import"), 2) => import(Path::new(&args[1]), false),
        (Some("import"), 3) if args[2] == "--replace" => import(Path::new(&args[1]), true),
        (Some("run"), _) => run_recipe(&args[1..], url, token_file),
        _ => {
            emit_json_line(&json!({"schema": CLI_ERROR_SCHEMA, "error": {"code": "input.usage"}}));
            20
        }
    }
}

/// Reads at most one byte past the shared JSON cap, so the parser, not the reader, reports an
/// oversize recipe (`recipe.limit`) or parameter object (`params.limit`).
fn read_capped(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(expander::MAX_RECIPE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_file(path: &Path) -> Result<Vec<u8>, Failure> {
    let file = fs::File::open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            Failure::new("recipe.not_found", 20)
        } else {
            Failure::new("recipe.unreadable", 23)
        }
    })?;
    read_capped(file).map_err(|_| Failure::new("recipe.unreadable", 23))
}

/// Loads `<library>/<name>.json`. The name is checked before any path is built.
fn load(library: &Path, name: &str) -> Result<RecipeV1, Failure> {
    if !expander::is_valid_name(name) {
        return Err(Failure::new("recipe.name", 20));
    }
    let bytes = read_file(&library.join(format!("{name}.json")))?;
    let recipe = expander::parse(&bytes)?;
    expander::check_file_stem(&recipe, name)?;
    Ok(recipe)
}

fn metadata(name: &str, recipe: Option<&RecipeV1>) -> Value {
    json!({
        "name": name,
        "revision": recipe.and_then(RecipeV1::revision),
        "description": recipe.and_then(RecipeV1::description),
        "parameters": recipe.map(|recipe| {
            recipe
                .parameters()
                .iter()
                .map(|parameter| {
                    json!({
                        "name": parameter.name,
                        "type": parameter.kind,
                        "max_chars": parameter.max_chars(),
                    })
                })
                .collect::<Vec<_>>()
        }),
    })
}

/// Adds the validation summary, or the failure, to `output`; returns it with the exit status.
fn with_validation(mut output: Value, outcome: Result<Summary, Failure>) -> (Value, u8) {
    match outcome {
        Ok(summary) => {
            output["valid"] = json!(true);
            output["route"] = json!(summary.route.name());
            output["chunks"] = json!(summary.chunks);
            output["planned_ms"] = json!(summary.planned_ms);
            output["error"] = Value::Null;
            (output, 0)
        }
        Err(failure) => {
            output["valid"] = json!(false);
            output["error"] = failure.json();
            (output, failure.exit)
        }
    }
}

fn list() -> u8 {
    let library = default_recipe_dir();
    let unreadable = || {
        emit_json_line(&json!({
            "schema": LIST_SCHEMA,
            "library": library.to_string_lossy(),
            "recipes": null,
            "error": {"code": "recipe.library_unreadable"},
        }));
        23
    };
    let mut names = Vec::new();
    match fs::read_dir(&library) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    return unreadable();
                };
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                    && path.is_file()
                {
                    if let Some(stem) = path.file_stem() {
                        names.push(stem.to_string_lossy().into_owned());
                    }
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return unreadable(),
    }
    names.sort();
    let recipes: Vec<Value> = names
        .iter()
        .map(|name| {
            let (mut entry, outcome) = match load(&library, name) {
                Ok(recipe) => (
                    metadata(name, Some(&recipe)),
                    expander::validate(&recipe).map_err(Failure::from),
                ),
                Err(failure) => (metadata(name, None), Err(failure)),
            };
            entry["valid"] = json!(outcome.is_ok());
            if let Err(failure) = outcome {
                entry["error"] = failure.json();
            }
            entry
        })
        .collect();
    emit_json_line(&json!({
        "schema": LIST_SCHEMA,
        "library": library.to_string_lossy(),
        "recipes": recipes,
    }));
    0
}

fn inspect(name: &str) -> u8 {
    let (output, exit) = match load(&default_recipe_dir(), name) {
        Ok(recipe) => {
            let mut output = metadata(recipe.name(), Some(&recipe));
            output["schema"] = json!(INSPECTION_SCHEMA);
            with_validation(output, expander::validate(&recipe).map_err(Failure::from))
        }
        Err(failure) => with_validation(json!({"schema": INSPECTION_SCHEMA}), Err(failure)),
    };
    emit_json_line(&output);
    exit
}

fn validate(recipe: Result<RecipeV1, Failure>) -> u8 {
    let (output, exit) = match recipe {
        Ok(recipe) => with_validation(
            json!({"schema": VALIDATION_SCHEMA, "name": recipe.name()}),
            expander::validate(&recipe).map_err(Failure::from),
        ),
        Err(failure) => with_validation(json!({"schema": VALIDATION_SCHEMA}), Err(failure)),
    };
    emit_json_line(&output);
    exit
}

/// The library's only writer: validates the source, then publishes it as `<name>.json`.
fn import(source: &Path, replace: bool) -> u8 {
    let mut output = json!({"schema": IMPORT_SCHEMA});
    let result = read_file(source).and_then(|bytes| {
        let recipe = expander::parse(&bytes)?;
        output["name"] = json!(recipe.name());
        expander::validate(&recipe)?;
        publish(&default_recipe_dir(), recipe.name(), &bytes, replace)
    });
    let exit = match result {
        Ok(replaced) => {
            output["imported"] = json!(true);
            output["replaced"] = json!(replaced);
            output["error"] = Value::Null;
            0
        }
        Err(failure) => {
            output["imported"] = json!(false);
            output["error"] = failure.json();
            failure.exit
        }
    };
    emit_json_line(&output);
    exit
}

/// Publishes `<name>.json`. Without `replace` the entry is created exclusively, which fails
/// atomically if the name exists, so a concurrent import is never overwritten. With `replace` a
/// complete temporary file is renamed over the entry, so a reader never sees a partial recipe.
/// No hard links: on Windows a scanner holding a deleted link open blocks later replacement.
/// Returns whether an entry was replaced.
fn publish(library: &Path, name: &str, bytes: &[u8], replace: bool) -> Result<bool, Failure> {
    let write_failed = Failure::new("recipe.write_failed", 25);
    // Saved recipes may hold literal text: owner-only on Unix, like the service token.
    let mut directory = fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut directory, 0o700);
    directory.create(library).map_err(|_| write_failed)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let target = library.join(format!("{name}.json"));
    let path = if replace {
        library.join(format!(".{name}.{}.tmp", uuid::Uuid::now_v7()))
    } else {
        target.clone()
    };
    let mut file = options.open(&path).map_err(|error| {
        if !replace && error.kind() == io::ErrorKind::AlreadyExists {
            Failure::new("recipe.exists", 20)
        } else {
            write_failed
        }
    })?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    let published = written.and_then(|()| {
        if replace {
            let existed = fs::symlink_metadata(&target).is_ok();
            retry_transient(|| fs::rename(&path, &target)).map(|()| existed)
        } else {
            Ok(false)
        }
    });
    if published.is_err() {
        let _ = fs::remove_file(&path);
    }
    published.map_err(|_| write_failed)
}

/// Windows scanners briefly open new files, so replacing one can fail with access denied for a few
/// milliseconds. This retries only that local file operation.
fn retry_transient(mut operation: impl FnMut() -> io::Result<()>) -> io::Result<()> {
    let mut attempts = 0;
    loop {
        match operation() {
            Err(error)
                if cfg!(windows)
                    && error.kind() == io::ErrorKind::PermissionDenied
                    && attempts < 40 =>
            {
                attempts += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            result => return result,
        }
    }
}

struct PreparedRun {
    route: &'static str,
    command_id: String,
    body: String,
    replacements: u64,
}

/// Stdout keeps exactly the command-result line; a parameter's index goes to stderr as metadata.
fn rejected(device: &str, failure: Failure) -> u8 {
    if failure.parameter_index.is_some() {
        eprintln!(
            "{}",
            json!({"schema": CLI_ERROR_SCHEMA, "error": failure.json()})
        );
    }
    emit_sequence_result(device, None, SequenceOutcome::Rejected, Some(failure.code));
    failure.exit
}

/// `run DEVICE NAME [--unsupported reject|replace] [--detach]`. Parameters come only from bounded
/// stdin, so any other argument is refused rather than read as a payload.
fn run_recipe(args: &[String], url: &str, token_file: &Path) -> u8 {
    let usage = Failure::new("input.usage", 20);
    let device = match args.first() {
        Some(device) if !device.is_empty() && !device.starts_with("--") => device.as_str(),
        _ => return rejected("", usage),
    };
    let Some(name) = args.get(1) else {
        return rejected(device, usage);
    };
    let mut unsupported = None;
    let mut detach = false;
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--detach" if !detach => detach = true,
            "--unsupported" if unsupported.is_none() => {
                unsupported = Some(match args.get(index + 1).map(String::as_str) {
                    Some("reject") => UnsupportedTextPolicy::Reject,
                    Some("replace") => UnsupportedTextPolicy::Replace,
                    _ => {
                        return rejected(device, Failure::new("input.unsupported_policy", 20));
                    }
                });
                index += 1;
            }
            _ => return rejected(device, Failure::new("input.argv_payload_refused", 20)),
        }
        index += 1;
    }
    let unsupported = unsupported.unwrap_or_default();
    let prepared = match prepare_run(name, unsupported) {
        Ok(prepared) => prepared,
        Err(failure) => return rejected(device, failure),
    };
    if unsupported == UnsupportedTextPolicy::Replace {
        // The explicit lossy override reports a metadata-only count; stdout keeps exactly the
        // command-result line.
        eprintln!(
            "{}",
            json!({"schema": REPLACEMENTS_SCHEMA, "replacements": prepared.replacements})
        );
    }
    let client = match sequence_client(url, token_file, device) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    submit_prepared_command(
        &client,
        device,
        detach,
        prepared.route,
        &prepared.command_id,
        &prepared.body,
    )
}

/// Everything before device contact: load, read parameters, expand, and prepare the one body.
fn prepare_run(name: &str, unsupported: UnsupportedTextPolicy) -> Result<PreparedRun, Failure> {
    let recipe = load(&default_recipe_dir(), name)?;
    let params = if recipe.parameters().is_empty() {
        Params::default()
    } else {
        let bytes = read_capped(io::stdin()).map_err(|_| Failure::new("input.invalid", 20))?;
        expander::parse_params(&bytes)?
    };
    let command_id = uuid::Uuid::now_v7().to_string();
    let expanded = expander::expand(&recipe, &params, unsupported, &command_id)?;
    let (command_id, body) = match &expanded.request {
        Request::Keyboard(request) => serde_json::to_string(request)
            .map_err(|_| "internal.serialization")
            .and_then(|raw| prepare_sequence(&raw))
            .map(|sequence| (sequence.command_id, sequence.body)),
        Request::Input(request) => serde_json::to_vec(request)
            .map_err(|_| "internal.serialization")
            .and_then(|raw| prepare_input_sequence(&raw))
            .map(|sequence| (sequence.command_id, sequence.body)),
    }
    .map_err(|code| Failure::new(code, prepare_exit(code)))?;
    Ok(PreparedRun {
        route: expanded.summary.route.path(),
        command_id,
        body,
        replacements: expanded.summary.replacements,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn library() -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!("keyctl-publish-{}", uuid::Uuid::now_v7()))
            .join("library")
    }

    fn entries(library: &Path) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(library)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn publish_never_overwrites_without_replace_even_when_the_entry_appears_late() {
        let library = library();
        assert_eq!(publish(&library, "open", b"first", false).ok(), Some(false));
        // No existence pre-check: the atomic link itself refuses an entry another import won.
        let refused = publish(&library, "open", b"second", false).err().unwrap();
        assert_eq!((refused.code, refused.exit), ("recipe.exists", 20));
        assert_eq!(fs::read(library.join("open.json")).unwrap(), b"first");
        assert_eq!(publish(&library, "open", b"third", true).ok(), Some(true));
        assert_eq!(fs::read(library.join("open.json")).unwrap(), b"third");
        assert_eq!(
            entries(&library),
            ["open.json"],
            "no temporary file remains"
        );
        fs::remove_dir_all(library.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn publish_keeps_the_library_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let library = library();
        assert_eq!(publish(&library, "open", b"first", false).ok(), Some(false));
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&library), 0o700);
        assert_eq!(mode(&library.join("open.json")), 0o600);
        assert_eq!(publish(&library, "open", b"second", true).ok(), Some(true));
        assert_eq!(mode(&library.join("open.json")), 0o600);
        fs::remove_dir_all(library.parent().unwrap()).unwrap();
    }

    #[test]
    fn example_is_one_valid_recipe_and_help_lists_every_subcommand() {
        let recipe = expander::parse(EXAMPLE.as_bytes()).unwrap();
        let summary = expander::validate(&recipe).unwrap();
        assert_eq!(summary.route.name(), "sequences");
        assert_eq!(recipe.parameters().len(), 1);
        assert_eq!(recipe.parameters()[0].kind, expander::ParameterKind::Text);
        assert!(!EXAMPLE.contains('\n'));
        for subcommand in [
            "list",
            "inspect NAME",
            "validate NAME",
            "validate --input PATH",
            "import PATH [--replace]",
            "run DEVICE NAME",
        ] {
            assert!(HELP.contains(subcommand), "{subcommand}");
        }
        let offline = Path::new("missing-token");
        for flag in ["--help", "--example"] {
            assert_eq!(run(&[flag.to_owned()], "http://127.0.0.1:9", offline), 0);
        }
        assert_eq!(
            run(
                &["--example".to_owned(), "extra".to_owned()],
                "http://127.0.0.1:9",
                offline
            ),
            20
        );
    }

    #[test]
    fn every_library_code_is_documented() {
        let doc = include_str!("../../../protocol/recipe-v1.md");
        let source = include_str!("recipe.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let codes: Vec<&str> = production
            .split('"')
            .filter(|token| {
                token.strip_prefix("recipe.").is_some_and(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                })
            })
            .collect();
        assert!(codes.contains(&"recipe.exists"), "{codes:?}");
        for code in codes {
            assert!(doc.contains(&format!("`{code}`")), "{code} is undocumented");
        }
    }
}
