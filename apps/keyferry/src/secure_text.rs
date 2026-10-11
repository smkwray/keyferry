//! An agent requests a local human prompt, never supplies or receives its text.
use super::ui;
use keyferry::api::{ApiClient, CommandOutcome, DeviceView};
use keyferry_core::process::SecureTextWake as WakeMode;
use keyferry_layouts::{
    compile_sequence, InputAction, InputArmPolicy, InputSequenceV1, KeyboardSequenceV1,
    SequenceAction, SequenceArmPolicy, TypingTiming, INPUT_SEQUENCE_SCHEMA_V1, LEGACY_WIRE_MAPPING,
    SEQUENCE_SCHEMA_V1,
};
use slint::ComponentHandle;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const PROMPT_LIFETIME: Duration = Duration::from_secs(120);
const RESULT_LIFETIME: Duration = Duration::from_secs(30);
const MAX_SECRET_BYTES: usize = 256;

fn sequence(text: &str, enter: bool) -> Result<Zeroizing<KeyboardSequenceV1>, &'static str> {
    if text.is_empty() || text.len() > MAX_SECRET_BYTES {
        return Err("Use 1–256 printable ASCII characters.");
    }
    if !text.bytes().all(|byte| (0x20..=0x7e).contains(&byte)) {
        return Err("Unsupported text: only printable ASCII is accepted; nothing was sent.");
    }
    let mut request = Zeroizing::new(KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.into(),
        command_id: uuid::Uuid::now_v7().to_string(),
        profile: LEGACY_WIRE_MAPPING.into(),
        arm: SequenceArmPolicy::CommandScoped,
        start_within_ms: 5000,
        timing: Some(TypingTiming::COMPATIBILITY),
        actions: vec![SequenceAction::Text {
            value: text.into(),
            timing: None,
        }],
    });
    if enter {
        // macOS password fields (e.g. the lock screen) drop an Enter that arrives immediately
        // after the last character; give the target a moment to accept the text first.
        request.actions.push(SequenceAction::Wait { ms: 400 });
        request.actions.push(SequenceAction::Tap {
            key: "ENTER".into(),
            timing: None,
        });
    }
    // Validation creates reversible HID reports too; wipe those when this scope exits.
    let _compiled = Zeroizing::new(
        compile_sequence(&request)
            .map_err(|_| "Text exceeds the one-shot command limits; nothing was sent.")?,
    );
    Ok(request)
}

fn ready(device: &DeviceView, id: &str) -> bool {
    device.id == id
        && device.link == "authenticated"
        && device.mode == "keyboard"
        && !device.armed
        && !device.maintenance
        && device.active_command_id.is_none()
}

fn clear(window: &ui::SecureTextWindow) {
    window.set_secret("".into());
    // Destroy the editor, including its undo history, instead of retaining a hidden field.
    window.set_accepting(false);
    window.set_ready(false);
}

fn finish(weak: slint::Weak<ui::SecureTextWindow>, message: String) {
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = weak.upgrade() {
            window.set_sending(false);
            window.set_status(format!("{message}\nCloses in 30 seconds.").into());
            // Give the owner time to read the receipt, then end the separate prompt process.
            let weak = window.as_weak();
            slint::Timer::single_shot(RESULT_LIFETIME, move || {
                if let Some(window) = weak.upgrade() {
                    let _ = window.hide();
                }
            });
        }
    });
}

fn submit_once(
    client: &ApiClient,
    id: &str,
    request: &mut KeyboardSequenceV1,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> String {
    if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
        request.zeroize();
        return "Request expired or cancelled. Nothing was sent.".into();
    }
    let route_ready = client.device(id).is_ok_and(|view| ready(&view, id));
    if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) || !route_ready {
        request.zeroize();
        return "Route changed, cancelled, or request expired. Nothing was sent.".into();
    }
    let command_id = request.command_id.clone();
    let result = client.submit_sequence(id, request).map(Zeroizing::new);
    request.zeroize();
    // Never display a peer's message or parser error: they can contain reflected input.
    let outcome = result
        .ok()
        .filter(|response| response.device_id == id && response.command_id == command_id)
        .map(|response| response.outcome);
    let outcome = await_outcome(client, id, &command_id, outcome, cancelled, None);
    let result = match outcome {
        Some(CommandOutcome::Emitted) => {
            "EMITTED: HID input completed. Successful unlock is unverified."
        }
        Some(CommandOutcome::Rejected) => "REJECTED: command rejected.",
        Some(CommandOutcome::Aborted) => {
            "ABORTED: input may be partial. Check the target before requesting again."
        }
        _ => "UNKNOWN: input may have started. Check the target before requesting again.",
    };
    format!("{result}\nCommand: {command_id}. No automatic retry.")
}

fn await_outcome(
    client: &ApiClient,
    id: &str,
    command_id: &str,
    mut outcome: Option<CommandOutcome>,
    cancelled: &AtomicBool,
    abort_at: Option<Instant>,
) -> Option<CommandOutcome> {
    let limit = Instant::now() + Duration::from_secs(30);
    let mut cancel_requested = false;
    loop {
        if (cancelled.load(Ordering::Acquire)
            || abort_at.is_some_and(|deadline| Instant::now() >= deadline))
            && !cancel_requested
        {
            // The POST may have started even when its receipt was lost. Cancel that exact
            // command once, independently of whether a receipt or outcome poll succeeded.
            if !matches!(
                outcome,
                Some(CommandOutcome::Emitted | CommandOutcome::Rejected | CommandOutcome::Aborted)
            ) {
                cancel_requested = true;
                let _ = client.cancel(id, Some(command_id)).map(Zeroizing::new);
            }
        }
        if outcome.is_some_and(CommandOutcome::is_terminal) || Instant::now() >= limit {
            break;
        }
        thread::sleep(Duration::from_millis(250));
        outcome = client
            .command_outcome(id, command_id)
            .map(Zeroizing::new)
            .ok()
            .filter(|response| response.device_id == id && response.command_id == command_id)
            .map(|response| response.outcome);
    }
    outcome
}

fn wake_sequence() -> InputSequenceV1 {
    // This request contains no text. Keep secrets on the hardened keyboard-sequence path.
    // The daemon selects V2 on extended firmware; absolute-only firmware rejects the move.
    InputSequenceV1 {
        schema: INPUT_SEQUENCE_SCHEMA_V1.into(),
        command_id: uuid::Uuid::now_v7().to_string(),
        keyboard_profile: None,
        arm: InputArmPolicy::CommandScoped,
        start_within_ms: 5000,
        keyboard_timing: None,
        actions: vec![
            InputAction::MoveRelative {
                dx_counts: 1,
                dy_counts: 0,
            },
            InputAction::Wait { ms: 150 },
            InputAction::MoveRelative {
                dx_counts: -1,
                dy_counts: 0,
            },
            InputAction::Wait { ms: 1000 },
        ],
    }
}

fn mac_login_wake_sequence() -> Zeroizing<KeyboardSequenceV1> {
    Zeroizing::new(KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.into(),
        command_id: uuid::Uuid::now_v7().to_string(),
        profile: LEGACY_WIRE_MAPPING.into(),
        arm: SequenceArmPolicy::CommandScoped,
        start_within_ms: 5000,
        timing: Some(TypingTiming::COMPATIBILITY),
        actions: vec![
            SequenceAction::Tap {
                key: "SHIFT".into(),
                timing: None,
            },
            SequenceAction::Wait { ms: 2000 },
        ],
    })
}

fn submit_with_wake(
    client: &ApiClient,
    id: &str,
    request: &mut KeyboardSequenceV1,
    wake: WakeMode,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> String {
    if wake != WakeMode::None {
        if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) {
            request.zeroize();
            return "Request expired or cancelled. Nothing was sent.".into();
        }
        let route_ready = client.device(id).is_ok_and(|view| ready(&view, id));
        if Instant::now() >= deadline || cancelled.load(Ordering::Acquire) || !route_ready {
            request.zeroize();
            return "Route changed, cancelled, or request expired. Nothing was sent.".into();
        }
        let (prelude_id, result) = match wake {
            WakeMode::Mouse => {
                let prelude = wake_sequence();
                let result = client.submit_input_sequence(id, &prelude);
                (prelude.command_id, result)
            }
            WakeMode::MacLogin => {
                let prelude = mac_login_wake_sequence();
                let result = client.submit_sequence(id, &prelude);
                (prelude.command_id.clone(), result)
            }
            WakeMode::None => unreachable!(),
        };
        let outcome = result
            .map(Zeroizing::new)
            .ok()
            .filter(|response| response.device_id == id && response.command_id == prelude_id)
            .map(|response| response.outcome);
        if await_outcome(client, id, &prelude_id, outcome, cancelled, Some(deadline))
            != Some(CommandOutcome::Emitted)
        {
            request.zeroize();
            return "Wake command failed or is unconfirmed. No text was sent. Check the target. No automatic retry.".into();
        }
    }
    // Recheck readiness, expiry and cancellation after the nonsecret wake command.
    let result = submit_once(client, id, request, deadline, cancelled);
    if wake != WakeMode::None {
        result.replace("Nothing was sent", "No text was sent")
    } else {
        result
    }
}

fn prompt_arguments(arguments: &[String]) -> Result<(uuid::Uuid, WakeMode), &'static str> {
    let (device, wake) = match arguments {
        [flag, device] if flag == "--secure-text" => (device, WakeMode::None),
        [flag, device, option, value] if flag == "--secure-text" && option == "--wake" => {
            let wake = WakeMode::parse(value).ok_or("Invalid wake selection.")?;
            (device, wake)
        }
        _ => return Err("usage: keyferry --secure-text DEVICE_UUID [--wake none|mouse|mac-login]"),
    };
    let device = uuid::Uuid::parse_str(device).map_err(|_| "Invalid device UUID.")?;
    Ok((device, wake))
}

pub fn run(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (device, wake) = prompt_arguments(arguments)?;
    let device_id = device.to_string();
    let client = ApiClient::from_environment().map_err(|_| "Local controller is unavailable")?;
    // This prompt does not own or stop the main app's daemon or BLE helper.
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .select()?;
    let window = ui::SecureTextWindow::new()?;
    window.set_destination(format!("Stick: {device_id}").into());
    window.set_append_enter(keyferry::api::secure_text_enter_default());
    window.set_wake_mode(wake as i32);
    let consumed = Arc::new(AtomicBool::new(false));
    let cancelled = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + PROMPT_LIFETIME;

    let weak = window.as_weak();
    let lookup = client.clone();
    let id = device_id.clone();
    thread::spawn(move || {
        let view = lookup.device(&id).ok();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                if !window.get_accepting() {
                    return;
                }
                if let Some(device) = view.filter(|device| ready(device, &id)) {
                    let route = device.link_path.as_deref().unwrap_or("unknown");
                    let via = device.via.as_deref().unwrap_or("local controller");
                    window.set_destination(
                        format!("{}\nStick: {id}\nRoute: {route} via {via}", device.label).into(),
                    );
                    window.set_ready(true);
                    window.set_status("Type the text, then press Enter to send or Esc to cancel. It is never shown to an agent, logged, or saved. This window expires after two minutes.".into());
                } else {
                    clear(&window);
                    finish(window.as_weak(), "The exact stick is unavailable, busy, or not authenticated and disarmed. Nothing was sent.".into());
                }
            }
        });
    });

    let weak = window.as_weak();
    let send_consumed = Arc::clone(&consumed);
    let send_cancelled = Arc::clone(&cancelled);
    window.on_send(move || {
        let Some(window) = weak.upgrade() else {
            return;
        };
        if !window.get_accepting() || !window.get_ready() {
            return;
        }
        if send_consumed.swap(true, Ordering::AcqRel) {
            return;
        }
        // SharedString::clone shares the editor allocation. Borrow it directly for validation
        // and the guarded request instead of allocating another whole-password String.
        // Slint owns this shared allocation; dropping it does not prove that it was wiped.
        let secret = window.get_secret();
        let enter = window.get_append_enter();
        let wake = match window.get_wake_mode() {
            0 => WakeMode::None,
            1 => WakeMode::Mouse,
            2 => WakeMode::MacLogin,
            _ => {
                clear(&window);
                finish(
                    window.as_weak(),
                    "Invalid wake selection. Nothing was sent.".into(),
                );
                return;
            }
        };
        clear(&window);
        if Instant::now() >= deadline {
            finish(
                window.as_weak(),
                "Request expired. Nothing was sent.".into(),
            );
            return;
        }
        let mut request = match sequence(&secret, enter) {
            Ok(request) => request,
            Err(message) => {
                finish(window.as_weak(), message.into());
                return;
            }
        };
        drop(secret);
        window.set_sending(true);
        window.set_status(
            "Sending once. Closing this window cannot undo keystrokes already sent.".into(),
        );
        let weak = weak.clone();
        let client = client.clone();
        let id = device_id.clone();
        let cancelled = Arc::clone(&send_cancelled);
        thread::spawn(move || {
            let message = submit_with_wake(&client, &id, &mut request, wake, deadline, &cancelled);
            finish(weak, message);
        });
    });

    let weak = window.as_weak();
    let dismiss_consumed = Arc::clone(&consumed);
    let dismiss_cancelled = Arc::clone(&cancelled);
    window.on_dismiss(move || {
        dismiss_consumed.store(true, Ordering::Release);
        if let Some(window) = weak.upgrade() {
            if window.get_sending() {
                dismiss_cancelled.store(true, Ordering::Release);
                window.set_status(
                    "Cancellation requested. Already typed input cannot be undone.".into(),
                );
                return;
            }
            clear(&window);
            let _ = window.hide();
        }
    });
    let weak = window.as_weak();
    let close_consumed = Arc::clone(&consumed);
    let close_cancelled = Arc::clone(&cancelled);
    window.window().on_close_requested(move || {
        close_consumed.store(true, Ordering::Release);
        if let Some(window) = weak.upgrade() {
            if window.get_sending() {
                close_cancelled.store(true, Ordering::Release);
                window.set_status("Cancellation requested. Waiting for the result…".into());
                return slint::CloseRequestResponse::KeepWindowShown;
            }
            clear(&window);
        }
        slint::CloseRequestResponse::HideWindow
    });
    let weak = window.as_weak();
    let timer = slint::Timer::default();
    timer.start(slint::TimerMode::SingleShot, PROMPT_LIFETIME, move || {
        if !consumed.swap(true, Ordering::AcqRel) {
            if let Some(window) = weak.upgrade() {
                clear(&window);
                finish(
                    window.as_weak(),
                    "Request expired. Nothing was sent.".into(),
                );
            }
        }
    });
    window.run()?;
    clear(&window);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    const DEVICE: &str = "019d1234-5678-7abc-8123-456789abcdef";

    #[test]
    fn optional_wake_gates_text_and_preserves_one_shot_cleanup() {
        check_wake_gates_text(WakeMode::Mouse);
    }

    #[test]
    fn mac_login_wake_gates_text_and_preserves_one_shot_cleanup() {
        check_wake_gates_text(WakeMode::MacLogin);
    }

    fn check_wake_gates_text(wake_mode: WakeMode) {
        for scenario in [
            "off",
            "emitted",
            "rejected",
            "aborted",
            "unknown",
            "lost",
            "mismatched",
            "cancel-wake",
            "cancel-text",
            "expired",
            "route-changed",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let client = ApiClient::new(
                keyferry::api::Endpoint::from_url(&format!(
                    "http://{}",
                    listener.local_addr().unwrap()
                ))
                .unwrap(),
                "test-token-123456",
            )
            .unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let owner_cancel = Arc::clone(&cancelled);
            let done = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&done);
            let server = thread::spawn(move || {
                let mut wake_id = String::new();
                let mut text_id = String::new();
                let (mut gets, mut wake_posts, mut text_posts, mut cancels) = (0, 0, 0, 0);
                let limit = Instant::now() + Duration::from_secs(5);
                loop {
                    let (mut stream, _) = match listener.accept() {
                        Ok(stream) => stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if stop.load(Ordering::Acquire) {
                                break;
                            }
                            assert!(Instant::now() < limit, "{scenario}: client did not finish");
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("{error}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut byte = [0];
                    while !bytes.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        bytes.push(byte[0]);
                    }
                    let headers = String::from_utf8(bytes).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    let response = if headers.starts_with(&format!("GET /v1/devices/{DEVICE} ")) {
                        gets += 1;
                        serde_json::json!({"id":DEVICE,"label":"test stick","transport":"tls","link":"authenticated","mode":"keyboard","armed":scenario == "route-changed" && gets == 2,"arm_policy":"command-scoped"})
                    } else if headers.starts_with(&format!("POST /v1/devices/{DEVICE}/input-sequences "))
                        || (wake_mode == WakeMode::MacLogin && scenario != "off" && wake_id.is_empty()
                            && headers.starts_with(&format!("POST /v1/devices/{DEVICE}/sequences "))) {
                        wake_posts += 1;
                        if wake_mode == WakeMode::Mouse {
                            let prelude: InputSequenceV1 = serde_json::from_slice(&body).unwrap();
                            assert_eq!(prelude.actions, wake_sequence().actions);
                            let compiled = keyferry_layouts::compile_input_sequence(&prelude).unwrap();
                            assert!(!compiled.has_keyboard);
                            assert!(compiled.has_pointer);
                            wake_id = prelude.command_id;
                        } else {
                            assert!(headers.starts_with(&format!("POST /v1/devices/{DEVICE}/sequences ")));
                            let prelude: KeyboardSequenceV1 = serde_json::from_slice(&body).unwrap();
                            assert_eq!(prelude.actions, mac_login_wake_sequence().actions);
                            assert_eq!(compile_sequence(&prelude).unwrap().text_characters, 0);
                            wake_id = prelude.command_id;
                        }
                        assert!(!String::from_utf8_lossy(&body).contains("private-fixture"));
                        if scenario == "lost" { continue; }
                        if scenario == "cancel-wake" { owner_cancel.store(true, Ordering::Release); }
                        if scenario == "expired" { thread::sleep(Duration::from_millis(200)); }
                        serde_json::json!({"device_id":DEVICE,"command_id":if scenario == "mismatched" { "different-command" } else { &wake_id },"outcome":match scenario {"rejected"=>"REJECTED", "aborted"=>"ABORTED", "unknown"=>"UNKNOWN", "cancel-wake"=>"ACCEPTED", _=>"EMITTED"},"message":"private-fixture"})
                    } else if headers.starts_with(&format!("POST /v1/devices/{DEVICE}/sequences ")) {
                        text_posts += 1;
                        assert!(matches!(scenario, "off" | "emitted" | "cancel-text"));
                        let request: KeyboardSequenceV1 = serde_json::from_slice(&body).unwrap();
                        assert!(matches!(&request.actions[0], SequenceAction::Text {value,..} if value == "private-fixture"));
                        text_id = request.command_id;
                        assert_ne!(text_id, wake_id);
                        if scenario == "cancel-text" { owner_cancel.store(true, Ordering::Release); }
                        serde_json::json!({"device_id":DEVICE,"command_id":text_id,"outcome":if scenario == "cancel-text" {"ACCEPTED"} else {"EMITTED"}})
                    } else if headers.starts_with(&format!("POST /v1/devices/{DEVICE}/cancel ")) {
                        cancels += 1;
                        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(value["command_id"].as_str(), Some(if scenario == "cancel-text" { text_id.as_str() } else { wake_id.as_str() }));
                        serde_json::json!({"device_id":DEVICE,"command_id":value["command_id"],"outcome":"ABORTED"})
                    } else {
                        let active = if scenario == "cancel-text" { &text_id } else { &wake_id };
                        assert!(headers.starts_with(&format!("GET /v1/devices/{DEVICE}/commands/{active} ")));
                        serde_json::json!({"device_id":DEVICE,"command_id":active,"outcome":if scenario.starts_with("cancel-") {"ABORTED"} else {"UNKNOWN"}})
                    }.to_string();
                    write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
                }
                assert_eq!(wake_posts, usize::from(scenario != "off"), "{scenario}");
                assert_eq!(
                    text_posts,
                    usize::from(matches!(scenario, "off" | "emitted" | "cancel-text")),
                    "{scenario}"
                );
                assert_eq!(
                    cancels,
                    usize::from(scenario.starts_with("cancel-")),
                    "{scenario}"
                );
            });
            let mut request = sequence("private-fixture", false).unwrap();
            let result = submit_with_wake(
                &client,
                DEVICE,
                &mut request,
                if scenario == "off" {
                    WakeMode::None
                } else {
                    wake_mode
                },
                Instant::now()
                    + if scenario == "expired" {
                        Duration::from_millis(100)
                    } else {
                        PROMPT_LIFETIME
                    },
                &cancelled,
            );
            done.store(true, Ordering::Release);
            server.join().unwrap();
            assert!(!result.contains("private-fixture"), "{scenario}");
            assert!(
                matches!(&request.actions[0], SequenceAction::Text {value,..} if value.is_empty())
            );
            if matches!(scenario, "off" | "emitted") {
                assert!(result.starts_with("EMITTED:"));
            } else if scenario == "cancel-text" {
                assert!(result.starts_with("ABORTED:"));
            } else {
                assert!(result.contains("No text was sent"), "{scenario}: {result}");
            }
        }
    }

    #[test]
    fn production_submission_posts_once_and_never_echoes_peer_messages_or_errors() {
        for status in [200, 500] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = ApiClient::new(
                keyferry::api::Endpoint::from_url(&format!(
                    "http://{}",
                    listener.local_addr().unwrap()
                ))
                .unwrap(),
                "test-token-123456",
            )
            .unwrap();
            let server = thread::spawn(move || {
                let mut command_id = String::new();
                for operation in 0..if status == 200 { 2 } else { 3 } {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let mut byte = [0];
                    while !bytes.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        bytes.push(byte[0]);
                    }
                    let headers = String::from_utf8(bytes).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    let response = if operation == 0 {
                        assert!(headers.starts_with(&format!("GET /v1/devices/{DEVICE} ")));
                        serde_json::json!({"id":DEVICE,"label":"test stick","transport":"tls","link":"authenticated","mode":"keyboard","armed":false,"arm_policy":"command-scoped"})
                    } else if operation == 1 {
                        assert!(headers.starts_with(&format!("POST /v1/devices/{DEVICE}/sequences ")));
                        let request: KeyboardSequenceV1 = serde_json::from_slice(&body).unwrap();
                        assert!(matches!(&request.actions[0], SequenceAction::Text { value, .. } if value == "private-fixture"));
                        command_id = request.command_id.clone();
                        serde_json::json!({"device_id":DEVICE,"command_id":request.command_id,"outcome":"EMITTED","message":"private-fixture","error":"private-fixture"})
                    } else {
                        assert!(headers.starts_with(&format!("GET /v1/devices/{DEVICE}/commands/{command_id} ")));
                        serde_json::json!({"device_id":DEVICE,"command_id":command_id,"outcome":"UNKNOWN","message":"private-fixture"})
                    }.to_string();
                    let code = if operation == 1 { status } else { 200 };
                    write!(stream, "HTTP/1.1 {code} result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).unwrap();
                }
                listener.set_nonblocking(true).unwrap();
                thread::sleep(Duration::from_millis(50));
                assert!(
                    listener.accept().is_err(),
                    "a lost/error response must not cause another submission"
                );
            });
            let mut request = sequence("private-fixture", false).unwrap();
            let message = submit_once(
                &client,
                DEVICE,
                &mut request,
                Instant::now() + PROMPT_LIFETIME,
                &AtomicBool::new(false),
            );
            assert!(!message.contains("private-fixture"));
            assert!(message.starts_with(if status == 200 { "EMITTED" } else { "UNKNOWN" }));
            assert!(
                matches!(&request.actions[0], SequenceAction::Text { value, .. } if value.is_empty())
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn lost_or_invalid_receipts_and_failed_poll_still_cancel_once_and_reconcile() {
        fn receive(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut byte = [0];
            while !bytes.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                bytes.push(byte[0]);
            }
            let headers = String::from_utf8(bytes).unwrap();
            let length = headers
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            (headers, body)
        }
        fn respond(stream: &mut std::net::TcpStream, code: u16, body: &str) {
            write!(
                stream,
                "HTTP/1.1 {code} result\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        for receipt in ["lost", "malformed", "mismatched", "failed-poll", "unknown"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = ApiClient::new(
                keyferry::api::Endpoint::from_url(&format!(
                    "http://{}",
                    listener.local_addr().unwrap()
                ))
                .unwrap(),
                "test-token-123456",
            )
            .unwrap();
            let cancelled = Arc::new(AtomicBool::new(false));
            let owner_cancel = Arc::clone(&cancelled);
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = receive(&mut stream);
                assert!(headers.starts_with(&format!("GET /v1/devices/{DEVICE} ")));
                assert!(body.is_empty());
                respond(&mut stream, 200, &serde_json::json!({"id":DEVICE,"label":"test stick","transport":"tls","link":"authenticated","mode":"keyboard","armed":false,"arm_policy":"command-scoped"}).to_string());
                drop(stream);

                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = receive(&mut stream);
                assert!(headers.starts_with(&format!("POST /v1/devices/{DEVICE}/sequences ")));
                let request: KeyboardSequenceV1 = serde_json::from_slice(&body).unwrap();
                let command_id = request.command_id;
                let response = |outcome: &str| {
                    serde_json::json!({"device_id":DEVICE,"command_id":command_id,"outcome":outcome}).to_string()
                };
                if receipt == "failed-poll" {
                    respond(&mut stream, 200, &response("ACCEPTED"));
                    drop(stream);
                    let (mut stream, _) = listener.accept().unwrap();
                    let (headers, body) = receive(&mut stream);
                    assert!(headers
                        .starts_with(&format!("GET /v1/devices/{DEVICE}/commands/{command_id} ")));
                    assert!(body.is_empty());
                    owner_cancel.store(true, Ordering::Release);
                    respond(&mut stream, 500, "{}");
                } else {
                    // Simulate an owner cancellation while the blocking POST is in flight.
                    owner_cancel.store(true, Ordering::Release);
                    match receipt {
                        "lost" => {},
                        "malformed" => respond(&mut stream, 200, "{}"),
                        "unknown" => respond(&mut stream, 200, &response("UNKNOWN")),
                        "mismatched" => respond(&mut stream, 200, &serde_json::json!({"device_id":DEVICE,"command_id":uuid::Uuid::now_v7(),"outcome":"ACCEPTED"}).to_string()),
                        _ => unreachable!(),
                    }
                    drop(stream);
                }

                // Let the lost response return EOF before accepting the cancellation request.
                let (mut stream, _) = listener.accept().unwrap();
                let (headers, body) = receive(&mut stream);
                assert!(headers.starts_with(&format!("POST /v1/devices/{DEVICE}/cancel ")));
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap()["command_id"],
                    command_id
                );
                respond(&mut stream, 200, &response("ABORTED"));
                drop(stream);

                if receipt != "unknown" {
                    let (mut stream, _) = listener.accept().unwrap();
                    let (headers, body) = receive(&mut stream);
                    assert!(headers
                        .starts_with(&format!("GET /v1/devices/{DEVICE}/commands/{command_id} ")));
                    assert!(body.is_empty());
                    respond(&mut stream, 200, &response("ABORTED"));
                    drop(stream);
                }
                listener.set_nonblocking(true).unwrap();
                thread::sleep(Duration::from_millis(50));
                assert!(
                    listener.accept().is_err(),
                    "submission and cancellation must never replay"
                );
            });
            let mut request = sequence("private-fixture", false).unwrap();
            let result = submit_once(
                &client,
                DEVICE,
                &mut request,
                Instant::now() + PROMPT_LIFETIME,
                &cancelled,
            );
            assert!(result.starts_with(if receipt == "unknown" {
                "UNKNOWN"
            } else {
                "ABORTED"
            }));
            assert!(!result.contains("private-fixture"));
            assert!(
                matches!(&request.actions[0], SequenceAction::Text { value, .. } if value.is_empty())
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn expiry_and_cancellation_prevent_any_controller_contact() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = ApiClient::new(
            keyferry::api::Endpoint::from_url(&format!(
                "http://{}",
                listener.local_addr().unwrap()
            ))
            .unwrap(),
            "test-token-123456",
        )
        .unwrap();
        for (deadline, cancelled) in [
            (Instant::now(), false),
            (Instant::now() + PROMPT_LIFETIME, true),
        ] {
            for wake in [WakeMode::None, WakeMode::Mouse, WakeMode::MacLogin] {
                let mut request = sequence("private-fixture", false).unwrap();
                assert!(submit_with_wake(
                    &client,
                    DEVICE,
                    &mut request,
                    wake,
                    deadline,
                    &AtomicBool::new(cancelled)
                )
                .contains("Nothing was sent"));
                assert!(listener.accept().is_err());
                assert!(
                    matches!(&request.actions[0], SequenceAction::Text {value,..} if value.is_empty())
                );
            }
        }
    }

    #[test]
    fn editor_clears_and_is_destroyed_after_consumption() {
        slint::platform::set_platform(Box::new(i_slint_backend_testing::TestingBackend::new(
            i_slint_backend_testing::TestingBackendOptions {
                renderer_name: Some("software".into()),
                ..Default::default()
            },
        )))
        .unwrap();
        let window = ui::SecureTextWindow::new().unwrap();
        assert_eq!(window.get_wake_mode(), 0);
        window.set_wake_mode(2);
        window.set_destination(
            format!("Test stick\nStick: {DEVICE}\nRoute: wifi via local controller").into(),
        );
        window.set_status("Type the text, then press Enter to send or Esc to cancel. It is never shown to an agent, logged, or saved. This window expires after two minutes.".into());
        window.show().unwrap();
        if let Some(directory) = std::env::var_os("KEYFERRY_UI_SNAPSHOT_DIR") {
            let snapshot = window.window().take_snapshot().unwrap();
            image::save_buffer(
                std::path::Path::new(&directory).join("secure-wake.png"),
                snapshot.as_bytes(),
                snapshot.width(),
                snapshot.height(),
                image::ColorType::Rgba8,
            )
            .unwrap();
        }
        window.set_secret("private-fixture".into());
        window.set_ready(true);
        clear(&window);
        assert!(window.get_secret().is_empty());
        assert!(!window.get_accepting());
        assert!(!window.get_ready());
    }

    #[test]
    fn mac_login_wake_contains_only_shift_and_wait() {
        let request = mac_login_wake_sequence();
        assert_eq!(request.arm, SequenceArmPolicy::CommandScoped);
        assert_eq!(request.start_within_ms, 5000);
        assert_eq!(request.timing, Some(TypingTiming::COMPATIBILITY));
        assert!(matches!(&request.actions[0], SequenceAction::Tap { key, .. } if key == "SHIFT"));
        assert!(matches!(
            &request.actions[1],
            SequenceAction::Wait { ms: 2000 }
        ));
        let compiled = Zeroizing::new(compile_sequence(&request).unwrap());
        assert_eq!(compiled.text_characters, 0);
        let mut saw_shift = false;
        for step in &compiled.steps {
            if let keyferry_layouts::ReportStep::Report(report) = step {
                assert!(report.keys.iter().all(|usage| *usage == 0));
                assert!(matches!(
                    report.modifiers,
                    0 | keyferry_layouts::MOD_LEFT_SHIFT
                ));
                saw_shift |= report.modifiers == keyferry_layouts::MOD_LEFT_SHIFT;
            }
        }
        assert!(saw_shift);
    }

    #[test]
    fn secure_text_is_strict_and_enter_requires_selection() {
        for text in ["", "pássword", "a\nb", "a\rb", "a\tb", "\0"] {
            assert!(sequence(text, false).is_err());
        }
        assert!(sequence(&"x".repeat(257), false).is_err());
        let mut request = sequence("Test password!", false).unwrap();
        assert_eq!(request.actions.len(), 1);
        assert_eq!(request.arm, SequenceArmPolicy::CommandScoped);
        assert_eq!(request.start_within_ms, 5000);
        assert!(!compile_sequence(&request).unwrap().steps.is_empty());
        request.zeroize();
        assert!(
            matches!(&request.actions[0], SequenceAction::Text { value, .. } if value.is_empty())
        );
        let request = sequence("Test password!", true).unwrap();
        assert!(matches!(
            &request.actions[1],
            SequenceAction::Wait { ms: 400 }
        ));
        assert!(matches!(&request.actions[2], SequenceAction::Tap { key, .. } if key == "ENTER"));
    }

    #[test]
    fn wake_preselection_is_metadata_only_and_strict() {
        for (arguments, expected) in [
            (vec!["--secure-text", DEVICE], WakeMode::None),
            (
                vec!["--secure-text", DEVICE, "--wake", "none"],
                WakeMode::None,
            ),
            (
                vec!["--secure-text", DEVICE, "--wake", "mouse"],
                WakeMode::Mouse,
            ),
            (
                vec!["--secure-text", DEVICE, "--wake", "mac-login"],
                WakeMode::MacLogin,
            ),
        ] {
            let arguments = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let (device, wake) = prompt_arguments(&arguments).unwrap();
            assert_eq!(device.to_string(), DEVICE);
            assert_eq!(wake, expected);
        }
        for arguments in [
            vec!["--secure-text", DEVICE, "--wake"],
            vec!["--secure-text", DEVICE, "--wake", "unsupported"],
            vec!["--secure-text", DEVICE, "--wake", "mouse", "extra"],
            vec!["--secure-text", DEVICE, "--secret", "private-fixture"],
        ] {
            let arguments = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(prompt_arguments(&arguments).is_err());
        }
    }

    #[test]
    fn invalid_prompt_arguments_never_start_a_gui() {
        for args in [
            vec![],
            vec!["--secure-text".into()],
            vec!["--secure-text".into(), "not-a-device".into()],
        ] {
            assert!(run(&args).is_err());
        }
    }
}
