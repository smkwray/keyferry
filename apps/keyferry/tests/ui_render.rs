mod ui {
    slint::include_modules!();
}

use i_slint_backend_testing::{TestingBackend, TestingBackendOptions};
use slint::{ComponentHandle, Model, ModelRc, PhysicalSize, VecModel};

const EXAMPLE: &str = r#"{
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
const COMPACT_EXAMPLE: &str = r#"{"schema":"keyferry.keyboard-sequence.v1","profile":"windows-us","arm":"command-scoped","start_within_ms":5000,"actions":[{"type":"wait","ms":3000},{"type":"tap","key":"A"},{"type":"wait","ms":250},{"type":"tap","key":"B"}]}"#;
const SUPPORTED_SIZES: [PhysicalSize; 2] =
    [PhysicalSize::new(980, 660), PhysicalSize::new(760, 540)];

fn populate(app: &ui::MainWindow) {
    app.set_local_computer_name("controller-a".into());
    app.set_endpoint_is_local(true);
    app.set_active_endpoint("Local".into());
    app.set_active_link("Wi-Fi".into());
    app.set_selected_device("Keyferry".into());
    app.set_selected_device_id("01234567-89ab-4cde-8fab-0123456789ab".into());
    app.set_nearby_status(
        "Using preferred Wi-Fi. Nearby Bluetooth remains available as fallback.".into(),
    );
    app.set_device_items(ModelRc::new(VecModel::from(vec![
        ui::DeviceListItem {
            id: "01234567-89ab-4cde-8fab-0123456789ab".into(),
            title: "Keyferry".into(),
            subtitle: "01234567 · Wi-Fi · Ready".into(),
        },
        ui::DeviceListItem {
            id: "89abcdef-89ab-4cde-8fab-0123456789ab".into(),
            title: "Keyferry".into(),
            subtitle: "89abcdef · Offline · Pinned selection".into(),
        },
    ])));
    app.set_device_fields(ModelRc::new(VecModel::from(vec![
        ui::DetailRow {
            label: "Control route".into(),
            value: "Wi-Fi".into(),
            tone: 0,
        },
        ui::DetailRow {
            label: "Control session".into(),
            value: "authenticated · tls".into(),
            tone: 0,
        },
        ui::DetailRow {
            label: "Command mode".into(),
            value: "keyboard".into(),
            tone: 0,
        },
        ui::DetailRow {
            label: "Firmware".into(),
            value: "0.9.0".into(),
            tone: 0,
        },
    ])));
    app.set_can_submit(true);
    app.set_usb_file_supported(true);
    app.set_usb_file_set_supported(true);
    app.set_usb_file_ready(true);
    app.set_usb_file_limit_kib((keyferry_protocol::file::MAX_FILE_BYTES / 1024) as i32);
    app.set_control_status("Ready to send.".into());
    app.set_text_input("Hello from Keyferry".into());
    app.set_text_send_enabled(true);
    app.set_preview_status(
        "Ready: 19 characters, 21 keystrokes in 1 bounded chunks; 0 replacements.".into(),
    );
    app.set_hotkey("CapsLock + Space + J".into());
    app.set_hotkey_valid(true);
    app.set_hotkey_status(
        "Ready · presses CAPS_LOCK → SPACE → J in order, then releases in reverse.".into(),
    );
    app.set_status("Command 019d…: EMITTED — terminal outcome.".into());

    app.set_sequence_example(EXAMPLE.into());
    app.set_sequence_input(COMPACT_EXAMPLE.into());
    app.set_sequence_status("Ready - 4 actions, 2 gestures, 3290 ms planned.".into());
    app.set_sequence_valid(true);
    app.set_sequence_actions(ModelRc::new(VecModel::from(vec![
        ui::SequenceActionItem {
            index: 0,
            title: "Wait".into(),
            detail: "3000 ms released".into(),
        },
        ui::SequenceActionItem {
            index: 1,
            title: "Tap".into(),
            detail: "A".into(),
        },
        ui::SequenceActionItem {
            index: 2,
            title: "Wait".into(),
            detail: "250 ms released".into(),
        },
        ui::SequenceActionItem {
            index: 3,
            title: "Tap".into(),
            detail: "B".into(),
        },
    ])));

    app.set_pairing_bundle("C:/private/first-hil".into());
    app.set_owner_kit_path("C:/private/owner-kit.json".into());
    app.set_wifi_policy_path("C:/private/roaming-policy.json".into());
    app.set_wifi_policy_loaded(true);
    app.set_wifi_policy_dirty(true);
    app.set_wifi_profile_items(ModelRc::new(VecModel::from(vec![
        ui::WifiProfileItem {
            index: 0,
            title: "Office".into(),
            subtitle: "Preference 1 · priority 255".into(),
        },
        ui::WifiProfileItem {
            index: 1,
            title: "Travel".into(),
            subtitle: "Preference 2 · priority 254".into(),
        },
    ])));
    app.set_selected_wifi_profile(0);
    app.set_wifi_ssid("Office".into());
    app.set_wifi_owner_password("password-not-rendered".into());
    app.set_provisioning_status(
        "Loaded 2 Wi-Fi profile(s) and preserved 1 access revocation(s).".into(),
    );
    app.set_local_recovery_status(
        "Connected directly. Safety released; network running; Bluetooth keyboard ready.".into(),
    );
    app.set_firmware_status("Reported endpoint firmware: 0.9.0".into());
    app.set_screen_power_supported(true);
    app.set_screen_power_known(true);
    app.set_screen_power_on(true);
    app.set_screen_power_status("Screen on.".into());
    app.set_output_mode_supported(true);
    app.set_output_mode_status("Keyboard output: USB keyboard.".into());
    app.set_ble_hid_bond_reset_supported(true);
    app.set_ble_hid_bond_reset_status("Bluetooth keyboard pairing is inactive.".into());
}

fn slug(title: &str) -> String {
    title
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn render(app: &ui::MainWindow, size: PhysicalSize, name: &str) {
    app.window().set_size(size);
    let snapshot = app
        .window()
        .take_snapshot()
        .expect("software renderer should take a snapshot");
    assert_eq!(
        (snapshot.width(), snapshot.height()),
        (size.width, size.height)
    );
    let pixels = snapshot.as_bytes();
    assert!(
        pixels.iter().any(|byte| *byte != 0),
        "{name} render must not be empty"
    );
    assert!(
        pixels.windows(4).any(|pixel| pixel != &pixels[..4]),
        "{name} render must contain more than one color"
    );
    // Set KEYFERRY_UI_SNAPSHOT_DIR to an ignored project-local directory to inspect every page.
    if let Some(directory) = std::env::var_os("KEYFERRY_UI_SNAPSHOT_DIR") {
        let path = std::path::Path::new(&directory)
            .join(format!("{name}-{}x{}.png", size.width, size.height));
        image::save_buffer(
            path,
            pixels,
            snapshot.width(),
            snapshot.height(),
            image::ColorType::Rgba8,
        )
        .expect("requested snapshot should be written");
    }
}

#[test]
fn every_page_renders_at_supported_sizes() {
    slint::platform::set_platform(Box::new(TestingBackend::new(TestingBackendOptions {
        renderer_name: Some("software".into()),
        ..Default::default()
    })))
    .expect("testing platform should be installed once");

    let app = ui::MainWindow::new().expect("main window should construct");
    populate(&app);

    let pages = app.get_nav_items().iter().collect::<Vec<_>>();
    assert!(!pages.is_empty(), "navigation must list pages");
    for entry in pages {
        app.set_page(entry.page);
        for size in SUPPORTED_SIZES {
            render(&app, size, &slug(&entry.title));
        }
    }
    // The selected stick owns its settings and direct-USB maintenance pages.
    for (page, name) in [
        (2, "devices-two-sticks"),
        (4, "device-keyboard-display"),
        (5, "device-connection-wifi"),
        (6, "device-usb-maintenance"),
    ] {
        app.set_page(page);
        for size in SUPPORTED_SIZES {
            render(&app, size, name);
        }
    }
    app.set_page(4);
    app.set_screen_power_on(false);
    app.set_screen_power_status("Screen off.".into());
    for size in SUPPORTED_SIZES {
        render(&app, size, "screen-off");
    }
    app.set_screen_power_supported(false);
    app.set_screen_power_known(false);
    app.set_screen_power_status("Screen on/off needs newer firmware on this stick.".into());
    render(&app, SUPPORTED_SIZES[1], "screen-unsupported");
    app.set_screen_power_supported(true);
    app.set_screen_power_known(true);
    app.set_screen_power_on(true);
    app.set_screen_power_status("Screen on.".into());

    app.set_selected_device("No device selected".into());
    app.set_selected_device_id("".into());
    for (page, name) in [
        (2, "devices-no-selection"),
        (4, "keyboard-display-no-selection"),
        (5, "connection-wifi-no-selection"),
        (6, "usb-maintenance-no-selection"),
    ] {
        app.set_page(page);
        for size in SUPPORTED_SIZES {
            render(&app, size, name);
        }
    }
    app.set_selected_device("Keyferry".into());
    app.set_selected_device_id("01234567-89ab-4cde-8fab-0123456789ab".into());

    // First run on a computer without its own credential: the Send page asks to authorize it.
    app.set_page(0);
    app.set_computer_authorized(false);
    for size in SUPPORTED_SIZES {
        render(&app, size, "authorize");
    }
    app.set_authorize_devices(ModelRc::new(VecModel::from(vec![
        "01234567-89ab-4cde-8fab-0123456789ab".into(),
        "89abcdef-89ab-4cde-8fab-0123456789ab".into(),
    ])));
    app.set_authorize_device("01234567-89ab-4cde-8fab-0123456789ab".into());
    app.set_authorize_status(
        "This owner kit covers 2 Keyferry devices. Choose the one this computer will control."
            .into(),
    );
    for size in SUPPORTED_SIZES {
        render(&app, size, "authorize-choose");
    }
    app.set_page(7);
    render(&app, SUPPORTED_SIZES[1], "setup-security-unauthorized");
    app.set_computer_authorized(true);

    // Streaming input stays busy and cancellable without any manual permission controls.
    app.set_page(0);
    app.set_can_cancel(true);
    app.set_can_submit(false);
    app.set_control_status("A large text file is streaming in bounded chunks…".into());
    app.set_file_mode(true);
    app.set_text_file_path("C:/private/notes.txt".into());
    app.set_text_file_busy(true);
    app.set_text_file_cancellable(true);
    app.set_text_file_status("Streaming: 4096 of 26985 bytes confirmed; chunk 2 of 14.".into());
    for size in SUPPORTED_SIZES {
        render(&app, size, "send-streaming");
    }

    // USB file uploads keep the device internally idle but the app busy until completion.
    app.set_can_cancel(false);
    app.set_can_submit(true);
    app.set_text_file_cancellable(false);
    app.set_control_status("Ready to send.".into());
    app.set_usb_file_status("Sending the file to the KEYFERRY drive…".into());
    app.set_text_file_status(app.get_usb_file_status());
    for size in SUPPORTED_SIZES {
        render(&app, size, "send-usb-file");
    }
    app.set_active_link("Control offline".into());
    app.set_can_submit(false);
    render(&app, SUPPORTED_SIZES[1], "send-usb-file-disconnected");

    app.set_active_link("Wi-Fi".into());
    app.set_can_submit(true);
    app.set_text_file_busy(false);
    app.set_file_mode(false);
    let pending = (0..16)
        .map(|index| ui::UsbFileItem {
            name: format!("pending-{index:02}.txt").into(),
            path: format!("C:/private/pending-{index:02}.txt").into(),
            size: 16_384,
        })
        .collect::<Vec<_>>();
    let published = (0..16)
        .map(|index| ui::UsbFileItem {
            name: format!("published-{index:02}.txt").into(),
            path: "".into(),
            size: 16_384,
        })
        .collect::<Vec<_>>();
    app.set_usb_pending_files(ModelRc::new(VecModel::from(pending)));
    app.set_usb_pending_total(262_144);
    app.set_usb_published_files(ModelRc::new(VecModel::from(published)));
    app.set_usb_published_total(262_144);
    app.set_usb_published_known(true);
    app.set_usb_file_status(
        "Review the names, then publish. Publishing replaces the whole USB drive.".into(),
    );
    render(&app, PhysicalSize::new(980, 740), "send-usb-files-full");
    render(&app, PhysicalSize::new(760, 540), "send-usb-files-compact");
    app.set_usb_pending_files(ModelRc::new(VecModel::from(Vec::<ui::UsbFileItem>::new())));
    app.set_usb_published_files(ModelRc::new(VecModel::from(Vec::<ui::UsbFileItem>::new())));
    app.set_usb_published_known(false);

    // Send with the selected device offline and nothing ready.
    app.set_file_mode(false);
    app.set_text_file_busy(false);
    app.set_text_file_cancellable(false);
    app.set_active_link("Control offline".into());
    app.set_control_status("The control link is offline; Bluetooth keyboard pairing may still be active. Commands are disabled until control reconnects. Device settings can still use the USB cable.".into());
    app.set_text_input("".into());
    app.set_text_send_enabled(false);
    app.set_preview_status("Enter text to send.".into());
    app.set_hotkey("Ctrl + Nope".into());
    app.set_hotkey_valid(false);
    app.set_hotkey_status("Key 2 is not a known key name. Try Ctrl, Shift, Alt, Win, CapsLock, Enter, F5, PageUp, or a single character.".into());
    for size in SUPPORTED_SIZES {
        render(&app, size, "send-waiting");
    }

    // Connected through a route the local daemon relays via another of the owner's controllers.
    app.set_active_link("tailnet".into());
    app.set_route_is_tailnet(true);
    app.set_route_via("controller-b".into());
    app.set_can_submit(true);
    app.set_control_status("Ready to send.".into());
    app.set_hotkey("".into());
    app.set_hotkey_status(
        "Type keys in the order you press them, such as Ctrl + L or CapsLock + Space + J.".into(),
    );
    for size in SUPPORTED_SIZES {
        render(&app, size, "send-relayed");
    }
    app.set_page(4);
    for size in SUPPORTED_SIZES {
        render(&app, size, "settings-relayed");
    }
    for (page, name) in [(5, "wifi-relayed"), (6, "usb-maintenance-relayed")] {
        app.set_page(page);
        for size in SUPPORTED_SIZES {
            render(&app, size, name);
        }
    }
}
