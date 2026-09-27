#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#![deny(unsafe_code)]

mod ui {
    slint::include_modules!();
}

mod provisioning;

use keyferry::{
    api::{
        ApiClient, ApiError, CommandOutcome, DeviceView, DisplayOrientation,
        DisplayOrientationStatus, EventRecord, OutputMode, OutputModeStatus, ScreenPower,
        ScreenPowerStatus, UsbFileStatus,
    },
    presentation::{outcome_view, render_diagnostic_event, OutcomeTone},
    preview::{
        append_sequence_action, hotkey_action, move_sequence_action, parse_key_names,
        prepare_sequence, preview_hotkey, preview_sequence, remove_sequence_action,
        sequence_action_summaries, SEQUENCE_DRAFT, SEQUENCE_EXAMPLE,
    },
    service::{self, ServiceManager, ServiceOutcome},
    text_stream::{
        preflight_text_file, preflight_text_value, run_text_file, run_text_value, TextFileOptions,
        TextFileResult, TextValueOptions,
    },
};
use keyferry_layouts::{
    compile_sequence, text_stream::UnsupportedTextPolicy, KeyboardSequenceV1, SequenceAction,
    SequenceArmPolicy, TypingTiming, SEQUENCE_SCHEMA_V1,
};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel, Weak};
use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard, RwLock,
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const REPLACE_UNSUPPORTED_LABEL: &str = "Replace with ?";
const DIAGNOSTICS_ENABLE_POLL: Duration = Duration::from_millis(100);
const EVENT_RECONNECT_BACKOFF: Duration = Duration::from_secs(2);
const OUTCOME_RECONCILE_INTERVAL: Duration = Duration::from_millis(500);
const OUTCOME_RECONCILE_TIMEOUT: Duration = Duration::from_secs(125);
const GATEWAY_REFRESH_STALE_AFTER: Duration = Duration::from_secs(5 * 60);
const DEVICE_WATCH_TICK: Duration = Duration::from_millis(500);
const DEVICE_WATCH_FAST_INTERVAL: Duration = Duration::from_secs(3);
const DEVICE_WATCH_SLOW_INTERVAL: Duration = Duration::from_secs(15);
const DEVICE_WATCH_CONNECTED_INTERVAL: Duration = Duration::from_secs(10);
const DEVICE_WATCH_FAST_FOR: Duration = Duration::from_secs(120);
const SERVICE_READY_TIMEOUT: Duration = Duration::from_secs(15);
const SERVICE_READY_POLL: Duration = Duration::from_millis(250);
static DEVICE_REFRESH_IN_FLIGHT: AtomicBool = AtomicBool::new(false);
static DEVICE_REFRESH_RERUN: AtomicBool = AtomicBool::new(false);
/// When the watched device was last seen not authenticated; `None` while it is connected.
static DEVICE_OFFLINE_SINCE: Mutex<Option<Instant>> = Mutex::new(None);
/// Serializes starting and stopping the background service; `true` once the app is exiting, after
/// which nothing starts it again.
static SERVICE_EXITING: Mutex<bool> = Mutex::new(false);

struct ActiveEndpoint {
    client: ApiClient,
    generation: u64,
    label: String,
}

struct ActiveApiClient {
    endpoint: RwLock<ActiveEndpoint>,
    mutations: Mutex<()>,
}

impl ActiveApiClient {
    fn new(client: ApiClient, label: impl Into<String>) -> Self {
        Self {
            endpoint: RwLock::new(ActiveEndpoint {
                client,
                generation: 0,
                label: label.into(),
            }),
            mutations: Mutex::new(()),
        }
    }

    fn snapshot(&self) -> (ApiClient, u64) {
        let endpoint = self.endpoint.read().expect("API client lock");
        (endpoint.client.clone(), endpoint.generation)
    }

    fn replace_if_current(
        &self,
        expected_generation: u64,
        client: ApiClient,
        label: impl Into<String>,
    ) -> bool {
        let mut endpoint = self.endpoint.write().expect("API client lock");
        if endpoint.generation != expected_generation {
            return false;
        }
        endpoint.client = client;
        endpoint.label = label.into();
        endpoint.generation = endpoint.generation.wrapping_add(1);
        true
    }

    fn is_current(&self, generation: u64) -> bool {
        self.endpoint.read().expect("API client lock").generation == generation
    }

    fn label(&self) -> String {
        self.endpoint.read().expect("API client lock").label.clone()
    }

    fn lock_mutations(&self) -> MutexGuard<'_, ()> {
        self.mutations.lock().expect("API mutation lock")
    }

    fn run_mutation<T>(
        &self,
        expected_generation: u64,
        operation: impl FnOnce(&ApiClient) -> T,
    ) -> Option<T> {
        let _mutation = self.lock_mutations();
        let (client, generation) = self.snapshot();
        (generation == expected_generation).then(|| operation(&client))
    }
}

type SharedApiClient = Arc<ActiveApiClient>;
type SharedRefreshClock = Arc<Mutex<Instant>>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Winit 0.30 windows default to transparent, which leaves the macOS title bar see-through.
    // The app paints an opaque background, so request an opaque window everywhere.
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .with_winit_window_attributes_hook(|attributes| attributes.with_transparent(false))
        .with_winit_custom_application_handler(StopServiceOnExit)
        .select()?;
    let window = ui::MainWindow::new()?;
    window.set_usb_file_limit_kib((keyferry_protocol::file::MAX_FILE_BYTES / 1024) as i32);
    let (initial_client, initial_label, initial_error) = match ApiClient::from_environment() {
        Ok(client) => (client, "Local", None),
        Err(error) => (
            ApiClient::unavailable(),
            "No daemon",
            Some(error.to_string()),
        ),
    };
    let client = Arc::new(ActiveApiClient::new(initial_client, initial_label));
    let selected_device = Arc::new(Mutex::new(None::<String>));
    let refresh_clock = Arc::new(Mutex::new(Instant::now()));
    let diagnostics_enabled = Arc::new(AtomicBool::new(false));

    install_navigation(&window);
    install_api_actions(
        &window,
        Arc::clone(&client),
        Arc::clone(&selected_device),
        Arc::clone(&refresh_clock),
    );
    install_provisioning_actions(&window, Arc::clone(&client));
    install_authorization(&window);
    install_diagnostics_actions(&window, Arc::clone(&diagnostics_enabled));
    install_preview(&window);
    let bundle = provisioning::default_bundle_path();
    let owner_kit = provisioning::default_owner_kit_path(std::path::Path::new(&bundle));
    window.set_wifi_policy_path(
        provisioning::default_wifi_policy_path(std::path::Path::new(&owner_kit)).into(),
    );
    window.set_owner_kit_path(owner_kit.into());
    window.set_pairing_bundle(bundle.into());
    window.set_local_computer_name(local_computer_name().into());
    window.set_active_endpoint(client.label().into());
    window.set_endpoint_is_local(client.label() == "Local");
    if let Some(error) = initial_error {
        window.set_status(format!("No local daemon: {error}").into());
    }
    start_local_service(
        window.as_weak(),
        Arc::clone(&client),
        Arc::clone(&selected_device),
    );
    install_activation_refresh(
        &window,
        Arc::clone(&client),
        Arc::clone(&selected_device),
        refresh_clock,
    );
    note_device_connected(false);
    start_device_watch(window.as_weak(), Arc::clone(&client), selected_device);
    start_event_feed(window.as_weak(), client, diagnostics_enabled);

    let result = window.run();
    stop_local_service();
    result?;
    Ok(())
}

/// Keyferry's background service runs only while this app is open (D-20260926-04). Start it, then
/// refresh once its local API answers. Without an installed service, as in a development run, the
/// app uses whatever daemon is already running.
fn start_local_service(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
) {
    thread::spawn(move || {
        let outcome = {
            let exiting = SERVICE_EXITING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if *exiting {
                return;
            }
            let run: &mut service::Runner<'_> = &mut service::run_command;
            ServiceManager::for_this_computer(run)
                .map_or_else(ServiceOutcome::Failed, |manager| manager.start(run))
        };
        let note = match outcome {
            ServiceOutcome::Started => {
                set_status(&weak, "Starting Keyferry's background service…");
                (!local_api_answers_within(SERVICE_READY_TIMEOUT)).then(|| {
                    "Keyferry's background service is starting; devices appear once it answers."
                        .to_owned()
                })
            }
            ServiceOutcome::NotInstalled => Some(
                "Keyferry's background service is not installed; using a daemon that is already running, if any."
                    .to_owned(),
            ),
            ServiceOutcome::Failed(error) => Some(format!(
                "Could not start Keyferry's background service: {error}"
            )),
            ServiceOutcome::Stopped | ServiceOutcome::NotRunning | ServiceOutcome::Unsupported => {
                None
            }
        };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak.upgrade() {
                adopt_local_daemon_if_unavailable(&window, &client);
                if let Some(note) = &note {
                    window.set_status(note.as_str().into());
                }
            }
            if client.snapshot().0.is_available() {
                start_device_refresh(weak, client, selected_device, note.is_none());
            }
        });
    });
}

fn local_api_answers_within(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if ApiClient::from_environment()
            .and_then(|client| client.devices())
            .is_ok()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(SERVICE_READY_POLL);
    }
}

/// Closing the app stops its background service and leaves the service defined for the next
/// launch. Runs from winit's `exiting` (window close, and Cmd+Q on macOS, which can end the process
/// without returning from the event loop) and again after the event loop returns; only the first
/// call acts.
fn stop_local_service() {
    let mut exiting = SERVICE_EXITING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if *exiting {
        return;
    }
    *exiting = true;
    let run: &mut service::Runner<'_> = &mut service::run_command;
    if let Ok(manager) = ServiceManager::for_this_computer(run) {
        let _ = manager.stop(run);
    }
}

struct StopServiceOnExit;

impl slint::winit_030::CustomApplicationHandler for StopServiceOnExit {
    fn exiting(
        &mut self,
        _event_loop: &slint::winit_030::winit::event_loop::ActiveEventLoop,
    ) -> slint::winit_030::EventResult {
        stop_local_service();
        slint::winit_030::EventResult::Propagate
    }
}

fn local_computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "This computer".to_owned())
}

fn mark_refresh_requested(clock: &SharedRefreshClock, now: Instant) {
    *clock.lock().expect("refresh clock lock") = now;
}

fn claim_stale_activation_refresh(clock: &SharedRefreshClock, now: Instant) -> bool {
    let mut last = clock.lock().expect("refresh clock lock");
    if now.saturating_duration_since(*last) < GATEWAY_REFRESH_STALE_AFTER {
        return false;
    }
    *last = now;
    true
}

fn install_activation_refresh(
    window: &ui::MainWindow,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    refresh_clock: SharedRefreshClock,
) {
    use slint::winit_030::{winit, EventResult, WinitWindowAccessor};

    let weak = window.as_weak();
    window.window().on_winit_window_event(move |_, event| {
        if matches!(event, winit::event::WindowEvent::Focused(true))
            && claim_stale_activation_refresh(&refresh_clock, Instant::now())
        {
            refresh_devices(
                weak.clone(),
                Arc::clone(&client),
                Arc::clone(&selected_device),
            );
        }
        EventResult::Propagate
    });
}

fn install_provisioning_actions(window: &ui::MainWindow, client: SharedApiClient) {
    let provisioning_in_flight = Arc::new(AtomicBool::new(false));
    let owner_password_in_flight = Arc::new(AtomicBool::new(false));
    let wifi_policy = Arc::new(Mutex::new(None::<provisioning::WifiPolicy>));

    let weak = window.as_weak();
    let check_in_flight = Arc::clone(&provisioning_in_flight);
    window.on_check_provisioning(move || {
        let Some(window) = weak.upgrade() else { return };
        let bundle = std::path::PathBuf::from(window.get_pairing_bundle().to_string());
        if check_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_provisioning_status("A local USB operation is already running.".into());
            return;
        }
        window.set_provisioning_busy(true);
        window.set_provisioning_status("Checking local authenticated USB access…".into());
        let weak_result = weak.clone();
        let check_in_flight = Arc::clone(&check_in_flight);
        thread::spawn(move || {
            let message = match provisioning::status(&bundle) {
                Ok(status) => format!("USB provisioning ready: {status}"),
                Err(error) => format!("USB provisioning check failed: {error}"),
            };
            check_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_provisioning_busy(false);
                    window.set_provisioning_status(message.into());
                }
            });
        });
    });

    let weak = window.as_weak();
    let load_in_flight = Arc::clone(&provisioning_in_flight);
    let load_policy = Arc::clone(&wifi_policy);
    window.on_load_wifi_policy(move || {
        let Some(window) = weak.upgrade() else { return };
        let path = std::path::PathBuf::from(window.get_wifi_policy_path().to_string());
        let selected_id = window.get_selected_device_id().to_string();
        if selected_id.is_empty() {
            window.set_provisioning_status("Select the Keyferry whose Wi-Fi policy you want to manage.".into());
            return;
        }
        if load_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_provisioning_status("A provisioning operation is already running.".into());
            return;
        }
        window.set_provisioning_busy(true);
        window.set_provisioning_status("Loading the complete private roaming policy…".into());
        let weak_result = weak.clone();
        let load_in_flight = Arc::clone(&load_in_flight);
        let load_policy = Arc::clone(&load_policy);
        thread::spawn(move || {
            let result = provisioning::load_wifi_policy(&path);
            let _ = slint::invoke_from_event_loop(move || {
                load_in_flight.store(false, Ordering::Release);
                let Some(window) = weak_result.upgrade() else { return };
                window.set_provisioning_busy(false);
                if window.get_selected_device_id().as_str() != selected_id {
                    return;
                }
                match result {
                    Ok(policy) => {
                        let profiles = policy.wifi_profiles.len();
                        let revocations = policy.revoked_installation_ids.len();
                        refresh_wifi_profile_items(&window, &policy);
                        *load_policy.lock().expect("Wi-Fi policy lock") = Some(policy);
                        window.set_selected_wifi_profile(-1);
                        window.set_wifi_ssid("".into());
                        window.set_wifi_password("".into());
                        window.set_wifi_policy_loaded(true);
                        window.set_wifi_policy_dirty(false);
                        window.set_provisioning_status(
                            format!(
                                "Loaded {profiles} Wi-Fi profile(s) and preserved {revocations} access revocation(s)."
                            )
                            .into(),
                        );
                    }
                    Err(error) => {
                        *load_policy.lock().expect("Wi-Fi policy lock") = None;
                        window.set_wifi_profile_items(ModelRc::new(VecModel::from(Vec::<
                            ui::WifiProfileItem,
                        >::new())));
                        window.set_wifi_policy_loaded(false);
                        window.set_wifi_policy_dirty(false);
                        window.set_provisioning_status(format!("Policy load failed: {error}").into());
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    window.on_new_wifi_profile(move || {
        if let Some(window) = weak.upgrade() {
            window.set_selected_wifi_profile(-1);
            window.set_wifi_ssid("".into());
            window.set_wifi_password("".into());
        }
    });

    let weak = window.as_weak();
    let select_policy = Arc::clone(&wifi_policy);
    window.on_select_wifi_profile(move |index| {
        let Some(window) = weak.upgrade() else { return };
        let policy = select_policy.lock().expect("Wi-Fi policy lock");
        let Some(profile) = policy.as_ref().and_then(|policy| {
            usize::try_from(index)
                .ok()
                .and_then(|index| policy.wifi_profiles.get(index))
        }) else {
            return;
        };
        window.set_selected_wifi_profile(index);
        window.set_wifi_ssid(profile.ssid.clone().into());
        window.set_wifi_password("".into());
    });

    let weak = window.as_weak();
    let save_policy = Arc::clone(&wifi_policy);
    window.on_save_wifi_profile(move || {
        let Some(window) = weak.upgrade() else { return };
        let ssid = window.get_wifi_ssid().to_string();
        let password = Zeroizing::new(window.get_wifi_password().to_string());
        let selected = window.get_selected_wifi_profile();
        let mut policy_guard = save_policy.lock().expect("Wi-Fi policy lock");
        let Some(policy) = policy_guard.as_mut() else {
            window.set_provisioning_status("Load the complete roaming policy first.".into());
            return;
        };
        let result = if let Ok(index) = usize::try_from(selected) {
            let Some(profile) = policy.wifi_profiles.get_mut(index) else {
                return;
            };
            let effective_password = if password.is_empty() {
                profile.password.as_str()
            } else {
                password.as_str()
            };
            provisioning::validate_wifi_profile(&ssid, effective_password).map(|()| {
                profile.ssid = ssid;
                if !password.is_empty() {
                    use zeroize::Zeroize as _;
                    profile.password.zeroize();
                    profile.password = password.to_string();
                }
            })
        } else if policy.wifi_profiles.len() >= provisioning::MAX_WIFI_PROFILES {
            Err("The roaming policy already contains eight Wi-Fi profiles.".to_owned())
        } else {
            provisioning::validate_wifi_profile(&ssid, password.as_str()).map(|()| {
                policy.wifi_profiles.push(provisioning::WifiProfile {
                    ssid,
                    password: password.to_string(),
                    priority: 0,
                });
            })
        };
        match result {
            Ok(()) => {
                policy.normalize_priorities();
                refresh_wifi_profile_items(&window, policy);
                let index = policy
                    .wifi_profiles
                    .iter()
                    .position(|profile| profile.ssid == window.get_wifi_ssid().as_str())
                    .map_or(-1, |index| index as i32);
                window.set_selected_wifi_profile(index);
                window.set_wifi_password("".into());
                window.set_wifi_policy_dirty(true);
                window.set_provisioning_status(
                    "Profile staged locally. Apply the complete policy by USB when ready.".into(),
                );
            }
            Err(error) => {
                window.set_provisioning_status(format!("Profile not saved: {error}").into());
            }
        }
    });

    let weak = window.as_weak();
    let remove_policy = Arc::clone(&wifi_policy);
    window.on_remove_wifi_profile(move || {
        let Some(window) = weak.upgrade() else { return };
        let Ok(index) = usize::try_from(window.get_selected_wifi_profile()) else {
            return;
        };
        let mut policy_guard = remove_policy.lock().expect("Wi-Fi policy lock");
        let Some(policy) = policy_guard.as_mut() else {
            return;
        };
        if index >= policy.wifi_profiles.len() {
            return;
        }
        policy.wifi_profiles.remove(index);
        policy.normalize_priorities();
        refresh_wifi_profile_items(&window, policy);
        window.set_selected_wifi_profile(-1);
        window.set_wifi_ssid("".into());
        window.set_wifi_password("".into());
        window.set_wifi_policy_dirty(true);
        window.set_provisioning_status(
            "Profile removal staged locally. Apply the complete policy by USB when ready.".into(),
        );
    });

    let weak = window.as_weak();
    let move_policy = Arc::clone(&wifi_policy);
    window.on_move_wifi_profile(move |delta| {
        let Some(window) = weak.upgrade() else { return };
        let selected = window.get_selected_wifi_profile();
        let target = selected.saturating_add(delta);
        let (Ok(index), Ok(target)) = (usize::try_from(selected), usize::try_from(target)) else {
            return;
        };
        let mut policy_guard = move_policy.lock().expect("Wi-Fi policy lock");
        let Some(policy) = policy_guard.as_mut() else {
            return;
        };
        if index >= policy.wifi_profiles.len() || target >= policy.wifi_profiles.len() {
            return;
        }
        policy.wifi_profiles.swap(index, target);
        policy.normalize_priorities();
        refresh_wifi_profile_items(&window, policy);
        window.set_selected_wifi_profile(target as i32);
        window.set_wifi_ssid(policy.wifi_profiles[target].ssid.clone().into());
        window.set_wifi_password("".into());
        window.set_wifi_policy_dirty(true);
        window.set_provisioning_status(
            "Profile order staged locally. Apply the complete policy by USB when ready.".into(),
        );
    });

    let weak = window.as_weak();
    let recover_in_flight = Arc::clone(&provisioning_in_flight);
    let recovered_policy = Arc::clone(&wifi_policy);
    let recovery_client = Arc::clone(&client);
    window.on_recover_initial_wifi_policy(move || {
        let Some(window) = weak.upgrade() else { return };
        let bundle = std::path::PathBuf::from(window.get_pairing_bundle().to_string());
        let owner_kit = std::path::PathBuf::from(window.get_owner_kit_path().to_string());
        let policy_path = std::path::PathBuf::from(window.get_wifi_policy_path().to_string());
        let password = Zeroizing::new(window.get_wifi_owner_password().to_string());
        let selected_id = window.get_selected_device_id().to_string();
        let (api, expected_generation) = recovery_client.snapshot();
        if !api.is_local() {
            window.set_provisioning_status(
                "Switch to the Local daemon before recovering the initial policy.".into(),
            );
            return;
        }
        if recover_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_provisioning_status("A local USB operation is already running.".into());
            return;
        }
        window.set_wifi_owner_password("".into());
        window.set_provisioning_busy(true);
        window.set_provisioning_status(
            "Pausing local commands and verifying the exact initial policy by USB…".into(),
        );
        let weak_result = weak.clone();
        let recover_in_flight = Arc::clone(&recover_in_flight);
        let recovered_policy = Arc::clone(&recovered_policy);
        let recovery_client = Arc::clone(&recovery_client);
        thread::spawn(move || {
            let result = recovery_client.run_mutation(expected_generation, |api| {
                let known_device_ids = api
                    .devices()
                    .map_err(|error| format!("Could not read local devices: {error}"))?
                    .into_iter()
                    .map(|device| device.id)
                    .collect::<Vec<_>>();
                let local_device_id =
                    provisioning::connected_local_device_id(&selected_id, &known_device_ids)?;
                if local_device_id != selected_id {
                    return Err(
                        "Select the Keyferry connected by USB before changing its Wi-Fi policy."
                            .to_owned(),
                    );
                }
                api.begin_maintenance(&local_device_id)
                    .map_err(|error| format!("Could not enter local maintenance: {error}"))?;
                let recovered = provisioning::recover_initial_wifi_policy(
                    &local_device_id,
                    &bundle,
                    &owner_kit,
                    &policy_path,
                    password.as_str(),
                );
                let resumed = api
                    .finish_maintenance(&local_device_id)
                    .map_err(|error| format!("Could not resume the local daemon: {error}"));
                match (recovered, resumed) {
                    (Ok(policy), Ok(_)) => Ok(policy),
                    (Err(error), Ok(_)) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                    (Err(operation), Err(resume)) => Err(format!("{operation}; {resume}")),
                }
            });
            recover_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(window) = weak_result.upgrade() else {
                    return;
                };
                window.set_provisioning_busy(false);
                if window.get_selected_device_id().as_str() != selected_id {
                    return;
                }
                match result {
                    Some(Ok(policy)) => {
                        refresh_wifi_profile_items(&window, &policy);
                        *recovered_policy.lock().expect("Wi-Fi policy lock") = Some(policy);
                        window.set_selected_wifi_profile(-1);
                        window.set_wifi_ssid("".into());
                        window.set_wifi_password("".into());
                        window.set_wifi_policy_loaded(true);
                        window.set_wifi_policy_dirty(false);
                        window.set_provisioning_status(
                            "Recovered the exact active initial policy without changing the dongle."
                                .into(),
                        );
                    }
                    Some(Err(error)) => window.set_provisioning_status(
                        format!("Initial policy recovery failed: {error}").into(),
                    ),
                    None => window.set_provisioning_status(
                        "Initial policy recovery cancelled because the active endpoint changed."
                            .into(),
                    ),
                }
            });
        });
    });

    let weak = window.as_weak();
    let wifi_in_flight = Arc::clone(&provisioning_in_flight);
    let apply_policy = Arc::clone(&wifi_policy);
    window.on_apply_wifi(move || {
        let Some(window) = weak.upgrade() else { return };
        if !window.get_wifi_policy_loaded() {
            window.set_provisioning_status("Load the selected Keyferry's complete Wi-Fi policy first.".into());
            return;
        }
        let owner_kit = std::path::PathBuf::from(window.get_owner_kit_path().to_string());
        let policy_path = std::path::PathBuf::from(window.get_wifi_policy_path().to_string());
        let password = Zeroizing::new(window.get_wifi_owner_password().to_string());
        let (api, expected_generation) = client.snapshot();
        if !api.is_local() {
            window.set_provisioning_status(
                "Switch to the Local daemon before changing dongle Wi-Fi.".into(),
            );
            return;
        }
        {
            let policy_guard = apply_policy.lock().expect("Wi-Fi policy lock");
            let Some(policy) = policy_guard.as_ref() else {
                window.set_provisioning_status("Load the complete roaming policy first.".into());
                return;
            };
            if let Err(error) = provisioning::validate_wifi_policy(policy) {
                window.set_provisioning_status(
                    format!("Wi-Fi policy update not ready: {error}").into(),
                );
                return;
            }
        }
        if owner_kit.as_os_str().is_empty()
            || policy_path.as_os_str().is_empty()
            || password.is_empty()
        {
            window.set_provisioning_status(
                "Choose the owner kit and complete policy, then enter its password.".into(),
            );
            return;
        }
        if wifi_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_provisioning_status("A local USB operation is already running.".into());
            return;
        }
        let policy = apply_policy
            .lock()
            .expect("Wi-Fi policy lock")
            .take()
            .expect("validated Wi-Fi policy remains loaded");
        let selected_id = window.get_selected_device_id().to_string();
        window.set_wifi_password("".into());
        window.set_wifi_owner_password("".into());
        window.set_provisioning_busy(true);
        window.set_provisioning_status(
            "Disarming and pausing the local command session before provisioning…".into(),
        );
        let weak_result = weak.clone();
        let shared_client = Arc::clone(&client);
        let wifi_in_flight = Arc::clone(&wifi_in_flight);
        let apply_policy = Arc::clone(&apply_policy);
        thread::spawn(move || {
            let result = shared_client.run_mutation(expected_generation, |api| {
                let known_device_ids = api
                    .devices()
                    .map_err(|error| format!("Could not read local devices: {error}"))?
                    .into_iter()
                    .map(|device| device.id)
                    .collect::<Vec<_>>();
                let local_device_id =
                    provisioning::connected_local_device_id(&selected_id, &known_device_ids)?;
                if local_device_id != selected_id {
                    return Err("Select the Keyferry connected by USB before changing its Wi-Fi policy.".to_owned());
                }
                api.begin_maintenance(&local_device_id)
                    .map_err(|error| format!("Could not enter local maintenance: {error}"))?;
                let provisioned = provisioning::save_and_update_wifi_policy(
                    &local_device_id,
                    &owner_kit,
                    &policy_path,
                    password.as_str(),
                    &policy,
                );
                let resumed = api
                    .finish_maintenance(&local_device_id)
                    .map_err(|error| format!("Could not resume the local daemon: {error}"));
                match (provisioned, resumed) {
                    (Ok(_), Ok(_)) => Ok(
                        "Wi-Fi policy committed. The dongle is rebooting and will reconnect automatically."
                            .to_owned(),
                    ),
                    (Err(error), Ok(_)) => Err(error),
                    (Ok(_), Err(error)) => Err(error),
                    (Err(operation), Err(resume)) => Err(format!("{operation}; {resume}")),
                }
            });
            *apply_policy.lock().expect("Wi-Fi policy lock") = Some(policy);
            let committed = matches!(result, Some(Ok(_)));
            let message = match result {
                Some(Ok(message)) => message,
                Some(Err(error)) => format!("Wi-Fi update failed: {error}"),
                None => "Wi-Fi update cancelled because the selected gateway changed.".to_owned(),
            };
            wifi_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_provisioning_busy(false);
                    if window.get_selected_device_id().as_str() != selected_id {
                        return;
                    }
                    if committed {
                        window.set_wifi_policy_dirty(false);
                    }
                    if shared_client.is_current(expected_generation) {
                        window.set_provisioning_status(message.into());
                    } else {
                        window.set_provisioning_status(
                            "The prior local USB operation finished after the gateway changed; return to Local and verify its state."
                                .into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let password_in_flight = Arc::clone(&owner_password_in_flight);
    window.on_change_owner_password(move || {
        let Some(window) = weak.upgrade() else { return };
        let owner_kit = std::path::PathBuf::from(window.get_owner_kit_path().to_string());
        let current = Zeroizing::new(window.get_current_owner_password().to_string());
        let new = Zeroizing::new(window.get_new_owner_password().to_string());
        let confirmation = Zeroizing::new(window.get_confirm_owner_password().to_string());
        if let Err(error) = provisioning::validate_owner_passphrase_inputs(
            &owner_kit,
            current.as_str(),
            new.as_str(),
            confirmation.as_str(),
        ) {
            window.set_owner_password_status(
                format!("Owner-kit password change not ready: {error}").into(),
            );
            return;
        }
        if password_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_owner_password_status("An owner-kit operation is already running.".into());
            return;
        }
        window.set_current_owner_password("".into());
        window.set_new_owner_password("".into());
        window.set_confirm_owner_password("".into());
        window.set_owner_password_busy(true);
        window.set_owner_password_status("Re-encrypting the owner kit…".into());
        let weak_result = weak.clone();
        let password_in_flight = Arc::clone(&password_in_flight);
        thread::spawn(move || {
            let message = match provisioning::change_owner_passphrase(
                &owner_kit,
                current.as_str(),
                new.as_str(),
                confirmation.as_str(),
            ) {
                Ok(_) => {
                    "Owner-kit password changed. Existing installations remain valid.".to_owned()
                }
                Err(error) => format!("Owner-kit password change failed: {error}"),
            };
            password_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_owner_password_status(message.into());
                    window.set_owner_password_busy(false);
                }
            });
        });
    });

    let weak = window.as_weak();
    let local_status_in_flight = Arc::clone(&provisioning_in_flight);
    window.on_refresh_local_status(move || {
        let Some(window) = weak.upgrade() else { return };
        let owner_kit = PathBuf::from(window.get_owner_kit_path().to_string());
        let device_id = window.get_selected_device_id().to_string();
        let password = Zeroizing::new(window.get_local_recovery_password().to_string());
        if !window.get_endpoint_is_local() || device_id.is_empty() {
            window.set_local_recovery_status(
                "Select a Keyferry on the Local controller before checking it over USB.".into(),
            );
            return;
        }
        if owner_kit.as_os_str().is_empty() || password.is_empty() {
            window.set_local_recovery_status(
                "Choose the encrypted owner kit and enter its password first.".into(),
            );
            return;
        }
        if local_status_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_local_recovery_status(
                "Another local USB operation is already running.".into(),
            );
            return;
        }
        window.set_local_recovery_password("".into());
        window.set_local_recovery_busy(true);
        window.set_provisioning_busy(true);
        window.set_local_recovery_status("Authenticating directly over USB…".into());
        let weak_result = weak.clone();
        let local_status_in_flight = Arc::clone(&local_status_in_flight);
        thread::spawn(move || {
            let message =
                match provisioning::local_status(&owner_kit, password.as_str(), &device_id) {
                    Ok(status) => status,
                    Err(error) => format!("Local status failed: {error}"),
                };
            local_status_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_local_recovery_busy(false);
                    window.set_provisioning_busy(false);
                    if window.get_selected_device_id().as_str() == device_id {
                        window.set_local_recovery_status(message.into());
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let local_repair_in_flight = Arc::clone(&provisioning_in_flight);
    window.on_run_local_recovery(move |action| {
        let Some(window) = weak.upgrade() else { return };
        let action = action.to_string();
        if !matches!(
            action.as_str(),
            "restart-network" | "forget-bluetooth" | "cancel-enrollment" | "reboot"
        ) {
            window.set_local_recovery_status("The selected local repair is unsupported.".into());
            window.set_local_recovery_confirming(false);
            return;
        }
        let owner_kit = PathBuf::from(window.get_owner_kit_path().to_string());
        let device_id = window.get_selected_device_id().to_string();
        let password = Zeroizing::new(window.get_local_recovery_password().to_string());
        if !window.get_endpoint_is_local() || device_id.is_empty() {
            window.set_local_recovery_status(
                "Select a Keyferry on the Local controller before repairing it over USB.".into(),
            );
            window.set_local_recovery_confirming(false);
            return;
        }
        if action == "forget-bluetooth"
            && (!window.get_local_recovery_confirming()
                || window.get_local_recovery_confirm_device_id().as_str() != device_id)
        {
            window.set_local_recovery_status(
                "Confirm Bluetooth pairing reset for this exact Keyferry first.".into(),
            );
            return;
        }
        if owner_kit.as_os_str().is_empty() || password.is_empty() {
            window.set_local_recovery_status(
                "Choose the encrypted owner kit and enter its password first.".into(),
            );
            window.set_local_recovery_confirming(false);
            return;
        }
        if local_repair_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_local_recovery_status(
                "Another local USB operation is already running.".into(),
            );
            return;
        }
        window.set_local_recovery_password("".into());
        window.set_local_recovery_confirming(false);
        window.set_local_recovery_busy(true);
        window.set_provisioning_busy(true);
        window.set_local_recovery_status(
            format!("Running {action} through authenticated local USB…").into(),
        );
        let weak_result = weak.clone();
        let local_repair_in_flight = Arc::clone(&local_repair_in_flight);
        thread::spawn(move || {
            let (message, completed) = match provisioning::local_recover(
                &owner_kit,
                password.as_str(),
                &device_id,
                &action,
            ) {
                Ok(result) => (result, true),
                Err(error) => (format!("Local recovery did not complete: {error}"), false),
            };
            local_repair_in_flight.store(false, Ordering::Release);
            if completed {
                schedule_automatic_refreshes(weak_result.clone());
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_local_recovery_busy(false);
                    window.set_provisioning_busy(false);
                    if window.get_selected_device_id().as_str() == device_id {
                        window.set_local_recovery_status(message.into());
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let second_in_flight = Arc::clone(&provisioning_in_flight);
    window.on_prepare_second_device(move || {
        let Some(window) = weak.upgrade() else { return };
        let owner_kit = PathBuf::from(window.get_owner_kit_path().to_string());
        let network_bundle = PathBuf::from(window.get_pairing_bundle().to_string());
        let password = Zeroizing::new(window.get_second_device_password().to_string());
        if owner_kit.as_os_str().is_empty() || password.is_empty() {
            window.set_second_device_status("Choose the encrypted owner kit and enter its password first.".into());
            return;
        }
        if second_in_flight.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
            window.set_second_device_status("Another local USB operation is already running.".into());
            return;
        }
        window.set_second_device_password("".into());
        window.set_provisioning_busy(true);
        window.set_second_device_status("Preparing a distinct second-device identity and firmware input…".into());
        let weak_result = weak.clone();
        let second_in_flight = Arc::clone(&second_in_flight);
        thread::spawn(move || {
            let message = match provisioning::prepare_second_device(
                &owner_kit,
                password.as_str(),
                &keyferry::api::default_installation_path(),
                &network_bundle,
            ) {
                Ok(prepared) => format!(
                    "Second Keyferry {} is prepared. No dongle was written. Installation: {}. Firmware input: {}. Input fingerprint {}.",
                    prepared.device_id,
                    prepared.expanded_installation.display(),
                    prepared.bootstrap.display(),
                    prepared.private_input_sha256,
                ),
                Err(error) => format!("Second-device preparation failed: {error}"),
            };
            second_in_flight.store(false, Ordering::Release);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_result.upgrade() {
                    window.set_second_device_status(message.into());
                    window.set_provisioning_busy(false);
                }
            });
        });
    });

    let weak = window.as_weak();
    let local_output_in_flight = Arc::clone(&provisioning_in_flight);
    window.on_set_local_output_mode(move |selection| {
        let action = match selection.as_str() {
            "usb-hid" => "usb-hid",
            "ble-hid" => "ble-hid",
            _ => {
                set_status(&weak, "Choose USB keyboard or Bluetooth keyboard output.");
                return;
            }
        };
        let Some(window) = weak.upgrade() else { return };
        let owner_kit = PathBuf::from(window.get_owner_kit_path().to_string());
        let device_id = window.get_selected_device_id().to_string();
        let password = Zeroizing::new(window.get_local_recovery_password().to_string());
        if !window.get_endpoint_is_local() || device_id.is_empty() {
            window.set_output_mode_status(
                "Select a Keyferry on the Local controller before changing its output over USB."
                    .into(),
            );
            return;
        }
        if owner_kit.as_os_str().is_empty() || password.is_empty() {
            window.set_output_mode_status(
                "Enter the owner password below before changing output over USB.".into(),
            );
            return;
        }
        if local_output_in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            window.set_output_mode_status("Another local USB operation is running.".into());
            return;
        }
        window.set_local_recovery_password("".into());
        window.set_local_recovery_busy(true);
        window.set_output_mode_busy(true);
        window.set_provisioning_busy(true);
        window.set_output_mode_status("Saving output mode directly over USB…".into());
        let weak_result = weak.clone();
        let local_output_in_flight = Arc::clone(&local_output_in_flight);
        thread::spawn(move || {
            let result =
                provisioning::local_recover(&owner_kit, password.as_str(), &device_id, action);
            local_output_in_flight.store(false, Ordering::Release);
            let completed = result.is_ok();
            if completed {
                schedule_automatic_refreshes(weak_result.clone());
            }
            let _ = slint::invoke_from_event_loop(move || {
                let Some(window) = weak_result.upgrade() else {
                    return;
                };
                window.set_local_recovery_busy(false);
                window.set_output_mode_busy(false);
                window.set_provisioning_busy(false);
                if window.get_selected_device_id().as_str() != device_id {
                    return;
                }
                match result {
                    Ok(message) => {
                        window.set_local_recovery_status(message.into());
                        window.set_output_mode_status(
                            "Output mode saved. Waiting for the dongle to restart…".into(),
                        );
                        window.set_status(
                            "Output mode changed over USB; status will refresh automatically."
                                .into(),
                        );
                    }
                    Err(error) => {
                        window.set_output_mode_status(
                            format!("Output mode did not change: {error}").into(),
                        );
                    }
                }
            });
        });
    });
}

/// A local daemon that was not running at startup, such as before this computer was
/// authorized, is adopted on the next refresh. A live endpoint is never replaced here.
fn adopt_local_daemon_if_unavailable(window: &ui::MainWindow, client: &SharedApiClient) {
    let (current, generation) = client.snapshot();
    if current.is_available() {
        return;
    }
    let Ok(local) = ApiClient::from_environment() else {
        return;
    };
    if client.replace_if_current(generation, local, "Local") {
        window.set_active_endpoint("Local".into());
        window.set_endpoint_is_local(true);
    }
}

enum AuthorizeOutcome {
    ChooseDevice(Vec<String>),
    Authorized,
}

/// Issues this computer's own credential for exactly one Keyferry listed by the owner kit.
fn authorize_with_owner_kit(
    owner_kit: &std::path::Path,
    passphrase: &str,
    chosen_device: Option<String>,
) -> Result<AuthorizeOutcome, String> {
    let device_id = match chosen_device {
        Some(device_id) => device_id,
        None => {
            let mut devices = provisioning::list_owner_devices(owner_kit, passphrase)?;
            match devices.len() {
                0 => return Err("This owner kit does not list any Keyferry.".to_owned()),
                1 => devices.remove(0),
                _ => return Ok(AuthorizeOutcome::ChooseDevice(devices)),
            }
        }
    };
    provisioning::authorize_this_computer(owner_kit, passphrase, &device_id)?;
    Ok(AuthorizeOutcome::Authorized)
}

/// Owner kit and password held only while the owner picks one of several listed devices.
/// The owner password is held only while the owner picks a device, and never longer than this.
const AUTHORIZE_CHOICE_TIMEOUT: Duration = Duration::from_secs(120);
type PendingAuthorization = Arc<Mutex<Option<(PathBuf, Zeroizing<String>, Instant)>>>;

fn install_authorization(window: &ui::MainWindow) {
    window.set_computer_authorized(provisioning::this_computer_is_authorized());
    let pending: PendingAuthorization = Arc::new(Mutex::new(None));

    let weak = window.as_weak();
    window.on_choose_owner_kit(move || {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose your Keyferry owner kit")
            .add_filter("Owner kit", &["json"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        if let Some(window) = weak.upgrade() {
            window.set_owner_kit_path(path.to_string_lossy().into_owned().into());
        }
    });

    let weak = window.as_weak();
    let pending_for_cancel = Arc::clone(&pending);
    window.on_cancel_authorize(move || {
        pending_for_cancel
            .lock()
            .expect("pending authorization lock")
            .take();
        if let Some(window) = weak.upgrade() {
            window.set_authorize_devices(ModelRc::default());
            window.set_authorize_device("".into());
            window.set_authorize_failed(false);
            window.set_authorize_status("".into());
        }
    });

    let weak = window.as_weak();
    window.on_authorize_this_computer(move || {
        let Some(window) = weak.upgrade() else { return };
        if window.get_authorize_busy() {
            return;
        }
        let chosen = window.get_authorize_device().to_string();
        let offered = window
            .get_authorize_devices()
            .iter()
            .any(|device| device == chosen.as_str());
        let held = pending.lock().expect("pending authorization lock").take();
        let (owner_kit, passphrase, chosen_device) = match held {
            Some((owner_kit, passphrase, held_at))
                if offered && held_at.elapsed() < AUTHORIZE_CHOICE_TIMEOUT =>
            {
                (owner_kit, passphrase, Some(chosen))
            }
            _ => (
                PathBuf::from(window.get_owner_kit_path().trim()),
                Zeroizing::new(window.get_authorize_password().to_string()),
                None,
            ),
        };
        window.set_authorize_password("".into());
        window.set_authorize_busy(true);
        window.set_authorize_failed(false);
        window.set_authorize_status("Reading the owner kit…".into());
        let weak = weak.clone();
        let pending = Arc::clone(&pending);
        thread::spawn(move || {
            let outcome = authorize_with_owner_kit(&owner_kit, &passphrase, chosen_device);
            if matches!(outcome, Ok(AuthorizeOutcome::ChooseDevice(_))) {
                let held_at = Instant::now();
                *pending.lock().expect("pending authorization lock") =
                    Some((owner_kit, passphrase, held_at));
                expire_pending_authorization(Arc::clone(&pending), held_at, weak.clone());
            } else {
                drop(passphrase);
            }
            let _ = slint::invoke_from_event_loop(move || {
                let Some(window) = weak.upgrade() else { return };
                window.set_authorize_busy(false);
                match outcome {
                    Ok(AuthorizeOutcome::ChooseDevice(devices)) => {
                        window.set_authorize_status(
                            format!(
                                "This owner kit covers {} Keyferry devices. Choose the one this computer will control.",
                                devices.len()
                            )
                            .into(),
                        );
                        window.set_authorize_device(devices[0].clone().into());
                        window.set_authorize_devices(ModelRc::new(VecModel::from(
                            devices.into_iter().map(SharedString::from).collect::<Vec<_>>(),
                        )));
                    }
                    Ok(AuthorizeOutcome::Authorized) => {
                        window.set_authorize_devices(ModelRc::default());
                        window.set_authorize_device("".into());
                        window.set_authorize_status(
                            "This computer is authorized. Waiting for the Keyferry to connect…"
                                .into(),
                        );
                        window.set_computer_authorized(true);
                        window.set_page(0);
                        refresh_when_local_daemon_starts(window.as_weak());
                    }
                    Err(error) => {
                        window.set_authorize_devices(ModelRc::default());
                        window.set_authorize_device("".into());
                        window.set_authorize_failed(true);
                        window.set_authorize_status(format!("Not authorized: {error}").into());
                    }
                }
            });
        });
    });
}

fn expire_pending_authorization(
    pending: PendingAuthorization,
    held_at: Instant,
    weak: Weak<ui::MainWindow>,
) {
    thread::spawn(move || {
        thread::sleep(AUTHORIZE_CHOICE_TIMEOUT);
        let mut guard = pending.lock().expect("pending authorization lock");
        if guard.as_ref().is_some_and(|(_, _, at)| *at == held_at) {
            guard.take();
            drop(guard);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(window) = weak.upgrade() else { return };
                window.set_authorize_devices(ModelRc::default());
                window.set_authorize_device("".into());
                window.set_authorize_status(
                    "The device choice expired. Enter the owner-kit password again.".into(),
                );
            });
        }
    });
}

/// The local daemon waits for this computer's credential and then publishes its API token.
fn refresh_when_local_daemon_starts(weak: Weak<ui::MainWindow>) {
    thread::spawn(move || {
        for _ in 0..15 {
            if ApiClient::from_environment().is_ok() {
                break;
            }
            thread::sleep(Duration::from_secs(2));
        }
        let weak_refresh = weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(window) = weak_refresh.upgrade() {
                window.invoke_refresh();
            }
        });
        schedule_automatic_refreshes(weak);
    });
}

fn schedule_automatic_refreshes(weak: Weak<ui::MainWindow>) {
    thread::spawn(move || {
        for delay in [Duration::from_secs(2), Duration::from_secs(4)] {
            thread::sleep(delay);
            let weak_refresh = weak.clone();
            if slint::invoke_from_event_loop(move || {
                if let Some(window) = weak_refresh.upgrade() {
                    window.invoke_refresh();
                }
            })
            .is_err()
            {
                return;
            }
        }
    });
}

fn refresh_wifi_profile_items(window: &ui::MainWindow, policy: &provisioning::WifiPolicy) {
    let items = policy
        .wifi_profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| ui::WifiProfileItem {
            index: index as i32,
            title: profile.ssid.clone().into(),
            subtitle: format!("Preference {} · priority {}", index + 1, profile.priority).into(),
        })
        .collect::<Vec<_>>();
    window.set_wifi_profile_items(ModelRc::new(VecModel::from(items)));
}

fn install_navigation(window: &ui::MainWindow) {
    let weak = window.as_weak();
    window.on_navigate(move |page| {
        if let Some(window) = weak.upgrade() {
            window.set_page(page);
        }
    });
}

fn install_preview(window: &ui::MainWindow) {
    let weak = window.as_weak();
    window.on_text_changed(move |_| {
        update_text_preview(&weak);
    });
    let weak = window.as_weak();
    window.on_profile_changed(move |_| {
        update_text_preview(&weak);
    });
    let weak = window.as_weak();
    window.on_text_options_changed(move || {
        update_text_preview(&weak);
    });
    let weak = window.as_weak();
    window.on_sequence_changed(move |source| {
        update_sequence_preview(&weak, source.as_str());
    });
    let weak = window.as_weak();
    window.on_hotkey_changed(move |input| {
        if let Some(window) = weak.upgrade() {
            apply_hotkey_preview(&window, input.as_str());
        }
    });

    let weak = window.as_weak();
    window.on_add_sequence_action(move || {
        let Some(window) = weak.upgrade() else { return };
        let action = match window.get_sequence_builder_type().as_str() {
            "Keys in order" => hotkey_action(window.get_sequence_builder_keys().as_str()),
            "Keys together" => parse_key_names(window.get_sequence_builder_keys().as_str())
                .and_then(|keys| {
                    if keys.len() < 2 {
                        return Err("Keys together needs at least two keys.".to_owned());
                    }
                    Ok(SequenceAction::Chord { keys, timing: None })
                }),
            "Text" => {
                let value = window.get_sequence_builder_text().to_string();
                if value.is_empty() {
                    Err("Enter literal text first.".to_owned())
                } else {
                    Ok(SequenceAction::Text {
                        value,
                        timing: None,
                    })
                }
            }
            "Wait" => window
                .get_sequence_builder_wait_ms()
                .as_str()
                .parse::<u16>()
                .map(|ms| SequenceAction::Wait { ms })
                .map_err(|_| "Wait must be a whole number from 1 to 10000 ms.".to_owned()),
            _ => Err("Choose a supported action type.".to_owned()),
        };
        let action = match action {
            Ok(action) => action,
            Err(message) => {
                window.set_sequence_builder_status(
                    format!("{message} The JSON was not changed.").into(),
                );
                return;
            }
        };
        let source = Zeroizing::new(window.get_sequence_input().to_string());
        match append_sequence_action(&source, action) {
            Ok(updated) => {
                window.set_sequence_input(updated.into());
                window.set_sequence_builder_text("".into());
                window.set_sequence_builder_keys("".into());
                window.set_sequence_builder_status(
                    "Action added after strict schema and safety validation.".into(),
                );
            }
            Err(code) => window.set_sequence_builder_status(
                format!("Action rejected: {code}. The JSON was not changed.").into(),
            ),
        }
    });

    let weak = window.as_weak();
    window.on_remove_sequence_action(move |index| {
        edit_sequence_in_window(&weak, |source| {
            let index = usize::try_from(index).map_err(|_| "builder.action_index")?;
            remove_sequence_action(source, index)
        });
    });

    let weak = window.as_weak();
    window.on_move_sequence_action(move |index, offset| {
        edit_sequence_in_window(&weak, |source| {
            let index = usize::try_from(index).map_err(|_| "builder.action_index")?;
            move_sequence_action(source, index, offset)
        });
    });

    update_text_preview(&window.as_weak());
    window.set_sequence_example(SEQUENCE_EXAMPLE.into());
    window.set_sequence_input(SEQUENCE_EXAMPLE.into());
    update_sequence_preview(&window.as_weak(), SEQUENCE_EXAMPLE);
    apply_hotkey_preview(window, "");
}

fn apply_hotkey_preview(window: &ui::MainWindow, input: &str) {
    let preview = preview_hotkey(input);
    window.set_hotkey_status(preview.status.into());
    window.set_hotkey_valid(preview.accepted);
}

fn edit_sequence_in_window(
    weak: &Weak<ui::MainWindow>,
    edit: impl FnOnce(&str) -> Result<String, &'static str>,
) {
    let Some(window) = weak.upgrade() else { return };
    let source = window.get_sequence_input().to_string();
    match edit(&source) {
        Ok(updated) => {
            window.set_sequence_input(updated.into());
            window.set_sequence_builder_status(
                "Sequence order updated after strict safety validation.".into(),
            );
        }
        Err(code) => window.set_sequence_builder_status(
            format!("Edit rejected: {code}. The JSON was not changed.").into(),
        ),
    }
}

fn ui_sequence(
    profile: String,
    actions: Vec<SequenceAction>,
) -> Result<KeyboardSequenceV1, &'static str> {
    ui_sequence_with_timing(profile, actions, TypingTiming::DESKTOP_SAFE)
}

fn ui_sequence_with_timing(
    profile: String,
    actions: Vec<SequenceAction>,
    timing: TypingTiming,
) -> Result<KeyboardSequenceV1, &'static str> {
    let request = KeyboardSequenceV1 {
        schema: SEQUENCE_SCHEMA_V1.to_owned(),
        command_id: uuid::Uuid::now_v7().to_string(),
        profile,
        arm: SequenceArmPolicy::CommandScoped,
        start_within_ms: 5000,
        timing: Some(timing),
        actions,
    };
    compile_sequence(&request).map_err(|error| error.code())?;
    Ok(request)
}

fn use_existing_arm_if_needed(request: &mut KeyboardSequenceV1, device: &DeviceView) {
    if device.armed {
        request.arm = SequenceArmPolicy::RequireExisting;
    }
}

fn submit_ui_sequence(
    client: &ApiClient,
    device_id: &str,
    request: &mut KeyboardSequenceV1,
) -> Result<keyferry::api::CommandResponse, ApiError> {
    let device = client.device(device_id)?;
    use_existing_arm_if_needed(request, &device);
    client.submit_sequence(device_id, request)
}

fn clear_sequence_payload(request: &mut KeyboardSequenceV1) {
    fn clear_action(action: &mut SequenceAction) {
        match action {
            SequenceAction::Text { value, .. } => value.zeroize(),
            SequenceAction::Tap { key, .. } => key.zeroize(),
            SequenceAction::Chord { keys, .. } | SequenceAction::OrderedChord { keys, .. } => {
                keys.iter_mut().for_each(Zeroize::zeroize)
            }
            SequenceAction::Wait { .. } => {}
            SequenceAction::Repeat { actions, .. } => {
                for action in actions {
                    match action {
                        keyferry_layouts::SequenceLeafAction::Text { value, .. } => value.zeroize(),
                        keyferry_layouts::SequenceLeafAction::Tap { key, .. } => key.zeroize(),
                        keyferry_layouts::SequenceLeafAction::Chord { keys, .. }
                        | keyferry_layouts::SequenceLeafAction::OrderedChord { keys, .. } => {
                            keys.iter_mut().for_each(Zeroize::zeroize);
                        }
                        keyferry_layouts::SequenceLeafAction::Wait { .. } => {}
                    }
                }
            }
        }
    }
    request.actions.iter_mut().for_each(clear_action);
}

fn text_options(window: &ui::MainWindow) -> Result<(TypingTiming, u16), &'static str> {
    parse_text_options(
        window.get_text_key_gap_ms().as_str(),
        window.get_text_send_after_seconds().as_str(),
    )
}

fn text_unsupported_policy(window: &ui::MainWindow) -> UnsupportedTextPolicy {
    if window.get_text_unsupported().as_str() == REPLACE_UNSUPPORTED_LABEL {
        UnsupportedTextPolicy::Replace
    } else {
        UnsupportedTextPolicy::Reject
    }
}

fn text_file_result_status(result: &TextFileResult) -> String {
    match result.outcome {
        CommandOutcome::Emitted => format!(
            "USB emission completed for {} source bytes; keyboard release confirmed. Target text not verified.",
            result.total_bytes
        ),
        CommandOutcome::Aborted => format!(
            "File stopped: {} of {} bytes confirmed; released state confirmed.",
            result.confirmed_bytes, result.total_bytes
        ),
        CommandOutcome::Rejected => "File rejected before any keystroke was admitted.".to_owned(),
        CommandOutcome::Unknown => format!(
            "Delivery is uncertain after {} confirmed bytes; do not resend automatically.",
            result.confirmed_bytes
        ),
        CommandOutcome::Queued | CommandOutcome::Accepted | CommandOutcome::Started => {
            "The daemon returned a nonterminal file-stream result.".to_owned()
        }
    }
}

fn parse_text_options(
    key_gap_ms: &str,
    send_after_seconds: &str,
) -> Result<(TypingTiming, u16), &'static str> {
    let key_gap_ms = key_gap_ms
        .parse::<u16>()
        .map_err(|_| "Between keys must be a whole number from 5 to 100 ms.")?;
    if !(5..=100).contains(&key_gap_ms) {
        return Err("Between keys must be a whole number from 5 to 100 ms.");
    }
    let send_after_seconds = send_after_seconds
        .parse::<u16>()
        .map_err(|_| "Send after must be a whole number from 0 to 10 seconds.")?;
    if send_after_seconds > 10 {
        return Err("Send after must be a whole number from 0 to 10 seconds.");
    }
    Ok((
        TypingTiming {
            key_down_ms: TypingTiming::DESKTOP_SAFE.key_down_ms,
            release_gap_ms: key_gap_ms,
        },
        send_after_seconds,
    ))
}

fn update_text_preview(weak: &Weak<ui::MainWindow>) {
    let Some(window) = weak.upgrade() else { return };
    let (timing, send_after_seconds) = match text_options(&window) {
        Ok(options) => options,
        Err(error) => {
            window.set_preview_status(format!("Rejected: {error}").into());
            window.set_text_send_enabled(false);
            return;
        }
    };
    if window.get_selected_profile().as_str() != "windows-us" {
        window.set_preview_status("Rejected: unsupported target profile.".into());
        window.set_text_send_enabled(false);
        return;
    }
    let options = TextValueOptions {
        timing,
        send_after_seconds,
        unsupported: text_unsupported_policy(&window),
    };
    match preflight_text_value(window.get_text_input().as_str(), options) {
        Ok(summary) => {
            let delay = if send_after_seconds > 0 {
                format!(" Typing starts {send_after_seconds} seconds after Send.")
            } else {
                String::new()
            };
            window.set_preview_status(
                format!(
                    "Ready: {} characters, {} keystrokes in {} bounded chunks; {} replacements.{delay}",
                    summary.source_scalars,
                    summary.gestures,
                    summary.children,
                    summary.replacements,
                )
                .into(),
            );
            window.set_text_send_enabled(true);
        }
        Err(error) => {
            window.set_preview_status(format!("Rejected: {error}").into());
            window.set_text_send_enabled(false);
        }
    }
}

fn preflight_text_file_for_ui(
    weak: Weak<ui::MainWindow>,
    selected: Arc<Mutex<Option<PathBuf>>>,
    busy: Arc<AtomicBool>,
    path: PathBuf,
) {
    if busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        set_status(&weak, "Wait for the current text operation to finish.");
        return;
    }
    let Some(window) = weak.upgrade() else {
        busy.store(false, Ordering::Release);
        return;
    };
    let (timing, send_after_seconds) = match text_options(&window) {
        Ok(options) => options,
        Err(error) => {
            busy.store(false, Ordering::Release);
            window.set_text_file_status(format!("Rejected: {error}").into());
            return;
        }
    };
    let unsupported = text_unsupported_policy(&window);
    window.set_text_file_path(path.to_string_lossy().into_owned().into());
    window.set_text_file_ready(false);
    window.set_text_file_busy(true);
    window.set_text_file_cancellable(false);
    window.set_text_file_status("Validating the file without loading it into the UI…".into());
    let options = TextFileOptions {
        path: path.clone(),
        timing,
        send_after_seconds,
        unsupported,
    };
    thread::spawn(move || {
        let result = preflight_text_file(&options);
        let _ = slint::invoke_from_event_loop(move || {
            busy.store(false, Ordering::Release);
            let Some(window) = weak.upgrade() else { return };
            window.set_text_file_busy(false);
            match result {
                Ok(summary) => {
                    *selected.lock().expect("selected text file lock") = Some(path);
                    window.set_text_file_ready(true);
                    window.set_text_file_status(
                        format!(
                            "Ready: {} lines, {} bytes, {} keystrokes in {} bounded chunks; {} replacements.",
                            summary.lines,
                            summary.source_bytes,
                            summary.gestures,
                            summary.children,
                            summary.replacements,
                        )
                        .into(),
                    );
                }
                Err(error) => {
                    *selected.lock().expect("selected text file lock") = None;
                    window.set_text_file_ready(false);
                    window.set_text_file_status(format!("Rejected: {error}").into());
                }
            }
        });
    });
}

fn update_sequence_preview(window: &Weak<ui::MainWindow>, source: &str) {
    let preview = preview_sequence(source);
    if let Some(window) = window.upgrade() {
        window.set_sequence_status(preview.status.into());
        window.set_sequence_valid(preview.accepted);
        let items = sequence_action_summaries(source)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(index, action)| ui::SequenceActionItem {
                index: index as i32,
                title: action.title.into(),
                detail: action.detail.into(),
            })
            .collect::<Vec<_>>();
        window.set_sequence_actions(ModelRc::new(VecModel::from(items)));
    }
}

fn install_api_actions(
    window: &ui::MainWindow,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    refresh_clock: SharedRefreshClock,
) {
    let selected_text_file = Arc::new(Mutex::new(None::<PathBuf>));
    let text_file_busy = Arc::new(AtomicBool::new(false));
    let weak = window.as_weak();
    let usb_client = Arc::clone(&client);
    let usb_device = Arc::clone(&selected_device);
    let usb_busy = Arc::clone(&text_file_busy);
    window.on_publish_usb_file(move || {
        start_usb_file(
            &weak,
            Arc::clone(&usb_client),
            Arc::clone(&usb_device),
            Arc::clone(&usb_busy),
            false,
        );
    });
    let weak = window.as_weak();
    let usb_client = Arc::clone(&client);
    let usb_device = Arc::clone(&selected_device);
    let usb_busy = Arc::clone(&text_file_busy);
    window.on_clear_usb_file(move || {
        start_usb_file(
            &weak,
            Arc::clone(&usb_client),
            Arc::clone(&usb_device),
            Arc::clone(&usb_busy),
            true,
        );
    });
    let weak = window.as_weak();
    window.on_choose_usb_files(move || {
        let Some(window) = weak.upgrade() else { return };
        if !window.get_usb_file_set_supported()
            || !window.get_usb_file_ready()
            || window.get_text_file_busy()
        {
            return;
        }
        let Some(paths) = rfd::FileDialog::new()
            .set_title("Choose files for the KEYFERRY USB drive")
            .pick_files()
        else {
            return;
        };
        match preview_usb_files(&paths) {
            Ok(items) => {
                let total = items.iter().map(|item| item.size).sum();
                window.set_usb_pending_total(total);
                window.set_usb_pending_files(ModelRc::new(VecModel::from(items)));
                window.set_usb_file_status(
                    "Review the names, then publish. Publishing replaces the whole USB drive."
                        .into(),
                );
            }
            Err(message) => window.set_usb_file_status(message.into()),
        }
    });
    let weak = window.as_weak();
    window.on_remove_usb_pending_file(move |remove_index| {
        let Some(window) = weak.upgrade() else { return };
        let model = window.get_usb_pending_files();
        let items = (0..model.row_count())
            .filter(|index| *index != remove_index as usize)
            .filter_map(|index| model.row_data(index))
            .collect::<Vec<_>>();
        window.set_usb_pending_total(items.iter().map(|item| item.size).sum());
        window.set_usb_pending_files(ModelRc::new(VecModel::from(items)));
    });
    let weak = window.as_weak();
    let usb_client = Arc::clone(&client);
    let usb_device = Arc::clone(&selected_device);
    let usb_busy = Arc::clone(&text_file_busy);
    window.on_publish_usb_files(move || {
        start_usb_files(
            &weak,
            Arc::clone(&usb_client),
            Arc::clone(&usb_device),
            Arc::clone(&usb_busy),
        );
    });
    let weak = window.as_weak();
    let usb_client = Arc::clone(&client);
    let usb_device = Arc::clone(&selected_device);
    let usb_busy = Arc::clone(&text_file_busy);
    window.on_refresh_usb_files(move || {
        refresh_usb_files(
            &weak,
            Arc::clone(&usb_client),
            Arc::clone(&usb_device),
            Arc::clone(&usb_busy),
        );
    });
    let text_file_cancel = Arc::new(AtomicBool::new(false));

    let weak = window.as_weak();
    let client_for_select = Arc::clone(&client);
    let selected_for_select = Arc::clone(&selected_device);
    window.on_select_device(move |device_id| {
        let device_id = device_id.to_string();
        let Some(window) = weak.upgrade() else { return };
        if window.get_provisioning_busy()
            || window.get_output_mode_busy()
            || window.get_text_file_busy()
            || window.get_display_orientation_busy()
            || window.get_screen_power_busy()
            || window.get_ble_hid_bond_reset_busy()
        {
            window.set_status(
                "Wait for the current device operation before selecting another Keyferry.".into(),
            );
            return;
        }
        if window.get_selected_device_id().as_str() != device_id {
            clear_device_specific_state(&window);
        }
        *selected_for_select.lock().expect("selected device lock") = Some(device_id.clone());
        window.set_selected_device("Reading device state…".into());
        window.set_selected_device_id(device_id.clone().into());
        clear_control_state(&window);
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_select);
        let selected_for_result = Arc::clone(&selected_for_select);
        thread::spawn(move || {
            let (snapshot, generation) = client.snapshot();
            let result = snapshot.device(&device_id);
            let output_mode = result.as_ref().ok().and_then(|device| {
                (!is_tailnet_device(device)
                    && device
                        .firmware
                        .as_ref()
                        .is_some_and(|firmware| firmware.ble_hid_output_v1))
                .then(|| snapshot.output_mode(&device_id))
            });
            let display_orientation = result.as_ref().ok().and_then(|device| {
                (!is_tailnet_device(device)
                    && device
                        .firmware
                        .as_ref()
                        .is_some_and(|firmware| firmware.display_orientation_v1))
                .then(|| snapshot.display_orientation(&device_id))
            });
            let screen_power = result.as_ref().ok().and_then(|device| {
                supports_screen_power(device).then(|| snapshot.screen_power(&device_id))
            });
            let _ = slint::invoke_from_event_loop(move || {
                if !client.is_current(generation)
                    || !selected_device_matches(&selected_for_result, &device_id)
                {
                    return;
                }
                if let Some(window) = weak_result.upgrade() {
                    match result {
                        Ok(device) => {
                            update_device_view(&window, &device);
                            if let Some(result) = output_mode {
                                apply_output_mode_result(&window, result);
                            }
                            if let Some(result) = display_orientation {
                                apply_display_orientation_result(&window, result);
                            }
                            if let Some(result) = screen_power {
                                apply_screen_power_result(&window, result);
                            }
                        }
                        Err(error) => {
                            clear_control_state(&window);
                            window.set_status(format!("Daemon request failed: {error}").into())
                        }
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let selected_for_file = Arc::clone(&selected_text_file);
    let busy_for_file = Arc::clone(&text_file_busy);
    window.on_choose_text_file(move || {
        if busy_for_file.load(Ordering::Acquire) {
            set_status(&weak, "Wait for the current text operation to finish.");
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose text to send with Keyferry")
            .add_filter("Text and AutoHotkey", &["txt", "ahk"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        preflight_text_file_for_ui(
            weak.clone(),
            Arc::clone(&selected_for_file),
            Arc::clone(&busy_for_file),
            path,
        );
    });

    let weak = window.as_weak();
    let selected_for_path = Arc::clone(&selected_text_file);
    let busy_for_path = Arc::clone(&text_file_busy);
    window.on_load_text_file_path(move || {
        let Some(window) = weak.upgrade() else { return };
        let value = window.get_text_file_path().trim().to_owned();
        if value.is_empty() {
            window.set_text_file_status("Paste a file path before loading it.".into());
            return;
        }
        preflight_text_file_for_ui(
            weak.clone(),
            Arc::clone(&selected_for_path),
            Arc::clone(&busy_for_path),
            PathBuf::from(value),
        );
    });

    let weak = window.as_weak();
    let selected_for_path_change = Arc::clone(&selected_text_file);
    let busy_for_path_change = Arc::clone(&text_file_busy);
    window.on_text_file_path_changed(move || {
        if busy_for_path_change.load(Ordering::Acquire) {
            return;
        }
        *selected_for_path_change
            .lock()
            .expect("selected text file lock") = None;
        if let Some(window) = weak.upgrade() {
            window.set_text_file_ready(false);
            window.set_text_file_status(
                if window.get_text_file_path().trim().is_empty() {
                    "Paste a UTF-8 text or AHK path, or choose a file."
                } else {
                    "Path changed. Click Load path to validate it."
                }
                .into(),
            );
        }
    });

    let weak = window.as_weak();
    let client_for_file = Arc::clone(&client);
    let device_for_file = Arc::clone(&selected_device);
    let selected_for_file = Arc::clone(&selected_text_file);
    let busy_for_file = Arc::clone(&text_file_busy);
    let cancel_for_file = Arc::clone(&text_file_cancel);
    window.on_send_text_file(move || {
        let Some(device_id) = device_for_file
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before sending a file.");
            return;
        };
        let Some(path) = selected_for_file
            .lock()
            .expect("selected text file lock")
            .clone()
        else {
            set_status(&weak, "Choose and validate a file before sending it.");
            return;
        };
        let Some(window) = weak.upgrade() else { return };
        let (timing, send_after_seconds) = match text_options(&window) {
            Ok(options) => options,
            Err(error) => {
                window.set_text_file_status(format!("Rejected: {error}").into());
                return;
            }
        };
        if busy_for_file
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            set_status(&weak, "A text-file operation is already running.");
            return;
        }
        cancel_for_file.store(false, Ordering::Release);
        let options = TextFileOptions {
            path,
            timing,
            send_after_seconds,
            unsupported: text_unsupported_policy(&window),
        };
        window.set_text_file_busy(true);
        window.set_text_file_cancellable(true);
        window.set_text_file_ready(false);
        window.set_text_file_status("Validating again before any keystrokes are sent…".into());
        set_control_pending(&window, "A large text file is streaming in bounded chunks…");
        set_status(&weak, "Starting the daemon-owned text stream…");
        let expected_generation = client_for_file.snapshot().1;
        let client = Arc::clone(&client_for_file);
        let cancel = Arc::clone(&cancel_for_file);
        let busy = Arc::clone(&busy_for_file);
        let weak_result = weak.clone();
        thread::spawn(move || {
            let progress_weak = weak_result.clone();
            let operation = client.run_mutation(expected_generation, |snapshot| {
                let result = run_text_file(snapshot, &device_id, &options, &cancel, |progress| {
                    let weak = progress_weak.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(window) = weak.upgrade() {
                            window.set_text_file_status(
                                format!(
                                    "Streaming: {} of {} bytes confirmed; chunk {} of {}.",
                                    progress.confirmed_bytes,
                                    progress.total_bytes,
                                    progress.confirmed_children,
                                    progress.total_children,
                                )
                                .into(),
                            );
                        }
                    });
                });
                let device_state = snapshot.device(&device_id);
                (result, device_state)
            });
            let _ = slint::invoke_from_event_loop(move || {
                busy.store(false, Ordering::Release);
                cancel.store(false, Ordering::Release);
                if !client.is_current(expected_generation) {
                    return;
                }
                let Some(window) = weak_result.upgrade() else {
                    return;
                };
                window.set_text_file_busy(false);
                window.set_text_file_cancellable(false);
                window.set_text_file_ready(true);
                match operation {
                    Some((Ok(result), device_state)) => {
                        let status = text_file_result_status(&result);
                        window.set_text_file_status(status.clone().into());
                        window.set_status(status.into());
                        if let Ok(device) = device_state {
                            update_device_view(&window, &device);
                        }
                    }
                    Some((Err(error), device_state)) => {
                        window.set_text_file_status(format!("Stream stopped: {error}").into());
                        window.set_status(format!("Text-file stream stopped: {error}").into());
                        if let Ok(device) = device_state {
                            update_device_view(&window, &device);
                        }
                    }
                    None => {
                        window.set_text_file_status(
                            "Stream stopped because the selected gateway changed.".into(),
                        );
                        window.set_status(
                            "Text-file stream stopped because the selected gateway changed.".into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let busy_for_cancel = Arc::clone(&text_file_busy);
    let cancel_for_cancel = Arc::clone(&text_file_cancel);
    window.on_cancel_text_file(move || {
        if !busy_for_cancel.load(Ordering::Acquire) {
            set_status(&weak, "No text stream is active.");
            return;
        }
        cancel_for_cancel.store(true, Ordering::Release);
        if let Some(window) = weak.upgrade() {
            window.set_text_file_cancellable(false);
            window.set_text_file_status(
                "Stopping after the current bounded operation and confirming key release…".into(),
            );
        }
    });

    let weak = window.as_weak();
    let client_for_text = Arc::clone(&client);
    let selected_for_text = Arc::clone(&selected_device);
    let busy_for_text = Arc::clone(&text_file_busy);
    let cancel_for_text = Arc::clone(&text_file_cancel);
    window.on_send_text(move || {
        let Some(device_id) = selected_for_text
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before sending text.");
            return;
        };
        let Some(window) = weak.upgrade() else { return };
        if window.get_selected_profile().as_str() != "windows-us" {
            set_status(&weak, "Text rejected: unsupported target profile.");
            return;
        }
        let (timing, send_after_seconds) = match text_options(&window) {
            Ok(options) => options,
            Err(error) => {
                set_status(&weak, &format!("Command rejected: {error}"));
                return;
            }
        };
        let options = TextValueOptions {
            timing,
            send_after_seconds,
            unsupported: text_unsupported_policy(&window),
        };
        let mut text = Zeroizing::new(window.get_text_input().to_string());
        let summary = match preflight_text_value(&text, options) {
            Ok(summary) => summary,
            Err(error) => {
                set_status(&weak, &format!("Text rejected: {error}"));
                return;
            }
        };
        if busy_for_text
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            set_status(&weak, "A text stream is already running.");
            return;
        }
        cancel_for_text.store(false, Ordering::Release);
        let text = std::mem::take(&mut *text);
        window.set_text_input("".into());
        window.set_text_file_busy(true);
        window.set_text_file_cancellable(true);
        window.set_text_file_status(
            format!(
                "Starting pasted text: {} characters in {} bounded chunks…",
                summary.source_scalars, summary.children,
            )
            .into(),
        );
        set_control_pending(
            &window,
            if send_after_seconds > 0 {
                "Streaming is ready; typing will wait before it starts…"
            } else {
                "Pasted text is streaming in bounded chunks…"
            },
        );
        set_status(&weak, "Starting the daemon-owned text stream…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_text);
        let busy = Arc::clone(&busy_for_text);
        let cancel = Arc::clone(&cancel_for_text);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let progress_weak = weak_result.clone();
            let operation = client.run_mutation(expected_generation, |snapshot| {
                let result = run_text_value(
                    snapshot,
                    &device_id,
                    text,
                    options,
                    &cancel,
                    |progress| {
                        let weak = progress_weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(window) = weak.upgrade() {
                                window.set_text_file_status(
                                    format!(
                                        "Streaming pasted text: {} of {} bytes confirmed; chunk {} of {}.",
                                        progress.confirmed_bytes,
                                        progress.total_bytes,
                                        progress.confirmed_children,
                                        progress.total_children,
                                    )
                                    .into(),
                                );
                            }
                        });
                    },
                );
                let device_state = snapshot.device(&device_id);
                (result, device_state)
            });
            let _ = slint::invoke_from_event_loop(move || {
                busy.store(false, Ordering::Release);
                cancel.store(false, Ordering::Release);
                if !client.is_current(expected_generation) {
                    return;
                }
                let Some(window) = weak_result.upgrade() else { return };
                window.set_text_file_busy(false);
                window.set_text_file_cancellable(false);
                match operation {
                    Some((Ok(result), device_state)) => {
                        let status = text_file_result_status(&result);
                        window.set_text_file_status(status.clone().into());
                        window.set_status(status.into());
                        if let Ok(device) = device_state {
                            update_device_view(&window, &device);
                        }
                    }
                    Some((Err(error), device_state)) => {
                        window.set_text_file_status(format!("Stream stopped: {error}").into());
                        window.set_status(format!("Pasted-text stream stopped: {error}").into());
                        if let Ok(device) = device_state {
                            update_device_view(&window, &device);
                        }
                    }
                    None => {
                        window.set_text_file_status(
                            "Stream stopped because the selected gateway changed.".into(),
                        );
                        window.set_status(
                            "Pasted-text stream stopped because the selected gateway changed."
                                .into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let client_for_sequence = Arc::clone(&client);
    let selected_for_sequence = Arc::clone(&selected_device);
    window.on_send_sequence(move || {
        let Some(device_id) = selected_for_sequence
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before sending a sequence.");
            return;
        };
        let Some(window) = weak.upgrade() else {
            return;
        };
        let source = Zeroizing::new(window.get_sequence_input().to_string());
        let generated_command_id = uuid::Uuid::now_v7().to_string();
        let mut prepared = match prepare_sequence(&source, &generated_command_id) {
            Ok(prepared) => prepared,
            Err(code) => {
                set_status(&weak, &format!("Sequence rejected: {code}"));
                return;
            }
        };
        window.set_sequence_input(SEQUENCE_DRAFT.into());
        set_control_pending(&window, "Submitting this sequence…");
        set_status(&weak, "Sending sequence to keyferryd…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_sequence);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let Some((result, device_state)) =
                client.run_mutation(expected_generation, |snapshot| {
                    let result = submit_ui_sequence(snapshot, &device_id, &mut prepared.request);
                    clear_sequence_payload(&mut prepared.request);
                    let device_state = snapshot.device(&device_id);
                    (result, device_state)
                })
            else {
                return;
            };
            show_command_result(
                &weak_result,
                &client,
                expected_generation,
                result,
                device_state,
            );
        });
    });

    let weak = window.as_weak();
    let client_for_hotkey = Arc::clone(&client);
    let selected_for_hotkey = Arc::clone(&selected_device);
    window.on_send_hotkey(move || {
        let Some(device_id) = selected_for_hotkey
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before sending keys.");
            return;
        };
        let Some(window) = weak.upgrade() else { return };
        let mut request = match hotkey_action(window.get_hotkey().as_str()).and_then(|action| {
            ui_sequence(window.get_selected_profile().to_string(), vec![action])
                .map_err(str::to_owned)
        }) {
            Ok(request) => request,
            Err(error) => {
                set_status(&weak, &format!("Keys rejected: {error}"));
                return;
            }
        };
        window.set_hotkey("".into());
        set_control_pending(&window, "Submitting this command…");
        set_status(&weak, "Sending keys to keyferryd…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_hotkey);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let Some((result, device_state)) =
                client.run_mutation(expected_generation, |snapshot| {
                    let result = submit_ui_sequence(snapshot, &device_id, &mut request);
                    clear_sequence_payload(&mut request);
                    let device_state = snapshot.device(&device_id);
                    (result, device_state)
                })
            else {
                return;
            };
            show_command_result(
                &weak_result,
                &client,
                expected_generation,
                result,
                device_state,
            );
        });
    });

    let weak = window.as_weak();
    let client_for_output_mode = Arc::clone(&client);
    let selected_for_output_mode = Arc::clone(&selected_device);
    window.on_set_output_mode(move |selection| {
        let requested = match selection.as_str() {
            "usb-hid" => OutputMode::UsbHid,
            "ble-hid" => OutputMode::BleHid,
            _ => {
                set_status(&weak, "Choose USB keyboard or Bluetooth keyboard output.");
                return;
            }
        };
        let Some(device_id) = selected_for_output_mode
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before changing keyboard output.");
            return;
        };
        if let Some(window) = weak.upgrade() {
            window.set_output_mode_busy(true);
            window.set_output_mode_status("Saving output mode and restarting the stick…".into());
        }
        set_status(&weak, "Saving keyboard output mode…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_output_mode);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let Some(result) = client.run_mutation(expected_generation, |snapshot| {
                snapshot.set_output_mode(&device_id, requested)
            }) else {
                return;
            };
            let _ = slint::invoke_from_event_loop(move || {
                if !client.is_current(expected_generation) {
                    return;
                }
                let Some(window) = weak_result.upgrade() else { return };
                window.set_output_mode_busy(false);
                match result {
                    Ok(status) => {
                        apply_output_mode_status(&window, &status);
                        schedule_automatic_refreshes(weak_result.clone());
                        window.set_status(
                            "Output mode saved. The stick is restarting; status will refresh automatically."
                                .into(),
                        );
                    }
                    Err(error) => {
                        window.set_output_mode_status(
                            "Switch confirmation was not received. Do not retry automatically; refresh to read the retained mode."
                                .into(),
                        );
                        window.set_status(format!("Output-mode request failed: {error}").into());
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let client_for_display_orientation = Arc::clone(&client);
    let selected_for_display_orientation = Arc::clone(&selected_device);
    window.on_set_display_orientation(move |selection| {
        let requested = match selection.as_str() {
            "normal" => DisplayOrientation::Normal,
            "rotated-180" => DisplayOrientation::Rotated180,
            _ => {
                set_status(&weak, "Choose Normal or Rotate 180°.");
                return;
            }
        };
        let Some(device_id) = selected_for_display_orientation
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before changing its screen orientation.");
            return;
        };
        if let Some(window) = weak.upgrade() {
            window.set_display_orientation_busy(true);
            window.set_display_orientation_status(
                "Saving screen orientation and restarting the stick…".into(),
            );
        }
        set_status(&weak, "Saving screen orientation…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_display_orientation);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let Some(result) = client.run_mutation(expected_generation, |snapshot| {
                snapshot.set_display_orientation(&device_id, requested)
            }) else {
                return;
            };
            let _ = slint::invoke_from_event_loop(move || {
                if !client.is_current(expected_generation) {
                    return;
                }
                let Some(window) = weak_result.upgrade() else { return };
                window.set_display_orientation_busy(false);
                match result {
                    Ok(status) => {
                        apply_display_orientation_status(&window, &status);
                        schedule_automatic_refreshes(weak_result.clone());
                        window.set_status(
                            "Screen orientation saved. The stick is restarting; status will refresh automatically."
                                .into(),
                        );
                    }
                    Err(error) => {
                        window.set_display_orientation_status(
                            "Orientation confirmation was not received. Do not retry automatically; refresh to read the retained setting."
                                .into(),
                        );
                        window.set_status(
                            format!("Display-orientation request failed: {error}").into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let client_for_screen_power = Arc::clone(&client);
    let selected_for_screen_power = Arc::clone(&selected_device);
    window.on_set_screen_power(move |selection| {
        let requested = match selection.as_str() {
            "on" => ScreenPower::On,
            "off" => ScreenPower::Off,
            _ => return,
        };
        let Some(window) = weak.upgrade() else { return };
        if !window.get_screen_power_supported()
            || !window.get_screen_power_known()
            || !window.get_can_submit()
            || window.get_screen_power_busy()
            || window.get_screen_power_pending()
            || window.get_provisioning_busy()
            || window.get_text_file_busy()
            || window.get_output_mode_busy()
            || window.get_display_orientation_busy()
        {
            return;
        }
        let Some(device_id) = selected_for_screen_power.lock().expect("selected device lock").clone() else {
            return;
        };
        window.set_screen_power_busy(true);
        window.set_screen_power_status("Saving screen setting…".into());
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_screen_power);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let result = client.run_mutation(expected_generation, |api| {
                api.set_screen_power(&device_id, requested)
            });
            let _ = slint::invoke_from_event_loop(move || {
                let Some(window) = weak_result.upgrade() else { return };
                if window.get_selected_device_id().as_str() != device_id {
                    return;
                }
                window.set_screen_power_busy(false);
                if !client.is_current(expected_generation) {
                    return;
                }
                match result {
                    Some(Ok(status)) => {
                        apply_screen_power_status(&window, &status);
                        schedule_automatic_refreshes(weak_result.clone());
                    }
                    Some(Err(_)) | None => {
                        window.set_screen_power_known(false);
                        window.set_screen_power_status(
                            "Screen change was not confirmed. Refresh to read its setting before trying again.".into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let client_for_bond_reset = Arc::clone(&client);
    let selected_for_bond_reset = Arc::clone(&selected_device);
    window.on_reset_ble_hid_bond(move || {
        let Some(device_id) = selected_for_bond_reset
            .lock()
            .expect("selected device lock")
            .clone()
        else {
            set_status(&weak, "Select a device before forgetting Bluetooth pairing.");
            return;
        };
        if let Some(window) = weak.upgrade() {
            window.set_ble_hid_bond_reset_busy(true);
            window.set_ble_hid_bond_reset_status(
                "Forgetting the Bluetooth keyboard bond and restarting the stick…".into(),
            );
        }
        set_status(&weak, "Forgetting Bluetooth keyboard pairing…");
        let weak_result = weak.clone();
        let client = Arc::clone(&client_for_bond_reset);
        let expected_generation = client.snapshot().1;
        thread::spawn(move || {
            let Some(result) = client.run_mutation(expected_generation, |snapshot| {
                snapshot.reset_ble_hid_bond(&device_id)
            }) else {
                return;
            };
            let _ = slint::invoke_from_event_loop(move || {
                if !client.is_current(expected_generation) {
                    return;
                }
                let Some(window) = weak_result.upgrade() else { return };
                window.set_ble_hid_bond_reset_busy(false);
                window.set_ble_hid_bond_reset_confirming(false);
                match result {
                    Ok(status) => {
                        schedule_automatic_refreshes(weak_result.clone());
                        let detail = if status.bond_was_present {
                            "Bluetooth keyboard pairing forgotten. The stick is restarting in pairing mode."
                        } else {
                            "No Bluetooth keyboard pairing was stored. The stick is restarting in pairing mode."
                        };
                        window.set_ble_hid_bond_reset_status(detail.into());
                        window.set_status(
                            "Bluetooth pairing reset completed. Refresh after the stick reconnects."
                                .into(),
                        );
                    }
                    Err(error) => {
                        window.set_ble_hid_bond_reset_status(
                            "Pairing reset was not confirmed. Do not retry automatically; refresh before deciding what to do."
                                .into(),
                        );
                        window.set_status(
                            format!("Bluetooth pairing reset failed: {error}").into(),
                        );
                    }
                }
            });
        });
    });

    let weak = window.as_weak();
    let client_for_release = Arc::clone(&client);
    let selected_for_release = Arc::clone(&selected_device);
    window.on_release_input(move || {
        run_device_command(
            &weak,
            Arc::clone(&client_for_release),
            Arc::clone(&selected_for_release),
            "Stopping input…",
            |client, id| client.disarm(id),
        );
    });

    let weak = window.as_weak();
    let client_for_cancel = Arc::clone(&client);
    let selected_for_cancel = Arc::clone(&selected_device);
    window.on_cancel(move || {
        run_device_command(
            &weak,
            Arc::clone(&client_for_cancel),
            Arc::clone(&selected_for_cancel),
            "Requesting cancellation…",
            |client, id| {
                client.cancel(id, None)?;
                client.device(id)
            },
        );
    });

    let weak = window.as_weak();
    let client_for_refresh = Arc::clone(&client);
    let selected_for_refresh = Arc::clone(&selected_device);
    window.on_refresh(move || {
        mark_refresh_requested(&refresh_clock, Instant::now());
        if let Some(window) = weak.upgrade() {
            adopt_local_daemon_if_unavailable(&window, &client_for_refresh);
        }
        refresh_devices(
            weak.clone(),
            Arc::clone(&client_for_refresh),
            Arc::clone(&selected_for_refresh),
        );
    });
}

fn start_usb_file(
    weak: &Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    busy: Arc<AtomicBool>,
    clear: bool,
) {
    let Some(window) = weak.upgrade() else { return };
    let Some(device_id) = selected_device
        .lock()
        .expect("selected device lock")
        .clone()
    else {
        return;
    };
    if !window.get_usb_file_ready() || busy.swap(true, Ordering::AcqRel) {
        return;
    }
    let path = (!clear && window.get_file_mode())
        .then(|| PathBuf::from(window.get_text_file_path().trim()));
    let clear_file_set = clear && window.get_usb_file_set_supported();
    let mut bytes = Zeroizing::new(if clear || path.is_some() {
        Vec::new()
    } else {
        window.get_text_input().as_bytes().to_vec()
    });
    window.set_text_file_busy(true);
    window.set_usb_published_known(false);
    window.set_usb_file_status(
        if clear {
            "Clearing the USB file…"
        } else {
            "Sending the file to the KEYFERRY drive…"
        }
        .into(),
    );
    window.set_text_file_status(window.get_usb_file_status());
    let expected_generation = client.snapshot().1;
    let weak = weak.clone();
    thread::spawn(move || {
        let result = (|| -> Result<_, String> {
            if let Some(path) = path {
                let file =
                    std::fs::File::open(path).map_err(|_| "Cannot open the selected file.")?;
                if !file
                    .metadata()
                    .map_err(|_| "Cannot read the selected file.")?
                    .is_file()
                {
                    return Err("Select a regular file.".to_owned());
                }
                file.take(keyferry_protocol::file::MAX_FILE_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "Cannot read the selected file.")?;
            }
            if bytes.len() > keyferry_protocol::file::MAX_FILE_BYTES {
                return Err(format!(
                    "File is too large. Maximum: {} bytes.",
                    keyferry_protocol::file::MAX_FILE_BYTES
                ));
            }
            client
                .run_mutation(expected_generation, |snapshot| {
                    if clear {
                        if clear_file_set {
                            snapshot.clear_usb_files(&device_id)
                        } else {
                            snapshot.clear_usb_file(&device_id)
                        }
                    } else {
                        snapshot.publish_usb_file(&device_id, &bytes)
                    }
                })
                .ok_or_else(|| "Selected connection changed; file was not sent.".to_owned())?
                .map_err(|error| {
                    format!("USB file: {error}. Check the KEYFERRY drive before retrying.")
                })
        })();
        bytes.zeroize();
        let _ = slint::invoke_from_event_loop(move || {
            busy.store(false, Ordering::Release);
            let Some(window) = weak.upgrade() else { return };
            window.set_text_file_busy(false);
            if !client.is_current(expected_generation)
                || !selected_device_matches(&selected_device, &device_id)
            {
                return;
            }
            let message = match result {
                Ok(status) if clear && status.state == "empty" => {
                    if clear_file_set {
                        show_published_usb_files(&window, &status);
                    }
                    window
                        .set_usb_pending_files(ModelRc::new(VecModel::from(
                            Vec::<ui::UsbFileItem>::new(),
                        )));
                    window.set_usb_pending_total(0);
                    "USB drive cleared.".to_owned()
                }
                Ok(status) if !clear && status.state == "published" => {
                    if window.get_usb_file_set_supported() {
                        show_published_usb_files(
                            &window,
                            &UsbFileStatus {
                                files: vec![keyferry::api::UsbFileEntry {
                                    name: "MESSAGE.TXT".to_owned(),
                                    size: status.size_bytes,
                                }],
                                ..status.clone()
                            },
                        );
                    }
                    if !window.get_file_mode() {
                        window.set_text_input("".into());
                    }
                    format!(
                        "{} bytes ready as KEYFERRY / MESSAGE.TXT. Open it on the USB-connected computer.",
                        status.size_bytes
                    )
                }
                Ok(_) => "File was not published. Check the KEYFERRY drive before sending again."
                    .to_owned(),
                Err(message) => message,
            };
            window.set_usb_file_status(message.clone().into());
            window.set_status(message.into());
        });
    });
}

fn preview_usb_files(paths: &[PathBuf]) -> Result<Vec<ui::UsbFileItem>, String> {
    use keyferry_protocol::file_set::{validate_names, MAX_FILES, MAX_FILE_BYTES};
    if paths.is_empty() || paths.len() > MAX_FILES {
        return Err(format!("Choose 1 to {MAX_FILES} files."));
    }
    let names = paths
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or("A selected file has an unsupported name.")
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_names(&names).map_err(|_| {
        "Use 1–64 ASCII letters, digits, spaces, ._- per filename; no reserved Windows names, leading/trailing spaces or dots, or duplicate names (ignoring case).".to_owned()
    })?;
    let mut items = Vec::with_capacity(paths.len());
    let mut total = 0usize;
    for (path, name) in paths.iter().zip(names) {
        let metadata = std::fs::metadata(path).map_err(|_| "Cannot read a selected file.")?;
        if !metadata.is_file() {
            return Err("Select regular files only.".to_owned());
        }
        let size = usize::try_from(metadata.len()).map_err(|_| "A file is too large.")?;
        total = total
            .checked_add(size)
            .ok_or("The selected files are too large.")?;
        if total > MAX_FILE_BYTES {
            return Err(format!(
                "Selected files exceed the shared {MAX_FILE_BYTES}-byte limit."
            ));
        }
        items.push(ui::UsbFileItem {
            name: name.into(),
            path: path.to_string_lossy().into_owned().into(),
            size: size as i32,
        });
    }
    Ok(items)
}

fn start_usb_files(
    weak: &Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    busy: Arc<AtomicBool>,
) {
    use keyferry_protocol::file_set::{validate_names, MAX_FILE_BYTES};
    let Some(window) = weak.upgrade() else { return };
    let Some(device_id) = selected_device
        .lock()
        .expect("selected device lock")
        .clone()
    else {
        return;
    };
    if !window.get_usb_file_set_supported()
        || !window.get_usb_file_ready()
        || busy.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let model = window.get_usb_pending_files();
    let items = (0..model.row_count())
        .filter_map(|index| model.row_data(index))
        .collect::<Vec<_>>();
    if items.is_empty() {
        busy.store(false, Ordering::Release);
        return;
    }
    window.set_text_file_busy(true);
    window.set_usb_published_known(false);
    window.set_usb_file_status("Publishing the selected files as one USB drive…".into());
    let expected_generation = client.snapshot().1;
    let weak = weak.clone();
    thread::spawn(move || {
        let result = (|| -> Result<_, String> {
            let names = items
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>();
            validate_names(&names).map_err(|_| "The selected USB file names are invalid.")?;
            let mut files = Vec::with_capacity(items.len());
            let mut total = 0usize;
            for item in &items {
                let path = PathBuf::from(item.path.as_str());
                let file = std::fs::File::open(path).map_err(|_| "Cannot open a selected file.")?;
                if !file
                    .metadata()
                    .map_err(|_| "Cannot read a selected file.")?
                    .is_file()
                {
                    return Err("Select regular files only.".to_owned());
                }
                let mut bytes = Zeroizing::new(Vec::new());
                file.take((MAX_FILE_BYTES - total + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "Cannot read a selected file.")?;
                total += bytes.len();
                if total > MAX_FILE_BYTES {
                    return Err(format!(
                        "Selected files exceed the shared {MAX_FILE_BYTES}-byte limit."
                    ));
                }
                files.push((item.name.to_string(), bytes));
            }
            let borrowed = files
                .iter()
                .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
                .collect::<Vec<_>>();
            let status = client
                .run_mutation(expected_generation, |snapshot| {
                    snapshot.publish_usb_files(&device_id, &borrowed)
                })
                .ok_or_else(|| "Selected connection changed; files were not sent.".to_owned())?
                .map_err(|error| {
                    format!("USB files: {error}. Check the KEYFERRY drive before retrying.")
                })?;
            if status.state != "published"
                || status.size_bytes != total
                || status.files.len() != files.len()
                || files.iter().any(|(name, bytes)| {
                    !status
                        .files
                        .iter()
                        .any(|entry| entry.name == *name && entry.size == bytes.len())
                })
            {
                return Err(
                    "Publication outcome is uncertain. Check the KEYFERRY drive before retrying."
                        .to_owned(),
                );
            }
            Ok(status)
        })();
        let _ = slint::invoke_from_event_loop(move || {
            busy.store(false, Ordering::Release);
            let Some(window) = weak.upgrade() else { return };
            window.set_text_file_busy(false);
            if !client.is_current(expected_generation)
                || !selected_device_matches(&selected_device, &device_id)
            {
                return;
            }
            let message = match result {
                Ok(status) => {
                    show_published_usb_files(&window, &status);
                    window
                        .set_usb_pending_files(ModelRc::new(VecModel::from(
                            Vec::<ui::UsbFileItem>::new(),
                        )));
                    window.set_usb_pending_total(0);
                    format!(
                        "{} files ({} bytes) ready on the USB-connected computer.",
                        status.files.len(),
                        status.size_bytes
                    )
                }
                Err(message) => message,
            };
            window.set_usb_file_status(message.clone().into());
            window.set_status(message.into());
        });
    });
}

fn show_published_usb_files(window: &ui::MainWindow, status: &UsbFileStatus) {
    if status.state != "empty" && status.state != "published" {
        window.set_usb_published_known(false);
        return;
    }
    let items = status
        .files
        .iter()
        .map(|entry| ui::UsbFileItem {
            name: entry.name.clone().into(),
            path: "".into(),
            size: entry.size as i32,
        })
        .collect::<Vec<_>>();
    window.set_usb_published_total(status.size_bytes as i32);
    window.set_usb_published_files(ModelRc::new(VecModel::from(items)));
    window.set_usb_published_known(true);
}

fn refresh_usb_files(
    weak: &Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    busy: Arc<AtomicBool>,
) {
    let Some(window) = weak.upgrade() else { return };
    let Some(device_id) = selected_device
        .lock()
        .expect("selected device lock")
        .clone()
    else {
        return;
    };
    if !window.get_usb_file_set_supported()
        || !window.get_usb_file_ready()
        || busy.swap(true, Ordering::AcqRel)
    {
        return;
    }
    window.set_text_file_busy(true);
    window.set_usb_file_status("Reading the USB drive…".into());
    let (snapshot, expected_generation) = client.snapshot();
    let weak = weak.clone();
    thread::spawn(move || {
        let result = snapshot.usb_files(&device_id);
        let _ = slint::invoke_from_event_loop(move || {
            busy.store(false, Ordering::Release);
            let Some(window) = weak.upgrade() else { return };
            window.set_text_file_busy(false);
            if !client.is_current(expected_generation)
                || !selected_device_matches(&selected_device, &device_id)
            {
                return;
            }
            let message = match result {
                Ok(status) => {
                    show_published_usb_files(&window, &status);
                    match status.state.as_str() {
                        "empty" => "KEYFERRY USB drive is empty.".to_owned(),
                        "published" => format!(
                            "KEYFERRY USB drive has {} files ({} bytes).",
                            status.files.len(),
                            status.size_bytes
                        ),
                        "receiving" => format!(
                            "USB file upload in progress: {} of {} bundle bytes. Published contents are not yet available.",
                            status.bundle_received_bytes,
                            status.bundle_size_bytes
                        ),
                        _ => "USB drive status is unknown; check the USB-connected computer."
                            .to_owned(),
                    }
                }
                Err(error) => {
                    window.set_usb_published_known(false);
                    format!("USB drive status: {error}")
                }
            };
            window.set_usb_file_status(message.into());
        });
    });
}

fn run_device_command<F>(
    weak: &Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    pending_message: &str,
    operation: F,
) where
    F: FnOnce(&ApiClient, &str) -> Result<DeviceView, ApiError> + Send + 'static,
{
    let Some(device_id) = selected_device
        .lock()
        .expect("selected device lock")
        .clone()
    else {
        set_status(weak, "Select a device first.");
        return;
    };
    if let Some(window) = weak.upgrade() {
        set_control_pending(&window, pending_message);
    }
    set_status(weak, pending_message);
    let weak_result = weak.clone();
    let expected_generation = client.snapshot().1;
    thread::spawn(move || {
        let Some(result) = client.run_mutation(expected_generation, |snapshot| {
            operation(snapshot, &device_id)
        }) else {
            return;
        };
        let _ = slint::invoke_from_event_loop(move || {
            if !client.is_current(expected_generation) {
                return;
            }
            if !selected_device_matches(&selected_device, &device_id) {
                return;
            }
            if let Some(window) = weak_result.upgrade() {
                match result {
                    Ok(device) => {
                        update_device_view(&window, &device);
                        window.set_status("Device state updated.".into());
                    }
                    Err(error) => {
                        clear_control_state(&window);
                        window.set_status(format!("Daemon request failed: {error}").into());
                    }
                }
            }
        });
    });
}

fn note_device_connected(connected: bool) {
    let mut offline_since = DEVICE_OFFLINE_SINCE.lock().expect("device watch lock");
    if connected {
        *offline_since = None;
    } else if offline_since.is_none() {
        *offline_since = Some(Instant::now());
    }
}

fn device_watch_interval(offline_for: Option<Duration>) -> Duration {
    match offline_for {
        None => DEVICE_WATCH_CONNECTED_INTERVAL,
        Some(offline_for) if offline_for < DEVICE_WATCH_FAST_FOR => DEVICE_WATCH_FAST_INTERVAL,
        Some(_) => DEVICE_WATCH_SLOW_INTERVAL,
    }
}

/// Read only the local daemon's device list every 10 s while connected. An offline selection is
/// polled every 3 s at first, then every 15 s after two minutes. This keeps tailnet holder changes
/// visible without running desktop-side discovery.
fn start_device_watch(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
) {
    thread::spawn(move || {
        let mut last_poll = Instant::now();
        loop {
            thread::sleep(DEVICE_WATCH_TICK);
            let offline_since = *DEVICE_OFFLINE_SINCE.lock().expect("device watch lock");
            let now = Instant::now();
            let interval = device_watch_interval(
                offline_since.map(|since| now.saturating_duration_since(since)),
            );
            if now.saturating_duration_since(last_poll) < interval
                || DEVICE_REFRESH_IN_FLIGHT.load(Ordering::Acquire)
            {
                continue;
            }
            last_poll = now;
            let weak = weak.clone();
            let client = Arc::clone(&client);
            let selected_device = Arc::clone(&selected_device);
            let scheduled = slint::invoke_from_event_loop(move || {
                if let Some(window) = weak.upgrade() {
                    adopt_local_daemon_if_unavailable(&window, &client);
                }
                start_device_refresh(weak, client, selected_device, false);
            });
            if scheduled.is_err() {
                return;
            }
        }
    });
}

fn refresh_devices(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
) {
    start_device_refresh(weak, client, selected_device, true);
}

/// Device refreshes never overlap. An announced refresh requested while another is running
/// runs once more afterwards; a quiet watch refresh is simply skipped and leaves the status bar
/// untouched.
fn start_device_refresh(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    selected_device: Arc<Mutex<Option<String>>>,
    announce: bool,
) {
    if DEVICE_REFRESH_IN_FLIGHT
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        if announce {
            DEVICE_REFRESH_RERUN.store(true, Ordering::Release);
        }
        return;
    }
    if announce {
        set_status(&weak, "Refreshing devices…");
    }
    thread::spawn(move || {
        let (snapshot, generation) = client.snapshot();
        let result = snapshot.devices().map(|devices| {
            let output_modes = devices
                .iter()
                .filter(|device| {
                    !is_tailnet_device(device)
                        && device
                            .firmware
                            .as_ref()
                            .is_some_and(|firmware| firmware.ble_hid_output_v1)
                })
                .map(|device| (device.id.clone(), snapshot.output_mode(&device.id)))
                .collect::<HashMap<_, _>>();
            let display_orientations = devices
                .iter()
                .filter(|device| {
                    !is_tailnet_device(device)
                        && device
                            .firmware
                            .as_ref()
                            .is_some_and(|firmware| firmware.display_orientation_v1)
                })
                .map(|device| (device.id.clone(), snapshot.display_orientation(&device.id)))
                .collect::<HashMap<_, _>>();
            let screen_powers = devices
                .iter()
                .filter(|device| supports_screen_power(device))
                .map(|device| (device.id.clone(), snapshot.screen_power(&device.id)))
                .collect::<HashMap<_, _>>();
            (devices, output_modes, display_orientations, screen_powers)
        });
        let rerun_weak = weak.clone();
        let rerun_client = Arc::clone(&client);
        let rerun_selected = Arc::clone(&selected_device);
        let scheduled = slint::invoke_from_event_loop(move || {
            DEVICE_REFRESH_IN_FLIGHT.store(false, Ordering::Release);
            if DEVICE_REFRESH_RERUN.swap(false, Ordering::AcqRel) {
                refresh_devices(rerun_weak, rerun_client, rerun_selected);
            }
            if !client.is_current(generation) {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            match result {
                Ok((devices, mut output_modes, mut display_orientations, mut screen_powers)) => {
                    let current = selected_device
                        .lock()
                        .expect("selected device lock")
                        .clone();
                    let selected = retain_or_choose_device(current, &devices);
                    if window.get_selected_device_id().as_str() != selected.as_deref().unwrap_or("")
                    {
                        clear_device_specific_state(&window);
                    }
                    let mut items = devices
                        .iter()
                        .map(|device| ui::DeviceListItem {
                            id: device.id.clone().into(),
                            title: device.label.clone().into(),
                            subtitle: device_row_subtitle(device).into(),
                        })
                        .collect::<Vec<_>>();
                    if let Some(id) = selected.as_deref() {
                        if !devices.iter().any(|device| device.id == id) {
                            items.push(offline_device_item(id));
                        }
                    }
                    window.set_device_items(ModelRc::new(VecModel::from(items)));
                    *selected_device.lock().expect("selected device lock") = selected.clone();
                    if let Some(id) = selected {
                        window.set_selected_device_id(id.clone().into());
                        if let Some(device) = devices.iter().find(|device| device.id == id) {
                            update_device_view(&window, device);
                            if let Some(result) = output_modes.remove(&device.id) {
                                apply_output_mode_result(&window, result);
                            }
                            if let Some(result) = display_orientations.remove(&device.id) {
                                apply_display_orientation_result(&window, result);
                            }
                            if let Some(result) = screen_powers.remove(&device.id) {
                                apply_screen_power_result(&window, result);
                            }
                        } else {
                            show_selected_device_offline(
                                &window,
                                &id,
                                "This Keyferry is offline on the selected controller. Choose another device explicitly or refresh after it reconnects.",
                            );
                        }
                    } else {
                        window.set_selected_device("No device selected".into());
                        window.set_selected_device_id(SharedString::default());
                        window.set_device_fields(ModelRc::new(VecModel::from(
                            Vec::<ui::DetailRow>::new(),
                        )));
                        clear_control_state(&window);
                        note_device_connected(false);
                    }
                    if announce {
                        window.set_status(device_count_status(devices.len()).into());
                    }
                }
                Err(error) => {
                    let retained = selected_device
                        .lock()
                        .expect("selected device lock")
                        .clone();
                    if let Some(id) = retained {
                        window.set_device_items(ModelRc::new(VecModel::from(vec![
                            offline_device_item(&id),
                        ])));
                        show_selected_device_offline(
                            &window,
                            &id,
                            "Device state could not be read. The selected Keyferry was retained and no other device was chosen.",
                        );
                    } else {
                        window.set_selected_device("Device state unavailable".into());
                        window.set_selected_device_id(SharedString::default());
                        clear_control_state(&window);
                        note_device_connected(false);
                    }
                    if announce {
                        window.set_status(format!("Daemon request failed: {error}").into());
                    }
                }
            }
        });
        if scheduled.is_err() {
            DEVICE_REFRESH_IN_FLIGHT.store(false, Ordering::Release);
        }
    });
}

fn install_diagnostics_actions(window: &ui::MainWindow, diagnostics_enabled: Arc<AtomicBool>) {
    let weak = window.as_weak();
    window.on_toggle_diagnostics(move || {
        let enabled = !diagnostics_enabled.load(Ordering::Acquire);
        diagnostics_enabled.store(enabled, Ordering::Release);
        if let Some(window) = weak.upgrade() {
            window.set_diagnostics_enabled(enabled);
            window.set_diagnostic_lines(ModelRc::new(VecModel::from(
                Vec::<ui::DiagnosticItem>::new(),
            )));
            window.set_status(
                if enabled {
                    "Metadata diagnostics enabled for this app session. Command contents remain excluded."
                } else {
                    "Metadata diagnostics disabled and the in-app history was cleared."
                }
                .into(),
            );
        }
    });
}

fn start_event_feed(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    diagnostics_enabled: Arc<AtomicBool>,
) {
    thread::spawn(move || loop {
        if !diagnostics_enabled.load(Ordering::Acquire) {
            thread::sleep(DIAGNOSTICS_ENABLE_POLL);
            continue;
        }
        let (snapshot, generation) = client.snapshot();
        if let Ok(mut events) = snapshot.events() {
            while let Ok(Some(event)) = events.next_event_while(|| {
                diagnostics_enabled.load(Ordering::Acquire) && client.is_current(generation)
            }) {
                append_event(&weak, &client, &diagnostics_enabled, generation, &event);
            }
        }
        if let Some(delay) = event_reconnect_delay(client.is_current(generation)) {
            thread::sleep(delay);
        }
    });
}

fn event_reconnect_delay(endpoint_is_current: bool) -> Option<Duration> {
    endpoint_is_current.then_some(EVENT_RECONNECT_BACKOFF)
}

fn append_event(
    weak: &Weak<ui::MainWindow>,
    client: &SharedApiClient,
    diagnostics_enabled: &Arc<AtomicBool>,
    generation: u64,
    event: &EventRecord,
) {
    let item = diagnostic_item(event);
    let _ = slint::invoke_from_event_loop({
        let weak = weak.clone();
        let client = Arc::clone(client);
        let diagnostics_enabled = Arc::clone(diagnostics_enabled);
        move || {
            if !diagnostics_enabled.load(Ordering::Acquire) || !client.is_current(generation) {
                return;
            }
            if let Some(window) = weak.upgrade() {
                let mut lines = window.get_diagnostic_lines().iter().collect::<Vec<_>>();
                lines.push(item);
                if lines.len() > 100 {
                    lines.drain(..lines.len() - 100);
                }
                window.set_diagnostic_lines(ModelRc::new(VecModel::from(lines)));
            }
        }
    });
}

fn diagnostic_item(event: &EventRecord) -> ui::DiagnosticItem {
    let outcome = outcome_view(event.outcome);
    let tone = match outcome.tone {
        OutcomeTone::Neutral => 0,
        OutcomeTone::Warning => 2,
        OutcomeTone::Failure => 3,
    };
    ui::DiagnosticItem {
        summary: render_diagnostic_event(event).into(),
        explanation: outcome.explanation.into(),
        tone,
    }
}

fn apply_output_mode_result(window: &ui::MainWindow, result: Result<OutputModeStatus, ApiError>) {
    match result {
        Ok(status) => apply_output_mode_status(window, &status),
        Err(error) => {
            window.set_output_mode_status(format!("Output mode could not be read: {error}").into())
        }
    }
}

fn apply_output_mode_status(window: &ui::MainWindow, status: &OutputModeStatus) {
    let active = match status.active {
        OutputMode::UsbHid => "USB keyboard",
        OutputMode::BleHid => "Bluetooth keyboard",
    };
    let stored = match status.stored {
        OutputMode::UsbHid => "USB keyboard",
        OutputMode::BleHid => "Bluetooth keyboard",
    };
    let message = if status.restart_pending {
        format!("Active: {active}. Saved: {stored}; restart pending.")
    } else {
        format!("Active output: {active}.")
    };
    window.set_output_mode_status(message.into());
    let ble_active = status.active == OutputMode::BleHid;
    window.set_ble_hid_active(ble_active);
    if window.get_ble_hid_bond_reset_supported() {
        window.set_ble_hid_bond_reset_status(
            if ble_active {
                "Forget the bonded keyboard target to pair this stick with a different computer."
            } else {
                "Switch to Bluetooth keyboard output before forgetting its pairing."
            }
            .into(),
        );
    }
}

fn apply_display_orientation_result(
    window: &ui::MainWindow,
    result: Result<DisplayOrientationStatus, ApiError>,
) {
    match result {
        Ok(status) => apply_display_orientation_status(window, &status),
        Err(error) => window.set_display_orientation_status(
            format!("Screen orientation could not be read: {error}").into(),
        ),
    }
}

fn apply_display_orientation_status(window: &ui::MainWindow, status: &DisplayOrientationStatus) {
    let label = |orientation| match orientation {
        DisplayOrientation::Normal => "Normal",
        DisplayOrientation::Rotated180 => "Rotated 180°",
    };
    let message = if status.restart_pending {
        format!(
            "Active: {}. Saved: {}; restart pending.",
            label(status.active),
            label(status.stored)
        )
    } else {
        format!("Active screen orientation: {}.", label(status.active))
    };
    window.set_display_orientation_status(message.into());
}

fn supports_screen_power(device: &DeviceView) -> bool {
    device.link == "authenticated"
        && !is_tailnet_device(device)
        && device
            .firmware
            .as_ref()
            .is_some_and(|firmware| firmware.screen_power_v1)
}

fn apply_screen_power_result(window: &ui::MainWindow, result: Result<ScreenPowerStatus, ApiError>) {
    match result {
        Ok(status) => apply_screen_power_status(window, &status),
        Err(_) => {
            window.set_screen_power_known(false);
            window.set_screen_power_status(
                "Screen setting could not be read. Refresh to try again.".into(),
            );
        }
    }
}

fn apply_screen_power_status(window: &ui::MainWindow, status: &ScreenPowerStatus) {
    if status.device_id != window.get_selected_device_id().as_str() {
        return;
    }
    let pending = status.available && status.active != status.stored;
    window.set_screen_power_known(status.available);
    window.set_screen_power_on(status.active == ScreenPower::On);
    window.set_screen_power_pending(pending);
    let label = |power| {
        if power == ScreenPower::On {
            "on"
        } else {
            "off"
        }
    };
    let message = if !status.available {
        format!(
            "Screen unavailable. Saved setting: {}.",
            label(status.stored)
        )
    } else if pending {
        format!("Saved. Turning the screen {}…", label(status.stored))
    } else {
        format!("Screen {}.", label(status.active))
    };
    window.set_screen_power_status(message.into());
}

fn update_device_view(window: &ui::MainWindow, device: &DeviceView) {
    if window.get_selected_device_id().as_str() != device.id {
        return;
    }
    note_device_connected(device.link == "authenticated");
    window.set_selected_device(device.label.clone().into());
    window.set_selected_device_id(device.id.clone().into());
    let is_tailnet = is_tailnet_device(device);
    window.set_route_is_tailnet(is_tailnet);
    window.set_route_via(if is_tailnet {
        device
            .via
            .as_deref()
            .map(display_route_via)
            .unwrap_or_else(|| "another computer".to_owned())
            .into()
    } else {
        SharedString::default()
    });
    let fields = render_device_fields(device);
    window.set_device_details(join_device_fields(&fields).into());
    window.set_device_fields(ModelRc::new(VecModel::from(fields)));
    let active = device
        .active_outcome
        .map(|outcome| format!("Active: {}", outcome_label(outcome)))
        .unwrap_or_else(|| "No active command".to_owned());
    window.set_active_command(active.into());
    let firmware = device
        .firmware
        .as_ref()
        .map(|firmware| format!("Reported endpoint firmware: {}", firmware.endpoint))
        .unwrap_or_else(|| "Firmware version is not reported by this device.".to_owned());
    window.set_firmware_status(firmware.into());
    let usb_file_supported = device
        .firmware
        .as_ref()
        .is_some_and(|firmware| firmware.usb_file_handoff_v1);
    let usb_file_set_supported = device
        .firmware
        .as_ref()
        .is_some_and(|firmware| firmware.usb_file_set_v2);
    window.set_usb_file_set_supported(usb_file_set_supported);
    window.set_usb_file_supported(usb_file_supported);
    if device.link != "authenticated" {
        window.set_usb_published_known(false);
    }
    window.set_usb_file_ready(
        (usb_file_supported || usb_file_set_supported)
            && device.link == "authenticated"
            && !device.armed
            && !device.maintenance
            && device.mode == "keyboard"
            && device.active_command_id.is_none(),
    );
    let output_mode_supported = !is_tailnet
        && device
            .firmware
            .as_ref()
            .is_some_and(|firmware| firmware.ble_hid_output_v1);
    window.set_output_mode_supported(output_mode_supported);
    let display_orientation_supported = !is_tailnet
        && device
            .firmware
            .as_ref()
            .is_some_and(|firmware| firmware.display_orientation_v1);
    window.set_display_orientation_supported(display_orientation_supported);
    window.set_screen_power_supported(supports_screen_power(device));
    if !supports_screen_power(device) {
        window.set_screen_power_known(false);
        window.set_screen_power_pending(false);
        window.set_screen_power_status(
            if device.link != "authenticated" {
                "Connect this stick to change its screen setting."
            } else {
                "Screen on/off needs newer firmware on this stick."
            }
            .into(),
        );
    }
    if !display_orientation_supported {
        window.set_display_orientation_status(
            "This firmware does not support changing screen orientation from the app.".into(),
        );
    }
    let bond_reset_supported = !is_tailnet
        && device
            .firmware
            .as_ref()
            .is_some_and(|firmware| firmware.ble_hid_bond_reset_v1);
    window.set_ble_hid_bond_reset_supported(bond_reset_supported);
    if !bond_reset_supported {
        window.set_ble_hid_bond_reset_status(
            "This firmware cannot forget a Bluetooth keyboard pairing from the app.".into(),
        );
        window.set_ble_hid_bond_reset_confirming(false);
    }
    if !output_mode_supported {
        window.set_output_mode_status(if device.link == "authenticated" {
            "This firmware does not support direct Bluetooth keyboard output.".into()
        } else {
            "Control is offline. Connect the dongle by USB, enter the owner password below, and choose the output."
                .into()
        });
    }
    window.set_nearby_status(nearby_gateway_status(Some(device)).into());
    window.set_active_link(active_link_label(device, window.get_active_link().as_str()).into());
    apply_control_state(window, control_availability(Some(device)));
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlAvailability {
    can_cancel: bool,
    can_release_input: bool,
    can_submit: bool,
    status: String,
}

fn control_availability(device: Option<&DeviceView>) -> ControlAvailability {
    let Some(device) = device else {
        return ControlAvailability {
            can_cancel: false,
            can_release_input: false,
            can_submit: false,
            status: "Select an authenticated device to begin.".to_owned(),
        };
    };
    if device.link != "authenticated" {
        return ControlAvailability {
            can_cancel: false,
            can_release_input: false,
            can_submit: false,
            status: "The control link is offline; Bluetooth keyboard pairing may still be active. Commands are disabled until control reconnects. Device settings can still use the USB cable."
                .to_owned(),
        };
    }
    if device.maintenance || device.mode != "keyboard" {
        return ControlAvailability {
            can_cancel: false,
            can_release_input: false,
            can_submit: false,
            status: "Keyboard control is unavailable in the current device mode.".to_owned(),
        };
    }
    if device.active_command_id.is_some() {
        return ControlAvailability {
            can_cancel: true,
            can_release_input: false,
            can_submit: false,
            status: "A command is active; wait for its terminal outcome or cancel it.".to_owned(),
        };
    }
    ControlAvailability {
        can_cancel: false,
        can_release_input: device.armed,
        can_submit: true,
        status: "Ready to send.".to_owned(),
    }
}

fn apply_control_state(window: &ui::MainWindow, state: ControlAvailability) {
    window.set_can_cancel(state.can_cancel);
    window.set_can_release_input(state.can_release_input);
    window.set_can_submit(state.can_submit);
    window.set_control_status(state.status.into());
}

fn clear_control_state(window: &ui::MainWindow) {
    window.set_usb_file_supported(false);
    window.set_usb_file_set_supported(false);
    window.set_usb_file_ready(false);
    window.set_usb_published_known(false);
    window.set_active_command("No active command".into());
    window.set_firmware_status("Select a device to view its reported firmware.".into());
    window.set_output_mode_supported(false);
    window.set_output_mode_busy(false);
    window.set_output_mode_status("Select a device to view its keyboard output.".into());
    window.set_display_orientation_supported(false);
    window.set_display_orientation_busy(false);
    window.set_display_orientation_status("Select a device to view its screen orientation.".into());
    window.set_screen_power_supported(false);
    window.set_screen_power_busy(false);
    window.set_screen_power_known(false);
    window.set_screen_power_pending(false);
    window.set_screen_power_status("Select a device to view its screen setting.".into());
    window.set_ble_hid_bond_reset_supported(false);
    window.set_ble_hid_active(false);
    window.set_ble_hid_bond_reset_busy(false);
    window.set_ble_hid_bond_reset_confirming(false);
    window.set_ble_hid_bond_reset_status(
        "Select a device to manage Bluetooth keyboard pairing.".into(),
    );
    window.set_nearby_status(nearby_gateway_status(None).into());
    window.set_active_link("Control offline".into());
    window.set_route_is_tailnet(false);
    window.set_route_via(SharedString::default());
    apply_control_state(window, control_availability(None));
}

fn clear_device_specific_state(window: &ui::MainWindow) {
    window.set_usb_pending_files(ModelRc::new(VecModel::from(Vec::<ui::UsbFileItem>::new())));
    window.set_usb_pending_total(0);
    window.set_usb_file_status("".into());
    window.set_usb_published_files(ModelRc::new(VecModel::from(Vec::<ui::UsbFileItem>::new())));
    window.set_usb_published_total(0);
    window.set_usb_published_known(false);
    window.set_local_recovery_password("".into());
    window.set_local_recovery_confirming(false);
    window.set_local_recovery_confirm_device_id("".into());
    window.set_local_recovery_status("".into());
    window.set_wifi_owner_password("".into());
    window.set_wifi_password("".into());
    window.set_wifi_ssid("".into());
    window.set_selected_wifi_profile(-1);
    window.set_wifi_profile_items(ModelRc::new(VecModel::from(
        Vec::<ui::WifiProfileItem>::new(),
    )));
    window.set_wifi_policy_loaded(false);
    window.set_wifi_policy_dirty(false);
    window.set_provisioning_status("Load this Keyferry's Wi-Fi policy before changing it.".into());
}

fn nearby_gateway_status(device: Option<&DeviceView>) -> String {
    match device.and_then(|device| device.link_path.as_deref()) {
        Some("tailnet") => format!(
            "Routed automatically through {}.",
            device
                .and_then(|device| device.via.as_deref())
                .map(display_route_via)
                .unwrap_or_else(|| "another computer".to_owned())
        ),
        Some("bluetooth") if device.is_some_and(|device| device.link == "authenticated") => {
            "Using Bluetooth fallback. Wi-Fi will be tried on the next control connection."
                .to_owned()
        }
        Some("wifi") if device.is_some_and(|device| device.link == "authenticated") => {
            "Using preferred Wi-Fi. Nearby Bluetooth remains available as fallback.".to_owned()
        }
        _ => "No authenticated control route. Wi-Fi is tried first, then nearby Bluetooth."
            .to_owned(),
    }
}

fn set_control_pending(window: &ui::MainWindow, status: &str) {
    window.set_can_cancel(false);
    window.set_can_release_input(false);
    window.set_can_submit(false);
    window.set_control_status(status.into());
}

fn short_device_id(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn retain_or_choose_device(current: Option<String>, devices: &[DeviceView]) -> Option<String> {
    current.or_else(|| devices.first().map(|device| device.id.clone()))
}

fn selected_device_matches(selection: &Arc<Mutex<Option<String>>>, device_id: &str) -> bool {
    selection.lock().expect("selected device lock").as_deref() == Some(device_id)
}

fn offline_device_item(device_id: &str) -> ui::DeviceListItem {
    ui::DeviceListItem {
        id: device_id.into(),
        title: format!("Keyferry {}", short_device_id(device_id)).into(),
        subtitle: format!(
            "{} · Offline · Pinned selection",
            short_device_id(device_id)
        )
        .into(),
    }
}

fn show_selected_device_offline(window: &ui::MainWindow, device_id: &str, details: &str) {
    note_device_connected(false);
    clear_control_state(window);
    window.set_selected_device(format!("Keyferry {}", short_device_id(device_id)).into());
    window.set_selected_device_id(device_id.into());
    window.set_device_details(details.into());
    window.set_device_fields(ModelRc::new(VecModel::from(vec![detail_row(
        "Control route",
        "Offline".to_owned(),
        2,
    )])));
}

fn device_row_subtitle(device: &DeviceView) -> String {
    let path = device_route_label(device);
    let availability = control_availability(Some(device));
    let state = if availability.can_submit {
        "Ready"
    } else if availability.can_cancel {
        "Busy"
    } else {
        "Unavailable"
    };
    format!("{} · {} · {}", short_device_id(&device.id), path, state)
}

fn device_count_status(count: usize) -> String {
    match count {
        0 => "No devices.".to_owned(),
        1 => "1 device".to_owned(),
        n => format!("{n} devices"),
    }
}

fn render_device_fields(device: &DeviceView) -> Vec<ui::DetailRow> {
    let mut rows = vec![
        detail_row("Control route", device_route_label(device), 0),
        detail_row(
            "Control session",
            format!("{} · {}", device.link, device.transport),
            0,
        ),
        detail_row("Command mode", device.mode.clone(), 0),
    ];
    if let Some(usb) = &device.usb {
        rows.push(detail_row("USB", usb.clone(), 0));
    }
    if let Some(active_host) = &device.active_host {
        rows.push(detail_row("Host", active_host.clone(), 0));
    }
    if let Some(firmware) = &device.firmware {
        rows.push(detail_row("Firmware", firmware.endpoint.clone(), 0));
    }
    rows
}

fn detail_row(label: &str, value: impl Into<String>, tone: i32) -> ui::DetailRow {
    ui::DetailRow {
        label: label.into(),
        value: value.into().into(),
        tone,
    }
}

fn join_device_fields(fields: &[ui::DetailRow]) -> String {
    fields
        .iter()
        .map(|row| format!("{}: {}", row.label, row.value))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
fn render_device_details(device: &DeviceView) -> String {
    join_device_fields(&render_device_fields(device))
}

fn display_link_path(path: &str) -> String {
    match path {
        "wifi" => "Wi-Fi".to_owned(),
        "bluetooth" => "Bluetooth".to_owned(),
        "offline" => "Control offline".to_owned(),
        // Other routes, such as one relayed by another of the owner's controllers, are shown
        // as the local daemon names them.
        other => other
            .chars()
            .filter(|character| !character.is_control())
            .take(48)
            .collect(),
    }
}

fn is_tailnet_device(device: &DeviceView) -> bool {
    device.link_path.as_deref() == Some("tailnet")
}

fn display_route_via(hostname: &str) -> String {
    let clean = hostname
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect::<String>();
    if clean.trim().is_empty() {
        "another computer".to_owned()
    } else {
        clean
    }
}

fn device_route_label(device: &DeviceView) -> String {
    if is_tailnet_device(device) {
        format!(
            "Tailnet via {}",
            device
                .via
                .as_deref()
                .map(display_route_via)
                .unwrap_or_else(|| "another computer".to_owned())
        )
    } else {
        device
            .link_path
            .as_deref()
            .map(display_link_path)
            .unwrap_or_else(|| "—".to_owned())
    }
}

fn active_link_label(device: &DeviceView, previous: &str) -> String {
    if device.link != "authenticated" {
        return "Control offline".to_owned();
    }
    match device.link_path.as_deref() {
        Some(path) if !matches!(path.trim(), "" | "offline") => display_link_path(path),
        _ if !matches!(previous, "" | "Control offline" | "Connected") => previous.to_owned(),
        _ => "Connected".to_owned(),
    }
}

fn outcome_label(outcome: CommandOutcome) -> &'static str {
    keyferry::presentation::outcome_view(outcome).label
}

fn show_command_result(
    weak: &Weak<ui::MainWindow>,
    client: &SharedApiClient,
    generation: u64,
    result: Result<keyferry::api::CommandResponse, ApiError>,
    device_state: Result<DeviceView, ApiError>,
) {
    let reconciliation = reconciliation_target(&result);
    let mut message = match &result {
        Ok(response) if response.outcome.is_terminal() => format!(
            "Command {}: {} — terminal outcome.",
            response.command_id,
            outcome_label(response.outcome)
        ),
        Ok(response) => format!(
            "Command {}: {} — waiting for a read-only terminal outcome.",
            response.command_id,
            outcome_label(response.outcome)
        ),
        Err(error) => format!("Daemon request failed: {error}"),
    };
    if let Err(error) = &device_state {
        message.push_str(&format!(" Current device state is unavailable: {error}"));
    }
    let reconciliation_weak = weak.clone();
    let reconciliation_client = Arc::clone(client);
    let weak = weak.clone();
    let client = Arc::clone(client);
    let _ = slint::invoke_from_event_loop(move || {
        if !client.is_current(generation) {
            return;
        }
        if let Some(window) = weak.upgrade() {
            match device_state {
                Ok(device) => update_device_view(&window, &device),
                Err(_) => clear_control_state(&window),
            }
            window.set_status(message.into());
        }
    });
    if let Some((device_id, command_id)) = reconciliation {
        start_outcome_reconciliation(
            reconciliation_weak,
            reconciliation_client,
            generation,
            device_id,
            command_id,
        );
    }
}

fn reconciliation_target(
    result: &Result<keyferry::api::CommandResponse, ApiError>,
) -> Option<(String, String)> {
    result.as_ref().ok().and_then(|response| {
        (!response.outcome.is_terminal())
            .then(|| (response.device_id.clone(), response.command_id.clone()))
    })
}

fn start_outcome_reconciliation(
    weak: Weak<ui::MainWindow>,
    client: SharedApiClient,
    generation: u64,
    device_id: String,
    command_id: String,
) {
    thread::spawn(move || {
        let deadline = Instant::now() + OUTCOME_RECONCILE_TIMEOUT;
        loop {
            if !client.is_current(generation) {
                return;
            }
            let (snapshot, current_generation) = client.snapshot();
            if current_generation != generation {
                return;
            }
            if let Ok(response) = snapshot.command_outcome(&device_id, &command_id) {
                if response.outcome.is_terminal() {
                    let device_state = snapshot.device(&device_id);
                    show_reconciled_outcome(&weak, &client, generation, response, device_state);
                    return;
                }
            }
            if Instant::now() >= deadline {
                let weak = weak.clone();
                let client = Arc::clone(&client);
                let message = format!(
                    "Command {command_id}: terminal outcome was not reconciled; query its existing ID. The command was not retried."
                );
                let _ = slint::invoke_from_event_loop(move || {
                    if client.is_current(generation) {
                        if let Some(window) = weak.upgrade() {
                            window.set_status(message.into());
                        }
                    }
                });
                return;
            }
            thread::sleep(OUTCOME_RECONCILE_INTERVAL);
        }
    });
}

fn show_reconciled_outcome(
    weak: &Weak<ui::MainWindow>,
    client: &SharedApiClient,
    generation: u64,
    response: keyferry::api::CommandResponse,
    device_state: Result<DeviceView, ApiError>,
) {
    let mut message = format!(
        "Command {}: {} — terminal outcome confirmed by read-only lookup; not retried.",
        response.command_id,
        outcome_label(response.outcome)
    );
    if let Err(error) = &device_state {
        message.push_str(&format!(" Current device state is unavailable: {error}"));
    }
    let weak = weak.clone();
    let client = Arc::clone(client);
    let _ = slint::invoke_from_event_loop(move || {
        if !client.is_current(generation) {
            return;
        }
        if let Some(window) = weak.upgrade() {
            match device_state {
                Ok(device) => update_device_view(&window, &device),
                Err(_) => clear_control_state(&window),
            }
            window.set_status(message.into());
        }
    });
}

fn set_status(weak: &Weak<ui::MainWindow>, message: &str) {
    let message = message.to_owned();
    let weak = weak.clone();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(window) = weak.upgrade() {
            window.set_status(message.into());
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn switching_devices_clears_private_controls_but_preserves_app_setup() {
        slint::platform::set_platform(Box::new(i_slint_backend_testing::TestingBackend::new(
            i_slint_backend_testing::TestingBackendOptions::default(),
        )))
        .expect("testing backend");
        let window = ui::MainWindow::new().expect("device window");
        window.set_local_recovery_password("test-secret".into());
        window.set_local_recovery_confirming(true);
        window.set_local_recovery_confirm_device_id("previous-device".into());
        window.set_local_recovery_status("previous-device result".into());
        window.set_wifi_owner_password("test-owner-secret".into());
        window.set_wifi_password("test-network-secret".into());
        window.set_wifi_ssid("previous-network".into());
        window.set_wifi_policy_loaded(true);
        window.set_wifi_policy_dirty(true);
        window.set_selected_wifi_profile(0);
        window.set_wifi_profile_items(ModelRc::new(VecModel::from(vec![ui::WifiProfileItem {
            index: 0,
            title: "previous-network".into(),
            subtitle: "".into(),
        }])));
        window.set_second_device_status("New device prepared".into());
        window.set_usb_pending_files(ModelRc::new(VecModel::from(vec![ui::UsbFileItem {
            name: "OLD.TXT".into(),
            path: "private-path".into(),
            size: 3,
        }])));
        window.set_usb_pending_total(3);
        window.set_usb_published_known(true);

        clear_device_specific_state(&window);

        assert!(window.get_local_recovery_password().is_empty());
        assert!(!window.get_local_recovery_confirming());
        assert!(window.get_local_recovery_confirm_device_id().is_empty());
        assert!(!window
            .get_local_recovery_status()
            .contains("previous-device"));
        assert!(window.get_wifi_owner_password().is_empty());
        assert!(window.get_wifi_password().is_empty());
        assert!(window.get_wifi_ssid().is_empty());
        assert!(!window.get_wifi_policy_loaded());
        assert!(!window.get_wifi_policy_dirty());
        assert_eq!(window.get_selected_wifi_profile(), -1);
        assert_eq!(window.get_wifi_profile_items().row_count(), 0);
        assert_eq!(window.get_second_device_status(), "New device prepared");
        assert_eq!(window.get_usb_pending_files().row_count(), 0);
        assert_eq!(window.get_usb_pending_total(), 0);
        assert!(!window.get_usb_published_known());

        window.set_selected_device_id("device-a".into());
        let mut screen = ScreenPowerStatus {
            schema: "keyferry.screen-power.v1".into(),
            device_id: "device-a".into(),
            active: ScreenPower::On,
            stored: ScreenPower::Off,
            available: true,
        };
        apply_screen_power_status(&window, &screen);
        assert!(window.get_screen_power_known());
        assert!(window.get_screen_power_pending());
        assert!(
            window.get_screen_power_on(),
            "saved off is not yet active off"
        );
        screen.active = ScreenPower::Off;
        apply_screen_power_status(&window, &screen);
        assert!(!window.get_screen_power_pending());
        assert!(!window.get_screen_power_on());
        screen.available = false;
        apply_screen_power_status(&window, &screen);
        assert!(!window.get_screen_power_known());
        assert!(window.get_screen_power_status().contains("unavailable"));
        window.set_selected_device_id("device-b".into());
        clear_control_state(&window);
        screen.available = true;
        apply_screen_power_status(&window, &screen);
        assert!(
            !window.get_screen_power_known(),
            "old device cannot repaint the new one"
        );
    }

    #[test]
    fn text_file_result_status_emitted_is_not_delivery() {
        let result = TextFileResult {
            job_id: "019d1234-5678-7abc-8123-456789abcdef".to_owned(),
            outcome: CommandOutcome::Emitted,
            confirmed_bytes: 25_985,
            total_bytes: 25_985,
            possible_start: true,
            terminal_zero_confirmed: true,
        };

        assert_eq!(
            text_file_result_status(&result),
            "USB emission completed for 25985 source bytes; keyboard release confirmed. Target text not verified."
        );
    }

    #[test]
    fn device_refresh_requires_manual_request_or_stale_reactivation() {
        let initial = Instant::now();
        let clock = Arc::new(Mutex::new(initial));

        assert!(!claim_stale_activation_refresh(
            &clock,
            initial + GATEWAY_REFRESH_STALE_AFTER - Duration::from_millis(1)
        ));
        assert!(claim_stale_activation_refresh(
            &clock,
            initial + GATEWAY_REFRESH_STALE_AFTER
        ));
        assert!(!claim_stale_activation_refresh(
            &clock,
            initial + GATEWAY_REFRESH_STALE_AFTER + Duration::from_secs(1)
        ));

        let manual = initial + Duration::from_secs(9 * 60);
        mark_refresh_requested(&clock, manual);
        assert!(!claim_stale_activation_refresh(
            &clock,
            manual + Duration::from_secs(4 * 60)
        ));
    }

    #[test]
    fn owner_ui_is_compiled_with_an_explicit_dark_style() {
        let build_script = include_str!("../build.rs");
        let main_source = include_str!("main.rs");
        let ui = include_str!("../ui/main.slint");

        assert!(main_source
            .starts_with("#![cfg_attr(target_os = \"windows\", windows_subsystem = \"windows\")]"));
        assert!(build_script.contains("with_style(\"fluent-dark\".into())"));
        assert!(ui.contains("Palette.color-scheme = ColorScheme.dark"));
        assert!(ui.contains("app-background: #07090c"));
        assert!(ui.contains("text-primary: #e6edf3"));
        assert!(ui.contains("preferred-width: 980px"));
        assert!(ui.contains("preferred-height: 660px"));
        assert!(!ui.contains("\n    width: 980px;"));
        assert!(!ui.contains("\n    height: 660px;"));
        assert!(ui.contains("\"Keyferry — \" + root.active-endpoint"));
        assert!(ui.contains("keyferry-128.png"));
        assert!(ui.contains("@keys(Escape)"));
        assert!(ui.contains(
            "property <bool> text-ready-to-send: root.can-submit && root.text-send-enabled && !root.text-file-busy"
        ));
        assert!(ui.contains(
            "root.page == 0 && (root.file-mode ? root.file-ready-to-send : root.text-ready-to-send)"
        ));
        assert!(ui.contains("\"Type text instead\" : \"Send a file…\""));
        assert!(ui.contains("text <=> root.text-file-path"));
        assert!(ui.contains("label: \"Load path\""));
        assert!(ui.contains("label: \"Choose file\""));
        assert!(ui.contains("label: root.file-mode ? \"Type file contents\" : \"Send\""));
        assert!(ui.contains("label: \"Cancel stream\""));
        assert!(ui.contains(
            "enabled: root.text-file-cancellable || root.can-cancel || root.can-release-input"
        ));
        assert!(ui.contains("root.text-file-cancellable"));
        assert!(main_source.contains("run_text_file("));
        assert!(main_source.contains("run_text_value("));
        assert!(ui.contains("KeyBinding"));
        assert!(ui.contains("@keys(Control + Digit1)"));
        assert!(ui.contains("shortcut.to-string()"));
        assert!(ui.contains("component AppButton inherits FocusScope"));
        assert!(ui.contains("focus-on-tab-navigation: true"));
        assert!(ui.contains("@keys(Return)"));
        assert!(ui.contains("@keys(Space)"));
        assert!(ui.contains("callback change-owner-password()"));
        assert!(ui.contains("input-type: InputType.password"));
        assert!(ui.contains("Changes only the encrypted owner-kit file"));
        assert!(ui.contains("Online via \" + root.route-via + \" over tailnet"));
        assert!(ui.contains(
            "root.page == 4 && root.selected-device-id != \"\" && root.route-is-tailnet"
        ));
        assert!(!ui.contains("callback select-gateway"));
        assert!(ui.contains("Firmware updates are unavailable in Keyferry v1"));
        assert!(!ui.contains("callback update-firmware"));
        assert!(ui.contains("callback set-output-mode(string)"));
        assert!(ui.contains("callback set-local-output-mode(string)"));
        assert!(ui.contains("label: \"USB keyboard\""));
        assert!(ui.contains("label: \"Bluetooth keyboard\""));
        assert!(ui.contains("root.set-local-output-mode(\"usb-hid\")"));
        assert!(ui.contains("root.set-local-output-mode(\"ble-hid\")"));
        assert!(ui.contains("the same buttons use the connected USB cable"));
        assert!(ui.contains("active-link: \"Control offline\""));
        assert!(ui.contains("callback reset-ble-hid-bond()"));
        assert!(ui.contains("Forget Bluetooth keyboard…"));
        assert!(ui.contains("Confirm forget and restart"));
        assert!(ui.contains("Wi-Fi, ownership, and recovery data are preserved"));
        assert!(ui.contains("callback send-sequence()"));
        assert!(ui.contains("callback sequence-changed(string)"));
        assert!(ui.contains("callback add-sequence-action()"));
        assert!(ui.contains("model: [\"Keys in order\", \"Keys together\", \"Text\", \"Wait\"]"));
        assert!(ui.contains("callback send-hotkey()"));
        assert!(ui.contains(
            "property <bool> hotkey-ready-to-send: root.can-submit && root.hotkey-valid && !root.text-file-busy"
        ));
        assert!(ui.contains("ADD VALIDATED ACTION"));
        assert!(ui.contains("root.page == 1 && root.can-submit && root.sequence-valid"));
        assert!(ui.contains("Reset example"));
        assert!(ui.contains("in-out property <bool> diagnostics-enabled: false"));
        assert!(ui.contains("callback toggle-diagnostics()"));
        assert!(ui.contains("Command history is off."));
        assert!(ui.contains("Stop on unsupported"));
        assert!(ui.contains("Replace with ?"));
    }

    #[test]
    fn provisioning_controls_require_complete_local_inputs() {
        let ui = include_str!("../ui/main.slint");

        for title in [
            "Send",
            "Sequences",
            "Devices",
            "Typing",
            "Setup & security",
            "Diagnostics",
        ] {
            assert!(ui.contains(&format!("title: \"{title}\"")));
        }
        assert!(ui.contains("root.endpoint-is-local"));
        assert!(ui.contains("root.selected-device-id != \"\""));
        assert!(ui.contains("root.wifi-password != \"\""));
        assert!(ui.contains("root.wifi-policy-loaded"));
        assert!(ui.contains("root.wifi-policy-dirty"));
        assert!(ui.contains("callback load-wifi-policy()"));
        assert!(ui.contains("callback move-wifi-profile(int)"));
        assert!(ui.contains("callback recover-initial-wifi-policy()"));
        assert!(ui.contains("Apply policy by USB"));
        assert!(ui.contains("Recover initial policy by USB"));
        assert!(ui.contains("root.new-owner-password == root.confirm-owner-password"));
        assert!(ui.contains("!root.provisioning-busy"));
        assert_eq!(ui.matches("text <=> root.pairing-bundle").count(), 1);
        assert!(!include_str!("provisioning.rs").contains("replace_wifi"));
        assert!(ui.contains("callback refresh-local-status()"));
        assert!(ui.contains("callback run-local-recovery(string)"));
        assert!(ui.contains("callback prepare-second-device()"));
        assert!(ui.contains("label: \"Check USB status\""));
        assert!(ui.contains("title: \"USB maintenance · \" + root.selected-device"));
        assert!(ui.contains("\"Prepare second Keyferry\""));
        assert!(include_str!("main.rs").contains("prepare_second_device("));
    }

    #[test]
    fn text_send_options_are_small_bounded_and_compile_into_the_sequence() {
        let (timing, delay_seconds) = parse_text_options("25", "3").unwrap();
        assert_eq!(timing.key_down_ms, 12);
        assert_eq!(timing.release_gap_ms, 25);
        assert_eq!(delay_seconds, 3);
        assert!(parse_text_options("4", "0").is_err());
        assert!(parse_text_options("8", "11").is_err());

        let request = ui_sequence_with_timing(
            "windows-us".to_owned(),
            vec![
                SequenceAction::Wait { ms: 3000 },
                SequenceAction::Text {
                    value: "safe".to_owned(),
                    timing: None,
                },
            ],
            timing,
        )
        .unwrap();
        let compiled = compile_sequence(&request).unwrap();
        assert_eq!(compiled.planned_ms, 3148);

        let ui = include_str!("../ui/main.slint");
        assert!(ui.contains("Between keys"));
        assert!(ui.contains("Send after"));
        assert!(ui.contains("text-key-gap-ms: \"40\""));
    }

    #[test]
    fn only_nonterminal_command_responses_start_read_only_reconciliation() {
        let response = |outcome| keyferry::api::CommandResponse {
            command_id: "command-1".to_owned(),
            device_id: "device-1".to_owned(),
            outcome,
            message: None,
        };
        let queued = Ok(response(CommandOutcome::Queued));
        assert_eq!(
            reconciliation_target(&queued),
            Some(("device-1".to_owned(), "command-1".to_owned()))
        );
        for outcome in [
            CommandOutcome::Emitted,
            CommandOutcome::Aborted,
            CommandOutcome::Rejected,
            CommandOutcome::Unknown,
        ] {
            assert_eq!(reconciliation_target(&Ok(response(outcome))), None);
        }
    }

    #[test]
    fn control_availability_requires_fresh_authenticated_command_state() {
        let mut device = DeviceView {
            id: "device-1".to_owned(),
            label: "Keyferry".to_owned(),
            transport: "tls".to_owned(),
            link_path: Some("wifi".to_owned()),
            via: None,
            link: "authenticated".to_owned(),
            usb: None,
            mode: "keyboard".to_owned(),
            armed: false,
            maintenance: false,
            arm_policy: "command-scoped".to_owned(),
            active_host: None,
            firmware: Some(keyferry::api::FirmwareView {
                endpoint: "test".to_owned(),
                ble_hid_output_v1: false,
                ble_hid_bond_reset_v1: false,
                targeted_gateway_transfer_v1: true,
                display_orientation_v1: false,
                screen_power_v1: false,
                usb_file_handoff_v1: false,
                usb_file_set_v2: false,
            }),
            capabilities: Vec::new(),
            active_command_id: None,
            active_outcome: None,
        };

        let disarmed = control_availability(Some(&device));
        assert!(
            !supports_screen_power(&device),
            "older firmware has no screen control"
        );
        device.firmware.as_mut().unwrap().screen_power_v1 = true;
        assert!(supports_screen_power(&device));
        device.link_path = Some("tailnet".into());
        assert!(!supports_screen_power(&device));
        device.link_path = Some("wifi".into());
        assert!(disarmed.can_submit);
        assert!(!disarmed.can_release_input);
        assert_eq!(disarmed.status, "Ready to send.");
        assert_eq!(device_row_subtitle(&device), "device-1 · Wi-Fi · Ready");

        device.armed = true;
        let armed = control_availability(Some(&device));
        assert!(armed.can_submit);
        assert!(armed.can_release_input);
        assert_eq!(armed.status, disarmed.status);

        device.active_command_id = Some("command-1".to_owned());
        let active = control_availability(Some(&device));
        assert!(active.can_cancel);
        assert!(!active.can_release_input);
        assert!(!active.can_submit);
        assert_eq!(device_row_subtitle(&device), "device-1 · Wi-Fi · Busy");

        device.active_command_id = None;
        device.maintenance = true;
        assert!(!control_availability(Some(&device)).can_submit);
        device.maintenance = false;
        device.mode = "maintenance".to_owned();
        assert!(!control_availability(Some(&device)).can_submit);
        device.mode = "keyboard".to_owned();
        device.link = "offline".to_owned();
        assert!(!supports_screen_power(&device));
        let offline = control_availability(Some(&device));
        assert!(!offline.can_cancel);
        assert!(!offline.can_release_input);
        assert!(!offline.can_submit);
        assert_eq!(
            device_row_subtitle(&device),
            "device-1 · Wi-Fi · Unavailable"
        );
    }

    #[test]
    fn stale_device_response_cannot_repaint_another_selection() {
        let selected = Arc::new(Mutex::new(Some("device-a".to_owned())));
        assert!(selected_device_matches(&selected, "device-a"));
        *selected.lock().unwrap() = Some("device-b".to_owned());
        assert!(!selected_device_matches(&selected, "device-a"));
        assert!(selected_device_matches(&selected, "device-b"));
    }

    #[test]
    fn authenticated_mutation_response_never_downgrades_the_link_badge_to_offline() {
        let mut device = DeviceView {
            id: "device-1".to_owned(),
            label: "Keyferry".to_owned(),
            transport: "tls".to_owned(),
            link_path: Some("offline".to_owned()),
            via: None,
            link: "authenticated".to_owned(),
            usb: None,
            mode: "keyboard".to_owned(),
            armed: true,
            maintenance: false,
            arm_policy: "temporary".to_owned(),
            active_host: None,
            firmware: None,
            capabilities: Vec::new(),
            active_command_id: None,
            active_outcome: None,
        };

        assert_eq!(active_link_label(&device, "Wi-Fi"), "Wi-Fi");
        assert_eq!(active_link_label(&device, "Control offline"), "Connected");
        device.link_path = Some("via controller-b".to_owned());
        assert_eq!(active_link_label(&device, "Wi-Fi"), "via controller-b");
        device.link_path = Some("wifi".to_owned());
        assert_eq!(active_link_label(&device, "Control offline"), "Wi-Fi");
        device.link = "offline".to_owned();
        assert_eq!(active_link_label(&device, "Wi-Fi"), "Control offline");
        assert_eq!(display_link_path("via\u{1b}[2J b"), "via[2J b");
    }

    #[test]
    fn device_watch_polls_fast_then_backs_off_and_keeps_connected_route_fresh() {
        assert_eq!(
            device_watch_interval(Some(Duration::from_secs(0))),
            DEVICE_WATCH_FAST_INTERVAL
        );
        assert_eq!(
            device_watch_interval(Some(Duration::from_secs(119))),
            DEVICE_WATCH_FAST_INTERVAL
        );
        assert_eq!(
            device_watch_interval(Some(Duration::from_secs(120))),
            DEVICE_WATCH_SLOW_INTERVAL
        );
        assert_eq!(device_watch_interval(None), DEVICE_WATCH_CONNECTED_INTERVAL);
        assert_eq!(DEVICE_WATCH_FAST_INTERVAL, Duration::from_secs(3));
        assert_eq!(DEVICE_WATCH_SLOW_INTERVAL, Duration::from_secs(15));
        assert_eq!(DEVICE_WATCH_CONNECTED_INTERVAL, Duration::from_secs(10));

        note_device_connected(false);
        let first = DEVICE_OFFLINE_SINCE.lock().unwrap().expect("watching");
        note_device_connected(false);
        assert_eq!(*DEVICE_OFFLINE_SINCE.lock().unwrap(), Some(first));
        note_device_connected(true);
        assert_eq!(*DEVICE_OFFLINE_SINCE.lock().unwrap(), None);
        let source = include_str!("main.rs");
        let watch = source
            .split("fn start_device_watch(")
            .nth(1)
            .and_then(|rest| rest.split("\nfn ").next())
            .expect("device watch source");
        assert!(!watch.contains("refresh_tailnet_candidates"));
        assert!(watch.contains("start_device_refresh(weak, client, selected_device, false)"));
    }

    #[test]
    fn ui_sequences_auto_arm_or_use_an_existing_explicit_arm_and_clear_payloads() {
        let mut request = ui_sequence(
            "windows-us".to_owned(),
            vec![SequenceAction::Text {
                value: "private password".to_owned(),
                timing: None,
            }],
        )
        .unwrap();
        assert_eq!(request.arm, SequenceArmPolicy::CommandScoped);

        let mut device = DeviceView {
            id: "device-1".to_owned(),
            label: "Keyferry".to_owned(),
            transport: "tls".to_owned(),
            link_path: Some("bluetooth".to_owned()),
            via: None,
            link: "authenticated".to_owned(),
            usb: None,
            mode: "keyboard".to_owned(),
            armed: true,
            maintenance: false,
            arm_policy: "temporary".to_owned(),
            active_host: None,
            firmware: None,
            capabilities: Vec::new(),
            active_command_id: None,
            active_outcome: None,
        };
        use_existing_arm_if_needed(&mut request, &device);
        assert_eq!(request.arm, SequenceArmPolicy::RequireExisting);
        clear_sequence_payload(&mut request);
        let SequenceAction::Text { value, .. } = &request.actions[0] else {
            panic!("expected text action")
        };
        assert!(value.is_empty());

        device.armed = false;
        let mut next = ui_sequence(
            "windows-us".to_owned(),
            vec![SequenceAction::Tap {
                key: "ENTER".to_owned(),
                timing: None,
            }],
        )
        .unwrap();
        use_existing_arm_if_needed(&mut next, &device);
        assert_eq!(next.arm, SequenceArmPolicy::CommandScoped);
    }

    #[test]
    fn diagnostics_distinguish_emitted_from_unknown_without_payload_text() {
        let mut event = EventRecord {
            command_id: "command-1".to_owned(),
            caller: "local".to_owned(),
            device_id: "device-1".to_owned(),
            profile: "windows-us".to_owned(),
            action_count: 1,
            char_count: 18,
            timestamp: "2026-09-13T00:00:00Z".to_owned(),
            duration_ms: Some(10),
            outcome: CommandOutcome::Emitted,
        };
        let payload = "private dictated payload";
        let emitted = diagnostic_item(&event);
        assert!(emitted.summary.contains("EMITTED"));
        assert!(emitted
            .explanation
            .contains("target application is not observable"));
        assert!(!emitted.summary.contains(payload));
        assert_eq!(emitted.tone, 2);

        event.outcome = CommandOutcome::Unknown;
        let unknown = diagnostic_item(&event);
        assert!(unknown.summary.contains("UNKNOWN"));
        assert!(unknown.explanation.contains("do not assume delivery"));
        assert_eq!(unknown.tone, 3);
    }

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn device_summary_leads_with_path_without_placeholder_noise() {
        let mut device = DeviceView {
            id: "01234567-89ab-4cde-8fab-0123456789ab".to_owned(),
            label: "Paired keyboard".to_owned(),
            transport: "tls".to_owned(),
            link_path: Some("bluetooth".to_owned()),
            via: None,
            link: "authenticated".to_owned(),
            usb: None,
            mode: "keyboard".to_owned(),
            armed: false,
            maintenance: false,
            arm_policy: "command-scoped".to_owned(),
            active_host: None,
            firmware: None,
            capabilities: Vec::new(),
            active_command_id: None,
            active_outcome: None,
        };
        let summary = render_device_details(&device);
        assert!(summary.starts_with("Control route: Bluetooth\n"));
        assert!(!summary.contains("not reported"));
        assert_eq!(short_device_id(&device.id), "01234567");
        assert_eq!(device_row_subtitle(&device), "01234567 · Bluetooth · Ready");
        assert!(nearby_gateway_status(Some(&device)).contains("Bluetooth fallback"));

        device.link_path = Some("wifi".to_owned());
        assert!(nearby_gateway_status(Some(&device)).contains("preferred Wi-Fi"));
        device.link = "offline".to_owned();
        assert!(nearby_gateway_status(Some(&device)).contains("Wi-Fi is tried first"));
        assert!(nearby_gateway_status(None).contains("Wi-Fi is tried first"));
        device.link = "authenticated".to_owned();
        device.link_path = Some("tailnet".to_owned());
        device.via = Some("controller-b".to_owned());
        assert_eq!(device_route_label(&device), "Tailnet via controller-b");
        assert!(nearby_gateway_status(Some(&device)).contains("controller-b"));
        device.via = Some("controller-c".to_owned());
        assert_eq!(device_route_label(&device), "Tailnet via controller-c");
        device.link_path = Some("wifi".to_owned());
        device.via = None;
        assert_eq!(device_route_label(&device), "Wi-Fi");
    }

    #[test]
    fn refresh_never_falls_back_from_an_explicit_physical_device() {
        let device = DeviceView {
            id: "11111111-1111-4111-8111-111111111111".to_owned(),
            label: "First".to_owned(),
            transport: "tls".to_owned(),
            link_path: Some("wifi".to_owned()),
            via: None,
            link: "authenticated".to_owned(),
            usb: None,
            mode: "keyboard".to_owned(),
            armed: false,
            maintenance: false,
            arm_policy: "command-scoped".to_owned(),
            active_host: None,
            firmware: None,
            capabilities: Vec::new(),
            active_command_id: None,
            active_outcome: None,
        };
        let available = vec![device];
        assert_eq!(
            retain_or_choose_device(None, &available).as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(
            retain_or_choose_device(
                Some("22222222-2222-4222-8222-222222222222".to_owned()),
                &available,
            )
            .as_deref(),
            Some("22222222-2222-4222-8222-222222222222")
        );
        assert_eq!(
            offline_device_item("22222222-2222-4222-8222-222222222222")
                .subtitle
                .as_str(),
            "22222222 · Offline · Pinned selection"
        );
    }

    #[test]
    fn endpoint_generation_rejects_stale_switches_and_results() {
        let local = ApiClient::new(
            keyferry::api::Endpoint::from_url("http://127.0.0.1:8042").unwrap(),
            "local-token",
        )
        .unwrap();
        let replacement = ApiClient::new(
            keyferry::api::Endpoint::from_url("http://127.0.0.1:8043").unwrap(),
            "replacement-token",
        )
        .unwrap();
        let stale = replacement.clone();
        let active = ActiveApiClient::new(local, "Local daemon");
        let (_, generation) = active.snapshot();

        assert!(active.replace_if_current(generation, replacement, "Selected gateway"));
        assert!(!active.is_current(generation));
        assert_eq!(active.label(), "Selected gateway");
        assert!(!active.replace_if_current(generation, stale, "Stale gateway"));
        assert_eq!(active.label(), "Selected gateway");
    }

    #[test]
    fn queued_mutation_is_dropped_if_a_switch_wins_the_gate() {
        let first = ApiClient::new(
            keyferry::api::Endpoint::from_url("http://127.0.0.1:8042").unwrap(),
            "first-token",
        )
        .unwrap();
        let second = ApiClient::new(
            keyferry::api::Endpoint::from_url("http://127.0.0.1:8043").unwrap(),
            "second-token",
        )
        .unwrap();
        let active = Arc::new(ActiveApiClient::new(first, "First"));
        let expected_generation = active.snapshot().1;
        let gate = active.lock_mutations();
        let calls = Arc::new(AtomicUsize::new(0));
        let worker = {
            let active = Arc::clone(&active);
            let calls = Arc::clone(&calls);
            thread::spawn(move || {
                active.run_mutation(expected_generation, |_| {
                    calls.fetch_add(1, AtomicOrdering::AcqRel);
                })
            })
        };
        assert!(active.replace_if_current(expected_generation, second, "Second"));
        drop(gate);

        assert!(worker.join().unwrap().is_none());
        assert_eq!(calls.load(AtomicOrdering::Acquire), 0);
        assert_eq!(active.label(), "Second");
    }

    #[test]
    fn ended_current_event_stream_backs_off_but_a_stale_stream_resnapshots_now() {
        assert_eq!(event_reconnect_delay(true), Some(EVENT_RECONNECT_BACKOFF));
        assert_eq!(event_reconnect_delay(false), None);
    }

    #[test]
    fn usb_file_preview_checks_names_duplicates_and_shared_limit_without_reading_contents() {
        let dir = std::env::temp_dir().join(format!(
            "keyferry-usb-preview-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let first = dir.join("Notes.txt");
        let second = dir.join("empty.JSON");
        std::fs::write(&first, b"abc").unwrap();
        std::fs::write(&second, b"").unwrap();
        let items = preview_usb_files(&[first.clone(), second.clone()]).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].size, 3);
        assert_eq!(items[1].size, 0);

        let other = dir.join("other");
        std::fs::create_dir(&other).unwrap();
        let duplicate = other.join("NOTES.TXT");
        std::fs::write(&duplicate, b"other").unwrap();
        assert!(preview_usb_files(&[first.clone(), duplicate.clone()]).is_err());
        let reserved = dir.join("CON.txt");
        assert!(preview_usb_files(&[reserved])
            .unwrap_err()
            .contains("reserved Windows names"));
        let oversized = dir.join("large.bin");
        std::fs::write(
            &oversized,
            vec![0; keyferry_protocol::file_set::MAX_FILE_BYTES],
        )
        .unwrap();
        assert!(preview_usb_files(&[first.clone(), oversized.clone()]).is_err());

        for path in [first, second, duplicate, oversized] {
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(other).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
