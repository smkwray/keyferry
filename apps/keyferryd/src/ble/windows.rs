use std::{
    collections::HashSet,
    future::Future,
    future::IntoFuture,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use futures_util::{stream::FuturesUnordered, StreamExt};
use keyferry_protocol::ble_transport::{
    AUTHENTICATION_TIMEOUT_MS, DEVICE_TO_GATEWAY_UUID, GATEWAY_TO_DEVICE_UUID,
    OPERATION_TIMEOUT_MS, PROGRESS_TIMEOUT_MS, SERVICE_UUID,
};
use tokio::{
    io::duplex,
    sync::{mpsc, watch},
    time::{self, Instant},
};
use windows::{
    core::{IInspectable, GUID, HRESULT},
    Devices::{
        Bluetooth::{
            Advertisement::{
                BluetoothLEAdvertisementFilter, BluetoothLEAdvertisementReceivedEventArgs,
                BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementWatcherStoppedEventArgs,
                BluetoothLEScanningMode,
            },
            BluetoothAddressType, BluetoothCacheMode, BluetoothConnectionStatus, BluetoothLEDevice,
            GenericAttributeProfile::{
                GattCharacteristic, GattCharacteristicProperties,
                GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
                GattDeviceService, GattValueChangedEventArgs, GattWriteOption,
            },
        },
        Enumeration::DeviceAccessStatus,
    },
    Foundation::TypedEventHandler,
    Storage::Streams::{DataReader, DataWriter, IBuffer},
};
use windows_future::{AsyncStatus, IAsyncOperation};

use super::{
    pipe::{BytePump, GattChannels, OutboundFragment, WriteAck, MAX_PENDING_BYTES},
    BleGatewayError,
};

const RETRY_DELAY: Duration = Duration::from_secs(1);
const DUPLEX_BYTES: usize = MAX_PENDING_BYTES;
const FAULT_CHANNEL_SLOTS: usize = 1;
const SCAN_CHANNEL_SLOTS: usize = 16;
const PRE_CCCD_TIMEOUT: Duration = Duration::from_secs(18);
static DIAGNOSTICS_ENABLED: AtomicBool = AtomicBool::new(false);
type CandidateFuture = Pin<Box<dyn Future<Output = (u64, Result<(), BleGatewayError>)>>>;

fn retry_allowed(single_shot: bool) -> bool {
    !single_shot
}

pub(super) async fn run(
    transport: crate::TlsTransport,
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    DIAGNOSTICS_ENABLED.store(single_shot, Ordering::Release);
    let current_generation = Arc::new(AtomicU64::new(0));

    loop {
        // During a gateway-yield lease, do not compete with the receiving
        // computer for the same BLE advertisement. The current authenticated
        // stream is closed by begin_maintenance(); this gate prevents the
        // retry loop from immediately reacquiring the stick.
        if !super::gateway_acquisition_enabled(&transport) {
            time::sleep(RETRY_DELAY).await;
            continue;
        }
        let candidate = match scan_for_candidate().await {
            Ok(candidate) => candidate,
            Err(error) => {
                // Adapter disable/enable and watcher aborts are recoverable.
                // Retry without terminating the daemon or exposing a device ID.
                eprintln!("Bluetooth scan unavailable: {error}");
                if !retry_allowed(single_shot) {
                    return Err(error);
                }
                time::sleep(RETRY_DELAY).await;
                continue;
            }
        };
        let generation = current_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let result = run_candidate(
            CandidateAdmission::Single(transport.clone()),
            candidate,
            generation,
            Arc::clone(&current_generation),
        )
        .await;

        // Invalidate callbacks before any subsequent scan can begin. A late
        // WinRT event from the old connection must not enter the next stream.
        current_generation.fetch_add(1, Ordering::AcqRel);
        if let Err(ref error) = result {
            // Errors contain only fixed stage names and numeric GATT status;
            // neither characteristic values nor device identifiers are logged.
            eprintln!("Bluetooth candidate closed: {error}");
        }
        if !retry_allowed(single_shot) {
            return result;
        }
        time::sleep(RETRY_DELAY).await;
    }
}

pub(super) async fn run_multi(
    router: crate::MultiTlsRouter,
    transports: Vec<crate::TlsTransport>,
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    if transports.is_empty() {
        return Err(runtime("multi-device Bluetooth gateway has no transports"));
    }
    DIAGNOSTICS_ENABLED.store(single_shot, Ordering::Release);
    loop {
        let result = run_multi_scan_session(router.clone(), &transports, single_shot).await;
        if let Err(ref error) = result {
            eprintln!("Bluetooth scan unavailable: {error}");
        }
        if !retry_allowed(single_shot) {
            return result;
        }
        time::sleep(RETRY_DELAY).await;
    }
}

async fn run_multi_scan_session(
    router: crate::MultiTlsRouter,
    transports: &[crate::TlsTransport],
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    let (_registration, mut event_receiver) = start_watcher()?;
    let mut active_addresses = HashSet::with_capacity(transports.len());
    let mut candidates: FuturesUnordered<CandidateFuture> = FuturesUnordered::new();

    loop {
        tokio::select! {
            event = event_receiver.recv() => match event {
                Some(ScanEvent::Candidate(candidate)) => {
                    if active_addresses.len() >= transports.len()
                        || active_addresses.contains(&candidate.address)
                        || !transports.iter().any(super::gateway_acquisition_enabled)
                    {
                        continue;
                    }
                    active_addresses.insert(candidate.address);
                    let candidate_router = router.clone();
                    candidates.push(Box::pin(async move {
                        let generation = Arc::new(AtomicU64::new(1));
                        let result = run_candidate(
                            CandidateAdmission::Multi(candidate_router),
                            candidate,
                            1,
                            Arc::clone(&generation),
                        )
                        .await;
                        generation.fetch_add(1, Ordering::AcqRel);
                        (candidate.address, result)
                    }));
                }
                Some(ScanEvent::Stopped) | None => {
                    return Err(runtime("advertisement watcher stopped"));
                }
            },
            completed = candidates.next(), if !candidates.is_empty() => {
                let Some(completed) = completed else {
                    return Err(runtime("Bluetooth candidate task set stopped"));
                };
                let (address, result) = completed;
                active_addresses.remove(&address);
                if let Err(ref error) = result {
                    eprintln!("Bluetooth candidate closed: {error}");
                }
                if single_shot {
                    return result;
                }
            }
        }
    }
}

async fn scan_for_candidate() -> Result<ScanCandidate, BleGatewayError> {
    let (_registration, mut event_receiver) = start_watcher()?;
    match event_receiver.recv().await {
        Some(ScanEvent::Candidate(address)) => Ok(address),
        Some(ScanEvent::Stopped) | None => Err(runtime("advertisement watcher stopped")),
    }
}

fn start_watcher() -> Result<(WatcherRegistration, mpsc::Receiver<ScanEvent>), BleGatewayError> {
    let filter = BluetoothLEAdvertisementFilter::new()
        .map_err(|_| runtime("could not create advertisement filter"))?;
    filter
        .Advertisement()
        .and_then(|advertisement| advertisement.ServiceUuids())
        .and_then(|uuids| uuids.Append(service_uuid()))
        .map_err(|_| runtime("could not configure service advertisement filter"))?;

    let watcher = BluetoothLEAdvertisementWatcher::Create(&filter)
        .map_err(|_| runtime("could not create advertisement watcher"))?;
    watcher
        .SetScanningMode(BluetoothLEScanningMode::Active)
        .map_err(|_| runtime("could not configure advertisement watcher"))?;

    let (events, event_receiver) = mpsc::channel(SCAN_CHANNEL_SLOTS);
    let received_events = events.clone();
    let received = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementReceivedEventArgs,
    >::new(move |_, args| {
        if let Some(args) = args.as_ref() {
            if advertisement_matches(args) {
                if let (Ok(address), Ok(address_type)) =
                    (args.BluetoothAddress(), args.BluetoothAddressType())
                {
                    let _ = received_events.try_send(ScanEvent::Candidate(ScanCandidate {
                        address,
                        address_type,
                    }));
                }
            }
        }
        Ok(())
    });
    let received_token = watcher
        .Received(&received)
        .map_err(|_| runtime("could not register advertisement callback"))?;

    let stopped_events = events;
    let stopped = TypedEventHandler::<
        BluetoothLEAdvertisementWatcher,
        BluetoothLEAdvertisementWatcherStoppedEventArgs,
    >::new(move |_, _| {
        let _ = stopped_events.try_send(ScanEvent::Stopped);
        Ok(())
    });
    let stopped_token = watcher
        .Stopped(&stopped)
        .map_err(|_| runtime("could not register advertisement stop callback"))?;
    let registration = WatcherRegistration {
        watcher,
        received_token,
        stopped_token,
    };
    registration
        .watcher
        .Start()
        .map_err(|_| runtime("could not start advertisement watcher"))?;
    Ok((registration, event_receiver))
}

fn advertisement_matches(args: &BluetoothLEAdvertisementReceivedEventArgs) -> bool {
    if !args.IsConnectable().unwrap_or(false) {
        return false;
    }
    let Ok(advertisement) = args.Advertisement() else {
        return false;
    };
    let Ok(uuids) = advertisement.ServiceUuids() else {
        return false;
    };
    let Ok(size) = uuids.Size() else {
        return false;
    };
    (0..size).any(|index| uuids.GetAt(index).is_ok_and(|uuid| uuid == service_uuid()))
}

async fn run_candidate(
    admission: CandidateAdmission,
    candidate: ScanCandidate,
    generation: u64,
    current_generation: Arc<AtomicU64>,
) -> Result<(), BleGatewayError> {
    let setup_deadline = Instant::now() + PRE_CCCD_TIMEOUT;
    let mut connection = establish_gatt(
        candidate,
        generation,
        Arc::clone(&current_generation),
        setup_deadline,
    )
    .await?;

    let (pump, channels) = BytePump::new(
        connection.att_mtu,
        Duration::from_millis(OPERATION_TIMEOUT_MS as u64),
    )
    .map_err(|error| runtime(format!("invalid byte-pump configuration: {error}")))?;
    let (daemon_stream, bridge_stream) = duplex(DUPLEX_BYTES);
    let (progress, progress_receiver) = watch::channel(Instant::now());
    connection
        .enable_indications(
            channels.inbound.clone(),
            progress.clone(),
            generation,
            current_generation,
            setup_deadline,
        )
        .await?;
    // CCCD setup can consume most of an operation timeout. Authentication's
    // no-progress clock starts only after the byte path is actually usable.
    progress.send_replace(Instant::now());

    let byte_pump = pump.run(bridge_stream);
    let gatt_driver = drive_gatt(connection, channels, progress);
    let bridge = async {
        tokio::pin!(byte_pump);
        tokio::pin!(gatt_driver);
        tokio::select! {
            result = &mut byte_pump => result
                .map_err(|error| runtime(format!("BLE byte pump stopped: {error}"))),
            result = &mut gatt_driver => result,
        }
    };
    tokio::pin!(bridge);

    let authentication: Pin<Box<dyn Future<Output = Result<(), crate::TlsTransportError>> + Send>> =
        match admission {
            CandidateAdmission::Single(transport) => Box::pin(async move {
                transport
                    .accept_stream_on(daemon_stream, crate::TlsLinkPath::Bluetooth)
                    .await
            }),
            CandidateAdmission::Multi(router) => Box::pin(async move {
                router
                    .accept_stream_on(daemon_stream, crate::TlsLinkPath::Bluetooth)
                    .await
                    .map(|_| ())
            }),
        };
    tokio::pin!(authentication);
    let authentication_deadline =
        Instant::now() + Duration::from_millis(AUTHENTICATION_TIMEOUT_MS as u64);
    await_authentication(
        &mut authentication,
        &mut bridge,
        progress_receiver,
        authentication_deadline,
    )
    .await?;

    bridge.await
}

#[derive(Clone)]
enum CandidateAdmission {
    Single(crate::TlsTransport),
    Multi(crate::MultiTlsRouter),
}

async fn await_authentication<A, B>(
    authentication: &mut std::pin::Pin<&mut A>,
    bridge: &mut std::pin::Pin<&mut B>,
    mut progress: watch::Receiver<Instant>,
    setup_deadline: Instant,
) -> Result<(), BleGatewayError>
where
    A: std::future::Future<Output = Result<(), crate::TlsTransportError>>,
    B: std::future::Future<Output = Result<(), BleGatewayError>>,
{
    let mut last_progress = *progress.borrow_and_update();
    loop {
        let progress_deadline = last_progress + Duration::from_millis(PROGRESS_TIMEOUT_MS as u64);
        tokio::select! {
            result = authentication.as_mut() => {
                return result.map_err(|error| runtime(format!("TLS admission failed: {error}")));
            }
            result = bridge.as_mut() => return result,
            changed = progress.changed() => {
                changed.map_err(|_| runtime("BLE progress monitor closed"))?;
                last_progress = *progress.borrow_and_update();
            }
            _ = time::sleep_until(progress_deadline) => {
                return Err(runtime("candidate made no byte progress"));
            }
            _ = time::sleep_until(setup_deadline) => {
                return Err(runtime("candidate setup deadline expired"));
            }
        }
    }
}

struct GattConnection {
    device: BluetoothLEDevice,
    service: GattDeviceService,
    gateway_to_device: GattCharacteristic,
    device_to_gateway: GattCharacteristic,
    value_changed_token: Option<i64>,
    connection_changed_token: i64,
    att_mtu: u16,
    fault_sender: mpsc::Sender<()>,
    fault_receiver: mpsc::Receiver<()>,
}

struct DeviceLease {
    device: Option<BluetoothLEDevice>,
    connection_changed_token: Option<i64>,
}

impl Drop for DeviceLease {
    fn drop(&mut self) {
        if let Some(token) = self.connection_changed_token.take() {
            if let Some(device) = self.device.as_ref() {
                let _ = device.RemoveConnectionStatusChanged(token);
            }
        }
        if let Some(device) = self.device.take() {
            let _ = device.Close();
            if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
                eprintln!("BLE diagnostic close_reason=device_lease_released");
            }
        }
    }
}

impl Drop for GattConnection {
    fn drop(&mut self) {
        if let Some(token) = self.value_changed_token {
            let _ = self.device_to_gateway.RemoveValueChanged(token);
        }
        let _ = self
            .device
            .RemoveConnectionStatusChanged(self.connection_changed_token);
        let _ = self.service.Close();
        let _ = self.device.Close();
    }
}

async fn establish_gatt(
    candidate: ScanCandidate,
    generation: u64,
    current_generation: Arc<AtomicU64>,
    setup_deadline: Instant,
) -> Result<GattConnection, BleGatewayError> {
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!(
            "BLE diagnostic candidate_address_type={}",
            candidate.address_type.0
        );
    }
    let device_operation = BluetoothLEDevice::FromBluetoothAddressWithBluetoothAddressTypeAsync(
        candidate.address,
        candidate.address_type,
    )
    .map_err(|_| runtime("could not begin BLE connection"))?;
    let device = operation(device_operation, "BLE connection", Some(setup_deadline)).await?;

    let device_access = device
        .DeviceAccessInformation()
        .and_then(|access| access.CurrentStatus())
        .map_err(|_| runtime("could not read Bluetooth device access status"))?;
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!("BLE diagnostic device_access_status={}", device_access.0);
    }
    if device_access != DeviceAccessStatus::Allowed {
        let _ = device.Close();
        return Err(runtime(format!(
            "Bluetooth device access is not allowed (status {})",
            device_access.0
        )));
    }

    let mut lease = DeviceLease {
        device: Some(device),
        connection_changed_token: None,
    };
    let (fault_sender, fault_receiver) = mpsc::channel(FAULT_CHANNEL_SLOTS);
    let connection_faults = fault_sender.clone();
    let connection_generation = Arc::clone(&current_generation);
    let observed_connection = Arc::new(std::sync::atomic::AtomicBool::new(
        lease
            .device
            .as_ref()
            .and_then(|device| device.ConnectionStatus().ok())
            == Some(BluetoothConnectionStatus::Connected),
    ));
    let callback_observed_connection = Arc::clone(&observed_connection);
    let observed_at = Instant::now();
    let connection_changed =
        TypedEventHandler::<BluetoothLEDevice, IInspectable>::new(move |sender, _| {
            if connection_generation.load(Ordering::Acquire) != generation {
                return Ok(());
            }
            let status = sender
                .as_ref()
                .and_then(|device| device.ConnectionStatus().ok())
                .unwrap_or(BluetoothConnectionStatus::Disconnected);
            if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
                eprintln!(
                    "BLE diagnostic t_ms={} connection_status={}",
                    observed_at.elapsed().as_millis(),
                    status.0
                );
            }
            if status == BluetoothConnectionStatus::Connected {
                callback_observed_connection.store(true, Ordering::Release);
            } else if callback_observed_connection.load(Ordering::Acquire) {
                let _ = connection_faults.try_send(());
            }
            Ok(())
        });
    let connection_changed_token = lease
        .device
        .as_ref()
        .expect("device lease")
        .ConnectionStatusChanged(&connection_changed)
        .map_err(|_| runtime("could not register connection callback"))?;
    drop(connection_changed);
    lease.connection_changed_token = Some(connection_changed_token);

    let services_operation = lease
        .device
        .as_ref()
        .expect("device lease")
        .GetGattServicesWithCacheModeAsync(BluetoothCacheMode::Uncached)
        .map_err(|_| runtime("could not begin GATT service discovery"))?;
    let services_result = operation(
        services_operation,
        "GATT service discovery",
        Some(setup_deadline),
    )
    .await?;
    let service_status = services_result
        .Status()
        .map_err(|_| runtime("could not read GATT service status"))?;
    let protocol_error = services_result
        .ProtocolError()
        .ok()
        .and_then(|value| value.Value().ok());
    let services = services_result
        .Services()
        .map_err(|_| runtime("could not read discovered GATT services"))?;
    let service_count = services
        .Size()
        .map_err(|_| runtime("could not count discovered GATT services"))?;
    let mut keyferry_service = None;
    for index in 0..service_count {
        let service = services
            .GetAt(index)
            .map_err(|_| runtime("could not open discovered GATT service"))?;
        if service.Uuid().ok() == Some(service_uuid()) {
            if keyferry_service.is_some() {
                let _ = service.Close();
                return Err(runtime("found duplicate Keyferry GATT services"));
            }
            keyferry_service = Some(service);
        } else {
            let _ = service.Close();
        }
    }
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!(
            "BLE diagnostic gatt_communication_status={} gatt_protocol_error={} service_count={} keyferry_service_count={}",
            service_status.0,
            protocol_error.map_or_else(|| "none".to_owned(), |value| value.to_string()),
            service_count,
            usize::from(keyferry_service.is_some()),
        );
    }
    require_success(service_status, "GATT service discovery")?;
    let service = keyferry_service.ok_or_else(|| runtime("Keyferry GATT service was not found"))?;

    let (gateway_to_device, device_to_gateway) =
        discover_characteristics(&service, setup_deadline).await?;

    let att_mtu = service
        .Session()
        .and_then(|session| session.MaxPduSize())
        .map_err(|_| runtime("could not read negotiated ATT MTU"))?;
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!("BLE diagnostic negotiated_att_mtu={att_mtu}");
    }

    let connection_changed_token = lease
        .connection_changed_token
        .take()
        .expect("registered connection callback");
    let device = lease.device.take().expect("device lease");

    Ok(GattConnection {
        device,
        service,
        gateway_to_device,
        device_to_gateway,
        value_changed_token: None,
        connection_changed_token,
        att_mtu,
        fault_sender,
        fault_receiver,
    })
}

impl GattConnection {
    async fn enable_indications(
        &mut self,
        inbound: super::pipe::InboundSender,
        progress: watch::Sender<Instant>,
        generation: u64,
        current_generation: Arc<AtomicU64>,
        setup_deadline: Instant,
    ) -> Result<(), BleGatewayError> {
        let value_faults = self.fault_sender.clone();
        let value_changed = TypedEventHandler::<GattCharacteristic, GattValueChangedEventArgs>::new(
            move |_, args| {
                if current_generation.load(Ordering::Acquire) != generation {
                    return Ok(());
                }
                let result = args
                    .as_ref()
                    .ok_or(())
                    .and_then(|args| read_buffer(args.CharacteristicValue()).map_err(|_| ()))
                    .and_then(|bytes| {
                        if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
                            eprintln!("BLE diagnostic inbound_fragment_bytes={}", bytes.len());
                        }
                        inbound.try_send(bytes).map_err(|_| ())
                    });
                if result.is_ok() {
                    progress.send_replace(Instant::now());
                } else {
                    let _ = value_faults.try_send(());
                }
                Ok(())
            },
        );
        self.value_changed_token = Some(
            self.device_to_gateway
                .ValueChanged(&value_changed)
                .map_err(|_| runtime("could not register indication callback"))?,
        );
        drop(value_changed);

        let cccd_operation = self
            .device_to_gateway
            .WriteClientCharacteristicConfigurationDescriptorWithResultAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Indicate,
            )
            .map_err(|_| runtime("could not begin indication subscription"))?;
        let cccd_result = operation(
            cccd_operation,
            "indication subscription",
            Some(setup_deadline),
        )
        .await?;
        require_success(
            cccd_result
                .Status()
                .map_err(|_| runtime("could not read indication subscription status"))?,
            "indication subscription",
        )
    }
}

async fn discover_characteristics(
    service: &GattDeviceService,
    setup_deadline: Instant,
) -> Result<(GattCharacteristic, GattCharacteristic), BleGatewayError> {
    let discovery_operation = service
        .GetCharacteristicsWithCacheModeAsync(BluetoothCacheMode::Uncached)
        .map_err(|_| runtime("could not begin characteristic discovery"))?;
    let result = operation(
        discovery_operation,
        "characteristic discovery",
        Some(setup_deadline),
    )
    .await?;
    require_success(
        result
            .Status()
            .map_err(|_| runtime("could not read characteristic discovery status"))?,
        "characteristic discovery",
    )?;
    let characteristics = result
        .Characteristics()
        .map_err(|_| runtime("could not read characteristic results"))?;
    if characteristics
        .Size()
        .map_err(|_| runtime("could not count characteristics"))?
        != 2
    {
        return Err(runtime("expected exactly two Keyferry characteristics"));
    }

    let mut gateway_to_device = None;
    let mut device_to_gateway = None;
    for index in 0..2 {
        let characteristic = characteristics
            .GetAt(index)
            .map_err(|_| runtime("could not open Keyferry characteristic"))?;
        let uuid = characteristic
            .Uuid()
            .map_err(|_| runtime("could not read characteristic UUID"))?;
        let properties = characteristic
            .CharacteristicProperties()
            .map_err(|_| runtime("could not read characteristic properties"))?;
        if uuid == gateway_to_device_uuid() {
            if properties != GattCharacteristicProperties::Write || gateway_to_device.is_some() {
                return Err(runtime("invalid gateway-to-device characteristic"));
            }
            gateway_to_device = Some(characteristic);
        } else if uuid == device_to_gateway_uuid() {
            if properties != GattCharacteristicProperties::Indicate || device_to_gateway.is_some() {
                return Err(runtime("invalid device-to-gateway characteristic"));
            }
            device_to_gateway = Some(characteristic);
        } else {
            return Err(runtime("unexpected Keyferry characteristic"));
        }
    }

    gateway_to_device
        .zip(device_to_gateway)
        .ok_or_else(|| runtime("Keyferry characteristics are incomplete"))
}

async fn drive_gatt(
    mut connection: GattConnection,
    mut channels: GattChannels,
    progress: watch::Sender<Instant>,
) -> Result<(), BleGatewayError> {
    loop {
        tokio::select! {
            fragment = channels.outbound.recv() => {
                let fragment = fragment.ok_or_else(|| runtime("outbound byte channel closed"))?;
                write_fragment(&connection.gateway_to_device, fragment, &progress).await?;
            }
            fault = connection.fault_receiver.recv() => {
                let _ = fault;
                return Err(runtime("BLE connection was lost"));
            }
        }
    }
}

async fn write_fragment(
    characteristic: &GattCharacteristic,
    fragment: OutboundFragment,
    progress: &watch::Sender<Instant>,
) -> Result<(), BleGatewayError> {
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!(
            "BLE diagnostic outbound_fragment_bytes={}",
            fragment.bytes().len()
        );
    }
    let buffer = make_buffer(fragment.bytes())?;
    let write_operation = characteristic
        .WriteValueWithResultAndOptionAsync(&buffer, GattWriteOption::WriteWithResponse)
        .map_err(|_| runtime("could not begin acknowledged GATT write"))?;
    let result = operation(write_operation, "acknowledged GATT write", None).await;
    let accepted = result
        .and_then(|result| {
            result
                .Status()
                .map_err(|_| runtime("could not read GATT write status"))
        })
        .is_ok_and(|status| status == GattCommunicationStatus::Success);
    let acknowledgement = if accepted {
        progress.send_replace(Instant::now());
        WriteAck::Acknowledged
    } else {
        WriteAck::Rejected
    };
    let _ = fragment.acknowledge(acknowledgement);
    if accepted {
        Ok(())
    } else {
        Err(runtime("acknowledged GATT write was rejected"))
    }
}

async fn operation<T>(
    operation: IAsyncOperation<T>,
    stage: &'static str,
    deadline: Option<Instant>,
) -> Result<T, BleGatewayError>
where
    T: windows::core::RuntimeType + 'static,
{
    let started_at = Instant::now();
    let operation_timeout = Duration::from_millis(OPERATION_TIMEOUT_MS as u64);
    let pending = operation.clone().into_future();
    tokio::pin!(pending);
    let marker_wait = deadline.map_or(operation_timeout, |deadline| {
        operation_timeout.min(deadline.saturating_duration_since(Instant::now()))
    });
    let first = time::timeout(marker_wait, pending.as_mut()).await;
    let (expired, result) = if let Ok(result) = first {
        (false, result)
    } else {
        let status = operation.Status().unwrap_or(AsyncStatus::Error);
        if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
            eprintln!(
                "BLE diagnostic t_ms={} stage={stage} operation_async_status={} marker=operation_timeout",
                started_at.elapsed().as_millis(),
                status.0
            );
        }
        if let Some(deadline) = deadline {
            match time::timeout_at(deadline, pending.as_mut()).await {
                Ok(result) => (false, result),
                Err(_) => {
                    let _ = operation.Cancel();
                    // WinRT Bluetooth connection work can outlive cancellation.
                    // Retain and await it so Close and the next scan can only
                    // occur after a terminal status.
                    (true, pending.await)
                }
            }
        } else {
            let _ = operation.Cancel();
            (true, pending.await)
        }
    };
    let status = operation.Status().unwrap_or(AsyncStatus::Error);
    let error_code = if status == AsyncStatus::Error {
        operation.ErrorCode().unwrap_or(HRESULT(0))
    } else {
        HRESULT(0)
    };
    if DIAGNOSTICS_ENABLED.load(Ordering::Acquire) {
        eprintln!(
            "BLE diagnostic t_ms={} stage={stage} operation_async_status={} operation_hresult=0x{:08X}",
            started_at.elapsed().as_millis(),
            status.0,
            error_code.0 as u32
        );
    }
    if operation_may_close(status) {
        let _ = operation.Close();
    } else {
        return Err(runtime(format!(
            "{stage} remained nonterminal after completion notification"
        )));
    }
    if expired {
        return Err(runtime(format!(
            "{stage} expired before terminal completion"
        )));
    }
    result.map_err(|error| {
        runtime(format!(
            "{stage} failed with HRESULT 0x{:08X}",
            error.code().0 as u32
        ))
    })
}

fn operation_may_close(status: AsyncStatus) -> bool {
    status != AsyncStatus::Started
}

fn require_success(
    status: GattCommunicationStatus,
    stage: &'static str,
) -> Result<(), BleGatewayError> {
    if status == GattCommunicationStatus::Success {
        Ok(())
    } else {
        Err(runtime(format!("{stage} returned status {}", status.0)))
    }
}

fn read_buffer(buffer: windows::core::Result<IBuffer>) -> windows::core::Result<Vec<u8>> {
    let buffer = buffer?;
    let length = buffer.Length()? as usize;
    let reader = DataReader::FromBuffer(&buffer)?;
    let mut bytes = vec![0_u8; length];
    let result = reader.ReadBytes(&mut bytes);
    let _ = reader.Close();
    result.map(|()| bytes)
}

fn make_buffer(bytes: &[u8]) -> Result<IBuffer, BleGatewayError> {
    let writer = DataWriter::new().map_err(|_| runtime("could not create GATT value buffer"))?;
    writer
        .WriteBytes(bytes)
        .map_err(|_| runtime("could not fill GATT value buffer"))?;
    let buffer = writer
        .DetachBuffer()
        .map_err(|_| runtime("could not detach GATT value buffer"))?;
    let _ = writer.Close();
    Ok(buffer)
}

fn service_uuid() -> GUID {
    GUID::from_u128(u128::from_be_bytes(SERVICE_UUID))
}

fn gateway_to_device_uuid() -> GUID {
    GUID::from_u128(u128::from_be_bytes(GATEWAY_TO_DEVICE_UUID))
}

fn device_to_gateway_uuid() -> GUID {
    GUID::from_u128(u128::from_be_bytes(DEVICE_TO_GATEWAY_UUID))
}

fn runtime(message: impl Into<String>) -> BleGatewayError {
    BleGatewayError::runtime(message)
}

#[derive(Clone, Copy)]
struct ScanCandidate {
    address: u64,
    address_type: BluetoothAddressType,
}

enum ScanEvent {
    Candidate(ScanCandidate),
    Stopped,
}

struct WatcherRegistration {
    watcher: BluetoothLEAdvertisementWatcher,
    received_token: i64,
    stopped_token: i64,
}

impl Drop for WatcherRegistration {
    fn drop(&mut self) {
        let _ = self.watcher.Stop();
        let _ = self.watcher.RemoveReceived(self.received_token);
        let _ = self.watcher.RemoveStopped(self.stopped_token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn winrt_operations_close_only_after_terminal_status() {
        assert!(!operation_may_close(AsyncStatus::Started));
        assert!(operation_may_close(AsyncStatus::Completed));
        assert!(operation_may_close(AsyncStatus::Canceled));
        assert!(operation_may_close(AsyncStatus::Error));
    }

    #[test]
    fn host_pre_cccd_deadline_precedes_firmware_deadline() {
        assert!(
            PRE_CCCD_TIMEOUT
                < Duration::from_millis(
                    keyferry_protocol::ble_transport::CCCD_SETUP_TIMEOUT_MS as u64,
                )
        );
    }

    #[test]
    fn single_shot_never_retries() {
        assert!(!retry_allowed(true));
        assert!(retry_allowed(false));
    }

    #[test]
    fn candidate_preserves_random_address_type() {
        let candidate = ScanCandidate {
            address: 0,
            address_type: BluetoothAddressType::Random,
        };
        assert_eq!(candidate.address_type, BluetoothAddressType::Random);
    }
}
