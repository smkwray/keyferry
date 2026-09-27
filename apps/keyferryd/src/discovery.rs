use std::{
    collections::BTreeSet,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, RwLock},
    time::Duration,
};

use getifaddrs::{Address, InterfaceFlags};
use tokio::{net::UdpSocket, task::JoinHandle, time};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayListenerSnapshot {
    pub generation: u64,
    pub addresses: Vec<SocketAddr>,
}

#[derive(Clone, Default)]
pub struct GatewayListenerRegistry(Arc<RwLock<GatewayListenerSnapshot>>);

impl GatewayListenerRegistry {
    #[must_use]
    pub fn snapshot(&self) -> GatewayListenerSnapshot {
        self.0.read().expect("gateway listener registry").clone()
    }

    fn replace(&self, plans: &[BeaconPlan]) {
        let mut state = self.0.write().expect("gateway listener registry");
        let addresses = plans
            .iter()
            .copied()
            .map(BeaconPlan::listener_address)
            .collect::<Vec<_>>();
        if state.addresses != addresses {
            state.generation = state.generation.wrapping_add(1).max(1);
            state.addresses = addresses;
        }
    }

    fn clear(&self) {
        self.replace(&[]);
    }

    #[cfg(test)]
    pub(crate) fn set_test_snapshot(&self, snapshot: GatewayListenerSnapshot) {
        *self.0.write().expect("gateway listener registry") = snapshot;
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BeaconPlan {
    bind: SocketAddrV4,
    destination: SocketAddrV4,
}

impl BeaconPlan {
    /// Resolve the selected active private IPv4 broadcast interfaces into
    /// exact sources and directed-broadcast destinations. Point-to-point links
    /// such as Tailscale are deliberately excluded; the endpoint independently
    /// checks that a beacon source belongs to its selected Wi-Fi subnet.
    pub fn selected(interface_names: &BTreeSet<String>) -> io::Result<Vec<Self>> {
        Self::selected_with_matches(interface_names).map(|(plans, _)| plans)
    }

    fn selected_with_matches(
        interface_names: &BTreeSet<String>,
    ) -> io::Result<(Vec<Self>, BTreeSet<String>)> {
        let mut plans = Vec::new();
        let mut matched = BTreeSet::new();
        for interface in getifaddrs::getifaddrs()? {
            #[cfg(windows)]
            let description = &interface.description;
            #[cfg(not(windows))]
            let description = "";
            let Some(selected_name) =
                selected_interface_name(interface_names, &interface.name, description)
            else {
                continue;
            };
            if !is_usable_broadcast_interface(interface.flags) {
                continue;
            }
            let Address::V4(address) = interface.address else {
                continue;
            };
            let Some(netmask) = address.netmask else {
                continue;
            };
            if !address.address.is_private() {
                continue;
            }
            if let Ok(plan) = Self::new(address.address, netmask) {
                plans.push(plan);
                matched.insert(selected_name.clone());
            }
        }
        plans.sort_unstable();
        plans.dedup();
        Ok((plans, matched))
    }

    pub fn new(interface: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, &'static str> {
        let address = u32::from(interface);
        let mask = u32::from(netmask);
        let inverted = !mask;
        let octets = interface.octets();
        let unicast = octets[0] != 0 && octets[0] != 127 && octets[0] < 224;
        let contiguous =
            mask != 0 && mask != u32::MAX && inverted > 1 && (inverted & (inverted + 1)) == 0;
        if !unicast || !contiguous {
            return Err(
                "discovery requires a unicast IPv4 interface and contiguous /1 through /30 netmask",
            );
        }
        let network = address & mask;
        let broadcast = network | inverted;
        if address == network || address == broadcast {
            return Err("discovery interface cannot be its subnet network or broadcast address");
        }
        Ok(Self {
            bind: SocketAddrV4::new(interface, 0),
            destination: SocketAddrV4::new(
                Ipv4Addr::from(broadcast),
                keyferry_protocol::discovery::PORT,
            ),
        })
    }

    #[must_use]
    pub fn bind_address(self) -> SocketAddr {
        self.bind.into()
    }

    #[must_use]
    pub fn destination(self) -> SocketAddr {
        self.destination.into()
    }

    #[must_use]
    pub fn listener_address(self) -> SocketAddr {
        SocketAddrV4::new(*self.bind.ip(), keyferry_protocol::roaming::DEVICE_TLS_PORT).into()
    }
}

fn selected_interface_name<'a>(
    interface_names: &'a BTreeSet<String>,
    internal_name: &str,
    description: &str,
) -> Option<&'a String> {
    #[cfg(windows)]
    {
        interface_names.iter().find(|selected| {
            selected.eq_ignore_ascii_case(internal_name)
                || selected.eq_ignore_ascii_case(description)
        })
    }
    #[cfg(not(windows))]
    {
        let _ = description;
        interface_names.get(internal_name)
    }
}

fn is_usable_broadcast_interface(flags: InterfaceFlags) -> bool {
    flags.contains(InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::BROADCAST)
        && !flags.intersects(InterfaceFlags::LOOPBACK | InterfaceFlags::POINTTOPOINT)
}

pub struct HostBeacon {
    socket: UdpSocket,
    destination: SocketAddr,
    packet: [u8; keyferry_protocol::discovery::BEACON_SIZE],
}

struct PortableGatewayInterface {
    plan: BeaconPlan,
    beacon: HostBeacon,
    listener_task: JoinHandle<()>,
}

#[derive(Clone)]
enum PortableGatewayBinding {
    Single(crate::TlsTransport),
    Multi(crate::InstallationTlsSecretSet, Vec<crate::TlsTransport>),
}

impl PortableGatewayInterface {
    async fn bind(
        plan: BeaconPlan,
        host_id: [u8; 16],
        binding: PortableGatewayBinding,
    ) -> io::Result<Self> {
        // Bind the authenticated listener before advertising it. If either
        // socket fails, this interface stays undiscoverable and Bluetooth
        // continues independently.
        let beacon = HostBeacon::bind(plan, host_id).await?;
        let listener_task = match binding {
            PortableGatewayBinding::Single(transport) => {
                let listener = crate::TlsListener::bind(plan.listener_address(), transport)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
                tokio::spawn(async move {
                    loop {
                        match listener.accept_one().await {
                            Ok(peer) => println!(
                                "owner-authorized Wi-Fi dongle session authenticated from {peer}"
                            ),
                            Err(error) => {
                                eprintln!(
                                    "owner-authorized Wi-Fi dongle connection rejected: {error}"
                                );
                                time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                })
            }
            PortableGatewayBinding::Multi(stores, transports) => {
                let listener =
                    crate::MultiTlsListener::bind(plan.listener_address(), &stores, transports)
                        .await
                        .map_err(|error| io::Error::other(error.to_string()))?;
                tokio::spawn(async move {
                    loop {
                        match listener.accept_one().await {
                            Ok((peer, device_id)) => println!(
                                "owner-authorized Wi-Fi dongle session authenticated from {peer} for {}",
                                uuid::Uuid::from_bytes(device_id)
                            ),
                            Err(error) => {
                                eprintln!(
                                    "owner-authorized Wi-Fi dongle connection rejected: {error}"
                                );
                                time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                })
            }
        };
        Ok(Self {
            plan,
            beacon,
            listener_task,
        })
    }
}

impl Drop for PortableGatewayInterface {
    fn drop(&mut self) {
        self.listener_task.abort();
    }
}

async fn stop_interfaces(interfaces: &mut Vec<PortableGatewayInterface>) {
    let mut stopping = std::mem::take(interfaces);
    for interface in &stopping {
        interface.listener_task.abort();
    }
    for interface in &mut stopping {
        let _ = (&mut interface.listener_task).await;
    }
}

fn encode_beacon(host_id: [u8; 16]) -> io::Result<[u8; keyferry_protocol::discovery::BEACON_SIZE]> {
    if host_id.iter().all(|byte| *byte == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "discovery host identifier is zero",
        ));
    }
    let mut packet = [0; keyferry_protocol::discovery::BEACON_SIZE];
    packet[..4].copy_from_slice(&keyferry_protocol::discovery::MAGIC);
    packet[4] = keyferry_protocol::discovery::VERSION;
    packet[6..].copy_from_slice(&host_id);
    Ok(packet)
}

impl HostBeacon {
    pub async fn bind(plan: BeaconPlan, host_id: [u8; 16]) -> io::Result<Self> {
        let packet = encode_beacon(host_id)?;
        let socket = UdpSocket::bind(plan.bind_address()).await?;
        socket.set_broadcast(true)?;
        Ok(Self {
            socket,
            destination: plan.destination(),
            packet,
        })
    }

    pub async fn announce_once(&self) -> io::Result<()> {
        let sent = self.socket.send_to(&self.packet, self.destination).await?;
        if sent != self.packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "discovery beacon was not sent in full",
            ));
        }
        Ok(())
    }

    pub async fn run(self) {
        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(error) = self.announce_once().await {
                eprintln!("discovery beacon send failed: {error}");
            }
        }
    }

    /// Follow interface changes without persisting a machine-specific IP.
    /// Each directed beacon has a listener bound to that exact private IPv4
    /// interface before the beacon is emitted. LAN failures leave Bluetooth
    /// available.
    pub async fn run_selected(
        host_id: [u8; 16],
        transport: crate::TlsTransport,
        interface_names: BTreeSet<String>,
        listener_registry: GatewayListenerRegistry,
    ) {
        Self::run_selected_binding(
            host_id,
            PortableGatewayBinding::Single(transport),
            interface_names,
            listener_registry,
        )
        .await;
    }

    pub async fn run_selected_multi(
        host_id: [u8; 16],
        stores: crate::InstallationTlsSecretSet,
        transports: Vec<crate::TlsTransport>,
        interface_names: BTreeSet<String>,
        listener_registry: GatewayListenerRegistry,
    ) {
        Self::run_selected_binding(
            host_id,
            PortableGatewayBinding::Multi(stores, transports),
            interface_names,
            listener_registry,
        )
        .await;
    }

    async fn run_selected_binding(
        host_id: [u8; 16],
        binding: PortableGatewayBinding,
        interface_names: BTreeSet<String>,
        listener_registry: GatewayListenerRegistry,
    ) {
        const REFRESH_TICKS: u8 = 10;

        if let Err(error) = encode_beacon(host_id) {
            eprintln!("portable discovery disabled: {error}");
            listener_registry.clear();
            return;
        }

        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        let mut interfaces = Vec::new();
        let mut refresh_in = 0;
        let mut last_missing = None;
        loop {
            interval.tick().await;
            let listener_stopped = interfaces
                .iter()
                .any(|interface: &PortableGatewayInterface| interface.listener_task.is_finished());
            if refresh_in == 0 || listener_stopped {
                match BeaconPlan::selected_with_matches(&interface_names) {
                    Ok((plans, matched)) => {
                        let missing = interface_names.len() - matched.len();
                        if last_missing != Some(missing) {
                            eprintln!(
                                "selected LAN interfaces active: {}/{}; unavailable: {missing}",
                                matched.len(),
                                interface_names.len()
                            );
                            last_missing = Some(missing);
                        }
                        let active_plans = interfaces
                            .iter()
                            .map(|interface| interface.plan)
                            .collect::<Vec<_>>();
                        if listener_stopped || plans != active_plans {
                            stop_interfaces(&mut interfaces).await;
                            let mut refreshed = Vec::with_capacity(plans.len());
                            for plan in plans {
                                match PortableGatewayInterface::bind(plan, host_id, binding.clone())
                                    .await
                                {
                                    Ok(interface) => refreshed.push(interface),
                                    Err(error) => eprintln!(
                                        "portable LAN interface unavailable ({}): {error}",
                                        plan.bind_address()
                                    ),
                                }
                            }
                            interfaces = refreshed;
                            listener_registry.replace(
                                &interfaces
                                    .iter()
                                    .map(|interface| interface.plan)
                                    .collect::<Vec<_>>(),
                            );
                        }
                        refresh_in = REFRESH_TICKS;
                    }
                    Err(error) => {
                        eprintln!("discovery interface refresh failed: {error}");
                        // Preserve working sockets across a transient
                        // enumeration error, but retry promptly.
                        refresh_in = 1;
                    }
                }
            }
            refresh_in = refresh_in.saturating_sub(1);

            // A gateway yield must make this host undiscoverable for the
            // entire lease. Keeping the listener bound is harmless because
            // TlsTransport rejects admission during maintenance, while
            // suppressing the beacon lets another authorized gateway win
            // discovery instead of repeatedly selecting this paused host.
            let acquisition_enabled = match &binding {
                PortableGatewayBinding::Single(transport) => {
                    crate::ble::gateway_acquisition_enabled(transport)
                }
                PortableGatewayBinding::Multi(_, transports) => transports
                    .iter()
                    .any(crate::ble::gateway_acquisition_enabled),
            };
            if !acquisition_enabled {
                continue;
            }

            let mut failures = 0usize;
            for interface in &interfaces {
                if interface.beacon.announce_once().await.is_err() {
                    failures += 1;
                }
            }
            if failures > 0 {
                eprintln!("discovery beacon send failed on {failures} interface(s)");
                refresh_in = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_uses_exact_interface_and_directed_broadcast() {
        let plan = BeaconPlan::new(
            "192.168.30.137".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .expect("valid plan");
        assert_eq!(plan.bind_address(), "192.168.30.137:0".parse().unwrap());
        assert_eq!(plan.destination(), "192.168.30.255:43917".parse().unwrap());
        assert_eq!(
            plan.listener_address(),
            "192.168.30.137:7443".parse().unwrap()
        );
    }

    #[test]
    fn only_active_broadcast_interfaces_are_usable() {
        assert!(is_usable_broadcast_interface(
            InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::BROADCAST
        ));
        for disallowed in [
            InterfaceFlags::empty(),
            InterfaceFlags::UP | InterfaceFlags::BROADCAST,
            InterfaceFlags::UP | InterfaceFlags::RUNNING,
            InterfaceFlags::UP
                | InterfaceFlags::RUNNING
                | InterfaceFlags::BROADCAST
                | InterfaceFlags::LOOPBACK,
            InterfaceFlags::UP
                | InterfaceFlags::RUNNING
                | InterfaceFlags::BROADCAST
                | InterfaceFlags::POINTTOPOINT,
        ] {
            assert!(!is_usable_broadcast_interface(disallowed));
        }
    }

    #[test]
    fn selected_interface_uses_platform_operator_name() {
        let selected = BTreeSet::from(["Ethernet 2".to_string()]);
        #[cfg(windows)]
        assert_eq!(
            selected_interface_name(&selected, "ethernet_32769", "Ethernet 2"),
            selected.get("Ethernet 2")
        );
        #[cfg(not(windows))]
        {
            assert!(selected_interface_name(&selected, "ethernet_32769", "Ethernet 2").is_none());
            assert_eq!(
                selected_interface_name(&selected, "Ethernet 2", ""),
                selected.get("Ethernet 2")
            );
        }
    }

    #[test]
    fn live_selected_interfaces_are_exact_when_required() {
        assert!(BeaconPlan::selected(&BTreeSet::new())
            .expect("empty interface selection")
            .is_empty());
        let selected = getifaddrs::getifaddrs()
            .expect("enumerate network interfaces")
            .filter(|interface| is_usable_broadcast_interface(interface.flags))
            .map(|interface| interface.name)
            .collect();
        let plans = BeaconPlan::selected(&selected).expect("select network interfaces");
        if std::env::var_os("KEYFERRY_REQUIRE_PORTABLE_LAN").is_some() {
            assert!(
                !plans.is_empty(),
                "this acceptance host requires at least one active private broadcast interface"
            );
        }
        for plan in plans {
            let SocketAddr::V4(bind) = plan.bind_address() else {
                panic!("portable interface must be IPv4");
            };
            assert!(bind.ip().is_private());
            assert_eq!(bind.port(), 0);
            let SocketAddr::V4(listener) = plan.listener_address() else {
                panic!("portable listener must be IPv4");
            };
            assert_eq!(listener.ip(), bind.ip());
            assert_eq!(listener.port(), keyferry_protocol::roaming::DEVICE_TLS_PORT);
        }
    }

    #[tokio::test]
    async fn live_selected_sockets_bind_and_announce_when_required() {
        if std::env::var_os("KEYFERRY_REQUIRE_PORTABLE_LAN").is_none() {
            return;
        }
        let selected = getifaddrs::getifaddrs()
            .expect("enumerate network interfaces")
            .filter(|interface| is_usable_broadcast_interface(interface.flags))
            .map(|interface| interface.name)
            .collect();
        let plans = BeaconPlan::selected(&selected).expect("select network interfaces");
        assert!(!plans.is_empty());
        let mut sockets = Vec::with_capacity(plans.len());
        for plan in plans {
            let listener = tokio::net::TcpListener::bind(plan.listener_address())
                .await
                .expect("bind exact-interface device TLS listener");
            let beacon = HostBeacon::bind(plan, [0x42; 16])
                .await
                .expect("bind exact-interface discovery beacon");
            beacon
                .announce_once()
                .await
                .expect("send directed discovery beacon");
            sockets.push((listener, beacon));
        }
    }

    #[test]
    fn invalid_interfaces_and_masks_fail_closed() {
        for (address, mask) in [
            ("0.0.0.0", "255.255.255.0"),
            ("127.0.0.1", "255.255.255.0"),
            ("224.0.0.1", "255.255.255.0"),
            ("192.168.30.0", "255.255.255.0"),
            ("192.168.30.255", "255.255.255.0"),
            ("192.168.30.137", "0.0.0.0"),
            ("192.168.30.137", "255.255.255.255"),
            ("192.168.30.137", "255.0.255.0"),
        ] {
            assert!(BeaconPlan::new(address.parse().unwrap(), mask.parse().unwrap()).is_err());
        }
    }

    #[test]
    fn beacon_matches_the_generated_cpp_wire_contract() {
        let host_id = [0x42; 16];
        let plan = BeaconPlan::new(
            "192.0.2.7".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .expect("valid plan");
        let packet = encode_beacon(host_id).expect("valid beacon");
        assert_eq!(
            packet,
            [
                b'K', b'F', b'H', b'B', 1, 0, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            ]
        );
        assert_eq!(plan.destination(), "192.0.2.255:43917".parse().unwrap());
        assert!(encode_beacon([0; 16]).is_err());
    }
}
