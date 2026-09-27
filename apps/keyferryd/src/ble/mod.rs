//! Native desktop BLE transport adapters.
//!
//! Bluetooth carries opaque TLS bytes only. Authentication and command
//! authority remain in [`crate::TlsTransport`].

mod pipe;

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
mod macos;

use std::fmt;

use crate::TlsTransport;

pub(crate) fn gateway_acquisition_enabled(transport: &TlsTransport) -> bool {
    !transport.is_in_maintenance()
}

#[derive(Debug)]
pub enum BleGatewayError {
    Unsupported,
    Runtime(String),
}

impl BleGatewayError {
    pub(super) fn runtime(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }
}

impl fmt::Display for BleGatewayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => {
                write!(
                    formatter,
                    "Bluetooth gateway is supported only on Windows and macOS"
                )
            }
            Self::Runtime(message) => write!(formatter, "Bluetooth gateway failed: {message}"),
        }
    }
}

impl std::error::Error for BleGatewayError {}

/// Run the byte-only BLE gateway until the task is cancelled or encounters a
/// fatal platform initialization error.
pub async fn run_ble_gateway(
    transport: TlsTransport,
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    #[cfg(windows)]
    {
        windows::run(transport, single_shot).await
    }

    #[cfg(target_os = "macos")]
    {
        macos::run(transport, single_shot).await
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (transport, single_shot);
        Err(BleGatewayError::Unsupported)
    }
}

/// Run one shared native BLE discovery manager for an issued multi-device
/// installation. The TLS ClientHello SNI selects an exact candidate and that
/// device's link secret must then authenticate it.
pub async fn run_ble_gateways(
    stores: crate::InstallationTlsSecretSet,
    transports: Vec<TlsTransport>,
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    #[cfg(windows)]
    {
        let router = crate::MultiTlsRouter::new(&stores, transports.clone())
            .map_err(|error| BleGatewayError::runtime(error.to_string()))?;
        windows::run_multi(router, transports, single_shot).await
    }

    #[cfg(target_os = "macos")]
    {
        if transports.len() == 1 {
            return macos::run(
                transports.into_iter().next().expect("one transport"),
                single_shot,
            )
            .await;
        }
        let _ = stores;
        Err(BleGatewayError::runtime(
            "simultaneous multi-device Bluetooth discovery is not yet available on macOS",
        ))
    }

    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (stores, transports, single_shot);
        Err(BleGatewayError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HostIdentity, TlsCredentials};

    #[tokio::test]
    async fn maintenance_disables_all_gateway_acquisition_until_finished() {
        let transport = TlsTransport::new(TlsCredentials::new(
            HostIdentity::generate().expect("host identity"),
            [0x44; 16],
            [0x55; 32],
        ))
        .expect("TLS transport");

        assert!(gateway_acquisition_enabled(&transport));
        transport
            .begin_maintenance()
            .await
            .expect("begin maintenance without a session");
        assert!(!gateway_acquisition_enabled(&transport));
        transport.finish_maintenance();
        assert!(gateway_acquisition_enabled(&transport));
    }
}
