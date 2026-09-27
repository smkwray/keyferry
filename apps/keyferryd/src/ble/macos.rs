use std::{
    env,
    path::PathBuf,
    pin::Pin,
    process::Stdio,
    task::{Context, Poll},
    time::Duration,
};

use keyferry_protocol::ble_transport::AUTHENTICATION_TIMEOUT_MS;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
    sync::oneshot,
    time,
};

use super::BleGatewayError;

const HELPER_ENV: &str = "KEYFERRY_BLE_HELPER";
const HELPER_NAME: &str = "keyferry-ble-bridge";
const READY_MAGIC: [u8; 4] = *b"KFMB";
const READY_VERSION: u16 = 1;
const MIN_FRAGMENT_BYTES: u16 = 20;
const MAX_FRAGMENT_BYTES: u16 = 244;
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) async fn run(
    transport: crate::TlsTransport,
    single_shot: bool,
) -> Result<(), BleGatewayError> {
    loop {
        // A gateway-yield lease must stop this Mac from spawning another
        // CoreBluetooth candidate while the receiving computer acquires the
        // stick. The admitted stream below is already closed by maintenance.
        if !super::gateway_acquisition_enabled(&transport) {
            time::sleep(RETRY_DELAY).await;
            continue;
        }
        let (stream, closed) = match spawn_helper().await {
            Ok(stream) => stream,
            Err(error) if !single_shot => {
                eprintln!("Bluetooth helper unavailable: {error}");
                time::sleep(RETRY_DELAY).await;
                continue;
            }
            Err(error) => return Err(error),
        };

        let result = transport
            .accept_stream_on(stream, crate::TlsLinkPath::Bluetooth)
            .await
            .map_err(|error| BleGatewayError::runtime(error.to_string()));
        if result.is_ok() && diagnostics_enabled() {
            eprintln!("BLE pipe admitted; waiting_for_stream_close=1");
        }
        let result = finish_candidate(result, closed).await;
        if single_shot {
            return result;
        }
        if let Err(ref error) = result {
            eprintln!("Bluetooth candidate closed: {error}");
        }
        time::sleep(RETRY_DELAY).await;
    }
}

// Admission transfers ownership of HelperStream to the TLS connection actor.
// Do not return from single-shot (main would stop the daemon), or start another
// helper, until that exact stream is dropped. No polling and no command retry.
async fn finish_candidate(
    result: Result<(), BleGatewayError>,
    closed: oneshot::Receiver<()>,
) -> Result<(), BleGatewayError> {
    result?;
    let _ = closed.await;
    Ok(())
}

fn diagnostics_enabled() -> bool {
    env::var_os("KEYFERRY_BLE_DIAGNOSTICS").is_some_and(|value| value == "1")
}

async fn spawn_helper() -> Result<(HelperStream, oneshot::Receiver<()>), BleGatewayError> {
    let helper = helper_path()?;
    spawn_helper_command(Command::new(&helper)).await
}

async fn spawn_helper_command(
    mut command: Command,
) -> Result<(HelperStream, oneshot::Receiver<()>), BleGatewayError> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| BleGatewayError::runtime("could not start the Bluetooth helper"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| BleGatewayError::runtime("Bluetooth helper stdin is unavailable"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| BleGatewayError::runtime("Bluetooth helper stdout is unavailable"))?;

    let mut header = [0_u8; 8];
    time::timeout(
        Duration::from_millis(AUTHENTICATION_TIMEOUT_MS as u64),
        stdout.read_exact(&mut header),
    )
    .await
    .map_err(|_| BleGatewayError::runtime("Bluetooth helper setup timed out"))?
    .map_err(|_| BleGatewayError::runtime("Bluetooth helper stopped before setup completed"))?;
    validate_ready_header(header)?;

    let (closed, receiver) = oneshot::channel();
    Ok((
        HelperStream {
            _child: child,
            stdin,
            stdout,
            closed: Some(closed),
            trace: diagnostics_enabled(),
            written_bytes: 0,
            read_bytes: 0,
            written_hash: Sha256::new(),
            read_hash: Sha256::new(),
        },
        receiver,
    ))
}

fn helper_path() -> Result<PathBuf, BleGatewayError> {
    if let Some(path) = env::var_os(HELPER_ENV) {
        return Ok(PathBuf::from(path));
    }
    let executable = env::current_exe()
        .map_err(|_| BleGatewayError::runtime("cannot locate the daemon executable"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| BleGatewayError::runtime("cannot locate the daemon directory"))?;
    Ok(directory.join(HELPER_NAME))
}

fn validate_ready_header(header: [u8; 8]) -> Result<u16, BleGatewayError> {
    if header[..4] != READY_MAGIC {
        return Err(BleGatewayError::runtime(
            "Bluetooth helper returned an invalid setup header",
        ));
    }
    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != READY_VERSION {
        return Err(BleGatewayError::runtime(
            "Bluetooth helper protocol version is incompatible",
        ));
    }
    let fragment_bytes = u16::from_be_bytes([header[6], header[7]]);
    if !(MIN_FRAGMENT_BYTES..=MAX_FRAGMENT_BYTES).contains(&fragment_bytes) {
        return Err(BleGatewayError::runtime(
            "Bluetooth helper returned an invalid fragment limit",
        ));
    }
    Ok(fragment_bytes)
}

struct HelperStream {
    _child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    closed: Option<oneshot::Sender<()>>,
    trace: bool,
    written_bytes: u64,
    read_bytes: u64,
    written_hash: Sha256,
    read_hash: Sha256,
}

impl Drop for HelperStream {
    fn drop(&mut self) {
        // Request child termination before waking the next-candidate loop.
        let _ = self._child.start_kill();
        if self.trace {
            eprintln!(
                "BLE pipe close written_bytes={} read_bytes={} written_sha256={:x} read_sha256={:x}",
                self.written_bytes,
                self.read_bytes,
                self.written_hash.clone().finalize(),
                self.read_hash.clone().finalize(),
            );
        }
        if let Some(closed) = self.closed.take() {
            let _ = closed.send(());
        }
    }
}

impl AsyncRead for HelperStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.stdout).poll_read(context, buffer);
        let bytes = &buffer.filled()[before..];
        self.read_bytes += bytes.len() as u64;
        if self.trace {
            self.read_hash.update(bytes);
        }
        result
    }
}

impl AsyncWrite for HelperStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let result = Pin::new(&mut self.stdin).poll_write(context, buffer);
        if let Poll::Ready(Ok(count)) = result {
            self.written_bytes += count as u64;
            if self.trace {
                self.written_hash.update(&buffer[..count]);
            }
        }
        result
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdin).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.stdin).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admitted_candidate_lives_until_its_stream_closes() {
        let (closed, receiver) = oneshot::channel();
        let finish = finish_candidate(Ok(()), receiver);
        tokio::pin!(finish);
        assert!(time::timeout(Duration::from_millis(30), &mut finish)
            .await
            .is_err());
        closed.send(()).unwrap();
        time::timeout(Duration::from_secs(1), finish)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn failed_admission_does_not_wait_for_live_stream() {
        let (_closed, receiver) = oneshot::channel();
        let result = time::timeout(
            Duration::from_secs(1),
            finish_candidate(
                Err(BleGatewayError::runtime("test admission failure")),
                receiver,
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stream_drop_without_explicit_signal_also_finishes() {
        let (closed, receiver) = oneshot::channel::<()>();
        drop(closed);
        time::timeout(Duration::from_secs(1), finish_candidate(Ok(()), receiver))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn real_child_stream_strips_one_header_and_reports_drop() {
        use tokio::io::AsyncWriteExt;

        // A synthetic local helper, no CoreBluetooth or credentials. Fragment
        // the private header and coalesce a payload with its final bytes.
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf 'KF'; sleep 0.02; printf 'MB\\000\\001\\000\\024XYZ'; exec cat");
        let (mut stream, mut closed) =
            time::timeout(Duration::from_secs(3), spawn_helper_command(command))
                .await
                .unwrap()
                .unwrap();
        let mut prefix = [0_u8; 3];
        stream.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix, b"XYZ");
        let bytes: Vec<u8> = (0..740).map(|index| (index % 251) as u8).collect();
        stream.write_all(&bytes).await.unwrap();
        let mut echoed = vec![0_u8; bytes.len()];
        time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, bytes);
        assert_eq!(stream.written_bytes, 740);
        assert_eq!(stream.read_bytes, 743); // Excludes the eight-byte header.
        assert!(matches!(
            closed.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        drop(stream);
        time::timeout(Duration::from_secs(1), closed)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn ready_header_is_strict_and_bounded() {
        assert_eq!(validate_ready_header(*b"KFMB\0\x01\0\x14").unwrap(), 20);
        assert_eq!(validate_ready_header(*b"KFMB\0\x01\0\xf4").unwrap(), 244);
        assert!(validate_ready_header(*b"NOPE\0\x01\0\x14").is_err());
        assert!(validate_ready_header(*b"KFMB\0\x02\0\x14").is_err());
        assert!(validate_ready_header(*b"KFMB\0\x01\0\x13").is_err());
        assert!(validate_ready_header(*b"KFMB\0\x01\0\xf5").is_err());
    }
}
