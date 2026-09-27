//! Platform-neutral bounded byte pump for the BLE GATT transport.
//!
//! The platform adapter submits received GATT values through [`InboundSender`]
//! and consumes [`OutboundFragment`] values. Each outbound fragment must be
//! explicitly acknowledged before the pump emits another one. The byte pump
//! does not interpret TLS or Keyferry protocol bytes.

#![cfg_attr(not(windows), allow(dead_code))]

use std::{fmt, io, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

pub(crate) const MIN_ATT_MTU: u16 = 23;
pub(crate) const MAX_ATT_MTU: u16 = 517;
pub(crate) const MAX_FRAGMENT_BYTES: usize = 244;
// The other half of the per-direction 8 KiB host budget is the Tokio duplex
// stream. Splitting the budget prevents callback queueing and stream buffering
// from silently combining into 16 KiB.
pub(crate) const MAX_PENDING_BYTES: usize = 4 * 1024;

const INBOUND_CHANNEL_SLOTS: usize = 64;
const OUTBOUND_CHANNEL_SLOTS: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteAck {
    Acknowledged,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InboundSubmitError {
    Empty,
    Oversize { size: usize, maximum: usize },
    ByteBudgetExhausted,
    QueueFull,
    Closed,
}

impl fmt::Display for InboundSubmitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("empty inbound BLE fragment"),
            Self::Oversize { size, maximum } => {
                write!(
                    formatter,
                    "inbound BLE fragment is {size} bytes; maximum is {maximum}"
                )
            }
            Self::ByteBudgetExhausted => formatter.write_str("inbound BLE byte budget exhausted"),
            Self::QueueFull => formatter.write_str("inbound BLE fragment queue is full"),
            Self::Closed => formatter.write_str("BLE byte pump is closed"),
        }
    }
}

impl std::error::Error for InboundSubmitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PumpError {
    InvalidAttMtu(u16),
    InvalidOperationTimeout,
    StreamClosed,
    StreamRead(io::ErrorKind),
    StreamWrite(io::ErrorKind),
    InboundChannelClosed,
    OutboundChannelClosed,
    OutboundDispatchTimeout,
    OutboundAcknowledgementTimeout,
    OutboundWriteRejected,
    InboundWriteTimeout,
}

impl fmt::Display for PumpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAttMtu(mtu) => write!(formatter, "invalid ATT MTU {mtu}"),
            Self::InvalidOperationTimeout => {
                formatter.write_str("operation timeout must be nonzero")
            }
            Self::StreamClosed => formatter.write_str("byte stream closed"),
            Self::StreamRead(kind) => write!(formatter, "byte-stream read failed: {kind}"),
            Self::StreamWrite(kind) => write!(formatter, "byte-stream write failed: {kind}"),
            Self::InboundChannelClosed => formatter.write_str("inbound BLE channel closed"),
            Self::OutboundChannelClosed => formatter.write_str("outbound BLE channel closed"),
            Self::OutboundDispatchTimeout => formatter.write_str("outbound BLE dispatch timed out"),
            Self::OutboundAcknowledgementTimeout => {
                formatter.write_str("outbound BLE acknowledgement timed out")
            }
            Self::OutboundWriteRejected => formatter.write_str("outbound BLE write was rejected"),
            Self::InboundWriteTimeout => formatter.write_str("inbound stream write timed out"),
        }
    }
}

impl std::error::Error for PumpError {}

struct QueuedInbound {
    bytes: Vec<u8>,
    // The byte budget is returned only after the fragment has been written or
    // discarded with the connection. This makes queued memory exactly bounded.
    _byte_budget: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub(crate) struct InboundSender {
    sender: mpsc::Sender<QueuedInbound>,
    byte_budget: Arc<Semaphore>,
    maximum_fragment: usize,
}

impl InboundSender {
    /// Submits one complete GATT value without blocking an OS callback.
    ///
    /// Any error is connection-fatal: callers must close the candidate link so
    /// loss, truncation, and implicit retransmission cannot be hidden.
    pub(crate) fn try_send(&self, bytes: Vec<u8>) -> Result<(), InboundSubmitError> {
        if bytes.is_empty() {
            return Err(InboundSubmitError::Empty);
        }
        if bytes.len() > self.maximum_fragment {
            return Err(InboundSubmitError::Oversize {
                size: bytes.len(),
                maximum: self.maximum_fragment,
            });
        }

        // Do not let a short value with attacker-influenced spare capacity
        // retain an allocation larger than the byte budget while queued.
        let bytes = bytes.into_boxed_slice().into_vec();

        let permits = u32::try_from(bytes.len())
            .expect("a BLE fragment length always fits in a 32-bit permit count");
        let byte_budget = self
            .byte_budget
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| InboundSubmitError::ByteBudgetExhausted)?;

        self.sender
            .try_send(QueuedInbound {
                bytes,
                _byte_budget: byte_budget,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => InboundSubmitError::QueueFull,
                mpsc::error::TrySendError::Closed(_) => InboundSubmitError::Closed,
            })
    }
}

pub(crate) struct OutboundFragment {
    bytes: Vec<u8>,
    acknowledgement: Option<oneshot::Sender<WriteAck>>,
}

impl OutboundFragment {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Completes the single in-flight GATT write. Dropping the fragment without
    /// acknowledging it also closes the pump.
    pub(crate) fn acknowledge(mut self, acknowledgement: WriteAck) -> bool {
        self.acknowledgement
            .take()
            .is_some_and(|sender| sender.send(acknowledgement).is_ok())
    }
}

pub(crate) struct GattChannels {
    pub(crate) inbound: InboundSender,
    pub(crate) outbound: mpsc::Receiver<OutboundFragment>,
}

pub(crate) struct BytePump {
    inbound: mpsc::Receiver<QueuedInbound>,
    outbound: mpsc::Sender<OutboundFragment>,
    fragment_bytes: usize,
    operation_timeout: Duration,
}

impl BytePump {
    pub(crate) fn new(
        att_mtu: u16,
        operation_timeout: Duration,
    ) -> Result<(Self, GattChannels), PumpError> {
        let fragment_bytes = fragment_bytes(att_mtu)?;
        if operation_timeout.is_zero() {
            return Err(PumpError::InvalidOperationTimeout);
        }

        let (inbound_sender, inbound) = mpsc::channel(INBOUND_CHANNEL_SLOTS);
        let (outbound, outbound_receiver) = mpsc::channel(OUTBOUND_CHANNEL_SLOTS);
        let byte_budget = Arc::new(Semaphore::new(MAX_PENDING_BYTES));

        Ok((
            Self {
                inbound,
                outbound,
                fragment_bytes,
                operation_timeout,
            },
            GattChannels {
                inbound: InboundSender {
                    sender: inbound_sender,
                    byte_budget,
                    maximum_fragment: fragment_bytes,
                },
                outbound: outbound_receiver,
            },
        ))
    }

    /// Runs both byte directions until either direction faults or closes.
    /// Dropping the other direction at that point is intentional fail-closed
    /// behavior; the owning connection manager must tear down the BLE link.
    pub(crate) async fn run<Stream>(self, stream: Stream) -> Result<(), PumpError>
    where
        Stream: AsyncRead + AsyncWrite + Unpin,
    {
        let (reader, writer) = tokio::io::split(stream);
        let outbound = pump_outbound(
            reader,
            self.outbound,
            self.fragment_bytes,
            self.operation_timeout,
        );
        let inbound = pump_inbound(writer, self.inbound, self.operation_timeout);
        tokio::pin!(outbound);
        tokio::pin!(inbound);

        tokio::select! {
            result = &mut outbound => result,
            result = &mut inbound => result,
        }
    }
}

pub(crate) fn fragment_bytes(att_mtu: u16) -> Result<usize, PumpError> {
    if !(MIN_ATT_MTU..=MAX_ATT_MTU).contains(&att_mtu) {
        return Err(PumpError::InvalidAttMtu(att_mtu));
    }

    Ok(usize::min(usize::from(att_mtu - 3), MAX_FRAGMENT_BYTES))
}

async fn pump_outbound<Reader>(
    mut reader: Reader,
    outbound: mpsc::Sender<OutboundFragment>,
    fragment_bytes: usize,
    operation_timeout: Duration,
) -> Result<(), PumpError>
where
    Reader: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; fragment_bytes];
    loop {
        // There is deliberately no idle timeout: an authenticated Keyferry
        // session may be idle indefinitely. Deadlines begin only after bytes
        // require a GATT operation.
        let count = reader
            .read(&mut buffer)
            .await
            .map_err(|error| PumpError::StreamRead(error.kind()))?;
        if count == 0 {
            return Err(PumpError::StreamClosed);
        }

        let (acknowledgement, acknowledged) = oneshot::channel();
        let fragment = OutboundFragment {
            bytes: buffer[..count].to_vec(),
            acknowledgement: Some(acknowledgement),
        };
        match timeout(operation_timeout, outbound.send(fragment)).await {
            Err(_) => return Err(PumpError::OutboundDispatchTimeout),
            Ok(Err(_)) => return Err(PumpError::OutboundChannelClosed),
            Ok(Ok(())) => {}
        }

        match timeout(operation_timeout, acknowledged).await {
            Err(_) => return Err(PumpError::OutboundAcknowledgementTimeout),
            Ok(Err(_)) => return Err(PumpError::OutboundChannelClosed),
            Ok(Ok(WriteAck::Rejected)) => return Err(PumpError::OutboundWriteRejected),
            Ok(Ok(WriteAck::Acknowledged)) => {}
        }
    }
}

async fn pump_inbound<Writer>(
    mut writer: Writer,
    mut inbound: mpsc::Receiver<QueuedInbound>,
    operation_timeout: Duration,
) -> Result<(), PumpError>
where
    Writer: AsyncWrite + Unpin,
{
    while let Some(fragment) = inbound.recv().await {
        match timeout(operation_timeout, writer.write_all(&fragment.bytes)).await {
            Err(_) => return Err(PumpError::InboundWriteTimeout),
            Ok(Err(error)) => return Err(PumpError::StreamWrite(error.kind())),
            Ok(Ok(())) => {}
        }
    }
    Err(PumpError::InboundChannelClosed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{duplex, AsyncReadExt, AsyncWriteExt},
        runtime::Builder,
    };

    const TEST_TIMEOUT: Duration = Duration::from_millis(200);

    fn run_test(test: impl std::future::Future<Output = ()>) {
        Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime")
            .block_on(test);
    }

    #[test]
    fn mtu_validation_bounds_fragment_size() {
        assert_eq!(fragment_bytes(22), Err(PumpError::InvalidAttMtu(22)));
        assert_eq!(fragment_bytes(23), Ok(20));
        assert_eq!(fragment_bytes(247), Ok(244));
        assert_eq!(fragment_bytes(517), Ok(244));
        assert_eq!(fragment_bytes(518), Err(PumpError::InvalidAttMtu(518)));
        assert!(matches!(
            BytePump::new(23, Duration::ZERO),
            Err(PumpError::InvalidOperationTimeout)
        ));
    }

    #[test]
    fn outbound_is_ordered_fragmented_and_single_flight() {
        run_test(async {
            let (pump, mut gatt) = BytePump::new(23, TEST_TIMEOUT).expect("pump");
            let (stream, mut peer) = duplex(512);
            let pump_task = tokio::spawn(pump.run(stream));
            let payload: Vec<u8> = (0_u8..53).collect();
            peer.write_all(&payload).await.expect("write source bytes");

            let first = gatt.outbound.recv().await.expect("first fragment");
            assert_eq!(first.bytes(), &payload[..20]);
            assert!(timeout(Duration::from_millis(20), gatt.outbound.recv())
                .await
                .is_err());
            assert!(first.acknowledge(WriteAck::Acknowledged));

            let mut received = payload[..20].to_vec();
            while received.len() < payload.len() {
                let fragment = gatt.outbound.recv().await.expect("next fragment");
                assert!(!fragment.bytes().is_empty());
                assert!(fragment.bytes().len() <= 20);
                received.extend_from_slice(fragment.bytes());
                assert!(fragment.acknowledge(WriteAck::Acknowledged));
            }
            assert_eq!(received, payload);

            peer.shutdown().await.expect("close source");
            assert_eq!(
                pump_task.await.expect("pump task"),
                Err(PumpError::StreamClosed)
            );
        });
    }

    #[test]
    fn inbound_rejects_invalid_fragments_and_preserves_bytes() {
        run_test(async {
            let (pump, gatt) = BytePump::new(247, TEST_TIMEOUT).expect("pump");
            let inbound = gatt.inbound.clone();
            let (stream, mut peer) = duplex(512);
            let pump_task = tokio::spawn(pump.run(stream));

            assert_eq!(inbound.try_send(Vec::new()), Err(InboundSubmitError::Empty));
            assert_eq!(
                inbound.try_send(vec![0; 245]),
                Err(InboundSubmitError::Oversize {
                    size: 245,
                    maximum: 244,
                })
            );

            let first: Vec<u8> = (0_u8..=127).collect();
            let second: Vec<u8> = (128_u8..=255).collect();
            inbound.try_send(first.clone()).expect("first fragment");
            inbound.try_send(second.clone()).expect("second fragment");

            let mut received = vec![0_u8; first.len() + second.len()];
            peer.read_exact(&mut received)
                .await
                .expect("read forwarded bytes");
            assert_eq!(received, [first, second].concat());

            drop(inbound);
            drop(gatt.inbound);
            assert_eq!(
                pump_task.await.expect("pump task"),
                Err(PumpError::InboundChannelClosed)
            );
        });
    }

    #[test]
    fn inbound_queue_and_byte_budget_are_bounded() {
        let (_pump, gatt) = BytePump::new(247, TEST_TIMEOUT).expect("pump");
        for _ in 0..(MAX_PENDING_BYTES / MAX_FRAGMENT_BYTES) {
            gatt.inbound
                .try_send(vec![0; MAX_FRAGMENT_BYTES])
                .expect("fragment within budget");
        }
        assert_eq!(
            gatt.inbound.try_send(vec![0; MAX_FRAGMENT_BYTES]),
            Err(InboundSubmitError::ByteBudgetExhausted)
        );

        let (_pump, gatt) = BytePump::new(23, TEST_TIMEOUT).expect("second pump");
        for _ in 0..INBOUND_CHANNEL_SLOTS {
            gatt.inbound.try_send(vec![0]).expect("queue slot");
        }
        assert_eq!(
            gatt.inbound.try_send(vec![0]),
            Err(InboundSubmitError::QueueFull)
        );
    }

    #[test]
    fn inbound_queue_does_not_retain_spare_vector_capacity() {
        let (mut pump, gatt) = BytePump::new(23, TEST_TIMEOUT).expect("pump");
        let mut oversized_allocation = Vec::with_capacity(MAX_PENDING_BYTES);
        oversized_allocation.push(0x5a);
        gatt.inbound
            .try_send(oversized_allocation)
            .expect("valid short fragment");

        let queued = pump.inbound.try_recv().expect("queued fragment");
        assert_eq!(queued.bytes, [0x5a]);
        assert_eq!(queued.bytes.capacity(), queued.bytes.len());
    }

    #[test]
    fn rejected_or_unacknowledged_write_closes_pump() {
        run_test(async {
            let (pump, mut gatt) = BytePump::new(23, TEST_TIMEOUT).expect("pump");
            let (stream, mut peer) = duplex(64);
            let pump_task = tokio::spawn(pump.run(stream));
            peer.write_all(b"reject").await.expect("write source bytes");
            let fragment = gatt.outbound.recv().await.expect("fragment");
            assert!(fragment.acknowledge(WriteAck::Rejected));
            assert_eq!(
                pump_task.await.expect("pump task"),
                Err(PumpError::OutboundWriteRejected)
            );

            let short_timeout = Duration::from_millis(20);
            let (pump, mut gatt) = BytePump::new(23, short_timeout).expect("second pump");
            let (stream, mut peer) = duplex(64);
            let pump_task = tokio::spawn(pump.run(stream));
            peer.write_all(b"timeout")
                .await
                .expect("write source bytes");
            let _held_fragment = gatt.outbound.recv().await.expect("fragment");
            assert_eq!(
                pump_task.await.expect("pump task"),
                Err(PumpError::OutboundAcknowledgementTimeout)
            );
        });
    }

    #[test]
    fn blocked_inbound_stream_write_times_out() {
        run_test(async {
            let short_timeout = Duration::from_millis(20);
            let (pump, gatt) = BytePump::new(247, short_timeout).expect("pump");
            let (stream, _peer) = duplex(1);
            gatt.inbound
                .try_send(vec![0x5a; MAX_FRAGMENT_BYTES])
                .expect("inbound fragment");
            assert_eq!(pump.run(stream).await, Err(PumpError::InboundWriteTimeout));
        });
    }
}
