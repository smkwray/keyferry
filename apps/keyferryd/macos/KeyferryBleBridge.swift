import CoreBluetooth
import CryptoKit
import Darwin
import Foundation

// This helper owns only CoreBluetooth. Standard input and output are an opaque,
// bidirectional TLS byte stream; all diagnostics go to standard error. It never
// receives Keyferry credentials and never parses protocol or command bytes.

private let serviceUUID = CBUUID(string: "A2E3F2A8-A4FF-4ED8-9B68-DDE0E3AD7691")
private let gatewayToDeviceUUID = CBUUID(string: "74BEFF36-3449-44DF-8DAF-0DA9C136F4AB")
private let deviceToGatewayUUID = CBUUID(string: "C912CBBF-A2F9-418F-985C-CC6279389C54")
private let setupTimeout: TimeInterval = 18
private let maximumFragmentBytes = 244
private let operationTimeout: TimeInterval = 8
private let maximumPendingOutputBytes = 8192

// BEGIN TESTABLE STREAM IO
// read(upToCount:) can accumulate a short pipe read while waiting to fill its
// requested length. A TLS byte pipe must forward *any* positive read promptly.
private enum BridgeStreamIO {
    static func readSome(_ fd: Int32, maximum: Int) throws -> Data {
        guard maximum > 0 else { throw POSIXError(.EINVAL) }
        var storage = [UInt8](repeating: 0, count: maximum)
        while true {
            let count = storage.withUnsafeMutableBytes {
                Darwin.read(fd, $0.baseAddress!, $0.count)
            }
            if count >= 0 { return Data(storage.prefix(count)) }
            let code = errno
            if code == EINTR { continue }
            throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
        }
    }

    static func makeNonblocking(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }

    // fd must be nonblocking. Account for short writes; retry only the
    // unwritten suffix. This is local pipe I/O, never a BLE/application retry.
    static func writeAll(_ fd: Int32, data: Data, deadline: DispatchTime) throws {
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < deadline.uptimeNanoseconds else {
                    throw POSIXError(.ETIMEDOUT)
                }
                let count = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count > 0 { offset += count; continue }
                let code = count == 0 ? EIO : errno
                if code == EINTR { continue }
                guard code == EAGAIN || code == EWOULDBLOCK else {
                    throw POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
                }
                let remaining = deadline.uptimeNanoseconds - now
                let milliseconds = Int32(min((remaining + 999_999) / 1_000_000, UInt64(Int32.max)))
                var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                let result = Darwin.poll(&descriptor, 1, milliseconds)
                if result < 0 && errno != EINTR {
                    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                }
                if result == 0 { throw POSIXError(.ETIMEDOUT) }
                if result > 0 && (descriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                    throw POSIXError(.EPIPE)
                }
            }
        }
    }
}
// END TESTABLE STREAM IO

private func diagnostic(_ message: String) {
    FileHandle.standardError.write(Data("Keyferry Bluetooth: \(message)\n".utf8))
}

final class Bridge: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {
    private let queue = DispatchQueue(label: "io.github.smkwray.keyferry.bluetooth")
    private var manager: CBCentralManager!
    private var peripheral: CBPeripheral?
    private var gatewayToDevice: CBCharacteristic?
    private var deviceToGateway: CBCharacteristic?
    private var setupDeadline: DispatchWorkItem?
    private var ready = false
    private var stopping = false
    private var readInFlight = false
    private var writeInFlight = false
    private var fragmentBytes = 0
    private var setupStage = "manager-start"
    private let outputQueue = DispatchQueue(label: "io.github.smkwray.keyferry.bluetooth.stdout")
    private var pendingOutputBytes = 0
    private var preReadyIndications: [Data] = []
    private var writeDeadline: DispatchWorkItem?
    private var pendingWrite: Data?
    private var writeSerial: UInt64 = 0
    private let trace = ProcessInfo.processInfo.environment["KEYFERRY_BLE_DIAGNOSTICS"] == "1"
    private let startedAt = DispatchTime.now().uptimeNanoseconds
    private var readBytes: UInt64 = 0
    private var acknowledgedBytes: UInt64 = 0
    private var indicationBytes: UInt64 = 0
    private var deliveredBytes: UInt64 = 0
    private var readHash = SHA256()
    private var acknowledgedHash = SHA256()
    private var indicationHash = SHA256()
    private var deliveredHash = SHA256()

    func start() {
        // All mutable state, including manager construction, belongs to queue.
        queue.async { [self] in startOnQueue() }
    }

    private func startOnQueue() {
        do {
            try BridgeStreamIO.makeNonblocking(STDOUT_FILENO)
        } catch {
            fail("daemon byte stream configuration failed")
            return
        }
        manager = CBCentralManager(
            delegate: self,
            queue: queue,
            options: [CBCentralManagerOptionShowPowerAlertKey: true]
        )
        let deadline = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard !self.ready else { return }
            self.fail("setup timed out at \(self.setupStage)")
        }
        setupDeadline = deadline
        queue.asyncAfter(deadline: .now() + setupTimeout, execute: deadline)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard !stopping else { return }
        switch central.state {
        case .poweredOn:
            advance("scanning")
            central.scanForPeripherals(
                withServices: [serviceUUID],
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
            )
        case .unauthorized:
            fail("Bluetooth permission is not granted")
        case .unsupported:
            fail("Bluetooth Low Energy is unsupported")
        case .poweredOff:
            fail("Bluetooth is powered off")
        case .resetting:
            fail("Bluetooth is resetting")
        case .unknown:
            break
        @unknown default:
            fail("Bluetooth entered an unknown state")
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover candidate: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard !stopping, peripheral == nil else { return }
        let advertised = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? []
        guard advertised.contains(serviceUUID) else { return }
        advance("connecting")
        central.stopScan()
        peripheral = candidate
        candidate.delegate = self
        central.connect(candidate, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard owns(peripheral), !stopping else { return }
        advance("service-discovery")
        peripheral.discoverServices([serviceUUID])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        guard owns(peripheral) else { return }
        fail("connection failed")
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        guard owns(peripheral) else { return }
        fail("connection closed")
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard owns(peripheral), !stopping else { return }
        guard error == nil,
              let services = peripheral.services?.filter({ $0.uuid == serviceUUID }),
              services.count == 1
        else {
            fail("service discovery failed\(errorSuffix(error))")
            return
        }
        advance("characteristic-discovery")
        peripheral.discoverCharacteristics(
            [gatewayToDeviceUUID, deviceToGatewayUUID],
            for: services[0]
        )
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard owns(peripheral), !stopping, service.uuid == serviceUUID else { return }
        guard error == nil, let characteristics = service.characteristics else {
            fail("characteristic discovery failed\(errorSuffix(error))")
            return
        }
        let writes = characteristics.filter { $0.uuid == gatewayToDeviceUUID }
        let indications = characteristics.filter { $0.uuid == deviceToGatewayUUID }
        guard writes.count == 1,
              indications.count == 1,
              writes[0].properties == .write,
              indications[0].properties == .indicate
        else {
            fail("characteristic contract is incompatible")
            return
        }
        gatewayToDevice = writes[0]
        deviceToGateway = indications[0]
        advance("indication-subscription")
        peripheral.setNotifyValue(true, for: indications[0])
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard owns(peripheral),
              !stopping,
              characteristic === deviceToGateway
        else { return }
        guard error == nil, characteristic.isNotifying else {
            fail("indication subscription failed")
            return
        }
        // A repeated successful subscription event must not inject another
        // private ready header into the TLS stream.
        guard !ready else { return }
        let available = peripheral.maximumWriteValueLength(for: .withResponse)
        guard available >= 20 else {
            fail("negotiated Bluetooth write length is too small")
            return
        }
        fragmentBytes = min(available, maximumFragmentBytes)
        setupDeadline?.cancel()
        setupDeadline = nil
        ready = true
        advance("ready")

        let header = Data([
            0x4b, 0x46, 0x4d, 0x42,
            0x00, 0x01,
            UInt8((fragmentBytes >> 8) & 0xff),
            UInt8(fragmentBytes & 0xff),
        ])
        enqueueOutput(header, isTLS: false)
        let early = preReadyIndications
        preReadyIndications.removeAll(keepingCapacity: false)
        // Early values already count against the same output byte budget.
        for value in early { dispatchOutput(value, isTLS: true) }
        scheduleRead()
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard owns(peripheral),
              !stopping,
              characteristic === gatewayToDevice
        else { return }
        guard writeInFlight, let value = pendingWrite else {
            fail("unexpected Bluetooth write acknowledgement")
            return
        }
        writeDeadline?.cancel()
        writeDeadline = nil
        writeInFlight = false
        pendingWrite = nil
        guard error == nil else {
            fail("Bluetooth write failed\(errorSuffix(error))")
            return
        }
        acknowledgedBytes += UInt64(value.count)
        if trace { acknowledgedHash.update(data: value) }
        traceEvent("write-ack")
        scheduleRead()
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard owns(peripheral),
              !stopping,
              characteristic === deviceToGateway
        else { return }
        guard error == nil,
              let value = characteristic.value,
              !value.isEmpty,
              value.count <= maximumFragmentBytes
        else {
            fail("Bluetooth indication was invalid")
            return
        }
        indicationBytes += UInt64(value.count)
        if trace { indicationHash.update(data: value) }
        traceEvent("indication")
        // Own an exact-size copy before leaving the delegate callback.
        let owned = value.withUnsafeBytes { Data(bytes: $0.baseAddress!, count: $0.count) }
        if !ready {
            guard pendingOutputBytes + owned.count + 8 <= maximumPendingOutputBytes else {
                fail("pre-ready indication byte budget exceeded")
                return
            }
            pendingOutputBytes += owned.count
            preReadyIndications.append(owned)
        } else {
            enqueueOutput(owned, isTLS: true)
        }
    }

    private func enqueueOutput(_ data: Data, isTLS: Bool) {
        guard !stopping else { return }
        guard pendingOutputBytes + data.count <= maximumPendingOutputBytes else {
            fail("daemon output byte budget exceeded")
            return
        }
        pendingOutputBytes += data.count
        dispatchOutput(data, isTLS: isTLS)
    }

    private func dispatchOutput(_ data: Data, isTLS: Bool) {
        // A blocked stdout must not block CoreBluetooth callbacks or timers.
        // Include queueing time in the absolute operation deadline.
        let deadline = DispatchTime.now() + operationTimeout
        outputQueue.async { [weak self] in
            do {
                try BridgeStreamIO.writeAll(STDOUT_FILENO, data: data, deadline: deadline)
                self?.queue.async { [weak self] in
                    guard let self, !self.stopping else { return }
                    self.pendingOutputBytes -= data.count
                    if isTLS {
                        self.deliveredBytes += UInt64(data.count)
                        if self.trace { self.deliveredHash.update(data: data) }
                    }
                    self.traceEvent("stdout-complete")
                }
            } catch {
                self?.queue.async { [weak self] in
                    self?.fail("daemon output failed or exceeded operation deadline")
                }
            }
        }
    }

    private func scheduleRead() {
        guard ready,
              !stopping,
              !readInFlight,
              !writeInFlight,
              fragmentBytes >= 20
        else { return }
        readInFlight = true
        let length = fragmentBytes
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let data = try BridgeStreamIO.readSome(STDIN_FILENO, maximum: length)
                self?.queue.async { [weak self] in
                    self?.handleRead(data)
                }
            } catch {
                self?.queue.async { [weak self] in
                    self?.fail("daemon byte stream read failed")
                }
            }
        }
    }

    private func handleRead(_ data: Data) {
        readInFlight = false
        guard ready, !stopping else { return }
        guard !data.isEmpty else {
            fail("daemon byte stream closed")
            return
        }
        guard data.count <= fragmentBytes,
              let peripheral,
              let gatewayToDevice,
              peripheral.state == .connected
        else {
            fail("Bluetooth write state is invalid")
            return
        }
        readBytes += UInt64(data.count)
        if trace { readHash.update(data: data) }
        traceEvent("stdin-read")
        writeInFlight = true
        pendingWrite = data
        writeSerial &+= 1
        let serial = writeSerial
        let deadline = DispatchWorkItem { [weak self] in
            guard let self, !self.stopping, self.writeInFlight,
                  self.writeSerial == serial else { return }
            self.fail("Bluetooth write acknowledgement timed out")
        }
        writeDeadline = deadline
        queue.asyncAfter(deadline: .now() + operationTimeout, execute: deadline)
        peripheral.writeValue(data, for: gatewayToDevice, type: .withResponse)
    }

    private func owns(_ candidate: CBPeripheral) -> Bool {
        peripheral === candidate
    }

    private func advance(_ stage: String) {
        setupStage = stage
        diagnostic("stage \(stage)")
    }

    private func errorSuffix(_ error: Error?) -> String {
        guard let error = error as NSError? else { return "" }
        return " (\(error.domain):\(error.code))"
    }

    private func traceEvent(_ event: String) {
        guard trace else { return }
        let elapsed = (DispatchTime.now().uptimeNanoseconds - startedAt) / 1_000_000
        diagnostic("event=\(event) elapsed_ms=\(elapsed) read_bytes=\(readBytes) ack_bytes=\(acknowledgedBytes) indication_bytes=\(indicationBytes) stdout_bytes=\(deliveredBytes)")
    }

    private func traceHashes() {
        guard trace else { return }
        func hex(_ hash: SHA256) -> String {
            hash.finalize().map { String(format: "%02x", $0) }.joined()
        }
        diagnostic("read_sha256=\(hex(readHash)) ack_sha256=\(hex(acknowledgedHash)) indication_sha256=\(hex(indicationHash)) stdout_sha256=\(hex(deliveredHash))")
    }

    private func fail(_ reason: String) {
        guard !stopping else { return }
        stopping = true
        ready = false
        setupDeadline?.cancel()
        setupDeadline = nil
        writeDeadline?.cancel()
        writeDeadline = nil
        traceEvent("close")
        traceHashes()
        manager?.stopScan()
        if let peripheral, peripheral.state != .disconnected {
            manager?.cancelPeripheralConnection(peripheral)
        }
        diagnostic(reason)
        Darwin.exit(EXIT_FAILURE)
    }
}

signal(SIGPIPE, SIG_IGN)
let bridge = Bridge()
bridge.start()
dispatchMain()
