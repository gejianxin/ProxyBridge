import NetworkExtension

/// Transparent proxy provider for the Rust helper.
///
/// This file is the Apple half of `--mode extension`. It is not compiled by
/// Cargo. A Mac with a Developer ID (or a development provisioning profile)
/// has to build and sign it. The entitlement is
/// `com.apple.developer.networking.networkextension` = `app-proxy-provider`.
/// System-extension approval is a user action in System Settings; this tree
/// does not notarize or install the extension.
///
/// The helper listens on 127.0.0.1:34080 and speaks the header in
/// `crates/proxybridge-platform/src/extension.rs`.
final class AppProxyProvider: NEAppProxyProvider {
    private let helper = NWEndpoint.hostPort(
        host: NWEndpoint.Host("127.0.0.1"),
        port: NWEndpoint.Port(rawValue: 34080)!
    )

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow,
              let remote = tcp.remoteEndpoint as? NWHostEndpoint,
              let port = UInt16(remote.port) else {
            return false
        }
        let connection = createTCPConnection(to: helper, enableTLS: false, tlsParameters: nil, delegate: nil)
        tcp.open(withLocalEndpoint: nil) { error in
            if error != nil {
                connection.cancel()
                return
            }
            self.writeHeader(connection: connection, flow: tcp, host: remote.hostname, port: port)
        }
        return true
    }

    private func writeHeader(connection: NWTCPConnection, flow: NEAppProxyTCPFlow, host: String, port: UInt16) {
        var bytes = Data([0x50, 0x42, 1, 1])
        let pid = flow.metaData.sourceAppSigningIdentifier.isEmpty ? UInt32(0) : UInt32(1)
        bytes.append(contentsOf: withUnsafeBytes(of: pid.bigEndian) { Data($0) })
        let path = flow.metaData.sourceAppSigningIdentifier.data(using: .utf8) ?? Data()
        let pathLen = UInt16(min(path.count, 1024)).bigEndian
        bytes.append(contentsOf: withUnsafeBytes(of: pathLen) { Data($0) })
        bytes.append(path.prefix(1024))
        if let v4 = IPv4Address(host) {
            bytes.append(1)
            bytes.append(contentsOf: v4.rawValue)
        } else if let v6 = IPv6Address(host) {
            bytes.append(2)
            bytes.append(contentsOf: v6.rawValue)
        } else {
            let name = host.data(using: .utf8) ?? Data()
            bytes.append(3)
            bytes.append(UInt8(min(name.count, 253)))
            bytes.append(name.prefix(253))
        }
        bytes.append(contentsOf: withUnsafeBytes(of: port.bigEndian) { Data($0) })
        connection.write(bytes) { error in
            if error != nil {
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                connection.cancel()
                return
            }
            self.readStatus(connection: connection, flow: flow)
        }
    }

    private func readStatus(connection: NWTCPConnection, flow: NEAppProxyTCPFlow) {
        connection.readMinimumLength(1, maximumLength: 1) { data, error in
            guard error == nil, let data, data.first == 1 else {
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                connection.cancel()
                return
            }
            self.pump(connection: connection, flow: flow)
        }
    }

    /// Copy until either side closes. A production build would bound memory
    /// and surface NEFlow errors; this is the working structure.
    private func pump(connection: NWTCPConnection, flow: NEAppProxyTCPFlow) {
        flow.readData { data, readError in
            if let data, !data.isEmpty {
                connection.write(data) { _ in
                    self.pump(connection: connection, flow: flow)
                }
                return
            }
            if readError != nil {
                connection.cancel()
            }
        }
    }
}
