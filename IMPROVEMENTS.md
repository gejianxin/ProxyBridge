# Upstream findings and remaining work

ProxyBridge (upstream: [InterceptSuite/ProxyBridge](https://github.com/InterceptSuite/ProxyBridge)) is a local, per-application proxy client. The 4.x tree in this fork is large enough, and split enough, that a line-by-line translation would keep the problems. The Rust workspace replaces the shared behavior with one engine and makes the unfinished platform paths explicit.

## Why the C and Swift tree is hard to keep improving

The product is three programs that only share an idea of a rule.

- Windows is Win32 C on WinDivert (`Windows/src`, about a dozen translation units plus a GUI and a service). Packet capture, TCP reassembly, and the SOCKS5/HTTP clients sit next to the UI.
- Linux is a separate C engine (`Linux/src`) with an eBPF datapath (`Linux/src/bpf`), NFQUEUE-era pieces, a GTK GUI, and a root daemon. `ProxyBridge_Start` needs root, `CAP_BPF`/`CAP_SYS_ADMIN`, and a BTF kernel >= 5.11. The header says the BPF program is a compiled subset of the userspace matcher, so the two can disagree.
- macOS is a Swift app plus a Network Extension (`MacOS/ProxyBridge`). Transparent capture cannot run without Apple's extension, entitlements, and a signed build.

Concrete costs of that split:

- SOCKS5, HTTP CONNECT, rule languages, and profile JSON are implemented more than once. Windows rules take `target_domains` as their own argument. Linux folds domains into the host list. A fix on one OS does not land on the others.
- The Linux splitter (`split_list` in `Linux/src/pb_rules.c`) silently truncates a token at 255 bytes. Flow records cap the process name at 40 bytes and the host at 64 (`ProxyBridgeFlow` / `PB_FLOW`). Those bounds are easy to miss from the GUI.
- Windows caps the proxy list (`MAX_PROXY_CONFIGS` is 32). Linux does not. Profiles are not one schema.
- Each OS has its own tests and its own CI workflow. Nothing compiles the rule engine once and runs it on every target.
- Memory safety is manual across packet parsing, IPC, and the GUI. That is a large, long-lived surface for a tool that runs as root or with a kernel driver.

None of this is a reason the original is unusable. It is a reason a new default and a new platform should not start by copying all three stacks.

## What the Rust port changes

- `proxybridge-core` owns configuration, the first-match rule engine, SOCKS5 (TCP CONNECT and UDP ASSOCIATE), and HTTP CONNECT. Tests cover the matcher, the default endpoint, and handshakes against local mocks.
- The coded default upstream is SOCKS5 `127.0.0.1:7898`, including omitted TOML fields. Environment variables and CLI flags override it. The example file `proxybridge.toml` records the same values.
- `proxybridge-platform` has a userspace SOCKS inbound on every OS, a Linux TCP and UDP redirect path, a WinDivert 2.2 IPv4 rewrite loop, and a Network Extension helper. `proxybridge backends` says the driver and the Apple signature are still required on those hosts.
- CI runs `cargo test` and `cargo clippy` on Linux x64, and `cargo check` for Linux x64, Linux arm64, Windows x64, macOS x64, and macOS arm64.
- Patterns that do not fit are errors. They are not truncated.

Behavior kept on purpose, because changing it would surprise people coming from the C port:

- No matching rule means direct.
- Loopback stays direct unless the matching rule is `proxy` and `localhost = true`. Block and direct rules do not apply to loopback.
- Multicast, broadcast, `0.0.0.0/8`, IPv6 link-local, DHCP, and port 53 (unless `dns_via_proxy`) stay direct.
- Traffic to the configured proxy address stays direct so the tunnel is not sent into itself.

## What landed after the first Rust commit

- **WinDivert (Windows x64).** `packet.rs` parses and rewrites IPv4 TCP/UDP, keeps a NAT table, and is unit tested on Linux. `windivert_driver.rs` loads WinDivert 2.2 (`WinDivertOpen` / `Recv` / `Send` / `Shutdown`) and feeds the shared `decide` function. Process ownership uses `GetExtendedTcpTable` and `GetExtendedUdpTable`. The DLL and `WinDivert64.sys` are not in the repo. `--mode windivert` on a non-Windows host says so. A Windows machine still has to install the driver, run elevated, and confirm a real flow.
- **Network Extension (macOS x64 and Apple Silicon).** `--mode extension` is a tested TCP helper (`PB` header, then a raw stream). `macos/NetworkExtension/AppProxyProvider.swift` is an `NEAppProxyProvider` that writes that header. The entitlement file asks for `app-proxy-provider`. Nothing here is signed or notarized. `cargo check` covers both Darwin targets; Xcode on a Mac has to produce the extension.
- **Linux transparent UDP and DNS.** iptables `REDIRECT` for UDP, `IP_RECVORIGDSTADDR`, and `IP_TRANSPARENT` replies. DNS responses that the process forwards are parsed (A and AAAA, compression pointers) and stored. A later flow to that address matches a domain rule. DoH and DoT still bypass it.
- **Process match.** Linux `/proc` now covers UDP as well as TCP. Windows uses the IP helper owner-PID tables. macOS walks libproc using the xnu `proc_info.h` layout (the `In4In6` size is asserted). The macOS walk has not been executed on a Mac.

## Still open

1. Run `--mode windivert` on Windows x64 with the official driver and fix whatever the live address flags or checksums do differently from the unit tests. IPv6 rewrite is not implemented.
2. Build and sign the Swift provider on a Mac, then confirm `handleNewFlow` against the helper. The extension currently copies app-to-helper bytes; a production copy would also pump helper-to-app data with backpressure.
3. cgroup or eBPF identity on Linux. `/proc` still races with PID reuse.
4. A GUI, and an importer for the old `.pbprofile` JSON, only after this config file stays the one format.
5. Inbound authentication if the SOCKS listener is ever bound off loopback.

Until the Windows driver and the Apple signature are exercised on those hosts, `--mode socks` is the path that is known to run everywhere, and `--mode redirect` is the transparent path known to run on Linux.
