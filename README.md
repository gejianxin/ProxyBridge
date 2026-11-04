# ProxyBridge (Rust)

ProxyBridge routes TCP and UDP from applications on your own machine through a SOCKS5 or HTTP proxy. It is a local proxy client in the same family as Proxifier: it does not inspect or modify payloads, and it does not capture traffic from other machines.

This repository is a fork of [InterceptSuite/ProxyBridge](https://github.com/InterceptSuite/ProxyBridge). The original project is three separate programs (Win32 C + WinDivert, Linux C + eBPF/NFQUEUE, and a Swift Network Extension). This fork adds a Rust workspace that shares one rule engine and one proxy client across platforms. The original C and Swift trees are still in `Windows/`, `Linux/`, and `MacOS/` as the upstream reference. They are not built by the Rust workflow.

The Rust port is MIT licensed, the same license as the original. Copyright (c) 2025 Anof-cyber/InterceptSuite. See [LICENSE](LICENSE).

## Default proxy

The coded default upstream is **SOCKS5 at `127.0.0.1:7898`**.

That default is used when no config file is loaded. It is also the default for every omitted field in `[proxy]`, and it is what [`proxybridge.toml`](proxybridge.toml) ships with. Override it in any of these ways; later ones win:

| Source | Example |
| --- | --- |
| Config file | `[proxy]` `type`, `host`, `port` in `proxybridge.toml` |
| Environment | `PROXYBRIDGE_PROXY_TYPE`, `PROXYBRIDGE_PROXY_HOST`, `PROXYBRIDGE_PROXY_PORT`, plus `PROXYBRIDGE_PROXY_USERNAME`, `PROXYBRIDGE_PROXY_PASSWORD`, `PROXYBRIDGE_SEND_DOMAIN`, `PROXYBRIDGE_DNS_VIA_PROXY`, `PROXYBRIDGE_ENABLED` |
| CLI | `--proxy socks5://127.0.0.1:7898`, or `--proxy-type`, `--proxy-host`, `--proxy-port`, `--proxy-user`, `--proxy-pass` |

`PROXYBRIDGE_CONFIG` selects a file. `--config` overrides that and accepts either `proxybridge.toml` or a Proxifier `.ppx`. `--no-config` ignores the file and starts from the built-in default. `./proxybridge.toml` is loaded automatically when you run from a directory that contains it.

`profiles/user-proxifier-profile.ppx` is a Proxifier 102 profile (SOCKS5 `127.0.0.1:7898`). `profiles/user-proxifier-profile.toml` is the same rules in this project's format. Release zips ship both, and use the converted file as `proxybridge.toml`.

With no rules in the file, one enabled catch-all rule proxies matching traffic. Loopback, multicast, broadcast, the unspecified address, IPv6 link-local, DHCP, port 53 (unless `dns_via_proxy` is true), and the proxy's own address stay direct. A proxy rule sends loopback only when `localhost = true`. Block and direct rules do not apply to loopback. This matches the original userspace matcher closely enough that the usual "don't proxy yourself" cases hold.

## What this build actually does

| Backend | Targets | Status |
| --- | --- | --- |
| `socks` | Linux x64, Linux arm64, Windows x64, macOS x64, macOS arm64 | Implemented. Userspace SOCKS5 listener. TCP CONNECT is relayed through SOCKS5 or HTTP CONNECT. UDP ASSOCIATE is relayed for SOCKS5 upstreams and for direct destinations. |
| `redirect` | Linux x64 and arm64 | Implemented for TCP (`SO_ORIGINAL_DST`) and UDP (`IP_RECVORIGDSTADDR`). DNS replies this process forwards are remembered so a later flow can match a domain rule. |
| `windivert` | Windows x64 | Implemented against the WinDivert 2.2 ABI. IPv4 TCP and UDP are rewritten to a local listener. The DLL and `WinDivert64.sys` are not bundled; a Windows host must install them and run elevated. |
| `extension` | macOS x64 and Apple Silicon | The Rust helper is implemented. The Swift `NEAppProxyProvider` is in `macos/NetworkExtension` and must be signed on a Mac. This build does not notarize it. |

`proxybridge backends` prints this table from the binary.

Process rules use `/proc` on Linux, the IP helper tables (`GetExtendedTcpTable` / `GetExtendedUdpTable`) on Windows, and libproc on macOS. The macOS layout follows xnu `proc_info.h` and still needs a Mac to confirm a live socket. The Network Extension sends the app signing identifier in the flow header, because the helper's TCP peer is the extension, not the app. Domain rules match a name the client sent, or a name learned from a DNS reply that ProxyBridge itself forwarded. DoH and DoT are not visible.

## Release zips

Runtime-only archives live in `dist/` and are rebuilt by [`.github/workflows/release-zips.yml`](.github/workflows/release-zips.yml). Each zip has the release binary, `proxybridge.toml` (the converted Proxifier profile, SOCKS5 `127.0.0.1:7898`), `profiles/user-proxifier-profile.ppx`, `profiles/user-proxifier-profile.toml`, and `README-run.txt`. No source, tests, or CI files are inside.

| Zip | How it is produced |
| --- | --- |
| `dist/proxybridge-linux-x64.zip` | This repo, `scripts/package-release.sh x86_64-unknown-linux-gnu proxybridge-linux-x64` |
| `dist/proxybridge-linux-arm64.zip` | Same script with `aarch64-unknown-linux-gnu` |
| `dist/proxybridge-windows-x64.zip` | Windows linker. The zip adds unmodified WinDivert 2.2.2 `WinDivert.dll` and `WinDivert64.sys` when the download works, plus `LICENSE-WinDivert.txt` and `NOTICE.txt`. |
| `dist/proxybridge-macos-arm64.zip` | macOS runner in the workflow. Not linked from Linux. |
| `dist/proxybridge-macos-x64.zip` | macOS runner in the workflow. Not linked from Linux. |

On a published GitHub release the workflow attaches those zips. Pull requests upload them as Actions artifacts.

## Build

Rust 1.85 or newer. From the repository root:

```bash
cargo test --workspace
cargo build --release -p proxybridge-cli
# binary: target/release/proxybridge
```

Check every named target (no linker required):

```bash
./scripts/check-targets.sh
```

That runs `cargo check --workspace` for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

### Linux x64

```bash
cargo build --release -p proxybridge-cli
./target/release/proxybridge run --mode socks
```

The SOCKS inbound listens on `127.0.0.1:2080` unless `--listen` is set. Point a proxy-aware app at it, or use it as the local side while you develop rules. The upstream is `127.0.0.1:7898` unless overridden.

Transparent TCP and UDP (root or `CAP_NET_ADMIN`):

```bash
sudo ./target/release/proxybridge run --mode redirect
# the process prints iptables rules; or print them alone:
./target/release/proxybridge iptables --no-config
```

The printed rules RETURN marked packets and, when the proxy host is an IP, packets addressed to that proxy, then `REDIRECT` other IPv4 TCP and UDP to the listen port. UDP replies use `IP_TRANSPARENT` so the application sees the original source. Without `CAP_NET_ADMIN` the reply cannot be spoofed.

### Linux arm64

The code is the same as Linux x64. On an arm64 machine:

```bash
cargo build --release -p proxybridge-cli
```

From an x64 machine, install an aarch64 linker and build:

```bash
sudo apt-get install gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-gnu
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release -p proxybridge-cli --target aarch64-unknown-linux-gnu
```

`cargo check --target aarch64-unknown-linux-gnu` does not need the linker. CI does that check.

### Windows x64

Userspace mode is ordinary Rust and does not need WinDivert:

```powershell
cargo build --release -p proxybridge-cli
.\target\release\proxybridge.exe run --mode socks
```

`cargo check --target x86_64-pc-windows-msvc` succeeds from Linux and compiles the WinDivert loop. Linking that target needs the MSVC linker on Windows, or `x86_64-pc-windows-gnu` with mingw-w64.

```powershell
.\target\release\proxybridge.exe run --mode windivert
```

That mode loads `WinDivert.dll` (WinDivert 2.2) and rewrites outbound IPv4 TCP and UDP toward `127.0.0.1:34010`, then relays them with the shared engine. Place `WinDivert.dll` and `WinDivert64.sys` next to the executable and run elevated. This repository does not ship those files, and the driver has not been executed in this environment. `--mode redirect` stays Linux-only.

### macOS x64 and Apple Silicon

```bash
# Intel
rustup target add x86_64-apple-darwin
cargo check -p proxybridge-cli --target x86_64-apple-darwin

# Apple Silicon
rustup target add aarch64-apple-darwin
cargo check -p proxybridge-cli --target aarch64-apple-darwin
```

Linking a macOS binary needs a Mac (or a full osxcross SDK). Both architectures compile `--mode socks`, the libproc lookup, and `--mode extension`.

```bash
./target/release/proxybridge run --mode extension
```

The helper listens on `127.0.0.1:34080`. `macos/NetworkExtension/AppProxyProvider.swift` is an `NEAppProxyProvider` that speaks that header. `ProxyBridgeExtension.entitlements` asks for `app-proxy-provider`. Apple has to sign the extension with a development or Developer ID profile; this tree has no provisioning profile and does not notarize anything. `--mode redirect` is rejected. `--mode windivert` is rejected.

## Rules and commands

```bash
proxybridge config --no-config
proxybridge decide --no-config --dest 8.8.8.8:443 --process curl --proto tcp
proxybridge run --mode socks --verbose 1
proxybridge iptables --listen-port 34010
proxybridge backends
```

Rules are first-match. Patterns follow the original Linux matcher:

- Process: globs against the full path and the file name. Lists split on `,` or `;`. `*` or empty matches any. Windows matches process names case-insensitively.
- Hosts: IPv4 and IPv6, CIDR, `a.b.c.d-e.f.g.h` ranges, octet wildcards (`192.168.*.*`, `10.1-2.*.5`), and domain globs (`*.example.com`). A token with a letter is a domain. A token with `:` is IPv6.
- Ports: `80,443,8000-9000`. `*` or empty matches any.
- Protocol: `tcp`, `udp`, or `both`.
- Action: `proxy`, `direct`, or `block`.

`send_domain = true` (the default) sends the hostname to the proxy. `false` resolves first and sends the address. HTTP upstreams can carry TCP CONNECT only; UDP through an HTTP proxy is dropped.

## Differences from the C/Swift project

- One Cargo workspace instead of a Win32 tree, a GTK/eBPF tree, and an Xcode app.
- Rules, SOCKS5, and HTTP CONNECT live in `crates/proxybridge-core` and are tested without a driver.
- Platform code is behind `crates/proxybridge-platform`. Linux redirect covers TCP and UDP. WinDivert is a real 2.2 capture loop that still needs the driver on Windows. The Network Extension helper runs everywhere; the Swift provider still needs a signature.
- The default upstream is SOCKS5 `127.0.0.1:7898` rather than "whatever the last GUI profile saved".
- No GUI, no update checker, no installer, and no eBPF program in the Rust build.
- Over-long patterns are rejected. The C splitter silently truncates a token at 255 bytes.

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the upstream findings and what is still open.

## Layout

```
Cargo.toml                      workspace
proxybridge.toml                example and default config
crates/proxybridge-core         config, rules, SOCKS5, HTTP CONNECT
crates/proxybridge-platform     socks, Linux redirect, WinDivert, extension helper
macos/NetworkExtension         Swift provider, entitlements, Info.plist
crates/proxybridge-cli          `proxybridge` binary
scripts/check-targets.sh        cargo check for the five targets
.github/workflows/rust.yml      test, clippy, and those checks
```

## Limitations

- Windows transparent mode needs WinDivert installed and has not been run on a Windows machine from this environment. IPv6 packets are passed through unchanged.
- macOS transparent mode needs the Swift provider built and signed on a Mac. The helper protocol is tested here; the extension binary is not.
- Linux transparent UDP spoofed replies need `CAP_NET_ADMIN`. DNS learning covers replies that ProxyBridge forwards, not DoH/DoT and not answers that never pass through the process.
- The macOS libproc layout is checked for size, not against a live socket, until it runs on a Mac.
- Inbound SOCKS has no authentication. It binds to loopback unless you pass another `--listen`. A non-loopback bind is an open proxy on that interface; the process logs a warning.
- The engine does not decrypt TLS and does not modify application data.

## License

MIT. The copyright notice in [LICENSE](LICENSE) must stay with the original authors. New Rust files in this fork are offered under that same license.
