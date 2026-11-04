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

`PROXYBRIDGE_CONFIG` selects a file. `--config` overrides that. `--no-config` ignores the file and starts from the built-in default. `./proxybridge.toml` is loaded automatically when you run from a directory that contains it.

With no rules in the file, one enabled catch-all rule proxies matching traffic. Loopback, multicast, broadcast, the unspecified address, IPv6 link-local, DHCP, port 53 (unless `dns_via_proxy` is true), and the proxy's own address stay direct. A proxy rule sends loopback only when `localhost = true`. Block and direct rules do not apply to loopback. This matches the original userspace matcher closely enough that the usual "don't proxy yourself" cases hold.

## What this build actually does

| Backend | Targets | Status |
| --- | --- | --- |
| `socks` | Linux x64, Linux arm64, Windows x64, macOS x64, macOS arm64 | Implemented. Userspace SOCKS5 listener. TCP CONNECT is relayed through SOCKS5 or HTTP CONNECT. UDP ASSOCIATE is relayed for SOCKS5 upstreams and for direct destinations. |
| `redirect` | Linux x64 and arm64 | Implemented for IPv4/IPv6 TCP. Listens locally, reads `SO_ORIGINAL_DST` after iptables `REDIRECT`, and marks its own sockets with `SO_MARK` so they are not redirected again. |
| WinDivert | Windows x64 | Stub. `start_windivert` returns an error. Use `--mode socks`. |
| Network Extension | macOS x64 and Apple Silicon | Stub. The Swift system extension is not reimplemented. Use `--mode socks`. Both architectures compile the userspace path. |

`proxybridge backends` prints this table from the binary.

Process-specific rules are attributed from `/proc` on Linux. On Windows and macOS the SOCKS client process is not identified yet, so only `process = "*"` rules match. Domain rules match the name the client asked for. If a rule contains an IP pattern and the client sent a domain, the engine resolves one address and matches against that. There is no DNS snooping of the application's own packets, which the C port does.

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

Transparent TCP (root or `CAP_NET_ADMIN`):

```bash
sudo ./target/release/proxybridge run --mode redirect
# the process prints iptables rules; or print them alone:
./target/release/proxybridge iptables --no-config
```

`redirect` is IPv4 and IPv6 TCP only. Transparent UDP is not implemented. The printed rules RETURN marked packets and, when the proxy host is an IP, packets addressed to that proxy, then `REDIRECT` other TCP to the listen port.

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

`cargo check --target x86_64-pc-windows-msvc` succeeds from Linux. Linking that target needs the MSVC linker on Windows, or `x86_64-pc-windows-gnu` with mingw-w64. `--mode redirect` is rejected on Windows. The WinDivert capture loop from the C port is not linked; calling the stub reports that plainly.

### macOS x64 and Apple Silicon

```bash
# Intel
rustup target add x86_64-apple-darwin
cargo check -p proxybridge-cli --target x86_64-apple-darwin

# Apple Silicon
rustup target add aarch64-apple-darwin
cargo check -p proxybridge-cli --target aarch64-apple-darwin
```

Linking a macOS binary needs a Mac (or a full osxcross SDK). Both architectures are supported by the userspace SOCKS backend. The Network Extension transparent proxy is a stub: it needs Apple entitlements and a signed system extension, and this tree does not claim to ship one. `--mode socks` is the path that runs. `--mode redirect` is rejected.

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
- Platform code is behind `crates/proxybridge-platform`. Linux TCP redirect is real. WinDivert and Network Extension are stubs that fail with an explicit error.
- The default upstream is SOCKS5 `127.0.0.1:7898` rather than "whatever the last GUI profile saved".
- No GUI, no update checker, no installer, and no eBPF program in the Rust build.
- Over-long patterns are rejected. The C splitter silently truncates a token at 255 bytes.

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the upstream findings and what is still open.

## Layout

```
Cargo.toml                      workspace
proxybridge.toml                example and default config
crates/proxybridge-core         config, rules, SOCKS5, HTTP CONNECT
crates/proxybridge-platform     socks inbound, Linux redirect, stubs
crates/proxybridge-cli          `proxybridge` binary
scripts/check-targets.sh        cargo check for the five targets
.github/workflows/rust.yml      test, clippy, and those checks
```

## Limitations

- Not a transparent proxy on Windows or macOS yet. Apps must use the SOCKS listener, or you stay on the original C/Swift build for kernel diversion.
- Linux transparent mode is TCP only and depends on iptables NAT `REDIRECT` plus `CAP_NET_ADMIN` for `SO_MARK`.
- No per-packet DNS snooping, so a transparent flow is matched by IP and port, not by the name the app looked up.
- Inbound SOCKS has no authentication. It binds to loopback unless you pass another `--listen`. A non-loopback bind is an open proxy on that interface; the process logs a warning.
- The engine does not decrypt TLS and does not modify application data.

## License

MIT. The copyright notice in [LICENSE](LICENSE) must stay with the original authors. New Rust files in this fork are offered under that same license.
