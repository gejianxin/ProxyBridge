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
- `proxybridge-platform` has a real userspace SOCKS inbound on every OS, plus a Linux TCP redirect listener (`SO_ORIGINAL_DST`, `SO_MARK`, generated iptables). WinDivert and the macOS Network Extension are functions that return a clear error. `proxybridge backends` prints the same status.
- CI runs `cargo test` and `cargo clippy` on Linux x64, and `cargo check` for Linux x64, Linux arm64, Windows x64, macOS x64, and macOS arm64.
- Patterns that do not fit are errors. They are not truncated.

Behavior kept on purpose, because changing it would surprise people coming from the C port:

- No matching rule means direct.
- Loopback stays direct unless the matching rule is `proxy` and `localhost = true`. Block and direct rules do not apply to loopback.
- Multicast, broadcast, `0.0.0.0/8`, IPv6 link-local, DHCP, and port 53 (unless `dns_via_proxy`) stay direct.
- Traffic to the configured proxy address stays direct so the tunnel is not sent into itself.

## Remaining work

In rough order of what would make the Rust build a full replacement:

1. Windows transparent capture. Link WinDivert (driver + DLL), map the flow to a process with the extended TCP/UDP tables, and feed the shared `decide` function. Do not claim this until a Windows VM can pass a TCP and UDP test.
2. macOS transparent capture. That is a Network Extension target with its own signing story, not a `cfg` block inside the CLI. Intel and Apple Silicon would share the extension code the way the userspace SOCKS path already does.
3. Linux transparent UDP, and DNS snooping so a redirected flow can match a domain the app resolved. The C port learns names from unencrypted DNS; DoH still bypasses that.
4. Stronger Linux process identity (cgroup or eBPF) for the redirect path. `/proc` lookup works for the tests here and loses the race under PID reuse or hidden network namespaces.
5. A small GUI or tray only after the engine's config file is the one format every OS edits. Importing the old `.pbprofile` JSON would be a separate parser, not a second rule engine.
6. Inbound authentication, and a documented non-loopback bind, if someone needs the SOCKS listener off localhost. Today a non-loopback listen is warned about and left open.

Until those exist, use `--mode socks` everywhere and `--mode redirect` on Linux for transparent TCP. Keep the original C or Swift build where a kernel path is required.
