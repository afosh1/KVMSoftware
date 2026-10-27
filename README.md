# KVM Shared Workspace

A secure, low-latency **LAN virtual KVM**. Move your mouse to the edge of one
laptop's screen and control hands off to the adjacent laptop — keyboard input is
shared, the clipboard syncs, and (by design, shipping later) files transfer.
Built for **trusted devices on the same local network** — not internet remote
desktop, and not screen streaming.

- **Local-first**: no cloud anywhere in the critical path.
- **Encrypted**: every byte travels over mutually-authenticated TLS 1.3.
- **Fast**: hot-path input rides unreliable QUIC datagrams (p50 ≈ 2–5 ms on a LAN).
- **Cross-platform**: Windows, macOS, Linux.

> Status: the full Rust core, transport, discovery, pairing crypto, keystore, OS
> adapters, engine orchestration, and headless daemon are implemented and
> covered by **98 passing tests** (incl. a real-QUIC end-to-end handoff test and
> a cross-resolution forwarding test).
> The desktop UI (Tauri + SvelteKit) frontend builds; the Tauri shell compiles on
> CI runners with the platform webview libraries. See [Verification](#verification)
> and [Known limitations](#known-limitations--roadmap).

---

## How it works

```
   Laptop A  ── cursor hits right edge ──►  Laptop B
   ┌──────────────┐                          ┌──────────────┐
   │ capture (X11/ │  QUIC datagrams (input) │ inject (XTEST │
   │  rdev/CGEvent)│ ───────────────────────►│  /SendInput)  │
   │ focus SM      │  QUIC streams (clipboard│ focus SM      │
   │ clipboard     │   / control / files)    │ clipboard     │
   └──────────────┘ ◄───────────────────────└──────────────┘
        mDNS discovery · SPAKE2+SAS pairing · pinned mutual TLS
```

A small, pure **focus state machine** decides when the cursor crossing a seam
becomes a control handoff, and guarantees a fail-safe: any dropped link returns
control to the local machine and releases every held key.

---

## Architecture

A Cargo workspace of small, single-responsibility crates. The domain core is
pure (no async, no I/O, no FFI) so 100% of the rules are unit-testable with no
hardware.

| Crate | Responsibility |
|---|---|
| `crates/proto` | Wire types, `postcard` codec + framing, version negotiation |
| `crates/core` | **Pure domain**: device registry, layout graph, focus state machine, clipboard policy, trust lifecycle, session/backoff, validation |
| `crates/transport` | QUIC (primary) + TCP/TLS (fallback), pinned mutual-TLS verifier |
| `crates/discovery` | mDNS/DNS-SD advertise + browse (`mdns-sd`) |
| `crates/pairing` | Self-signed identity (`rcgen`), SPAKE2 PAKE, SAS verification |
| `crates/keystore` | OS keychain (`keyring`) + permission-locked file fallback |
| `crates/adapter-api` | OS-adapter traits (capture / injection / clipboard / geometry) + mocks |
| `crates/adapter-native` | Linux `x11rb`, Win/macOS `enigo`, `rdev` capture, `arboard` clipboard |
| `crates/engine` | Orchestrator: owns the runtime, wires everything behind a command/event API |
| `crates/cli` | Headless daemon (`kvm`) — servers, testing, the app's logic in miniature |
| `app/kvm-desktop` | Tauri v2 shell (`src-tauri`) + SvelteKit UI (`ui`) |

### Key decisions (and why)

- **QUIC over WebRTC.** On a LAN there is no NAT, so WebRTC's ICE/STUN/TURN is
  dead weight. QUIC gives ~2–3 ms lower input latency (RFC 9221 unreliable
  datagrams), native TLS 1.3 self-signed **certificate pinning** (no CA), and a
  dual datagram+stream path — in a mature crate. *(Documented deviation from the
  original WebRTC suggestion.)*
- **TCP/TLS fallback** for networks that block UDP — reliable-only, same pinned
  mTLS, higher latency, transparent to the engine.
- **Unreliable datagrams for input, reliable streams for everything else.**
  Fire-and-forget input is never delayed by retransmits or head-of-line-blocked
  by a clipboard/file transfer (separate streams per kind).
- **`postcard` on the wire** (compact, stable byte layout); JSON only at the UI↔shell boundary.
- **Pure domain + effects.** `core` emits `DomainEffect`s; the `engine` executes
  them. The whole handoff is testable on in-memory mock adapters.
- **TOFU trust + pinned self-signed certs; SPAKE2 + SAS pairing.** No PKI on a LAN.
- **Native cursor warp** (not a generic input lib) so edge detection never stalls.

---

## Security model

- **Mutual TLS, always.** Each device self-signs an Ed25519/ECDSA certificate at
  first launch. During pairing the peers exchange and **pin** each other's
  SHA-256 fingerprint; the transport's custom verifier accepts a peer only if its
  presented certificate hashes to a pinned value *and* the signature checks out.
  A pinning-rejection test proves an unpinned peer cannot connect.
- **Pairing** uses SPAKE2 (a short numeric code as the password) plus a **Short
  Authentication String** the user compares on both screens to defeat MITM.
- **Secure defaults.** Only paired/trusted peers connect; clipboard is text-only
  by default (images/files off); both ends must consent to any clipboard flow;
  0-RTT resume is restricted to idempotent input.
- **Keys at rest** live in the OS keychain (Keychain / Credential Manager /
  Secret Service); a permission-locked file fallback (`0600`) covers headless
  Linux.
- **Fail-safe input.** Any disconnect or error returns control home and releases
  all held keys/buttons — no stuck modifiers, no stranded machine.
- **No telemetry leaves the device.** Diagnostics (RTT, loss, reconnects) are local.

---

## Build & run

### Prerequisites

- **Rust** stable (`rustup`, pinned via `rust-toolchain.toml`).
- **Node 22+** and **pnpm 11** (for the UI).
- Platform libraries:
  - **Linux (X11)**: `libx11-dev libxtst-dev libxi-dev libxcb1-dev` for the
    native adapter; for the desktop app also `libwebkit2gtk-4.1-dev libgtk-3-dev
    librsvg2-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev`.
  - **macOS**: Xcode command-line tools.
  - **Windows**: WebView2 runtime (preinstalled on Win 11) + MSVC toolchain.

### Backend (core, transport, daemon)

```sh
make check        # fmt + clippy(-D warnings) + the full test suite
cargo run -p kvm-cli   # run the headless daemon on one machine
```

The daemon prints this device's id + certificate fingerprint. To trust a peer
without the GUI (manual TOFU), set on the *other* machine:

```sh
KVM_TRUST=<peer-uuid>:<peer-fingerprint-hex> cargo run -p kvm-cli
```

Both daemons advertise over mDNS and auto-connect once they trust each other.

### Desktop app

```sh
make app-dev      # SvelteKit + Tauri dev (hot reload)
make app-build    # produce a bundle for the current OS
```

Generate icons once before the first release bundle (see
`app/kvm-desktop/src-tauri/icons/README.md`).

---

## OS permissions

The setup wizard explains and checks these:

| OS | What's needed |
|---|---|
| **macOS** | **Accessibility** + **Input Monitoring** (System Settings → Privacy & Security). Distribution builds must be codesigned + notarized; the app discloses its use of input event taps. |
| **Windows** | No prompt. Low-level hooks (`SetWindowsHookEx`) and `SendInput` may be flagged by antivirus — the binary should be Authenticode-signed. Cannot inject into elevated apps unless itself elevated. |
| **Linux (X11)** | None required. **Wayland** input capture/injection is restricted (libei/portals) and is post-MVP. |

---

## Usage

1. Launch the app on both laptops; complete the **Setup** wizard (identity +
   permissions).
2. **Devices** → find the peer → **Pair**; compare the verification code on both
   screens and confirm.
3. **Layout** → drag the screens into their physical left-to-right order; **Save**.
4. Move the cursor off the shared edge → control hands to the neighbour. Type,
   copy/paste across machines. Press the release hotkey (or **Release control**
   in Diagnostics) to reclaim focus.
5. **Sharing** → toggle clipboard text/images/files per device.
6. **Diagnostics** → live connection state, latency, loss, and activity log.

---

## Verification

| Layer | How it's verified |
|---|---|
| Domain (focus SM, layout math, policy, trust, session, codec) | 65 unit + property tests |
| Pairing (SPAKE2 handshake, SAS, cert gen) | 7 tests |
| Transport | Real-socket loopback: pinned mTLS roundtrip, **pinning rejection**, TCP/TLS fallback |
| Engine | **End-to-end over real QUIC + mock adapters**: edge→handoff, input forwarded & injected, hotkey release, transport-loss `release_all`, clipboard sync |
| Native Linux adapter | Compiles + unit-tested on this platform |
| Frontend | `vite build` + `svelte-check` |
| Win/macOS adapters & Tauri shell | Compiled on CI runners (require platform libs); manual E2E on hardware |

Run `make check` (or see `.github/workflows/ci.yml`, which matrixes Linux/Windows/macOS).

---

## Known limitations & roadmap

These are deliberate MVP boundaries, with the seams already in place:

- **Single seamless cursor — Linux/X11 (done).** While controlling a remote, the
  controller now grabs local pointer + keyboard (`XGrabPointer`/`XGrabKeyboard`),
  hides its hardware cursor (XFixes), and parks it at screen-center, re-centering
  after every forwarded sample. So exactly **one** crosshair is visible and local
  motion can never pin against a screen edge and stall the remote. This is on by
  default; the `StopCapture` fail-safe + Ctrl+Alt+Q always release the grab.
- **Cross-resolution / extended-desktop mapping (done).** Each device advertises
  its real combined-desktop geometry in the `Hello` handshake; the engine builds
  the layout from those *actual* sizes and forwards an **absolute** cursor
  position in the destination's own pixel space, so screens of different
  resolutions line up and the cursor reaches every part of each screen.
- **Input suppression on Windows/macOS.** The X11 grab above is implemented;
  Windows (`SetWindowsHookEx` eat) and macOS (`CGEventTap` suppression) still
  *observe* events and are the remaining on-hardware hardening item.
- **SPAKE2-over-network pairing.** The crypto + SAS are implemented and tested;
  the in-app flow currently does manual-fingerprint TOFU. Wiring the SPAKE2
  message exchange over a dedicated pairing stream is the next step.
- **File / image transfer.** Protocol is frozen in `proto::v1` (forward
  compatible); implementation is post-MVP.
- **Wayland.** X11 first; Wayland via libei portals is experimental/post-MVP.
- **Per-monitor geometry & HiDPI scaling.** A device's monitors are treated as
  one combined region today (its bounding box); true per-monitor seams and
  applying the reported HiDPI `scale` to forwarded motion are incremental.
- **Keymaps & toggle sync.** A common-key map ships now; exhaustive keymaps and
  CapsLock/NumLock toggle-state sync at handoff are incremental.

---

## License

Dual-licensed under MIT or Apache-2.0.
