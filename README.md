# xnutesting

> **Research & Education Only** — Proof-of-concept exploit harness for the XNU AIO Kevent Use-After-Free vulnerability.  
> Do not use illegally. For personal devices or controlled research environments only.

---

## Overview

**xnutesting** is an iOS SwiftUI app for researching and testing a security vulnerability in the XNU kernel. The project focuses on a **Use-After-Free (UAF)** bug in the kernel's AIO (Asynchronous I/O) subsystem, chained with a kernel read/write primitive via ICMPv6.

| Field | Details |
|-------|---------|
| **Vulnerability** | XNU AIO Kevent Use-After-Free (`bsd/kern/kern_aio.c`) |
| **CVE** | CVE-2026-XXXX *(placeholder)* |
| **Affected** | iOS ≤ 26.2.x (xnu-12377.62.x) — includes **26.2.1** |
| **Patched** | iOS 26.3 (xnu-12377.81.4) |
| **Confirmed device** | iPhone 11 Pro — A13 (arm64e) |
| **Compatible devices** | All arm64e (A12+): iPhone XS, 11, 12, 13… |
| **Sandbox** | Exploitable from app sandbox, no special entitlements required |

---

## Bug Mechanics

### Root Cause

`lio_listio()` registers a kevent **after** the AIO work item has already been enqueued into the kernel. If a racing thread calls `aio_return()` in that window, the `aio_workq_entry` is **freed** while its knote still holds a dangling pointer to it. When `kevent64()` is subsequently called, `filt_aioprocess` reads from freed memory → kernel panic (`FAR = 0x58`).

### Exploitation Chain

```
Stage 1 — AIO UAF (Double-Free)
  lio_listio()          → aio_workq_entry queued, knote registered
  aio_return() [racer]  → entry freed (aio_workq_entry ~224B, KT_DEFAULT zone)
  aio_read() [reclaim]  → slot immediately reused (LIFO, same CPU)
  kevent64()            → filt_aioprocess reads reclaimed slot
                           → kev.ext[1] = leaked kernel value (+0x20)
                           → TAILQ_REMOVE write primitive

Stage 2 — ICMPv6 Kernel R/W
  Spray 64 ICMPv6 sockets (post-UAF to avoid zone noise)
  Corrupt inpcb→icmp6filter → points to second socket's PCB
  getsockopt()  → early_kread64()  (arbitrary kernel read)
  setsockopt()  → early_kwrite64() (arbitrary kernel write)

Stage 3 — Kernel Base Scan
  Read pr_input pointer from protosw struct
  XPACI (arm64e PAC strip) + backward page scan
  Match Mach-O magic (0xFEEDFACF) → kernel base & slide
```

---

## Project Structure

```
xnutesting/
├── xnutesting/
│   ├── ContentView.swift               # SwiftUI UI harness, real-time log capture
│   ├── xnutestingApp.swift             # App entry point
│   ├── xnutesting-Bridging-Header.h    # Swift ↔ ObjC/C bridge
│   └── ex/
│       ├── ex_bridge.h                 # C/ObjC entry point declarations
│       ├── ex_PoC.c                    # Minimal PoC — triggers kernel panic only
│       ├── ex.m                        # ObjC UAF double-free variant (no KRW)
│       ├── ex_combined.m               # Full chain: AIO UAF → ICMPv6 KRW
│       └── dsw.m                       # Darksword: physical KRW via IOSurface
└── xnutestingTests/
└── xnutestingUITests/
```

### Modules

| File | Description |
|------|-------------|
| `ex_PoC.c` | Minimal PoC — triggers kernel panic, no further exploitation |
| `ex.m` | ObjC variant of UAF double-free, no KRW primitive |
| `ex_combined.m` | **Full exploit chain**: AIO UAF + ICMPv6 KRW + kernel base scan |
| `dsw.m` | Darksword KRW using physical OOB read/write via IOSurface (`PurpleGfxMem`). Requires entitlement — skipped in combined chain |
| `ContentView.swift` | SwiftUI harness with real-time log output, 4 trigger buttons (one per module) |

---

## Technical Details

### LIFO Zone Trick (CPU Affinity)

To ensure the freed slot is reclaimed **on the same CPU** (LIFO zone magazine reuse), both the main thread and racer thread are pinned to the same CPU tag (`THREAD_AFFINITY_POLICY`, tag `42`). If different CPUs are used, the freed slot enters CPU-A's magazine while the reclaim alloc draws from CPU-B's magazine → LIFO miss → kevent64 reads a zeroed slot → panic.

### ICMPv6 KRW Primitive

```
controlSocket → setsockopt(ICMP6_FILTER) writes target address into icmp6filter
rwSocket      → getsockopt(ICMP6_FILTER) reads 0x20 bytes from that address
```

By corrupting the `icmp6filter` pointer inside `inpcb`, two sockets form a control/read-write pair enabling arbitrary kernel read/write (up to 32 bytes per call).

### arm64e PAC

On arm64e (A12+), function pointers are signed with PAC. The `__xpaci()` macro (instruction `XPACI X0`) strips the PAC signature before the kernel base scan.

---

## Usage

1. Open `xnutesting.xcodeproj` in Xcode.
2. Build and deploy to a device running iOS ≤ 26.2.x (vulnerable — includes 26.2.1).
3. The app presents 4 buttons:
   - **Run Double-Free UAF** — `ex.m`, UAF stage only (no KRW)
   - **Run Kernel Panic PoC** — `ex_PoC.c`, deliberate kernel panic
   - **Run Combined KRW Chain** — `ex_combined.m`, full chain (recommended)
   - **Run Darksword KRW** — `dsw.m`, physical KRW (requires entitlement)
4. Real-time log output is displayed on screen.

> ⚠️ **Run Kernel Panic PoC** will immediately reboot the device on vulnerable systems.

---

## Device Compatibility

| Device | Chip | iOS 26.2 | iOS 26.2.1 | iOS 26.3+ |
|--------|------|----------|------------|-----------|
| iPhone 11 Pro | A13 | ✅ Confirmed | ✅ Expected | ❌ Patched |
| iPhone 12 | A14 | ✅ Expected | ✅ Expected | ❌ Patched |
| iPhone 13+ | A15+ | ✅ Expected | ✅ Expected | ❌ Patched |
| iPhone XS/X | A12 | ✅ Expected | ✅ Expected | ❌ Patched |

> **Note on iPhone 12 (iOS 26.2.1):** The vulnerability is in the kernel (`bsd/kern/kern_aio.c`) and is chip-independent. iOS 26.2.1 is a minor patch on top of 26.2 — the kernel ABI is unchanged (`xnu-12377.62.x`) and the hardcoded `inpcb`/`socket` offsets remain valid. `ex_combined.m` (full chain) and `ex_PoC.c` (panic) are expected to work normally.

---

## Known Limitations

- `dsw.m` (`pe_v1`/`pe_v2`, physical OOB) requires the `IOSurface PurpleGfxMem` entitlement — not available from a standard sandbox.
- The full KRW chain (`ex_combined.m`) needs `kev.ext[1]` to be a valid kernel pointer. Without an `ipc_port` spray into the freed slot before `kevent64`, `ext[1]` only contains the `aio_nbytes` placeholder value.
- Race success rate is ~1–10 attempts depending on CPU load.
- Struct offsets (`OFFSET_PCB_SOCKET`, `OFFSET_ICMP6FILT`, …) were verified against `xnu-12377.62.10`. If Apple changes internal layout in a minor patch, re-verification is required.

---

## References

- XNU source: `bsd/kern/kern_aio.c` — `lio_listio`, `aio_return`, `filt_aioprocess`
- Patch commit (iOS 26.3): xnu-12377.81.4
- IOSurface physical mapping: `IOSurfaceGetBaseAddress` + `mach_make_memory_entry_64`
