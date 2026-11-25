# Roadmap

## v1: keyless enroll/verify + standalone PAM — done
`sudo`, `polkit`, PAM-based greeters/lockers via `pam_cvfp.so`; i3lock via the `cvlock` watcher.
Ships as **path B** in the README — for systems without `fprintd`, or where you would rather not
run it. It owns the USB device directly, so it is mutually exclusive with v2.

## v2 (headline): a libfprint TOD driver — done
Shipped as `driver/cvfp-tod.c`, so `fprintd`, `pam_fprintd` and the desktop fingerprint panels
drive the sensor with no custom PAM module and no lock-screen watcher. Drop one `.so` into
`/usr/lib/libfprint-2/tod-1/`; **no libfprint rebuild needed**.

Fully asynchronous: every USB transfer goes through `fpi_usb_transfer_submit` and each operation
is an `fpi_ssm`, so the main loop never blocks — `Claim`/`EnrollStart`/`VerifyStart` return
immediately instead of timing out, and cancellation unwinds cleanly.

Validated end to end on a Dell Latitude 5531: `fprintd-enroll` completes 12 stages,
`fprintd-verify` reports `verify-match`, `sudo` authenticates through `pam_fprintd`, and the
device is left healthy.

> **Last validated:** 2026-09-01 — `libfprint-tod` 1.94.8+tod1, `fprintd` 1.94.5, CachyOS,
> kernel 7.2.2, Dell Latitude 5531 (`0a5c:5843`). Re-validated 2026-11-23 on a Dell Latitude
> 7430 (same USB ID): enroll and verify (match and no-match) confirmed end to end after the
> identify / template-binding rework. Re-validated **2026-11-25** on the same 7430 with
> Arch Linux fprintd 1.94.5-2 with MR !259 ("close after suspend") applied (MR tests
> backported for compatibility): suspend during an active verify, idle sleep/resume, and
> repeated sleep/wake cycles all recover cleanly — post-resume Claims open a fresh channel
> and verify in seconds.
> If you are reading this much later, re-check before trusting it: the driver links against
> versioned symbols in `libfprint-2-tod`, so a libfprint ABI bump is exactly the kind of change
> that breaks it quietly (see [driver/README.md](driver/README.md)).

**How the protocol (see `docs/secure-channel.md`) maps to `FpiDeviceClass`:**
| vfunc | sequence | status |
|---|---|---|
| `probe` | match USB `0a5c:5843` | done |
| `open` | `0x23`/`0x24` handshake (ephemeral key) + `0x02` open | done |
| `verify` | `0x66` capture → async `0x03` → `0x2F` identify (bound handle) | done |
| `enroll` | `0x6D` discard → `0x8A` → (`0x66`→async→`0x6C`)×N → `0x6E` commit | done |
| `close` | `0x68` cancel + `0x04` close | done |
| `list` / `delete` / `identify` | `0x2F` template management | **not implemented** — see below |

**`suspend`/`resume` vfuncs are deliberately not implemented** (decision, 2026-11-25): the
core's cancel-based fallback for drivers without them is fully handled host-side since
fprintd MR !259 ("close after suspend"), and the code that must actually run at sleep —
the chip teardown — already lives in the driver's cancel path, which is exercised and
proven in that fallback. Completing suspend from the driver (vs completing it with an
error, which is what cancels the running action) would move the teardown onto an untested
path; revisit only if the core's suspend semantics change.

## v3 / help wanted
- **Other ControlVault 3 units and USB IDs.** The original work was developed on a Dell
  Latitude 5531 (`0a5c:5843`); enroll and verify are also confirmed working on a Latitude 7430
  (same USB ID). Other CV3 units and the nearby IDs `0a5c:5842/5844/5845` remain untested.
  Reports either way are the most valuable contribution.
- **Packaging** (AUR and friends) — straightforward now that it is keyless.
- **Upstreaming the driver into libfprint**, so affected laptops work out of the box. The MIT
  licence here is deliberately compatible with libfprint's LGPL-2.1+.
- **On-device template management.** Enrolled fingerprints live on the device already: the
  `0x6E` commit creates the template on the chip, and the stored print on the host (`fpi-data`)
  is only a reference — the 20-byte enrollment id plus the chip's u32 template handle. Matching
  runs entirely on-device (`0x2F` identify with the bound handle), so the biometric data itself
  never leaves the chip. The driver still registers as host storage (`FP_DEVICE_FEATURE_VERIFY`),
  which describes where fprintd keeps those reference prints. Not implemented yet: enumerating
  or deleting the chip's templates. The driver has no delete path, so removing an enrollment
  through fprintd discards only the host reference and the chip's template stays behind;
  `list`/`delete` and a user-facing identify need a `0x2F` store diff to map the chip's stable
  biometric-derived ids to enrollments. See the notes in `driver/cvfp-tod.c`.
- A `udev` rule instead of setuid for the v1 helper's device access (path B only).
