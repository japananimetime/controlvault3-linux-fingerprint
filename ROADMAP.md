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
> kernel 7.2.2, Dell Latitude 5531 (`0a5c:5843`).
> If you are reading this much later, re-check before trusting it: the driver links against
> versioned symbols in `libfprint-2-tod`, so a libfprint ABI bump is exactly the kind of change
> that breaks it quietly (see [driver/README.md](driver/README.md)).

**How the protocol (see `docs/secure-channel.md`) maps to `FpiDeviceClass`:**
| vfunc | sequence | status |
|---|---|---|
| `probe` | match USB `0a5c:5843` | done |
| `open` | `0x23`/`0x24` handshake (ephemeral key) + `0x02` open | done |
| `verify` | `0x66` capture → async `0x03` → `0x73` match | done |
| `enroll` | `0x6D` discard → `0x8A` → (`0x66`→async→`0x6C`)×N → `0x6E` commit | done |
| `close` | `0x68` cancel + `0x04` close | done |
| `list` / `delete` / `identify` | `0x2F` template management | **not implemented** — see below |

## v3 / help wanted
- **Other ControlVault 3 units and USB IDs.** Everything here was developed against a single
  Dell Latitude 5531 (`0a5c:5843`). Other CV3 units very likely work; `0a5c:5842/5844/5845` are
  probably close but untested. Reports either way are the most valuable contribution.
- **Packaging** (AUR and friends) — straightforward now that it is keyless.
- **Upstreaming the driver into libfprint**, so affected laptops work out of the box. The MIT
  licence here is deliberately compatible with libfprint's LGPL-2.1+.
- **On-device template storage.** The driver uses host storage (`FP_DEVICE_FEATURE_VERIFY`) and
  trusts the chip's match flag, which is authoritative — the chip only matches fingers actually
  in its store. `list`/`delete`/`identify` additionally need a `0x2F` store diff to map the
  chip's stable biometric-derived ids to enrollments; see the notes in `driver/cvfp-tod.c`.
- A `udev` rule instead of setuid for the v1 helper's device access (path B only).
