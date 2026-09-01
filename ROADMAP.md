# Roadmap

## v1 (this repo): keyless enroll/verify + PAM  — done
Works today: `sudo`, `polkit`, PAM-based greeters/lockers via `pam_cvfp.so`; i3lock via the
`cvlock` watcher. Not integrated with `fprintd`/`libfprint`.

## v2 (headline): a libfprint TOD driver — make it a first-class reader
Turn the reverse-engineered channel into a proper **libfprint TOD driver**, so `fprintd`, the
GNOME/KDE fingerprint settings panels, and the standard `pam_fprintd` module all drive it — no
custom PAM lines, no lock-screen watcher. Users install one `.so` and enroll in their Settings app.

**Feasibility (confirmed by a spike):**
- The system already ships a TOD-enabled `libfprint` (`libfprint-tod`), the TOD driver headers
  (`/usr/include/libfprint-2/tod-1/drivers_api.h`), and a drop-in slot — Dell's non-working
  `libfprint-2-tod-1-broadcom.so`. A minimal `FpiDeviceClass` driver compiles cleanly against
  them (deps: `glib-2.0 gobject-2.0 gusb`). **No libfprint rebuild needed.**

**Plan — map our protocol (see `docs/secure-channel.md`) to `FpiDeviceClass` vfuncs:**
| vfunc | our sequence |
|---|---|
| `probe` | match USB `0a5c:5843` |
| `open` | `0x23`/`0x24` handshake (ephemeral key) + `0x02` open, as an `fpi_ssm` |
| `verify` / `identify` | `0x66` capture → async `0x03` → `0x73` match; report result |
| `enroll` | `0x6D` discard → `0x8A` → (`0x66`→async→`0x6C`)×N → completion → `0x6E` commit, reporting stage progress to libfprint |
| `list` / `delete` / `clear_storage` | `0x2F` and template management; store the device template id in the `FpPrint` blob |
| `close` | `0x04` close |

**Effort:** ~4–6 focused sessions + hardware testing (roughly a week). Main detail work: porting
our blocking flow to libfprint's async state machines, and mapping on-chip templates to `FpPrint`
(the stock broadcom driver is a reference for the latter).

**Upstreaming:** once working, propose to the libfprint maintainers. Users can use the TOD `.so`
before any upstream merge.

## Also welcome
- Confirm/adjust for other ControlVault 3 units and USB IDs.
- A `udev` rule instead of setuid for the v1 helper's device access.
- Packaging (AUR) for both v1 and the v2 driver.
