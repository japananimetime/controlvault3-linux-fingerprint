# libfprint TOD driver (v2, in progress)

A native `libfprint` TOD driver for the ControlVault 3 sensor, so `fprintd` + the GNOME/KDE
fingerprint settings + `pam_fprintd` drive it directly — no `pam_cvfp` line, no `cvlock` watcher.
Drop-in replacement for the stock (non-working) `libfprint-2-tod-1-broadcom.so`.

**Status:** milestone 1 — `probe` + `open` (keyless ECDH handshake + channel) + `close`. Compiles
and links against the installed TOD headers; `enroll`/`verify`/`identify`/`list`/`delete` next.
See [../docs/secure-channel.md](../docs/secure-channel.md) and [../ROADMAP.md](../ROADMAP.md).

## Build
```bash
gcc -shared -fPIC cvfp-tod.c -o libfprint-2-tod-1-cvfp.so \
  $(pkg-config --cflags glib-2.0 gobject-2.0 gusb) \
  -I/usr/include/libfprint-2 -I/usr/include/libfprint-2/tod-1 \
  $(pkg-config --libs glib-2.0 gobject-2.0 gusb) -lcrypto
```
Install into the TOD drivers dir (`/usr/lib/libfprint-2/tod-1/`), disable the stock broadcom `.so`,
and restart `fprintd`. Exposes the driver via the `fpi_tod_shared_driver_get_type` entry point.
