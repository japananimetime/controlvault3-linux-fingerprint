# libfprint TOD driver (v2, in progress)

A native `libfprint` TOD driver for the ControlVault 3 sensor, so `fprintd` + the GNOME/KDE
fingerprint settings + `pam_fprintd` drive it directly — no `pam_cvfp` line, no `cvlock` watcher.
Drop-in replacement for the stock (non-working) `libfprint-2-tod-1-broadcom.so`.

**Status:** milestone 1 **confirmed on hardware** — `probe` + `open` (keyless ECDH handshake +
channel) + `close` run inside `libfprint`/`fprintd`'s async stack (`libfprint sees 1 device …
driver=cvfp … cvfp: secure channel open … OPEN OK`). The async integration — the one real
unknown — works. Next: `verify`/`identify`, then `enroll`, then `list`/`delete`/`clear_storage`,
each mapping the sequences in ../docs/secure-channel.md to the vfuncs the same way.
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
