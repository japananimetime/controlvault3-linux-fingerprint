# libfprint TOD driver

A native `libfprint` TOD driver for the ControlVault 3 sensor, so `fprintd` + the GNOME/KDE
fingerprint settings + `pam_fprintd` drive it directly — no `pam_cvfp` line, no `cvlock` watcher.
Drop-in replacement for the stock (non-working) `libfprint-2-tod-1-broadcom.so`.

**Status: working end to end on hardware.** `probe`, `open` (keyless ECDH handshake + channel),
`enroll`, `verify` and `close` all run inside `libfprint`/`fprintd`'s async stack:
`fprintd-enroll` completes and commits its enrollment, and `fprintd-verify` returns
`verify-match` for an enrolled finger and `verify-no-match` for a different one. The chip's two
stall traps — the host-timestamp interrupt and event-only completions (both documented in
../docs/secure-channel.md) — are handled inside the driver. `list`/`delete`/`clear_storage`
template management is future work.
See [../docs/secure-channel.md](../docs/secure-channel.md) and [../ROADMAP.md](../ROADMAP.md).

## Build
```bash
gcc -shared -fPIC cvfp-tod.c -o libfprint-2-tod-1-cvfp.so \
  $(pkg-config --cflags --libs libfprint-2-tod-1) \
  $(pkg-config --libs glib-2.0 gobject-2.0 gusb) -lcrypto
```

> **You must LINK against `libfprint-2-tod` (`pkg-config --libs libfprint-2-tod-1`), not merely add
> its `-I` include paths.** `libfprint-2-tod.so` exports *versioned* symbols, and several have more
> than one version: `LIBFPRINT_TOD_1.0.0` is version index **2**, `LIBFPRINT_TOD_1_1.92` is index 3.
> glibc resolves an **unversioned** undefined reference to the *base* version (index < 3), so a
> driver that is compiled with only the include paths silently binds `fpi_ssm_new_full` to the
> legacy **4-argument** compatibility thunk. That thunk does `mov %rcx,%r8`, which shifts the modern
> 5-argument call by one: `machine_name` receives `start_cleanup` (a small integer), and libfprint
> calls `g_strdup((char *) 4)` — an immediate **SIGSEGV inside `fp_device_open`**, before the driver
> executes a single line of its own code. The thunk tail-`jmp`s, so it never appears in a backtrace;
> the crash looks like it comes from `fpi_ssm_new_full` itself.
>
> Verify the link is right:
> ```bash
> readelf -sW libfprint-2-tod-1-cvfp.so | grep fpi_ssm_new_full
> # want: fpi_ssm_new_full@LIBFPRINT_TOD_1_1.92   (NOT unversioned, NOT @LIBFPRINT_TOD_1.0.0)
> ```
Install into the TOD drivers dir (`/usr/lib/libfprint-2/tod-1/`), disable the stock broadcom `.so`,
and restart `fprintd`. Exposes the driver via the `fpi_tod_shared_driver_get_type` entry point.
