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

## Reading the fprintd journal
With fprintd's debug output enabled, the driver logs everything under the `cvfp:` prefix (plus
`[cvfp] O_NUM/V_NUM/TD_NUM entering state` state-machine lines). The greppable anchors, in a
successful verify (captured under Arch Linux fprintd 1.94.5-2 with the MR applied; prefixes
and hex tails trimmed):

```
[cvfp] O_NUM entering state 0                   # open handshake starts (0x23)
cvfp: secure channel open (handle 0x2402cc00)   # ECDH handshake + 0x02 session open done
[cvfp] V_NUM entering state 0                   # verify: 0x66 capture armed
[cvfp] V_NUM completed successfully
[cvfp] TD_NUM entering state 0                  # teardown: 0x68 disarm + 0x04 close
[cvfp] TD_NUM completed successfully            # always check this on a Release/Release-fail
```

The line that carries the verdict:

```
cvfp: 0x2F verdict=1 matched_id=0x00b46b0f (bound 0x00b46b0f)
```

`verdict=1` is a match, `0` a no-match; `matched_id` must equal `bound` — a mismatch means the
chip matched a different template than the print bound.

The full signatures for the clock dance, cancel teardown, suspend handling and the wake probe
are documented in
[../docs/secure-channel.md](../docs/secure-channel.md) (Sleep/resume and other cancels section).
If a claim produces no `[cvfp]` lines at all, the failure is upstream of the driver — fprintd
or libfprint core, not here.

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
