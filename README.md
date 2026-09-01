# controlvault3-linux-fingerprint

Native Linux fingerprint support for the **Dell / Broadcom ControlVault 3** sensor
(BCM58200, USB `0a5c:5843`) — the one `libfprint` / `fprintd` can't drive, so fingerprint
enrollment on affected Dell Latitude / Precision laptops just fails.

This project reverse-engineers the sensor's encrypted command channel and reimplements enrollment
and verification from scratch, then wires them into PAM so you can **tap to authenticate** for
`sudo`, `polkit`/`pkexec`, the login screen, and the lock screen.

> **No Windows required.** Early work extracted a key from Windows, but it turned out the chip
> doesn't authenticate the host key at all — so the tools generate an ephemeral key each run.
> Build it, enroll a finger, done. See [docs/secure-channel.md](docs/secure-channel.md).

## Is this for me?
- **Yes if** `lsusb` shows `0a5c:5843` (Broadcom ControlVault 3) and fingerprint enrollment fails
  in GNOME/KDE/`fprintd`. Common on Dell Latitude 5xxx / Precision with the fingerprint option.
- Developed and tested on a **Dell Latitude 5531**. Other ControlVault 3 units very likely work;
  other CV models / USB IDs may need adjustment. Reports welcome.

## Quick start

There are **two independent ways** to use this, and you should **pick exactly one**. Both want
exclusive ownership of the sensor; running them side by side makes them fight over the USB device
and wedge the chip.

### A — libfprint TOD driver *(recommended)*

Makes the sensor a first-class `fprintd` reader, so `pam_fprintd`, `fprintd-enroll`/`fprintd-verify`
and the GNOME/KDE fingerprint panels all just work. No custom PAM module, no lock-screen watcher.

```bash
# deps: a C compiler, openssl (dev headers), libfprint-2-tod-1 (dev)
cd driver
gcc -shared -fPIC cvfp-tod.c -o libfprint-2-tod-1-cvfp.so \
  $(pkg-config --cflags --libs libfprint-2-tod-1) \
  $(pkg-config --libs glib-2.0 gobject-2.0 gusb) -lcrypto

# take over the slot Dell's non-working driver occupies
sudo mv /usr/lib/libfprint-2/tod-1/libfprint-2-tod-1-broadcom.so{,.disabled}
sudo install -Dm755 libfprint-2-tod-1-cvfp.so /usr/lib/libfprint-2/tod-1/
sudo systemctl restart fprintd

fprintd-enroll        # touch ~12x
fprintd-verify        # tap once
```

Then add the standard line to whichever `/etc/pam.d/<service>` you want — `sudo`, your greeter,
`polkit-1` — above the password include:

```
auth   sufficient   pam_fprintd.so
```

> **Build note:** the driver **must be linked against `libfprint-2-tod`** (that is what
> `pkg-config --libs libfprint-2-tod-1` does), not merely compiled with its `-I` paths. If you only
> add the include paths it will **segfault the moment any client opens the device**, for a subtle
> symbol-versioning reason explained in [driver/README.md](driver/README.md).

### B — standalone PAM *(no fprintd)*

The original path. Useful if you don't want `fprintd` at all, or your `libfprint` has no TOD support.

```bash
# deps: a C compiler, libusb-1.0, openssl (dev headers)
sudo systemctl stop fprintd        # it fights for the USB device

# 1) enroll a finger (touch ~12x)
cd tools && gcc -O2 -o cvchan cvchan.c -lusb-1.0 -lcrypto && sudo ./cvchan

# 2) install the PAM authenticator (sudo, polkit, login)
cd ../pam && sudo ./install.sh

# 3) test
sudo -k && sudo id                 # -> "Touch the fingerprint sensor"
```

- **`cvchan`** with no args = enroll; `cvchan verify` = one-shot match; `cvchan reset` = clear a
  stuck enrollment.
- **`pam/install.sh`** builds the `pam_cvfp.so` module + the `cvfp-verify` helper, masks `fprintd`,
  and adds a `sufficient` fingerprint line to `sudo`, `login`, and `polkit-1`.

### Either way

- **Password always stays as the fallback** — every PAM line is `sufficient`, so you cannot be
  locked out by a failed or missing fingerprint.
- **Enroll deliberately.** Press firmly and fully on each of the ~12 taps and shift the contact
  point slightly between them (center, then a little left/right/up/down). A rushed enroll makes a
  weak template that matches inconsistently; a careful one matches every time.
- **Lock screens**: anything PAM-based (swaylock, hyprlock, gtklock, GDM, SDDM…) takes the same
  one-line PAM edit. i3lock-color has no PAM-promptable moment, so use the tap-to-unlock watcher in
  [integrations/](integrations/README.md) (it drives whichever path you chose).

## What works
| Surface | Path A (fprintd) | Path B (standalone) |
|---|---|---|
| `sudo` | `pam_fprintd.so` | `pam_cvfp.so` |
| `polkit` / `pkexec` GUI dialogs | `pam_fprintd.so` | `pam_cvfp.so` |
| Login greeters / console | `pam_fprintd.so` | `pam_cvfp.so` |
| PAM-based lock screens | `pam_fprintd.so` | `pam_cvfp.so` |
| GNOME/KDE fingerprint settings | yes | no |
| i3lock-color | `integrations/i3lock/cvlock` watcher (tap to unlock) | same watcher |

## Layout
```
driver/        the libfprint TOD driver — the main deliverable (path A)
pam/           standalone PAM module + setuid verify helper      (path B)
integrations/  optional per-desktop bits (i3lock watcher, notes for others)
tools/         dev + research tooling, not needed to use either path:
               cvchan (enroll/verify/reset), cvrecover (clear a stuck endpoint)
docs/          the protocol reverse-engineering writeup
windows/       appendix: how it was discovered (NOT needed to use it)
```

## Honest caveats
- **Single-factor.** A fingerprint match alone authenticates (that's the point). Remove the
  `pam_cvfp` line, or pair it with the password, if you want two factors.
- **Physical-access security model.** The chip encrypts the channel but doesn't authenticate the
  host — like most internal readers, its security is "you have the laptop open." Don't expect it to
  resist someone with root or physical USB access.
- **The sensor can wedge** if a process is killed mid-capture. The tools defend against this:
  SIGTERM/SIGINT/SIGHUP handlers cancel the capture and close the session before exiting, and a
  light wedge is auto-recovered (USB `authorized` toggle) on the next run. **Never** "recover" it
  with a USB port reset (`libusb_reset_device`, or the port `disable` knob): that is what turns a
  recoverable wedge into a chip that will not enumerate at all (`error -110`) until a cold boot —
  see docs/secure-channel.md#recovery. Only a `kill -9`
  mid-capture, or the rare deep wedge, needs a manual reboot — see
  [docs/secure-channel.md](docs/secure-channel.md).
- One device family tested. **Try it, report back**, and please don't publish anyone's keys.

## Roadmap & help wanted
The headline next step is a **libfprint TOD driver** so this works through `fprintd` and every
desktop's built-in fingerprint support (no PAM edits, no watcher). Feasibility is confirmed; see
[ROADMAP.md](ROADMAP.md).

- Confirm/adjust for other ControlVault 3 units and USB IDs.
- A `udev` rule instead of setuid for device access.
- Package it (AUR, etc.) now that it's keyless.

## License
MIT (see LICENSE). Interoperability reverse-engineering of your own hardware. Not affiliated with
Dell or Broadcom; no vendor code is included — the protocol constants here are observations of a
wire format, and nothing needs a key extracted from anywhere.

If this saved you a reinstall and we ever meet, you can buy me a beer. 🍺
