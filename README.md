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
```bash
# deps: a C compiler, libusb-1.0, openssl (dev headers)
sudo systemctl stop fprintd        # it fights for the USB device

# 1) enroll a finger (touch ~12x)
cd src && gcc -O2 -o cvchan cvchan.c -lusb-1.0 -lcrypto && sudo ./cvchan

# 2) install the PAM authenticator (sudo, polkit, login)
cd ../pam && sudo ./install.sh

# 3) test
sudo -k && sudo id                 # -> "Touch the fingerprint sensor"
```

- **`cvchan`** with no args = enroll; `cvchan verify` = one-shot match; `cvchan reset` = clear a
  stuck enrollment.
- **Enroll deliberately.** Press firmly and fully on each of the ~12 taps and shift the contact
  point slightly between them (center, then a little left/right/up/down). A rushed enroll makes a
  weak template that matches inconsistently; a careful one matches every time.
- **`pam/install.sh`** builds the `pam_cvfp.so` module + the `cvfp-verify` helper, masks the
  (non-functional) `fprintd`, and adds a `sufficient` fingerprint line to `sudo`, `login`, and
  `polkit-1` — **password always stays as the fallback, you can't be locked out.**
- **Lock screens**: anything PAM-based (swaylock, hyprlock, gtklock, GDM, SDDM…) takes the same
  one-line PAM edit. i3lock-color has no PAM-promptable moment, so use the tap-to-unlock watcher in
  [integrations/](integrations/README.md).

## What works
| Surface | Mechanism |
|---|---|
| `sudo` | `pam_cvfp.so` (with password fallback) |
| `polkit` / `pkexec` GUI dialogs | `pam_cvfp.so` |
| Login greeters / console | `pam_cvfp.so` |
| PAM-based lock screens | `pam_cvfp.so` |
| i3lock-color | `integrations/i3lock/cvlock` watcher (tap to unlock) |

## Layout
```
src/           core: enroll + verify over the reverse-engineered channel (keyless)
pam/           the PAM module + setuid verify helper + installer  (universal)
integrations/  optional per-desktop bits (i3lock watcher, notes for others)
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
  light wedge is auto-recovered (USB `authorized` toggle) on the next run. Only a `kill -9`
  mid-capture, or the rare deep wedge, needs a manual reboot — see
  [docs/secure-channel.md](docs/secure-channel.md).
- One device family tested. **Try it, report back**, and please don't publish anyone's keys.

## Help wanted
- Confirm/adjust for other ControlVault 3 units and USB IDs.
- A `udev` rule instead of setuid for device access.
- Package it (AUR, etc.) now that it's keyless.

## License
MIT (see LICENSE). Interoperability reverse-engineering of your own hardware. Not affiliated with
Dell or Broadcom; no vendor code is included.
