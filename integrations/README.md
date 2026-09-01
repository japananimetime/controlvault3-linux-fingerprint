# Desktop / lock-screen integrations

The **PAM module** (`../pam`) already covers `sudo`, `polkit`/`pkexec`, console/greeter logins,
and any lock screen that authenticates through PAM — `swaylock`, `hyprlock`, `gtklock`,
`xsecurelock`, GDM, SDDM, etc. For those, add one line to the relevant `/etc/pam.d/<service>`:

```
auth   sufficient   pam_cvfp.so timeout=8      # before the password include
```

Some lock screens authenticate *as you type* and have no moment to prompt for a fingerprint
(**i3lock-color** is one). For those, use a small **background watcher** that polls the sensor
while locked and unlocks on a verified tap — no typing, no window to hit.

## i3lock (`i3lock/cvlock`)
```bash
install -Dm755 i3lock/cvlock ~/.local/bin/cvlock
mkdir -p ~/.config/cvlock && echo 10 > ~/.config/cvlock/blur   # or drop lock.png for an image
```
Point i3 at it (both the manual bind and the xss-lock auto-locker), and REMOVE the `pam_cvfp`
line from `/etc/pam.d/i3lock` if you added one (the watcher handles the finger; leaving the PAM
line only delays the password and fights the watcher for the device):

```
bindsym $mod+l exec "~/.local/bin/cvlock"
exec_always --no-startup-id pkill -x xss-lock; xss-lock --transfer-sleep-lock -- ~/.local/bin/cvlock
```

The same watcher pattern works for any locker you can start and kill from a script; adapt `cvlock`.
