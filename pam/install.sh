#!/bin/bash
# Install the ControlVault fingerprint PAM authenticator (keyless — no Windows, no key file).
# Run as root:  sudo ./install.sh
set -e
[ "$(id -u)" = 0 ] || { echo "run as root: sudo ./install.sh"; exit 1; }
cd "$(dirname "$0")"

gcc -O2 -o cvfp-verify cvfp-verify.c -lusb-1.0 -lcrypto
gcc -fPIC -shared -o pam_cvfp.so pam_cvfp.c -lpam

# cvfp-verify is setuid root so it can claim the USB device even when the caller (a lock screen,
# a greeter) runs as an unprivileged user. It takes no file input, only an optional timeout.
install -Dm4755 -o root -g root cvfp-verify /usr/local/bin/cvfp-verify
install -Dm755  -o root -g root pam_cvfp.so  /usr/lib/security/pam_cvfp.so

# the stock libfprint/fprintd cannot drive this sensor and would fight for the USB device
systemctl stop fprintd 2>/dev/null || true
systemctl mask fprintd.service 2>/dev/null || true

add_fp() {  # $1 service file, $2 extra args, $3 include keyword
  local f="$1" a="$2" inc="$3"
  [ -f "$f" ] || return 0; grep -q pam_cvfp "$f" && return 0
  cp "$f" "$f.bak.cvfp"
  awk -v a="$a" -v inc="$inc" \
    '$1=="auth" && $2=="include" && $3==inc && !d { printf "auth\tsufficient\tpam_cvfp.so%s\n",(a==""?"":" " a); d=1 } { print }' \
    "$f.bak.cvfp" > "$f"
}
add_fp /etc/pam.d/sudo "" system-auth      # sudo: tap or password
add_fp /etc/pam.d/login "timeout=8" system-auth   # console + most greeters that include login
if [ ! -f /etc/pam.d/polkit-1 ] || ! grep -q pam_cvfp /etc/pam.d/polkit-1; then
  cat > /etc/pam.d/polkit-1 <<POLKIT
#%PAM-1.0
auth       sufficient   pam_cvfp.so timeout=8
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
POLKIT
fi

# make lockouts short so a fingerprint miss never traps you for 10 minutes
if [ -f /etc/security/faillock.conf ]; then
  sed -i '/^[[:space:]]*deny[[:space:]]*=/d; /^[[:space:]]*unlock_time[[:space:]]*=/d' /etc/security/faillock.conf
  printf 'deny = 6\nunlock_time = 90\n' >> /etc/security/faillock.conf
fi

echo "installed. enroll a finger:  sudo ../tools/cvchan   (touch ~12x)"
echo "then test:  sudo -k && sudo id   /   pkexec id"
