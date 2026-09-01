/* Windows-style soft recovery for the ControlVault 3: clear endpoint halts (STALL). No reset.
 *
 * WHY THERE IS NO libusb_reset_device() HERE ANY MORE (2026-09-01):
 * A soft wedge is a stuck bulk endpoint — the chip still enumerates and still answers EP0
 * control transfers perfectly. libusb_reset_device() issues a USB *port reset*, which is the
 * same operation as the port `disable` knob that docs/secure-channel.md has always warned is
 * unrecoverable. Against an already-wedged chip it kills the BCM58200's USB stack outright:
 * EP0 stops answering, every enumeration attempt returns `device descriptor read, error -110`,
 * and the kernel's own `attempt power cycle` cannot bring it back. Because this chip is a
 * soldered internal device fed from a mainboard rail (not switchable port VBUS), nothing short
 * of a full system power-down re-runs its firmware — hence the cold boots.
 *
 * Captured live: authorized-toggle at 17:32:09 re-enumerated the device fine; reset at 17:32:17;
 * first -110 at 17:32:23; "unable to enumerate USB device" by 17:35:07.
 *
 * Windows never resets this device: it aborts the pipe and issues CLEAR_FEATURE(ENDPOINT_HALT),
 * which is exactly what this tool does. That is why Windows needs no reboots.
 *
 * Escalation ladder, gentlest first — never go past step 2 automatically:
 *   1. USB `authorized` 0/1 toggle (cvchan does this itself on a 0x23 timeout)
 *   2. clear_halt on 0x01 / 0x81 / 0x85   <- this tool
 *   3. (nothing) a wedged-but-enumerating chip is recoverable; a reset one is not
 */
#include <stdio.h>
#include <string.h>
#include <libusb-1.0/libusb.h>

int main(int argc, char **argv){
  int force_reset = (argc > 1 && strcmp(argv[1], "--force-reset") == 0);
  libusb_context *ctx = NULL;
  if (libusb_init(&ctx)) { printf("libusb_init failed\n"); return 1; }
  libusb_device_handle *h = libusb_open_device_with_vid_pid(ctx, 0x0a5c, 0x5843);
  if (!h){ printf("device open failed (not present?)\n"); libusb_exit(ctx); return 1; }
  libusb_set_auto_detach_kernel_driver(h, 1);
  int r = libusb_claim_interface(h, 0);
  printf("claim_interface: %d (%s)\n", r, r ? libusb_error_name(r) : "ok");

  /* clear STALL on the three endpoints the protocol uses */
  int e[3] = {0x01, 0x81, 0x85};
  for (int i = 0; i < 3; i++){
    int c = libusb_clear_halt(h, e[i]);
    printf("clear_halt 0x%02x: %d (%s)\n", e[i], c, c ? libusb_error_name(c) : "ok");
  }

  if (force_reset){
    printf("\n*** --force-reset: issuing libusb_reset_device().\n");
    printf("*** This is the operation that BRICKS the chip until a cold boot (error -110).\n");
    printf("*** Only meaningful if you are about to power the machine down anyway.\n");
    int rs = libusb_reset_device(h);
    printf("reset_device: %d (%s)\n", rs, rs ? libusb_error_name(rs) : "ok");
  } else {
    printf("\nhalts cleared; NOT resetting (a reset would need a cold boot to undo).\n");
    printf("if the chip is still wedged, leave it enumerated and retry — do not escalate.\n");
  }

  if (r == 0) libusb_release_interface(h, 0);
  libusb_close(h);
  libusb_exit(ctx);
  return 0;
}
