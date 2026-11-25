# The ControlVault 3 fingerprint secure channel

Reverse-engineered protocol for the Dell/Broadcom **ControlVault 3** fingerprint sensor
(BCM58200, USB `0a5c:5843`), enough to enroll and verify fingerprints natively on Linux. The
stock `libfprint-2-tod1-broadcom` driver never opens this channel, which is why enrollment always
failed with `libfprint`.

## Why the stock driver fails
Every fingerprint command that matters (`0x6C update`, `0x6E commit`, `0x2F identify`) must be sent
**inside an encrypted, per-session channel**. The Linux TOD driver sends them in the clear, so the
chip rejects them (`0x8C`/`0x8E`). Windows negotiates the channel with two handshake commands
(`0x23`/`0x24`) that appear in **none** of the Linux driver's traffic.

## Transport
USB bulk OUT `0x01`, bulk IN `0x81`, interrupt IN `0x85`. Every command is a frame:

```
+0   u32  magic = 1
+4   u32  total frame length
+8   u16  command
+10  u8   attr        (per-command, see table)
+11  u8   encoding    0x00 = plaintext, 0x02 = wrapped (encrypted)
+12  u32  = 2
+16  u32  session handle (0 for sessionless)
+20  u32  status       (reply: CV status; 0 = ok) — PLAINTEXT even in wrapped frames
+24  16B  IV / nonce   (wrapped frames: the AES-CBC IV)
+40  u32  parameter length (see notes per encoding)
+44  ...  parameters
```

Send a frame on bulk OUT; the chip answers on interrupt IN with `status:u32 + reply_len:u32`; if
`reply_len > 0`, read `reply_len` bytes from bulk IN. **Always** issue the bulk read the chip
announced, even for `reply_len == 0` drains, or the chip wedges.

## The handshake (`0x23` / `0x24`) — ECDH, and the key finding
```
0x23  host -> chip : 20-byte client nonce
      chip -> host : 128 static bytes (device ECDH public key + cert) + 24-byte device nonce
0x24  host -> chip : 20-byte nonce  +  host ECDH public key (P-256 X||Y, 64 bytes)
```

> **The chip does NOT authenticate the host key.** A freshly generated random P-256 keypair is
> accepted — the chip derives the same session secret from `ECDH(devicePriv, hostPub)` for any
> host keypair, and there is no registration/allow-list check. So **no key extraction is needed**;
> a native driver generates an ephemeral keypair each session. (This was discovered the hard way
> by extracting the Windows host key first — see `../windows` — but that turned out to be
> unnecessary.)

## Key schedule
```
Z          = ECDH(hostPriv, devicePub)                 # devicePub = 0x23-reply first 64 bytes
master     = SHA1(Z)                                   # 20 bytes
deviceNonce = 0x23-reply bytes [128:148]               # from the chip
hostNonce2  = the 20-byte 0x24 field                   # host-chosen (may be random)
sessionKey = SHA1(master ‖ deviceNonce ‖ hostNonce2)[:16]   # AES-128
```

## Wrapped frames
Parameters of session commands are AES-128-CBC/PKCS7 encrypted under `sessionKey`, IV at `+24`.
The plaintext is `TLV ‖ token(32) ‖ zero-pad`, where **`token` is an integrity MAC**:

```
macKey = SHA256("CV secure session blob\0")            # constant
token  = HMAC-SHA256(macKey, header(44) ‖ TLV ‖ u32le(seq))
```

- `header` is the final 44-byte header (with its IV and length already set).
- `TLV` is the leading parameter block; its length goes in the `+40` field.
- **`seq` is a per-session wrapped-command counter**: `0x02 open` = 0, then 1, 2, 3 … It resets on
  each new `0x02`; unwrapped commands (`0x8A`, `0x04`, `0x23`, `0x24`) do not increment it. A wrong
  counter is rejected with `CV 0x0F`.

The reply is wrapped the same way (no MAC), IV at `+24`, ciphertext = everything after the header.

### Command reference (fingerprint subset)
| Cmd | attr `+10` | enc | meaning |
|---|---|---|---|
| `0x23` / `0x24` | `0x41` / `0x01` | plain | ECDH handshake |
| `0x02` | `0x45` | wrapped | open_session (TLV carries the app/user scope) |
| `0x8A` | `0x44` | plain | enrollment start |
| `0x6D` | `0x45` | wrapped | discard pending enrollment |
| `0x66` | `0x47` | wrapped | arm capture (reply carries a 20-byte capture hash) |
| `0x6C` | `0x45` | wrapped | update enrollment (submit a sample) |
| `0x6E` | `0x45` | wrapped | commit enrollment |
| `0x2F` | `0x47` | wrapped | identify / match (carries a u32 template handle) |
| `0x73` | `0x47` | wrapped | legacy hash match — refused with status 89 on current firmware |
| `0x04` / `0x68` | `0x44` | plain | close session / cancel capture |

## The host-timestamp interrupt (type 5)
The sensor can request the host clock at any time — mid-exchange or while waiting for a finger —
and until it is answered the chip stalls everything else. The answer is a vendor control
transfer: `bmRequestType 0x40` (host-to-device, vendor, device), `bRequest 0x0d`,
`wValue`/`wIndex` = the packed timestamp, no data stage. Unsolicited clock syncs are refused, so
only answer when the chip asks.

The packed u32 timestamp, least-significant bits first:
`day:5 | month:4 | (year-2000):6 | hour:5 | min:6 | sec:6` — one second is `1 << 26`.

Timing matters as much as format. Answer at the moment of the event; answers deferred past it
are followed by total chip silence. When a deferred answer must precede a new command, the
control write completes before that command's bulk OUT is submitted — answering and sending in
the same instant leaves the chip deaf to both.

In the fprintd journal the whole dance looks like (Arch Linux fprintd 1.94.5-2 with the MR
applied; debug output, prefixes trimmed):

```
cvfp: reply-listener intr (before rl parse): len=8 [ 05 00 00 00 00 00 00 00 ]
cvfp: host-timestamp request detected mid-exchange — deferring the clock sync
cvfp: 0x2F announcement replaced by a type-5 clock request — answering now, listening for the deferred reply
cvfp: answering host-timestamp request (type 5) with packed bdc03579
cvfp: deferred 0x2F reply listener returned: rlen=108 last_cv=0 last_event=0x5
cvfp: 0x2F verdict=1 matched_id=0x00b46b0f (bound 0x00b46b0f)
```

The listener window can also catch the chip re-requesting a clock it did not receive mid-answer
(`cvfp: finalize-listener: host-timestamp request --- answering, re-arming the window`); the
driver records such a request instead of overlapping the in-flight answer write.

## Enrollment
```
0x02 open  →  0x6D discard  →  0x8A start
repeat:
  0x66 capture            (arms; reply has a 20-byte capture hash)
  wait interrupt 0x03     (the finger is actually read, asynchronously)
  0x6C update (hash)      CV 0x00 = sample accepted; 0xA4/0x89 = retry this scan
completion:               after ~11-12 samples the 0x6C reply returns a NEW 20-byte
                          template id (≠ the sample hash) and its slot field increments
0x6E commit (template id) CV 0x00 = stored
```
Do **not** over-collect past the completion signal — further `0x6C` returns `0x8C` and corrupts the
enrollment. A stuck enrollment is cleared with `0x6D discard`.

**Event-only completion:** current firmware can end the sample loop by signalling event `0x05`
("template updated") instead of answering the final `0x6C`: the reply announcement never comes,
but the chip consumed the command and its wrapped-sequence counter advanced. Keep the counter in
sync, answer any deferred clock request, and open a listener-only interrupt window for the
deferred finalize reply — the enrolment id needed for the commit is only announced there. If
nothing arrives in the window, commit with the accumulated id. Only a commit carrying the
enrolment id is accepted; a commit carrying the sample-hash fallback id is refused (`0x8E`), and
that refusal also releases the chip's "finalize pending" state.

## Verify
```
0x02 open  →  0x66 capture  →  wait 0x03  →  0x2F identify (bound template handle)
```
The request is `0x2F` (attr `0x47`) with TLV
`(0,4,session handle) (0,4,0x48) (0,4,0x53e2) (0,4,0) (2,4,<template handle>)`, template length
60. The `<template handle>` is the u32 id from the `0x6E` commit reply, bound into the stored
print at enroll time; a handle-0 request is an invalid bind. The older hash form (`0x73`) is
refused with status `89` on current firmware.

The reply decrypts to a verdict: word at plaintext `+8` is `1` = match, `0` = no match, with the
matched u32 template handle at `+20` (plus a 32-byte token). A genuine on-device biometric
comparison; proven by a wrong-finger test returning `0`.

## Recovery
An interrupted session (a killed process leaving a capture armed) wedges the command interface
(`0x23` bulk-OUT timeout, USB still enumerated). Gentle fix:
`echo 0 > /sys/bus/usb/devices/<dev>/authorized; sleep 2; echo 1 > .../authorized`.

Do **not** use the port `disable` knob, and do **not** call `libusb_reset_device()` — they are the
same USB port reset, and against an already-wedged chip both are *unrecoverable*.
Measured on the Latitude 5531: the `authorized` toggle re-enumerated the device fine (EP0 was
healthy — only a bulk endpoint was stuck); `libusb_reset_device()` immediately afterwards killed
the BCM58200's USB stack outright: every later enumeration returned `device descriptor read/64,
error -110`, the kernel's own `usb usb3-port8: attempt power cycle` did nothing, and the port
settled at `unable to enumerate USB device`. The chip is a soldered internal device fed from a mainboard
rail rather than switchable port VBUS, so nothing but a full system power-down re-runs its
firmware. **This, not the driver, is what every "needs a cold boot" has actually been.**

Windows never resets this device — it aborts the pipe and issues `CLEAR_FEATURE(ENDPOINT_HALT)`.
That is the whole reason Windows needs no reboots. Escalation ladder, and never go past step 2:

1. `authorized` 0/1 toggle (cvchan does this itself on a `0x23` timeout)
2. `clear_halt` on `0x01` / `0x81` / `0x85` (`cvrecover`)
3. *nothing* — a wedged-but-enumerating chip recovers on its own; a reset one never does. The tools here defend against it two ways: they install SIGTERM/SIGINT/SIGHUP handlers that
cancel the capture and close the session before exiting (so a cancelled prompt or a suspend can't
wedge it), and on startup they detect a light wedge (`0x23` timeout) and auto-recover with the
`authorized` toggle before retrying. Only an uncatchable `kill -9` mid-capture, or the rare deep
wedge, still needs the manual reboot.


### Sleep/resume and other cancels

The driver runs its teardown (0x68 disarm + 0x04 close) whenever an operation is cancelled:
a verify or enroll cancelled by VerifyStop, a lock screen or a suspend disarms the chip before
the cancellation is reported, so the sensor is clean when fprintd releases the interface.
Before that existed, a cancelled prompt left a capture armed with no live host session: the
next open saw an empty 0x23 announcement (leftover sensor events fired first), or straight
bulk-OUT timeouts; repeated Claims silently skipped the open sequence; and the command
interface recovered by itself only after ~105 s of complete silence (measured on a Dell Latitude
7430). An `authorized` 0/1 toggle recovers it at once (step 1 of the ladder
above). With the fix, resume looks like any first open — open + verify in under a second.

The healthy cancel-teardown, as it appears in the fprintd journal (Arch Linux fprintd 1.94.5-2
with the MR applied; debug output, prefixes trimmed, hex elided after the command id where
marked `…`):

```
[cvfp] SSM V_NUM failed in state 3 with error: Operation was cancelled
cvfp: verify was cancelled mid-capture — disarming (0x68) and closing (0x04) before reporting
[cvfp] TD_NUM entering state 0
cvfp: reply-listener intr (before rl parse): len=8 [ 00 00 00 00 2c 00 00 00 ]
cvfp: bulk reply: len=44 [ 01 00 00 00 2c 00 00 00 68 00 44 01 … ]
cvfp: reply status@+20 = 0x00
[cvfp] TD_NUM entering state 1
cvfp: reply-listener intr (before rl parse): len=8 [ 00 00 00 00 2c 00 00 00 ]
cvfp: bulk reply: len=44 [ 01 00 00 00 2c 00 00 00 04 00 40 05 … ]
cvfp: reply status@+20 = 0x0e
[cvfp] TD_NUM completed successfully
```

Both replies carry CV status `0x00` for the `0x68` disarm and `0x0e` for the `0x04` close — the
`0x0e` is part of the normal close dance, not an error, and the teardown treats both as success.

The host had its own wedge, which the driver cannot fix from below: while a device is
suspended, libfprint refuses `fp_device_close()` with `BUSY`, so a client whose verify was
cancelled by the suspend released fprintd's session but left libfprint's device open — and
every later Claim failed with "The device has already been opened!" until the daemon
restarted (upstream issues #173/#216). fprintd MR !259 raises the fix upstream ("close a
device left open when Release is refused during suspend"; open/unmerged at the time of
writing — validated on Arch Linux fprintd 1.94.5-2 with the MR applied, MR tests backported
for compatibility): a Release refused that way completes anyway, the close is owed, and it runs
on resume — the journal line to watch for is `closed unclaimed device`, after `Device 0
is suspended, it will be closed on resume` at sleep. In that validation, suspend during an
active verify, a following idle sleep/resume, and repeated sleep/wake cycles all recovered:
post-resume Claims opened a fresh secure channel (`O_NUM entering state 0`) and
verified in seconds.

Related quirk, now tolerated: between operations the sensor can emit bare event interrupts
(e.g. event 0x03 from a touch on the lock screen, right after a Release and just before the
next 0x23 announcement). The open handshake's listener swallows up to 3 of those instead of
misreading a bare event as an unannounced reply; announcements are delivered FIFO, so the
queued one arrives in the re-armed window.

### Clean-session resume freeze and EP0 wake retry

Teardown-on-cancel is not the whole story: about fifteen minutes after a run of clean
verifies (each ending in the full 0x68 disarm + 0x04 close teardown), the first Claim
after a suspend died at the USB layer with "device was disconnected" — the
suspend tore the interface away mid-handshake. After resume the chip was frozen harder
than the earlier event wedge: the first bulk OUT of every open timed out after
exactly 5 seconds with no interrupt at all, across twelve minutes and many Claims. An
fprintd restart changed nothing (it reclaims the interface but never touches the chip),
and there was no sign of the ~105 s self-recovery seen during the earlier event wedge. The lesson: a
cleanly closed session does not prevent the freeze — it happens inside the chip across
the suspend itself.

The one lever that still worked was step 1 of the ladder: EP0 stays alive while the bulk
endpoints NAK (proven by the authorized toggle re-enumerating the device). The driver
now uses that: when the FIRST bulk OUT of the open handshake times out — no session
handle exists yet, so this is ladder-safe by construction — it sends one benign EP0
vendor control read (a dummy request the interface refuses; a STALL is as good an
answer as data, since both prove the control path ran) and retries the 0x23 handshake
exactly once. No reset, no port disable; the worst case is one extra 5-second timeout.
The authorized 0/1 toggle (step 1 of the ladder above) remains the manual coarse fallback
after a suspect resume.

The wake probe has never fired in the field yet — both observed freezes pre-date it — so these
are expected signatures rather than captured ones (the driver emits these lines verbatim):

```
cvfp: first open bulk OUT timed out — EP0 wake probe, then one 0x23 retry
cvfp: EP0 wake probe answered (8 bytes) — control path alive
cvfp: retrying the 0x23 handshake once
```

If instead the next line is the `got no answer` variant, EP0 did not survive either and the
authorized toggle is the remaining ladder step.
