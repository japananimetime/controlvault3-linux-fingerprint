# The ControlVault 3 fingerprint secure channel

Reverse-engineered protocol for the Dell/Broadcom **ControlVault 3** fingerprint sensor
(BCM58200, USB `0a5c:5843`), enough to enroll and verify fingerprints natively on Linux. The
stock `libfprint-2-tod1-broadcom` driver never opens this channel, which is why enrollment always
failed with `libfprint`.

## Why the stock driver fails
Every fingerprint command that matters (`0x6C update`, `0x6E commit`, `0x73 match`) must be sent
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
| `0x73` | `0x47` | wrapped | match (verify) |
| `0x04` / `0x68` | `0x44` | plain | close session / cancel capture |

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

## Verify
```
0x02 open  →  0x66 capture  →  wait 0x03  →  0x73 match
```
The `0x73` reply decrypts to a verdict: word at plaintext `+8` is `1` = match (with the matched
20-byte template id at `+32`), `0` = no match. A genuine on-device biometric comparison; proven by
a wrong-finger test returning `0`.

## Recovery
An interrupted session (a killed process leaving a capture armed) wedges the command interface
(`0x23` bulk-OUT timeout, USB still enumerated). Gentle fix:
`echo 0 > /sys/bus/usb/devices/<dev>/authorized; sleep 2; echo 1 > .../authorized`. Do **not** use
the port `disable` knob — it can cause an unrecoverable `error -110` needing a reboot. The tools here defend against it two ways: they install SIGTERM/SIGINT/SIGHUP handlers that
cancel the capture and close the session before exiting (so a cancelled prompt or a suspend can't
wedge it), and on startup they detect a light wedge (`0x23` timeout) and auto-recover with the
`authorized` toggle before retrying. Only an uncatchable `kill -9` mid-capture, or the rare deep
wedge, still needs the manual reboot.
