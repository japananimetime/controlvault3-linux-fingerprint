# Windows appendix — how the channel was discovered (NOT needed to use the sensor)

> **You do not need any of this.** The chip does not authenticate the host key, so the Linux tools
> generate an ephemeral keypair and work with no Windows involvement. This directory is kept only
> to document how the secure channel was reverse-engineered, and as a starting point for anyone
> extending the work.

The channel was found by capturing a working Windows enrollment (USBPcap + `capture-enroll.ps1`),
hooking the Windows CNG crypto to read the session key and decrypted payloads (`cvhook.js`,
Frida), and — before we realized the host key wasn't checked — extracting the Windows host ECDH
key via DPAPI/LSA. That extraction is documented in the project history but is unnecessary in
practice. `REVERSING.md` has the dynamic-analysis recipe.

Nothing here contains keys or per-machine secrets.
