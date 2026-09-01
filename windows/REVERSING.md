---
tags: [controlvault, windows, reversing, howto]
created: 2026-09-01
---

# Windows Dynamic-Analysis Recipe

Goal: capture the **session key** and the **decrypted `0x6C`/`0x6E` payloads** during a real
Windows enrollment, so the [[Secure Channel|wrapping]] can be reproduced on Linux. Targets and
theory: [[Windows Secure-Channel Targets]].

> [!warning] Admin, and Secure Boot / anti-tamper
> Run everything **elevated**. Frida injects a thread; if a Dell security agent or HVCI blocks
> injection, use the x64dbg route below instead. Nothing here modifies the chip or the driver —
> it only reads buffers in RAM.

## Frida route (preferred — scriptable buffer dumps)

> [!note] Executed 2026-09-01 on the Windows side — read this before the manual steps
> `capture-keys.py` (in this folder) is the runner that does all of the below. The bare
> `frida -p <PID> -l cvhook.js` from the original recipe does **not** work as-is on this machine
> for two reasons, both handled by the runner:
>
> - **Frida 17 removed the static `Module.findExportByName(dll, fn)`.** `cvhook.js` was updated to
>   resolve exports off the module object and to force-load `ncrypt.dll` when it is lazy. Without
>   this the script threw on load and hooked nothing.
> - **`WUDFHost.exe` (which hosts `ushwbfdrv.dll`) refuses Frida agent injection** —
>   `ProcessNotRespondingError`, and it is *not* a signature block (`MicrosoftSignedOnly: OFF`).
>   The injectable processes are **`WbioSrvc`** (svchost — carries `bcmbipdll` + the three Brcm
>   adapters + `ncrypt`/`bcrypt`) and the two bcm host services. `WbioSrvc` is **demand-start**, so
>   its PID does not exist until enrollment begins; the runner starts it first.
>
> If the capture comes back empty, the wrap runs only in `WUDFHost` and Frida cannot reach it —
> use the WinDbg/x64dbg route, whose debugger attach is allowed where injection is refused.

### 1. Install
```powershell
winget install --id Python.Python.3.13 -e --scope machine
& "C:\Program Files\Python313\python.exe" -m pip install frida-tools
```

### 2 + 3. Arm and enroll (one command)
```powershell
& "C:\Program Files\Python313\python.exe" capture-keys.py --auto -t 240
```
It starts `WbioSrvc`, attaches to every injectable CV process, skips `WUDFHost` with a note, then
prints **ARMED**. Only THEN: Settings → Accounts → Sign-in options → Fingerprint → add a finger,
and touch through the whole enrollment. It writes `../captures/win-enroll-hooks.log` and prints a
summary; non-zero `NCryptDeriveKey`/`BCryptEncrypt`/`BCryptDecrypt` counts mean the capture worked.

Manual equivalent, one process at a time (note the Frida-17 caveat above):
```powershell
frida -p <PID> -l cvhook.js  >  cvhook-enroll.log  2>&1
```
Wait for `[*] cvhook armed`, enroll, `Ctrl+D` to detach.

### 4. What you get, and what matters
- **`NCryptCreatePersistedKey` / `NCryptOpenKey`** — settles the fork: a `keyName="BCM Host ECDH
  KEY"` on *Open* means persisted (extractable from disk); a null name on *Create* means
  ephemeral. The flag line says user vs machine store.
- **`NCryptDeriveKey >>> DERIVED SESSION KEY`** and **`BCryptGenerateSymmetricKey RAW KEY`** — the
  session key in the clear. With it, decrypt the recorded `captures/win-enroll1.pcap` offline.
- **`BCryptDecrypt >>> DECRYPTED`** — the wrapped payloads already in plaintext. This is the real
  `0x6C update_enrollment` / `0x6E commit` parameter format — the thing the wire never shows.
- **`NCryptDeriveKey` KDF name + parameters** — the exact derivation (KDF label, hash alg, the
  prepend/append secrets) needed to recompute the key on Linux.

Save `cvhook-enroll.log` and drop it in `captures/` (rename `win-enroll-hooks.log`). Correlate the
`CIPHERTEXT`/`PLAINTEXT` pairs to frames in the pcap by matching ciphertext bytes.

## x64dbg route (fallback if injection is blocked)

Attach x64dbg (64-bit) to the process from step 2. Set breakpoints by API, log-and-continue:

```
bp ncrypt.NCryptDeriveKey
bp bcrypt.BCryptGenerateSymmetricKey
bp bcrypt.BCryptDecrypt
bp ncrypt.NCryptOpenKey
```

- **NCryptOpenKey**: at the breakpoint, `rdx`... no — arg3 `pwszKeyName` is in **r8**
  (x64: rcx,rdx,r8,r9). `du r8` to read the key name.
- **BCryptGenerateSymmetricKey**: raw key = `pbSecret` (5th arg) at `[rsp+0x28]` on entry;
  `dq [rsp+0x28]` to get the pointer, then `db <ptr> L20`.
- **NCryptDeriveKey**: `pbDerivedKey` (4th arg) = `r9`; the bytes are filled on return, so set a
  breakpoint on the return address and `db r9 L20` there. `cbDerivedKey` at `[rsp+0x28]`.
- **BCryptDecrypt**: `pbOutput` (7th arg) at `[rsp+0x38]`; dump it on return.

x64 arg positions: 1=rcx 2=rdx 3=r8 4=r9 5=[rsp+0x28] 6=[rsp+0x30] 7=[rsp+0x38] 8=[rsp+0x40]
9=[rsp+0x48] 10=[rsp+0x50]. (The first 32 bytes above rsp are shadow space.)

## Static companion (Ghidra)

Load `bcmbipdll.dll` and `ushwbfdrv.dll`. There are almost no exports — navigate by the log
format strings, which embed each function's own name (`"%s: ..."`). Search:
`cvhSetUpSecureSession`, `GetHostEncryptNonceCmd`, `cvhEncryptCmd`, `MSCNG_EncryptParamBlob`,
`GenerateSecureSessionCNGHMAC`. Xref each string to its function. Use the Frida-captured key/KDF
to confirm the static reading rather than deriving it cold.

## After you have the key + KDF
Port the derivation and AES wrap into the Linux harnesses (`src/cvwrap.c` already does the
handshake). Then a wrapped `0x02` → `0x66` → `0x6C`×N → `0x6E` sequence can be issued from Linux.
If instead the key turns out user/machine-persisted and you just want it working, the cheaper win
is an on-Windows helper that drives WBF directly — see the endgames in
[[Windows Secure-Channel Targets]].
