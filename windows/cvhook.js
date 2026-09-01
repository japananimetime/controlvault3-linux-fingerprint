/* cvhook.js — Frida hooks for the ControlVault secure channel.
 *
 * Hooks the SYSTEM crypto exports (ncrypt.dll / bcrypt.dll) that bcmbipdll.dll and
 * ushwbfdrv.dll call underneath cvhSetUpSecureSession / MSCNG_EncryptParamBlob. Those
 * internal functions are not exported, but they bottom out in these documented APIs, so
 * hooking here needs no addresses and catches the same material:
 *
 *   - NCryptOpenKey / NCryptCreatePersistedKey  -> is "BCM Host ECDH KEY" persisted or ephemeral,
 *                                                  user- or machine-scoped  (settles the fork)
 *   - NCryptSecretAgreement / NCryptDeriveKey   -> the ECDH inputs and the DERIVED SESSION KEY
 *   - BCryptGenerateSymmetricKey                -> the RAW AES session key, straight out
 *   - BCryptEncrypt / BCryptDecrypt             -> plaintext<->ciphertext + IV/nonce/tag
 *                                                  (Decrypt output = the wrapped payloads, in clear)
 *   - NCryptExportKey                           -> any key blob the stack exports
 *
 * Run:  frida -p <PID> -l cvhook.js        (attach BEFORE starting the enroll)
 *       see find-cv-process.ps1 for the PID.  Output is copy-pasteable hex.
 */

'use strict';

var MAXDUMP = 512;         // cap per-buffer hexdump
var n = { };               // call counters per hook

function tag(name) { n[name] = (n[name] || 0) + 1; return name + ' #' + n[name]; }

function wstr(p) {
  try { return (p.isNull()) ? '(null)' : p.readUtf16String(); } catch (e) { return '(unreadable)'; }
}
function dump(label, ptr, len) {
  try {
    if (ptr.isNull() || len <= 0) { console.log('    ' + label + ': (empty)'); return; }
    var m = Math.min(len, MAXDUMP);
    console.log('    ' + label + ' [' + len + ' bytes' + (m < len ? ', first ' + m : '') + ']:');
    console.log(hexdump(ptr, { length: m, ansi: false, header: false })
                  .split('\n').map(function (l) { return '      ' + l; }).join('\n'));
  } catch (e) { console.log('    ' + label + ': (read failed: ' + e + ')'); }
}
function u32(p) { try { return p.readU32(); } catch (e) { return -1; } }

// Frida 17 removed the static Module.findExportByName(dll, fn); resolution is now off the
// module object. ncrypt.dll can also be loaded lazily (WUDFHost maps it only when the secure
// session starts), so force-load system DLLs into the target first — safe, and the target's own
// later LoadLibrary returns the same mapping.
function resolve(dll, fn) {
  var m = Process.findModuleByName(dll);
  if (m === null) { try { m = Module.load(dll); } catch (e) { return null; } }
  return m ? m.findExportByName(fn) : null;
}

function hook(dll, fn, cfg) {
  var a = resolve(dll, fn);
  if (a === null) { console.log('[!] ' + dll + '!' + fn + ' not found (module not loaded)'); return; }
  Interceptor.attach(a, cfg);
  console.log('[+] hooked ' + dll + '!' + fn + ' @ ' + a);
}

/* ---- key provenance: persisted vs ephemeral, user vs machine ---- */

hook('ncrypt.dll', 'NCryptOpenKey', {   // (hProv, phKey, pwszKeyName, dwKeySpec, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptOpenKey') + ' ===');
    console.log('    keyName = "' + wstr(args[2]) + '"   flags=0x' + args[4].toInt32().toString(16));
    console.log('    -> a persisted key is being OPENED (it exists on disk).');
  }
});

hook('ncrypt.dll', 'NCryptCreatePersistedKey', {  // (hProv, phKey, pwszAlgId, pwszKeyName, dwKeySpec, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptCreatePersistedKey') + ' ===');
    var name = wstr(args[3]);
    var flags = args[5].toInt32();
    console.log('    algId="' + wstr(args[2]) + '"  keyName="' + name + '"  flags=0x' + flags.toString(16));
    console.log('    -> ' + (name === '(null)' || name === '' ? 'EPHEMERAL (no name)' : 'PERSISTED as "' + name + '"')
                + '; ' + ((flags & 0x20) ? 'MACHINE store (NCRYPT_MACHINE_KEY_FLAG)' : 'USER store'));
  }
});

hook('ncrypt.dll', 'NCryptOpenStorageProvider', { // (phProv, pwszProviderName, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptOpenStorageProvider') + ' ===  provider="' + wstr(args[1]) + '"');
  }
});

/* ---- the key agreement and the derived session key ---- */

hook('ncrypt.dll', 'NCryptSecretAgreement', {  // (hPriv, hPub, phSecret, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptSecretAgreement') + ' ===');
    console.log('    hPrivKey=' + args[0] + '  hPubKey=' + args[1] + '  (ECDH shared secret handle produced)');
  }
});

hook('ncrypt.dll', 'NCryptDeriveKey', {
  // (hSecret, pwszKDF, pParameterList, pbDerivedKey, cbDerivedKey, pcbResult, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptDeriveKey') + ' ===');
    console.log('    KDF="' + wstr(args[1]) + '"');
    this.out = args[3]; this.cb = args[4].toInt32(); this.pcb = args[5];
    // walk the NCryptBufferDesc parameter list (cBuffers, version, pBuffers[])
    try {
      var pl = args[2];
      if (!pl.isNull()) {
        var cBuf = pl.add(4).readU32();          // {ULONG ulVersion; ULONG cBuffers; PVOID pBuffers}
        var pBuf = pl.add(8).readPointer();
        console.log('    KDF parameters (' + cBuf + '):');
        for (var i = 0; i < cBuf && i < 8; i++) {
          var e = pBuf.add(i * 16);              // {ULONG cbBuffer; ULONG BufferType; PVOID pvBuffer}
          var cb = e.readU32(), typ = e.add(4).readU32(), pv = e.add(8).readPointer();
          // CNG KDF BufferType: 0=HASH_ALGORITHM(wide str) 1=SECRET_PREPEND 2=SECRET_APPEND
          // 3=HMAC_KEY 8=ALGORITHMID 9=PARTYUINFO 10=PARTYVINFO 0xD=LABEL 0xE=CONTEXT 0xF=SALT
          var names={0:'HASH_ALGORITHM',1:'SECRET_PREPEND',2:'SECRET_APPEND',3:'HMAC_KEY',8:'ALGORITHMID',9:'PARTYUINFO',10:'PARTYVINFO',13:'LABEL',14:'CONTEXT',15:'SALT'};
          var isWide = (typ === 0);   // hash algorithm name, e.g. "SHA256"
          var pretty = isWide ? wstr(pv) : '';
          console.log('      type=' + typ + ' (' + (names[typ]||'?') + ') cb=' + cb + (pretty ? '  "' + pretty + '"' : ''));
          if (!isWide && cb > 0 && cb <= 128) dump('        val', pv, cb);
        }
      }
    } catch (e) { console.log('    (param list parse failed: ' + e + ')'); }
  },
  onLeave: function (ret) {
    var got = u32(this.pcb);
    console.log('    >>> DERIVED SESSION KEY (ret=0x' + ret.toInt32().toString(16) + '):');
    dump('KEY', this.out, got > 0 ? got : this.cb);
  }
});

/* ---- the raw symmetric key going into AES, and the AES itself ---- */

hook('bcrypt.dll', 'BCryptGenerateSymmetricKey', {
  // (hAlg, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('BCryptGenerateSymmetricKey') + ' ===  (raw AES key material)');
    dump('RAW KEY', args[4], args[5].toInt32());
  }
});

function gcmInfo(p) {
  try {
    if (p.isNull()) return;
    if (p.readU32() < 40) return;                 // cbSize sanity
    var pbNonce = p.add(8).readPointer(), cbNonce = p.add(16).readU32();
    var pbTag   = p.add(40).readPointer(), cbTag = p.add(48).readU32();
    dump('nonce/IV', pbNonce, cbNonce);
    if (!pbTag.isNull() && cbTag > 0) dump('GCM tag', pbTag, cbTag);
  } catch (e) { }
}

hook('bcrypt.dll', 'BCryptEncrypt', {
  // (hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('BCryptEncrypt') + ' ===');
    dump('PLAINTEXT in', args[1], args[2].toInt32());
    if (!args[4].isNull()) dump('IV', args[4], args[5].toInt32());
    gcmInfo(args[3]);
    this.out = args[6]; this.pcb = args[8]; this.pad = args[3];
  },
  onLeave: function () {
    dump('CIPHERTEXT out', this.out, u32(this.pcb));
    gcmInfo(this.pad);                            // tag is filled on the way out
  }
});

hook('bcrypt.dll', 'BCryptDecrypt', {
  onEnter: function (args) {
    console.log('\n=== ' + tag('BCryptDecrypt') + ' ===');
    dump('CIPHERTEXT in', args[1], args[2].toInt32());
    if (!args[4].isNull()) dump('IV', args[4], args[5].toInt32());
    gcmInfo(args[3]);
    this.out = args[6]; this.pcb = args[8];
  },
  onLeave: function () {
    console.log('    >>> DECRYPTED (the wrapped payload, in clear):');
    dump('PLAINTEXT out', this.out, u32(this.pcb));
  }
});

/* ---- any exported key blob (may reveal the host private key) ---- */

hook('ncrypt.dll', 'NCryptExportKey', {
  // (hKey, hExportKey, pwszBlobType, pParameterList, pbOutput, cbOutput, pcbResult, dwFlags)
  onEnter: function (args) {
    console.log('\n=== ' + tag('NCryptExportKey') + ' ===  blobType="' + wstr(args[2]) + '"');
    this.out = args[4]; this.pcb = args[6];
  },
  onLeave: function () { dump('exported blob', this.out, u32(this.pcb)); }
});

console.log('\n[*] cvhook armed. Start the fingerprint enrollment now.\n');
