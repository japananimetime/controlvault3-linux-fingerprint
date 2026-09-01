// cvchan — native Linux ControlVault secure channel: open the wrapped session the way Windows
// does, from scratch, using the extracted host ECDH private key.
//
// This is the payoff of the whole reverse-engineering effort (see "Secure Channel Internals.md").
// The Windows driver never opens this channel; the stock Linux driver's 0x6C is rejected because
// it is unwrapped. Here we reproduce the exact Windows key schedule:
//
//     Z          = ECDH(hostPrivD, devicePub)              devicePub = 0x23-reply param[0:64]
//     master     = SHA1(Z)
//     sessionKey = SHA1( master || deviceNonce || hostNonce2 )[:16]      (AES-128)
//                    deviceNonce = 0x23-reply tail[128:148] (device random)
//                    hostNonce2  = the 20 bytes we send in 0x24          (our random)
//     wrap       = AES-128-CBC / PKCS7 over the parameter area; IV = 16 random bytes at frame +24
//
// Validated offline: this key decrypts win-enroll1's wrapped frames to the exact known plaintext.
//
// MILESTONE 1 (this file's main goal): open the channel — wrapped 0x02 accepted (CV 0x00) — which
// proves the extraction + KDF end-to-end on real hardware. MILESTONE 2: the enroll sequence
// (0x8A/0x66/0x6C/0x6E) is scaffolded below using the decrypted plaintext formats.
//
//
// Keyless: generates an ephemeral host keypair each run. The chip does not authenticate
// the host key, so no extraction / stored key is needed.
// Build:  gcc -O2 -o cvchan cvchan.c -lusb-1.0 -lcrypto
// Run as root with fprintd stopped.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define VID 0x0a5c
#define PID 0x5843
#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_INT 0x85


static libusb_device_handle *h;
static unsigned char rb[8192];
static int rlen;

static void put32(unsigned char *p, unsigned v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static unsigned get32(const unsigned char *p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned)p[3]<<24); }
static void hexdump(const char *t, const unsigned char *p, int n){
    printf("      %s", t); for(int i=0;i<n;i++) printf("%02x%s", p[i], (i%4==3)?" ":""); printf("\n");
}
static int unhex(const char *s, unsigned char *o){ int n=0; for(;s[0]&&s[1];s+=2){ char b[3]={s[0],s[1],0}; o[n++]=(unsigned char)strtol(b,0,16);} return n; }

// ---- crypto -------------------------------------------------------------------------------

static EC_KEY *host_key = NULL;          // ephemeral host keypair (generated per run)
static unsigned char host_pub[64];       // its public key, X||Y
static unsigned char session_key[16];   // AES-128 key
static unsigned char master[20];        // SHA1(Z)
static unsigned wrap_seq = 0;           // per-session wrapped-command counter (MAC suffix)

static int gen_host_key(void){
    host_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(!host_key || !EC_KEY_generate_key(host_key)) return -1;
    const EC_GROUP *g = EC_KEY_get0_group(host_key);
    const EC_POINT *P = EC_KEY_get0_public_key(host_key);
    BN_CTX *c = BN_CTX_new(); BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates(g, P, x, y, c);
    BN_bn2binpad(x, host_pub, 32); BN_bn2binpad(y, host_pub+32, 32);
    BN_free(x); BN_free(y); BN_CTX_free(c);
    return 0;
}

// Z = ECDH(ephemeral host key, devicePub[0:64] = X||Y). Returns 32-byte shared secret (X coord) in out.
static int ecdh_shared(const unsigned char *devpub64, unsigned char out[32]){
    int ok=-1;
    const EC_GROUP *grp = EC_KEY_get0_group(host_key);
    BIGNUM *x = BN_bin2bn(devpub64, 32, NULL);
    BIGNUM *y = BN_bin2bn(devpub64+32, 32, NULL);
    EC_POINT *pub = EC_POINT_new(grp);
    BN_CTX *ctx = BN_CTX_new();
    if(EC_POINT_set_affine_coordinates(grp, pub, x, y, ctx) &&
       ECDH_compute_key(out, 32, pub, host_key, NULL) == 32)
        ok = 0;
    EC_POINT_free(pub); BN_free(x); BN_free(y); BN_CTX_free(ctx);
    return ok;
}

// sessionKey = SHA1( master(20) || deviceNonce(20) || hostNonce2(20) )[:16]
static void derive_session_key(const unsigned char *deviceNonce, const unsigned char *hostNonce2){
    unsigned char buf[60], dig[20];
    memcpy(buf,    master,      20);
    memcpy(buf+20, deviceNonce, 20);
    memcpy(buf+40, hostNonce2,  20);
    SHA1(buf, 60, dig);
    memcpy(session_key, dig, 16);
}

// AES-128-CBC, IV supplied. PKCS7. Returns output length, or -1.
static int aes_cbc(int enc, const unsigned char *iv, const unsigned char *in, int inlen,
                   unsigned char *out){
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l1=0, l2=0, rc=-1;
    if(EVP_CipherInit_ex(c, EVP_aes_128_cbc(), NULL, session_key, iv, enc) &&
       EVP_CipherUpdate(c, out, &l1, in, inlen) &&
       EVP_CipherFinal_ex(c, out+l1, &l2))
        rc = l1+l2;
    EVP_CIPHER_CTX_free(c);
    return rc;
}


static int hdr(unsigned char*,unsigned,unsigned,unsigned,unsigned,unsigned);

// The frame integrity token: HMAC-SHA256(macKey, header || tlv || 4 zero bytes), placed in the
// 32-byte token slot before encryption. macKey = SHA256("CV secure session blob\0"). Discovered
// by matching a live-captured enroll token. Without it the chip returns CV 0x0F.
static const unsigned char MAC_SEED[23] =
  {'C','V',' ','s','e','c','u','r','e',' ','s','e','s','s','i','o','n',' ','b','l','o','b','\0'};

// Build a wrapped command with the MAC token. tlv = leading param (declared at +40); the full
// plaintext is tlv(tlvlen) + token(32) + zero-trailer to reach ptlen, then AES-CBC/PKCS7.
static int build_wrapped_mac(unsigned char *out, unsigned cmd, unsigned attr, unsigned handle,
                             const unsigned char *tlv, int tlvlen, int ptlen, unsigned macsuffix){
    unsigned char macKey[32]; SHA256(MAC_SEED, 23, macKey);
    unsigned char iv[16]; RAND_bytes(iv, 16);
    int ctlen = ((ptlen/16)+1)*16;              // PKCS7 always adds a block when ptlen%16==0
    int total = 44 + ctlen;
    hdr(out, cmd, attr, 0x02, handle, total);
    memcpy(out+24, iv, 16);
    put32(out+40, tlvlen);                       // +40 = logical (declared) param length

    // MAC input = header(44) + tlv + 4 zero bytes
    // MAC input = header || tlv || 4-byte LE command suffix (0x02:0, 0x66:1, 0x6C:9, 0x6E:1)
    unsigned char macin[256]; memcpy(macin, out, 44); memcpy(macin+44, tlv, tlvlen);
    put32(macin+44+tlvlen, macsuffix);
    unsigned char token[32]; unsigned int tl;
    HMAC(EVP_sha256(), macKey, 32, macin, 44+tlvlen+4, token, &tl);

    // plaintext = tlv || token || zero trailer
    unsigned char pt[256]; memset(pt, 0, ptlen);
    memcpy(pt, tlv, tlvlen);
    memcpy(pt+tlvlen, token, 32);
    unsigned char ct[512];
    int clen = aes_cbc(1, iv, pt, ptlen, ct);
    if(clen < 0) return -1;
    memcpy(out+44, ct, clen);
    return total;
}

// ---- USB transaction ----------------------------------------------------------------------

static int xfer(const unsigned char *frame, int n, const char *tag){
    static unsigned char out[8192]; memcpy(out, frame, n);
    int a=0, rc=libusb_bulk_transfer(h, EP_OUT, out, n, &a, 5000);
    if(rc){ printf("    %-14s bulk OUT %s\n", tag, libusb_error_name(rc)); return -2; }
    unsigned char ib[32];
    rc=libusb_interrupt_transfer(h, EP_INT, ib, sizeof ib, &a, 60000);
    if(rc){ printf("    %-14s intr IN %s\n", tag, libusb_error_name(rc)); return -2; }
    unsigned ts=get32(ib), rl=(a>=8)?get32(ib+4):0;
    if(rl==0){ printf("    %-14s transport=0x%02x len=0 (no body)\n", tag, ts); rlen=0; return -3; }
    rc=libusb_bulk_transfer(h, EP_IN, rb, rl>sizeof rb ? sizeof rb : rl, &a, 5000);
    if(rc){ printf("    %-14s bulk IN %s\n", tag, libusb_error_name(rc)); return -2; }
    rlen=a; int cv=(a>=24)?(int)get32(rb+20):-1;
    printf("    %-14s transport=0x%02x len=%-4d CVstatus=0x%02X\n", tag, ts, a, cv);
    return cv;
}

// Wait for the async "finger captured" event (interrupt status 0x03). See Async Capture Protocol.
static int wait_capture_event(void){
    unsigned char ib[32]; int a=0;
    int rc=libusb_interrupt_transfer(h, EP_INT, ib, sizeof ib, &a, 60000);
    if(rc){ printf("    async wait: %s\n", libusb_error_name(rc)); return -1; }
    unsigned ts=get32(ib);
    printf("    async event  status=0x%02x\n", ts);
    return (ts==0x03) ? 0 : -1;
}

// ---- framing ------------------------------------------------------------------------------

// Build a header at p for cmd, with +10 attr and +11 encoding. Returns 44 (header size).
static int hdr(unsigned char *p, unsigned cmd, unsigned attr, unsigned enc, unsigned handle,
               unsigned total){
    memset(p, 0, 44);
    put32(p, 1);
    put32(p+4, total);
    p[8]=cmd & 0xff; p[9]=(cmd>>8)&0xff; p[10]=attr; p[11]=enc;
    put32(p+12, 2);
    put32(p+16, handle);
    return 44;
}

// Build a WRAPPED session frame: header + IV@+24 + AES-CBC(param). attr/enc per Secure Channel
// (session-scoped wrapped: +10=0x45, +11=0x02; 0x66 uses +10=0x47). Returns total length.
static int build_wrapped(unsigned char *out, unsigned cmd, unsigned attr, unsigned handle,
                         const unsigned char *param, int plen, int declared_len){
    unsigned char iv[16]; RAND_bytes(iv, 16);
    unsigned char ct[512];
    int clen = aes_cbc(1, iv, param, plen, ct);
    if(clen < 0) return -1;
    int total = 44 + clen;
    hdr(out, cmd, attr, 0x02, handle, total);
    memcpy(out+24, iv, 16);        // IV lives in the header nonce slot
    // +40 is the LOGICAL param length (the leading TLV), not the ciphertext length:
    // 0x02->36, 0x66->36, 0x8a->12, 0x6c->48. The token + trailer follow inside the encryption.
    put32(out+40, declared_len);
    memcpy(out+44, ct, clen);
    return total;
}

// Decrypt a wrapped reply's parameter area (in rb) into pt. Returns plaintext length or -1.
static int unwrap_reply(unsigned char *pt){
    if(rlen < 44+16) return -1;
    int clen = rlen - 44;                 // ciphertext = everything after the header
    if(clen <= 0 || clen % 16) return -1;
    return aes_cbc(0, rb+24, rb+44, clen, pt);   // aes_cbc strips PKCS7
}

static void close_handle(unsigned handle){
    if(!handle) return;
    unsigned char cl[56]; hdr(cl, 0x04, 0x40, 0x04, 0, 56);   // 0x04 is sessionless plaintext
    put32(cl+40, 12); put32(cl+48, 4); put32(cl+52, handle);
    xfer(cl, 56, "0x04 close");
}


// Send an UNWRAPPED session command (0x8A, 0x39, 0x04, 0x68): header + plaintext TLV. +11=0x00.
static int send_plain(unsigned cmd, unsigned attr, const unsigned char *tlv, int tlvlen,
                      unsigned handle, const char *tag){
    unsigned char f[128]; int total = 44 + tlvlen;
    hdr(f, cmd, attr, 0x00, handle, total);
    put32(f+40, tlvlen);
    if(tlv && tlvlen) memcpy(f+44, tlv, tlvlen);
    return xfer(f, total, tag);
}

static int cap_armed = 0;
// Cancel a pending capture (0x68 is unwrapped, sessionless in every capture).
static void cancel_pending(void){
    if(!cap_armed) return;
    unsigned char t68[12] = {0,0,0,0, 4,0,0,0, 0,0,0,0};
    send_plain(0x68, 0x44, t68, 12, 0, "0x68 cancel");
    cap_armed = 0;
}

// Search a decrypted plaintext for a TLV entry of the given value size; copy the value out.
static int find_param_pt(const unsigned char *pt, int ptlen, int want, unsigned char *out){
    for(int i=0; i+8+want <= ptlen; i+=4)
        if(get32(pt+i) <= 3 && get32(pt+i+4) == (unsigned)want){ memcpy(out, pt+i+8, want); return 1; }
    return 0;
}

// ---- main ---------------------------------------------------------------------------------

int main(int argc, char **argv){
    if(gen_host_key()){ fprintf(stderr, "key generation failed\n"); return 1; }

    libusb_context *ctx=0;
    if(libusb_init(&ctx)){ fprintf(stderr,"libusb_init failed\n"); return 1; }
    h=libusb_open_device_with_vid_pid(ctx, VID, PID);
    if(!h){ fprintf(stderr,"device not found (fprintd holding it?)\n"); return 1; }
    if(libusb_kernel_driver_active(h,0)==1) libusb_detach_kernel_driver(h,0);
    if(libusb_claim_interface(h,0)){ fprintf(stderr,"claim_interface failed\n"); return 1; }

    // --- 0x23 challenge: sessionless, plaintext, 20-byte client nonce -----------------------
    unsigned char clientNonce[20]; RAND_bytes(clientNonce, 20);
    unsigned char f23[68]; hdr(f23, 0x23, 0x41, 0x00, 0, 68);
    put32(f23+40, 24);                       // param len = 24
    memcpy(f23+44, clientNonce, 20);
    put32(f23+64, 1);
    printf("=== handshake ===\n");
    if(xfer(f23, 68, "0x23 challenge") != 0){ printf("  0x23 rejected\n"); goto done; }

    unsigned handle = get32(rb+16);
    unsigned char devicePub[64], deviceNonce[20];
    memcpy(devicePub,   rb+44,      64);     // param[0:64]  = device ECDH public key
    memcpy(deviceNonce, rb+44+128,  20);     // param[128:148] = device nonce
    printf("      handle 0x%08x\n", handle);
    hexdump("devicePub X   ", devicePub, 16);
    hexdump("deviceNonce   ", deviceNonce, 20);

    // --- 0x24 response: host pubkey + our hostNonce2 (which enters the KDF) ------------------
    unsigned char hostNonce2[20]; RAND_bytes(hostNonce2, 20);
    unsigned char f24[128]; hdr(f24, 0x24, 0x01, 0x00, handle, 128);
    put32(f24+40, 84);                       // param len = 84 = 20 nonce + 64 pubkey
    memcpy(f24+44,    hostNonce2, 20);
    memcpy(f24+44+20, host_pub,   64);
    if(xfer(f24, 128, "0x24 response") != 0){ printf("  0x24 rejected\n"); close_handle(handle); goto done; }

    // --- derive the session key -------------------------------------------------------------
    unsigned char Z[32];
    if(ecdh_shared(devicePub, Z)){ printf("  ECDH failed\n"); close_handle(handle); goto done; }
    SHA1(Z, 32, master);
    derive_session_key(deviceNonce, hostNonce2);
    printf("\n=== key derivation ===\n");
    hexdump("Z (ECDH)      ", Z, 16);
    hexdump("master SHA1(Z)", master, 20);
    hexdump("session key   ", session_key, 16);

    // --- MILESTONE: wrapped 0x02 open_session -----------------------------------------------
    // Plaintext param from win-enroll1 (the 32-byte value is a per-session token; zero-fill is
    // accepted by the chip in testing — if not, capture a fresh one). PKCS7 is added by aes_cbc.
    // 0x02 open_session: 36-byte TLV param, then HMAC token + trailer -> 80-byte plaintext.
    unsigned char tlv02[36] = {
        0,0,0,0, 4,0,0,0, 0x4f,0,0,0, 1,0,0,0,
        0,0,0,0, 1,0,0,0, 0,0,0,0, 1,0,0,0, 0,0,0,0 };
    unsigned char f02[256];
    int n02 = build_wrapped_mac(f02, 0x02, 0x45, handle, tlv02, 36, 80, wrap_seq);
    printf("\n=== wrapped 0x02 open_session ===\n");
    hexdump("IV sent       ", f02+24, 16);
    int cv = xfer(f02, n02, "0x02 wrapped");

    if(cv != 0){ printf("\n  0x02 open failed (CV 0x%02X) — cannot enroll.\n", cv); close_handle(handle); goto done; }
    { unsigned char pt[512]; int pl = unwrap_reply(pt);
      printf("\n  *** CHANNEL OPEN (CV 0x00) ***\n");
      if(pl>0) hexdump("  reply         ", pt, pl>32?32:pl); }
    wrap_seq = 1;  // 0x02 consumed seq 0

    if(argc>2 && strcmp(argv[2],"verify")==0){
        printf("\n=== verify: touch the enrolled finger ===\n");
        // 0x66 capture (wrapped) -> async 0x03 -> 0x73 match
        unsigned char t66[36] = {
            0,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0, 1,0,0,0, 0,0,0,0, 4,0,0,0, 0x23,0,0,0 };
        put32(t66+8, handle);
        unsigned char f66[256]; int n66=build_wrapped_mac(f66,0x66,0x47,handle,t66,36,80,wrap_seq);
        int c=xfer(f66,n66,"0x66 capture");
        if(c==0x85){ cancel_pending(); c=xfer(f66,n66,"0x66 retry"); }
        if(c!=0){ printf("  0x66 failed CV 0x%02X\n", c); cancel_pending(); close_handle(handle); goto done; }
        wrap_seq++; cap_armed=1;
        if(wait_capture_event() < 0){ cancel_pending(); close_handle(handle); goto done; }
        cap_armed=0;
        // 0x73 match: TLV(68), attr 0x47, ptlen 112 (TLV+token+12 pad)
        unsigned char t73[68] = {
            0,0,0,0, 4,0,0,0, 0,0,0,0,               // handle @ +8
            0,0,0,0, 4,0,0,0, 0x48,0x01,0,0,
            0,0,0,0, 4,0,0,0, 0xe2,0x53,0,0,
            0,0,0,0, 4,0,0,0, 0,0,0,0,
            2,0,0,0, 4,0,0,0, 0xd3,0x0a,0x7b,0,
            3,0,0,0, 0x14,0,0,0 };
        put32(t73+8, handle);
        unsigned char f73[256]; int n73=build_wrapped_mac(f73,0x73,0x47,handle,t73,68,112,wrap_seq);
        c=xfer(f73,n73,"0x73 match");
        printf("\n=== verify result ===\n");
        if(c==0){
            unsigned char pt[512]; int pl=unwrap_reply(pt);
            printf("  0x73 reply plaintext (%d bytes):\n", pl);
            for(int i=0;i<pl;i+=16){ printf("    +%03d:",i); for(int j=i;j<i+16&&j<pl;j++) printf(" %02x",pt[j]); printf("\n"); }
            unsigned mflag = get32(pt+8);   // +8: 1 = match, 0 = no match (verified by wrong-finger test)
            if(mflag == 1){
                // matched template id is the 20-byte value after the d3.. / 14000000 marker
                unsigned char mid[20]; if(pl>=52) memcpy(mid, pt+32, 20);
                hexdump("  matched id    ", mid, 20);
                printf("  *** MATCH — the finger matched an enrolled template ***\n");
            } else {
                printf("  match flag = %u  ->  NO MATCH (finger not enrolled)\n", mflag);
            }
        } else printf("  0x73 returned CV 0x%02X\n", c);
        cancel_pending(); close_handle(handle); goto done;
    }

    // ===================== ENROLLMENT =====================
    // 0x8A start (unwrapped), then per sample: 0x66 capture (wrapped) -> async 0x03 ->
    // 0x6C update (wrapped, carries the capture hash) -> 0x8F more / 0x00 done. Then 0x6E commit.
    printf("\n=== enrollment: touch the sensor repeatedly ===\n");
    // Discard any pending/stuck enrollment (0x6D) first, then start fresh.
    { unsigned char t6d[12] = {0,0,0,0, 4,0,0,0, 0,0,0,0};
      put32(t6d+8, handle);
      unsigned char f6d[128]; int n6d=build_wrapped_mac(f6d,0x6D,0x45,handle,t6d,12,48,wrap_seq);
      int cd=xfer(f6d,n6d,"0x6D discard");
      if(cd!=0x0F && cd>=0) wrap_seq++;
      printf("  (discard CV 0x%02X)\n", cd);
    }
    if(argc>2 && strcmp(argv[2],"reset")==0){
        printf("\n(reset mode: state cleared, exiting)\n");
        cancel_pending(); close_handle(handle); goto done;
    }
    { unsigned char t8a[12] = {0,0,0,0, 4,0,0,0, 0,0,0,0};
      send_plain(0x8A, 0x44, t8a, 12, 0, "0x8A start"); }

    unsigned char lasthash[20]; memset(lasthash,0,20);
    unsigned char commit_id[20]; int have_commit_id=0;
    const int NEED = 16;   // Windows collects ~16 samples before commit
    int accepted=0, done_flag=0;
    for(int spl=0; spl<30 && !done_flag; spl++){
        // 0x66 capture (wrapped, TLV 36)
        unsigned char t66[36] = {
            0,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0, 1,0,0,0, 0,0,0,0, 4,0,0,0, 0x23,0,0,0 };
        put32(t66+8, handle);
        unsigned char f66[256]; int n66=build_wrapped_mac(f66,0x66,0x47,handle,t66,36,80,wrap_seq);
        printf("\n[sample %d] touch now...\n", spl+1);
        int c=xfer(f66,n66,"0x66 capture");
        if(c==0x85){ // capture already pending: cancel then retry
            unsigned char t68[12]={0,0,0,0,4,0,0,0,0,0,0,0}; put32(t68+8,handle);
            send_plain(0x68,0x40,t68,12,handle,"0x68 cancel");
            c=xfer(f66,n66,"0x66 retry");
        }
        if(c!=0){ if(c<0) break; if(c==0x0F){printf("  (0x66 MAC rejected at seq=%u)\n",wrap_seq);} continue; }
        wrap_seq++; cap_armed = 1;
        // extract the 20-byte capture hash from the decrypted arm-ACK
        unsigned char pt[512]; int pl=unwrap_reply(pt);
        printf("  0x66 reply plaintext (%d bytes):\n", pl);
        for(int i=0;i<pl;i+=16){ printf("    +%03d:",i); for(int j=i;j<i+16&&j<pl;j++) printf(" %02x",pt[j]); printf("\n"); }
        unsigned char hash[20];
        if(pl<=0 || !find_param_pt(pt,pl,20,hash)){ printf("  (no 20-byte hash in 0x66 reply) — cancelling\n"); cancel_pending(); break; }
        hexdump("  capture hash  ", hash, 20);
        // block until the device reports the finger was actually read
        if(wait_capture_event() < 0) break;   // returns 0 on the 0x03 finger-read event
        memcpy(lasthash,hash,20);
        // 0x6C update (wrapped, TLV 48 with the hash)
        unsigned char t6c[48] = {
            0,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0, 0x14,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 2,0,0,0, 0,0,0,0 };
        put32(t6c+8, handle); memcpy(t6c+20, hash, 20);
        unsigned char f6c[256]; int n6c=build_wrapped_mac(f6c,0x6C,0x45,handle,t6c,48,80,wrap_seq);
        c=xfer(f6c,n6c,"0x6C update");
        cap_armed = 0;
        if(c!=0x0F && c>=0) wrap_seq++;
        if(c==0 || c==0x8F){ accepted++;
            unsigned char rpt[512]; int rpl=unwrap_reply(rpt);
            printf("  0x6C reply (%d): ", rpl);
            for(int i=0;i<rpl && i<64;i++) printf("%02x%s", rpt[i], (i%4==3)?" ":"");
            printf("\n  -> stage accepted (CV 0x%02X) [%d accepted]\n", c, accepted);
            memcpy(lasthash, hash, 20);
            // Completion: the device returns a NEW 20-byte id (!= the sample hash we sent).
            unsigned char rhash[20];
            if(find_param_pt(rpt, rpl, 20, rhash) && memcmp(rhash, hash, 20)!=0){
                memcpy(commit_id, rhash, 20); have_commit_id = 1; done_flag = 1;
                printf("  *** ENROLLMENT COMPLETE — device template id received ***\n");
            }
        }
        else if(c==0xA4||c==0x89){ printf("  -> retry this scan (0x%02X)\n", c); }
        else if(c==0x8C){ printf("  -> 0x8C (no more samples accepted) — stopping\n"); done_flag=1; }
        else if(c<0) break;
        else { printf("  -> 0x6C returned CV 0x%02X\n", c); }
    }
    printf("\n  accepted stages: %d, done_flag=%d\n", accepted, done_flag);

    // 0x6E commit (wrapped, TLV 64 with the last hash)
    { unsigned char t6e[64] = {
        0,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0, 0x14,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        2,0,0,0, 0,0,0,0, 2,0,0,0, 0,0,0,0, 3,0,0,0, 0,0,0,0 };
      put32(t6e+8, handle); memcpy(t6e+20, have_commit_id?commit_id:lasthash, 20);
      printf("  committing with %s id\n", have_commit_id?"device-template":"last-hash");
      unsigned char f6e[256]; int n6e=build_wrapped_mac(f6e,0x6E,0x45,handle,t6e,64,96,wrap_seq);
      printf("\n=== commit ===\n");
      int c=xfer(f6e,n6e,"0x6E commit");
      if(c==0) printf("  *** COMMIT OK (CV 0x00) — enrollment stored ***\n");
      else printf("  commit returned CV 0x%02X\n", c);
    }

    // 0x2F query (wrapped) — ground truth: is a template now stored?
    { unsigned char t2f[56] = {
        0,0,0,0, 4,0,0,0, 0,0,0,0, 0,0,0,0, 4,0,0,0, 0x48,0,0,0,
        0,0,0,0, 4,0,0,0, 0xe2,0x53,0,0, 0,0,0,0, 4,0,0,0, 0,0,0,0, 2,0,0,0, 0,0,0,0 };
      put32(t2f+8, handle);
      unsigned char f2f[256]; int n2f=build_wrapped_mac(f2f,0x2F,0x42,handle,t2f,56,88,wrap_seq+1);
      int c=xfer(f2f,n2f,"0x2F query");
      if(c==0){ unsigned char pt[512]; int pl=unwrap_reply(pt);
        printf("  0x2F reply plaintext (%d bytes):\n", pl);
        for(int i=0;i<pl;i+=16){ printf("    +%03d:",i); for(int j=i;j<i+16&&j<pl;j++) printf(" %02x",pt[j]); printf("\n"); } }
    }

    cancel_pending();
    close_handle(handle);

done:
    libusb_release_interface(h,0); libusb_close(h); libusb_exit(ctx);
    return 0;
}
