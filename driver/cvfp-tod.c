/*
 * libfprint TOD driver for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 * Implements the reverse-engineered secure channel (see ../docs/secure-channel.md): keyless
 * ECDH-P256 handshake, AES-128-CBC wrapping, enroll/verify. Drop-in replacement for the stock
 * (non-working) libfprint-2-tod-1-broadcom.so.
 *
 * Fully asynchronous. Every USB transfer goes through fpi_usb_transfer_submit and each device
 * operation (open / enroll / verify / close) is driven by an fpi_ssm state machine, so the glib
 * main loop is never blocked: fprintd's Claim/EnrollStart/VerifyStart D-Bus calls return
 * immediately and a cancelled operation unwinds cleanly instead of being SIGKILLed.
 */
#include "drivers_api.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define NR_ENROLL_STAGES 12
#define MAX_ENROLL_SAMPLES 30
#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_INT 0x85

/* Bulk timeouts must stay at 5000ms, exactly like the proven cvchan: a shorter bulk-OUT timeout
   cancels the URB mid-flight and leaves the device's endpoint deep-wedged (survives a USB reset,
   needs a cold boot). The command-reply interrupt gets the same generous window cvchan uses. */
#define TO_BULK    5000
#define TO_INTR   60000
#define TO_FINGER 30000
#define TO_TEARDOWN 3000

struct _FpiDeviceCvfp {
  FpDevice      parent;
  EC_KEY       *host_key;
  guint8        host_pub[64];
  guint8        session_key[16];
  guint8        master[20];
  guint         wrap_seq;
  guint32       handle;

  /* last transceive result */
  guint8        rb[8192];
  gsize         rlen;
  int           last_cv;
  int           last_event;

  /* handshake scratch (0x23 reply -> 0x24 -> KDF) */
  guint8        dpub[64];
  guint8        dn[20];
  guint8        hn2[20];

  /* per-operation scratch */
  gboolean      did_retry;
  int           e_spl;
  int           e_accepted;
  gboolean      e_done;
  guint8        e_hash[20];
  guint8        e_lastid[20];

  GError       *open_error;   /* carried across the open-failure teardown ssm */
};
G_DECLARE_FINAL_TYPE (FpiDeviceCvfp, fpi_device_cvfp, FPI, DEVICE_CVFP, FpDevice)
G_DEFINE_TYPE (FpiDeviceCvfp, fpi_device_cvfp, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = 0x0a5c, .pid = 0x5843 },
  { .vid = 0, .pid = 0 },
};
static const guint8 MAC_SEED[23] =
  {'C','V',' ','s','e','c','u','r','e',' ','s','e','s','s','i','o','n',' ','b','l','o','b','\0'};

static void   p32 (guint8 *p, guint32 v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static guint32 g32 (const guint8 *p){ return p[0]|(p[1]<<8)|(p[2]<<16)|((guint32)p[3]<<24); }

/* --- crypto (keyless: ephemeral host keypair) ------------------------------------------------ */
static gboolean cvfp_gen_key (FpiDeviceCvfp *self){
  self->host_key = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  if (!self->host_key || !EC_KEY_generate_key (self->host_key)) return FALSE;
  const EC_GROUP *g = EC_KEY_get0_group (self->host_key);
  const EC_POINT *P = EC_KEY_get0_public_key (self->host_key);
  BN_CTX *c = BN_CTX_new (); BIGNUM *x = BN_new (), *y = BN_new ();
  EC_POINT_get_affine_coordinates (g, P, x, y, c);
  BN_bn2binpad (x, self->host_pub, 32); BN_bn2binpad (y, self->host_pub+32, 32);
  BN_free (x); BN_free (y); BN_CTX_free (c);
  return TRUE;
}
static gboolean cvfp_ecdh (FpiDeviceCvfp *self, const guint8 *devpub, guint8 out[32]){
  gboolean ok = FALSE; const EC_GROUP *g = EC_KEY_get0_group (self->host_key);
  BIGNUM *x = BN_bin2bn (devpub,32,0), *y = BN_bin2bn (devpub+32,32,0);
  EC_POINT *P = EC_POINT_new (g); BN_CTX *c = BN_CTX_new ();
  if (EC_POINT_set_affine_coordinates (g,P,x,y,c) && ECDH_compute_key (out,32,P,self->host_key,0)==32) ok = TRUE;
  EC_POINT_free (P); BN_free (x); BN_free (y); BN_CTX_free (c); return ok;
}
static int cvfp_aes (FpiDeviceCvfp *self, int enc, const guint8 *iv, const guint8 *in, int inlen, guint8 *out){
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new (); int l1=0,l2=0,r=-1;
  if (EVP_CipherInit_ex (c,EVP_aes_128_cbc(),0,self->session_key,iv,enc) &&
      EVP_CipherUpdate (c,out,&l1,in,inlen) && EVP_CipherFinal_ex (c,out+l1,&l2)) r = l1+l2;
  EVP_CIPHER_CTX_free (c); return r;
}
static int cvfp_hdr (guint8 *p, guint cmd, guint attr, guint enc, guint32 handle, guint total){
  memset (p,0,44); p32(p,1); p32(p+4,total); p[8]=cmd&0xff; p[9]=(cmd>>8)&0xff; p[10]=attr; p[11]=enc; p32(p+12,2); p32(p+16,handle); return 44;
}
static int cvfp_build_wrapped (FpiDeviceCvfp *self, guint8 *out, guint cmd, guint attr, guint32 handle,
                               const guint8 *tlv, int tlvlen, int ptlen, guint suffix){
  guint8 macKey[32]; SHA256 (MAC_SEED,23,macKey);
  guint8 iv[16]; RAND_bytes (iv,16);
  int ctlen = ((ptlen/16)+1)*16, total = 44+ctlen;
  cvfp_hdr (out,cmd,attr,0x02,handle,total); memcpy (out+24,iv,16); p32 (out+40,tlvlen);
  guint8 macin[256]; memcpy (macin,out,44); memcpy (macin+44,tlv,tlvlen); p32 (macin+44+tlvlen,suffix);
  guint8 token[32]; guint tl; HMAC (EVP_sha256(),macKey,32,macin,44+tlvlen+4,token,&tl);
  guint8 pt[256]; memset (pt,0,ptlen); memcpy (pt,tlv,tlvlen); memcpy (pt+tlvlen,token,32);
  guint8 ct[512]; int clen = cvfp_aes (self,1,iv,pt,ptlen,ct); if (clen<0) return -1;
  memcpy (out+44,ct,clen); return total;
}
/* build an UNWRAPPED session frame (0x8A, 0x04, 0x68) into f; returns its length */
static int cvfp_build_plain (guint8 *f, guint cmd, guint attr, guint32 hdr_handle, const guint8 *tlv, int tlvlen){
  int total = 44+tlvlen; cvfp_hdr (f,cmd,attr,0x00,hdr_handle,total); p32 (f+40,tlvlen);
  if (tlv && tlvlen) memcpy (f+44,tlv,tlvlen); return total;
}

/* --- decrypt a wrapped reply; find a TLV value of a given size ------------------------------- */
static int cvfp_unwrap (FpiDeviceCvfp *self, guint8 *pt){
  if (self->rlen < 44+16) return -1; int cl = self->rlen - 44; if (cl % 16) return -1;
  return cvfp_aes (self, 0, self->rb+24, self->rb+44, cl, pt);
}
static gboolean cvfp_find_param (const guint8 *pt, int pl, int want, guint8 *out){
  for (int i=0; i+8+want <= pl; i+=4)
    if (g32(pt+i) <= 3 && g32(pt+i+4) == (guint32)want) { memcpy (out, pt+i+8, want); return TRUE; }
  return FALSE;
}

/* --- asynchronous transceive: bulk OUT -> interrupt (reply length) -> bulk IN ----------------- */
/* On success the result lands in self->rb/rlen/last_cv and the ssm jumps to `next`; any USB-level
   failure marks the ssm failed. Only one transceive is ever in flight (operations are serial). */
typedef struct { FpiSsm *ssm; guint intr_ms; int next; } CvfpTsc;

static void tsc_in_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpTsc *x = ud; FpiSsm *ssm = x->ssm; int next = x->next;
  g_free (x);
  if (err) { fpi_ssm_mark_failed (ssm, err); return; }
  self->rlen = t->actual_length;
  memcpy (self->rb, t->buffer, self->rlen);
  self->last_cv = (self->rlen >= 24) ? (int) g32 (self->rb+20) : -1;
  fpi_ssm_jump_to_state (ssm, next);
}
static void tsc_int_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpTsc *x = ud;
  if (err) { FpiSsm *ssm = x->ssm; g_free (x); fpi_ssm_mark_failed (ssm, err); return; }
  guint32 rl = (t->actual_length >= 8) ? g32 (t->buffer+4) : 0;
  if (rl == 0) {  /* no reply body: normal for the unwrapped 0x8A / 0x68 / 0x04 commands */
    FpiSsm *ssm = x->ssm; int next = x->next; g_free (x);
    self->rlen = 0; self->last_cv = -3;
    fpi_ssm_jump_to_state (ssm, next); return;
  }
  FpiUsbTransfer *in = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (in, EP_IN, rl > sizeof self->rb ? sizeof self->rb : rl);
  fpi_usb_transfer_submit (in, TO_BULK, NULL, tsc_in_cb, x);
}
static void tsc_out_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  CvfpTsc *x = ud;
  if (err) { FpiSsm *ssm = x->ssm; g_free (x); fpi_ssm_mark_failed (ssm, err); return; }
  FpiUsbTransfer *ir = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (ir, EP_INT, 32);
  fpi_usb_transfer_submit (ir, x->intr_ms, NULL, tsc_int_cb, x);
}
/* The command transfers deliberately get no GCancellable: they complete in milliseconds, and
   aborting one mid-flight is exactly what wedges this chip. Only the finger wait is cancellable. */
static void cvfp_transceive (FpDevice *dev, FpiSsm *ssm, const guint8 *frame, gsize n,
                             guint intr_ms, int next){
  CvfpTsc *x = g_new0 (CvfpTsc, 1); x->ssm = ssm; x->intr_ms = intr_ms; x->next = next;
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (t, EP_OUT, n);
  memcpy (t->buffer, frame, n);
  fpi_usb_transfer_submit (t, TO_BULK, NULL, tsc_out_cb, x);
}

/* --- asynchronous wait for the "finger read" event (interrupt status 0x03) -------------------- */
typedef struct { FpiSsm *ssm; int next; } CvfpWait;
static void finger_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpWait *w = ud; FpiSsm *ssm = w->ssm; int next = w->next;
  g_free (w);
  if (err) { fpi_ssm_mark_failed (ssm, err); return; }
  self->last_event = (t->actual_length >= 4) ? (int) g32 (t->buffer) : -1;
  fpi_ssm_jump_to_state (ssm, next);
}
/* This is the one long wait, so it takes the device's GCancellable: when fprintd cancels the
   operation the transfer aborts at once instead of hanging until the timeout. The capture stays
   armed on the chip, which is harmless — the next 0x66 gets 0x85 and the cancel+retry path below
   clears it, and dev_close sends an explicit 0x68 anyway. */
static void cvfp_wait_finger (FpDevice *dev, FpiSsm *ssm, int next){
  CvfpWait *w = g_new0 (CvfpWait, 1); w->ssm = ssm; w->next = next;
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (t, EP_INT, 32);
  fpi_usb_transfer_submit (t, TO_FINGER, fpi_device_get_cancellable (dev), finger_cb, w);
}

/* --- shared frame builders -------------------------------------------------------------------- */
static int build_66 (FpiDeviceCvfp *self, guint8 *f){
  guint8 t[36] = {0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,1,0,0,0,0,0,0,0,4,0,0,0,0x23,0,0,0};
  p32 (t+8, self->handle);
  return cvfp_build_wrapped (self,f,0x66,0x47,self->handle,t,36,80,self->wrap_seq);
}
/* mid-capture cancel: session-scoped (attr 0x40, handle in the header), unwrapped -> no seq bump */
static int build_68_mid (FpiDeviceCvfp *self, guint8 *f){
  guint8 t[12] = {0,0,0,0,4,0,0,0,0,0,0,0}; p32 (t+8, self->handle);
  return cvfp_build_plain (f,0x68,0x40,self->handle,t,12);
}
/* teardown cancel: sessionless (attr 0x44, handle 0 in the header) */
static int build_68_final (FpiDeviceCvfp *self, guint8 *f){
  guint8 t[12] = {0,0,0,0,4,0,0,0,0,0,0,0}; p32 (t+8, self->handle);
  return cvfp_build_plain (f,0x68,0x44,0,t,12);
}
static int build_04_close (FpiDeviceCvfp *self, guint8 *f){
  cvfp_hdr (f,0x04,0x40,0x04,0,56); p32 (f+40,12); p32 (f+48,4); p32 (f+52,self->handle); return 56;
}

static void fail_wrap (FpiSsm *ssm){
  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "cvfp: frame wrap failed"));
}
/* arm a capture (wrapped 0x66) and continue at `next` once the chip acknowledges */
static void send_66 (FpDevice *dev, FpiSsm *ssm, int next){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[256]; int n = build_66 (self, f);
  if (n < 0) { fail_wrap (ssm); return; }
  cvfp_transceive (dev, ssm, f, n, TO_INTR, next);
}

/* The chip advances its wrap counter on every MAC-valid wrapped command — including one that
   answers 0x85 "capture pending" — so the host must follow suit after each wrapped transceive. */
static void bump_seq (FpiDeviceCvfp *self){
  if (self->last_cv != 0x0F && self->last_cv >= 0) self->wrap_seq++;
}
static void fail_cv (FpiSsm *ssm, const char *what, int cv){
  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                      "cvfp: %s returned %d", what, cv));
}
static void set_print_id (FpPrint *print, const guint8 *id20){
  /* Host-stored RAW print: fprintd serializes it to disk. The device holds the real template and
     does the matching, so the print body is just a reference (we still stash the enroll id). */
  fpi_print_set_type (print, FPI_PRINT_RAW);
  GVariant *v = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, id20, 20, 1);
  g_object_set (print, "fpi-data", v, NULL);
}

/* --- teardown ssm: optional 0x68 cancel, then 0x04 close-handle ------------------------------- */
enum { TD_CANCEL, TD_CLOSE, TD_FIN, TD_NUM };
static void td_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[128];
  switch (fpi_ssm_get_cur_state (ssm)) {
  case TD_CANCEL:
    if (!GPOINTER_TO_INT (fpi_ssm_get_data (ssm))) { fpi_ssm_jump_to_state (ssm, TD_CLOSE); return; }
    cvfp_transceive (dev, ssm, f, build_68_final (self,f), TO_TEARDOWN, TD_CLOSE);
    return;
  case TD_CLOSE:
    cvfp_transceive (dev, ssm, f, build_04_close (self,f), TO_TEARDOWN, TD_FIN);
    return;
  case TD_FIN:
    self->handle = 0;
    fpi_ssm_mark_completed (ssm);
    return;
  }
}
static void cvfp_start_teardown (FpDevice *dev, gboolean send_cancel, FpiSsmCompletedCallback done){
  FpiSsm *ssm = fpi_ssm_new (dev, td_run, TD_NUM);
  fpi_ssm_set_data (ssm, GINT_TO_POINTER (send_cancel ? 1 : 0), NULL);
  fpi_ssm_start (ssm, done);
}
static void cvfp_release (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (self->host_key) { EC_KEY_free (self->host_key); self->host_key = NULL; }
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  if (usb) g_usb_device_release_interface (usb, 0, 0, NULL);
}

/* --- open: 0x23 challenge -> 0x24 response -> ECDH/KDF -> wrapped 0x02 ------------------------ */
enum { O_23, O_24, O_02, O_FIN, O_NUM };
static void open_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  switch (fpi_ssm_get_cur_state (ssm)) {
  case O_23: {
    guint8 cn[20]; RAND_bytes (cn, 20);
    guint8 f[68]; cvfp_hdr (f,0x23,0x41,0,0,68); p32 (f+40,24); memcpy (f+44,cn,20); p32 (f+64,1);
    cvfp_transceive (dev, ssm, f, 68, TO_INTR, O_24);
    return; }
  case O_24: {
    if (self->last_cv != 0) { fail_cv (ssm, "0x23 challenge", self->last_cv); return; }
    if (self->rlen < 44+148) { fail_cv (ssm, "0x23 short reply", (int) self->rlen); return; }
    self->handle = g32 (self->rb+16);
    memcpy (self->dpub, self->rb+44, 64);
    memcpy (self->dn,   self->rb+44+128, 20);
    RAND_bytes (self->hn2, 20);
    guint8 f[128]; cvfp_hdr (f,0x24,0x01,0,self->handle,128); p32 (f+40,84);
    memcpy (f+44,self->hn2,20); memcpy (f+64,self->host_pub,64);
    cvfp_transceive (dev, ssm, f, 128, TO_INTR, O_02);
    return; }
  case O_02: {
    if (self->last_cv != 0) { fail_cv (ssm, "0x24 response", self->last_cv); return; }
    guint8 Z[32];
    if (!cvfp_ecdh (self, self->dpub, Z)) {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "cvfp: ECDH failed"));
      return; }
    SHA1 (Z,32,self->master);
    { guint8 b[60],dg[20]; memcpy (b,self->master,20); memcpy (b+20,self->dn,20); memcpy (b+40,self->hn2,20);
      SHA1 (b,60,dg); memcpy (self->session_key,dg,16); }
    guint8 tlv[36] = {0,0,0,0,4,0,0,0,0x4f,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0};
    guint8 f[256]; int n = cvfp_build_wrapped (self,f,0x02,0x45,self->handle,tlv,36,80,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, O_FIN);
    return; }
  case O_FIN:
    if (self->last_cv != 0) { fail_cv (ssm, "0x02 open_session", self->last_cv); return; }
    self->wrap_seq = 1;   /* 0x02 consumed seq 0 */
    fpi_ssm_mark_completed (ssm);
    return;
  }
}
static void open_teardown_done (FpiSsm *ssm, FpDevice *dev, GError *td_error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  g_clear_error (&td_error);              /* best effort: report the original open failure */
  cvfp_release (dev);
  fpi_device_open_complete (dev, g_steal_pointer (&self->open_error));
}
static void open_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (!error) {
    fp_info ("cvfp: secure channel open (handle 0x%08x)", self->handle);
    fpi_device_open_complete (dev, NULL);
    return;
  }
  /* The 0x23 step may already have allocated a session handle on the MCU; tear it down or it
     dangles across OS reboots and wedges every later open. */
  if (self->handle) {
    self->open_error = error;
    cvfp_start_teardown (dev, FALSE, open_teardown_done);
    return;
  }
  cvfp_release (dev);
  fpi_device_open_complete (dev, error);
}

/* --- verify: 0x66 capture -> finger event -> 0x73 match --------------------------------------- */
enum { V_CAP, V_CAP_RESP, V_CAP_RETRY, V_WAIT, V_MATCH, V_MATCH_RESP, V_ABORT, V_NUM };
static void verify_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[256];
  switch (fpi_ssm_get_cur_state (ssm)) {
  case V_CAP:
    self->did_retry = FALSE;
    send_66 (dev, ssm, V_CAP_RESP);
    return;
  case V_CAP_RESP:
    bump_seq (self);
    if (self->last_cv == 0x85) {   /* a capture is still armed from a cancelled run: clear + re-arm */
      if (self->did_retry) { fail_cv (ssm, "0x66 capture", 0x85); return; }
      self->did_retry = TRUE;
      cvfp_transceive (dev, ssm, f, build_68_mid (self,f), TO_INTR, V_CAP_RETRY);
      return; }
    if (self->last_cv != 0) { fail_cv (ssm, "0x66 capture", self->last_cv); return; }
    fpi_ssm_jump_to_state (ssm, V_WAIT);
    return;
  case V_CAP_RETRY:   /* rebuild at the *current* seq — the failed 0x66 still advanced the chip */
    send_66 (dev, ssm, V_CAP_RESP);
    return;
  case V_WAIT:
    cvfp_wait_finger (dev, ssm, V_MATCH);
    return;
  case V_MATCH: {
    if (self->last_event != 0x03) { cvfp_transceive (dev, ssm, f, build_68_final (self,f), TO_TEARDOWN, V_ABORT); return; }
    guint8 t[68] = {0,0,0,0,4,0,0,0,0,0,0,0, 0,0,0,0,4,0,0,0,0x48,0x01,0,0,
                    0,0,0,0,4,0,0,0,0xe2,0x53,0,0, 0,0,0,0,4,0,0,0,0,0,0,0,
                    2,0,0,0,4,0,0,0,0xd3,0x0a,0x7b,0, 3,0,0,0,0x14,0,0,0};
    p32 (t+8, self->handle);
    int n = cvfp_build_wrapped (self,f,0x73,0x47,self->handle,t,68,112,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, V_MATCH_RESP);
    return; }
  case V_MATCH_RESP: {
    bump_seq (self);
    if (self->last_cv != 0) { fail_cv (ssm, "0x73 match", self->last_cv); return; }
    guint8 pt[512]; int pl = cvfp_unwrap (self, pt);
    gboolean matched = (pl >= 12 && g32 (pt+8) == 1);   /* match flag at plaintext +8 (1 = match) */
    fp_dbg ("cvfp: 0x73 match flag=%u", (pl >= 12) ? g32 (pt+8) : 0);
    /* The device matches against its own template store, which only ever holds fingers we actually
       enrolled — an unenrolled finger cannot produce matchflag=1 — so the flag is authoritative.
       We do NOT compare template ids: the id 0x73 reports (a stable biometric-derived hash) lives
       in a different id space from the per-enrollment id the 0x6C completion reply returns, so the
       two never match. This is exactly why cvchan trusts the flag too. */
    FpPrint *print = NULL; fpi_device_get_verify_data (dev, &print);
    fpi_device_verify_report (dev, matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, print, NULL);
    fpi_ssm_mark_completed (ssm);
    return; }
  case V_ABORT:
    fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "cvfp: no finger"));
    return;
  }
}
static void verify_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  fpi_device_verify_complete (dev, error);
}
static void dev_verify (FpDevice *dev){
  fpi_ssm_start (fpi_ssm_new (dev, verify_run, V_NUM), verify_done);
}

/* --- enroll: 0x6D discard -> 0x8A start -> N x (0x66 -> finger -> 0x6C) -> 0x6E commit --------- */
enum { EN_DISCARD, EN_START, EN_CAP, EN_CAP_RESP, EN_CAP_RETRY, EN_WAIT,
       EN_UPDATE, EN_UPDATE_RESP, EN_COMMIT, EN_COMMIT_RESP, EN_NUM };
static void enroll_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[256];
  switch (fpi_ssm_get_cur_state (ssm)) {
  case EN_DISCARD: {   /* drop any half-finished enrollment left on the chip */
    self->e_spl = 0; self->e_accepted = 0; self->e_done = FALSE;
    memset (self->e_lastid, 0, 20);
    guint8 t[12] = {0,0,0,0,4,0,0,0,0,0,0,0}; p32 (t+8, self->handle);
    int n = cvfp_build_wrapped (self,f,0x6D,0x45,self->handle,t,12,48,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, EN_START);
    return; }
  case EN_START: {
    bump_seq (self);   /* for the 0x6D above */
    guint8 t[12] = {0,0,0,0,4,0,0,0,0,0,0,0};
    cvfp_transceive (dev, ssm, f, cvfp_build_plain (f,0x8A,0x44,0,t,12), TO_INTR, EN_CAP);
    return; }
  case EN_CAP:   /* top of the sample loop (0x8A is unwrapped: no seq bump) */
    self->did_retry = FALSE;
    if (self->e_done || self->e_spl >= MAX_ENROLL_SAMPLES) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }
    self->e_spl++;
    send_66 (dev, ssm, EN_CAP_RESP);
    return;
  case EN_CAP_RESP: {
    bump_seq (self);
    if (self->last_cv == 0x85) {
      if (self->did_retry) { fail_cv (ssm, "0x66 capture", 0x85); return; }
      self->did_retry = TRUE;
      cvfp_transceive (dev, ssm, f, build_68_mid (self,f), TO_INTR, EN_CAP_RETRY);
      return; }
    if (self->last_cv < 0) { fail_cv (ssm, "0x66 capture", self->last_cv); return; }
    if (self->last_cv != 0) { fpi_ssm_jump_to_state (ssm, EN_CAP); return; }   /* e.g. 0x0F: retry */
    guint8 pt[512]; int pl = cvfp_unwrap (self, pt);
    if (pl <= 0 || !cvfp_find_param (pt, pl, 20, self->e_hash)) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }
    fpi_ssm_jump_to_state (ssm, EN_WAIT);
    return; }
  case EN_CAP_RETRY:
    send_66 (dev, ssm, EN_CAP_RESP);
    return;
  case EN_WAIT:
    cvfp_wait_finger (dev, ssm, EN_UPDATE);
    return;
  case EN_UPDATE: {
    if (self->last_event != 0x03) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }
    /* 20 zero-bytes between the 0x14 tag and the 2,0,0,0 TLV, so the 20-byte hash written at
       offset 20 lands clear of the tag (which must sit at offset 40) — exactly like cvchan.
       At 16 the command is malformed, the chip ignores it, and the interrupt wait wedges. */
    guint8 t[48] = {0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0x14,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0};
    p32 (t+8, self->handle); memcpy (t+20, self->e_hash, 20);
    int n = cvfp_build_wrapped (self,f,0x6C,0x45,self->handle,t,48,80,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, EN_UPDATE_RESP);
    return; }
  case EN_UPDATE_RESP: {
    bump_seq (self);
    if (self->last_cv == 0 || self->last_cv == 0x8F) {
      self->e_accepted++;
      memcpy (self->e_lastid, self->e_hash, 20);
      FpPrint *print = NULL; fpi_device_get_enroll_data (dev, &print);
      fpi_device_enroll_progress (dev, self->e_accepted, print, NULL);
      /* completion: the 0x6C reply carries a NEW 20-byte id (!= the sample hash we sent) */
      guint8 rpt[512]; int rpl = cvfp_unwrap (self, rpt); guint8 rid[20];
      if (rpl > 0 && cvfp_find_param (rpt, rpl, 20, rid) && memcmp (rid, self->e_hash, 20) != 0) {
        memcpy (self->e_lastid, rid, 20); self->e_done = TRUE; }
      fpi_ssm_jump_to_state (ssm, EN_CAP);
      return; }
    if (self->last_cv == 0x8C) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }  /* no more accepted */
    if (self->last_cv < 0) { fail_cv (ssm, "0x6C update", self->last_cv); return; }
    fpi_ssm_jump_to_state (ssm, EN_CAP);   /* 0xA4 / 0x89: retry this scan */
    return; }
  case EN_COMMIT: {
    /* Commit if the device signalled completion, or (fallback, like cvchan) if we gathered enough
       accepted stages — so a run that never emits the explicit completion id still enrolls. */
    if (!self->e_done && self->e_accepted < NR_ENROLL_STAGES) {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
        "cvfp: enrollment did not complete (%d/%d stages)", self->e_accepted, NR_ENROLL_STAGES));
      return; }
    guint8 t[64] = {0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0x14,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    2,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0};
    p32 (t+8, self->handle); memcpy (t+20, self->e_lastid, 20);
    int n = cvfp_build_wrapped (self,f,0x6E,0x45,self->handle,t,64,96,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, EN_COMMIT_RESP);
    return; }
  case EN_COMMIT_RESP:
    bump_seq (self);
    if (self->last_cv != 0) { fail_cv (ssm, "0x6E commit", self->last_cv); return; }
    fpi_ssm_mark_completed (ssm);
    return;
  }
}
static void enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (error) { fpi_device_enroll_complete (dev, NULL, error); return; }
  FpPrint *print = NULL; fpi_device_get_enroll_data (dev, &print);
  set_print_id (print, self->e_lastid);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}
static void dev_enroll (FpDevice *dev){
  fpi_ssm_start (fpi_ssm_new (dev, enroll_run, EN_NUM), enroll_done);
}

/* --- FpiDeviceClass vfuncs ------------------------------------------------------------------- */
static void dev_probe (FpDevice *dev){
  fpi_device_probe_complete (dev, NULL, "Dell ControlVault 3 (cvfp)", NULL);
}
static void dev_open (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  g_autoptr(GError) err = NULL;
  if (!g_usb_device_claim_interface (usb, 0, 0, &err)) { fpi_device_open_complete (dev, g_steal_pointer (&err)); return; }
  self->wrap_seq = 0; self->handle = 0;
  if (!cvfp_gen_key (self)) {
    g_usb_device_release_interface (usb, 0, 0, NULL);
    fpi_device_open_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "cvfp: keygen failed"));
    return;
  }
  /* Returns immediately; the handshake runs on the main loop and open_done reports the result. */
  fpi_ssm_start (fpi_ssm_new (dev, open_run, O_NUM), open_done);
}
static void close_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  g_clear_error (&error);           /* teardown is best effort: close must always succeed */
  cvfp_release (dev);
  fpi_device_close_complete (dev, NULL);
}
static void dev_close (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (!self->handle) { cvfp_release (dev); fpi_device_close_complete (dev, NULL); return; }
  /* clear any armed capture, then drop the session handle, so nothing dangles on the MCU */
  cvfp_start_teardown (dev, TRUE, close_done);
}

static void fpi_device_cvfp_init (FpiDeviceCvfp *self){}
static void fpi_device_cvfp_class_init (FpiDeviceCvfpClass *klass){
  FpDeviceClass *dc = FP_DEVICE_CLASS (klass);
  dc->id = "cvfp";
  dc->full_name = "Dell ControlVault 3 fingerprint";
  dc->type = FP_DEVICE_TYPE_USB;
  dc->id_table = id_table;
  dc->scan_type = FP_SCAN_TYPE_PRESS;
  dc->nr_enroll_stages = NR_ENROLL_STAGES;
  /* Host storage: fprintd keeps the print metadata on disk and passes it back to verify. The
     device stores the template internally for matching, and dev_verify trusts the device match
     flag (the id it reports is a stable biometric hash we can't know at enroll time, so device
     STORAGE/IDENTIFY/list would need a 0x2F store-diff to map ids — left as future work). */
  dc->features = FP_DEVICE_FEATURE_VERIFY;
  dc->probe = dev_probe;
  dc->open  = dev_open;
  dc->close = dev_close;
  dc->enroll = dev_enroll;
  dc->verify = dev_verify;
}

/* TOD entry point: libfprint-tod calls this to obtain the driver's GType. */
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void);
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void){ return fpi_device_cvfp_get_type (); }
