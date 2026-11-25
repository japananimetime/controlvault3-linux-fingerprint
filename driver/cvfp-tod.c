/*
 * libfprint TOD driver for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 * Implements the reverse-engineered secure channel (see ../docs/secure-channel.md): keyless
 * ECDH-P256 handshake, AES-128-CBC wrapping, enroll/verify. Drop-in replacement for the stock
 * (non-working) libfprint-2-tod-1-broadcom.so.
 *
 * Templates are device-managed: enroll commits (0x6E) and binds the sensor template
 * handle from the commit reply into the stored print; verify (0x2F, attr 0x47) carries that u32
 * handle and accepts the verdict only when the matched handle equals the bound one (id binding).
 * The sensor's host-timestamp request (interrupt type 5) is answered with a 0x40/0x0d control
 * transfer below the SSM layer; an unanswered clock stalls the chip completely.
 *
 * The verify 0x2F's reply announcement can be REPLACED by a type-5
 * clock request — the chip consumed the command and wants the clock answered first; the match
 * path answers at the instant of the event and harvests the deferred reply in a listener-only
 * window (V_MATCH_REPLY), mirroring the proven enroll-finalize pattern; deferred clock flushes
 * before the next command are sequential (clock-then-out), never racing the command frame.
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
#include <string.h>   /* strstr: cvfp_is_cancel */
#include <openssl/rand.h>
#include <time.h>

#define NR_ENROLL_STAGES 12
#define MAX_ENROLL_SAMPLES 30
#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_INT 0x85

/* Bulk timeouts must stay at 5000ms, exactly like the proven cvchan: a shorter bulk-OUT timeout
   cancels the URB mid-flight and leaves the device's endpoint deep-wedged (survives a USB reset,
   needs a cold boot). The command-reply interrupt gets the same generous window cvchan uses. */
#define TO_BULK    5000
#define EP0_PROBE_REQ 0x44   /* dummy vendor byte; the interface stalls it (see wake probe) */
#define TO_INTR   60000
#define TO_FINGER 30000
#define TO_TEARDOWN 3000
#define TO_DRAIN   5000   /* best-effort drain of a reply the chip owes without an announcement */
#define TO_LSN    3000   /* listener-only window after the deferred clock answer: the enroll finalize reply AND the verify match reply (ms) */

struct _FpiDeviceCvfp {
  FpDevice      parent;
  EC_KEY       *host_key;
  guint8        host_pub[64];
  guint8        session_key[16];
  guint8        master[20];
  guint         wrap_seq;
  guint32       handle;
  gboolean      o_probe_tried; /* EP0 wake-probe budget: the 0x23 handshake gets one retry */

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
  guint32       e_complete;    /* non-zero when the chip signalled enroll completion (id or 0x05 event) */
  gboolean      e_dead_sess;   /* chip answered 0x05-to-0x6D with a dead session; teardown can only give up */
  guint32       print_handle;  /* sensor template handle bound at commit (the 0x6E reply id) */
  gboolean      print_bound;   /* TRUE once a verify run binds against the print's sensor handle */
  guint8        e_hash[20];
  guint8        e_lastid[20];
  gboolean      e_announce_pending; /* the final stage completed event-only; listen for the deferred finalize reply before committing */
  gboolean      pending_clock; /* a type-5 clock request arrived mid-exchange; answered at the event (match path) or flushed sequentially before the next command */
  gboolean      clock_in_flight; /* a 0x0d clock answer write is submitted; a type-5 arriving meanwhile is recorded in pending_clock instead of overlapped. The transceive flush yields to this too: it skips the overlap and relies on the chip re-requesting */
  int           commit_tries;  /* how many 0x6E commits this session has sent (0x8E-restart guard) */
  int           op_events;     /* bare chip events swallowed by the command listener this operation */

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

static void dump_bytes (const char *tag, gsize actual, const guint8 *p, gsize buf){
  GString *s = g_string_new ("");
  for (gsize i = 0; i < actual && i < 40 && i < buf; i++)
    g_string_append_printf (s, " %02x", p[i]);
  fp_dbg ("cvfp: %s: len=%u [%s ]", tag, (guint) actual, s->str);
  g_string_free (s, TRUE);
}
/* --- the host-timestamp clock (interrupt type 5) ----------------------------------------------- */
/* The sensor may deliver interrupt type 5 = CV_GET_HOST_TIMESTAMP_INTERRUPT at any time, including
 * inside a pending command exchange or a finger wait. The host must answer it with a vendor
 * control transfer (0x40 / 0x0d, wValue/wIndex = packed timestamp, no data stage); until it does,
 * the chip stalls everything else. Measured on this chip 2026-10-29 by cv3-tod: an unsolicited
 * clock sync is also refused, so we only answer when the chip asks. Packed u32 bit layout:
 * day 0..4 | month 5..8 | year-2000 9..14 | hour 15..19 | minute 20..25 | second 26..31.
 * The answer is an ASYNC fill_control transfer (this GUsb takes enum request-type/recipient,
 * not a raw bmRequestType byte - 0x40 in that slot produced a garbage setup packet and a STALL
 * that stalled the drain, the 0x6E commit and even the teardown). Mid-exchange
 * requests (tsc_int_cb) set pending_clock, and cvfp_transceive flushes it before the next
 * request frame - answer-after-reply, matching the Windows driver's demux order. That
 * flush is SEQUENTIAL (the control write completes, only then is the next command's OUT
 * submitted - answering the clock and sending the 0x68 teardown OUT in the same
 * instant leaves the chip deaf to both), and the verify match path answers at the INSTANT
 * of the event instead of deferring (every answer given at the moment of the event
 * landed; later answers were followed by total chip silence). Only the finger
 * wait answers inline: there is no reply the chip owes while it waits for a finger. */
/* USB transfer ownership: fpi_usb_transfer_submit() STEALS the caller's reference.
 * Its doc: "(transfer full) ... will be stolen when this function is called ... free'ed
 * automatically, after the callback ran unless fpi_usb_transfer_ref() is explicitly
 * called" — so completion callbacks must NEVER unref their transfer. clock_sync_done
 * used to, and every clock answer logged "fpi_usb_transfer_unref: assertion
 * 'self->ref_count' failed" — twice per verify, visible in any debug journal capture.
 * The same bug sat in tsc_clock_then_out and wake_probe_done, where it was worse:
 * the transfer was read (t->actual_length) after the unref. */
static void clock_sync_done (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  self->clock_in_flight = FALSE;   /* cleared first, even on error — the write slot is free again */
  if (err) fp_dbg ("cvfp: clock sync control write failed (best effort): %s", err->message);
  /* fire-and-forget: no unref — submit() already owns the reference (see above) */
}
static guint32 cvfp_pack_timestamp (void){
  time_t now = time (NULL); struct tm *lt = localtime (&now);
  return ((guint32) (lt->tm_sec & 0x3f) << 26) | ((guint32) ((lt->tm_min & 0x3f) << 20)) |
         ((guint32) (lt->tm_hour & 0x1f) << 15) | ((guint32) ((lt->tm_year + 1900 - 2000) & 0x3f) << 9) |
         ((guint32) ((lt->tm_mon + 1) & 0x0f) << 5) | ((guint32) (lt->tm_mday & 0x1f));
}
/* build (not submit) the vendor/device 0x0d clock control transfer */
static FpiUsbTransfer *new_clock_sync_transfer (FpDevice *dev){
  guint32 ts = cvfp_pack_timestamp ();
  fp_dbg ("cvfp: answering host-timestamp request (type 5) with packed %08x", ts);
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_control (t,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 0x0d, ts & 0xffff, ts >> 16, 0);
  return t;
}
/* Only one clock answer may be written at a time — two concurrent 0x0d control writes are
 * exactly the "answering two things in the same instant leaves the chip deaf to both" hazard
 * the clock protocol already documented. A type-5 arriving while an answer is still being
 * written is recorded in pending_clock instead and answered at the next sequential flush
 * (cvfp_transceive) or event slot, never overlapped. */
static void send_clock_sync (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (!fpi_device_get_usb_device (dev)) return;
  self->clock_in_flight = TRUE;
  fpi_usb_transfer_submit (new_clock_sync_transfer (dev), 1000, NULL, clock_sync_done, NULL);
}

/* --- asynchronous transceive: bulk OUT -> interrupt (reply length) -> bulk IN ----------------- */
/* On success the result lands in self->rb/rlen/last_cv and the ssm jumps to `next`; any USB-level
   failure marks the ssm failed. Only one transceive is ever in flight (operations are serial). */
typedef struct { FpiSsm *ssm; guint intr_ms; int next; guint8 *frame; gsize n; } CvfpTsc;

static void tsc_int_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err);  /* below */

/* Re-arm the listener of an in-flight transceive with its ORIGINAL window — used when the first
   interrupt turns out to be a bare chip event rather than the reply announcement. */
static void tsc_listener_rearm (FpDevice *dev, CvfpTsc *x){
  FpiUsbTransfer *r = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (r, EP_INT, 32);
  fpi_usb_transfer_submit (r, x->intr_ms, NULL, tsc_int_cb, x);
}

static void tsc_in_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpTsc *x = ud; FpiSsm *ssm = x->ssm; int next = x->next;
  g_free (x);
  if (err) { fpi_ssm_mark_failed (ssm, err); return; }
  self->rlen = t->actual_length;
  memcpy (self->rb, t->buffer, self->rlen);
  self->last_cv = (self->rlen >= 24) ? (int) g32 (self->rb+20) : -1;
  dump_bytes ("bulk reply", self->rlen, self->rb, sizeof self->rb);
  fp_dbg ("cvfp: reply status@+20 = 0x%02x", self->rlen >= 24 ? (unsigned) g32 (self->rb+20) : 0);
  fpi_ssm_jump_to_state (ssm, next);
}
static void tsc_int_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpTsc *x = ud;
  if (err) { FpiSsm *ssm = x->ssm; g_free (x); fpi_ssm_mark_failed (ssm, err); return; }
  dump_bytes ("reply-listener intr (before rl parse)", t->actual_length, t->buffer, 32);
  guint32 rl = (t->actual_length >= 8) ? g32 (t->buffer+4) : 0;
  if (rl == 0) {  /* empty announcement: either an async chip event, or an unannounced reply */
    if (t->actual_length >= 4)
      self->last_event = (int) g32 (t->buffer);
    if (self->last_event == 5) {
      /* Do NOT answer mid-exchange: a synchronous control write here stalled and the
         starved chip then also stalled the drain, the 0x6E commit and the teardown.
         Generic commands flush it before the next request frame, sequentially (the write
         completes before the OUT goes out). The verify match path answers at the instant
         of the event (V_MATCH_RESP) and harvests the deferred reply in a listener window
         (V_MATCH_REPLY). */
      fp_dbg ("cvfp: host-timestamp request detected mid-exchange — deferring the clock sync");
      self->pending_clock = TRUE;   /* the flush never overlaps an in-flight answer (see cvfp_transceive); a re-armed request is answered there or re-requested */
    }
    /* The open handshake's listener is armed right after the interface claim, so it also sees
       events the chip was still emitting from BEFORE the open — observed on the lock screen: a
       touch fired event 0x03 right after the previous release, before the 0x23 announcement,
       and the listener misread it as an empty reply (-3) and failed the open. A bare event is
       not an unannounced reply: announcements are delivered FIFO, so after swallowing the event
       the queued announcement arrives in the re-armed window (original timeout). Capped at 3
       swallows per operation; real silence still falls through to the -3 path below. The
       type-5 request is excluded — an announcement genuinely replaced by a clock request must
       still surface as -3/event=5 for the match path to answer it at the event. */
    if (self->last_event && self->last_event != 5 && self->op_events < 3) {
      self->op_events++;
      fp_dbg ("cvfp: listener swallowed bare chip event 0x%02x, re-arming for the announcement",
              self->last_event);
      tsc_listener_rearm (dev, x);
      return;
    }
    fp_dbg ("cvfp: *** listener read an EMPTY interrupt (rl==0) → will report -3 ***");
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
  g_clear_pointer (&x->frame, g_free);   /* the OUT carried the frame copy; the heap copy is spent */
  if (err) { FpiSsm *ssm = x->ssm; g_free (x); fpi_ssm_mark_failed (ssm, err); return; }
  FpiUsbTransfer *ir = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (ir, EP_INT, 32);
  fpi_usb_transfer_submit (ir, x->intr_ms, NULL, tsc_int_cb, x);
}
/* The command transfers deliberately get no GCancellable: they complete in milliseconds, and
   aborting one mid-flight is exactly what wedges this chip. Only the finger wait is cancellable. */
/* When a deferred clock sync must be flushed before a new command, the vendor 0x0d
   control write COMPLETES first and only then is the pending command's bulk OUT submitted —
   submitting the answer and the 0x68 teardown OUT in the same instant leaves
   the chip deaf to both (the teardown times out). The frame is copied to the heap because the
   caller's stack buffer is gone by the time the control write completes. */
static void tsc_clock_then_out (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  CvfpTsc *x = ud;
  FPI_DEVICE_CVFP (dev)->clock_in_flight = FALSE;   /* the flush's own clock write is done (even on error) */
  if (err) fp_dbg ("cvfp: deferred clock sync write failed (best effort, continuing): %s", err->message);
  /* no unref: submit() stole the reference (see clock_sync_done) */
  FpiUsbTransfer *o = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (o, EP_OUT, x->n);
  memcpy (o->buffer, x->frame, x->n);
  fp_dbg ("cvfp: clock sync answered — submitting the pending command frame");
  fpi_usb_transfer_submit (o, TO_BULK, NULL, tsc_out_cb, x);
}
static void cvfp_transceive (FpDevice *dev, FpiSsm *ssm, const guint8 *frame, gsize n,
                             guint intr_ms, int next){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  CvfpTsc *x = g_new0 (CvfpTsc, 1);
  x->ssm = ssm; x->intr_ms = intr_ms; x->next = next;
  if (self->pending_clock) {   /* answer a mid-exchange type-5 request now (after the reply) */
    self->pending_clock = FALSE;
    if (self->clock_in_flight) {
      /* Only reachable if a previous answer's control write is still hanging (frozen-chip
         territory — a healthy chip completes it in ms). Never overlap two 0x0d writes:
         skip the flush, the chip re-requests what it did not receive, and that request
         is answered at the next serialized instant-answer site. */
      fp_dbg ("cvfp: clock answer still in flight — skipping the flush overlap (chip will re-request)");
    } else {
      self->clock_in_flight = TRUE;
      fp_dbg ("cvfp: flushing deferred clock sync before the next request (sequential)");
      x->n = n; x->frame = g_malloc (n); memcpy (x->frame, frame, n);
      fpi_usb_transfer_submit (new_clock_sync_transfer (dev), 1000, NULL, tsc_clock_then_out, x);
      return;   /* x belongs to the clock->OUT chain; tsc_out_cb frees the heap frame copy */
    }
  }
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
  dump_bytes ("finger-wait intr", t->actual_length, t->buffer, 32);
  self->last_event = (t->actual_length >= 4) ? (int) g32 (t->buffer) : -1;
  if (self->last_event == 5) {
    /* The clock request can arrive while we wait for a finger. Answer it and keep waiting —
       the re-armed wait has no cancellable, so a cancel during this window unwinds at the
       next 0x66/0x6C instead; that matches how cv3-tod's shared finger wait behaves. */
    fp_dbg ("cvfp: host-timestamp request during finger wait — answering, continuing the wait");
    if (!self->clock_in_flight) {   /* a second type-5 while one answer is being written: record and answer at the next flush instead */
      self->pending_clock = TRUE;
      send_clock_sync (dev);
    }
    CvfpWait *w2 = g_new0 (CvfpWait, 1); w2->ssm = ssm; w2->next = next;
    FpiUsbTransfer *r = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_interrupt (r, EP_INT, 32);
    fpi_usb_transfer_submit (r, TO_FINGER, NULL, finger_cb, w2);
    return;
  }
  fpi_ssm_jump_to_state (ssm, next);
}
/* This is the one long wait, so it takes the device's GCancellable: when fprintd cancels the
   operation the transfer aborts at once instead of hanging until the timeout. The failure is
   NOT left there: verify_done/enroll_done watch for the cancellation and run the teardown SSM
   (0x68 disarm + 0x04 close) BEFORE reporting, so a cancelled verify (cancel button, lock
   screen, suspend) leaves the chip with no armed capture and no open session. Letting the armed
   capture dangle across fprintd's Release + interface-drop wedges the command interface —
   observed 2026-11-23 after a cancelled verify: the chip answered nothing (empty 0x23
   announcement, then bulk-OUT timeouts) and only self-recovered after ~105 s of complete
   silence, while fprintd's repeated re-Claims silently skipped the whole open sequence. */
static void cvfp_wait_finger (FpDevice *dev, FpiSsm *ssm, int next){
  CvfpWait *w = g_new0 (CvfpWait, 1); w->ssm = ssm; w->next = next;
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (t, EP_INT, 32);
  fpi_usb_transfer_submit (t, TO_FINGER, fpi_device_get_cancellable (dev), finger_cb, w);
}


/* --- listener-only interrupt read --- receive a reply the chip announces WITHOUT the host
   having sent a new command (used after the deferred clock answer on the event-only completion
   path). Announcement [00 00 00 00 rl] -> read the rl-byte bulk body -> jump. Nothing/another
   event in `ms` -> jump with last_cv = -3 / the event's id. This is NOT the retired bare drain:
   cvfp_transceive itself arms the interrupt listener after every OUT, so the announcement the
   chip may owe for the FINALIZE is only deliverable between exchanges --- exactly this window. */
typedef struct { FpiSsm *ssm; int next; } CvfpLsn;
static void lsns_in_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpLsn *x = ud; FpiSsm *ssm = x->ssm; int next = x->next;
  g_free (x);
  if (err) { fpi_ssm_mark_failed (ssm, err); return; }
  self->rlen = t->actual_length;
  memcpy (self->rb, t->buffer, self->rlen);
  self->last_cv = (self->rlen >= 24) ? (int) g32 (self->rb+20) : -1;
  dump_bytes ("finalize-listener bulk body", self->rlen, self->rb, sizeof self->rb);
  fpi_ssm_jump_to_state (ssm, next);
}
static void lsns_int_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpLsn *x = ud;
  if (err) { FpiSsm *ssm = x->ssm; g_free (x); fpi_ssm_mark_failed (ssm, err); return; }
  dump_bytes ("finalize-listener intr", t->actual_length, t->buffer, 32);
  guint32 rl = (t->actual_length >= 8) ? g32 (t->buffer+4) : 0;
  int ev = (t->actual_length >= 4) ? (int) g32 (t->buffer) : 0;
  if (ev == 5) {  /* another clock request: keep listening; answer only if no answer is being written */
    fp_dbg ("cvfp: finalize-listener: host-timestamp request --- answering, re-arming the window");
    if (!self->clock_in_flight) {   /* a second type-5 while one answer is being written: record and answer at the next flush instead */
      self->pending_clock = TRUE;
      send_clock_sync (dev);
    }
    CvfpLsn *x2 = g_new0 (CvfpLsn, 1); x2->ssm = x->ssm; x2->next = x->next;
    g_free (x);
    FpiUsbTransfer *r = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_interrupt (r, EP_INT, 32);
    fpi_usb_transfer_submit (r, TO_LSN, NULL, lsns_int_cb, x2);
    return;
  }
  if (rl == 0) {  /* nothing announced in the window (empty/event interrupt) */
    FpiSsm *ssm = x->ssm; int next = x->next; g_free (x);
    self->rlen = 0;
    if (ev) self->last_event = ev;
    self->last_cv = -3;
    fp_dbg ("cvfp: finalize-listener: no announcement in the window (event 0x%02x)", ev);
    fpi_ssm_jump_to_state (ssm, next); return;
  }
  FpiUsbTransfer *in = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (in, EP_IN, rl > sizeof self->rb ? sizeof self->rb : rl);
  fpi_usb_transfer_submit (in, TO_BULK, NULL, lsns_in_cb, x);
}
/* Arm the listener-only window. */
static void cvfp_listen (FpDevice *dev, FpiSsm *ssm, guint ms, int next){
  CvfpLsn *x = g_new0 (CvfpLsn, 1); x->ssm = ssm; x->next = next;
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_interrupt (t, EP_INT, 32);
  fpi_usb_transfer_submit (t, ms, NULL, lsns_int_cb, x);
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
/* The stored print body is one GVariant "ay" of 24 bytes: the 20-byte enroll id (legacy layout,
   still parsed from old prints) followed by the 4-byte LE sensor template handle bound at commit
   bound at commit. fprintd serializes fpi-data verbatim for RAW prints, so both survive a save/load
   round-trip; fp_print_get_uid/fpi-uid does not exist in this libfprint (1.95.2+tod1). */
#define CVFP_PRINT_BODY_LEN 24
static gboolean
cvfp_read_body (GVariant *ay, guint8 *body)
{
  /* A previous verify crash came from calling
     g_variant_get_fixed_array (v, NULL, 1) with n_elements == NULL, and glib
     rejects that unconditionally (g_return_val_if_fail (n_elements != NULL,
     NULL)). The NULL was then dereferenced (body[20]): a
     deterministic fprintd segfault. This reader never calls
     g_variant_get_fixed_array; it iterates the 'ay' children
     (g_variant_get_child_value + g_variant_get_byte), which works for every
     variant form, and it is all-or-nothing (read into a temp buffer; body is
     only touched on full success). */
  guint8 tmp[CVFP_PRINT_BODY_LEN];
  fp_dbg ("cvfp: cvfp_read_body: enter, ay=%p", (void *) ay);
  if (!ay || !g_variant_is_of_type (ay, G_VARIANT_TYPE ("ay"))) {
    fp_dbg ("cvfp: cvfp_read_body: not an 'ay' variant");
    return FALSE;
  }
  gsize n = g_variant_n_children (ay);
  if (n < CVFP_PRINT_BODY_LEN) {
    fp_dbg ("cvfp: cvfp_read_body: only %u children (need %d)", (guint) n, CVFP_PRINT_BODY_LEN);
    return FALSE;
  }
  for (gsize i = 0; i < CVFP_PRINT_BODY_LEN; i++) {
    GVariant *c = g_variant_get_child_value (ay, i);
    if (!c) {
      fp_dbg ("cvfp: cvfp_read_body: child %u fetch failed", (guint) i);
      return FALSE;
    }
    tmp[i] = g_variant_get_byte (c);
    g_variant_unref (c);
  }
  memcpy (body, tmp, CVFP_PRINT_BODY_LEN);
  fp_dbg ("cvfp: cvfp_read_body: ok: id=%02x%02x%02x%02x%02x… handle@20..23=%02x%02x%02x%02x",
          body[0], body[1], body[2], body[3], body[4], body[20], body[21], body[22], body[23]);
  return TRUE;
}
static guint32 print_get_handle (FpPrint *print){
  /* Hardened via cvfp_read_body above — every pointer checked, every stage logged, and
     no g_variant_get_fixed_array call with a NULL out-param (which returns NULL for
     every variant and, once dereferenced at body[20], segfaults). */
  GVariant *v = NULL;
  guint32 h = 0;
  fp_dbg ("cvfp: print_get_handle: print=%p", (void *) print);
  if (!print) { fp_dbg ("cvfp: print_get_handle: NULL print"); return 0; }
  g_object_get (print, "fpi-data", &v, NULL);
  fp_dbg ("cvfp: print_get_handle: fpi-data=%p", (void *) v);
  if (!v) return 0;
  guint8 body[CVFP_PRINT_BODY_LEN] = {0};
  if (cvfp_read_body (v, body))
    h = body[20] | (body[21] << 8) | (body[22] << 16) | ((guint32) body[23] << 24);
  g_variant_unref (v);
  fp_dbg ("cvfp: print_get_handle: handle=0x%08x", h);
  return h;
}
static void set_print_id (FpPrint *print, const guint8 *id20){
  /* Host-stored RAW print: fprintd serializes it to disk. The device holds the real template and
     does the matching, so the print body is a reference: enroll id + the sensor template handle
     (zero here; enroll_done overwrites bytes 20..23 with the handle the 0x6E reply bound). */
  fpi_print_set_type (print, FPI_PRINT_RAW);
  guint8 body[CVFP_PRINT_BODY_LEN] = {0};
  memcpy (body, id20, 20);
  GVariant *v = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, body, CVFP_PRINT_BODY_LEN, 1);
  g_object_set (print, "fpi-data", v, NULL);
}

/* --- teardown ssm: optional 0x68 cancel, then 0x04 close-handle ------------------------------- */
enum { TD_CANCEL, TD_CLOSE, TD_FIN, TD_NUM };
#define TD_TIMEOUT (4 * TO_TEARDOWN)   /* a chip with a still-armed capture answers the 0x68 cancel slowly */
static void td_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[128];
  switch (fpi_ssm_get_cur_state (ssm)) {
  case TD_CANCEL:
    if (self->e_dead_sess) {
      fp_dbg ("cvfp: teardown: chip killed the session after 0x05 - skipping cancel/close (nothing to talk to)");
      fpi_ssm_jump_to_state (ssm, TD_FIN);
      return; }
    /* after a mid-run SSM death the capture/enroll session is left armed and the chip is deaf to
       the close until it is disarmed (that is what timed out in the traces) — always send 0x68; */
    cvfp_transceive (dev, ssm, f, build_68_final (self,f), TD_TIMEOUT, TD_CLOSE);
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

/* Open-failure teardown. libfprint opens the GUsbDevice in fp_device_open(), but
   fpi_device_open_complete() does NOT close it again when open completes with an ERROR: the
   library's only g_usb_device_close() sits in fpi_device_close_complete(), and that path is
   unreachable after a failed open because is_open stays FALSE, so fp_device_close() refuses.
   The handle then stays open for the life of the fprintd process and every later Claim fails
   with "Open failed with error: Device 0a5c:5843 is already open" until fprintd is restarted
   -- and our fprintd runs --no-timeout, so it never idles out and resets itself either.
   Confirmed against libfprint-TOD 1.94.8 (installed) and 1.95.1: still unfixed upstream.
   The dying process announces it as:
     libusb: warning [libusb_exit] device 3.3 still referenced
     libusb: warning [libusb_exit] application left some devices open
   So close it ourselves. ONLY on the failure path: a successful open is closed later by
   fpi_device_close_complete(), and closing here too would be a double close. */
static void cvfp_open_fail (FpDevice *dev, GError *error){
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  cvfp_release (dev);                       /* frees the host key, drops interface 0 */
  if (usb) g_usb_device_close (usb, NULL);  /* the bit libfprint forgets */
  fpi_device_open_complete (dev, error);
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
/* EP0 wake probe: after a resume from suspend this chip has now twice frozen with both bulk
   endpoints NAKing for many minutes (2026-11-23 with a leftover capture, 2026-11-24 even
   after a cleanly closed session — 5-second bulk-OUT timeouts, zero interrupts, no
   self-recovery) while EP0 still answers: the authorized 0/1 toggle recovers the endpoints,
   which proves the control path survives the freeze. So when the FIRST bulk OUT of the open
   handshake times out (O state 0, before any session handle exists), poke the chip with one
   benign EP0 control read — a dummy vendor request the interface refuses; a STALL is as good
   an answer as data, both prove EP0 ran — then retry the 0x23 handshake exactly once.
   Ladder-safe by construction: no reset, no port disable, worst case one extra 5-second
   timeout. Same main-context async idiom as send_clock_sync. */
static void open_done (FpiSsm *ssm, FpDevice *dev, GError *error);  /* below, calls cvfp_wake_probe */
static void wake_probe_done (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  /* no unref: submit() stole the reference (see clock_sync_done); the probe log
   * reads t->actual_length and must do so BEFORE the transfer is freed, which
   * happens automatically after this callback returns */
  if (err) fp_info ("cvfp: EP0 wake probe got no answer: %s", err->message);
  else fp_info ("cvfp: EP0 wake probe answered (%u bytes) — control path alive",
                (unsigned) t->actual_length);
  fp_info ("cvfp: retrying the 0x23 handshake once");
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  self->o_probe_tried = TRUE;   /* armed only when the retry really starts */
  fpi_ssm_start (fpi_ssm_new (dev, open_run, O_NUM), open_done);
}
static void cvfp_wake_probe (FpDevice *dev){
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_control (t,
                                 G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 EP0_PROBE_REQ, 0, 0, 8);
  fpi_usb_transfer_submit (t, 1000, NULL, wake_probe_done, NULL);
}

static void open_teardown_done (FpiSsm *ssm, FpDevice *dev, GError *td_error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  g_clear_error (&td_error);              /* best effort: report the original open failure */
  cvfp_open_fail (dev, g_steal_pointer (&self->open_error));
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
  /* Resume freeze: a suspend that hit mid-open can leave both bulk endpoints NAKing for
     minutes (2026-11-24: 'device was disconnected' at claim, then every open timing out
     at the first bulk OUT with zero interrupts) while EP0 stays alive. Before reporting,
     give the chip one EP0 wake probe through the still working control path and retry
     the handshake exactly once — the probe fires only when no handle exists yet. */
  if (!self->o_probe_tried) {
    fp_info ("cvfp: first open bulk OUT timed out — EP0 wake probe, then one 0x23 retry");
    cvfp_wake_probe (dev);
    return;
  }
  cvfp_open_fail (dev, error);
}

/* --- verify: 0x66 capture -> finger event -> 0x2F identify (attr 0x47) -> verdict -------------- */
/* Per cv3-tod's vendor-blob disassembly + hardware measurements (2026-10-29): the hash-pointer
   decides the command byte in the vendor code — 0x73 only in its hash form, which answers 0x0E;
   the handle-array request with no hash is 0x2F/attr 0x47. CV3 constants are (0,4,handle),
   (0,4,0x48), (0,4,0x53e2), (0,4,0), (2,4*count,handles...). The vendor's 0x148/0x7b0ad3 came
   from ControlVault 2 reference material and do not occur in this chip's blob. Plaintext reply:
   (0,4,verdict) (0,4,matched u32 handle) + 32-byte token; verdict word at +8, handle at +20. */
enum { V_CAP, V_CAP_RESP, V_CAP_RETRY, V_WAIT, V_MATCH, V_MATCH_RESP, V_MATCH_REPLY, V_ABORT, V_NUM };

typedef struct { FpiSsm *ssm; int round; int want_match; } CvfpDrain;
static void drain_in_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err);  /* defined in the enroll section */
static void start_drain (FpDevice *dev, FpiSsm *ssm, int want_match);                   /* defined after drain_in_cb */
/* Decrypt the 0x2F reply sitting in self->rb and report the verdict — shared by the
   normal announcement path (V_MATCH_RESP) and the deferred listener-window path
   (V_MATCH_REPLY) so the binding rule lives in exactly one place. */
static void verify_report_from_reply (FpiDeviceCvfp *self, FpiSsm *ssm, FpDevice *dev){
  guint8 pt[512]; int pl = cvfp_unwrap (self, pt);
  guint32 verdict = (pl >= 12) ? g32 (pt+8) : 0;
  guint32 matched_id = (pl >= 24) ? g32 (pt+20) : 0;
  fp_dbg ("cvfp: 0x2F verdict=%u matched_id=0x%08x (bound 0x%08x)", verdict, matched_id, self->print_handle);
  /* cv3-tod id binding: accept only when the chip matched the exact template this print was
     enrolled with — closes the cross-user prompt hole and the forged-flag hole. */
  gboolean matched = (verdict == 1 && matched_id == self->print_handle);
  /* verdict==0 with matched_id==0 is a genuine no-match (cv3-tod measured shape); anything else
     without binding equality is treated as no-match — never as success. */
  FpPrint *print = NULL; fpi_device_get_verify_data (dev, &print);
  fpi_device_verify_report (dev, matched ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL, print, NULL);
  fpi_ssm_mark_completed (ssm);
}
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
    if (self->last_event != 0x03 && self->last_event != 5) { cvfp_transceive (dev, ssm, f, build_68_final (self,f), TO_TEARDOWN, V_ABORT); return; }
    /* identify request (cv3-tod measured shape, TLV len 60, plaintext 96):
       (0,4,handle)(0,4,0x48)(0,4,0x53e2)(0,4,0)(2,4,<template handle>); no hash entry —
       the hash form is 0x73 and is not the identify path on this chip. */
    guint8 t[60] = {0,0,0,0,4,0,0,0,0,0,0,0, 0,0,0,0,4,0,0,0,0x48,0,0,0,
                    0,0,0,0,4,0,0,0,0xe2,0x53,0,0, 0,0,0,0,4,0,0,0,0,0,0,0,
                    2,0,0,0,4,0,0,0,0,0,0,0};
    p32 (t+8, self->handle);
    p32 (t+56, self->print_handle);
    int n = cvfp_build_wrapped (self,f,0x2F,0x47,self->handle,t,60,96,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, V_MATCH_RESP);
    return; }
  case V_MATCH_RESP: {
    /* A valid-length announcement means the chip consumed the 0x2F — the reply advances
       the wrapped counter exactly once, then the verdict is reported. */
    if (self->last_cv == 0) { bump_seq (self); verify_report_from_reply (self, ssm, dev); return; }
    /* The 0x2F's reply announcement can be REPLACED by a type-5
       host-timestamp request — the exact shape the enrollment finalize already shows:
       the chip consumed the command, wants the clock answered
       FIRST, and announces the real reply only inside a listener-only window after the clock
       answer (announcements are consumed by the listener armed per transceive; an OUT frame
       steals them). Mirror the proven enroll pattern: bump the seq unconditionally (the
       wrapped counter advances on the event-only 0x6C completion), answer the
       clock at the instant of the event (every answer given at the moment of the event
       landed; later answers were followed by total chip silence), then open the listener
       window for the deferred 0x2F reply. */
    if (self->last_cv == -3 && self->last_event == 5) {
      self->wrap_seq++;   /* the chip consumed the 0x2F even though its announcement is deferred */
      self->pending_clock = FALSE;   /* answered here — never re-answer or race it later */
      fp_dbg ("cvfp: 0x2F announcement replaced by a type-5 clock request — answering now, listening for the deferred reply");
      send_clock_sync (dev);
      cvfp_listen (dev, ssm, TO_LSN, V_MATCH_REPLY);
      return; }
    bump_seq (self);   /* 0x0F refusal etc.: the old bump-then-fail behaviour for any other -3 */
    fail_cv (ssm, "0x2F match", self->last_cv);
    return; }
  case V_MATCH_REPLY: {   /* the deferred 0x2F reply announced inside the listener window */
    fp_dbg ("cvfp: deferred 0x2F reply listener returned: rlen=%u last_cv=%d last_event=0x%x",
            (guint) self->rlen, self->last_cv, self->last_event);
    if (self->last_cv != 0 || self->rlen < 24) {
      fail_cv (ssm, "0x2F match (the deferred reply was never announced)", self->last_cv);
      return; }
    verify_report_from_reply (self, ssm, dev);   /* no extra seq bump: counted at V_MATCH_RESP */
    return; }
  case V_ABORT:
    fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "cvfp: no finger"));
    return;
  }
}
static gboolean cvfp_is_cancel (const GError *e){
  /* libfprint delivers the finger-wait abort as G_IO_ERROR/G_IO_ERROR_CANCELLED
     ("Operation was cancelled"); accept the message as a fallback in case a wrapper
     re-domains it. */
  return e && (g_error_matches (e, G_IO_ERROR, G_IO_ERROR_CANCELLED) ||
               (e->message && strstr (e->message, "cancelled")));
}
static void verify_report_cancelled (FpiSsm *ssm, FpDevice *dev, GError *td_error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  /* the teardown SSM completed; report the original cancellation. */
  g_clear_error (&td_error);
  fpi_device_verify_complete (dev, g_steal_pointer (&self->open_error));
}
static void verify_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  /* A cancelled run (finger-wait abort) must disarm the capture and close the session BEFORE
     the verdict is reported: after fprintd sees the cancellation it Releases, and libfprint
     drops the claimed interface with no further USB traffic to the chip. open_error carries
     the failing error across the teardown SSM (same pattern as open_done's teardown). */
  if (cvfp_is_cancel (error)) {
    self->open_error = error;
    fp_dbg ("cvfp: verify was cancelled mid-capture — disarming (0x68) and closing (0x04) before reporting");
    cvfp_start_teardown (dev, TRUE, verify_report_cancelled);
    return;
  }
  fpi_device_verify_complete (dev, error);
}
static void dev_verify (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  FpPrint *print = NULL;
  fpi_device_get_verify_data (dev, &print);
  /* The print body carries the sensor template handle — the binding. A print
     without one (legacy sample-hash print) cannot be bound to a template, and any 0x2F built
     from it would be a handle-0 identify: an invalid bind request. Fail before touching the
     sensor; re-enroll to fix it. */
  fp_dbg ("cvfp: dev_verify entered, print=%p", (void *) print);
  self->print_handle = print_get_handle (print);   /* hardened helper handles NULL itself */
  if (!print || !self->print_handle) {
    fpi_device_verify_complete (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
      "cvfp: print has no bound sensor template handle — re-enroll this finger"));
    return;
  }
  self->print_bound = TRUE;
  self->op_events = 0;                    /* fresh event-swallow budget for this operation's listeners */
  fpi_ssm_start (fpi_ssm_new (dev, verify_run, V_NUM), verify_done);
}

/* --- enroll: 0x6D discard -> 0x8A start -> N x (0x66 -> finger -> 0x6C) -> 0x6E commit --------- */
enum { EN_DISCARD, EN_START, EN_CAP, EN_CAP_RESP, EN_CAP_RETRY, EN_WAIT,
       EN_UPDATE, EN_UPDATE_RESP, EN_UPDATE_DRAIN, EN_UPDATE_DRAIN_RESP, EN_FINALE, EN_COMMIT, EN_COMMIT_RESP, EN_NUM };

/* Drain callback: ANY outcome keeps the SSM alive - a timeout on this speculative read is the
   expected "event-only completion" case and just falls through to the commit. */
static void drain_in_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer ud, GError *err){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev); CvfpDrain *dr = ud; FpiSsm *ssm = dr->ssm;
  /* dr stays alive across retry rounds; it is freed exactly once, on a terminal branch */
  if (err) {  /* timeout: the chip defers its owed reply (template write etc.) - wait in rounds */
    fp_dbg ("cvfp: drain round %d found nothing pending (%s)", dr->round, err->message);
    g_error_free (err);
    if (dr->round + 1 < 3) {
      dr->round++;
      FpiUsbTransfer *r = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk (r, EP_IN, sizeof self->rb);
      fpi_usb_transfer_submit (r, TO_DRAIN, NULL, drain_in_cb, dr);
      return;
    }
    g_free (dr);
    self->rlen = 0; self->last_cv = 0;
    fpi_ssm_jump_to_state (ssm, EN_UPDATE_DRAIN_RESP);   /* event-only completion (timeout rounds) */
    return;
  }
  self->rlen = t->actual_length;
  memcpy (self->rb, t->buffer, self->rlen);
  self->last_cv = (self->rlen >= 24) ? (int) g32 (self->rb+20) : -1;
  dump_bytes ("bulk reply (drain)", self->rlen, self->rb, sizeof self->rb);
  fp_dbg ("cvfp: drain reply status@+20 = 0x%02x", self->rlen >= 24 ? (unsigned) g32 (self->rb+20) : 0);
  {
    g_free (dr);   /* terminal */
    fpi_ssm_jump_to_state (ssm, EN_UPDATE_DRAIN_RESP);
    return;
  }
}
/* One shared entry point for reading an unannounced (deferred) bulk body (enroll-only).
   want_match is kept for call-compatibility but must be 0: verify has no drain path. */
/* The speculative bulk drain is retired — the bare bulk-in reads it performed (without a
   preceding reply announcement) are the prime suspect for wedging the finalize window, and the
   drain never yielded a byte in any run. Kept for protocol reference; not called. */
__attribute__((unused)) static void start_drain (FpDevice *dev, FpiSsm *ssm, int want_match){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  CvfpDrain *dr = g_new0 (CvfpDrain, 1);
  dr->ssm = ssm; dr->round = 0; dr->want_match = (want_match != 0);   /* enroll-only */
  FpiUsbTransfer *t = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk (t, EP_IN, sizeof self->rb);
  fpi_usb_transfer_submit (t, TO_DRAIN, NULL, drain_in_cb, dr);
}

static void enroll_run (FpiSsm *ssm, FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 f[256];
  switch (fpi_ssm_get_cur_state (ssm)) {
  case EN_DISCARD: {   /* drop any half-finished enrollment left on the chip */
    self->e_spl = 0; self->e_accepted = 0; self->e_done = FALSE; self->e_complete = 0; self->e_dead_sess = FALSE;
    /* commit_tries is deliberately NOT reset here — it must survive the 0x8E restart so the
       two-commit cap holds across passes. It is zeroed once per session in dev_open. */
    self->print_handle = 0;   /* fresh binding per enroll — never carry a stale handle */
    memset (self->e_lastid, 0, 20);
    self->e_announce_pending = FALSE;
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
    if (self->e_done || self->e_spl >= NR_ENROLL_STAGES - 1 || self->e_complete) {
      /* After the final accepted update the chip is
         re-armed with one more 0x66 and the FOLLOW-UP decides the branch: a refusal (0x85,
         capture-armed after completion) routes to the commit, and a 0x00 ack (with a fresh
         20-byte sample) routes back to the wait — matching the successful end-to-end flow
         exactly (12 updates + a 13th capture arm). Driver-side guessing of the 13th update's
         semantics produced three timed-out, chip-silent failures —
         the chip, not the driver, declares the end. The sample hash
         of an acking 13th poll is a plain extra sample of the same finger and is harmless. */
      send_66 (dev, ssm, EN_CAP_RESP);
      return; }
    self->e_spl++;
    self->e_spl++;
    send_66 (dev, ssm, EN_CAP_RESP);
    return;
  case EN_CAP_RESP: {
    fp_dbg ("cvfp: EN_CAP_RESP (0x66 ack) last_cv=%d", self->last_cv);
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
    /* Event 5 during the wait is "template updated" — the session is live, do NOT treat it
       as a dead session and abandon to commit (that route has never produced a successful commit
       on this device; committed runs only ever arrived here after a finger event 0x03). */
    if (self->last_event != 0x03 && self->last_event != 5) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }
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
    fp_dbg ("cvfp: EN_UPDATE_RESP (0x6C reply) last_cv=%d", self->last_cv);
    bump_seq (self);
    if (self->last_cv == 0 || self->last_cv == 0x8F) {
      self->e_accepted++;
      memcpy (self->e_lastid, self->e_hash, 20);
      FpPrint *print = NULL; fpi_device_get_enroll_data (dev, &print);
      fpi_device_enroll_progress (dev, self->e_accepted, print, NULL);
      /* The reply's (0,20) id is the chip's per-update confirmation — keep it for the 0x6E
         commit frame (e_lastid), but it is not the template handle; the handle arrives in the
         0x6E reply. */
      guint8 rpt[512]; int rpl = cvfp_unwrap (self, rpt); guint8 rid[20];
      if (rpl > 0 && cvfp_find_param (rpt, rpl, 20, rid) && memcmp (rid, self->e_hash, 20) != 0) {
        memcpy (self->e_lastid, rid, 20); self->e_done = TRUE; }
      fpi_ssm_jump_to_state (ssm, EN_CAP);
      return; }
    if (self->last_cv == 0x8C) { fpi_ssm_jump_to_state (ssm, EN_COMMIT); return; }  /* no more accepted */
    if (self->last_cv < 0) {
      /* Some firmware ends the sample loop by sending an async event on EP_INT instead of a 0x6C
         reply (observed on BCM58200: the final update is answered with event 0x05 "template
         updated"). The chip consumed the command (its reply announcement never comes, but the
         wrapped-counter advanced), so keep the wrap-seq in sync, count the sample as accepted
         and go straight to commit — do NOT fail the enroll here. */
      if (self->last_cv == -3 && self->last_event == 0x05) {
        self->e_accepted++;
        self->e_complete = 0x05;
        self->e_announce_pending = TRUE;   /* give the chip a listener window to announce the
                                              final reply (carrying the enrolment id) after the
                                              clock is answered, before we commit */
        fp_dbg ("cvfp: 0x6C answered by completion event 0x05 (rl==0) — treating as accepted stage %d", self->e_accepted);
        fpi_ssm_jump_to_state (ssm, EN_UPDATE_DRAIN);
        return;
      }
      fail_cv (ssm, "0x6C update", self->last_cv); return; }
    fpi_ssm_jump_to_state (ssm, EN_CAP);   /* 0xA4 / 0x89: retry this scan */
    return; }
  case EN_UPDATE_DRAIN: {   /* post-completion housekeeping — bump seq, clock, listen, commit */
    /* The chip consumed the 12th wrapped frame, so its wrap counter advanced even though the
       reply listener read an empty (event) interrupt: bump the seq unconditionally, else the
       commit would be MAC-invalid anyway. Then answer any deferred clock request, open the
       listener window for the finalize announcement, then commit. */
    self->wrap_seq++;   /* the chip consumed the 12th frame: bump unconditionally
                           (bump_seq would skip it while last_cv is still -3) */
    if (self->pending_clock) {   /* answer the completion event's clock request FIRST — every
                                    answer given at the moment of the
                                    event lands, while
                                    answers given later are followed by total chip silence. */
      self->pending_clock = FALSE;
      fp_dbg ("cvfp: answering the completion event's deferred clock sync before commit");
      send_clock_sync (dev);
    }
    /* Measured: 13 poll/update pairs, the completion
       arriving event-only, the deferred clock answered, and the 0x6E commit racing out in the
       SAME SECOND carrying the sample-hash fallback id. The commit was never announced
       back — and per the measured commit rule a fallback-id commit is refused/
       dropped material: "the enrolment id is the id to commit". In every committed run the host
       held the real id in hand BEFORE 0x6E. The bare bulk drain never yielded a byte, but
       it read WITH a command outstanding (chip silent by design); a listener-only window here
       reads with nothing outstanding, right after the clock the chip asked for was satisfied.
       If the chip finalizes asynchronously after the clock answer, its announcement is only
       deliverable in this exact window (announcements are consumed by the listener armed per
       transceive; an OUT frame steals it). Bounded TO_LSN window: announced reply ->
       EN_UPDATE_DRAIN_RESP harvests the id into the commit frame; silence -> commit as before. */
    if (self->e_announce_pending) {
      self->e_announce_pending = FALSE;
      fp_dbg ("cvfp: event-only completion — listening for the chip's deferred finalize reply before committing");
      cvfp_listen (dev, ssm, TO_LSN, EN_UPDATE_DRAIN_RESP);
      return;
    }
    fpi_ssm_jump_to_state (ssm, EN_COMMIT);
    return; }
  case EN_UPDATE_DRAIN_RESP: {   /* the finalize-listener window returned */
    fp_dbg ("cvfp: finalize-listener result: %u bytes, last_cv=%d", (guint) self->rlen, self->last_cv);
    if (self->last_cv == 0 && self->rlen >= 24) {   /* the chip announced and delivered a reply body */
      guint8 rpt[512]; int rpl = cvfp_unwrap (self, rpt);
      if (rpl > 0) {
        guint8 rid[20];
        if (cvfp_find_param (rpt, rpl, 20, rid) && memcmp (rid, self->e_hash, 20) != 0) {
          memcpy (self->e_lastid, rid, 20); self->e_done = TRUE;
          fp_dbg ("cvfp: deferred finalize reply carried an enrolment id %02x%02x%02x%02x%02x%02x… — committing with it",
                  rid[0], rid[1], rid[2], rid[3], rid[4], rid[5]);
        } else {
          fp_dbg ("cvfp: deferred finalize reply carried no new id — committing with the accumulated e_lastid");
        }
      } else {
        fp_dbg ("cvfp: deferred finalize reply failed to unwrap — committing with the accumulated e_lastid "
                "(the announcement may predate the clock answer; wrap counter skew)");
      }
    } else {
      /* nothing announced in the window: the chip went quiet after the clock answer. Commit with
         what we have (the fallback id) — the 0x8E-restart stays as recovery. */
      fp_dbg ("cvfp: no finalize announcement within %dms — committing with the accumulated e_lastid (e_done=%d e_complete=0x%x)",
              TO_LSN, self->e_done, self->e_complete);
    }
    fpi_ssm_jump_to_state (ssm, EN_COMMIT);
    return; }
  case EN_FINALE:   /* retained for state-table stability; not reachable in the current flow */
    fpi_ssm_mark_completed (ssm);
    return;

  case EN_COMMIT: {
    fp_dbg ("cvfp: EN_COMMIT e_accepted=%d e_done=%d e_complete=0x%x", self->e_accepted, self->e_done, self->e_complete);
    /* Commit if the device signalled completion, or (fallback, like cvchan) if we gathered enough
       accepted stages — so a run that never emits the explicit completion id still enrolls. */
    /* e_complete: this chip can end the sample loop via event 0x05 instead of a 0x6C completion
       id, leaving e_accepted one short of the advertised stage count — that still counts. */
    if (!self->e_done && !self->e_complete && self->e_accepted + 1 < NR_ENROLL_STAGES) {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
        "cvfp: enrollment did not complete (%d/%d stages)", self->e_accepted, NR_ENROLL_STAGES));
      return; }
    guint8 t[64] = {0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,0x14,0,0,0,
                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                    2,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,3,0,0,0,0,0,0,0};
    p32 (t+8, self->handle); memcpy (t+20, self->e_lastid, 20);
    /* Make the committed id visible in the log — a commit carrying the sample-hash
       FALLBACK is expected to be refused (0x8E; the enrolment id is the
       id to commit), so a silent/refused commit must be attributable to the id it carried. */
    fp_dbg ("cvfp: 0x6E commit carries id %02x%02x%02x%02x%02x%02x… (e_done=%d e_complete=0x%x)",
            self->e_lastid[0], self->e_lastid[1], self->e_lastid[2],
            self->e_lastid[3], self->e_lastid[4], self->e_lastid[5],
            self->e_done, self->e_complete);
    self->commit_tries++;
    int n = cvfp_build_wrapped (self,f,0x6E,0x45,self->handle,t,64,96,self->wrap_seq);
    if (n < 0) { fail_wrap (ssm); return; }
    cvfp_transceive (dev, ssm, f, n, TO_INTR, EN_COMMIT_RESP);
    return; }
  case EN_COMMIT_RESP:
    bump_seq (self);
    if (self->last_cv == 0x8E) {
      /* The wrapped commit was refused — that is the unwedge path for a
         chip left in "finalize pending" after an event-only completion (and for a commit that
         carried the sample-hash fallback id). Either way the refusal ends the finalize wait. Drop
         the armed frame and re-run the exchange once instead of failing the session; at most two
         commits (this one and one more) guard against looping. */
      fp_dbg ("cvfp: 0x6E commit refused (0x8E, try %d) — chip released from the finalize wait", self->commit_tries);
      if (self->commit_tries >= 2) {
        /* second refusal: give up cleanly — enroll_done gets the error and stores no print */
        fail_cv (ssm, "0x6E commit (twice)", self->last_cv);
        return; }
      fp_dbg ("cvfp: re-running the enrollment exchange for a binding id");
      self->e_spl = 0; self->e_accepted = 0; self->e_done = FALSE; self->e_complete = 0;
      self->e_announce_pending = FALSE;   /* fresh exchange re-arms the window on its own completion */
      fpi_ssm_jump_to_state (ssm, EN_DISCARD);
      return; }
    if (self->last_cv != 0) { fail_cv (ssm, "0x6E commit", self->last_cv); return; }
    /* Parse the wrapped 0x6E reply — (0,4,0) (0,4,<u32 handle>) (3,0) per cv3-tod — and bind
       the sensor template handle into the print. This is the id 0x2F verify binds against; a
       sample-hash id is never a valid bind (sample-hash commits are refused with 0x8E). */
    {
      guint8 rpt[512]; int rpl = cvfp_unwrap (self, rpt);
      guint8 h[4];
      if (rpl > 0 && cvfp_find_param (rpt, rpl, 4, h)) {
        self->print_handle = g32 (h);
        fp_dbg ("cvfp: 0x6E bound sensor template handle 0x%08x into the print", self->print_handle);
      } else {
        fp_dbg ("cvfp: 0x6E reply carried no u32 template handle — print stays unbound (verify will decline it)");
      }
    }
    fpi_ssm_mark_completed (ssm);
    return;
  }
}
static void enroll_report_cancelled (FpiSsm *ssm, FpDevice *dev, GError *td_error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  g_clear_error (&td_error);
  fpi_device_enroll_complete (dev, NULL, g_steal_pointer (&self->open_error));
}
static void enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  /* Same contract as verify_done: a cancelled enroll (stuck read, pressed stop) disarms and
     closes before the error is reported, so the Release that follows never leaves a live
     session or an armed capture behind on the chip. */
  if (cvfp_is_cancel (error)) {
    self->open_error = error;
    fp_dbg ("cvfp: enroll was cancelled mid-capture — disarming (0x68) and closing (0x04) before reporting");
    cvfp_start_teardown (dev, TRUE, enroll_report_cancelled);
    return;
  }
  if (error) { fpi_device_enroll_complete (dev, NULL, error); return; }
  FpPrint *print = NULL; fpi_device_get_enroll_data (dev, &print);
  set_print_id (print, self->e_lastid);
  /* Also bind the sensor template handle the chip assigned at commit, so verify
     can bind against it. An unbound print is a data-model error, not a soft-fail: verify with it
     sends handle 0 and the chip cannot honour a request bound to nothing (cv3-tod measured). */
  if (self->print_handle) {
    /* Read the body with the contract-proof cvfp_read_body (no
       g_variant_get_fixed_array anywhere on the read path); bytes 20..23 get the sensor
       template handle the chip bound at commit (the 0x6E reply id); if the read
       comes up short, bytes 0..19 are rebuilt from the enrolment id we still hold. */
    GVariant *old; g_object_get (print, "fpi-data", &old, NULL);
    guint8 body[CVFP_PRINT_BODY_LEN] = {0};
    memcpy (body, self->e_lastid, 20);   /* the enroll id only — never old handle bytes */
    if (old) {
      cvfp_read_body (old, body);        /* all-or-nothing: body only rewritten on full read */
      g_clear_pointer (&old, g_variant_unref);
    } else {
      fp_dbg ("cvfp: enroll_done: fpi-data gone post set_print_id — building body from e_lastid");
    }
    p32 (body + 20, self->print_handle);
    GVariant *h = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, body, CVFP_PRINT_BODY_LEN, 1);
    g_object_set (print, "fpi-data", h, NULL);
    fp_dbg ("cvfp: binding sensor handle 0x%08x into the stored print", self->print_handle);
  } else {
    fp_dbg ("cvfp: enroll completed without a bindable sensor handle — the print will not verify");
  }
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}
static void dev_enroll (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  self->op_events = 0;                    /* fresh event-swallow budget for this operation's listeners */
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
  if (!g_usb_device_claim_interface (usb, 0, 0, &err)) { cvfp_open_fail (dev, g_steal_pointer (&err)); return; }
  self->op_events = 0;                    /* fresh event-swallow budget for the handshake listener */
  self->wrap_seq = 0; self->handle = 0;
  self->print_handle = 0; self->print_bound = FALSE;   /* fresh session, fresh binding */
  self->commit_tries = 0;   /* session-scoped 0x8E-restart budget (see EN_DISCARD) */
  self->o_probe_tried = FALSE;   /* fresh open, fresh wake-retry budget */
  if (!cvfp_gen_key (self)) {
    cvfp_open_fail (dev, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "cvfp: keygen failed"));
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
  /* Host storage: fprintd keeps the print metadata on disk and passes it back at verify. The
     stored print's fpi-data carries the sensor template handle bound at commit;
     dev_verify binds 0x2F to that handle. Device STORAGE/IDENTIFY/list remains future work. */
  dc->features = FP_DEVICE_FEATURE_VERIFY;
  /* Verify is 0x2F identify with a bound handle; device-side matching with id binding means
     the print's fpi-data carries the sensor template handle (20-byte enrolment id + u32
     handle, the 24-byte print body described at cvfp_read_body). */
  dc->probe = dev_probe;
  dc->open  = dev_open;
  dc->close = dev_close;
  dc->enroll = dev_enroll;
  dc->verify = dev_verify;
}

/* TOD entry point: libfprint-tod calls this to obtain the driver's GType. */
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void);
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void){ return fpi_device_cvfp_get_type (); }
