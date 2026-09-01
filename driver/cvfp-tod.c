/*
 * libfprint TOD driver for the Dell/Broadcom ControlVault 3 fingerprint sensor (0a5c:5843).
 * Implements the reverse-engineered secure channel (see ../docs/secure-channel.md): keyless
 * ECDH-P256 handshake, AES-128-CBC wrapping, enroll/verify. Drop-in replacement for the stock
 * (non-working) libfprint-2-tod-1-broadcom.so.
 *
 * Milestone 1: probe + open (handshake) + close. enroll/verify follow.
 */
#include "drivers_api.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_INT 0x85

struct _FpiDeviceCvfp {
  FpDevice      parent;
  EC_KEY       *host_key;
  guint8        host_pub[64];
  guint8        session_key[16];
  guint8        master[20];
  guint         wrap_seq;
  guint32       handle;
  guint8        rb[8192];
  gsize         rlen;
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

/* --- synchronous transceive (OUT -> INTR status/len -> IN reply) ----------------------------- */
static int cvfp_xfer (FpDevice *dev, const guint8 *frame, gsize n, guint out_ms, guint intr_ms){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  g_autoptr(GError) err = NULL;
  { g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk (t, EP_OUT, n); memcpy (t->buffer, frame, n);
    if (!fpi_usb_transfer_submit_sync (t, out_ms, &err)) return -2; }
  guint32 rl = 0;
  { g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_interrupt (t, EP_INT, 32);
    if (!fpi_usb_transfer_submit_sync (t, intr_ms, &err)) return -2;
    if (t->actual_length >= 8) rl = g32 (t->buffer+4); }
  if (rl == 0) { self->rlen = 0; return -3; }
  { g_autoptr(FpiUsbTransfer) t = fpi_usb_transfer_new (dev);
    fpi_usb_transfer_fill_bulk (t, EP_IN, rl > sizeof self->rb ? sizeof self->rb : rl);
    if (!fpi_usb_transfer_submit_sync (t, 5000, &err)) return -2;
    self->rlen = t->actual_length; memcpy (self->rb, t->buffer, self->rlen);
    return (self->rlen >= 24) ? (int) g32 (self->rb+20) : -1; }
}

/* --- the ECDH handshake + session open ------------------------------------------------------- */
static gboolean cvfp_open_channel (FpDevice *dev, GError **error){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  guint8 cn[20]; RAND_bytes (cn, 20);
  guint8 f23[68]; cvfp_hdr (f23,0x23,0x41,0,0,68); p32 (f23+40,24); memcpy (f23+44,cn,20); p32 (f23+64,1);
  if (cvfp_xfer (dev,f23,68,2500,60000) != 0) goto fail;
  self->handle = g32 (self->rb+16);
  guint8 dpub[64], dn[20]; memcpy (dpub,self->rb+44,64); memcpy (dn,self->rb+44+128,20);
  guint8 hn2[20]; RAND_bytes (hn2,20);
  guint8 f24[128]; cvfp_hdr (f24,0x24,0x01,0,self->handle,128); p32 (f24+40,84); memcpy (f24+44,hn2,20); memcpy (f24+64,self->host_pub,64);
  if (cvfp_xfer (dev,f24,128,5000,60000) != 0) goto fail;
  guint8 Z[32]; if (!cvfp_ecdh (self,dpub,Z)) goto fail;
  SHA1 (Z,32,self->master);
  { guint8 b[60],dg[20]; memcpy (b,self->master,20); memcpy (b+20,dn,20); memcpy (b+40,hn2,20); SHA1 (b,60,dg); memcpy (self->session_key,dg,16); }
  guint8 tlv02[36] = {0,0,0,0,4,0,0,0,0x4f,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0};
  guint8 f02[256]; int n02 = cvfp_build_wrapped (self,f02,0x02,0x45,self->handle,tlv02,36,80,self->wrap_seq);
  if (cvfp_xfer (dev,f02,n02,5000,60000) != 0) goto fail;
  self->wrap_seq = 1;
  fp_info ("cvfp: secure channel open (handle 0x%08x)", self->handle);
  return TRUE;
fail:
  g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO, "cvfp: channel handshake failed");
  return FALSE;
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
  self->wrap_seq = 0;
  if (!cvfp_gen_key (self)) { g_set_error (&err, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL, "keygen failed"); fpi_device_open_complete (dev, g_steal_pointer (&err)); return; }
  if (!cvfp_open_channel (dev, &err)) { fpi_device_open_complete (dev, g_steal_pointer (&err)); return; }
  fpi_device_open_complete (dev, NULL);
}
static void dev_close (FpDevice *dev){
  FpiDeviceCvfp *self = FPI_DEVICE_CVFP (dev);
  if (self->handle) { guint8 c[56]; cvfp_hdr (c,0x04,0x40,0x04,0,56); p32 (c+40,12); p32 (c+48,4); p32 (c+52,self->handle); cvfp_xfer (dev,c,56,2000,3000); self->handle = 0; }
  if (self->host_key) { EC_KEY_free (self->host_key); self->host_key = NULL; }
  GUsbDevice *usb = fpi_device_get_usb_device (dev);
  g_autoptr(GError) err = NULL;
  g_usb_device_release_interface (usb, 0, 0, &err);
  fpi_device_close_complete (dev, NULL);
}

static void fpi_device_cvfp_init (FpiDeviceCvfp *self){}
static void fpi_device_cvfp_class_init (FpiDeviceCvfpClass *klass){
  FpDeviceClass *dc = FP_DEVICE_CLASS (klass);
  dc->id = "cvfp";
  dc->full_name = "Dell ControlVault 3 fingerprint";
  dc->type = FP_DEVICE_TYPE_USB;
  dc->id_table = id_table;
  dc->scan_type = FP_SCAN_TYPE_PRESS;
  dc->nr_enroll_stages = 12;
  dc->probe = dev_probe;
  dc->open  = dev_open;
  dc->close = dev_close;
}

/* TOD entry point: libfprint-tod calls this to obtain the driver's GType. */
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void);
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void){ return fpi_device_cvfp_get_type (); }
