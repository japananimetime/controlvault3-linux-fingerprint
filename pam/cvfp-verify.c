// cvfp-verify — authenticate a fingerprint over the ControlVault secure channel.
// Exit 0 = MATCH, 1 = NO MATCH / timeout, 2 = error. Prints a touch prompt to stderr.
// Keyless: generates an ephemeral host keypair each run (the chip does not authenticate it).
//
// This is the verify path proven in cvchan.c, stripped to a single quiet check for PAM use.
// Build: gcc -O2 -o cvfp-verify cvfp-verify.c -lusb-1.0 -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libusb-1.0/libusb.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define VID 0x0a5c
#define PID 0x5843
#define EP_OUT 0x01
#define EP_IN  0x81
#define EP_INT 0x85
static int touch_timeout_ms = 12000;   // overridable via argv[2]

static const unsigned char MAC_SEED[23] =
  {'C','V',' ','s','e','c','u','r','e',' ','s','e','s','s','i','o','n',' ','b','l','o','b','\0'};

static libusb_device_handle *h;
static unsigned char rb[8192];
static int rlen;
static EC_KEY *host_key = NULL; static unsigned char host_pub[64];
static unsigned char session_key[16], master[20];
static unsigned wrap_seq = 0;

static void put32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static unsigned get32(const unsigned char*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned)p[3]<<24);}
static int unhex(const char*s,unsigned char*o){int n=0;for(;s[0]&&s[1];s+=2){char b[3]={s[0],s[1],0};o[n++]=(unsigned char)strtol(b,0,16);}return n;}

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
static int ecdh(const unsigned char*pub,unsigned char out[32]){
    int ok=-1; const EC_GROUP*g=EC_KEY_get0_group(host_key);
    BIGNUM*x=BN_bin2bn(pub,32,0),*y=BN_bin2bn(pub+32,32,0);
    EC_POINT*P=EC_POINT_new(g); BN_CTX*c=BN_CTX_new();
    if(EC_POINT_set_affine_coordinates(g,P,x,y,c)&&ECDH_compute_key(out,32,P,host_key,0)==32) ok=0;
    EC_POINT_free(P);BN_free(x);BN_free(y);BN_CTX_free(c); return ok;
}
static int aes(int enc,const unsigned char*iv,const unsigned char*in,int inlen,unsigned char*out){
    EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new(); int l1=0,l2=0,rc=-1;
    if(EVP_CipherInit_ex(c,EVP_aes_128_cbc(),0,session_key,iv,enc)&&EVP_CipherUpdate(c,out,&l1,in,inlen)&&EVP_CipherFinal_ex(c,out+l1,&l2)) rc=l1+l2;
    EVP_CIPHER_CTX_free(c); return rc;
}
static int hdr(unsigned char*p,unsigned cmd,unsigned attr,unsigned enc,unsigned handle,unsigned total){
    memset(p,0,44); put32(p,1); put32(p+4,total); p[8]=cmd&0xff; p[9]=(cmd>>8)&0xff; p[10]=attr; p[11]=enc; put32(p+12,2); put32(p+16,handle); return 44;
}
static int xfer(const unsigned char*frame,int n,int touch_ms){
    static unsigned char out[8192]; memcpy(out,frame,n);
    int a=0,rc=libusb_bulk_transfer(h,EP_OUT,out,n,&a,5000); if(rc) return -2;
    unsigned char ib[32]; rc=libusb_interrupt_transfer(h,EP_INT,ib,sizeof ib,&a, touch_ms?touch_ms:60000); if(rc) return -2;
    unsigned rl=(a>=8)?get32(ib+4):0;
    if(rl==0){ rlen=0; return -3; }
    rc=libusb_bulk_transfer(h,EP_IN,rb,rl>sizeof rb?sizeof rb:rl,&a,5000); if(rc) return -2;
    rlen=a; return (a>=24)?(int)get32(rb+20):-1;
}
static int build_wrapped(unsigned char*out,unsigned cmd,unsigned attr,unsigned handle,const unsigned char*tlv,int tlvlen,int ptlen,unsigned suffix){
    unsigned char macKey[32]; SHA256(MAC_SEED,23,macKey);
    unsigned char iv[16]; RAND_bytes(iv,16);
    int ctlen=((ptlen/16)+1)*16, total=44+ctlen;
    hdr(out,cmd,attr,0x02,handle,total); memcpy(out+24,iv,16); put32(out+40,tlvlen);
    unsigned char macin[256]; memcpy(macin,out,44); memcpy(macin+44,tlv,tlvlen); put32(macin+44+tlvlen,suffix);
    unsigned char token[32]; unsigned int tl; HMAC(EVP_sha256(),macKey,32,macin,44+tlvlen+4,token,&tl);
    unsigned char pt[256]; memset(pt,0,ptlen); memcpy(pt,tlv,tlvlen); memcpy(pt+tlvlen,token,32);
    unsigned char ct[512]; int clen=aes(1,iv,pt,ptlen,ct); if(clen<0) return -1;
    memcpy(out+44,ct,clen); return total;
}
static int unwrap(unsigned char*pt){ if(rlen<44+16) return -1; int cl=rlen-44; if(cl%16) return -1; return aes(0,rb+24,rb+44,cl,pt); }
static void close_handle(unsigned hnd){ if(!hnd) return; unsigned char c[56]; hdr(c,0x04,0x40,0x04,0,56); put32(c+40,12); put32(c+48,4); put32(c+52,hnd); xfer(c,56,0); }
static void cancel(void){ unsigned char t[12]={0,0,0,0,4,0,0,0,0,0,0,0}; unsigned char f[56]; hdr(f,0x68,0x44,0x00,0,44+12); put32(f+40,12); memcpy(f+44,t,12); xfer(f,56,0); }

int main(int argc,char**argv){
    if(argc>1){ int t=atoi(argv[1]); if(t>=1000 && t<=60000) touch_timeout_ms=t; }
    if(gen_host_key()) return 2;
    libusb_context*ctx=0; if(libusb_init(&ctx)) return 2;
    h=libusb_open_device_with_vid_pid(ctx,VID,PID); if(!h){ fprintf(stderr,"cvfp: sensor not found\n"); return 2; }
    if(libusb_kernel_driver_active(h,0)==1) libusb_detach_kernel_driver(h,0);
    if(libusb_claim_interface(h,0)){ fprintf(stderr,"cvfp: sensor busy\n"); return 2; }
    int result = 1;   // default: no match

    // handshake + open
    unsigned char cn[20]; RAND_bytes(cn,20);
    unsigned char f23[68]; hdr(f23,0x23,0x41,0x00,0,68); put32(f23+40,24); memcpy(f23+44,cn,20); put32(f23+64,1);
    if(xfer(f23,68,0)!=0){ result=2; goto out; }
    unsigned handle=get32(rb+16); unsigned char dpub[64],dnonce[20];
    memcpy(dpub,rb+44,64); memcpy(dnonce,rb+44+128,20);
    unsigned char hn2[20]; RAND_bytes(hn2,20);
    unsigned char f24[128]; hdr(f24,0x24,0x01,0x00,handle,128); put32(f24+40,84); memcpy(f24+44,hn2,20); memcpy(f24+64,host_pub,64);
    if(xfer(f24,128,0)!=0){ result=2; goto out; }
    unsigned char Z[32]; if(ecdh(dpub,Z)){ result=2; goto out; }
    SHA1(Z,32,master);
    { unsigned char b[60],dg[20]; memcpy(b,master,20);memcpy(b+20,dnonce,20);memcpy(b+40,hn2,20); SHA1(b,60,dg); memcpy(session_key,dg,16); }
    unsigned char tlv02[36]={0,0,0,0,4,0,0,0,0x4f,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0};
    unsigned char f02[256]; int n02=build_wrapped(f02,0x02,0x45,handle,tlv02,36,80,wrap_seq);
    if(xfer(f02,n02,0)!=0){ result=2; goto out; } wrap_seq=1;

    // arm capture, wait for finger
    fprintf(stderr,"Touch the fingerprint sensor...\n");
    unsigned char t66[36]={0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,1,0,0,0,0,0,0,0,4,0,0,0,0x23,0,0,0};
    put32(t66+8,handle);
    unsigned char f66[256]; int n66=build_wrapped(f66,0x66,0x47,handle,t66,36,80,wrap_seq);
    int c=xfer(f66,n66,0);
    if(c==0x85){ cancel(); c=xfer(f66,n66,0); }
    if(c!=0){ result=1; goto close; }
    wrap_seq++;
    // wait for the async finger-read event (bounded)
    { unsigned char ib[32]; int a=0; int rc=libusb_interrupt_transfer(h,EP_INT,ib,sizeof ib,&a,touch_timeout_ms);
      if(rc || (a>=4 && get32(ib)!=0x03)){ cancel(); result=1; goto close; } }

    // match
    unsigned char t73[68]={0,0,0,0,4,0,0,0,0,0,0,0, 0,0,0,0,4,0,0,0,0x48,0x01,0,0,
        0,0,0,0,4,0,0,0,0xe2,0x53,0,0, 0,0,0,0,4,0,0,0,0,0,0,0,
        2,0,0,0,4,0,0,0,0xd3,0x0a,0x7b,0, 3,0,0,0,0x14,0,0,0};
    put32(t73+8,handle);
    unsigned char f73[256]; int n73=build_wrapped(f73,0x73,0x47,handle,t73,68,112,wrap_seq);
    c=xfer(f73,n73,0);
    if(c==0){ unsigned char pt[512]; int pl=unwrap(pt); if(pl>=12 && get32(pt+8)==1) result=0; }

close:
    close_handle(handle);
out:
    libusb_release_interface(h,0); libusb_close(h); libusb_exit(ctx);
    if(result==0) fprintf(stderr,"cvfp: match\n");
    else if(result==1) fprintf(stderr,"cvfp: no match\n");
    return result;
}
