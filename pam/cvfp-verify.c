// cvfp-verify — authenticate a fingerprint over the ControlVault secure channel.
// Exit 0 = MATCH, 1 = NO MATCH / timeout, 2 = error. Prints a touch prompt to stderr.
// Keyless: generates an ephemeral host keypair each run (the chip does not authenticate it).
//
// Robustness:
//   * Signal handlers (TERM/INT/HUP) cancel the capture and close the session before exiting,
//     so a cancelled prompt or a suspend never leaves the sensor wedged.
//   * If the first handshake times out (a light wedge from some earlier crash), the sensor is
//     auto-recovered with a USB `authorized` toggle and the handshake is retried once. (A deep
//     wedge — the chip's command processor stuck — is rare and needs a reboot.)
// Build: gcc -O2 -o cvfp-verify cvfp-verify.c -lusb-1.0 -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <strings.h>
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

static const unsigned char MAC_SEED[23] =
  {'C','V',' ','s','e','c','u','r','e',' ','s','e','s','s','i','o','n',' ','b','l','o','b','\0'};

static libusb_device_handle *h;
static unsigned char rb[8192];
static int rlen;
static EC_KEY *host_key = NULL; static unsigned char host_pub[64];
static unsigned char session_key[16], master[20];
static unsigned wrap_seq = 0;
static int touch_timeout_ms = 12000;

static volatile sig_atomic_t g_sig = 0;   // set by signal handler
static unsigned g_session = 0;            // open session handle (for teardown)
static int g_armed = 0;                   // a capture is armed (for teardown)
static void on_sig(int s){ (void)s; g_sig = 1; }

static void put32(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}
static unsigned get32(const unsigned char*p){return p[0]|(p[1]<<8)|(p[2]<<16)|((unsigned)p[3]<<24);}
static void napms(long ms){ struct timespec t={ms/1000,(ms%1000)*1000000L}; nanosleep(&t,0); }

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
static int aescbc(int e,const unsigned char*iv,const unsigned char*in,int il,unsigned char*out){
    EVP_CIPHER_CTX*c=EVP_CIPHER_CTX_new();int l1=0,l2=0,r=-1;
    if(EVP_CipherInit_ex(c,EVP_aes_128_cbc(),0,session_key,iv,e)&&EVP_CipherUpdate(c,out,&l1,in,il)&&EVP_CipherFinal_ex(c,out+l1,&l2))r=l1+l2;
    EVP_CIPHER_CTX_free(c); return r;
}
static int hdr(unsigned char*p,unsigned cmd,unsigned attr,unsigned enc,unsigned handle,unsigned total){
    memset(p,0,44); put32(p,1); put32(p+4,total); p[8]=cmd&0xff; p[9]=(cmd>>8)&0xff; p[10]=attr; p[11]=enc; put32(p+12,2); put32(p+16,handle); return 44;
}
// Normal transaction. out_ms bounds the bulk-OUT (wedge detection); intr_ms the interrupt read.
static int xfer2(const unsigned char*frame,int n,int out_ms,int intr_ms){
    static unsigned char out[8192]; memcpy(out,frame,n);
    int a=0,rc=libusb_bulk_transfer(h,EP_OUT,out,n,&a,out_ms); if(rc) return -2;
    unsigned char ib[32]; rc=libusb_interrupt_transfer(h,EP_INT,ib,sizeof ib,&a,intr_ms); if(rc) return -2;
    unsigned rl=(a>=8)?get32(ib+4):0;
    if(rl==0){ rlen=0; return -3; }
    rc=libusb_bulk_transfer(h,EP_IN,rb,rl>sizeof rb?sizeof rb:rl,&a,5000); if(rc) return -2;
    rlen=a; return (a>=24)?(int)get32(rb+20):-1;
}
static int xfer(const unsigned char*frame,int n){ return xfer2(frame,n,5000,60000); }
// Best-effort short-timeout transaction, for teardown while unwinding.
static void quick(const unsigned char*frame,int n){
    static unsigned char out[8192]; memcpy(out,frame,n); int a=0;
    if(libusb_bulk_transfer(h,EP_OUT,out,n,&a,1000)) return;
    unsigned char ib[32]; if(libusb_interrupt_transfer(h,EP_INT,ib,sizeof ib,&a,1500)) return;
    unsigned rl=(a>=8)?get32(ib+4):0; if(rl){int d=0;libusb_bulk_transfer(h,EP_IN,rb,rl>sizeof rb?sizeof rb:rl,&d,1000);}
}
static int build_wrapped(unsigned char*out,unsigned cmd,unsigned attr,unsigned handle,const unsigned char*tlv,int tlvlen,int ptlen,unsigned suffix){
    unsigned char macKey[32]; SHA256(MAC_SEED,23,macKey);
    unsigned char iv[16]; RAND_bytes(iv,16);
    int ctlen=((ptlen/16)+1)*16, total=44+ctlen;
    hdr(out,cmd,attr,0x02,handle,total); memcpy(out+24,iv,16); put32(out+40,tlvlen);
    unsigned char macin[256]; memcpy(macin,out,44); memcpy(macin+44,tlv,tlvlen); put32(macin+44+tlvlen,suffix);
    unsigned char token[32]; unsigned int tl; HMAC(EVP_sha256(),macKey,32,macin,44+tlvlen+4,token,&tl);
    unsigned char pt[256]; memset(pt,0,ptlen); memcpy(pt,tlv,tlvlen); memcpy(pt+tlvlen,token,32);
    unsigned char ct[512]; int clen=aescbc(1,iv,pt,ptlen,ct); if(clen<0) return -1;
    memcpy(out+44,ct,clen); return total;
}
static int unwrap(unsigned char*pt){ if(rlen<44+16) return -1; int cl=rlen-44; if(cl%16) return -1; return aescbc(0,rb+24,rb+44,cl,pt); }

// --- teardown + recovery ---------------------------------------------------------------------
static void tear_down(void){          // cancel a pending capture and close the session, quickly
    if(!h) return;
    if(g_armed){ unsigned char f[56]; hdr(f,0x68,0x44,0x00,0,56); put32(f+40,12); quick(f,56); g_armed=0; }
    if(g_session){ unsigned char c[56]; hdr(c,0x04,0x40,0x04,0,56); put32(c+40,12); put32(c+48,4); put32(c+52,g_session); quick(c,56); g_session=0; }
}
static int rd(const char*base,const char*leaf,char*o,int n){ char p[600]; snprintf(p,sizeof p,"%s/%s",base,leaf); FILE*f=fopen(p,"r"); if(!f)return -1; int r=fread(o,1,n-1,f); fclose(f); if(r<=0)return -1; o[r]=0; o[strcspn(o,"\n")]=0; return 0; }
static void recover_device(void){     // toggle USB authorized to clear a light wedge (setuid root)
    DIR*d=opendir("/sys/bus/usb/devices"); if(!d) return; struct dirent*e; char base[600]={0};
    while((e=readdir(d))){ if(e->d_name[0]=='.')continue; char b[600],v[16],p[16];
        snprintf(b,sizeof b,"/sys/bus/usb/devices/%s",e->d_name);
        if(rd(b,"idVendor",v,16)||rd(b,"idProduct",p,16))continue;
        if(!strcasecmp(v,"0a5c")&&!strcasecmp(p,"5843")){ snprintf(base,sizeof base,"%s",b); break; } }
    closedir(d); if(!base[0]) return;
    char ap[640]; snprintf(ap,sizeof ap,"%s/authorized",base);
    FILE*f=fopen(ap,"w"); if(f){ fputs("0",f); fclose(f); } napms(2000);
    f=fopen(ap,"w"); if(f){ fputs("1",f); fclose(f); } napms(3000);
}

int main(int argc,char**argv){
    if(argc>1){ int t=atoi(argv[1]); if(t>=1000 && t<=60000) touch_timeout_ms=t; }
    if(gen_host_key()) return 2;
    struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_handler=on_sig;
    sigaction(SIGTERM,&sa,0); sigaction(SIGINT,&sa,0); sigaction(SIGHUP,&sa,0);

    libusb_context*ctx=0; if(libusb_init(&ctx)) return 2;
    int result = 1;                   // default: no match

    // open + handshake, with one auto-recovery retry if the sensor is wedged
    unsigned handle=0; unsigned char dpub[64],dn[20]; int ready=0;
    for(int attempt=0; attempt<2 && !ready && !g_sig; attempt++){
        if(attempt>0){                // recover from a light wedge and re-enumerate
            if(h){ libusb_release_interface(h,0); libusb_close(h); h=NULL; }
            recover_device();
        }
        for(int t=0;t<25 && !h;t++){ h=libusb_open_device_with_vid_pid(ctx,VID,PID); if(!h) napms(200); }
        if(!h) continue;
        if(libusb_kernel_driver_active(h,0)==1) libusb_detach_kernel_driver(h,0);
        // claim with retry: the device may be transiently held (e.g. a lock-screen watcher between polls)
        int claimed=0; for(int t=0;t<12 && !claimed && !g_sig;t++){ if(libusb_claim_interface(h,0)==0) claimed=1; else napms(250); }
        if(!claimed){ libusb_close(h); h=NULL; break; }   // still busy: fall through to password, don't disturb the holder
        unsigned char cn[20]; RAND_bytes(cn,20);
        unsigned char f23[68]; hdr(f23,0x23,0x41,0,0,68); put32(f23+40,24); memcpy(f23+44,cn,20); put32(f23+64,1);
        int out_ms = (attempt==0) ? 2500 : 5000;   // detect a wedge fast on the first try
        if(xfer2(f23,68,out_ms,60000)==0){ handle=get32(rb+16); memcpy(dpub,rb+44,64); memcpy(dn,rb+44+128,20); ready=1; }
    }
    if(g_sig){ result=2; goto out; }
    if(!ready){ fprintf(stderr,"cvfp: sensor unavailable\n"); result=2; goto out; }

    // 0x24 with our ephemeral public key
    unsigned char hn2[20]; RAND_bytes(hn2,20);
    unsigned char f24[128]; hdr(f24,0x24,0x01,0,handle,128); put32(f24+40,84); memcpy(f24+44,hn2,20); memcpy(f24+64,host_pub,64);
    if(xfer(f24,128)!=0){ result=2; goto out; }
    unsigned char Z[32]; if(ecdh(dpub,Z)){ result=2; goto out; }
    SHA1(Z,32,master);
    { unsigned char b[60],dg[20]; memcpy(b,master,20);memcpy(b+20,dn,20);memcpy(b+40,hn2,20); SHA1(b,60,dg); memcpy(session_key,dg,16); }

    // 0x02 open
    unsigned char tlv02[36]={0,0,0,0,4,0,0,0,0x4f,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0};
    unsigned char f02[256]; int n02=build_wrapped(f02,0x02,0x45,handle,tlv02,36,80,wrap_seq);
    if(xfer(f02,n02)!=0){ result=2; goto out; }
    g_session=handle; wrap_seq=1;
    if(g_sig){ tear_down(); result=2; goto out; }

    // arm capture, wait for the finger (interruptible)
    fprintf(stderr,"Touch the fingerprint sensor...\n");
    unsigned char t66[36]={0,0,0,0,4,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0,1,0,0,0,0,0,0,0,4,0,0,0,0x23,0,0,0};
    put32(t66+8,handle);
    unsigned char f66[256]; int n66=build_wrapped(f66,0x66,0x47,handle,t66,36,80,wrap_seq);
    int c=xfer(f66,n66);
    if(c==0x85){ unsigned char f[56]; hdr(f,0x68,0x44,0,0,56); put32(f+40,12); quick(f,56); c=xfer(f66,n66); }
    if(c!=0){ result=1; goto close; }
    wrap_seq++; g_armed=1;

    { int got=0; long waited=0;        // poll so a signal can interrupt the wait
      while(waited < touch_timeout_ms && !g_sig){
        unsigned char ib[32]; int a=0;
        int rc=libusb_interrupt_transfer(h,EP_INT,ib,sizeof ib,&a,200);
        if(rc==LIBUSB_ERROR_TIMEOUT){ waited+=200; continue; }
        if(rc){ break; }
        if(a>=4 && get32(ib)==0x03){ got=1; break; }
      }
      if(!got){ tear_down(); result = g_sig?2:1; goto out; }
    }

    // match
    unsigned char t73[68]={0,0,0,0,4,0,0,0,0,0,0,0, 0,0,0,0,4,0,0,0,0x48,0x01,0,0,
        0,0,0,0,4,0,0,0,0xe2,0x53,0,0, 0,0,0,0,4,0,0,0,0,0,0,0,
        2,0,0,0,4,0,0,0,0xd3,0x0a,0x7b,0, 3,0,0,0,0x14,0,0,0};
    put32(t73+8,handle);
    unsigned char f73[256]; int n73=build_wrapped(f73,0x73,0x47,handle,t73,68,112,wrap_seq);
    g_armed=0;                          // the match consumes the capture
    c=xfer(f73,n73);
    if(c==0){ unsigned char pt[512]; int pl=unwrap(pt); if(pl>=12 && get32(pt+8)==1) result=0; }

close:
    tear_down();
out:
    if(h){ libusb_release_interface(h,0); libusb_close(h); } libusb_exit(ctx);
    if(result==0) fprintf(stderr,"cvfp: match\n");
    else if(result==1) fprintf(stderr,"cvfp: no match\n");
    return result;
}
