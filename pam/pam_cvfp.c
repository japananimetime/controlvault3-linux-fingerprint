// pam_cvfp — PAM auth via the ControlVault fingerprint (calls /usr/local/bin/cvfp-verify).
// Use as:  auth  sufficient  pam_cvfp.so     (place BEFORE the password line so it never locks out)
// Optional args: helper=/path  key=/path  debug
//   exit 0 -> PAM_SUCCESS (match);  1 -> PAM_AUTH_ERR (no match);  else -> PAM_AUTHINFO_UNAVAIL.
#include <stdio.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv){
    const char *helper = "/usr/local/bin/cvfp-verify";
    int debug = 0; char tobuf[16]; const char *tostr = NULL;
    for(int i=0;i<argc;i++){
        if(!strncmp(argv[i],"helper=",7)) helper=argv[i]+7;
        else if(!strncmp(argv[i],"timeout=",8)){ int sec=atoi(argv[i]+8); if(sec>=1&&sec<=60){ snprintf(tobuf,sizeof tobuf,"%d",sec*1000); tostr=tobuf; } }
        else if(!strcmp(argv[i],"debug")) debug=1;
    }
    pam_info(pamh, "Touch the fingerprint sensor (or wait for password)...");
    pam_syslog(pamh, LOG_INFO, "cvfp: starting fingerprint auth");

    pid_t pid = fork();
    if(pid < 0) return PAM_AUTHINFO_UNAVAIL;
    if(pid == 0){
        if(!debug){ freopen("/dev/null","w",stderr); }
        if(tostr) execl(helper, helper, tostr, (char*)NULL);
        else      execl(helper, helper, (char*)NULL);
        _exit(2);
    }
    int status=0;
    if(waitpid(pid,&status,0) < 0) return PAM_AUTHINFO_UNAVAIL;
    if(!WIFEXITED(status)) return PAM_AUTHINFO_UNAVAIL;
    int rc = WEXITSTATUS(status);
    pam_syslog(pamh, LOG_INFO, "cvfp: helper exit=%d", rc);
    switch(rc){
        case 0:  return PAM_SUCCESS;
        case 1:  return PAM_AUTH_ERR;            // no match / timeout
        default: return PAM_AUTHINFO_UNAVAIL;    // sensor busy or error -> fall through to next module
    }
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){ return PAM_SUCCESS; }
