#include "xdr.h"

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef XDR_SUFFIX
#define XDR_SUFFIX      ".xdr"
#endif

enum {
    PATH_TLV = 0,
    PATH_XDR = 1,
    PATH_SHA = 2,
    PATH_BAD = 3,
    
    PATH_END
};

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE              INOTIFY_EVSIZE
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_ev, _len)    OS_HAS_SUFFIX((_ev)->name, _len, XDR_SUFFIX, sizeof(XDR_SUFFIX)-1)

static char EVBUF[EVCOUNT * INOTIFY_EVSIZE];

static char *self;

static inline void
ev_debug(inotify_ev_t *ev)
{
    if (ev->mask & IN_CLOSE_WRITE) {
        xdr_dprint("event close write file:%s", ev->name);
    }

    if (ev->mask & IN_MOVED_TO) {
        xdr_dprint("event move to file:%s", ev->name);
    }
}

static nameflag_t opt[] = {
    { .flag = TLV_OPT_CLI,          .name = "--cli",        .help = "cli mode"},
    { .flag = TLV_OPT_IP6,          .name = "--ip6",        .help = "ipv6[not support now]"},
    { .flag = TLV_OPT_DUMP,         .name = "--dump",       .help = "dump all"},
    { .flag = TLV_OPT_STRICT,       .name = "--strict",     .help = "strict check"},
    { .flag = TLV_OPT_DUMP_SIMPLE,  .name = "--dump-simple",.help = "dump with simple format"},
    { .flag = TLV_OPT_SPLIT,        .name = "--file-split", .help = "dpi file split from xdr"},
};

static int usage(void)
{
    os_println("%s [OPTION] tlv-path xdr-path sha-path", self);
    os_println(__tab "OPTION:");

    int i;

    for (i=0; i<os_count_of(opt); i++) {
        os_println(__tab "%s: %s", opt[i].name, opt[i].help);
    }

    return -1;
}

static void
opt_analysis(char *args)
{
    int flag = get_nameflag_byname(opt, args);

    set_option(flag);
}

static int xdr_handle(char *file, int len, char *path[PATH_END])
{
    static int tlv_path_len;
    static int xdr_path_len;
    static char tlv[1+OS_FILENAME_LEN]; 
    static char xdr[1+OS_FILENAME_LEN]; 
    xpair_t pair = XPAIR_INITER(file, tlv, xdr, path[PATH_SHA], path[PATH_BAD]);

    if (0==tlv_path_len) {
        tlv_path_len = strlen(path[PATH_TLV]);
        memcpy(tlv, path[PATH_TLV], tlv_path_len);
        tlv[tlv_path_len++] = '/';
    }

    if (0==xdr_path_len) {
        xdr_path_len = strlen(path[PATH_XDR]);
        memcpy(xdr, path[PATH_XDR], xdr_path_len);
        xdr[xdr_path_len++] = '/';
    }
    
    memcpy(tlv+tlv_path_len, file, len); tlv[tlv_path_len+len] = 0;
    memcpy(xdr+xdr_path_len, file, len); xdr[xdr_path_len+len] = 0;
    
    xdr_dprint("handle tlv:%s", tlv);
    xdr_dprint("handle xdr:%s", xdr);

    int err = tlv_to_xdr(&pair);
    if (err<0) {
        // log
    }

    return 0;
}

static int remove_handle(char *file, char *path[PATH_END])
{
    char filename[1+OS_FILENAME_LEN] = {0};

    os_saprintf(filename, "%s/%s", path[PATH_TLV], file);

    remove(filename);
    
    xdr_dprint("remove %s", filename);
    
    return 0;
}

static int handle(inotify_ev_t *ev, char *path[PATH_END])
{
    int len = inotify_ev_len(ev);
    
    if (ISXDR(ev, len)) {
        return xdr_handle(ev->name, len, path);
    } else {
        return remove_handle(ev->name, path);
    }
}

static int monitor(char *path[PATH_END])
{
    int fd, err;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        return -errno;
    }

    err = inotify_add_watch(fd, path[PATH_TLV], EVMASK);
    if (err<0) {
        return -errno;
    }

    for (;;) {
        int len = read(fd, EVBUF, sizeof(EVBUF));
        if (len == -1 && errno != EAGAIN) {
            return -errno;
        }
        OS_VAR(time) = time(NULL);

        inotify_ev_t *ev    = (inotify_ev_t *)EVBUF;
        inotify_ev_t *end   = (inotify_ev_t *)(EVBUF + len);
        
        for (; ev<end; ev=EVNEXT(ev)) {
            if (ev->mask & EVMASK) {
                ev_debug(ev);
                
                err = handle(ev, path);
                if (err<0) {
                    return err;
                }
            }
        }
    }
}

#ifndef ENV_TLV_FILE
#define ENV_TLV_FILE    "TLV_FILE"
#endif

static int cli(char *path[PATH_END])
{
    char *file = env_gets(ENV_TLV_FILE, NULL);
    if (NULL==file) {
        os_println("not found env ENV_TLV_FILE");
    }
    
    return xdr_handle(file, strlen(file), path);
}

int main(int argc, char *argv[])
{
    self = argv[0];

    tlv_check_obj();
    
    argc--; argv++;
    while(1) {
        char *args = argv[0];

        if (false==is_option_args(args)) {
            break;
        }
        
        if (0==strcmp("--help", args)) {
            return usage();
        } else {
            opt_analysis(args);
        }

        argc--; argv++;
    }

    if (PATH_END != argc) {
        return usage();
    }

    if (is_option(TLV_OPT_CLI)) {
        return cli(argv);
    } else {
        return monitor(argv);
    }
}

/******************************************************************************/
