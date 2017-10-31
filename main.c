#include "xdr.h"

DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef XDR_SUFFIX
#define XDR_SUFFIX      ".xdr"
#endif

enum {
    PATH_TLV = 0,
    PATH_XDR = 1,
    PATH_SHA = 2,
    
    PATH_END
};

typedef struct inotify_event inotify_ev_t;

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE(_namelen)    (sizeof(inotify_ev_t) + _namelen + 1)
#define EVNEXT(_ev)         (inotify_ev_t *)((char *)(_ev) + EVSIZE((_ev)->len - 1))
#define ISXDR(_ev)          OS_HAS_SUFFIX((_ev)->name, (_ev)->len-1, XDR_SUFFIX, sizeof(XDR_SUFFIX)-1)

static char EVBUF[EVCOUNT * EVSIZE(NAME_MAX)];

static char *self;

static struct {
    char *name;
    uint32 flag;
} opt[] = {
    { .name = "--dump",         .flag = TLV_OPT_DUMP },
    { .name = "--file-split",   .flag = TLV_OPT_FILE_SPLIT },
};

static int usage(void)
{
    os_println("%s [OPTION] tlv-path xdr-path sha-path", self);
    os_println(__tab "OPTION:");
    os_println(__tab "--dump: dump all");

    return -1;
}

static int xdr_handle(inotify_ev_t *ev, char *path[PATH_END])
{
    char tlv[1+OS_FILENAME_LEN] = {0};
    char xdr[1+OS_FILENAME_LEN] = {0};
    xpair_t pair = XPAIR_INITER(tlv, xdr, path[PATH_SHA]);

    os_saprintf(tlv, "%s/%s", path[PATH_TLV], ev->name);
    os_saprintf(xdr, "%s/%s", path[PATH_XDR], ev->name);
    
    int err = tlv_to_xdr(&pair);
    if (err<0) {
        // log
    }

    return 0;
}

static int remove_handle(inotify_ev_t *ev, char *path[PATH_END])
{
    char tlv[1+OS_FILENAME_LEN] = {0};

    os_saprintf(tlv, "%s/%s", path[PATH_TLV], ev->name);

    remove(tlv);

    return 0;
}

static int handle(inotify_ev_t *ev, char *path[PATH_END])
{
    if (ISXDR(ev)) {
        return xdr_handle(ev, path);
    } else {
        return remove_handle(ev, path);
    }
}

static int run(char *path[PATH_END])
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

        inotify_ev_t *ev    = (inotify_ev_t *)EVBUF;
        inotify_ev_t *end   = (inotify_ev_t *)(EVBUF + len);

        for (; ev<end; ev=EVNEXT(ev)) {
            if (ev->mask & EVMASK) {
                err = handle(ev, path);
                if (err<0) {
                    return err;
                }
            }
        }
    }
}

int main(int argc, char *argv[])
{
    self = argv[0];

    argc--; argv++;
    while(1) {
        char *args = argv[0];

        if (false==is_option_args(args)) {
            break;
        }
        
        if (0==strcmp("--help", args)) {
            return usage();
        }
        
        int i;
        for (i=0; i<os_count_of(opt); i++) {
            if (0==strcmp(opt[i].name, args)) {
                tlv_opt_set(opt[i].flag);
            }
        }
        
        argc--; argv++;
    }

    if (3 != argc) {
        return usage();
    }

    return run(argv);
}

/******************************************************************************/
