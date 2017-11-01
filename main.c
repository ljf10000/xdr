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

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE              INOTIFY_EVSIZE
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_ev)          OS_HAS_SUFFIX((_ev)->name, inotify_ev_len(_ev), XDR_SUFFIX, sizeof(XDR_SUFFIX)-1)

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

static int usage(void)
{
    os_println("%s [OPTION] tlv-path xdr-path sha-path", self);
    os_println(__tab "OPTION:");
    os_println(__tab "--dump: dump all");

    return -1;
}

static struct {
    char *name;
    uint32 flag;
    int (*handle)(char *args);
} opt[] = {
    { .name = "--cli",          .flag = TLV_OPT_CLI },
    { .name = "--dump",         .flag = TLV_OPT_DUMP },
    { .name = "--dump-simple",  .flag = TLV_OPT_DUMP_SIMPLE },
    { .name = "--file-split",   .flag = TLV_OPT_SPLIT },
};

static void
opt_analysis(char *args)
{
    int i;
    
    for (i=0; i<os_count_of(opt); i++) {
        if (0==strcmp(opt[i].name, args)) {
            tlv_opt_set(opt[i].flag);

            return;
        }
    }
}

static int xdr_handle(inotify_ev_t *ev, char *path[PATH_END])
{
    char tlv[1+OS_FILENAME_LEN] = {0};
    char xdr[1+OS_FILENAME_LEN] = {0};
    xpair_t pair = XPAIR_INITER(tlv, xdr, path[PATH_SHA]);

    os_saprintf(tlv, "%s/%s", path[PATH_TLV], ev->name);
    os_saprintf(xdr, "%s/%s", path[PATH_XDR], ev->name);

    xdr_dprint("handle tlv:%s", tlv);
    xdr_dprint("handle xdr:%s", xdr);
    
    int err = tlv_to_xdr(&pair);
    if (err<0) {
        // log
    }

    return 0;
}

static int remove_handle(inotify_ev_t *ev, char *path[PATH_END])
{
    char filename[1+OS_FILENAME_LEN] = {0};

    os_saprintf(filename, "%s/%s", path[PATH_TLV], ev->name);

    remove(filename);
    
    xdr_dprint("remove %s", filename);
    
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

static int cli(char *path[PATH_END])
{
    xpair_t pair = XPAIR_INITER(path[PATH_TLV], path[PATH_XDR], path[PATH_SHA]);

    return tlv_to_xdr(&pair);
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
        } else {
            opt_analysis(args);
        }

        argc--; argv++;
    }

    if (3 != argc) {
        return usage();
    }

    xdr_dprint("argv[0]=%s", argv[0]);
    xdr_dprint("argv[1]=%s", argv[1]);
    xdr_dprint("argv[2]=%s", argv[2]);
    
    if (is_tlv_opt(TLV_OPT_CLI)) {
        return cli(argv);
    } else {
        return monitor(argv);
    }
}

/******************************************************************************/
