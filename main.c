#include "xdr.h"

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef XDR_SUFFIX
#define XDR_SUFFIX      ".xdr"
#endif

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE              INOTIFY_EVSIZE
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_ev, _len)    OS_HAS_SUFFIX((_ev)->name, _len, XDR_SUFFIX, sizeof(XDR_SUFFIX)-1)

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
    { .flag = OPT_CLI,          .name = "--cli",        .help = "cli mode"},
    { .flag = OPT_IP6,          .name = "--ip6",        .help = "ipv6[not support now]"},
    { .flag = OPT_DUMP,         .name = "--dump",       .help = "dump all"},
    { .flag = OPT_STRICT,       .name = "--strict",     .help = "strict check"},
    { .flag = OPT_DUMP_SIMPLE,  .name = "--dump-simple",.help = "dump with simple format"},
    { .flag = OPT_SPLIT,        .name = "--file-split", .help = "dpi file split from xdr"},
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

static xpath_t Path[PATH_END];

static void path_init(xpath_t xpath[PATH_END], char *path[PATH_END])
{
    int i;

    for (i=0; i<PATH_END; i++) {
        xpath_init(&xpath[i], path[i]);
    }
}

static int xdr_handle(char *file, int namelen, xpath_t xpath[])
{
    xpair_t pair = XPAIR_INITER(file, namelen, xpath);

    xpath_fill(&xpath[PATH_TLV], file, namelen);
    xpath_fill(&xpath[PATH_XDR], file, namelen);
    
    int err = tlv_to_xdr(&pair);
    if (err<0) {
        // log
    }

    return 0;
}

static int tlv_remove(char *file, int namelen, xpath_t xpath[])
{
    char *filename = xpath_fill(&xpath[PATH_TLV], file, namelen);
    
    remove(filename);
    
    xdr_dprint("remove %s", filename);
    
    return 0;
}

static int handler(inotify_ev_t *ev, xpath_t xpath[])
{
    int namelen = inotify_ev_len(ev);
    
    if (ISXDR(ev, namelen)) {
        return xdr_handle(ev->name, namelen, xpath);
    } else {
        return tlv_remove(ev->name, namelen, xpath);
    }
}

static int monitor(char *watch, xpath_t xpath[])
{
    static char EV_BUFFER[EVCOUNT * INOTIFY_EVSIZE];
    int fd, len, err;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        return -errno;
    }

    err = inotify_add_watch(fd, watch, EVMASK);
    if (err<0) {
        return -errno;
    }

    for (;;) {
        len = read(fd, EV_BUFFER, sizeof(EV_BUFFER));
        if (len == -1 && errno != EAGAIN) {
            return -errno;
        }
        OS_VAR(time) = time(NULL);

        inotify_ev_t *ev    = (inotify_ev_t *)EV_BUFFER;
        inotify_ev_t *end   = (inotify_ev_t *)(EV_BUFFER + len);
        
        for (; ev<end; ev=EVNEXT(ev)) {
            if (ev->mask & EVMASK) {
                // ev_debug(ev);
                
                err = handler(ev, xpath);
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

static int cli(xpath_t xpath[])
{
    char *file = env_gets(ENV_TLV_FILE, NULL);
    if (NULL==file) {
        os_println("not found env ENV_TLV_FILE");
    }
    
    return xdr_handle(file, strlen(file), xpath);
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
            option_analysis(opt, os_count_of(opt), args);
        }

        argc--; argv++;
    }

    if (PATH_END != argc) {
        return usage();
    }

    path_init(Path, argv);

    if (is_option(OPT_CLI)) {
        return cli(Path);
    } else {
        return monitor(argv[PATH_TLV], Path);
    }
}

/******************************************************************************/
