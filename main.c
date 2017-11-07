#include "xdr.h"

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE              INOTIFY_EVSIZE
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_file, _len)  os_str_has_suffix(_file, _len, "." XDR_SUFFIX, sizeof("." XDR_SUFFIX)-1)

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
    { .flag = OPT_CLI,          .name = "--cli",        .help = "cli mode. must support env: ENV_TLV_FILE"},
    { .flag = OPT_IP6,          .name = "--ip6",        .help = "ipv6[not support now]"},
    { .flag = OPT_STRICT,       .name = "--strict",     .help = "strict check"},
    { .flag = OPT_DUMP,         .name = "--dump",       .help = "dump all"},
    { .flag = OPT_DUMP_SIMPLE,  .name = "--dump-simple",.help = "dump with simple format"},
    { .flag = OPT_DUMP_PRE,     .name = "--dump-pre",   .help = "dump pre check"},
    { .flag = OPT_SPLIT,        .name = "--file-split", .help = "dpi file split from xdr"},
};

static int
usage(void)
{
    os_println("%s [OPTION] tlv-path xdr-path sha-path", self);

    return nameflag_usage(opt);
}

static xpath_t Path[PATH_END];

static void
init_xpath(xpath_t path[PATH_END], char *dir[PATH_END])
{
    int i;

    for (i=0; i<PATH_END; i++) {
        xpath_init(&path[i], dir[i]);
    }
}

static int
xdr_handle(xpath_t path[], char *filename, int namelen)
{
    struct xparse parse = XPARSE_INITER(path, filename, namelen);
    int err;
    
    xp_init(&parse);

    err = xp_open(&parse);
    if (err<0) {
        goto ERROR;
    }

    err = xp_run(&parse);
    if (err<0) {
        goto ERROR;
    }

ERROR:
    tlv_dprint("xdr_handle xp_close");
    xp_close(&parse);

    return err;
}

static int
tlv_remove(xpath_t path[], char *filename, int namelen)
{
    char *fullname = xpath_fill(&path[PATH_TLV], filename, namelen);
    
    remove(fullname);
    
    xdr_dprint("remove %s", fullname);
    
    return 0;
}

static int
monitor(const char *watch, xpath_t path[])
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
                len = inotify_ev_len(ev);
                ev_debug(ev);

                if (ISXDR(ev->name, len)) {
                    err = xdr_handle(path, ev->name, len);
                    if (err<0) {
                        // log
                    }
                } else {
                    tlv_remove(path, ev->name, len);
                }
            }
        }
    }
}

#ifndef ENV_TLV_FILE
#define ENV_TLV_FILE    "TLV_FILE"
#endif

static int
cli(xpath_t path[])
{
    char *filename = env_gets(ENV_TLV_FILE, NULL);
    if (NULL==filename) {
        os_println("not found env ENV_TLV_FILE");

        return -EBADENV;
    }
    
    return xdr_handle(path, filename, strlen(filename));
}

static int
check(int argc, char *argv[])
{
    int i;

    if (PATH_END != argc) {
        return -1;
    }

    for (i=0; i<PATH_END; i++) {
        if (false==os_fisdir(argv[i])) {
            return -1;
        }
    }

    return 0;
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
            option_analysis(opt, args);
        }

        argc--; argv++;
    }

    if (0!=check(argc, argv)) {
        return usage();
    }
    
    init_xpath(Path, argv);

    if (is_option(OPT_CLI)) {
        return cli(Path);
    } else {
        return monitor(argv[PATH_TLV], Path);
    }
}

/******************************************************************************/
