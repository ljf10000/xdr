#include "xdr.h"
#include <pthread.h>

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef ENV_TLV_FILE
#define ENV_TLV_FILE        "TLV_FILE"
#endif

#ifndef ENV_WORKER
#define ENV_WORKER          "WORKER"
#endif

#ifndef WORKER_COUNT
#define WORKER_COUNT        8
#endif

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVCOUNT             128
#define EVSIZE              INOTIFY_EVSIZE
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_file, _len)  os_str_has_suffix(_file, _len, "." XDR_SUFFIX, sizeof("." XDR_SUFFIX)-1)

static char *self;

static xpath_t Path[PATH_END];
static xst_t St[WORKER_COUNT][XB_STCOUNT];

static int Fd[WORKER_COUNT];
static int FdCount;
static int FdWorker;

static nameflag_t opt[] = {
    { .flag = OPT_CLI,          .name = "--cli",        .help = "cli mode"},
    { .flag = OPT_IP6,          .name = "--ip6",        .help = "ipv6[not support now]"},
    { .flag = OPT_STRICT,       .name = "--strict",     .help = "strict check"},
    { .flag = OPT_DUMP,         .name = "--dump",       .help = "dump all"},
    { .flag = OPT_DUMP_SB,      .name = "--dump-sb",    .help = "dump short binary"},
    { .flag = OPT_DUMP_PRE,     .name = "--dump-pre",   .help = "dump before check"},
    { .flag = OPT_DUMP_ST,      .name = "--dump-st",    .help = "dump statistic"},
    { .flag = OPT_SPLIT,        .name = "--file-split", .help = "dpi file split from xdr"},
#if D_tlv_trace
    { .flag = OPT_TRACE_TLV,    .name = "--trace-tlv",  .help = "trace tlv parse"},
#endif
#if D_xdr_trace
    { .flag = OPT_TRACE_XDR,    .name = "--trace-xdr",  .help = "trace xdr parse"},
#endif
    { .flag = OPT_TRACE_EV,     .name = "--trace-ev",   .help = "trace inotify event"},
    { .flag = OPT_MULTI,        .name = "--multi",      .help = "multi thread"},
};

static inline void
ev_trace(inotify_ev_t *ev)
{
    if (ev->mask & IN_CLOSE_WRITE) {
        os_println("event close write file:%s", ev->name);
    }

    if (ev->mask & IN_MOVED_TO) {
        os_println("event move to file:%s", ev->name);
    }
}

static int
usage(void)
{
    os_println("%s [OPTION] tlv-path xdr-path sha-path", self);

    return nameflag_usage(opt);
}

static void
statistic(struct xparse *parse)
{
    if (is_option(OPT_DUMP_ST)) {
        os_printf(
            "worker[%d] "
            "tlv %llu:%llu, "
            "xdr %llu:%llu, "
            "raw %llu:%llu, "
            "file %llu, "
            "ssls %llu, "
            "sslc %llu, "
            "request %llu, "
            "response %llu"
            __crlf, 
            parse->wid,
            parse->st_tlv->ok, parse->st_tlv->error,
            parse->st_xdr->ok, parse->st_xdr->error,
            parse->st_raw->ok, parse->st_raw->error,
            parse->st_file_content->ok,
            parse->st_ssl_server->ok,
            parse->st_ssl_client->ok,
            parse->st_http_request->ok,
            parse->st_http_response->ok);
    }
}

static int
xdr_handle(int wid, char *filename, int namelen)
{
    struct xparse parse = XPARSE_INITER(Path, St[wid], filename, namelen, wid);
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
    xp_close(&parse);
    if (err<0) {
        parse.st_raw->error++;
    } else {
        parse.st_raw->ok++;
    }
    statistic(&parse);
    
    return err;
}

static int
tlv_remove(int wid, char *filename, int namelen)
{
    char *fullname = xpath_fill(&Path[PATH_TLV], filename, namelen);
    
    remove(fullname);
    
    xdr_dprint("worker[%d] remove %s", wid, fullname);
    
    return 0;
}

static int (*handle)(inotify_ev_t *ev);

static int
common(int wid, char *filename, int namelen)
{
    if (ISXDR(filename, namelen)) {
        int err = xdr_handle(wid, filename, namelen);
        if (err<0) {
            // log
        }
    } else {
        tlv_remove(wid, filename, namelen);
    }

    return 0;
}

static void *
worker(void *args)
{
    int err, len, wid = (int)(uint32)(uint64)args;
    uint64 data;
    char *filename;

    os_println("worker[%d] start", wid);
    
    while(1) {
        len = read(Fd[wid], &data, sizeof(data));
        if (len == sizeof(data)) {
            filename = (char *)data;

            os_println("worker[%d] recv data:%llu:%s", wid, data, filename);
            
            common(wid, filename, strlen(filename));
            free(filename);
        } else {
            os_println("worker[%d] recv error:%d", wid, -errno);
        }
    }
    
    return NULL;
}

static int
single(inotify_ev_t *ev)
{
    int len = inotify_ev_len(ev);

    return common(0, ev->name, len);
}

static int
multi(inotify_ev_t *ev)
{
    char *filename = strdup(ev->name);
    if (NULL==filename) {
        os_println("notify worker[%d] NOMEM", FdWorker);

        return -ENOMEM;
    }
    
    uint64 data = (uint64)filename;

    int len = write(Fd[FdWorker], &data, sizeof(data));
    if (len != sizeof(data)) {
        int err = -errno;
        
        os_println("notify worker[%d] data:%llu:%s error:%d", FdWorker, data, filename, err);

        return err;
    } else {
        os_println("notify worker[%d] data:%llu:%s ok", FdWorker, data, filename);
    }
    
    FdWorker = (FdWorker+1)%FdCount;

    return 0;
}

static int
monitor(const char *watch)
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
                if (is_option(OPT_TRACE_EV)) {
                    ev_trace(ev);
                }

                (*handle)(ev);
            }
        }
    }
}

static int
cli(void)
{
    char *filename = env_gets(ENV_TLV_FILE, NULL);
    if (NULL==filename) {
        os_println("not found env TLV_FILE");

        return -EBADENV;
    }
    
    return xdr_handle(0, filename, strlen(filename));
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

static int
init_xpath(char *path[PATH_END])
{
    int i;

    for (i=0; i<PATH_END; i++) {
        xpath_init(&Path[i], path[i]);
    }

    return 0;
}

static int
init_multi(void)
{
    int i, fd, err;

    FdCount = env_geti(ENV_WORKER, 0);
    if (FdCount<=0 || FdCount>WORKER_COUNT) {
        FdCount = WORKER_COUNT;
    }

    for (i=0; i<FdCount; i++) {
        pthread_t tid;
        
        fd = eventfd(0, EFD_CLOEXEC);
        if (fd<0) {
            return -errno;
        }
        Fd[i] = fd;
        
        err = pthread_create(&tid, NULL, worker, (void *)(uint64)i);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

static int
init(char *path[PATH_END])
{
    int err;
    
    init_xpath(path);

    if (is_option(OPT_MULTI)) {
        err = init_multi();
        if (err<0) {
            return err;
        }
        
        handle = multi;
    } else {
        handle = single;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int err;
    
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
    
    err = init(argv);
    if (err<0) {
        return err;
    }
    
    if (is_option(OPT_CLI)) {
        return cli();
    } else {
        return monitor(argv[PATH_TLV]);
    }
}

/******************************************************************************/
