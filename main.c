#include "xdr.h"

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef ENV_TLV_FILE
#define ENV_TLV_FILE        "TLV_FILE"
#endif

#ifndef ENV_WORKER
#define ENV_WORKER          "WORKER"
#endif

#ifndef ENV_CACHE
#define ENV_CACHE           "CACHE"
#endif

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_file, _len)  os_str_has_suffix(_file, _len, "." XDR_SUFFIX, sizeof("." XDR_SUFFIX)-1)

static char *self;
static xpath_t Path[PATH_END];

static xworker_t *Worker;
static int WorkerID;
static int WorkerCount = 1;
static int WorkerCacheCount = 1;

static inline xworker_t *
xw_worker(int wid)
{
    return &Worker[wid];
}

static int
__xw_wait_publisher(xworker_t **publisher)
{
    xworker_t *w;
    int id;
    
    while(1) {
        for (; WorkerID<WorkerCount; WorkerID++) {
            w = xw_worker(WorkerID);

            id = xw_get_publisher(w);
            if (id>=0) {
                *publisher = w;

                return id;
            }
        }

        WorkerID = 0;

        usleep(1000);
    }
}

static int
xw_wait_publisher(xworker_t **publisher)
{
    if (is_option(OPT_MULTI)) {
        return __xw_wait_publisher(publisher);
    } 
    else {
        *publisher = xw_worker(0);
        
        return 0;
    }
}

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
            parse->worker->wid,
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
    struct xparse parse = XPARSE_INITER(xw_worker(wid), Path, filename, namelen);
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

static int
ev_handle(xworker_t *w)
{
    int id = xw_get_consumer(w);
    xworker_cache_t *cache = xw_cache(w, id);
    inotify_ev_t *ev  = (inotify_ev_t *)(cache->buf);
    inotify_ev_t *end = (inotify_ev_t *)(cache->buf + cache->len);
    int len, err;
    
    for (; ev<end; ev=EVNEXT(ev)) {
        if (ev->mask & EVMASK) {
            if (is_option(OPT_TRACE_EV)) {
                ev_trace(ev);
            }

            len = inotify_ev_len(ev);
            if (ISXDR(ev->name, len)) {
                err = xdr_handle(w->wid, ev->name, len);
                if (err<0) {
                    // log
                }
            } else {
                tlv_remove(w->wid, ev->name, len);
            }
        }
    }

    return 0;
}


static void *
worker(void *args)
{
    int wid = (int)(uint32)(uint64)args;
    xworker_t *w = xw_worker(wid);

    while(1) {
        ev_handle(w);
    }
    
    return NULL;
}

static int
monitor(const char *watch)
{
    xworker_t *w;
    xworker_cache_t *cache;
    int fd, err, id;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        return -errno;
    }

    err = inotify_add_watch(fd, watch, EVMASK);
    if (err<0) {
        return -errno;
    }

    for (;;) {
        id = xw_wait_publisher(&w);
        cache = xw_cache(w, id);
        
        cache->len = read(fd, cache->buf, EVBUFSIZE);
        if (cache->len == -1 && errno != EAGAIN) {
            return -errno;
        }
        OS_VAR(time) = time(NULL);

        if (is_option(OPT_MULTI)) {
            xw_put_publisher(w, id);
        } else {
            ev_handle(w);
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
init_worker(int wid)
{
    xworker_t *w = xw_worker(wid);
    int err;

    w->wid = wid;
    w->cache_count = WorkerCacheCount;
    w->cache = (xworker_cache_t *)os_calloc(WorkerCacheCount, sizeof(xworker_cache_t));
    if (NULL==w->cache) {
        return -ENOMEM;
    }
    
    if (is_option(OPT_MULTI)) {
        err = pthread_mutex_init(&w->mutex, NULL);
        if (err<0) {
            return err;
        }
        
        err = pthread_create(&w->tid, NULL, worker, (void *)(uint64)wid);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

static int
init_workers(void)
{
    int i, err;

    Worker = (xworker_t *)os_calloc(WorkerCount, sizeof(*Worker));
    if (NULL==Worker) {
        return -ENOMEM;
    }
    
    for (i=0; i<WorkerCount; i++) {
        err = init_worker(i);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

static int 
xw_envi(char *env, int deft)
{
    int v = env_geti(env, deft);
    if (v<=0 || v>deft) {
        v = deft;
    }

    return v;
}

static void
init_env(void)
{
    WorkerCount     = xw_envi(ENV_WORKER, WORKER_COUNT);
    WorkerCacheCount= xw_envi(ENV_CACHE,  CACHE_COUNT);
}

static int
init(char *path[PATH_END])
{
    int err;
    
    init_xpath(path);

    if (is_option(OPT_CLI)) {
        // cli not multi-thread
        clr_option(OPT_MULTI);
    }
    
    if (is_option(OPT_MULTI)) {
        init_env();
    }

    err = init_workers();
    if (err<0) {
        return err;
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
