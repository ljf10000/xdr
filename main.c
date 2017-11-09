#include "xdr.h"

DECLARE_OS_VARS;
DECLARE_TLV_VARS;
/******************************************************************************/
#ifndef ENV_XDR_FILE
#define ENV_XDR_FILE        "XDR_FILE"
#endif

#ifndef ENV_XDR_WORKER
#define ENV_XDR_WORKER      "XDR_WORKER"
#endif

#ifndef ENV_XDR_QUE
#define ENV_XDR_QUE         "XDR_QUE"
#endif

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVNEXT(_ev)         inotify_ev_next(_ev)
#define ISXDR(_file, _len)  os_str_has_suffix(_file, _len, "." XDR_SUFFIX, sizeof("." XDR_SUFFIX)-1)

static char *self;
static xpath_t WorkerPath[WORKER_COUNT][PATH_END];
static xst_t WorkerSt[WORKER_COUNT][XB_STCOUNT];

static xworker_t Worker;
static int WorkerCount = 1;
static int WrokerQueCount = 1;

static inline uint64
get_publisher(void)
{
    if (is_option(OPT_MULTI)) {
        uint64 id;
        
        while(INVALID_WORKER_ID==(id = xw_get_publisher(&Worker))) {
            usleep(XDR_USLEEP);
        }

        return id;
    } else {
        return 0;
    }
}

static inline int
put_publisher(uint64 id)
{
    if (is_option(OPT_MULTI)) {
        return xw_put_publisher(&Worker, id);
    } else {
        return 0;
    }
}

static inline uint64
get_consumer(int wid)
{
    if (is_option(OPT_MULTI)) {
        uint64 id;
        
        while(INVALID_WORKER_ID==(id = xw_get_consumer(&Worker, wid))) {
            usleep(XDR_USLEEP);
        }

        return id;
    } else {
        return 0;
    }
}

static inline xworker_que_t *
get_qentry(uint64 id)
{
    return xw_qentry(&Worker, id);
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
statistic(struct xparse *parse, int wid)
{
    if (is_option(OPT_DUMP_ST)) {
        os_printf(
            "worker:%d "
            "tlv %llu:%llu, "
            "xdr %llu:%llu, "
            "raw %llu:%llu, "
            "file %llu, "
            "ssls %llu, "
            "sslc %llu, "
            "request %llu, "
            "response %llu"
            __crlf, 
            wid,
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
#define WORK_ID wid
    struct xparse parse = XPARSE_INITER(wid, WorkerPath[wid], WorkerSt[wid], filename, namelen);
    int err;

    xp_init(&parse);

    err = tlv_trace(xp_open(&parse), "xp_open");
    if (err<0) {
        goto ERROR;
    }

    err = tlv_trace(xp_run(&parse), "xp_run");
    if (err<0) {
        goto ERROR;
    }

ERROR:
    tlv_trace(xp_close(&parse), "xp_close");
    if (err<0) {
        parse.st_raw->error++;
    } else {
        parse.st_raw->ok++;
    }
    statistic(&parse, wid);
    
    return err;
#undef WORK_ID
}

static int
tlv_remove(int wid, char *filename, int namelen)
{
    char *fullname = xpath_fill(&WorkerPath[wid][PATH_TLV], filename, namelen);
    
    remove(fullname);
    
    os_println("worker:%d remove %s", wid, fullname);
    
    return 0;
}

static int
ev_handle(int wid)
{
    uint64 id = get_consumer(wid);
    xworker_que_t *que = get_qentry(id);
    inotify_ev_t *ev  = (inotify_ev_t *)(que->buf);
    inotify_ev_t *end = (inotify_ev_t *)(que->buf + que->len);
    int len, err;

    for (; ev<end; ev=EVNEXT(ev)) {
        if (ev->mask & EVMASK) {
            if (is_option(OPT_TRACE_EV)) {
                ev_trace(ev);
            }

            len = inotify_ev_len(ev);
            if (ISXDR(ev->name, len)) {
                err = xdr_handle(wid, ev->name, len);
                if (err<0) {
                    // log
                }
            } else {
                tlv_remove(wid, ev->name, len);
            }
        }
    }

    return 0;
}


static void *
worker(void *args)
{
    int wid = (int)(uint32)(uint64)args;

    os_println("start worker:%d", wid);

    while(1) {
        ev_handle(wid);
    }
    
    return NULL;
}

static int
monitor(const char *watch)
{
    xworker_que_t *que;
    int fd, err;
    uint64 id;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        return -errno;
    }

    err = inotify_add_watch(fd, watch, EVMASK);
    if (err<0) {
        return -errno;
    }

    for (;;) {
        id = get_publisher();
        que = get_qentry(id);
        
        que->len = read(fd, que->buf, EVBUFSIZE);
        if (que->len == -1 && errno != EAGAIN) {
            os_println("master read error:%d", -errno);
            
            return -errno;
        }
        OS_VAR(time) = time(NULL);

        if (is_option(OPT_MULTI)) {
            err = put_publisher(id);
            if (err<0) {
                
            }
        } else {
            ev_handle(0);
        }
    }
}

static int
cli(void)
{
    char *filename = env_gets(ENV_XDR_FILE, NULL);
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

static void
init_xpath(int wid, char *path[PATH_END])
{
    int i;

    for (i=0; i<PATH_END; i++) {
        xpath_init(&WorkerPath[wid][i], path[i]);
    }
}

static int
init_worker(char *path[PATH_END])
{
    int i, err;

    Worker.qcount = WrokerQueCount;
    Worker.que = (xworker_que_t *)os_calloc(WrokerQueCount, sizeof(xworker_que_t));
    if (NULL==Worker.que) {
        return -ENOMEM;
    }

    for (i=0; i<WorkerCount; i++) {
        init_xpath(i, path);
        
        if (is_option(OPT_MULTI)) {
            pthread_t tid;
            
            err = pthread_mutex_init(&Worker.mutex, NULL);
            if (err<0) {
                return err;
            }
            
            err = pthread_create(&tid, NULL, worker, (void *)(uint64)i);
            if (err<0) {
                return err;
            }
        }
    }

    return 0;
}

static int 
xw_envi(char *env, int max)
{
    int v = env_geti(env, max);
    if (v<=0 || v>max) {
        v = max;
    }
    
    return v;
}

static void
init_env(void)
{
    if (is_option(OPT_MULTI)) {
        WorkerCount     = xw_envi(ENV_XDR_WORKER, WORKER_COUNT);
        WrokerQueCount= xw_envi(ENV_XDR_QUE,  QUE_COUNT);

        os_println("worker count %d",       WorkerCount);
        os_println("worker queue count %d", WrokerQueCount);
    }
}

static void
pre(void)
{
    if (is_option(OPT_CLI)) {
        // cli not multi-thread
        clr_option(OPT_MULTI);
    }
}

static int
init(char *path[PATH_END])
{
    int err;
    
    init_env();

    err = init_worker(path);
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

    pre();
    
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
