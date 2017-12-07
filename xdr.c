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

#ifndef ENV_XDR_SLEEP
#define ENV_XDR_SLEEP       "XDR_SLEEP"
#endif

#ifndef ENV_DUMP_TLV_STRING
#define ENV_DUMP_TLV_STRING "DUMP_TLV_STRING"
#endif

#ifndef ENV_DUMP_TLV_BINARY
#define ENV_DUMP_TLV_BINARY "DUMP_TLV_BINARY"
#endif

#define EVMASK              (IN_CLOSE_WRITE|IN_MOVED_TO)
#define ISXDR(_file, _len)  os_str_has_suffix(_file, _len, "." XDR_SUFFIX, sizeof("." XDR_SUFFIX)-1)

static char *self;

static xque_t   WorkerQue;
static int      WorkerSleep;
static int      WorkerCount = 1;
static int      WrokerQueCount = 1;

int DumpTlvString = -1;
int DumpTlvBinary = -1;

static struct {
    xpath_t path[PATH_END];
    xst_t   st[XST_END];
    FILE    *trace;
} Worker[WORKER_COUNT];

FILE *WorkerStream(int wid)
{
    return Worker[wid].trace;
}

xw_stream_t *xw_stream = WorkerStream;

static inline uint64
get_publisher(void)
{
    if (is_option(OPT_MULTI)) {
        uint64 id;
        
        while(INVALID_WORKER_ID==(id = xq_get_publisher(&WorkerQue))) {
            usleep(WorkerSleep);
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
        return xq_put_publisher(&WorkerQue, id);
    } else {
        return 0;
    }
}

static inline uint64
get_consumer(int wid)
{
    if (is_option(OPT_MULTI)) {
        uint64 id;
        
        while(INVALID_WORKER_ID==(id = xq_get_consumer(&WorkerQue, wid))) {
            usleep(WorkerSleep);
        }

        return id;
    } else {
        return 0;
    }
}

static inline xque_buffer_t *
get_qb(uint64 id)
{
    return xq_entry(&WorkerQue, id);
}

static nameflag_t opt[] = {
    { .flag = OPT_CLI,          .name = "--cli",        .help = "cli mode[must supply env " ENV_XDR_FILE "]"},
    { .flag = OPT_IP6,          .name = "--ip6",        .help = "ipv6[not support now]"},
    { .flag = OPT_STRICT,       .name = "--strict",     .help = "strict check"},
    { .flag = OPT_MULTI,        .name = "--multi",      .help = "multi thread"},
    { .flag = OPT_DUMP,         .name = "--dump",       .help = "dump all"},
    { .flag = OPT_DUMP_PRE,     .name = "--dump-pre",   .help = "dump before check"},
    { .flag = OPT_DUMP_ST,      .name = "--dump-st",    .help = "dump statistic"},
    { .flag = OPT_DUMP_EV,      .name = "--dump-ev",    .help = "dump inotify event"},
    { .flag = OPT_DUMP_QUE,     .name = "--dump-que",   .help = "dump queue"},
    { .flag = OPT_DUMP_ERR,     .name = "--dump-error", .help = "dump error"},
    { .flag = OPT_DUMP_INIT,    .name = "--dump-init",  .help = "dump init"},
    { .flag = OPT_TRACE_TLV,    .name = "--trace-tlv",  .help = "trace tlv parse"},
    { .flag = OPT_TRACE_XDR,    .name = "--trace-xdr",  .help = "trace xdr parse"},
#if 0
    { .flag = OPT_DUMP_SB,      .name = "--dump-sb",    .help = "dump short binary"},
    { .flag = OPT_SPLIT,        .name = "--file-split", .help = "dpi file split from xdr"},
#endif
};

static inline void
ev_dump(inotify_ev_t *ev)
{
    if (ev->mask & IN_CLOSE_WRITE) {
        option_dump(OPT_DUMP_EV, "event close write file:%s", ev->name);
    }

    if (ev->mask & IN_MOVED_TO) {
        option_dump(OPT_DUMP_EV, "event move to file:%s", ev->name);
    }
}

static int
usage(void)
{
    int err;
    
    os_println("[ENV] %s [OPTION] tlv-path xdr-path sha-path bad-path", self);
    err = nameflag_usage(opt);
    
    os_println(__tab "ENV:");
    os_println(__tab2 ENV_XDR_SLEEP  "=" SYMBOL_TO_STRING(XDR_USLEEP)   ", just for multi thread mode");
    os_println(__tab2 ENV_XDR_QUE    "=" SYMBOL_TO_STRING(WORKER_COUNT) ", just for multi thread mode");
    os_println(__tab2 ENV_XDR_WORKER "=" SYMBOL_TO_STRING(QUE_COUNT)    ", just for multi thread mode");

    return err;
}

static void
statistic(struct xparse *parse, int wid)
{
    if (is_option(OPT_DUMP_ST)) {
        xst_t *st = parse->st;
        int i;
        
        os_printf("worker:%d", wid);
        for (i=0; i<XST_END; i++) {
            os_printf(" %s %"PRIu64":%"PRIu64, 
                xst_getnamebyid(i), st[i].ok, st[i].error);
        }
        os_printf(__crlf __crlf);
    }
}

static int
xdr_handle(int wid, char *filename, int namelen)
{
    struct xparse parse = XPARSE_INITER(wid, Worker[wid].path, Worker[wid].st, filename, namelen);
    int err;

    xdr_dprint(wid, "xdr_handle ...");
    
    xp_init(&parse);

    err = tlv_trace(xp_open(&parse), wid, "xp_open");
    if (err<0) {
        goto ERROR;
    }

    err = xdr_trace(xp_parse(&parse), wid, "xp_parse");
    if (err<0) {
        goto ERROR;
    }

ERROR:
    tlv_trace(xp_close(&parse), wid, "xp_close");
    xp_st_by(err, &parse, XST_raw);
    statistic(&parse, wid);

    xdr_dprint(wid, "xdr_handle ok.");
    
    return err;
}

static int
tlv_remove(int wid, char *filename, int namelen)
{
    char *fullname = xpath_fill(&Worker[wid].path[PATH_TLV], filename, namelen);
    
    remove(fullname);
    
    option_dump(OPT_DUMP_EV, "worker:%d remove %s", wid, fullname);
    
    return 0;
}

static int
ev_handle(int wid)
{
    uint64 id = get_consumer(wid);
    xque_buffer_t *qb = get_qb(id);
    inotify_ev_t *ev  = xp_ev_first(qb);
    inotify_ev_t *end = xq_ev_end(qb);
    int len, err, count = 0;

    for (; ev<end; ev=inotify_ev_next(ev), count++) {
        if (ev->mask & EVMASK) {
            // ev_dump(ev);

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

    option_dump_init("start worker:%d", wid);

    while(1) {
        ev_handle(wid);
    }
    
    return NULL;
}

static int
monitor(const char *watch)
{
    xque_buffer_t *qb;
    int fd, err;
    uint64 id;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        option_dump_error("create inotify error:%d", -errno);
        
        return -errno;
    }

    err = inotify_add_watch(fd, watch, EVMASK);
    if (err<0) {
        option_dump_error("inotify watch %s error:%d", watch, -errno);
        
        return -errno;
    }

    for (;;) {
        id = get_publisher();
        qb = get_qb(id);
        
        qb->len = read(fd, qb->buf, EVBUFSIZE);
        if (qb->len == -1 && errno != EAGAIN) {
            option_dump_error("inotify read error:%d", -errno);
            
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
        option_dump_error("not found env TLV_FILE");

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
        xpath_init(&Worker[wid].path[i], path[i]);
    }
}

static int
init_trace(int wid)
{
    if (is_option(OPT_TRACE_TLV) || is_option(OPT_TRACE_XDR)) {
        char filename[1+OS_FILENAME_LEN] = {0};

        os_sprintf(filename, "worker%d.log", wid);

        Worker[wid].trace = fopen(filename, "w+");
        if (NULL==Worker[wid].trace) {
            option_dump_error("open trace file %s error", filename);
            
            return -EBADF;
        }
    }
    
    return 0;
}

static int
init_multi(int wid)
{
    int err;
        
    if (is_option(OPT_MULTI)) {
        pthread_t tid;

        err = pthread_mutex_init(&WorkerQue.mutex, NULL);
        if (err<0) {
            return err;
        }
        
        err = pthread_create(&tid, NULL, worker, (void *)(uint64)wid);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

static int
init_worker(char *path[PATH_END])
{
    int i, err;

    WorkerQue.qcount = WrokerQueCount;
    WorkerQue.qb = (xque_buffer_t *)os_calloc(WrokerQueCount, sizeof(xque_buffer_t));
    if (NULL==WorkerQue.qb) {
        return -ENOMEM;
    }

    for (i=0; i<WorkerCount; i++) {
        init_xpath(i, path);

        err = init_trace(i);
        if (err<0) {
            return err;
        }

        err = init_multi(i);
        if (err<0) {
            return err;
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
    DumpTlvString = env_geti(ENV_DUMP_TLV_STRING, -1);
    DumpTlvBinary = env_geti(ENV_DUMP_TLV_BINARY, -1);
    
    if (is_option(OPT_MULTI)) {
        WorkerSleep     = xw_envi(ENV_XDR_SLEEP,    XDR_USLEEP);
        WorkerCount     = xw_envi(ENV_XDR_WORKER,   WORKER_COUNT);
        WrokerQueCount  = xw_envi(ENV_XDR_QUE,      QUE_COUNT);
        
        option_dump_init("worker sleep %d",       WorkerSleep);
        option_dump_init("worker count %d",       WorkerCount);
        option_dump_init("worker queue count %d", WrokerQueCount);
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
