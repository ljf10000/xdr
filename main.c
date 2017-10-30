#include "xdr.h"

DECLARE_TLV_VARS;
/******************************************************************************/
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

#define EVENTS      (IN_CLOSE_WRITE|IN_MOVED_TO)
#define EVENTSIZE   (sizeof(struct inotify_event) + NAME_MAX + 1)
#define EVENTCOUNT  1024

static char evbuf[EVENTCOUNT*EVENTSIZE];

int handle(char *tlv_path, char *xdr_path, char *sha_path)
{
    struct inotify_event *ev;
    char *p;
    int fd, err, len;

    fd = inotify_init1(IN_CLOEXEC);
    if (fd<0) {
        return -errno;
    }
    
    err = inotify_add_watch(fd, tlv_path, EVENTS);
    if (err<0) {
        return -errno;
    }

    for (;;) {
        len = read(fd, evbuf, sizeof(evbuf));
        if (len == -1 && errno != EAGAIN) {
            return -errno;
        }

        for (p=evbuf; p<evbuf+len; p+=sizeof(struct inotify_event) + ev->len) {
            ev = (struct inotify_event *)p;

            if (ev->mask & EVENTS) {
                char tlv[1+OS_FILENAME_LEN] = {0};
                char xdr[1+OS_FILENAME_LEN] = {0};
                xpair_t pair = XPAIR_INITER(tlv, xdr, sha_path);

                os_saprintf(tlv, "%s/%s", tlv_path, ev->name);
                os_saprintf(xdr, "%s/%s", xdr_path, ev->name);
                
                err = tlv_to_xdr(&pair);
                if (err<0) {
                    // log
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

    return handle(argv[0], argv[1], argv[2]);
}

/******************************************************************************/
