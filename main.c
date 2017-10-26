#include "xdr.h"

DECLARE_XTLV_VARS;
/******************************************************************************/
static char *self;

static struct {
    char *name;
    uint32 flag;
} opt[] = {
    { .name = "--dump",         .flag = XTLV_OPT_DUMP },
    { .name = "--file-split",   .flag = XTLV_OPT_FILE_SPLIT },
};

static int usage(void)
{
    os_println("%s [OPTION] input-file prefix", self);
    os_println(__tab "OPTION:");
    os_println(__tab "--dump: dump all");

    return -1;
}

int main(int argc, char *argv[])
{
    int err = 0;
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
                xtlv_opt_set(opt[i].flag);
            }
        }
        
        argc--; argv++;
    }

    if (2 != argc) {
        return usage();
    }

    char *input     = argv[0];
    char *prefix    = argv[1];

    char *buffer = NULL;
    uint32 len = 0;

    err = os_readfileall(input, &buffer, &len);
    if (err<0) {
        goto ERROR;
    }
    xtlv_dprint("read %s size:%d", input, len);

    int count = xtlv_count(buffer, len);
    if (count<0) {
        err = count; goto ERROR;
    }
    
    err = xtlv_foreach((xtlv_t *)buffer, count, xtlv_parse, NULL);

ERROR:
    os_free(buffer);
    return err;
}

/******************************************************************************/
