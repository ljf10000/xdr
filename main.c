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
    os_println("%s [OPTION] input-file prefix", self);
    os_println(__tab "OPTION:");
    os_println(__tab "--dump: dump all");

    return -1;
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

    if (2 != argc) {
        return usage();
    }

    xpair_t pair = XPAIR_INITER(argv[0], argv[1]);

    return tlv_to_xdr(&pair);
}

/******************************************************************************/
