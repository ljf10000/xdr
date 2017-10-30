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

    char *tlv_path = argv[0];
    char *xdr_path = argv[1];
    char *sha_path = argv[2];

    mv_t handle(const char *path, const char *file)
    {
        char tlv[1+OS_FILENAME_LEN] = {0};
        char xdr[1+OS_FILENAME_LEN] = {0};
        
        os_snprintf(tlv, OS_FILENAME_LEN, "%s/%s", tlv_path, file);
        os_snprintf(xdr, OS_FILENAME_LEN, "%s/%s", xdr_path, file);
        
        xpair_t pair = XPAIR_INITER(tlv, xdr, sha_path);

        int err = tlv_to_xdr(&pair);
        if (err<0) {
            return mv2_go(err);
        }

        return mv2_ok;
    }
    
    return os_fscan_dir(tlv_path, false, NULL, handle);
}

/******************************************************************************/
