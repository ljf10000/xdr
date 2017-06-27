#include "xdr.h"

DECLARE_XTLV_VARS;
/******************************************************************************/
char *self;

int usage(void)
{
    os_println("%s [OPTION] old-xdr-file new-xdr-file", self);
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
        } else if (0==strcmp("--dump", args)) {
            __xtlv_debug |= XDEBUG_DUMP;
        }

        argc--; argv++;
    }

    if (2 != argc) {
        return usage();
    }

    char *filename_tlv = argv[0];
    char *filename_xdr = argv[1];

    char *buffer = NULL;
    uint32 len = 0;
    int err;

    os_println("read %s ...", filename_tlv);
    err = os_readfileall(filename_tlv, &buffer, &len);
    if (err<0) {
        return err;
    }
    os_println("read %s ok.", filename_tlv);

    xblock_t block;

    os_println("init block ...");
    err = xblock_init(&block, buffer, len);
    if (err<0) {
        return err;
    }
    os_println("init block ok.");

    os_println("parse block ...");
    err = xblock_parse(&block);
    if (err<0) {
        return err;
    }
    os_println("parse block ok.");

    xblock_release(&block);
    os_free(buffer);
    
    return 0;
}

/******************************************************************************/
