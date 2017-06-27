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

    xtlv_dprint("parse %s ...", filename_tlv);

    //xtlv_dprint("read %s ...", filename_tlv);
    err = os_readfileall(filename_tlv, &buffer, &len);
    if (err<0) {
        return err;
    }
    //xtlv_dprint("read %s size:%d", filename_tlv, len);

    xblock_t block;

    //xtlv_dprint("init block ...");
    err = xblock_init(&block, buffer, len);
    if (err<0) {
        return err;
    }
    //xtlv_dprint("init block ok.");

    //xtlv_dprint("parse block ...");
    err = xblock_parse(&block);
    if (err<0) {
        return err;
    }
    //xtlv_dprint("parse block ok.");

    xblock_release(&block);
    os_free(buffer);
    
    xtlv_dprint("parse %s ok.", filename_tlv);
    
    return 0;
}

/******************************************************************************/
