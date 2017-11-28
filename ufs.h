#ifndef __UFS_H_554906612bb04a819c8d03c8785a5bbe__
#define __UFS_H_554906612bb04a819c8d03c8785a5bbe__
/******************************************************************************/
#ifndef UFS_VERSION
#define UFS_VERSION         0
#endif

#ifndef ENV_THIS_NODE
#define ENV_THIS_NODE       "THIS_NODE"
#endif

#ifndef ENV_UFS_HOME
#define ENV_UFS_HOME        "UFS_HOME"
#endif

#ifndef ENV_UFS_NODES
#define ENV_UFS_NODES       "UFS_NODES"
#endif

#ifndef ENV_UFS_DIRS
#define ENV_UFS_DIRS        "UFS_DIRS"
#endif

#ifndef ENV_UFS_LIVE
#define ENV_UFS_LIVE        "UFS_LIVE"
#endif

#ifndef ENV_UFS_PORT
#define ENV_UFS_PORT        "UFS_PORT"
#endif

#ifndef ENV_UFS_REPLICATION
#define ENV_UFS_REPLICATION "UFS_REPLICATION"
#endif

#ifndef ENV_UFS_DBFILENAME
#define ENV_UFS_DBFILENAME  "UFS_DBFILENAME"
#endif

#ifndef DEFT_UFS_HOME
#define DEFT_UFS_HOME           "."
#endif

#ifndef DEFT_UFS_LIVE
#define DEFT_UFS_LIVE           7776000 // 3600*24*30*3
#endif

#ifndef DEFT_UFS_PORT
#define DEFT_UFS_PORT           8290
#endif

#ifndef DEFT_UFS_REPLICATION
#define DEFT_UFS_REPLICATION    2
#endif

#ifndef DEFT_UFS_DBFILENAME
#define DEFT_UFS_DBFILENAME     "udfs.db"
#endif

#if 1
#define UFS_CMD_MAPPER(_)   \
    _(UFS_CMD, push,    0)  \
    _(UFS_CMD, touch,   1)  \
    _(UFS_CMD, pull,    2)  \
    _(UFS_CMD, del,     3)  \
    /* end */
DECLARE_ENUM(UFS_CMD, ufs_cmd, UFS_CMD_MAPPER, UFS_CMD_END);

#define UFS_CMD_push        UFS_CMD_push
#define UFS_CMD_touch       UFS_CMD_touch
#define UFS_CMD_pull        UFS_CMD_pull
#define UFS_CMD_del         UFS_CMD_del
#define UFS_CMD_END         UFS_CMD_END

static inline bool is_good_ufs_cmd(int id);
static inline char *ufs_cmd_getnamebyid(int id);
#endif

enum {
    UFS_F_RESPONSE  = 0x01,
    UFS_F_ERROR     = 0x02,
};

enum { UFS_DIGEST_SIZE = SHA256_DIGEST_SIZE };

typedef struct {
    byte version;
    byte _;
    byte cmd;
    byte flag;

    union {
        struct {
            int     err;
            uint32  len;
            char    errs[0];    // align 4
        } e;

        struct {
            uint32  bkdr;
            byte    digest[UFS_DIGEST_SIZE];
        } id;

        struct {
            uint32  bkdr;
            byte    digest[UFS_DIGEST_SIZE];
            
            time_t  time;
            uint32  size; // content size
            byte    content[0]; // align 4
        } c;
    } 
    u;
} 
ufs_proto_t;

#define ufs_proto_errno(_proto)     (_proto)->u.e.err
#define ufs_proto_errlen(_proto)    (_proto)->u.e.len
#define ufs_proto_errs(_proto)      (_proto)->u.e.errs

#define ufs_proto_bkdr(_proto)      (_proto)->u.c.bkdr
#define ufs_proto_digest(_proto)    (_proto)->u.c.digest
#define ufs_proto_time(_proto)      (_proto)->u.c.time
#define ufs_proto_size(_proto)      (_proto)->u.c.size
#define ufs_proto_content(_proto)   (_proto)->u.c.content

typedef struct {
    int node_count;
    int dir_count;
    int replication;
    int port;
    uint32 live;

    char **nodes;
    char **dirs;
    char *home;
    char *db;
} udfs_conf_t;

#define UDFS_CONF_INITER    {   \
    .home = DEFT_UFS_HOME,      \
    .live = DEFT_UFS_LIVE,      \
    .port = DEFT_UFS_PORT,      \
    .replication = DEFT_UFS_REPLICATION,  \
    .db = DEFT_UFS_DBFILENAME,  \
}

static inline int
udfs_conf_init(udfs_conf_t *conf)
{
    
    return 0;
}
/******************************************************************************/
#endif /* __UFS_H_554906612bb04a819c8d03c8785a5bbe__ */

