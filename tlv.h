#ifndef __TLV_H_d203748a8a974e6282d89ddcde27123a__
#define __TLV_H_d203748a8a974e6282d89ddcde27123a__
/******************************************************************************/
#include "os.h"
/******************************************************************************/
typedef uint64 xdr_time_t;
#define xdr_time_second(_us_time)   ((time_t)((_us_time)/1000000))

typedef union {
    uint32 ip[4];
} xdr_ipaddr_t;
#define xdr_ip(_addr)               (_addr)->ip[0]

enum {
    XTLV_T_u8,
    XTLV_T_u16,
    XTLV_T_u32,
    XTLV_T_u64,
    
    XTLV_T_i8,
    XTLV_T_i16,
    XTLV_T_i32,
    XTLV_T_i64,
    
    XTLV_T_string,
    XTLV_T_binary,
    XTLV_T_object,
    
    XTLV_T_time,
    XTLV_T_ip4,     // u32
    XTLV_T_ip6,     // 4 * u32
    
    XTLV_T_end
};

enum {
    XTLV_F_MULTI = 0x01,
    XTLV_F_FIXED = 0x02,
};

typedef struct xtlv_st xtlv_t;
typedef struct xdr_buffer_st xdr_buffer_t;

typedef void xtlv_dump_f(xtlv_t *tlv);
typedef int xtlv_check_f(xtlv_t *tlv);
typedef int xtlv_to_xdr_f(xdr_buffer_t *x, xtlv_t *tlv);

static inline void xtlv_dump_session(xtlv_t *tlv);
static inline void xtlv_dump_session_st(xtlv_t *tlv);
static inline void xtlv_dump_session_time(xtlv_t *tlv);
static inline void xtlv_dump_tcp(xtlv_t *tlv);
static inline void xtlv_dump_L7(xtlv_t *tlv);
static inline void xtlv_dump_http(xtlv_t *tlv);
static inline void xtlv_dump_sip(xtlv_t *tlv);
static inline void xtlv_dump_rtsp(xtlv_t *tlv);

typedef struct {
    int     id;
    int     type;
    uint32  flag;
    uint32  minsize;
    uint32  maxsize;
    char    *name;

    xtlv_dump_f *dump;
    xtlv_check_f *check;
    xtlv_to_xdr_f *toxdr;
} xtlv_ops_t;

#define XTLV_MAPPER(_) \
    _(header,               0,  XTLV_T_binary,  0, 0, 0, NULL, NULL, NULL) \
    _(session_state,        1,  XTLV_T_u32,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    _(appid,                2,  XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(session,              3,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_session_t), xtlv_dump_session, NULL, NULL) \
    _(session_st,           4,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_session_st_t), xtlv_dump_session_st, NULL, NULL) \
    _(session_time,         5,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_session_time_t, xtlv_dump_session_time, NULL, NULL) \
    _(service_st,           6,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_service_st_t), xtlv_dump_session_st, NULL, NULL) \
    _(tcp,                  7,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_tcp_t), xtlv_dump_tcp, NULL, NULL) \
    _(first_response_delay, 8,  XTLV_T_u32,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    _(L7,                   9,  XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_L7_t), xtlv_dump_L7, NULL, NULL) \
    _(http,                 10, XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_http_t), xtlv_dump_http, NULL, NULL) \
    _(http_host,            11, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_url,             12, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_host_xonline,    13, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_user_agent,      14, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_content,         15, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_refer,           16, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_cookie,          17, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(http_location,        18, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(sip,                  19, XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_sip_t), xtlv_dump_sip, NULL, NULL) \
    _(sip_calling_number,   20, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(sip_called_number,    21, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(sip_session_id,       22, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(rtsp,                 23, XTLV_T_object,  XTLV_F_FIXED, 0, sizeof(xtlv_rtsp_t), xtlv_dump_rtsp, NULL, NULL) \
    _(rtsp_url,             24, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(rtsp_user_agent,      25, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(rtsp_server_ip,       26, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(ftp_status,           27, XTLV_T_u16,     XTLV_F_FIXED, 0, sizeof(uint16), NULL, NULL, NULL) \
    _(ftp_user,             28, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(ftp_pwd,              29, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(ftp_trans_mode,       30, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(ftp_trans_type,       31, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(ftp_filename,         32, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(ftp_filesize,         33, XTLV_T_u32,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    _(ftp_response_delay,   34, XTLV_T_time,    XTLV_F_FIXED, 0, sizeof(xdr_time_t), NULL, NULL, NULL) \
    _(ftp_trans_time,       35, XTLV_T_time,    XTLV_F_FIXED, 0, sizeof(xdr_time_t), NULL, NULL, NULL) \
    _(mail_msg_type,        36, XTLV_T_u16,     XTLV_F_FIXED, 0, sizeof(uint16), NULL, NULL, NULL) \
    _(mail_status_code,     37, XTLV_T_i16,     XTLV_F_FIXED, 0, sizeof( int16), NULL, NULL, NULL) \
    _(mail_user,            38, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(mail_sender,          39, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(mail_length,          40, XTLV_T_u32,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    _(mail_domain,          41, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(mail_recver,          42, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(mail_hdr,             43, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(mail_acs_type,        44, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(dns_domain,           45, XTLV_T_string,  0, 0, 0, NULL, NULL, NULL) \
    _(dns_ip_count,         46, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(dns_ip4,              47, XTLV_T_ip4,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    _(dns_ip6,              48, XTLV_T_ip6,     XTLV_F_FIXED, 0, sizeof(xdr_ipaddr_t), NULL, NULL, NULL) \
    _(dns_response_code,    49, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(dns_count_request,    50, XTLV_T_u8,      XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL)  \
    _(dns_count_response_record, 51, XTLV_T_u8, XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL) \
    _(dns_count_response_auth,   52, XTLV_T_u8, XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL) \
    _(dns_count_response_extra,  53, XTLV_T_u8, XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL) \
    _(dns_delay,            54, XTLV_T_u32,     XTLV_F_FIXED, 0, sizeof(uint32), NULL, NULL, NULL) \
    \
    _(http_request,         201, XTLV_T_binary, 0, 0, 0, NULL, NULL, NULL) \
    _(http_response,        202, XTLV_T_binary, 0, 0, 0, NULL, NULL, NULL) \
    _(file_content,         203, XTLV_T_binary, 0, 0, 0, NULL, NULL, NULL) \
    _(ssl_server_cert,      204, XTLV_T_binary, XTLV_F_MULTI, 0, 0, NULL, NULL, NULL) \
    _(ssl_client_cert,      205, XTLV_T_binary, XTLV_F_MULTI, 0, 0, NULL, NULL, NULL) \
    _(ssl_fail_reason,      206, XTLV_T_u8,     XTLV_F_FIXED, 0, sizeof(uint8), NULL, NULL, NULL) \
    /* end */
#define XTLV_ID_END         207
#define xtlv_foreach(i)     for (i=0; i<XTLV_ID_END; i++)

#define XTLV_OPS_STRUCT(_name, _id, _type, _flag, _dump, _check, _toxdr) [_id] = { \
    .id     = _id,      \
    .type   = _type,    \
    .flag   = _flag,    \
    .name   = #_name,   \
    .dump   = _dump,    \
    .check  = _check,   \
    .toxdr  = _toxdr,   \
},  /* end */

extern xtlv_ops_t __xtlv_ops[];
extern uint32 __xtlv_debug;

#define DECLARE_XTLV_VARS \
    uint32 __xtlv_debug; \
    xtlv_ops_t __xtlv_ops[XTLV_ID_END] = { XTLV_MAPPER(XTLV_OPS_STRUCT) }

enum {
    XDEBUG_DUMP = 0x01,
};

static inline bool
is_xdebug_dump()
{
    return XDEBUG_DUMP==(XDEBUG_DUMP & __xtlv_debug);
}

static inline bool
is_good_xtlv_id(_id)
{
    return is_good_enum(_id, XTLV_ID_END);
}

static inline xtlv_ops_t *
xtlv_ops(int id)
{
    if (false==is_good_xtlv_id(id)) {
        return NULL;
    }

    return &__xtlv_ops[id];
}

struct xtlv_st {
    byte    id;
    byte    pad;

    union {
        struct {
            uint16  _:4;
            uint16  len:12;
        } n;    // normal

        struct {
            uint16  e:1;
            uint16  _:15;
        } e;    // extend
    } h;

    union {
        byte data[0];

        struct {
            uint32  len;
            byte    data[0];
        } e;
    } d;
};

static inline int
xtlv_ops_check(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    if (NULL==ops) {
        return -e_xtlv_invalid_id;
    }

    if (xtlv_len(tlv) < xtlv_hdrlen(tlv)) {
        return -e_xtlv_too_small;
    }

    if (ops->check) {
        return (*ops->check)(tlv);
    }

    uint32 dlen = xtlv_datalen(tlv);
    if (XTLV_F_FIXED==(XTLV_F_FIXED & tlv->flag)) {
        if (ops->maxsize && dlen != ops->maxsize) {
            return -e_xtlv_invalid_object_size;
        }
    } else {
        if (ops->minsize && dlen < ops->minsize) {
            return -e_xtlv_too_small;
        }
        else if (ops->maxsize && dlen > ops->maxsize) {
            return -e_xtlv_too_big;
        }
    }

    return 0;
}

#define xtlv_extend(_tlv)       (_tlv)->h.e.e

#define xtlv_data_n(_tlv)       (_tlv)->d.data
#define xtlv_data_e(_tlv)       (_tlv)->d.e.data
#define xtlv_data(_tlv)         (xtlv_extend(_tlv)?xtlv_data_e(_tlv):xtlv_data_n(_tlv))

#define xtlv_len_n(_tlv)        (_tlv)->h.n.len
#define xtlv_len_e(_tlv)        (_tlv)->d.e.len
#define xtlv_len(_tlv)          (xtlv_extend(_tlv)?xtlv_len_e(_tlv):xtlv_len_n(_tlv))

#define xtlv_hdrlen_e           sizeof(xtlv_t)
#define xtlv_hdrlen_n           (sizeof(xtlv_t)-sizeof(uint32))
#define xtlv_hdrlen(_tlv)       (xtlv_extend(_tlv)?xtlv_hdrlen_e:xtlv_hdrlen_n)

#define xtlv_datalen_e(_tlv)    (xtlv_len_e(_tlv)-xtlv_hdrlen_e)
#define xtlv_datalen_n(_tlv)    (xtlv_len_n(_tlv)-xtlv_hdrlen_n)
#define xtlv_datalen(_tlv)      (xtlv_extend(_tlv)?xtlv_datalen_e(_tlv):xtlv_datalen_n(_tlv))

#define xtlv_strlen(_tlv)       (xtlv_datalen(_tlv) - (_tlv)->pad)
#define xtlv_binlen(_tlv)       (xtlv_datalen(_tlv) - (_tlv)->pad)

#define xtlv_first(_tlv_header) (xtlv_t *)xtlv_data(_tlv)
#define xtlv_next(_tlv)         (xtlv_t *)((void *)(_tlv) + xtlv_len(_tlv))

#define xtlv_u8(_tlv)       (_tlv)->pad
#define xtlv_u16(_tlv)      (*(uint16 *)xtlv_data(_tlv))
#define xtlv_u32(_tlv)      (*(uint32 *)xtlv_data(_tlv))
#define xtlv_u64(_tlv)      (*(uint64 *)xtlv_data(_tlv))

#define xtlv_i8(_tlv)       (_tlv)->pad
#define xtlv_i16(_tlv)      (*(int16 *)xtlv_data(_tlv))
#define xtlv_i32(_tlv)      (*(int32 *)xtlv_data(_tlv))
#define xtlv_i64(_tlv)      (*(int64 *)xtlv_data(_tlv))

#define xtlv_time(_tlv)     (*(xdr_time_t *)xtlv_data(_tlv))

#define xtlv_ip4(_tlv)      (*(uint32 *)xtlv_data(_tlv))
#define xtlv_ip6(_tlv)      ((xdr_ipaddr_t *)xtlv_data(_tlv))

#define xtlv_string(_tlv)   xtlv_data(_tlv)
#define xtlv_binary(_tlv)   xtlv_data(_tlv)

#define xtlv_session(_tlv)      (xtlv_session_t *)xtlv_data(_tlv)
#define xtlv_session_st(_tlv)   (xtlv_session_st_t *)xtlv_data(_tlv)
#define xtlv_session_time(_tlv) (xtlv_session_time_t *)xtlv_data(_tlv)
#define xtlv_service_st(_tlv)   (xtlv_service_st_t *)xtlv_data(_tlv)
#define xtlv_tcp(_tlv)          (xtlv_tcp_t *)xtlv_data(_tlv)
#define xtlv_L7(_tlv)           (xtlv_L7_t *)xtlv_data(_tlv)
#define xtlv_http(_tlv)         (xtlv_http_t *)xtlv_data(_tlv)
#define xtlv_sip(_tlv)          (xtlv_sip_t *)xtlv_data(_tlv)
#define xtlv_rtsp(_tlv)         (xtlv_rtsp_t *)xtlv_data(_tlv)

#define XTLV_DUMP(_fmt, _args...)       os_println(__tab _fmt, ##_args)
#define XTLV_DUMP2(_fmt, _args...)      os_println(__tab2 _fmt, ##_args)

#define __XTLV_DUMP_BY(_tlv, _format, _type)  do{ \
    xtlv_ops_t *ops = xtlv_ops((_tlv)->id); \
                                            \
    XTLV_DUMP("id: %d, %s: " _format, (_tlv)->id, ops->name, xtlv_##_type(_tlv)); \
}while(0)

#define XTLV_DUMP_NUMBER(_tlv, _type)   __XTLV_DUMP_BY(_tlv, "%d", _type)
#define XTLV_DUMP_STRING(_tlv)          __XTLV_DUMP_BY(_tlv, "%s", string)

static inline void xtlv_dump_u8 (xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, u8);  }
static inline void xtlv_dump_u16(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, u16); }
static inline void xtlv_dump_u32(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, u32); }
static inline void xtlv_dump_u64(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, u64); }

static inline void xtlv_dump_i8 (xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, i8);  }
static inline void xtlv_dump_i16(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, i16); }
static inline void xtlv_dump_i32(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, i32); }
static inline void xtlv_dump_i64(xtlv_t *tlv) { XTLV_DUMP_NUMBER(tlv, i64); }

static inline void xtlv_dump_string(xtlv_t *tlv) { XTLV_DUMP_STRING(tlv); }

static inline void 
xtlv_dump_time(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    XTLV_DUMP("id:%d, %s: %s", tlv->id, ops->name, os_time_string(xdr_time_second(xtlv_time(tlv))));
}

static inline void 
xtlv_dump_ip4(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    uint32 ip = xtlv_ip4(tlv);
    ip = htonl(ip);
    
    XTLV_DUMP("id:%d, %s: %s", tlv->id, ops->name, os_ipstring(ip));
}

static inline void 
xtlv_dump_ip6(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    XTLV_DUMP("id: %d, %s: ipv6 address", tlv->id, ops->name);
}

static inline void 
xtlv_dump_binary(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    
    XTLV_DUMP("id: %d, %s:", tlv->id, ops->name);

    os_dump_buffer(xtlv_binary(tlv), xtlv_datalen(tlv));
}

enum { XDR_SESSION_IPV4 = 0 };

typedef struct {
    byte ver;
    byte dir;
    byte proto;
    byte _;
    
    uint16 sport;
    uint16 dport;
    
    xdr_ipaddr_t sip;
    xdr_ipaddr_t dip;
} xtlv_session_t;
#define xtlv_session_sip(_session)   xdr_ip(&(_session)->sip)
#define xtlv_session_dip(_session)   xdr_ip(&(_session)->dip)

static inline void 
xtlv_dump_session(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_session_t *obj = xtlv_session(tlv);
    
    XTLV_DUMP("id: %d, session:", tlv->id);
    
    XTLV_DUMP2("version: %d", obj->ver);
    XTLV_DUMP2("dir    : %d", obj->dir);
    XTLV_DUMP2("proto  : %d", obj->proto);
    XTLV_DUMP2("sport  : %d", obj->sport);
    XTLV_DUMP2("dport  : %d", obj->dport);

    if (XDR_SESSION_IPV4==obj->ver) {
        uint32 ip;

        ip = xdr_ip(&obj->sip);
        ip = htonl(ip);
        XTLV_DUMP2("sip    : %d", os_ipstring(ip));
        
        ip = xdr_ip(&obj->dip);
        ip = htonl(ip);
        XTLV_DUMP2("dip    : %d", os_ipstring(ip));
    } else {
        XTLV_DUMP2("sip    : ipv6 address");
        XTLV_DUMP2("dip    : ipv6 addres");
    }
}

typedef struct {
    uint32 flow[2];
    uint32 ip_packet[2];
    uint32 tcp_disorder[2];
    uint32 tcp_retransmit[2];
    uint32 ip_frag[2];
    uint32 duration[2];
} xtlv_session_st_t, xtlv_service_st_t;

static inline void 
xtlv_dump_session_st(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_session_st_t *obj = xtlv_session_st(tlv);
    int i;
    
    XTLV_DUMP("id: %d, session_st:", tlv->id);

    for (i=0; i<2; i++) {
        char c = (0==i)?'u':'d';
        
        XTLV_DUMP2("[%c]flow            : %d", c, obj->flow[i]);
        XTLV_DUMP2("[%c]ip_packet       : %d", c, obj->ip_packet[i]);
        XTLV_DUMP2("[%c]tcp_disorder    : %d", c, obj->tcp_disorder[i]);
        XTLV_DUMP2("[%c]tcp_retransmit  : %d", c, obj->tcp_retransmit[i]);
        XTLV_DUMP2("[%c]ip_frag         : %d", c, obj->ip_frag[i]);
        XTLV_DUMP2("[%c]duration        : %d", c, obj->duration[i]);
    }
}

typedef struct {
    xdr_time_t create;
    xdr_time_t start;
    xdr_time_t stop;
} xtlv_session_time_t;

static inline void 
xtlv_dump_session_time(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_session_time_t *obj = xtlv_session_time(tlv);
    
    XTLV_DUMP("id: %d, session:", tlv->id);
    
    XTLV_DUMP2("create: %s", os_time_string(xdr_time_second(obj->create)));
    XTLV_DUMP2("start : %s", os_time_string(xdr_time_second(obj->start)));
    XTLV_DUMP2("stop  : %s", os_time_string(xdr_time_second(obj->stop)));
}

typedef struct {
    uint16 synack_to_syn_time;
    uint16 ack_to_syn_time;
    
    byte complete;
    byte close_reason;
    byte _[2];
    
    uint32 first_request_delay;
    uint32 first_response_delay;
    uint32 window;
    
    uint16 mss;
    byte count_retry;
    byte count_retry_ack;
    
    byte count_ack;
    byte connect_status;
    byte handshake12;
    byte handshake23;
} 
xtlv_tcp_t;

enum { XDR_TCP_COMPLETE = 1 };

static inline void 
xtlv_dump_tcp(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_tcp_t *obj = xtlv_tcp(tlv);
    
    XTLV_DUMP("id: %d, session:", tlv->id);
    
    XTLV_DUMP2("synack_to_syn_time  : %u us", obj->synack_to_syn_time);
    XTLV_DUMP2("ack_to_syn_time     : %u us", obj->ack_to_syn_time);
    XTLV_DUMP2("complete            : %s", bool_string(XDR_TCP_COMPLETE==obj->complete));
    XTLV_DUMP2("close_reason        : %d", obj->close_reason);
    XTLV_DUMP2("first_request_delay : %u ms", obj->first_request_delay);
    XTLV_DUMP2("first_response_delay: %u ms", obj->first_response_delay);
    XTLV_DUMP2("window              : %u", obj->window);
    XTLV_DUMP2("mss                 : %u", obj->mss);
    XTLV_DUMP2("count_retry         : %u", obj->count_retry);
    XTLV_DUMP2("count_retry_ack     : %u", obj->count_retry_ack);
    XTLV_DUMP2("count_ack           : %u", obj->count_ack);
    XTLV_DUMP2("connect_status      : %u", obj->connect_status);
    XTLV_DUMP2("handshake12         : %s", success_string(0==obj->handshake12));
    XTLV_DUMP2("handshake23         : %s", success_string(0==obj->handshake23));
}

typedef struct {
    byte status;
    byte class;
    uint16 protocol;
} xtlv_L7_t;

static inline void 
xtlv_dump_L7(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_L7_t *obj = xtlv_L7(tlv);
    
    XTLV_DUMP("id: %d, L7:", tlv->id);
    
    XTLV_DUMP2("status  : %u", obj->status);
    XTLV_DUMP2("class   : %u", obj->class);
    XTLV_DUMP2("protocol: %u", obj->protocol);
}

typedef struct {
    xdr_time_t time_request;
    xdr_time_t time_first_response;
    xdr_time_t time_last_content;
    uint64 service_delay;
    
    uint16 status_code;
    byte method;
    byte version;
    
    union {
        struct {
            byte first:2;
            byte flag:3;
            byte head:1;
            byte _:2;
        } st;

        byte v;
    } u;
    byte ie;
    byte portal;
    byte _;
}
xtlv_http_t;

static inline void 
xtlv_dump_http(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_http_t *obj = xtlv_http(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("time_request        : %s", os_time_string(xdr_time_second(obj->time_request)));
    XTLV_DUMP2("time_first_response : %s", os_time_string(xdr_time_second(obj->time_first_response)));
    XTLV_DUMP2("time_last_content   : %s", os_time_string(xdr_time_second(obj->time_last_content)));
    XTLV_DUMP2("service_delay       : %llu us", obj->service_delay);
    XTLV_DUMP2("status_code         : %u", obj->status_code);
    XTLV_DUMP2("method              : %u", obj->method);
    XTLV_DUMP2("version             : %u", obj->version);

    XTLV_DUMP2("first               : %s", bool_string(obj->u.st.first));
    XTLV_DUMP2("flag                : %u", obj->flag);
    XTLV_DUMP2("head                : %s", yes_string(obj->version));
    XTLV_DUMP2("ie                  : %u", obj->ie);
    XTLV_DUMP2("portal              : %u", obj->portal);
}

enum { XDR_SIP_INVITE = 1 };
enum { XDR_SIP_BYE = 1 };

typedef struct {
    byte call_direction;
    byte call_type;
    byte hangup_reason;
    byte signal_type;
    
    uint16 dataflow_count;
    union {
        struct {
            uint16 invite:1;
            uint16 bye:1;
            uint16 malloc:1;
            uint16 _:13;
        } st;

        uint16 v;
    } u;
} xtlv_sip_t;

static inline void 
xtlv_dump_sip(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_sip_t *obj = xtlv_sip(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("call_direction  : %u", obj->call_direction);
    XTLV_DUMP2("call_type       : %u", obj->call_type);
    XTLV_DUMP2("hangup_reason   : %u", obj->hangup_reason);
    XTLV_DUMP2("signal_type     : %u", obj->signal_type);
    XTLV_DUMP2("dataflow_count  : %u", obj->dataflow_count);
    XTLV_DUMP2("invite          : %s", bool_string(XDR_SIP_INVITE==obj->u.st.invite));
    XTLV_DUMP2("bye             : %s", bool_string(XDR_SIP_BYE==obj->bye));
    XTLV_DUMP2("malloc          : %s", bool_string(obj->malloc));
}

typedef struct {
    uint16 port_client_start;
    uint16 port_client_end;
    uint16 port_server_start;
    uint16 port_client_end;
    uint16 count_video;
    uint16 count_audio;
    
    uint32 describe_delay;
} xtlv_rtsp_t;

static inline void 
xtlv_dump_rtsp(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_rtsp_t *obj = xtlv_rtsp(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("port_client_start   : %u", obj->port_client_start);
    XTLV_DUMP2("port_client_end     : %u", obj->port_client_end);
    XTLV_DUMP2("port_server_start   : %u", obj->port_server_start);
    XTLV_DUMP2("port_client_end     : %u", obj->port_client_end);
    XTLV_DUMP2("count_video         : %u", obj->count_video);
    XTLV_DUMP2("count_audio         : %u", obj->count_audio);
    XTLV_DUMP2("describe_delay      : %u", obj->describe_delay);
}

static inline void
xtlv_dump(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    if (ops->dump) {
        (*ops->dump)(tlv);

        return;
    }

    switch(ops->type) {
        case XTLV_T_u8: 
            xtlv_dump_u8(tlv);
            break;
        case XTLV_T_u16: 
            xtlv_dump_u16(tlv);
            break;
        case XTLV_T_u32: 
            xtlv_dump_u32(tlv);
            break;
        case XTLV_T_u64: 
            xtlv_dump_u64(tlv);
            break;
            
        case XTLV_T_i8: 
            xtlv_dump_i8(tlv);
            break;
        case XTLV_T_i16: 
            xtlv_dump_i16(tlv);
            break;
        case XTLV_T_i32: 
            xtlv_dump_i32(tlv);
            break;
        case XTLV_T_i64: 
            xtlv_dump_i64(tlv);
            break;
        
        case XTLV_T_string: 
            xtlv_dump_string(tlv);
            break;
        case XTLV_T_binary: 
            xtlv_dump_binary(tlv);
            break;       
        case XTLV_T_time: 
            xtlv_dump_time(tlv);
            break;
        case XTLV_T_ip4: 
            xtlv_dump_ip4(tlv);
            break;
        case XTLV_T_ip6: 
            xtlv_dump_ip6(tlv);
            break;
    }
}

enum { XCACHE_EXPAND = 32 };

typedef struct {
    xtlv_t *tlv;
    
    xtlv_t **multi;
    uint16 current, count;
} xcache_t;

static inline bool
is_xcache_multi(xcache_t *cache)
{
    return cache->multi;
}

static inline int
xcache_expand(xcache_t *cache)
{
    if (NULL==cache->multi) {
        cache->multi = (xtlv_t **)os_calloc(XCACHE_EXPAND, sizeof(xtlv_t *));
        if (NULL==cache->multi) {
            return -ENOMEM;
        }
        cache->current = 0;
        cache->count = XCACHE_EXPAND;
    }

    if (cache->current == cache->count) {
        cache->multi = (xtlv_t **)os_realloc(cache->count + XCACHE_EXPAND, sizeof(xtlv_t *));
        if (NULL==cache->multi) {
            return -ENOMEM;
        }
        cache->count += XCACHE_EXPAND;
    }

    return 0;
}

static inline int
xcache_save_multi(xcache_t *cache, xtlv_t *tlv)
{
    int err = 0;

    err = xcache_expand(cache);
    if (err<0) {
        return err;
    }

    if (0==cache->current) {
        /*
        * first, save at cache->tlv
        * second, save at cache->multi
        *   so, copy cache->tlv to cache->multi[0]
        */
        cache->multi[0] = cache->tlv;
        cache->current++
    }

    cache->multi[cache->current++] = tlv;
}

typedef struct {
    xtlv_t *header;
    
    xcache_t cache[XTLV_ID_END];
} xrecord_t;

static inline int
xrecord_release(xrecord_t *x)
{
    xcache_t *cache;
    uint32 i;
    
    xtlv_foreach(i) {
        cache = &x->cache[i];
        
        if (cache->multi) {
            os_free(cache->multi);
        }
    }
    
    return 0;
}

static inline int
xrecord_save(xrecord_t *x, xtlv_t *tlv)
{
    xcache_t *cache = &x->cache[tlv->id];
    if (NULL==cache->tlv) {
        cache->tlv = tlv;

        return 0;
    }

    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    if (XTLV_F_MULTI & ops->flag) {
        return xcache_save_multi(cache, tlv);
    } 
    else {
        return -e_xtlv_not_support_multi;
    }
}

static inline int
__xrecord_parse(xrecord_t *x, xtlv_t *tlv, uint32 left)
{
    int err = 0;

    err = xtlv_ops_check(tlv);
    if (err<0) {
        return err;
    }

    err = xrecord_save(x, tlv);
    if (err<0) {
        return err;
    }

    if (is_xdebug_dump()) {
        xtlv_dump(tlv);
    }
    
    return __xrecord_parse(x, xtlv_next(tlv), left - xtlv_len(tlv));
}

static inline int
xrecord_parse(xrecord_t *x)
{
    xtlv_t *tlv = (xtlv_t *)x->buffer;
    if (0!=tlv->id) {
        return -e_xtlv_header_must_first;
    }
    else if (xtlv_len(tlv) != x->len) {
        return e_xtlv_header_length_not_match;
    }
    else if (x->len <= xtlv_hdrlen(tlv)) {
        return e_xtlv_header_no_body;
    }

    return __xrecord_parse(x, xtlv_first(tlv), x->len - xtlv_hdrlen(tlv));
}

typedef struct {
    void *buffer;
    uint32 len;
    
    xrecord_t **records;
    int count;
} xblock_t;

static inline int
xblock_pre(void *buffer, uint32 left)
{
    xtlv_t *h = (xtlv_t *)buffer;
    uint32 count = 0;

    while(left > 0) {
        count++;
        
        if (left < xtlv_hdrlen(h)) {
            return -e_xtlv_too_small;
        }
        else if (left < xtlv_len(h)) {
            return -e_xtlv_too_small;
        }
        else if (left == xtlv_len(h)) {
            break;
        }
        
        h = xtlv_next(h);
    }

    return count;
}

static inline int
xblock_init(xblock_t *block, void *buffer, uint32 len)
{
    xtlv_t *h;
    int i, count;
    
    block->buffer   = buffer;
    block->len      = len;

    count = xblock_pre(buffer, len);
    if (count<0) {
        return count;
    }

    block->records = (xrecord_t **)os_malloc(count * sizeof(xrecord_t *));
    if (NULL==block->records) {
        return -ENOMEM;
    }
    block->count = count;

    for (i=0, h=(xtlv_t *)buffer; 
         i < count;
         i++, h=xtlv_next(h)) {
        block->records[i]->header = h;
    }
    
    return 0;
}

static inline int
xblock_release(xblock_t *block)
{
    if (block->records) {
        int i;

        for (i=0; i<block->count; i++) {
            xrecord_release(block->records[i]);
        }
        
        os_free(block->records);
    }
}

static inline int
xblock_parse(xblock_t *block)
{
    int i, err;

    for (i=0; i<block->count; i++) {
        err = xrecord_parse(block->records[i]);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

enum {
    e_xtlv_header_must_first        = 1000,
    e_xtlv_header_length_not_match  = 1001,
    e_xtlv_header_no_body           = 1002,
    e_xtlv_invalid_id               = 1003,
    e_xtlv_invalid_object_size      = 1004,
    e_xtlv_too_small                = 1005,
    e_xtlv_too_big                  = 1006,
    e_xtlv_not_support_multi        = 1007,
};
/******************************************************************************/
#endif /* __TLV_H_d203748a8a974e6282d89ddcde27123a__ */
