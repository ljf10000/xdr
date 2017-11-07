#ifndef __TLV_H_d203748a8a974e6282d89ddcde27123a__
#define __TLV_H_d203748a8a974e6282d89ddcde27123a__
/******************************************************************************/
#include "os.h"
/******************************************************************************/
#ifndef D_tlv_dprint
#define D_tlv_dprint    1
#endif

#if D_tlv_dprint
#define tlv_dprint(_fmt, _args...)      os_println(_fmt, ##_args)
#else
#define tlv_dprint(_fmt, _args...)      os_do_nothing()
#endif

#ifndef D_tlv_trace
#define D_tlv_trace     1
#endif

#if D_tlv_trace
#define tlv_trace(_call, _fmt, _args...)    os_trace(tlv_dprint, _call, _fmt, ##_args)
#else
#define tlv_trace(_call, _fmt, _args...)    (_call)
#endif

#ifndef TLV_MAXDATA
#define TLV_MAXDATA     (128*1024*1024)
#endif

#ifndef TLV_MAXCOUNT
#define TLV_MAXCOUNT    (128*1024)
#endif

#ifndef XDR_SUFFIX
#define XDR_SUFFIX      "xdr"
#endif

#ifndef ERR_SUFFIX
#define ERR_SUFFIX      "err"
#endif

#ifndef XDR_VERSION
#define XDR_VERSION     0
#endif

#ifndef XDR_EXPAND
#define XDR_EXPAND      (32*1024)
#endif

#define XDR_ALIGN(x)        OS_ALIGN(x, 4)
#define XDR_EXPAND_ALIGN(x) OS_ALIGN(x + XDR_EXPAND, XDR_EXPAND)
#define XDR_DIGEST_SIZE     SHA256_DIGEST_SIZE

struct xb;
struct tlv;
struct xdr;
struct xparse;

typedef uint32 xdr_offset_t;
typedef uint32 xdr_size_t;
typedef uint32 xdr_delay_t;

typedef uint8  tlv_u8_t;
typedef uint16 tlv_u16_t;
typedef uint32 tlv_u32_t;
typedef uint64 tlv_u64_t;

typedef uint64 xdr_duration_t,  tlv_duration_t;
typedef uint64 xdr_time_t,      tlv_time_t;
#define XDR_SECOND(_us)         ((time_t)((_us)/1000000))

typedef uint32 xdr_ip4_t, tlv_ip4_t;
typedef struct {
    uint32 ip[4];
} xdr_ipaddr_t, xdr_ip6_t, tlv_ip6_t;
#define XDR_IP(_addr)   (_addr)->ip[0]

enum {
    OPT_CLI         = 0x01,
    OPT_IP6         = 0x02,
    OPT_SPLIT       = 0x04,
    OPT_STRICT      = 0x08,
    OPT_DUMP        = 0x10,
    OPT_DUMP_SIMPLE = 0x20 | OPT_DUMP,
};

enum {
    PATH_TLV = 0,
    PATH_XDR = 1,
    PATH_SHA = 2,
    PATH_BAD = 3,
    
    PATH_END
};

enum {
    TLV_F_MULTI             = 0x1000,
    TLV_F_FIXED             = 0x2000,
    
    TLV_F_FILE_CONTENT      = 0x0001,
    TLV_F_HTTP_REQUEST      = 0x0002,
    TLV_F_HTTP_RESPONSE     = 0x0004,
    TLV_F_SSL_SERVER_CERT   = 0x0008,
    TLV_F_SSL_CLIENT_CERT   = 0x0010,

    TLV_F_HTTP              = TLV_F_HTTP_REQUEST|TLV_F_HTTP_RESPONSE,
    TLV_F_CERT              = TLV_F_SSL_SERVER_CERT|TLV_F_SSL_CLIENT_CERT,
    TLV_F_FILE              = TLV_F_FILE_CONTENT|TLV_F_HTTP|TLV_F_CERT,
};

#if 1
#define TLV_T_MAPPER(_)         \
    _(TLV_T,    u8,         0)  \
    _(TLV_T,    u16,        1)  \
    _(TLV_T,    u32,        2)  \
    _(TLV_T,    u64,        3)  \
    _(TLV_T,    string,     4)  \
    _(TLV_T,    binary,     5)  \
    _(TLV_T,    object,     6)  \
    _(TLV_T,    time,       7)  \
    _(TLV_T,    duration,   8)  \
    _(TLV_T,    ip4,        9)  \
    _(TLV_T,    ip6,        10) \
    /* end */
DECLARE_ENUM(TLV_T, tlv_type, TLV_T_MAPPER, TLV_T_END);

static inline bool is_good_tlv_type(int id);
static inline char *tlv_type_getnamebyid(int id);
static inline int tlv_type_getidbyname(const char *name);

#define TLV_T_u8        TLV_T_u8
#define TLV_T_u16       TLV_T_u16
#define TLV_T_string    TLV_T_string
#define TLV_T_binary    TLV_T_binary
#define TLV_T_object    TLV_T_object
#define TLV_T_END       TLV_T_END
#endif

struct tlv {
    byte id;
    byte pad;
    
    uint16 e:1;
    uint16 _:3;
    uint16 len:12;

    byte body[0];
};

#define tlv_extend(_tlv)        (_tlv)->e

#define tlv_data_n(_tlv)        (_tlv)->body
#define tlv_data_e(_tlv)        ((_tlv)->body + sizeof(uint32))
#define tlv_data(_tlv)          (tlv_extend(_tlv)?tlv_data_e(_tlv):tlv_data_n(_tlv))

#if 0
static inline uint32
tlv_len_n(struct tlv *tlv)
{
    if (is_option(OPT_STRICT)) {
        
    } else {
        return tlv->len;
    }
}
#else
#define tlv_len_n(_tlv)         (_tlv)->len
#endif

#define tlv_len_e(_tlv)         (*(uint32 *)(_tlv)->body)
#define tlv_len(_tlv)           (tlv_extend(_tlv)?tlv_len_e(_tlv):tlv_len_n(_tlv))

#define tlv_hdrlen_n            sizeof(struct tlv)
#define tlv_hdrlen_e            (sizeof(struct tlv)+sizeof(uint32))
#define tlv_hdrlen(_tlv)        (tlv_extend(_tlv)?tlv_hdrlen_e:tlv_hdrlen_n)

#define tlv_datalen_n(_tlv)     (tlv_len_n(_tlv)-tlv_hdrlen_n)
#define tlv_datalen_e(_tlv)     (tlv_len_e(_tlv)-tlv_hdrlen_e)
#define tlv_datalen(_tlv)       (tlv_extend(_tlv)?tlv_datalen_e(_tlv):tlv_datalen_n(_tlv))

#define tlv_binlen(_tlv)        (tlv_datalen(_tlv) - (_tlv)->pad)
#define tlv_strlen(_tlv)        tlv_binlen(_tlv)

#define tlv_first(_tlv_header)  (struct tlv *)tlv_data(_tlv_header)
#define tlv_next(_tlv)          (struct tlv *)((byte *)(_tlv) + tlv_len(_tlv))

#define tlv_u8(_tlv)        (_tlv)->pad
#define tlv_u16(_tlv)       (*(uint16 *)tlv_data(_tlv))
#define tlv_u32(_tlv)       (*(uint32 *)tlv_data(_tlv))
#define tlv_u64(_tlv)       (*(uint64 *)tlv_data(_tlv))

#define tlv_i8(_tlv)        (_tlv)->pad
#define tlv_i16(_tlv)       (*(int16 *)tlv_data(_tlv))
#define tlv_i32(_tlv)       (*(int32 *)tlv_data(_tlv))
#define tlv_i64(_tlv)       (*(int64 *)tlv_data(_tlv))

#define tlv_time(_tlv)      (*(tlv_time_t *)tlv_data(_tlv))
#define tlv_duration(_tlv)  (*(tlv_duration_t *)tlv_data(_tlv))

#define tlv_ip4(_tlv)       (*(tlv_ip4_t *)tlv_data(_tlv))
#define tlv_ip6(_tlv)       ((tlv_ip6_t *)tlv_data(_tlv))

#define tlv_binary(_tlv)    tlv_data(_tlv)
#define tlv_string(_tlv)    ((char *)tlv_binary(_tlv))

#define tlv_session(_tlv)       ((tlv_session_t *)tlv_data(_tlv))
#define tlv_session_st(_tlv)    ((tlv_session_st_t *)tlv_data(_tlv))
#define tlv_session_time(_tlv)  ((tlv_session_time_t *)tlv_data(_tlv))
#define tlv_service_st(_tlv)    ((tlv_service_st_t *)tlv_data(_tlv))
#define tlv_tcp(_tlv)           ((tlv_tcp_t *)tlv_data(_tlv))
#define tlv_L7(_tlv)            ((tlv_L7_t *)tlv_data(_tlv))
#define tlv_http(_tlv)          ((tlv_http_t *)tlv_data(_tlv))
#define tlv_sip(_tlv)           ((tlv_sip_t *)tlv_data(_tlv))
#define tlv_rtsp(_tlv)          ((tlv_rtsp_t *)tlv_data(_tlv))

typedef struct {
    int     type;
    uint32  flag;
    uint32  minsize;
    uint32  maxsize;
    char    *name;

    void (*dump)(struct tlv * /*tlv*/);
    int (*check)(struct xparse * /*parse*/, struct tlv * /*tlv*/);
    int (*toxdr)(struct xb * /*x*/, struct tlv * /*tlv*/);
} tlv_ops_t;

static inline bool is_good_tlv_id(int id);

extern tlv_ops_t __tlv_ops[];

static inline tlv_ops_t *
tlv_ops(struct tlv *tlv) 
{
    return is_good_tlv_id(tlv->id)?&__tlv_ops[tlv->id]:NULL;
}

#define tlv_ops_field(_tlv, _field, _deft)  ({  \
    tlv_ops_t *m_ops = tlv_ops(_tlv);   \
                                        \
    m_ops?m_ops->_field:_deft;          \
})

#define tlv_ops_var(_tlv, _field)       tlv_ops_field(_tlv, _field, 0)
#define tlv_ops_string(_tlv, _field)    tlv_ops_field(_tlv, _field, "invalid-tlv-id")

#define tlv_ops_flag(_tlv)              tlv_ops_var(_tlv, flag)
#define tlv_ops_fixed(_tlv)             tlv_ops_var(_tlv, maxsize)
#define tlv_ops_name(_tlv)              tlv_ops_string(_tlv, name)

#define TLV_DUMP( _fmt, _args...)       os_println(__tab  _fmt, ##_args)
#define TLV_DUMP2(_fmt, _args...)       os_println(__tab2 _fmt, ##_args)
#define TLV_DUMP3(_fmt, _args...)       os_println(__tab3 _fmt, ##_args)
#define TLV_DUMP4(_fmt, _args...)       os_println(__tab4 _fmt, ##_args)

#define TLV_DUMP_BY(_tlv, _format, _type) \
    TLV_DUMP("id: %d, %s: " _format, (_tlv)->id, tlv_ops_name(_tlv), tlv_##_type(_tlv))

static inline void
tlv_dump_u8 (struct tlv *tlv)
{
    TLV_DUMP_BY(tlv, "%u", u8); 
}

static inline void
tlv_dump_u16(struct tlv *tlv)
{
    TLV_DUMP_BY(tlv, "%u", u16); 
}

static inline void
tlv_dump_u32(struct tlv *tlv)
{
    TLV_DUMP_BY(tlv, "%u", u32); 
}

static inline void
tlv_dump_u64(struct tlv *tlv)
{
    TLV_DUMP_BY(tlv, "%llu", u64); 
}

static inline void
tlv_dump_string(struct tlv *tlv)
{
    TLV_DUMP_BY(tlv, "%s", string); 
}

#ifndef XDR_DUMP_SIMPLE
#define XDR_DUMP_SIMPLE     128
#endif

static inline void 
tlv_dump_binary(struct tlv *tlv)
{
    if (is_option(OPT_SPLIT)) {
        TLV_DUMP("id: %d, %s: %s", tlv->id, tlv_ops_name(tlv), tlv_string(tlv));
    } else {
        TLV_DUMP("id: %d, %s:", tlv->id, tlv_ops_name(tlv));

        int size = tlv_datalen(tlv);
        if (is_option(OPT_DUMP_SIMPLE)) {
            size = os_min(size, XDR_DUMP_SIMPLE);
        }

        os_dump_buffer(tlv_binary(tlv), size);
    }
}

static inline void 
tlv_dump_time(struct tlv *tlv)
{
    TLV_DUMP("id:%d, %s: %s", tlv->id, tlv_ops_name(tlv), unsafe_time_string(XDR_SECOND(tlv_time(tlv))));
}

static inline void
tlv_dump_duration(struct tlv *tlv) 
{
    tlv_duration_t d = tlv_duration(tlv);
    uint32 s = (uint32)(d>>32);
    uint32 us= (uint32)(d & 0xffffffff);
    
    TLV_DUMP("id:%d, %s %ds:%dus", tlv->id, tlv_ops_name(tlv), s, us); 
}

static inline void 
tlv_dump_ip4(struct tlv *tlv)
{
    uint32 ip = tlv_ip4(tlv); // ip = htonl(ip);
    
    TLV_DUMP("id:%d, %s: %s", tlv->id, tlv_ops_name(tlv), unsafe_ipstring(ip));
}

static inline void 
tlv_dump_ip6(struct tlv *tlv)
{
    TLV_DUMP("id: %d, %s: ipv6 address", tlv->id, tlv_ops_name(tlv));
}

static inline void tlv_dump_session(struct tlv *tlv);
static inline void tlv_dump_session_st(struct tlv *tlv);
#define tlv_dump_service_st    tlv_dump_session_st
static inline void tlv_dump_session_time(struct tlv *tlv);
static inline void tlv_dump_tcp(struct tlv *tlv);
static inline void tlv_dump_L7(struct tlv *tlv);
static inline void tlv_dump_http(struct tlv *tlv);
static inline void tlv_dump_sip(struct tlv *tlv);
static inline void tlv_dump_rtsp(struct tlv *tlv);

static inline int tlv_check_session(struct xparse *parse, struct tlv *tlv);

static inline int to_xdr_session_state(struct xb *x, struct tlv *tlv);
static inline int to_xdr_appid(struct xb *x, struct tlv *tlv);
static inline int to_xdr_session(struct xb *x, struct tlv *tlv);
static inline int to_xdr_session_st(struct xb *x, struct tlv *tlv);
static inline int to_xdr_service_st(struct xb *x, struct tlv *tlv);
static inline int to_xdr_session_time(struct xb *x, struct tlv *tlv);
static inline int to_xdr_tcp(struct xb *x, struct tlv *tlv);
static inline int to_xdr_first_response_delay(struct xb *x, struct tlv *tlv);
static inline int to_xdr_L7(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_host(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_url(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_host_xonline(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_user_agent(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_content(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_refer(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_cookie(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_location(struct xb *x, struct tlv *tlv);
static inline int to_xdr_sip(struct xb *x, struct tlv *tlv);
static inline int to_xdr_sip_calling_number(struct xb *x, struct tlv *tlv);
static inline int to_xdr_sip_called_number(struct xb *x, struct tlv *tlv);
static inline int to_xdr_sip_session_id(struct xb *x, struct tlv *tlv);
static inline int to_xdr_rtsp(struct xb *x, struct tlv *tlv);
static inline int to_xdr_rtsp_url(struct xb *x, struct tlv *tlv);
static inline int to_xdr_rtsp_user_agent(struct xb *x, struct tlv *tlv);
static inline int to_xdr_rtsp_server_ip(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_status(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_user(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_pwd(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_trans_mode(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_trans_type(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_filename(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_filesize(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_response_delay(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ftp_trans_duration(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_msg_type(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_status_code(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_user(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_sender(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_length(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_domain(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_recver(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_hdr(struct xb *x, struct tlv *tlv);
static inline int to_xdr_mail_acs_type(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_domain(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_ip_count(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_ip4(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_ip6(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_response_code(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_count_request(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_count_response_record(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_count_response_auth(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_count_response_extra(struct xb *x, struct tlv *tlv);
static inline int to_xdr_dns_delay(struct xb *x, struct tlv *tlv);

static inline int to_xdr_http_request(struct xb *x, struct tlv *tlv);
static inline int to_xdr_http_response(struct xb *x, struct tlv *tlv);
static inline int to_xdr_file_content(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ssl_server_cert(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ssl_client_cert(struct xb *x, struct tlv *tlv);
static inline int to_xdr_ssl_fail_reason(struct xb *x, struct tlv *tlv);

#define tlv_mapper_fixed(_mapper, _id, _name, _type, _check, _flag) \
    _mapper(_name, _id, TLV_T_##_type, TLV_F_FIXED|_flag, 0, sizeof(tlv_##_type##_t), tlv_dump_##_type, _check, to_xdr_##_name)
#define tlv_mapper_dynamic(_mapper, _id, _name, _type, _check, _flag) \
    _mapper(_name, _id, TLV_T_##_type, _flag, 0, 0, tlv_dump_##_type, _check, to_xdr_##_name)

#define tlv_mapper_object(_mapper, _id, _name, _check, _flag) \
    _mapper(_name, _id, TLV_T_object, TLV_F_FIXED|_flag, 0, sizeof(tlv_##_name##_t), tlv_dump_##_name, _check, to_xdr_##_name)
#define tlv_mapper_nothing(_mapper, _id, _name, _check, _flag) \
    _mapper(_name, _id, TLV_T_string, _flag, 0, 0, NULL, _check, NULL)

#define tlv_mapper_u8( _mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, u8, _check, _flag)
#define tlv_mapper_u16(_mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, u16, _check, _flag)
#define tlv_mapper_u32(_mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, u32, _check, _flag)
#define tlv_mapper_u64(_mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, u64, _check, _flag)
#define tlv_mapper_ip4(_mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, ip4, _check, _flag)
#define tlv_mapper_ip6(_mapper, _id, _name, _check, _flag)  tlv_mapper_fixed(_mapper, _id, _name, ip6, _check, _flag)
#define tlv_mapper_time(_mapper, _id, _name, _check, _flag)     tlv_mapper_fixed(_mapper, _id, _name, time, _check, _flag)
#define tlv_mapper_duration(_mapper, _id, _name, _check, _flag) tlv_mapper_fixed(_mapper, _id, _name, duration, _check, _flag)
#define tlv_mapper_string(_mapper, _id, _name, _check, _flag)   tlv_mapper_dynamic(_mapper, _id, _name, string, _check, _flag)
#define tlv_mapper_binary(_mapper, _id, _name, _check, _flag)   tlv_mapper_dynamic(_mapper, _id, _name, binary, _check, _flag)

#define TLV_MAPPER(_) \
    tlv_mapper_nothing(_,   0,  header,         NULL,   0) \
    \
    tlv_mapper_u8(_,        1,  session_state,  NULL,   0) \
    tlv_mapper_u8(_,        2,  appid,          NULL,   0) \
    tlv_mapper_object(_,    3,  session,        tlv_check_session,  0) \
    tlv_mapper_object(_,    4,  session_st,     NULL,   0) \
    tlv_mapper_object(_,    5,  session_time,   NULL,   0) \
    tlv_mapper_object(_,    6,  service_st,     NULL,   0) \
    tlv_mapper_object(_,    7,  tcp,            NULL,   0) \
    tlv_mapper_u32(_,       8,  first_response_delay,   NULL,   0) \
    tlv_mapper_object(_,    9,  L7,             NULL,   0) \
    tlv_mapper_object(_,    10, http,           NULL,   0) \
    tlv_mapper_string(_,    11, http_host,      NULL,   0) \
    tlv_mapper_string(_,    12, http_url,       NULL,   0) \
    tlv_mapper_string(_,    13, http_host_xonline,      NULL,   0) \
    tlv_mapper_string(_,    14, http_user_agent,NULL,   0) \
    tlv_mapper_string(_,    15, http_content,   NULL,   0) \
    tlv_mapper_string(_,    16, http_refer,     NULL,   0) \
    tlv_mapper_string(_,    17, http_cookie,    NULL,   0) \
    tlv_mapper_string(_,    18, http_location,  NULL,   0) \
    tlv_mapper_object(_,    19, sip,            NULL,   0) \
    tlv_mapper_string(_,    20, sip_calling_number,     NULL,   0) \
    tlv_mapper_string(_,    21, sip_called_number,      NULL,   0) \
    tlv_mapper_string(_,    22, sip_session_id, NULL,   0) \
    tlv_mapper_object(_,    23, rtsp,           NULL,   0) \
    tlv_mapper_string(_,    24, rtsp_url,       NULL,   0) \
    tlv_mapper_string(_,    25, rtsp_user_agent,NULL,   0) \
    tlv_mapper_string(_,    26, rtsp_server_ip, NULL,   0) \
    tlv_mapper_u16(_,       27, ftp_status,     NULL,   0) \
    tlv_mapper_string(_,    28, ftp_user,       NULL,   0) \
    tlv_mapper_string(_,    29, ftp_pwd,        NULL,   0) \
    tlv_mapper_u8(_,        30, ftp_trans_mode, NULL,   0) \
    tlv_mapper_u8(_,        31, ftp_trans_type, NULL,   0) \
    tlv_mapper_string(_,    32, ftp_filename,   NULL,   0) \
    tlv_mapper_u32(_,       33, ftp_filesize,   NULL,   0) \
    tlv_mapper_duration(_,  34, ftp_response_delay,     NULL,   0) \
    tlv_mapper_duration(_,  35, ftp_trans_duration,     NULL,   0) \
    tlv_mapper_u16(_,       36, mail_msg_type,  NULL,   0) \
    tlv_mapper_u16(_,       37, mail_status_code,       NULL,   0) \
    tlv_mapper_string(_,    38, mail_user,      NULL,   0) \
    tlv_mapper_string(_,    39, mail_sender,    NULL,   0) \
    tlv_mapper_u32(_,       40, mail_length,    NULL,   0) \
    tlv_mapper_string(_,    41, mail_domain,    NULL,   0) \
    tlv_mapper_string(_,    42, mail_recver,    NULL,   0) \
    tlv_mapper_string(_,    43, mail_hdr,       NULL,   0) \
    tlv_mapper_u8(_,        44, mail_acs_type,  NULL,   0) \
    tlv_mapper_string(_,    45, dns_domain,     NULL,   0) \
    tlv_mapper_u8(_,        46, dns_ip_count,   NULL,   0) \
    tlv_mapper_ip4(_,       47, dns_ip4,        NULL,   TLV_F_MULTI) \
    tlv_mapper_ip6(_,       48, dns_ip6,        NULL,   TLV_F_MULTI) \
    tlv_mapper_u8(_,        49, dns_response_code,      NULL,   0) \
    tlv_mapper_u8(_,        50, dns_count_request,      NULL,   0) \
    tlv_mapper_u8(_,        51, dns_count_response_record,  NULL,   0) \
    tlv_mapper_u8(_,        52, dns_count_response_auth,    NULL,   0) \
    tlv_mapper_u8(_,        53, dns_count_response_extra,   NULL,   0) \
    tlv_mapper_u32(_,       54, dns_delay,      NULL,   0) \
    \
    tlv_mapper_binary(_,    201,http_request,   NULL,   TLV_F_HTTP_REQUEST) \
    tlv_mapper_binary(_,    202,http_response,  NULL,   TLV_F_HTTP_RESPONSE) \
    tlv_mapper_binary(_,    203,file_content,   NULL,   TLV_F_FILE_CONTENT) \
    tlv_mapper_binary(_,    204,ssl_server_cert,NULL,   TLV_F_MULTI|TLV_F_SSL_SERVER_CERT) \
    tlv_mapper_binary(_,    205,ssl_client_cert,NULL,   TLV_F_MULTI|TLV_F_SSL_CLIENT_CERT) \
    tlv_mapper_u8(_,        206,ssl_fail_reason,NULL,   0) \
    /* end */

#if 0
    tlv_mapper_u8(_,        55, vpn_type,       NULL,   0) \
    tlv_mapper_u8(_,        56, proxy_type,     NULL,   0) \
    tlv_mapper_u32(_,       57, app_proto,      NULL,   0) \
    tlv_mapper_u64(_,       58, vpn,            NULL,   0) \
    tlv_mapper_u8(_,        59, dns_pkt_valid,  NULL,   0) \
    tlv_mapper_string(_,    60, qq_number,      NULL,   0) \
    tlv_mapper_u8(_,        61, pkt_dir,        NULL,   0) \
    /* end */
#endif

#define tlv_id_low_end      55
#define tlv_id_high_begin   201

#define __TLV_ENUM(_name, _id, _type, _flag, _minsize, _maxsize, _dump, _check, _toxdr)  tlv_id_##_name = _id,
enum { TLV_MAPPER(__TLV_ENUM) tlv_id_end };

// just for source insight
#define tlv_id_header          tlv_id_header
#define tlv_id_appid           tlv_id_appid
#define tlv_id_file_content    tlv_id_file_content
#define tlv_id_http_request    tlv_id_http_request
#define tlv_id_http_response   tlv_id_http_response
#define tlv_id_ssl_server_cert tlv_id_ssl_server_cert
#define tlv_id_ssl_client_cert tlv_id_ssl_client_cert
#define tlv_id_dns_ip4         tlv_id_dns_ip4
#define tlv_id_dns_ip6         tlv_id_dns_ip6
#define tlv_id_end             tlv_id_end

static inline bool
is_good_tlv_id(int id)
{
    return is_good_value(id, 0, tlv_id_low_end) 
        || is_good_value(id, tlv_id_high_begin, tlv_id_end);
}

#define __TLV_STRUCT(_name, _id, _type, _flag, _minsize, _maxsize, _dump, _check, _toxdr) [_id] = { \
    .type   = _type,    \
    .flag   = _flag,    \
    .name   = #_name,   \
    .minsize= _minsize, \
    .maxsize= _maxsize, \
    .dump   = _dump,    \
    .check  = _check,   \
    .toxdr  = _toxdr,   \
},  /* end */
#define DECLARE_TLV_VARS \
    tlv_ops_t __tlv_ops[tlv_id_end] = { TLV_MAPPER(__TLV_STRUCT) }; \
    os_fake_declare /* end */

#if 0
      |<-filename    |<-suffix
/path/xxxxxxxxxxxxxx.xdr
|<------fullname------>|
#endif

typedef struct {
    char fullname[1+OS_FILENAME_LEN];
    char *filename;
    char *suffix;
} xpath_t;

static inline void
xpath_init(xpath_t *path, char *dir)
{
    int len = strlen(dir);

    memcpy(path->fullname, dir, len);
    if ('/' != dir[len-1]) {
        path->fullname[len++] = '/';
    }
    path->filename = path->fullname + len;
}

static inline char *
xpath_fill(xpath_t *path, char *filename, int namelen)
{
    os_strmcpy(path->filename, filename, namelen);
    
    path->suffix = path->filename + namelen - (sizeof(ERR_SUFFIX) - 1);
    
    return path->fullname;
}

static inline char *
xpath_change(xpath_t *path, char *suffix)
{
    // xxx.xdr <==> xxx.err
    *(uint32 *)path->suffix = *(uint32 *)suffix;
    
    return path->fullname;
}

#ifndef TLV_CACHE_MULTI
#define TLV_CACHE_MULTI    31
#endif

typedef struct {
    int count;

    struct tlv *multi[TLV_CACHE_MULTI];
} tlv_cache_t;

typedef struct {
    struct xparse *parse;
    int count;
    
    tlv_cache_t cache[tlv_id_end];
} tlv_record_t;
#define TLV_RECORD_INITER(_parse)   { .parse = _parse }

struct xb {
    struct xparse *parse;
    char *fullname;
    int fd;

    union {
        void *header;
        
        struct tlv *tlv;
        struct xdr *xdr;
    } u;

    xdr_size_t      size;       // include struct xdr/tlv header
    xdr_offset_t    current;    // include struct xdr/tlv header
};
#define XBUFFER_INITER(_fullname)   {   \
    .fullname   = _fullname,            \
    .fd         = -1,                   \
    .current    = sizeof(struct xdr),   \
} /* end */

static inline int
xb_mmap(struct xb *x, bool readonly)
{
    int prot = readonly?PROT_READ:(PROT_READ|PROT_WRITE);
    int flag = readonly?MAP_PRIVATE:MAP_SHARED;
    int err;
    
    if (!readonly) {
        err = ftruncate(x->fd, x->size);
        if (err<0) {
            os_println("ftruncate %s size:%d error:%d ...", x->fullname, x->size, -errno);
        
            return -errno;
        }
    }

    x->u.header = os_mmap(x->size, prot, flag, x->fd, 0);
    if (NULL==x->u.header) {
        os_println("mmap %s error:%d ...", x->fullname, -errno);
        
        return -errno;
    }

    return 0;
}

static inline int
xb_munmap(struct xb *x)
{
    if (x->u.header) {
        int err = os_munmap(x->u.header, x->size);
        if (err<0) {
            os_println("munmap %s error:%d ...", x->fullname, -errno);
            
            return -errno;
        }
    }

    return 0;
}

static inline int
xb_close(struct xb *x)
{
    os_close(x->fd);
    
    return xb_munmap(x);
}

static inline int
xb_open(struct xb *x, bool readonly, int size)
{
    int flag = readonly?O_RDONLY:(O_CREAT|O_RDWR);

    x->fd = open(x->fullname, flag|O_CLOEXEC, 0664);
    if (x->fd<0) {
        os_println("open %s error:%d ...", x->fullname, -errno);
        
        return -errno;
    }

    x->size = (xdr_size_t)size;
    
    return xb_mmap(x, readonly);
}

struct xparse {
    char *name;     // just filename, not include path
    int namelen;    // just filename, not include path
    
    xpath_t *path;  // xpath_t path[PATH_END];
    
    int count;      // tlv count
    struct xb tlv;
    struct xb xdr;
};

#define XPARSE_INITER(_path, _name, _namelen)              {    \
    .name       = _name,                                        \
    .namelen    = _namelen,                                     \
    .path       = _path,                                        \
    .tlv        = XBUFFER_INITER((_path)[PATH_TLV].filename),   \
    .xdr        = XBUFFER_INITER((_path)[PATH_XDR].filename),   \
}   /* end */

static inline int
tlv_open(struct xb *x, int size)
{
    return xb_open(x, true, size);
}

static inline int
tlv_close(struct xb *x)
{
    return xb_close(x);
}

static inline int xdr_open(struct xb *x, int size);
static inline int xdr_close(struct xb *x);

static inline void
xp_init(struct xparse *parse)
{
    parse->tlv.parse = parse;
    parse->xdr.parse = parse;

    xpath_fill(&parse->path[PATH_TLV], parse->name, parse->namelen);
    xpath_fill(&parse->path[PATH_XDR], parse->name, parse->namelen);
}

static inline int
xp_close(struct xparse *parse)
{
    tlv_trace(tlv_close(&parse->tlv), "tlv_close");
    tlv_trace(xdr_close(&parse->xdr), "xdr_close");

    return 0;
}

static inline int
xp_open(struct xparse *parse)
{
    struct xb *tlv = &parse->tlv;
    struct xb *xdr = &parse->xdr;
    int size, err;

    size = os_fsize(tlv->fullname);
    if (size<0) {
        return size;
    }

    err = tlv_trace(tlv_open(tlv, size), "tlv_open %s:%d", tlv->fullname, size);
    if (err<0) {
        return err;
    }

    size = XDR_EXPAND_ALIGN(size);
    err = tlv_trace(xdr_open(xdr, size), "xdr_open %s:%d", xdr->fullname, size);
    if (err<0) {
        return err;
    }

    return 0;
}

static inline void
xp_verror(FILE *stream, struct xparse *parse, struct tlv *tlv, int err, const char *fmt, va_list args)
{
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);

    fprintf(stream, __crlf __tab 
        "ERROR:%d tlv name:%s id:%d extend:%d fixed:%d pad:%d alen:%u hlen:%u dlen:%u" __crlf, 
        err,
        tlv_ops_name(tlv), 
        tlv->id, 
        tlv_extend(tlv),
        tlv_ops_fixed(tlv),
        tlv->pad, 
        tlv_len(tlv),
        tlv_hdrlen(tlv),
        tlv_datalen(tlv));
}

static inline void
xp_error(struct xparse *parse, struct tlv *tlv, int err, const char *fmt, ...)
{
    va_list args;
    char *fullname;

    va_start(args, fmt);
    xp_verror(stdout, parse, tlv, err, fmt, args);
    va_end(args);

    xp_close(parse);

    fullname = parse->xdr.fullname;
    {
        remove(fullname);
    }

    fullname = parse->tlv.fullname;
    {
        xpath_t *path = &parse->path[PATH_BAD];
        
        xpath_fill(path, parse->name, parse->namelen);

        // log
        xpath_change(path, ERR_SUFFIX);
        FILE *stream = fopen(fullname, "a+");
            va_start(args, fmt);
            xp_verror(stream, parse, tlv, err, fmt, args);
            va_end(args);
        fclose(stream);
        
        // move tlvs/xxx.xdr ==> bad/xxx.err
        xpath_change(path, XDR_SUFFIX);
        rename(fullname, path->fullname);
    }
}

typedef int tlv_walk_t(struct xparse *parse, struct tlv *tlv);

static inline int
tlv_walk(struct xparse *parse, struct tlv *tlv, uint32 left, tlv_walk_t *walk)
{
    int err;

    if (left > TLV_MAXDATA) {
        return xp_error(parse, tlv, -ETOOBIG, "too big:%d", left);
    }
    
    while(left>0) {
        if (parse->count > TLV_MAXCOUNT) {
            return xp_error(parse, tlv, -ETOOMORE, "too more tlv:%d", parse->count);
        }
        else if (left < tlv_hdrlen(tlv)) {
            return xp_error(parse, tlv, -ETOOSMALL, "left:%d < tlv hdrlen:%d", left, tlv_hdrlen(tlv));
        }
        else if (left < tlv_len(tlv)) {
            return xp_error(parse, tlv, -ETOOSMALL, "left:%d < tlv len:%d", left, tlv_len(tlv));
        }
        
        err = (*walk)(parse, tlv);
        if (err<0) {
            os_println("break walk!!!");
            return err;
        }

        left -= tlv_len(tlv); tlv = tlv_next(tlv);
    }

    return 0;
}

static inline void
tlv_dump(struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv);

    if (ops && ops->dump) {
        (*ops->dump)(tlv);
    }
}

static inline int
tlv_check_fixed(struct xparse *parse, struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv); // not NULL
    uint32 dlen = tlv_datalen(tlv);
    
    switch (ops->type) {
        case TLV_T_u8:
            if (0 != dlen) {
                return xp_error(parse, tlv, -EINVAL9, "tlv check fixed i8");
            }
            
            break;
        case TLV_T_u16:
            if (sizeof(uint32) != dlen) {
                return xp_error(parse, tlv, -EINVAL8, "tlv check fixed i16");
            }

            break;
        default:
            if (is_option(OPT_STRICT)) {
                if (dlen != ops->maxsize) {
                    return xp_error(parse, tlv, -EINVAL7, "tlv check fixed[strict] other");
                }
            } else {
                if (dlen < ops->maxsize) {
                    return xp_error(parse, tlv, -EINVAL7, "tlv check fixed[loose] other");
                }
            }
            

            break;
    }

    return 0;
}

static inline int
tlv_check_dynamic(struct xparse *parse, struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv); // not NULL
    uint32 dlen = tlv_datalen(tlv);
    
    if (ops->minsize && dlen < ops->minsize) {
        return xp_error(parse, tlv, -ETOOSMALL, "tlv check dynamic too small");
    }
    else if (ops->maxsize && dlen > ops->maxsize) {
        return xp_error(parse, tlv, -ETOOBIG, "tlv check dynamic too big");
    }
#if 0
    else if (tlv_datalen(tlv) < tlv->pad) {
        return xp_error(parse, tlv, -ETOOBIG, "tlv check dynamic too big pad");
    }
#endif

    return 0;
}

static inline int
tlv_check(struct xparse *parse, struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv);
    if (NULL==ops) {
        return xp_error(parse, tlv, -EBADIDX, "not support tlv id:%d", tlv->id);
    }
    else if (tlv_len(tlv) < tlv_hdrlen(tlv)) {
        return xp_error(parse, tlv, -ETOOSMALL, "tlv check too small");
    }
    
    if (tlv_extend(tlv)) {
        if (tlv_len(tlv) < 4096 && is_option(OPT_STRICT)) {
            return xp_error(parse, tlv, -EPROTOCOL, "tlv[extend] too small len:%d", tlv_len(tlv));
        }
    }

    switch(ops->type) {
        case TLV_T_string:
        case TLV_T_binary:
            if (tlv_datalen(tlv) < tlv->pad) {
                return xp_error(parse, tlv, -EPROTOCOL, "tlv[extend] datalen:%d < pad:%d", tlv_datalen(tlv), tlv->pad);
            }
    }

    if (ops->check) {
        int err = (*ops->check)(tlv);
        if (err<0) {
            return err;
        }
    }

    if (TLV_F_FIXED & ops->flag) {
        // use default checker
        return tlv_check_fixed(parse, tlv);
    } else {
        return tlv_check_dynamic(parse, tlv);
    }
}

enum { XDR_IPV4 = 0, XDR_IPV6 = 1 };

#ifndef sizeof_session
#define sizeof_session  40
#endif

typedef struct {
    byte ver;
    byte dir;
    byte proto;
    byte _;
    
    uint16 sport;
    uint16 dport;
    
    xdr_ipaddr_t sip;
    xdr_ipaddr_t dip;
} tlv_session_t, xdr_session6_t;

enum { XDR_SESSION_HSIZE = sizeof(tlv_session_t) - 2*sizeof(xdr_ipaddr_t) };

static inline void 
tlv_dump_session(struct tlv *tlv)
{
    tlv_session_t *obj = tlv_session(tlv);
    
    TLV_DUMP("id: %d, session:", tlv->id);
    
    TLV_DUMP2("version: %d", obj->ver);
    TLV_DUMP2("dir    : %d", obj->dir);
    TLV_DUMP2("proto  : %d", obj->proto);
    TLV_DUMP2("sport  : %d", obj->sport);
    TLV_DUMP2("dport  : %d", obj->dport);

    if (XDR_IPV4==obj->ver) {
        uint32 ip;

        ip = XDR_IP(&obj->sip); // ip = htonl(ip);
        TLV_DUMP2("sip    : %s", unsafe_ipstring(ip));
        
        ip = XDR_IP(&obj->dip); // ip = htonl(ip);
        TLV_DUMP2("dip    : %s", unsafe_ipstring(ip));
    } else {
        TLV_DUMP2("sip    : ipv6 address");
        TLV_DUMP2("dip    : ipv6 addres");
    }
}

#ifndef sizeof_session_st
#define sizeof_session_st   44
#endif

#ifndef sizeof_service_st
#define sizeof_service_st   sizeof_session_st
#endif

typedef struct {
    uint32 flow[2];
    uint32 ip_packet[2];
    uint32 tcp_disorder[2];
    uint32 tcp_retransmit[2];
    uint32 ip_frag[2];
    
    uint16 duration[2];
} tlv_session_st_t, tlv_service_st_t, xdr_session_st_t, xdr_service_st_t;

static inline void 
tlv_dump_session_st(struct tlv *tlv)
{
    tlv_session_st_t *obj = tlv_session_st(tlv);
    int i;
    
    TLV_DUMP("id: %d, %s:", tlv->id, tlv_ops_name(tlv));

    for (i=0; i<2; i++) {
        char c = (0==i)?'u':'d';
        
        TLV_DUMP2("[%c]flow            : %d", c, obj->flow[i]);
        TLV_DUMP2("[%c]ip_packet       : %d", c, obj->ip_packet[i]);
        TLV_DUMP2("[%c]tcp_disorder    : %d", c, obj->tcp_disorder[i]);
        TLV_DUMP2("[%c]tcp_retransmit  : %d", c, obj->tcp_retransmit[i]);
        TLV_DUMP2("[%c]ip_frag         : %d", c, obj->ip_frag[i]);
        TLV_DUMP2("[%c]duration        : %d", c, obj->duration[i]);
    }
}

#ifndef sizeof_session_time
#define sizeof_session_time 24
#endif

typedef struct {
    tlv_time_t create;
    tlv_time_t start;
    tlv_time_t stop;
} tlv_session_time_t, xdr_session_time_t;

static inline void 
tlv_dump_session_time(struct tlv *tlv)
{
    tlv_session_time_t *obj = tlv_session_time(tlv);
    
    TLV_DUMP("id: %d, session_time:", tlv->id);
    
    TLV_DUMP2("create: %s", unsafe_time_string(XDR_SECOND(obj->create)));
    TLV_DUMP2("start : %s", unsafe_time_string(XDR_SECOND(obj->start)));
    TLV_DUMP2("stop  : %s", unsafe_time_string(XDR_SECOND(obj->stop)));
}

#ifndef sizeof_tcp
#define sizeof_tcp      28
#endif

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
tlv_tcp_t, xdr_tcp_t;

enum { XDR_TCP_COMPLETE = 1 };

static inline void 
tlv_dump_tcp(struct tlv *tlv)
{
    tlv_tcp_t *obj = tlv_tcp(tlv);
    
    TLV_DUMP("id: %d, tcp:", tlv->id);
    
    TLV_DUMP2("synack_to_syn_time  : %u us", obj->synack_to_syn_time);
    TLV_DUMP2("ack_to_syn_time     : %u us", obj->ack_to_syn_time);
    TLV_DUMP2("complete            : %s", bool_string(XDR_TCP_COMPLETE==obj->complete));
    TLV_DUMP2("close_reason        : %d", obj->close_reason);
    TLV_DUMP2("first_request_delay : %u ms", obj->first_request_delay);
    TLV_DUMP2("first_response_delay: %u ms", obj->first_response_delay);
    TLV_DUMP2("window              : %u", obj->window);
    TLV_DUMP2("mss                 : %u", obj->mss);
    TLV_DUMP2("count_retry         : %u", obj->count_retry);
    TLV_DUMP2("count_retry_ack     : %u", obj->count_retry_ack);
    TLV_DUMP2("count_ack           : %u", obj->count_ack);
    TLV_DUMP2("connect_status      : %u", obj->connect_status);
    TLV_DUMP2("handshake12         : %s", success_string(0==obj->handshake12));
    TLV_DUMP2("handshake23         : %s", success_string(0==obj->handshake23));
}

#ifndef sizeof_L7
#define sizeof_L7   4
#endif

typedef struct {
    byte status;
    byte class;
    uint16 protocol;
} tlv_L7_t, xdr_L7_t;

static inline void 
tlv_dump_L7(struct tlv *tlv)
{
    tlv_L7_t *obj = tlv_L7(tlv);
    
    TLV_DUMP("id: %d, L7:", tlv->id);
    
    TLV_DUMP2("status  : %u", obj->status);
    TLV_DUMP2("class   : %u", obj->class);
    TLV_DUMP2("protocol: %u", obj->protocol);
}

#ifndef sizeof_http
#define sizeof_http     44
#endif

typedef struct {
    xdr_time_t time_request;
    xdr_time_t time_first_response;
    xdr_time_t time_last_content;
    xdr_duration_t service_delay;
    
    uint32 content_length;
    
    uint16 status_code;
    byte method;
    byte version;

    byte _0:2;
    byte head:1;
    byte flag:3;
    byte first:2;
    byte ie;
    byte portal;
    byte _1;
}
tlv_http_t;

#if 0 // little endian
 00 01 02 03 04 05 06 07
+--+--+--+--+--+--+--+--+
|  R  |H |  flag  |first|
+--+--+--+--+--+--+--+--+
R: resv
H: head

#define TLV_MASK_HTTP_FIRST     0xc0
#define TLV_MASK_HTTP_FLAG      0x38
#define TLV_MASK_HTTP_HEAD      0x04

static inline int
tlv_http_first(tlv_http_t *obj)
{
    return (obj->v & TLV_MASK_HTTP_FIRST) >> 6;
}

static inline int
tlv_http_flag(tlv_http_t *obj)
{
    return (obj->v & TLV_MASK_HTTP_FLAG) >> 3;
}

static inline int
tlv_http_head(tlv_http_t *obj)
{
    return (obj->v & TLV_MASK_HTTP_HEAD) >> 2;
}
#endif

static inline void 
tlv_dump_http(struct tlv *tlv)
{
    tlv_http_t *obj = tlv_http(tlv);
    
    TLV_DUMP("id: %d, http:", tlv->id);
    
    TLV_DUMP2("time_request        : %s", unsafe_time_string(XDR_SECOND(obj->time_request)));
    TLV_DUMP2("time_first_response : %s", unsafe_time_string(XDR_SECOND(obj->time_first_response)));
    TLV_DUMP2("time_last_content   : %s", unsafe_time_string(XDR_SECOND(obj->time_last_content)));
    TLV_DUMP2("service_delay       : %llu us", obj->service_delay);
    TLV_DUMP2("content_length      : %u", obj->content_length);
    TLV_DUMP2("status_code         : %u", obj->status_code);
    TLV_DUMP2("method              : %u", obj->method);
    TLV_DUMP2("version             : %u", obj->version);

    TLV_DUMP2("first               : %s", bool_string(obj->first));
    TLV_DUMP2("flag                : %u", obj->flag);
    TLV_DUMP2("head                : %s", bool_string(obj->head));
    TLV_DUMP2("ie                  : %u", obj->ie);
    TLV_DUMP2("portal              : %u", obj->portal);
}

enum { XDR_SIP_INVITE = 1 };
enum { XDR_SIP_BYE = 1 };

#ifndef sizeof_sip
#define sizeof_sip      8
#endif

typedef struct {
    byte call_direction;
    byte call_type;
    byte hangup_reason;
    byte signal_type;
    
    uint16 dataflow_count;
    uint16 _:13;
    uint16 malloc:1;
    uint16 bye:1;
    uint16 invite:1;
} tlv_sip_t;

static inline void 
tlv_dump_sip(struct tlv *tlv)
{
    tlv_sip_t *obj = tlv_sip(tlv);

    TLV_DUMP("id: %d, http:", tlv->id);

    TLV_DUMP2("call_direction  : %u", obj->call_direction);
    TLV_DUMP2("call_type       : %u", obj->call_type);
    TLV_DUMP2("hangup_reason   : %u", obj->hangup_reason);
    TLV_DUMP2("signal_type     : %u", obj->signal_type);
    TLV_DUMP2("dataflow_count  : %u", obj->dataflow_count);
    TLV_DUMP2("invite          : %s", bool_string(XDR_SIP_INVITE==obj->invite));
    TLV_DUMP2("bye             : %s", bool_string(XDR_SIP_BYE==obj->bye));
    TLV_DUMP2("malloc          : %s", bool_string(obj->malloc));
}

#ifndef sizeof_rtsp
#define sizeof_rtsp     16
#endif

typedef struct {
    uint16 port_client_start;
    uint16 port_client_end;
    uint16 port_server_start;
    uint16 port_server_end;
    uint16 count_video;
    uint16 count_audio;
    
    uint32 describe_delay;
} tlv_rtsp_t;

static inline void 
tlv_dump_rtsp(struct tlv *tlv)
{
    tlv_rtsp_t *obj = tlv_rtsp(tlv);
    
    TLV_DUMP("id: %d, http:", tlv->id);
    
    TLV_DUMP2("port_client_start   : %u", obj->port_client_start);
    TLV_DUMP2("port_client_end     : %u", obj->port_client_end);
    TLV_DUMP2("port_server_start   : %u", obj->port_server_start);
    TLV_DUMP2("port_server_end     : %u", obj->port_server_end);
    TLV_DUMP2("count_video         : %u", obj->count_video);
    TLV_DUMP2("count_audio         : %u", obj->count_audio);
    TLV_DUMP2("describe_delay      : %u", obj->describe_delay);
}

static inline int
tlv_check_session(struct xparse *parse, struct tlv *tlv)
{
    tlv_session_t *obj = tlv_session(tlv);
    
    switch (obj->proto) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            return 0;
        case IPPROTO_ICMP:
        case IPPROTO_IGMP:
        case IPPROTO_IPIP:
        case IPPROTO_GRE:
        case IPPROTO_ESP:
        case IPPROTO_AH:
            if (!is_option(OPT_STRICT)) {
                return 0;
            }
    }

    int err = -ENOSUPPORT;
    xp_error(parse, tlv, err, "no support ip proto:%d", obj->proto);
    tlv_dump_session(tlv);

    return err;
}

static inline int
tlv_cache_save(struct xparse *parse, tlv_cache_t *cache, struct tlv *tlv)
{
    tlv_dprint("tlv_cache_save ...");
    if (cache->count < TLV_CACHE_MULTI) {
        if (0==cache->count) {
            cache->multi[cache->count++] = tlv;
        }
        else if (TLV_F_MULTI & tlv_ops_flag(tlv)) {
            cache->multi[cache->count++] = tlv;
        }
        else {
            tlv_dprint("tlv_cache_save ENOSUPPORT.");
            
            return xp_error(parse, tlv, -ENOSUPPORT, "not support cache multi");
        }
    }
    else {
        tlv_dprint("tlv_cache_save ENOSPACE.");
        return xp_error(parse, tlv, -ENOSPACE, "too more cache multi");
    }
    
    tlv_dprint("tlv_cache_save ok.");

    return 0;
}

static inline int
tlv_record_save(tlv_record_t *r, struct tlv *tlv)
{
    tlv_cache_t *cache = &r->cache[tlv->id];

    int err = tlv_trace(tlv_cache_save(r->parse, cache, tlv), "tlv_record_save");
    if (err<0) {
        return err;
    }
    
    r->count++;
    
    return 0;
}

static inline int
tlv_record_parse(tlv_record_t *r)
{
    int walk(struct xparse *parse, struct tlv *tlv) 
    {
        int err;

        err = tlv_trace(tlv_check(parse, tlv), "tlv_check %d", parse->count);
        if (err<0) {
            return err;
        }

        err = tlv_trace(tlv_record_save(r, tlv), "tlv_record_save %d", parse->count);
        if (err<0) {
            return err;
        }

        if (is_option(OPT_DUMP)) {
            tlv_dump(tlv);
        }
        
        return 0;
    }

    struct tlv *header = r->parse->tlv.u.header;
    
    return tlv_walk(r->parse, tlv_first(header), tlv_datalen(header), walk);
}

#ifndef TLV_CHECK_OBJ
#define TLV_CHECK_OBJ(_name)    BUILD_BUG_ON(sizeof(tlv_##_name##_t) != sizeof_##_name)
#endif

static inline void
tlv_check_obj(void) 
{
    TLV_CHECK_OBJ(session);
    TLV_CHECK_OBJ(session_st);
    TLV_CHECK_OBJ(session_time);
    TLV_CHECK_OBJ(service_st);
    TLV_CHECK_OBJ(tcp);
    TLV_CHECK_OBJ(L7);
    TLV_CHECK_OBJ(http);
    TLV_CHECK_OBJ(sip);
    TLV_CHECK_OBJ(rtsp);
}
/******************************************************************************/
#endif /* __TLV_H_d203748a8a974e6282d89ddcde27123a__ */
