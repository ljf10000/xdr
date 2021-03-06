#ifndef __TLV_H_d203748a8a974e6282d89ddcde27123a__
#define __TLV_H_d203748a8a974e6282d89ddcde27123a__
/******************************************************************************/
#include "os.h"
/******************************************************************************/
#ifndef TLV_MAXDATA
#define TLV_MAXDATA     (128*1024*1024)
#endif

#ifndef TLV_MAXCOUNT
#define TLV_MAXCOUNT    (128*1024)
#endif

#ifndef DUMP_STREAM
#define DUMP_STREAM     stdout
#endif

#ifndef DUMP_SHORT
#define DUMP_SHORT      32
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

#ifndef XDR_USLEEP
#define XDR_USLEEP      (100*1000)
#endif

#ifndef WORKER_COUNT
#define WORKER_COUNT    32
#endif

#ifndef QUE_COUNT
#define QUE_COUNT       (8*1024)
#endif

#ifndef EVBUFSIZE
#define EVBUFSIZE       (4*1024-sizeof(int32))
#endif

#define XDR_ALIGN(x)        OS_ALIGN(x, 4)
#define XDR_EXPAND_ALIGN(x) OS_ALIGN(x + XDR_EXPAND, XDR_EXPAND)
#define XDR_DIGEST_SIZE     SHA256_DIGEST_SIZE

struct xb;
struct tlv;
struct xdr;
struct xparse;

#define INVALID_XDR_OFFSET  0

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

typedef FILE *xw_stream_t(int /* wid */);

extern xw_stream_t *xw_stream;

extern int DumpTlvString;
extern int DumpTlvBinary;

static inline void
xw_trace(int wid, const char *fmt, ...)
{
    va_list args;
    FILE *f;

    if (xw_stream && (f = (*xw_stream)(wid))) {
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);

        fflush(f);
    }
}

#define tlv_dprint(_wid, _fmt, _args...)    do{if (is_option(OPT_TRACE_TLV)) { xw_trace(_wid, _fmt __crlf, ##_args); }}while(0)
#define xdr_dprint(_wid, _fmt, _args...)    do{if (is_option(OPT_TRACE_XDR)) { xw_trace(_wid, _fmt __crlf, ##_args); }}while(0)

#ifndef xw_trace_by
#define xw_trace_by(_call, _wid, _is_trace, _fmt, _args...) ({  \
    int m_err, m_wid = _wid;                    \
    bool m_is_trace = _is_trace;                \
                                                \
    if (m_is_trace) {                           \
        xw_trace(m_wid, _fmt " ..." __crlf, ##_args); \
    }                                           \
                                                \
    m_err = (_call);                            \
                                                \
    if (m_is_trace) {                           \
        xw_trace(m_wid, "%s:%d " _fmt __crlf2, ok_string(m_err), m_err, ##_args); \
    }                                           \
                                                \
    m_err;                                      \
})  /* end */
#endif

#define tlv_trace(_call, _wid, _fmt, _args...)  xw_trace_by(_call, _wid, is_option(OPT_TRACE_TLV), _fmt, ##_args)
#define xdr_trace(_call, _wid, _fmt, _args...)  xw_trace_by(_call, _wid, is_option(OPT_TRACE_XDR), _fmt, ##_args)

typedef uint32 xdr_ip4_t, tlv_ip4_t;
typedef struct {
    uint32 ip[4];
} xdr_ipaddr_t, xdr_ip6_t, tlv_ip6_t;
#define XDR_IP(_addr)   (_addr)->ip[0]

enum {
    PATH_TLV = 0,
    PATH_XDR = 1,
    PATH_SHA = 2,
    PATH_BAD = 3,
    
    PATH_END
};

enum {
    OPT_DUMP        = 0x0001,
    OPT_DUMP_SB     = 0x0002 | OPT_DUMP,
    OPT_DUMP_PRE    = 0x0004 | OPT_DUMP,
    OPT_DUMP_ST     = 0x0008,
    OPT_DUMP_EV     = 0x0010,
    OPT_DUMP_QUE    = 0x0020,
    OPT_DUMP_ERR    = 0x0040,
    OPT_DUMP_INIT   = 0x0080,
    
    OPT_CLI         = 0x0001<<16,
    OPT_IP6         = 0x0002<<16,
    OPT_MULTI       = 0x0004<<16,
    OPT_STRICT      = 0x0008<<16,
    
    OPT_TRACE_TLV   = 0x0010<<16,
    OPT_TRACE_XDR   = 0x0020<<16,
    
    OPT_SPLIT       = 0x1000<<16,
};

#define option_dump_error(_fmt, _args...)   option_dump(OPT_DUMP_ERR,   _fmt, ##_args)
#define option_dump_init(_fmt, _args...)    option_dump(OPT_DUMP_INIT,  _fmt, ##_args)

enum {
    TLV_F_MULTI             = 0x0001,
    TLV_F_FIXED             = 0x0002,
    
    TLV_F_HTTP_REQUEST      = 0x0010,
    TLV_F_HTTP_RESPONSE     = 0x0020,
    TLV_F_SSL_SERVER_CERT   = 0x0100,
    TLV_F_SSL_CLIENT_CERT   = 0x0200,
    TLV_F_FILE_CONTENT      = 0x1000,

    TLV_F_HTTP              = TLV_F_HTTP_REQUEST|TLV_F_HTTP_RESPONSE,
    TLV_F_CERT              = TLV_F_SSL_SERVER_CERT|TLV_F_SSL_CLIENT_CERT,
    
    TLV_F_FILE              = TLV_F_FILE_CONTENT|TLV_F_HTTP|TLV_F_CERT,
};

static inline const char *
tlv_flag_to_dir(int flag)
{
    static nameflag_t opt[] = {
        { .flag = TLV_F_FILE_CONTENT,   .name = "file" },
        { .flag = TLV_F_HTTP,           .name = "http" },
        { .flag = TLV_F_CERT,           .name = "cert" },
    };

    return get_nameflag_byflag(opt, flag);
}

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

#define TLV_T_u8        TLV_T_u8
#define TLV_T_u16       TLV_T_u16
#define TLV_T_string    TLV_T_string
#define TLV_T_binary    TLV_T_binary
#define TLV_T_object    TLV_T_object
#define TLV_T_END       TLV_T_END
#endif


#if 0 /* normal format */
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           id          |          pad          | 0|reserve |              len                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             body ...
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

#if 0 /* extend format */
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           id          |          pad          | 1|                   reserve                  |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                              len                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             body ...
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
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

#define tlv_len_n(_tlv)         ((uint32)(_tlv)->len)
#define tlv_len_e(_tlv)         (*(uint32 *)(_tlv)->body)
#define tlv_len(_tlv)           (tlv_extend(_tlv)?tlv_len_e(_tlv):tlv_len_n(_tlv))
#define tlv_next(_tlv)          (struct tlv *)((byte *)(_tlv) + tlv_len(_tlv))

#define tlv_hdrlen_n            ((uint32)(sizeof(struct tlv)))
#define tlv_hdrlen_e            ((uint32)(sizeof(struct tlv)+sizeof(uint32)))
#define tlv_hdrlen(_tlv)        (tlv_extend(_tlv)?tlv_hdrlen_e:tlv_hdrlen_n)

#define tlv_datalen_n(_tlv)     (tlv_len_n(_tlv)-tlv_hdrlen_n)
#define tlv_datalen_e(_tlv)     (tlv_len_e(_tlv)-tlv_hdrlen_e)
#define tlv_datalen(_tlv)       (tlv_extend(_tlv)?tlv_datalen_e(_tlv):tlv_datalen_n(_tlv))

#define tlv_binlen(_tlv)        (tlv_len(_tlv) - (_tlv)->pad)
#define tlv_strlen(_tlv)        tlv_binlen(_tlv)

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

#define tlv_binary(_tlv)    ((byte *)tlv_data(_tlv))
#define tlv_string(_tlv)    ((char *)tlv_data(_tlv))

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

    void (*dump)(FILE * /*stream*/, struct tlv * /*tlv*/);
    int (*check)(struct xparse * /*parse*/, struct tlv * /*tlv*/);
    int (*toxdr)(struct xb * /*x*/, struct tlv * /*tlv*/);
} tlv_ops_t;

static inline bool is_good_tlv_id(int id);

extern tlv_ops_t __tlv_ops[];

static inline tlv_ops_t *
tlv_ops(struct tlv *tlv) 
{
    return is_good_tlv_id(tlv->id) ? &__tlv_ops[tlv->id] : NULL;
}

#define tlv_is_string(_tlv)     (tlv_ops(_tlv)->type==TLV_T_string)
#define tlv_is_binary(_tlv)     (tlv_ops(_tlv)->type==TLV_T_binary)

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

static inline int xp_error(struct xparse *parse, struct tlv *tlv, int err, const char *fmt, ...);

#define TLV_DUMP( _stream, _fmt, _args...)  fprintf(_stream, __tab  _fmt __crlf, ##_args)
#define TLV_DUMP2(_stream, _fmt, _args...)  TLV_DUMP( _stream, __tab _fmt, ##_args)
#define TLV_DUMP3(_stream, _fmt, _args...)  TLV_DUMP2(_stream, __tab _fmt, ##_args)
#define TLV_DUMP4(_stream, _fmt, _args...)  TLV_DUMP3(_stream, __tab _fmt, ##_args)

#define TLV_DUMP_BY(_stream, _tlv, _format, _type) \
    TLV_DUMP(_stream, "id: %d, %s: " _format, (_tlv)->id, tlv_ops_name(_tlv), tlv_##_type(_tlv))

static inline void
tlv_dump_u8(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP_BY(stream, tlv, "%u", u8); 
}

static inline void
tlv_dump_u16(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP_BY(stream, tlv, "%u", u16); 
}

static inline void
tlv_dump_u32(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP_BY(stream, tlv, "%u", u32); 
}

static inline void
tlv_dump_u64(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP_BY(stream, tlv, "%"PRIu64, u64); 
}

static inline void
tlv_dump_string(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP_BY(stream, tlv, "%s", string); 
}

static inline void 
tlv_dump_binary(FILE *stream, struct tlv *tlv)
{
    if (is_option(OPT_SPLIT)) {
        TLV_DUMP(stream, "id: %d, %s: %s", tlv->id, tlv_ops_name(tlv), tlv_string(tlv));
    } else {
        TLV_DUMP(stream, "id: %d, %s:", tlv->id, tlv_ops_name(tlv));

        os_dump_buffer(stream, tlv_binary(tlv), os_min(tlv_datalen(tlv), DUMP_SHORT));
    }
}

static inline void 
tlv_dump_tlv(FILE *stream, struct tlv *tlv)
{
    if (is_option(OPT_SPLIT)) {
        TLV_DUMP(stream, "id: %d, %s: %s", tlv->id, tlv_ops_name(tlv), tlv_string(tlv));
    } else {
        TLV_DUMP(stream, "id: %d, %s:", tlv->id, tlv_ops_name(tlv));

        os_dump_buffer(stream, tlv, os_min(tlv_len(tlv), DUMP_SHORT));
    }
}

static inline void 
tlv_dump_time(FILE *stream, struct tlv *tlv)
{
    time_string_t tstring;
        
    TLV_DUMP(stream, "id:%d, %s: %s", tlv->id, tlv_ops_name(tlv), 
        os_time_string(XDR_SECOND(tlv_time(tlv)), tstring));
}

static inline void
tlv_dump_duration(FILE *stream, struct tlv *tlv) 
{
    tlv_duration_t d = tlv_duration(tlv);
    uint32 s = (uint32)(d>>32);
    uint32 us= (uint32)(d & 0xffffffff);
    
    TLV_DUMP(stream, "id:%d, %s %ds:%dus", tlv->id, tlv_ops_name(tlv), s, us); 
}

static inline void 
tlv_dump_ip4(FILE *stream, struct tlv *tlv)
{
    uint32 ip = tlv_ip4(tlv); // ip = htonl(ip);
    ip_string_t string;
    
    TLV_DUMP(stream, "id:%d, %s: %s", tlv->id, 
        tlv_ops_name(tlv), 
        os_ipstring(ip, string));
}

static inline void 
tlv_dump_ip6(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, %s: ipv6 address", tlv->id, tlv_ops_name(tlv));
}

static inline void 
tlv_dump_header(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, %s: alen %u", tlv->id, tlv_ops_name(tlv), tlv_len(tlv));
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
dump_session(FILE *stream, tlv_session_t *obj)
{
    TLV_DUMP2(stream, "version: %d", obj->ver);
    TLV_DUMP2(stream, "dir    : %d", obj->dir);
    TLV_DUMP2(stream, "proto  : %d", obj->proto);
    TLV_DUMP2(stream, "sport  : %d", obj->sport);
    TLV_DUMP2(stream, "dport  : %d", obj->dport);

    if (XDR_IPV4==obj->ver) {
        uint32 ip;
        ip_string_t string;
        
        ip = XDR_IP(&obj->sip); // ip = htonl(ip);
        TLV_DUMP2(stream, "sip    : %s", os_ipstring(ip, string));
        
        ip = XDR_IP(&obj->dip); // ip = htonl(ip);
        TLV_DUMP2(stream, "dip    : %s", os_ipstring(ip, string));
    } else {
        TLV_DUMP2(stream, "sip    : ipv6 address");
        TLV_DUMP2(stream, "dip    : ipv6 addres");
    }
}

static inline void 
tlv_dump_session(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, session:", tlv->id);

    dump_session(stream, tlv_session(tlv));
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
dump_session_st(FILE *stream, tlv_session_st_t *obj)
{
    int i;

    for (i=0; i<2; i++) {
        char c = (0==i) ? 'u' : 'd';
        
        TLV_DUMP2(stream, "[%c]flow            : %d", c, obj->flow[i]);
        TLV_DUMP2(stream, "[%c]ip_packet       : %d", c, obj->ip_packet[i]);
        TLV_DUMP2(stream, "[%c]tcp_disorder    : %d", c, obj->tcp_disorder[i]);
        TLV_DUMP2(stream, "[%c]tcp_retransmit  : %d", c, obj->tcp_retransmit[i]);
        TLV_DUMP2(stream, "[%c]ip_frag         : %d", c, obj->ip_frag[i]);
        TLV_DUMP2(stream, "[%c]duration        : %d", c, obj->duration[i]);
    }
}

static inline void 
tlv_dump_session_st(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, %s:", tlv->id, tlv_ops_name(tlv));

    dump_session_st(stream, tlv_session_st(tlv));
}
#define tlv_dump_service_st    tlv_dump_session_st

#ifndef sizeof_session_time
#define sizeof_session_time 24
#endif

typedef struct {
    tlv_time_t create;
    tlv_time_t start;
    tlv_time_t stop;
} tlv_session_time_t, xdr_session_time_t;

static inline void 
dump_session_time(FILE *stream, tlv_session_time_t *obj)
{
    time_string_t tstring;
    
    TLV_DUMP2(stream, "create: %s", 
        os_time_string(XDR_SECOND(obj->create), tstring));
    TLV_DUMP2(stream, "start : %s", 
        os_time_string(XDR_SECOND(obj->start), tstring));
    TLV_DUMP2(stream, "stop  : %s", 
        os_time_string(XDR_SECOND(obj->stop), tstring));
}

static inline void 
tlv_dump_session_time(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, session_time:", tlv->id);

    dump_session_time(stream, tlv_session_time(tlv));
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
dump_tcp(FILE *stream, tlv_tcp_t *obj)
{  
    TLV_DUMP2(stream, "synack_to_syn_time  : %u us", obj->synack_to_syn_time);
    TLV_DUMP2(stream, "ack_to_syn_time     : %u us", obj->ack_to_syn_time);
    TLV_DUMP2(stream, "complete            : %s", bool_string(XDR_TCP_COMPLETE==obj->complete));
    TLV_DUMP2(stream, "close_reason        : %d", obj->close_reason);
    TLV_DUMP2(stream, "first_request_delay : %u ms", obj->first_request_delay);
    TLV_DUMP2(stream, "first_response_delay: %u ms", obj->first_response_delay);
    TLV_DUMP2(stream, "window              : %u", obj->window);
    TLV_DUMP2(stream, "mss                 : %u", obj->mss);
    TLV_DUMP2(stream, "count_retry         : %u", obj->count_retry);
    TLV_DUMP2(stream, "count_retry_ack     : %u", obj->count_retry_ack);
    TLV_DUMP2(stream, "count_ack           : %u", obj->count_ack);
    TLV_DUMP2(stream, "connect_status      : %u", obj->connect_status);
    TLV_DUMP2(stream, "handshake12         : %s", success_string(0==obj->handshake12));
    TLV_DUMP2(stream, "handshake23         : %s", success_string(0==obj->handshake23));
}

static inline void 
tlv_dump_tcp(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, tcp:", tlv->id);

    dump_tcp(stream, tlv_tcp(tlv));
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
dump_L7(FILE *stream, tlv_L7_t *obj)
{
    TLV_DUMP2(stream, "status  : %u", obj->status);
    TLV_DUMP2(stream, "class   : %u", obj->class);
    TLV_DUMP2(stream, "protocol: %u", obj->protocol);
}

static inline void 
tlv_dump_L7(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, L7:", tlv->id);
    
    dump_L7(stream, tlv_L7(tlv));
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

    byte first:2;
    byte flag:3;
    byte head:1;
    byte _0:2;

    byte ie;
    byte portal;
    byte _1;
}
tlv_http_t;

static inline void 
dump_http(FILE *stream, tlv_http_t *obj)
{
    time_string_t tstring;

    TLV_DUMP2(stream, "time_request        : %s", 
        os_time_string(XDR_SECOND(obj->time_request), tstring));
    TLV_DUMP2(stream, "time_first_response : %s", 
        os_time_string(XDR_SECOND(obj->time_first_response), tstring));
    TLV_DUMP2(stream, "time_last_content   : %s", 
        os_time_string(XDR_SECOND(obj->time_last_content), tstring));
    TLV_DUMP2(stream, "service_delay       : %"PRIu64" us", obj->service_delay);
    TLV_DUMP2(stream, "content_length      : %u", obj->content_length);
    TLV_DUMP2(stream, "status_code         : %u", obj->status_code);
    TLV_DUMP2(stream, "method              : %u", obj->method);
    TLV_DUMP2(stream, "version             : %u", obj->version);

    TLV_DUMP2(stream, "first               : %s", bool_string(obj->first));
    TLV_DUMP2(stream, "flag                : %u", obj->flag);
    TLV_DUMP2(stream, "head                : %s", bool_string(obj->head));
    TLV_DUMP2(stream, "ie                  : %u", obj->ie);
    TLV_DUMP2(stream, "portal              : %u", obj->portal);
}

static inline void 
tlv_dump_http(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, http:", tlv->id);

    dump_http(stream, tlv_http(tlv));
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

    uint16 invite:1;
    uint16 bye:1;
    uint16 malloc:1;
    uint16 _:13;
} tlv_sip_t;

static inline void 
dump_sip(FILE *stream, tlv_sip_t *obj)
{
    TLV_DUMP2(stream, "call_direction  : %u", obj->call_direction);
    TLV_DUMP2(stream, "call_type       : %u", obj->call_type);
    TLV_DUMP2(stream, "hangup_reason   : %u", obj->hangup_reason);
    TLV_DUMP2(stream, "signal_type     : %u", obj->signal_type);
    TLV_DUMP2(stream, "dataflow_count  : %u", obj->dataflow_count);
    TLV_DUMP2(stream, "invite          : %s", bool_string(XDR_SIP_INVITE==obj->invite));
    TLV_DUMP2(stream, "bye             : %s", bool_string(XDR_SIP_BYE==obj->bye));
    TLV_DUMP2(stream, "malloc          : %s", bool_string(obj->malloc));
}

static inline void 
tlv_dump_sip(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, http:", tlv->id);

    dump_sip(stream, tlv_sip(tlv));
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
dump_rtsp(FILE *stream, tlv_rtsp_t *obj)
{
    TLV_DUMP2(stream, "port_client_start   : %u", obj->port_client_start);
    TLV_DUMP2(stream, "port_client_end     : %u", obj->port_client_end);
    TLV_DUMP2(stream, "port_server_start   : %u", obj->port_server_start);
    TLV_DUMP2(stream, "port_server_end     : %u", obj->port_server_end);
    TLV_DUMP2(stream, "count_video         : %u", obj->count_video);
    TLV_DUMP2(stream, "count_audio         : %u", obj->count_audio);
    TLV_DUMP2(stream, "describe_delay      : %u", obj->describe_delay);
}

static inline void 
tlv_dump_rtsp(FILE *stream, struct tlv *tlv)
{
    TLV_DUMP(stream, "id: %d, http:", tlv->id);

    dump_rtsp(stream, tlv_rtsp(tlv));
}

static inline int
tlv_check_header(struct xparse *parse, struct tlv *tlv)
{
    if (tlv_extend(tlv)) {
        return 0;
    }

    return xp_error(parse, tlv, -EPROTOCOL, "tlv header not extend");
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
            if (is_option(OPT_STRICT)) {
                return xp_error(parse, tlv, -ENOSUPPORT, "no support ip proto:%d", obj->proto);
            }
    }

    return 0;
}

#ifndef TLV_SSL_CERT_MINSIZE
#define TLV_SSL_CERT_MINSIZE    128
#endif

static inline int
tlv_check_ssl_cert(struct xparse *parse, struct tlv *tlv)
{
    if (tlv_datalen(tlv) < TLV_SSL_CERT_MINSIZE) {
        return xp_error(parse, tlv, -ETOOSMALL, "ssl cert too short:%d", tlv_datalen(tlv));
    }

    return 0;
}

static inline int to_xdr_header(struct xb *x, struct tlv *tlv) { return 0; }
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
    tlv_mapper_u32(_,       0,  header,         tlv_check_header,   0) \
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
    tlv_mapper_binary(_,    204,ssl_server_cert, tlv_check_ssl_cert,    TLV_F_MULTI|TLV_F_SSL_SERVER_CERT) \
    tlv_mapper_binary(_,    205,ssl_client_cert, tlv_check_ssl_cert,    TLV_F_MULTI|TLV_F_SSL_CLIENT_CERT) \
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
    
typedef struct {
    uint64 ok;
    uint64 error;
} xst_t;

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
#define xpath_fullname(_path, _id)      (_path)[_id].fullname

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
xpath_fill_sha(xpath_t *path, const char *dir, char *sha)
{
    char *p = path->filename;
    int len = strlen(dir);

    // push dir
    memcpy(p, dir, len); p += len; *p++ = '/';
    // push sha
    memcpy(p, sha, 2*XDR_DIGEST_SIZE); p[2*XDR_DIGEST_SIZE] = 0;
    
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
#define TLV_CACHE_MULTI    63
#endif

typedef struct {
    uint32 OS_ALIGNP count;
    
    struct tlv *multi[TLV_CACHE_MULTI];
} tlv_cache_t;

typedef struct {
    struct xparse *parse;

    uint32 OS_ALIGNP count;

    tlv_cache_t cache[tlv_id_end];
} tlv_record_t;
#define TLV_RECORD_INITER(_parse)   { .parse = _parse }

struct xb {
    struct xparse *parse;
    
    char    *fullname;
    int     fd;
    void            *buffer;
    xdr_size_t      size;       // include struct xdr/tlv header

    xdr_offset_t    obj;        // obj offsetof buffer
    xdr_offset_t    current;    // pointer to obj body when obj init
};

#define XBUFFER_INITER(_fullname)   {   \
    .fullname   = _fullname,            \
    .fd         = -1,                   \
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
            option_dump_error("ftruncate %s size:%d error:%d", x->fullname, x->size, -errno);
        
            return -errno;
        }
    }

    x->buffer = os_mmap(x->size, prot, flag, x->fd, 0);
    if (NULL==x->buffer) {
        x->buffer = NULL;
        option_dump_error("mmap %s error:%d", x->fullname, -errno);
        
        return -errno;
    }

    err = madvise(x->buffer, x->size, MADV_SEQUENTIAL);
    if (err<0) {
        option_dump_error("madvise %s error:%d", x->fullname, -errno);
    }
    
    return 0;
}

static inline int
xb_munmap(struct xb *x)
{
    if (x->buffer) {
        int i, err = 0;

        for (i=0; i<3; i++) {
            err = os_munmap(x->fullname, x->buffer, x->size);
            if (0==err) {
                return 0;
            }
        }

        return err;
    }

    return 0;
}

static inline int
xb_close(struct xb *x)
{
    os_close(x->fd);

    if (x->buffer) {
        madvise(x->buffer, x->size, MADV_DONTNEED);
    }
    
    return xb_munmap(x);
}

static inline int
xb_open(struct xb *x, bool readonly, int size)
{
    int flag = readonly?O_RDONLY:(O_CREAT|O_RDWR);

    x->fd = open(x->fullname, flag|O_CLOEXEC, 0664);
    if (x->fd<0) {
        option_dump_error("open %s error:%d ...", x->fullname, -errno);
        
        return -errno;
    }

    x->size = (xdr_size_t)size;
    
    return xb_mmap(x, readonly);
}

typedef struct {
    int32   len;
    byte    buf[EVBUFSIZE];
} xque_buffer_t; // 4096

static inline inotify_ev_t *
xp_ev_first(xque_buffer_t *qb) 
{
    return (inotify_ev_t *)qb->buf;
}

static inline inotify_ev_t *
xq_ev_end(xque_buffer_t *qb) 
{
    return (inotify_ev_t *)(qb->buf + qb->len);
}

typedef struct {
    uint64 publisher;
    uint64 consumer;
    
    pthread_mutex_t mutex;
    uint64 qcount;
    xque_buffer_t *qb;  // 8K * 4K = 32M
} xque_t OS_CACHEALIGN;

#ifndef INVALID_WORKER_ID
#define INVALID_WORKER_ID   ((uint64)(-1))
#endif

static inline void
xq_lock(xque_t *q)
{
    pthread_mutex_lock(&q->mutex);
}

static inline void
xq_unlock(xque_t *q)
{
    pthread_mutex_unlock(&q->mutex);
}

static inline xque_buffer_t *
xq_entry(xque_t *q, uint64 id)
{
    uint64 ID = id % q->qcount;
    
    if (ID>=q->qcount) {
        os_assert(0);
        option_dump_error("invalid ID:%"PRIu64":%"PRIu64, id, ID);
        
        return NULL;
    } else {
        return q->qb + ID;
    }
}

static inline uint64
xq_count(xque_t *q)
{
    if (q->publisher >= q->consumer) {
        return q->publisher - q->consumer;
    } else {
        return INVALID_WORKER_ID;
    }
}

static inline bool
is_xq_full(xque_t *q)
{
    return xq_count(q)==q->qcount;
}

static inline bool
is_xq_empty(xque_t *q)
{
    return q->publisher==q->consumer;
}

#define xq_dump(_q, _fmt, _args...) do{ \
    if (is_option(OPT_DUMP_QUE)) {      \
        os_println("["                  \
            "publisher:%"PRIu64         \
            " consumer:%"PRIu64         \
            " count:%"PRIu64            \
            "]" __tab _fmt,             \
            (_q)->publisher,            \
            (_q)->consumer,             \
            xq_count(_q),               \
            ##_args);                   \
    }                                   \
}while(0)

static inline uint64
xq_get_publisher(xque_t *q)
{
    int err = 0;
    uint64 id = INVALID_WORKER_ID;
    
    xq_lock(q);
    if (is_xq_full(q)) {
        err = -1; goto ERROR;
    }

    id = q->publisher;
ERROR:
    xq_unlock(q);

    switch (err) {
        case 0:
            xq_dump(q, "get publisher:%"PRIu64, id);
            break;
        case -1:
            // xq_dump(q, "get publisher failed(empty)");            
            break;
    }

    return id;
}

static inline int
xq_put_publisher(xque_t *q, uint64 id)
{
    int err = 0;
    
    xq_lock(q);
    if (is_xq_full(q)) {
        err = -1; os_assert(0); goto ERROR;
    }
    else if (q->publisher != id) {
        err = -2; os_assert(0); goto ERROR;
    }

    q->publisher++;
ERROR:
    xq_unlock(q);

    switch (err) {
        case 0:
            xq_dump(q, "put publisher:%"PRIu64, id);
            break;
        case -1:
            // xq_dump(q, "put publisher:%"PRIu64" failed(full)", id);
            break;
        case -2:
            xq_dump(q, "put publisher:%"PRIu64" failed(not-match %"PRIu64")", id, q->publisher);
            break;
    }
    
    return err;
}

static inline uint64
xq_get_consumer(xque_t *q, int wid)
{
    int err = 0;
    uint64 id = INVALID_WORKER_ID;
   
    xq_lock(q);
    if (is_xq_empty(q)) {
        err = -1; goto ERROR;
    }

    id = q->consumer++;
ERROR:
    xq_unlock(q);

    switch (err) {
        case 0:
            xq_dump(q, "get worker:%d consumer:%"PRIu64, wid, id);
            break;
        case -1:
            // xq_dump(q, "get worker:%d consumer failed(empty)", wid);
            break;
    }
    
    return id;
}

#if 1
#define XST_ENUM_MAPPER(_)  \
    _(XST, tlv,         0) \
    _(XST, xdr,         1) \
    _(XST, raw,         2) \
    _(XST, frequest,    3) \
    _(XST, fresponse,   4) \
    _(XST, fcontent,    5) \
    _(XST, ssls,        6) \
    _(XST, sslc,        7) \
    /* end */
DECLARE_ENUM(XST, xst, XST_ENUM_MAPPER, XST_END);

static inline char *xst_getnamebyid(int id);

#define XST_tlv         XST_tlv
#define XST_xdr         XST_xdr
#define XST_raw         XST_raw
#define XST_frequest    XST_frequest
#define XST_fresponse   XST_fresponse
#define XST_fcontent    XST_fcontent
#define XST_ssls        XST_ssls
#define XST_sslc        XST_sslc
#define XST_END         XST_END
#endif

struct xparse {
    FILE *ferr;     // bad file
    char *filename; // just filename, not include path
    int namelen;    // just filename, not include path
    int wid;
    
    xpath_t *path;  // xpath_t  path[PATH_END];
    xst_t   *st;    // xst_t    st[XST_END];
    
    int count;      // tlv count
    struct xb tlv;
    struct xb xdr;
};

#define xst_update(_parse, _id, _field)     do{ (_parse)->st[_id]._field++; }while(0)
#define xst_update_ok(_parse, _id)          xst_update(_parse, _id, ok)
#define xst_update_error(_parse, _id)       xst_update(_parse, _id, error)
#define xst_update_by(_err, _parse, _id)    do{ \
    if (_err<0) {                               \
        xst_update_error(_parse, _id);          \
    } else {                                    \
        xst_update_ok(_parse, _id);             \
    }                                           \
}while(0)

#define XPARSE_INITER(_wid, _path, _st, _filename, _namelen) { \
    .wid            = _wid,         \
    .filename       = _filename,    \
    .namelen        = _namelen,     \
    .path           = _path,        \
    .st             = _st,          \
    .tlv            = XBUFFER_INITER((_path)[PATH_TLV].fullname),   \
    .xdr            = XBUFFER_INITER((_path)[PATH_XDR].fullname),   \
}   /* end */

static inline xpath_t *
xp_path(struct xparse *parse, int id)
{
    return &parse->path[id];
}

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

    xpath_fill(xp_path(parse, PATH_TLV), parse->filename, parse->namelen);
    xpath_fill(xp_path(parse, PATH_XDR), parse->filename, parse->namelen);
    xpath_fill(xp_path(parse, PATH_BAD), parse->filename, parse->namelen);
}

static inline int
xp_close(struct xparse *parse)
{
    tlv_trace(tlv_close(&parse->tlv), parse->wid, "tlv_close");
    tlv_trace(xdr_close(&parse->xdr), parse->wid, "xdr_close");

    os_fclose(parse->ferr);

    return 0;
}

static inline int
xp_open(struct xparse *parse)
{
    struct xb *tlv = &parse->tlv;
    struct xb *xdr = &parse->xdr;
    int size, err;

    // maybe multi-file have same name
    if (os_fexist(xdr->fullname)) {
        return -EEXIST;
    }
    
    size = os_fsize(tlv->fullname);
    if (size<0) {
        option_dump_error("get size %s error:%d", tlv->fullname, size);
        
        return size;
    }
    
    err = tlv_trace(tlv_open(tlv, size), parse->wid, "tlv_open %s:%d", tlv->fullname, size);
    if (err<0) {
        return err;
    }

    size = XDR_EXPAND_ALIGN(size);
    err = tlv_trace(xdr_open(xdr, size), parse->wid, "xdr_open %s:%d", xdr->fullname, size);
    if (err<0) {
        return err;
    }
    
    return 0;
}

static inline void
xp_verror(FILE *stream, struct xparse *parse, struct tlv *tlv, int err, const char *fmt, va_list args)
{
    fprintf(stream, __tab "ERROR:%d, ", err);
    vfprintf(stream, fmt, args);
    fprintf(stream,
        ", %s offset:%d" __crlf,
        parse->filename,
        (uint32)((byte *)tlv - (byte *)parse->tlv.buffer));

    fprintf(stream, __tab
            "tlv name:%s id:%d extend:%d fixed:%d pad:%d alen:%u hlen:%u dlen:%u"
            __crlf, 
            tlv_ops_name(tlv), 
            tlv->id, 
            tlv_extend(tlv),
            tlv_ops_fixed(tlv),
            tlv->pad,
            tlv_len(tlv),
            tlv_hdrlen(tlv),
            tlv_datalen(tlv));

    tlv_dump_tlv(stream, tlv);
}

static inline int
xp_error(struct xparse *parse, struct tlv *tlv, int err, const char *fmt, ...)
{
    va_list args;
    xpath_t *path = xp_path(parse, PATH_BAD);
    
    if (tlv) {
        xpath_change(path, ERR_SUFFIX);

        if (NULL==parse->ferr) {
            parse->ferr = fopen(path->fullname, "a+");
        }

        // write to err
        if (parse->ferr) {
            va_start(args, fmt);
            xp_verror(parse->ferr, parse, tlv, err, fmt, args);
            va_end(args);
        } else {
            option_dump_error("open %s error", path->fullname);
        }
        
        // write to stdout
        if (DUMP_STREAM) {
            va_start(args, fmt);
            xp_verror(DUMP_STREAM, parse, tlv, err, fmt, args);
            va_end(args);
        }
    }

    // move tlvs/xxx.xdr ==> bad/xxx.err
    xpath_change(path, XDR_SUFFIX);
    tlv_close(&parse->tlv);
    rename(parse->tlv.fullname, path->fullname);

    // delete xdrs/xxx.xdr    
    xdr_close(&parse->xdr);
    remove(parse->xdr.fullname);
    
    return err;
}

typedef int tlv_walk_t(struct xparse *parse, struct tlv *tlv);

static inline int
tlv_walk(struct xparse *parse, struct tlv *tlv, uint32 left, tlv_walk_t *walk)
{
    int err = 0;

    if (left > TLV_MAXDATA) {
        return xp_error(parse, tlv, -ETOOBIG, "left too big:%u", left);
    }
    
    while(left>0) {
        if (parse->count > TLV_MAXCOUNT) {
            return xp_error(parse, tlv, -ETOOMORE, "too more tlv:%d", parse->count);
        }
        else if (left < tlv_hdrlen(tlv)) {
            return xp_error(parse, tlv, -ETOOSMALL, "left:%u < tlv hdrlen:%u", left, tlv_hdrlen(tlv));
        }
        else if (left < tlv_len(tlv)) {
            return xp_error(parse, tlv, -ETOOSMALL, "left:%u < tlv len:%u", left, tlv_len(tlv));
        }
        
        err = (*walk)(parse, tlv);
        if (err<0) {
            return err;
        }

        left -= tlv_len(tlv); tlv = tlv_next(tlv);
    }

    return 0;
}

static inline void
tlv_dump(FILE *stream, struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv);

    if (stream && ops && ops->dump) {
        (*ops->dump)(stream, tlv);
    }
}

static inline int
tlv_check_fixed(struct xparse *parse, struct tlv *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv); // not NULL
    uint32 dlen = tlv_datalen(tlv);
    uint32 fixed;
    
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
            fixed = ops->maxsize;
            
            if (is_option(OPT_STRICT)) {
                if (dlen != fixed) {
                    return xp_error(parse, tlv, -EINVAL7, 
                        "tlv check fixed[strict] datalen[%u] != fixed[%u]", dlen, fixed);
                }
            } else {
                if (dlen < ops->maxsize) {
                    return xp_error(parse, tlv, -EINVAL7, 
                        "tlv check fixed[loose] datalen[%u] < fixed[%u]", dlen, fixed);
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
        return xp_error(parse, tlv, -ETOOSMALL, 
            "tlv check dynamic datalen[%u] < minsize[%u]", dlen, ops->minsize);
    }
    else if (ops->maxsize && dlen > ops->maxsize) {
        return xp_error(parse, tlv, -ETOOBIG, 
            "tlv check dynamic datalen[%u] > maxsize[%u]", dlen, ops->maxsize);
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
    } else if (tlv_len(tlv) < tlv_hdrlen(tlv)) {
        return xp_error(parse, tlv, -ETOOSMALL, 
            "tlv alen[%u] < hdrlen[%u]", tlv_len(tlv), tlv_hdrlen(tlv));
    }
    
    if (tlv_extend(tlv)) {
        if (tlv_len(tlv) < 4096 && is_option(OPT_STRICT)) {
            return xp_error(parse, tlv, -EPROTOCOL, 
                "tlv[extend] alen[%u] < LIMIT[%u]", tlv_len(tlv), 4096);
        }
    }

    switch(ops->type) {
        case TLV_T_string:
            if (DumpTlvString==tlv->id) {
                tlv_dump(DUMP_STREAM, tlv);
            }
            
            /* no break */
        case TLV_T_binary: /* down */
            if (DumpTlvBinary==tlv->id) {
                tlv_dump(DUMP_STREAM, tlv);                
            }
            
            if (tlv_len(tlv) < tlv->pad) {
                return xp_error(parse, tlv, -EPROTOCOL, 
                    "string tlv alen:%u < pad:%u", tlv_len(tlv), tlv->pad);
            }
    }

    if (ops->check) {
        int err = (*ops->check)(parse, tlv);
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

static inline int
tlv_cache_save(struct xparse *parse, tlv_cache_t *cache, struct tlv *tlv)
{
    if (cache->count < TLV_CACHE_MULTI) {
        if (0==cache->count) {
            tlv_dprint(parse->wid, "save tlv %s", tlv_ops_name(tlv));
            
            cache->multi[cache->count++] = tlv;
        }
        else if (TLV_F_MULTI & tlv_ops_flag(tlv)) {
            tlv_dprint(parse->wid, "save multi tlv %s", tlv_ops_name(tlv));
            
            cache->multi[cache->count++] = tlv;
        }
        else {
            return xp_error(parse, tlv, -ENOSUPPORT, "not support cache multi");
        }
    }
    else {
        return xp_error(parse, tlv, -ENOSPACE, "too more[%u] cache multi", TLV_CACHE_MULTI);
    }
    
    return 0;
}

static inline int
tlv_record_save(tlv_record_t *r, struct tlv *tlv)
{
    tlv_cache_t *cache = &r->cache[tlv->id];
    
    int err = tlv_trace(tlv_cache_save(r->parse, cache, tlv), r->parse->wid, "tlv_cache_save");
    if (err<0) {
        return err;
    }

    return 0;
}

static inline int
tlv_record_parse(tlv_record_t *r, struct tlv *header)
{
    int walk(struct xparse *parse, struct tlv *tlv) 
    {
        int err;

        if (is_option(OPT_DUMP_PRE)) {
            tlv_dump(DUMP_STREAM, tlv);
        }

        err = tlv_trace(tlv_check(parse, tlv), parse->wid, "tlv_check %d:%d", parse->count, r->count);
        if (err<0) {
            parse->st[XST_tlv].error++;
            
            return err;
        }

        err = tlv_trace(tlv_record_save(r, tlv), parse->wid, "tlv_record_save %d:%d", parse->count, r->count);
        if (err<0) {
            parse->st[XST_tlv].error++;
            
            return err;
        }

        if (is_option(OPT_DUMP) && !is_option(OPT_DUMP_PRE)) {
            tlv_dump(DUMP_STREAM, tlv);
        }
        

        r->count++;
        parse->st[XST_tlv].ok++;

        return 0;
    }

    return tlv_walk(r->parse, (struct tlv *)tlv_data(header), tlv_datalen(header), walk);
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
