#ifndef __XDR_H_049defbc41a4441e855ee0479dad96eb__
#define __XDR_H_049defbc41a4441e855ee0479dad96eb__
/******************************************************************************/
#include "tlv.h"
/******************************************************************************/
#if 1
#define XDR_ARRAY_MAPPER(_) \
    _(XDR_ARRAY, string,0)  \
    _(XDR_ARRAY, ip4,   1)  \
    _(XDR_ARRAY, ip6,   2)  \
    _(XDR_ARRAY, cert,  3)  \
    /* end */
DECLARE_ENUM(XDR_ARRAY, xdr_array, XDR_ARRAY_MAPPER, XDR_ARRAY_END);

static inline bool is_good_xdr_array(int id);
static inline char *xdr_array_getnamebyid(int id);
static inline int xdr_array_getidbyname(const char *name);

#define XDR_ARRAY_string    XDR_ARRAY_string
#define XDR_ARRAY_ip4       XDR_ARRAY_ip4
#define XDR_ARRAY_ip6       XDR_ARRAY_ip6
#define XDR_ARRAY_cert      XDR_ARRAY_cert
#define XDR_ARRAY_END       XDR_ARRAY_END
#endif

static inline void *
xdr_strcpy(void *dst, void *src, xdr_size_t size)
{
    byte *p = (byte *)memcpy(dst, src, size);
    
    p[size] = 0;
    
    return p;
}

#if 0
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                              size                                             |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             offset                                            |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

typedef struct {
    /*
    * not include '\0'
    *   real len must align 4
    */
    xdr_size_t      size;
    xdr_offset_t    offset;
} xdr_string_t, xdr_binary_t;

#if 0
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             size                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     count                     |                     type                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             body...
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

typedef struct {
    xdr_size_t size;

    uint16 count;
    uint16 type;    // XDR_ARRAY_END

    byte entry[0];
} xdr_array_t;

static inline byte *
xdr_array_entry(xdr_array_t *array, int idx)
{
    return array->entry + (array->size * idx);
}

#if 0
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|          ver          |           dir         |        proto          |         _             |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     sport                     |                     dport                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                              sip                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                              dip                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

typedef struct {
    byte ver;
    byte dir;
    byte proto;
    byte _;
    
    uint16 sport;
    uint16 dport;
    
    xdr_ip4_t sip;
    xdr_ip4_t dip;
} xdr_session4_t;
#define xdr_session_bkdr(_session) \
    os_bkdr((byte *)(_session)+sizeof(uint32), sizeof(*(_session))-sizeof(uint32))

typedef union {
    xdr_session4_t *session4;
    xdr_session6_t *session6;

    void *session;
} xdr_session_t;

enum {
    XDR_FILE_HEADER_SIZE    = 60,
    XDR_FILE_PAD_SIZE       = (XDR_FILE_HEADER_SIZE     //(60
                                - sizeof(xdr_size_t)    // -4
                                - sizeof(bkdr_t)        // -4
                                - XDR_DIGEST_SIZE),     // -32) = 20
};

#if 0
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             size                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             bkdr                                              |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                            digest[32]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                              _[20]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                             body ...
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

typedef struct {
    xdr_size_t  size;
    bkdr_t      bkdr;
    byte digest[XDR_DIGEST_SIZE];
    byte _[XDR_FILE_PAD_SIZE];
    
    byte body[0];
} xdr_file_t;

#if 0
 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                         time_request[time]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                         time_first_response[time]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                         time_last_content[time]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                         service_delay[duration]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                         content_length                                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     status_code               |        method         |        version        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|           u           |           ie          |        portal         |         _             |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                       offsetof_request                                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                       offsetof_response                                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           host[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           url[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           host_xonline[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           user_agent[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           content[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           refer[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           cookie[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           location[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           cookie[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           cookie[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           cookie[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                           cookie[string]
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#endif

typedef struct {
    // begin, same as tlv_http_t
    xdr_time_t time_request;
    xdr_time_t time_first_response;
    xdr_time_t time_last_content;
    xdr_duration_t service_delay;
    
    xdr_size_t content_length;
    
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
    // end, same as tlv_http_t

    xdr_offset_t offsetof_request;    // xdr_file_t
    xdr_offset_t offsetof_response;   // xdr_file_t
    
    xdr_string_t host;
    xdr_string_t url;
    xdr_string_t host_xonline;
    xdr_string_t user_agent;
    xdr_string_t content;
    xdr_string_t refer;
    xdr_string_t cookie;
    xdr_string_t location;
} 
xdr_http_t;

typedef struct {
    // begin, same as tlv_sip_t
    byte call_direction;
    byte call_type;
    byte hangup_reason;
    byte signal_type;
    
    uint16 dataflow_count;
    uint16 _:13;
    uint16 malloc:1;
    uint16 bye:1;
    uint16 invite:1;
    // end, same as tlv_sip_t
    
    xdr_string_t calling_number;
    xdr_string_t called_number;
    xdr_string_t session_id;
}
xdr_sip_t;

typedef struct {
    // begin, same as tlv_rtsp_t
    uint16 port_client_start;
    uint16 port_client_end;
    uint16 port_server_start;
    uint16 port_server_end;
    uint16 count_video;
    uint16 count_audio;
    
    xdr_delay_t describe_delay;
    // end, same as tlv_rtsp_t
    
    xdr_string_t url;
    xdr_string_t user_agent;
    xdr_string_t server_ip;
} xdr_rtsp_t;

typedef struct {
    byte trans_mode;
    byte trans_type;
    byte _[2];
    
    xdr_size_t filesize;
    xdr_duration_t response_delay;
    xdr_duration_t trans_duration;
    
    xdr_string_t status;
    xdr_string_t user;
    xdr_string_t pwd;
    xdr_string_t filename;
} xdr_ftp_t;

typedef struct {
    uint16 msg_type;
     int16 status_code;
    xdr_size_t length;
    
    byte acs_type;
    byte _[3];
    
    xdr_string_t user;
    xdr_string_t domain;
    xdr_string_t sender;
    xdr_string_t recver;
    xdr_string_t hdr;
} xdr_mail_t;

enum { XDR_DNS_DOMAIN_SIZE = 63 };

typedef struct {
    byte response_code;
    byte count_request;
    byte count_response_record;
    byte count_response_auth;
    
    byte count_response_extra;
    byte ip_version;    // 0: ipv4
    byte ip_count;
    byte _;

    xdr_delay_t delay;
    /*
    * if 1==ip_count, 0==ip_version
    *   then 
    *       ip4 is the ip address
    *       the ip array is not used
    */
    xdr_ip4_t ip4;
    
    xdr_array_t ip; // uint32
    xdr_string_t domain;
} 
xdr_dns_t;

typedef struct {
    xdr_file_t file;
    
    byte version;
    byte _;
    uint16 key_usage;
    
    xdr_time_t not_before;
    xdr_time_t not_after;
    
    char domain[1+XDR_DNS_DOMAIN_SIZE];
    xdr_string_t serial_number;
    xdr_string_t country_name;
    xdr_string_t organization_name;
    xdr_string_t organization_unit_name;
    xdr_string_t common_name;
} xdr_cert_t;

typedef struct {
    byte reason;
    byte verfy;
    byte verfy_failed_idx;
    byte _;

    xdr_string_t verfy_failed_desc;
    
    xdr_array_t cert_server; // xdr_cert_t
    xdr_array_t cert_client; // xdr_cert_t
} xdr_ssl_t;

enum {
    XDR_ALERT_IDS,
    XDR_ALERT_VDS,
    XDR_ALERT_WAF,

    XDR_ALERT_END
};

typedef struct {
    byte type;  // XDR_ALERT_END
    byte _[3];
} xdr_alert_t;

enum {
    XDR_F_FILE              = 0x0002,
    XDR_F_HTTP_REQUEST      = 0x0004,
    XDR_F_HTTP_RESPONSE     = 0x0008,
    XDR_F_SSL_SERVER_CERT   = 0x0010,
    XDR_F_SSL_CLIENT_CERT   = 0x0020,
};

enum {
    XDR_CLASS_COMMON    = 100,
    XDR_CLASS_NDS       = 101,
    XDR_CLASS_MMS       = 102,
    XDR_CLASS_HTTP      = 103,
    XDR_CLASS_FTP       = 104,
    XDR_CLASS_MAIL      = 105,
    XDR_CLASS_VOIP      = 106,
    XDR_CLASS_RTSP      = 107,
    XDR_CLASS_P2P       = 108,
    XDR_CLASS_VIDEO     = 109,
    XDR_CLASS_IM        = 110,
    XDR_CLASS_SSL       = 111,
};

struct xdr {
    byte version;   // xdr version, must first
    byte _0[3];
    
    byte appid;
    byte ip_proto;
    byte session_state;
    byte ip_version;

    bkdr_t bkdr;        // session bkdr
    time_t time;        // time of analysis xdr
    uint32 seq;
    uint32 flag;        // XDR_F_XXX
    xdr_size_t  total;  // total size
    xdr_delay_t first_response_delay;

    xdr_time_t session_time_create;
    xdr_time_t session_time_start;
    xdr_time_t session_time_stop;

    xdr_offset_t offsetof_session;
    xdr_offset_t offsetof_session_st;
    xdr_offset_t offsetof_service_st;
    xdr_offset_t offsetof_alert;
    xdr_offset_t offsetof_file_content;

    xdr_offset_t offsetof_L4; // tcp
    xdr_offset_t offsetof_L5; // http/sip/rtsp/ftp/mail/dns
    xdr_offset_t offsetof_L6; // ssl

    xdr_L7_t L7;

    byte body[0];
};

#define XDR_OBJ(_xdr, _offset)  ((_offset)?((byte *)(_xdr) + (_offset)):NULL)

static inline void
xdr_init(struct xdr *xdr)
{
    os_objzero(xdr);

    xdr->version= XDR_VERSION;
    xdr->time   = OS_VAR(time);
    xdr->seq    = OS_VAR(seq)++;
}

static inline int
xdr_open(struct xb *x, int size)
{
    int err = xb_open(x, false, size);
    if (0==err) {
        xdr_init(x->u.xdr);
    }

    return err;
}

static inline int
xdr_close(struct xb *x)
{
    if (x->u.xdr) {
        x->u.xdr->total = x->current;
    }

    if (x->fd<0) {
        ftruncate(x->fd, x->current);
    }

    return xb_close(x);
}

static inline xdr_session_t
xdr_session(struct xdr *xdr)
{
    xdr_session_t session = {
        .session = XDR_OBJ(xdr, xdr->offsetof_session),
    };

    return session;
}

static inline xdr_session_st_t *
xdr_session_st(struct xdr *xdr)
{
    return (xdr_session_st_t *)XDR_OBJ(xdr, xdr->offsetof_session_st);
}

static inline xdr_service_st_t *
xdr_service_st(struct xdr *xdr)
{
    return (xdr_service_st_t *)XDR_OBJ(xdr, xdr->offsetof_service_st);
}

static inline xdr_tcp_t *
xdr_tcp(struct xdr *xdr)
{
    return (xdr_tcp_t *)XDR_OBJ(xdr, xdr->offsetof_L4);
}

static inline xdr_http_t *
xdr_http(struct xdr *xdr)
{
    return (xdr_http_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_sip_t *
xdr_sip(struct xdr *xdr)
{
    return (xdr_sip_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_rtsp_t *
xdr_rtsp(struct xdr *xdr)
{
    return (xdr_rtsp_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_ftp_t *
xdr_ftp(struct xdr *xdr)
{
    return (xdr_ftp_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_mail_t *
xdr_mail(struct xdr *xdr)
{
    return (xdr_mail_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_dns_t *
xdr_dns(struct xdr *xdr)
{
    return (xdr_dns_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_ssl_t *
xdr_ssl(struct xdr *xdr)
{
    return (xdr_ssl_t *)XDR_OBJ(xdr, xdr->offsetof_L6);
}

static inline xdr_L7_t *
xdr_L7(struct xdr *xdr)
{
    return &xdr->L7;
}

static inline void *
xb_current(struct xb *x)
{
    return x->u.header + x->current;
}

static inline xdr_offset_t
xb_offset(struct xb *x, void *pointer)
{
    return pointer - x->u.header;
}

static inline xdr_size_t
xb_left(struct xb *x)
{
    return (x->size > x->current)?(x->size - x->current):0;
}

static inline bool
xb_enought(struct xb *x, xdr_size_t size)
{
    return xb_left(x) >= XDR_ALIGN(size);
}

static inline void *
xb_put(struct xb *x, xdr_size_t size)
{
    void *current = xb_current(x);
    
    //xdr_dprint("xb_put %d:%d ...", x->current, XDR_ALIGN(size));
    x->current += XDR_ALIGN(size);
    //xdr_dprint("xb_put %d:%d ok.", x->current, XDR_ALIGN(size));

    return current;
}

static inline int
xb_expand(struct xb *x, xdr_size_t size)
{
#define WORK_ID x->parse->wid
    if (false==xb_enought(x, size)) {
        int err;

        err = tlv_trace(xb_munmap(x), "xb_munmap");
        
        x->size += XDR_EXPAND_ALIGN(size);
        
        err = tlv_trace(xb_mmap(x, false), "xb_mmap");
        if (err<0) {
            return err;
        }
    }

    return 0;
#undef WORK_ID
}

static inline byte *
xb_obj(struct xb *x, xdr_offset_t offset)
{
    return XDR_OBJ(x->u.xdr, offset);
}

static inline void *
xb_pre(struct xb *x, xdr_size_t size)
{
    return (0==xb_expand(x, size))?xb_put(x, size):NULL;
}

static inline void *
xb_pre_obj(struct xb *x, xdr_size_t size, xdr_offset_t *poffset)
{
    xdr_offset_t offset = *poffset;
    if (offset) {
        return xb_obj(x, offset);
    }
    
    void *p = xb_pre(x, size);
    if (p) {
        *poffset = xb_offset(x, p);
    }

    return p;
}

static inline xdr_array_t *
xb_pre_array(struct xb *x, xdr_array_t *a, int type, xdr_size_t size, int count)
{
    xdr_size_t allsize = count * XDR_ALIGN(size);
    void *p = xb_pre(x, allsize);
    if (NULL==p) {
        return NULL;
    }

    a->type = type;
    a->size = size;
    a->count = count;

    return a;
}

static inline xdr_string_t *
xb_pre_string(struct xb *x, xdr_string_t *obj, void *buf, xdr_size_t size)
{
    void *p = xb_pre(x, XDR_ALIGN(1+size));
    if (NULL==p) {
        return NULL;
    }
    
    xdr_strcpy(p, buf, size);
    
    obj->size = size;
    obj->offset = xb_offset(x, p);

    return p;
}

static inline int
xb_pre_string_ex(struct xb *x, xdr_string_t *obj, struct tlv *tlv)
{
    return xb_pre_string(x, obj, tlv_data(tlv), tlv_datalen(tlv))?0:-ENOMEM;
}

static inline xdr_binary_t *
xb_pre_binnary(struct xb *x, xdr_binary_t *obj, void *buf, xdr_size_t size)
{
    void *p = xb_pre(x, XDR_ALIGN(size));
    if (NULL==p) {
        return NULL;
    }
    memcpy(p, buf, size);
    
    obj->size = size;
    obj->offset = xb_offset(x, p);

    return p;
}

static inline int
xb_pre_binary_ex(struct xb *x, xdr_binary_t *obj, struct tlv *tlv)
{
    return xb_pre_binnary(x, obj, tlv_data(tlv), tlv_datalen(tlv))?0:-ENOMEM;
}

static inline const char *
getdirbyflag(int flag)
{
    static nameflag_t opt[] = {
        { .flag = TLV_F_FILE_CONTENT,   .name = "file" },
        { .flag = TLV_F_HTTP,           .name = "http" },
        { .flag = TLV_F_CERT,           .name = "cert" },
    };

    return get_nameflag_byflag(opt, flag);
}

static inline char *
getshafilename(xpath_t *path, const char *dir, char *sha)
{
    char *p = path->filename;
    int len = strlen(dir);

    // push dir
    memcpy(p, dir, len); p += len; *p++ = '/';
    // push sha
    memcpy(p, sha, 2*XDR_DIGEST_SIZE); p[2*XDR_DIGEST_SIZE] = 0;
    
    return path->fullname;
}

static inline int
xb_pre_file_bybuffer(struct xb *x, xdr_file_t *file, struct tlv *tlv)
{
    const char *dir = getdirbyflag(tlv_ops_flag(tlv));
    if (NULL==dir) {
        return -ENOSUPPORT;
    }
    
    byte *buf   = tlv_data(tlv);
    int len     = tlv_binlen(tlv);

    sha256(buf, len, file->digest);
    file->bkdr = os_bkdr(file->digest, sizeof(file->digest));
    file->size = len;
    
    char digest[1+2*XDR_DIGEST_SIZE] = {0};
    os_bin2hex(digest, sizeof(digest)-1, file->digest, sizeof(file->digest));
    
    xpath_t *path = xp_path(x->parse, PATH_SHA);
    char *filename = getshafilename(path, dir, digest);
    
    if (os_fexist(filename)) {
        return 0;
    } else {
        
        return os_mmap_w_async(filename, buf, len);
    }
}

static inline int
xb_pre_file_bypath(struct xb *x, xdr_file_t *file, struct tlv *tlv)
{
    char fullname[1+OS_FILENAME_LEN];
    
    // todo: filename <== /PREFIX/tlv_string(tlv)
    
    int size = os_fdigest(fullname, file->digest);
    if (size < 0) {
        return size;
    }
    file->size = size;

    return 0;
}

static inline int
xb_pre_file(struct xb *x, xdr_file_t *file, struct tlv *tlv)
{
    int err;
    
    if (is_option(OPT_SPLIT)) {
        err = xb_pre_file_bypath(x, file, tlv);
    } else {
        err = xb_pre_file_bybuffer(x, file, tlv);
    }

    if (err<0) {
        return err;
    }

    x->u.xdr->flag |= tlv_ops_flag(tlv) & TLV_F_FILE;

    return 0;
}

static inline int
xb_pre_file_ex(struct xb *x, xdr_offset_t *poffset, struct tlv *tlv)
{
    xdr_file_t *file = (xdr_file_t *)xb_pre(x, sizeof(xdr_file_t));
    if (NULL==file) {
        return -ENOMEM;
    }

    int err = xb_pre_file(x, file, tlv);
    if (err<0) {
        return err;
    }

    *poffset = xb_offset(x, file);

    return 0;
}

#define xb_pre_by(_x, _type, _field_offsetof) \
    (_type *)xb_pre_obj(_x, sizeof(_type), &(_x)->u.xdr->_field_offsetof)

#define xb_pre_L4(_x, _type)    xb_pre_by(_x, _type, offsetof_L4)
#define xb_pre_L5(_x, _type)    xb_pre_by(_x, _type, offsetof_L5)
#define xb_pre_L6(_x, _type)    xb_pre_by(_x, _type, offsetof_L6)

static inline xdr_session4_t *
xb_pre_session4(struct xb *x)
{
    return xb_pre_by(x, xdr_session4_t, offsetof_session);
}

static inline xdr_session6_t *
xb_pre_session6(struct xb *x)
{
    return xb_pre_by(x, xdr_session6_t, offsetof_session);
}

static inline xdr_session_st_t *
xb_pre_session_st(struct xb *x)
{
    return xb_pre_by(x, xdr_session_st_t, offsetof_session_st);
}

static inline xdr_service_st_t *
xb_pre_service_st(struct xb *x)
{
    return xb_pre_by(x, xdr_service_st_t, offsetof_service_st);
}

static inline xdr_tcp_t *
xb_pre_tcp(struct xb *x)
{
    return xb_pre_L4(x, xdr_tcp_t);
}

static inline xdr_http_t *
xb_pre_http(struct xb *x)
{
    return xb_pre_L5(x, xdr_http_t);
}

static inline xdr_sip_t *
xb_pre_sip(struct xb *x)
{
    return xb_pre_L5(x, xdr_sip_t);
}

static inline xdr_rtsp_t *
xb_pre_rtsp(struct xb *x)
{
    return xb_pre_L5(x, xdr_rtsp_t);
}

static inline xdr_ftp_t *
xb_pre_ftp(struct xb *x)
{
    return xb_pre_L5(x, xdr_ftp_t);
}

static inline xdr_mail_t *
xb_pre_mail(struct xb *x)
{
    return xb_pre_L5(x, xdr_mail_t);
}

static inline xdr_dns_t *
xb_pre_dns(struct xb *x)
{
    return xb_pre_L5(x, xdr_dns_t);
}

static inline xdr_ssl_t *
xb_pre_ssl(struct xb *x)
{
    return xb_pre_L6(x, xdr_ssl_t);
}

#define to_xdr_by(_x, _tlv, _field, _nt)    ({(_x)->u.xdr->_field = tlv_##_nt(_tlv); 0; })
#define to_xdr_obj(_x, _tlv, _obj)          ({  \
    tlv_##_obj##_t *__src = tlv_##_obj(_tlv);   \
    xdr_##_obj##_t *__dst = xb_pre_##_obj(_x);  \
                                                \
    os_objcpy(__dst, __src);                    \
                                                \
    0;                                          \
})  /* end */


static inline int
to_xdr_session_state(struct xb *x, struct tlv *tlv)
{
    return to_xdr_by(x, tlv, session_state, u8);
}

static inline int
to_xdr_appid(struct xb *x, struct tlv *tlv)
{
    return to_xdr_by(x, tlv, appid, u8);
}

static inline int
to_xdr_session(struct xb *x, struct tlv *tlv)
{
    tlv_session_t *src = tlv_session(tlv);
    
    if (XDR_IPV4==src->ver) {
        xdr_session4_t *dst = xb_pre_session4(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        memcpy(dst, src, XDR_SESSION_HSIZE);

        dst->sip = XDR_IP(&src->sip);
        dst->dip = XDR_IP(&src->dip);

        x->u.xdr->bkdr = xdr_session_bkdr(dst);
    } else {
        xdr_session6_t *dst = xb_pre_session6(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        os_objcpy(dst, src);
        
        x->u.xdr->bkdr = xdr_session_bkdr(dst);
    }
    
    x->u.xdr->ip_version = src->ver;
    
    return 0;
}

static inline int
to_xdr_session_st(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, session_st);
}

static inline int
to_xdr_service_st(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, service_st);
}

static inline int
to_xdr_session_time(struct xb *x, struct tlv *tlv)
{
    tlv_session_time_t *tm = tlv_session_time(tlv);
    
    x->u.xdr->session_time_create = tm->create;
    x->u.xdr->session_time_start  = tm->start;
    x->u.xdr->session_time_stop   = tm->stop;

    return 0;
}

static inline int
to_xdr_tcp(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, tcp);
}

static inline int
to_xdr_first_response_delay(struct xb *x, struct tlv *tlv)
{
    return to_xdr_by(x, tlv, first_response_delay, u32);
}

static inline int
to_xdr_L7(struct xb *x, struct tlv *tlv)
{
    os_objcpy(&x->u.xdr->L7, tlv_L7(tlv));
    
    return 0;
}

static inline int
to_xdr_http(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, http);
}

static inline int
to_xdr_http_host(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->host, tlv);
}

static inline int
to_xdr_http_url(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->url, tlv);
}

static inline int
to_xdr_http_host_xonline(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->host_xonline, tlv);
}

static inline int
to_xdr_http_user_agent(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->user_agent, tlv);
}

static inline int
to_xdr_http_content(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->content, tlv);
}

static inline int
to_xdr_http_refer(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->refer, tlv);
}

static inline int
to_xdr_http_cookie(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->cookie, tlv);
}

static inline int
to_xdr_http_location(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->location, tlv);
}

static inline int
to_xdr_sip(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, sip);
}

static inline int
to_xdr_sip_calling_number(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->calling_number, tlv);
}

static inline int
to_xdr_sip_called_number(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->called_number, tlv);
}

static inline int
to_xdr_sip_session_id(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->session_id, tlv);
}

static inline int
to_xdr_rtsp(struct xb *x, struct tlv *tlv)
{
    return to_xdr_obj(x, tlv, rtsp);
}

static inline int
to_xdr_rtsp_url(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->url, tlv);
}

static inline int
to_xdr_rtsp_user_agent(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->user_agent, tlv);
}

static inline int
to_xdr_rtsp_server_ip(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->server_ip, tlv);
}

static inline int
to_xdr_ftp_status(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->status, tlv);
}

static inline int
to_xdr_ftp_user(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->user, tlv);
}

static inline int
to_xdr_ftp_pwd(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->pwd, tlv);
}

static inline int
to_xdr_ftp_trans_mode(struct xb *x, struct tlv *tlv)
{
    xb_pre_ftp(x)->trans_mode = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_ftp_trans_type(struct xb *x, struct tlv *tlv)
{
    xb_pre_ftp(x)->trans_type = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_ftp_filename(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->filename, tlv);
}

static inline int
to_xdr_ftp_filesize(struct xb *x, struct tlv *tlv)
{
    xb_pre_ftp(x)->filesize = tlv_u32(tlv);
    
    return 0;
}

static inline int
to_xdr_ftp_response_delay(struct xb *x, struct tlv *tlv)
{
    xb_pre_ftp(x)->response_delay = tlv_duration(tlv);
    
    return 0;
}

static inline int
to_xdr_ftp_trans_duration(struct xb *x, struct tlv *tlv)
{
    xb_pre_ftp(x)->trans_duration = tlv_duration(tlv);
    
    return 0;
}

static inline int
to_xdr_mail_msg_type(struct xb *x, struct tlv *tlv)
{
    xb_pre_mail(x)->msg_type = tlv_u16(tlv);
    
    return 0;
}

static inline int
to_xdr_mail_status_code(struct xb *x, struct tlv *tlv)
{
    xb_pre_mail(x)->status_code = tlv_i16(tlv);
    
    return 0;
}

static inline int
to_xdr_mail_user(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->user, tlv);
}

static inline int
to_xdr_mail_sender(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->sender, tlv);
}

static inline int
to_xdr_mail_length(struct xb *x, struct tlv *tlv)
{
    xb_pre_mail(x)->length = tlv_u32(tlv);
    
    return 0;
}

static inline int
to_xdr_mail_domain(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->domain, tlv);
}

static inline int
to_xdr_mail_recver(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->recver, tlv);
}

static inline int
to_xdr_mail_hdr(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->hdr, tlv);
}

static inline int
to_xdr_mail_acs_type(struct xb *x, struct tlv *tlv)
{
    xb_pre_mail(x)->acs_type = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_domain(struct xb *x, struct tlv *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_dns(x)->domain, tlv);
}

static inline int
to_xdr_dns_ip_count(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->ip_count = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_ip4(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->ip_version = XDR_IPV4;
    
    return 0;
}

static inline int
to_xdr_dns_ip6(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->ip_version = XDR_IPV6;
    
    return 0;
}

static inline int
to_xdr_dns_response_code(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->response_code = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_count_request(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->count_request = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_count_response_record(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->count_response_record = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_count_response_auth(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->count_response_auth = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_count_response_extra(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->count_response_extra = tlv_u8(tlv);
    
    return 0;
}

static inline int
to_xdr_dns_delay(struct xb *x, struct tlv *tlv)
{
    xb_pre_dns(x)->delay = tlv_u32(tlv);
    
    return 0;
}

static inline int
to_xdr_http_request(struct xb *x, struct tlv *tlv)
{
    int err = xb_pre_file_ex(x, &xb_pre_http(x)->offsetof_request, tlv);
    if (0==err) {
        x->parse->st_http_request->ok++;
    }

    return err;
}

static inline int
to_xdr_http_response(struct xb *x, struct tlv *tlv)
{
    int err = xb_pre_file_ex(x, &xb_pre_http(x)->offsetof_response, tlv);
    if (0==err) {
        x->parse->st_http_response->ok++;
    }

    return err;
}

static inline int
to_xdr_file_content(struct xb *x, struct tlv *tlv)
{
    int err = xb_pre_file_ex(x, &x->u.xdr->offsetof_file_content, tlv);
    if (0==err) {
        x->parse->st_file_content->ok++;
    }

    return err;
}

static inline int
to_xdr_ssl_server_cert(struct xb *x, struct tlv *tlv)
{
    return 0; // do nothing
}

static inline int
to_xdr_ssl_client_cert(struct xb *x, struct tlv *tlv)
{
    return 0; // do nothing
}

static inline int
to_xdr_ssl_fail_reason(struct xb *x, struct tlv *tlv)
{
    xb_pre_ssl(x)->reason = tlv_u8(tlv);
    
    return 0;
}


static inline int
to_xdr_dns(tlv_record_t *r, struct xb *x)
{
    xdr_dns_t *dns = xdr_dns(x->u.xdr);
    if (NULL==dns) {
        return 0;
    }

    xdr_size_t size, type;
    int id;
    
    if (XDR_IPV4 == dns->ip_version) {
        id = tlv_id_dns_ip4;
        type = XDR_ARRAY_ip4;
        size = sizeof(xdr_size_t);
    } else {
        id = tlv_id_dns_ip6;
        type = XDR_ARRAY_ip6;
        size = sizeof(xdr_ipaddr_t);
    }
    
    tlv_cache_t *cache = &r->cache[id];
    if (0==cache->count) {
        return 0;
    }
    
    int i, count = cache->count;

    if (1==count && XDR_IPV4==dns->ip_version) {
        dns->ip4 = tlv_u32(cache->multi[0]);

        return 0;
    }
    
    xdr_array_t *array = xb_pre_array(x, &dns->ip, type, size, count);
    if (NULL==array) {
        return -ENOMEM;
    }
    
    for (i=0; i<count; i++) {
        struct tlv *tlv = cache->multi[i];

        memcpy(xdr_array_entry(array, i), tlv_data(tlv), size);
    }

    return 0;
}

static inline int
to_xdr_ssl_helper(tlv_record_t *r, struct xb *x, xdr_array_t *certs, int id)
{
    tlv_cache_t *cache = &r->cache[id];
    if (0==cache->count) {
        return 0;
    }
    
    int i, err, count = cache->count;
    xdr_cert_t *cert;
    
    xdr_array_t *array = xb_pre_array(x, certs, XDR_ARRAY_cert, sizeof(xdr_cert_t), count);
    if (NULL==array) {
        return -ENOMEM;
    }
    
    for (i=0; i<count; i++) {
        cert = (xdr_cert_t *)xdr_array_entry(array, i);

        err = xb_pre_file(x, &cert->file, cache->multi[i]);
        if (err<0) {
            return err;
        }
    }

    switch (id) {
        case tlv_id_ssl_server_cert:
            x->parse->st_ssl_server->ok += count;
            break;
        case tlv_id_ssl_client_cert:
            x->parse->st_ssl_client->ok += count;
            break;
    }

    return 0;
}

static inline int
to_xdr_ssl(tlv_record_t *r, struct xb *x)
{
    xdr_ssl_t *ssl = xdr_ssl(x->u.xdr);
    if (NULL==ssl) {
        return 0;
    }
    
    int err;

    err = to_xdr_ssl_helper(r, x, &ssl->cert_server, tlv_id_ssl_server_cert);
    if (err<0) {
        return err;
    }

    err = to_xdr_ssl_helper(r, x, &ssl->cert_client, tlv_id_ssl_client_cert);
    if (err<0) {
        return err;
    }
    
    return 0;
}

static inline int
to_xdr_helper(tlv_cache_t *cache, struct xb *x)
{
    tlv_ops_t *ops;
    struct tlv *tlv;
    int i, err;

    if (cache->count>0) {
        for (i=0; i<cache->count; i++) {
            tlv = cache->multi[i];
            ops = tlv_ops(tlv);

            if (ops && ops->toxdr) {
                err = (*ops->toxdr)(x, tlv);
                if (err<0) {
                    if (tlv->id>200) {
                        // xdr_dprint("toxdr %d:%d %s:%d.", i, tlv->id, ok_string(err), err);
                    }
                    
                    return err;
                }
            }
        }
    }

    return 0;
}

static inline int
to_xdr(tlv_record_t *r, struct xb *x)
{
    int i, err;

    for (i=tlv_id_header; i<tlv_id_low_end; i++) {
        err = to_xdr_helper(&r->cache[i], x);
        if (err<0) {
            return err;
        }
    }

    for (i=tlv_id_high_begin; i<tlv_id_end; i++) {
        err = to_xdr_helper(&r->cache[i], x);
        if (err<0) {
            return err;
        }
    }
    
    err = to_xdr_ssl(r, x);
    if (err<0) {
        return err;
    }

    err = to_xdr_dns(r, x);
    if (err<0) {
        return err;
    }
    
    return 0;
}

static inline int
xp_run(struct xparse *parse)
{
    int walk(struct xparse *parse, struct tlv *header)
    {
#define WORK_ID parse->wid
        tlv_record_t r = TLV_RECORD_INITER(parse);
        int err;

        err = tlv_trace(tlv_record_parse(&r), "tlv_record_parse:%d", parse->count);
        if (err<0) {
            parse->st_xdr->error++;
            return err;
        }

        err = tlv_trace(to_xdr(&r, &parse->xdr), "to_xdr:%d", parse->count);
        if (err<0) {
            parse->st_xdr->error++;
            return err;
        }

        parse->count++;
        parse->st_xdr->ok++;
        
        return 0;
#undef WORK_ID
    }

    return tlv_walk(parse, parse->tlv.u.tlv, parse->tlv.size, walk);
}
/******************************************************************************/
#endif /* __XDR_H_049defbc41a4441e855ee0479dad96eb__ */
