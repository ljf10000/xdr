#ifndef __XDR_H_049defbc41a4441e855ee0479dad96eb__
#define __XDR_H_049defbc41a4441e855ee0479dad96eb__
/******************************************************************************/
#include "tlv.h"
/******************************************************************************/
#ifndef XDR_VERSION
#define XDR_VERSION     0
#endif

#ifndef XDR_EXPAND
#define XDR_EXPAND      (32*1024)
#endif

#define XDR_ALIGN(x)    OS_ALIGN(x, 4)

typedef uint32 xdr_offset_t;
typedef uint64 big_offset_t;

static inline void *
xdr_strcpy(void *dst, void *src, uint32 size)
{
    byte *p = (byte *)memcpy(dst, src, size);
    
    p[size] = 0;
    
    return p;
}

typedef struct {
    /*
    * not include '\0'
    *   real len must align 4
    */
    uint32 len;
    xdr_offset_t offset;
} xdr_string_t, xdr_binary_t;

enum {
    XDR_FILE_FILE,
    XDR_FILE_HTTP,
    XDR_FILE_CERT,

    XDR_FILE_END
};

enum {
    XDR_ARRAY_STRING,
    XDR_ARRAY_IP4,
    XDR_ARRAY_IP6,
    XDR_ARRAY_CERT,
    
    XDR_ARRAY_END
};

typedef struct {
    uint32 size;

    byte count;
    byte type;    // XDR_ARRAY_END
    byte _[2];

    byte entry[0];
} xdr_array_t;

static inline byte *
xdr_array_entry(xdr_array_t *array, int idx)
{
    return array->entry + (array->size * idx);
}

typedef struct {
    byte ver;
    byte dir;
    byte proto;
    byte _;
    
    uint16 sport;
    uint16 dport;
    
    uint32 sip;
    uint32 dip;
} xdr_session4_t;

typedef union {
    xdr_session4_t *session4;
    xdr_session6_t *session6;

    void *session;
} xdr_session_t;

enum { XDR_DIGEST_SIZE = SHA256_DIGEST_SIZE };

#define XDR_HDFS_FILENAME   "2017-01-01/0000"           // 15

typedef struct {
    bkdr_t bkdr;
    uint32 size;    // cookie size, cookie is the small file
    byte digest[XDR_DIGEST_SIZE];
    byte _[20];      // keep sizeof(xf_cookie_t) == 60
    
    byte body[0];
} xf_cookie_t;

/*
* file      := count + xdr + cookies
* cookies   := cookie ...
*/
typedef struct {
    uint32 count;   // cookie count
    
    xdr_t xdrs[0];
} xf_file_t;

typedef struct {
    uint32 size;    // real file size
    byte digest[XDR_DIGEST_SIZE];

    /*
    * file as buffer:
    *   file.len is file size
    *   file.offset store file content
    *
    * file as path:
    *   file.len is strlen(path)
    *   file.offset store path
    */
    xdr_string_t file;  // local file

    big_offset_t offset;// for hdfs
    char hdfs[1+sizeof(XDR_HDFS_FILENAME)];
} xdr_file_t;

typedef struct {
    // begin, same as xtlv_http_t
    xdr_time_t time_request;
    xdr_time_t time_first_response;
    xdr_time_t time_last_content;
    xdr_duration_t service_delay;
    
    uint32 content_length;
    
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
    // end, same as xtlv_http_t
    
    xdr_string_t host;
    xdr_string_t url;
    xdr_string_t host_xonline;
    xdr_string_t user_agent;
    xdr_string_t content;
    xdr_string_t refer;
    xdr_string_t cookie;
    xdr_string_t location;

    xdr_offset_t offsetof_request;    // xdr_file_t
    xdr_offset_t offsetof_response;   // xdr_file_t
} 
xdr_http_t;

typedef struct {
    // begin, same as xtlv_sip_t
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
    // end, same as xtlv_sip_t
    
    xdr_string_t calling_number;
    xdr_string_t called_number;
    xdr_string_t session_id;
}
xdr_sip_t;

typedef struct {
    // begin, same as xtlv_rtsp_t
    uint16 port_client_start;
    uint16 port_client_end;
    uint16 port_server_start;
    uint16 port_server_end;
    uint16 count_video;
    uint16 count_audio;
    
    uint32 describe_delay;
    // end, same as xtlv_rtsp_t
    
    xdr_string_t url;
    xdr_string_t user_agent;
    xdr_string_t server_ip;
} xdr_rtsp_t;

typedef struct {
    byte trans_mode;
    byte trans_type;
    byte _[2];
    
    uint32 filesize;
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
    uint32 length;
    
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

    uint32 delay;
    /*
    * if 1==ip_count, 0==ip_version
    *   then 
    *       ip4 is the ip address
    *       the ip array is not used
    */
    uint32 ip4;
    
    xdr_array_t ip; // uint32
    xdr_string_t domain;
} 
xdr_dns_t;

typedef struct {
    xdr_file_t file;
    
    char domain[1+XDR_DNS_DOMAIN_SIZE];
} xdr_cert_t;

typedef struct {
    byte reason;
    byte _[3];

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
    XDR_F_IPV6              = 0x0001,
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
};

typedef struct {
    byte version;   // xdr version
    byte appid;
    byte ip_proto;
    byte session_state;

    byte ip_version;
    byte _[3];
    
    xdr_time_t session_time_create;
    xdr_time_t session_time_start;
    xdr_time_t session_time_stop;
    
    bkdr_t bkdr;

    uint32 total;   // total size
    uint32 flag;    // XDR_F_XXX
    uint32 first_response_delay;

    xdr_offset_t offsetof_session;
    xdr_offset_t offsetof_session_st;
    xdr_offset_t offsetof_service_st;
    xdr_offset_t offsetof_alert;
    xdr_offset_t offsetof_file_content;
    // tcp
    xdr_offset_t offsetof_L4;
    // http/sip/rtsp/ftp/mail/dns
    xdr_offset_t offsetof_L5;
    // ssl
    xdr_offset_t offsetof_L6;

    xdr_L7_t L7;

    byte body[0];
} 
xdr_t;

#define XDR_OBJ(_proto, _offset)    ((_offset)?((byte *)(_proto) + (_offset)):NULL)

static inline xdr_session_t
xdr_session(xdr_t *xdr)
{
    xdr_session_t session = {
        .session = XDR_OBJ(xdr, xdr->offsetof_session),
    };

    return session;
}

static inline xdr_session_st_t *
xdr_session_st(xdr_t *xdr)
{
    return (xdr_session_st_t *)XDR_OBJ(xdr, xdr->offsetof_session_st);
}

static inline xdr_service_st_t *
xdr_service_st(xdr_t *xdr)
{
    return (xdr_service_st_t *)XDR_OBJ(xdr, xdr->offsetof_service_st);
}

static inline xdr_tcp_t *
xdr_tcp(xdr_t *xdr)
{
    return (xdr_tcp_t *)XDR_OBJ(xdr, xdr->offsetof_L4);
}

static inline xdr_http_t *
xdr_http(xdr_t *xdr)
{
    return (xdr_http_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_sip_t *
xdr_sip(xdr_t *xdr)
{
    return (xdr_sip_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_rtsp_t *
xdr_rtsp(xdr_t *xdr)
{
    return (xdr_rtsp_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_ftp_t *
xdr_ftp(xdr_t *xdr)
{
    return (xdr_ftp_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_mail_t *
xdr_mail(xdr_t *xdr)
{
    return (xdr_mail_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_dns_t *
xdr_dns(xdr_t *xdr)
{
    return (xdr_dns_t *)XDR_OBJ(xdr, xdr->offsetof_L5);
}

static inline xdr_ssl_t *
xdr_ssl(xdr_t *xdr)
{
    return (xdr_ssl_t *)XDR_OBJ(xdr, xdr->offsetof_L6);
}

static inline xdr_L7_t *
xdr_L7(xdr_t *xdr)
{
    return &xdr->L7;
}

struct xdr_buffer_st {
    union {
        void *buffer;
        xdr_t *xdr;
    } u;
    
    xdr_offset_t offset;
    uint32 size;
};

static inline void *
xb_current(xdr_buffer_t *x)
{
    return x->u.buffer + x->offset;
}

static inline xdr_offset_t
xb_offset(xdr_buffer_t *x, void *pointer)
{
    return pointer - (void *)x;
}

static inline uint32
xb_left(xdr_buffer_t *x)
{
    return (x->size > x->offset)?(x->size - x->offset):0;
}

static inline bool
xb_enought(xdr_buffer_t *x, uint32 size)
{
    return xb_left(x) >= XDR_ALIGN(size);
}

static inline void
xb_put(xdr_buffer_t *x, uint32 size)
{
    x->offset += XDR_ALIGN(size);
}

static inline int
xb_expand(xdr_buffer_t *x, uint32 size)
{
    if (false==xb_enought(x, size)) {
        uint32 expand = os_max(XDR_EXPAND, size);
        
        x->u.buffer = os_realloc(x->u.buffer, x->size + expand);
        if (NULL==x->u.buffer) {
            return -ENOMEM;
        }
        
        x->size += expand;
    }

    return 0;
}

static inline byte *
xb_obj(xdr_buffer_t *x, xdr_offset_t offset)
{
    return XDR_OBJ(x->u.xdr, offset);
}

static inline byte *
xb_pre(xdr_buffer_t *x, uint32 size)
{
    if (xb_expand(x, size) < 0) {
        return NULL;
    }
    
    byte *current = (byte *)xb_current(x);
    
    xb_put(x, size);
    
    return current;
}

static inline void *
xb_pre_obj(xdr_buffer_t *x, uint32 size, xdr_offset_t *poffset)
{
    xdr_offset_t offset = *poffset;
    if (offset) {
        return xb_obj(x, offset);
    }
    
    byte *p = xb_pre(x, size);
    if (NULL==p) {
        return NULL;
    }

    *poffset = xb_offset(x, p);

    return p;
}

static inline xdr_array_t *
xb_pre_array(xdr_buffer_t *x, xdr_array_t *a, uint32 type, uint32 size, uint32 count)
{
    uint32 allsize = count * XDR_ALIGN(size);
    byte *p = xb_pre(x, allsize);
    if (NULL==p) {
        return NULL;
    }

    a->type = type;
    a->size = size;
    a->count = count;

    return a;
}

static inline xdr_string_t *
xb_pre_string(xdr_buffer_t *x, xdr_string_t *obj, void *buf, uint32 len)
{
    xdr_string_t *p = (xdr_string_t *)xb_pre(x, XDR_ALIGN(1+len));
    if (NULL==p) {
        return NULL;
    }
    xdr_strcpy(p, buf, len);
    
    obj->len = len;
    obj->offset = xb_offset(x, p);

    return p;
}

static inline int
xb_pre_string_ex(xdr_buffer_t *x, xdr_string_t *obj, xtlv_t *tlv)
{
    return xb_pre_string(x, obj, xtlv_data(tlv), xtlv_datalen(tlv))?0:-ENOMEM;
}

static inline xdr_binary_t *
xb_pre_binnary(xdr_buffer_t *x, xdr_binary_t *obj, void *buf, uint32 len)
{
    xdr_binary_t *p = (xdr_binary_t *)xb_pre(x, XDR_ALIGN(len));
    if (NULL==p) {
        return NULL;
    }
    memcpy(p, buf, len);
    
    obj->len = len;
    obj->offset = xb_offset(x, p);

    return p;
}

static inline int
xb_pre_binary_ex(xdr_buffer_t *x, xdr_binary_t *obj, xtlv_t *tlv)
{
    return xb_pre_binnary(x, obj, xtlv_data(tlv), xtlv_datalen(tlv))?0:-ENOMEM;
}

static inline int
xb_pre_file_as_file(xdr_buffer_t *x, xdr_file_t *file, xtlv_t *tlv, uint32 flag)
{
    uint32 size = xtlv_datalen(tlv);
    byte *buf = xtlv_data(tlv);
    
    // todo: save file
    char path[1+OS_FILENAME_LEN];
    
    if (NULL==xb_pre_string(x, &file->file, path, strlen(path))) {
        return -ENOMEM;
    }

    file->size     = size;
    sha256(buf, size, file->digest);
    
    x->u.xdr->flag |= flag;

    return 0;
}

static inline int
xb_pre_file_as_path(xdr_buffer_t *x, xdr_file_t *file, xtlv_t *tlv, uint32 flag)
{
    char *filename = xtlv_string(tlv);
    if (NULL==xb_pre_string(x, &file->file, filename, strlen(filename))) {
        return -ENOMEM;
    }

    int size = os_fdigest(filename, file->digest);
    if (size < 0) {
        return size;
    }
    file->size     = size;
    x->u.xdr->flag |= flag;
    
    return 0;
}

static inline int
xb_pre_file(xdr_buffer_t *x, xdr_file_t *file, xtlv_t *tlv, uint32 flag)
{
    if (is_xtlv_opt_file_as_path()) {
        return xb_pre_file_as_path(x, file, tlv, flag);
    } else {
        return xb_pre_file_as_file(x, file, tlv, flag);
    }
}

static inline int
xb_pre_file_ex(xdr_buffer_t *x, xdr_offset_t *poffset, xtlv_t *tlv, uint32 flag)
{
    xdr_file_t *file = (xdr_file_t *)xb_pre(x, sizeof(xdr_file_t));
    if (NULL==file) {
        return -ENOMEM;
    }

    int err = xb_pre_file(x, file, tlv, flag);
    if (err<0) {
        return err;
    }

    *poffset = xb_offset(x, file);

    return 0;
}

#define xb_pre_by(_x, _type, _field_offsetof) \
    (_type *)xb_pre_obj(_x, sizeof(_type), &(_x)->u.proto->_field_offsetof)

#define xb_pre_L4(_x, _type)    xb_pre_by(_x, _type, offsetof_L4)
#define xb_pre_L5(_x, _type)    xb_pre_by(_x, _type, offsetof_L5)
#define xb_pre_L6(_x, _type)    xb_pre_by(_x, _type, offsetof_L6)

static inline xdr_session4_t *
xb_pre_session4(xdr_buffer_t *x)
{
    return xb_pre_by(x, xdr_session4_t, offsetof_session);
}

static inline xdr_session6_t *
xb_pre_session6(xdr_buffer_t *x)
{
    return xb_pre_by(x, xdr_session6_t, offsetof_session);
}

static inline xdr_session_st_t *
xb_pre_session_st(xdr_buffer_t *x)
{
    return xb_pre_by(x, xdr_session_st_t, offsetof_session_st);
}

static inline xdr_service_st_t *
xb_pre_service_st(xdr_buffer_t *x)
{
    return xb_pre_by(x, xdr_service_st_t, offsetof_service_st);
}

static inline xdr_tcp_t *
xb_pre_tcp(xdr_buffer_t *x)
{
    return xb_pre_L4(x, xdr_tcp_t);
}

static inline xdr_http_t *
xb_pre_http(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_http_t);
}

static inline xdr_sip_t *
xb_pre_sip(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_sip_t);
}

static inline xdr_rtsp_t *
xb_pre_rtsp(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_rtsp_t);
}

static inline xdr_ftp_t *
xb_pre_ftp(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_ftp_t);
}

static inline xdr_mail_t *
xb_pre_mail(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_mail_t);
}

static inline xdr_dns_t *
xb_pre_dns(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_dns_t);
}

static inline xdr_ssl_t *
xb_pre_ssl(xdr_buffer_t *x)
{
    return xb_pre_L6(x, xdr_ssl_t);
}

#define xtlv_to_xdr_by(_x, _tlv, _field, _nt)    ({(_x)->u.proto->_field = xtlv_##_nt(_tlv); 0; })
#define xtlv_to_xdr_obj(_x, _tlv, _obj)         ({ \
    xtlv_##_obj##_t *__src = xtlv_##_obj(_tlv);     \
    xdr_##_obj##_t *__dst = xb_pre_##_obj(_x);      \
                                                    \
    os_objcpy(__dst, __src);                        \
                                                    \
    0;                                              \
})  /* end */


static inline int
xtlv_to_xdr_session_state(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_by(x, tlv, session_state, u8);
}

static inline int
xtlv_to_xdr_appid(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_by(x, tlv, appid, u8);
}

static inline int
xtlv_to_xdr_session(xdr_buffer_t *x, xtlv_t *tlv)
{
    xtlv_session_t *src = xtlv_session(tlv);
    
    if (XDR_IPV4==src->ver) {
        xdr_session4_t *dst = xb_pre_session4(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        memcpy(dst, src, XDR_SESSION_HSIZE);

        dst->sip = XDR_IP(&src->sip);
        dst->dip = XDR_IP(&src->dip);

        x->u.xdr->bkdr = os_bkdr(dst, sizeof(*dst));
    } else {
        xdr_session6_t *dst = xb_pre_session6(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        os_objcpy(dst, src);
        
        x->u.xdr->bkdr = os_bkdr(dst, sizeof(*dst));
    }
    
    x->u.xdr->ip_version = src->ver;
    
    return 0;
}

static inline int
xtlv_to_xdr_session_st(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, session_st);
}

static inline int
xtlv_to_xdr_service_st(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, service_st);
}

static inline int
xtlv_to_xdr_session_time(xdr_buffer_t *x, xtlv_t *tlv)
{
    xtlv_session_time_t *tm = xtlv_session_time(tlv);
    
    x->u.xdr->session_time_create = tm->create;
    x->u.xdr->session_time_start  = tm->start;
    x->u.xdr->session_time_stop   = tm->stop;

    return 0;
}

static inline int
xtlv_to_xdr_tcp(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, tcp);
}

static inline int
xtlv_to_xdr_first_response_delay(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_by(x, tlv, first_response_delay, u32);
}

static inline int
xtlv_to_xdr_L7(xdr_buffer_t *x, xtlv_t *tlv)
{
    os_objcpy(&x->u.xdr->L7, xtlv_L7(tlv));
    
    return 0;
}

static inline int
xtlv_to_xdr_http(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, http);
}

static inline int
xtlv_to_xdr_http_host(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->host, tlv);
}

static inline int
xtlv_to_xdr_http_url(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->url, tlv);
}

static inline int
xtlv_to_xdr_http_host_xonline(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->host_xonline, tlv);
}

static inline int
xtlv_to_xdr_http_user_agent(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->user_agent, tlv);
}

static inline int
xtlv_to_xdr_http_content(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->content, tlv);
}

static inline int
xtlv_to_xdr_http_refer(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->refer, tlv);
}

static inline int
xtlv_to_xdr_http_cookie(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->cookie, tlv);
}

static inline int
xtlv_to_xdr_http_location(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_http(x)->location, tlv);
}

static inline int
xtlv_to_xdr_sip(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, sip);
}

static inline int
xtlv_to_xdr_sip_calling_number(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->calling_number, tlv);
}

static inline int
xtlv_to_xdr_sip_called_number(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->called_number, tlv);
}

static inline int
xtlv_to_xdr_sip_session_id(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_sip(x)->session_id, tlv);
}

static inline int
xtlv_to_xdr_rtsp(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, rtsp);
}

static inline int
xtlv_to_xdr_rtsp_url(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->url, tlv);
}

static inline int
xtlv_to_xdr_rtsp_user_agent(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->user_agent, tlv);
}

static inline int
xtlv_to_xdr_rtsp_server_ip(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_rtsp(x)->server_ip, tlv);
}

static inline int
xtlv_to_xdr_ftp_status(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->status, tlv);
}

static inline int
xtlv_to_xdr_ftp_user(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->user, tlv);
}

static inline int
xtlv_to_xdr_ftp_pwd(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->pwd, tlv);
}

static inline int
xtlv_to_xdr_ftp_trans_mode(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ftp(x)->trans_mode = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_ftp_trans_type(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ftp(x)->trans_type = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_ftp_filename(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_ftp(x)->filename, tlv);
}

static inline int
xtlv_to_xdr_ftp_filesize(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ftp(x)->filesize = xtlv_u32(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_ftp_response_delay(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ftp(x)->response_delay = xtlv_duration(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_ftp_trans_duration(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ftp(x)->trans_duration = xtlv_duration(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_mail_msg_type(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_mail(x)->msg_type = xtlv_u16(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_mail_status_code(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_mail(x)->status_code = xtlv_i16(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_mail_user(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->user, tlv);
}

static inline int
xtlv_to_xdr_mail_sender(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->sender, tlv);
}

static inline int
xtlv_to_xdr_mail_length(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_mail(x)->length = xtlv_u32(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_mail_domain(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->domain, tlv);
}

static inline int
xtlv_to_xdr_mail_recver(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->recver, tlv);
}

static inline int
xtlv_to_xdr_mail_hdr(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_mail(x)->hdr, tlv);
}

static inline int
xtlv_to_xdr_mail_acs_type(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_mail(x)->acs_type = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_domain(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_string_ex(x, &xb_pre_dns(x)->domain, tlv);
}

static inline int
xtlv_to_xdr_dns_ip_count(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->ip_count = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_ip4(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->ip_version = XDR_IPV4;
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_ip6(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->ip_version = XDR_IPV6;
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_response_code(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->response_code = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_count_request(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->count_request = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_count_response_record(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->count_response_record = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_count_response_auth(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->count_response_auth = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_count_response_extra(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->count_response_extra = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_dns_delay(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_dns(x)->delay = xtlv_u32(tlv);
    
    return 0;
}

static inline int
xtlv_to_xdr_http_request(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_file_ex(x, &xb_pre_http(x)->offsetof_request, tlv, XDR_F_HTTP_REQUEST);
}

static inline int
xtlv_to_xdr_http_response(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_file_ex(x, &xb_pre_http(x)->offsetof_response, tlv, XDR_F_HTTP_RESPONSE);
}

static inline int
xtlv_to_xdr_file_content(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_file_ex(x, &x->u.xdr->offsetof_file_content, tlv, XDR_F_FILE);
}

static inline int
xtlv_to_xdr_ssl_server_cert(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0; // do nothing
}

static inline int
xtlv_to_xdr_ssl_client_cert(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0; // do nothing
}

static inline int
xtlv_to_xdr_ssl_fail_reason(xdr_buffer_t *x, xtlv_t *tlv)
{
    xb_pre_ssl(x)->reason = xtlv_u8(tlv);
    
    return 0;
}

static inline int
xtlv_record_to_xdr_dns(xdr_buffer_t *x, xtlv_record_t *r)
{
    xdr_dns_t *dns = xdr_dns(x->u.xdr);
    if (NULL==dns) {
        return 0;
    }

    uint32 size, type;
    int id;
    
    if (XDR_IPV4 == dns->ip_version) {
        id = xtlv_id_dns_ip4;
        type = XDR_ARRAY_IP4;
        size = sizeof(uint32);
    } else {
        id = xtlv_id_dns_ip6;
        type = XDR_ARRAY_IP6;
        size = sizeof(xdr_ipaddr_t);
    }
    
    xtlv_cache_t *cache = &r->cache[id];
    if (is_xtlv_cache_empty(cache)) {
        return 0;
    }
    
    int i, count = xtlv_cache_multi_count(cache);

    if (1==count && XDR_IPV4==dns->ip_version) {
        dns->ip4 = xtlv_u32(cache->tlv);

        return 0;
    }
    
    xdr_array_t *array = xb_pre_array(x, &dns->ip, type, size, count);
    if (NULL==array) {
        return -ENOMEM;
    }
    
    for (i=0; i<count; i++) {
        xtlv_t *tlv = cache->multi[i];

        memcpy(xdr_array_entry(array, i), xtlv_data(tlv), size);
    }

    return 0;
}

static inline int
xtlv_record_to_xdr_ssl_cert(xdr_buffer_t *x, xdr_array_t *certs, xtlv_record_t *r, int id)
{
    uint32 flag = 0;
    
    switch (id) {
        case xtlv_id_ssl_server_cert:
            flag = XDR_F_SSL_SERVER_CERT;
            break;
        case xtlv_id_ssl_client_cert:
            flag = XDR_F_SSL_CLIENT_CERT;
            break;
        default:
            return -1;
    }
    
    xtlv_cache_t *cache = &r->cache[id];
    if (is_xtlv_cache_empty(cache)) {
        return 0;
    }
    
    int i, err, count = xtlv_cache_multi_count(cache);
    xdr_cert_t *cert;
    
    xdr_array_t *array = xb_pre_array(x, certs, XDR_ARRAY_CERT, sizeof(xdr_cert_t), count);
    if (NULL==array) {
        return -ENOMEM;
    }
    
    for (i=0; i<count; i++) {
        cert = (xdr_cert_t *)xdr_array_entry(array, i);

        err = xb_pre_file(x, &cert->file, xtlv_cache_multi_tlv(cache, i), flag);
        if (err<0) {
            return err;
        }
    }

    return 0;
}

static inline int
xtlv_record_to_xdr_ssl(xdr_buffer_t *x, xtlv_record_t *r)
{
    xdr_ssl_t *ssl = xdr_ssl(x->u.xdr);
    if (NULL==ssl) {
        return 0;
    }
    
    int err;

    err = xtlv_record_to_xdr_ssl_cert(x, &ssl->cert_server, r, xtlv_id_ssl_server_cert);
    if (err<0) {
        return err;
    }

    err = xtlv_record_to_xdr_ssl_cert(x, &ssl->cert_client, r, xtlv_id_ssl_client_cert);
    if (err<0) {
        return err;
    }
    
    return 0;
}

static inline int
xtlv_record_to_xdr(xdr_buffer_t *x, xtlv_record_t *r)
{
    int i, err;

    err = xtlv_record_to_xdr_ssl(x, r);
    if (err<0) {
        return err;
    }

    err = xtlv_record_to_xdr_dns(x, r);
    if (err<0) {
        return err;
    }

    return 0;
}

/******************************************************************************/
#endif /* __XDR_H_049defbc41a4441e855ee0479dad96eb__ */
