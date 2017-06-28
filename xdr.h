#ifndef __XDR_H_049defbc41a4441e855ee0479dad96eb__
#define __XDR_H_049defbc41a4441e855ee0479dad96eb__
/******************************************************************************/
#include "tlv.h"
/******************************************************************************/
#define XDR_IN
#define XDR_OUT
#define XDR_INOUT

#define XDR_ALIGN(x)    OS_ALIGN(x, 4)

enum { XDR_EXPAND = 32*1024 };

static inline void *
xdr_strcpy(void *dst, void *src, uint32 size)
{
    byte *p = (byte *)memcpy(dst, src, size);
    
    p[size] = 0;
    
    return p;
}

enum {
    XDR_F_IPV6  = 0x0001,
};

enum {
    XDR_OBJ_STRING,
    XDR_OBJ_IP4,
    XDR_OBJ_IP6,
    XDR_OBJ_CERT,
    
    XDT_OBJ_END
};

typedef struct {
    /*
    * not include '\0'
    *   real len must align 4
    */
    uint32 len;
    uint32 offset;
} xdr_string_t, xdr_binary_t;

typedef struct {
    uint32 offset;
    uint16 count;
    uint16 type;    // XDT_OBJ_END
    uint32 size;
} xdr_array_t;

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

typedef xtlv_session_t xdr_session6_t;

typedef union {
    xdr_session4_t *session4;
    xdr_session6_t *session6;

    void *session;
} xdr_session_t;

typedef struct {
    uint32 flow;
    uint32 ip_packet;
    uint32 ip_frag;
    uint32 tcp_disorder;
    uint32 tcp_retransmit;
    
    uint16 duration;
    uint16 _;
} xdr_session_st_t, xdr_service_st_t;

typedef xtlv_session_time_t xdr_session_time_t;

static inline xdr_session_time_t *
alloc_xdr_session_time(xdr_buffer_t *x)
{
    return NULL;
}

typedef xtlv_tcp_t   xdr_tcp_t;
typedef xtlv_L7_t    xdr_L7_t;

enum { XDR_DIGEST_SIZE = SHA256_DIGEST_SIZE };

typedef struct {
    uint64 offset;
    uint32 size;
    uint32 hash;
    byte digest[XDR_DIGEST_SIZE];
    xdr_string_t path;
} xdr_file_t;

typedef struct {
    // begin, same as xtlv_http_t
    uint64 time_request;
    uint64 time_first_response;
    uint64 time_last_content;
    uint64 service_delay;
    
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

    uint32 offsetof_request;    // xdr_file_t
    uint32 offsetof_response;   // xdr_file_t
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

typedef struct {
    byte response_code;
    byte count_request;
    byte count_response_record;
    byte count_response_auth;
    
    byte count_response_extra;
    byte ip_version;
    byte _[2];

    uint32 delay;
    
    xdr_array_t ip; // entry is uint32
    xdr_string_t domain;
} xdr_dns_t;

typedef struct {
    // begin same as xdr_file_t
    uint64 offset;
    uint32 size;
    uint32 hash;
    byte digest[XDR_DIGEST_SIZE];
    xdr_string_t path;
    // end same as xdr_file_t
    
    xdr_string_t domain;
} xdr_cert_t;

typedef struct {
    byte reason;
    byte _[3];

    xdr_array_t cert_server; // array of xdr_cert_t
    xdr_array_t cert_client; // array of xdr_cert_t
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

typedef struct {
    byte version;   // xdr version
    byte appid;
    byte ip_proto;
    byte session_state;
    
    uint32 total;
    uint32 flag;
    uint32 first_response_delay;

    uint32 offsetof_session;
    uint32 offsetof_session_time;
    uint32 offsetof_session_st; // up && down
    uint32 offsetof_service_st; // up && down
    uint32 offsetof_alert;
    uint32 offsetof_file;
    // tcp
    uint32 offsetof_L4;
    // http/sip/rtsp/ftp/mail/dns
    uint32 offsetof_L5;
    // ssl
    uint32 offsetof_L6;

    xdr_L7_t L7;
} 
xdr_proto_t;

static inline void *
xdr_proto_obj(xdr_proto_t *proto, uint32 offset)
{
    return (byte *)proto + offset;
}


enum {
    XFILE_FILE              = 0x01,
    XFILE_HTTP_REQUEST      = 0x02,
    XFILE_HTTP_RESPONSE     = 0x04,
};

typedef struct {
    uint64 offset;
    uint32 size;    // cookie size, cookie is the small file
    uint32 hash;
    uint32 flag;
    byte digest[XDR_DIGEST_SIZE];
    byte _[8];      // keep sizeof(xdr_cookie_t) == 60
    
    byte body[0];
} xdr_cookie_t;

/*
* file      := count + proto + cookies
* cookies   := cookie ...
*/
typedef struct {
    uint32 count;   // cookie count
    
    xdr_proto_t proto[0];
} xdr_local_file_t;

typedef struct {
    xdr_proto_t *proto;

    xdr_session_t       session;
    
    xdr_session_time_t  *session_time;
    xdr_session_st_t    *session_st;
    xdr_service_st_t    *service_st;
    
    xdr_tcp_t   *tcp;
    xdr_http_t  *http;
    xdr_sip_t   *sip;
    xdr_rtsp_t  *rtsp;
    xdr_ftp_t   *ftp;
    xdr_mail_t  *mail;
    xdr_dns_t   *dns;
    xdr_ssl_t   *ssl;
} xdr_msg_t;

struct xdr_buffer_st {
    union {
        void *buffer;
        xdr_proto_t *proto;
    } u;
    
    uint32 offset;
    uint32 size;
};

static inline void *
xb_current(xdr_buffer_t *x)
{
    return x->u.buffer + x->offset;
}

static inline uint32
xb_offset(xdr_buffer_t *x, void *pointer)
{
    return pointer - (void *)x;
}

static inline uint32
xb_left(xdr_buffer_t *x)
{
    return x->size - x->offset;
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
xb_obj(xdr_buffer_t *x, uint32 size, uint32 *poffset)
{
    uint32 offset = *poffset;
    if (offset) {
        return xdr_proto_obj(x->u.proto, offset);
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
    uint32 len = count * XDR_ALIGN(size);
    byte *p = xb_pre(x, len);
    if (NULL==p) {
        return NULL;
    }

    a->type = type;
    a->size = size;
    a->count = count;
    a->offset = xb_offset(x, p);

    return a;
}

static inline xdr_string_t *
xb_pre_string(xdr_buffer_t *x, xdr_string_t *obj, void *buf, uint32 len)
{
    byte *p = xb_pre(x, XDR_ALIGN(1+len));
    if (NULL==p) {
        return NULL;
    }
    xdr_strcpy(p, buf, len);
    
    obj->len = len;
    obj->offset = xb_offset(x, p);

    return s;
}

static inline int
xb_pre_string_ex(xdr_buffer_t *x, xdr_string_t *obj, xtlv_t *tlv)
{
    return xb_pre_string(x, obj, xtlv_data(tlv), xtlv_datalen(tlv))?0:-ENOMEM;
}

static inline xdr_string_t *
xb_pre_binnary(xdr_buffer_t *x, xdr_binary_t *obj, void *buf, uint32 len)
{
    byte *p = xb_pre(x, XDR_ALIGN(len));
    if (NULL==p) {
        return NULL;
    }
    memcpy(p, buf, len);
    
    obj->len = len;
    obj->offset = xb_offset(x, p);

    return s;
}

static inline int
xb_pre_binary_ex(xdr_buffer_t *x, xdr_binary_t *obj, xtlv_t *tlv)
{
    return xb_pre_binnary(x, obj, xtlv_data(tlv), xtlv_datalen(tlv))?0:-ENOMEM;
}

#define xb_pre_proto(_x, _type, _field_offsetof) \
    (_type *)xb_obj(_x, sizeof(_type), &(_x)->u.proto->_field_offsetof)

#define xb_pre_L4(_x, _type)    xb_pre_proto(_x, _type, offsetof_L4)
#define xb_pre_L5(_x, _type)    xb_pre_proto(_x, _type, offsetof_L5)
#define xb_pre_L6(_x, _type)    xb_pre_proto(_x, _type, offsetof_L6)

static inline xdr_session4_t *
xb_pre_session4(xdr_buffer_t *x)
{
    return xb_pre_proto(x, xdr_session4_t, offsetof_session);
}

static inline xdr_session6_t *
xb_pre_session6(xdr_buffer_t *x)
{
    return xb_pre_proto(x, xdr_session6_t, offsetof_session);
}

static inline xdr_session_time_t *
xb_pre_session_time(xdr_buffer_t *x)
{
    return xb_pre_proto(x, xdr_session_time_t, offsetof_session_time);
}

static inline xdr_session_st_t *
xb_pre_session_st(xdr_buffer_t *x)
{
    return (xdr_session_st_t *)xb_obj(x, 
        2 * sizeof(xdr_session_st_t), // up && down
        &x->u.proto->offsetof_session_st);
}

static inline xdr_service_st_t *
xb_pre_service_st(xdr_buffer_t *x)
{
    return (xdr_service_st_t *)xb_obj(x, 
        2 * sizeof(xdr_service_st_t), // up && down
        &x->u.proto->offsetof_service_st);
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

static inline int
xdr_parse(XDR_OUT xdr_msg_t *msg, XDR_IN xdr_buffer_t *x)
{
    return 0;
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
    
    if (XDR_SESSION_IPV4==src->ver) {
        xdr_session4_t *dst = xb_pre_session4(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        memcpy(dst, src, XDR_SESSION_HSIZE);

        dst->sip = xdr_ip(&src->sip);
        dst->dip = xdr_ip(&src->dip);
    } else {
        xdr_session6_t *dst = xb_pre_session6(x);
        if (NULL==dst) {
            return -ENOMEM;
        }
        
        os_objcpy(dst, src);
    }
    
    return 0;
}

static inline void
xtlv_to_xdr_session_st_helper(xdr_session_st_t *dst, xtlv_session_st_t *src, int idx)
{
    dst->flow           = src->flow[idx];
    dst->ip_packet      = src->ip_packet[idx];
    dst->ip_frag        = src->ip_frag[idx];
    dst->tcp_disorder   = src->tcp_disorder[idx];
    dst->tcp_retransmit = src->tcp_retransmit[idx];
    dst->duration       = src->duration[idx];
}

static inline int
xtlv_to_xdr_session_st(xdr_buffer_t *x, xtlv_t *tlv)
{
    xtlv_session_st_t *src = xtlv_session_st(tlv);
    xdr_session_st_t *dst = xb_pre_session_st(x);

    xtlv_to_xdr_session_st_helper(dst, src, 0);
    xtlv_to_xdr_session_st_helper(dst+1, src, 1);
    
    return 0;
}

static inline int
xtlv_to_xdr_session_time(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xtlv_to_xdr_obj(x, tlv, session_time);
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
    os_objcpy(&x->u.proto->L7, xtlv_L7(tlv));
    
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
    return 0;
}

static inline int
xtlv_to_xdr_dns_ip4(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0;
}

static inline int
xtlv_to_xdr_dns_ip6(xdr_buffer_t *x, xtlv_t *tlv)
{
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
    return xb_pre_binary_ex(x, &xb_pre_http(x)->request, tlv);
}

static inline int
xtlv_to_xdr_http_response(xdr_buffer_t *x, xtlv_t *tlv)
{
    return xb_pre_binary_ex(x, &xb_pre_http(x)->response, tlv);
}

static inline int
xtlv_to_xdr_file_content(xdr_buffer_t *x, xtlv_t *tlv)
{
    
    return 0;
}

static inline int
xtlv_to_xdr_ssl_server_cert(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0;
}

static inline int
xtlv_to_xdr_ssl_client_cert(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0;
}

static inline int
xtlv_to_xdr_ssl_fail_reason(xdr_buffer_t *x, xtlv_t *tlv)
{
    return 0;
}

/******************************************************************************/
#endif /* __XDR_H_049defbc41a4441e855ee0479dad96eb__ */
