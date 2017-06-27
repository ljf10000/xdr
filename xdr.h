#ifndef __XDR_H_049defbc41a4441e855ee0479dad96eb__
#define __XDR_H_049defbc41a4441e855ee0479dad96eb__
/******************************************************************************/
#include "tlv.h"
/******************************************************************************/
#define XDR_IN
#define XDR_OUT
#define XDR_INOUT

#define XDR_ALIGN(x)    OS_ALIGN(x, 4)

static inline void *
xdr_memcpy(void *dst, void *src, uint32 size)
{
    uint32 i, align = XDR_ALIGN(size);
    byte *p = (byte *)memcpy(dst, src, size);

    for (i=size; i<align; i++) {
        p[i] = 0;
    }

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
} xdr_session_t, xdr_session4_t;
typedef xtlv_session_t xdr_session6_t;

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
    xdr_string_t request;
    xdr_string_t response;
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
    uint64 response_delay;
    uint64 trans_time;
    
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
    xdr_string_t cert;
    xdr_string_t domain;
} xdr_cert_t;

typedef struct {
    byte reason;
    byte _[3];

    xdr_array_t cert_server; // entry is xdr_cert_t
    xdr_array_t cert_client; // entry is xdr_cert_t
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
    byte _0;
    
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

typedef struct {
    xdr_proto_t *proto;

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

static inline void *
xb_pre(xdr_buffer_t *x, uint32 size)
{
    if (xb_enought(x, size)) {
        void *current = xb_current(x);

        xb_put(x, size);

        return current;
    } else {
        return NULL;
    }
}

static inline xdr_string_t *
xb_pre_string(xdr_buffer_t *x, xdr_string_t *s, void *buf, uint32 len)
{
    void *p = xb_pre(x, XDR_ALIGN(len));
    if (NULL==p) {
        return NULL;
    }

    xdr_memcpy(p, buf, len);
    xb_put(x, len);

    s->len = len;
    s->offset = xb_offset(x, p);

    return s;
}

static inline xdr_array_t *
xb_pre_array(xdr_buffer_t *x, xdr_array_t *a, uint32 type, uint32 size, uint32 count)
{
    uint32 len = count * XDR_ALIGN(size);
    void *p = xb_pre(x, len);
    if (NULL==p) {
        return NULL;
    }

    xb_put(x, len);

    a->type = type;
    a->size = size;
    a->count = count;
    a->offset = xb_offset(x, p);

    return a;
}

static inline void *
xb_pre_obj(xdr_buffer_t *x, uint32 size, uint32 *offset)
{
    void *p = xb_pre(x, size);
    if (NULL==p) {
        return NULL;
    }

    *offset = xb_offset(x, p);

    return p;
}

#define xb_pre_proto(_xb, _type, _field_offsetof) \
    (_type *)xb_pre_obj(_xb, sizeof(_type), &(_xb)->u.proto->_field_offsetof)
#define xb_pre_L4(_xb, _type) \
    xb_pre_proto(_xb, _type, offsetof_L4)
#define xb_pre_L5(_xb, _type) \
    xb_pre_proto(_xb, _type, offsetof_L5)
#define xb_pre_L6(_xb, _type) \
    xb_pre_proto(_xb, _type, offsetof_L6)

static inline xdr_session_time_t *
xb_pre_session_time(xdr_buffer_t *x)
{
    return xb_pre_proto(x, xdr_session_time_t, offsetof_session_time);
}

static inline xdr_session_st_t *
xb_pre_session_st(xdr_buffer_t *x)
{
    return (xdr_session_st_t *)xb_pre_obj(x, 
        2 * sizeof(xdr_session_st_t), // up && down
        &x->u.proto->offsetof_session_st);
}

static inline xdr_service_st_t *
xb_pre_service_st(xdr_buffer_t *x)
{
    return (xdr_service_st_t *)xb_pre_obj(x, 
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

static inline xdr_string_t *
xb_pre_http_host(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->host, buf, len);
}

static inline xdr_string_t *
xb_pre_http_url(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->url, buf, len);
}

static inline xdr_string_t *
xb_pre_http_host_xonline(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->host_xonline, buf, len);
}

static inline xdr_string_t *
xb_pre_http_user_agent(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->user_agent, buf, len);
}

static inline xdr_string_t *
xb_pre_http_content(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->content, buf, len);
}

static inline xdr_string_t *
xb_pre_http_refer(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->refer, buf, len);
}

static inline xdr_string_t *
xb_pre_http_cookie(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->cookie, buf, len);
}

static inline xdr_string_t *
xb_pre_http_location(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->location, buf, len);
}

static inline xdr_string_t *
xb_pre_http_request(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->request, buf, len);
}

static inline xdr_string_t *
xb_pre_http_response(xdr_buffer_t *x, xdr_http_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->response, buf, len);
}

static inline xdr_sip_t *
xb_pre_sip(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_sip_t);
}

static inline xdr_string_t *
xb_pre_sip_calling_number(xdr_buffer_t *x, xdr_sip_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->calling_number, buf, len);
}

static inline xdr_string_t *
xb_pre_sip_called_number(xdr_buffer_t *x, xdr_sip_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->called_number, buf, len);
}

static inline xdr_string_t *
xb_pre_sip_session_id(xdr_buffer_t *x, xdr_sip_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->session_id, buf, len);
}

static inline xdr_rtsp_t *
xb_pre_rtsp(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_rtsp_t);
}

static inline xdr_string_t *
xb_pre_rtsp_url(xdr_buffer_t *x, xdr_rtsp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->url, buf, len);
}

static inline xdr_string_t *
xb_pre_rtsp_user_agent(xdr_buffer_t *x, xdr_rtsp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->user_agent, buf, len);
}

static inline xdr_string_t *
xb_pre_rtsp_server_ip(xdr_buffer_t *x, xdr_rtsp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->server_ip, buf, len);
}

static inline xdr_ftp_t *
xb_pre_ftp(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_ftp_t);
}

static inline xdr_string_t *
xb_pre_ftp_status(xdr_buffer_t *x, xdr_ftp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->status, buf, len);
}

static inline xdr_string_t *
xb_pre_ftp_user(xdr_buffer_t *x, xdr_ftp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->user, buf, len);
}

static inline xdr_string_t *
xb_pre_ftp_pwd(xdr_buffer_t *x, xdr_ftp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->pwd, buf, len);
}

static inline xdr_string_t *
xb_pre_ftp_filename(xdr_buffer_t *x, xdr_ftp_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->filename, buf, len);
}

static inline xdr_mail_t *
xb_pre_mail(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_mail_t);
}

static inline xdr_string_t *
xb_pre_mail_user(xdr_buffer_t *x, xdr_mail_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->user, buf, len);
}

static inline xdr_string_t *
xb_pre_mail_domain(xdr_buffer_t *x, xdr_mail_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->domain, buf, len);
}

static inline xdr_string_t *
xb_pre_mail_sender(xdr_buffer_t *x, xdr_mail_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->sender, buf, len);
}

static inline xdr_string_t *
xb_pre_mail_recver(xdr_buffer_t *x, xdr_mail_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->recver, buf, len);
}

static inline xdr_string_t *
xb_pre_mail_hdr(xdr_buffer_t *x, xdr_mail_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->hdr, buf, len);
}

static inline xdr_dns_t *
xb_pre_dns(xdr_buffer_t *x)
{
    return xb_pre_L5(x, xdr_dns_t);
}

static inline xdr_string_t *
xb_pre_dns_domain(xdr_buffer_t *x, xdr_dns_t *proto, void *buf, uint32 len)
{
    return xb_pre_string(x, &proto->domain, buf, len);
}

static inline xdr_array_t *
xb_pre_dns_ip(xdr_buffer_t *x, xdr_dns_t *proto, uint32 count, uint32 ip[])
{
    return xb_pre_array(x, &proto->ip, XDR_OBJ_IP4, sizeof(uint32), count);
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

/******************************************************************************/
#endif /* __XDR_H_049defbc41a4441e855ee0479dad96eb__ */
