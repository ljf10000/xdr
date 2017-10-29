#ifndef __TLV_H_d203748a8a974e6282d89ddcde27123a__
#define __TLV_H_d203748a8a974e6282d89ddcde27123a__
/******************************************************************************/
#include "os.h"
/******************************************************************************/
#if 0
#define tlv_dprint(_fmt, _args...)     os_println(_fmt, ##_args)
#else
#define tlv_dprint(_fmt, _args...)     os_do_nothing()
#endif

enum {
    e_tlv_header_length_not_match  = 1,
    e_tlv_header_no_body           = 2,
    e_tlv_invalid_id               = 3,
    e_tlv_invalid_object_size      = 4,
    e_tlv_invalid_short_size       = 5,
    e_tlv_too_small                = 6,
    e_tlv_too_big                  = 7,
    e_tlv_not_support_multi        = 8,
    e_tlv_max_multi                = 9,
};

typedef uint8  tlv_u8_t;
typedef uint16 tlv_u16_t;
typedef uint32 tlv_u32_t;
typedef uint64 tlv_u64_t;

typedef int8   tlv_i8_t;
typedef int16  tlv_i16_t;
typedef int32  tlv_i32_t;
typedef int64  tlv_i64_t;

typedef uint64 xdr_duration_t,  tlv_duration_t;
typedef uint64 xdr_time_t,      tlv_time_t;
#define XDR_SECOND(_us)     ((time_t)((_us)/1000000))

typedef uint32 xdr_ip4_t, tlv_ip4_t;
typedef struct {
    uint32 ip[4];
} xdr_ipaddr_t, xdr_ip6_t, tlv_ip6_t;
#define XDR_IP(_addr)   (_addr)->ip[0]

enum {
    TLV_T_u8,
    TLV_T_u16,
    TLV_T_u32,
    TLV_T_u64,
    
    TLV_T_i8,
    TLV_T_i16,
    TLV_T_i32,
    TLV_T_i64,
    
    TLV_T_string,
    TLV_T_binary,
    TLV_T_object,
    
    TLV_T_time,    // u64
    TLV_T_duration,// u64
    
    TLV_T_ip4,     // u32
    TLV_T_ip6,     // 4 * u32
    
    TLV_T_end
};

enum {
    TLV_F_MULTI = 0x01,
    TLV_F_FIXED = 0x02,
    TLV_F_FILE  = 0x04,
};

enum {
    XDR_FILE_NONE,
    XDR_FILE_FILE,
    XDR_FILE_HTTP,
    XDR_FILE_CERT,

    XDR_FILE_END
};

typedef struct tlv_st tlv_t;
typedef struct xdr_buffer_st xdr_buffer_t;

static inline void tlv_dump_u8 (tlv_t *tlv);
static inline void tlv_dump_u16(tlv_t *tlv);
static inline void tlv_dump_u32(tlv_t *tlv);
static inline void tlv_dump_u64(tlv_t *tlv);

static inline void tlv_dump_i8 (tlv_t *tlv);
static inline void tlv_dump_i16(tlv_t *tlv);
static inline void tlv_dump_i32(tlv_t *tlv);
static inline void tlv_dump_i64(tlv_t *tlv);

static inline void tlv_dump_string(tlv_t *tlv);
static inline void tlv_dump_binary(tlv_t *tlv);
static inline void tlv_dump_time(tlv_t *tlv);
static inline void tlv_dump_duration(tlv_t *tlv);
static inline void tlv_dump_ip4(tlv_t *tlv);
static inline void tlv_dump_ip6(tlv_t *tlv);

static inline void tlv_dump_session(tlv_t *tlv);
static inline void tlv_dump_session_st(tlv_t *tlv);
#define tlv_dump_service_st    tlv_dump_session_st
static inline void tlv_dump_session_time(tlv_t *tlv);
static inline void tlv_dump_tcp(tlv_t *tlv);
static inline void tlv_dump_L7(tlv_t *tlv);
static inline void tlv_dump_http(tlv_t *tlv);
static inline void tlv_dump_sip(tlv_t *tlv);
static inline void tlv_dump_rtsp(tlv_t *tlv);

static inline int tlv_to_xdr_session_state(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_appid(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_session(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_session_st(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_service_st(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_session_time(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_tcp(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_first_response_delay(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_L7(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_host(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_url(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_host_xonline(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_user_agent(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_content(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_refer(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_cookie(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_location(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_sip(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_sip_calling_number(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_sip_called_number(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_sip_session_id(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_rtsp(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_rtsp_url(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_rtsp_user_agent(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_rtsp_server_ip(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_status(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_user(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_pwd(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_trans_mode(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_trans_type(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_filename(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_filesize(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_response_delay(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ftp_trans_duration(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_msg_type(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_status_code(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_user(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_sender(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_length(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_domain(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_recver(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_hdr(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_mail_acs_type(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_domain(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_ip_count(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_ip4(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_ip6(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_response_code(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_count_request(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_count_response_record(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_count_response_auth(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_count_response_extra(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_dns_delay(xdr_buffer_t *x, tlv_t *tlv);

static inline int tlv_to_xdr_http_request(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_http_response(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_file_content(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ssl_server_cert(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ssl_client_cert(xdr_buffer_t *x, tlv_t *tlv);
static inline int tlv_to_xdr_ssl_fail_reason(xdr_buffer_t *x, tlv_t *tlv);

typedef struct {
    int     id;
    int     type;
    uint32  flag;
    uint32  minsize;
    uint32  maxsize;
    char    *name;

    void (*dump)(tlv_t * /*tlv*/);
    int (*check)(tlv_t * /*tlv*/);
    int (*toxdr)(xdr_buffer_t * /*x*/, tlv_t * /*tlv*/);
} tlv_ops_t;

#define tlv_mapper_fixed(_mapper, _id, _name, _obj, _flag) \
    _mapper(_name, _id, TLV_T_##_obj, TLV_F_FIXED|_flag, 0, sizeof(tlv_##_obj##_t), tlv_dump_##_obj, NULL, tlv_to_xdr_##_name)
#define tlv_mapper_dynamic(_mapper, _id, _name, _obj, _flag) \
    _mapper(_name, _id, TLV_T_##_obj, _flag, 0, 0, tlv_dump_##_obj, NULL, tlv_to_xdr_##_name)

#define tlv_mapper_object(_mapper, _id, _name, _flag) \
    _mapper(_name, _id, TLV_T_object, TLV_F_FIXED|_flag, 0, sizeof(tlv_##_name##_t), tlv_dump_##_name, NULL, tlv_to_xdr_##_name)
#define tlv_mapper_nothing(_mapper, _id, _name, _flag) \
    _mapper(_name, _id, TLV_T_string, _flag, 0, 0, NULL, NULL, NULL)

#define tlv_mapper_u8( _mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, u8, _flag)
#define tlv_mapper_u16(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, u16, _flag)
#define tlv_mapper_u32(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, u32, _flag)
#define tlv_mapper_u64(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, u64, _flag)
#define tlv_mapper_i8( _mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, i8, _flag)
#define tlv_mapper_i16(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, i16, _flag)
#define tlv_mapper_i32(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, i32, _flag)
#define tlv_mapper_i64(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, i64, _flag)
#define tlv_mapper_ip4(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, ip4, _flag)
#define tlv_mapper_ip6(_mapper, _id, _name, _flag)     tlv_mapper_fixed(_mapper, _id, _name, ip6, _flag)
#define tlv_mapper_time(_mapper, _id, _name, _flag)        tlv_mapper_fixed(_mapper, _id, _name, time, _flag)
#define tlv_mapper_duration(_mapper, _id, _name, _flag)    tlv_mapper_fixed(_mapper, _id, _name, duration, _flag)
#define tlv_mapper_string(_mapper, _id, _name, _flag)      tlv_mapper_dynamic(_mapper, _id, _name, string, _flag)
#define tlv_mapper_binary(_mapper, _id, _name, _flag)      tlv_mapper_dynamic(_mapper, _id, _name, binary, _flag)

#define TLV_MAPPER(_) \
    tlv_mapper_nothing(_,  0, header, 0) \
    \
    tlv_mapper_u8(_,       1, session_state, 0) \
    tlv_mapper_u8(_,       2, appid, 0) \
    tlv_mapper_object(_,   3, session, 0) \
    tlv_mapper_object(_,   4, session_st, 0) \
    tlv_mapper_object(_,   5, session_time, 0) \
    tlv_mapper_object(_,   6, service_st, 0) \
    tlv_mapper_object(_,   7, tcp, 0) \
    tlv_mapper_u32(_,      8, first_response_delay, 0) \
    tlv_mapper_object(_,   9, L7, 0) \
    tlv_mapper_object(_,   10, http, 0) \
    tlv_mapper_string(_,   11, http_host, 0) \
    tlv_mapper_string(_,   12, http_url, 0) \
    tlv_mapper_string(_,   13, http_host_xonline, 0) \
    tlv_mapper_string(_,   14, http_user_agent, 0) \
    tlv_mapper_string(_,   15, http_content, 0) \
    tlv_mapper_string(_,   16, http_refer, 0) \
    tlv_mapper_string(_,   17, http_cookie, 0) \
    tlv_mapper_string(_,   18, http_location, 0) \
    tlv_mapper_object(_,   19, sip, 0) \
    tlv_mapper_string(_,   20, sip_calling_number, 0) \
    tlv_mapper_string(_,   21, sip_called_number, 0) \
    tlv_mapper_string(_,   22, sip_session_id, 0) \
    tlv_mapper_object(_,   23, rtsp, 0) \
    tlv_mapper_string(_,   24, rtsp_url, 0) \
    tlv_mapper_string(_,   25, rtsp_user_agent, 0) \
    tlv_mapper_string(_,   26, rtsp_server_ip, 0) \
    tlv_mapper_u16(_,      27, ftp_status, 0) \
    tlv_mapper_string(_,   28, ftp_user, 0) \
    tlv_mapper_string(_,   29, ftp_pwd, 0) \
    tlv_mapper_u8(_,       30, ftp_trans_mode, 0) \
    tlv_mapper_u8(_,       31, ftp_trans_type, 0) \
    tlv_mapper_string(_,   32, ftp_filename, 0) \
    tlv_mapper_u32(_,      33, ftp_filesize, 0) \
    tlv_mapper_duration(_, 34, ftp_response_delay, 0) \
    tlv_mapper_duration(_, 35, ftp_trans_duration, 0) \
    tlv_mapper_u16(_,      36, mail_msg_type, 0) \
    tlv_mapper_i16(_,      37, mail_status_code, 0) \
    tlv_mapper_string(_,   38, mail_user, 0) \
    tlv_mapper_string(_,   39, mail_sender, 0) \
    tlv_mapper_u32(_,      40, mail_length, 0) \
    tlv_mapper_string(_,   41, mail_domain, 0) \
    tlv_mapper_string(_,   42, mail_recver, 0) \
    tlv_mapper_string(_,   43, mail_hdr, 0) \
    tlv_mapper_u8(_,       44, mail_acs_type, 0) \
    tlv_mapper_string(_,   45, dns_domain, 0) \
    tlv_mapper_u8(_,       46, dns_ip_count, 0) \
    tlv_mapper_ip4(_,      47, dns_ip4, TLV_F_MULTI) \
    tlv_mapper_ip6(_,      48, dns_ip6, TLV_F_MULTI) \
    tlv_mapper_u8(_,       49, dns_response_code, 0) \
    tlv_mapper_u8(_,       50, dns_count_request, 0) \
    tlv_mapper_u8(_,       51, dns_count_response_record, 0) \
    tlv_mapper_u8(_,       52, dns_count_response_auth, 0) \
    tlv_mapper_u8(_,       53, dns_count_response_extra, 0) \
    tlv_mapper_u32(_,      54, dns_delay, 0) \
    \
    tlv_mapper_binary(_,   201, http_request,  TLV_F_FILE) \
    tlv_mapper_binary(_,   202, http_response, TLV_F_FILE) \
    tlv_mapper_binary(_,   203, file_content,  TLV_F_FILE) \
    tlv_mapper_binary(_,   204, ssl_server_cert, TLV_F_MULTI|TLV_F_FILE) \
    tlv_mapper_binary(_,   205, ssl_client_cert, TLV_F_MULTI|TLV_F_FILE) \
    tlv_mapper_u8(_,       206, ssl_fail_reason, 0) \
    /* end */

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

#define __TLV_STRUCT(_name, _id, _type, _flag, _minsize, _maxsize, _dump, _check, _toxdr) [_id] = { \
    .id     = _id,      \
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
    uint32 __tlv_opt; \
    uint32 xdr_seq; \
    tlv_ops_t __tlv_ops[tlv_id_end] = { TLV_MAPPER(__TLV_STRUCT) }; \
    os_extern_unused_var /* end */

extern tlv_ops_t __tlv_ops[];
extern uint32 __tlv_opt;
extern uint32 xdr_seq;

enum {
    TLV_OPT_DUMP = 0x01,
    TLV_OPT_FILE_SPLIT = 0x02,
};

static inline void
tlv_opt_set(uint32 flag)
{
    __tlv_opt |= flag;
}

static inline bool
is_tlv_opt_dump(void)
{
    return TLV_OPT_DUMP==(TLV_OPT_DUMP & __tlv_opt);
}

static inline bool
is_tlv_opt_file_split(void)
{
    return TLV_OPT_FILE_SPLIT==(TLV_OPT_FILE_SPLIT & __tlv_opt);
}

static inline bool
is_good_tlv_id(int id)
{
    return is_good_enum(id, tlv_id_end);
}

static inline tlv_ops_t *
tlv_ops(int id)
{
    if (false==is_good_tlv_id(id)) {
        return NULL;
    }

    return &__tlv_ops[id];
}

struct tlv_st {
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

#define tlv_extend(_tlv)       (_tlv)->h.e.e

#define tlv_data_n(_tlv)       (_tlv)->d.data
#define tlv_data_e(_tlv)       (_tlv)->d.e.data
#define tlv_data(_tlv)         (tlv_extend(_tlv)?tlv_data_e(_tlv):tlv_data_n(_tlv))

#define tlv_len_n(_tlv)        (_tlv)->h.n.len
#define tlv_len_e(_tlv)        (_tlv)->d.e.len
#define tlv_len(_tlv)          (tlv_extend(_tlv)?tlv_len_e(_tlv):tlv_len_n(_tlv))

#define tlv_hdrlen_e           sizeof(tlv_t)
#define tlv_hdrlen_n           (sizeof(tlv_t)-sizeof(uint32))
#define tlv_hdrlen(_tlv)       (tlv_extend(_tlv)?tlv_hdrlen_e:tlv_hdrlen_n)

#define tlv_datalen_e(_tlv)    (tlv_len_e(_tlv)-tlv_hdrlen_e)
#define tlv_datalen_n(_tlv)    (tlv_len_n(_tlv)-tlv_hdrlen_n)
#define tlv_datalen(_tlv)      (tlv_extend(_tlv)?tlv_datalen_e(_tlv):tlv_datalen_n(_tlv))

#define tlv_strlen(_tlv)       (tlv_datalen(_tlv) - (_tlv)->pad)
#define tlv_binlen(_tlv)       (tlv_datalen(_tlv) - (_tlv)->pad)

#define tlv_first(_tlv_header) (tlv_t *)tlv_data(_tlv_header)
#define tlv_next(_tlv)         (tlv_t *)((byte *)(_tlv) + tlv_len(_tlv))

#define tlv_u8(_tlv)       (_tlv)->pad
#define tlv_u16(_tlv)      (*(uint16 *)tlv_data(_tlv))
#define tlv_u32(_tlv)      (*(uint32 *)tlv_data(_tlv))
#define tlv_u64(_tlv)      (*(uint64 *)tlv_data(_tlv))

#define tlv_i8(_tlv)       (_tlv)->pad
#define tlv_i16(_tlv)      (*(int16 *)tlv_data(_tlv))
#define tlv_i32(_tlv)      (*(int32 *)tlv_data(_tlv))
#define tlv_i64(_tlv)      (*(int64 *)tlv_data(_tlv))

#define tlv_time(_tlv)     (*(tlv_time_t *)tlv_data(_tlv))
#define tlv_duration(_tlv) (*(tlv_duration_t *)tlv_data(_tlv))

#define tlv_ip4(_tlv)      (*(uint32 *)tlv_data(_tlv))
#define tlv_ip6(_tlv)      ((xdr_ipaddr_t *)tlv_data(_tlv))

#define tlv_string(_tlv)   ((char *)tlv_data(_tlv))
#define tlv_binary(_tlv)   tlv_data(_tlv)

#define tlv_session(_tlv)      (tlv_session_t *)tlv_data(_tlv)
#define tlv_session_st(_tlv)   (tlv_session_st_t *)tlv_data(_tlv)
#define tlv_session_time(_tlv) (tlv_session_time_t *)tlv_data(_tlv)
#define tlv_service_st(_tlv)   (tlv_service_st_t *)tlv_data(_tlv)
#define tlv_tcp(_tlv)          (tlv_tcp_t *)tlv_data(_tlv)
#define tlv_L7(_tlv)           (tlv_L7_t *)tlv_data(_tlv)
#define tlv_http(_tlv)         (tlv_http_t *)tlv_data(_tlv)
#define tlv_sip(_tlv)          (tlv_sip_t *)tlv_data(_tlv)
#define tlv_rtsp(_tlv)         (tlv_rtsp_t *)tlv_data(_tlv)

static inline void
tlv_dump(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);

    if (ops->dump) {
        (*ops->dump)(tlv);
    }
}

static inline int
tlv_error(tlv_t *tlv, int err, char *serr)
{
    if (err<0) {
        tlv_ops_t *ops = tlv_ops(tlv->id);

        if (TLV_F_FIXED & ops->flag) {
            os_println("%s tlv name:%s fixed:%d id:%d pad:%d alen:%u hlen:%u dlen:%u", 
                serr?serr:"",
                ops->name, 
                ops->maxsize,
                tlv->id, 
                tlv->pad, 
                tlv_len(tlv),
                tlv_hdrlen(tlv),
                tlv_datalen(tlv));
        } else {
            os_println("%s tlv name:%s id:%d pad:%d alen:%u hlen:%u dlen:%u", 
                serr?serr:"",
                ops->name, 
                tlv->id, 
                tlv->pad, 
                tlv_len(tlv),
                tlv_hdrlen(tlv),
                tlv_datalen(tlv));
        }
    }

    return err;
}

static inline int
tlv_check_fixed(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);
    uint32 dlen = tlv_datalen(tlv);
    
    switch (ops->type) {
        case TLV_T_u8:
        case TLV_T_i8:
            if (0 != dlen) {
                return tlv_error(tlv, 
                    -e_tlv_invalid_short_size,
                    "tlv_check_fixed i8");
            }
            
            break;
        case TLV_T_u16:
        case TLV_T_i16:
            if (sizeof(uint32) != dlen) {
                return tlv_error(tlv, 
                    -e_tlv_invalid_short_size,
                    "tlv_check_fixed i16");
            }

            break;
        default:
            if (dlen != ops->maxsize) {
                return tlv_error(tlv, 
                    -e_tlv_invalid_object_size,
                    "tlv_check_fixed other");
            }

            break;
    }

    return 0;
}

static inline int
tlv_check_dynamic(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);
    uint32 dlen = tlv_datalen(tlv);
    
    if (ops->minsize && dlen < ops->minsize) {
        return tlv_error(tlv, 
            -e_tlv_too_small,
            "tlv_check_dynamic too small");
    }
    else if (ops->maxsize && dlen > ops->maxsize) {
        return tlv_error(tlv, 
            -e_tlv_too_big,
            "tlv_check_dynamic too big");
    }

    return 0;
}

static inline int
tlv_check(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);
    if (NULL==ops) {
        return tlv_error(tlv, 
            -e_tlv_invalid_id,
            "tlv_check invalid id");
    }

    if (tlv_len(tlv) < tlv_hdrlen(tlv)) {
        return tlv_error(tlv, 
            -e_tlv_too_small,
            "tlv_check too small");
    }

    if (ops->check) {
        return tlv_error(tlv, 
            (*ops->check)(tlv),
            "tlv_check ops check");
    }

    // use default checker
    if (TLV_F_FIXED & ops->flag) {
        return tlv_check_fixed(tlv);
    } else {
        return tlv_check_dynamic(tlv);
    }
}

#define TLV_DUMP(_fmt, _args...)       os_println(__tab _fmt, ##_args)
#define TLV_DUMP2(_fmt, _args...)      os_println(__tab2 _fmt, ##_args)
#define TLV_DUMP3(_fmt, _args...)      os_println(__tab3 _fmt, ##_args)
#define TLV_DUMP4(_fmt, _args...)      os_println(__tab4 _fmt, ##_args)

#define TLV_DUMP_BY(_tlv, _format, _type)  do{ \
    tlv_ops_t *ops = tlv_ops((_tlv)->id); \
                                            \
    TLV_DUMP("id: %d, %s: " _format, (_tlv)->id, ops->name, tlv_##_type(_tlv)); \
}while(0)

static inline void tlv_dump_u8 (tlv_t *tlv) { TLV_DUMP_BY(tlv, "%u", u8);  }
static inline void tlv_dump_u16(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%u", u16); }
static inline void tlv_dump_u32(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%u", u32); }
static inline void tlv_dump_u64(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%llu", u64); }

static inline void tlv_dump_i8 (tlv_t *tlv) { TLV_DUMP_BY(tlv, "%d", i8);  }
static inline void tlv_dump_i16(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%d", i16); }
static inline void tlv_dump_i32(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%d", i32); }
static inline void tlv_dump_i64(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%lld", i64); }

static inline void tlv_dump_string(tlv_t *tlv) { TLV_DUMP_BY(tlv, "%s", string); }

static inline void 
tlv_dump_time(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);

    TLV_DUMP("id:%d, %s: %s", tlv->id, ops->name, os_time_string(XDR_SECOND(tlv_time(tlv))));
}

static inline void tlv_dump_duration(tlv_t *tlv) 
{
    tlv_ops_t *ops = tlv_ops(tlv->id);
    tlv_duration_t d = tlv_duration(tlv);
    uint32 s = (uint32)(d>>32);
    uint32 us= (uint32)(d & 0xffffffff);
    
    TLV_DUMP("id:%d, %s %ds:%dus", tlv->id, ops->name, s, us); 
}

static inline void 
tlv_dump_ip4(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);

    uint32 ip = tlv_ip4(tlv); // ip = htonl(ip);
    
    TLV_DUMP("id:%d, %s: %s", tlv->id, ops->name, os_ipstring(ip));
}

static inline void 
tlv_dump_ip6(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);

    TLV_DUMP("id: %d, %s: ipv6 address", tlv->id, ops->name);
}

static inline void 
tlv_dump_binary(tlv_t *tlv)
{
    tlv_ops_t *ops = tlv_ops(tlv->id);

    if (is_tlv_opt_file_split()) {
        TLV_DUMP("id: %d, %s: %s", tlv->id, ops->name, tlv_string(tlv));
    } else {
        TLV_DUMP("id: %d, %s:", tlv->id, ops->name);

        os_dump_buffer(tlv_binary(tlv), tlv_datalen(tlv));
    }
}

enum { XDR_IPV4 = 0, XDR_IPV6 = 1 };

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
tlv_dump_session(tlv_t *tlv)
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
        TLV_DUMP2("sip    : %s", os_ipstring(ip));
        
        ip = XDR_IP(&obj->dip); // ip = htonl(ip);
        TLV_DUMP2("dip    : %s", os_ipstring(ip));
    } else {
        TLV_DUMP2("sip    : ipv6 address");
        TLV_DUMP2("dip    : ipv6 addres");
    }
}

typedef struct {
    uint32 flow[2];
    uint32 ip_packet[2];
    uint32 tcp_disorder[2];
    uint32 tcp_retransmit[2];
    uint32 ip_frag[2];
    
    uint16 duration[2];
} tlv_session_st_t, tlv_service_st_t, xdr_session_st_t, xdr_service_st_t;

static inline void 
tlv_dump_session_st(tlv_t *tlv)
{
    tlv_session_st_t *obj = tlv_session_st(tlv);
    int i;
    
    TLV_DUMP("id: %d, %s:", tlv->id, tlv_ops(tlv->id)->name);

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

typedef struct {
    tlv_time_t create;
    tlv_time_t start;
    tlv_time_t stop;
} tlv_session_time_t, xdr_session_time_t;

static inline void 
tlv_dump_session_time(tlv_t *tlv)
{
    tlv_session_time_t *obj = tlv_session_time(tlv);
    
    TLV_DUMP("id: %d, session_time:", tlv->id);
    
    TLV_DUMP2("create: %s", os_time_string(XDR_SECOND(obj->create)));
    TLV_DUMP2("start : %s", os_time_string(XDR_SECOND(obj->start)));
    TLV_DUMP2("stop  : %s", os_time_string(XDR_SECOND(obj->stop)));
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
tlv_tcp_t, xdr_tcp_t;

enum { XDR_TCP_COMPLETE = 1 };

static inline void 
tlv_dump_tcp(tlv_t *tlv)
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

typedef struct {
    byte status;
    byte class;
    uint16 protocol;
} tlv_L7_t, xdr_L7_t;

static inline void 
tlv_dump_L7(tlv_t *tlv)
{
    tlv_L7_t *obj = tlv_L7(tlv);
    
    TLV_DUMP("id: %d, L7:", tlv->id);
    
    TLV_DUMP2("status  : %u", obj->status);
    TLV_DUMP2("class   : %u", obj->class);
    TLV_DUMP2("protocol: %u", obj->protocol);
}

typedef struct {
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
}
tlv_http_t;

static inline void 
tlv_dump_http(tlv_t *tlv)
{
    tlv_http_t *obj = tlv_http(tlv);
    
    TLV_DUMP("id: %d, http:", tlv->id);
    
    TLV_DUMP2("time_request        : %s", os_time_string(XDR_SECOND(obj->time_request)));
    TLV_DUMP2("time_first_response : %s", os_time_string(XDR_SECOND(obj->time_first_response)));
    TLV_DUMP2("time_last_content   : %s", os_time_string(XDR_SECOND(obj->time_last_content)));
    TLV_DUMP2("service_delay       : %llu us", obj->service_delay);
    TLV_DUMP2("content_length      : %u", obj->content_length);
    TLV_DUMP2("status_code         : %u", obj->status_code);
    TLV_DUMP2("method              : %u", obj->method);
    TLV_DUMP2("version             : %u", obj->version);

    TLV_DUMP2("first               : %s", bool_string(obj->u.st.first));
    TLV_DUMP2("flag                : %u", obj->u.st.flag);
    TLV_DUMP2("head                : %s", yes_string(obj->u.st.head));
    TLV_DUMP2("ie                  : %u", obj->ie);
    TLV_DUMP2("portal              : %u", obj->portal);
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
} tlv_sip_t;

static inline void 
tlv_dump_sip(tlv_t *tlv)
{
    tlv_sip_t *obj = tlv_sip(tlv);
    
    TLV_DUMP("id: %d, http:", tlv->id);
    
    TLV_DUMP2("call_direction  : %u", obj->call_direction);
    TLV_DUMP2("call_type       : %u", obj->call_type);
    TLV_DUMP2("hangup_reason   : %u", obj->hangup_reason);
    TLV_DUMP2("signal_type     : %u", obj->signal_type);
    TLV_DUMP2("dataflow_count  : %u", obj->dataflow_count);
    TLV_DUMP2("invite          : %s", bool_string(XDR_SIP_INVITE==obj->u.st.invite));
    TLV_DUMP2("bye             : %s", bool_string(XDR_SIP_BYE==obj->u.st.bye));
    TLV_DUMP2("malloc          : %s", bool_string(obj->u.st.malloc));
}

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
tlv_dump_rtsp(tlv_t *tlv)
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

#ifndef TLV_CACHE_MULTI
#define TLV_CACHE_MULTI    7
#endif

typedef struct {
    int count;

    tlv_t *multi[TLV_CACHE_MULTI];
} tlv_cache_t;

static inline int
tlv_cache_save(tlv_cache_t *cache, tlv_t *tlv)
{
    int err = 0;

    if (cache->count < TLV_CACHE_MULTI) {
        if (0==cache->count) {
            cache->multi[cache->count++] = tlv;

            tlv_dprint("save record tlv id:%d", tlv->id);
        } else {
            tlv_ops_t *ops = tlv_ops(tlv->id);
            if (TLV_F_MULTI & ops->flag) {
                cache->multi[cache->count++] = tlv;
                
                tlv_dprint("save record multi tlv id:%d", tlv->id);
            } else {
                err = -e_tlv_not_support_multi;
            }
        }
    }
    else {
        err = -e_tlv_max_multi;
    }

    return err;

    
}

typedef struct {
    tlv_t *header;
    
    tlv_cache_t cache[tlv_id_end];
} tlv_record_t;

static inline int
tlv_record_save(tlv_record_t *record, tlv_t *tlv)
{
    tlv_cache_t *cache = &record->cache[tlv->id];

    return tlv_cache_save(cache, tlv);
}

static inline int
tlv_record_parse(tlv_record_t *record)
{
    tlv_t *h = record->header;
    uint32 left = tlv_datalen(h);
    tlv_t *tlv = tlv_first(h);
    int err;
    
    while(left>0) {
        err = tlv_check(tlv);
        if (err<0) {
            return err;
        }

        err = tlv_record_save(record, tlv);
        if (err<0) {
            return err;
        }

        if (is_tlv_opt_dump()) {
            tlv_dump(tlv);
        }

        left -= tlv_len(tlv); tlv = tlv_next(tlv);
    }

    return 0;
}

static inline int
tlv_count(void *buffer, int len)
{
    tlv_t *h = (tlv_t *)buffer;
    uint32 left = (uint32)len;
    int count = 0;

    while(left > 0) {
        count++;
        
        if (left < tlv_hdrlen(h)) {
            return -e_tlv_too_small;
        }
        else if (left < tlv_len(h)) {
            return -e_tlv_too_small;
        }
        else if (left == tlv_len(h)) {
            break;
        }

        left -= tlv_len(h);
        h = tlv_next(h);
    }

    return count;
}

static inline int
tlv_foreach(tlv_t *header, int count, int (*each)(tlv_t *h, void *data), void *data)
{
    int i, err = 0;
    tlv_t *h;

    tlv_dprint("tlv foreach ...");
    
    for (i=0, h=header; i<count; i++, h = tlv_next(h)) {
        err = (*each)(h, data);
        if (err<0) {
            return err;
        }
    }

    tlv_dprint("tlv foreach ok.");
    
    return err;
}

static inline int
tlv_parse(tlv_t *h, void *data)
{
    tlv_record_t r = { .header = h };

    return tlv_record_parse(&r);
}
/******************************************************************************/
#endif /* __TLV_H_d203748a8a974e6282d89ddcde27123a__ */
