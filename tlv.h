#ifndef __TLV_H_d203748a8a974e6282d89ddcde27123a__
#define __TLV_H_d203748a8a974e6282d89ddcde27123a__
/******************************************************************************/
#include "os.h"
/******************************************************************************/
#if 0
#define xtlv_dprint(_fmt, _args...)     os_println(_fmt, ##_args)
#else
#define xtlv_dprint(_fmt, _args...)     os_do_nothing()
#endif

enum {
    e_xtlv_header_must_first        = 1000,
    e_xtlv_header_length_not_match  = 1001,
    e_xtlv_header_no_body           = 1002,
    e_xtlv_invalid_id               = 1003,
    e_xtlv_invalid_object_size      = 1004,
    e_xtlv_invalid_short_size       = 1005,
    e_xtlv_too_small                = 1006,
    e_xtlv_too_big                  = 1007,
    e_xtlv_not_support_multi        = 1008,
};

typedef uint64 xdr_time_t;
typedef uint64 xdr_duration_t;

static inline time_t
xdr_time_second(xdr_time_t us)
{
    return (time_t)(us/1000000);
}

typedef struct {
    uint32 ip[4];
} xdr_ipaddr_t;
#define xdr_ip(_addr)   (_addr)->ip[0]

#define xtlv_u8_t   uint8
#define xtlv_u16_t  uint16
#define xtlv_u32_t  uint32
#define xtlv_u64_t  uint64
#define xtlv_i8_t   int8
#define xtlv_i16_t  int16
#define xtlv_i32_t  int32
#define xtlv_i64_t  int64
#define xtlv_ip4_t  uint32

#define xtlv_ip6_t      xdr_ipaddr_t
#define xtlv_time_t     xdr_time_t
#define xtlv_duration_t xdr_duration_t

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
    
    XTLV_T_time,    // u64
    XTLV_T_duration,// u64
    
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

static inline void xtlv_dump_u8 (xtlv_t *tlv);
static inline void xtlv_dump_u16(xtlv_t *tlv);
static inline void xtlv_dump_u32(xtlv_t *tlv);
static inline void xtlv_dump_u64(xtlv_t *tlv);

static inline void xtlv_dump_i8 (xtlv_t *tlv);
static inline void xtlv_dump_i16(xtlv_t *tlv);
static inline void xtlv_dump_i32(xtlv_t *tlv);
static inline void xtlv_dump_i64(xtlv_t *tlv);

static inline void xtlv_dump_string(xtlv_t *tlv);
static inline void xtlv_dump_binary(xtlv_t *tlv);
static inline void xtlv_dump_time(xtlv_t *tlv);
static inline void xtlv_dump_duration(xtlv_t *tlv);
static inline void xtlv_dump_ip4(xtlv_t *tlv);
static inline void xtlv_dump_ip6(xtlv_t *tlv);

static inline void xtlv_dump_session(xtlv_t *tlv);
static inline void xtlv_dump_session_st(xtlv_t *tlv);
#define xtlv_dump_service_st    xtlv_dump_session_st
static inline void xtlv_dump_session_time(xtlv_t *tlv);
static inline void xtlv_dump_tcp(xtlv_t *tlv);
static inline void xtlv_dump_L7(xtlv_t *tlv);
static inline void xtlv_dump_http(xtlv_t *tlv);
static inline void xtlv_dump_sip(xtlv_t *tlv);
static inline void xtlv_dump_rtsp(xtlv_t *tlv);

static inline int xtlv_to_xdr_session_state(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_appid(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_session(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_session_st(xdr_buffer_t *x, xtlv_t *tlv);
#define xtlv_to_xdr_service_st xtlv_to_xdr_session_st
static inline int xtlv_to_xdr_session_time(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_tcp(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_first_response_delay(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_L7(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_host(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_url(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_host_xonline(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_user_agent(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_content(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_refer(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_cookie(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_location(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_sip(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_sip_calling_number(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_sip_called_number(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_sip_session_id(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_rtsp(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_rtsp_url(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_rtsp_user_agent(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_rtsp_server_ip(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_status(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_user(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_pwd(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_trans_mode(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_trans_type(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_filename(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_filesize(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_response_delay(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ftp_trans_duration(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_msg_type(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_status_code(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_user(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_sender(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_length(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_domain(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_recver(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_hdr(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_mail_acs_type(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_domain(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_ip_count(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_ip4(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_ip6(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_response_code(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_count_request(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_count_response_record(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_count_response_auth(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_count_response_extra(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_dns_delay(xdr_buffer_t *x, xtlv_t *tlv);

static inline int xtlv_to_xdr_http_request(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_http_response(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_file_content(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ssl_server_cert(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ssl_client_cert(xdr_buffer_t *x, xtlv_t *tlv);
static inline int xtlv_to_xdr_ssl_fail_reason(xdr_buffer_t *x, xtlv_t *tlv);

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

#define xtlv_mapper_fixed(_mapper, _id, _name, _obj) \
    _mapper(_name, _id, XTLV_T_##_obj, XTLV_F_FIXED, 0, sizeof(xtlv_##_obj##_t), xtlv_dump_##_obj, NULL, xtlv_to_xdr_##_name)
#define xtlv_mapper_dynamic(_mapper, _id, _name, _obj) \
    _mapper(_name, _id, XTLV_T_##_obj, 0, 0, 0, xtlv_dump_##_obj, NULL, xtlv_to_xdr_##_name)

#define xtlv_mapper_object(_mapper, _id, _name) \
    _mapper(_name, _id, XTLV_T_object, XTLV_F_FIXED, 0, sizeof(xtlv_##_name##_t), xtlv_dump_##_name, NULL, xtlv_to_xdr_##_name)
#define xtlv_mapper_nothing(_mapper, _id, _name) \
    _mapper(_name, _id, XTLV_T_binary, 0, 0, 0, NULL, NULL, NULL)

#define xtlv_mapper_u8( _mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, u8)
#define xtlv_mapper_u16(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, u16)
#define xtlv_mapper_u32(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, u32)
#define xtlv_mapper_u64(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, u64)
#define xtlv_mapper_i8( _mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, i8)
#define xtlv_mapper_i16(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, i16)
#define xtlv_mapper_i32(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, i32)
#define xtlv_mapper_i64(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, i64)
#define xtlv_mapper_ip4(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, ip4)
#define xtlv_mapper_ip6(_mapper, _id, _name)    xtlv_mapper_fixed(_mapper, _id, _name, ip6)
#define xtlv_mapper_time(_mapper, _id, _name)       xtlv_mapper_fixed(_mapper, _id, _name, time)
#define xtlv_mapper_duration(_mapper, _id, _name)   xtlv_mapper_fixed(_mapper, _id, _name, duration)
#define xtlv_mapper_string(_mapper, _id, _name)     xtlv_mapper_dynamic(_mapper, _id, _name, string)
#define xtlv_mapper_binary(_mapper, _id, _name)     xtlv_mapper_dynamic(_mapper, _id, _name, binary)

#define XTLV_MAPPER(_) \
    xtlv_mapper_nothing(_,  0, header) \
    \
    xtlv_mapper_u8(_,       1, session_state) \
    xtlv_mapper_u8(_,       2, appid) \
    xtlv_mapper_object(_,   3, session) \
    xtlv_mapper_object(_,   4, session_st) \
    xtlv_mapper_object(_,   5, session_time) \
    xtlv_mapper_object(_,   6, service_st) \
    xtlv_mapper_object(_,   7, tcp) \
    xtlv_mapper_u32(_,      8, first_response_delay) \
    xtlv_mapper_object(_,   9, L7) \
    xtlv_mapper_object(_,   10, http) \
    xtlv_mapper_string(_,   11, http_host) \
    xtlv_mapper_string(_,   12, http_url) \
    xtlv_mapper_string(_,   13, http_host_xonline) \
    xtlv_mapper_string(_,   14, http_user_agent) \
    xtlv_mapper_string(_,   15, http_content) \
    xtlv_mapper_string(_,   16, http_refer) \
    xtlv_mapper_string(_,   17, http_cookie) \
    xtlv_mapper_string(_,   18, http_location) \
    xtlv_mapper_object(_,   19, sip) \
    xtlv_mapper_string(_,   20, sip_calling_number) \
    xtlv_mapper_string(_,   21, sip_called_number) \
    xtlv_mapper_string(_,   22, sip_session_id) \
    xtlv_mapper_object(_,   23, rtsp) \
    xtlv_mapper_string(_,   24, rtsp_url) \
    xtlv_mapper_string(_,   25, rtsp_user_agent) \
    xtlv_mapper_string(_,   26, rtsp_server_ip) \
    xtlv_mapper_u16(_,      27, ftp_status) \
    xtlv_mapper_string(_,   28, ftp_user) \
    xtlv_mapper_string(_,   29, ftp_pwd) \
    xtlv_mapper_u8(_,       30, ftp_trans_mode) \
    xtlv_mapper_u8(_,       31, ftp_trans_type) \
    xtlv_mapper_string(_,   32, ftp_filename) \
    xtlv_mapper_u32(_,      33, ftp_filesize) \
    xtlv_mapper_duration(_, 34, ftp_response_delay) \
    xtlv_mapper_duration(_, 35, ftp_trans_duration) \
    xtlv_mapper_u16(_,      36, mail_msg_type) \
    xtlv_mapper_i16(_,      37, mail_status_code) \
    xtlv_mapper_string(_,   38, mail_user) \
    xtlv_mapper_string(_,   39, mail_sender) \
    xtlv_mapper_u32(_,      40, mail_length) \
    xtlv_mapper_string(_,   41, mail_domain) \
    xtlv_mapper_string(_,   42, mail_recver) \
    xtlv_mapper_string(_,   43, mail_hdr) \
    xtlv_mapper_u8(_,       44, mail_acs_type) \
    xtlv_mapper_string(_,   45, dns_domain) \
    xtlv_mapper_u8(_,       46, dns_ip_count) \
    xtlv_mapper_ip4(_,      47, dns_ip4) \
    xtlv_mapper_ip6(_,      48, dns_ip6) \
    xtlv_mapper_u8(_,       49, dns_response_code) \
    xtlv_mapper_u8(_,       50, dns_count_request) \
    xtlv_mapper_u8(_,       51, dns_count_response_record) \
    xtlv_mapper_u8(_,       52, dns_count_response_auth) \
    xtlv_mapper_u8(_,       53, dns_count_response_extra) \
    xtlv_mapper_u32(_,      54, dns_delay) \
    \
    xtlv_mapper_binary(_,   201, http_request) \
    xtlv_mapper_binary(_,   202, http_response) \
    xtlv_mapper_binary(_,   203, file_content) \
    xtlv_mapper_binary(_,   204, ssl_server_cert) \
    xtlv_mapper_binary(_,   205, ssl_client_cert) \
    xtlv_mapper_u8(_,       206, ssl_fail_reason) \
    /* end */

#define XTLV_OPS_ENUM(_name, _id, _type, _flag, _minsize, _maxsize, _dump, _check, _toxdr)  xtlv_id_##_name = _id,
enum { XTLV_MAPPER(XTLV_OPS_ENUM) xtlv_id_end };

// just for source insight
#define xtlv_id_header  xtlv_id_header
#define xtlv_id_end     xtlv_id_end

#define XTLV_OPS_STRUCT(_name, _id, _type, _flag, _minsize, _maxsize, _dump, _check, _toxdr) [_id] = { \
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
#define DECLARE_XTLV_VARS \
    uint32 __xtlv_opt; \
    uint32 xdr_seq; \
    xtlv_ops_t __xtlv_ops[xtlv_id_end] = { XTLV_MAPPER(XTLV_OPS_STRUCT) }; \
    os_extern_unused_var /* end */

extern xtlv_ops_t __xtlv_ops[];
extern uint32 __xtlv_opt;
extern uint32 xdr_seq;

enum {
    XTLV_OPT_DUMP = 0x01,
};

static inline void
xtlv_opt_set(uint32 flag)
{
    __xtlv_opt |= flag;
}

static inline bool
is_xtlv_opt_dump(void)
{
    return XTLV_OPT_DUMP==(XTLV_OPT_DUMP & __xtlv_opt);
}

static inline bool
is_good_xtlv_id(int id)
{
    return is_good_enum(id, xtlv_id_end);
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

#define xtlv_first(_tlv_header) (xtlv_t *)xtlv_data(_tlv_header)
#define xtlv_next(_tlv)         (xtlv_t *)((byte *)(_tlv) + xtlv_len(_tlv))

#define xtlv_u8(_tlv)       (_tlv)->pad
#define xtlv_u16(_tlv)      (*(uint16 *)xtlv_data(_tlv))
#define xtlv_u32(_tlv)      (*(uint32 *)xtlv_data(_tlv))
#define xtlv_u64(_tlv)      (*(uint64 *)xtlv_data(_tlv))

#define xtlv_i8(_tlv)       (_tlv)->pad
#define xtlv_i16(_tlv)      (*(int16 *)xtlv_data(_tlv))
#define xtlv_i32(_tlv)      (*(int32 *)xtlv_data(_tlv))
#define xtlv_i64(_tlv)      (*(int64 *)xtlv_data(_tlv))

#define xtlv_time(_tlv)     (*(xtlv_time_t *)xtlv_data(_tlv))
#define xtlv_duration(_tlv) (*(xtlv_duration_t *)xtlv_data(_tlv))

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

static inline void
xtlv_dump(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    if (ops->dump) {
        (*ops->dump)(tlv);
    }
}

static inline int
xtlv_error(xtlv_t *tlv, int err)
{
    if (err<0) {
        xtlv_ops_t *ops = xtlv_ops(tlv->id);

        if (XTLV_F_FIXED & ops->flag) {
            os_println("tlv name:%s fixed:%d id:%d pad:%d alen:%u hlen:%u dlen:%u", 
                ops->name, 
                ops->maxsize,
                tlv->id, 
                tlv->pad, 
                xtlv_len(tlv),
                xtlv_hdrlen(tlv),
                xtlv_datalen(tlv));
        } else {
            os_println("tlv name:%s id:%d pad:%d alen:%u hlen:%u dlen:%u", 
                ops->name, 
                tlv->id, 
                tlv->pad, 
                xtlv_len(tlv),
                xtlv_hdrlen(tlv),
                xtlv_datalen(tlv));
        }
    }

    return err;
}

static inline int
xtlv_check_fixed(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    uint32 dlen = xtlv_datalen(tlv);
    
    switch (ops->type) {
        case XTLV_T_u8:
        case XTLV_T_i8:
            if (0 != dlen) {
                return xtlv_error(tlv, -e_xtlv_invalid_short_size);
            }
            
            break;
        case XTLV_T_u16:
        case XTLV_T_i16:
            if (sizeof(uint32) != dlen) {
                return xtlv_error(tlv, -e_xtlv_invalid_short_size);
            }

            break;
        default:
            if (dlen != ops->maxsize) {
                return xtlv_error(tlv, -e_xtlv_invalid_object_size);
            }

            break;
    }

    return 0;
}

static inline int
xtlv_check_dynamic(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    uint32 dlen = xtlv_datalen(tlv);
    
    if (ops->minsize && dlen < ops->minsize) {
        return xtlv_error(tlv, -e_xtlv_too_small);
    }
    else if (ops->maxsize && dlen > ops->maxsize) {
        return xtlv_error(tlv, -e_xtlv_too_big);
    }

    return 0;
}

static inline int
xtlv_check(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    if (NULL==ops) {
        return xtlv_error(tlv, -e_xtlv_invalid_id);
    }

    if (xtlv_len(tlv) < xtlv_hdrlen(tlv)) {
        return xtlv_error(tlv, -e_xtlv_too_small);
    }

    if (ops->check) {
        return xtlv_error(tlv, (*ops->check)(tlv));
    }

    // use default checker
    if (XTLV_F_FIXED & ops->flag) {
        return xtlv_check_fixed(tlv);
    } else {
        return xtlv_check_dynamic(tlv);
    }
}

#define XTLV_DUMP(_fmt, _args...)       os_println(__tab _fmt, ##_args)
#define XTLV_DUMP2(_fmt, _args...)      os_println(__tab2 _fmt, ##_args)

#define XTLV_DUMP_BY(_tlv, _format, _type)  do{ \
    xtlv_ops_t *ops = xtlv_ops((_tlv)->id); \
                                            \
    XTLV_DUMP("id: %d, %s: " _format, (_tlv)->id, ops->name, xtlv_##_type(_tlv)); \
}while(0)

static inline void xtlv_dump_u8 (xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%u", u8);  }
static inline void xtlv_dump_u16(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%u", u16); }
static inline void xtlv_dump_u32(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%u", u32); }
static inline void xtlv_dump_u64(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%llu", u64); }

static inline void xtlv_dump_i8 (xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%d", i8);  }
static inline void xtlv_dump_i16(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%d", i16); }
static inline void xtlv_dump_i32(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%d", i32); }
static inline void xtlv_dump_i64(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%lld", i64); }

static inline void xtlv_dump_string(xtlv_t *tlv) { XTLV_DUMP_BY(tlv, "%s", string); }

static inline void 
xtlv_dump_time(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    XTLV_DUMP("id:%d, %s: %s", tlv->id, ops->name, os_time_string(xdr_time_second(xtlv_time(tlv))));
}

static inline void xtlv_dump_duration(xtlv_t *tlv) 
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    xtlv_duration_t d = xtlv_duration(tlv);
    uint32 s = (uint32)(d>>32);
    uint32 us= (uint32)(d & 0xffffffff);
    
    XTLV_DUMP("id:%d, %s %ds:%dus", tlv->id, ops->name, s, us); 
}

static inline void 
xtlv_dump_ip4(xtlv_t *tlv)
{
    xtlv_ops_t *ops = xtlv_ops(tlv->id);

    uint32 ip = xtlv_ip4(tlv);
    // ip = htonl(ip);
    
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

enum { XDR_SESSION_HSIZE = sizeof(xtlv_session_t) - 2*sizeof(xdr_ipaddr_t) };

static inline void 
xtlv_dump_session(xtlv_t *tlv)
{
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
        // ip = htonl(ip);
        XTLV_DUMP2("sip    : %s", os_ipstring(ip));
        
        ip = xdr_ip(&obj->dip);
        // ip = htonl(ip);
        XTLV_DUMP2("dip    : %s", os_ipstring(ip));
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
    
    uint16 duration[2];
} xtlv_session_st_t, xtlv_service_st_t;

static inline void 
xtlv_dump_session_st(xtlv_t *tlv)
{
    xtlv_session_st_t *obj = xtlv_session_st(tlv);
    int i;
    
    XTLV_DUMP("id: %d, %s:", tlv->id, xtlv_ops(tlv->id)->name);

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
    xtlv_time_t create;
    xtlv_time_t start;
    xtlv_time_t stop;
} xtlv_session_time_t;

static inline void 
xtlv_dump_session_time(xtlv_t *tlv)
{
    xtlv_session_time_t *obj = xtlv_session_time(tlv);
    
    XTLV_DUMP("id: %d, session_time:", tlv->id);
    
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
    xtlv_tcp_t *obj = xtlv_tcp(tlv);
    
    XTLV_DUMP("id: %d, tcp:", tlv->id);
    
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
    xtlv_L7_t *obj = xtlv_L7(tlv);
    
    XTLV_DUMP("id: %d, L7:", tlv->id);
    
    XTLV_DUMP2("status  : %u", obj->status);
    XTLV_DUMP2("class   : %u", obj->class);
    XTLV_DUMP2("protocol: %u", obj->protocol);
}

typedef struct {
    xtlv_time_t time_request;
    xtlv_time_t time_first_response;
    xtlv_time_t time_last_content;
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
}
xtlv_http_t;

static inline void 
xtlv_dump_http(xtlv_t *tlv)
{
    xtlv_http_t *obj = xtlv_http(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("time_request        : %s", os_time_string(xdr_time_second(obj->time_request)));
    XTLV_DUMP2("time_first_response : %s", os_time_string(xdr_time_second(obj->time_first_response)));
    XTLV_DUMP2("time_last_content   : %s", os_time_string(xdr_time_second(obj->time_last_content)));
    XTLV_DUMP2("service_delay       : %llu us", obj->service_delay);
    XTLV_DUMP2("content_length      : %u", obj->content_length);
    XTLV_DUMP2("status_code         : %u", obj->status_code);
    XTLV_DUMP2("method              : %u", obj->method);
    XTLV_DUMP2("version             : %u", obj->version);

    XTLV_DUMP2("first               : %s", bool_string(obj->u.st.first));
    XTLV_DUMP2("flag                : %u", obj->u.st.flag);
    XTLV_DUMP2("head                : %s", yes_string(obj->u.st.head));
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
    xtlv_sip_t *obj = xtlv_sip(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("call_direction  : %u", obj->call_direction);
    XTLV_DUMP2("call_type       : %u", obj->call_type);
    XTLV_DUMP2("hangup_reason   : %u", obj->hangup_reason);
    XTLV_DUMP2("signal_type     : %u", obj->signal_type);
    XTLV_DUMP2("dataflow_count  : %u", obj->dataflow_count);
    XTLV_DUMP2("invite          : %s", bool_string(XDR_SIP_INVITE==obj->u.st.invite));
    XTLV_DUMP2("bye             : %s", bool_string(XDR_SIP_BYE==obj->u.st.bye));
    XTLV_DUMP2("malloc          : %s", bool_string(obj->u.st.malloc));
}

typedef struct {
    uint16 port_client_start;
    uint16 port_client_end;
    uint16 port_server_start;
    uint16 port_server_end;
    uint16 count_video;
    uint16 count_audio;
    
    uint32 describe_delay;
} xtlv_rtsp_t;

static inline void 
xtlv_dump_rtsp(xtlv_t *tlv)
{
    xtlv_rtsp_t *obj = xtlv_rtsp(tlv);
    
    XTLV_DUMP("id: %d, http:", tlv->id);
    
    XTLV_DUMP2("port_client_start   : %u", obj->port_client_start);
    XTLV_DUMP2("port_client_end     : %u", obj->port_client_end);
    XTLV_DUMP2("port_server_start   : %u", obj->port_server_start);
    XTLV_DUMP2("port_server_end     : %u", obj->port_server_end);
    XTLV_DUMP2("count_video         : %u", obj->count_video);
    XTLV_DUMP2("count_audio         : %u", obj->count_audio);
    XTLV_DUMP2("describe_delay      : %u", obj->describe_delay);
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
    return NULL!=cache->multi;
}

static inline int
xcache_expand(xcache_t *cache)
{
    if (NULL==cache->multi) {
        xtlv_dprint("init record multi ...");
        
        cache->multi = (xtlv_t **)os_calloc(XCACHE_EXPAND, sizeof(xtlv_t *));
        if (NULL==cache->multi) {
            return -ENOMEM;
        }
        cache->current = 0;
        cache->count = XCACHE_EXPAND;
        
        xtlv_dprint("init record multi ok.");
    }

    if (cache->current == cache->count) {
        xtlv_dprint("expand record multi ...");
        
        cache->multi = (xtlv_t **)os_realloc(cache->multi, (cache->count + XCACHE_EXPAND) * sizeof(xtlv_t *));
        if (NULL==cache->multi) {
            return -ENOMEM;
        }
        cache->count += XCACHE_EXPAND;
        
        xtlv_dprint("expand record multi ok.");
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
        xtlv_dprint("copy record multi ...");
        
        /*
        * first, save at cache->tlv
        * second, save at cache->multi
        *   so, copy cache->tlv to cache->multi[0]
        */
        cache->multi[0] = cache->tlv;
        cache->current++;
        
        xtlv_dprint("copy record multi ok.");
    }
    
    xtlv_dprint("save record multi ...");
    cache->multi[cache->current++] = tlv;
    xtlv_dprint("save record multi ok.");

    return 0;
}

typedef struct {
    xtlv_t *header;
    
    xcache_t cache[xtlv_id_end];
} xrecord_t;

static inline int
xrecord_release(xrecord_t *record)
{
    xcache_t *cache;
    uint32 i;
    
    for (i=0; i<xtlv_id_end; i++) {
        cache = &record->cache[i];
        
        if (cache->multi) {
            xtlv_dprint("release record cache:%d multi ...", i);
            os_free(cache->multi);
            xtlv_dprint("release record cache:%d multi ok.", i);
        }
    }
    
    return 0;
}

static inline int
xrecord_save(xrecord_t *record, xtlv_t *tlv)
{
    xcache_t *cache = &record->cache[tlv->id];
    if (NULL==cache->tlv) {
        cache->tlv = tlv;

        xtlv_dprint("save record tlv id:%d", tlv->id);
        
        return 0;
    }

    xtlv_dprint("try save record multi tlv id:%d", tlv->id);
    
    xtlv_ops_t *ops = xtlv_ops(tlv->id);
    if (XTLV_F_MULTI & ops->flag) {
        return xtlv_error(tlv, xcache_save_multi(cache, tlv));
    } 
    else {
        return xtlv_error(tlv, -e_xtlv_not_support_multi);
    }
}

static inline int
__xrecord_parse(xrecord_t *record, xtlv_t *tlv, uint32 left)
{
    int err = 0;

    if (0==left) {
        return 0;
    }
    
    err = xtlv_check(tlv);
    if (err<0) {
        return err;
    }

    err = xrecord_save(record, tlv);
    if (err<0) {
        return err;
    }

    if (is_xtlv_opt_dump()) {
        xtlv_dump(tlv);
    }
    
    return __xrecord_parse(record, xtlv_next(tlv), left - xtlv_len(tlv));
}

static inline int
xrecord_parse(xrecord_t *record)
{
    xtlv_t *h = record->header;
    
    if (xtlv_id_header == h->id) {
        return __xrecord_parse(record, xtlv_first(h), xtlv_datalen(h));
    } else {
        return -e_xtlv_header_must_first;
    }
}

typedef struct {
    void *buffer;
    uint32 len;
    
    xrecord_t *records;
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

        left -= xtlv_len(h);
        h = xtlv_next(h);
    }

    return count;
}

static inline int
xblock_post(xblock_t *block)
{
    xtlv_t *h;
    int i;
    
    xtlv_dprint("xblock post ...");
    for (i=0, h=(xtlv_t *)block->buffer; 
         i < block->count;
         i++, h=xtlv_next(h)) {
        block->records[i].header = h;
    }
    xtlv_dprint("xblock post ok.");

    return 0;
}

static inline int
xblock_init(xblock_t *block, void *buffer, uint32 len)
{
    block->buffer   = buffer;
    block->len      = len;

    xtlv_dprint("xblock pre ...");
    int count = xblock_pre(buffer, len);
    if (count<0) {
        return count;
    }
    xtlv_dprint("xblock pre ok.");

    block->records = (xrecord_t *)os_calloc(count, sizeof(xrecord_t));
    if (NULL==block->records) {
        return -ENOMEM;
    }
    block->count = count;
    xtlv_dprint("xblock count:%d", count);
    
    return xblock_post(block);
}

static inline void
xblock_release(xblock_t *block)
{
    xtlv_dprint("release block ...");
    if (block->records) {
        int i;

        for (i=0; i<block->count; i++) {
            xtlv_dprint("release record:%d ...", i);
            xrecord_release(&block->records[i]);
            xtlv_dprint("release record:%d ok.", i);
        }
        
        os_free(block->records);
    }
    xtlv_dprint("release block ok.");
}

static inline int
xblock_parse(xblock_t *block)
{
    int i, err;

    for (i=0; i<block->count; i++) {
        xtlv_dprint("xrecord parse:%d ...", i);
        err = xrecord_parse(&block->records[i]);
        if (err<0) {
            return err;
        }
        xtlv_dprint("xrecord parse:%d ok.", i);
    }

    return 0;
}
/******************************************************************************/
#endif /* __TLV_H_d203748a8a974e6282d89ddcde27123a__ */
