#ifndef __XDR_ENDIAN_H_049defbc41a4441e855ee0479dad96eb__
#define __XDR_ENDIAN_H_049defbc41a4441e855ee0479dad96eb__
/******************************************************************************/
#ifndef XDR_BIGENDIAN
#define XDR_BIGENDIAN    0
#endif

#define XDR_NTOH64(_v)  do{ (_v) = ntonll(_v); }while(0)
#define XDR_NTOH32(_v)  do{ (_v) = ntonl(_v); }while(0)
#define XDR_NTOH16(_v)  do{ (_v) = ntons(_v); }while(0)

#define XDR_HTON64(_v)  XDR_NTOH64(_v)
#define XDR_HTON32(_v)  XDR_NTOH32(_v)
#define XDR_HTON16(_v)  XDR_NTOH16(_v)

#if XDR_BIGENDIAN
static inline void
xdr_string_ntoh(xdr_string_t *p) 
{
    XDR_NTOH32(p->len);
    XDR_NTOH32(p->offset);
}
#else
#define xdr_string_ntoh(_p) os_do_nothing()
#endif
#define xdr_string_hton(_p) xdr_string_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_array_ntoh(xdr_array_t *p) 
{
    XDR_NTOH32(p->offset);
    XDR_NTOH32(p->size);
    
    XDR_NTOH16(p->count);
    XDR_NTOH16(p->type);
}
#else
#define xdr_array_ntoh(_p) os_do_nothing()
#endif
#define xdr_array_hton(_p) xdr_array_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_session_ntoh(xdr_session_st_t *p) 
{
    XDR_NTOH32(p->bytes);
    XDR_NTOH32(p->ip_packet);
    XDR_NTOH32(p->ip_frag);
    XDR_NTOH32(p->tcp_disorder);
    XDR_NTOH32(p->duration);
}
#else
#define xdr_session_ntoh(_p) os_do_nothing()
#endif
#define xdr_session_hton(_p) xdr_session_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_service_st_ntoh(xdr_service_st_t *p) 
{
    XDR_NTOH32(p->bytes);
    XDR_NTOH32(p->ip_packet);
    XDR_NTOH32(p->ip_frag);
    XDR_NTOH32(p->tcp_disorder);
    XDR_NTOH32(p->tcp_retransmit);
    XDR_NTOH32(p->duration);
}
#else
#define xdr_service_st_ntoh(_p) os_do_nothing()
#endif
#define xdr_service_st_hton(_p) xdr_service_st_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_tcp_ntoh(xdr_tcp_t *p) 
{
    XDR_NTOH32(p->first_request_delay);
    XDR_NTOH32(p->first_response_delay);
    XDR_NTOH32(p->window);
    
    XDR_NTOH16(p->synack_to_syn_time);
    XDR_NTOH16(p->ack_to_syn_time);
    XDR_NTOH16(p->mss);
    XDR_NTOH16(p->flag);
}
#else
#define xdr_tcp_ntoh(_p) os_do_nothing()
#endif
#define xdr_tcp_hton(_p) xdr_tcp_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_tcp_ntoh(xdr_http_t *p) 
{
    XDR_NTOH64(p->time_request);
    XDR_NTOH64(p->time_first_response);
    XDR_NTOH64(p->time_last_content);
    
    XDR_NTOH16(p->status_code);
    XDR_NTOH16(p->u.v);
    
    xdr_string_ntoh(&p->host);
    xdr_string_ntoh(&p->url);
    xdr_string_ntoh(&p->host_xonline);
    xdr_string_ntoh(&p->user_agent);
    xdr_string_ntoh(&p->content);
    xdr_string_ntoh(&p->refer);
    xdr_string_ntoh(&p->cookie);
    xdr_string_ntoh(&p->location);
    xdr_string_ntoh(&p->request);
    xdr_string_ntoh(&p->response);
}
#else
#define xdr_tcp_ntoh(_p) os_do_nothing()
#endif
#define xdr_tcp_hton(_p) xdr_tcp_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_sip_ntoh(xdr_sip_t *p) 
{
    XDR_NTOH16(p->dataflow_count);
    XDR_NTOH16(p->u.v);
    
    xdr_string_ntoh(&p->calling_number);
    xdr_string_ntoh(&p->called_number);
    xdr_string_ntoh(&p->session_id);
}
#else
#define xdr_sip_ntoh(_p) os_do_nothing()
#endif
#define xdr_sip_hton(_p) xdr_sip_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_rtsp_ntoh(xdr_rtsp_t *p) 
{
    XDR_NTOH16(p->dataflow_count);
    XDR_NTOH16(p->port_client_end);
    XDR_NTOH16(p->port_server_start);
    XDR_NTOH16(p->port_client_end);
    XDR_NTOH16(p->count_video);
    XDR_NTOH16(p->count_audio);
    
    XDR_NTOH32(p->describe_delay);
    
    xdr_string_ntoh(&p->url);
    xdr_string_ntoh(&p->user_agent);
    xdr_string_ntoh(&p->server_ip);
}
#else
#define xdr_rtsp_ntoh(_p) os_do_nothing()
#endif
#define xdr_rtsp_hton(_p) xdr_rtsp_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_ftp_ntoh(xdr_ftp_t *p) 
{
    XDR_NTOH32(p->filesize);
    XDR_NTOH64(p->response_delay);
    XDR_NTOH64(p->trans_duration);
    
    xdr_string_ntoh(&p->status);
    xdr_string_ntoh(&p->user);
    xdr_string_ntoh(&p->pwd);
    xdr_string_ntoh(&p->filename);
}
#else
#define xdr_ftp_ntoh(_p) os_do_nothing()
#endif
#define xdr_ftp_hton(_p) xdr_ftp_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_mail_ntoh(xdr_mail_t *p) 
{
    XDR_NTOH16(p->msg_type);
    XDR_NTOH16(p->status_code);
    XDR_NTOH32(p->length);
    
    xdr_string_ntoh(&p->user);
    xdr_string_ntoh(&p->domain);
    xdr_string_ntoh(&p->sender);
    xdr_string_ntoh(&p->recver);
    xdr_string_ntoh(&p->hdr);
}
#else
#define xdr_mail_ntoh(_p) os_do_nothing()
#endif
#define xdr_mail_hton(_p) xdr_mail_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_dns_ntoh(xdr_dns_t *p) 
{
    XDR_NTOH32(p->delay);
    
    xdr_array_ntoh(&p->ip);
    xdr_string_ntoh(&p->domain);
}
#else
#define xdr_dns_ntoh(_p) os_do_nothing()
#endif
#define xdr_dns_hton(_p) xdr_dns_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_cert_ntoh(xdr_cert_t *p) 
{
    xdr_string_ntoh(&p->cert);
    xdr_string_ntoh(&p->domain);
}
#else
#define xdr_cert_ntoh(_p) os_do_nothing()
#endif
#define xdr_cert_hton(_p) xdr_cert_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_ssl_ntoh(xdr_ssl_t *p) 
{
    xdr_array_ntoh(&p->cert_server);
    xdr_array_ntoh(&p->cert_client);
}
#else
#define xdr_ssl_ntoh(_p) os_do_nothing()
#endif
#define xdr_ssl_hton(_p) xdr_ssl_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_alert_ntoh(xdr_alert_t *p) 
{
    
}
#else
#define xdr_alert_ntoh(_p) os_do_nothing()
#endif
#define xdr_alert_hton(_p) xdr_alert_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_session_time_ntoh(xdr_session_time_t *p) 
{
    XDR_NTOH64(p->create);
    XDR_NTOH64(p->start);
    XDR_NTOH64(p->stop);
}
#else
#define xdr_session_time_ntoh(_p) os_do_nothing()
#endif
#define xdr_session_time_hton(_p) xdr_session_time_ntoh(_p)

#if XDR_BIGENDIAN
static inline void
xdr_proto_ntoh(xdr_proto_t *p) 
{
    XDR_NTOH32(p->offsetof_session_time);
    XDR_NTOH32(p->offsetof_session_st);
    XDR_NTOH32(p->offsetof_service_st);
    XDR_NTOH32(p->offsetof_alert);
    XDR_NTOH32(p->offsetof_file);
    
    XDR_NTOH32(p->offsetof_L4);
    XDR_NTOH32(p->offsetof_L5);
    XDR_NTOH32(p->offsetof_L6);

    XDR_NTOH16(p->L7.protocol);

    XDR_NTOH32(p->total);
    XDR_NTOH32(p->flag);

    XDR_NTOH32(p->ip_src);
    XDR_NTOH32(p->ip_dst);
    XDR_NTOH16(p->port_src);
    XDR_NTOH16(p->port_dst);

    XDR_NTOH32(p->first_response_delay);
}
#else
#define xdr_proto_ntoh(_p) os_do_nothing()
#endif
#define xdr_proto_hton(_p) xdr_proto_ntoh(_p)

/******************************************************************************/
#endif /* __XDR_ENDIAN_H_049defbc41a4441e855ee0479dad96eb__ */
