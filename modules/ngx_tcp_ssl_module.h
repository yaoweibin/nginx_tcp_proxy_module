
#ifndef _NGX_TCP_SSL_H_INCLUDED_
#define _NGX_TCP_SSL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct {
    ngx_flag_t                      enable;

    ngx_ssl_t                       ssl;

    ngx_flag_t                      prefer_server_ciphers;

    ngx_uint_t                      protocols;

    ngx_uint_t                      verify;
    ngx_uint_t                      verify_depth;

    ssize_t                         builtin_session_cache;

    time_t                          session_timeout;

    ngx_str_t                       certificate;
    ngx_str_t                       certificate_key;
    ngx_str_t                       dhparam;
#if defined(nginx_version) && nginx_version >= 1000006
    ngx_str_t                       ecdh_curve; 
#endif
    ngx_str_t                       client_certificate;
    ngx_str_t                       crl;

    ngx_str_t                       ciphers;

    ngx_shm_zone_t                 *shm_zone;

    u_char                         *file;
    ngx_uint_t                      line;
} ngx_tcp_ssl_srv_conf_t;


extern ngx_module_t  ngx_tcp_ssl_module;


#endif /* _NGX_TCP_SSL_H_INCLUDED_ */
