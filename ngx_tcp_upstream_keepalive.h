
#ifndef _NGX_TCP_UPSTREAM_KEEPALIVE_H_INCLUDED_
#define _NGX_TCP_UPSTREAM_KEEPALIVE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>

typedef struct {
    ngx_uint_t                         max_cached;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_tcp_upstream_init_pt           original_init_upstream;
    ngx_tcp_upstream_init_peer_pt      original_init_peer;

} ngx_tcp_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_tcp_upstream_keepalive_srv_conf_t  *conf;

    ngx_tcp_upstream_t                *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

} ngx_tcp_upstream_keepalive_peer_data_t;


typedef struct {
    ngx_tcp_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    u_char                             sockaddr[NGX_SOCKADDRLEN];

} ngx_tcp_upstream_keepalive_cache_t;

#endif
