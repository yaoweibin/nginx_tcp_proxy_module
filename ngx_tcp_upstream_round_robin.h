
#ifndef _NGX_TCP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_
#define _NGX_TCP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct {
    struct sockaddr                *sockaddr;
    socklen_t                       socklen;
    ngx_str_t                       name;

    ngx_int_t                       current_weight;
    ngx_int_t                       weight;

    ngx_uint_t                      fails;
    time_t                          accessed;

    ngx_uint_t                      max_fails;
    time_t                          fail_timeout;

    ngx_uint_t                      check_index;

    ngx_uint_t                      down;          /* unsigned  down:1; */

#if (NGX_TCP_SSL)
    ngx_ssl_session_t              *ssl_session;   /* local to a process */
#endif
} ngx_tcp_upstream_rr_peer_t;


typedef struct ngx_tcp_upstream_rr_peers_s  ngx_tcp_upstream_rr_peers_t;

struct ngx_tcp_upstream_rr_peers_s {
    ngx_uint_t                      single;        /* unsigned  single:1; */
    ngx_uint_t                      number;
    ngx_uint_t                      last_cached;

 /* ngx_mutex_t                    *mutex; */
    ngx_connection_t              **cached;

    ngx_str_t                      *name;

    ngx_tcp_upstream_rr_peers_t    *next;

    ngx_tcp_upstream_rr_peer_t     peer[1];
};


typedef struct {
    ngx_tcp_upstream_rr_peers_t    *peers;
    ngx_uint_t                      current;
    uintptr_t                      *tried;
    uintptr_t                       data;
} ngx_tcp_upstream_rr_peer_data_t;


ngx_int_t ngx_tcp_upstream_init_round_robin(ngx_conf_t *cf,
    ngx_tcp_upstream_srv_conf_t *us);
ngx_int_t ngx_tcp_upstream_init_round_robin_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us);
ngx_int_t ngx_tcp_upstream_create_round_robin_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_resolved_t *ur);
ngx_int_t ngx_tcp_upstream_get_round_robin_peer(ngx_peer_connection_t *pc,
    void *data);
void ngx_tcp_upstream_free_round_robin_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

#if (NGX_TCP_SSL)
ngx_int_t ngx_tcp_upstream_set_round_robin_peer_session(
    ngx_peer_connection_t *pc, void *data);
void ngx_tcp_upstream_save_round_robin_peer_session(ngx_peer_connection_t *pc,
     void *data);
#endif


#endif /* _NGX_TCP_UPSTREAM_ROUND_ROBIN_H_INCLUDED_ */
