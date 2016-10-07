
#ifndef _NGX_TCP_UPSTREAM_H_INCLUDED_
#define _NGX_TCP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_tcp.h>


#define NGX_TCP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_TCP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_TCP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_TCP_UPSTREAM_FT_TCP_500         0x00000010
#define NGX_TCP_UPSTREAM_FT_TCP_502         0x00000020
#define NGX_TCP_UPSTREAM_FT_TCP_503         0x00000040
#define NGX_TCP_UPSTREAM_FT_TCP_504         0x00000080
#define NGX_TCP_UPSTREAM_FT_TCP_404         0x00000100
#define NGX_TCP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_TCP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_TCP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_TCP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_TCP_UPSTREAM_FT_OFF             0x80000000

#define NGX_TCP_UPSTREAM_FT_STATUS          (NGX_TCP_UPSTREAM_FT_TCP_500  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_502  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_503  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_504  \
                                             |NGX_TCP_UPSTREAM_FT_TCP_404)

#define NGX_TCP_UPSTREAM_INVALID_HEADER     40


#define NGX_TCP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_TCP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_TCP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_TCP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010

typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;

    ngx_str_t                       *peer;
} ngx_tcp_upstream_state_t;


typedef struct {
    ngx_uint_t                       check_shm_size;
    ngx_tcp_check_peers_conf_t      *peers_conf;
    ngx_array_t                      upstreams; /* ngx_tcp_upstream_srv_conf_t */
} ngx_tcp_upstream_main_conf_t;


typedef ngx_int_t (*ngx_tcp_upstream_init_pt)(ngx_conf_t *cf,
        ngx_tcp_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_tcp_upstream_init_peer_pt)(ngx_tcp_session_t *s,
        ngx_tcp_upstream_srv_conf_t *us);

typedef struct {
    ngx_tcp_upstream_init_pt         init_upstream;
    ngx_tcp_upstream_init_peer_pt    init;
    void                            *data;
} ngx_tcp_upstream_peer_t;

typedef struct {
    ngx_peer_addr_t                 *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_uint_t                       max_busy;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_tcp_upstream_server_t;


#define NGX_TCP_UPSTREAM_CREATE        0x0001
#define NGX_TCP_UPSTREAM_WEIGHT        0x0002
#define NGX_TCP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_TCP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_TCP_UPSTREAM_DOWN          0x0010
#define NGX_TCP_UPSTREAM_BACKUP        0x0020
#define NGX_TCP_UPSTREAM_SRUN_ID       0x0040
#define NGX_TCP_UPSTREAM_MAX_BUSY      0x0080

struct ngx_tcp_upstream_srv_conf_s {

    ngx_tcp_upstream_peer_t          peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_tcp_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
#if (nginx_version) >= 1003011
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */
#endif

    ngx_uint_t                       fall_count;
    ngx_uint_t                       rise_count;
    ngx_msec_t                       check_interval;
    ngx_msec_t                       check_timeout;

    check_conf_t                    *check_type_conf;
    ngx_str_t                        send;

    union {
        ngx_uint_t                   return_code;
        ngx_uint_t                   status_alive;
    } code;
};


typedef struct {
    ngx_tcp_upstream_srv_conf_t     *upstream;

    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       timeout;
} ngx_tcp_upstream_conf_t;


struct ngx_tcp_upstream_resolved_s {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
#if (nginx_version) >= 1005008
    #if (nginx_version) >= 1009001
        ngx_resolver_addr_t *addrs;
    #else
        ngx_addr_t *addrs;
    #endif
    #else
        in_addr_t *addrs;
#endif

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
};


typedef void (*ngx_tcp_upstream_handler_pt)(ngx_tcp_session_t *s,
        ngx_tcp_upstream_t *u);

struct ngx_tcp_upstream_s {
    ngx_tcp_upstream_handler_pt      read_event_handler;
    ngx_tcp_upstream_handler_pt      write_event_handler;

    ngx_peer_connection_t            peer;
    ngx_tcp_upstream_conf_t         *conf;
    ngx_tcp_upstream_resolved_t     *resolved;
    ngx_tcp_upstream_state_t        *state;
    ngx_tcp_cleanup_pt              *cleanup;
};


typedef struct {
    ngx_uint_t                       status;
    ngx_uint_t                       mask;
} ngx_tcp_upstream_next_t;


ngx_int_t ngx_tcp_upstream_create(ngx_tcp_session_t *s);
void ngx_tcp_upstream_init(ngx_tcp_session_t *s);
ngx_tcp_upstream_srv_conf_t *ngx_tcp_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);

ngx_int_t ngx_tcp_upstream_check_broken_connection(ngx_tcp_session_t *s);
void ngx_tcp_upstream_next(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u,
     ngx_uint_t ft_type);

#define ngx_tcp_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_tcp_upstream_module;


#endif /* _NGX_TCP_UPSTREAM_H_INCLUDED_ */
