
#ifndef _NGX_TCP_SESSION_H_INCLUDED_
#define _NGX_TCP_SESSION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_tcp.h>


typedef struct ngx_tcp_session_s {
    uint32_t                signature;         /* "TCP" */

    ngx_pool_t             *pool;

    ngx_connection_t       *connection;
    ngx_tcp_upstream_t     *upstream;

    ngx_str_t               out;
    ngx_buf_t              *buffer;

    void                  **ctx;
    void                  **main_conf;
    void                  **srv_conf;

    ngx_resolver_ctx_t     *resolver_ctx;

    ngx_tcp_cleanup_t      *cleanup;

    time_t                  start_sec;
    ngx_msec_t              start_msec;

    off_t                   bytes_read;
    off_t                   bytes_write;

    unsigned                quit:1;
    ngx_str_t              *addr_text;
    ngx_str_t               host;

} ngx_tcp_session_t;


typedef void (*ngx_tcp_cleanup_pt)(void *data);


struct ngx_tcp_cleanup_s {
    ngx_tcp_cleanup_pt      handler;
    void                   *data;
    ngx_tcp_cleanup_t      *next;
};

void ngx_tcp_init_connection(ngx_connection_t *c);

void ngx_tcp_send(ngx_event_t *wev);
ngx_int_t ngx_tcp_read_command(ngx_tcp_session_t *s, ngx_connection_t *c);
void ngx_tcp_auth(ngx_tcp_session_t *s, ngx_connection_t *c);
void ngx_tcp_close_connection(ngx_connection_t *c);
void ngx_tcp_session_internal_server_error(ngx_tcp_session_t *s);

u_char *ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len);

void ngx_tcp_finalize_session(ngx_tcp_session_t *s);

ngx_tcp_cleanup_t * ngx_tcp_cleanup_add(ngx_tcp_session_t *s, size_t size);

ngx_int_t ngx_tcp_access_handler(ngx_tcp_session_t *s);
ngx_int_t ngx_tcp_log_handler(ngx_tcp_session_t *s);

#endif
