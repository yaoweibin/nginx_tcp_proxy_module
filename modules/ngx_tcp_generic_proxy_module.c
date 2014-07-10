

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct ngx_tcp_proxy_s {
    ngx_peer_connection_t    *upstream;
    ngx_buf_t                *buffer;
} ngx_tcp_proxy_ctx_t;


typedef struct ngx_tcp_proxy_conf_s {
    ngx_tcp_upstream_conf_t   upstream;

    ngx_str_t                 url;
    size_t                    buffer_size;
} ngx_tcp_proxy_conf_t;


static void ngx_tcp_proxy_init_session(ngx_tcp_session_t *s); 
static  void ngx_tcp_proxy_init_upstream(ngx_connection_t *c, 
    ngx_tcp_session_t *s);
static void ngx_tcp_upstream_init_proxy_handler(ngx_tcp_session_t *s, 
    ngx_tcp_upstream_t *u);
static char *ngx_tcp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_tcp_proxy_dummy_read_handler(ngx_event_t *ev);
static void ngx_tcp_proxy_dummy_write_handler(ngx_event_t *ev);
static void ngx_tcp_proxy_handler(ngx_event_t *ev);
static void *ngx_tcp_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_tcp_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_tcp_protocol_t  ngx_tcp_generic_protocol = {

    ngx_string("tcp_generic"),
    { 0, 0, 0, 0 },
    NGX_TCP_GENERIC_PROTOCOL,
    ngx_tcp_proxy_init_session,
    NULL,
    NULL,
    ngx_string("500 Internal server error" CRLF)

};


static ngx_command_t  ngx_tcp_proxy_commands[] = {

    { ngx_string("proxy_pass"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_proxy_pass,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("proxy_buffer"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_proxy_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_connect_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_proxy_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_proxy_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_proxy_conf_t, upstream.send_timeout),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_proxy_module_ctx = {
    &ngx_tcp_generic_protocol,             /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_proxy_create_conf,             /* create server configuration */
    ngx_tcp_proxy_merge_conf               /* merge server configuration */
};


ngx_module_t  ngx_tcp_proxy_module = {
    NGX_MODULE_V1,
    &ngx_tcp_proxy_module_ctx,             /* module context */
    ngx_tcp_proxy_commands,                /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void 
ngx_tcp_proxy_init_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t         *c;
    ngx_tcp_proxy_conf_t     *pcf;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp proxy init session");

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_proxy_module);

    s->buffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    if (s->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    s->out.len = 0;

    c->write->handler = ngx_tcp_proxy_dummy_write_handler;
    c->read->handler = ngx_tcp_proxy_dummy_read_handler;

    ngx_add_timer(c->read, cscf->timeout);

    ngx_tcp_proxy_init_upstream(c, s);

    return;
}


static void
ngx_tcp_proxy_dummy_write_handler(ngx_event_t *wev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "tcp proxy dummy write handler: %d", c->fd);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static void
ngx_tcp_proxy_dummy_read_handler(ngx_event_t *rev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "tcp proxy dummy read handler: %d", c->fd);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static  void
ngx_tcp_proxy_init_upstream(ngx_connection_t *c, ngx_tcp_session_t *s)
{
    ngx_tcp_upstream_t       *u;
    ngx_tcp_proxy_ctx_t      *p;
    ngx_tcp_proxy_conf_t     *pcf;

    s->connection->log->action = "ngx_tcp_proxy_init_upstream";

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_proxy_module);
    if (pcf->upstream.upstream == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_tcp_proxy_ctx_t));
    if (p == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_set_ctx(s, p, ngx_tcp_proxy_module);

    if (ngx_tcp_upstream_create(s) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    u = s->upstream;

    u->conf = &pcf->upstream;

    u->write_event_handler = ngx_tcp_upstream_init_proxy_handler;
    u->read_event_handler = ngx_tcp_upstream_init_proxy_handler;

    p->upstream = &u->peer;

    p->buffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    if (p->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_upstream_init(s);

    return;
}


static void 
ngx_tcp_upstream_init_proxy_handler(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u)
{
    ngx_connection_t         *c;
    ngx_tcp_proxy_ctx_t      *pctx;
    ngx_tcp_proxy_conf_t     *pcf;

    c = s->connection;
    c->log->action = "ngx_tcp_upstream_init_proxy_handler";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp proxy upstream init proxy");

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_proxy_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_proxy_module);

    if (pcf == NULL || pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    pctx->upstream = &s->upstream->peer;

    c = pctx->upstream->connection;
    if (c->read->timedout || c->write->timedout) {
        ngx_tcp_upstream_next(s, u, NGX_TCP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (ngx_tcp_upstream_check_broken_connection(s) != NGX_OK){
        ngx_tcp_upstream_next(s, u, NGX_TCP_UPSTREAM_FT_ERROR);
        return;
    }

    s->connection->read->handler = ngx_tcp_proxy_handler;
    s->connection->write->handler = ngx_tcp_proxy_handler;

    c->read->handler = ngx_tcp_proxy_handler;
    c->write->handler = ngx_tcp_proxy_handler;

    ngx_add_timer(c->read, pcf->upstream.read_timeout);
    ngx_add_timer(c->write, pcf->upstream.send_timeout);

    if (ngx_handle_read_event(s->connection->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

#if (NGX_TCP_SSL)

    /* 
     * The ssl connection with client may not trigger the read event again,
     * So I trigger it in this function.
     * */
    if (s->connection->ssl) {
        ngx_tcp_proxy_handler(s->connection->read); 
    }

#endif

    return;
}


static void
ngx_tcp_proxy_handler(ngx_event_t *ev) 
{
    char                     *action, *recv_action, *send_action;
    off_t                    *read_bytes, *write_bytes;
    size_t                    size;
    ssize_t                   n;
    ngx_buf_t                *b;
    ngx_err_t                 err;
    ngx_uint_t                do_write, first_read;
    ngx_connection_t         *c, *src, *dst;
    ngx_tcp_session_t        *s;
    ngx_tcp_proxy_conf_t     *pcf;
    ngx_tcp_proxy_ctx_t      *pctx;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = ev->data;
    s = c->data;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    if (ev->timedout) {
        c->log->action = "proxying";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "proxy timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_proxy_module);

    if (pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    read_bytes = NULL;
    write_bytes = NULL;

    if (c == s->connection) {
        if (ev->write) {
            recv_action = "client write: proxying and reading from upstream";
            send_action = "client write: proxying and sending to client";
            src = pctx->upstream->connection;
            dst = c;
            b = pctx->buffer;
            write_bytes = &s->bytes_write;
        } else {
            recv_action = "client read: proxying and reading from client";
            send_action = "client read: proxying and sending to upstream";
            src = c;
            dst = pctx->upstream->connection;
            b = s->buffer;
            read_bytes = &s->bytes_read;
        }

    } else {
        if (ev->write) {
            recv_action = "upstream write: proxying and reading from client";
            send_action = "upstream write: proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;
            read_bytes = &s->bytes_read;
        } else {
            recv_action = "upstream read: proxying and reading from upstream";
            send_action = "upstream read: proxying and sending to client";
            src = c;
            dst = s->connection;
            b = pctx->buffer;
            write_bytes = &s->bytes_write;
        }
    }

    do_write = ev->write ? 1 : 0;

#if (NGX_TCP_SSL)
    /* SSL Need this */
    if (s->connection->ssl) {
        first_read = 1;
    } else {
    	first_read = 0;
    }
#else
    first_read = 0;
#endif

    ngx_log_debug4(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "tcp proxy handler: %d, #%d > #%d, time:%ui",
                   do_write, src->fd, dst->fd, ngx_current_msec);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);
                err = ngx_socket_errno;

                ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
                               "tcp proxy handler send:%d", n);

                if (n == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, c->log, err, "proxy send error");

                    ngx_tcp_finalize_session(s);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (write_bytes) {
                        *write_bytes += n;
                    }

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size) {
            if (src->read->ready || first_read) { 

                first_read = 0;
                c->log->action = recv_action;

                n = src->recv(src, b->last, size);
                err = ngx_socket_errno;

                ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
                               "tcp proxy handler recv:%d", n);

                if (n == NGX_AGAIN || n == 0) {
                    break;
                }

                if (n > 0) {
                    do_write = 1;
                    b->last += n;

                    if (read_bytes) {
                        *read_bytes += n;
                    }

                    continue;
                }

                if (n == NGX_ERROR) {
                    src->read->eof = 1;
                }
            }
        }

        break;
    }

    c->log->action = "nginx tcp proxying";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
            || (pctx->upstream->connection->read->eof
                && pctx->buffer->pos == pctx->buffer->last)
            || (s->connection->read->eof
                && pctx->upstream->connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_proxy_module);

    if (c == s->connection) {
        ngx_add_timer(c->read, cscf->timeout);
    }

    if (c == pctx->upstream->connection) {
        if (ev->write) {
            ngx_add_timer(c->write, pcf->upstream.send_timeout);
        } else {
            ngx_add_timer(c->read, pcf->upstream.read_timeout);
        }
    }

    return;
}


static char *
ngx_tcp_proxy_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_proxy_conf_t *pcf = conf;

    u_short                     port = 80;
    ngx_str_t                  *value, *url = &pcf->url;
    ngx_url_t                   u;
    ngx_tcp_core_srv_conf_t    *cscf;

    cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);

    if (cscf->protocol && ngx_strncmp(cscf->protocol->name.data,
                                      (u_char *)"tcp_generic",
                                      sizeof("tcp_generic") - 1) != 0) {

        return "the protocol should be tcp_generic";
    }

    if (cscf->protocol == NULL) {
        cscf->protocol = &ngx_tcp_generic_protocol;
    }

    if (pcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    url = &value[1];

    ngx_memzero(&u, sizeof(u));

    u.url.len = url->len;
    u.url.data = url->data;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    pcf->upstream.upstream = ngx_tcp_upstream_add(cf, &u, 0);
    if (pcf->upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_tcp_proxy_create_conf(ngx_conf_t *cf) 
{
    ngx_tcp_proxy_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->buffer_size = NGX_CONF_UNSET_SIZE;

    pcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    return pcf;
}


static char *
ngx_tcp_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_tcp_proxy_conf_t *prev = parent;
    ngx_tcp_proxy_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    return NGX_CONF_OK;
}
