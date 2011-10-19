
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_tcp.h>

#define _GNU_SOURCE
#include <fcntl.h>

#include <http_request_parser.h>

typedef struct ngx_tcp_websocket_s {
    ngx_peer_connection_t  *upstream;
    ngx_buf_t              *buffer;

    http_request_parser   *parser;
} ngx_tcp_websocket_ctx_t;


typedef struct ngx_tcp_websocket_conf_s {
    ngx_tcp_upstream_conf_t  upstream;

    ngx_str_t   url;
    size_t      buffer_size;

    /*TODO: support for the variable in the websocket_pass*/
    ngx_array_t *websocket_lengths;
    ngx_array_t *websocket_values;
} ngx_tcp_websocket_conf_t;


static void ngx_tcp_websocket_init_session(ngx_tcp_session_t *s);
static  void ngx_tcp_websocket_init_upstream(ngx_connection_t *c, ngx_tcp_session_t *s);
static void ngx_tcp_upstream_websocket_proxy_init_handler(ngx_tcp_session_t *s, 
        ngx_tcp_upstream_t *u);
static char *ngx_tcp_websocket_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_tcp_websocket_dummy_read_handler(ngx_event_t *ev);
static void ngx_tcp_websocket_dummy_write_handler(ngx_event_t *ev);
static void ngx_tcp_websocket_init_protocol(ngx_event_t *ev);
static void websocket_http_request_parser_init(http_request_parser *hp, void *data); 

static void request_method(void *data, const signed char *at, size_t length);
static void request_uri(void *data, const signed char *at, size_t length);
static void fragment(void *data, const signed char *at, size_t length);
static void request_path(void *data, const signed char *at, size_t length);
static void query_string(void *data, const signed char *at, size_t length);
static void http_version(void *data, const signed char *at, size_t length);
static void header_done(void *data, const signed char *at, size_t length);
static void http_field(void *data, const signed char *field, size_t flen, 
        const signed char *value, size_t vlen);

static void ngx_tcp_websocket_parse_protocol(ngx_event_t *ev);
static ngx_int_t websocket_http_request_parser_execute(http_request_parser *hp); 

static void ngx_tcp_websocket_proxy_handler(ngx_event_t *ev);
static void *ngx_tcp_websocket_create_conf(ngx_conf_t *cf);
static char *ngx_tcp_websocket_merge_conf(ngx_conf_t *cf, void *parent,
        void *child);

static ngx_tcp_protocol_t  ngx_tcp_websocket_protocol = {
    ngx_string("tcp_websocket"),
    { 80, 443, 0, 0 },
    NGX_TCP_WEBSOCKET_PROTOCOL,
    ngx_tcp_websocket_init_session,
    ngx_tcp_websocket_init_protocol,
    ngx_tcp_websocket_parse_protocol,

    ngx_string("500 Internal server error" CRLF)
};


static ngx_command_t  ngx_tcp_websocket_commands[] = {

    { ngx_string("websocket_pass"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_websocket_pass,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("websocket_buffer"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_websocket_conf_t, buffer_size),
      NULL },

    { ngx_string("websocket_connect_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_websocket_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("websocket_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_websocket_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("websocket_send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_websocket_conf_t, upstream.send_timeout),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_websocket_module_ctx = {
    &ngx_tcp_websocket_protocol,               /* protocol */

    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */

    ngx_tcp_websocket_create_conf,             /* create server configuration */
    ngx_tcp_websocket_merge_conf               /* merge server configuration */
};


ngx_module_t  ngx_tcp_websocket_module = {
    NGX_MODULE_V1,
    &ngx_tcp_websocket_module_ctx,         /* module context */
    ngx_tcp_websocket_commands,            /* module directives */
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
ngx_tcp_websocket_init_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t             *c;
    ngx_tcp_websocket_ctx_t      *pctx;
    ngx_tcp_core_srv_conf_t      *cscf;
    ngx_tcp_websocket_conf_t     *pcf;

    c = s->connection;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_websocket_module);

    pctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_tcp_websocket_ctx_t));
    if (pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }
    ngx_tcp_set_ctx(s, pctx, ngx_tcp_websocket_module);

    s->out.len = 0;

    s->buffer = ngx_create_temp_buf(s->connection->pool, pcf->buffer_size);
    if (s->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    c->write->handler = ngx_tcp_websocket_dummy_write_handler;
    c->read->handler = ngx_tcp_websocket_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }

    if (c->read->ready) {
        ngx_tcp_websocket_init_protocol(c->read);
    }

    return;
}


static void
ngx_tcp_websocket_dummy_write_handler(ngx_event_t *wev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = wev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0, "tcp websocket dummy write handler: %d", c->fd);

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static void
ngx_tcp_websocket_dummy_read_handler(ngx_event_t *rev) 
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0, "tcp websocket dummy read handler: %d", c->fd);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static void
ngx_tcp_websocket_init_protocol(ngx_event_t *ev) 
{
    ngx_connection_t             *c;
    ngx_tcp_session_t            *s;
    ngx_tcp_websocket_ctx_t      *pctx;

    c = ev->data;
    s = c->data;

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_websocket_module);

    pctx->parser = ngx_pcalloc(s->connection->pool, sizeof(http_request_parser));
    if (pctx->parser == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    websocket_http_request_parser_init(pctx->parser, s);

    c->read->handler = ngx_tcp_websocket_parse_protocol;

    ngx_tcp_websocket_parse_protocol(ev);
}


static void 
websocket_http_request_parser_init(http_request_parser *hp, void *data) 
{
    hp->data           = data;
    hp->request_method = request_method;
    hp->request_uri    = request_uri;
    hp->fragment       = fragment;
    hp->request_path   = request_path;
    hp->query_string   = query_string;
    hp->http_version   = http_version;
    hp->http_field     = http_field;
    hp->header_done    = header_done;
    
    http_request_parser_init(hp);
}


static void 
request_method(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "METHOD: \"%V\"", &str);
#endif
}


static void 
request_uri(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "URI: \"%V\"", &str);
#endif
}


static void 
fragment(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "FRAMENT: \"%V\"", &str);
#endif
}


static void 
request_path(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "PATH: \"%V\"", &str);
#endif
}


static void 
query_string(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "QUERY: \"%V\"", &str);
#endif
}


static void 
http_version(void *data, const signed char *at, size_t length)
{
#if (NGX_DEBUG)
    ngx_str_t          str;
    ngx_tcp_session_t *s = data;

    str.data = (u_char *) at;
    str.len = length;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "VERSION: \"%V\"", &str);
#endif
}


static void 
http_field(void *data, const signed char *field, 
        size_t flen, const signed char *value, size_t vlen)
{
#if (NGX_DEBUG)
    ngx_str_t             str_field, str_value;
    ngx_tcp_session_t    *s = data;

    str_field.data = (u_char *) field;
    str_field.len = flen;

    str_value.data = (u_char *) value;
    str_value.len = vlen;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, s->connection->log, 0, 
            "%V: %V", &str_field, &str_value);
#endif
}


static void 
header_done(void *data, const signed char *at, size_t length)
{
    /*void */
}


static void 
ngx_tcp_websocket_parse_protocol(ngx_event_t *ev)
{
    u_char                       *new_buf;
    ssize_t                       size, n;
    ngx_int_t                     rc;
    ngx_connection_t             *c;
    ngx_tcp_session_t            *s;
    ngx_tcp_websocket_ctx_t      *pctx;
    ngx_tcp_websocket_conf_t     *pcf;

    c = ev->data;
    s = c->data;

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_websocket_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_websocket_module);

    while (1) {
        n = s->buffer->end - s->buffer->last;
        /*Not enough buffer? Enlarge twice*/
        if (n == 0) {
            size = s->buffer->end - s->buffer->start;

            if ((size_t)size > pcf->buffer_size << 3) {

                ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                        "too large websocket handshake packet error with client: %V #%d",
                        &c->addr_text, c->fd);

                ngx_tcp_finalize_session(s);
                return;
            }

            new_buf = ngx_palloc(c->pool, size * 2);
            if (new_buf == NULL) {
                goto websocket_recv_fail;
            }

            ngx_memcpy(new_buf, s->buffer->start, size);

            s->buffer->pos = s->buffer->start = new_buf;
            s->buffer->last = new_buf + size;
            s->buffer->end = new_buf + size * 2;

            n = s->buffer->end - s->buffer->last;
        }

        size = c->recv(c, s->buffer->last, n);

#if (NGX_DEBUG)
        ngx_err_t                      err;

        err = (size >= 0) ? 0 : ngx_socket_errno;
        ngx_log_debug3(NGX_LOG_DEBUG_TCP, ev->log, err, 
                "tcp websocket recv size: %d, client: %V #%d", size, &c->addr_text, c->fd);
#endif

        if (size > 0) {
            s->buffer->last += size;
            continue;
        } else if (size == 0 || size == NGX_AGAIN) {
            break;
        }
        else {
            c->error = 1;
            goto websocket_recv_fail;
        }
    }

    rc = websocket_http_request_parser_execute(pctx->parser); 

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0, 
            "tcp websocket parse rc: %d, fd: %d", rc, c->fd);

    switch (rc) {
        case NGX_AGAIN:
            return;
        case NGX_ERROR:
            goto websocket_recv_fail;
        case NGX_OK:
        default:
            ngx_tcp_websocket_init_upstream(c, s);
    }

    return;

websocket_recv_fail:

    ngx_log_error(NGX_LOG_ERR, ev->log, 0,
            "recv websocket handshake packet error with client: %V #%d", 
            &c->addr_text, c->fd);

    ngx_tcp_finalize_session(s);
}


static ngx_int_t 
websocket_http_request_parser_execute(http_request_parser *hp) 
{
    ssize_t                       n, offset, length;
    ngx_int_t                     rc;
    ngx_tcp_session_t            *s;

    s = hp->data;

    if ((s->buffer->last - s->buffer->pos) > 0) {
        offset = s->buffer->pos - s->buffer->start;
        length = s->buffer->last - s->buffer->start;

        n = http_request_parser_execute(hp, (signed char *)s->buffer->start, length, offset);
        s->buffer->pos += n;

        rc = http_request_parser_finish(hp);

        if (rc == 0) {
            return NGX_AGAIN;
        }
        else if (rc == 1){
            return NGX_OK;
        }
        else {
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                    "http request parse error with client: %V, recv data: %s", 
                    &s->connection->addr_text, s->buffer->start);
            return NGX_ERROR;
        }
    }
    
    return NGX_AGAIN;
}


static  void
ngx_tcp_websocket_init_upstream(ngx_connection_t *c, ngx_tcp_session_t *s) 
{
    ngx_tcp_upstream_t           *u;
    ngx_tcp_websocket_ctx_t      *pctx;
    ngx_tcp_websocket_conf_t     *pcf;

    s->connection->log->action = "ngx_tcp_websocket_init";

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_websocket_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_websocket_module);

    c->write->handler = ngx_tcp_websocket_dummy_write_handler;
    c->read->handler = ngx_tcp_websocket_dummy_read_handler;

    if (ngx_tcp_upstream_create(s) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    u = s->upstream;

    u->conf = &pcf->upstream;

    u->write_event_handler = ngx_tcp_upstream_websocket_proxy_init_handler;
    u->read_event_handler = ngx_tcp_upstream_websocket_proxy_init_handler;

    pctx->upstream = &u->peer;

    pctx->buffer = ngx_create_temp_buf(s->connection->pool, 
            (s->buffer->end - s->buffer->start));
    if (pctx->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    /* 
     * move back to the start position, send the handshake 
     * packet to backend server */
    s->buffer->pos = s->buffer->start;
    s->connection->read->ready = 1;

    ngx_tcp_upstream_init(s);

    return;
}


static void 
ngx_tcp_upstream_websocket_proxy_init_handler(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u) 
{
    ngx_connection_t             *c;
    ngx_tcp_core_srv_conf_t      *cscf;
    ngx_tcp_websocket_ctx_t      *pctx;
    ngx_tcp_websocket_conf_t     *pcf;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    c = s->connection;
    c->log->action = "ngx_tcp_websocket_init_handler";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 
            0, "tcp websocket upstream init websocket");

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_websocket_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_websocket_module);

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

    s->connection->read->handler = ngx_tcp_websocket_proxy_handler;
    s->connection->write->handler = ngx_tcp_websocket_proxy_handler;

    c->read->handler = ngx_tcp_websocket_proxy_handler;
    c->write->handler = ngx_tcp_websocket_proxy_handler;

    ngx_add_timer(c->read, pcf->upstream.read_timeout);
    ngx_add_timer(c->write, pcf->upstream.send_timeout);

#if (NGX_TCP_SSL)

    /* The ssl connection with client may not trigger the read event again, 
     * So I trigger it in this function.  */
    if (s->connection->ssl) {
        ngx_tcp_websocket_proxy_handler(s->connection->read); 
        return;
    }

#endif

    if (ngx_handle_read_event(s->connection->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_websocket_proxy_handler(s->connection->read);

    return;
}


static void
ngx_tcp_websocket_proxy_handler(ngx_event_t *ev) 
{
    char                      *action, *recv_action, *send_action;
    off_t                     *read_bytes, *write_bytes;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_err_t                  err;
    ngx_uint_t                 do_write;
    ngx_connection_t          *c, *src, *dst;
    ngx_tcp_session_t         *s;
    ngx_tcp_websocket_ctx_t   *pctx;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_websocket_conf_t  *pcf;

    c = ev->data;
    s = c->data;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    if (ev->timedout) {
        c->log->action = "websocket proxying";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "websocket timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_websocket_module);

    if (pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    read_bytes = write_bytes = NULL;
    if (c == s->connection) {
        if (ev->write) {
            recv_action = "client write: websocket proxying and reading from upstream";
            send_action = "client write: websocket proxying and sending to client";
            src = pctx->upstream->connection;
            dst = c;
            b = pctx->buffer;
            write_bytes = &s->bytes_write;
        } else {
            recv_action = "client read: websocket proxying and reading from client";
            send_action = "client read: websocket proxying and sending to upstream";
            src = c;
            dst = pctx->upstream->connection;
            b = s->buffer;
            read_bytes = &s->bytes_read;
        }

    } else {
        if (ev->write) {
            recv_action = "upstream write: websocket proxying and reading from client";
            send_action = "upstream write: websocket proxying and sending to upstream";
            src = s->connection;
            dst = c;
            b = s->buffer;
            read_bytes = &s->bytes_read;
        } else {
            recv_action = "upstream read: websocket proxying and reading from upstream";
            send_action = "upstream read: websocket proxying and sending to client";
            src = c;
            dst = s->connection;
            b = pctx->buffer;
            write_bytes = &s->bytes_write;
        }
    }

    do_write = ev->write ? 1 : 0;

    if (b->pos != b->last) {
        do_write = 1;
        *read_bytes += b->last - b->pos;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_TCP, ev->log, 0,
            "tcp websocket proxy handler: %d, #%d > #%d, time:%ui",
            do_write, src->fd, dst->fd, ngx_current_msec);

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);
                err = ngx_socket_errno;

                ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0, 
                        "tcp websocket proxy handler send:%d", n);

                if (n == NGX_ERROR) {
                    ngx_log_error(NGX_LOG_ERR, c->log, err, "websocket send error");

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

        if (size && src->read->ready) {
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);
            err = ngx_socket_errno;

            ngx_log_debug1(NGX_LOG_DEBUG_TCP, ev->log, 0,
                    "tcp websocket proxy handler recv:%d", n);

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

        break;
    }

    c->log->action = "nginx tcp websocketing";

    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
            || (pctx->upstream->connection->read->eof
                && pctx->buffer->pos == pctx->buffer->last)
            || (s->connection->read->eof
                && pctx->upstream->connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
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

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_websocket_module);

    if (c == s->connection) {
        ngx_add_timer(c->read, cscf->timeout);
    }

    if (c == pctx->upstream->connection) {
        if (ev->write) {
            ngx_add_timer(c->read, pcf->upstream.read_timeout);
        } else {
            ngx_add_timer(c->write, pcf->upstream.send_timeout);
        }
    }

    return;
}


static char *
ngx_tcp_websocket_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_websocket_conf_t   *pcf = conf;

    u_short                     port = 80;
    ngx_str_t                  *value, *url = &pcf->url;
    ngx_url_t                   u;

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
ngx_tcp_websocket_create_conf(ngx_conf_t *cf) 
{
    ngx_tcp_websocket_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_websocket_conf_t));
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
ngx_tcp_websocket_merge_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_tcp_websocket_conf_t *prev = parent;
    ngx_tcp_websocket_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size, (size_t) ngx_pagesize);

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    return NGX_CONF_OK;
}
