/*
 * Copyright (C) 2013 Shang Yuanchun <idealities@gmail.com>
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>

/*
 * header: |---- 4 ----|-- 2 --|-- 2 --|
 *           length       type  padding
 *
 * all are little endian
 *
 */
typedef struct ngx_tcp_monitor_header_s {
    uint32_t length;
    uint16_t type;
    uint16_t spare0;
} ngx_tcp_monitor_header_t;

#define HEADER_LENGTH sizeof(ngx_tcp_monitor_header_t)

#define monitor_packet_size(ptr) (*(u_char *)(ptr)  + \
                     (*((u_char *)(ptr) + 1) << 8)  + \
                     (*((u_char *)(ptr) + 2) << 16) + \
                     (*((u_char *)(ptr) + 3) << 24) )

#define MONITOR_TYPE_OFFSET offsetof(ngx_tcp_monitor_header_t, type)
#define monitor_packet_type(ptr) (*((u_char *)(ptr) + MONITOR_TYPE_OFFSET) + \
                      (*((u_char *)(ptr) + MONITOR_TYPE_OFFSET + 1) << 8) )

#define set_monitor_packet_size(ptr, size) do { \
        *(u_char *)(ptr) = (size) & 0xff; \
        *((u_char *)(ptr) + 1) = ((size) >> 8)  & 0xff; \
        *((u_char *)(ptr) + 2) = ((size) >> 16) & 0xff; \
        *((u_char *)(ptr) + 3) = ((size) >> 24) & 0xff; \
        } while(0)

#define set_monitor_return_code(ptr, code) do { \
        *((u_char *)(ptr) + MONITOR_TYPE_OFFSET) = (code) & 0xff; \
        *((u_char *)(ptr) + MONITOR_TYPE_OFFSET + 1) = ((code) >> 8)  & 0xff; \
        } while(0)

#define PACKET_TYPE_JSON     1
#define PACKET_TYPE_TLV      2
#define PACKET_TYPE_BSON     3
#define PACKET_TYPE_MSGPACK  4

typedef struct ngx_tcp_monitor_ctx_s {
    ngx_peer_connection_t    *upstream;

    // ngx_tcp_session_t's buffer is header_in
    // request_body is the request body
    ngx_buf_t                *request_body;
    ngx_uint_t                request_len;

    ngx_buf_t                *header_out;

    ngx_buf_t                *upstream_request_header;
    ngx_buf_t                *upstream_request_tail;

    ngx_buf_t                *upstream_response;
} ngx_tcp_monitor_ctx_t;


typedef struct ngx_tcp_monitor_conf_s {
    ngx_tcp_upstream_conf_t   upstream;
    ngx_str_t                 url;
    ngx_str_t                 queue_name;
} ngx_tcp_monitor_conf_t;

static inline size_t ngx_get_num_size(ngx_uint_t i)
{
    size_t n = 0;

    do {
        i /= 10;
        n++;
    } while (i > 0);

    return n;
}

static void ngx_tcp_monitor_init_session(ngx_tcp_session_t *s); 
static void ngx_tcp_monitor_init_upstream(ngx_connection_t *c,
    ngx_tcp_session_t *s);
static void ngx_tcp_upstream_init_monitor_handler(ngx_tcp_session_t *s, 
    ngx_tcp_upstream_t *u);
static char *ngx_tcp_monitor_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_tcp_monitor_client_read_handler(ngx_event_t *rev);
static void ngx_tcp_monitor_client_write_handler(ngx_event_t *wev);
static void ngx_tcp_monitor_upstream_read_handler(ngx_event_t *rev);
static void ngx_tcp_monitor_upstream_write_handler(ngx_event_t *wev);
static void *ngx_tcp_monitor_create_conf(ngx_conf_t *cf);
static char *ngx_tcp_monitor_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_tcp_monitor_build_query(ngx_tcp_session_t *s,
    ngx_buf_t **header, ngx_buf_t **tail);
static ngx_int_t ngx_tcp_monitor_build_response(ngx_tcp_session_t *s);

static ngx_tcp_protocol_t  ngx_tcp_monitor_protocol = {

    ngx_string("monitor_server"),
    { 0, 0, 0, 0 },
    NGX_TCP_GENERIC_PROTOCOL,
    ngx_tcp_monitor_init_session,
    NULL,
    NULL,
    ngx_string("500 Internal server error" CRLF)

};


static ngx_command_t  ngx_tcp_monitor_commands[] = {

    { ngx_string("monitor_pass"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_monitor_pass,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("queue_name"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_monitor_conf_t, queue_name),
      NULL },

    { ngx_string("monitor_connect_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_monitor_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("monitor_read_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_monitor_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("monitor_send_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_monitor_conf_t, upstream.send_timeout),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_monitor_module_ctx = {
    &ngx_tcp_monitor_protocol,             /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_monitor_create_conf,           /* create server configuration */
    ngx_tcp_monitor_merge_conf             /* merge server configuration */
};


ngx_module_t  ngx_tcp_monitor_module = {
    NGX_MODULE_V1,
    &ngx_tcp_monitor_module_ctx,           /* module context */
    ngx_tcp_monitor_commands,              /* module directives */
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
ngx_tcp_monitor_init_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t         *c;
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_monitor_ctx_t    *ctx;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp monitor init session");

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    s->buffer = ngx_create_temp_buf(s->connection->pool, HEADER_LENGTH);
    if (s->buffer == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    s->out.len = 0;

    c->write->handler = ngx_tcp_monitor_client_write_handler;
    c->read->handler  = ngx_tcp_monitor_client_read_handler;

    ngx_add_timer(c->read, cscf->timeout);

    ctx = ngx_pcalloc(s->connection->pool, sizeof(ngx_tcp_monitor_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_set_ctx(s, ctx, ngx_tcp_monitor_module);

    // We will call this after we receive data completely
    // ngx_tcp_monitor_init_upstream(c, s);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    return;
}


/*
 * FIXME: 1. I am not sure below will block!
 *        2. Server did not close connection currently!
 *
 */
static void
ngx_tcp_monitor_client_read_handler(ngx_event_t *rev) 
{
    ssize_t                 n, size;
    ngx_int_t               rc;
    ngx_err_t               err;
    ngx_buf_t              *b;
    ngx_connection_t       *c;
    ngx_tcp_session_t      *s;
    ngx_tcp_monitor_ctx_t  *pctx;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "tcp monitor client read handler: %d", c->fd);

    if (rev->timedout) {
        c->log->action = "monitoring";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "monitor timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    if (pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    for ( ;; ) {
        if (c->read->ready) {

            c->log->action = "client read: reading from client";
            if (s->bytes_read < (off_t)HEADER_LENGTH) {
                size = HEADER_LENGTH - s->bytes_read;
                b    = s->buffer;
            } else {
                if (pctx->request_body == NULL) {
                    pctx->request_len  = monitor_packet_size(s->buffer->start);
                    pctx->request_body = ngx_create_temp_buf(c->pool,
                                             pctx->request_len);
                }
                size = pctx->request_len - s->bytes_read + HEADER_LENGTH;
                b    = pctx->request_body;
            }
            if (size < 0) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "client data not correct, handler: %d", c->fd);
                ngx_tcp_finalize_session(s);
                return;
            }
            n   = c->recv(c, b->last, size);
            err = ngx_socket_errno;

            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, err, "client read error");
                ngx_tcp_finalize_session(s);
                return;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                           "tcp monitor handler recv:%d", n);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                b->last       += n;
                s->bytes_read += n;
                continue;
            }

            if (n == NGX_ERROR) {
                c->read->eof = 1;
            }
        }

        break;
    }

    if (s->bytes_read == (off_t)(pctx->request_len + HEADER_LENGTH))
    {
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "read client data done");
        rc = ngx_tcp_monitor_build_query(s, &pctx->upstream_request_header,
                &pctx->upstream_request_tail);
        if (rc != NGX_OK) {
            ngx_tcp_finalize_session(s);
            return;
        }
        ngx_tcp_monitor_init_upstream(c, s);
        return;
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }
}


static void
ngx_tcp_monitor_client_write_handler(ngx_event_t *wev) 
{
    ssize_t              n, size;
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;
    ngx_tcp_monitor_ctx_t  *pctx;
    ngx_err_t               err;

    c = wev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp monitor client write handler");

    if (wev->timedout) {
        c->log->action = "monitoring";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "monitor client send timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "tcp monitor client write handler: %d", c->fd);

    for ( ;; ) {
        if (c->write->ready) {
            c->log->action = "client send: sending to client";
            size = pctx->header_out->end - pctx->header_out->pos;
            if (size <= 0) {
                break;
            }
            n = c->send(c, pctx->header_out->pos, size);
            err = ngx_socket_errno;

            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, err, "monitor client send error");
                return;
            }
            if (n > 0) {
                pctx->header_out->pos +=n;
                continue;
            }
        }
        break;
    }

    if (pctx->header_out->pos == pctx->header_out->end) {
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "client send data done");
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
    }
}


static void ngx_tcp_monitor_upstream_read_handler(ngx_event_t *rev)
{
    ssize_t                 n, size;
    ngx_int_t               rc;
    ngx_err_t               err;
    ngx_connection_t       *c;
    ngx_tcp_session_t      *s;
    ngx_tcp_monitor_ctx_t  *pctx;

    c = rev->data;
    s = c->data;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "tcp monitor upstream read handler: %d", c->fd);

    if (rev->timedout) {
        c->log->action = "monitoring";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "monitor timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    if (pctx->upstream_response == NULL) {
        pctx->upstream_response = ngx_create_temp_buf(c->pool, ngx_pagesize);
        if (pctx->upstream_response == NULL) {
            ngx_tcp_finalize_session(s);
            return;
        }
        s->bytes_read = 0;
    }

    for ( ;; ) {
        if (c->read->ready) {
            c->log->action = "upstream read: reading from upstream";
            size = (pctx->upstream_response->end
                    - pctx->upstream_response->start) - s->bytes_read;
            n    = c->recv(c, pctx->upstream_response->last, size);
            err  = ngx_socket_errno;

            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, err, "upstream read error");
                ngx_tcp_finalize_session(s);
                return;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_TCP, rev->log, 0,
                           "tcp monitor handler recv:%d", n);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                pctx->upstream_response->last += n;
                s->bytes_read += n;
                continue;
            }

            if (n == NGX_ERROR) {
                c->read->eof = 1;
            }
        }
        break;
    }

    if (c->read->eof ||
        (*(pctx->upstream_response->last - 1) == LF)) {
        rc = ngx_tcp_monitor_build_response(s);
        if (rc != NGX_OK) {
            ngx_tcp_finalize_session(s);
            return;
        }
        s->connection->write->handler(s->connection->write);
        return;
    }

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }
}


static void ngx_tcp_monitor_upstream_write_handler(ngx_event_t *wev)
{
    ssize_t              n, size;
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;
    ngx_uint_t           header_length;
    ngx_uint_t           tail_length;
    ngx_tcp_monitor_ctx_t  *pctx;
    ngx_buf_t              *b;
    ngx_err_t               err;
    ngx_tcp_monitor_conf_t *pcf;

    c = wev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp monitor upstream write handler");

    if (wev->timedout) {
        c->log->action = "monitoring";

        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "monitor upstream send timed out");
        c->timedout = 1;

        ngx_tcp_finalize_session(s);
        return;
    }

    pcf  = ngx_tcp_get_module_srv_conf(s, ngx_tcp_monitor_module);
    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    if (pctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0,
                   "tcp monitor upstream write handler: %d", c->fd);

    header_length = pctx->upstream_request_header->end -
                    pctx->upstream_request_header->start;
    tail_length   = pctx->upstream_request_tail->end -
                    pctx->upstream_request_tail->start;
    if (s->bytes_write == (off_t)(header_length + pctx->request_len + tail_length)) {
        return;
    }

    for ( ;; ) {
        if (c->write->ready) {
            c->log->action = "upstream send: sending to upstream server";
            size = header_length - s->bytes_write;
            b    = pctx->upstream_request_header;
            if (size <= 0) {
                size += pctx->request_len;
                b     = pctx->request_body;
            }
            if (size <= 0) {
                size += tail_length;
                b     = pctx->upstream_request_tail;
            }
            if (size <= 0) {
                break;
            }
            n = c->send(c, b->pos, size);
            err = ngx_socket_errno;

            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_ERR, c->log, err, "monitor upstream send error");
                return;
            }
            if (n > 0) {
                b->pos +=n;
                s->bytes_write += n;
                continue;
            }
        }
        break;
    }

    if (s->bytes_write == (off_t)(header_length + pctx->request_len + tail_length)) {
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "upstream send data done");
        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }
        ngx_add_timer(c->read, pcf->upstream.read_timeout);
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_tcp_finalize_session(s);
            return;
        }
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }
}


static ngx_int_t
ngx_tcp_monitor_build_query(ngx_tcp_session_t *s, ngx_buf_t **header, ngx_buf_t **tail)
{
    size_t  len;
    u_short packet_type;
    ngx_tcp_monitor_conf_t  *pcf;
    ngx_tcp_monitor_ctx_t   *pctx;

    pcf  = ngx_tcp_get_module_srv_conf(s, ngx_tcp_monitor_module);
    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    packet_type = monitor_packet_type(s->buffer->start);
    // FIXME: below is specific to redis protocol
    // http://redis.io/topics/protocol
    switch(packet_type) {
        case PACKET_TYPE_JSON:
            len = sizeof("*3" CRLF "$5" CRLF "LPUSH" CRLF "$") -1
                  + ngx_get_num_size(pcf->queue_name.len)
                  + sizeof(CRLF) -1 + pcf->queue_name.len
                  + sizeof(CRLF "$") -1
                  + ngx_get_num_size(pctx->request_len)
                  + sizeof(CRLF) - 1;
            *header = ngx_create_temp_buf(s->connection->pool, len);
            if (*header == NULL) {
                return NGX_ERROR;
            }
            ngx_sprintf((*header)->last, "*3"CRLF"$5"CRLF"LPUSH"CRLF
                        "$%d"CRLF"%*s"CRLF"$%d"CRLF,
                        pcf->queue_name.len,
                        pcf->queue_name.len,
                        pcf->queue_name.data,
                        pctx->request_len);
            len   = sizeof(CRLF) -1;
            *tail = ngx_create_temp_buf(s->connection->pool, len);
            if (*tail == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy((*tail)->last, CRLF, sizeof(CRLF) - 1);
            return NGX_OK;

        default:
            ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                          "invalid monitor packet type: %hu", packet_type);
            return NGX_ERROR;
    }
}


static ngx_int_t ngx_tcp_monitor_build_response(ngx_tcp_session_t *s)
{
    u_char chr;
    ngx_tcp_monitor_ctx_t   *pctx;

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    set_monitor_packet_size(pctx->header_out->start, 0);
    if (*(pctx->upstream_response->last - 1) != LF ||
        *(pctx->upstream_response->last - 2) != CR) {
        return NGX_ERROR;
    }
    chr = *pctx->upstream_response->pos;
    switch (chr) {
        case '+':
        case ':':
            set_monitor_return_code(pctx->header_out->start, 0);
            break;
        case '-':
        default:
            set_monitor_return_code(pctx->header_out->start, 1);
            break;
    }
    return NGX_OK;
}


static  void
ngx_tcp_monitor_init_upstream(ngx_connection_t *c, ngx_tcp_session_t *s)
{
    ngx_tcp_upstream_t       *u;
    ngx_tcp_monitor_ctx_t    *p;
    ngx_tcp_monitor_conf_t   *pcf;

    s->connection->log->action = "ngx_tcp_monitor_init_upstream";

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_monitor_module);
    if (pcf->upstream.upstream == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (ngx_tcp_upstream_create(s) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    u = s->upstream;

    u->conf = &pcf->upstream;

    u->write_event_handler = ngx_tcp_upstream_init_monitor_handler;
    u->read_event_handler  = ngx_tcp_upstream_init_monitor_handler;

    p = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);
    p->upstream = &u->peer;

    p->header_out = ngx_create_temp_buf(s->connection->pool, HEADER_LENGTH);
    if (p->header_out == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_upstream_init(s);

    return;
}


static void 
ngx_tcp_upstream_init_monitor_handler(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u)
{
    ngx_connection_t         *c;
    ngx_tcp_monitor_ctx_t      *pctx;
    ngx_tcp_monitor_conf_t     *pcf;

    c = s->connection;
    c->log->action = "ngx_tcp_upstream_init_monitor_handler";

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp monitor upstream init monitor");

    pcf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_monitor_module);

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_monitor_module);

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

    c->read->handler  = ngx_tcp_monitor_upstream_read_handler;
    c->write->handler = ngx_tcp_monitor_upstream_write_handler;

    ngx_add_timer(c->write, pcf->upstream.send_timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    c->write->handler(c->write);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp monitor upstream init monitor done");

    return;
}


static char *
ngx_tcp_monitor_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_monitor_conf_t *pcf = conf;

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
        cscf->protocol = &ngx_tcp_monitor_protocol;
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
ngx_tcp_monitor_create_conf(ngx_conf_t *cf) 
{
    ngx_tcp_monitor_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_monitor_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    pcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    return pcf;
}


static char *
ngx_tcp_monitor_merge_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_tcp_monitor_conf_t *prev = parent;
    ngx_tcp_monitor_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    return NGX_CONF_OK;
}
