
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static void ngx_tcp_init_session(ngx_connection_t *c);

void
ngx_tcp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t             i;
    ngx_tcp_port_t       *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_tcp_log_ctx_t    *ctx;
    ngx_tcp_in_addr_t    *addr;
    ngx_tcp_session_t    *s;
    ngx_tcp_addr_conf_t  *addr_conf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
    ngx_tcp_in6_addr_t   *addr6;
#endif


    /* find the server configuration for the address:port */

    /* AF_INET only */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;

            addr6 = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (ngx_memcmp(&addr6[i].addr6, &sin6->sin6_addr, 16) == 0) {
                    break;
                }
            }

            addr_conf = &addr6[i].conf;

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            addr6 = port->addrs;
            addr_conf = &addr6[0].conf;
            break;
#endif

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_tcp_session_t));
    if (s == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_tcp_log_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_tcp_log_error;
    c->log->data = ctx;
    c->log->action = "nginx tcp module init connection";

    c->log_error = NGX_ERROR_INFO;

    ngx_tcp_init_session(c);
}


static void
ngx_tcp_init_session(ngx_connection_t *c)
{
    ngx_tcp_session_t        *s;
    ngx_tcp_core_srv_conf_t  *cscf;

    s = c->data;

    s->signature = NGX_TCP_MODULE;
    s->pool = c->pool;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    if (cscf == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    /*s->protocol = cscf->protocol->type;*/

    s->ctx = ngx_pcalloc(s->pool, sizeof(void *) * ngx_tcp_max_module);
    if (s->ctx == NULL) {
        ngx_tcp_finalize_session(s);
        return;
    }

    if (s->buffer == NULL) {

        s->buffer = ngx_create_temp_buf(s->pool, 4096);
        if (s->buffer == NULL) {
            ngx_tcp_finalize_session(s);
            return;
        }
    }

    c->write->handler = ngx_tcp_send;

    ngx_tcp_proxy_init_session(c, s);

	/*cscf->protocol->init_session(s, c);*/
}

void
ngx_tcp_send(ngx_event_t *wev)
{
    ngx_int_t                  n;
    ngx_connection_t          *c;
    ngx_tcp_session_t        *s;
    ngx_tcp_core_srv_conf_t  *cscf;

    c = wev->data;
    s = c->data;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_tcp_close_connection(c);
        return;
    }

    if (s->out.len == 0) {
        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
        }

        return;
    }

    n = c->send(c, s->out.data, s->out.len);
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, wev->log, 0, "nginx tcp send:%d", n);

    if (n > 0) {
        s->out.len -= n;

        if (wev->timer_set) {
            ngx_del_timer(wev);
        }

        if (s->quit) {
            ngx_tcp_close_connection(c);
            return;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_close_connection(c);
        return;
    }

    /* n == NGX_AGAIN */

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_add_timer(c->write, cscf->timeout);

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }
}

void
ngx_tcp_session_internal_server_error(ngx_tcp_session_t *s)
{
    ngx_tcp_core_srv_conf_t  *cscf;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    s->out = cscf->protocol->internal_server_error;
    s->quit = 1;

    ngx_tcp_send(s->connection->write);
}

void 
ngx_tcp_finalize_session(ngx_tcp_session_t *s)
{
    ngx_connection_t *c;
    ngx_tcp_cleanup_t *cln;

    c = s->connection;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "close tcp session: %d", c->fd);

    for (cln = s->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
            cln->handler = NULL;
        }
    }

    ngx_tcp_close_connection(c);

    return;
}

void
ngx_tcp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "close tcp connection: %d", c->fd);

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


u_char *
ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char              *p;
    ngx_tcp_session_t  *s;
    ngx_tcp_log_ctx_t  *ctx;
    ngx_tcp_proxy_ctx_t *pctx;


    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V",
                     s->addr_text);
    len -= p - buf;
    buf = p;

    pctx = ngx_tcp_get_module_ctx(s, ngx_tcp_proxy_module);

    if (pctx == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", upstream: %V", pctx->upstream->name);

    return p;
}


ngx_tcp_cleanup_t *
ngx_tcp_cleanup_add(ngx_tcp_session_t *s, size_t size)
{
    ngx_tcp_cleanup_t  *cln;

    cln = ngx_palloc(s->pool, sizeof(ngx_tcp_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = ngx_palloc(s->pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = s->cleanup;

    s->cleanup = cln;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp cleanup add: %p", cln);

    return cln;
}
