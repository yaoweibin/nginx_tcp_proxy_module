
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_http.h>

/* ngx_spinlock is defined without a matching unlock primitive */
#define ngx_spinlock_unlock(lock)       (void) ngx_atomic_cmp_set(lock, ngx_pid, 0)

static void ngx_tcp_upstream_cleanup(void *data);

static void ngx_tcp_upstream_connect(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u);
static void ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u,
        ngx_int_t rc);

static char *ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_tcp_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

static ngx_int_t ngx_tcp_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool);
static ngx_int_t ngx_tcp_upstream_check_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_tcp_check_init_process(ngx_cycle_t *cycle);

static char * ngx_tcp_upstream_check_status_set_status(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_tcp_upstream_commands[] = {

    { ngx_string("upstream"),
        NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
        ngx_tcp_upstream,
        0,
        0,
        NULL },

    { ngx_string("server"),
        NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
        ngx_tcp_upstream_server,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("check"),
        NGX_TCP_UPS_CONF|NGX_CONF_1MORE,
        ngx_tcp_upstream_check,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("check_shm_size"),
        NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_size_slot,
        NGX_TCP_MAIN_CONF_OFFSET,
        offsetof(ngx_tcp_upstream_main_conf_t, check_shm_size),
        NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_module_ctx = {
    NULL,

    ngx_tcp_upstream_create_main_conf,    /* create main configuration */
    ngx_tcp_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
};

ngx_module_t  ngx_tcp_upstream_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_module_ctx,         /* module context */
    ngx_tcp_upstream_commands,            /* module directives */
    NGX_TCP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_tcp_check_init_process,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_command_t  ngx_tcp_upstream_check_status_commands[] = {

    { ngx_string("check_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_tcp_upstream_check_status_set_status,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_tcp_upstream_check_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t  ngx_tcp_upstream_check_status_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_check_status_module_ctx, /* module context */
    ngx_tcp_upstream_check_status_commands,    /* module directives */
    NGX_HTTP_MODULE,                           /* module type */
    NULL,                                      /* init master */
    NULL,                                      /* init module */
    NULL,                                      /* init process */
    NULL,                                      /* init thread */
    NULL,                                      /* exit thread */
    NULL,                                      /* exit process */
    NULL,                                      /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_uint_t ngx_tcp_check_shm_generation = 0;
static ngx_tcp_check_peers_conf_t *check_peers_ctx = NULL;

ngx_int_t
ngx_tcp_upstream_create(ngx_tcp_session_t *s) {
    ngx_tcp_upstream_t  *u;

    u = s->upstream;

    if (u && u->cleanup) {
        ngx_tcp_upstream_cleanup(s);
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    u = ngx_pcalloc(s->pool, sizeof(ngx_tcp_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }

    s->upstream = u;

    u->peer.log = s->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;

    return NGX_OK;
}


/*do something with the session*/
void
ngx_tcp_upstream_init(ngx_tcp_session_t *s) {

    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_connection_t               *c;
    ngx_tcp_cleanup_t             *cln;
    ngx_tcp_upstream_t            *u;
    ngx_tcp_core_srv_conf_t       *cscf;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_tcp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t  *umcf;

    c = s->connection;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
            "tcp init upstream, client timer: %d", c->read->timer_set);

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u = s->upstream;

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT)
                    == NGX_ERROR)
            {
                ngx_tcp_finalize_session(s);
                return;
            }
        }
    }

    cln = ngx_tcp_cleanup_add(s, 0);

    cln->handler = ngx_tcp_upstream_cleanup;
    cln->data = s;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

        /*TODO: support variable in the proxy_pass*/
        if (u->resolved->sockaddr) {

            if (ngx_tcp_upstream_create_round_robin_peer(s, u->resolved)
                    != NGX_OK)
            {
                ngx_tcp_finalize_session(s);
                return;
            }

            ngx_tcp_upstream_connect(s, u);

            return;
        }

        host = &u->resolved->host;

        umcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                    && ((uscf->port == 0 && u->resolved->no_port)
                        || uscf->port == u->resolved->port)
                    && ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        temp.name = *host;

        ctx = ngx_resolve_start(cscf->resolver, &temp);
        if (ctx == NULL) {
            ngx_tcp_finalize_session(s);
            return;
        }

        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "no resolver defined to resolve %V", host);
            ngx_tcp_finalize_session(s);
            return;
        }

        ctx->name = *host;
        ctx->type = NGX_RESOLVE_A;
        ctx->handler = ngx_tcp_upstream_resolve_handler;
        ctx->data = s;
        ctx->timeout = cscf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_tcp_finalize_session(s);
            return;
        }

        return;
    }

found:

    if (uscf->peer.init(s, uscf) != NGX_OK) {
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_tcp_upstream_connect(s, u);
}

static void
ngx_tcp_upstream_resolve_handler(ngx_resolver_ctx_t *ctx) {

    ngx_tcp_session_t            *s;
    ngx_tcp_upstream_resolved_t  *ur;

    s = ctx->data;

    s->upstream->resolved->ctx = NULL;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "%V could not be resolved (%i: %s)",
                &ctx->name, ctx->state,
                ngx_resolver_strerror(ctx->state));

        ngx_resolve_name_done(ctx);
        ngx_tcp_finalize_session(s);
        return;
    }

    ur = s->upstream->resolved;
    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
        in_addr_t   addr;
        ngx_uint_t  i;

        for (i = 0; i < ctx->naddrs; i++) {
            addr = ntohl(ur->addrs[i]);

            ngx_log_debug4(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                    "name was resolved to %ud.%ud.%ud.%ud",
                    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                    (addr >> 8) & 0xff, addr & 0xff);
        }
    }
#endif

    if (ngx_tcp_upstream_create_round_robin_peer(s, ur) != NGX_OK) {
        ngx_resolve_name_done(ctx);
        ngx_tcp_finalize_session(s);
        return;
    }

    ngx_resolve_name_done(ctx);

    ngx_tcp_upstream_connect(s, s->upstream);

    /*need add the event.*/
}


static void
ngx_tcp_upstream_handler(ngx_event_t *ev) {

    ngx_connection_t     *c;
    ngx_tcp_session_t   *s;
    ngx_tcp_upstream_t  *u;

    c = ev->data;
    s = c->data;

    u = s->upstream;
    c = s->connection;

    if (ev->write) {
        if (u->write_event_handler) {
            u->write_event_handler(s, u);
        }

    } else {

        if (u->read_event_handler) {
            u->read_event_handler(s, u);
        }
    }
}

ngx_int_t 
ngx_tcp_upstream_check_broken_connection(ngx_tcp_session_t *s) {

    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_connection_t     *c;
    ngx_tcp_upstream_t  *u;

    u = s->upstream;
    c = u->peer.connection;

    if (u->peer.connection == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp upstream check upstream, fd:%d", c->fd);

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, err, "tcp check upstream recv(): %d", n);

    if (n >= 0 || err == NGX_EAGAIN) {
        return NGX_OK;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }
    }

    c->error = 1;

    return NGX_ERROR;
}


static void
ngx_tcp_upstream_connect(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u) {

    ngx_int_t                 rc;
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_connection_t         *c;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    rc = ngx_event_connect_peer(&u->peer);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0, "tcp upstream connect: %d", rc);

    if (rc != NGX_OK && rc != NGX_AGAIN) {
        ngx_tcp_upstream_finalize_session(s, u, 0);
        return;
    }

    /*u->state->peer = u->peer.name;*/

    /* rc == NGX_OK || rc == NGX_AGAIN */

    c = u->peer.connection;

    c->data = s;
    c->pool = s->connection->pool;
    c->log = s->connection->log;
    c->read->log = c->log;
    c->write->log = c->log;

    c->write->handler = ngx_tcp_upstream_handler;
    c->read->handler = ngx_tcp_upstream_handler;

    if (rc == NGX_AGAIN) {
        /*connect busy*/
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }
    else {
        ngx_add_timer(c->read, u->conf->read_timeout);
        ngx_add_timer(c->write, u->conf->send_timeout);
    }
}

void
ngx_tcp_upstream_next(ngx_tcp_session_t *s, ngx_tcp_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_uint_t  state;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp next upstream, fail_type: %xi", ft_type);

    state = NGX_PEER_FAILED;

    if (ft_type != NGX_TCP_UPSTREAM_FT_NOLIVE) {
        u->peer.free(&u->peer, u->peer.data, state);
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ETIMEDOUT,
                      "upstream no alive");
    }

    if (ft_type == NGX_TCP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (s->connection->error) {
        ngx_tcp_upstream_finalize_session(s, u, 0);
        return;
    }

    if (u->peer.cached && ft_type == NGX_TCP_UPSTREAM_FT_ERROR) {
        /*TODO: cached*/
    }
    else {
        if (u->peer.tries == 0) {
            ngx_tcp_upstream_finalize_session(s, u, 0);
            return;
        }
    }

    if (u->peer.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "close tcp upstream connection: %d",
                       u->peer.connection->fd);
#if (NGX_TCP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        ngx_close_connection(u->peer.connection);
    }

    ngx_tcp_upstream_connect(s, u);
}

    static void
ngx_tcp_upstream_cleanup(void *data)
{
    ngx_tcp_session_t *s = data;

    ngx_tcp_upstream_t  *u;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "cleanup tcp upstream session: fd: %d", s->connection->fd);

    u = s->upstream;

    if (u->resolved && u->resolved->ctx) {
        ngx_resolve_name_done(u->resolved->ctx);
    }

    ngx_tcp_upstream_finalize_session(s, u, NGX_DONE);
}


    static void
ngx_tcp_upstream_finalize_session(ngx_tcp_session_t *s,
        ngx_tcp_upstream_t *u, ngx_int_t rc)
{
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "finalize tcp upstream session: %i", rc);

    if (u->cleanup) {
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

    if (u->state && u->state->response_sec) {
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;

        if (u->pipe) {
            u->state->response_length = u->pipe->read_length;
        }
    }

    /*u->finalize_session(r, rc);*/

    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                "close tcp upstream connection: %d",
                u->peer.connection->fd);

            ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                "tcp upstream temp fd: %d",
                u->pipe->temp_file->file.fd);
    }

    if (rc == NGX_DECLINED || rc == NGX_DONE) {
        return;
    }

    s->connection->log->action = "sending to client";

    ngx_tcp_finalize_session(s);
}

ngx_tcp_upstream_srv_conf_t *
ngx_tcp_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags) {

    ngx_uint_t                      i;
    ngx_tcp_upstream_server_t     *us;
    ngx_tcp_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_tcp_upstream_main_conf_t  *umcf;

    if (!(flags & NGX_TCP_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len || 
                ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len) != 0)
        {
            continue;
        }

        if ((flags & NGX_TCP_UPSTREAM_CREATE)
                && (uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NGX_TCP_UPSTREAM_CREATE) && u->port) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                    "upstream \"%V\" may not have port %d",
                    &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_TCP_UPSTREAM_CREATE) && uscfp[i]->port) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                    "upstream \"%V\" may not have port %d in %s:%ui",
                    &u->host, uscfp[i]->port,
                    uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (uscfp[i]->default_port && u->default_port
                && uscfp[i]->default_port != u->default_port)
        {
            continue;
        }

        return uscfp[i];
    }

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->default_port = u->default_port;

    if (u->naddrs == 1) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = u->naddrs;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


static char *
ngx_tcp_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy) {

    char                          *rv;
    void                          *mconf;
    ngx_str_t                     *value;
    ngx_url_t                      u;
    ngx_uint_t                     m;
    ngx_conf_t                     pcf;
    ngx_tcp_module_t             *module;
    ngx_tcp_conf_ctx_t           *ctx, *tcp_ctx;
    ngx_tcp_upstream_srv_conf_t  *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;

    uscf = ngx_tcp_upstream_add(cf, &u, 
            NGX_TCP_UPSTREAM_CREATE
            |NGX_TCP_UPSTREAM_WEIGHT
            |NGX_TCP_UPSTREAM_MAX_FAILS
            |NGX_TCP_UPSTREAM_FAIL_TIMEOUT
            |NGX_TCP_UPSTREAM_MAX_BUSY
            |NGX_TCP_UPSTREAM_DOWN
            |NGX_TCP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_tcp_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }

    }

    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_UPS_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}


static char *
ngx_tcp_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_tcp_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    ngx_str_t                   *value, s;
    ngx_url_t                    u;
    ngx_int_t                    weight, max_fails, max_busy;
    ngx_uint_t                   i;
    ngx_tcp_upstream_server_t  *us;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 4,
                sizeof(ngx_tcp_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_tcp_upstream_server_t));

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    weight = 1;
    max_fails = 1;
    max_busy = 0;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_WEIGHT)) {
                goto invalid;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_MAX_FAILS)) {
                goto invalid;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_busy=", 9) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_MAX_BUSY)) {
                goto invalid;
            }

            max_busy = ngx_atoi(&value[i].data[9], value[i].len - 9);

            if (max_busy == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_FAIL_TIMEOUT)) {
                goto invalid;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "backup", 6) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_BACKUP)) {
                goto invalid;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "down", 4) == 0) {

            if (!(uscf->flags & NGX_TCP_UPSTREAM_DOWN)) {
                goto invalid;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->max_busy = max_busy;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static char *
ngx_tcp_upstream_check(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

    ngx_tcp_upstream_srv_conf_t  *uscf = conf;
    ngx_str_t *value, s;
    ngx_uint_t i, rise, fall, type;
    ngx_msec_t interval, timeout;

    /*set default*/
    rise = 2;
    fall = 5;
    interval = 30000;
    timeout = 500;
    type = NGX_TCP_CHECK_TCP;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            s.len = value[i].len - 4;
            s.data = value[i].data + 4;

            if (ngx_strncmp(s.data, "tcp", s.len) == 0) {

                type = NGX_TCP_CHECK_TCP;

                continue;
            }
            else {
                goto invalid_check_parameter;
            }
        }

        if (ngx_strncmp(value[i].data, "interval=", 9) == 0) {
            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            interval = ngx_atoi(s.data, s.len);
            if (interval == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "timeout=", 8) == 0) {
            s.len = value[i].len - 8;
            s.data = value[i].data + 8;

            timeout = ngx_atoi(s.data, s.len);
            if (timeout == (ngx_msec_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "rise=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            rise = ngx_atoi(s.data, s.len);
            if (rise == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fall=", 5) == 0) {
            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            fall = ngx_atoi(s.data, s.len);
            if (fall == (ngx_uint_t) NGX_ERROR) {
                goto invalid_check_parameter;
            }

            continue;
        }

        goto invalid_check_parameter;
    }

    uscf->check_type = type;
    uscf->check_interval = interval;
    uscf->check_timeout = timeout;
    uscf->fall_count = fall;
    uscf->rise_count = rise;

    return NGX_CONF_OK;

invalid_check_parameter:
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}

static void *
ngx_tcp_upstream_create_main_conf(ngx_conf_t *cf) {

    ngx_tcp_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                sizeof(ngx_tcp_upstream_srv_conf_t *)) != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&umcf->peers_conf.peers, cf->pool, 16,
                sizeof(ngx_tcp_check_peer_conf_t)) != NGX_OK)
    {
        return NULL;
    }

    return umcf;
}

static char *
ngx_tcp_upstream_init_main_conf(ngx_conf_t *cf, void *conf) {

    ngx_tcp_upstream_main_conf_t   *umcf = conf;

    ngx_uint_t                      i, shm_size, need_check;
    ngx_str_t                      *shm_name;
    ngx_shm_zone_t                 *shm_zone;
    ngx_tcp_upstream_init_pt        init;
    ngx_tcp_upstream_srv_conf_t   **uscfp;

    uscfp = umcf->upstreams.elts;

    need_check = 0;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->check_interval) {
            need_check = 1;
        }
    }

    if (need_check) {
        ngx_tcp_check_shm_generation++;

        shm_name = &umcf->peers_conf.check_shm_name;

        if (ngx_tcp_check_get_shm_name(shm_name, cf->pool) == NGX_ERROR) {
            return NGX_CONF_ERROR;
        }

        /*the default check shmare memory size*/
        shm_size = (umcf->upstreams.nelts + 1 )* ngx_pagesize;

        shm_size = shm_size < umcf->check_shm_size ? umcf->check_shm_size : shm_size;

        shm_zone = ngx_shared_memory_add(cf, shm_name, shm_size, &ngx_tcp_upstream_module);

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, cf->log, 0,
                "[tcp_upstream] upsteam:%V, shm_zone size:%ui", shm_name, shm_size);

        shm_zone->data = &umcf->peers_conf;
        check_peers_ctx = &umcf->peers_conf;

        shm_zone->init = ngx_tcp_upstream_check_init_shm_zone;
    }

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
            ngx_tcp_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

ngx_uint_t 
ngx_tcp_check_peer_down(ngx_uint_t index){

    ngx_tcp_check_peer_conf_t     *peer_conf;

    if (check_peers_ctx == NULL || index >= check_peers_ctx->peers.nelts) {
        return 0;
    }

    peer_conf = check_peers_ctx->peers.elts;

    return peer_conf[index].shm->down;
}

ngx_uint_t
ngx_tcp_check_add_peer(ngx_conf_t *cf, ngx_tcp_upstream_srv_conf_t *uscf,
        ngx_peer_addr_t *peer) {

    ngx_tcp_upstream_main_conf_t  *umcf; 
    ngx_tcp_check_peers_conf_t    *peers_conf;
    ngx_tcp_check_peer_conf_t     *peer_conf;

    umcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_upstream_module);

    peers_conf = &umcf->peers_conf;

    peer_conf = ngx_array_push(&peers_conf->peers);
    peer_conf->index = peers_conf->peers.nelts - 1;
    peer_conf->conf = uscf;
    peer_conf->peer = peer;

    return peer_conf->index;
}

#define SHM_NAME_LEN 256

static ngx_int_t
ngx_tcp_upstream_check_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {

    ngx_uint_t                      i;
    ngx_slab_pool_t                *shpool;
    ngx_tcp_check_peer_shm_t       *peer_shm;
    ngx_tcp_check_peers_conf_t     *peers_conf;
    ngx_tcp_check_peers_shm_t      *peers_shm;

    peers_conf = shm_zone->data;

    if (peers_conf == NULL || peers_conf->peers.nelts == 0) {
        return NGX_OK;
    }

    if (data) {
        peers_shm = data;
    }
    else {
        shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

        peers_shm = ngx_slab_alloc(shpool, sizeof(*peers_shm) +
                (peers_conf->peers.nelts - 1) * sizeof(ngx_tcp_check_peer_shm_t));

        if (peers_shm == NULL) {
            ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                    "tcp upstream check_shm_size is too small, you should set a larger size.");
            return NGX_ERROR;
        }
    }

    peers_shm->generation = ngx_tcp_check_shm_generation;

    for (i = 0; i < peers_conf->peers.nelts; i++) {
        peer_shm = &peers_shm->peers[i];

        peer_shm->owner = NGX_INVALID_PID;
        peer_shm->access_time = 0;
        peer_shm->fall_count = 0;
        peer_shm->rise_count = 0;

        peer_shm->down = 1;
    }

    peers_conf->peers_shm = peers_shm;


    return NGX_OK;
}

static ngx_int_t 
ngx_tcp_check_get_shm_name(ngx_str_t *shm_name, ngx_pool_t *pool) {

    u_char    *last;

    shm_name->data = ngx_palloc(pool, SHM_NAME_LEN);
    if (shm_name->data == NULL) {
        return NGX_ERROR;
    }

    last = ngx_snprintf(shm_name->data, SHM_NAME_LEN, "%s#%ui", "ngx_tcp_upstream", 
            ngx_tcp_check_shm_generation);

    shm_name->len = last - shm_name->data;

    return NGX_OK;
}

static ngx_shm_zone_t *
ngx_shared_memory_find(ngx_cycle_t *cycle, ngx_str_t *name, void *tag)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;

    part = (ngx_list_part_t *) & (cycle->shared_memory.part);
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (name->len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(name->data, shm_zone[i].shm.name.data, name->len)
            != 0)
        {
            continue;
        }

        if (tag != shm_zone[i].tag) {
            continue;
        }

        return &shm_zone[i];
    }

    return NULL;
}

static void 
ngx_tcp_check_clean_event(ngx_tcp_check_peer_conf_t *peer_conf) {
    ngx_connection_t *c;

    c = peer_conf->pc.connection;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, 0, 
            "tcp check clean event: index:%d, fd: %d", 
            peer_conf->index, c->fd);

    ngx_close_connection(c);

    if (peer_conf->check_timeout_ev.timer_set) {
        ngx_del_timer(&peer_conf->check_timeout_ev);
    }

    ngx_spinlock(&peer_conf->shm->lock, ngx_pid, 1024);

    peer_conf->shm->owner = NGX_INVALID_PID;

    ngx_spinlock_unlock(&peer_conf->shm->lock);
}

static ngx_flag_t has_cleared = 0;

static void 
ngx_tcp_check_clear_all_events() {
    ngx_uint_t                     i;
    ngx_tcp_check_peers_conf_t    *peers_conf;
    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_check_peers_shm_t     *peers_shm;
    ngx_tcp_check_peer_shm_t      *peer_shm;

    if (has_cleared || check_peers_ctx == NULL) {
        return;
    }

    has_cleared = 1;

    peers_conf = check_peers_ctx;
    peers_shm = peers_conf->peers_shm;

    peer_conf = peers_conf->peers.elts;
    peer_shm = peers_shm->peers;
    for (i = 0; i < peers_conf->peers.nelts; i++) {
        if (peer_conf[i].check_ev.timer_set) {
            ngx_del_timer(&peer_conf[i].check_ev);
        }
        if (peer_shm[i].owner == ngx_pid) {
            ngx_tcp_check_clean_event(&peer_conf[i]);
        }
    }
}

static ngx_int_t 
ngx_tcp_check_need_exit() {

    if (ngx_terminate || ngx_exiting || ngx_quit) {
        ngx_tcp_check_clear_all_events();
        return 1;
    }

    return 0;
}

static void 
ngx_tcp_check_dummy_handler(ngx_event_t *event) {

    return;
}

static void 
ngx_tcp_check_finish_handler(ngx_event_t *event) {

    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_upstream_srv_conf_t   *uscf;
    
    if (ngx_tcp_check_need_exit()) {
        return;
    }

    peer_conf = event->data;
    uscf = peer_conf->conf;
}

static void 
ngx_tcp_check_status_update(ngx_tcp_check_peer_conf_t *peer_conf, ngx_int_t result) {

    ngx_tcp_upstream_srv_conf_t   *uscf;

    uscf = peer_conf->conf;

    if (result) {
        peer_conf->shm->rise_count++; 
        peer_conf->shm->fall_count = 0; 
        if (peer_conf->shm->down && peer_conf->shm->rise_count >= uscf->rise_count) {
            peer_conf->shm->down = 0; 
        } 
    }
    else {
        peer_conf->shm->rise_count = 0; 
        peer_conf->shm->fall_count++; 
        if (!peer_conf->shm->down && peer_conf->shm->fall_count >= uscf->fall_count) {
            peer_conf->shm->down = 1; 
        }
    }

    peer_conf->shm->access_time = ngx_current_msec; 
}


static void 
ngx_tcp_check_timeout_handler(ngx_event_t *event) {

    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_upstream_srv_conf_t   *uscf;
    
    if (ngx_tcp_check_need_exit()) {
        return;
    }

    peer_conf = event->data;
    uscf = peer_conf->conf;

    ngx_log_error(NGX_LOG_ERR, event->log, 0,
            "check time out with peer: %V ", &peer_conf->peer->name);

    ngx_tcp_check_status_update(peer_conf, 0);
    ngx_tcp_check_clean_event(peer_conf);
}

static void 
ngx_tcp_check_peek_handler(ngx_event_t *event) {

    ngx_int_t                      n;
    char                           buf[1];
    ngx_err_t                      err;
    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_upstream_srv_conf_t   *uscf;
    ngx_connection_t              *c;

    if (ngx_tcp_check_need_exit()) {
        return;
    }

    c = event->data;
    peer_conf = c->data;
    uscf = peer_conf->conf;

    c = peer_conf->pc.connection;
    if (c == NULL || c->fd <= 0) {
        ngx_tcp_check_status_update(peer_conf, 0);
        ngx_tcp_check_clean_event(peer_conf);
        return;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, c->log, err, 
            "tcp check upstream recv(): %d, fd: %d",
            n, c->fd);

    if (n >= 0 || err == NGX_EAGAIN) {
        ngx_tcp_check_status_update(peer_conf, 1);
    }
    else {
        c->error = 1;
        ngx_tcp_check_status_update(peer_conf, 0);
    }

    ngx_tcp_check_clean_event(peer_conf);

    /*dummy*/
    ngx_tcp_check_finish_handler(event);
}

static void 
ngx_tcp_check_connect_handler(ngx_event_t *event) {

    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_upstream_srv_conf_t   *uscf;
    ngx_connection_t              *c;
    ngx_int_t                      rc;

    if (ngx_tcp_check_need_exit()) {
        return;
    }

    peer_conf = event->data;
    uscf = peer_conf->conf;

    ngx_memzero(&peer_conf->pc, sizeof(ngx_peer_connection_t));

    peer_conf->pc.sockaddr = peer_conf->peer->sockaddr;
    peer_conf->pc.socklen = peer_conf->peer->socklen;
    peer_conf->pc.name = &peer_conf->peer->name;

    peer_conf->pc.get = ngx_event_get_peer;
    peer_conf->pc.log = event->log;
    peer_conf->pc.log_error = NGX_ERROR_ERR; 

    peer_conf->pc.cached = 0;
    peer_conf->pc.connection = NULL;

    rc = ngx_event_connect_peer(&peer_conf->pc);

    if (rc == NGX_ERROR || rc == NGX_DECLINED) {
        ngx_tcp_check_status_update(peer_conf, 0);
        return;
    }

    /*NGX_OK or NGX_AGAIN*/
    c = peer_conf->pc.connection;
    c->data = peer_conf;
    c->log = peer_conf->pc.log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;

    /*different check_type, differe handler */
    c->write->handler = ngx_tcp_check_peek_handler;
    c->read->handler = ngx_tcp_check_dummy_handler;

    ngx_add_timer(&peer_conf->check_timeout_ev, uscf->check_timeout);
}

static void 
ngx_tcp_check_begin_handler(ngx_event_t *event) {

    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_upstream_srv_conf_t   *uscf;

    if (ngx_tcp_check_need_exit()) {
        return;
    }

    peer_conf = event->data;
    uscf = peer_conf->conf;

    /*Add 100ms to fine adjust the timer*/
    ngx_add_timer(event, uscf->check_interval + 100);

    /*This process are processing the event now.*/
    if (peer_conf->shm->owner == ngx_pid) {
        return;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_TCP, event->log, 0, 
            "tcp check begin handler index:%ud, owner: %ud, ngx_pid: %ud, time:%ud", 
            peer_conf->index, peer_conf->shm->owner, ngx_pid, 
            (ngx_current_msec - peer_conf->shm->access_time));

    ngx_spinlock(&peer_conf->shm->lock, ngx_pid, 1024);

    if (((ngx_current_msec - peer_conf->shm->access_time) >= uscf->check_interval) && 
            peer_conf->shm->owner == NGX_INVALID_PID)
    {
        peer_conf->shm->owner = ngx_pid;
    }

    ngx_spinlock_unlock(&peer_conf->shm->lock);

    if (peer_conf->shm->owner == ngx_pid) {
        ngx_tcp_check_connect_handler(event);
    }
}

static ngx_int_t 
ngx_tcp_check_init_process(ngx_cycle_t *cycle) {

    ngx_uint_t                     i;
    ngx_msec_t                     t, delay;
    ngx_str_t                      shm_name;
    ngx_shm_zone_t                *shm_zone;
    ngx_tcp_check_peers_conf_t    *peers_conf;
    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_check_peers_shm_t     *peers_shm;
    ngx_tcp_check_peer_shm_t      *peer_shm;
    ngx_tcp_upstream_srv_conf_t   *uscf;

    if (ngx_tcp_check_get_shm_name(&shm_name, cycle->pool) == NGX_ERROR) {
        return NGX_ERROR;
    }

    shm_zone = ngx_shared_memory_find(cycle, &shm_name, &ngx_tcp_upstream_module);

    if (shm_zone == NULL || shm_zone->data == NULL) {
        return NGX_OK;
    }

    peers_conf = shm_zone->data;
    peers_shm = peers_conf->peers_shm;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, cycle->log, 0, 
            "tcp check upstream init_process, shm_name: %V, peer number: %ud",
            &shm_name, peers_conf->peers.nelts);

    srand(ngx_pid);

    peer_conf = peers_conf->peers.elts;
    peer_shm = peers_shm->peers;

    for (i = 0; i < peers_conf->peers.nelts; i++) {
        peer_conf[i].shm = &peer_shm[i];

        peer_conf[i].check_ev.handler = ngx_tcp_check_begin_handler;
        peer_conf[i].check_ev.log = cycle->log;
        peer_conf[i].check_ev.data = &peer_conf[i];
        peer_conf[i].check_ev.timer_set = 0;

        peer_conf[i].check_timeout_ev.handler = ngx_tcp_check_timeout_handler;
        peer_conf[i].check_timeout_ev.log = cycle->log;
        peer_conf[i].check_timeout_ev.data = &peer_conf[i];
        peer_conf[i].check_timeout_ev.timer_set = 0;

        uscf = peer_conf[i].conf;

        /* Default delay interval is 1 second. 
           I don't want to trigger the check event too close. */
        delay = uscf->check_interval > 1000 ? uscf->check_interval : 1000;
        t = ngx_random() % delay;

        ngx_add_timer(&peer_conf[i].check_ev, t);
    }

    return NGX_OK;
}

static ngx_int_t 
ngx_tcp_upstream_check_status_handler(ngx_http_request_t *r) {

    ngx_int_t          rc;
    ngx_uint_t         i;
    ngx_buf_t         *b;
    ngx_str_t          shm_name;
    ngx_chain_t        out;
    ngx_shm_zone_t    *shm_zone;
    ngx_tcp_check_peers_conf_t    *peers_conf;
    ngx_tcp_check_peer_conf_t     *peer_conf;
    ngx_tcp_check_peers_shm_t     *peers_shm;
    ngx_tcp_check_peer_shm_t      *peer_shm;


    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.content_type.len = sizeof("text/plain") - 1;
    r->headers_out.content_type.data = (u_char *) "text/plain";

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    if (ngx_tcp_check_get_shm_name(&shm_name, r->pool) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    shm_zone = ngx_shared_memory_find((ngx_cycle_t *)ngx_cycle, &shm_name, 
            &ngx_tcp_upstream_module);

    if (shm_zone == NULL || shm_zone->data == NULL) {

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "[tcp upstream check] can not find the shared memory zone \"%V\" ", &shm_name);

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    peers_conf = shm_zone->data;
    peers_shm = peers_conf->peers_shm;

    peer_conf = peers_conf->peers.elts;
    peer_shm = peers_shm->peers;

    b = ngx_create_temp_buf(r->pool, ngx_pagesize);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->last = ngx_sprintf(b->last, 
            "check upstream server number: %ui\n\n",
            peers_conf->peers.nelts);

    for (i = 0; i < peers_conf->peers.nelts; i++) {

        b->last = ngx_sprintf(b->last, 
                "server %ui: name=%V, down=%ui, rise=%ui, fall=%ui\n",
                i, &peer_conf[i].peer->name, peer_shm[i].down, 
                peer_shm[i].rise_count, peer_shm[i].fall_count);
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *
ngx_tcp_upstream_check_status_set_status(ngx_conf_t *cf, 
        ngx_command_t *cmd, void *conf) {

    ngx_http_core_loc_conf_t                *clcf;
    ngx_str_t                               *value;

    value = cf->args->elts;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_tcp_upstream_check_status_handler;

    return NGX_CONF_OK;
}
