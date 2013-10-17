
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>
#include <ngx_tcp_upstream_keepalive.h>

static ngx_int_t ngx_tcp_upstream_init_keepalive_peer(ngx_tcp_session_t *r,
                                                      ngx_tcp_upstream_srv_conf_t *us);
static ngx_int_t ngx_tcp_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
                                                     void *data);
static void ngx_tcp_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
                                                 void *data, ngx_uint_t state);

static void ngx_tcp_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_tcp_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_tcp_upstream_keepalive_close(ngx_connection_t *c);


#if (NGX_HTTP_SSL)
static ngx_int_t ngx_tcp_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_tcp_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void *ngx_tcp_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_tcp_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_tcp_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_TCP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_tcp_upstream_keepalive,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_keepalive_module_ctx = {
    NULL,
    ngx_tcp_upstream_keepalive_create_conf,
    NULL,
    NULL,
    NULL
};


ngx_module_t  ngx_tcp_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_keepalive_module_ctx,  /* module context */
    ngx_tcp_upstream_keepalive_commands,     /* module directives */
    NGX_TCP_MODULE,                          /* module type */
    NULL,                                    /* init master */
    NULL,                                    /* init module */
    NULL,                                    /* init process */
    NULL,                                    /* init thread */
    NULL,                                    /* exit thread */
    NULL,                                    /* exit process */
    NULL,                                    /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_tcp_upstream_init_keepalive(ngx_conf_t *cf,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_uint_t                               i;
    ngx_tcp_upstream_keepalive_srv_conf_t  *kcf;
    ngx_tcp_upstream_keepalive_cache_t     *cached;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "init keepalive");

    kcf = ngx_tcp_conf_upstream_srv_conf(us,
                                         ngx_tcp_upstream_keepalive_module);

    if (kcf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kcf->original_init_peer = us->peer.init;

    us->peer.init = ngx_tcp_upstream_init_keepalive_peer;

    /* allocate cache items and add to free queue */

    cached = ngx_pcalloc(cf->pool,
                sizeof(ngx_tcp_upstream_keepalive_cache_t) * kcf->max_cached);
    if (cached == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&kcf->cache);
    ngx_queue_init(&kcf->free);

    for (i = 0; i < kcf->max_cached; i++) {
        ngx_queue_insert_head(&kcf->free, &cached[i].queue);
        cached[i].conf = kcf;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_init_keepalive_peer(ngx_tcp_session_t *r,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_tcp_upstream_keepalive_peer_data_t  *kp;
    ngx_tcp_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_tcp_conf_upstream_srv_conf(us,
                                          ngx_tcp_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_tcp_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get  = ngx_tcp_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_tcp_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_tcp_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_tcp_upstream_keepalive_save_session;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_keepalive_peer_data_t  *kp = data;
    ngx_tcp_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_tcp_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->conf->free, q);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                           "get keepalive peer: using connection %p", c);

            c->idle = 0;
            c->log = pc->log;
            c->read->log = pc->log;
            c->write->log = pc->log;
            c->pool->log = pc->log;

            pc->connection = c;
            pc->cached = 1;

            return NGX_DONE;
        }
    }

    return NGX_OK;
}


static void
ngx_tcp_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_tcp_upstream_keepalive_peer_data_t  *kp = data;
    ngx_tcp_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q;
    ngx_connection_t     *c;
    ngx_tcp_upstream_t   *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) {

        q = ngx_queue_last(&kp->conf->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_tcp_upstream_keepalive_cache_t, queue);

        ngx_tcp_upstream_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_tcp_upstream_keepalive_cache_t, queue);
    }

    item->connection = c;
    ngx_queue_insert_head(&kp->conf->cache, q);

    pc->connection = NULL;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_tcp_upstream_keepalive_dummy_handler;
    c->read->handler  = ngx_tcp_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    if (c->read->ready) {
        ngx_tcp_upstream_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_tcp_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_tcp_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_tcp_upstream_keepalive_srv_conf_t  *conf;
    ngx_tcp_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* stale event */

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_tcp_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


static void
ngx_tcp_upstream_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_tcp_upstream_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_tcp_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_tcp_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void *
ngx_tcp_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_tcp_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_tcp_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     */

    conf->max_cached = 1;

    return conf;
}


static char *
ngx_tcp_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_upstream_srv_conf_t            *uscf;
    ngx_tcp_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;
    ngx_uint_t   i;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);

    if (kcf->original_init_upstream) {
        return "is duplicate";
    }

    kcf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_tcp_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_tcp_upstream_init_keepalive;

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "single") == 0) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "the \"single\" parameter is deprecated");
            continue;
        }

        goto invalid;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}
