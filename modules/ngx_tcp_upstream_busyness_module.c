
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


typedef struct {
    /* the round robin data must be first */
    ngx_tcp_upstream_rr_peer_data_t    rrp;

    u_char                             tries;

    ngx_event_get_peer_pt              get_rr_peer;
} ngx_tcp_upstream_busyness_peer_data_t;


static ngx_int_t ngx_tcp_upstream_init_busyness_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us);
static ngx_int_t ngx_tcp_upstream_get_busyness_peer(ngx_peer_connection_t *pc,
    void *data);
static char *ngx_tcp_upstream_busyness(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_tcp_upstream_busyness_commands[] = {

    { ngx_string("busyness"),
      NGX_TCP_UPS_CONF|NGX_CONF_NOARGS,
      ngx_tcp_upstream_busyness,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_upstream_busyness_module_ctx = {
    NULL,                                 

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */
};


ngx_module_t  ngx_tcp_upstream_busyness_module = {
    NGX_MODULE_V1,
    &ngx_tcp_upstream_busyness_module_ctx, /* module context */
    ngx_tcp_upstream_busyness_commands,    /* module directives */
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


ngx_int_t
ngx_tcp_upstream_init_busyness(ngx_conf_t *cf, ngx_tcp_upstream_srv_conf_t *us)
{
    if (ngx_tcp_upstream_init_round_robin(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    us->peer.init = ngx_tcp_upstream_init_busyness_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_upstream_init_busyness_peer(ngx_tcp_session_t *s,
    ngx_tcp_upstream_srv_conf_t *us)
{
    ngx_tcp_upstream_busyness_peer_data_t  *bp;

    bp = ngx_palloc(s->pool, sizeof(ngx_tcp_upstream_busyness_peer_data_t));
    if (bp == NULL) {
        return NGX_ERROR;
    }

    s->upstream->peer.data = &bp->rrp;

    if (ngx_tcp_upstream_init_round_robin_peer(s, us) != NGX_OK) {
        return NGX_ERROR;
    }

    s->upstream->peer.get = ngx_tcp_upstream_get_busyness_peer;

    bp->tries = 0;
    bp->get_rr_peer = ngx_tcp_upstream_get_round_robin_peer;

    return NGX_OK;
}


static ngx_uint_t
ngx_tcp_upstream_get_least_busy_index(ngx_tcp_upstream_rr_peers_t *rrps) 
{
    ngx_uint_t i, j, peer_index, check_index, busyness, min_busyness, start;

    min_busyness = (ngx_uint_t) (-1);

    peer_index = start = ngx_random() % rrps->number;

    for (i = 0; i < rrps->number; i++, start++) {

        j =  start % rrps->number;
        check_index = rrps->peer[j].check_index;

        busyness = ngx_tcp_check_get_peer_busyness(check_index);
        if (busyness < min_busyness && !ngx_tcp_check_peer_down(check_index)) {
            min_busyness = busyness;
            peer_index = j;
        }
    }

    return peer_index;
}


static ngx_int_t
ngx_tcp_upstream_get_busyness_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_tcp_upstream_busyness_peer_data_t  *bp = data;

    time_t                        now;
    uintptr_t                     m;
    ngx_uint_t                    n, p;
    ngx_tcp_upstream_rr_peer_t   *peer;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "get busyness peer, try: %ui", pc->tries);

    /* TODO: cached */

    if (bp->tries > 20 || bp->rrp.peers->single ||
            bp->rrp.peers->peer[0].check_index
                                    == (ngx_uint_t) NGX_INVALID_CHECK_INDEX) {

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "get busyness peer0, bp->tries: %ui", bp->tries);

        return bp->get_rr_peer(pc, &bp->rrp);
    }

    now = ngx_time();

    pc->cached = 0;
    pc->connection = NULL;

    for ( ;; ) {
        p = ngx_tcp_upstream_get_least_busy_index(bp->rrp.peers);

        n = p / (8 * sizeof(uintptr_t));
        m = (uintptr_t) 1 << p % (8 * sizeof(uintptr_t));

        if (!(bp->rrp.tried[n] & m)) {

            peer = &bp->rrp.peers->peer[p];

            ngx_log_debug4(NGX_LOG_DEBUG_TCP, pc->log, 0,
                           "get busyness peer, check_index: %ui, %ui, "
                           "%04XA, num: %d",
                           peer->check_index, p, m, bp->rrp.peers->number);

            /* ngx_lock_mutex(bp->rrp.peers->mutex); */

            if (!peer->down) {
                if (peer->max_fails == 0 || peer->fails < peer->max_fails) {
                    break;
                }

                if (now - peer->accessed > peer->fail_timeout) {
                    peer->fails = 0;
                    break;
                }
            }

            bp->rrp.tried[n] |= m;

            /* ngx_unlock_mutex(bp->rrp.peers->mutex); */

            pc->tries--;

        }

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "get busyness peer, bp->tries: %ui, p: %ui",
                       bp->tries, p);

        if (++bp->tries >= 20) {
            return bp->get_rr_peer(pc, &bp->rrp);
        }
    }

    bp->rrp.current = p;

    pc->sockaddr = peer->sockaddr;
    pc->socklen = peer->socklen;
    pc->name = &peer->name;
    pc->check_index = peer->check_index;

    /* ngx_unlock_mutex(bp->rrp.peers->mutex); */

    bp->rrp.tried[n] |= m;

    return NGX_OK;
}


static char *
ngx_tcp_upstream_busyness(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_upstream_srv_conf_t  *uscf;

    uscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_upstream_module);

    uscf->peer.init_upstream = ngx_tcp_upstream_init_busyness;

    uscf->flags = NGX_TCP_UPSTREAM_CREATE
                  |NGX_TCP_UPSTREAM_MAX_FAILS
                  |NGX_TCP_UPSTREAM_FAIL_TIMEOUT
                  |NGX_TCP_UPSTREAM_MAX_BUSY
                  |NGX_TCP_UPSTREAM_DOWN;

    return NGX_CONF_OK;
}
