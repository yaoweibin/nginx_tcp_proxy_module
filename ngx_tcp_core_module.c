
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static void *ngx_tcp_core_create_main_conf(ngx_conf_t *cf);
static void *ngx_tcp_core_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent,
        void *child);
static char *ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static char *ngx_tcp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_log_set_access_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_tcp_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_command_t  ngx_tcp_core_commands[] = {

    {   ngx_string("server"),
        NGX_TCP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_MULTI|NGX_CONF_NOARGS,
        ngx_tcp_core_server,
        0,
        0,
        NULL },

    {   ngx_string("listen"),
        NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
        ngx_tcp_core_listen,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    {   ngx_string("so_keepalive"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_TCP_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_core_srv_conf_t, so_keepalive),
        NULL },

    {   ngx_string("tcp_nodelay"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_TCP_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_core_srv_conf_t, tcp_nodelay),
        NULL },

    {   ngx_string("timeout"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_TCP_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_core_srv_conf_t, timeout),
        NULL },

    {   ngx_string("server_name"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_TCP_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_core_srv_conf_t, server_name),
        NULL },

    {   ngx_string("resolver"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_tcp_core_resolver,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    {   ngx_string("resolver_timeout"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_msec_slot,
        NGX_TCP_SRV_CONF_OFFSET,
        offsetof(ngx_tcp_core_srv_conf_t, resolver_timeout),
        NULL },

    {   ngx_string("allow"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_tcp_access_rule,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    {   ngx_string("deny"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
        ngx_tcp_access_rule,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    {   ngx_string("access_log"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE12,
        ngx_tcp_log_set_access_log,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    {   ngx_string("open_log_file_cache"),
        NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1234,
        ngx_tcp_log_open_file_cache,
        NGX_TCP_SRV_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_core_module_ctx = {
    NULL,                                  /* protocol */

    ngx_tcp_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_tcp_core_create_srv_conf,         /* create server configuration */
    ngx_tcp_core_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_tcp_core_module = {
    NGX_MODULE_V1,
    &ngx_tcp_core_module_ctx,             /* module context */
    ngx_tcp_core_commands,                /* module directives */
    NGX_TCP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_tcp_core_create_main_conf(ngx_conf_t *cf) 
{
    ngx_tcp_core_main_conf_t  *cmcf;

    cmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&cmcf->servers, cf->pool, 4,
                sizeof(ngx_tcp_core_srv_conf_t *))
            != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&cmcf->listen, cf->pool, 4, sizeof(ngx_tcp_listen_t))
            != NGX_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
ngx_tcp_core_create_srv_conf(ngx_conf_t *cf) 
{
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_log_srv_conf_t   *lscf;

    cscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     cscf->protocol = NULL;
     */

    cscf->timeout = NGX_CONF_UNSET_MSEC;
    cscf->resolver_timeout = NGX_CONF_UNSET_MSEC;
    cscf->so_keepalive = NGX_CONF_UNSET;
    cscf->tcp_nodelay = NGX_CONF_UNSET;

    cscf->resolver = NGX_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    lscf = cscf->access_log = ngx_pcalloc(cf->pool, 
            sizeof(ngx_tcp_core_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     lscf->logs = NULL;
     */

    lscf->open_file_cache = NGX_CONF_UNSET_PTR;

    return cscf;
}


static char *
ngx_tcp_core_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_tcp_core_srv_conf_t *prev = parent;
    ngx_tcp_core_srv_conf_t *conf = child;
    ngx_tcp_log_srv_conf_t  *plscf = prev->access_log;
    ngx_tcp_log_srv_conf_t  *lscf = conf->access_log;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    ngx_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout, 30000);

    ngx_conf_merge_value(conf->so_keepalive, prev->so_keepalive, 0);
    ngx_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    ngx_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    ngx_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }

    if (lscf->open_file_cache == NGX_CONF_UNSET_PTR) {

        lscf->open_file_cache = plscf->open_file_cache;
        lscf->open_file_cache_valid = plscf->open_file_cache_valid;
        lscf->open_file_cache_min_uses = plscf->open_file_cache_min_uses;

        if (lscf->open_file_cache == NGX_CONF_UNSET_PTR) {
            lscf->open_file_cache = NULL;
        }
    }

    if (lscf->logs || lscf->off) {
        return NGX_CONF_OK;
    }

    lscf->logs = plscf->logs;
    lscf->off = plscf->off;

    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    ngx_uint_t                  m;
    ngx_conf_t                  pcf;
    ngx_tcp_module_t           *module;
    ngx_tcp_conf_ctx_t         *ctx, *tcp_ctx;
    ngx_tcp_core_srv_conf_t    *cscf, **cscfp;
    ngx_tcp_core_main_conf_t   *cmcf;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    tcp_ctx = cf->ctx;
    ctx->main_conf = tcp_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

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

    /* the server configuration context */

    cscf = ctx->srv_conf[ngx_tcp_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];

    cscfp = ngx_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return NGX_CONF_ERROR;
    }

    *cscfp = cscf;

    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_TCP_SRV_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    return rv;
}


static char *
ngx_tcp_core_listen(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    size_t                      len, off;
    in_port_t                   port;
    ngx_str_t                  *value;
    ngx_url_t                   u;
    ngx_uint_t                  i, m;
    struct sockaddr            *sa;
    ngx_tcp_listen_t           *ls;
    ngx_tcp_module_t           *module;
    struct sockaddr_in         *sin;
    ngx_tcp_core_main_conf_t   *cmcf;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6        *sin6;
#endif

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.listen = 1;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "%s in \"%V\" of the \"listen\" directive",
                    u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    cmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_core_module);

    ls = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {

        sa = (struct sockaddr *) ls[i].sockaddr;

        if (sa->sa_family != u.family) {
            continue;
        }

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
            case AF_INET6:
                off = offsetof(struct sockaddr_in6, sin6_addr);
                len = 16;
                sin6 = (struct sockaddr_in6 *) sa;
                port = sin6->sin6_port;
                break;
#endif

            default: /* AF_INET */
                off = offsetof(struct sockaddr_in, sin_addr);
                len = 4;
                sin = (struct sockaddr_in *) sa;
                port = sin->sin_port;
                break;
        }

        if (ngx_memcmp(ls[i].sockaddr + off, u.sockaddr + off, len) != 0) {
            continue;
        }

        if (port != u.port) {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate \"%V\" address and port pair", &u.url);
        return NGX_CONF_ERROR;
    }

    ls = ngx_array_push(&cmcf->listen);
    if (ls == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(ls, sizeof(ngx_tcp_listen_t));

    ngx_memcpy(ls->sockaddr, u.sockaddr, u.socklen);

    ls->socklen = u.socklen;
    ls->wildcard = u.wildcard;
    ls->ctx = cf->ctx;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->protocol == NULL) {
            continue;
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (ngx_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            struct sockaddr  *sa;
            u_char            buf[NGX_SOCKADDR_STRLEN];

            sa = (struct sockaddr *) ls->sockaddr;

            if (sa->sa_family == AF_INET6) {

                if (ngx_strcmp(&value[i].data[10], "n") == 0) {
                    ls->ipv6only = 1;

                } else if (ngx_strcmp(&value[i].data[10], "ff") == 0) {
                    ls->ipv6only = 2;

                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                            "invalid ipv6only flags \"%s\"",
                            &value[i].data[9]);
                    return NGX_CONF_ERROR;
                }

                ls->bind = 1;

            } else {
                len = ngx_sock_ntop(sa, buf, NGX_SOCKADDR_STRLEN, 1);

                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "ipv6only is not supported "
                        "on addr \"%*s\", ignored", len, buf);
            }

            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "bind ipv6only is not supported "
                    "on this platform");
            return NGX_CONF_ERROR;
#endif
        }

        if (ngx_strcmp(value[i].data, "ssl") == 0) {
#if (NGX_TCP_SSL)
            ls->ssl = 1;
            continue;
#else
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "ngx_tcp_ssl_module");
            return NGX_CONF_ERROR;
#endif
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "the invalid \"%V\" parameter", &value[i]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_core_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_core_srv_conf_t  *cscf = conf;

    ngx_url_t   u;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.host = value[1];
    u.port = 53;

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V: %s", &u.host, u.err);
        return NGX_CONF_ERROR;
    }

    cscf->resolver = ngx_resolver_create(cf, &u.addrs[0]);
    if (cscf->resolver == NULL) {
        return NGX_CONF_OK;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_access_rule(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_tcp_core_srv_conf_t *cscf = conf;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t               cidr;
    ngx_tcp_access_rule_t   *rule;

    if (cscf->rules == NULL) {
        cscf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_tcp_access_rule_t));
        if (cscf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(cscf->rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    rule->deny = (value[0].data[0] == 'd') ? 1 : 0;

    if (value[1].len == 3 && ngx_strcmp(value[1].data, "all") == 0) {
        rule->mask = 0;
        rule->addr = 0;

        return NGX_CONF_OK;
    }

    rc = ngx_ptocidr(&value[1], &cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cidr.family != AF_INET) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"allow\" supports IPv4 only");
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    rule->mask = cidr.u.in.mask;
    rule->addr = cidr.u.in.addr;

    return NGX_CONF_OK;
}


static char *
ngx_tcp_log_set_access_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t *cscf = conf;
    ngx_tcp_log_srv_conf_t  *lscf = cscf->access_log;

    ssize_t                     buf;
    ngx_str_t                  *value, name;
    ngx_tcp_log_t              *log;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        lscf->off = 1;
        if (cf->args->nelts == 2) {
            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    if (lscf->logs == NULL) {
        lscf->logs = ngx_array_create(cf->pool, 2, sizeof(ngx_tcp_log_t));
        if (lscf->logs == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    log = ngx_array_push(lscf->logs);
    if (log == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(log, sizeof(ngx_tcp_log_t));

    log->file = ngx_conf_open_file(cf->cycle, &value[1]);
    if (log->file == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        if (ngx_strncmp(value[2].data, "buffer=", 7) != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        name.len = value[2].len - 7;
        name.data = value[2].data + 7;

        buf = ngx_parse_size(&name);

        if (buf == NGX_ERROR) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        if (log->file->buffer && log->file->last - log->file->pos != buf) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "access_log \"%V\" already defined "
                               "with different buffer size", &value[1]);
            return NGX_CONF_ERROR;
        }

        log->file->buffer = ngx_palloc(cf->pool, buf);
        if (log->file->buffer == NULL) {
            return NGX_CONF_ERROR;
        }

        log->file->pos = log->file->buffer;
        log->file->last = log->file->buffer + buf;
    }

    return NGX_CONF_OK;
}


static char *
ngx_tcp_log_open_file_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_core_srv_conf_t *cscf = conf;
    ngx_tcp_log_srv_conf_t  *lscf = cscf->access_log;

    time_t       inactive, valid;
    ngx_str_t   *value, s;
    ngx_int_t    max, min_uses;
    ngx_uint_t   i;

    if (lscf->open_file_cache != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            max = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (max == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            inactive = ngx_parse_time(&s, 1);
            if (inactive < 0) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "min_uses=", 9) == 0) {

            min_uses = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (min_uses == NGX_ERROR) {
                goto failed;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "valid=", 6) == 0) {

            s.len = value[i].len - 6;
            s.data = value[i].data + 6;

            valid = ngx_parse_time(&s, 1);
            if (valid < 0) {
                goto failed;
            }

            continue;
        }

        if (ngx_strcmp(value[i].data, "off") == 0) {

            lscf->open_file_cache = NULL;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"open_log_file_cache\" parameter \"%V\"",
                           &value[i]);
        return NGX_CONF_ERROR;
    }

    if (lscf->open_file_cache == NULL) {
        return NGX_CONF_OK;
    }

    if (max == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                        "\"open_log_file_cache\" must have \"max\" parameter");
        return NGX_CONF_ERROR;
    }

    lscf->open_file_cache = ngx_open_file_cache_init(cf->pool, max, inactive);

    if (lscf->open_file_cache) {

        lscf->open_file_cache_valid = valid;
        lscf->open_file_cache_min_uses = min_uses;

        return NGX_CONF_OK;
    }

    return NGX_CONF_ERROR;
}


