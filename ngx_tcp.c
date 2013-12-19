
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>


static char *ngx_tcp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_tcp_add_ports(ngx_conf_t *cf, ngx_array_t *ports,
    ngx_tcp_listen_t *listen);
static ngx_int_t ngx_tcp_add_virtual_servers(ngx_conf_t *cf, 
        ngx_tcp_core_main_conf_t *cmcf, ngx_tcp_listen_t *listen);
static char * ngx_tcp_optimize_servers(ngx_conf_t *cf, 
        ngx_tcp_core_main_conf_t *cmcf, ngx_array_t *ports);
static ngx_int_t ngx_tcp_add_addrs(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr);
#if (NGX_HAVE_INET6)
static ngx_int_t ngx_tcp_add_addrs6(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr);
#endif
static ngx_int_t ngx_tcp_cmp_conf_addrs(const void *one, const void *two);


ngx_uint_t  ngx_tcp_max_module;


static ngx_command_t  ngx_tcp_commands[] = {

    { ngx_string("tcp"),
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_tcp_block,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_tcp_module_ctx = {
    ngx_string("tcp"),
    NULL,
    NULL
};


ngx_module_t  ngx_tcp_module = {
    NGX_MODULE_V1,
    &ngx_tcp_module_ctx,                   /* module context */
    ngx_tcp_commands,                      /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_tcp_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_uint_t                   i, m, mi, s;
    ngx_conf_t                   pcf;
    ngx_array_t                  ports;
    ngx_tcp_listen_t           *listen;
    ngx_tcp_module_t           *module;
    ngx_tcp_conf_ctx_t         *ctx;
    ngx_tcp_core_srv_conf_t   **cscfp;
    ngx_tcp_core_main_conf_t   *cmcf;


    /* the main tcp context */

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    *(ngx_tcp_conf_ctx_t **) conf = ctx;

    /* count the number of the tcp modules and set up their indices */

    ngx_tcp_max_module = 0;
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        ngx_modules[m]->ctx_index = ngx_tcp_max_module++;
    }


    /* the tcp main_conf context, it is the same in the all tcp contexts */

    ctx->main_conf = ngx_pcalloc(cf->pool,
                                 sizeof(void *) * ngx_tcp_max_module);
    if (ctx->main_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * the tcp null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_tcp_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }


    /*
     * create the main_conf's, the null srv_conf's, and the null loc_conf's
     * of the all tcp modules
     */

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }


    /* parse inside the tcp{} block */

    pcf = *cf;
    cf->ctx = ctx;

    cf->module_type = NGX_TCP_MODULE;
    cf->cmd_type = NGX_TCP_MAIN_CONF;
    rv = ngx_conf_parse(cf, NULL);

    if (rv != NGX_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init tcp{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[ngx_tcp_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_TCP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;
        mi = ngx_modules[m]->ctx_index;

        /* init tcp{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != NGX_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf, ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != NGX_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    *cf = pcf;

    if (ngx_array_init(&ports, cf->temp_pool, 4, sizeof(ngx_tcp_conf_port_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (ngx_tcp_add_ports(cf, &ports, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }

        if (ngx_tcp_add_virtual_servers(cf, cmcf, &listen[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return ngx_tcp_optimize_servers(cf, cmcf, &ports);
}


static ngx_int_t
ngx_tcp_add_ports(ngx_conf_t *cf, ngx_array_t *ports, ngx_tcp_listen_t *listen)
{
    in_port_t              p;
    ngx_uint_t             i;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_tcp_conf_port_t   *port;
    ngx_tcp_conf_addr_t   *addr;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif

    sa = (struct sockaddr *) &listen->sockaddr;

    switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) sa;
        p = sin6->sin6_port;
        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) sa;
        p = sin->sin_port;
        break;
    }

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {
        if (p == port[i].port && sa->sa_family == port[i].family) {

            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = ngx_array_push(ports);
    if (port == NULL) {
        return NGX_ERROR;
    }

    port->family = sa->sa_family;
    port->port = p;

    if (ngx_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(ngx_tcp_conf_addr_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

found:

    addr = ngx_array_push(&port->addrs);
    if (addr == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(addr, sizeof(ngx_tcp_conf_addr_t));

    addr->sockaddr = (struct sockaddr *) &listen->sockaddr;
    addr->socklen = listen->socklen;
    addr->ctx = listen->ctx;
    addr->bind = listen->bind;
    addr->wildcard = listen->wildcard;
    if (listen->default_port) {
        addr->default_ctx = listen->ctx;
    }
#if (NGX_TCP_SSL)
    addr->ssl = listen->ssl;
#endif
#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    addr->ipv6only = listen->ipv6only;
#endif

    return NGX_OK;
}


static ngx_int_t 
ngx_tcp_add_virtual_servers(ngx_conf_t *cf, ngx_tcp_core_main_conf_t *cmcf,
    ngx_tcp_listen_t *listen)
{
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_virtual_server_t  *vs;

    cscf = listen->conf;
    if (cscf == NULL || cscf->server_name.len == 0) {
        return NGX_OK;
    }

    vs = ngx_array_push(&cmcf->virtual_servers);
    if (vs == NULL) {
        return NGX_ERROR;
    }

    vs->name.len = cscf->server_name.len;
    vs->name.data = cscf->server_name.data;
    vs->hash = ngx_hash_key(vs->name.data, vs->name.len);
    vs->listen = listen;
    vs->ctx = listen->ctx;

    return NGX_OK;
}


static char *
ngx_tcp_optimize_servers(ngx_conf_t *cf, ngx_tcp_core_main_conf_t *cmcf,
    ngx_array_t *ports)
{
    ngx_uint_t             i, p, last, bind_wildcard;
    ngx_listening_t       *ls;
    ngx_tcp_port_t        *mport;
    ngx_tcp_conf_port_t   *port;
    ngx_tcp_conf_addr_t   *addr;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        ngx_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(ngx_tcp_conf_addr_t), ngx_tcp_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].wildcard) {
            addr[last - 1].bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].bind) {
                i++;
                continue;
            }

            ls = ngx_create_listening(cf, addr[i].sockaddr, addr[i].socklen);
            if (ls == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = ngx_tcp_init_connection;
            ls->pool_size = 256;

            /* TODO: error_log directive */
            ls->logp = &cf->cycle->new_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = ngx_accept_log_error;

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
            ls->ipv6only = addr[i].ipv6only;
#endif

            mport = ngx_palloc(cf->pool, sizeof(ngx_tcp_port_t));
            if (mport == NULL) {
                return NGX_CONF_ERROR;
            }

            ls->servers = mport;

            if (i == last - 1) {
                mport->naddrs = last;

            } else {
                mport->naddrs = 1;
                i = 0;
            }

            switch (ls->sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
            case AF_INET6:
                if (ngx_tcp_add_addrs6(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (ngx_tcp_add_addrs(cf, mport, addr) != NGX_OK) {
                    return NGX_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_tcp_add_addrs(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr)
{
    u_char              *p;
    size_t               len;
    ngx_uint_t           i, j;
    ngx_tcp_in_addr_t   *addrs;
    struct sockaddr_in  *sin, *sin_b;
    u_char               buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_tcp_in_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].ctx;

        for (j = 0; j < mport->naddrs; j++) {
            sin_b = (struct sockaddr_in *) addr[j].sockaddr;
            if ((sin->sin_addr.s_addr == sin_b->sin_addr.s_addr) && addr[j].default_ctx) {
                addrs[i].conf.default_ctx = addr[j].default_ctx;
            }
        }

#if (NGX_TCP_SSL)
        addrs[i].conf.ssl = addr[i].ssl;
#endif

#if defined(nginx_version) && nginx_version >= 1005003
        len = ngx_sock_ntop(addr[i].sockaddr, addr[i].socklen, buf, NGX_SOCKADDR_STRLEN, 1);
#else
        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);
#endif

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs[i].conf.addr_text.len = len;
        addrs[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}


#if (NGX_HAVE_INET6)

static ngx_int_t
ngx_tcp_add_addrs6(ngx_conf_t *cf, ngx_tcp_port_t *mport,
    ngx_tcp_conf_addr_t *addr)
{
    u_char               *p;
    size_t                len;
    ngx_uint_t            i, j;
    ngx_tcp_in6_addr_t   *addrs6;
    struct sockaddr_in6  *sin6, *sin6_b;
    u_char                buf[NGX_SOCKADDR_STRLEN];

    mport->addrs = ngx_pcalloc(cf->pool,
                               mport->naddrs * sizeof(ngx_tcp_in6_addr_t));
    if (mport->addrs == NULL) {
        return NGX_ERROR;
    }

    addrs6 = mport->addrs;

    for (i = 0; i < mport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].ctx;

        for (j = 0; j < mport->naddrs; j++) {
            sin6_b = (struct sockaddr_in6 *) addr[j].sockaddr;

            if ((ngx_memcmp(&sin6->sin6_addr, &sin6_b->sin6_addr, 16) == 0) && 
                    addr[j].default_ctx) {
                addrs6[i].conf.default_ctx = addr[j].default_ctx;
            }
        }

#if (NGX_TCP_SSL)
        addrs6[i].conf.ssl = addr[i].ssl;
#endif

#if defined(nginx_version) && nginx_version >= 1005003
        len = ngx_sock_ntop(addr[i].sockaddr, addr[i].socklen, buf, NGX_SOCKADDR_STRLEN, 1);
#else
        len = ngx_sock_ntop(addr[i].sockaddr, buf, NGX_SOCKADDR_STRLEN, 1);
#endif

        p = ngx_pnalloc(cf->pool, len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, buf, len);

        addrs6[i].conf.addr_text.len = len;
        addrs6[i].conf.addr_text.data = p;
    }

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_tcp_cmp_conf_addrs(const void *one, const void *two)
{
    ngx_tcp_conf_addr_t  *first, *second;

    first = (ngx_tcp_conf_addr_t *) one;
    second = (ngx_tcp_conf_addr_t *) two;

    if (first->wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (first->bind && !second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->bind && second->bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
