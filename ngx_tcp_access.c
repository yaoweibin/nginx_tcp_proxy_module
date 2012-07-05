
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


ngx_int_t
ngx_tcp_access_handler(ngx_tcp_session_t *s) 
{
    ngx_uint_t                   i;
    struct sockaddr_in          *sin;
    ngx_tcp_access_rule_t       *rule;
    ngx_tcp_core_srv_conf_t     *cscf;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    if (cscf->rules == NULL) {
        return NGX_DECLINED;
    }

    /* AF_INET only */

    if (s->connection->sockaddr->sa_family != AF_INET) {
        return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *) s->connection->sockaddr;

    rule = cscf->rules->elts;
    for (i = 0; i < cscf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       sin->sin_addr.s_addr, rule[i].mask, rule[i].addr);

        if ((sin->sin_addr.s_addr & rule[i].mask) == rule[i].addr) {
            if (rule[i].deny) {
                ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                              "access forbidden by rule");

                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
