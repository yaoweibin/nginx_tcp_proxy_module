

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>


static void ngx_tcp_log_write(ngx_tcp_session_t *s, ngx_http_log_t *log,
    u_char *buf, size_t len);

/* 
static ngx_str_t  ngx_http_combined_fmt =
    ngx_string("$remote_addr - $remote_user [$time_local] "
               "\"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\"");

*/

ngx_int_t
ngx_tcp_log_handler(ngx_tcp_session_t *s)
{
    u_char                   *line, *p;
    size_t                    len;
    ngx_uint_t                i, l;
    ngx_tcp_log_t            *log;
    ngx_open_file_t          *file;
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_tcp_log_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp access log handler");

    cscf = ngx_http_get_module_loc_conf(s, ngx_tcp_core_module);
    lscf = cscf->access_log;

    if (lscf->off) {
        return NGX_OK;
    }

    log = lscf->logs->elts;
    for (l = 0; l < lscf->logs->nelts; l++) {

        if (ngx_time() == log[l].disk_full_time) {

            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */

            continue;
        }

        len = 0;

        /*Calculate he length*/

        len += NGX_LINEFEED_SIZE;

        file = log[l].file;

        if (file && file->buffer) {

            if (len > (size_t) (file->last - file->pos)) {

                ngx_tcp_log_write(s, &log[l], file->buffer,
                                   file->pos - file->buffer);

                file->pos = file->buffer;
            }

            if (len <= (size_t) (file->last - file->pos)) {

                p = file->pos;

                /*fill the log data with buffer*/

                ngx_linefeed(p);

                file->pos = p;

                continue;
            }
        }

        line = ngx_pnalloc(s->pool, len);
        if (line == NULL) {
            return NGX_ERROR;
        }

        p = line;

        /*fill the log data with line*/

        ngx_linefeed(p);

        ngx_tcp_log_write(s, &log[l], line, p - line);
    }

    return NGX_OK;
}


static void
ngx_tcp_log_write(ngx_tcp_session_t *s, ngx_tcp_log_t *log, u_char *buf,
    size_t len)
{
    u_char     *name;
    time_t      now;
    ssize_t     n;
    ngx_err_t   err;

    name = log->file->name.data;
    n = ngx_write_fd(log->file->fd, buf, len);

    if (n == (ssize_t) len) {
        return;
    }

    now = ngx_time();

    if (n == -1) {
        err = ngx_errno;

        if (err == NGX_ENOSPC) {
            log->disk_full_time = now;
        }

        if (now - log->error_log_time > 59) {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, err,
                          ngx_write_fd_n " to \"%s\" failed", name);

            log->error_log_time = now;
        }

        return;
    }

    if (now - log->error_log_time > 59) {
        ngx_log_error(NGX_LOG_ALERT, s->connection->log, 0,
                      ngx_write_fd_n " to \"%s\" was incomplete: %z of %uz",
                      name, n, len);

        log->error_log_time = now;
    }
}
