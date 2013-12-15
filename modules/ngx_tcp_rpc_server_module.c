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
typedef struct ngx_tcp_rpc_header_s {
    uint32_t length;
    uint32_t magic;
    uint16_t type;
    uint16_t version;
    uint32_t spare0;
} __attribute__ ((packed)) ngx_tcp_rpc_header_t;

#define HEADER_LENGTH sizeof(ngx_tcp_rpc_header_t)

#define rpc_packet_size(ptr) (*(u_char *)(ptr)  + \
                     (*((u_char *)(ptr) + 1) << 8)  + \
                     (*((u_char *)(ptr) + 2) << 16) + \
                     (*((u_char *)(ptr) + 3) << 24) )

#define RPC_TYPE_OFFSET offsetof(ngx_tcp_rpc_header_t, type)
#define rpc_packet_type(ptr) (*((u_char *)(ptr) + RPC_TYPE_OFFSET) + \
                      (*((u_char *)(ptr) + RPC_TYPE_OFFSET + 1) << 8) )

#define PACKET_TYPE_JSON     1
#define PACKET_TYPE_TLV      2
#define PACKET_TYPE_BSON     3
#define PACKET_TYPE_MSGPACK  4

typedef struct ngx_tcp_rpc_ctx_s {
    ngx_peer_connection_t    *upstream;

    // ngx_tcp_session_t's buffer is header_in
    // request_body is the request body
    ngx_buf_t                *request_body;
    ngx_uint_t                request_len;

    ngx_buf_t                *header_out;
} ngx_tcp_rpc_ctx_t;


typedef struct ngx_tcp_rpc_conf_s {
    ngx_tcp_upstream_conf_t   upstream;
    ngx_int_t                 rpc_server;
    ngx_str_t                 document_root;
} ngx_tcp_rpc_conf_t;

static void ngx_tcp_rpc_init_session(ngx_tcp_session_t *s);
static void ngx_tcp_rpc_client_read_handler(ngx_event_t *rev);
static void ngx_tcp_rpc_client_write_handler(ngx_event_t *wev);
static void *ngx_tcp_rpc_create_conf(ngx_conf_t *cf);
static char *ngx_tcp_rpc_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);

static ngx_tcp_protocol_t  ngx_tcp_rpc_protocol = {

    ngx_string("rpc_server"),
    { 0, 0, 0, 0 },
    NGX_TCP_GENERIC_PROTOCOL,
    ngx_tcp_rpc_init_session,
    NULL,
    NULL,
    ngx_string("500 Internal server error" CRLF)

};


static ngx_command_t  ngx_tcp_rpc_commands[] = {

    { ngx_string("rpc_server"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_rpc_conf_t, rpc_server),
      NULL },

    { ngx_string("root"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_rpc_conf_t, document_root),
      NULL },

    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_rpc_module_ctx = {
    &ngx_tcp_rpc_protocol,             /* protocol */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_tcp_rpc_create_conf,           /* create server configuration */
    ngx_tcp_rpc_merge_conf             /* merge server configuration */
};


ngx_module_t  ngx_tcp_rpc_module = {
    NGX_MODULE_V1,
    &ngx_tcp_rpc_module_ctx,               /* module context */
    ngx_tcp_rpc_commands,                  /* module directives */
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
ngx_tcp_rpc_init_session(ngx_tcp_session_t *s)
{
    return;
}


static void
ngx_tcp_rpc_client_read_handler(ngx_event_t *rev)
{
    return;
}


static void
ngx_tcp_rpc_client_write_handler(ngx_event_t *wev)
{
    return;
}


static void *
ngx_tcp_rpc_create_conf(ngx_conf_t *cf)
{
    ngx_tcp_rpc_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_rpc_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    return pcf;
}


#define unused(arg) (void)(arg)

static char *
ngx_tcp_rpc_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_tcp_rpc_conf_t *prev = parent;
    ngx_tcp_rpc_conf_t *conf = child;

    unused(prev);
    unused(conf);

    unused(ngx_tcp_rpc_client_read_handler);
    unused(ngx_tcp_rpc_client_write_handler);

    return NGX_CONF_OK;
}
