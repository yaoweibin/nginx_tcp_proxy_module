#ifndef _NGX_TCP_UPSTREAM_CHECK_H_INCLUDED_
#define _NGX_TCP_UPSTREAM_CHECK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_tcp.h>


typedef struct {
    u_char major;
    u_char minor;
} ssl_protocol_version_t;

typedef struct {
    u_char                 msg_type;
    ssl_protocol_version_t version;
    uint16_t               length;

    u_char                 handshake_type;
    u_char                 handshake_length[3];
    ssl_protocol_version_t hello_version;

    time_t                 time;
    u_char                 random[28];

    u_char                 others[0];
} __attribute__((packed)) server_ssl_hello_t;

typedef struct {

    u_char                 packet_length[3];
    u_char                 packet_number;

    u_char                 protocol_version;
    u_char                 others[0];
} __attribute__((packed)) mysql_handshake_init_t;

typedef struct {
    ngx_buf_t send;
    ngx_buf_t recv;

    void *parser;
} ngx_tcp_check_ctx;

/*state*/
#define NGX_TCP_CHECK_CONNECT_DONE     0x0001
#define NGX_TCP_CHECK_SEND_DONE        0x0002
#define NGX_TCP_CHECK_RECV_DONE        0x0004
#define NGX_TCP_CHECK_ALL_DONE         0x0008

typedef struct {
    ngx_pid_t  owner;

    ngx_msec_t access_time;

    ngx_uint_t fall_count;
    ngx_uint_t rise_count;

    ngx_atomic_t lock;
    ngx_atomic_t business;
    ngx_atomic_t down;

    ngx_uint_t access_count;
} ngx_tcp_check_peer_shm_t;

typedef struct {
    ngx_uint_t generation;

    ngx_uint_t state;
    ngx_atomic_t lock;

    /*store the ngx_tcp_check_status_peer_t*/
    ngx_tcp_check_peer_shm_t peers[0];
} ngx_tcp_check_peers_shm_t;

typedef ngx_int_t (*ngx_tcp_check_packet_init_pt)(ngx_tcp_check_peer_conf_t *peer_conf); 
typedef ngx_int_t (*ngx_tcp_check_packet_parse_pt)(ngx_tcp_check_peer_conf_t *peer_conf); 
typedef void (*ngx_tcp_check_packet_clean_pt)(ngx_tcp_check_peer_conf_t *peer_conf); 

#define NGX_TCP_CHECK_TCP              0x0001
#define NGX_TCP_CHECK_HTTP             0x0002
#define NGX_TCP_CHECK_SSL_HELLO        0x0004
#define NGX_TCP_CHECK_SMTP             0x0008
#define NGX_TCP_CHECK_MYSQL            0x0010
#define NGX_TCP_CHECK_POP3             0x0020
#define NGX_TCP_CHECK_IMAP             0x0040


#define NGX_CHECK_HTTP_2XX             0x0002
#define NGX_CHECK_HTTP_3XX             0x0004
#define NGX_CHECK_HTTP_4XX             0x0008
#define NGX_CHECK_HTTP_5XX             0x0010
#define NGX_CHECK_HTTP_6XX             0x0020
#define NGX_CHECK_HTTP_ERR             0x8000

#define NGX_CHECK_SMTP_2XX             0x0002
#define NGX_CHECK_SMTP_3XX             0x0004
#define NGX_CHECK_SMTP_4XX             0x0008
#define NGX_CHECK_SMTP_5XX             0x0010
#define NGX_CHECK_SMTP_6XX             0x0020
#define NGX_CHECK_SMTP_ERR             0x8000

struct check_conf_s {
    ngx_uint_t type;

    char *name;

    ngx_str_t default_send;
    
    /*HTTP*/
    ngx_uint_t default_status_alive;

    ngx_event_handler_pt  send_handler;
    ngx_event_handler_pt  recv_handler;

    ngx_tcp_check_packet_init_pt     init;
    ngx_tcp_check_packet_parse_pt    parse;
    ngx_tcp_check_packet_clean_pt    reinit;

    unsigned need_pool;
};

struct ngx_tcp_check_peer_conf_s {

    ngx_flag_t                       state;
    ngx_pool_t                      *pool;
    ngx_uint_t                       index;
    ngx_uint_t                       max_busy;
    ngx_tcp_upstream_srv_conf_t     *conf;
    ngx_peer_addr_t                 *peer;
    ngx_event_t                      check_ev;
    ngx_event_t                      check_timeout_ev;
    ngx_peer_connection_t            pc;

    void *                           check_data;
    ngx_event_handler_pt             send_handler;
    ngx_event_handler_pt             recv_handler;

    ngx_tcp_check_packet_init_pt     init;
    ngx_tcp_check_packet_parse_pt    parse;
    ngx_tcp_check_packet_clean_pt    reinit;

    ngx_tcp_check_peer_shm_t         *shm;
};

struct ngx_tcp_check_peers_conf_s {
    ngx_str_t                        check_shm_name;
    ngx_array_t                      peers;

    ngx_tcp_check_peers_shm_t       *peers_shm;
};


/*HTTP parser*/
typedef void (*element_cb)(void *data, const char *at, size_t length);
typedef void (*field_cb)(void *data, const char *field, size_t flen, const char *value, size_t vlen);


typedef struct http_parser { 
  int cs;
  size_t body_start;
  int content_len;
  int status_code_n;
  size_t nread;
  size_t mark;
  size_t field_start;
  size_t field_len;

  void *data;

  field_cb http_field;

  element_cb http_version;
  element_cb status_code;
  element_cb reason_phrase;
  element_cb header_done;
  
} http_parser;

int http_parser_init(http_parser *parser);
int http_parser_finish(http_parser *parser);
size_t http_parser_execute(http_parser *parser, const char *data, size_t len, size_t off);
int http_parser_has_error(http_parser *parser);
int http_parser_is_finished(http_parser *parser);

#define http_parser_nread(parser) (parser)->nread 

typedef struct smtp_parser {

  int cs;
  size_t nread;
  size_t mark;

  int hello_reply_code;

  void *data;

  element_cb domain;
  element_cb greeting_text;
  element_cb reply_code;
  element_cb reply_text;
  element_cb smtp_done;
    
} smtp_parser;

int smtp_parser_init(smtp_parser *parser);
int smtp_parser_finish(smtp_parser *parser);
size_t smtp_parser_execute(smtp_parser *parser, const char *data, size_t len, size_t off);
int smtp_parser_has_error(smtp_parser *parser);
int smtp_parser_is_finished(smtp_parser *parser);

#define http_parser_nread(parser) (parser)->nread 


ngx_int_t ngx_tcp_upstream_init_main_check_conf(ngx_conf_t *cf, void*conf);

ngx_uint_t ngx_tcp_check_add_peer(ngx_conf_t *cf, ngx_tcp_upstream_srv_conf_t *uscf,
        ngx_peer_addr_t *peer, ngx_uint_t max_busy);

ngx_uint_t ngx_tcp_check_peer_down(ngx_uint_t index);

void ngx_tcp_check_get_peer(ngx_uint_t index);
void ngx_tcp_check_free_peer(ngx_uint_t index);

check_conf_t *ngx_tcp_get_check_type_conf(ngx_str_t *str);

#endif //_NGX_TCP_UPSTREAM_CHECK_H_INCLUDED_

