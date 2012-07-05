
#ifndef _NGX_TCP_HTTP_RESPONSE_PARSER_H_INCLUDED_
#define _NGX_TCP_HTTP_RESPONSE_PARSER_H_INCLUDED_

#include <parser.h>

typedef struct http_response_parser { 
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
  
} http_response_parser;


int http_response_parser_init(http_response_parser *parser);
int http_response_parser_finish(http_response_parser *parser);
size_t http_response_parser_execute(http_response_parser *parser,
        const signed char *data, size_t len, size_t off);
int http_response_parser_has_error(http_response_parser *parser);
int http_response_parser_is_finished(http_response_parser *parser);

#define http_response_parser_nread(parser) (parser)->nread 


#endif //_NGX_TCP_HTTP_RESPONSE_PARSER_H_INCLUDED_
