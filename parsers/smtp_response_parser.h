
#ifndef _NGX_TCP_SMTP_RESPONSE_PARSER_H_INCLUDED_
#define _NGX_TCP_SMTP_RESPONSE_PARSER_H_INCLUDED_

#include <parser.h>

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
size_t smtp_parser_execute(smtp_parser *parser, const signed char *data, size_t len, size_t off);
int smtp_parser_has_error(smtp_parser *parser);
int smtp_parser_is_finished(smtp_parser *parser);

#endif //_NGX_TCP_SMTP_RESPONSE_PARSER_H_INCLUDED_
