
#include "../ngx_tcp_upstream_check.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define LEN(AT, FPC) (FPC - buffer - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - buffer)
#define PTR_TO(F) (buffer + parser->F)

/** Machine **/

%%{
  
  machine smtp_parser;

  action mark {MARK(mark, fpc);}

  action domain {
    if(parser->domain != NULL) {
      parser->domain(parser->data, PTR_TO(mark), LEN(mark, fpc));
    }
  }

  action greeting_text {	
    if(parser->greeting_text != NULL)
      parser->greeting_text(parser->data, PTR_TO(mark), LEN(mark, fpc));
  }

  action reply_code {
    if(parser->reply_code != NULL)
      parser->reply_code(parser->data, PTR_TO(mark), LEN(mark,fpc));
  }

  action reply_text {
    if(parser->reply_text != NULL)
      parser->reply_text(parser->data, PTR_TO(mark), LEN(mark,fpc));
  }

  action done { 
    if(parser->smtp_done != NULL)
      parser->smtp_done(parser->data, fpc + 1, pe - fpc - 1);
    fbreak;
  }

#### SMTP PROTOCOL GRAMMAR
  CRLF = "\r\n";
  SP = " ";

  Let_dig = alnum;
  Ldh_str = ( alnum | "-" )* alnum;
  Snum = digit{1,3};
#Standardized_tag = Ldh_str;
#Not supported yet
#General_address_literal = Standardized_tag ":" content{1,d};

  IPv4_address_literal = Snum ("." Snum){3};

  IPv6_hex  = xdigit{1,4};
  IPv6_full = IPv6_hex ( ":" IPv6_hex ){7};
  IPv6_comp = (IPv6_hex (":" IPv6_hex){0,5})? "::" (IPv6_hex (":" IPv6_hex){0,5})?;
  IPv6v4_full = IPv6_hex (":" IPv6_hex){5} ":" IPv4_address_literal;
  IPv6v4_comp = (IPv6_hex (":" IPv6_hex){0,3})? "::" (IPv6_hex (":" IPv6_hex){0,3} ":")? IPv4_address_literal;

  IPv6_addr = ( IPv6_full | IPv6_comp | IPv6v4_full | IPv6v4_comp );

  IPv6_address_literal = "IPv6:" IPv6_addr;
  
  Sub_domain = Let_dig Ldh_str?;
#Address_literal = "[" ( Pv4_address_literal | IPv6_address_literal | General_address_literal ) "]";
  Address_literal = "[" ( IPv4_address_literal | IPv6_address_literal ) "]";

#It should be '+', but smtp.163.com is sucks.
#Domain = (( Sub_domain ( '.' Sub_domain )+ ) | Address_literal ) >mark %domain;
  Domain = (( Sub_domain ( '.' Sub_domain )? ) | Address_literal ) >mark %domain;

  Greeting_text = ( ascii -- ("\r" | "\n") )+ >mark %greeting_text;

  Greeting_line = "220 " Domain ( SP Greeting_text )? CRLF;


  
  Reply_code = ( digit+ ) >mark %reply_code;

  Ehlo_keyword = Let_dig ( Let_dig | "-" )*;
  Ehlo_param   = ( ascii -- ( cntrl | SP ) )+;

#the "=" is not in the RFC, the reason see also: http://www.linuxquestions.org/questions/linux-networking-3/qmail-auth-login-auth%3Dlogin-arghhhhhhhh-226524/
  Ehlo_line = ( Ehlo_keyword ( ( SP | "=" ) Ehlo_param )* ) >mark %reply_text;

Ehlo_reply_ok = ( ( "250" Domain ( SP Greeting_text )? CRLF ) 
        | ("250-" Domain ( SP Greeting_text)? CRLF ( "250-" Ehlo_line CRLF )* Reply_code SP Ehlo_line CRLF) ); 

  Reply_text = ( ascii -- ("\r" | "\n") )+ >mark %reply_text;

  General_reply_line = Reply_code ( SP Reply_text )? CRLF;

  Reply_line = ( General_reply_line | Ehlo_reply_ok );


  Response = Greeting_line Reply_line @done;

main := Response;

}%%

/** Data **/
%% write data;

int smtp_parser_init(smtp_parser *parser)  {

  int cs = 0;
  %% write init;
  parser->cs = cs;
  parser->mark = 0;
  parser->nread = 0;

  return(1);
}


/** exec **/
size_t smtp_parser_execute(smtp_parser *parser, const signed char *buffer, size_t len, size_t off)  {

  const signed char *p, *pe;
  int cs = parser->cs;

  assert(off <= len && "offset past end of buffer");

  p = buffer + off;
  pe = buffer + len;

  %% write exec;

  if (!smtp_parser_has_error(parser))
    parser->cs = cs;
  parser->nread += p - (buffer + off);

  return(parser->nread);
}

int smtp_parser_finish(smtp_parser *parser)
{
  if (smtp_parser_has_error(parser) ) {
    return -1;
  } else if (smtp_parser_is_finished(parser) ) {
    return 1;
  } else {
    return 0;
  }
}

int smtp_parser_has_error(smtp_parser *parser) {
  return parser->cs == smtp_parser_error;
}

int smtp_parser_is_finished(smtp_parser *parser) {
  return parser->cs >= smtp_parser_first_final;
}
