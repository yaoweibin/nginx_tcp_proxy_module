
#include <http_response_parser.h>

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
  
  machine http_response_parser;

  action mark {MARK(mark, fpc); }

  action start_field { MARK(field_start, fpc); }
  action write_field { 
    parser->field_len = LEN(field_start, fpc);
  }

  action start_value { MARK(mark, fpc); }

  action write_value {
    if(parser->http_field != NULL) {
      parser->http_field(parser->data, PTR_TO(field_start), parser->field_len, PTR_TO(mark), LEN(mark, fpc));
    }
  }

  action http_version {	
    if(parser->http_version != NULL)
      parser->http_version(parser->data, PTR_TO(mark), LEN(mark, fpc));
  }

  action status_code {
    if(parser->status_code != NULL)
      parser->status_code(parser->data, PTR_TO(mark), LEN(mark,fpc));
  }

  action reason_phrase {
    if(parser->reason_phrase != NULL)
      parser->reason_phrase(parser->data, PTR_TO(mark), LEN(mark,fpc));
  }

  action done { 
    parser->body_start = fpc - buffer + 1; 
    if(parser->header_done != NULL)
      parser->header_done(parser->data, fpc + 1, pe - fpc - 1);
    fbreak;
  }

#### HTTP PROTOCOL GRAMMAR
# line endings
  CRLF = "\r\n";

# character types
  CTL = (cntrl | 127);
  tspecials = ("(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\\" | "\"" | "/" | "[" | "]" | "?" | "=" | "{" | "}" | " " | "\t");

# elements
  token = (ascii -- (CTL | tspecials));

  Reason_Phrase = ( ascii -- ("\r" | "\n") )+ >mark %reason_phrase;

  Status_Code = ( digit+ ) >mark %status_code ;

  http_number = ( digit+ "." digit+ ) ;
  HTTP_Version = ( "HTTP/" http_number ) >mark %http_version ;

  Response_Line = ( HTTP_Version " " Status_Code " " Reason_Phrase CRLF ) ;

  field_name = ( token -- ":" )+ >start_field %write_field;

  field_value = any* >start_value %write_value;

  message_header = field_name ":" " "* field_value :> CRLF;

  Response = Response_Line ( message_header )* ( CRLF @done );

main := Response;

}%%

/** Data **/
%% write data;

int http_response_parser_init(http_response_parser *parser)  {
  int cs = 0;
  %% write init;
  parser->cs = cs;
  parser->body_start = 0;
  parser->content_len = 0;
  parser->mark = 0;
  parser->nread = 0;
  parser->field_len = 0;
  parser->field_start = 0;    

  return(1);
}


/** exec **/
size_t http_response_parser_execute(http_response_parser *parser, const signed char *buffer, size_t len, size_t off)  {
  const signed char *p, *pe;
  int cs = parser->cs;

  assert(off <= len && "offset past end of buffer");

  p = buffer + off;
  pe = buffer + len;

  %% write exec;

  if (!http_response_parser_has_error(parser))
    parser->cs = cs;
  parser->nread += p - (buffer + off);

  assert(p <= pe && "buffer overflow after parsing execute");
  assert(parser->nread <= len && "nread longer than length");
  assert(parser->body_start <= len && "body starts after buffer end");
  assert(parser->mark < len && "mark is after buffer end");
  assert(parser->field_len <= len && "field has length longer than whole buffer");
  assert(parser->field_start < len && "field starts after buffer end");

  return(parser->nread);
}

int http_response_parser_finish(http_response_parser *parser)
{
  if (http_response_parser_has_error(parser) ) {
    return -1;
  } else if (http_response_parser_is_finished(parser) ) {
    return 1;
  } else {
    return 0;
  }
}

int http_response_parser_has_error(http_response_parser *parser) {
  return parser->cs == http_response_parser_error;
}

int http_response_parser_is_finished(http_response_parser *parser) {
  return parser->cs >= http_response_parser_first_final;
}
