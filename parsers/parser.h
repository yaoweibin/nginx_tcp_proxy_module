
#ifndef _NGX_TCP_PARSER_H_INCLUDED_
#define _NGX_TCP_PARSER_H_INCLUDED_

#include <sys/types.h>

/*HTTP parser*/
typedef void (*element_cb)(void *data, const signed char *at, size_t length);
typedef void (*field_cb)(void *data, const signed char *field, 
        size_t flen, const signed char *value, size_t vlen);


#endif //_NGX_TCP_PARSER_H_INCLUDED_
