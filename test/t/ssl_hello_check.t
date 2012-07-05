#
#===============================================================================
#
#         FILE:  ssl_hello_check.t
#
#  DESCRIPTION: test 
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Weibin Yao (http://yaoweibin.cn/), yaoweibin@gmail.com
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  03/02/2010 03:18:28 PM
#     REVISION:  ---
#===============================================================================


# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: the ssl_hello_check test
--- config
    upstream test{
        server www.varnish-cache.org:443;

        #ip_hash;
        check interval=3000 rise=1 fall=5 timeout=1000 type=ssl_hello;
    }

    server {
        listen 1984;

        proxy_pass test;
    }
--- request_https
GET /
--- response_body_like: ^.*$
