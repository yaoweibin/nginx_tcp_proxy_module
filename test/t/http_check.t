#
#===============================================================================
#
#         FILE:  http_check.t
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

=== TEST 1: the http_check test
--- config
    upstream test{
        server blog.163.com;

        check interval=3000 rise=1 fall=5 timeout=1000 type=http;
        check_http_send "GET /test HTTP/1.0\r\n\r\n";
        check_http_expect_alive http_2xx http_3xx http_4xx;
    }

    server {
        listen 1984;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$

=== TEST 2: the http_check test without check
--- config
    upstream test{
        server blog.163.com;
    }

    server {
        listen 1984;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$

=== TEST 3: the http_check which use the raw name 
--- config
    upstream test{
        server blog.163.com;

        check interval=3000 rise=1 fall=5 timeout=1000 type=http;
        check_http_send "GET /test HTTP/1.0\r\n\r\n";
        check_http_expect_alive http_2xx http_3xx http_4xx;
    }

    server {
        listen 1984;

        proxy_pass blog.163.com;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$
