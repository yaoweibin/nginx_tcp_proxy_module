#
#===============================================================================
#
#         FILE:  tcp_check.t
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

=== TEST 1: the tcp_check test
--- config
    upstream test{
        server blog.163.com;
        #ip_hash;
        check interval=3000 rise=1 fall=5 timeout=1000;
    }

    server {
        listen 1984;

        protocol tcp_generic;
        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$

=== TEST 2: the round robin test without check
--- config
    upstream test{
        server blog.163.com;
    }

    server {
        listen 1984;
        #server_names a.b.c d.e.f;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$

=== TEST 3: the ip_hash test without check
--- config
    upstream test{
        server blog.163.com;
        ip_hash;
    }

    server {
        listen 1984;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$
