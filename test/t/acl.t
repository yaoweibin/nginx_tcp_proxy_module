#
#===============================================================================
#
#         FILE:  acl.t
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

=== TEST 1: test ACL
--- config
    upstream test{
        server blog.163.com;
    }

    server {
        deny 127.0.0.1;

        listen 1984;

        proxy_pass test;
    }
--- request
GET /
--- error_code: 500
--- response_body_like: ^.*$

=== TEST 2: test ACL without anything
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
--- response_body_like: ^.*$

=== TEST 3: test ACL witht other ip
--- config
    upstream test{
        server blog.163.com;
    }

    server {
        deny 10.231.143.122;
        listen 1984;

        server_name _;

        tcp_nodelay on;
        so_keepalive on;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^.*$
