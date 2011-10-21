#
#===============================================================================
#
#         FILE:  sample.t
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

=== TEST 1: the ssl command
--- config
    upstream test{
        server blog.163.com;
        ip_hash;
    }

    server {
        listen 1984 ssl;

        proxy_pass test;
    }
--- request_https
GET /
--- response_body_like: ^<(.*)>$
