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
        server 172.19.0.129;
        server 172.19.0.130;
        server 172.19.0.131;
        server 172.19.0.132;
        server 172.19.0.235;
        server 172.19.0.236;
        server 172.19.0.237;
        server 172.19.0.238;
        server 172.19.0.239;
        #ip_hash;
    }

    server {
        deny 127.0.0.1;

        listen 1982;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$
