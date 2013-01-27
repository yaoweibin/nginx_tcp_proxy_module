
# vi:filetype=perl

use lib 'lib';
use Test::Nginx::LWP;

plan tests => repeat_each() * 2 * blocks();

#no_diff;

run_tests();

__DATA__

=== TEST 1: test the default
--- config
 
    upstream bad_server{
       #unknown server
       server 127.0.0.1:5678;
    }

    upstream test{
        server blog.163.com;
        #ip_hash;
        check interval=3000 rise=1 fall=5 timeout=1000;
    }

    server {
        listen 1984;
        server_name foo.barzzzz.com;

        proxy_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        proxy_pass test;
    }
--- request
GET /
--- response_body_like: ^<(.*)>$

=== TEST 2: test the proxy_bind
--- config
 
    upstream test{
        server 127.0.0.1:1985;
    }

    server {
        listen 1985;
        server_name foo.barzzzz.com;

        proxy_pass www.taobao.com;
    }

    server {
        listen 1984 default;
        server_name www.taobao.com;

        proxy_bind 127.0.0.1;
        proxy_pass test;
    }
--- request_headers
Host: www.taobao.com
--- request
GET /
--- response_body_like: ^.*$

=== TEST 3: test the bad proxy_bind
--- config
 
    upstream test{
        server blog.163.com;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        proxy_bind 127.0.0.1;
        proxy_pass test;
    }
--- request
GET /
--- error_code: 500
--- response_body_like: ^.*$

