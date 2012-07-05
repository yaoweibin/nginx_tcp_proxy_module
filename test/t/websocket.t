
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

=== TEST 2: test the server_name
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

        websocket_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass test;
    }
--- request_headers
Host: foo.barzzzz.com
--- request
GET /
--- error_code: 500
--- response_body_like: ^.*$

=== TEST 3: test the default server_name
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

        websocket_pass ws://bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass ws://test;
    }
--- request_headers
Host: foo.barzzzzoo.com
--- request
GET /
--- response_body_like: ^.*$

=== TEST 4: test the default path
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

        websocket_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass test;
        websocket_pass /bad bad_server;
        websocket_pass /public test;
    }
--- request
GET /404
--- error_code: 404
--- response_body_like: ^.*$

=== TEST 5: test the bad path
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

        websocket_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass test;
        websocket_pass /bad bad_server;
        websocket_pass /public test;
    }
--- request
GET /bad
--- error_code: 500
--- response_body_like: ^.*$

=== TEST 6: test the good path
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

        websocket_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass test;
        websocket_pass /bad bad_server;
        websocket_pass /public test;
    }
--- request_headers
Host: blog.163.com
--- request
GET /public/theme
--- error_code: 200
--- response_body_like: ^.*$

=== TEST 7: test the unknow path
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

        websocket_pass bad_server;
    }

    server {
        listen 1984 default;
        server_name blog.163.com;

        websocket_pass / bad_server;
        websocket_pass /bad bad_server;
        websocket_pass /public test;
    }
--- request_headers
Host: blog.163.com
--- request
GET /hoho
--- error_code: 500
--- response_body_like: ^.*$
