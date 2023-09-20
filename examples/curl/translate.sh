#!/bin/bash

# all option
./configure --with-bearssl --with-gnutls=/home/hanxj/gnutls-3.6.16/build
--with-mbedtls --with-mesalink=/home/hanxj/mesalink/build --with-nss-deprecated --with-openssl --with-rustls --with-wolfssl --with-gssapi --with-libssh2 --with-nghttp2 --enable-crypto-auth --enable-http --with-quiche=/home/hanxj/quiche/target/release --without-ngtcp2 --enable-debug--with-hyper=/home/hanxj/hyper --enable-ldap --enable-ares
intercept-build makec2rust transpile compile_commands.json -b main -o res
cd res
cargo build
cd ..

make clean
# rtsp.c libssh.c asyn_thread.c hostip4.c curl_des.c
./configure --with-mbedtls --without-ngtcp2 --with-libssh --disable-ares
--disable-ipv6
intercept-build makec2rust transpile compile_commands.json -b main -o res2
cd res2
cargo build

