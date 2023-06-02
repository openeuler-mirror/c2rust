#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(c_variadic)]
#![feature(extern_types)]
#![feature(label_break_value)]
#![feature(register_tool)]
#![register_tool(c2rust)]
#![feature(rustc_private)]
#![feature(const_mut_refs)]
#![feature(const_fn_fn_ptr_basics)]


#[macro_use]
extern crate c2rust_bitfields;
extern crate libc;
pub mod src {
pub mod lib {
pub mod http2;
pub mod altsvc;
pub mod amigaos;
pub mod asyn_ares;
pub mod asyn_thread;
pub mod base64;
pub mod bufref;
pub mod c_hyper;
pub mod conncache;
pub mod connect;
pub mod content_encoding;
pub mod cookie;
pub mod curl_addrinfo;
pub mod curl_ctype;
pub mod curl_des;
pub mod curl_endian;
pub mod curl_fnmatch;
pub mod curl_get_line;
pub mod curl_gethostname;
pub mod curl_gssapi;
pub mod curl_memrchr;
pub mod curl_multibyte;
pub mod curl_ntlm_core;
pub mod curl_ntlm_wb;
pub mod curl_path;
pub mod curl_range;
pub mod curl_rtmp;
pub mod curl_sasl;
pub mod curl_sspi;
pub mod curl_threads;
pub mod dict;
pub mod doh;
pub mod dotdot;
pub mod dynbuf;
pub mod easy;
pub mod easygetopt;
pub mod easyoptions;
pub mod escape;
pub mod file;
pub mod fileinfo;
pub mod formdata;
pub mod ftp;
pub mod ftplistparser;
pub mod getenv;
pub mod getinfo;
pub mod gopher;
pub mod hash;
pub mod hmac;
pub mod hostasyn;
pub mod hostcheck;
pub mod hostip;
pub mod hostip4;
pub mod hostip6;
pub mod hostsyn;
pub mod hsts;
pub mod http;
pub mod http_aws_sigv4;
pub mod http_chunks;
pub mod http_digest;
pub mod http_negotiate;
pub mod http_ntlm;
pub mod http_proxy;
pub mod idn_win32;
pub mod if2ip;
pub mod imap;
pub mod inet_ntop;
pub mod inet_pton;
pub mod krb5;
pub mod ldap;
pub mod llist;
pub mod md4;
pub mod md5;
pub mod memdebug;
pub mod mime;
pub mod mprintf;
pub mod mqtt;
pub mod multi;
pub mod netrc;
pub mod non_ascii;
pub mod nonblock;
pub mod openldap;
pub mod parsedate;
pub mod pingpong;
pub mod pop3;
pub mod progress;
pub mod psl;
pub mod rand;
pub mod rename;
pub mod rtsp;
pub mod select;
pub mod sendf;
pub mod setopt;
pub mod sha256;
pub mod share;
pub mod slist;
pub mod smb;
pub mod smtp;
pub mod socketpair;
pub mod socks;
pub mod socks_gssapi;
pub mod socks_sspi;
pub mod speedcheck;
pub mod splay;
pub mod strcase;
pub mod strdup;
pub mod strerror;
pub mod strtok;
pub mod strtoofft;
pub mod system_win32;
pub mod telnet;
pub mod tftp;
pub mod timeval;
pub mod transfer;
pub mod url;
pub mod urlapi;
pub mod vauth {
pub mod cleartext;
pub mod cram;
pub mod digest;
pub mod digest_sspi;
pub mod gsasl;
pub mod krb5_gssapi;
pub mod krb5_sspi;
pub mod ntlm;
pub mod ntlm_sspi;
pub mod oauth2;
pub mod spnego_gssapi;
pub mod spnego_sspi;
pub mod vauth;
} // mod vauth
pub mod version;
pub mod version_win32;
pub mod vquic {
pub mod ngtcp2;
pub mod quiche;
pub mod vquic;
} // mod vquic
pub mod vssh {
pub mod libssh;
pub mod libssh2;
pub mod wolfssh;
} // mod vssh
pub mod vtls {
pub mod bearssl;
pub mod gskit;
pub mod gtls;
pub mod keylog;
pub mod mbedtls;
pub mod mbedtls_threadlock;
pub mod mesalink;
pub mod nss;
pub mod openssl;
pub mod rustls;
pub mod schannel;
pub mod schannel_verify;
pub mod sectransp;
pub mod vtls;
pub mod wolfssl;
} // mod vtls
pub mod warnless;
pub mod wildcard;
pub mod x509asn1;
} // mod lib
pub mod src {
pub mod slist_wc;
pub mod tool_binmode;
pub mod tool_bname;
pub mod tool_cb_dbg;
pub mod tool_cb_hdr;
pub mod tool_cb_prg;
pub mod tool_cb_rea;
pub mod tool_cb_see;
pub mod tool_cb_wrt;
pub mod tool_cfgable;
pub mod tool_convert;
pub mod tool_dirhie;
pub mod tool_doswin;
pub mod tool_easysrc;
pub mod tool_filetime;
pub mod tool_formparse;
pub mod tool_getparam;
pub mod tool_getpass;
pub mod tool_help;
pub mod tool_helpers;
pub mod tool_homedir;
pub mod tool_hugehelp;
pub mod tool_libinfo;
pub mod tool_main;
pub mod tool_msgs;
pub mod tool_operate;
pub mod tool_operhlp;
pub mod tool_panykey;
pub mod tool_paramhlp;
pub mod tool_parsecfg;
pub mod tool_progress;
pub mod tool_setopt;
pub mod tool_sleep;
pub mod tool_strdup;
pub mod tool_urlglob;
pub mod tool_util;
pub mod tool_vms;
pub mod tool_writeout;
pub mod tool_writeout_json;
pub mod tool_xattr;
} // mod src
} // mod src
