use ::libc;
extern "C" {
    
    
    
    
    
    
    
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn __ctype_b_loc() -> *mut *const u16;
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::setopt::curl_easy_setopt;
pub use crate::src::src::tool_easysrc::easysrc_add;
pub use crate::src::src::tool_easysrc::easysrc_addf;
pub use crate::src::lib::altsvc::Curl_easy;
pub use crate::src::lib::altsvc::curl_mime;
pub use crate::src::src::slist_wc::slist_wc;
pub use crate::src::lib::imap::_IO_marker;
pub use crate::src::lib::speedcheck::_IO_codecvt;
pub use crate::src::lib::vtls::vtls::_IO_wide_data;
pub use crate::src::src::tool_easysrc::easysrc_clean;
pub use crate::src::src::tool_easysrc::easysrc_code;
pub use crate::src::src::tool_easysrc::easysrc_data;
pub use crate::src::src::tool_easysrc::easysrc_decl;
pub use crate::src::src::tool_easysrc::easysrc_mime_count;
pub use crate::src::src::tool_easysrc::easysrc_slist_count;
pub use crate::src::src::tool_easysrc::easysrc_toohard;
pub type __builtin_va_list = crate::src::lib::dict::__builtin_va_list;
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::lib::dict::__va_list_tag;
pub type __off_t = crate::src::lib::altsvc::__off_t;
pub type __off64_t = crate::src::lib::altsvc::__off64_t;
pub type size_t = crate::src::lib::altsvc::size_t;
pub type curl_off_t = crate::src::lib::altsvc::curl_off_t;
pub type va_list = crate::src::lib::dict::va_list;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::lib::altsvc::_IO_FILE;
pub type _IO_lock_t = crate::src::lib::altsvc::_IO_lock_t;
pub type FILE = crate::src::lib::altsvc::FILE;
pub type CURL = crate::src::lib::altsvc::CURL;
// #[derive(Copy, Clone)]

pub type curl_slist = crate::src::lib::altsvc::curl_slist;
pub type CURLcode = crate::src::lib::altsvc::CURLcode;
pub const CURL_LAST: CURLcode = 99;
pub const CURLE_SSL_CLIENTCERT: CURLcode = 98;
pub const CURLE_PROXY: CURLcode = 97;
pub const CURLE_QUIC_CONNECT_ERROR: CURLcode = 96;
pub const CURLE_HTTP3: CURLcode = 95;
pub const CURLE_AUTH_ERROR: CURLcode = 94;
pub const CURLE_RECURSIVE_API_CALL: CURLcode = 93;
pub const CURLE_HTTP2_STREAM: CURLcode = 92;
pub const CURLE_SSL_INVALIDCERTSTATUS: CURLcode = 91;
pub const CURLE_SSL_PINNEDPUBKEYNOTMATCH: CURLcode = 90;
pub const CURLE_NO_CONNECTION_AVAILABLE: CURLcode = 89;
pub const CURLE_CHUNK_FAILED: CURLcode = 88;
pub const CURLE_FTP_BAD_FILE_LIST: CURLcode = 87;
pub const CURLE_RTSP_SESSION_ERROR: CURLcode = 86;
pub const CURLE_RTSP_CSEQ_ERROR: CURLcode = 85;
pub const CURLE_FTP_PRET_FAILED: CURLcode = 84;
pub const CURLE_SSL_ISSUER_ERROR: CURLcode = 83;
pub const CURLE_SSL_CRL_BADFILE: CURLcode = 82;
pub const CURLE_AGAIN: CURLcode = 81;
pub const CURLE_SSL_SHUTDOWN_FAILED: CURLcode = 80;
pub const CURLE_SSH: CURLcode = 79;
pub const CURLE_REMOTE_FILE_NOT_FOUND: CURLcode = 78;
pub const CURLE_SSL_CACERT_BADFILE: CURLcode = 77;
pub const CURLE_CONV_REQD: CURLcode = 76;
pub const CURLE_CONV_FAILED: CURLcode = 75;
pub const CURLE_TFTP_NOSUCHUSER: CURLcode = 74;
pub const CURLE_REMOTE_FILE_EXISTS: CURLcode = 73;
pub const CURLE_TFTP_UNKNOWNID: CURLcode = 72;
pub const CURLE_TFTP_ILLEGAL: CURLcode = 71;
pub const CURLE_REMOTE_DISK_FULL: CURLcode = 70;
pub const CURLE_TFTP_PERM: CURLcode = 69;
pub const CURLE_TFTP_NOTFOUND: CURLcode = 68;
pub const CURLE_LOGIN_DENIED: CURLcode = 67;
pub const CURLE_SSL_ENGINE_INITFAILED: CURLcode = 66;
pub const CURLE_SEND_FAIL_REWIND: CURLcode = 65;
pub const CURLE_USE_SSL_FAILED: CURLcode = 64;
pub const CURLE_FILESIZE_EXCEEDED: CURLcode = 63;
pub const CURLE_LDAP_INVALID_URL: CURLcode = 62;
pub const CURLE_BAD_CONTENT_ENCODING: CURLcode = 61;
pub const CURLE_PEER_FAILED_VERIFICATION: CURLcode = 60;
pub const CURLE_SSL_CIPHER: CURLcode = 59;
pub const CURLE_SSL_CERTPROBLEM: CURLcode = 58;
pub const CURLE_OBSOLETE57: CURLcode = 57;
pub const CURLE_RECV_ERROR: CURLcode = 56;
pub const CURLE_SEND_ERROR: CURLcode = 55;
pub const CURLE_SSL_ENGINE_SETFAILED: CURLcode = 54;
pub const CURLE_SSL_ENGINE_NOTFOUND: CURLcode = 53;
pub const CURLE_GOT_NOTHING: CURLcode = 52;
pub const CURLE_OBSOLETE51: CURLcode = 51;
pub const CURLE_OBSOLETE50: CURLcode = 50;
pub const CURLE_SETOPT_OPTION_SYNTAX: CURLcode = 49;
pub const CURLE_UNKNOWN_OPTION: CURLcode = 48;
pub const CURLE_TOO_MANY_REDIRECTS: CURLcode = 47;
pub const CURLE_OBSOLETE46: CURLcode = 46;
pub const CURLE_INTERFACE_FAILED: CURLcode = 45;
pub const CURLE_OBSOLETE44: CURLcode = 44;
pub const CURLE_BAD_FUNCTION_ARGUMENT: CURLcode = 43;
pub const CURLE_ABORTED_BY_CALLBACK: CURLcode = 42;
pub const CURLE_FUNCTION_NOT_FOUND: CURLcode = 41;
pub const CURLE_OBSOLETE40: CURLcode = 40;
pub const CURLE_LDAP_SEARCH_FAILED: CURLcode = 39;
pub const CURLE_LDAP_CANNOT_BIND: CURLcode = 38;
pub const CURLE_FILE_COULDNT_READ_FILE: CURLcode = 37;
pub const CURLE_BAD_DOWNLOAD_RESUME: CURLcode = 36;
pub const CURLE_SSL_CONNECT_ERROR: CURLcode = 35;
pub const CURLE_HTTP_POST_ERROR: CURLcode = 34;
pub const CURLE_RANGE_ERROR: CURLcode = 33;
pub const CURLE_OBSOLETE32: CURLcode = 32;
pub const CURLE_FTP_COULDNT_USE_REST: CURLcode = 31;
pub const CURLE_FTP_PORT_FAILED: CURLcode = 30;
pub const CURLE_OBSOLETE29: CURLcode = 29;
pub const CURLE_OPERATION_TIMEDOUT: CURLcode = 28;
pub const CURLE_OUT_OF_MEMORY: CURLcode = 27;
pub const CURLE_READ_ERROR: CURLcode = 26;
pub const CURLE_UPLOAD_FAILED: CURLcode = 25;
pub const CURLE_OBSOLETE24: CURLcode = 24;
pub const CURLE_WRITE_ERROR: CURLcode = 23;
pub const CURLE_HTTP_RETURNED_ERROR: CURLcode = 22;
pub const CURLE_QUOTE_ERROR: CURLcode = 21;
pub const CURLE_OBSOLETE20: CURLcode = 20;
pub const CURLE_FTP_COULDNT_RETR_FILE: CURLcode = 19;
pub const CURLE_PARTIAL_FILE: CURLcode = 18;
pub const CURLE_FTP_COULDNT_SET_TYPE: CURLcode = 17;
pub const CURLE_HTTP2: CURLcode = 16;
pub const CURLE_FTP_CANT_GET_HOST: CURLcode = 15;
pub const CURLE_FTP_WEIRD_227_FORMAT: CURLcode = 14;
pub const CURLE_FTP_WEIRD_PASV_REPLY: CURLcode = 13;
pub const CURLE_FTP_ACCEPT_TIMEOUT: CURLcode = 12;
pub const CURLE_FTP_WEIRD_PASS_REPLY: CURLcode = 11;
pub const CURLE_FTP_ACCEPT_FAILED: CURLcode = 10;
pub const CURLE_REMOTE_ACCESS_DENIED: CURLcode = 9;
pub const CURLE_WEIRD_SERVER_REPLY: CURLcode = 8;
pub const CURLE_COULDNT_CONNECT: CURLcode = 7;
pub const CURLE_COULDNT_RESOLVE_HOST: CURLcode = 6;
pub const CURLE_COULDNT_RESOLVE_PROXY: CURLcode = 5;
pub const CURLE_NOT_BUILT_IN: CURLcode = 4;
pub const CURLE_URL_MALFORMAT: CURLcode = 3;
pub const CURLE_FAILED_INIT: CURLcode = 2;
pub const CURLE_UNSUPPORTED_PROTOCOL: CURLcode = 1;
pub const CURLE_OK: CURLcode = 0;
pub type C2RustUnnamed = u32;
pub const CURLPROXY_SOCKS5_HOSTNAME: C2RustUnnamed = 7;
pub const CURLPROXY_SOCKS4A: C2RustUnnamed = 6;
pub const CURLPROXY_SOCKS5: C2RustUnnamed = 5;
pub const CURLPROXY_SOCKS4: C2RustUnnamed = 4;
pub const CURLPROXY_HTTPS: C2RustUnnamed = 2;
pub const CURLPROXY_HTTP_1_0: C2RustUnnamed = 1;
pub const CURLPROXY_HTTP: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = u32;
pub const CURLUSESSL_LAST: C2RustUnnamed_0 = 4;
pub const CURLUSESSL_ALL: C2RustUnnamed_0 = 3;
pub const CURLUSESSL_CONTROL: C2RustUnnamed_0 = 2;
pub const CURLUSESSL_TRY: C2RustUnnamed_0 = 1;
pub const CURLUSESSL_NONE: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = u32;
pub const CURLFTPSSL_CCC_LAST: C2RustUnnamed_1 = 3;
pub const CURLFTPSSL_CCC_ACTIVE: C2RustUnnamed_1 = 2;
pub const CURLFTPSSL_CCC_PASSIVE: C2RustUnnamed_1 = 1;
pub const CURLFTPSSL_CCC_NONE: C2RustUnnamed_1 = 0;
pub type CURLoption = crate::src::lib::doh::CURLoption;
pub const CURLOPT_LASTENTRY: CURLoption = 40311;
pub const CURLOPT_PROXY_CAINFO_BLOB: CURLoption = 40310;
pub const CURLOPT_CAINFO_BLOB: CURLoption = 40309;
pub const CURLOPT_DOH_SSL_VERIFYSTATUS: CURLoption = 308;
pub const CURLOPT_DOH_SSL_VERIFYHOST: CURLoption = 307;
pub const CURLOPT_DOH_SSL_VERIFYPEER: CURLoption = 306;
pub const CURLOPT_AWS_SIGV4: CURLoption = 10305;
pub const CURLOPT_HSTSWRITEDATA: CURLoption = 10304;
pub const CURLOPT_HSTSWRITEFUNCTION: CURLoption = 20303;
pub const CURLOPT_HSTSREADDATA: CURLoption = 10302;
pub const CURLOPT_HSTSREADFUNCTION: CURLoption = 20301;
pub const CURLOPT_HSTS: CURLoption = 10300;
pub const CURLOPT_HSTS_CTRL: CURLoption = 299;
pub const CURLOPT_SSL_EC_CURVES: CURLoption = 10298;
pub const CURLOPT_PROXY_ISSUERCERT_BLOB: CURLoption = 40297;
pub const CURLOPT_PROXY_ISSUERCERT: CURLoption = 10296;
pub const CURLOPT_ISSUERCERT_BLOB: CURLoption = 40295;
pub const CURLOPT_PROXY_SSLKEY_BLOB: CURLoption = 40294;
pub const CURLOPT_PROXY_SSLCERT_BLOB: CURLoption = 40293;
pub const CURLOPT_SSLKEY_BLOB: CURLoption = 40292;
pub const CURLOPT_SSLCERT_BLOB: CURLoption = 40291;
pub const CURLOPT_MAIL_RCPT_ALLLOWFAILS: CURLoption = 290;
pub const CURLOPT_SASL_AUTHZID: CURLoption = 10289;
pub const CURLOPT_MAXAGE_CONN: CURLoption = 288;
pub const CURLOPT_ALTSVC: CURLoption = 10287;
pub const CURLOPT_ALTSVC_CTRL: CURLoption = 286;
pub const CURLOPT_HTTP09_ALLOWED: CURLoption = 285;
pub const CURLOPT_TRAILERDATA: CURLoption = 10284;
pub const CURLOPT_TRAILERFUNCTION: CURLoption = 20283;
pub const CURLOPT_CURLU: CURLoption = 10282;
pub const CURLOPT_UPKEEP_INTERVAL_MS: CURLoption = 281;
pub const CURLOPT_UPLOAD_BUFFERSIZE: CURLoption = 280;
pub const CURLOPT_DOH_URL: CURLoption = 10279;
pub const CURLOPT_DISALLOW_USERNAME_IN_URL: CURLoption = 278;
pub const CURLOPT_PROXY_TLS13_CIPHERS: CURLoption = 10277;
pub const CURLOPT_TLS13_CIPHERS: CURLoption = 10276;
pub const CURLOPT_DNS_SHUFFLE_ADDRESSES: CURLoption = 275;
pub const CURLOPT_HAPROXYPROTOCOL: CURLoption = 274;
pub const CURLOPT_RESOLVER_START_DATA: CURLoption = 10273;
pub const CURLOPT_RESOLVER_START_FUNCTION: CURLoption = 20272;
pub const CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS: CURLoption = 271;
pub const CURLOPT_TIMEVALUE_LARGE: CURLoption = 30270;
pub const CURLOPT_MIMEPOST: CURLoption = 10269;
pub const CURLOPT_SSH_COMPRESSION: CURLoption = 268;
pub const CURLOPT_SOCKS5_AUTH: CURLoption = 267;
pub const CURLOPT_REQUEST_TARGET: CURLoption = 10266;
pub const CURLOPT_SUPPRESS_CONNECT_HEADERS: CURLoption = 265;
pub const CURLOPT_ABSTRACT_UNIX_SOCKET: CURLoption = 10264;
pub const CURLOPT_PROXY_PINNEDPUBLICKEY: CURLoption = 10263;
pub const CURLOPT_PRE_PROXY: CURLoption = 10262;
pub const CURLOPT_PROXY_SSL_OPTIONS: CURLoption = 261;
pub const CURLOPT_PROXY_CRLFILE: CURLoption = 10260;
pub const CURLOPT_PROXY_SSL_CIPHER_LIST: CURLoption = 10259;
pub const CURLOPT_PROXY_KEYPASSWD: CURLoption = 10258;
pub const CURLOPT_PROXY_SSLKEYTYPE: CURLoption = 10257;
pub const CURLOPT_PROXY_SSLKEY: CURLoption = 10256;
pub const CURLOPT_PROXY_SSLCERTTYPE: CURLoption = 10255;
pub const CURLOPT_PROXY_SSLCERT: CURLoption = 10254;
pub const CURLOPT_PROXY_TLSAUTH_TYPE: CURLoption = 10253;
pub const CURLOPT_PROXY_TLSAUTH_PASSWORD: CURLoption = 10252;
pub const CURLOPT_PROXY_TLSAUTH_USERNAME: CURLoption = 10251;
pub const CURLOPT_PROXY_SSLVERSION: CURLoption = 250;
pub const CURLOPT_PROXY_SSL_VERIFYHOST: CURLoption = 249;
pub const CURLOPT_PROXY_SSL_VERIFYPEER: CURLoption = 248;
pub const CURLOPT_PROXY_CAPATH: CURLoption = 10247;
pub const CURLOPT_PROXY_CAINFO: CURLoption = 10246;
pub const CURLOPT_KEEP_SENDING_ON_ERROR: CURLoption = 245;
pub const CURLOPT_TCP_FASTOPEN: CURLoption = 244;
pub const CURLOPT_CONNECT_TO: CURLoption = 10243;
pub const CURLOPT_TFTP_NO_OPTIONS: CURLoption = 242;
pub const CURLOPT_STREAM_DEPENDS_E: CURLoption = 10241;
pub const CURLOPT_STREAM_DEPENDS: CURLoption = 10240;
pub const CURLOPT_STREAM_WEIGHT: CURLoption = 239;
pub const CURLOPT_DEFAULT_PROTOCOL: CURLoption = 10238;
pub const CURLOPT_PIPEWAIT: CURLoption = 237;
pub const CURLOPT_SERVICE_NAME: CURLoption = 10236;
pub const CURLOPT_PROXY_SERVICE_NAME: CURLoption = 10235;
pub const CURLOPT_PATH_AS_IS: CURLoption = 234;
pub const CURLOPT_SSL_FALSESTART: CURLoption = 233;
pub const CURLOPT_SSL_VERIFYSTATUS: CURLoption = 232;
pub const CURLOPT_UNIX_SOCKET_PATH: CURLoption = 10231;
pub const CURLOPT_PINNEDPUBLICKEY: CURLoption = 10230;
pub const CURLOPT_HEADEROPT: CURLoption = 229;
pub const CURLOPT_PROXYHEADER: CURLoption = 10228;
pub const CURLOPT_EXPECT_100_TIMEOUT_MS: CURLoption = 227;
pub const CURLOPT_SSL_ENABLE_ALPN: CURLoption = 226;
pub const CURLOPT_SSL_ENABLE_NPN: CURLoption = 225;
pub const CURLOPT_LOGIN_OPTIONS: CURLoption = 10224;
pub const CURLOPT_DNS_LOCAL_IP6: CURLoption = 10223;
pub const CURLOPT_DNS_LOCAL_IP4: CURLoption = 10222;
pub const CURLOPT_DNS_INTERFACE: CURLoption = 10221;
pub const CURLOPT_XOAUTH2_BEARER: CURLoption = 10220;
pub const CURLOPT_XFERINFOFUNCTION: CURLoption = 20219;
pub const CURLOPT_SASL_IR: CURLoption = 218;
pub const CURLOPT_MAIL_AUTH: CURLoption = 10217;
pub const CURLOPT_SSL_OPTIONS: CURLoption = 216;
pub const CURLOPT_TCP_KEEPINTVL: CURLoption = 215;
pub const CURLOPT_TCP_KEEPIDLE: CURLoption = 214;
pub const CURLOPT_TCP_KEEPALIVE: CURLoption = 213;
pub const CURLOPT_ACCEPTTIMEOUT_MS: CURLoption = 212;
pub const CURLOPT_DNS_SERVERS: CURLoption = 10211;
pub const CURLOPT_GSSAPI_DELEGATION: CURLoption = 210;
pub const CURLOPT_CLOSESOCKETDATA: CURLoption = 10209;
pub const CURLOPT_CLOSESOCKETFUNCTION: CURLoption = 20208;
pub const CURLOPT_TRANSFER_ENCODING: CURLoption = 207;
pub const CURLOPT_TLSAUTH_TYPE: CURLoption = 10206;
pub const CURLOPT_TLSAUTH_PASSWORD: CURLoption = 10205;
pub const CURLOPT_TLSAUTH_USERNAME: CURLoption = 10204;
pub const CURLOPT_RESOLVE: CURLoption = 10203;
pub const CURLOPT_FNMATCH_DATA: CURLoption = 10202;
pub const CURLOPT_CHUNK_DATA: CURLoption = 10201;
pub const CURLOPT_FNMATCH_FUNCTION: CURLoption = 20200;
pub const CURLOPT_CHUNK_END_FUNCTION: CURLoption = 20199;
pub const CURLOPT_CHUNK_BGN_FUNCTION: CURLoption = 20198;
pub const CURLOPT_WILDCARDMATCH: CURLoption = 197;
pub const CURLOPT_INTERLEAVEFUNCTION: CURLoption = 20196;
pub const CURLOPT_INTERLEAVEDATA: CURLoption = 10195;
pub const CURLOPT_RTSP_SERVER_CSEQ: CURLoption = 194;
pub const CURLOPT_RTSP_CLIENT_CSEQ: CURLoption = 193;
pub const CURLOPT_RTSP_TRANSPORT: CURLoption = 10192;
pub const CURLOPT_RTSP_STREAM_URI: CURLoption = 10191;
pub const CURLOPT_RTSP_SESSION_ID: CURLoption = 10190;
pub const CURLOPT_RTSP_REQUEST: CURLoption = 189;
pub const CURLOPT_FTP_USE_PRET: CURLoption = 188;
pub const CURLOPT_MAIL_RCPT: CURLoption = 10187;
pub const CURLOPT_MAIL_FROM: CURLoption = 10186;
pub const CURLOPT_SSH_KEYDATA: CURLoption = 10185;
pub const CURLOPT_SSH_KEYFUNCTION: CURLoption = 20184;
pub const CURLOPT_SSH_KNOWNHOSTS: CURLoption = 10183;
pub const CURLOPT_REDIR_PROTOCOLS: CURLoption = 182;
pub const CURLOPT_PROTOCOLS: CURLoption = 181;
pub const CURLOPT_SOCKS5_GSSAPI_NEC: CURLoption = 180;
pub const CURLOPT_SOCKS5_GSSAPI_SERVICE: CURLoption = 10179;
pub const CURLOPT_TFTP_BLKSIZE: CURLoption = 178;
pub const CURLOPT_NOPROXY: CURLoption = 10177;
pub const CURLOPT_PROXYPASSWORD: CURLoption = 10176;
pub const CURLOPT_PROXYUSERNAME: CURLoption = 10175;
pub const CURLOPT_PASSWORD: CURLoption = 10174;
pub const CURLOPT_USERNAME: CURLoption = 10173;
pub const CURLOPT_CERTINFO: CURLoption = 172;
pub const CURLOPT_ADDRESS_SCOPE: CURLoption = 171;
pub const CURLOPT_ISSUERCERT: CURLoption = 10170;
pub const CURLOPT_CRLFILE: CURLoption = 10169;
pub const CURLOPT_SEEKDATA: CURLoption = 10168;
pub const CURLOPT_SEEKFUNCTION: CURLoption = 20167;
pub const CURLOPT_PROXY_TRANSFER_MODE: CURLoption = 166;
pub const CURLOPT_COPYPOSTFIELDS: CURLoption = 10165;
pub const CURLOPT_OPENSOCKETDATA: CURLoption = 10164;
pub const CURLOPT_OPENSOCKETFUNCTION: CURLoption = 20163;
pub const CURLOPT_SSH_HOST_PUBLIC_KEY_MD5: CURLoption = 10162;
pub const CURLOPT_POSTREDIR: CURLoption = 161;
pub const CURLOPT_NEW_DIRECTORY_PERMS: CURLoption = 160;
pub const CURLOPT_NEW_FILE_PERMS: CURLoption = 159;
pub const CURLOPT_HTTP_CONTENT_DECODING: CURLoption = 158;
pub const CURLOPT_HTTP_TRANSFER_DECODING: CURLoption = 157;
pub const CURLOPT_CONNECTTIMEOUT_MS: CURLoption = 156;
pub const CURLOPT_TIMEOUT_MS: CURLoption = 155;
pub const CURLOPT_FTP_SSL_CCC: CURLoption = 154;
pub const CURLOPT_SSH_PRIVATE_KEYFILE: CURLoption = 10153;
pub const CURLOPT_SSH_PUBLIC_KEYFILE: CURLoption = 10152;
pub const CURLOPT_SSH_AUTH_TYPES: CURLoption = 151;
pub const CURLOPT_SSL_SESSIONID_CACHE: CURLoption = 150;
pub const CURLOPT_SOCKOPTDATA: CURLoption = 10149;
pub const CURLOPT_SOCKOPTFUNCTION: CURLoption = 20148;
pub const CURLOPT_FTP_ALTERNATIVE_TO_USER: CURLoption = 10147;
pub const CURLOPT_MAX_RECV_SPEED_LARGE: CURLoption = 30146;
pub const CURLOPT_MAX_SEND_SPEED_LARGE: CURLoption = 30145;
pub const CURLOPT_CONV_FROM_UTF8_FUNCTION: CURLoption = 20144;
pub const CURLOPT_CONV_TO_NETWORK_FUNCTION: CURLoption = 20143;
pub const CURLOPT_CONV_FROM_NETWORK_FUNCTION: CURLoption = 20142;
pub const CURLOPT_CONNECT_ONLY: CURLoption = 141;
pub const CURLOPT_LOCALPORTRANGE: CURLoption = 140;
pub const CURLOPT_LOCALPORT: CURLoption = 139;
pub const CURLOPT_FTP_FILEMETHOD: CURLoption = 138;
pub const CURLOPT_FTP_SKIP_PASV_IP: CURLoption = 137;
pub const CURLOPT_IGNORE_CONTENT_LENGTH: CURLoption = 136;
pub const CURLOPT_COOKIELIST: CURLoption = 10135;
pub const CURLOPT_FTP_ACCOUNT: CURLoption = 10134;
pub const CURLOPT_IOCTLDATA: CURLoption = 10131;
pub const CURLOPT_IOCTLFUNCTION: CURLoption = 20130;
pub const CURLOPT_FTPSSLAUTH: CURLoption = 129;
pub const CURLOPT_TCP_NODELAY: CURLoption = 121;
pub const CURLOPT_POSTFIELDSIZE_LARGE: CURLoption = 30120;
pub const CURLOPT_USE_SSL: CURLoption = 119;
pub const CURLOPT_NETRC_FILE: CURLoption = 10118;
pub const CURLOPT_MAXFILESIZE_LARGE: CURLoption = 30117;
pub const CURLOPT_RESUME_FROM_LARGE: CURLoption = 30116;
pub const CURLOPT_INFILESIZE_LARGE: CURLoption = 30115;
pub const CURLOPT_MAXFILESIZE: CURLoption = 114;
pub const CURLOPT_IPRESOLVE: CURLoption = 113;
pub const CURLOPT_FTP_RESPONSE_TIMEOUT: CURLoption = 112;
pub const CURLOPT_PROXYAUTH: CURLoption = 111;
pub const CURLOPT_FTP_CREATE_MISSING_DIRS: CURLoption = 110;
pub const CURLOPT_SSL_CTX_DATA: CURLoption = 10109;
pub const CURLOPT_SSL_CTX_FUNCTION: CURLoption = 20108;
pub const CURLOPT_HTTPAUTH: CURLoption = 107;
pub const CURLOPT_FTP_USE_EPRT: CURLoption = 106;
pub const CURLOPT_UNRESTRICTED_AUTH: CURLoption = 105;
pub const CURLOPT_HTTP200ALIASES: CURLoption = 10104;
pub const CURLOPT_PRIVATE: CURLoption = 10103;
pub const CURLOPT_ACCEPT_ENCODING: CURLoption = 10102;
pub const CURLOPT_PROXYTYPE: CURLoption = 101;
pub const CURLOPT_SHARE: CURLoption = 10100;
pub const CURLOPT_NOSIGNAL: CURLoption = 99;
pub const CURLOPT_BUFFERSIZE: CURLoption = 98;
pub const CURLOPT_CAPATH: CURLoption = 10097;
pub const CURLOPT_COOKIESESSION: CURLoption = 96;
pub const CURLOPT_DEBUGDATA: CURLoption = 10095;
pub const CURLOPT_DEBUGFUNCTION: CURLoption = 20094;
pub const CURLOPT_PREQUOTE: CURLoption = 10093;
pub const CURLOPT_DNS_CACHE_TIMEOUT: CURLoption = 92;
pub const CURLOPT_DNS_USE_GLOBAL_CACHE: CURLoption = 91;
pub const CURLOPT_SSLENGINE_DEFAULT: CURLoption = 90;
pub const CURLOPT_SSLENGINE: CURLoption = 10089;
pub const CURLOPT_SSLKEYTYPE: CURLoption = 10088;
pub const CURLOPT_SSLKEY: CURLoption = 10087;
pub const CURLOPT_SSLCERTTYPE: CURLoption = 10086;
pub const CURLOPT_FTP_USE_EPSV: CURLoption = 85;
pub const CURLOPT_HTTP_VERSION: CURLoption = 84;
pub const CURLOPT_SSL_CIPHER_LIST: CURLoption = 10083;
pub const CURLOPT_COOKIEJAR: CURLoption = 10082;
pub const CURLOPT_SSL_VERIFYHOST: CURLoption = 81;
pub const CURLOPT_HTTPGET: CURLoption = 80;
pub const CURLOPT_HEADERFUNCTION: CURLoption = 20079;
pub const CURLOPT_CONNECTTIMEOUT: CURLoption = 78;
pub const CURLOPT_EGDSOCKET: CURLoption = 10077;
pub const CURLOPT_RANDOM_FILE: CURLoption = 10076;
pub const CURLOPT_FORBID_REUSE: CURLoption = 75;
pub const CURLOPT_FRESH_CONNECT: CURLoption = 74;
pub const CURLOPT_OBSOLETE72: CURLoption = 72;
pub const CURLOPT_MAXCONNECTS: CURLoption = 71;
pub const CURLOPT_TELNETOPTIONS: CURLoption = 10070;
pub const CURLOPT_FILETIME: CURLoption = 69;
pub const CURLOPT_MAXREDIRS: CURLoption = 68;
pub const CURLOPT_CAINFO: CURLoption = 10065;
pub const CURLOPT_SSL_VERIFYPEER: CURLoption = 64;
pub const CURLOPT_KRBLEVEL: CURLoption = 10063;
pub const CURLOPT_INTERFACE: CURLoption = 10062;
pub const CURLOPT_HTTPPROXYTUNNEL: CURLoption = 61;
pub const CURLOPT_POSTFIELDSIZE: CURLoption = 60;
pub const CURLOPT_PROXYPORT: CURLoption = 59;
pub const CURLOPT_AUTOREFERER: CURLoption = 58;
pub const CURLOPT_XFERINFODATA: CURLoption = 10057;
pub const CURLOPT_PROGRESSFUNCTION: CURLoption = 20056;
pub const CURLOPT_PUT: CURLoption = 54;
pub const CURLOPT_TRANSFERTEXT: CURLoption = 53;
pub const CURLOPT_FOLLOWLOCATION: CURLoption = 52;
pub const CURLOPT_NETRC: CURLoption = 51;
pub const CURLOPT_APPEND: CURLoption = 50;
pub const CURLOPT_DIRLISTONLY: CURLoption = 48;
pub const CURLOPT_POST: CURLoption = 47;
pub const CURLOPT_UPLOAD: CURLoption = 46;
pub const CURLOPT_FAILONERROR: CURLoption = 45;
pub const CURLOPT_NOBODY: CURLoption = 44;
pub const CURLOPT_NOPROGRESS: CURLoption = 43;
pub const CURLOPT_HEADER: CURLoption = 42;
pub const CURLOPT_VERBOSE: CURLoption = 41;
pub const CURLOPT_OBSOLETE40: CURLoption = 10040;
pub const CURLOPT_POSTQUOTE: CURLoption = 10039;
pub const CURLOPT_STDERR: CURLoption = 10037;
pub const CURLOPT_CUSTOMREQUEST: CURLoption = 10036;
pub const CURLOPT_TIMEVALUE: CURLoption = 34;
pub const CURLOPT_TIMECONDITION: CURLoption = 33;
pub const CURLOPT_SSLVERSION: CURLoption = 32;
pub const CURLOPT_COOKIEFILE: CURLoption = 10031;
pub const CURLOPT_HEADERDATA: CURLoption = 10029;
pub const CURLOPT_QUOTE: CURLoption = 10028;
pub const CURLOPT_CRLF: CURLoption = 27;
pub const CURLOPT_KEYPASSWD: CURLoption = 10026;
pub const CURLOPT_SSLCERT: CURLoption = 10025;
pub const CURLOPT_HTTPPOST: CURLoption = 10024;
pub const CURLOPT_HTTPHEADER: CURLoption = 10023;
pub const CURLOPT_COOKIE: CURLoption = 10022;
pub const CURLOPT_RESUME_FROM: CURLoption = 21;
pub const CURLOPT_LOW_SPEED_TIME: CURLoption = 20;
pub const CURLOPT_LOW_SPEED_LIMIT: CURLoption = 19;
pub const CURLOPT_USERAGENT: CURLoption = 10018;
pub const CURLOPT_FTPPORT: CURLoption = 10017;
pub const CURLOPT_REFERER: CURLoption = 10016;
pub const CURLOPT_POSTFIELDS: CURLoption = 10015;
pub const CURLOPT_INFILESIZE: CURLoption = 14;
pub const CURLOPT_TIMEOUT: CURLoption = 13;
pub const CURLOPT_READFUNCTION: CURLoption = 20012;
pub const CURLOPT_WRITEFUNCTION: CURLoption = 20011;
pub const CURLOPT_ERRORBUFFER: CURLoption = 10010;
pub const CURLOPT_READDATA: CURLoption = 10009;
pub const CURLOPT_RANGE: CURLoption = 10007;
pub const CURLOPT_PROXYUSERPWD: CURLoption = 10006;
pub const CURLOPT_USERPWD: CURLoption = 10005;
pub const CURLOPT_PROXY: CURLoption = 10004;
pub const CURLOPT_PORT: CURLoption = 3;
pub const CURLOPT_URL: CURLoption = 10002;
pub const CURLOPT_WRITEDATA: CURLoption = 10001;
pub type C2RustUnnamed_2 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_2 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_2 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_2 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_2 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_2 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_2 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_2 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_2 = 0;
pub type CURL_NETRC_OPTION = crate::src::lib::altsvc::CURL_NETRC_OPTION;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type C2RustUnnamed_3 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_3 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_3 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_3 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_3 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_3 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_3 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_3 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_3 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_3 = 0;
pub type curl_TimeCond = crate::src::lib::altsvc::curl_TimeCond;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
pub type C2RustUnnamed_4 = u32;
pub const _ISalnum: C2RustUnnamed_4 = 8;
pub const _ISpunct: C2RustUnnamed_4 = 4;
pub const _IScntrl: C2RustUnnamed_4 = 2;
pub const _ISblank: C2RustUnnamed_4 = 1;
pub const _ISgraph: C2RustUnnamed_4 = 32768;
pub const _ISprint: C2RustUnnamed_4 = 16384;
pub const _ISspace: C2RustUnnamed_4 = 8192;
pub const _ISxdigit: C2RustUnnamed_4 = 4096;
pub const _ISdigit: C2RustUnnamed_4 = 2048;
pub const _ISalpha: C2RustUnnamed_4 = 1024;
pub const _ISlower: C2RustUnnamed_4 = 512;
pub const _ISupper: C2RustUnnamed_4 = 256;
// #[derive(Copy, Clone)]

pub type OperationConfig = crate::src::src::tool_cb_dbg::OperationConfig;
// #[derive(Copy, Clone)]

pub type State = crate::src::src::tool_cb_dbg::State;
// #[derive(Copy, Clone)]

pub type URLGlob = crate::src::src::tool_cb_dbg::URLGlob;
// #[derive(Copy, Clone)]

pub type URLPattern = crate::src::src::tool_cb_dbg::URLPattern;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_5 = crate::src::src::tool_cb_dbg::C2RustUnnamed;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_6 = crate::src::src::tool_cb_dbg::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_7 = crate::src::src::tool_cb_dbg::C2RustUnnamed_1;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_8 = crate::src::src::tool_cb_dbg::C2RustUnnamed_2;
pub type URLPatternType = crate::src::src::tool_cb_dbg::URLPatternType;
pub const UPTNumRange: URLPatternType = 3;
pub const UPTCharRange: URLPatternType = 2;
pub const UPTSet: URLPatternType = 1;
// #[derive(Copy, Clone)]

pub type getout = crate::src::src::tool_cb_dbg::getout;
// #[derive(Copy, Clone)]

pub type GlobalConfig = crate::src::src::tool_cb_dbg::GlobalConfig;
pub type trace = crate::src::src::tool_cb_dbg::trace;
pub const TRACE_PLAIN: trace = 3;
pub const TRACE_ASCII: trace = 2;
pub const TRACE_BIN: trace = 1;
pub const TRACE_NONE: trace = 0;
pub type curl_error = crate::src::src::tool_cb_dbg::curl_error;
pub const ERR_LAST: curl_error = 2;
pub const ERR_BINARY_TERMINAL: curl_error = 1;
pub const ERR_NONE: curl_error = 0;
pub type HttpReq = crate::src::src::tool_cb_dbg::HttpReq;
pub const HTTPREQ_SIMPLEPOST: HttpReq = 4;
pub const HTTPREQ_MIMEPOST: HttpReq = 3;
pub const HTTPREQ_HEAD: HttpReq = 2;
pub const HTTPREQ_GET: HttpReq = 1;
pub const HTTPREQ_UNSPEC: HttpReq = 0;
// #[derive(Copy, Clone)]

pub type tool_mime = crate::src::src::tool_cb_dbg::tool_mime;
pub type toolmimekind = crate::src::src::tool_cb_dbg::toolmimekind;
pub const TOOLMIME_STDINDATA: toolmimekind = 6;
pub const TOOLMIME_STDIN: toolmimekind = 5;
pub const TOOLMIME_FILEDATA: toolmimekind = 4;
pub const TOOLMIME_FILE: toolmimekind = 3;
pub const TOOLMIME_DATA: toolmimekind = 2;
pub const TOOLMIME_PARTS: toolmimekind = 1;
pub const TOOLMIME_NONE: toolmimekind = 0;
// #[derive(Copy, Clone)]

pub type NameValue = crate::src::src::tool_operate::NameValue;
// #[derive(Copy, Clone)]

pub type NameValueUnsigned = crate::src::src::tool_operate::NameValueUnsigned;
#[no_mangle]
pub static mut setopt_nv_CURLPROXY: [NameValue; 8] = [
    {
        let mut init = NameValue {
            name: b"CURLPROXY_HTTP\0" as *const u8 as *const i8,
            value: CURLPROXY_HTTP as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_HTTP_1_0\0" as *const u8 as *const i8,
            value: CURLPROXY_HTTP_1_0 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_HTTPS\0" as *const u8 as *const i8,
            value: CURLPROXY_HTTPS as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS4\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS4 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS5\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS5 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS4A\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS4A as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS5_HOSTNAME\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS5_HOSTNAME as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURL_SOCKS_PROXY: [NameValue; 5] = [
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS4\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS4 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS5\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS5 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS4A\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS4A as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROXY_SOCKS5_HOSTNAME\0" as *const u8 as *const i8,
            value: CURLPROXY_SOCKS5_HOSTNAME as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLHSTS: [NameValueUnsigned; 2] = [
    {
        let mut init = NameValueUnsigned {
            name: b"CURLHSTS_ENABLE\0" as *const u8 as *const i8,
            value: ((1 as i32) << 0 as i32) as i64
                as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: 0 as *const i8,
            value: 0 as i32 as u64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLAUTH: [NameValueUnsigned; 11] = [
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_ANY\0" as *const u8 as *const i8,
            value: !((1 as i32 as u64) << 4 as i32),
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_ANYSAFE\0" as *const u8 as *const i8,
            value: !((1 as i32 as u64) << 0 as i32
                | (1 as i32 as u64) << 4 as i32),
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_BASIC\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 0 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_DIGEST\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 1 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_GSSNEGOTIATE\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 2 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_NTLM\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 3 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_DIGEST_IE\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 4 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_NTLM_WB\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 5 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_ONLY\0" as *const u8 as *const i8,
            value: (1 as i32 as u64) << 31 as i32,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLAUTH_NONE\0" as *const u8 as *const i8,
            value: 0 as i32 as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: 0 as *const i8,
            value: 0 as i32 as u64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURL_HTTP_VERSION: [NameValue; 7] = [
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_NONE\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_NONE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_1_0\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_1_0 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_1_1\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_1_1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_2_0\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_2_0 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_2TLS\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_2TLS as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_HTTP_VERSION_3\0" as *const u8 as *const i8,
            value: CURL_HTTP_VERSION_3 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURL_SSLVERSION: [NameValue; 9] = [
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_DEFAULT\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_DEFAULT as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_TLSv1\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_TLSv1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_SSLv2\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_SSLv2 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_SSLv3\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_SSLv3 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_TLSv1_0\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_TLSv1_0 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_TLSv1_1\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_TLSv1_1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_TLSv1_2\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_TLSv1_2 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_SSLVERSION_TLSv1_3\0" as *const u8 as *const i8,
            value: CURL_SSLVERSION_TLSv1_3 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURL_TIMECOND: [NameValue; 5] = [
    {
        let mut init = NameValue {
            name: b"CURL_TIMECOND_IFMODSINCE\0" as *const u8 as *const i8,
            value: CURL_TIMECOND_IFMODSINCE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_TIMECOND_IFUNMODSINCE\0" as *const u8 as *const i8,
            value: CURL_TIMECOND_IFUNMODSINCE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_TIMECOND_LASTMOD\0" as *const u8 as *const i8,
            value: CURL_TIMECOND_LASTMOD as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_TIMECOND_NONE\0" as *const u8 as *const i8,
            value: CURL_TIMECOND_NONE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLFTPSSL_CCC: [NameValue; 4] = [
    {
        let mut init = NameValue {
            name: b"CURLFTPSSL_CCC_NONE\0" as *const u8 as *const i8,
            value: CURLFTPSSL_CCC_NONE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLFTPSSL_CCC_PASSIVE\0" as *const u8 as *const i8,
            value: CURLFTPSSL_CCC_PASSIVE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLFTPSSL_CCC_ACTIVE\0" as *const u8 as *const i8,
            value: CURLFTPSSL_CCC_ACTIVE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLUSESSL: [NameValue; 5] = [
    {
        let mut init = NameValue {
            name: b"CURLUSESSL_NONE\0" as *const u8 as *const i8,
            value: CURLUSESSL_NONE as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLUSESSL_TRY\0" as *const u8 as *const i8,
            value: CURLUSESSL_TRY as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLUSESSL_CONTROL\0" as *const u8 as *const i8,
            value: CURLUSESSL_CONTROL as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLUSESSL_ALL\0" as *const u8 as *const i8,
            value: CURLUSESSL_ALL as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLSSLOPT: [NameValueUnsigned; 7] = [
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_ALLOW_BEAST\0" as *const u8 as *const i8,
            value: ((1 as i32) << 0 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_NO_REVOKE\0" as *const u8 as *const i8,
            value: ((1 as i32) << 1 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_NO_PARTIALCHAIN\0" as *const u8 as *const i8,
            value: ((1 as i32) << 2 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_REVOKE_BEST_EFFORT\0" as *const u8 as *const i8,
            value: ((1 as i32) << 3 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_NATIVE_CA\0" as *const u8 as *const i8,
            value: ((1 as i32) << 4 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: b"CURLSSLOPT_AUTO_CLIENT_CERT\0" as *const u8 as *const i8,
            value: ((1 as i32) << 5 as i32) as u64,
        };
        init
    },
    {
        let mut init = NameValueUnsigned {
            name: 0 as *const i8,
            value: 0 as i32 as u64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURL_NETRC: [NameValue; 4] = [
    {
        let mut init = NameValue {
            name: b"CURL_NETRC_IGNORED\0" as *const u8 as *const i8,
            value: CURL_NETRC_IGNORED as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_NETRC_OPTIONAL\0" as *const u8 as *const i8,
            value: CURL_NETRC_OPTIONAL as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURL_NETRC_REQUIRED\0" as *const u8 as *const i8,
            value: CURL_NETRC_REQUIRED as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
#[no_mangle]
pub static mut setopt_nv_CURLPROTO: [NameValue; 24] = [
    {
        let mut init = NameValue {
            name: b"CURLPROTO_ALL\0" as *const u8 as *const i8,
            value: !(0 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_DICT\0" as *const u8 as *const i8,
            value: ((1 as i32) << 9 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_FILE\0" as *const u8 as *const i8,
            value: ((1 as i32) << 10 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_FTP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 2 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_FTPS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 3 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_GOPHER\0" as *const u8 as *const i8,
            value: ((1 as i32) << 25 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_HTTP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 0 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_HTTPS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 1 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_IMAP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 12 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_IMAPS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 13 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_LDAP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 7 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_LDAPS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 8 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_POP3\0" as *const u8 as *const i8,
            value: ((1 as i32) << 14 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_POP3S\0" as *const u8 as *const i8,
            value: ((1 as i32) << 15 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_RTSP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 18 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SCP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 4 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SFTP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 5 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SMB\0" as *const u8 as *const i8,
            value: ((1 as i32) << 26 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SMBS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 27 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SMTP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 16 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_SMTPS\0" as *const u8 as *const i8,
            value: ((1 as i32) << 17 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_TELNET\0" as *const u8 as *const i8,
            value: ((1 as i32) << 6 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLPROTO_TFTP\0" as *const u8 as *const i8,
            value: ((1 as i32) << 11 as i32) as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
static mut setopt_nv_CURLNONZERODEFAULTS: [NameValue; 9] = [
    {
        let mut init = NameValue {
            name: b"CURLOPT_SSL_VERIFYPEER\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_SSL_VERIFYHOST\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_SSL_ENABLE_NPN\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_SSL_ENABLE_ALPN\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_TCP_NODELAY\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_PROXY_SSL_VERIFYPEER\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_PROXY_SSL_VERIFYHOST\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: b"CURLOPT_SOCKS5_AUTH\0" as *const u8 as *const i8,
            value: 1 as i32 as i64,
        };
        init
    },
    {
        let mut init = NameValue {
            name: 0 as *const i8,
            value: 0 as i32 as i64,
        };
        init
    },
];
unsafe extern "C" fn c_escape(
    mut str: *const i8,
    mut len: curl_off_t,
) -> *mut i8 {
    let mut s: *const i8 = 0 as *const i8;
    let mut c: u8 = 0;
    let mut escaped: *mut i8 = 0 as *mut i8;
    let mut e: *mut i8 = 0 as *mut i8;
    let mut cutoff: u32 = 0 as i32 as u32;
    if len == -(1 as i32) as i64 {
        len = strlen(str) as curl_off_t;
    }
    if len > 2000 as i32 as i64 {
        len = 2000 as i32 as curl_off_t;
        cutoff = 3 as i32 as u32;
    }
    escaped = malloc(
        (4 as i32 as u64)
            .wrapping_mul(len as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_add(cutoff as u64),
    ) as *mut i8;
    if escaped.is_null() {
        return 0 as *mut i8;
    }
    e = escaped;
    s = str;
    while len != 0 {
        c = *s as u8;
        if c as i32 == '\n' as i32 {
            strcpy(e, b"\\n\0" as *const u8 as *const i8);
            e = e.offset(2 as i32 as isize);
        } else if c as i32 == '\r' as i32 {
            strcpy(e, b"\\r\0" as *const u8 as *const i8);
            e = e.offset(2 as i32 as isize);
        } else if c as i32 == '\t' as i32 {
            strcpy(e, b"\\t\0" as *const u8 as *const i8);
            e = e.offset(2 as i32 as isize);
        } else if c as i32 == '\\' as i32 {
            strcpy(e, b"\\\\\0" as *const u8 as *const i8);
            e = e.offset(2 as i32 as isize);
        } else if c as i32 == '"' as i32 {
            strcpy(e, b"\\\"\0" as *const u8 as *const i8);
            e = e.offset(2 as i32 as isize);
        } else if *(*__ctype_b_loc()).offset(c as i32 as isize) as i32
                & _ISprint as i32 as u16 as i32 == 0
            {
            curl_msnprintf(
                e,
                5 as i32 as size_t,
                b"\\x%02x\0" as *const u8 as *const i8,
                c as u32,
            );
            e = e.offset(4 as i32 as isize);
        } else {
            let fresh0 = e;
            e = e.offset(1);
            *fresh0 = c as i8;
        }
        s = s.offset(1);
        len -= 1;
    }
    loop {
        let fresh1 = cutoff;
        cutoff = cutoff.wrapping_sub(1);
        if !(fresh1 != 0) {
            break;
        }
        let fresh2 = e;
        e = e.offset(1);
        *fresh2 = '.' as i32 as i8;
    }
    *e = '\u{0}' as i32 as i8;
    return escaped;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt_enum(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut nvlist: *const NameValue,
    mut lval: i64,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut skip: bool = 0 as i32 != 0;
    ret = curl_easy_setopt(curl, tag, lval);
    if lval == 0 {
        skip = 1 as i32 != 0;
    }
    if !((*config).libcurl).is_null() && !skip && ret as u64 == 0 {
        let mut nv: *const NameValue = 0 as *const NameValue;
        nv = nvlist;
        while !((*nv).name).is_null() {
            if (*nv).value == lval {
                break;
            }
            nv = nv.offset(1);
        }
        if ((*nv).name).is_null() {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"curl_easy_setopt(hnd, %s, %ldL);\0" as *const u8
                    as *const i8,
                name,
                lval,
            );
            ret as u64 != 0;
        } else {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"curl_easy_setopt(hnd, %s, (long)%s);\0" as *const u8
                    as *const i8,
                name,
                (*nv).name,
            );
            ret as u64 != 0;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt_flags(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut nvlist: *const NameValue,
    mut lval: i64,
) -> CURLcode {
    let mut current_block: u64;
    let mut ret: CURLcode = CURLE_OK;
    let mut skip: bool = 0 as i32 != 0;
    ret = curl_easy_setopt(curl, tag, lval);
    if lval == 0 {
        skip = 1 as i32 != 0;
    }
    if !((*config).libcurl).is_null() && !skip && ret as u64 == 0 {
        let mut preamble: [i8; 80] = [0; 80];
        let mut rest: i64 = lval;
        let mut nv: *const NameValue = 0 as *const NameValue;
        curl_msnprintf(
            preamble.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 80]>() as u64,
            b"curl_easy_setopt(hnd, %s, \0" as *const u8 as *const i8,
            name,
        );
        nv = nvlist;
        loop {
            if ((*nv).name).is_null() {
                current_block = 6009453772311597924;
                break;
            }
            if (*nv).value & !rest == 0 as i32 as i64 {
                rest &= !(*nv).value;
                ret = easysrc_addf(
                    &mut easysrc_code as *mut *mut slist_wc,
                    b"%s(long)%s%s\0" as *const u8 as *const i8,
                    preamble.as_mut_ptr(),
                    (*nv).name,
                    if rest != 0 {
                        b" |\0" as *const u8 as *const i8
                    } else {
                        b");\0" as *const u8 as *const i8
                    },
                );
                if ret as u64 != 0 {
                    current_block = 1352102670574683382;
                    break;
                }
                if rest == 0 {
                    current_block = 6009453772311597924;
                    break;
                }
                curl_msnprintf(
                    preamble.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 80]>() as u64,
                    b"%*s\0" as *const u8 as *const i8,
                    strlen(preamble.as_mut_ptr()),
                    b"\0" as *const u8 as *const i8,
                );
            }
            nv = nv.offset(1);
        }
        match current_block {
            1352102670574683382 => {}
            _ => {
                if rest != 0 {
                    ret = easysrc_addf(
                        &mut easysrc_code as *mut *mut slist_wc,
                        b"%s%ldL);\0" as *const u8 as *const i8,
                        preamble.as_mut_ptr(),
                        rest,
                    );
                    ret as u64 != 0;
                }
            }
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt_bitmask(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut nvlist: *const NameValueUnsigned,
    mut lval: i64,
) -> CURLcode {
    let mut current_block: u64;
    let mut ret: CURLcode = CURLE_OK;
    let mut skip: bool = 0 as i32 != 0;
    ret = curl_easy_setopt(curl, tag, lval);
    if lval == 0 {
        skip = 1 as i32 != 0;
    }
    if !((*config).libcurl).is_null() && !skip && ret as u64 == 0 {
        let mut preamble: [i8; 80] = [0; 80];
        let mut rest: u64 = lval as u64;
        let mut nv: *const NameValueUnsigned = 0 as *const NameValueUnsigned;
        curl_msnprintf(
            preamble.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 80]>() as u64,
            b"curl_easy_setopt(hnd, %s, \0" as *const u8 as *const i8,
            name,
        );
        nv = nvlist;
        loop {
            if ((*nv).name).is_null() {
                current_block = 6009453772311597924;
                break;
            }
            if (*nv).value & !rest == 0 as i32 as u64 {
                rest &= !(*nv).value;
                ret = easysrc_addf(
                    &mut easysrc_code as *mut *mut slist_wc,
                    b"%s(long)%s%s\0" as *const u8 as *const i8,
                    preamble.as_mut_ptr(),
                    (*nv).name,
                    if rest != 0 {
                        b" |\0" as *const u8 as *const i8
                    } else {
                        b");\0" as *const u8 as *const i8
                    },
                );
                if ret as u64 != 0 {
                    current_block = 4025506196647738108;
                    break;
                }
                if rest == 0 {
                    current_block = 6009453772311597924;
                    break;
                }
                curl_msnprintf(
                    preamble.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 80]>() as u64,
                    b"%*s\0" as *const u8 as *const i8,
                    strlen(preamble.as_mut_ptr()),
                    b"\0" as *const u8 as *const i8,
                );
            }
            nv = nv.offset(1);
        }
        match current_block {
            4025506196647738108 => {}
            _ => {
                if rest != 0 {
                    ret = easysrc_addf(
                        &mut easysrc_code as *mut *mut slist_wc,
                        b"%s%luUL);\0" as *const u8 as *const i8,
                        preamble.as_mut_ptr(),
                        rest,
                    );
                    ret as u64 != 0;
                }
            }
        }
    }
    return ret;
}
unsafe extern "C" fn libcurl_generate_slist(
    mut slist: *mut curl_slist,
    mut slistno: *mut i32,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    let mut escaped: *mut i8 = 0 as *mut i8;
    easysrc_slist_count += 1;
    *slistno = easysrc_slist_count;
    ret = easysrc_addf(
        &mut easysrc_decl as *mut *mut slist_wc,
        b"struct curl_slist *slist%d;\0" as *const u8 as *const i8,
        *slistno,
    );
    if !(ret as u64 != 0) {
        ret = easysrc_addf(
            &mut easysrc_data as *mut *mut slist_wc,
            b"slist%d = NULL;\0" as *const u8 as *const i8,
            *slistno,
        );
        if !(ret as u64 != 0) {
            ret = easysrc_addf(
                &mut easysrc_clean as *mut *mut slist_wc,
                b"curl_slist_free_all(slist%d);\0" as *const u8 as *const i8,
                *slistno,
            );
            if !(ret as u64 != 0) {
                ret = easysrc_addf(
                    &mut easysrc_clean as *mut *mut slist_wc,
                    b"slist%d = NULL;\0" as *const u8 as *const i8,
                    *slistno,
                );
                if !(ret as u64 != 0) {
                    while !slist.is_null() {
                        free(escaped as *mut libc::c_void);
                        escaped = 0 as *mut i8;
                        escaped = c_escape(
                            (*slist).data,
                            -(1 as i32) as curl_off_t,
                        );
                        if escaped.is_null() {
                            return CURLE_OUT_OF_MEMORY;
                        }
                        ret = easysrc_addf(
                            &mut easysrc_data as *mut *mut slist_wc,
                            b"slist%d = curl_slist_append(slist%d, \"%s\");\0"
                                as *const u8 as *const i8,
                            *slistno,
                            *slistno,
                            escaped,
                        );
                        if ret as u64 != 0 {
                            break;
                        }
                        slist = (*slist).next;
                    }
                }
            }
        }
    }
    free(escaped as *mut libc::c_void);
    escaped = 0 as *mut i8;
    return ret;
}
unsafe extern "C" fn libcurl_generate_mime_part(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut part: *mut tool_mime,
    mut mimeno: i32,
) -> CURLcode {
    let mut current_block: u64;
    let mut ret: CURLcode = CURLE_OK;
    let mut submimeno: i32 = 0 as i32;
    let mut escaped: *mut i8 = 0 as *mut i8;
    let mut data: *const i8 = 0 as *const i8;
    let mut filename: *const i8 = (*part).filename;
    if !((*part).prev).is_null() {
        ret = libcurl_generate_mime_part(curl, config, (*part).prev, mimeno);
        if ret as u64 != 0 {
            return ret;
        }
    }
    ret = easysrc_addf(
        &mut easysrc_code as *mut *mut slist_wc,
        b"part%d = curl_mime_addpart(mime%d);\0" as *const u8 as *const i8,
        mimeno,
        mimeno,
    );
    if !(ret as u64 != 0) {
        match (*part).kind as u32 {
            1 => {
                ret = libcurl_generate_mime(curl, config, part, &mut submimeno);
                if ret as u64 == 0 {
                    ret = easysrc_addf(
                        &mut easysrc_code as *mut *mut slist_wc,
                        b"curl_mime_subparts(part%d, mime%d);\0" as *const u8
                            as *const i8,
                        mimeno,
                        submimeno,
                    );
                    if ret as u64 != 0 {
                        current_block = 9854908333842869459;
                    } else {
                        ret = easysrc_addf(
                            &mut easysrc_code as *mut *mut slist_wc,
                            b"mime%d = NULL;\0" as *const u8 as *const i8,
                            submimeno,
                        );
                        if ret as u64 != 0 {
                            current_block = 9854908333842869459;
                        } else {
                            current_block = 7494008139977416618;
                        }
                    }
                } else {
                    current_block = 7494008139977416618;
                }
            }
            2 => {
                data = (*part).data;
                if ret as u64 == 0 {
                    free(escaped as *mut libc::c_void);
                    escaped = 0 as *mut i8;
                    escaped = c_escape(data, -(1 as i32) as curl_off_t);
                    if escaped.is_null() {
                        ret = CURLE_OUT_OF_MEMORY;
                        current_block = 9854908333842869459;
                    } else {
                        ret = easysrc_addf(
                            &mut easysrc_code as *mut *mut slist_wc,
                            b"curl_mime_data(part%d, \"%s\", CURL_ZERO_TERMINATED);\0"
                                as *const u8 as *const i8,
                            mimeno,
                            escaped,
                        );
                        if ret as u64 != 0 {
                            current_block = 9854908333842869459;
                        } else {
                            current_block = 7494008139977416618;
                        }
                    }
                } else {
                    current_block = 7494008139977416618;
                }
            }
            3 | 4 => {
                escaped = c_escape((*part).data, -(1 as i32) as curl_off_t);
                if escaped.is_null() {
                    ret = CURLE_OUT_OF_MEMORY;
                    current_block = 9854908333842869459;
                } else {
                    ret = easysrc_addf(
                        &mut easysrc_code as *mut *mut slist_wc,
                        b"curl_mime_filedata(part%d, \"%s\");\0" as *const u8
                            as *const i8,
                        mimeno,
                        escaped,
                    );
                    if ret as u64 != 0 {
                        current_block = 9854908333842869459;
                    } else if (*part).kind as u32
                            == TOOLMIME_FILEDATA as i32 as u32
                            && filename.is_null()
                        {
                        ret = easysrc_addf(
                            &mut easysrc_code as *mut *mut slist_wc,
                            b"curl_mime_filename(part%d, NULL);\0" as *const u8
                                as *const i8,
                            mimeno,
                        );
                        if ret as u64 != 0 {
                            current_block = 9854908333842869459;
                        } else {
                            current_block = 7494008139977416618;
                        }
                    } else {
                        current_block = 7494008139977416618;
                    }
                }
            }
            5 => {
                if filename.is_null() {
                    filename = b"-\0" as *const u8 as *const i8;
                }
                current_block = 5235537862154438448;
            }
            6 => {
                current_block = 5235537862154438448;
            }
            _ => {
                current_block = 7494008139977416618;
            }
        }
        match current_block {
            9854908333842869459 => {}
            _ => {
                match current_block {
                    5235537862154438448 => {
                        ret = easysrc_addf(
                            &mut easysrc_code as *mut *mut slist_wc,
                            b"curl_mime_data_cb(part%d, -1, (curl_read_callback) fread, \\\0"
                                as *const u8 as *const i8,
                            mimeno,
                        );
                        if ret as u64 != 0 {
                            current_block = 9854908333842869459;
                        } else {
                            ret = easysrc_add(
                                &mut easysrc_code,
                                b"                  (curl_seek_callback) fseek, NULL, stdin);\0"
                                    as *const u8 as *const i8,
                            );
                            if ret as u64 != 0 {
                                current_block = 9854908333842869459;
                            } else {
                                current_block = 7494008139977416618;
                            }
                        }
                    }
                    _ => {}
                }
                match current_block {
                    9854908333842869459 => {}
                    _ => {
                        if ret as u64 == 0 && !((*part).encoder).is_null() {
                            free(escaped as *mut libc::c_void);
                            escaped = 0 as *mut i8;
                            escaped = c_escape(
                                (*part).encoder,
                                -(1 as i32) as curl_off_t,
                            );
                            if escaped.is_null() {
                                ret = CURLE_OUT_OF_MEMORY;
                                current_block = 9854908333842869459;
                            } else {
                                ret = easysrc_addf(
                                    &mut easysrc_code as *mut *mut slist_wc,
                                    b"curl_mime_encoder(part%d, \"%s\");\0" as *const u8
                                        as *const i8,
                                    mimeno,
                                    escaped,
                                );
                                if ret as u64 != 0 {
                                    current_block = 9854908333842869459;
                                } else {
                                    current_block = 17787701279558130514;
                                }
                            }
                        } else {
                            current_block = 17787701279558130514;
                        }
                        match current_block {
                            9854908333842869459 => {}
                            _ => {
                                if ret as u64 == 0 && !filename.is_null() {
                                    free(escaped as *mut libc::c_void);
                                    escaped = 0 as *mut i8;
                                    escaped = c_escape(
                                        filename,
                                        -(1 as i32) as curl_off_t,
                                    );
                                    if escaped.is_null() {
                                        ret = CURLE_OUT_OF_MEMORY;
                                        current_block = 9854908333842869459;
                                    } else {
                                        ret = easysrc_addf(
                                            &mut easysrc_code as *mut *mut slist_wc,
                                            b"curl_mime_filename(part%d, \"%s\");\0" as *const u8
                                                as *const i8,
                                            mimeno,
                                            escaped,
                                        );
                                        if ret as u64 != 0 {
                                            current_block = 9854908333842869459;
                                        } else {
                                            current_block = 6014157347423944569;
                                        }
                                    }
                                } else {
                                    current_block = 6014157347423944569;
                                }
                                match current_block {
                                    9854908333842869459 => {}
                                    _ => {
                                        if ret as u64 == 0 && !((*part).name).is_null() {
                                            free(escaped as *mut libc::c_void);
                                            escaped = 0 as *mut i8;
                                            escaped = c_escape(
                                                (*part).name,
                                                -(1 as i32) as curl_off_t,
                                            );
                                            if escaped.is_null() {
                                                ret = CURLE_OUT_OF_MEMORY;
                                                current_block = 9854908333842869459;
                                            } else {
                                                ret = easysrc_addf(
                                                    &mut easysrc_code as *mut *mut slist_wc,
                                                    b"curl_mime_name(part%d, \"%s\");\0" as *const u8
                                                        as *const i8,
                                                    mimeno,
                                                    escaped,
                                                );
                                                if ret as u64 != 0 {
                                                    current_block = 9854908333842869459;
                                                } else {
                                                    current_block = 3575278370434307847;
                                                }
                                            }
                                        } else {
                                            current_block = 3575278370434307847;
                                        }
                                        match current_block {
                                            9854908333842869459 => {}
                                            _ => {
                                                if ret as u64 == 0 && !((*part).type_0).is_null() {
                                                    free(escaped as *mut libc::c_void);
                                                    escaped = 0 as *mut i8;
                                                    escaped = c_escape(
                                                        (*part).type_0,
                                                        -(1 as i32) as curl_off_t,
                                                    );
                                                    if escaped.is_null() {
                                                        ret = CURLE_OUT_OF_MEMORY;
                                                        current_block = 9854908333842869459;
                                                    } else {
                                                        ret = easysrc_addf(
                                                            &mut easysrc_code as *mut *mut slist_wc,
                                                            b"curl_mime_type(part%d, \"%s\");\0" as *const u8
                                                                as *const i8,
                                                            mimeno,
                                                            escaped,
                                                        );
                                                        if ret as u64 != 0 {
                                                            current_block = 9854908333842869459;
                                                        } else {
                                                            current_block = 12696043255897098083;
                                                        }
                                                    }
                                                } else {
                                                    current_block = 12696043255897098083;
                                                }
                                                match current_block {
                                                    9854908333842869459 => {}
                                                    _ => {
                                                        if ret as u64 == 0 && !((*part).headers).is_null() {
                                                            let mut slistno: i32 = 0;
                                                            ret = libcurl_generate_slist((*part).headers, &mut slistno);
                                                            if ret as u64 == 0 {
                                                                ret = easysrc_addf(
                                                                    &mut easysrc_code as *mut *mut slist_wc,
                                                                    b"curl_mime_headers(part%d, slist%d, 1);\0" as *const u8
                                                                        as *const i8,
                                                                    mimeno,
                                                                    slistno,
                                                                );
                                                                if !(ret as u64 != 0) {
                                                                    ret = easysrc_addf(
                                                                        &mut easysrc_code as *mut *mut slist_wc,
                                                                        b"slist%d = NULL;\0" as *const u8 as *const i8,
                                                                        slistno,
                                                                    );
                                                                    ret as u64 != 0;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    free(escaped as *mut libc::c_void);
    escaped = 0 as *mut i8;
    return ret;
}
unsafe extern "C" fn libcurl_generate_mime(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut toolmime: *mut tool_mime,
    mut mimeno: *mut i32,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    easysrc_mime_count += 1;
    *mimeno = easysrc_mime_count;
    ret = easysrc_addf(
        &mut easysrc_decl as *mut *mut slist_wc,
        b"curl_mime *mime%d;\0" as *const u8 as *const i8,
        *mimeno,
    );
    if !(ret as u64 != 0) {
        ret = easysrc_addf(
            &mut easysrc_data as *mut *mut slist_wc,
            b"mime%d = NULL;\0" as *const u8 as *const i8,
            *mimeno,
        );
        if !(ret as u64 != 0) {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"mime%d = curl_mime_init(hnd);\0" as *const u8 as *const i8,
                *mimeno,
            );
            if !(ret as u64 != 0) {
                ret = easysrc_addf(
                    &mut easysrc_clean as *mut *mut slist_wc,
                    b"curl_mime_free(mime%d);\0" as *const u8 as *const i8,
                    *mimeno,
                );
                if !(ret as u64 != 0) {
                    ret = easysrc_addf(
                        &mut easysrc_clean as *mut *mut slist_wc,
                        b"mime%d = NULL;\0" as *const u8 as *const i8,
                        *mimeno,
                    );
                    if !(ret as u64 != 0) {
                        if !((*toolmime).subparts).is_null() {
                            ret = easysrc_addf(
                                &mut easysrc_decl as *mut *mut slist_wc,
                                b"curl_mimepart *part%d;\0" as *const u8
                                    as *const i8,
                                *mimeno,
                            );
                            if !(ret as u64 != 0) {
                                ret = libcurl_generate_mime_part(
                                    curl,
                                    config,
                                    (*toolmime).subparts,
                                    *mimeno,
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt_mimepost(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut mimepost: *mut curl_mime,
) -> CURLcode {
    let mut ret: CURLcode = curl_easy_setopt(curl, tag, mimepost);
    let mut mimeno: i32 = 0 as i32;
    if ret as u64 == 0 && !((*config).libcurl).is_null() {
        ret = libcurl_generate_mime(
            curl,
            config,
            (*(*config).current).mimeroot,
            &mut mimeno,
        );
        if ret as u64 == 0 {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"curl_easy_setopt(hnd, %s, mime%d);\0" as *const u8
                    as *const i8,
                name,
                mimeno,
            );
            ret as u64 != 0;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt_slist(
    mut curl: *mut CURL,
    mut config: *mut GlobalConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut list: *mut curl_slist,
) -> CURLcode {
    let mut ret: CURLcode = CURLE_OK;
    ret = curl_easy_setopt(curl, tag, list);
    if !((*config).libcurl).is_null() && !list.is_null() && ret as u64 == 0 {
        let mut i: i32 = 0;
        ret = libcurl_generate_slist(list, &mut i);
        if ret as u64 == 0 {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"curl_easy_setopt(hnd, %s, slist%d);\0" as *const u8
                    as *const i8,
                name,
                i,
            );
            ret as u64 != 0;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn tool_setopt(
    mut curl: *mut CURL,
    mut str: bool,
    mut global: *mut GlobalConfig,
    mut config: *mut OperationConfig,
    mut name: *const i8,
    mut tag: CURLoption,
    mut args: ...
) -> CURLcode {
    let mut arg: ::std::ffi::VaListImpl;
    let mut buf: [i8; 256] = [0; 256];
    let mut value: *const i8 = 0 as *const i8;
    let mut remark: bool = 0 as i32 != 0;
    let mut skip: bool = 0 as i32 != 0;
    let mut escape: bool = 0 as i32 != 0;
    let mut escaped: *mut i8 = 0 as *mut i8;
    let mut ret: CURLcode = CURLE_OK;
    arg = args.clone();
    if (tag as u32) < 10000 as i32 as u32 {
        let mut lval: i64 = arg.arg::<i64>();
        let mut defval: i64 = 0 as i64;
        let mut nv: *const NameValue = 0 as *const NameValue;
        nv = setopt_nv_CURLNONZERODEFAULTS.as_ptr();
        while !((*nv).name).is_null() {
            if strcmp(name, (*nv).name) == 0 {
                defval = (*nv).value;
                break;
            } else {
                nv = nv.offset(1);
            }
        }
        curl_msnprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64,
            b"%ldL\0" as *const u8 as *const i8,
            lval,
        );
        value = buf.as_mut_ptr();
        ret = curl_easy_setopt(curl, tag, lval);
        if lval == defval {
            skip = 1 as i32 != 0;
        }
    } else if (tag as u32) < 30000 as i32 as u32 {
        let mut pval: *mut libc::c_void = arg.arg::<*mut libc::c_void>();
        if tag as u32 >= 20000 as i32 as u32 {
            if !pval.is_null() {
                value = b"functionpointer\0" as *const u8 as *const i8;
                remark = 1 as i32 != 0;
            } else {
                skip = 1 as i32 != 0;
            }
        } else if !pval.is_null() && str as i32 != 0 {
            value = pval as *mut i8;
            escape = 1 as i32 != 0;
        } else if !pval.is_null() {
            value = b"objectpointer\0" as *const u8 as *const i8;
            remark = 1 as i32 != 0;
        } else {
            skip = 1 as i32 != 0;
        }
        ret = curl_easy_setopt(curl, tag, pval);
    } else if (tag as u32) < 40000 as i32 as u32 {
        let mut oval: curl_off_t = arg.arg::<curl_off_t>();
        curl_msnprintf(
            buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 256]>() as u64,
            b"(curl_off_t)%ld\0" as *const u8 as *const i8,
            oval,
        );
        value = buf.as_mut_ptr();
        ret = curl_easy_setopt(curl, tag, oval);
        if oval == 0 {
            skip = 1 as i32 != 0;
        }
    } else {
        let mut pblob: *mut libc::c_void = arg.arg::<*mut libc::c_void>();
        if !pblob.is_null() {
            value = b"blobpointer\0" as *const u8 as *const i8;
            remark = 1 as i32 != 0;
        } else {
            skip = 1 as i32 != 0;
        }
        ret = curl_easy_setopt(curl, tag, pblob);
    }
    if !((*global).libcurl).is_null() && !skip && ret as u64 == 0 {
        if remark {
            ret = easysrc_addf(
                &mut easysrc_toohard as *mut *mut slist_wc,
                b"%s set to a %s\0" as *const u8 as *const i8,
                name,
                value,
            );
            ret as u64 != 0;
        } else if escape {
            let mut len: curl_off_t = -(1 as i32) as curl_off_t;
            if tag as u32 == CURLOPT_POSTFIELDS as i32 as u32 {
                len = (*config).postfieldsize;
            }
            escaped = c_escape(value, len);
            if escaped.is_null() {
                ret = CURLE_OUT_OF_MEMORY;
            } else {
                ret = easysrc_addf(
                    &mut easysrc_code as *mut *mut slist_wc,
                    b"curl_easy_setopt(hnd, %s, \"%s\");\0" as *const u8
                        as *const i8,
                    name,
                    escaped,
                );
                ret as u64 != 0;
            }
        } else {
            ret = easysrc_addf(
                &mut easysrc_code as *mut *mut slist_wc,
                b"curl_easy_setopt(hnd, %s, %s);\0" as *const u8 as *const i8,
                name,
                value,
            );
            ret as u64 != 0;
        }
    }
    free(escaped as *mut libc::c_void);
    escaped = 0 as *mut i8;
    return ret;
}
#[no_mangle]
pub extern "C" fn tool_setopt_skip(mut tag: CURLoption) -> bool {
    return 0 as i32 != 0;
}
