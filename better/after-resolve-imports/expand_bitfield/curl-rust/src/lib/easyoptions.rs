use ::libc;
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
pub type curl_easytype = crate::src::lib::easygetopt::curl_easytype;
pub const CURLOT_FUNCTION: curl_easytype = 8;
pub const CURLOT_BLOB: curl_easytype = 7;
pub const CURLOT_CBPTR: curl_easytype = 6;
pub const CURLOT_SLIST: curl_easytype = 5;
pub const CURLOT_STRING: curl_easytype = 4;
pub const CURLOT_OBJECT: curl_easytype = 3;
pub const CURLOT_OFF_T: curl_easytype = 2;
pub const CURLOT_VALUES: curl_easytype = 1;
pub const CURLOT_LONG: curl_easytype = 0;
// #[derive(Copy, Clone)]

pub type curl_easyoption = crate::src::lib::easygetopt::curl_easyoption;
#[no_mangle]
pub static mut Curl_easyopts: [curl_easyoption; 305] = [
    {
        let mut init = curl_easyoption {
            name: b"ABSTRACT_UNIX_SOCKET\0" as *const u8 as *const i8,
            id: CURLOPT_ABSTRACT_UNIX_SOCKET,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ACCEPTTIMEOUT_MS\0" as *const u8 as *const i8,
            id: CURLOPT_ACCEPTTIMEOUT_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ACCEPT_ENCODING\0" as *const u8 as *const i8,
            id: CURLOPT_ACCEPT_ENCODING,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ADDRESS_SCOPE\0" as *const u8 as *const i8,
            id: CURLOPT_ADDRESS_SCOPE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ALTSVC\0" as *const u8 as *const i8,
            id: CURLOPT_ALTSVC,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ALTSVC_CTRL\0" as *const u8 as *const i8,
            id: CURLOPT_ALTSVC_CTRL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"APPEND\0" as *const u8 as *const i8,
            id: CURLOPT_APPEND,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"AUTOREFERER\0" as *const u8 as *const i8,
            id: CURLOPT_AUTOREFERER,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"AWS_SIGV4\0" as *const u8 as *const i8,
            id: CURLOPT_AWS_SIGV4,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"BUFFERSIZE\0" as *const u8 as *const i8,
            id: CURLOPT_BUFFERSIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CAINFO\0" as *const u8 as *const i8,
            id: CURLOPT_CAINFO,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CAINFO_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_CAINFO_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CAPATH\0" as *const u8 as *const i8,
            id: CURLOPT_CAPATH,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CERTINFO\0" as *const u8 as *const i8,
            id: CURLOPT_CERTINFO,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CHUNK_BGN_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CHUNK_BGN_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CHUNK_DATA\0" as *const u8 as *const i8,
            id: CURLOPT_CHUNK_DATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CHUNK_END_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CHUNK_END_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CLOSESOCKETDATA\0" as *const u8 as *const i8,
            id: CURLOPT_CLOSESOCKETDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CLOSESOCKETFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CLOSESOCKETFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONNECTTIMEOUT\0" as *const u8 as *const i8,
            id: CURLOPT_CONNECTTIMEOUT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONNECTTIMEOUT_MS\0" as *const u8 as *const i8,
            id: CURLOPT_CONNECTTIMEOUT_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONNECT_ONLY\0" as *const u8 as *const i8,
            id: CURLOPT_CONNECT_ONLY,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONNECT_TO\0" as *const u8 as *const i8,
            id: CURLOPT_CONNECT_TO,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONV_FROM_NETWORK_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CONV_FROM_NETWORK_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONV_FROM_UTF8_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CONV_FROM_UTF8_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CONV_TO_NETWORK_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_CONV_TO_NETWORK_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COOKIE\0" as *const u8 as *const i8,
            id: CURLOPT_COOKIE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COOKIEFILE\0" as *const u8 as *const i8,
            id: CURLOPT_COOKIEFILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COOKIEJAR\0" as *const u8 as *const i8,
            id: CURLOPT_COOKIEJAR,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COOKIELIST\0" as *const u8 as *const i8,
            id: CURLOPT_COOKIELIST,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COOKIESESSION\0" as *const u8 as *const i8,
            id: CURLOPT_COOKIESESSION,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"COPYPOSTFIELDS\0" as *const u8 as *const i8,
            id: CURLOPT_COPYPOSTFIELDS,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CRLF\0" as *const u8 as *const i8,
            id: CURLOPT_CRLF,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CRLFILE\0" as *const u8 as *const i8,
            id: CURLOPT_CRLFILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CURLU\0" as *const u8 as *const i8,
            id: CURLOPT_CURLU,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"CUSTOMREQUEST\0" as *const u8 as *const i8,
            id: CURLOPT_CUSTOMREQUEST,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DEBUGDATA\0" as *const u8 as *const i8,
            id: CURLOPT_DEBUGDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DEBUGFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_DEBUGFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DEFAULT_PROTOCOL\0" as *const u8 as *const i8,
            id: CURLOPT_DEFAULT_PROTOCOL,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DIRLISTONLY\0" as *const u8 as *const i8,
            id: CURLOPT_DIRLISTONLY,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DISALLOW_USERNAME_IN_URL\0" as *const u8 as *const i8,
            id: CURLOPT_DISALLOW_USERNAME_IN_URL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_CACHE_TIMEOUT\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_CACHE_TIMEOUT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_INTERFACE\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_INTERFACE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_LOCAL_IP4\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_LOCAL_IP4,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_LOCAL_IP6\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_LOCAL_IP6,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_SERVERS\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_SERVERS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_SHUFFLE_ADDRESSES\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_SHUFFLE_ADDRESSES,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DNS_USE_GLOBAL_CACHE\0" as *const u8 as *const i8,
            id: CURLOPT_DNS_USE_GLOBAL_CACHE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DOH_SSL_VERIFYHOST\0" as *const u8 as *const i8,
            id: CURLOPT_DOH_SSL_VERIFYHOST,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DOH_SSL_VERIFYPEER\0" as *const u8 as *const i8,
            id: CURLOPT_DOH_SSL_VERIFYPEER,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DOH_SSL_VERIFYSTATUS\0" as *const u8 as *const i8,
            id: CURLOPT_DOH_SSL_VERIFYSTATUS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"DOH_URL\0" as *const u8 as *const i8,
            id: CURLOPT_DOH_URL,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"EGDSOCKET\0" as *const u8 as *const i8,
            id: CURLOPT_EGDSOCKET,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ENCODING\0" as *const u8 as *const i8,
            id: CURLOPT_ACCEPT_ENCODING,
            type_0: CURLOT_STRING,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ERRORBUFFER\0" as *const u8 as *const i8,
            id: CURLOPT_ERRORBUFFER,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"EXPECT_100_TIMEOUT_MS\0" as *const u8 as *const i8,
            id: CURLOPT_EXPECT_100_TIMEOUT_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FAILONERROR\0" as *const u8 as *const i8,
            id: CURLOPT_FAILONERROR,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FILE\0" as *const u8 as *const i8,
            id: CURLOPT_WRITEDATA,
            type_0: CURLOT_CBPTR,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FILETIME\0" as *const u8 as *const i8,
            id: CURLOPT_FILETIME,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FNMATCH_DATA\0" as *const u8 as *const i8,
            id: CURLOPT_FNMATCH_DATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FNMATCH_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_FNMATCH_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FOLLOWLOCATION\0" as *const u8 as *const i8,
            id: CURLOPT_FOLLOWLOCATION,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FORBID_REUSE\0" as *const u8 as *const i8,
            id: CURLOPT_FORBID_REUSE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FRESH_CONNECT\0" as *const u8 as *const i8,
            id: CURLOPT_FRESH_CONNECT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTPAPPEND\0" as *const u8 as *const i8,
            id: CURLOPT_APPEND,
            type_0: CURLOT_LONG,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTPLISTONLY\0" as *const u8 as *const i8,
            id: CURLOPT_DIRLISTONLY,
            type_0: CURLOT_LONG,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTPPORT\0" as *const u8 as *const i8,
            id: CURLOPT_FTPPORT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTPSSLAUTH\0" as *const u8 as *const i8,
            id: CURLOPT_FTPSSLAUTH,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_ACCOUNT\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_ACCOUNT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_ALTERNATIVE_TO_USER\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_ALTERNATIVE_TO_USER,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_CREATE_MISSING_DIRS\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_CREATE_MISSING_DIRS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_FILEMETHOD\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_FILEMETHOD,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_RESPONSE_TIMEOUT\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_RESPONSE_TIMEOUT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_SKIP_PASV_IP\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_SKIP_PASV_IP,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_SSL\0" as *const u8 as *const i8,
            id: CURLOPT_USE_SSL,
            type_0: CURLOT_VALUES,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_SSL_CCC\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_SSL_CCC,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_USE_EPRT\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_USE_EPRT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_USE_EPSV\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_USE_EPSV,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"FTP_USE_PRET\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_USE_PRET,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"GSSAPI_DELEGATION\0" as *const u8 as *const i8,
            id: CURLOPT_GSSAPI_DELEGATION,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HAPPY_EYEBALLS_TIMEOUT_MS\0" as *const u8 as *const i8,
            id: CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HAPROXYPROTOCOL\0" as *const u8 as *const i8,
            id: CURLOPT_HAPROXYPROTOCOL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HEADER\0" as *const u8 as *const i8,
            id: CURLOPT_HEADER,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HEADERDATA\0" as *const u8 as *const i8,
            id: CURLOPT_HEADERDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HEADERFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_HEADERFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HEADEROPT\0" as *const u8 as *const i8,
            id: CURLOPT_HEADEROPT,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTS\0" as *const u8 as *const i8,
            id: CURLOPT_HSTS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTSREADDATA\0" as *const u8 as *const i8,
            id: CURLOPT_HSTSREADDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTSREADFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_HSTSREADFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTSWRITEDATA\0" as *const u8 as *const i8,
            id: CURLOPT_HSTSWRITEDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTSWRITEFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_HSTSWRITEFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HSTS_CTRL\0" as *const u8 as *const i8,
            id: CURLOPT_HSTS_CTRL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTP09_ALLOWED\0" as *const u8 as *const i8,
            id: CURLOPT_HTTP09_ALLOWED,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTP200ALIASES\0" as *const u8 as *const i8,
            id: CURLOPT_HTTP200ALIASES,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTPAUTH\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPAUTH,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTPGET\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPGET,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTPHEADER\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPHEADER,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTPPOST\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPPOST,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTPPROXYTUNNEL\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPPROXYTUNNEL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTP_CONTENT_DECODING\0" as *const u8 as *const i8,
            id: CURLOPT_HTTP_CONTENT_DECODING,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTP_TRANSFER_DECODING\0" as *const u8 as *const i8,
            id: CURLOPT_HTTP_TRANSFER_DECODING,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"HTTP_VERSION\0" as *const u8 as *const i8,
            id: CURLOPT_HTTP_VERSION,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"IGNORE_CONTENT_LENGTH\0" as *const u8 as *const i8,
            id: CURLOPT_IGNORE_CONTENT_LENGTH,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INFILE\0" as *const u8 as *const i8,
            id: CURLOPT_READDATA,
            type_0: CURLOT_CBPTR,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INFILESIZE\0" as *const u8 as *const i8,
            id: CURLOPT_INFILESIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INFILESIZE_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_INFILESIZE_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INTERFACE\0" as *const u8 as *const i8,
            id: CURLOPT_INTERFACE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INTERLEAVEDATA\0" as *const u8 as *const i8,
            id: CURLOPT_INTERLEAVEDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"INTERLEAVEFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_INTERLEAVEFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"IOCTLDATA\0" as *const u8 as *const i8,
            id: CURLOPT_IOCTLDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"IOCTLFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_IOCTLFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"IPRESOLVE\0" as *const u8 as *const i8,
            id: CURLOPT_IPRESOLVE,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ISSUERCERT\0" as *const u8 as *const i8,
            id: CURLOPT_ISSUERCERT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"ISSUERCERT_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_ISSUERCERT_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"KEEP_SENDING_ON_ERROR\0" as *const u8 as *const i8,
            id: CURLOPT_KEEP_SENDING_ON_ERROR,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"KEYPASSWD\0" as *const u8 as *const i8,
            id: CURLOPT_KEYPASSWD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"KRB4LEVEL\0" as *const u8 as *const i8,
            id: CURLOPT_KRBLEVEL,
            type_0: CURLOT_STRING,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"KRBLEVEL\0" as *const u8 as *const i8,
            id: CURLOPT_KRBLEVEL,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"LOCALPORT\0" as *const u8 as *const i8,
            id: CURLOPT_LOCALPORT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"LOCALPORTRANGE\0" as *const u8 as *const i8,
            id: CURLOPT_LOCALPORTRANGE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"LOGIN_OPTIONS\0" as *const u8 as *const i8,
            id: CURLOPT_LOGIN_OPTIONS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"LOW_SPEED_LIMIT\0" as *const u8 as *const i8,
            id: CURLOPT_LOW_SPEED_LIMIT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"LOW_SPEED_TIME\0" as *const u8 as *const i8,
            id: CURLOPT_LOW_SPEED_TIME,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAIL_AUTH\0" as *const u8 as *const i8,
            id: CURLOPT_MAIL_AUTH,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAIL_FROM\0" as *const u8 as *const i8,
            id: CURLOPT_MAIL_FROM,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAIL_RCPT\0" as *const u8 as *const i8,
            id: CURLOPT_MAIL_RCPT,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAIL_RCPT_ALLLOWFAILS\0" as *const u8 as *const i8,
            id: CURLOPT_MAIL_RCPT_ALLLOWFAILS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAXAGE_CONN\0" as *const u8 as *const i8,
            id: CURLOPT_MAXAGE_CONN,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAXCONNECTS\0" as *const u8 as *const i8,
            id: CURLOPT_MAXCONNECTS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAXFILESIZE\0" as *const u8 as *const i8,
            id: CURLOPT_MAXFILESIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAXFILESIZE_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_MAXFILESIZE_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAXREDIRS\0" as *const u8 as *const i8,
            id: CURLOPT_MAXREDIRS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAX_RECV_SPEED_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_MAX_RECV_SPEED_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MAX_SEND_SPEED_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_MAX_SEND_SPEED_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"MIMEPOST\0" as *const u8 as *const i8,
            id: CURLOPT_MIMEPOST,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NETRC\0" as *const u8 as *const i8,
            id: CURLOPT_NETRC,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NETRC_FILE\0" as *const u8 as *const i8,
            id: CURLOPT_NETRC_FILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NEW_DIRECTORY_PERMS\0" as *const u8 as *const i8,
            id: CURLOPT_NEW_DIRECTORY_PERMS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NEW_FILE_PERMS\0" as *const u8 as *const i8,
            id: CURLOPT_NEW_FILE_PERMS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NOBODY\0" as *const u8 as *const i8,
            id: CURLOPT_NOBODY,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NOPROGRESS\0" as *const u8 as *const i8,
            id: CURLOPT_NOPROGRESS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NOPROXY\0" as *const u8 as *const i8,
            id: CURLOPT_NOPROXY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"NOSIGNAL\0" as *const u8 as *const i8,
            id: CURLOPT_NOSIGNAL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"OPENSOCKETDATA\0" as *const u8 as *const i8,
            id: CURLOPT_OPENSOCKETDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"OPENSOCKETFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_OPENSOCKETFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PASSWORD\0" as *const u8 as *const i8,
            id: CURLOPT_PASSWORD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PATH_AS_IS\0" as *const u8 as *const i8,
            id: CURLOPT_PATH_AS_IS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PINNEDPUBLICKEY\0" as *const u8 as *const i8,
            id: CURLOPT_PINNEDPUBLICKEY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PIPEWAIT\0" as *const u8 as *const i8,
            id: CURLOPT_PIPEWAIT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PORT\0" as *const u8 as *const i8,
            id: CURLOPT_PORT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POST\0" as *const u8 as *const i8,
            id: CURLOPT_POST,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POST301\0" as *const u8 as *const i8,
            id: CURLOPT_POSTREDIR,
            type_0: CURLOT_VALUES,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POSTFIELDS\0" as *const u8 as *const i8,
            id: CURLOPT_POSTFIELDS,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POSTFIELDSIZE\0" as *const u8 as *const i8,
            id: CURLOPT_POSTFIELDSIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POSTFIELDSIZE_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_POSTFIELDSIZE_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POSTQUOTE\0" as *const u8 as *const i8,
            id: CURLOPT_POSTQUOTE,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"POSTREDIR\0" as *const u8 as *const i8,
            id: CURLOPT_POSTREDIR,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PREQUOTE\0" as *const u8 as *const i8,
            id: CURLOPT_PREQUOTE,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PRE_PROXY\0" as *const u8 as *const i8,
            id: CURLOPT_PRE_PROXY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PRIVATE\0" as *const u8 as *const i8,
            id: CURLOPT_PRIVATE,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROGRESSDATA\0" as *const u8 as *const i8,
            id: CURLOPT_XFERINFODATA,
            type_0: CURLOT_CBPTR,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROGRESSFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_PROGRESSFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROTOCOLS\0" as *const u8 as *const i8,
            id: CURLOPT_PROTOCOLS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYAUTH\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYAUTH,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYHEADER\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYHEADER,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYPASSWORD\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYPASSWORD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYPORT\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYPORT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYTYPE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYTYPE,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYUSERNAME\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYUSERNAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXYUSERPWD\0" as *const u8 as *const i8,
            id: CURLOPT_PROXYUSERPWD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_CAINFO\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_CAINFO,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_CAINFO_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_CAINFO_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_CAPATH\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_CAPATH,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_CRLFILE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_CRLFILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_ISSUERCERT\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_ISSUERCERT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_ISSUERCERT_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_ISSUERCERT_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_KEYPASSWD\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_KEYPASSWD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_PINNEDPUBLICKEY\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_PINNEDPUBLICKEY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SERVICE_NAME\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SERVICE_NAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLCERT\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLCERT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLCERTTYPE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLCERTTYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLCERT_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLCERT_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLKEY\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLKEY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLKEYTYPE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLKEYTYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLKEY_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLKEY_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSLVERSION\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSLVERSION,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSL_CIPHER_LIST\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSL_CIPHER_LIST,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSL_OPTIONS\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSL_OPTIONS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSL_VERIFYHOST\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSL_VERIFYHOST,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_SSL_VERIFYPEER\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_SSL_VERIFYPEER,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_TLS13_CIPHERS\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_TLS13_CIPHERS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_TLSAUTH_PASSWORD\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_TLSAUTH_PASSWORD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_TLSAUTH_TYPE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_TLSAUTH_TYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_TLSAUTH_USERNAME\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_TLSAUTH_USERNAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PROXY_TRANSFER_MODE\0" as *const u8 as *const i8,
            id: CURLOPT_PROXY_TRANSFER_MODE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"PUT\0" as *const u8 as *const i8,
            id: CURLOPT_PUT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"QUOTE\0" as *const u8 as *const i8,
            id: CURLOPT_QUOTE,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RANDOM_FILE\0" as *const u8 as *const i8,
            id: CURLOPT_RANDOM_FILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RANGE\0" as *const u8 as *const i8,
            id: CURLOPT_RANGE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"READDATA\0" as *const u8 as *const i8,
            id: CURLOPT_READDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"READFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_READFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"REDIR_PROTOCOLS\0" as *const u8 as *const i8,
            id: CURLOPT_REDIR_PROTOCOLS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"REFERER\0" as *const u8 as *const i8,
            id: CURLOPT_REFERER,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"REQUEST_TARGET\0" as *const u8 as *const i8,
            id: CURLOPT_REQUEST_TARGET,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RESOLVE\0" as *const u8 as *const i8,
            id: CURLOPT_RESOLVE,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RESOLVER_START_DATA\0" as *const u8 as *const i8,
            id: CURLOPT_RESOLVER_START_DATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RESOLVER_START_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_RESOLVER_START_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RESUME_FROM\0" as *const u8 as *const i8,
            id: CURLOPT_RESUME_FROM,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RESUME_FROM_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_RESUME_FROM_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSPHEADER\0" as *const u8 as *const i8,
            id: CURLOPT_HTTPHEADER,
            type_0: CURLOT_SLIST,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_CLIENT_CSEQ\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_CLIENT_CSEQ,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_REQUEST\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_REQUEST,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_SERVER_CSEQ\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_SERVER_CSEQ,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_SESSION_ID\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_SESSION_ID,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_STREAM_URI\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_STREAM_URI,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"RTSP_TRANSPORT\0" as *const u8 as *const i8,
            id: CURLOPT_RTSP_TRANSPORT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SASL_AUTHZID\0" as *const u8 as *const i8,
            id: CURLOPT_SASL_AUTHZID,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SASL_IR\0" as *const u8 as *const i8,
            id: CURLOPT_SASL_IR,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SEEKDATA\0" as *const u8 as *const i8,
            id: CURLOPT_SEEKDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SEEKFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_SEEKFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SERVER_RESPONSE_TIMEOUT\0" as *const u8 as *const i8,
            id: CURLOPT_FTP_RESPONSE_TIMEOUT,
            type_0: CURLOT_LONG,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SERVICE_NAME\0" as *const u8 as *const i8,
            id: CURLOPT_SERVICE_NAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SHARE\0" as *const u8 as *const i8,
            id: CURLOPT_SHARE,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SOCKOPTDATA\0" as *const u8 as *const i8,
            id: CURLOPT_SOCKOPTDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SOCKOPTFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_SOCKOPTFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SOCKS5_AUTH\0" as *const u8 as *const i8,
            id: CURLOPT_SOCKS5_AUTH,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SOCKS5_GSSAPI_NEC\0" as *const u8 as *const i8,
            id: CURLOPT_SOCKS5_GSSAPI_NEC,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SOCKS5_GSSAPI_SERVICE\0" as *const u8 as *const i8,
            id: CURLOPT_SOCKS5_GSSAPI_SERVICE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_AUTH_TYPES\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_AUTH_TYPES,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_COMPRESSION\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_COMPRESSION,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_HOST_PUBLIC_KEY_MD5\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_HOST_PUBLIC_KEY_MD5,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_KEYDATA\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_KEYDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_KEYFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_KEYFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_KNOWNHOSTS\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_KNOWNHOSTS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_PRIVATE_KEYFILE\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_PRIVATE_KEYFILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSH_PUBLIC_KEYFILE\0" as *const u8 as *const i8,
            id: CURLOPT_SSH_PUBLIC_KEYFILE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLCERT\0" as *const u8 as *const i8,
            id: CURLOPT_SSLCERT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLCERTPASSWD\0" as *const u8 as *const i8,
            id: CURLOPT_KEYPASSWD,
            type_0: CURLOT_STRING,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLCERTTYPE\0" as *const u8 as *const i8,
            id: CURLOPT_SSLCERTTYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLCERT_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_SSLCERT_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLENGINE\0" as *const u8 as *const i8,
            id: CURLOPT_SSLENGINE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLENGINE_DEFAULT\0" as *const u8 as *const i8,
            id: CURLOPT_SSLENGINE_DEFAULT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLKEY\0" as *const u8 as *const i8,
            id: CURLOPT_SSLKEY,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLKEYPASSWD\0" as *const u8 as *const i8,
            id: CURLOPT_KEYPASSWD,
            type_0: CURLOT_STRING,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLKEYTYPE\0" as *const u8 as *const i8,
            id: CURLOPT_SSLKEYTYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLKEY_BLOB\0" as *const u8 as *const i8,
            id: CURLOPT_SSLKEY_BLOB,
            type_0: CURLOT_BLOB,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSLVERSION\0" as *const u8 as *const i8,
            id: CURLOPT_SSLVERSION,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_CIPHER_LIST\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_CIPHER_LIST,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_CTX_DATA\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_CTX_DATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_CTX_FUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_CTX_FUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_EC_CURVES\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_EC_CURVES,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_ENABLE_ALPN\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_ENABLE_ALPN,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_ENABLE_NPN\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_ENABLE_NPN,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_FALSESTART\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_FALSESTART,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_OPTIONS\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_OPTIONS,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_SESSIONID_CACHE\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_SESSIONID_CACHE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_VERIFYHOST\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_VERIFYHOST,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_VERIFYPEER\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_VERIFYPEER,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SSL_VERIFYSTATUS\0" as *const u8 as *const i8,
            id: CURLOPT_SSL_VERIFYSTATUS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"STDERR\0" as *const u8 as *const i8,
            id: CURLOPT_STDERR,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"STREAM_DEPENDS\0" as *const u8 as *const i8,
            id: CURLOPT_STREAM_DEPENDS,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"STREAM_DEPENDS_E\0" as *const u8 as *const i8,
            id: CURLOPT_STREAM_DEPENDS_E,
            type_0: CURLOT_OBJECT,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"STREAM_WEIGHT\0" as *const u8 as *const i8,
            id: CURLOPT_STREAM_WEIGHT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"SUPPRESS_CONNECT_HEADERS\0" as *const u8 as *const i8,
            id: CURLOPT_SUPPRESS_CONNECT_HEADERS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TCP_FASTOPEN\0" as *const u8 as *const i8,
            id: CURLOPT_TCP_FASTOPEN,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TCP_KEEPALIVE\0" as *const u8 as *const i8,
            id: CURLOPT_TCP_KEEPALIVE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TCP_KEEPIDLE\0" as *const u8 as *const i8,
            id: CURLOPT_TCP_KEEPIDLE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TCP_KEEPINTVL\0" as *const u8 as *const i8,
            id: CURLOPT_TCP_KEEPINTVL,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TCP_NODELAY\0" as *const u8 as *const i8,
            id: CURLOPT_TCP_NODELAY,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TELNETOPTIONS\0" as *const u8 as *const i8,
            id: CURLOPT_TELNETOPTIONS,
            type_0: CURLOT_SLIST,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TFTP_BLKSIZE\0" as *const u8 as *const i8,
            id: CURLOPT_TFTP_BLKSIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TFTP_NO_OPTIONS\0" as *const u8 as *const i8,
            id: CURLOPT_TFTP_NO_OPTIONS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TIMECONDITION\0" as *const u8 as *const i8,
            id: CURLOPT_TIMECONDITION,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TIMEOUT\0" as *const u8 as *const i8,
            id: CURLOPT_TIMEOUT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TIMEOUT_MS\0" as *const u8 as *const i8,
            id: CURLOPT_TIMEOUT_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TIMEVALUE\0" as *const u8 as *const i8,
            id: CURLOPT_TIMEVALUE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TIMEVALUE_LARGE\0" as *const u8 as *const i8,
            id: CURLOPT_TIMEVALUE_LARGE,
            type_0: CURLOT_OFF_T,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TLS13_CIPHERS\0" as *const u8 as *const i8,
            id: CURLOPT_TLS13_CIPHERS,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TLSAUTH_PASSWORD\0" as *const u8 as *const i8,
            id: CURLOPT_TLSAUTH_PASSWORD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TLSAUTH_TYPE\0" as *const u8 as *const i8,
            id: CURLOPT_TLSAUTH_TYPE,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TLSAUTH_USERNAME\0" as *const u8 as *const i8,
            id: CURLOPT_TLSAUTH_USERNAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TRAILERDATA\0" as *const u8 as *const i8,
            id: CURLOPT_TRAILERDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TRAILERFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_TRAILERFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TRANSFERTEXT\0" as *const u8 as *const i8,
            id: CURLOPT_TRANSFERTEXT,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"TRANSFER_ENCODING\0" as *const u8 as *const i8,
            id: CURLOPT_TRANSFER_ENCODING,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"UNIX_SOCKET_PATH\0" as *const u8 as *const i8,
            id: CURLOPT_UNIX_SOCKET_PATH,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"UNRESTRICTED_AUTH\0" as *const u8 as *const i8,
            id: CURLOPT_UNRESTRICTED_AUTH,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"UPKEEP_INTERVAL_MS\0" as *const u8 as *const i8,
            id: CURLOPT_UPKEEP_INTERVAL_MS,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"UPLOAD\0" as *const u8 as *const i8,
            id: CURLOPT_UPLOAD,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"UPLOAD_BUFFERSIZE\0" as *const u8 as *const i8,
            id: CURLOPT_UPLOAD_BUFFERSIZE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"URL\0" as *const u8 as *const i8,
            id: CURLOPT_URL,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"USERAGENT\0" as *const u8 as *const i8,
            id: CURLOPT_USERAGENT,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"USERNAME\0" as *const u8 as *const i8,
            id: CURLOPT_USERNAME,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"USERPWD\0" as *const u8 as *const i8,
            id: CURLOPT_USERPWD,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"USE_SSL\0" as *const u8 as *const i8,
            id: CURLOPT_USE_SSL,
            type_0: CURLOT_VALUES,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"VERBOSE\0" as *const u8 as *const i8,
            id: CURLOPT_VERBOSE,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"WILDCARDMATCH\0" as *const u8 as *const i8,
            id: CURLOPT_WILDCARDMATCH,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"WRITEDATA\0" as *const u8 as *const i8,
            id: CURLOPT_WRITEDATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"WRITEFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_WRITEFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"WRITEHEADER\0" as *const u8 as *const i8,
            id: CURLOPT_HEADERDATA,
            type_0: CURLOT_CBPTR,
            flags: ((1 as i32) << 0 as i32) as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"XFERINFODATA\0" as *const u8 as *const i8,
            id: CURLOPT_XFERINFODATA,
            type_0: CURLOT_CBPTR,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"XFERINFOFUNCTION\0" as *const u8 as *const i8,
            id: CURLOPT_XFERINFOFUNCTION,
            type_0: CURLOT_FUNCTION,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: b"XOAUTH2_BEARER\0" as *const u8 as *const i8,
            id: CURLOPT_XOAUTH2_BEARER,
            type_0: CURLOT_STRING,
            flags: 0 as i32 as u32,
        };
        init
    },
    {
        let mut init = curl_easyoption {
            name: 0 as *const i8,
            id: CURLOPT_LASTENTRY,
            type_0: CURLOT_LONG,
            flags: 0 as i32 as u32,
        };
        init
    },
];
