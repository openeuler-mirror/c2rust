use :: c2rust_bitfields;
use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type Curl_URL;
    pub type thread_data;
    pub type altsvcinfo;
    pub type hsts;
    pub type TELNET;
    pub type smb_request;
    pub type ldapreqinfo;
    pub type contenc_writer;
    pub type psl_ctx_st;
    pub type Curl_share;
    pub type curl_pushheaders;
    pub type http_connect_state;
    pub type ldapconninfo;
    pub type tftp_state_data;
    pub type nghttp2_session;
    pub type Gsasl_session;
    pub type Gsasl;
    pub type x509_st;
    pub type ssl_st;
    pub type ssl_ctx_st;
    pub type stack_st_void;
    pub type evp_md_ctx_st;
    pub type evp_md_st;
    pub type engine_st;
    pub type ssl_session_st;
    pub type X509_pubkey_st;
    pub type ocsp_response_st;
    pub type ocsp_basic_response_st;
    pub type ocsp_cert_id_st;
    pub type stack_st_X509;
    pub type stack_st;
    pub type x509_store_st;
    pub type bio_st;
    pub type bio_method_st;
    pub type X509_name_st;
    pub type X509_name_entry_st;
    pub type stack_st_GENERAL_NAME;
    pub type ASN1_VALUE_st;
    pub type asn1_object_st;
    pub type evp_pkey_st;
    pub type bignum_st;
    pub type dh_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type stack_st_X509_EXTENSION;
    pub type X509_extension_st;
    pub type ssl_cipher_st;
    pub type x509_store_ctx_st;
    pub type x509_lookup_st;
    pub type x509_lookup_method_st;
    pub type evp_cipher_st;
    pub type X509_crl_st;
    pub type stack_st_X509_INFO;
    pub type ui_method_st;
    pub type ui_string_st;
    pub type ui_st;
    pub type PKCS12_st;
    pub type ssl_method_st;
    pub type ossl_init_settings_st;
    fn curl_slist_append(_: *mut curl_slist, _: *const i8) -> *mut curl_slist;
    fn curl_slist_free_all(_: *mut curl_slist);
    fn recv(__fd: i32, __buf: *mut libc::c_void, __n: size_t, __flags: i32) -> ssize_t;
    fn __errno_location() -> *mut i32;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: u64) -> i32;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strncpy(_: *mut i8, _: *const i8, _: u64) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn Curl_now() -> curltime;
    fn inet_pton(__af: i32, __cp: *const i8, __buf: *mut libc::c_void) -> i32;
    fn Curl_infof(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_failf(_: *mut Curl_easy, fmt: *const i8, _: ...);
    fn Curl_debug(data: *mut Curl_easy, type_0: curl_infotype, ptr: *mut i8, size: size_t) -> i32;
    fn Curl_timeleft(data: *mut Curl_easy, nowp: *mut curltime, duringconnect: bool) -> timediff_t;
    fn Curl_conncontrol(conn: *mut connectdata, closeit: i32);
    fn Curl_socket_check(
        readfd: curl_socket_t,
        readfd2: curl_socket_t,
        writefd: curl_socket_t,
        timeout_ms: timediff_t,
    ) -> i32;
    fn Curl_wait_ms(timeout_ms: timediff_t) -> i32;
    fn Curl_none_false_start() -> bool;
    fn Curl_ssl_getsock(conn: *mut connectdata, socks: *mut curl_socket_t) -> i32;
    fn Curl_ssl_init_certinfo(data: *mut Curl_easy, num: i32) -> CURLcode;
    fn Curl_ssl_push_certinfo_len(
        data: *mut Curl_easy,
        certnum: i32,
        label: *const i8,
        value: *const i8,
        valuelen: size_t,
    ) -> CURLcode;
    fn Curl_ssl_sessionid_lock(data: *mut Curl_easy);
    fn Curl_ssl_sessionid_unlock(data: *mut Curl_easy);
    fn Curl_ssl_getsessionid(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        isProxy: bool,
        ssl_sessionid: *mut *mut libc::c_void,
        idsize: *mut size_t,
        sockindex: i32,
    ) -> bool;
    fn Curl_ssl_addsessionid(
        data: *mut Curl_easy,
        conn: *mut connectdata,
        isProxy: bool,
        ssl_sessionid: *mut libc::c_void,
        idsize: size_t,
        sockindex: i32,
    ) -> CURLcode;
    fn Curl_ssl_delsessionid(data: *mut Curl_easy, ssl_sessionid: *mut libc::c_void);
    fn Curl_pin_peer_pubkey(
        data: *mut Curl_easy,
        pinnedpubkey: *const i8,
        pubkey: *const u8,
        pubkeylen: size_t,
    ) -> CURLcode;
    fn Curl_tls_keylog_open();
    fn Curl_tls_keylog_close();
    fn Curl_tls_keylog_enabled() -> bool;
    fn Curl_tls_keylog_write_line(line: *const i8) -> bool;
    fn Curl_strcasecompare(first: *const i8, second: *const i8) -> i32;
    fn Curl_strncasecompare(first: *const i8, second: *const i8, max: size_t) -> i32;
    fn Curl_strntolower(dest: *mut i8, src: *const i8, n: size_t);
    fn Curl_cert_hostcheck(match_pattern: *const i8, hostname: *const i8) -> i32;
    fn Curl_set_in_callback(data: *mut Curl_easy, value: bool);
    fn Curl_multiuse_state(data: *mut Curl_easy, bundlestate: i32);
    fn Curl_strerror(err: i32, buf: *mut i8, buflen: size_t) -> *const i8;
    fn curl_msnprintf(buffer: *mut i8, maxlength: size_t, format: *const i8, _: ...) -> i32;
    fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
    fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
    fn EVP_DigestUpdate(ctx: *mut EVP_MD_CTX, d: *const libc::c_void, cnt: size_t) -> i32;
    fn EVP_DigestFinal_ex(ctx: *mut EVP_MD_CTX, md: *mut u8, s: *mut u32) -> i32;
    fn EVP_DigestInit(ctx: *mut EVP_MD_CTX, type_0: *const EVP_MD) -> i32;
    fn EVP_sha1() -> *const EVP_MD;
    fn EVP_sha256() -> *const EVP_MD;
    fn EVP_PKEY_id(pkey: *const EVP_PKEY) -> i32;
    fn EVP_PKEY_get0_RSA(pkey: *mut EVP_PKEY) -> *mut rsa_st;
    fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut rsa_st;
    fn EVP_PKEY_get0_DSA(pkey: *mut EVP_PKEY) -> *mut dsa_st;
    fn EVP_PKEY_get0_DH(pkey: *mut EVP_PKEY) -> *mut dh_st;
    fn EVP_PKEY_free(pkey: *mut EVP_PKEY);
    fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> i32;
    fn SSL_alert_desc_string_long(value: i32) -> *const i8;
    fn SSL_CTX_set_msg_callback(
        ctx: *mut SSL_CTX,
        cb: Option<
            unsafe extern "C" fn(
                i32,
                i32,
                i32,
                *const libc::c_void,
                size_t,
                *mut SSL,
                *mut libc::c_void,
            ) -> (),
        >,
    );
    fn SSL_CTX_new(meth: *const SSL_METHOD) -> *mut SSL_CTX;
    fn TLS_client_method() -> *const SSL_METHOD;
    fn SSL_pending(s: *const SSL) -> i32;
    fn SSL_get_shutdown(ssl: *const SSL) -> i32;
    fn d2i_PrivateKey_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY;
    fn OPENSSL_init_ssl(opts: uint64_t, settings: *const OPENSSL_INIT_SETTINGS) -> i32;
    fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64;
    fn SSL_CTX_set_next_proto_select_cb(
        s: *mut SSL_CTX,
        cb: SSL_CTX_npn_select_cb_func,
        arg: *mut libc::c_void,
    );
    fn SSL_CTX_set_alpn_protos(ctx: *mut SSL_CTX, protos: *const u8, protos_len: u32) -> i32;
    fn SSL_CTX_set_default_passwd_cb_userdata(ctx: *mut SSL_CTX, u: *mut libc::c_void);
    fn SSL_CTX_set_default_passwd_cb(ctx: *mut SSL_CTX, cb: Option<pem_password_cb>);
    fn PEM_read_bio_X509_AUX(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut X509;
    fn SSL_CTX_use_certificate_chain_file(ctx: *mut SSL_CTX, file: *const i8) -> i32;
    fn d2i_X509_bio(bp: *mut BIO, x509: *mut *mut X509) -> *mut X509;
    fn SSL_CTX_use_certificate_file(ctx: *mut SSL_CTX, file: *const i8, type_0: i32) -> i32;
    fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> i32;
    fn SSL_CTX_add_client_CA(ctx: *mut SSL_CTX, x: *mut X509) -> i32;
    fn OPENSSL_sk_pop(st: *mut OPENSSL_STACK) -> *mut libc::c_void;
    fn PEM_read_bio_PrivateKey(
        bp: *mut BIO,
        x: *mut *mut EVP_PKEY,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
    fn SSL_CTX_use_PrivateKey_file(ctx: *mut SSL_CTX, file: *const i8, type_0: i32) -> i32;
    fn SSL_CTX_set_ciphersuites(ctx: *mut SSL_CTX, str: *const i8) -> i32;
    fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> i32;
    fn SSL_get_certificate(ssl: *const SSL) -> *mut X509;
    fn RSA_flags(r: *const RSA) -> i32;
    fn RSA_free(r: *mut RSA);
    fn SSL_get_privatekey(ssl: *const SSL) -> *mut evp_pkey_st;
    fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> i32;
    fn SSL_CTX_set_post_handshake_auth(ctx: *mut SSL_CTX, val: i32);
    fn SSL_CTX_set_srp_username(ctx: *mut SSL_CTX, name: *mut i8) -> i32;
    fn SSL_CTX_set_srp_password(ctx: *mut SSL_CTX, password: *mut i8) -> i32;
    fn SSL_CTX_set_cipher_list(_: *mut SSL_CTX, str: *const i8) -> i32;
    fn PEM_X509_INFO_read_bio(
        bp: *mut BIO,
        sk: *mut stack_st_X509_INFO,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut stack_st_X509_INFO;
    fn X509_STORE_add_cert(ctx: *mut X509_STORE, x: *mut X509) -> i32;
    fn X509_STORE_add_crl(ctx: *mut X509_STORE, x: *mut X509_CRL) -> i32;
    fn OPENSSL_sk_pop_free(
        st: *mut OPENSSL_STACK,
        func: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    );
    fn X509_INFO_free(a: *mut X509_INFO);
    fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        CAfile: *const i8,
        CApath: *const i8,
    ) -> i32;
    fn X509_STORE_add_lookup(v: *mut X509_STORE, m: *mut X509_LOOKUP_METHOD) -> *mut X509_LOOKUP;
    fn X509_LOOKUP_file() -> *mut X509_LOOKUP_METHOD;
    fn X509_load_crl_file(ctx: *mut X509_LOOKUP, file: *const i8, type_0: i32) -> i32;
    fn X509_STORE_set_flags(ctx: *mut X509_STORE, flags: u64) -> i32;
    fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: i32, callback: SSL_verify_cb);
    fn SSL_CTX_set_keylog_callback(ctx: *mut SSL_CTX, cb: SSL_CTX_keylog_cb_func);
    fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: i32, larg: i64, parg: *mut libc::c_void) -> i64;
    fn SSL_CTX_sess_set_new_cb(
        ctx: *mut SSL_CTX,
        new_session_cb: Option<unsafe extern "C" fn(*mut ssl_st, *mut SSL_SESSION) -> i32>,
    );
    fn SSL_get_ex_data(ssl: *const SSL, idx: i32) -> *mut libc::c_void;
    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    fn SSL_set_session(to: *mut SSL, session: *mut SSL_SESSION) -> i32;
    fn SSL_set_bio(s: *mut SSL, rbio: *mut BIO, wbio: *mut BIO);
    fn BIO_f_ssl() -> *const BIO_METHOD;
    fn SSL_set_fd(s: *mut SSL, fd: i32) -> i32;
    fn SSL_connect(ssl: *mut SSL) -> i32;
    fn SSL_get_version(s: *const SSL) -> *const i8;
    fn SSL_CIPHER_get_name(c: *const SSL_CIPHER) -> *const i8;
    fn SSL_get_current_cipher(s: *const SSL) -> *const SSL_CIPHER;
    fn SSL_get0_alpn_selected(ssl: *const SSL, data: *mut *const u8, len: *mut u32);
    fn X509_get_version(x: *const X509) -> i64;
    fn X509_get_serialNumber(x: *mut X509) -> *mut ASN1_INTEGER;
    fn BIO_puts(bp: *mut BIO, buf: *const i8) -> i32;
    fn X509_get0_signature(
        psig: *mut *const ASN1_BIT_STRING,
        palg: *mut *const X509_ALGOR,
        x: *const X509,
    );
    fn X509_PUBKEY_get0_param(
        ppkalg: *mut *mut ASN1_OBJECT,
        pk: *mut *const u8,
        ppklen: *mut i32,
        pa: *mut *mut X509_ALGOR,
        pub_0: *mut X509_PUBKEY,
    ) -> i32;
    fn i2a_ASN1_OBJECT(bp: *mut BIO, a: *const ASN1_OBJECT) -> i32;
    fn X509_EXTENSION_get_object(ex: *mut X509_EXTENSION) -> *mut ASN1_OBJECT;
    fn i2t_ASN1_OBJECT(buf: *mut i8, buf_len: i32, a: *const ASN1_OBJECT) -> i32;
    fn X509_get0_extensions(x: *const X509) -> *const stack_st_X509_EXTENSION;
    fn ASN1_STRING_print(bp: *mut BIO, v: *const ASN1_STRING) -> i32;
    fn X509_EXTENSION_get_data(ne: *mut X509_EXTENSION) -> *mut ASN1_OCTET_STRING;
    fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;
    fn RSA_get0_key(
        r: *const RSA,
        n: *mut *const BIGNUM,
        e: *mut *const BIGNUM,
        d: *mut *const BIGNUM,
    );
    fn BN_num_bits(a: *const BIGNUM) -> i32;
    fn DSA_get0_pqg(
        d: *const DSA,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DSA_get0_key(d: *const DSA, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn BN_print(bio: *mut BIO, a: *const BIGNUM) -> i32;
    fn BIO_printf(bio: *mut BIO, format: *const i8, _: ...) -> i32;
    fn PEM_write_bio_X509(bp: *mut BIO, x: *mut X509) -> i32;
    fn X509_get0_notBefore(x: *const X509) -> *const ASN1_TIME;
    fn ASN1_TIME_print(fp: *mut BIO, a: *const ASN1_TIME) -> i32;
    fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
    fn X509_get_ext_d2i(
        x: *const X509,
        nid: i32,
        crit: *mut i32,
        idx: *mut i32,
    ) -> *mut libc::c_void;
    fn X509_NAME_get_index_by_NID(name: *mut X509_NAME, nid: i32, lastpos: i32) -> i32;
    fn ASN1_STRING_type(x: *const ASN1_STRING) -> i32;
    fn ASN1_STRING_length(x: *const ASN1_STRING) -> i32;
    fn CRYPTO_malloc(num: size_t, file: *const i8, line: i32) -> *mut libc::c_void;
    fn ASN1_STRING_get0_data(x: *const ASN1_STRING) -> *const u8;
    fn ASN1_STRING_to_UTF8(out: *mut *mut u8, in_0: *const ASN1_STRING) -> i32;
    fn X509_NAME_ENTRY_get_data(ne: *const X509_NAME_ENTRY) -> *mut ASN1_STRING;
    fn X509_NAME_get_entry(name: *const X509_NAME, loc: i32) -> *mut X509_NAME_ENTRY;
    fn X509_get_subject_name(a: *const X509) -> *mut X509_NAME;
    fn CRYPTO_free(ptr: *mut libc::c_void, file: *const i8, line: i32);
    fn X509_NAME_print_ex(out: *mut BIO, nm: *const X509_NAME, indent: i32, flags: u64) -> i32;
    fn BIO_s_mem() -> *const BIO_METHOD;
    fn X509_get_issuer_name(a: *const X509) -> *mut X509_NAME;
    fn BIO_new_mem_buf(buf: *const libc::c_void, len: i32) -> *mut BIO;
    fn BIO_new(type_0: *const BIO_METHOD) -> *mut BIO;
    fn BIO_s_file() -> *const BIO_METHOD;
    fn BIO_ctrl(bp: *mut BIO, cmd: i32, larg: i64, parg: *mut libc::c_void) -> i64;
    fn PEM_read_bio_X509(
        bp: *mut BIO,
        x: *mut *mut X509,
        cb: Option<pem_password_cb>,
        u: *mut libc::c_void,
    ) -> *mut X509;
    fn BIO_free(a: *mut BIO) -> i32;
    fn SSL_get_verify_result(ssl: *const SSL) -> i64;
    fn X509_verify_cert_error_string(n: i64) -> *const i8;
    fn SSL_ctrl(ssl: *mut SSL, cmd: i32, larg: i64, parg: *mut libc::c_void) -> i64;
    fn SSL_get_peer_cert_chain(s: *const SSL) -> *mut stack_st_X509;
    fn SSL_CTX_get_cert_store(_: *const SSL_CTX) -> *mut X509_STORE;
    fn SSL_get_peer_certificate(s: *const SSL) -> *mut X509;
    fn OPENSSL_sk_num(_: *const OPENSSL_STACK) -> i32;
    fn OPENSSL_sk_value(_: *const OPENSSL_STACK, _: i32) -> *mut libc::c_void;
    fn i2d_X509_PUBKEY(a: *mut X509_PUBKEY, out: *mut *mut u8) -> i32;
    fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509_PUBKEY;
    fn X509_free(a: *mut X509);
    fn SSL_write(ssl: *mut SSL, buf: *const libc::c_void, num: i32) -> i32;
    fn SSL_get_error(s: *const SSL, ret_code: i32) -> i32;
    fn OpenSSL_version_num() -> u64;
    fn SSL_read(ssl: *mut SSL, buf: *mut libc::c_void, num: i32) -> i32;
    fn SSL_shutdown(s: *mut SSL) -> i32;
    fn SSL_set_connect_state(s: *mut SSL);
    fn SSL_free(ssl: *mut SSL);
    fn SSL_CTX_free(_: *mut SSL_CTX);
    fn SSL_SESSION_free(ses: *mut SSL_SESSION);
    fn SSL_set_ex_data(ssl: *mut SSL, idx: i32, data: *mut libc::c_void) -> i32;
    fn CRYPTO_get_ex_new_index(
        class_index: i32,
        argl: i64,
        argp: *mut libc::c_void,
        new_func: Option<CRYPTO_EX_new>,
        dup_func: Option<CRYPTO_EX_dup>,
        free_func: Option<CRYPTO_EX_free>,
    ) -> i32;
    fn RAND_bytes(buf: *mut u8, num: i32) -> i32;
    fn RAND_add(buf: *const libc::c_void, num: i32, randomness: f64);
    fn RAND_load_file(file: *const i8, max_bytes: i64) -> i32;
    fn RAND_file_name(file: *mut i8, num: size_t) -> *const i8;
    fn RAND_status() -> i32;
    fn GENERAL_NAMES_free(a: *mut GENERAL_NAMES);
    fn X509V3_EXT_print(out: *mut BIO, ext: *mut X509_EXTENSION, flag: u64, indent: i32) -> i32;
    fn X509_check_issued(issuer: *mut X509, subject: *mut X509) -> i32;
    fn ERR_get_error() -> u64;
    fn ERR_peek_error() -> u64;
    fn ERR_peek_last_error() -> u64;
    fn ERR_clear_error();
    fn ERR_error_string_n(e: u64, buf: *mut i8, len: size_t);
    fn PKCS12_free(a: *mut PKCS12);
    fn PKCS12_PBE_add();
    fn PKCS12_parse(
        p12: *mut PKCS12,
        pass: *const i8,
        pkey: *mut *mut EVP_PKEY,
        cert: *mut *mut X509,
        ca: *mut *mut stack_st_X509,
    ) -> i32;
    fn d2i_PKCS12_bio(bp: *mut BIO, p12: *mut *mut PKCS12) -> *mut PKCS12;
    fn OCSP_cert_to_id(
        dgst: *const EVP_MD,
        subject: *const X509,
        issuer: *const X509,
    ) -> *mut OCSP_CERTID;
    fn OCSP_response_status(resp: *mut OCSP_RESPONSE) -> i32;
    fn OCSP_response_get1_basic(resp: *mut OCSP_RESPONSE) -> *mut OCSP_BASICRESP;
    fn OCSP_resp_find_status(
        bs: *mut OCSP_BASICRESP,
        id: *mut OCSP_CERTID,
        status: *mut i32,
        reason: *mut i32,
        revtime: *mut *mut ASN1_GENERALIZEDTIME,
        thisupd: *mut *mut ASN1_GENERALIZEDTIME,
        nextupd: *mut *mut ASN1_GENERALIZEDTIME,
    ) -> i32;
    fn OCSP_check_validity(
        thisupd: *mut ASN1_GENERALIZEDTIME,
        nextupd: *mut ASN1_GENERALIZEDTIME,
        sec: i64,
        maxsec: i64,
    ) -> i32;
    fn OCSP_BASICRESP_free(a: *mut OCSP_BASICRESP);
    fn OCSP_RESPONSE_free(a: *mut OCSP_RESPONSE);
    fn d2i_OCSP_RESPONSE(
        a: *mut *mut OCSP_RESPONSE,
        in_0: *mut *const u8,
        len: i64,
    ) -> *mut OCSP_RESPONSE;
    fn OCSP_CERTID_free(a: *mut OCSP_CERTID);
    fn OCSP_response_status_str(s: i64) -> *const i8;
    fn OCSP_cert_status_str(s: i64) -> *const i8;
    fn OCSP_basic_verify(
        bs: *mut OCSP_BASICRESP,
        certs: *mut stack_st_X509,
        st: *mut X509_STORE,
        flags: u64,
    ) -> i32;
    fn OCSP_crl_reason_str(s: i64) -> *const i8;
    fn UI_get0_user_data(ui: *mut UI) -> *mut libc::c_void;
    fn UI_OpenSSL() -> *mut UI_METHOD;
    fn UI_method_set_opener(
        method: *mut UI_METHOD,
        opener: Option<unsafe extern "C" fn(*mut UI) -> i32>,
    ) -> i32;
    fn ENGINE_ctrl_cmd(
        e: *mut ENGINE,
        cmd_name: *const i8,
        i: i64,
        p: *mut libc::c_void,
        f: Option<unsafe extern "C" fn() -> ()>,
        cmd_optional: i32,
    ) -> i32;
    fn ENGINE_ctrl(
        e: *mut ENGINE,
        cmd: i32,
        i: i64,
        p: *mut libc::c_void,
        f: Option<unsafe extern "C" fn() -> ()>,
    ) -> i32;
    fn UI_method_get_opener(
        method: *const UI_METHOD,
    ) -> Option<unsafe extern "C" fn(*mut UI) -> i32>;
    fn UI_method_set_closer(
        method: *mut UI_METHOD,
        closer: Option<unsafe extern "C" fn(*mut UI) -> i32>,
    ) -> i32;
    fn UI_method_get_closer(
        method: *const UI_METHOD,
    ) -> Option<unsafe extern "C" fn(*mut UI) -> i32>;
    fn UI_method_set_reader(
        method: *mut UI_METHOD,
        reader: Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32>,
    ) -> i32;
    fn UI_set_result(ui: *mut UI, uis: *mut UI_STRING, result: *const i8) -> i32;
    fn UI_method_get_reader(
        method: *const UI_METHOD,
    ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32>;
    fn UI_method_set_writer(
        method: *mut UI_METHOD,
        writer: Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32>,
    ) -> i32;
    fn UI_get_string_type(uis: *mut UI_STRING) -> UI_string_types;
    fn UI_get_input_flags(uis: *mut UI_STRING) -> i32;
    fn UI_method_get_writer(
        method: *const UI_METHOD,
    ) -> Option<unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32>;
    fn UI_destroy_method(ui_method: *mut UI_METHOD);
    fn UI_create_method(name: *const i8) -> *mut UI_METHOD;
    fn ENGINE_by_id(id: *const i8) -> *mut ENGINE;
    fn ENGINE_free(e: *mut ENGINE) -> i32;
    fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE;
    fn ENGINE_get_id(e: *const ENGINE) -> *const i8;
    fn ENGINE_get_first() -> *mut ENGINE;
    fn ENGINE_init(e: *mut ENGINE) -> i32;
    fn ENGINE_finish(e: *mut ENGINE) -> i32;
    fn ENGINE_load_private_key(
        e: *mut ENGINE,
        key_id: *const i8,
        ui_method: *mut UI_METHOD,
        callback_data: *mut libc::c_void,
    ) -> *mut EVP_PKEY;
    fn ENGINE_set_default(e: *mut ENGINE, flags: u32) -> i32;
    fn curlx_uztosi(uznum: size_t) -> i32;
    static mut Curl_cmalloc: curl_malloc_callback;
    static mut Curl_cfree: curl_free_callback;
}
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __int32_t = i32;
pub type __uint32_t = u32;
pub type __uint64_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __pid_t = i32;
pub type __time_t = i64;
pub type __ssize_t = i64;
pub type __socklen_t = u32;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = u64;
pub type int32_t = __int32_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = u16;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [i8; 14],
}
pub type C2RustUnnamed = u32;
pub const MSG_CMSG_CLOEXEC: C2RustUnnamed = 1073741824;
pub const MSG_FASTOPEN: C2RustUnnamed = 536870912;
pub const MSG_ZEROCOPY: C2RustUnnamed = 67108864;
pub const MSG_BATCH: C2RustUnnamed = 262144;
pub const MSG_WAITFORONE: C2RustUnnamed = 65536;
pub const MSG_MORE: C2RustUnnamed = 32768;
pub const MSG_NOSIGNAL: C2RustUnnamed = 16384;
pub const MSG_ERRQUEUE: C2RustUnnamed = 8192;
pub const MSG_RST: C2RustUnnamed = 4096;
pub const MSG_CONFIRM: C2RustUnnamed = 2048;
pub const MSG_SYN: C2RustUnnamed = 1024;
pub const MSG_FIN: C2RustUnnamed = 512;
pub const MSG_WAITALL: C2RustUnnamed = 256;
pub const MSG_EOR: C2RustUnnamed = 128;
pub const MSG_DONTWAIT: C2RustUnnamed = 64;
pub const MSG_TRUNC: C2RustUnnamed = 32;
pub const MSG_PROXY: C2RustUnnamed = 16;
pub const MSG_CTRUNC: C2RustUnnamed = 8;
pub const MSG_DONTROUTE: C2RustUnnamed = 4;
pub const MSG_PEEK: C2RustUnnamed = 2;
pub const MSG_OOB: C2RustUnnamed = 1;
pub type curl_socklen_t = socklen_t;
pub type curl_off_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_easy {
    pub magic: u32,
    pub next: *mut Curl_easy,
    pub prev: *mut Curl_easy,
    pub conn: *mut connectdata,
    pub connect_queue: Curl_llist_element,
    pub conn_queue: Curl_llist_element,
    pub mstate: CURLMstate,
    pub result: CURLcode,
    pub msg: Curl_message,
    pub sockets: [curl_socket_t; 5],
    pub actions: [u8; 5],
    pub numsocks: i32,
    pub dns: Names,
    pub multi: *mut Curl_multi,
    pub multi_easy: *mut Curl_multi,
    pub share: *mut Curl_share,
    pub psl: *mut PslCache,
    pub req: SingleRequest,
    pub set: UserDefined,
    pub cookies: *mut CookieInfo,
    pub hsts: *mut hsts,
    pub asi: *mut altsvcinfo,
    pub progress: Progress,
    pub state: UrlState,
    pub wildcard: WildcardData,
    pub info: PureInfo,
    pub tsi: curl_tlssessioninfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_tlssessioninfo {
    pub backend: curl_sslbackend,
    pub internals: *mut libc::c_void,
}
pub type curl_sslbackend = u32;
pub const CURLSSLBACKEND_RUSTLS: curl_sslbackend = 14;
pub const CURLSSLBACKEND_BEARSSL: curl_sslbackend = 13;
pub const CURLSSLBACKEND_MESALINK: curl_sslbackend = 12;
pub const CURLSSLBACKEND_MBEDTLS: curl_sslbackend = 11;
pub const CURLSSLBACKEND_AXTLS: curl_sslbackend = 10;
pub const CURLSSLBACKEND_SECURETRANSPORT: curl_sslbackend = 9;
pub const CURLSSLBACKEND_SCHANNEL: curl_sslbackend = 8;
pub const CURLSSLBACKEND_WOLFSSL: curl_sslbackend = 7;
pub const CURLSSLBACKEND_POLARSSL: curl_sslbackend = 6;
pub const CURLSSLBACKEND_GSKIT: curl_sslbackend = 5;
pub const CURLSSLBACKEND_OBSOLETE4: curl_sslbackend = 4;
pub const CURLSSLBACKEND_NSS: curl_sslbackend = 3;
pub const CURLSSLBACKEND_GNUTLS: curl_sslbackend = 2;
pub const CURLSSLBACKEND_OPENSSL: curl_sslbackend = 1;
pub const CURLSSLBACKEND_NONE: curl_sslbackend = 0;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct PureInfo {
    pub httpcode: i32,
    pub httpproxycode: i32,
    pub httpversion: i32,
    pub filetime: time_t,
    pub header_size: curl_off_t,
    pub request_size: curl_off_t,
    pub proxyauthavail: u64,
    pub httpauthavail: u64,
    pub numconnects: i64,
    pub contenttype: *mut i8,
    pub wouldredirect: *mut i8,
    pub retry_after: curl_off_t,
    pub conn_primary_ip: [i8; 46],
    pub conn_primary_port: i32,
    pub conn_local_ip: [i8; 46],
    pub conn_local_port: i32,
    pub conn_scheme: *const i8,
    pub conn_protocol: u32,
    pub certs: curl_certinfo,
    pub pxcode: CURLproxycode,
    #[bitfield(name = "timecond", ty = "bit", bits = "0..=0")]
    pub timecond: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type bit = u32;
pub type CURLproxycode = u32;
pub const CURLPX_LAST: CURLproxycode = 34;
pub const CURLPX_USER_REJECTED: CURLproxycode = 33;
pub const CURLPX_UNKNOWN_MODE: CURLproxycode = 32;
pub const CURLPX_UNKNOWN_FAIL: CURLproxycode = 31;
pub const CURLPX_SEND_REQUEST: CURLproxycode = 30;
pub const CURLPX_SEND_CONNECT: CURLproxycode = 29;
pub const CURLPX_SEND_AUTH: CURLproxycode = 28;
pub const CURLPX_RESOLVE_HOST: CURLproxycode = 27;
pub const CURLPX_REQUEST_FAILED: CURLproxycode = 26;
pub const CURLPX_REPLY_UNASSIGNED: CURLproxycode = 25;
pub const CURLPX_REPLY_TTL_EXPIRED: CURLproxycode = 24;
pub const CURLPX_REPLY_NOT_ALLOWED: CURLproxycode = 23;
pub const CURLPX_REPLY_NETWORK_UNREACHABLE: CURLproxycode = 22;
pub const CURLPX_REPLY_HOST_UNREACHABLE: CURLproxycode = 21;
pub const CURLPX_REPLY_GENERAL_SERVER_FAILURE: CURLproxycode = 20;
pub const CURLPX_REPLY_CONNECTION_REFUSED: CURLproxycode = 19;
pub const CURLPX_REPLY_COMMAND_NOT_SUPPORTED: CURLproxycode = 18;
pub const CURLPX_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: CURLproxycode = 17;
pub const CURLPX_RECV_REQACK: CURLproxycode = 16;
pub const CURLPX_RECV_CONNECT: CURLproxycode = 15;
pub const CURLPX_RECV_AUTH: CURLproxycode = 14;
pub const CURLPX_RECV_ADDRESS: CURLproxycode = 13;
pub const CURLPX_NO_AUTH: CURLproxycode = 12;
pub const CURLPX_LONG_USER: CURLproxycode = 11;
pub const CURLPX_LONG_PASSWD: CURLproxycode = 10;
pub const CURLPX_LONG_HOSTNAME: CURLproxycode = 9;
pub const CURLPX_IDENTD_DIFFER: CURLproxycode = 8;
pub const CURLPX_IDENTD: CURLproxycode = 7;
pub const CURLPX_GSSAPI_PROTECTION: CURLproxycode = 6;
pub const CURLPX_GSSAPI_PERMSG: CURLproxycode = 5;
pub const CURLPX_GSSAPI: CURLproxycode = 4;
pub const CURLPX_CLOSED: CURLproxycode = 3;
pub const CURLPX_BAD_VERSION: CURLproxycode = 2;
pub const CURLPX_BAD_ADDRESS_TYPE: CURLproxycode = 1;
pub const CURLPX_OK: CURLproxycode = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_certinfo {
    pub num_of_certs: i32,
    pub certinfo: *mut *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_slist {
    pub data: *mut i8,
    pub next: *mut curl_slist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct WildcardData {
    pub state: wildcard_states,
    pub path: *mut i8,
    pub pattern: *mut i8,
    pub filelist: Curl_llist,
    pub protdata: *mut libc::c_void,
    pub dtor: wildcard_dtor,
    pub customptr: *mut libc::c_void,
}
pub type wildcard_dtor = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist {
    pub head: *mut Curl_llist_element,
    pub tail: *mut Curl_llist_element,
    pub dtor: Curl_llist_dtor,
    pub size: size_t,
}
pub type Curl_llist_dtor = Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_llist_element {
    pub ptr: *mut libc::c_void,
    pub prev: *mut Curl_llist_element,
    pub next: *mut Curl_llist_element,
}
pub type wildcard_states = u32;
pub const CURLWC_DONE: wildcard_states = 7;
pub const CURLWC_ERROR: wildcard_states = 6;
pub const CURLWC_SKIP: wildcard_states = 5;
pub const CURLWC_CLEAN: wildcard_states = 4;
pub const CURLWC_DOWNLOADING: wildcard_states = 3;
pub const CURLWC_MATCHING: wildcard_states = 2;
pub const CURLWC_INIT: wildcard_states = 1;
pub const CURLWC_CLEAR: wildcard_states = 0;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UrlState {
    pub conn_cache: *mut conncache,
    pub keeps_speed: curltime,
    pub lastconnect_id: i64,
    pub headerb: dynbuf,
    pub buffer: *mut i8,
    pub ulbuf: *mut i8,
    pub current_speed: curl_off_t,
    pub first_host: *mut i8,
    pub retrycount: i32,
    pub first_remote_port: i32,
    pub session: *mut Curl_ssl_session,
    pub sessionage: i64,
    pub tempwrite: [tempbuf; 3],
    pub tempcount: u32,
    pub os_errno: i32,
    pub scratch: *mut i8,
    pub followlocation: i64,
    pub prev_signal: Option<unsafe extern "C" fn(i32) -> ()>,
    pub digest: digestdata,
    pub proxydigest: digestdata,
    pub authhost: auth,
    pub authproxy: auth,
    pub async_0: Curl_async,
    pub engine: *mut libc::c_void,
    pub expiretime: curltime,
    pub timenode: Curl_tree,
    pub timeoutlist: Curl_llist,
    pub expires: [time_node; 13],
    pub most_recent_ftp_entrypath: *mut i8,
    pub httpwant: u8,
    pub httpversion: u8,
    #[bitfield(name = "prev_block_had_trailing_cr", ty = "bit", bits = "0..=0")]
    pub prev_block_had_trailing_cr: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 5],
    pub crlf_conversions: curl_off_t,
    pub range: *mut i8,
    pub resume_from: curl_off_t,
    pub rtsp_next_client_CSeq: i64,
    pub rtsp_next_server_CSeq: i64,
    pub rtsp_CSeq_recv: i64,
    pub infilesize: curl_off_t,
    pub drain: size_t,
    pub fread_func: curl_read_callback,
    pub in_0: *mut libc::c_void,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: i32,
    pub uh: *mut CURLU,
    pub up: urlpieces,
    pub httpreq: Curl_HttpReq,
    pub url: *mut i8,
    pub referer: *mut i8,
    pub cookielist: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub trailers_bytes_sent: size_t,
    pub trailers_buf: dynbuf,
    pub trailers_state: trailers_state,
    pub aptr: dynamically_allocated_data,
    #[bitfield(name = "multi_owned_by_easy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "this_is_a_follow", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "refused_stream", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "errorbuf", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "allow_port", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "authproblem", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ftp_trying_alternative", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "wildcardmatch", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "expect100header", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "disableexpect", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "use_range", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "rangestringalloc", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "done", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "previouslypending", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "cookie_engine", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "list_only", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "url_alloc", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "referer_alloc", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "wildcard_resolve", ty = "bit", bits = "20..=20")]
    pub multi_owned_by_easy_this_is_a_follow_refused_stream_errorbuf_allow_port_authproblem_ftp_trying_alternative_wildcardmatch_expect100header_disableexpect_use_range_rangestringalloc_done_stream_depends_e_previouslypending_cookie_engine_prefer_ascii_list_only_url_alloc_referer_alloc_wildcard_resolve:
        [u8; 3],
    #[bitfield(padding)]
    pub c2rust_padding_0: [u8; 5],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynamically_allocated_data {
    pub proxyuserpwd: *mut i8,
    pub uagent: *mut i8,
    pub accept_encoding: *mut i8,
    pub userpwd: *mut i8,
    pub rangeline: *mut i8,
    pub ref_0: *mut i8,
    pub host: *mut i8,
    pub cookiehost: *mut i8,
    pub rtsp_transport: *mut i8,
    pub te: *mut i8,
    pub user: *mut i8,
    pub passwd: *mut i8,
    pub proxyuser: *mut i8,
    pub proxypasswd: *mut i8,
}
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dynbuf {
    pub bufr: *mut i8,
    pub leng: size_t,
    pub allc: size_t,
    pub toobig: size_t,
}
pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct urlpieces {
    pub scheme: *mut i8,
    pub hostname: *mut i8,
    pub port: *mut i8,
    pub user: *mut i8,
    pub password: *mut i8,
    pub options: *mut i8,
    pub path: *mut i8,
    pub query: *mut i8,
}
pub type CURLU = Curl_URL;
pub type curl_read_callback =
    Option<unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct time_node {
    pub list: Curl_llist_element,
    pub time: curltime,
    pub eid: expire_id,
}
pub type expire_id = u32;
pub const EXPIRE_LAST: expire_id = 13;
pub const EXPIRE_QUIC: expire_id = 12;
pub const EXPIRE_TOOFAST: expire_id = 11;
pub const EXPIRE_TIMEOUT: expire_id = 10;
pub const EXPIRE_SPEEDCHECK: expire_id = 9;
pub const EXPIRE_RUN_NOW: expire_id = 8;
pub const EXPIRE_MULTI_PENDING: expire_id = 7;
pub const EXPIRE_HAPPY_EYEBALLS: expire_id = 6;
pub const EXPIRE_HAPPY_EYEBALLS_DNS: expire_id = 5;
pub const EXPIRE_DNS_PER_NAME2: expire_id = 4;
pub const EXPIRE_DNS_PER_NAME: expire_id = 3;
pub const EXPIRE_CONNECTTIMEOUT: expire_id = 2;
pub const EXPIRE_ASYNC_NAME: expire_id = 1;
pub const EXPIRE_100_TIMEOUT: expire_id = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curltime {
    pub tv_sec: time_t,
    pub tv_usec: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_tree {
    pub smaller: *mut Curl_tree,
    pub larger: *mut Curl_tree,
    pub samen: *mut Curl_tree,
    pub samep: *mut Curl_tree,
    pub key: curltime,
    pub payload: *mut libc::c_void,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Curl_async {
    pub hostname: *mut i8,
    pub dns: *mut Curl_dns_entry,
    pub tdata: *mut thread_data,
    pub resolver: *mut libc::c_void,
    pub port: i32,
    pub status: i32,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    pub done: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_dns_entry {
    pub addr: *mut Curl_addrinfo,
    pub timestamp: time_t,
    pub inuse: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_addrinfo {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: curl_socklen_t,
    pub ai_canonname: *mut i8,
    pub ai_addr: *mut sockaddr,
    pub ai_next: *mut Curl_addrinfo,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct auth {
    pub want: u64,
    pub picked: u64,
    pub avail: u64,
    #[bitfield(name = "done", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "multipass", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "iestyle", ty = "bit", bits = "2..=2")]
    pub done_multipass_iestyle: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct digestdata {
    pub nonce: *mut i8,
    pub cnonce: *mut i8,
    pub realm: *mut i8,
    pub algo: i32,
    pub opaque: *mut i8,
    pub qop: *mut i8,
    pub algorithm: *mut i8,
    pub nc: i32,
    #[bitfield(name = "stale", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "userhash", ty = "bit", bits = "1..=1")]
    pub stale_userhash: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tempbuf {
    pub b: dynbuf,
    pub type_0: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl_session {
    pub name: *mut i8,
    pub conn_to_host: *mut i8,
    pub scheme: *const i8,
    pub sessionid: *mut libc::c_void,
    pub idsize: size_t,
    pub age: i64,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub ssl_config: ssl_primary_config,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_primary_config {
    pub version: i64,
    pub version_max: i64,
    pub CApath: *mut i8,
    pub CAfile: *mut i8,
    pub issuercert: *mut i8,
    pub clientcert: *mut i8,
    pub random_file: *mut i8,
    pub egdsocket: *mut i8,
    pub cipher_list: *mut i8,
    pub cipher_list13: *mut i8,
    pub pinned_key: *mut i8,
    pub cert_blob: *mut curl_blob,
    pub ca_info_blob: *mut curl_blob,
    pub issuercert_blob: *mut curl_blob,
    pub curves: *mut i8,
    #[bitfield(name = "verifypeer", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "verifyhost", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "verifystatus", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "sessionid", ty = "bit", bits = "3..=3")]
    pub verifypeer_verifyhost_verifystatus_sessionid: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_blob {
    pub data: *mut libc::c_void,
    pub len: size_t,
    pub flags: u32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct conncache {
    pub hash: Curl_hash,
    pub num_conn: size_t,
    pub next_connection_id: i64,
    pub last_cleanup: curltime,
    pub closure_handle: *mut Curl_easy,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_hash {
    pub table: *mut Curl_llist,
    pub hash_func: hash_function,
    pub comp_func: comp_function,
    pub dtor: Curl_hash_dtor,
    pub slots: i32,
    pub size: size_t,
}
pub type Curl_hash_dtor = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type comp_function =
    Option<unsafe extern "C" fn(*mut libc::c_void, size_t, *mut libc::c_void, size_t) -> size_t>;
pub type hash_function = Option<unsafe extern "C" fn(*mut libc::c_void, size_t, size_t) -> size_t>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct Progress {
    pub lastshow: time_t,
    pub size_dl: curl_off_t,
    pub size_ul: curl_off_t,
    pub downloaded: curl_off_t,
    pub uploaded: curl_off_t,
    pub current_speed: curl_off_t,
    pub width: i32,
    pub flags: i32,
    pub timespent: timediff_t,
    pub dlspeed: curl_off_t,
    pub ulspeed: curl_off_t,
    pub t_nslookup: timediff_t,
    pub t_connect: timediff_t,
    pub t_appconnect: timediff_t,
    pub t_pretransfer: timediff_t,
    pub t_starttransfer: timediff_t,
    pub t_redirect: timediff_t,
    pub start: curltime,
    pub t_startsingle: curltime,
    pub t_startop: curltime,
    pub t_acceptdata: curltime,
    pub ul_limit_start: curltime,
    pub ul_limit_size: curl_off_t,
    pub dl_limit_start: curltime,
    pub dl_limit_size: curl_off_t,
    pub speeder: [curl_off_t; 6],
    pub speeder_time: [curltime; 6],
    pub speeder_c: i32,
    #[bitfield(name = "callback", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_t_startransfer_set", ty = "bit", bits = "1..=1")]
    pub callback_is_t_startransfer_set: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type timediff_t = curl_off_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CookieInfo {
    pub cookies: [*mut Cookie; 256],
    pub filename: *mut i8,
    pub numcookies: i64,
    pub running: bool,
    pub newsession: bool,
    pub lastct: i32,
    pub next_expiration: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Cookie {
    pub next: *mut Cookie,
    pub name: *mut i8,
    pub value: *mut i8,
    pub path: *mut i8,
    pub spath: *mut i8,
    pub domain: *mut i8,
    pub expires: curl_off_t,
    pub expirestr: *mut i8,
    pub version: *mut i8,
    pub maxage: *mut i8,
    pub tailmatch: bool,
    pub secure: bool,
    pub livecookie: bool,
    pub httponly: bool,
    pub creationtime: i32,
    pub prefix: u8,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct UserDefined {
    pub err: *mut FILE,
    pub debugdata: *mut libc::c_void,
    pub errorbuffer: *mut i8,
    pub proxyport: i64,
    pub out: *mut libc::c_void,
    pub in_set: *mut libc::c_void,
    pub writeheader: *mut libc::c_void,
    pub rtp_out: *mut libc::c_void,
    pub use_port: i64,
    pub httpauth: u64,
    pub proxyauth: u64,
    pub socks5auth: u64,
    pub maxredirs: i64,
    pub keep_post: i32,
    pub postfields: *mut libc::c_void,
    pub seek_func: curl_seek_callback,
    pub postfieldsize: curl_off_t,
    pub localport: u16,
    pub localportrange: i32,
    pub fwrite_func: curl_write_callback,
    pub fwrite_header: curl_write_callback,
    pub fwrite_rtp: curl_write_callback,
    pub fread_func_set: curl_read_callback,
    pub fprogress: curl_progress_callback,
    pub fxferinfo: curl_xferinfo_callback,
    pub fdebug: curl_debug_callback,
    pub ioctl_func: curl_ioctl_callback,
    pub fsockopt: curl_sockopt_callback,
    pub sockopt_client: *mut libc::c_void,
    pub fopensocket: curl_opensocket_callback,
    pub opensocket_client: *mut libc::c_void,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub seek_client: *mut libc::c_void,
    pub convfromnetwork: curl_conv_callback,
    pub convtonetwork: curl_conv_callback,
    pub convfromutf8: curl_conv_callback,
    pub hsts_read: curl_hstsread_callback,
    pub hsts_read_userp: *mut libc::c_void,
    pub hsts_write: curl_hstswrite_callback,
    pub hsts_write_userp: *mut libc::c_void,
    pub progress_client: *mut libc::c_void,
    pub ioctl_client: *mut libc::c_void,
    pub timeout: i64,
    pub connecttimeout: i64,
    pub accepttimeout: i64,
    pub happy_eyeballs_timeout: i64,
    pub server_response_timeout: i64,
    pub maxage_conn: i64,
    pub tftp_blksize: i64,
    pub filesize: curl_off_t,
    pub low_speed_limit: i64,
    pub low_speed_time: i64,
    pub max_send_speed: curl_off_t,
    pub max_recv_speed: curl_off_t,
    pub set_resume_from: curl_off_t,
    pub headers: *mut curl_slist,
    pub proxyheaders: *mut curl_slist,
    pub httppost: *mut curl_httppost,
    pub mimepost: curl_mimepart,
    pub quote: *mut curl_slist,
    pub postquote: *mut curl_slist,
    pub prequote: *mut curl_slist,
    pub source_quote: *mut curl_slist,
    pub source_prequote: *mut curl_slist,
    pub source_postquote: *mut curl_slist,
    pub telnet_options: *mut curl_slist,
    pub resolve: *mut curl_slist,
    pub connect_to: *mut curl_slist,
    pub timecondition: curl_TimeCond,
    pub proxytype: curl_proxytype,
    pub timevalue: time_t,
    pub method: Curl_HttpReq,
    pub httpwant: u8,
    pub ssl: ssl_config_data,
    pub proxy_ssl: ssl_config_data,
    pub general_ssl: ssl_general_config,
    pub dns_cache_timeout: i64,
    pub buffer_size: i64,
    pub upload_buffer_size: u32,
    pub private_data: *mut libc::c_void,
    pub http200aliases: *mut curl_slist,
    pub ipver: u8,
    pub max_filesize: curl_off_t,
    pub ftp_filemethod: curl_ftpfile,
    pub ftpsslauth: curl_ftpauth,
    pub ftp_ccc: curl_ftpccc,
    pub ftp_create_missing_dirs: i32,
    pub ssh_keyfunc: curl_sshkeycallback,
    pub ssh_keyfunc_userp: *mut libc::c_void,
    pub use_netrc: CURL_NETRC_OPTION,
    pub use_ssl: curl_usessl,
    pub new_file_perms: i64,
    pub new_directory_perms: i64,
    pub ssh_auth_types: i64,
    pub str_0: [*mut i8; 80],
    pub blobs: [*mut curl_blob; 8],
    pub scope_id: u32,
    pub allowed_protocols: i64,
    pub redir_protocols: i64,
    pub mail_rcpt: *mut curl_slist,
    pub rtspreq: Curl_RtspReq,
    pub rtspversion: i64,
    pub chunk_bgn: curl_chunk_bgn_callback,
    pub chunk_end: curl_chunk_end_callback,
    pub fnmatch: curl_fnmatch_callback,
    pub fnmatch_data: *mut libc::c_void,
    pub gssapi_delegation: i64,
    pub tcp_keepidle: i64,
    pub tcp_keepintvl: i64,
    pub maxconnects: size_t,
    pub expect_100_timeout: i64,
    pub stream_depends_on: *mut Curl_easy,
    pub stream_weight: i32,
    pub stream_dependents: *mut Curl_http2_dep,
    pub resolver_start: curl_resolver_start_callback,
    pub resolver_start_client: *mut libc::c_void,
    pub upkeep_interval_ms: i64,
    pub fmultidone: multidone_func,
    pub dohfor: *mut Curl_easy,
    pub uh: *mut CURLU,
    pub trailer_data: *mut libc::c_void,
    pub trailer_callback: curl_trailer_callback,
    #[bitfield(name = "is_fread_set", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "is_fwrite_set", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "free_referer", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tftp_no_options", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "sep_headers", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "cookiesession", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "crlf", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "strip_path_slash", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "ssh_compression", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "get_filetime", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "tunnel_thru_httpproxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "prefer_ascii", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "remote_append", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "list_only", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "ftp_use_port", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "ftp_use_pret", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "ftp_skip_ip", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "hide_progress", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "http_fail_on_error", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "http_keep_sending_on_error", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "http_follow_location", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "http_transfer_encoding", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "allow_auth_to_other_hosts", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "include_header", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "http_set_referer", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "http_auto_referer", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "opt_no_body", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "upload", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "verbose", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "krb", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "reuse_forbid", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "reuse_fresh", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "no_signal", ty = "bit", bits = "34..=34")]
    #[bitfield(name = "tcp_nodelay", ty = "bit", bits = "35..=35")]
    #[bitfield(name = "ignorecl", ty = "bit", bits = "36..=36")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "37..=37")]
    #[bitfield(name = "http_te_skip", ty = "bit", bits = "38..=38")]
    #[bitfield(name = "http_ce_skip", ty = "bit", bits = "39..=39")]
    #[bitfield(name = "proxy_transfer_mode", ty = "bit", bits = "40..=40")]
    #[bitfield(name = "sasl_ir", ty = "bit", bits = "41..=41")]
    #[bitfield(name = "wildcard_enabled", ty = "bit", bits = "42..=42")]
    #[bitfield(name = "tcp_keepalive", ty = "bit", bits = "43..=43")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "44..=44")]
    #[bitfield(name = "ssl_enable_npn", ty = "bit", bits = "45..=45")]
    #[bitfield(name = "ssl_enable_alpn", ty = "bit", bits = "46..=46")]
    #[bitfield(name = "path_as_is", ty = "bit", bits = "47..=47")]
    #[bitfield(name = "pipewait", ty = "bit", bits = "48..=48")]
    #[bitfield(name = "suppress_connect_headers", ty = "bit", bits = "49..=49")]
    #[bitfield(name = "dns_shuffle_addresses", ty = "bit", bits = "50..=50")]
    #[bitfield(name = "stream_depends_e", ty = "bit", bits = "51..=51")]
    #[bitfield(name = "haproxyprotocol", ty = "bit", bits = "52..=52")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "53..=53")]
    #[bitfield(name = "disallow_username_in_url", ty = "bit", bits = "54..=54")]
    #[bitfield(name = "doh", ty = "bit", bits = "55..=55")]
    #[bitfield(name = "doh_get", ty = "bit", bits = "56..=56")]
    #[bitfield(name = "doh_verifypeer", ty = "bit", bits = "57..=57")]
    #[bitfield(name = "doh_verifyhost", ty = "bit", bits = "58..=58")]
    #[bitfield(name = "doh_verifystatus", ty = "bit", bits = "59..=59")]
    #[bitfield(name = "http09_allowed", ty = "bit", bits = "60..=60")]
    #[bitfield(name = "mail_rcpt_allowfails", ty = "bit", bits = "61..=61")]
    pub is_fread_set_is_fwrite_set_free_referer_tftp_no_options_sep_headers_cookiesession_crlf_strip_path_slash_ssh_compression_get_filetime_tunnel_thru_httpproxy_prefer_ascii_remote_append_list_only_ftp_use_port_ftp_use_epsv_ftp_use_eprt_ftp_use_pret_ftp_skip_ip_hide_progress_http_fail_on_error_http_keep_sending_on_error_http_follow_location_http_transfer_encoding_allow_auth_to_other_hosts_include_header_http_set_referer_http_auto_referer_opt_no_body_upload_verbose_krb_reuse_forbid_reuse_fresh_no_signal_tcp_nodelay_ignorecl_connect_only_http_te_skip_http_ce_skip_proxy_transfer_mode_sasl_ir_wildcard_enabled_tcp_keepalive_tcp_fastopen_ssl_enable_npn_ssl_enable_alpn_path_as_is_pipewait_suppress_connect_headers_dns_shuffle_addresses_stream_depends_e_haproxyprotocol_abstract_unix_socket_disallow_username_in_url_doh_doh_get_doh_verifypeer_doh_verifyhost_doh_verifystatus_http09_allowed_mail_rcpt_allowfails:
        [u8; 8],
}
pub type curl_trailer_callback =
    Option<unsafe extern "C" fn(*mut *mut curl_slist, *mut libc::c_void) -> i32>;
pub type multidone_func = Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode) -> i32>;
pub type CURLcode = u32;
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
pub type curl_resolver_start_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_void, *mut libc::c_void) -> i32>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_http2_dep {
    pub next: *mut Curl_http2_dep,
    pub data: *mut Curl_easy,
}
pub type curl_fnmatch_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, *const i8) -> i32>;
pub type curl_chunk_end_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i64>;
pub type curl_chunk_bgn_callback =
    Option<unsafe extern "C" fn(*const libc::c_void, *mut libc::c_void, i32) -> i64>;
pub type Curl_RtspReq = u32;
pub const RTSPREQ_LAST: Curl_RtspReq = 12;
pub const RTSPREQ_RECEIVE: Curl_RtspReq = 11;
pub const RTSPREQ_RECORD: Curl_RtspReq = 10;
pub const RTSPREQ_SET_PARAMETER: Curl_RtspReq = 9;
pub const RTSPREQ_GET_PARAMETER: Curl_RtspReq = 8;
pub const RTSPREQ_TEARDOWN: Curl_RtspReq = 7;
pub const RTSPREQ_PAUSE: Curl_RtspReq = 6;
pub const RTSPREQ_PLAY: Curl_RtspReq = 5;
pub const RTSPREQ_SETUP: Curl_RtspReq = 4;
pub const RTSPREQ_ANNOUNCE: Curl_RtspReq = 3;
pub const RTSPREQ_DESCRIBE: Curl_RtspReq = 2;
pub const RTSPREQ_OPTIONS: Curl_RtspReq = 1;
pub const RTSPREQ_NONE: Curl_RtspReq = 0;
pub type curl_usessl = u32;
pub const CURLUSESSL_LAST: curl_usessl = 4;
pub const CURLUSESSL_ALL: curl_usessl = 3;
pub const CURLUSESSL_CONTROL: curl_usessl = 2;
pub const CURLUSESSL_TRY: curl_usessl = 1;
pub const CURLUSESSL_NONE: curl_usessl = 0;
pub type CURL_NETRC_OPTION = u32;
pub const CURL_NETRC_LAST: CURL_NETRC_OPTION = 3;
pub const CURL_NETRC_REQUIRED: CURL_NETRC_OPTION = 2;
pub const CURL_NETRC_OPTIONAL: CURL_NETRC_OPTION = 1;
pub const CURL_NETRC_IGNORED: CURL_NETRC_OPTION = 0;
pub type curl_sshkeycallback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *const curl_khkey,
        *const curl_khkey,
        curl_khmatch,
        *mut libc::c_void,
    ) -> i32,
>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_khkey {
    pub key: *const i8,
    pub len: size_t,
    pub keytype: curl_khtype,
}
pub type curl_khtype = u32;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = Curl_easy;
pub type curl_ftpccc = u32;
pub const CURLFTPSSL_CCC_LAST: curl_ftpccc = 3;
pub const CURLFTPSSL_CCC_ACTIVE: curl_ftpccc = 2;
pub const CURLFTPSSL_CCC_PASSIVE: curl_ftpccc = 1;
pub const CURLFTPSSL_CCC_NONE: curl_ftpccc = 0;
pub type curl_ftpauth = u32;
pub const CURLFTPAUTH_LAST: curl_ftpauth = 3;
pub const CURLFTPAUTH_TLS: curl_ftpauth = 2;
pub const CURLFTPAUTH_SSL: curl_ftpauth = 1;
pub const CURLFTPAUTH_DEFAULT: curl_ftpauth = 0;
pub type curl_ftpfile = u32;
pub const FTPFILE_SINGLECWD: curl_ftpfile = 3;
pub const FTPFILE_NOCWD: curl_ftpfile = 2;
pub const FTPFILE_MULTICWD: curl_ftpfile = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_general_config {
    pub max_ssl_sessions: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_config_data {
    pub primary: ssl_primary_config,
    pub certverifyresult: i64,
    pub CRLfile: *mut i8,
    pub fsslctx: curl_ssl_ctx_callback,
    pub fsslctxp: *mut libc::c_void,
    pub cert_type: *mut i8,
    pub key: *mut i8,
    pub key_blob: *mut curl_blob,
    pub key_type: *mut i8,
    pub key_passwd: *mut i8,
    pub username: *mut i8,
    pub password: *mut i8,
    pub authtype: CURL_TLSAUTH,
    #[bitfield(name = "certinfo", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "falsestart", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "enable_beast", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "no_revoke", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "no_partialchain", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "revoke_best_effort", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "native_ca_store", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "auto_client_cert", ty = "bit", bits = "7..=7")]
    pub certinfo_falsestart_enable_beast_no_revoke_no_partialchain_revoke_best_effort_native_ca_store_auto_client_cert:
        [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback =
    Option<unsafe extern "C" fn(*mut CURL, *mut libc::c_void, *mut libc::c_void) -> CURLcode>;
pub type curl_proxytype = u32;
pub const CURLPROXY_SOCKS5_HOSTNAME: curl_proxytype = 7;
pub const CURLPROXY_SOCKS4A: curl_proxytype = 6;
pub const CURLPROXY_SOCKS5: curl_proxytype = 5;
pub const CURLPROXY_SOCKS4: curl_proxytype = 4;
pub const CURLPROXY_HTTPS: curl_proxytype = 2;
pub const CURLPROXY_HTTP_1_0: curl_proxytype = 1;
pub const CURLPROXY_HTTP: curl_proxytype = 0;
pub type curl_TimeCond = u32;
pub const CURL_TIMECOND_LAST: curl_TimeCond = 4;
pub const CURL_TIMECOND_LASTMOD: curl_TimeCond = 3;
pub const CURL_TIMECOND_IFUNMODSINCE: curl_TimeCond = 2;
pub const CURL_TIMECOND_IFMODSINCE: curl_TimeCond = 1;
pub const CURL_TIMECOND_NONE: curl_TimeCond = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mimepart {
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mime,
    pub nextpart: *mut curl_mimepart,
    pub kind: mimekind,
    pub flags: u32,
    pub data: *mut i8,
    pub readfunc: curl_read_callback,
    pub seekfunc: curl_seek_callback,
    pub freefunc: curl_free_callback,
    pub arg: *mut libc::c_void,
    pub fp: *mut FILE,
    pub curlheaders: *mut curl_slist,
    pub userheaders: *mut curl_slist,
    pub mimetype: *mut i8,
    pub filename: *mut i8,
    pub name: *mut i8,
    pub datasize: curl_off_t,
    pub state: mime_state,
    pub encoder: *const mime_encoder,
    pub encstate: mime_encoder_state,
    pub lastreadstatus: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder_state {
    pub pos: size_t,
    pub bufbeg: size_t,
    pub bufend: size_t,
    pub buf: [i8; 256],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_encoder {
    pub name: *const i8,
    pub encodefunc:
        Option<unsafe extern "C" fn(*mut i8, size_t, bool, *mut curl_mimepart) -> size_t>,
    pub sizefunc: Option<unsafe extern "C" fn(*mut curl_mimepart) -> curl_off_t>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mime_state {
    pub state: mimestate,
    pub ptr: *mut libc::c_void,
    pub offset: curl_off_t,
}
pub type mimestate = u32;
pub const MIMESTATE_LAST: mimestate = 9;
pub const MIMESTATE_END: mimestate = 8;
pub const MIMESTATE_CONTENT: mimestate = 7;
pub const MIMESTATE_BOUNDARY2: mimestate = 6;
pub const MIMESTATE_BOUNDARY1: mimestate = 5;
pub const MIMESTATE_BODY: mimestate = 4;
pub const MIMESTATE_EOH: mimestate = 3;
pub const MIMESTATE_USERHEADERS: mimestate = 2;
pub const MIMESTATE_CURLHEADERS: mimestate = 1;
pub const MIMESTATE_BEGIN: mimestate = 0;
pub type curl_free_callback = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type curl_seek_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_off_t, i32) -> i32>;
pub type mimekind = u32;
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_mime {
    pub easy: *mut Curl_easy,
    pub parent: *mut curl_mimepart,
    pub firstpart: *mut curl_mimepart,
    pub lastpart: *mut curl_mimepart,
    pub boundary: [i8; 41],
    pub state: mime_state,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_httppost {
    pub next: *mut curl_httppost,
    pub name: *mut i8,
    pub namelength: i64,
    pub contents: *mut i8,
    pub contentslength: i64,
    pub buffer: *mut i8,
    pub bufferlength: i64,
    pub contenttype: *mut i8,
    pub contentheader: *mut curl_slist,
    pub more: *mut curl_httppost,
    pub flags: i64,
    pub showfilename: *mut i8,
    pub userp: *mut libc::c_void,
    pub contentlen: curl_off_t,
}
pub type curl_hstswrite_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *mut curl_hstsentry,
        *mut curl_index,
        *mut libc::c_void,
    ) -> CURLSTScode,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_index {
    pub index: size_t,
    pub total: size_t,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct curl_hstsentry {
    pub name: *mut i8,
    pub namelen: size_t,
    #[bitfield(name = "includeSubDomains", ty = "u32", bits = "0..=0")]
    pub includeSubDomains: [u8; 1],
    pub expire: [i8; 18],
}
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback =
    Option<unsafe extern "C" fn(*mut CURL, *mut curl_hstsentry, *mut libc::c_void) -> CURLSTScode>;
pub type curl_conv_callback = Option<unsafe extern "C" fn(*mut i8, size_t) -> CURLcode>;
pub type curl_closesocket_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_socket_t) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback = Option<
    unsafe extern "C" fn(*mut libc::c_void, curlsocktype, *mut curl_sockaddr) -> curl_socket_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_sockaddr {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addrlen: u32,
    pub addr: sockaddr,
}
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, curl_socket_t, curlsocktype) -> i32>;
pub type curl_ioctl_callback =
    Option<unsafe extern "C" fn(*mut CURL, i32, *mut libc::c_void) -> curlioerr>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback = Option<
    unsafe extern "C" fn(*mut CURL, curl_infotype, *mut i8, size_t, *mut libc::c_void) -> i32,
>;
pub type curl_infotype = u32;
pub const CURLINFO_END: curl_infotype = 7;
pub const CURLINFO_SSL_DATA_OUT: curl_infotype = 6;
pub const CURLINFO_SSL_DATA_IN: curl_infotype = 5;
pub const CURLINFO_DATA_OUT: curl_infotype = 4;
pub const CURLINFO_DATA_IN: curl_infotype = 3;
pub const CURLINFO_HEADER_OUT: curl_infotype = 2;
pub const CURLINFO_HEADER_IN: curl_infotype = 1;
pub const CURLINFO_TEXT: curl_infotype = 0;
pub type curl_xferinfo_callback = Option<
    unsafe extern "C" fn(*mut libc::c_void, curl_off_t, curl_off_t, curl_off_t, curl_off_t) -> i32,
>;
pub type curl_progress_callback =
    Option<unsafe extern "C" fn(*mut libc::c_void, f64, f64, f64, f64) -> i32>;
pub type curl_write_callback =
    Option<unsafe extern "C" fn(*mut i8, size_t, size_t, *mut libc::c_void) -> size_t>;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct SingleRequest {
    pub size: curl_off_t,
    pub maxdownload: curl_off_t,
    pub bytecount: curl_off_t,
    pub writebytecount: curl_off_t,
    pub headerbytecount: curl_off_t,
    pub deductheadercount: curl_off_t,
    pub pendingheader: curl_off_t,
    pub start: curltime,
    pub now: curltime,
    pub badheader: C2RustUnnamed_2,
    pub headerline: i32,
    pub str_0: *mut i8,
    pub offset: curl_off_t,
    pub httpcode: i32,
    pub keepon: i32,
    pub start100: curltime,
    pub exp100: expect100,
    pub upgr101: upgrade101,
    pub writer_stack: *mut contenc_writer,
    pub timeofdoc: time_t,
    pub bodywrites: i64,
    pub location: *mut i8,
    pub newurl: *mut i8,
    pub upload_present: ssize_t,
    pub upload_fromhere: *mut i8,
    pub p: C2RustUnnamed_0,
    pub doh: *mut dohdata,
    #[bitfield(name = "header", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "content_range", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "upload_done", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "ignorebody", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "http_bodyless", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "chunk", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "ignore_cl", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "upload_chunky", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "getheader", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "forbidchunk", ty = "bit", bits = "9..=9")]
    pub header_content_range_upload_done_ignorebody_http_bodyless_chunk_ignore_cl_upload_chunky_getheader_forbidchunk:
        [u8; 2],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 6],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dohdata {
    pub headers: *mut curl_slist,
    pub probe: [dnsprobe; 2],
    pub pending: u32,
    pub port: i32,
    pub host: *const i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dnsprobe {
    pub easy: *mut CURL,
    pub dnstype: i32,
    pub dohbuffer: [u8; 512],
    pub dohlen: size_t,
    pub serverdoh: dynbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub file: *mut FILEPROTO,
    pub ftp: *mut FTP,
    pub http: *mut HTTP,
    pub imap: *mut IMAP,
    pub ldap: *mut ldapreqinfo,
    pub mqtt: *mut MQTT,
    pub pop3: *mut POP3,
    pub rtsp: *mut RTSP,
    pub smb: *mut smb_request,
    pub smtp: *mut SMTP,
    pub ssh: *mut SSHPROTO,
    pub telnet: *mut TELNET,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SSHPROTO {
    pub path: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SMTP {
    pub transfer: curl_pp_transfer,
    pub custom: *mut i8,
    pub rcpt: *mut curl_slist,
    pub rcpt_had_ok: bool,
    pub trailing_crlf: bool,
    pub rcpt_last_error: i32,
    pub eob: size_t,
}
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct RTSP {
    pub http_wrapper: HTTP,
    pub CSeq_sent: i64,
    pub CSeq_recv: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct HTTP {
    pub sendit: *mut curl_mimepart,
    pub postsize: curl_off_t,
    pub postdata: *const i8,
    pub p_pragma: *const i8,
    pub form: curl_mimepart,
    pub backup: back,
    pub sending: C2RustUnnamed_1,
    pub send_buffer: dynbuf,
    pub stream_id: int32_t,
    pub bodystarted: bool,
    pub header_recvbuf: dynbuf,
    pub nread_header_recvbuf: size_t,
    pub trailer_recvbuf: dynbuf,
    pub status_code: i32,
    pub pausedata: *const uint8_t,
    pub pauselen: size_t,
    pub close_handled: bool,
    pub push_headers: *mut *mut i8,
    pub push_headers_used: size_t,
    pub push_headers_alloc: size_t,
    pub error: uint32_t,
    pub closed: bool,
    pub mem: *mut i8,
    pub len: size_t,
    pub memlen: size_t,
    pub upload_mem: *const uint8_t,
    pub upload_len: size_t,
    pub upload_left: curl_off_t,
}
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct back {
    pub fread_func: curl_read_callback,
    pub fread_in: *mut libc::c_void,
    pub postdata: *const i8,
    pub postsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct POP3 {
    pub transfer: curl_pp_transfer,
    pub id: *mut i8,
    pub custom: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MQTT {
    pub sendleftovers: *mut i8,
    pub nsend: size_t,
    pub npacket: size_t,
    pub firstbyte: u8,
    pub remaining_length: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct IMAP {
    pub transfer: curl_pp_transfer,
    pub mailbox: *mut i8,
    pub uidvalidity: *mut i8,
    pub uid: *mut i8,
    pub mindex: *mut i8,
    pub section: *mut i8,
    pub partial: *mut i8,
    pub query: *mut i8,
    pub custom: *mut i8,
    pub custom_params: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FTP {
    pub path: *mut i8,
    pub pathalloc: *mut i8,
    pub transfer: curl_pp_transfer,
    pub downloadsize: curl_off_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct FILEPROTO {
    pub path: *mut i8,
    pub freepath: *mut i8,
    pub fd: i32,
}
pub type upgrade101 = u32;
pub const UPGR101_WORKING: upgrade101 = 3;
pub const UPGR101_RECEIVED: upgrade101 = 2;
pub const UPGR101_REQUESTED: upgrade101 = 1;
pub const UPGR101_INIT: upgrade101 = 0;
pub type expect100 = u32;
pub const EXP100_FAILED: expect100 = 3;
pub const EXP100_SENDING_REQUEST: expect100 = 2;
pub const EXP100_AWAITING_CONTINUE: expect100 = 1;
pub const EXP100_SEND_DATA: expect100 = 0;
pub type C2RustUnnamed_2 = u32;
pub const HEADER_ALLBAD: C2RustUnnamed_2 = 2;
pub const HEADER_PARTHEADER: C2RustUnnamed_2 = 1;
pub const HEADER_NORMAL: C2RustUnnamed_2 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PslCache {
    pub psl: *const psl_ctx_t,
    pub expires: time_t,
    pub dynamic: bool,
}
pub type psl_ctx_t = psl_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_multi {
    pub magic: u32,
    pub easyp: *mut Curl_easy,
    pub easylp: *mut Curl_easy,
    pub num_easy: i32,
    pub num_alive: i32,
    pub msglist: Curl_llist,
    pub pending: Curl_llist,
    pub socket_cb: curl_socket_callback,
    pub socket_userp: *mut libc::c_void,
    pub push_cb: curl_push_callback,
    pub push_userp: *mut libc::c_void,
    pub hostcache: Curl_hash,
    pub psl: PslCache,
    pub timetree: *mut Curl_tree,
    pub sockhash: Curl_hash,
    pub conn_cache: conncache,
    pub maxconnects: i64,
    pub max_host_connections: i64,
    pub max_total_connections: i64,
    pub timer_cb: curl_multi_timer_callback,
    pub timer_userp: *mut libc::c_void,
    pub timer_lastcall: curltime,
    pub max_concurrent_streams: u32,
    pub wakeup_pair: [curl_socket_t; 2],
    pub multiplexing: bool,
    pub recheckstate: bool,
    pub in_callback: bool,
    pub ipv6_works: bool,
    pub ssl_seeded: bool,
}
pub type curl_multi_timer_callback =
    Option<unsafe extern "C" fn(*mut CURLM, i64, *mut libc::c_void) -> i32>;
pub type CURLM = Curl_multi;
pub type curl_push_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        *mut CURL,
        size_t,
        *mut curl_pushheaders,
        *mut libc::c_void,
    ) -> i32,
>;
pub type curl_socket_callback = Option<
    unsafe extern "C" fn(
        *mut CURL,
        curl_socket_t,
        i32,
        *mut libc::c_void,
        *mut libc::c_void,
    ) -> i32,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Names {
    pub hostcache: *mut Curl_hash,
    pub hostcachetype: C2RustUnnamed_3,
}
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_message {
    pub list: Curl_llist_element,
    pub extmsg: CURLMsg,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CURLMsg {
    pub msg: CURLMSG,
    pub easy_handle: *mut CURL,
    pub data: C2RustUnnamed_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub whatever: *mut libc::c_void,
    pub result: CURLcode,
}
pub type CURLMSG = u32;
pub const CURLMSG_LAST: CURLMSG = 2;
pub const CURLMSG_DONE: CURLMSG = 1;
pub const CURLMSG_NONE: CURLMSG = 0;
pub type CURLMstate = u32;
pub const MSTATE_LAST: CURLMstate = 17;
pub const MSTATE_MSGSENT: CURLMstate = 16;
pub const MSTATE_COMPLETED: CURLMstate = 15;
pub const MSTATE_DONE: CURLMstate = 14;
pub const MSTATE_RATELIMITING: CURLMstate = 13;
pub const MSTATE_PERFORMING: CURLMstate = 12;
pub const MSTATE_DID: CURLMstate = 11;
pub const MSTATE_DOING_MORE: CURLMstate = 10;
pub const MSTATE_DOING: CURLMstate = 9;
pub const MSTATE_DO: CURLMstate = 8;
pub const MSTATE_PROTOCONNECTING: CURLMstate = 7;
pub const MSTATE_PROTOCONNECT: CURLMstate = 6;
pub const MSTATE_TUNNELING: CURLMstate = 5;
pub const MSTATE_CONNECTING: CURLMstate = 4;
pub const MSTATE_RESOLVING: CURLMstate = 3;
pub const MSTATE_CONNECT: CURLMstate = 2;
pub const MSTATE_PENDING: CURLMstate = 1;
pub const MSTATE_INIT: CURLMstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectdata {
    pub cnnct: connstate,
    pub bundle_node: Curl_llist_element,
    pub chunk: Curl_chunker,
    pub fclosesocket: curl_closesocket_callback,
    pub closesocket_client: *mut libc::c_void,
    pub connection_id: i64,
    pub dns_entry: *mut Curl_dns_entry,
    pub ip_addr: *mut Curl_addrinfo,
    pub tempaddr: [*mut Curl_addrinfo; 2],
    pub scope_id: u32,
    pub transport: C2RustUnnamed_6,
    pub host: hostname,
    pub hostname_resolve: *mut i8,
    pub secondaryhostname: *mut i8,
    pub conn_to_host: hostname,
    pub socks_proxy: proxy_info,
    pub http_proxy: proxy_info,
    pub port: i32,
    pub remote_port: i32,
    pub conn_to_port: i32,
    pub secondary_port: u16,
    pub primary_ip: [i8; 46],
    pub ip_version: u8,
    pub user: *mut i8,
    pub passwd: *mut i8,
    pub options: *mut i8,
    pub sasl_authzid: *mut i8,
    pub httpversion: u8,
    pub now: curltime,
    pub created: curltime,
    pub lastused: curltime,
    pub sock: [curl_socket_t; 2],
    pub tempsock: [curl_socket_t; 2],
    pub tempfamily: [i32; 2],
    pub recv: [Option<Curl_recv>; 2],
    pub send: [Option<Curl_send>; 2],
    pub ssl: [ssl_connect_data; 2],
    pub proxy_ssl: [ssl_connect_data; 2],
    pub ssl_extra: *mut libc::c_void,
    pub ssl_config: ssl_primary_config,
    pub proxy_ssl_config: ssl_primary_config,
    pub bits: ConnectBits,
    pub num_addr: i32,
    pub connecttime: curltime,
    pub timeoutms_per_addr: [timediff_t; 2],
    pub handler: *const Curl_handler,
    pub given: *const Curl_handler,
    pub keepalive: curltime,
    pub sockfd: curl_socket_t,
    pub writesockfd: curl_socket_t,
    pub easyq: Curl_llist,
    pub seek_func: curl_seek_callback,
    pub seek_client: *mut libc::c_void,
    pub gsasl: gsasldata,
    pub http_ntlm_state: curlntlm,
    pub proxy_ntlm_state: curlntlm,
    pub ntlm: ntlmdata,
    pub proxyntlm: ntlmdata,
    pub trailer: dynbuf,
    pub proto: C2RustUnnamed_5,
    pub connect_state: *mut http_connect_state,
    pub bundle: *mut connectbundle,
    pub unix_domain_socket: *mut i8,
    pub localdev: *mut i8,
    pub localportrange: i32,
    pub cselect_bits: i32,
    pub waitfor: i32,
    pub negnpn: i32,
    pub localport: u16,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connectbundle {
    pub multiuse: i32,
    pub num_connections: size_t,
    pub conn_list: Curl_llist,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_5 {
    pub ftpc: ftp_conn,
    pub httpc: http_conn,
    pub sshc: ssh_conn,
    pub tftpc: *mut tftp_state_data,
    pub imapc: imap_conn,
    pub pop3c: pop3_conn,
    pub smtpc: smtp_conn,
    pub rtspc: rtsp_conn,
    pub smbc: smb_conn,
    pub rtmp: *mut libc::c_void,
    pub ldapc: *mut ldapconninfo,
    pub mqtt: mqtt_conn,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct mqtt_conn {
    pub state: mqttstate,
    pub nextstate: mqttstate,
    pub packetid: u32,
}
pub type mqttstate = u32;
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smb_conn {
    pub state: smb_conn_state,
    pub user: *mut i8,
    pub domain: *mut i8,
    pub share: *mut i8,
    pub challenge: [u8; 8],
    pub session_key: u32,
    pub uid: u16,
    pub recv_buf: *mut i8,
    pub upload_size: size_t,
    pub send_size: size_t,
    pub sent: size_t,
    pub got: size_t,
}
pub type smb_conn_state = u32;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtsp_conn {
    pub rtp_buf: *mut i8,
    pub rtp_bufsize: ssize_t,
    pub rtp_channel: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct smtp_conn {
    pub pp: pingpong,
    pub state: smtpstate,
    pub ssldone: bool,
    pub domain: *mut i8,
    pub sasl: SASL,
    pub tls_supported: bool,
    pub size_supported: bool,
    pub utf8_supported: bool,
    pub auth_supported: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASL {
    pub params: *const SASLproto,
    pub state: saslstate,
    pub authmechs: u16,
    pub prefmech: u16,
    pub authused: u16,
    pub resetprefs: bool,
    pub mutual_auth: bool,
    pub force_ir: bool,
}
pub type saslstate = u32;
pub const SASL_FINAL: saslstate = 17;
pub const SASL_CANCEL: saslstate = 16;
pub const SASL_GSASL: saslstate = 15;
pub const SASL_OAUTH2_RESP: saslstate = 14;
pub const SASL_OAUTH2: saslstate = 13;
pub const SASL_GSSAPI_NO_DATA: saslstate = 12;
pub const SASL_GSSAPI_TOKEN: saslstate = 11;
pub const SASL_GSSAPI: saslstate = 10;
pub const SASL_NTLM_TYPE2MSG: saslstate = 9;
pub const SASL_NTLM: saslstate = 8;
pub const SASL_DIGESTMD5_RESP: saslstate = 7;
pub const SASL_DIGESTMD5: saslstate = 6;
pub const SASL_CRAMMD5: saslstate = 5;
pub const SASL_EXTERNAL: saslstate = 4;
pub const SASL_LOGIN_PASSWD: saslstate = 3;
pub const SASL_LOGIN: saslstate = 2;
pub const SASL_PLAIN: saslstate = 1;
pub const SASL_STOP: saslstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SASLproto {
    pub service: *const i8,
    pub contcode: i32,
    pub finalcode: i32,
    pub maxirlen: size_t,
    pub sendauth: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const i8, *const i8) -> CURLcode,
    >,
    pub sendcont:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *const i8) -> CURLcode>,
    pub getmessage: Option<unsafe extern "C" fn(*mut i8, *mut *mut i8) -> ()>,
}
pub type smtpstate = u32;
pub const SMTP_LAST: smtpstate = 13;
pub const SMTP_QUIT: smtpstate = 12;
pub const SMTP_POSTDATA: smtpstate = 11;
pub const SMTP_DATA: smtpstate = 10;
pub const SMTP_RCPT: smtpstate = 9;
pub const SMTP_MAIL: smtpstate = 8;
pub const SMTP_COMMAND: smtpstate = 7;
pub const SMTP_AUTH: smtpstate = 6;
pub const SMTP_UPGRADETLS: smtpstate = 5;
pub const SMTP_STARTTLS: smtpstate = 4;
pub const SMTP_HELO: smtpstate = 3;
pub const SMTP_EHLO: smtpstate = 2;
pub const SMTP_SERVERGREET: smtpstate = 1;
pub const SMTP_STOP: smtpstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pingpong {
    pub cache: *mut i8,
    pub cache_size: size_t,
    pub nread_resp: size_t,
    pub linestart_resp: *mut i8,
    pub pending_resp: bool,
    pub sendthis: *mut i8,
    pub sendleft: size_t,
    pub sendsize: size_t,
    pub response: curltime,
    pub response_time: timediff_t,
    pub sendbuf: dynbuf,
    pub statemachine: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub endofresp: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut i8, size_t, *mut i32) -> bool,
    >,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pop3_conn {
    pub pp: pingpong,
    pub state: pop3state,
    pub ssldone: bool,
    pub tls_supported: bool,
    pub eob: size_t,
    pub strip: size_t,
    pub sasl: SASL,
    pub authtypes: u32,
    pub preftype: u32,
    pub apoptimestamp: *mut i8,
}
pub type pop3state = u32;
pub const POP3_LAST: pop3state = 11;
pub const POP3_QUIT: pop3state = 10;
pub const POP3_COMMAND: pop3state = 9;
pub const POP3_PASS: pop3state = 8;
pub const POP3_USER: pop3state = 7;
pub const POP3_APOP: pop3state = 6;
pub const POP3_AUTH: pop3state = 5;
pub const POP3_UPGRADETLS: pop3state = 4;
pub const POP3_STARTTLS: pop3state = 3;
pub const POP3_CAPA: pop3state = 2;
pub const POP3_SERVERGREET: pop3state = 1;
pub const POP3_STOP: pop3state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct imap_conn {
    pub pp: pingpong,
    pub state: imapstate,
    pub ssldone: bool,
    pub preauth: bool,
    pub sasl: SASL,
    pub preftype: u32,
    pub cmdid: u32,
    pub resptag: [i8; 5],
    pub tls_supported: bool,
    pub login_disabled: bool,
    pub ir_supported: bool,
    pub mailbox: *mut i8,
    pub mailbox_uidvalidity: *mut i8,
    pub dyn_0: dynbuf,
}
pub type imapstate = u32;
pub const IMAP_LAST: imapstate = 15;
pub const IMAP_LOGOUT: imapstate = 14;
pub const IMAP_SEARCH: imapstate = 13;
pub const IMAP_APPEND_FINAL: imapstate = 12;
pub const IMAP_APPEND: imapstate = 11;
pub const IMAP_FETCH_FINAL: imapstate = 10;
pub const IMAP_FETCH: imapstate = 9;
pub const IMAP_SELECT: imapstate = 8;
pub const IMAP_LIST: imapstate = 7;
pub const IMAP_LOGIN: imapstate = 6;
pub const IMAP_AUTHENTICATE: imapstate = 5;
pub const IMAP_UPGRADETLS: imapstate = 4;
pub const IMAP_STARTTLS: imapstate = 3;
pub const IMAP_CAPABILITY: imapstate = 2;
pub const IMAP_SERVERGREET: imapstate = 1;
pub const IMAP_STOP: imapstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_conn {
    pub authlist: *const i8,
    pub passphrase: *const i8,
    pub rsa_pub: *mut i8,
    pub rsa: *mut i8,
    pub authed: bool,
    pub acceptfail: bool,
    pub state: sshstate,
    pub nextstate: sshstate,
    pub actualcode: CURLcode,
    pub quote_item: *mut curl_slist,
    pub quote_path1: *mut i8,
    pub quote_path2: *mut i8,
    pub homedir: *mut i8,
    pub readdir_line: *mut i8,
    pub secondCreateDirs: i32,
    pub orig_waitfor: i32,
    pub slash_pos: *mut i8,
}
pub type sshstate = i32;
pub const SSH_LAST: sshstate = 60;
pub const SSH_QUIT: sshstate = 59;
pub const SSH_SESSION_FREE: sshstate = 58;
pub const SSH_SESSION_DISCONNECT: sshstate = 57;
pub const SSH_SCP_CHANNEL_FREE: sshstate = 56;
pub const SSH_SCP_WAIT_CLOSE: sshstate = 55;
pub const SSH_SCP_WAIT_EOF: sshstate = 54;
pub const SSH_SCP_SEND_EOF: sshstate = 53;
pub const SSH_SCP_DONE: sshstate = 52;
pub const SSH_SCP_DOWNLOAD: sshstate = 51;
pub const SSH_SCP_DOWNLOAD_INIT: sshstate = 50;
pub const SSH_SCP_UPLOAD_INIT: sshstate = 49;
pub const SSH_SCP_TRANS_INIT: sshstate = 48;
pub const SSH_SFTP_SHUTDOWN: sshstate = 47;
pub const SSH_SFTP_CLOSE: sshstate = 46;
pub const SSH_SFTP_DOWNLOAD_STAT: sshstate = 45;
pub const SSH_SFTP_DOWNLOAD_INIT: sshstate = 44;
pub const SSH_SFTP_READDIR_DONE: sshstate = 43;
pub const SSH_SFTP_READDIR_BOTTOM: sshstate = 42;
pub const SSH_SFTP_READDIR_LINK: sshstate = 41;
pub const SSH_SFTP_READDIR: sshstate = 40;
pub const SSH_SFTP_READDIR_INIT: sshstate = 39;
pub const SSH_SFTP_CREATE_DIRS_MKDIR: sshstate = 38;
pub const SSH_SFTP_CREATE_DIRS: sshstate = 37;
pub const SSH_SFTP_CREATE_DIRS_INIT: sshstate = 36;
pub const SSH_SFTP_UPLOAD_INIT: sshstate = 35;
pub const SSH_SFTP_TRANS_INIT: sshstate = 34;
pub const SSH_SFTP_FILETIME: sshstate = 33;
pub const SSH_SFTP_GETINFO: sshstate = 32;
pub const SSH_SFTP_QUOTE_STATVFS: sshstate = 31;
pub const SSH_SFTP_QUOTE_UNLINK: sshstate = 30;
pub const SSH_SFTP_QUOTE_RMDIR: sshstate = 29;
pub const SSH_SFTP_QUOTE_RENAME: sshstate = 28;
pub const SSH_SFTP_QUOTE_MKDIR: sshstate = 27;
pub const SSH_SFTP_QUOTE_SYMLINK: sshstate = 26;
pub const SSH_SFTP_QUOTE_SETSTAT: sshstate = 25;
pub const SSH_SFTP_QUOTE_STAT: sshstate = 24;
pub const SSH_SFTP_NEXT_QUOTE: sshstate = 23;
pub const SSH_SFTP_QUOTE: sshstate = 22;
pub const SSH_SFTP_POSTQUOTE_INIT: sshstate = 21;
pub const SSH_SFTP_QUOTE_INIT: sshstate = 20;
pub const SSH_SFTP_REALPATH: sshstate = 19;
pub const SSH_SFTP_INIT: sshstate = 18;
pub const SSH_AUTH_DONE: sshstate = 17;
pub const SSH_AUTH_GSSAPI: sshstate = 16;
pub const SSH_AUTH_KEY: sshstate = 15;
pub const SSH_AUTH_KEY_INIT: sshstate = 14;
pub const SSH_AUTH_HOST: sshstate = 13;
pub const SSH_AUTH_HOST_INIT: sshstate = 12;
pub const SSH_AUTH_AGENT: sshstate = 11;
pub const SSH_AUTH_AGENT_LIST: sshstate = 10;
pub const SSH_AUTH_AGENT_INIT: sshstate = 9;
pub const SSH_AUTH_PASS: sshstate = 8;
pub const SSH_AUTH_PASS_INIT: sshstate = 7;
pub const SSH_AUTH_PKEY: sshstate = 6;
pub const SSH_AUTH_PKEY_INIT: sshstate = 5;
pub const SSH_AUTHLIST: sshstate = 4;
pub const SSH_HOSTKEY: sshstate = 3;
pub const SSH_S_STARTUP: sshstate = 2;
pub const SSH_INIT: sshstate = 1;
pub const SSH_STOP: sshstate = 0;
pub const SSH_NO_STATE: sshstate = -1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct http_conn {
    pub binsettings: [uint8_t; 80],
    pub binlen: size_t,
    pub trnsfr: *mut Curl_easy,
    pub h2: *mut nghttp2_session,
    pub send_underlying: Option<Curl_send>,
    pub recv_underlying: Option<Curl_recv>,
    pub inbuf: *mut i8,
    pub inbuflen: size_t,
    pub nread_inbuf: size_t,
    pub pause_stream_id: int32_t,
    pub drain_total: size_t,
    pub settings: h2settings,
    pub local_settings: [nghttp2_settings_entry; 3],
    pub local_settings_num: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nghttp2_settings_entry {
    pub settings_id: int32_t,
    pub value: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct h2settings {
    pub max_concurrent_streams: uint32_t,
    pub enable_push: bool,
}
pub type Curl_recv =
    unsafe extern "C" fn(*mut Curl_easy, i32, *mut i8, size_t, *mut CURLcode) -> ssize_t;
pub type Curl_send = unsafe extern "C" fn(
    *mut Curl_easy,
    i32,
    *const libc::c_void,
    size_t,
    *mut CURLcode,
) -> ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ftp_conn {
    pub pp: pingpong,
    pub entrypath: *mut i8,
    pub file: *mut i8,
    pub dirs: *mut *mut i8,
    pub dirdepth: i32,
    pub dont_check: bool,
    pub ctl_valid: bool,
    pub cwddone: bool,
    pub cwdcount: i32,
    pub cwdfail: bool,
    pub wait_data_conn: bool,
    pub newport: u16,
    pub newhost: *mut i8,
    pub prevpath: *mut i8,
    pub transfertype: i8,
    pub count1: i32,
    pub count2: i32,
    pub count3: i32,
    pub state: ftpstate,
    pub state_saved: ftpstate,
    pub retr_size_saved: curl_off_t,
    pub server_os: *mut i8,
    pub known_filesize: curl_off_t,
}
pub type ftpstate = u32;
pub const FTP_LAST: ftpstate = 35;
pub const FTP_QUIT: ftpstate = 34;
pub const FTP_STOR: ftpstate = 33;
pub const FTP_RETR: ftpstate = 32;
pub const FTP_LIST: ftpstate = 31;
pub const FTP_PASV: ftpstate = 30;
pub const FTP_PRET: ftpstate = 29;
pub const FTP_PORT: ftpstate = 28;
pub const FTP_RETR_REST: ftpstate = 27;
pub const FTP_REST: ftpstate = 26;
pub const FTP_STOR_SIZE: ftpstate = 25;
pub const FTP_RETR_SIZE: ftpstate = 24;
pub const FTP_SIZE: ftpstate = 23;
pub const FTP_STOR_TYPE: ftpstate = 22;
pub const FTP_RETR_TYPE: ftpstate = 21;
pub const FTP_LIST_TYPE: ftpstate = 20;
pub const FTP_TYPE: ftpstate = 19;
pub const FTP_MDTM: ftpstate = 18;
pub const FTP_MKD: ftpstate = 17;
pub const FTP_CWD: ftpstate = 16;
pub const FTP_POSTQUOTE: ftpstate = 15;
pub const FTP_STOR_PREQUOTE: ftpstate = 14;
pub const FTP_RETR_PREQUOTE: ftpstate = 13;
pub const FTP_QUOTE: ftpstate = 12;
pub const FTP_NAMEFMT: ftpstate = 11;
pub const FTP_SYST: ftpstate = 10;
pub const FTP_PWD: ftpstate = 9;
pub const FTP_CCC: ftpstate = 8;
pub const FTP_PROT: ftpstate = 7;
pub const FTP_PBSZ: ftpstate = 6;
pub const FTP_ACCT: ftpstate = 5;
pub const FTP_PASS: ftpstate = 4;
pub const FTP_USER: ftpstate = 3;
pub const FTP_AUTH: ftpstate = 2;
pub const FTP_WAIT220: ftpstate = 1;
pub const FTP_STOP: ftpstate = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ntlmdata {
    pub flags: u32,
    pub nonce: [u8; 8],
    pub target_info_len: u32,
    pub target_info: *mut libc::c_void,
    pub ntlm_auth_hlpr_socket: curl_socket_t,
    pub ntlm_auth_hlpr_pid: pid_t,
    pub challenge: *mut i8,
    pub response: *mut i8,
}
pub type curlntlm = u32;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gsasldata {
    pub ctx: *mut Gsasl,
    pub client: *mut Gsasl_session,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_handler {
    pub scheme: *const i8,
    pub setup_connection:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> CURLcode>,
    pub do_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub done: Option<unsafe extern "C" fn(*mut Curl_easy, CURLcode, bool) -> CURLcode>,
    pub do_more: Option<unsafe extern "C" fn(*mut Curl_easy, *mut i32) -> CURLcode>,
    pub connect_it: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub connecting: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub doing: Option<unsafe extern "C" fn(*mut Curl_easy, *mut bool) -> CURLcode>,
    pub proto_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub doing_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub domore_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub perform_getsock:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut curl_socket_t) -> i32>,
    pub disconnect:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, bool) -> CURLcode>,
    pub readwrite: Option<
        unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, *mut ssize_t, *mut bool) -> CURLcode,
    >,
    pub connection_check:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, u32) -> u32>,
    pub attach: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata) -> ()>,
    pub defport: i32,
    pub protocol: u32,
    pub family: u32,
    pub flags: u32,
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ConnectBits {
    pub tcpconnect: [bool; 2],
    pub proxy_ssl_connected: [bool; 2],
    #[bitfield(name = "httpproxy", ty = "bit", bits = "0..=0")]
    #[bitfield(name = "socksproxy", ty = "bit", bits = "1..=1")]
    #[bitfield(name = "proxy_user_passwd", ty = "bit", bits = "2..=2")]
    #[bitfield(name = "tunnel_proxy", ty = "bit", bits = "3..=3")]
    #[bitfield(name = "proxy_connect_closed", ty = "bit", bits = "4..=4")]
    #[bitfield(name = "close", ty = "bit", bits = "5..=5")]
    #[bitfield(name = "reuse", ty = "bit", bits = "6..=6")]
    #[bitfield(name = "altused", ty = "bit", bits = "7..=7")]
    #[bitfield(name = "conn_to_host", ty = "bit", bits = "8..=8")]
    #[bitfield(name = "conn_to_port", ty = "bit", bits = "9..=9")]
    #[bitfield(name = "proxy", ty = "bit", bits = "10..=10")]
    #[bitfield(name = "user_passwd", ty = "bit", bits = "11..=11")]
    #[bitfield(name = "ipv6_ip", ty = "bit", bits = "12..=12")]
    #[bitfield(name = "ipv6", ty = "bit", bits = "13..=13")]
    #[bitfield(name = "do_more", ty = "bit", bits = "14..=14")]
    #[bitfield(name = "protoconnstart", ty = "bit", bits = "15..=15")]
    #[bitfield(name = "retry", ty = "bit", bits = "16..=16")]
    #[bitfield(name = "authneg", ty = "bit", bits = "17..=17")]
    #[bitfield(name = "rewindaftersend", ty = "bit", bits = "18..=18")]
    #[bitfield(name = "ftp_use_epsv", ty = "bit", bits = "19..=19")]
    #[bitfield(name = "ftp_use_eprt", ty = "bit", bits = "20..=20")]
    #[bitfield(name = "ftp_use_data_ssl", ty = "bit", bits = "21..=21")]
    #[bitfield(name = "ftp_use_control_ssl", ty = "bit", bits = "22..=22")]
    #[bitfield(name = "netrc", ty = "bit", bits = "23..=23")]
    #[bitfield(name = "bound", ty = "bit", bits = "24..=24")]
    #[bitfield(name = "multiplex", ty = "bit", bits = "25..=25")]
    #[bitfield(name = "tcp_fastopen", ty = "bit", bits = "26..=26")]
    #[bitfield(name = "tls_enable_npn", ty = "bit", bits = "27..=27")]
    #[bitfield(name = "tls_enable_alpn", ty = "bit", bits = "28..=28")]
    #[bitfield(name = "connect_only", ty = "bit", bits = "29..=29")]
    #[bitfield(name = "doh", ty = "bit", bits = "30..=30")]
    #[bitfield(name = "abstract_unix_socket", ty = "bit", bits = "31..=31")]
    #[bitfield(name = "tls_upgraded", ty = "bit", bits = "32..=32")]
    #[bitfield(name = "sock_accepted", ty = "bit", bits = "33..=33")]
    #[bitfield(name = "parallel_connect", ty = "bit", bits = "34..=34")]
    pub httpproxy_socksproxy_proxy_user_passwd_tunnel_proxy_proxy_connect_closed_close_reuse_altused_conn_to_host_conn_to_port_proxy_user_passwd_ipv6_ip_ipv6_do_more_protoconnstart_retry_authneg_rewindaftersend_ftp_use_epsv_ftp_use_eprt_ftp_use_data_ssl_ftp_use_control_ssl_netrc_bound_multiplex_tcp_fastopen_tls_enable_npn_tls_enable_alpn_connect_only_doh_abstract_unix_socket_tls_upgraded_sock_accepted_parallel_connect:
        [u8; 5],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 3],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ssl_connect_data {
    pub state: ssl_connection_state,
    pub connecting_state: ssl_connect_state,
    pub backend: *mut ssl_backend_data,
    #[bitfield(name = "use_0", ty = "bit", bits = "0..=0")]
    pub use_0: [u8; 1],
    #[bitfield(padding)]
    pub c2rust_padding: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_backend_data {
    pub logger: *mut Curl_easy,
    pub ctx: *mut SSL_CTX,
    pub handle: *mut SSL,
    pub server_cert: *mut X509,
}
pub type X509 = x509_st;
pub type SSL = ssl_st;
pub type SSL_CTX = ssl_ctx_st;
pub type ssl_connect_state = u32;
pub const ssl_connect_done: ssl_connect_state = 5;
pub const ssl_connect_3: ssl_connect_state = 4;
pub const ssl_connect_2_writing: ssl_connect_state = 3;
pub const ssl_connect_2_reading: ssl_connect_state = 2;
pub const ssl_connect_2: ssl_connect_state = 1;
pub const ssl_connect_1: ssl_connect_state = 0;
pub type ssl_connection_state = u32;
pub const ssl_connection_complete: ssl_connection_state = 2;
pub const ssl_connection_negotiating: ssl_connection_state = 1;
pub const ssl_connection_none: ssl_connection_state = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct proxy_info {
    pub host: hostname,
    pub port: i64,
    pub proxytype: curl_proxytype,
    pub user: *mut i8,
    pub passwd: *mut i8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostname {
    pub rawalloc: *mut i8,
    pub encalloc: *mut i8,
    pub name: *mut i8,
    pub dispname: *const i8,
}
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_chunker {
    pub datasize: curl_off_t,
    pub state: ChunkyState,
    pub hexindex: u8,
    pub hexbuffer: [i8; 17],
}
pub type ChunkyState = u32;
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct connstate {
    pub state: connect_t,
    pub outstanding: ssize_t,
    pub outp: *mut u8,
}
pub type connect_t = u32;
pub const CONNECT_DONE: connect_t = 17;
pub const CONNECT_REQ_READ_MORE: connect_t = 16;
pub const CONNECT_REQ_READ: connect_t = 15;
pub const CONNECT_REQ_SENDING: connect_t = 14;
pub const CONNECT_REQ_SEND: connect_t = 13;
pub const CONNECT_RESOLVE_REMOTE: connect_t = 12;
pub const CONNECT_RESOLVED: connect_t = 11;
pub const CONNECT_RESOLVING: connect_t = 10;
pub const CONNECT_REQ_INIT: connect_t = 9;
pub const CONNECT_AUTH_READ: connect_t = 8;
pub const CONNECT_AUTH_SEND: connect_t = 7;
pub const CONNECT_AUTH_INIT: connect_t = 6;
pub const CONNECT_GSSAPI_INIT: connect_t = 5;
pub const CONNECT_SOCKS_READ: connect_t = 4;
pub const CONNECT_SOCKS_READ_INIT: connect_t = 3;
pub const CONNECT_SOCKS_SEND: connect_t = 2;
pub const CONNECT_SOCKS_INIT: connect_t = 1;
pub const CONNECT_INIT: connect_t = 0;
pub type curl_malloc_callback = Option<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type C2RustUnnamed_7 = u32;
pub const CURL_HTTP_VERSION_LAST: C2RustUnnamed_7 = 31;
pub const CURL_HTTP_VERSION_3: C2RustUnnamed_7 = 30;
pub const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: C2RustUnnamed_7 = 5;
pub const CURL_HTTP_VERSION_2TLS: C2RustUnnamed_7 = 4;
pub const CURL_HTTP_VERSION_2_0: C2RustUnnamed_7 = 3;
pub const CURL_HTTP_VERSION_1_1: C2RustUnnamed_7 = 2;
pub const CURL_HTTP_VERSION_1_0: C2RustUnnamed_7 = 1;
pub const CURL_HTTP_VERSION_NONE: C2RustUnnamed_7 = 0;
pub type C2RustUnnamed_8 = u32;
pub const CURL_SSLVERSION_LAST: C2RustUnnamed_8 = 8;
pub const CURL_SSLVERSION_TLSv1_3: C2RustUnnamed_8 = 7;
pub const CURL_SSLVERSION_TLSv1_2: C2RustUnnamed_8 = 6;
pub const CURL_SSLVERSION_TLSv1_1: C2RustUnnamed_8 = 5;
pub const CURL_SSLVERSION_TLSv1_0: C2RustUnnamed_8 = 4;
pub const CURL_SSLVERSION_SSLv3: C2RustUnnamed_8 = 3;
pub const CURL_SSLVERSION_SSLv2: C2RustUnnamed_8 = 2;
pub const CURL_SSLVERSION_TLSv1: C2RustUnnamed_8 = 1;
pub const CURL_SSLVERSION_DEFAULT: C2RustUnnamed_8 = 0;
pub type C2RustUnnamed_9 = u32;
pub const CURL_SSLVERSION_MAX_LAST: C2RustUnnamed_9 = 524288;
pub const CURL_SSLVERSION_MAX_TLSv1_3: C2RustUnnamed_9 = 458752;
pub const CURL_SSLVERSION_MAX_TLSv1_2: C2RustUnnamed_9 = 393216;
pub const CURL_SSLVERSION_MAX_TLSv1_1: C2RustUnnamed_9 = 327680;
pub const CURL_SSLVERSION_MAX_TLSv1_0: C2RustUnnamed_9 = 262144;
pub const CURL_SSLVERSION_MAX_DEFAULT: C2RustUnnamed_9 = 65536;
pub const CURL_SSLVERSION_MAX_NONE: C2RustUnnamed_9 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct curl_ssl_backend {
    pub id: curl_sslbackend,
    pub name: *const i8,
}
pub type CURLINFO = u32;
pub const CURLINFO_LASTONE: CURLINFO = 60;
pub const CURLINFO_REFERER: CURLINFO = 1048636;
pub const CURLINFO_PROXY_ERROR: CURLINFO = 2097211;
pub const CURLINFO_EFFECTIVE_METHOD: CURLINFO = 1048634;
pub const CURLINFO_RETRY_AFTER: CURLINFO = 6291513;
pub const CURLINFO_APPCONNECT_TIME_T: CURLINFO = 6291512;
pub const CURLINFO_REDIRECT_TIME_T: CURLINFO = 6291511;
pub const CURLINFO_STARTTRANSFER_TIME_T: CURLINFO = 6291510;
pub const CURLINFO_PRETRANSFER_TIME_T: CURLINFO = 6291509;
pub const CURLINFO_CONNECT_TIME_T: CURLINFO = 6291508;
pub const CURLINFO_NAMELOOKUP_TIME_T: CURLINFO = 6291507;
pub const CURLINFO_TOTAL_TIME_T: CURLINFO = 6291506;
pub const CURLINFO_SCHEME: CURLINFO = 1048625;
pub const CURLINFO_PROTOCOL: CURLINFO = 2097200;
pub const CURLINFO_PROXY_SSL_VERIFYRESULT: CURLINFO = 2097199;
pub const CURLINFO_HTTP_VERSION: CURLINFO = 2097198;
pub const CURLINFO_TLS_SSL_PTR: CURLINFO = 4194349;
pub const CURLINFO_ACTIVESOCKET: CURLINFO = 5242924;
pub const CURLINFO_TLS_SESSION: CURLINFO = 4194347;
pub const CURLINFO_LOCAL_PORT: CURLINFO = 2097194;
pub const CURLINFO_LOCAL_IP: CURLINFO = 1048617;
pub const CURLINFO_PRIMARY_PORT: CURLINFO = 2097192;
pub const CURLINFO_RTSP_CSEQ_RECV: CURLINFO = 2097191;
pub const CURLINFO_RTSP_SERVER_CSEQ: CURLINFO = 2097190;
pub const CURLINFO_RTSP_CLIENT_CSEQ: CURLINFO = 2097189;
pub const CURLINFO_RTSP_SESSION_ID: CURLINFO = 1048612;
pub const CURLINFO_CONDITION_UNMET: CURLINFO = 2097187;
pub const CURLINFO_CERTINFO: CURLINFO = 4194338;
pub const CURLINFO_APPCONNECT_TIME: CURLINFO = 3145761;
pub const CURLINFO_PRIMARY_IP: CURLINFO = 1048608;
pub const CURLINFO_REDIRECT_URL: CURLINFO = 1048607;
pub const CURLINFO_FTP_ENTRY_PATH: CURLINFO = 1048606;
pub const CURLINFO_LASTSOCKET: CURLINFO = 2097181;
pub const CURLINFO_COOKIELIST: CURLINFO = 4194332;
pub const CURLINFO_SSL_ENGINES: CURLINFO = 4194331;
pub const CURLINFO_NUM_CONNECTS: CURLINFO = 2097178;
pub const CURLINFO_OS_ERRNO: CURLINFO = 2097177;
pub const CURLINFO_PROXYAUTH_AVAIL: CURLINFO = 2097176;
pub const CURLINFO_HTTPAUTH_AVAIL: CURLINFO = 2097175;
pub const CURLINFO_HTTP_CONNECTCODE: CURLINFO = 2097174;
pub const CURLINFO_PRIVATE: CURLINFO = 1048597;
pub const CURLINFO_REDIRECT_COUNT: CURLINFO = 2097172;
pub const CURLINFO_REDIRECT_TIME: CURLINFO = 3145747;
pub const CURLINFO_CONTENT_TYPE: CURLINFO = 1048594;
pub const CURLINFO_STARTTRANSFER_TIME: CURLINFO = 3145745;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD_T: CURLINFO = 6291472;
pub const CURLINFO_CONTENT_LENGTH_UPLOAD: CURLINFO = 3145744;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD_T: CURLINFO = 6291471;
pub const CURLINFO_CONTENT_LENGTH_DOWNLOAD: CURLINFO = 3145743;
pub const CURLINFO_FILETIME_T: CURLINFO = 6291470;
pub const CURLINFO_FILETIME: CURLINFO = 2097166;
pub const CURLINFO_SSL_VERIFYRESULT: CURLINFO = 2097165;
pub const CURLINFO_REQUEST_SIZE: CURLINFO = 2097164;
pub const CURLINFO_HEADER_SIZE: CURLINFO = 2097163;
pub const CURLINFO_SPEED_UPLOAD_T: CURLINFO = 6291466;
pub const CURLINFO_SPEED_UPLOAD: CURLINFO = 3145738;
pub const CURLINFO_SPEED_DOWNLOAD_T: CURLINFO = 6291465;
pub const CURLINFO_SPEED_DOWNLOAD: CURLINFO = 3145737;
pub const CURLINFO_SIZE_DOWNLOAD_T: CURLINFO = 6291464;
pub const CURLINFO_SIZE_DOWNLOAD: CURLINFO = 3145736;
pub const CURLINFO_SIZE_UPLOAD_T: CURLINFO = 6291463;
pub const CURLINFO_SIZE_UPLOAD: CURLINFO = 3145735;
pub const CURLINFO_PRETRANSFER_TIME: CURLINFO = 3145734;
pub const CURLINFO_CONNECT_TIME: CURLINFO = 3145733;
pub const CURLINFO_NAMELOOKUP_TIME: CURLINFO = 3145732;
pub const CURLINFO_TOTAL_TIME: CURLINFO = 3145731;
pub const CURLINFO_RESPONSE_CODE: CURLINFO = 2097154;
pub const CURLINFO_EFFECTIVE_URL: CURLINFO = 1048577;
pub const CURLINFO_NONE: CURLINFO = 0;
pub type uint16_t = __uint16_t;
pub type uint64_t = __uint64_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed_10,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type dupstring = u32;
pub const STRING_LAST: dupstring = 80;
pub const STRING_AWS_SIGV4: dupstring = 79;
pub const STRING_COPYPOSTFIELDS: dupstring = 78;
pub const STRING_LASTZEROTERMINATED: dupstring = 77;
pub const STRING_SSL_EC_CURVES: dupstring = 76;
pub const STRING_DNS_LOCAL_IP6: dupstring = 75;
pub const STRING_DNS_LOCAL_IP4: dupstring = 74;
pub const STRING_DNS_INTERFACE: dupstring = 73;
pub const STRING_DNS_SERVERS: dupstring = 72;
pub const STRING_SASL_AUTHZID: dupstring = 71;
pub const STRING_HSTS: dupstring = 70;
pub const STRING_ALTSVC: dupstring = 69;
pub const STRING_DOH: dupstring = 68;
pub const STRING_TARGET: dupstring = 67;
pub const STRING_UNIX_SOCKET_PATH: dupstring = 66;
pub const STRING_BEARER: dupstring = 65;
pub const STRING_TLSAUTH_PASSWORD_PROXY: dupstring = 64;
pub const STRING_TLSAUTH_PASSWORD: dupstring = 63;
pub const STRING_TLSAUTH_USERNAME_PROXY: dupstring = 62;
pub const STRING_TLSAUTH_USERNAME: dupstring = 61;
pub const STRING_MAIL_AUTH: dupstring = 60;
pub const STRING_MAIL_FROM: dupstring = 59;
pub const STRING_SERVICE_NAME: dupstring = 58;
pub const STRING_PROXY_SERVICE_NAME: dupstring = 57;
pub const STRING_SSH_KNOWNHOSTS: dupstring = 56;
pub const STRING_SSH_HOST_PUBLIC_KEY_MD5: dupstring = 55;
pub const STRING_SSH_PUBLIC_KEY: dupstring = 54;
pub const STRING_SSH_PRIVATE_KEY: dupstring = 53;
pub const STRING_RTSP_TRANSPORT: dupstring = 52;
pub const STRING_RTSP_STREAM_URI: dupstring = 51;
pub const STRING_RTSP_SESSION_ID: dupstring = 50;
pub const STRING_NOPROXY: dupstring = 49;
pub const STRING_PROXYPASSWORD: dupstring = 48;
pub const STRING_PROXYUSERNAME: dupstring = 47;
pub const STRING_OPTIONS: dupstring = 46;
pub const STRING_PASSWORD: dupstring = 45;
pub const STRING_USERNAME: dupstring = 44;
pub const STRING_SSL_ENGINE: dupstring = 43;
pub const STRING_SSL_ISSUERCERT_PROXY: dupstring = 42;
pub const STRING_SSL_ISSUERCERT: dupstring = 41;
pub const STRING_SSL_CRLFILE_PROXY: dupstring = 40;
pub const STRING_SSL_CRLFILE: dupstring = 39;
pub const STRING_USERAGENT: dupstring = 38;
pub const STRING_SSL_RANDOM_FILE: dupstring = 37;
pub const STRING_SSL_EGDSOCKET: dupstring = 36;
pub const STRING_SSL_CIPHER13_LIST_PROXY: dupstring = 35;
pub const STRING_SSL_CIPHER13_LIST: dupstring = 34;
pub const STRING_SSL_CIPHER_LIST_PROXY: dupstring = 33;
pub const STRING_SSL_CIPHER_LIST: dupstring = 32;
pub const STRING_SSL_PINNEDPUBLICKEY_PROXY: dupstring = 31;
pub const STRING_SSL_PINNEDPUBLICKEY: dupstring = 30;
pub const STRING_SSL_CAFILE_PROXY: dupstring = 29;
pub const STRING_SSL_CAFILE: dupstring = 28;
pub const STRING_SSL_CAPATH_PROXY: dupstring = 27;
pub const STRING_SSL_CAPATH: dupstring = 26;
pub const STRING_SET_URL: dupstring = 25;
pub const STRING_SET_REFERER: dupstring = 24;
pub const STRING_SET_RANGE: dupstring = 23;
pub const STRING_PRE_PROXY: dupstring = 22;
pub const STRING_PROXY: dupstring = 21;
pub const STRING_NETRC_FILE: dupstring = 20;
pub const STRING_KRB_LEVEL: dupstring = 19;
pub const STRING_KEY_TYPE_PROXY: dupstring = 18;
pub const STRING_KEY_TYPE: dupstring = 17;
pub const STRING_KEY_PASSWD_PROXY: dupstring = 16;
pub const STRING_KEY_PASSWD: dupstring = 15;
pub const STRING_KEY_PROXY: dupstring = 14;
pub const STRING_KEY: dupstring = 13;
pub const STRING_FTPPORT: dupstring = 12;
pub const STRING_FTP_ALTERNATIVE_TO_USER: dupstring = 11;
pub const STRING_FTP_ACCOUNT: dupstring = 10;
pub const STRING_ENCODING: dupstring = 9;
pub const STRING_DEVICE: dupstring = 8;
pub const STRING_DEFAULT_PROTOCOL: dupstring = 7;
pub const STRING_CUSTOMREQUEST: dupstring = 6;
pub const STRING_COOKIEJAR: dupstring = 5;
pub const STRING_COOKIE: dupstring = 4;
pub const STRING_CERT_TYPE_PROXY: dupstring = 3;
pub const STRING_CERT_TYPE: dupstring = 2;
pub const STRING_CERT_PROXY: dupstring = 1;
pub const STRING_CERT: dupstring = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Curl_ssl {
    pub info: curl_ssl_backend,
    pub supports: u32,
    pub sizeof_ssl_backend_data: size_t,
    pub init: Option<unsafe extern "C" fn() -> i32>,
    pub cleanup: Option<unsafe extern "C" fn() -> ()>,
    pub version: Option<unsafe extern "C" fn(*mut i8, size_t) -> size_t>,
    pub check_cxn: Option<unsafe extern "C" fn(*mut connectdata) -> i32>,
    pub shut_down: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32>,
    pub data_pending: Option<unsafe extern "C" fn(*const connectdata, i32) -> bool>,
    pub random: Option<unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode>,
    pub cert_status_request: Option<unsafe extern "C" fn() -> bool>,
    pub connect_blocking:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode>,
    pub connect_nonblocking:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32, *mut bool) -> CURLcode>,
    pub getsock: Option<unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32>,
    pub get_internals:
        Option<unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void>,
    pub close_one: Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> ()>,
    pub close_all: Option<unsafe extern "C" fn(*mut Curl_easy) -> ()>,
    pub session_free: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub set_engine: Option<unsafe extern "C" fn(*mut Curl_easy, *const i8) -> CURLcode>,
    pub set_engine_default: Option<unsafe extern "C" fn(*mut Curl_easy) -> CURLcode>,
    pub engines_list: Option<unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist>,
    pub false_start: Option<unsafe extern "C" fn() -> bool>,
    pub sha256sum: Option<unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode>,
    pub associate_connection:
        Option<unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> ()>,
    pub disassociate_connection: Option<unsafe extern "C" fn(*mut Curl_easy, i32) -> ()>,
}
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    i32,
    i64,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut stack_st_void,
}
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut libc::c_void,
    i32,
    i64,
    *mut libc::c_void,
) -> i32;
pub type CRYPTO_EX_new = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    i32,
    i64,
    *mut libc::c_void,
) -> ();
pub type EVP_MD_CTX = evp_md_ctx_st;
pub type EVP_MD = evp_md_st;
pub type ENGINE = engine_st;
pub type SSL_SESSION = ssl_session_st;
pub type X509_PUBKEY = X509_pubkey_st;
pub type OCSP_RESPONSE = ocsp_response_st;
pub type OCSP_BASICRESP = ocsp_basic_response_st;
pub type ASN1_GENERALIZEDTIME = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: i32,
    pub type_0: i32,
    pub data: *mut u8,
    pub flags: i64,
}
pub type OCSP_CERTID = ocsp_cert_id_st;
pub type OPENSSL_STACK = stack_st;
pub type X509_STORE = x509_store_st;
pub type BIO = bio_st;
pub type pem_password_cb = unsafe extern "C" fn(*mut i8, i32, i32, *mut libc::c_void) -> i32;
pub type BIO_METHOD = bio_method_st;
pub type X509_NAME = X509_name_st;
pub type BUF_MEM = buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: size_t,
    pub data: *mut i8,
    pub max: size_t,
    pub flags: u64,
}
pub type ASN1_STRING = asn1_string_st;
pub type X509_NAME_ENTRY = X509_name_entry_st;
pub type GENERAL_NAMES = stack_st_GENERAL_NAME;
pub type ASN1_IA5STRING = asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_11 {
    pub ptr: *mut i8,
    pub otherName: *mut OTHERNAME,
    pub rfc822Name: *mut ASN1_IA5STRING,
    pub dNSName: *mut ASN1_IA5STRING,
    pub x400Address: *mut ASN1_TYPE,
    pub directoryName: *mut X509_NAME,
    pub ediPartyName: *mut EDIPARTYNAME,
    pub uniformResourceIdentifier: *mut ASN1_IA5STRING,
    pub iPAddress: *mut ASN1_OCTET_STRING,
    pub registeredID: *mut ASN1_OBJECT,
    pub ip: *mut ASN1_OCTET_STRING,
    pub dirn: *mut X509_NAME,
    pub ia5: *mut ASN1_IA5STRING,
    pub rid: *mut ASN1_OBJECT,
    pub other: *mut ASN1_TYPE,
}
pub type ASN1_TYPE = asn1_type_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: i32,
    pub value: C2RustUnnamed_12,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_12 {
    pub ptr: *mut i8,
    pub boolean: ASN1_BOOLEAN,
    pub asn1_string: *mut ASN1_STRING,
    pub object: *mut ASN1_OBJECT,
    pub integer: *mut ASN1_INTEGER,
    pub enumerated: *mut ASN1_ENUMERATED,
    pub bit_string: *mut ASN1_BIT_STRING,
    pub octet_string: *mut ASN1_OCTET_STRING,
    pub printablestring: *mut ASN1_PRINTABLESTRING,
    pub t61string: *mut ASN1_T61STRING,
    pub ia5string: *mut ASN1_IA5STRING,
    pub generalstring: *mut ASN1_GENERALSTRING,
    pub bmpstring: *mut ASN1_BMPSTRING,
    pub universalstring: *mut ASN1_UNIVERSALSTRING,
    pub utctime: *mut ASN1_UTCTIME,
    pub generalizedtime: *mut ASN1_GENERALIZEDTIME,
    pub visiblestring: *mut ASN1_VISIBLESTRING,
    pub utf8string: *mut ASN1_UTF8STRING,
    pub set: *mut ASN1_STRING,
    pub sequence: *mut ASN1_STRING,
    pub asn1_value: *mut ASN1_VALUE,
}
pub type ASN1_VALUE = ASN1_VALUE_st;
pub type ASN1_UTF8STRING = asn1_string_st;
pub type ASN1_VISIBLESTRING = asn1_string_st;
pub type ASN1_UTCTIME = asn1_string_st;
pub type ASN1_UNIVERSALSTRING = asn1_string_st;
pub type ASN1_BMPSTRING = asn1_string_st;
pub type ASN1_GENERALSTRING = asn1_string_st;
pub type ASN1_T61STRING = asn1_string_st;
pub type ASN1_PRINTABLESTRING = asn1_string_st;
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type ASN1_BIT_STRING = asn1_string_st;
pub type ASN1_ENUMERATED = asn1_string_st;
pub type ASN1_INTEGER = asn1_string_st;
pub type ASN1_OBJECT = asn1_object_st;
pub type ASN1_BOOLEAN = i32;
pub type EDIPARTYNAME = EDIPartyName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut ASN1_STRING,
    pub partyName: *mut ASN1_STRING,
}
pub type OTHERNAME = otherName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut ASN1_OBJECT,
    pub value: *mut ASN1_TYPE,
}
pub type GENERAL_NAME = GENERAL_NAME_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_NAME_st {
    pub type_0: i32,
    pub d: C2RustUnnamed_11,
}
pub type ASN1_TIME = asn1_string_st;
pub type EVP_PKEY = evp_pkey_st;
pub type BIGNUM = bignum_st;
pub type DH = dh_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type X509_EXTENSION = X509_extension_st;
pub type X509_ALGOR = X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut ASN1_OBJECT,
    pub parameter: *mut ASN1_TYPE,
}
pub type numcert_t = i32;
pub type SSL_CIPHER = ssl_cipher_st;
pub type SSL_CTX_keylog_cb_func = Option<unsafe extern "C" fn(*const SSL, *const i8) -> ()>;
pub type SSL_verify_cb = Option<unsafe extern "C" fn(i32, *mut X509_STORE_CTX) -> i32>;
pub type X509_STORE_CTX = x509_store_ctx_st;
pub type X509_LOOKUP = x509_lookup_st;
pub type X509_LOOKUP_METHOD = x509_lookup_method_st;
pub type X509_INFO = X509_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_info_st {
    pub x509: *mut X509,
    pub crl: *mut X509_CRL,
    pub x_pkey: *mut X509_PKEY,
    pub enc_cipher: EVP_CIPHER_INFO,
    pub enc_len: i32,
    pub enc_data: *mut i8,
}
pub type EVP_CIPHER_INFO = evp_cipher_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const EVP_CIPHER,
    pub iv: [u8; 16],
}
pub type EVP_CIPHER = evp_cipher_st;
pub type X509_PKEY = private_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key_st {
    pub version: i32,
    pub enc_algor: *mut X509_ALGOR,
    pub enc_pkey: *mut ASN1_OCTET_STRING,
    pub dec_pkey: *mut EVP_PKEY,
    pub key_length: i32,
    pub key_data: *mut i8,
    pub key_free: i32,
    pub cipher: EVP_CIPHER_INFO,
}
pub type X509_CRL = X509_crl_st;
pub type sk_X509_INFO_freefunc = Option<unsafe extern "C" fn(*mut X509_INFO) -> ()>;
pub type OPENSSL_sk_freefunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type UI_METHOD = ui_method_st;
pub type UI_STRING = ui_string_st;
pub type UI = ui_st;
pub const UIT_VERIFY: UI_string_types = 2;
pub const UIT_PROMPT: UI_string_types = 1;
pub type UI_string_types = u32;
pub const UIT_ERROR: UI_string_types = 5;
pub const UIT_INFO: UI_string_types = 4;
pub const UIT_BOOLEAN: UI_string_types = 3;
pub const UIT_NONE: UI_string_types = 0;
pub type sk_X509_freefunc = Option<unsafe extern "C" fn(*mut X509) -> ()>;
pub type PKCS12 = PKCS12_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub cert_id: *const i8,
    pub cert: *mut X509,
}
pub type SSL_CTX_npn_select_cb_func = Option<
    unsafe extern "C" fn(*mut SSL, *mut *mut u8, *mut u8, *const u8, u32, *mut libc::c_void) -> i32,
>;
pub type ctx_option_t = i64;
pub type SSL_METHOD = ssl_method_st;
pub type OPENSSL_INIT_SETTINGS = ossl_init_settings_st;
#[inline]
extern "C" fn sk_X509_pop(mut sk: *mut stack_st_X509) -> *mut X509 {
    return (unsafe { OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) }) as *mut X509;
}
#[inline]
extern "C" fn sk_X509_pop_free(mut sk: *mut stack_st_X509, mut freefunc: sk_X509_freefunc) {
    (unsafe { OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        ::std::mem::transmute::<sk_X509_freefunc, OPENSSL_sk_freefunc>(freefunc),
    ) });
}
#[inline]
extern "C" fn sk_X509_INFO_num(mut sk: *const stack_st_X509_INFO) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_INFO_value(
    mut sk: *const stack_st_X509_INFO,
    mut idx: i32,
) -> *mut X509_INFO {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509_INFO;
}
#[inline]
extern "C" fn sk_X509_INFO_pop_free(
    mut sk: *mut stack_st_X509_INFO,
    mut freefunc: sk_X509_INFO_freefunc,
) {
    (unsafe { OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        ::std::mem::transmute::<sk_X509_INFO_freefunc, OPENSSL_sk_freefunc>(freefunc),
    ) });
}
#[inline]
extern "C" fn sk_X509_EXTENSION_num(mut sk: *const stack_st_X509_EXTENSION) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const stack_st_X509_EXTENSION,
    mut idx: i32,
) -> *mut X509_EXTENSION {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509_EXTENSION;
}
#[inline]
extern "C" fn sk_X509_num(mut sk: *const stack_st_X509) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_value(mut sk: *const stack_st_X509, mut idx: i32) -> *mut X509 {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509;
}
#[inline]
extern "C" fn sk_GENERAL_NAME_num(mut sk: *const stack_st_GENERAL_NAME) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const stack_st_GENERAL_NAME,
    mut idx: i32,
) -> *mut GENERAL_NAME {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut GENERAL_NAME;
}
extern "C" fn ossl_keylog_callback(mut _ssl: *const SSL, mut line: *const i8) {
    (unsafe { Curl_tls_keylog_write_line(line) });
}
extern "C" fn SSL_ERROR_to_str(mut err: i32) -> *const i8 {
    match err {
        0 => return b"SSL_ERROR_NONE\0" as *const u8 as *const i8,
        1 => return b"SSL_ERROR_SSL\0" as *const u8 as *const i8,
        2 => return b"SSL_ERROR_WANT_READ\0" as *const u8 as *const i8,
        3 => return b"SSL_ERROR_WANT_WRITE\0" as *const u8 as *const i8,
        4 => return b"SSL_ERROR_WANT_X509_LOOKUP\0" as *const u8 as *const i8,
        5 => return b"SSL_ERROR_SYSCALL\0" as *const u8 as *const i8,
        6 => return b"SSL_ERROR_ZERO_RETURN\0" as *const u8 as *const i8,
        7 => return b"SSL_ERROR_WANT_CONNECT\0" as *const u8 as *const i8,
        8 => return b"SSL_ERROR_WANT_ACCEPT\0" as *const u8 as *const i8,
        9 => return b"SSL_ERROR_WANT_ASYNC\0" as *const u8 as *const i8,
        10 => return b"SSL_ERROR_WANT_ASYNC_JOB\0" as *const u8 as *const i8,
        _ => return b"SSL_ERROR unknown\0" as *const u8 as *const i8,
    };
}
extern "C" fn ossl_strerror(mut error: u64, mut buf: *mut i8, mut size: size_t) -> *mut i8 {
    if size != 0 {
        (unsafe { *buf = '\u{0}' as i32 as i8 });
    }
    (unsafe { ERR_error_string_n(error, buf, size) });
    if size > 1 as i32 as u64 && (unsafe { *buf }) == 0 {
        (unsafe { strncpy(
            buf,
            if error != 0 {
                b"Unknown error\0" as *const u8 as *const i8
            } else {
                b"No error\0" as *const u8 as *const i8
            },
            size,
        ) });
        (unsafe { *buf.offset(size.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as i8 });
    }
    return buf;
}
extern "C" fn ossl_get_ssl_data_index() -> i32 {
    static mut ssl_ex_data_data_index: i32 = -(1 as i32);
    if (unsafe { ssl_ex_data_data_index }) < 0 as i32 {
        (unsafe { ssl_ex_data_data_index = CRYPTO_get_ex_new_index(
            0 as i32,
            0 as i32 as i64,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        ) });
    }
    return unsafe { ssl_ex_data_data_index };
}
extern "C" fn ossl_get_ssl_conn_index() -> i32 {
    static mut ssl_ex_data_conn_index: i32 = -(1 as i32);
    if (unsafe { ssl_ex_data_conn_index }) < 0 as i32 {
        (unsafe { ssl_ex_data_conn_index = CRYPTO_get_ex_new_index(
            0 as i32,
            0 as i32 as i64,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        ) });
    }
    return unsafe { ssl_ex_data_conn_index };
}
extern "C" fn ossl_get_ssl_sockindex_index() -> i32 {
    static mut sockindex_index: i32 = -(1 as i32);
    if (unsafe { sockindex_index }) < 0 as i32 {
        (unsafe { sockindex_index = CRYPTO_get_ex_new_index(
            0 as i32,
            0 as i32 as i64,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        ) });
    }
    return unsafe { sockindex_index };
}
extern "C" fn ossl_get_proxy_index() -> i32 {
    static mut proxy_index: i32 = -(1 as i32);
    if (unsafe { proxy_index }) < 0 as i32 {
        (unsafe { proxy_index = CRYPTO_get_ex_new_index(
            0 as i32,
            0 as i32 as i64,
            0 as *mut libc::c_void,
            None,
            None,
            None,
        ) });
    }
    return unsafe { proxy_index };
}
extern "C" fn passwd_callback(
    mut buf: *mut i8,
    mut num: i32,
    mut encrypting: i32,
    mut global_passwd: *mut libc::c_void,
) -> i32 {
    if encrypting == 0 {
        let mut klen: i32 = unsafe { curlx_uztosi(strlen(global_passwd as *mut i8)) };
        if num > klen {
            (unsafe { memcpy(
                buf as *mut libc::c_void,
                global_passwd,
                (klen + 1 as i32) as u64,
            ) });
            return klen;
        }
    }
    return 0 as i32;
}
extern "C" fn rand_enough() -> bool {
    return if 0 as i32 != (unsafe { RAND_status() }) {
        1 as i32
    } else {
        0 as i32
    } != 0;
}
extern "C" fn ossl_seed(mut data: *mut Curl_easy) -> CURLcode {
    let mut fname: [i8; 256] = [0; 256];
    if !(unsafe { (*data).multi }).is_null() && (unsafe { (*(*data).multi).ssl_seeded }) as i32 != 0 {
        return CURLE_OK;
    }
    if rand_enough() {
        if !(unsafe { (*data).multi }).is_null() {
            (unsafe { (*(*data).multi).ssl_seeded = 1 as i32 != 0 });
        }
        return CURLE_OK;
    }
    (unsafe { RAND_load_file(
        if !((*data).set.str_0[STRING_SSL_RANDOM_FILE as i32 as usize]).is_null() {
            (*data).set.str_0[STRING_SSL_RANDOM_FILE as i32 as usize] as *const i8
        } else {
            b"/dev/urandom\0" as *const u8 as *const i8
        },
        1024 as i32 as i64,
    ) });
    if rand_enough() {
        return CURLE_OK;
    }
    loop {
        let mut randb: [u8; 64] = [0; 64];
        let mut len: size_t = ::std::mem::size_of::<[u8; 64]>() as u64;
        let mut i: size_t = 0;
        let mut i_max: size_t = 0;
        i = 0 as i32 as size_t;
        i_max = len.wrapping_div(::std::mem::size_of::<curltime>() as u64);
        while i < i_max {
            let mut tv: curltime = unsafe { Curl_now() };
            (unsafe { Curl_wait_ms(1 as i32 as timediff_t) });
            tv.tv_sec = (tv.tv_sec as u64).wrapping_mul(i.wrapping_add(1 as i32 as u64)) as time_t
                as time_t;
            tv.tv_usec = (tv.tv_usec as u32).wrapping_mul((i as u32).wrapping_add(2 as i32 as u32))
                as i32 as i32;
            tv.tv_sec = (tv.tv_sec as u64
                ^ (((unsafe { Curl_now() }).tv_sec + (unsafe { Curl_now() }).tv_usec as i64) as u64)
                    .wrapping_mul(i.wrapping_add(3 as i32 as u64))
                    << 8 as i32) as time_t;
            tv.tv_usec = (tv.tv_usec as u32
                ^ ((((unsafe { Curl_now() }).tv_sec + (unsafe { Curl_now() }).tv_usec as i64) as u64)
                    .wrapping_mul(i.wrapping_add(4 as i32 as u64)) as u32)
                    << 16 as i32) as i32;
            (unsafe { memcpy(
                &mut *randb
                    .as_mut_ptr()
                    .offset(i.wrapping_mul(::std::mem::size_of::<curltime>() as u64) as isize)
                    as *mut u8 as *mut libc::c_void,
                &mut tv as *mut curltime as *const libc::c_void,
                ::std::mem::size_of::<curltime>() as u64,
            ) });
            i = i.wrapping_add(1);
        }
        (unsafe { RAND_add(
            randb.as_mut_ptr() as *const libc::c_void,
            len as i32,
            len as f64 / 2 as i32 as f64,
        ) });
        if rand_enough() {
            break;
        }
    }
    fname[0 as i32 as usize] = 0 as i32 as i8;
    (unsafe { RAND_file_name(
        fname.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 256]>() as u64,
    ) });
    if fname[0 as i32 as usize] != 0 {
        (unsafe { RAND_load_file(fname.as_mut_ptr(), 1024 as i32 as i64) });
        if rand_enough() {
            return CURLE_OK;
        }
    }
    (unsafe { Curl_infof(
        data,
        b"libcurl is now using a weak random seed!\0" as *const u8 as *const i8,
    ) });
    return (if rand_enough() as i32 != 0 {
        CURLE_OK as i32
    } else {
        CURLE_SSL_CONNECT_ERROR as i32
    }) as CURLcode;
}
extern "C" fn do_file_type(mut type_0: *const i8) -> i32 {
    if type_0.is_null() || (unsafe { *type_0.offset(0 as i32 as isize) }) == 0 {
        return 1 as i32;
    }
    if (unsafe { Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const i8) }) != 0 {
        return 1 as i32;
    }
    if (unsafe { Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const i8) }) != 0 {
        return 2 as i32;
    }
    if (unsafe { Curl_strcasecompare(type_0, b"ENG\0" as *const u8 as *const i8) }) != 0 {
        return 42 as i32;
    }
    if (unsafe { Curl_strcasecompare(type_0, b"P12\0" as *const u8 as *const i8) }) != 0 {
        return 43 as i32;
    }
    return -(1 as i32);
}
extern "C" fn ssl_ui_reader(mut ui: *mut UI, mut uis: *mut UI_STRING) -> i32 {
    let mut password: *const i8 = 0 as *const i8;
    match (unsafe { UI_get_string_type(uis) }) as u32 {
        1 | 2 => {
            password = (unsafe { UI_get0_user_data(ui) }) as *const i8;
            if !password.is_null() && (unsafe { UI_get_input_flags(uis) }) & 0x2 as i32 != 0 {
                (unsafe { UI_set_result(ui, uis, password) });
                return 1 as i32;
            }
        }
        _ => {}
    }
    return unsafe { (UI_method_get_reader(UI_OpenSSL())).expect("non-null function pointer")(ui, uis) };
}
extern "C" fn ssl_ui_writer(mut ui: *mut UI, mut uis: *mut UI_STRING) -> i32 {
    match (unsafe { UI_get_string_type(uis) }) as u32 {
        1 | 2 => {
            if !(unsafe { UI_get0_user_data(ui) }).is_null() && (unsafe { UI_get_input_flags(uis) }) & 0x2 as i32 != 0 {
                return 1 as i32;
            }
        }
        _ => {}
    }
    return unsafe { (UI_method_get_writer(UI_OpenSSL())).expect("non-null function pointer")(ui, uis) };
}
extern "C" fn is_pkcs11_uri(mut string: *const i8) -> bool {
    return !string.is_null()
        && (unsafe { Curl_strncasecompare(
            string,
            b"pkcs11:\0" as *const u8 as *const i8,
            7 as i32 as size_t,
        ) }) != 0;
}
extern "C" fn SSL_CTX_use_certificate_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut type_0: i32,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as i32;
    }
    if type_0 == 2 as i32 {
        x = unsafe { d2i_X509_bio(in_0, 0 as *mut *mut X509) };
        current_block = 1917311967535052937;
    } else if type_0 == 1 as i32 {
        x = unsafe { PEM_read_bio_X509(
            in_0,
            0 as *mut *mut X509,
            Some(
                passwd_callback
                    as unsafe extern "C" fn(*mut i8, i32, i32, *mut libc::c_void) -> i32,
            ),
            key_passwd as *mut libc::c_void,
        ) };
        current_block = 1917311967535052937;
    } else {
        ret = 0 as i32;
        current_block = 6802497266704708067;
    }
    match current_block {
        1917311967535052937 => {
            if x.is_null() {
                ret = 0 as i32;
            } else {
                ret = unsafe { SSL_CTX_use_certificate(ctx, x) };
            }
        }
        _ => {}
    }
    (unsafe { X509_free(x) });
    (unsafe { BIO_free(in_0) });
    return ret;
}
extern "C" fn SSL_CTX_use_PrivateKey_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut type_0: i32,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut pkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as i32;
    }
    if type_0 == 1 as i32 {
        pkey = unsafe { PEM_read_bio_PrivateKey(
            in_0,
            0 as *mut *mut EVP_PKEY,
            Some(
                passwd_callback
                    as unsafe extern "C" fn(*mut i8, i32, i32, *mut libc::c_void) -> i32,
            ),
            key_passwd as *mut libc::c_void,
        ) };
        current_block = 14523784380283086299;
    } else if type_0 == 2 as i32 {
        pkey = unsafe { d2i_PrivateKey_bio(in_0, 0 as *mut *mut EVP_PKEY) };
        current_block = 14523784380283086299;
    } else {
        ret = 0 as i32;
        current_block = 15486141263482268688;
    }
    match current_block {
        14523784380283086299 => {
            if pkey.is_null() {
                ret = 0 as i32;
            } else {
                ret = unsafe { SSL_CTX_use_PrivateKey(ctx, pkey) };
                (unsafe { EVP_PKEY_free(pkey) });
            }
        }
        _ => {}
    }
    (unsafe { BIO_free(in_0) });
    return ret;
}
extern "C" fn SSL_CTX_use_certificate_chain_blob(
    mut ctx: *mut SSL_CTX,
    mut blob: *const curl_blob,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut x: *mut X509 = 0 as *mut X509;
    let mut passwd_callback_userdata: *mut libc::c_void = key_passwd as *mut libc::c_void;
    let mut in_0: *mut BIO = unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as i32;
    }
    (unsafe { ERR_clear_error() });
    x = unsafe { PEM_read_bio_X509_AUX(
        in_0,
        0 as *mut *mut X509,
        Some(passwd_callback as unsafe extern "C" fn(*mut i8, i32, i32, *mut libc::c_void) -> i32),
        key_passwd as *mut libc::c_void,
    ) };
    if x.is_null() {
        ret = 0 as i32;
    } else {
        ret = unsafe { SSL_CTX_use_certificate(ctx, x) };
        if (unsafe { ERR_peek_error() }) != 0 as i32 as u64 {
            ret = 0 as i32;
        }
        if ret != 0 {
            let mut ca: *mut X509 = 0 as *mut X509;
            let mut err: u64 = 0;
            if (unsafe { SSL_CTX_ctrl(
                ctx,
                88 as i32,
                0 as i32 as i64,
                0 as *mut libc::c_void as *mut i8 as *mut libc::c_void,
            ) }) == 0
            {
                ret = 0 as i32;
            } else {
                loop {
                    ca = unsafe { PEM_read_bio_X509(
                        in_0,
                        0 as *mut *mut X509,
                        Some(
                            passwd_callback
                                as unsafe extern "C" fn(
                                    *mut i8,
                                    i32,
                                    i32,
                                    *mut libc::c_void,
                                ) -> i32,
                        ),
                        passwd_callback_userdata,
                    ) };
                    if ca.is_null() {
                        current_block = 26972500619410423;
                        break;
                    }
                    if !((unsafe { SSL_CTX_ctrl(
                        ctx,
                        89 as i32,
                        0 as i32 as i64,
                        ca as *mut i8 as *mut libc::c_void,
                    ) }) == 0)
                    {
                        continue;
                    }
                    (unsafe { X509_free(ca) });
                    ret = 0 as i32;
                    current_block = 913271366073613996;
                    break;
                }
                match current_block {
                    913271366073613996 => {}
                    _ => {
                        err = unsafe { ERR_peek_last_error() };
                        if (err >> 24 as i64 & 0xff as i64 as u64) as i32 == 9 as i32
                            && (err & 0xfff as i64 as u64) as i32 == 108 as i32
                        {
                            (unsafe { ERR_clear_error() });
                        } else {
                            ret = 0 as i32;
                        }
                    }
                }
            }
        }
    }
    (unsafe { X509_free(x) });
    (unsafe { BIO_free(in_0) });
    return ret;
}
extern "C" fn cert_stuff(
    mut data: *mut Curl_easy,
    mut ctx: *mut SSL_CTX,
    mut cert_file: *mut i8,
    mut cert_blob: *const curl_blob,
    mut cert_type: *const i8,
    mut key_file: *mut i8,
    mut key_blob: *const curl_blob,
    mut key_type: *const i8,
    mut key_passwd: *mut i8,
) -> i32 {
    let mut current_block: u64;
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut check_privkey: bool = 1 as i32 != 0;
    let mut file_type: i32 = do_file_type(cert_type);
    if !cert_file.is_null() || !cert_blob.is_null() || file_type == 42 as i32 {
        let mut ssl: *mut SSL = 0 as *mut SSL;
        let mut x509: *mut X509 = 0 as *mut X509;
        let mut cert_done: i32 = 0 as i32;
        let mut cert_use_result: i32 = 0;
        if !key_passwd.is_null() {
            (unsafe { SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd as *mut libc::c_void) });
            (unsafe { SSL_CTX_set_default_passwd_cb(
                ctx,
                Some(
                    passwd_callback
                        as unsafe extern "C" fn(*mut i8, i32, i32, *mut libc::c_void) -> i32,
                ),
            ) });
        }
        match file_type {
            1 => {
                cert_use_result = if !cert_blob.is_null() {
                    SSL_CTX_use_certificate_chain_blob(ctx, cert_blob, key_passwd)
                } else {
                    unsafe { SSL_CTX_use_certificate_chain_file(ctx, cert_file) }
                };
                if cert_use_result != 1 as i32 {
                    (unsafe { Curl_failf (data , b"could not load PEM client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0" as * const u8 as * const i8 , ossl_strerror (ERR_get_error () , error_buffer . as_mut_ptr () , :: std :: mem :: size_of :: < [i8 ; 256] > () as u64 ,) ,) }) ;
                    return 0 as i32;
                }
            }
            2 => {
                cert_use_result = if !cert_blob.is_null() {
                    SSL_CTX_use_certificate_blob(ctx, cert_blob, file_type, key_passwd)
                } else {
                    unsafe { SSL_CTX_use_certificate_file(ctx, cert_file, file_type) }
                };
                if cert_use_result != 1 as i32 {
                    (unsafe { Curl_failf (data , b"could not load ASN1 client certificate, OpenSSL error %s, (no key found, wrong pass phrase, or wrong file format?)\0" as * const u8 as * const i8 , ossl_strerror (ERR_get_error () , error_buffer . as_mut_ptr () , :: std :: mem :: size_of :: < [i8 ; 256] > () as u64 ,) ,) }) ;
                    return 0 as i32;
                }
            }
            42 => {
                if (unsafe { (*data).state.engine }).is_null() {
                    if is_pkcs11_uri(cert_file) {
                        if ossl_set_engine(data, b"pkcs11\0" as *const u8 as *const i8) as u32
                            != CURLE_OK as i32 as u32
                        {
                            return 0 as i32;
                        }
                    }
                }
                if !(unsafe { (*data).state.engine }).is_null() {
                    let mut cmd_name: *const i8 = b"LOAD_CERT_CTRL\0" as *const u8 as *const i8;
                    let mut params: C2RustUnnamed_13 = C2RustUnnamed_13 {
                        cert_id: 0 as *const i8,
                        cert: 0 as *mut X509,
                    };
                    params.cert_id = cert_file;
                    params.cert = 0 as *mut X509;
                    if (unsafe { ENGINE_ctrl(
                        (*data).state.engine as *mut ENGINE,
                        13 as i32,
                        0 as i32 as i64,
                        cmd_name as *mut libc::c_void,
                        None,
                    ) }) == 0
                    {
                        (unsafe { Curl_failf(
                            data,
                            b"ssl engine does not support loading certificates\0" as *const u8
                                as *const i8,
                        ) });
                        return 0 as i32;
                    }
                    if (unsafe { ENGINE_ctrl_cmd(
                        (*data).state.engine as *mut ENGINE,
                        cmd_name,
                        0 as i32 as i64,
                        &mut params as *mut C2RustUnnamed_13 as *mut libc::c_void,
                        None,
                        1 as i32,
                    ) }) == 0
                    {
                        (unsafe { Curl_failf(
                            data,
                            b"ssl engine cannot load client cert with id '%s' [%s]\0" as *const u8
                                as *const i8,
                            cert_file,
                            ossl_strerror(
                                ERR_get_error(),
                                error_buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 256]>() as u64,
                            ),
                        ) });
                        return 0 as i32;
                    }
                    if (params.cert).is_null() {
                        (unsafe { Curl_failf(
                            data,
                            b"ssl engine didn't initialized the certificate properly.\0"
                                as *const u8 as *const i8,
                        ) });
                        return 0 as i32;
                    }
                    if (unsafe { SSL_CTX_use_certificate(ctx, params.cert) }) != 1 as i32 {
                        (unsafe { Curl_failf(
                            data,
                            b"unable to set client certificate\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { X509_free(params.cert) });
                        return 0 as i32;
                    }
                    (unsafe { X509_free(params.cert) });
                } else {
                    (unsafe { Curl_failf(
                        data,
                        b"crypto engine not set, can't load certificate\0" as *const u8
                            as *const i8,
                    ) });
                    return 0 as i32;
                }
            }
            43 => {
                let mut cert_bio: *mut BIO = 0 as *mut BIO;
                let mut p12: *mut PKCS12 = 0 as *mut PKCS12;
                let mut pri: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                let mut ca: *mut stack_st_X509 = 0 as *mut stack_st_X509;
                if !cert_blob.is_null() {
                    cert_bio = unsafe { BIO_new_mem_buf((*cert_blob).data, (*cert_blob).len as i32) };
                    if cert_bio.is_null() {
                        (unsafe { Curl_failf(
                            data,
                            b"BIO_new_mem_buf NULL, OpenSSL error %s\0" as *const u8 as *const i8,
                            ossl_strerror(
                                ERR_get_error(),
                                error_buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 256]>() as u64,
                            ),
                        ) });
                        return 0 as i32;
                    }
                } else {
                    cert_bio = unsafe { BIO_new(BIO_s_file()) };
                    if cert_bio.is_null() {
                        (unsafe { Curl_failf(
                            data,
                            b"BIO_new return NULL, OpenSSL error %s\0" as *const u8 as *const i8,
                            ossl_strerror(
                                ERR_get_error(),
                                error_buffer.as_mut_ptr(),
                                ::std::mem::size_of::<[i8; 256]>() as u64,
                            ),
                        ) });
                        return 0 as i32;
                    }
                    if (unsafe { BIO_ctrl(
                        cert_bio,
                        108 as i32,
                        (0x1 as i32 | 0x2 as i32) as i64,
                        cert_file as *mut libc::c_void,
                    ) }) as i32
                        <= 0 as i32
                    {
                        (unsafe { Curl_failf(
                            data,
                            b"could not open PKCS12 file '%s'\0" as *const u8 as *const i8,
                            cert_file,
                        ) });
                        (unsafe { BIO_free(cert_bio) });
                        return 0 as i32;
                    }
                }
                p12 = unsafe { d2i_PKCS12_bio(cert_bio, 0 as *mut *mut PKCS12) };
                (unsafe { BIO_free(cert_bio) });
                if p12.is_null() {
                    (unsafe { Curl_failf(
                        data,
                        b"error reading PKCS12 file '%s'\0" as *const u8 as *const i8,
                        if !cert_blob.is_null() {
                            b"(memory blob)\0" as *const u8 as *const i8
                        } else {
                            cert_file as *const i8
                        },
                    ) });
                    return 0 as i32;
                }
                (unsafe { PKCS12_PBE_add() });
                if (unsafe { PKCS12_parse(p12, key_passwd, &mut pri, &mut x509, &mut ca) }) == 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"could not parse PKCS12 file, check password, OpenSSL error %s\0"
                            as *const u8 as *const i8,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                    (unsafe { PKCS12_free(p12) });
                    return 0 as i32;
                }
                (unsafe { PKCS12_free(p12) });
                if (unsafe { SSL_CTX_use_certificate(ctx, x509) }) != 1 as i32 {
                    (unsafe { Curl_failf(
                        data,
                        b"could not load PKCS12 client certificate, OpenSSL error %s\0" as *const u8
                            as *const i8,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                } else if (unsafe { SSL_CTX_use_PrivateKey(ctx, pri) }) != 1 as i32 {
                    (unsafe { Curl_failf(
                        data,
                        b"unable to use private key from PKCS12 file '%s'\0" as *const u8
                            as *const i8,
                        cert_file,
                    ) });
                } else if (unsafe { SSL_CTX_check_private_key(ctx) }) == 0 {
                    (unsafe { Curl_failf (data , b"private key from PKCS12 file '%s' does not match certificate in same file\0" as * const u8 as * const i8 , cert_file ,) }) ;
                } else {
                    if !ca.is_null() {
                        loop {
                            if !(sk_X509_num(ca) != 0) {
                                current_block = 17395932908762866334;
                                break;
                            }
                            let mut x: *mut X509 = sk_X509_pop(ca);
                            if (unsafe { SSL_CTX_add_client_CA(ctx, x) }) == 0 {
                                (unsafe { X509_free(x) });
                                (unsafe { Curl_failf(
                                    data,
                                    b"cannot add certificate to client CA list\0" as *const u8
                                        as *const i8,
                                ) });
                                current_block = 13467756696118492503;
                                break;
                            } else {
                                if !((unsafe { SSL_CTX_ctrl(
                                    ctx,
                                    14 as i32,
                                    0 as i32 as i64,
                                    x as *mut i8 as *mut libc::c_void,
                                ) }) == 0)
                                {
                                    continue;
                                }
                                (unsafe { X509_free(x) });
                                (unsafe { Curl_failf(
                                    data,
                                    b"cannot add certificate to certificate chain\0" as *const u8
                                        as *const i8,
                                ) });
                                current_block = 13467756696118492503;
                                break;
                            }
                        }
                    } else {
                        current_block = 17395932908762866334;
                    }
                    match current_block {
                        13467756696118492503 => {}
                        _ => {
                            cert_done = 1 as i32;
                        }
                    }
                }
                (unsafe { EVP_PKEY_free(pri) });
                (unsafe { X509_free(x509) });
                sk_X509_pop_free(ca, Some(X509_free as unsafe extern "C" fn(*mut X509) -> ()));
                if cert_done == 0 {
                    return 0 as i32;
                }
            }
            _ => {
                (unsafe { Curl_failf(
                    data,
                    b"not supported file type '%s' for certificate\0" as *const u8 as *const i8,
                    cert_type,
                ) });
                return 0 as i32;
            }
        }
        if key_file.is_null() && key_blob.is_null() {
            key_file = cert_file;
            key_blob = cert_blob;
        } else {
            file_type = do_file_type(key_type);
        }
        let mut current_block_141: u64;
        match file_type {
            1 => {
                if cert_done != 0 {
                    current_block_141 = 14358540534591340610;
                } else {
                    current_block_141 = 9074170816027543424;
                }
            }
            2 => {
                current_block_141 = 9074170816027543424;
            }
            42 => {
                let mut priv_key: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
                if (unsafe { (*data).state.engine }).is_null() {
                    if is_pkcs11_uri(key_file) {
                        if ossl_set_engine(data, b"pkcs11\0" as *const u8 as *const i8) as u32
                            != CURLE_OK as i32 as u32
                        {
                            return 0 as i32;
                        }
                    }
                }
                if !(unsafe { (*data).state.engine }).is_null() {
                    let mut ui_method: *mut UI_METHOD = unsafe { UI_create_method(
                        b"curl user interface\0" as *const u8 as *const i8 as *mut i8,
                    ) };
                    if ui_method.is_null() {
                        (unsafe { Curl_failf(
                            data,
                            b"unable do create OpenSSL user-interface method\0" as *const u8
                                as *const i8,
                        ) });
                        return 0 as i32;
                    }
                    (unsafe { UI_method_set_opener(ui_method, UI_method_get_opener(UI_OpenSSL())) });
                    (unsafe { UI_method_set_closer(ui_method, UI_method_get_closer(UI_OpenSSL())) });
                    (unsafe { UI_method_set_reader(
                        ui_method,
                        Some(ssl_ui_reader as unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32),
                    ) });
                    (unsafe { UI_method_set_writer(
                        ui_method,
                        Some(ssl_ui_writer as unsafe extern "C" fn(*mut UI, *mut UI_STRING) -> i32),
                    ) });
                    priv_key = unsafe { ENGINE_load_private_key(
                        (*data).state.engine as *mut ENGINE,
                        key_file,
                        ui_method,
                        key_passwd as *mut libc::c_void,
                    ) };
                    (unsafe { UI_destroy_method(ui_method) });
                    if priv_key.is_null() {
                        (unsafe { Curl_failf(
                            data,
                            b"failed to load private key from crypto engine\0" as *const u8
                                as *const i8,
                        ) });
                        return 0 as i32;
                    }
                    if (unsafe { SSL_CTX_use_PrivateKey(ctx, priv_key) }) != 1 as i32 {
                        (unsafe { Curl_failf(
                            data,
                            b"unable to set private key\0" as *const u8 as *const i8,
                        ) });
                        (unsafe { EVP_PKEY_free(priv_key) });
                        return 0 as i32;
                    }
                    (unsafe { EVP_PKEY_free(priv_key) });
                } else {
                    (unsafe { Curl_failf(
                        data,
                        b"crypto engine not set, can't load private key\0" as *const u8
                            as *const i8,
                    ) });
                    return 0 as i32;
                }
                current_block_141 = 14358540534591340610;
            }
            43 => {
                if cert_done == 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"file type P12 for private key not supported\0" as *const u8 as *const i8,
                    ) });
                    return 0 as i32;
                }
                current_block_141 = 14358540534591340610;
            }
            _ => {
                (unsafe { Curl_failf(
                    data,
                    b"not supported file type for private key\0" as *const u8 as *const i8,
                ) });
                return 0 as i32;
            }
        }
        match current_block_141 {
            9074170816027543424 => {
                cert_use_result = if !key_blob.is_null() {
                    SSL_CTX_use_PrivateKey_blob(ctx, key_blob, file_type, key_passwd)
                } else {
                    unsafe { SSL_CTX_use_PrivateKey_file(ctx, key_file, file_type) }
                };
                if cert_use_result != 1 as i32 {
                    (unsafe { Curl_failf(
                        data,
                        b"unable to set private key file: '%s' type %s\0" as *const u8 as *const i8,
                        if !key_file.is_null() {
                            key_file as *const i8
                        } else {
                            b"(memory blob)\0" as *const u8 as *const i8
                        },
                        if !key_type.is_null() {
                            key_type
                        } else {
                            b"PEM\0" as *const u8 as *const i8
                        },
                    ) });
                    return 0 as i32;
                }
            }
            _ => {}
        }
        ssl = unsafe { SSL_new(ctx) };
        if ssl.is_null() {
            (unsafe { Curl_failf(
                data,
                b"unable to create an SSL structure\0" as *const u8 as *const i8,
            ) });
            return 0 as i32;
        }
        x509 = unsafe { SSL_get_certificate(ssl) };
        if !x509.is_null() {
            let mut pktmp: *mut EVP_PKEY = unsafe { X509_get_pubkey(x509) };
            (unsafe { EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl)) });
            (unsafe { EVP_PKEY_free(pktmp) });
        }
        let mut priv_key_0: *mut EVP_PKEY = unsafe { SSL_get_privatekey(ssl) };
        let mut pktype: i32 = 0;
        pktype = unsafe { EVP_PKEY_id(priv_key_0) };
        if pktype == 6 as i32 {
            let mut rsa: *mut RSA = unsafe { EVP_PKEY_get1_RSA(priv_key_0) };
            if (unsafe { RSA_flags(rsa) }) & 0x1 as i32 != 0 {
                check_privkey = 0 as i32 != 0;
            }
            (unsafe { RSA_free(rsa) });
        }
        (unsafe { SSL_free(ssl) });
        if check_privkey as i32 == 1 as i32 {
            if (unsafe { SSL_CTX_check_private_key(ctx) }) == 0 {
                (unsafe { Curl_failf(
                    data,
                    b"Private key does not match the certificate public key\0" as *const u8
                        as *const i8,
                ) });
                return 0 as i32;
            }
        }
    }
    return 1 as i32;
}
extern "C" fn x509_name_oneline(mut a: *mut X509_NAME, mut buf: *mut i8, mut size: size_t) -> i32 {
    let mut bio_out: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
    let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
    let mut rc: i32 = 0;
    if bio_out.is_null() {
        return 1 as i32;
    }
    rc = unsafe { X509_NAME_print_ex(bio_out, a, 0 as i32, ((3 as i32) << 16 as i32) as u64) };
    (unsafe { BIO_ctrl(
        bio_out,
        115 as i32,
        0 as i32 as i64,
        &mut biomem as *mut *mut BUF_MEM as *mut i8 as *mut libc::c_void,
    ) });
    if (unsafe { (*biomem).length }) < size {
        size = unsafe { (*biomem).length };
    } else {
        size = size.wrapping_sub(1);
    }
    (unsafe { memcpy(
        buf as *mut libc::c_void,
        (*biomem).data as *const libc::c_void,
        size,
    ) });
    (unsafe { *buf.offset(size as isize) = 0 as i32 as i8 });
    (unsafe { BIO_free(bio_out) });
    return (rc == 0) as i32;
}
extern "C" fn ossl_init() -> i32 {
    let flags: uint64_t = (0x200 as i64
        | 0x400 as i64
        | 0x1000 as i64
        | 0x2000 as i64
        | 0x4000 as i64
        | 0x40 as i64
        | 0 as i32 as i64) as uint64_t;
    (unsafe { OPENSSL_init_ssl(flags, 0 as *const OPENSSL_INIT_SETTINGS) });
    (unsafe { Curl_tls_keylog_open() });
    if ossl_get_ssl_data_index() < 0 as i32
        || ossl_get_ssl_conn_index() < 0 as i32
        || ossl_get_ssl_sockindex_index() < 0 as i32
        || ossl_get_proxy_index() < 0 as i32
    {
        return 0 as i32;
    }
    return 1 as i32;
}
extern "C" fn ossl_cleanup() {
    (unsafe { Curl_tls_keylog_close() });
}
extern "C" fn ossl_check_cxn(mut conn: *mut connectdata) -> i32 {
    let mut buf: i8 = 0;
    let mut nread: ssize_t = 0;
    nread = unsafe { recv(
        (*conn).sock[0 as i32 as usize],
        &mut buf as *mut i8 as *mut libc::c_void,
        1 as i32 as size_t,
        MSG_PEEK as i32,
    ) };
    if nread == 0 as i32 as i64 {
        return 0 as i32;
    }
    if nread == 1 as i32 as i64 {
        return 1 as i32;
    } else {
        if nread == -(1 as i32) as i64 {
            let mut err: i32 = unsafe { *__errno_location() };
            if err == 115 as i32 || err == 11 as i32 {
                return 1 as i32;
            }
            if err == 104 as i32
                || err == 103 as i32
                || err == 100 as i32
                || err == 102 as i32
                || err == 108 as i32
                || err == 110 as i32
                || err == 107 as i32
            {
                return 0 as i32;
            }
        }
    }
    return -(1 as i32);
}
extern "C" fn ossl_set_engine(mut data: *mut Curl_easy, mut engine: *const i8) -> CURLcode {
    let mut e: *mut ENGINE = 0 as *mut ENGINE;
    e = unsafe { ENGINE_by_id(engine) };
    if e.is_null() {
        (unsafe { Curl_failf(
            data,
            b"SSL Engine '%s' not found\0" as *const u8 as *const i8,
            engine,
        ) });
        return CURLE_SSL_ENGINE_NOTFOUND;
    }
    if !(unsafe { (*data).state.engine }).is_null() {
        (unsafe { ENGINE_finish((*data).state.engine as *mut ENGINE) });
        (unsafe { ENGINE_free((*data).state.engine as *mut ENGINE) });
        let fresh0 = unsafe { &mut ((*data).state.engine) };
        *fresh0 = 0 as *mut libc::c_void;
    }
    if (unsafe { ENGINE_init(e) }) == 0 {
        let mut buf: [i8; 256] = [0; 256];
        (unsafe { ENGINE_free(e) });
        (unsafe { Curl_failf(
            data,
            b"Failed to initialise SSL Engine '%s': %s\0" as *const u8 as *const i8,
            engine,
            ossl_strerror(
                ERR_get_error(),
                buf.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        return CURLE_SSL_ENGINE_INITFAILED;
    }
    let fresh1 = unsafe { &mut ((*data).state.engine) };
    *fresh1 = e as *mut libc::c_void;
    return CURLE_OK;
}
extern "C" fn ossl_set_engine_default(mut data: *mut Curl_easy) -> CURLcode {
    if !(unsafe { (*data).state.engine }).is_null() {
        if (unsafe { ENGINE_set_default((*data).state.engine as *mut ENGINE, 0xffff as i32 as u32) }) > 0 as i32
        {
            (unsafe { Curl_infof(
                data,
                b"set default crypto engine '%s'\0" as *const u8 as *const i8,
                ENGINE_get_id((*data).state.engine as *const ENGINE),
            ) });
        } else {
            (unsafe { Curl_failf(
                data,
                b"set default crypto engine '%s' failed\0" as *const u8 as *const i8,
                ENGINE_get_id((*data).state.engine as *const ENGINE),
            ) });
            return CURLE_SSL_ENGINE_SETFAILED;
        }
    }
    return CURLE_OK;
}
extern "C" fn ossl_engines_list(mut _data: *mut Curl_easy) -> *mut curl_slist {
    let mut list: *mut curl_slist = 0 as *mut curl_slist;
    let mut beg: *mut curl_slist = 0 as *mut curl_slist;
    let mut e: *mut ENGINE = 0 as *mut ENGINE;
    e = unsafe { ENGINE_get_first() };
    while !e.is_null() {
        beg = unsafe { curl_slist_append(list, ENGINE_get_id(e)) };
        if beg.is_null() {
            (unsafe { curl_slist_free_all(list) });
            return 0 as *mut curl_slist;
        }
        list = beg;
        e = unsafe { ENGINE_get_next(e) };
    }
    return list;
}
extern "C" fn ossl_closeone(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut connssl: *mut ssl_connect_data,
) {
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if !(unsafe { (*backend).handle }).is_null() {
        let mut buf: [i8; 32] = [0; 32];
        let fresh2 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
        *fresh2 = data;
        (unsafe { SSL_read(
            (*backend).handle,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 32]>() as u64 as i32,
        ) });
        (unsafe { SSL_shutdown((*backend).handle) });
        (unsafe { SSL_set_connect_state((*backend).handle) });
        (unsafe { SSL_free((*backend).handle) });
        let fresh3 = unsafe { &mut ((*backend).handle) };
        *fresh3 = 0 as *mut SSL;
    }
    if !(unsafe { (*backend).ctx }).is_null() {
        (unsafe { SSL_CTX_free((*backend).ctx) });
        let fresh4 = unsafe { &mut ((*backend).ctx) };
        *fresh4 = 0 as *mut SSL_CTX;
    }
}
extern "C" fn ossl_close(mut data: *mut Curl_easy, mut conn: *mut connectdata, mut sockindex: i32) {
    ossl_closeone(
        data,
        conn,
        unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) },
    );
    ossl_closeone(
        data,
        conn,
        unsafe { &mut *((*conn).proxy_ssl).as_mut_ptr().offset(sockindex as isize) },
    );
}
extern "C" fn ossl_shutdown(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> i32 {
    let mut retval: i32 = 0 as i32;
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut buf: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut nread: ssize_t = 0;
    let mut buffsize: i32 = 0;
    let mut err: i32 = 0;
    let mut done: bool = 0 as i32 != 0;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut loop_0: i32 = 10 as i32;
    if (unsafe { (*data).set.ftp_ccc }) as u32 == CURLFTPSSL_CCC_ACTIVE as i32 as u32 {
        (unsafe { SSL_shutdown((*backend).handle) });
    }
    if !(unsafe { (*backend).handle }).is_null() {
        buffsize = ::std::mem::size_of::<[i8; 256]>() as u64 as i32;
        while !done && {
            let fresh5 = loop_0;
            loop_0 = loop_0 - 1;
            fresh5 != 0
        } {
            let mut what: i32 = unsafe { Curl_socket_check(
                (*conn).sock[sockindex as usize],
                -(1 as i32),
                -(1 as i32),
                10000 as i32 as timediff_t,
            ) };
            if what > 0 as i32 {
                (unsafe { ERR_clear_error() });
                nread = (unsafe { SSL_read(
                    (*backend).handle,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buffsize,
                ) }) as ssize_t;
                err = unsafe { SSL_get_error((*backend).handle, nread as i32) };
                match err {
                    0 | 6 => {
                        done = 1 as i32 != 0;
                    }
                    2 => {
                        (unsafe { Curl_infof(data, b"SSL_ERROR_WANT_READ\0" as *const u8 as *const i8) });
                    }
                    3 => {
                        (unsafe { Curl_infof(data, b"SSL_ERROR_WANT_WRITE\0" as *const u8 as *const i8) });
                        done = 1 as i32 != 0;
                    }
                    _ => {
                        sslerror = unsafe { ERR_get_error() };
                        (unsafe { Curl_failf(
                            data,
                            b"OpenSSL SSL_read on shutdown: %s, errno %d\0" as *const u8
                                as *const i8,
                            if sslerror != 0 {
                                ossl_strerror(
                                    sslerror,
                                    buf.as_mut_ptr(),
                                    ::std::mem::size_of::<[i8; 256]>() as u64,
                                ) as *const i8
                            } else {
                                SSL_ERROR_to_str(err)
                            },
                            *__errno_location(),
                        ) });
                        done = 1 as i32 != 0;
                    }
                }
            } else if 0 as i32 == what {
                (unsafe { Curl_failf(data, b"SSL shutdown timeout\0" as *const u8 as *const i8) });
                done = 1 as i32 != 0;
            } else {
                (unsafe { Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const i8,
                    *__errno_location(),
                ) });
                retval = -(1 as i32);
                done = 1 as i32 != 0;
            }
        }
        if (unsafe { ((*data).set).verbose() }) != 0 {
            match unsafe { SSL_get_shutdown((*backend).handle) } {
                1 => {
                    (unsafe { Curl_infof(
                        data,
                        b"SSL_get_shutdown() returned SSL_SENT_SHUTDOWN\0" as *const u8
                            as *const i8,
                    ) });
                }
                2 => {
                    (unsafe { Curl_infof(
                        data,
                        b"SSL_get_shutdown() returned SSL_RECEIVED_SHUTDOWN\0" as *const u8
                            as *const i8,
                    ) });
                }
                3 => {
                    (unsafe { Curl_infof(
                        data,
                        b"SSL_get_shutdown() returned SSL_SENT_SHUTDOWN|SSL_RECEIVED__SHUTDOWN\0"
                            as *const u8 as *const i8,
                    ) });
                }
                _ => {}
            }
        }
        (unsafe { SSL_free((*backend).handle) });
        let fresh6 = unsafe { &mut ((*backend).handle) };
        *fresh6 = 0 as *mut SSL;
    }
    return retval;
}
extern "C" fn ossl_session_free(mut ptr: *mut libc::c_void) {
    (unsafe { SSL_SESSION_free(ptr as *mut SSL_SESSION) });
}
extern "C" fn ossl_close_all(mut data: *mut Curl_easy) {
    if !(unsafe { (*data).state.engine }).is_null() {
        (unsafe { ENGINE_finish((*data).state.engine as *mut ENGINE) });
        (unsafe { ENGINE_free((*data).state.engine as *mut ENGINE) });
        let fresh7 = unsafe { &mut ((*data).state.engine) };
        *fresh7 = 0 as *mut libc::c_void;
    }
}
extern "C" fn subj_alt_hostcheck(
    mut data: *mut Curl_easy,
    mut match_pattern: *const i8,
    mut hostname: *const i8,
    mut dispname: *const i8,
) -> bool {
    if (unsafe { Curl_cert_hostcheck(match_pattern, hostname) }) != 0 {
        (unsafe { Curl_infof(
            data,
            b" subjectAltName: host \"%s\" matched cert's \"%s\"\0" as *const u8 as *const i8,
            dispname,
            match_pattern,
        ) });
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn verifyhost(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut server_cert: *mut X509,
) -> CURLcode {
    let mut matched: bool = 0 as i32 != 0;
    let mut target: i32 = 2 as i32;
    let mut addrlen: size_t = 0 as i32 as size_t;
    let mut altnames: *mut stack_st_GENERAL_NAME = 0 as *mut stack_st_GENERAL_NAME;
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_10 {
            __u6_addr8: [0; 16],
        },
    };
    let mut result: CURLcode = CURLE_OK;
    let mut dNSName: bool = 0 as i32 != 0;
    let mut iPAddress: bool = 0 as i32 != 0;
    let hostname: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    let dispname: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).http_proxy.host.dispname }
    } else {
        unsafe { (*conn).host.dispname }
    };
    if (unsafe { ((*conn).bits).ipv6_ip() }) as i32 != 0
        && (unsafe { inet_pton(
            10 as i32,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        ) }) != 0
    {
        target = 7 as i32;
        addrlen = ::std::mem::size_of::<in6_addr>() as u64;
    } else if (unsafe { inet_pton(
        2 as i32,
        hostname,
        &mut addr as *mut in6_addr as *mut libc::c_void,
    ) }) != 0
    {
        target = 7 as i32;
        addrlen = ::std::mem::size_of::<in_addr>() as u64;
    }
    altnames = (unsafe { X509_get_ext_d2i(server_cert, 85 as i32, 0 as *mut i32, 0 as *mut i32) })
        as *mut stack_st_GENERAL_NAME;
    if !altnames.is_null() {
        let mut numalts: i32 = 0;
        let mut i: i32 = 0;
        let mut dnsmatched: bool = 0 as i32 != 0;
        let mut ipmatched: bool = 0 as i32 != 0;
        numalts = sk_GENERAL_NAME_num(altnames);
        i = 0 as i32;
        while i < numalts && !dnsmatched {
            let mut check: *const GENERAL_NAME = sk_GENERAL_NAME_value(altnames, i);
            if (unsafe { (*check).type_0 }) == 2 as i32 {
                dNSName = 1 as i32 != 0;
            } else if (unsafe { (*check).type_0 }) == 7 as i32 {
                iPAddress = 1 as i32 != 0;
            }
            if (unsafe { (*check).type_0 }) == target {
                let mut altptr: *const i8 = (unsafe { ASN1_STRING_get0_data((*check).d.ia5) }) as *mut i8;
                let mut altlen: size_t = (unsafe { ASN1_STRING_length((*check).d.ia5) }) as size_t;
                match target {
                    2 => {
                        if altlen == (unsafe { strlen(altptr) })
                            && subj_alt_hostcheck(data, altptr, hostname, dispname) as i32 != 0
                        {
                            dnsmatched = 1 as i32 != 0;
                        }
                    }
                    7 => {
                        if altlen == addrlen
                            && (unsafe { memcmp(
                                altptr as *const libc::c_void,
                                &mut addr as *mut in6_addr as *const libc::c_void,
                                altlen,
                            ) }) == 0
                        {
                            ipmatched = 1 as i32 != 0;
                            (unsafe { Curl_infof(
                                data,
                                b" subjectAltName: host \"%s\" matched cert's IP address!\0"
                                    as *const u8 as *const i8,
                                dispname,
                            ) });
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        (unsafe { GENERAL_NAMES_free(altnames) });
        if dnsmatched as i32 != 0 || ipmatched as i32 != 0 {
            matched = 1 as i32 != 0;
        }
    }
    if !matched {
        if dNSName as i32 != 0 || iPAddress as i32 != 0 {
            (unsafe { Curl_infof(
                data,
                b" subjectAltName does not match %s\0" as *const u8 as *const i8,
                dispname,
            ) });
            (unsafe { Curl_failf(
                data,
                b"SSL: no alternative certificate subject name matches target host name '%s'\0"
                    as *const u8 as *const i8,
                dispname,
            ) });
            result = CURLE_PEER_FAILED_VERIFICATION;
        } else {
            let mut j: i32 = 0;
            let mut i_0: i32 = -(1 as i32);
            let mut nulstr: *mut u8 = b"\0" as *const u8 as *const i8 as *mut u8;
            let mut peer_CN: *mut u8 = nulstr;
            let mut name: *mut X509_NAME = unsafe { X509_get_subject_name(server_cert) };
            if !name.is_null() {
                loop {
                    j = unsafe { X509_NAME_get_index_by_NID(name, 13 as i32, i_0) };
                    if !(j >= 0 as i32) {
                        break;
                    }
                    i_0 = j;
                }
            }
            if i_0 >= 0 as i32 {
                let mut tmp: *mut ASN1_STRING =
                    unsafe { X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i_0)) };
                if !tmp.is_null() {
                    if (unsafe { ASN1_STRING_type(tmp) }) == 12 as i32 {
                        j = unsafe { ASN1_STRING_length(tmp) };
                        if j >= 0 as i32 {
                            peer_CN = (unsafe { CRYPTO_malloc(
                                (j + 1 as i32) as size_t,
                                b"vtls/openssl.c\0" as *const u8 as *const i8,
                                1786 as i32,
                            ) }) as *mut u8;
                            if !peer_CN.is_null() {
                                (unsafe { memcpy(
                                    peer_CN as *mut libc::c_void,
                                    ASN1_STRING_get0_data(tmp) as *const libc::c_void,
                                    j as u64,
                                ) });
                                (unsafe { *peer_CN.offset(j as isize) = '\u{0}' as i32 as u8 });
                            }
                        }
                    } else {
                        j = unsafe { ASN1_STRING_to_UTF8(&mut peer_CN, tmp) };
                    }
                    if !peer_CN.is_null() && (unsafe { curlx_uztosi(strlen(peer_CN as *mut i8)) }) != j {
                        (unsafe { Curl_failf(
                            data,
                            b"SSL: illegal cert name field\0" as *const u8 as *const i8,
                        ) });
                        result = CURLE_PEER_FAILED_VERIFICATION;
                    }
                }
            }
            if peer_CN == nulstr {
                peer_CN = 0 as *mut u8;
            } else {
                let mut rc: CURLcode = CURLE_OK as i32 as CURLcode;
                if rc as u64 != 0 {
                    (unsafe { CRYPTO_free(
                        peer_CN as *mut libc::c_void,
                        b"vtls/openssl.c\0" as *const u8 as *const i8,
                        1813 as i32,
                    ) });
                    return rc;
                }
            }
            if !(result as u64 != 0) {
                if peer_CN.is_null() {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL: unable to obtain common name from peer certificate\0" as *const u8
                            as *const i8,
                    ) });
                    result = CURLE_PEER_FAILED_VERIFICATION;
                } else if (unsafe { Curl_cert_hostcheck(peer_CN as *const i8, hostname) }) == 0 {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL: certificate subject name '%s' does not match target host name '%s'\0"
                            as *const u8 as *const i8,
                        peer_CN,
                        dispname,
                    ) });
                    result = CURLE_PEER_FAILED_VERIFICATION;
                } else {
                    (unsafe { Curl_infof(
                        data,
                        b" common name: %s (matched)\0" as *const u8 as *const i8,
                        peer_CN,
                    ) });
                }
            }
            if !peer_CN.is_null() {
                (unsafe { CRYPTO_free(
                    peer_CN as *mut libc::c_void,
                    b"vtls/openssl.c\0" as *const u8 as *const i8,
                    1835 as i32,
                ) });
            }
        }
    }
    return result;
}
extern "C" fn verifystatus(
    mut data: *mut Curl_easy,
    mut connssl: *mut ssl_connect_data,
) -> CURLcode {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut ocsp_status: i32 = 0;
    let mut status: *mut u8 = 0 as *mut u8;
    let mut p: *const u8 = 0 as *const u8;
    let mut result: CURLcode = CURLE_OK;
    let mut rsp: *mut OCSP_RESPONSE = 0 as *mut OCSP_RESPONSE;
    let mut br: *mut OCSP_BASICRESP = 0 as *mut OCSP_BASICRESP;
    let mut st: *mut X509_STORE = 0 as *mut X509_STORE;
    let mut ch: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut cert: *mut X509 = 0 as *mut X509;
    let mut id: *mut OCSP_CERTID = 0 as *mut OCSP_CERTID;
    let mut cert_status: i32 = 0;
    let mut crl_reason: i32 = 0;
    let mut rev: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut thisupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut nextupd: *mut ASN1_GENERALIZEDTIME = 0 as *mut ASN1_GENERALIZEDTIME;
    let mut ret: i32 = 0;
    let mut len: i64 = unsafe { SSL_ctrl(
        (*backend).handle,
        70 as i32,
        0 as i32 as i64,
        &mut status as *mut *mut u8 as *mut libc::c_void,
    ) };
    if status.is_null() {
        (unsafe { Curl_failf(
            data,
            b"No OCSP response received\0" as *const u8 as *const i8,
        ) });
        result = CURLE_SSL_INVALIDCERTSTATUS;
    } else {
        p = status;
        rsp = unsafe { d2i_OCSP_RESPONSE(0 as *mut *mut OCSP_RESPONSE, &mut p, len) };
        if rsp.is_null() {
            (unsafe { Curl_failf(data, b"Invalid OCSP response\0" as *const u8 as *const i8) });
            result = CURLE_SSL_INVALIDCERTSTATUS;
        } else {
            ocsp_status = unsafe { OCSP_response_status(rsp) };
            if ocsp_status != 0 as i32 {
                (unsafe { Curl_failf(
                    data,
                    b"Invalid OCSP response status: %s (%d)\0" as *const u8 as *const i8,
                    OCSP_response_status_str(ocsp_status as i64),
                    ocsp_status,
                ) });
                result = CURLE_SSL_INVALIDCERTSTATUS;
            } else {
                br = unsafe { OCSP_response_get1_basic(rsp) };
                if br.is_null() {
                    (unsafe { Curl_failf(data, b"Invalid OCSP response\0" as *const u8 as *const i8) });
                    result = CURLE_SSL_INVALIDCERTSTATUS;
                } else {
                    ch = unsafe { SSL_get_peer_cert_chain((*backend).handle) };
                    st = unsafe { SSL_CTX_get_cert_store((*backend).ctx) };
                    if (unsafe { OCSP_basic_verify(br, ch, st, 0 as i32 as u64) }) <= 0 as i32 {
                        (unsafe { Curl_failf(
                            data,
                            b"OCSP response verification failed\0" as *const u8 as *const i8,
                        ) });
                        result = CURLE_SSL_INVALIDCERTSTATUS;
                    } else {
                        cert = unsafe { SSL_get_peer_certificate((*backend).handle) };
                        if cert.is_null() {
                            (unsafe { Curl_failf(
                                data,
                                b"Error getting peer certificate\0" as *const u8 as *const i8,
                            ) });
                            result = CURLE_SSL_INVALIDCERTSTATUS;
                        } else {
                            i = 0 as i32;
                            while i < sk_X509_num(ch) {
                                let mut issuer: *mut X509 = sk_X509_value(ch, i);
                                if (unsafe { X509_check_issued(issuer, cert) }) == 0 as i32 {
                                    id = unsafe { OCSP_cert_to_id(EVP_sha1(), cert, issuer) };
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                            (unsafe { X509_free(cert) });
                            if id.is_null() {
                                (unsafe { Curl_failf(
                                    data,
                                    b"Error computing OCSP ID\0" as *const u8 as *const i8,
                                ) });
                                result = CURLE_SSL_INVALIDCERTSTATUS;
                            } else {
                                ret = unsafe { OCSP_resp_find_status(
                                    br,
                                    id,
                                    &mut cert_status,
                                    &mut crl_reason,
                                    &mut rev,
                                    &mut thisupd,
                                    &mut nextupd,
                                ) };
                                (unsafe { OCSP_CERTID_free(id) });
                                if ret != 1 as i32 {
                                    (unsafe { Curl_failf(
                                        data,
                                        b"Could not find certificate ID in OCSP response\0"
                                            as *const u8
                                            as *const i8,
                                    ) });
                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                } else if (unsafe { OCSP_check_validity(
                                    thisupd,
                                    nextupd,
                                    300 as i64,
                                    -(1 as i64),
                                ) }) == 0
                                {
                                    (unsafe { Curl_failf(
                                        data,
                                        b"OCSP response has expired\0" as *const u8 as *const i8,
                                    ) });
                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                } else {
                                    (unsafe { Curl_infof(
                                        data,
                                        b"SSL certificate status: %s (%d)\0" as *const u8
                                            as *const i8,
                                        OCSP_cert_status_str(cert_status as i64),
                                        cert_status,
                                    ) });
                                    match cert_status {
                                        0 => {}
                                        1 => {
                                            current_block = 6359284123386842674;
                                            match current_block {
                                                1467979945751933765 => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                }
                                                _ => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                    (unsafe { Curl_failf (data , b"SSL certificate revocation reason: %s (%d)\0" as * const u8 as * const i8 , OCSP_crl_reason_str (crl_reason as i64) , crl_reason ,) }) ;
                                                }
                                            }
                                        }
                                        2 | _ => {
                                            current_block = 1467979945751933765;
                                            match current_block {
                                                1467979945751933765 => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                }
                                                _ => {
                                                    result = CURLE_SSL_INVALIDCERTSTATUS;
                                                    (unsafe { Curl_failf (data , b"SSL certificate revocation reason: %s (%d)\0" as * const u8 as * const i8 , OCSP_crl_reason_str (crl_reason as i64) , crl_reason ,) }) ;
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
    if !br.is_null() {
        (unsafe { OCSP_BASICRESP_free(br) });
    }
    (unsafe { OCSP_RESPONSE_free(rsp) });
    return result;
}
extern "C" fn ssl_msg_type(mut ssl_ver: i32, mut msg: i32) -> *const i8 {
    if ssl_ver == 0x3 as i32 {
        match msg {
            0 => return b"Hello request\0" as *const u8 as *const i8,
            1 => return b"Client hello\0" as *const u8 as *const i8,
            2 => return b"Server hello\0" as *const u8 as *const i8,
            4 => return b"Newsession Ticket\0" as *const u8 as *const i8,
            11 => return b"Certificate\0" as *const u8 as *const i8,
            12 => return b"Server key exchange\0" as *const u8 as *const i8,
            16 => return b"Client key exchange\0" as *const u8 as *const i8,
            13 => return b"Request CERT\0" as *const u8 as *const i8,
            14 => return b"Server finished\0" as *const u8 as *const i8,
            15 => return b"CERT verify\0" as *const u8 as *const i8,
            20 => return b"Finished\0" as *const u8 as *const i8,
            22 => return b"Certificate Status\0" as *const u8 as *const i8,
            8 => return b"Encrypted Extensions\0" as *const u8 as *const i8,
            23 => return b"Supplemental data\0" as *const u8 as *const i8,
            5 => return b"End of early data\0" as *const u8 as *const i8,
            24 => return b"Key update\0" as *const u8 as *const i8,
            67 => return b"Next protocol\0" as *const u8 as *const i8,
            254 => return b"Message hash\0" as *const u8 as *const i8,
            _ => {}
        }
    }
    return b"Unknown\0" as *const u8 as *const i8;
}
extern "C" fn tls_rt_type(mut type_0: i32) -> *const i8 {
    match type_0 {
        256 => return b"TLS header\0" as *const u8 as *const i8,
        20 => return b"TLS change cipher\0" as *const u8 as *const i8,
        21 => return b"TLS alert\0" as *const u8 as *const i8,
        22 => return b"TLS handshake\0" as *const u8 as *const i8,
        23 => return b"TLS app data\0" as *const u8 as *const i8,
        _ => return b"TLS Unknown\0" as *const u8 as *const i8,
    };
}
extern "C" fn ossl_trace(
    mut direction: i32,
    mut ssl_ver: i32,
    mut content_type: i32,
    mut buf: *const libc::c_void,
    mut len: size_t,
    mut _ssl: *mut SSL,
    mut userp: *mut libc::c_void,
) {
    let mut unknown: [i8; 32] = [0; 32];
    let mut verstr: *const i8 = 0 as *const i8;
    let mut conn: *mut connectdata = userp as *mut connectdata;
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(0 as i32 as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut data: *mut Curl_easy = unsafe { (*backend).logger };
    if conn.is_null()
        || data.is_null()
        || (unsafe { ((*data).set.fdebug).is_none() })
        || direction != 0 as i32 && direction != 1 as i32
    {
        return;
    }
    match ssl_ver {
        2 => {
            verstr = b"SSLv2\0" as *const u8 as *const i8;
        }
        768 => {
            verstr = b"SSLv3\0" as *const u8 as *const i8;
        }
        769 => {
            verstr = b"TLSv1.0\0" as *const u8 as *const i8;
        }
        770 => {
            verstr = b"TLSv1.1\0" as *const u8 as *const i8;
        }
        771 => {
            verstr = b"TLSv1.2\0" as *const u8 as *const i8;
        }
        772 => {
            verstr = b"TLSv1.3\0" as *const u8 as *const i8;
        }
        0 => {}
        _ => {
            (unsafe { curl_msnprintf(
                unknown.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 32]>() as u64,
                b"(%x)\0" as *const u8 as *const i8,
                ssl_ver,
            ) });
            verstr = unknown.as_mut_ptr();
        }
    }
    if ssl_ver != 0 && content_type != 0x101 as i32 {
        let mut msg_name: *const i8 = 0 as *const i8;
        let mut tls_rt_name: *const i8 = 0 as *const i8;
        let mut ssl_buf: [i8; 1024] = [0; 1024];
        let mut msg_type: i32 = 0;
        let mut txt_len: i32 = 0;
        ssl_ver >>= 8 as i32;
        if ssl_ver == 0x3 as i32 && content_type != 0 {
            tls_rt_name = tls_rt_type(content_type);
        } else {
            tls_rt_name = b"\0" as *const u8 as *const i8;
        }
        if content_type == 20 as i32 {
            msg_type = (unsafe { *(buf as *mut i8) }) as i32;
            msg_name = b"Change cipher spec\0" as *const u8 as *const i8;
        } else if content_type == 21 as i32 {
            msg_type = (((unsafe { *(buf as *mut i8).offset(0 as i32 as isize) }) as i32) << 8 as i32)
                + (unsafe { *(buf as *mut i8).offset(1 as i32 as isize) }) as i32;
            msg_name = unsafe { SSL_alert_desc_string_long(msg_type) };
        } else {
            msg_type = (unsafe { *(buf as *mut i8) }) as i32;
            msg_name = ssl_msg_type(ssl_ver, msg_type);
        }
        txt_len = unsafe { curl_msnprintf(
            ssl_buf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 1024]>() as u64,
            b"%s (%s), %s, %s (%d):\n\0" as *const u8 as *const i8,
            verstr,
            if direction != 0 {
                b"OUT\0" as *const u8 as *const i8
            } else {
                b"IN\0" as *const u8 as *const i8
            },
            tls_rt_name,
            msg_name,
            msg_type,
        ) };
        if 0 as i32 <= txt_len
            && (txt_len as u32 as u64) < ::std::mem::size_of::<[i8; 1024]>() as u64
        {
            (unsafe { Curl_debug(data, CURLINFO_TEXT, ssl_buf.as_mut_ptr(), txt_len as size_t) });
        }
    }
    (unsafe { Curl_debug(
        data,
        (if direction == 1 as i32 {
            CURLINFO_SSL_DATA_OUT as i32
        } else {
            CURLINFO_SSL_DATA_IN as i32
        }) as curl_infotype,
        buf as *mut i8,
        len,
    ) });
}
extern "C" fn select_next_protocol(
    mut out: *mut *mut u8,
    mut outlen: *mut u8,
    mut in_0: *const u8,
    mut inlen: u32,
    mut key: *const i8,
    mut keylen: u32,
) -> i32 {
    let mut i: u32 = 0;
    i = 0 as i32 as u32;
    while i.wrapping_add(keylen) <= inlen {
        if (unsafe { memcmp(
            &*in_0.offset(i.wrapping_add(1 as i32 as u32) as isize) as *const u8
                as *const libc::c_void,
            key as *const libc::c_void,
            keylen as u64,
        ) }) == 0 as i32
        {
            (unsafe { *out = &*in_0.offset(i.wrapping_add(1 as i32 as u32) as isize) as *const u8 as *mut u8 });
            (unsafe { *outlen = *in_0.offset(i as isize) });
            return 0 as i32;
        }
        i = i.wrapping_add(((unsafe { *in_0.offset(i as isize) }) as i32 + 1 as i32) as u32);
    }
    return -(1 as i32);
}
extern "C" fn select_next_proto_cb(
    mut _ssl: *mut SSL,
    mut out: *mut *mut u8,
    mut outlen: *mut u8,
    mut in_0: *const u8,
    mut inlen: u32,
    mut arg: *mut libc::c_void,
) -> i32 {
    let mut data: *mut Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    if (unsafe { (*data).state.httpwant }) as i32 >= CURL_HTTP_VERSION_2_0 as i32
        && select_next_protocol(
            out,
            outlen,
            in_0,
            inlen,
            b"h2\0" as *const u8 as *const i8,
            2 as i32 as u32,
        ) == 0
    {
        (unsafe { Curl_infof(
            data,
            b"NPN, negotiated HTTP2 (%s)\0" as *const u8 as *const i8,
            b"h2\0" as *const u8 as *const i8,
        ) });
        (unsafe { (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32 });
        return 0 as i32;
    }
    if select_next_protocol(
        out,
        outlen,
        in_0,
        inlen,
        b"http/1.1\0" as *const u8 as *const i8,
        8 as i32 as u32,
    ) == 0
    {
        (unsafe { Curl_infof(data, b"NPN, negotiated HTTP1.1\0" as *const u8 as *const i8) });
        (unsafe { (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32 });
        return 0 as i32;
    }
    (unsafe { Curl_infof(
        data,
        b"NPN, no overlap, use HTTP1.1\0" as *const u8 as *const i8,
    ) });
    (unsafe { *out = b"http/1.1\0" as *const u8 as *const i8 as *mut u8 });
    (unsafe { *outlen = 8 as i32 as u8 });
    (unsafe { (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32 });
    return 0 as i32;
}
extern "C" fn set_ssl_version_min_max(
    mut ctx: *mut SSL_CTX,
    mut conn: *mut connectdata,
) -> CURLcode {
    let mut curl_ssl_version_min: i64 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.version }
    } else {
        unsafe { (*conn).ssl_config.version }
    };
    let mut curl_ssl_version_max: i64 = 0;
    let mut ossl_ssl_version_min: i64 = 0 as i32 as i64;
    let mut ossl_ssl_version_max: i64 = 0 as i32 as i64;
    match curl_ssl_version_min {
        1 | 4 => {
            ossl_ssl_version_min = 0x301 as i32 as i64;
        }
        5 => {
            ossl_ssl_version_min = 0x302 as i32 as i64;
        }
        6 => {
            ossl_ssl_version_min = 0x303 as i32 as i64;
        }
        7 => {
            ossl_ssl_version_min = 0x304 as i32 as i64;
        }
        _ => {}
    }
    if curl_ssl_version_min != CURL_SSLVERSION_DEFAULT as i32 as i64 {
        if (unsafe { SSL_CTX_ctrl(
            ctx,
            123 as i32,
            ossl_ssl_version_min,
            0 as *mut libc::c_void,
        ) }) == 0
        {
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    curl_ssl_version_max = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.version_max }
    } else {
        unsafe { (*conn).ssl_config.version_max }
    };
    let mut current_block_15: u64;
    match curl_ssl_version_max {
        262144 => {
            ossl_ssl_version_max = 0x301 as i32 as i64;
            current_block_15 = 18386322304582297246;
        }
        327680 => {
            ossl_ssl_version_max = 0x302 as i32 as i64;
            current_block_15 = 18386322304582297246;
        }
        393216 => {
            ossl_ssl_version_max = 0x303 as i32 as i64;
            current_block_15 = 18386322304582297246;
        }
        458752 => {
            ossl_ssl_version_max = 0x304 as i32 as i64;
            current_block_15 = 18386322304582297246;
        }
        0 => {
            current_block_15 = 15928048810361310416;
        }
        65536 | _ => {
            current_block_15 = 15928048810361310416;
        }
    }
    match current_block_15 {
        15928048810361310416 => {
            ossl_ssl_version_max = 0 as i32 as i64;
        }
        _ => {}
    }
    if (unsafe { SSL_CTX_ctrl(
        ctx,
        124 as i32,
        ossl_ssl_version_max,
        0 as *mut libc::c_void,
    ) }) == 0
    {
        return CURLE_SSL_CONNECT_ERROR;
    }
    return CURLE_OK;
}
extern "C" fn ossl_new_session_cb(mut ssl: *mut SSL, mut ssl_sessionid: *mut SSL_SESSION) -> i32 {
    let mut res: i32 = 0 as i32;
    let mut conn: *mut connectdata = 0 as *mut connectdata;
    let mut data: *mut Curl_easy = 0 as *mut Curl_easy;
    let mut sockindex: i32 = 0;
    let mut sockindex_ptr: *mut curl_socket_t = 0 as *mut curl_socket_t;
    let mut data_idx: i32 = ossl_get_ssl_data_index();
    let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
    let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
    let mut proxy_idx: i32 = ossl_get_proxy_index();
    let mut isproxy: bool = false;
    if data_idx < 0 as i32
        || connectdata_idx < 0 as i32
        || sockindex_idx < 0 as i32
        || proxy_idx < 0 as i32
    {
        return 0 as i32;
    }
    conn = (unsafe { SSL_get_ex_data(ssl, connectdata_idx) }) as *mut connectdata;
    if conn.is_null() {
        return 0 as i32;
    }
    data = (unsafe { SSL_get_ex_data(ssl, data_idx) }) as *mut Curl_easy;
    sockindex_ptr = (unsafe { SSL_get_ex_data(ssl, sockindex_idx) }) as *mut curl_socket_t;
    sockindex = (unsafe { sockindex_ptr.offset_from(((*conn).sock).as_mut_ptr()) }) as i64 as i32;
    isproxy = if !(unsafe { SSL_get_ex_data(ssl, proxy_idx) }).is_null() {
        1 as i32
    } else {
        0 as i32
    } != 0;
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*data).set.proxy_ssl.primary).sessionid() }) as i32
    } else {
        (unsafe { ((*data).set.ssl.primary).sessionid() }) as i32
    } != 0
    {
        let mut incache: bool = false;
        let mut old_ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
        (unsafe { Curl_ssl_sessionid_lock(data) });
        if isproxy {
            incache = 0 as i32 != 0;
        } else {
            incache = !(unsafe { Curl_ssl_getsessionid(
                data,
                conn,
                isproxy,
                &mut old_ssl_sessionid,
                0 as *mut size_t,
                sockindex,
            ) });
        }
        if incache {
            if old_ssl_sessionid != ssl_sessionid as *mut libc::c_void {
                (unsafe { Curl_infof(
                    data,
                    b"old SSL session ID is stale, removing\0" as *const u8 as *const i8,
                ) });
                (unsafe { Curl_ssl_delsessionid(data, old_ssl_sessionid) });
                incache = 0 as i32 != 0;
            }
        }
        if !incache {
            if (unsafe { Curl_ssl_addsessionid(
                data,
                conn,
                isproxy,
                ssl_sessionid as *mut libc::c_void,
                0 as i32 as size_t,
                sockindex,
            ) }) as u64
                == 0
            {
                res = 1 as i32;
            } else {
                (unsafe { Curl_failf(
                    data,
                    b"failed to store ssl session\0" as *const u8 as *const i8,
                ) });
            }
        }
        (unsafe { Curl_ssl_sessionid_unlock(data) });
    }
    return res;
}
extern "C" fn load_cacert_from_memory(
    mut ctx: *mut SSL_CTX,
    mut ca_info_blob: *const curl_blob,
) -> CURLcode {
    let mut cbio: *mut BIO = 0 as *mut BIO;
    let mut inf: *mut stack_st_X509_INFO = 0 as *mut stack_st_X509_INFO;
    let mut i: i32 = 0;
    let mut count: i32 = 0 as i32;
    let mut cts: *mut X509_STORE = 0 as *mut X509_STORE;
    let mut itmp: *mut X509_INFO = 0 as *mut X509_INFO;
    if (unsafe { (*ca_info_blob).len }) > 2147483647 as i32 as size_t {
        return CURLE_SSL_CACERT_BADFILE;
    }
    cts = unsafe { SSL_CTX_get_cert_store(ctx) };
    if cts.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    cbio = unsafe { BIO_new_mem_buf((*ca_info_blob).data, (*ca_info_blob).len as i32) };
    if cbio.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    inf = unsafe { PEM_X509_INFO_read_bio(
        cbio,
        0 as *mut stack_st_X509_INFO,
        None,
        0 as *mut libc::c_void,
    ) };
    if inf.is_null() {
        (unsafe { BIO_free(cbio) });
        return CURLE_SSL_CACERT_BADFILE;
    }
    i = 0 as i32;
    while i < sk_X509_INFO_num(inf) {
        itmp = sk_X509_INFO_value(inf, i);
        if !(unsafe { (*itmp).x509 }).is_null() {
            if (unsafe { X509_STORE_add_cert(cts, (*itmp).x509) }) != 0 {
                count += 1;
            } else {
                count = 0 as i32;
                break;
            }
        }
        if !(unsafe { (*itmp).crl }).is_null() {
            if (unsafe { X509_STORE_add_crl(cts, (*itmp).crl) }) != 0 {
                count += 1;
            } else {
                count = 0 as i32;
                break;
            }
        }
        i += 1;
    }
    sk_X509_INFO_pop_free(
        inf,
        Some(X509_INFO_free as unsafe extern "C" fn(*mut X509_INFO) -> ()),
    );
    (unsafe { BIO_free(cbio) });
    return (if count > 0 as i32 {
        CURLE_OK as i32
    } else {
        CURLE_SSL_CACERT_BADFILE as i32
    }) as CURLcode;
}
extern "C" fn ossl_connect_step1(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut ciphers: *mut i8 = 0 as *mut i8;
    let mut req_method: *const SSL_METHOD = 0 as *const SSL_METHOD;
    let mut lookup: *mut X509_LOOKUP = 0 as *mut X509_LOOKUP;
    let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut ctx_options: ctx_option_t = 0 as i32 as ctx_option_t;
    let mut ssl_sessionid: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut sni: bool = false;
    let hostname: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).http_proxy.host.name }
    } else {
        unsafe { (*conn).host.name }
    };
    let mut addr: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_10 {
            __u6_addr8: [0; 16],
        },
    };
    let ssl_version: i64 = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.version }
    } else {
        unsafe { (*conn).ssl_config.version }
    };
    let ssl_authtype: CURL_TLSAUTH = (if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { (*data).set.proxy_ssl.authtype }) as u32
    } else {
        (unsafe { (*data).set.ssl.authtype }) as u32
    }) as CURL_TLSAUTH;
    let ssl_cert: *mut i8 = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*data).set.proxy_ssl.primary.clientcert }
    } else {
        unsafe { (*data).set.ssl.primary.clientcert }
    };
    let mut ssl_cert_blob: *const curl_blob = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*data).set.proxy_ssl.primary.cert_blob }
    } else {
        unsafe { (*data).set.ssl.primary.cert_blob }
    };
    let mut ca_info_blob: *const curl_blob = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.ca_info_blob }
    } else {
        unsafe { (*conn).ssl_config.ca_info_blob }
    };
    let ssl_cert_type: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*data).set.proxy_ssl.cert_type }
    } else {
        unsafe { (*data).set.ssl.cert_type }
    };
    let ssl_cafile: *const i8 = if !ca_info_blob.is_null() {
        0 as *mut i8
    } else if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.CAfile }
    } else {
        unsafe { (*conn).ssl_config.CAfile }
    };
    let ssl_capath: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.CApath }
    } else {
        unsafe { (*conn).ssl_config.CApath }
    };
    let verifypeer: bool = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*conn).proxy_ssl_config).verifypeer() }) as i32
    } else {
        (unsafe { ((*conn).ssl_config).verifypeer() }) as i32
    } != 0;
    let ssl_crlfile: *const i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*data).set.proxy_ssl.CRLfile }
    } else {
        unsafe { (*data).set.ssl.CRLfile }
    };
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    let mut imported_native_ca: bool = 0 as i32 != 0;
    result = ossl_seed(data);
    if result as u64 != 0 {
        return result;
    }
    *if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { &mut (*data).set.proxy_ssl.certverifyresult }
    } else {
        unsafe { &mut (*data).set.ssl.certverifyresult }
    } = (0 as i32 == 0) as i32 as i64;
    match ssl_version {
        0 | 1 | 4 | 5 | 6 | 7 => {
            req_method = unsafe { TLS_client_method() };
            sni = 1 as i32 != 0;
        }
        2 => {
            (unsafe { Curl_failf(data, b"No SSLv2 support\0" as *const u8 as *const i8) });
            return CURLE_NOT_BUILT_IN;
        }
        3 => {
            (unsafe { Curl_failf(data, b"No SSLv3 support\0" as *const u8 as *const i8) });
            return CURLE_NOT_BUILT_IN;
        }
        _ => {
            (unsafe { Curl_failf(
                data,
                b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8 as *const i8,
            ) });
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    let fresh8 = unsafe { &mut ((*backend).ctx) };
    *fresh8 = unsafe { SSL_CTX_new(req_method) };
    if (unsafe { (*backend).ctx }).is_null() {
        (unsafe { Curl_failf(
            data,
            b"SSL: couldn't create a context: %s\0" as *const u8 as *const i8,
            ossl_strerror(
                ERR_peek_error(),
                error_buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { SSL_CTX_ctrl(
        (*backend).ctx,
        33 as i32,
        0x10 as u32 as i64,
        0 as *mut libc::c_void,
    ) });
    if (unsafe { ((*data).set.fdebug).is_some() }) && (unsafe { ((*data).set).verbose() }) as i32 != 0 {
        (unsafe { SSL_CTX_set_msg_callback(
            (*backend).ctx,
            Some(
                ossl_trace
                    as unsafe extern "C" fn(
                        i32,
                        i32,
                        i32,
                        *const libc::c_void,
                        size_t,
                        *mut SSL,
                        *mut libc::c_void,
                    ) -> (),
            ),
        ) });
        (unsafe { SSL_CTX_ctrl(
            (*backend).ctx,
            16 as i32,
            0 as i32 as i64,
            conn as *mut libc::c_void,
        ) });
        let fresh9 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
        *fresh9 = data;
    }
    ctx_options =
        (0x80000000 as u32 | 0x800 as u32 | 0x4 as u32 | 0x10 as u32 | 0x40 as u32) as ctx_option_t;
    ctx_options |= 0x4000 as u32 as i64;
    ctx_options |= 0x20000 as u32 as i64;
    ctx_options &= !(0 as i32) as i64;
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*data).set.proxy_ssl).enable_beast() }) as i32
    } else {
        (unsafe { ((*data).set.ssl).enable_beast() }) as i32
    } == 0
    {
        ctx_options &= !(0x800 as u32) as i64;
    }
    let mut current_block_41: u64;
    match ssl_version {
        2 | 3 => return CURLE_NOT_BUILT_IN,
        0 | 1 => {
            current_block_41 = 569580139798018676;
        }
        4 => {
            current_block_41 = 569580139798018676;
        }
        5 => {
            current_block_41 = 12764152861449555441;
        }
        6 | 7 => {
            current_block_41 = 5591280506610124101;
        }
        _ => {
            (unsafe { Curl_failf(
                data,
                b"Unrecognized parameter passed via CURLOPT_SSLVERSION\0" as *const u8 as *const i8,
            ) });
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    match current_block_41 {
        569580139798018676 => {
            current_block_41 = 12764152861449555441;
        }
        _ => {}
    }
    match current_block_41 {
        12764152861449555441 => {}
        _ => {}
    }
    ctx_options |= 0 as i32 as i64;
    ctx_options |= 0x2000000 as u32 as i64;
    result = set_ssl_version_min_max(unsafe { (*backend).ctx }, conn);
    if result as u32 != CURLE_OK as i32 as u32 {
        return result;
    }
    (unsafe { SSL_CTX_set_options((*backend).ctx, ctx_options as u64) });
    if (unsafe { ((*conn).bits).tls_enable_npn() }) != 0 {
        (unsafe { SSL_CTX_set_next_proto_select_cb(
            (*backend).ctx,
            Some(
                select_next_proto_cb
                    as unsafe extern "C" fn(
                        *mut SSL,
                        *mut *mut u8,
                        *mut u8,
                        *const u8,
                        u32,
                        *mut libc::c_void,
                    ) -> i32,
            ),
            data as *mut libc::c_void,
        ) });
    }
    if (unsafe { ((*conn).bits).tls_enable_alpn() }) != 0 {
        let mut cur: i32 = 0 as i32;
        let mut protocols: [u8; 128] = [0; 128];
        if (unsafe { (*data).state.httpwant }) as i32 >= CURL_HTTP_VERSION_2_0 as i32
            && (!(CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                && ssl_connection_complete as i32 as u32
                    != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state }) as u32)
                || (unsafe { ((*conn).bits).tunnel_proxy() }) == 0)
        {
            let fresh10 = cur;
            cur = cur + 1;
            protocols[fresh10 as usize] = 2 as i32 as u8;
            (unsafe { memcpy(
                &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8 as *mut libc::c_void,
                b"h2\0" as *const u8 as *const i8 as *const libc::c_void,
                2 as i32 as u64,
            ) });
            cur += 2 as i32;
            (unsafe { Curl_infof(
                data,
                b"ALPN, offering %s\0" as *const u8 as *const i8,
                b"h2\0" as *const u8 as *const i8,
            ) });
        }
        let fresh11 = cur;
        cur = cur + 1;
        protocols[fresh11 as usize] = 8 as i32 as u8;
        (unsafe { memcpy(
            &mut *protocols.as_mut_ptr().offset(cur as isize) as *mut u8 as *mut libc::c_void,
            b"http/1.1\0" as *const u8 as *const i8 as *const libc::c_void,
            8 as i32 as u64,
        ) });
        cur += 8 as i32;
        (unsafe { Curl_infof(
            data,
            b"ALPN, offering %s\0" as *const u8 as *const i8,
            b"http/1.1\0" as *const u8 as *const i8,
        ) });
        if (unsafe { SSL_CTX_set_alpn_protos((*backend).ctx, protocols.as_mut_ptr(), cur as u32) }) != 0 {
            (unsafe { Curl_failf(data, b"Error setting ALPN\0" as *const u8 as *const i8) });
            return CURLE_SSL_CONNECT_ERROR;
        }
    }
    if !ssl_cert.is_null() || !ssl_cert_blob.is_null() || !ssl_cert_type.is_null() {
        if result as u64 == 0
            && cert_stuff(
                data,
                unsafe { (*backend).ctx },
                ssl_cert,
                ssl_cert_blob,
                ssl_cert_type,
                if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*data).set.proxy_ssl.key }
                } else {
                    unsafe { (*data).set.ssl.key }
                },
                if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*data).set.proxy_ssl.key_blob }
                } else {
                    unsafe { (*data).set.ssl.key_blob }
                },
                if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*data).set.proxy_ssl.key_type }
                } else {
                    unsafe { (*data).set.ssl.key_type }
                },
                if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*data).set.proxy_ssl.key_passwd }
                } else {
                    unsafe { (*data).set.ssl.key_passwd }
                },
            ) == 0
        {
            result = CURLE_SSL_CERTPROBLEM;
        }
        if result as u64 != 0 {
            return result;
        }
    }
    ciphers = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.cipher_list }
    } else {
        unsafe { (*conn).ssl_config.cipher_list }
    };
    if ciphers.is_null() {
        ciphers = 0 as *mut libc::c_void as *mut i8;
    }
    if !ciphers.is_null() {
        if (unsafe { SSL_CTX_set_cipher_list((*backend).ctx, ciphers) }) == 0 {
            (unsafe { Curl_failf(
                data,
                b"failed setting cipher list: %s\0" as *const u8 as *const i8,
                ciphers,
            ) });
            return CURLE_SSL_CIPHER;
        }
        (unsafe { Curl_infof(
            data,
            b"Cipher selection: %s\0" as *const u8 as *const i8,
            ciphers,
        ) });
    }
    let mut ciphers13: *mut i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.cipher_list13 }
    } else {
        unsafe { (*conn).ssl_config.cipher_list13 }
    };
    if !ciphers13.is_null() {
        if (unsafe { SSL_CTX_set_ciphersuites((*backend).ctx, ciphers13) }) == 0 {
            (unsafe { Curl_failf(
                data,
                b"failed setting TLS 1.3 cipher suite: %s\0" as *const u8 as *const i8,
                ciphers13,
            ) });
            return CURLE_SSL_CIPHER;
        }
        (unsafe { Curl_infof(
            data,
            b"TLS 1.3 cipher selection: %s\0" as *const u8 as *const i8,
            ciphers13,
        ) });
    }
    (unsafe { SSL_CTX_set_post_handshake_auth((*backend).ctx, 1 as i32) });
    let mut curves: *mut i8 = if CURLPROXY_HTTPS as i32 as u32
        == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*conn).proxy_ssl_config.curves }
    } else {
        unsafe { (*conn).ssl_config.curves }
    };
    if !curves.is_null() {
        if (unsafe { SSL_CTX_ctrl(
            (*backend).ctx,
            92 as i32,
            0 as i32 as i64,
            curves as *mut libc::c_void,
        ) }) == 0
        {
            (unsafe { Curl_failf(
                data,
                b"failed setting curves list: '%s'\0" as *const u8 as *const i8,
                curves,
            ) });
            return CURLE_SSL_CIPHER;
        }
    }
    if ssl_authtype as u32 == CURL_TLSAUTH_SRP as i32 as u32 {
        let ssl_username: *mut i8 = if CURLPROXY_HTTPS as i32 as u32
            == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            unsafe { (*data).set.proxy_ssl.username }
        } else {
            unsafe { (*data).set.ssl.username }
        };
        (unsafe { Curl_infof(
            data,
            b"Using TLS-SRP username: %s\0" as *const u8 as *const i8,
            ssl_username,
        ) });
        if (unsafe { SSL_CTX_set_srp_username((*backend).ctx, ssl_username) }) == 0 {
            (unsafe { Curl_failf(
                data,
                b"Unable to set SRP user name\0" as *const u8 as *const i8,
            ) });
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        if (unsafe { SSL_CTX_set_srp_password(
            (*backend).ctx,
            if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                && ssl_connection_complete as i32 as u32
                    != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state as u32
            {
                (*data).set.proxy_ssl.password
            } else {
                (*data).set.ssl.password
            },
        ) }) == 0
        {
            (unsafe { Curl_failf(
                data,
                b"failed setting SRP password\0" as *const u8 as *const i8,
            ) });
            return CURLE_BAD_FUNCTION_ARGUMENT;
        }
        if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            unsafe { (*conn).proxy_ssl_config.cipher_list }
        } else {
            unsafe { (*conn).ssl_config.cipher_list }
        }
        .is_null()
        {
            (unsafe { Curl_infof(data, b"Setting cipher list SRP\0" as *const u8 as *const i8) });
            if (unsafe { SSL_CTX_set_cipher_list((*backend).ctx, b"SRP\0" as *const u8 as *const i8) }) == 0 {
                (unsafe { Curl_failf(
                    data,
                    b"failed setting SRP cipher list\0" as *const u8 as *const i8,
                ) });
                return CURLE_SSL_CIPHER;
            }
        }
    }
    if !ca_info_blob.is_null() {
        result = load_cacert_from_memory(unsafe { (*backend).ctx }, ca_info_blob);
        if result as u64 != 0 {
            if result as u32 == CURLE_OUT_OF_MEMORY as i32 as u32
                || verifypeer as i32 != 0 && !imported_native_ca
            {
                (unsafe { Curl_failf(
                    data,
                    b"error importing CA certificate blob\0" as *const u8 as *const i8,
                ) });
                return result;
            }
            (unsafe { Curl_infof(
                data,
                b"error importing CA certificate blob, continuing anyway\0" as *const u8
                    as *const i8,
            ) });
        }
    }
    if !ssl_cafile.is_null() || !ssl_capath.is_null() {
        if (unsafe { SSL_CTX_load_verify_locations((*backend).ctx, ssl_cafile, ssl_capath) }) == 0 {
            if verifypeer as i32 != 0 && !imported_native_ca {
                (unsafe { Curl_failf(
                    data,
                    b"error setting certificate verify locations:  CAfile: %s CApath: %s\0"
                        as *const u8 as *const i8,
                    if !ssl_cafile.is_null() {
                        ssl_cafile
                    } else {
                        b"none\0" as *const u8 as *const i8
                    },
                    if !ssl_capath.is_null() {
                        ssl_capath
                    } else {
                        b"none\0" as *const u8 as *const i8
                    },
                ) });
                return CURLE_SSL_CACERT_BADFILE;
            }
            (unsafe { Curl_infof(
                data,
                b"error setting certificate verify locations, continuing anyway:\0" as *const u8
                    as *const i8,
            ) });
        } else {
            (unsafe { Curl_infof(
                data,
                b"successfully set certificate verify locations:\0" as *const u8 as *const i8,
            ) });
        }
        (unsafe { Curl_infof(
            data,
            b" CAfile: %s\0" as *const u8 as *const i8,
            if !ssl_cafile.is_null() {
                ssl_cafile
            } else {
                b"none\0" as *const u8 as *const i8
            },
        ) });
        (unsafe { Curl_infof(
            data,
            b" CApath: %s\0" as *const u8 as *const i8,
            if !ssl_capath.is_null() {
                ssl_capath
            } else {
                b"none\0" as *const u8 as *const i8
            },
        ) });
    }
    if !ssl_crlfile.is_null() {
        lookup = unsafe { X509_STORE_add_lookup(SSL_CTX_get_cert_store((*backend).ctx), X509_LOOKUP_file()) };
        if lookup.is_null() || (unsafe { X509_load_crl_file(lookup, ssl_crlfile, 1 as i32) }) == 0 {
            (unsafe { Curl_failf(
                data,
                b"error loading CRL file: %s\0" as *const u8 as *const i8,
                ssl_crlfile,
            ) });
            return CURLE_SSL_CRL_BADFILE;
        }
        (unsafe { Curl_infof(
            data,
            b"successfully loaded CRL file:\0" as *const u8 as *const i8,
        ) });
        (unsafe { X509_STORE_set_flags(
            SSL_CTX_get_cert_store((*backend).ctx),
            (0x4 as i32 | 0x8 as i32) as u64,
        ) });
        (unsafe { Curl_infof(
            data,
            b"  CRLfile: %s\0" as *const u8 as *const i8,
            ssl_crlfile,
        ) });
    }
    if verifypeer {
        (unsafe { X509_STORE_set_flags(SSL_CTX_get_cert_store((*backend).ctx), 0x8000 as i32 as u64) });
        if (if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            (unsafe { ((*data).set.proxy_ssl).no_partialchain() }) as i32
        } else {
            (unsafe { ((*data).set.ssl).no_partialchain() }) as i32
        }) == 0
            && ssl_crlfile.is_null()
        {
            (unsafe { X509_STORE_set_flags(
                SSL_CTX_get_cert_store((*backend).ctx),
                0x80000 as i32 as u64,
            ) });
        }
    }
    (unsafe { SSL_CTX_set_verify(
        (*backend).ctx,
        if verifypeer as i32 != 0 {
            0x1 as i32
        } else {
            0 as i32
        },
        None,
    ) });
    if unsafe { Curl_tls_keylog_enabled() } {
        (unsafe { SSL_CTX_set_keylog_callback(
            (*backend).ctx,
            Some(ossl_keylog_callback as unsafe extern "C" fn(*const SSL, *const i8) -> ()),
        ) });
    }
    (unsafe { SSL_CTX_ctrl(
        (*backend).ctx,
        44 as i32,
        (0x1 as i32 | (0x100 as i32 | 0x200 as i32)) as i64,
        0 as *mut libc::c_void,
    ) });
    (unsafe { SSL_CTX_sess_set_new_cb(
        (*backend).ctx,
        Some(ossl_new_session_cb as unsafe extern "C" fn(*mut SSL, *mut SSL_SESSION) -> i32),
    ) });
    if unsafe { ((*data).set.ssl.fsslctx).is_some() } {
        (unsafe { Curl_set_in_callback(data, 1 as i32 != 0) });
        result = unsafe { (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
            .expect("non-null function pointer")(
            data,
            (*backend).ctx as *mut libc::c_void,
            (*data).set.ssl.fsslctxp,
        ) };
        (unsafe { Curl_set_in_callback(data, 0 as i32 != 0) });
        if result as u64 != 0 {
            (unsafe { Curl_failf(
                data,
                b"error signaled by ssl ctx callback\0" as *const u8 as *const i8,
            ) });
            return result;
        }
    }
    if !(unsafe { (*backend).handle }).is_null() {
        (unsafe { SSL_free((*backend).handle) });
    }
    let fresh12 = unsafe { &mut ((*backend).handle) };
    *fresh12 = unsafe { SSL_new((*backend).ctx) };
    if (unsafe { (*backend).handle }).is_null() {
        (unsafe { Curl_failf(
            data,
            b"SSL: couldn't create a context (handle)!\0" as *const u8 as *const i8,
        ) });
        return CURLE_OUT_OF_MEMORY;
    }
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*conn).proxy_ssl_config).verifystatus() }) as i32
    } else {
        (unsafe { ((*conn).ssl_config).verifystatus() }) as i32
    } != 0
    {
        (unsafe { SSL_ctrl(
            (*backend).handle,
            65 as i32,
            1 as i32 as i64,
            0 as *mut libc::c_void,
        ) });
    }
    (unsafe { SSL_set_connect_state((*backend).handle) });
    let fresh13 = unsafe { &mut ((*backend).server_cert) };
    *fresh13 = 0 as *mut X509;
    if 0 as i32
        == (unsafe { inet_pton(
            2 as i32,
            hostname,
            &mut addr as *mut in6_addr as *mut libc::c_void,
        ) })
        && 0 as i32
            == (unsafe { inet_pton(
                10 as i32,
                hostname,
                &mut addr as *mut in6_addr as *mut libc::c_void,
            ) })
        && sni as i32 != 0
    {
        let mut nlen: size_t = unsafe { strlen(hostname) };
        if nlen as i64 >= (unsafe { (*data).set.buffer_size }) {
            return CURLE_SSL_CONNECT_ERROR;
        }
        (unsafe { Curl_strntolower((*data).state.buffer, hostname, nlen) });
        (unsafe { *((*data).state.buffer).offset(nlen as isize) = 0 as i32 as i8 });
        if (unsafe { SSL_ctrl(
            (*backend).handle,
            55 as i32,
            0 as i32 as i64,
            (*data).state.buffer as *mut libc::c_void,
        ) }) == 0
        {
            (unsafe { Curl_infof(
                data,
                b"WARNING: failed to configure server name indication (SNI) TLS extension\0"
                    as *const u8 as *const i8,
            ) });
        }
    }
    ossl_associate_connection(data, conn, sockindex);
    (unsafe { Curl_ssl_sessionid_lock(data) });
    if !(unsafe { Curl_ssl_getsessionid(
        data,
        conn,
        if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as i32 as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            1 as i32
        } else {
            0 as i32
        } != 0,
        &mut ssl_sessionid,
        0 as *mut size_t,
        sockindex,
    ) }) {
        if (unsafe { SSL_set_session((*backend).handle, ssl_sessionid as *mut SSL_SESSION) }) == 0 {
            (unsafe { Curl_ssl_sessionid_unlock(data) });
            (unsafe { Curl_failf(
                data,
                b"SSL: SSL_set_session failed: %s\0" as *const u8 as *const i8,
                ossl_strerror(
                    ERR_get_error(),
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                ),
            ) });
            return CURLE_SSL_CONNECT_ERROR;
        }
        (unsafe { Curl_infof(data, b"SSL re-using session ID\0" as *const u8 as *const i8) });
    }
    (unsafe { Curl_ssl_sessionid_unlock(data) });
    if (unsafe { ((*conn).proxy_ssl[sockindex as usize]).use_0() }) != 0 {
        let bio: *mut BIO = unsafe { BIO_new(BIO_f_ssl()) };
        let mut handle: *mut SSL = unsafe { (*(*conn).proxy_ssl[sockindex as usize].backend).handle };
        (unsafe { BIO_ctrl(
            bio,
            109 as i32,
            0 as i32 as i64,
            handle as *mut i8 as *mut libc::c_void,
        ) });
        (unsafe { SSL_set_bio((*backend).handle, bio, bio) });
    } else if (unsafe { SSL_set_fd((*backend).handle, sockfd) }) == 0 {
        (unsafe { Curl_failf(
            data,
            b"SSL: SSL_set_fd failed: %s\0" as *const u8 as *const i8,
            ossl_strerror(
                ERR_get_error(),
                error_buffer.as_mut_ptr(),
                ::std::mem::size_of::<[i8; 256]>() as u64,
            ),
        ) });
        return CURLE_SSL_CONNECT_ERROR;
    }
    (unsafe { (*connssl).connecting_state = ssl_connect_2 });
    return CURLE_OK;
}
extern "C" fn ossl_connect_step2(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut err: i32 = 0;
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    (unsafe { ERR_clear_error() });
    err = unsafe { SSL_connect((*backend).handle) };
    if 1 as i32 != err {
        let mut detail: i32 = unsafe { SSL_get_error((*backend).handle, err) };
        if 2 as i32 == detail {
            (unsafe { (*connssl).connecting_state = ssl_connect_2_reading });
            return CURLE_OK;
        }
        if 3 as i32 == detail {
            (unsafe { (*connssl).connecting_state = ssl_connect_2_writing });
            return CURLE_OK;
        }
        if 9 as i32 == detail {
            (unsafe { (*connssl).connecting_state = ssl_connect_2 });
            return CURLE_OK;
        } else {
            let mut errdetail: u64 = 0;
            let mut error_buffer : [i8 ; 256] = * (unsafe { :: std :: mem :: transmute :: < & [u8 ; 256] , & mut [i8 ; 256] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
            let mut result: CURLcode = CURLE_OK;
            let mut lerr: i64 = 0;
            let mut lib: i32 = 0;
            let mut reason: i32 = 0;
            (unsafe { (*connssl).connecting_state = ssl_connect_2 });
            errdetail = unsafe { ERR_get_error() };
            lib = (errdetail >> 24 as i64 & 0xff as i64 as u64) as i32;
            reason = (errdetail & 0xfff as i64 as u64) as i32;
            if lib == 20 as i32 && (reason == 134 as i32 || reason == 1045 as i32) {
                result = CURLE_PEER_FAILED_VERIFICATION;
                lerr = unsafe { SSL_get_verify_result((*backend).handle) };
                if lerr != 0 as i32 as i64 {
                    *if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                        && ssl_connection_complete as i32 as u32
                            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state }) as u32
                    {
                        unsafe { &mut (*data).set.proxy_ssl.certverifyresult }
                    } else {
                        unsafe { &mut (*data).set.ssl.certverifyresult }
                    } = lerr;
                    (unsafe { curl_msnprintf(
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                        b"SSL certificate problem: %s\0" as *const u8 as *const i8,
                        X509_verify_cert_error_string(lerr),
                    ) });
                } else {
                    (unsafe { strcpy(
                        error_buffer.as_mut_ptr(),
                        b"SSL certificate verification failed\0" as *const u8 as *const i8,
                    ) });
                }
            } else if lib == 20 as i32 && reason == 1116 as i32 {
                result = CURLE_SSL_CLIENTCERT;
                ossl_strerror(
                    errdetail,
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                );
            } else {
                result = CURLE_SSL_CONNECT_ERROR;
                ossl_strerror(
                    errdetail,
                    error_buffer.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 256]>() as u64,
                );
            }
            if CURLE_SSL_CONNECT_ERROR as i32 as u32 == result as u32
                && errdetail == 0 as i32 as u64
            {
                let hostname: *const i8 = if CURLPROXY_HTTPS as i32 as u32
                    == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*conn).http_proxy.host.name }
                } else {
                    unsafe { (*conn).host.name }
                };
                let port: i64 = (if CURLPROXY_HTTPS as i32 as u32
                    == (unsafe { (*conn).http_proxy.proxytype }) as u32
                    && ssl_connection_complete as i32 as u32
                        != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state }) as u32
                {
                    unsafe { (*conn).port }
                } else {
                    unsafe { (*conn).remote_port }
                }) as i64;
                let mut extramsg : [i8 ; 80] = * (unsafe { :: std :: mem :: transmute :: < & [u8 ; 80] , & mut [i8 ; 80] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
                let mut sockerr: i32 = unsafe { *__errno_location() };
                if sockerr != 0 && detail == 5 as i32 {
                    (unsafe { Curl_strerror(
                        sockerr,
                        extramsg.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 80]>() as u64,
                    ) });
                }
                (unsafe { Curl_failf(
                    data,
                    b"OpenSSL SSL_connect: %s in connection to %s:%ld \0" as *const u8 as *const i8,
                    if extramsg[0 as i32 as usize] as i32 != 0 {
                        extramsg.as_mut_ptr() as *const i8
                    } else {
                        SSL_ERROR_to_str(detail)
                    },
                    hostname,
                    port,
                ) });
                return result;
            }
            (unsafe { Curl_failf(
                data,
                b"%s\0" as *const u8 as *const i8,
                error_buffer.as_mut_ptr(),
            ) });
            return result;
        }
    } else {
        (unsafe { (*connssl).connecting_state = ssl_connect_3 });
        (unsafe { Curl_infof(
            data,
            b"SSL connection using %s / %s\0" as *const u8 as *const i8,
            SSL_get_version((*backend).handle),
            SSL_CIPHER_get_name(SSL_get_current_cipher((*backend).handle)),
        ) });
        if (unsafe { ((*conn).bits).tls_enable_alpn() }) != 0 {
            let mut neg_protocol: *const u8 = 0 as *const u8;
            let mut len: u32 = 0;
            (unsafe { SSL_get0_alpn_selected((*backend).handle, &mut neg_protocol, &mut len) });
            if len != 0 {
                (unsafe { Curl_infof(
                    data,
                    b"ALPN, server accepted to use %.*s\0" as *const u8 as *const i8,
                    len,
                    neg_protocol,
                ) });
                if len == 2 as i32 as u32
                    && (unsafe { memcmp(
                        b"h2\0" as *const u8 as *const i8 as *const libc::c_void,
                        neg_protocol as *const libc::c_void,
                        len as u64,
                    ) }) == 0
                {
                    (unsafe { (*conn).negnpn = CURL_HTTP_VERSION_2_0 as i32 });
                } else if len == 8 as i32 as u32
                    && (unsafe { memcmp(
                        b"http/1.1\0" as *const u8 as *const i8 as *const libc::c_void,
                        neg_protocol as *const libc::c_void,
                        8 as i32 as u64,
                    ) }) == 0
                {
                    (unsafe { (*conn).negnpn = CURL_HTTP_VERSION_1_1 as i32 });
                }
            } else {
                (unsafe { Curl_infof(
                    data,
                    b"ALPN, server did not agree to a protocol\0" as *const u8 as *const i8,
                ) });
            }
            (unsafe { Curl_multiuse_state(
                data,
                if (*conn).negnpn == CURL_HTTP_VERSION_2_0 as i32 {
                    2 as i32
                } else {
                    -(1 as i32)
                },
            ) });
        }
        return CURLE_OK;
    };
}
extern "C" fn asn1_object_dump(mut a: *mut ASN1_OBJECT, mut buf: *mut i8, mut len: size_t) -> i32 {
    let mut i: i32 = 0;
    let mut ilen: i32 = 0;
    ilen = len as i32;
    if ilen < 0 as i32 {
        return 1 as i32;
    }
    i = unsafe { i2t_ASN1_OBJECT(buf, ilen, a) };
    if i >= ilen {
        return 1 as i32;
    }
    return 0 as i32;
}
extern "C" fn pubkey_show(
    mut data: *mut Curl_easy,
    mut mem: *mut BIO,
    mut num: i32,
    mut type_0: *const i8,
    mut name: *const i8,
    mut bn: *const BIGNUM,
) {
    let mut ptr: *mut i8 = 0 as *mut i8;
    let mut namebuf: [i8; 32] = [0; 32];
    (unsafe { curl_msnprintf(
        namebuf.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 32]>() as u64,
        b"%s(%s)\0" as *const u8 as *const i8,
        type_0,
        name,
    ) });
    if !bn.is_null() {
        (unsafe { BN_print(mem, bn) });
    }
    let mut info_len: i64 = unsafe { BIO_ctrl(
        mem,
        3 as i32,
        0 as i32 as i64,
        &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
    ) };
    (unsafe { Curl_ssl_push_certinfo_len(data, num, namebuf.as_mut_ptr(), ptr, info_len as size_t) });
    let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
}
extern "C" fn X509V3_ext(
    mut data: *mut Curl_easy,
    mut certnum: i32,
    mut exts: *const stack_st_X509_EXTENSION,
) {
    let mut i: i32 = 0;
    if sk_X509_EXTENSION_num(exts) <= 0 as i32 {
        return;
    }
    i = 0 as i32;
    while i < sk_X509_EXTENSION_num(exts) {
        let mut obj: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        let mut ext: *mut X509_EXTENSION = sk_X509_EXTENSION_value(exts, i);
        let mut biomem: *mut BUF_MEM = 0 as *mut BUF_MEM;
        let mut namebuf: [i8; 128] = [0; 128];
        let mut bio_out: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
        if bio_out.is_null() {
            return;
        }
        obj = unsafe { X509_EXTENSION_get_object(ext) };
        asn1_object_dump(
            obj,
            namebuf.as_mut_ptr(),
            ::std::mem::size_of::<[i8; 128]>() as u64,
        );
        if (unsafe { X509V3_EXT_print(bio_out, ext, 0 as i32 as u64, 0 as i32) }) == 0 {
            (unsafe { ASN1_STRING_print(bio_out, X509_EXTENSION_get_data(ext) as *mut ASN1_STRING) });
        }
        (unsafe { BIO_ctrl(
            bio_out,
            115 as i32,
            0 as i32 as i64,
            &mut biomem as *mut *mut BUF_MEM as *mut i8 as *mut libc::c_void,
        ) });
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            certnum,
            namebuf.as_mut_ptr(),
            (*biomem).data,
            (*biomem).length,
        ) });
        (unsafe { BIO_free(bio_out) });
        i += 1;
    }
}
extern "C" fn get_cert_chain(
    mut data: *mut Curl_easy,
    mut connssl: *mut ssl_connect_data,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut sk: *mut stack_st_X509 = 0 as *mut stack_st_X509;
    let mut i: i32 = 0;
    let mut numcerts: numcert_t = 0;
    let mut mem: *mut BIO = 0 as *mut BIO;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    sk = unsafe { SSL_get_peer_cert_chain((*backend).handle) };
    if sk.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    numcerts = sk_X509_num(sk);
    result = unsafe { Curl_ssl_init_certinfo(data, numcerts) };
    if result as u64 != 0 {
        return result;
    }
    mem = unsafe { BIO_new(BIO_s_mem()) };
    i = 0 as i32;
    while i < numcerts {
        let mut num: *mut ASN1_INTEGER = 0 as *mut ASN1_INTEGER;
        let mut x: *mut X509 = sk_X509_value(sk, i);
        let mut pubkey: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
        let mut j: i32 = 0;
        let mut ptr: *mut i8 = 0 as *mut i8;
        let mut psig: *const ASN1_BIT_STRING = 0 as *const ASN1_BIT_STRING;
        (unsafe { X509_NAME_print_ex(
            mem,
            X509_get_subject_name(x),
            0 as i32,
            (1 as i32
                | 2 as i32
                | 4 as i32
                | 0x10 as i32
                | 0x100 as i32
                | 0x200 as i32
                | 8 as i32
                | (2 as i32) << 16 as i32
                | (1 as i32) << 23 as i32
                | 0 as i32) as u64,
        ) });
        let mut info_len: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Subject\0" as *const u8 as *const i8,
            ptr,
            info_len as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        (unsafe { X509_NAME_print_ex(
            mem,
            X509_get_issuer_name(x),
            0 as i32,
            (1 as i32
                | 2 as i32
                | 4 as i32
                | 0x10 as i32
                | 0x100 as i32
                | 0x200 as i32
                | 8 as i32
                | (2 as i32) << 16 as i32
                | (1 as i32) << 23 as i32
                | 0 as i32) as u64,
        ) });
        let mut info_len_0: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Issuer\0" as *const u8 as *const i8,
            ptr,
            info_len_0 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        (unsafe { BIO_printf(mem, b"%lx\0" as *const u8 as *const i8, X509_get_version(x)) });
        let mut info_len_1: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Version\0" as *const u8 as *const i8,
            ptr,
            info_len_1 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        num = unsafe { X509_get_serialNumber(x) };
        if (unsafe { (*num).type_0 }) == 2 as i32 | 0x100 as i32 {
            (unsafe { BIO_puts(mem, b"-\0" as *const u8 as *const i8) });
        }
        j = 0 as i32;
        while j < (unsafe { (*num).length }) {
            (unsafe { BIO_printf(
                mem,
                b"%02x\0" as *const u8 as *const i8,
                *((*num).data).offset(j as isize) as i32,
            ) });
            j += 1;
        }
        let mut info_len_2: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Serial Number\0" as *const u8 as *const i8,
            ptr,
            info_len_2 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        let mut sigalg: *const X509_ALGOR = 0 as *const X509_ALGOR;
        let mut xpubkey: *mut X509_PUBKEY = 0 as *mut X509_PUBKEY;
        let mut pubkeyoid: *mut ASN1_OBJECT = 0 as *mut ASN1_OBJECT;
        (unsafe { X509_get0_signature(&mut psig, &mut sigalg, x) });
        if !sigalg.is_null() {
            (unsafe { i2a_ASN1_OBJECT(mem, (*sigalg).algorithm) });
            let mut info_len_3: i64 = unsafe { BIO_ctrl(
                mem,
                3 as i32,
                0 as i32 as i64,
                &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
            ) };
            (unsafe { Curl_ssl_push_certinfo_len(
                data,
                i,
                b"Signature Algorithm\0" as *const u8 as *const i8,
                ptr,
                info_len_3 as size_t,
            ) });
            let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        }
        xpubkey = unsafe { X509_get_X509_PUBKEY(x) };
        if !xpubkey.is_null() {
            (unsafe { X509_PUBKEY_get0_param(
                &mut pubkeyoid,
                0 as *mut *const u8,
                0 as *mut i32,
                0 as *mut *mut X509_ALGOR,
                xpubkey,
            ) });
            if !pubkeyoid.is_null() {
                (unsafe { i2a_ASN1_OBJECT(mem, pubkeyoid) });
                let mut info_len_4: i64 = unsafe { BIO_ctrl(
                    mem,
                    3 as i32,
                    0 as i32 as i64,
                    &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
                ) };
                (unsafe { Curl_ssl_push_certinfo_len(
                    data,
                    i,
                    b"Public Key Algorithm\0" as *const u8 as *const i8,
                    ptr,
                    info_len_4 as size_t,
                ) });
                let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
            }
        }
        X509V3_ext(data, i, unsafe { X509_get0_extensions(x) });
        (unsafe { ASN1_TIME_print(mem, X509_get0_notBefore(x)) });
        let mut info_len_5: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Start date\0" as *const u8 as *const i8,
            ptr,
            info_len_5 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        (unsafe { ASN1_TIME_print(mem, X509_get0_notAfter(x)) });
        let mut info_len_6: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Expire date\0" as *const u8 as *const i8,
            ptr,
            info_len_6 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        pubkey = unsafe { X509_get_pubkey(x) };
        if pubkey.is_null() {
            (unsafe { Curl_infof(
                data,
                b"   Unable to load public key\0" as *const u8 as *const i8,
            ) });
        } else {
            let mut pktype: i32 = 0;
            pktype = unsafe { EVP_PKEY_id(pubkey) };
            match pktype {
                6 => {
                    let mut rsa: *mut RSA = 0 as *mut RSA;
                    rsa = unsafe { EVP_PKEY_get0_RSA(pubkey) };
                    let mut n: *const BIGNUM = 0 as *const BIGNUM;
                    let mut e: *const BIGNUM = 0 as *const BIGNUM;
                    (unsafe { RSA_get0_key(rsa, &mut n, &mut e, 0 as *mut *const BIGNUM) });
                    (unsafe { BIO_printf(mem, b"%d\0" as *const u8 as *const i8, BN_num_bits(n)) });
                    let mut info_len_7: i64 = unsafe { BIO_ctrl(
                        mem,
                        3 as i32,
                        0 as i32 as i64,
                        &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
                    ) };
                    (unsafe { Curl_ssl_push_certinfo_len(
                        data,
                        i,
                        b"RSA Public Key\0" as *const u8 as *const i8,
                        ptr,
                        info_len_7 as size_t,
                    ) });
                    let _ = 1 as i32
                        != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"rsa\0" as *const u8 as *const i8,
                        b"n\0" as *const u8 as *const i8,
                        n,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"rsa\0" as *const u8 as *const i8,
                        b"e\0" as *const u8 as *const i8,
                        e,
                    );
                }
                116 => {
                    let mut dsa: *mut DSA = 0 as *mut DSA;
                    dsa = unsafe { EVP_PKEY_get0_DSA(pubkey) };
                    let mut p: *const BIGNUM = 0 as *const BIGNUM;
                    let mut q: *const BIGNUM = 0 as *const BIGNUM;
                    let mut g: *const BIGNUM = 0 as *const BIGNUM;
                    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
                    (unsafe { DSA_get0_pqg(dsa, &mut p, &mut q, &mut g) });
                    (unsafe { DSA_get0_key(dsa, &mut pub_key, 0 as *mut *const BIGNUM) });
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dsa\0" as *const u8 as *const i8,
                        b"p\0" as *const u8 as *const i8,
                        p,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dsa\0" as *const u8 as *const i8,
                        b"q\0" as *const u8 as *const i8,
                        q,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dsa\0" as *const u8 as *const i8,
                        b"g\0" as *const u8 as *const i8,
                        g,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dsa\0" as *const u8 as *const i8,
                        b"pub_key\0" as *const u8 as *const i8,
                        pub_key,
                    );
                }
                28 => {
                    let mut dh: *mut DH = 0 as *mut DH;
                    dh = unsafe { EVP_PKEY_get0_DH(pubkey) };
                    let mut p_0: *const BIGNUM = 0 as *const BIGNUM;
                    let mut q_0: *const BIGNUM = 0 as *const BIGNUM;
                    let mut g_0: *const BIGNUM = 0 as *const BIGNUM;
                    let mut pub_key_0: *const BIGNUM = 0 as *const BIGNUM;
                    (unsafe { DH_get0_pqg(dh, &mut p_0, &mut q_0, &mut g_0) });
                    (unsafe { DH_get0_key(dh, &mut pub_key_0, 0 as *mut *const BIGNUM) });
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dh\0" as *const u8 as *const i8,
                        b"p\0" as *const u8 as *const i8,
                        p_0,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dh\0" as *const u8 as *const i8,
                        b"q\0" as *const u8 as *const i8,
                        q_0,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dh\0" as *const u8 as *const i8,
                        b"g\0" as *const u8 as *const i8,
                        g_0,
                    );
                    pubkey_show(
                        data,
                        mem,
                        i,
                        b"dh\0" as *const u8 as *const i8,
                        b"pub_key\0" as *const u8 as *const i8,
                        pub_key_0,
                    );
                }
                _ => {}
            }
            (unsafe { EVP_PKEY_free(pubkey) });
        }
        if !psig.is_null() {
            j = 0 as i32;
            while j < (unsafe { (*psig).length }) {
                (unsafe { BIO_printf(
                    mem,
                    b"%02x:\0" as *const u8 as *const i8,
                    *((*psig).data).offset(j as isize) as i32,
                ) });
                j += 1;
            }
            let mut info_len_8: i64 = unsafe { BIO_ctrl(
                mem,
                3 as i32,
                0 as i32 as i64,
                &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
            ) };
            (unsafe { Curl_ssl_push_certinfo_len(
                data,
                i,
                b"Signature\0" as *const u8 as *const i8,
                ptr,
                info_len_8 as size_t,
            ) });
            let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        }
        (unsafe { PEM_write_bio_X509(mem, x) });
        let mut info_len_9: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        (unsafe { Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Cert\0" as *const u8 as *const i8,
            ptr,
            info_len_9 as size_t,
        ) });
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        i += 1;
    }
    (unsafe { BIO_free(mem) });
    return CURLE_OK;
}
extern "C" fn pkp_pin_peer_pubkey(
    mut data: *mut Curl_easy,
    mut cert: *mut X509,
    mut pinnedpubkey: *const i8,
) -> CURLcode {
    let mut len1: i32 = 0 as i32;
    let mut len2: i32 = 0 as i32;
    let mut buff1: *mut u8 = 0 as *mut u8;
    let mut temp: *mut u8 = 0 as *mut u8;
    let mut result: CURLcode = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    if pinnedpubkey.is_null() {
        return CURLE_OK;
    }
    if cert.is_null() {
        return result;
    }
    len1 = unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), 0 as *mut *mut u8) };
    if !(len1 < 1 as i32) {
        temp = (unsafe { Curl_cmalloc.expect("non-null function pointer")(len1 as size_t) }) as *mut u8;
        buff1 = temp;
        if !buff1.is_null() {
            len2 = unsafe { i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &mut temp) };
            if !(len1 != len2 || temp.is_null() || (unsafe { temp.offset_from(buff1) }) as i64 != len1 as i64) {
                result = unsafe { Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1 as size_t) };
            }
        }
    }
    if !buff1.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(buff1 as *mut libc::c_void) });
    }
    return result;
}
extern "C" fn servercert(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut connssl: *mut ssl_connect_data,
    mut strict: bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut rc: i32 = 0;
    let mut lerr: i64 = 0;
    let mut issuer: *mut X509 = 0 as *mut X509;
    let mut fp: *mut BIO = 0 as *mut BIO;
    let mut error_buffer : [i8 ; 256] = * (unsafe { :: std :: mem :: transmute :: < & [u8 ; 256] , & mut [i8 ; 256] , > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut buffer: [i8; 2048] = [0; 2048];
    let mut ptr: *const i8 = 0 as *const i8;
    let mut mem: *mut BIO = unsafe { BIO_new(BIO_s_mem()) };
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if (unsafe { ((*data).set.ssl).certinfo() }) != 0 {
        get_cert_chain(data, connssl);
    }
    let fresh14 = unsafe { &mut ((*backend).server_cert) };
    *fresh14 = unsafe { SSL_get_peer_certificate((*backend).handle) };
    if (unsafe { (*backend).server_cert }).is_null() {
        (unsafe { BIO_free(mem) });
        if !strict {
            return CURLE_OK;
        }
        (unsafe { Curl_failf(
            data,
            b"SSL: couldn't get peer certificate!\0" as *const u8 as *const i8,
        ) });
        return CURLE_PEER_FAILED_VERIFICATION;
    }
    (unsafe { Curl_infof(
        data,
        b"%s certificate:\0" as *const u8 as *const i8,
        if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
            && ssl_connection_complete as i32 as u32
                != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state as u32
        {
            b"Proxy\0" as *const u8 as *const i8
        } else {
            b"Server\0" as *const u8 as *const i8
        },
    ) });
    rc = x509_name_oneline(
        unsafe { X509_get_subject_name((*backend).server_cert) },
        buffer.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 2048]>() as u64,
    );
    (unsafe { Curl_infof(
        data,
        b" subject: %s\0" as *const u8 as *const i8,
        if rc != 0 {
            b"[NONE]\0" as *const u8 as *const i8
        } else {
            buffer.as_mut_ptr() as *const i8
        },
    ) });
    let mut len: i64 = 0;
    (unsafe { ASN1_TIME_print(mem, X509_get0_notBefore((*backend).server_cert)) });
    len = unsafe { BIO_ctrl(
        mem,
        3 as i32,
        0 as i32 as i64,
        &mut ptr as *mut *const i8 as *mut *mut i8 as *mut i8 as *mut libc::c_void,
    ) };
    (unsafe { Curl_infof(
        data,
        b" start date: %.*s\0" as *const u8 as *const i8,
        len as i32,
        ptr,
    ) });
    (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) });
    (unsafe { ASN1_TIME_print(mem, X509_get0_notAfter((*backend).server_cert)) });
    len = unsafe { BIO_ctrl(
        mem,
        3 as i32,
        0 as i32 as i64,
        &mut ptr as *mut *const i8 as *mut *mut i8 as *mut i8 as *mut libc::c_void,
    ) };
    (unsafe { Curl_infof(
        data,
        b" expire date: %.*s\0" as *const u8 as *const i8,
        len as i32,
        ptr,
    ) });
    (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) });
    (unsafe { BIO_free(mem) });
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*conn).proxy_ssl_config).verifyhost() }) as i32
    } else {
        (unsafe { ((*conn).ssl_config).verifyhost() }) as i32
    } != 0
    {
        result = verifyhost(data, conn, unsafe { (*backend).server_cert });
        if result as u64 != 0 {
            (unsafe { X509_free((*backend).server_cert) });
            let fresh15 = unsafe { &mut ((*backend).server_cert) };
            *fresh15 = 0 as *mut X509;
            return result;
        }
    }
    rc = x509_name_oneline(
        unsafe { X509_get_issuer_name((*backend).server_cert) },
        buffer.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 2048]>() as u64,
    );
    if rc != 0 {
        if strict {
            (unsafe { Curl_failf(
                data,
                b"SSL: couldn't get X509-issuer name!\0" as *const u8 as *const i8,
            ) });
        }
        result = CURLE_PEER_FAILED_VERIFICATION;
    } else {
        (unsafe { Curl_infof(
            data,
            b" issuer: %s\0" as *const u8 as *const i8,
            buffer.as_mut_ptr(),
        ) });
        if !(if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            unsafe { (*conn).proxy_ssl_config.issuercert }
        } else {
            unsafe { (*conn).ssl_config.issuercert }
        })
        .is_null()
            || !(if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                && ssl_connection_complete as i32 as u32
                    != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state }) as u32
            {
                unsafe { (*conn).proxy_ssl_config.issuercert_blob }
            } else {
                unsafe { (*conn).ssl_config.issuercert_blob }
            })
            .is_null()
        {
            if !if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                && ssl_connection_complete as i32 as u32
                    != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state }) as u32
            {
                unsafe { (*conn).proxy_ssl_config.issuercert_blob }
            } else {
                unsafe { (*conn).ssl_config.issuercert_blob }
            }
            .is_null()
            {
                fp = unsafe { BIO_new_mem_buf(
                    (*if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as i32 as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.issuercert_blob
                    } else {
                        (*conn).ssl_config.issuercert_blob
                    })
                    .data,
                    (*if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as i32 as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.issuercert_blob
                    } else {
                        (*conn).ssl_config.issuercert_blob
                    })
                    .len as i32,
                ) };
            } else {
                fp = unsafe { BIO_new(BIO_s_file()) };
                if fp.is_null() {
                    (unsafe { Curl_failf(
                        data,
                        b"BIO_new return NULL, OpenSSL error %s\0" as *const u8 as *const i8,
                        ossl_strerror(
                            ERR_get_error(),
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                    (unsafe { X509_free((*backend).server_cert) });
                    let fresh16 = unsafe { &mut ((*backend).server_cert) };
                    *fresh16 = 0 as *mut X509;
                    return CURLE_OUT_OF_MEMORY;
                }
                if (unsafe { BIO_ctrl(
                    fp,
                    108 as i32,
                    (0x1 as i32 | 0x2 as i32) as i64,
                    (if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                        && ssl_connection_complete as i32 as u32
                            != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32)
                            {
                                0 as i32
                            } else {
                                1 as i32
                            }) as usize]
                                .state as u32
                    {
                        (*conn).proxy_ssl_config.issuercert
                    } else {
                        (*conn).ssl_config.issuercert
                    }) as *mut libc::c_void,
                ) }) as i32
                    <= 0 as i32
                {
                    if strict {
                        (unsafe { Curl_failf(
                            data,
                            b"SSL: Unable to open issuer cert (%s)\0" as *const u8 as *const i8,
                            if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                                && ssl_connection_complete as i32 as u32
                                    != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
                                        == -(1 as i32)
                                    {
                                        0 as i32
                                    } else {
                                        1 as i32
                                    })
                                        as usize]
                                        .state as u32
                            {
                                (*conn).proxy_ssl_config.issuercert
                            } else {
                                (*conn).ssl_config.issuercert
                            },
                        ) });
                    }
                    (unsafe { BIO_free(fp) });
                    (unsafe { X509_free((*backend).server_cert) });
                    let fresh17 = unsafe { &mut ((*backend).server_cert) };
                    *fresh17 = 0 as *mut X509;
                    return CURLE_SSL_ISSUER_ERROR;
                }
            }
            issuer = unsafe { PEM_read_bio_X509(fp, 0 as *mut *mut X509, None, 0 as *mut libc::c_void) };
            if issuer.is_null() {
                if strict {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL: Unable to read issuer cert (%s)\0" as *const u8 as *const i8,
                        if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                            && ssl_connection_complete as i32 as u32
                                != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
                                    == -(1 as i32)
                                {
                                    0 as i32
                                } else {
                                    1 as i32
                                }) as usize]
                                    .state as u32
                        {
                            (*conn).proxy_ssl_config.issuercert
                        } else {
                            (*conn).ssl_config.issuercert
                        },
                    ) });
                }
                (unsafe { BIO_free(fp) });
                (unsafe { X509_free(issuer) });
                (unsafe { X509_free((*backend).server_cert) });
                let fresh18 = unsafe { &mut ((*backend).server_cert) };
                *fresh18 = 0 as *mut X509;
                return CURLE_SSL_ISSUER_ERROR;
            }
            if (unsafe { X509_check_issued(issuer, (*backend).server_cert) }) != 0 as i32 {
                if strict {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL: Certificate issuer check failed (%s)\0" as *const u8 as *const i8,
                        if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                            && ssl_connection_complete as i32 as u32
                                != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize]
                                    == -(1 as i32)
                                {
                                    0 as i32
                                } else {
                                    1 as i32
                                }) as usize]
                                    .state as u32
                        {
                            (*conn).proxy_ssl_config.issuercert
                        } else {
                            (*conn).ssl_config.issuercert
                        },
                    ) });
                }
                (unsafe { BIO_free(fp) });
                (unsafe { X509_free(issuer) });
                (unsafe { X509_free((*backend).server_cert) });
                let fresh19 = unsafe { &mut ((*backend).server_cert) };
                *fresh19 = 0 as *mut X509;
                return CURLE_SSL_ISSUER_ERROR;
            }
            (unsafe { Curl_infof(
                data,
                b" SSL certificate issuer check ok (%s)\0" as *const u8 as *const i8,
                if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as i32 as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    (*conn).proxy_ssl_config.issuercert
                } else {
                    (*conn).ssl_config.issuercert
                },
            ) });
            (unsafe { BIO_free(fp) });
            (unsafe { X509_free(issuer) });
        }
        lerr = unsafe { SSL_get_verify_result((*backend).handle) };
        *if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            unsafe { &mut (*data).set.proxy_ssl.certverifyresult }
        } else {
            unsafe { &mut (*data).set.ssl.certverifyresult }
        } = lerr;
        if lerr != 0 as i32 as i64 {
            if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                && ssl_connection_complete as i32 as u32
                    != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state }) as u32
            {
                (unsafe { ((*conn).proxy_ssl_config).verifypeer() }) as i32
            } else {
                (unsafe { ((*conn).ssl_config).verifypeer() }) as i32
            } != 0
            {
                if strict {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL certificate verify result: %s (%ld)\0" as *const u8 as *const i8,
                        X509_verify_cert_error_string(lerr),
                        lerr,
                    ) });
                }
                result = CURLE_PEER_FAILED_VERIFICATION;
            } else {
                (unsafe { Curl_infof(
                    data,
                    b" SSL certificate verify result: %s (%ld), continuing anyway.\0" as *const u8
                        as *const i8,
                    X509_verify_cert_error_string(lerr),
                    lerr,
                ) });
            }
        } else {
            (unsafe { Curl_infof(
                data,
                b" SSL certificate verify ok.\0" as *const u8 as *const i8,
            ) });
        }
    }
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*conn).proxy_ssl_config).verifystatus() }) as i32
    } else {
        (unsafe { ((*conn).ssl_config).verifystatus() }) as i32
    } != 0
    {
        result = verifystatus(data, connssl);
        if result as u64 != 0 {
            (unsafe { X509_free((*backend).server_cert) });
            let fresh20 = unsafe { &mut ((*backend).server_cert) };
            *fresh20 = 0 as *mut X509;
            return result;
        }
    }
    if !strict {
        result = CURLE_OK;
    }
    ptr = if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY_PROXY as i32 as usize] }
    } else {
        unsafe { (*data).set.str_0[STRING_SSL_PINNEDPUBLICKEY as i32 as usize] }
    };
    if result as u64 == 0 && !ptr.is_null() {
        result = pkp_pin_peer_pubkey(data, unsafe { (*backend).server_cert }, ptr);
        if result as u64 != 0 {
            (unsafe { Curl_failf(
                data,
                b"SSL: public key does not match pinned public key!\0" as *const u8 as *const i8,
            ) });
        }
    }
    (unsafe { X509_free((*backend).server_cert) });
    let fresh21 = unsafe { &mut ((*backend).server_cert) };
    *fresh21 = 0 as *mut X509;
    (unsafe { (*connssl).connecting_state = ssl_connect_done });
    return result;
}
extern "C" fn ossl_connect_step3(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    result = servercert(
        data,
        conn,
        connssl,
        (if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            (unsafe { ((*conn).proxy_ssl_config).verifypeer() }) as i32
        } else {
            (unsafe { ((*conn).ssl_config).verifypeer() }) as i32
        }) != 0
            || (if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
                && ssl_connection_complete as i32 as u32
                    != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                        0 as i32
                    } else {
                        1 as i32
                    }) as usize]
                        .state }) as u32
            {
                (unsafe { ((*conn).proxy_ssl_config).verifyhost() }) as i32
            } else {
                (unsafe { ((*conn).ssl_config).verifyhost() }) as i32
            }) != 0,
    );
    if result as u64 == 0 {
        (unsafe { (*connssl).connecting_state = ssl_connect_done });
    }
    return result;
}
extern "C" fn ossl_connect_common(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut sockfd: curl_socket_t = unsafe { (*conn).sock[sockindex as usize] };
    let mut what: i32 = 0;
    if ssl_connection_complete as i32 as u32 == (unsafe { (*connssl).state }) as u32 {
        (unsafe { *done = 1 as i32 != 0 });
        return CURLE_OK;
    }
    if ssl_connect_1 as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32 {
        let timeout_ms: timediff_t = unsafe { Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0) };
        if timeout_ms < 0 as i32 as i64 {
            (unsafe { Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8) });
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = ossl_connect_step1(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    while ssl_connect_2 as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32
        || ssl_connect_2_reading as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32
        || ssl_connect_2_writing as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32
    {
        let timeout_ms_0: timediff_t = unsafe { Curl_timeleft(data, 0 as *mut curltime, 1 as i32 != 0) };
        if timeout_ms_0 < 0 as i32 as i64 {
            (unsafe { Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8) });
            return CURLE_OPERATION_TIMEDOUT;
        }
        if (unsafe { (*connssl).connecting_state }) as u32 == ssl_connect_2_reading as i32 as u32
            || (unsafe { (*connssl).connecting_state }) as u32 == ssl_connect_2_writing as i32 as u32
        {
            let mut writefd: curl_socket_t =
                if ssl_connect_2_writing as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32 {
                    sockfd
                } else {
                    -(1 as i32)
                };
            let mut readfd: curl_socket_t =
                if ssl_connect_2_reading as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32 {
                    sockfd
                } else {
                    -(1 as i32)
                };
            what = unsafe { Curl_socket_check(
                readfd,
                -(1 as i32),
                writefd,
                if nonblocking as i32 != 0 {
                    0 as i32 as i64
                } else {
                    timeout_ms_0
                },
            ) };
            if what < 0 as i32 {
                (unsafe { Curl_failf(
                    data,
                    b"select/poll on SSL socket, errno: %d\0" as *const u8 as *const i8,
                    *__errno_location(),
                ) });
                return CURLE_SSL_CONNECT_ERROR;
            }
            if 0 as i32 == what {
                if nonblocking {
                    (unsafe { *done = 0 as i32 != 0 });
                    return CURLE_OK;
                }
                (unsafe { Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8) });
                return CURLE_OPERATION_TIMEDOUT;
            }
        }
        result = ossl_connect_step2(data, conn, sockindex);
        if result as u32 != 0
            || nonblocking as i32 != 0
                && (ssl_connect_2 as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32
                    || ssl_connect_2_reading as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32
                    || ssl_connect_2_writing as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32)
        {
            return result;
        }
    }
    if ssl_connect_3 as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32 {
        result = ossl_connect_step3(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as i32 as u32 == (unsafe { (*connssl).connecting_state }) as u32 {
        (unsafe { (*connssl).state = ssl_connection_complete });
        let fresh22 = unsafe { &mut ((*conn).recv[sockindex as usize]) };
        *fresh22 = Some(ossl_recv as Curl_recv);
        let fresh23 = unsafe { &mut ((*conn).send[sockindex as usize]) };
        *fresh23 = Some(ossl_send as Curl_send);
        (unsafe { *done = 1 as i32 != 0 });
    } else {
        (unsafe { *done = 0 as i32 != 0 });
    }
    (unsafe { (*connssl).connecting_state = ssl_connect_1 });
    return CURLE_OK;
}
extern "C" fn ossl_connect_nonblocking(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> CURLcode {
    return ossl_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
}
extern "C" fn ossl_connect(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) -> CURLcode {
    let mut result: CURLcode = CURLE_OK;
    let mut done: bool = 0 as i32 != 0;
    result = ossl_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
    if result as u64 != 0 {
        return result;
    }
    return CURLE_OK;
}
extern "C" fn ossl_data_pending(mut conn: *const connectdata, mut connindex: i32) -> bool {
    let mut connssl: *const ssl_connect_data =
        (unsafe { &*((*conn).ssl).as_ptr().offset(connindex as isize) }) as *const ssl_connect_data;
    if !(unsafe { (*(*connssl).backend).handle }).is_null() && (unsafe { SSL_pending((*(*connssl).backend).handle) }) != 0 {
        return 1 as i32 != 0;
    }
    let mut proxyssl: *const ssl_connect_data =
        (unsafe { &*((*conn).proxy_ssl).as_ptr().offset(connindex as isize) }) as *const ssl_connect_data;
    if !(unsafe { (*(*proxyssl).backend).handle }).is_null() && (unsafe { SSL_pending((*(*proxyssl).backend).handle) }) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn ossl_send(
    mut data: *mut Curl_easy,
    mut sockindex: i32,
    mut mem: *const libc::c_void,
    mut len: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut err: i32 = 0;
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut memlen: i32 = 0;
    let mut rc: i32 = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    (unsafe { ERR_clear_error() });
    memlen = if len > 2147483647 as i32 as size_t {
        2147483647 as i32
    } else {
        len as i32
    };
    let fresh24 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
    *fresh24 = data;
    rc = unsafe { SSL_write((*backend).handle, mem, memlen) };
    if rc <= 0 as i32 {
        err = unsafe { SSL_get_error((*backend).handle, rc) };
        match err {
            2 | 3 => {
                (unsafe { *curlcode = CURLE_AGAIN });
                return -(1 as i32) as ssize_t;
            }
            5 => {
                let mut sockerr: i32 = unsafe { *__errno_location() };
                sslerror = unsafe { ERR_get_error() };
                if sslerror != 0 {
                    ossl_strerror(
                        sslerror,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    );
                } else if sockerr != 0 {
                    (unsafe { Curl_strerror(
                        sockerr,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ) });
                } else {
                    (unsafe { strncpy(
                        error_buffer.as_mut_ptr(),
                        SSL_ERROR_to_str(err),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    ) });
                    error_buffer[(::std::mem::size_of::<[i8; 256]>() as u64)
                        .wrapping_sub(1 as i32 as u64) as usize] = '\u{0}' as i32 as i8;
                }
                (unsafe { Curl_failf(
                    data,
                    b"OpenSSL SSL_write: %s, errno %d\0" as *const u8 as *const i8,
                    error_buffer.as_mut_ptr(),
                    sockerr,
                ) });
                (unsafe { *curlcode = CURLE_SEND_ERROR });
                return -(1 as i32) as ssize_t;
            }
            1 => {
                sslerror = unsafe { ERR_get_error() };
                if (sslerror >> 24 as i64 & 0xff as i64 as u64) as i32 == 20 as i32
                    && (sslerror & 0xfff as i64 as u64) as i32 == 128 as i32
                    && (unsafe { (*conn).ssl[sockindex as usize].state }) as u32
                        == ssl_connection_complete as i32 as u32
                    && (unsafe { (*conn).proxy_ssl[sockindex as usize].state }) as u32
                        == ssl_connection_complete as i32 as u32
                {
                    let mut ver: [i8; 120] = [0; 120];
                    ossl_version(ver.as_mut_ptr(), ::std::mem::size_of::<[i8; 120]>() as u64);
                    (unsafe { Curl_failf(
                        data,
                        b"Error: %s does not support double SSL tunneling.\0" as *const u8
                            as *const i8,
                        ver.as_mut_ptr(),
                    ) });
                } else {
                    (unsafe { Curl_failf(
                        data,
                        b"SSL_write() error: %s\0" as *const u8 as *const i8,
                        ossl_strerror(
                            sslerror,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ),
                    ) });
                }
                (unsafe { *curlcode = CURLE_SEND_ERROR });
                return -(1 as i32) as ssize_t;
            }
            _ => {}
        }
        (unsafe { Curl_failf(
            data,
            b"OpenSSL SSL_write: %s, errno %d\0" as *const u8 as *const i8,
            SSL_ERROR_to_str(err),
            *__errno_location(),
        ) });
        (unsafe { *curlcode = CURLE_SEND_ERROR });
        return -(1 as i32) as ssize_t;
    }
    (unsafe { *curlcode = CURLE_OK });
    return rc as ssize_t;
}
extern "C" fn ossl_recv(
    mut data: *mut Curl_easy,
    mut num: i32,
    mut buf: *mut i8,
    mut buffersize: size_t,
    mut curlcode: *mut CURLcode,
) -> ssize_t {
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut nread: ssize_t = 0;
    let mut buffsize: i32 = 0;
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    (unsafe { ERR_clear_error() });
    buffsize = if buffersize > 2147483647 as i32 as size_t {
        2147483647 as i32
    } else {
        buffersize as i32
    };
    let fresh25 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
    *fresh25 = data;
    nread = (unsafe { SSL_read((*backend).handle, buf as *mut libc::c_void, buffsize) }) as ssize_t;
    if nread <= 0 as i32 as i64 {
        let mut err: i32 = unsafe { SSL_get_error((*backend).handle, nread as i32) };
        match err {
            0 => {}
            6 => {
                if num == 0 as i32 {
                    (unsafe { Curl_conncontrol(conn, 1 as i32) });
                }
            }
            2 | 3 => {
                (unsafe { *curlcode = CURLE_AGAIN });
                return -(1 as i32) as ssize_t;
            }
            _ => {
                sslerror = unsafe { ERR_get_error() };
                if nread < 0 as i32 as i64 || sslerror != 0 {
                    let mut sockerr: i32 = unsafe { *__errno_location() };
                    if sslerror != 0 {
                        ossl_strerror(
                            sslerror,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        );
                    } else if sockerr != 0 && err == 5 as i32 {
                        (unsafe { Curl_strerror(
                            sockerr,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ) });
                    } else {
                        (unsafe { strncpy(
                            error_buffer.as_mut_ptr(),
                            SSL_ERROR_to_str(err),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        ) });
                        error_buffer[(::std::mem::size_of::<[i8; 256]>() as u64)
                            .wrapping_sub(1 as i32 as u64)
                            as usize] = '\u{0}' as i32 as i8;
                    }
                    (unsafe { Curl_failf(
                        data,
                        b"OpenSSL SSL_read: %s, errno %d\0" as *const u8 as *const i8,
                        error_buffer.as_mut_ptr(),
                        sockerr,
                    ) });
                    (unsafe { *curlcode = CURLE_RECV_ERROR });
                    return -(1 as i32) as ssize_t;
                }
            }
        }
    }
    return nread;
}
extern "C" fn ossl_version(mut buffer: *mut i8, mut size: size_t) -> size_t {
    let mut sub: [i8; 3] = [0; 3];
    let mut ssleay_value: u64 = 0;
    sub[2 as i32 as usize] = '\u{0}' as i32 as i8;
    sub[1 as i32 as usize] = '\u{0}' as i32 as i8;
    ssleay_value = unsafe { OpenSSL_version_num() };
    if ssleay_value < 0x906000 as i32 as u64 {
        ssleay_value = 0x1010106f as i64 as u64;
        sub[0 as i32 as usize] = '\u{0}' as i32 as i8;
    } else if ssleay_value & 0xff0 as i32 as u64 != 0 {
        let mut minor_ver: i32 = (ssleay_value >> 4 as i32 & 0xff as i32 as u64) as i32;
        if minor_ver > 26 as i32 {
            sub[1 as i32 as usize] =
                ((minor_ver - 1 as i32) % 26 as i32 + 'a' as i32 + 1 as i32) as i8;
            sub[0 as i32 as usize] = 'z' as i32 as i8;
        } else {
            sub[0 as i32 as usize] = (minor_ver + 'a' as i32 - 1 as i32) as i8;
        }
    } else {
        sub[0 as i32 as usize] = '\u{0}' as i32 as i8;
    }
    return (unsafe { curl_msnprintf(
        buffer,
        size,
        b"%s/%lx.%lx.%lx%s\0" as *const u8 as *const i8,
        b"OpenSSL\0" as *const u8 as *const i8,
        ssleay_value >> 28 as i32 & 0xf as i32 as u64,
        ssleay_value >> 20 as i32 & 0xff as i32 as u64,
        ssleay_value >> 12 as i32 & 0xff as i32 as u64,
        sub.as_mut_ptr(),
    ) }) as size_t;
}
extern "C" fn ossl_random(
    mut data: *mut Curl_easy,
    mut entropy: *mut u8,
    mut length: size_t,
) -> CURLcode {
    let mut rc: i32 = 0;
    if !data.is_null() {
        if ossl_seed(data) as u64 != 0 {
            return CURLE_FAILED_INIT;
        }
    } else if !rand_enough() {
        return CURLE_FAILED_INIT;
    }
    rc = unsafe { RAND_bytes(entropy, curlx_uztosi(length)) };
    return (if rc == 1 as i32 {
        CURLE_OK as i32
    } else {
        CURLE_FAILED_INIT as i32
    }) as CURLcode;
}
extern "C" fn ossl_sha256sum(
    mut tmp: *const u8,
    mut tmplen: size_t,
    mut sha256sum: *mut u8,
    mut _unused: size_t,
) -> CURLcode {
    let mut mdctx: *mut EVP_MD_CTX = 0 as *mut EVP_MD_CTX;
    let mut len: u32 = 0 as i32 as u32;
    mdctx = unsafe { EVP_MD_CTX_new() };
    if mdctx.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    (unsafe { EVP_DigestInit(mdctx, EVP_sha256()) });
    (unsafe { EVP_DigestUpdate(mdctx, tmp as *const libc::c_void, tmplen) });
    (unsafe { EVP_DigestFinal_ex(mdctx, sha256sum, &mut len) });
    (unsafe { EVP_MD_CTX_free(mdctx) });
    return CURLE_OK;
}
extern "C" fn ossl_cert_status_request() -> bool {
    return 1 as i32 != 0;
}
extern "C" fn ossl_get_internals(
    mut connssl: *mut ssl_connect_data,
    mut info: CURLINFO,
) -> *mut libc::c_void {
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    return if info as u32 == CURLINFO_TLS_SESSION as i32 as u32 {
        (unsafe { (*backend).ctx }) as *mut libc::c_void
    } else {
        (unsafe { (*backend).handle }) as *mut libc::c_void
    };
}
extern "C" fn ossl_associate_connection(
    mut data: *mut Curl_easy,
    mut conn: *mut connectdata,
    mut sockindex: i32,
) {
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if (unsafe { (*backend).handle }).is_null() {
        return;
    }
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*data).set.proxy_ssl.primary).sessionid() }) as i32
    } else {
        (unsafe { ((*data).set.ssl.primary).sessionid() }) as i32
    } != 0
    {
        let mut data_idx: i32 = ossl_get_ssl_data_index();
        let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
        let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
        let mut proxy_idx: i32 = ossl_get_proxy_index();
        if data_idx >= 0 as i32
            && connectdata_idx >= 0 as i32
            && sockindex_idx >= 0 as i32
            && proxy_idx >= 0 as i32
        {
            (unsafe { SSL_set_ex_data((*backend).handle, data_idx, data as *mut libc::c_void) });
            (unsafe { SSL_set_ex_data(
                (*backend).handle,
                connectdata_idx,
                conn as *mut libc::c_void,
            ) });
            (unsafe { SSL_set_ex_data(
                (*backend).handle,
                sockindex_idx,
                ((*conn).sock).as_mut_ptr().offset(sockindex as isize) as *mut libc::c_void,
            ) });
            (unsafe { SSL_set_ex_data(
                (*backend).handle,
                proxy_idx,
                if CURLPROXY_HTTPS as i32 as u32 == (*conn).http_proxy.proxytype as u32
                    && ssl_connection_complete as i32 as u32
                        != (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                            0 as i32
                        } else {
                            1 as i32
                        }) as usize]
                            .state as u32
                {
                    1 as i32 as *mut libc::c_void
                } else {
                    0 as *mut libc::c_void
                },
            ) });
        }
    }
}
extern "C" fn ossl_disassociate_connection(mut data: *mut Curl_easy, mut sockindex: i32) {
    let mut conn: *mut connectdata = unsafe { (*data).conn };
    let mut connssl: *mut ssl_connect_data =
        (unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }) as *mut ssl_connect_data;
    let mut backend: *mut ssl_backend_data = unsafe { (*connssl).backend };
    if (unsafe { (*backend).handle }).is_null() {
        return;
    }
    if if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
        && ssl_connection_complete as i32 as u32
            != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                0 as i32
            } else {
                1 as i32
            }) as usize]
                .state }) as u32
    {
        (unsafe { ((*data).set.proxy_ssl.primary).sessionid() }) as i32
    } else {
        (unsafe { ((*data).set.ssl.primary).sessionid() }) as i32
    } != 0
    {
        let mut data_idx: i32 = ossl_get_ssl_data_index();
        let mut connectdata_idx: i32 = ossl_get_ssl_conn_index();
        let mut sockindex_idx: i32 = ossl_get_ssl_sockindex_index();
        let mut proxy_idx: i32 = ossl_get_proxy_index();
        if data_idx >= 0 as i32
            && connectdata_idx >= 0 as i32
            && sockindex_idx >= 0 as i32
            && proxy_idx >= 0 as i32
        {
            (unsafe { SSL_set_ex_data((*backend).handle, data_idx, 0 as *mut libc::c_void) });
            (unsafe { SSL_set_ex_data((*backend).handle, connectdata_idx, 0 as *mut libc::c_void) });
            (unsafe { SSL_set_ex_data((*backend).handle, sockindex_idx, 0 as *mut libc::c_void) });
            (unsafe { SSL_set_ex_data((*backend).handle, proxy_idx, 0 as *mut libc::c_void) });
        }
    }
}
#[no_mangle]
pub static mut Curl_ssl_openssl: Curl_ssl =  {
    {
        let mut init = Curl_ssl {
            info: {
                let mut init = curl_ssl_backend {
                    id: CURLSSLBACKEND_OPENSSL,
                    name: b"openssl\0" as *const u8 as *const i8,
                };
                init
            },
            supports: ((1 as i32) << 0 as i32
                | (1 as i32) << 6 as i32
                | (1 as i32) << 1 as i32
                | (1 as i32) << 2 as i32
                | (1 as i32) << 3 as i32
                | (1 as i32) << 5 as i32
                | (1 as i32) << 4 as i32) as u32,
            sizeof_ssl_backend_data: ::std::mem::size_of::<ssl_backend_data>() as u64,
            init: Some(ossl_init as unsafe extern "C" fn() -> i32),
            cleanup: Some(ossl_cleanup as unsafe extern "C" fn() -> ()),
            version: Some(ossl_version as unsafe extern "C" fn(*mut i8, size_t) -> size_t),
            check_cxn: Some(ossl_check_cxn as unsafe extern "C" fn(*mut connectdata) -> i32),
            shut_down: Some(
                ossl_shutdown as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> i32,
            ),
            data_pending: Some(
                ossl_data_pending as unsafe extern "C" fn(*const connectdata, i32) -> bool,
            ),
            random: Some(
                ossl_random as unsafe extern "C" fn(*mut Curl_easy, *mut u8, size_t) -> CURLcode,
            ),
            cert_status_request: Some(ossl_cert_status_request as unsafe extern "C" fn() -> bool),
            connect_blocking: Some(
                ossl_connect
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> CURLcode,
            ),
            connect_nonblocking: Some(
                ossl_connect_nonblocking
                    as unsafe extern "C" fn(
                        *mut Curl_easy,
                        *mut connectdata,
                        i32,
                        *mut bool,
                    ) -> CURLcode,
            ),
            getsock: Some(
                Curl_ssl_getsock
                    as unsafe extern "C" fn(*mut connectdata, *mut curl_socket_t) -> i32,
            ),
            get_internals: Some(
                ossl_get_internals
                    as unsafe extern "C" fn(*mut ssl_connect_data, CURLINFO) -> *mut libc::c_void,
            ),
            close_one: Some(
                ossl_close as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
            ),
            close_all: Some(ossl_close_all as unsafe extern "C" fn(*mut Curl_easy) -> ()),
            session_free: Some(ossl_session_free as unsafe extern "C" fn(*mut libc::c_void) -> ()),
            set_engine: Some(
                ossl_set_engine as unsafe extern "C" fn(*mut Curl_easy, *const i8) -> CURLcode,
            ),
            set_engine_default: Some(
                ossl_set_engine_default as unsafe extern "C" fn(*mut Curl_easy) -> CURLcode,
            ),
            engines_list: Some(
                ossl_engines_list as unsafe extern "C" fn(*mut Curl_easy) -> *mut curl_slist,
            ),
            false_start: Some(Curl_none_false_start as unsafe extern "C" fn() -> bool),
            sha256sum: Some(
                ossl_sha256sum
                    as unsafe extern "C" fn(*const u8, size_t, *mut u8, size_t) -> CURLcode,
            ),
            associate_connection: Some(
                ossl_associate_connection
                    as unsafe extern "C" fn(*mut Curl_easy, *mut connectdata, i32) -> (),
            ),
            disassociate_connection: Some(
                ossl_disassociate_connection as unsafe extern "C" fn(*mut Curl_easy, i32) -> (),
            ),
        };
        init
    }
};
