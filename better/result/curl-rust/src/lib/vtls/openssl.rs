
use :: libc;
extern "C" {
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
    fn recv(__fd: i32, __buf: *mut core::ffi::c_void, __n: u64, __flags: i32) -> i64;
    fn __errno_location() -> *mut i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memcmp(_: *const core::ffi::c_void, _: *const core::ffi::c_void, _: u64) -> i32;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strncpy(_: *mut i8, _: *const i8, _: u64) -> *mut i8;
    fn strlen(_: *const i8) -> u64;
    fn inet_pton(__af: i32, __cp: *const i8, __buf: *mut core::ffi::c_void) -> i32;
    fn EVP_MD_CTX_new() -> *mut crate::src::lib::vtls::openssl::evp_md_ctx_st;
    fn EVP_MD_CTX_free(ctx: *mut crate::src::lib::vtls::openssl::evp_md_ctx_st);
    fn EVP_DigestUpdate(
        ctx: *mut crate::src::lib::vtls::openssl::evp_md_ctx_st,
        d: *const core::ffi::c_void,
        cnt: u64,
    ) -> i32;
    fn EVP_DigestFinal_ex(
        ctx: *mut crate::src::lib::vtls::openssl::evp_md_ctx_st,
        md: *mut u8,
        s: *mut u32,
    ) -> i32;
    fn EVP_DigestInit(
        ctx: *mut crate::src::lib::vtls::openssl::evp_md_ctx_st,
        type_0: *const crate::src::lib::vtls::openssl::evp_md_st,
    ) -> i32;
    fn EVP_sha1() -> *const crate::src::lib::vtls::openssl::evp_md_st;
    fn EVP_sha256() -> *const crate::src::lib::vtls::openssl::evp_md_st;
    fn EVP_PKEY_id(pkey: *const crate::src::lib::vtls::openssl::evp_pkey_st) -> i32;
    fn EVP_PKEY_get0_RSA(
        pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> *mut crate::src::lib::vtls::openssl::rsa_st;
    fn EVP_PKEY_get1_RSA(
        pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> *mut crate::src::lib::vtls::openssl::rsa_st;
    fn EVP_PKEY_get0_DSA(
        pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> *mut crate::src::lib::vtls::openssl::dsa_st;
    fn EVP_PKEY_get0_DH(
        pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> *mut crate::src::lib::vtls::openssl::dh_st;
    fn EVP_PKEY_free(pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st);
    fn EVP_PKEY_copy_parameters(
        to: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
        from: *const crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> i32;
    fn SSL_alert_desc_string_long(value: i32) -> *const i8;
    fn SSL_CTX_set_msg_callback(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        cb: Option<
            unsafe extern "C" fn(
                _: i32,
                _: i32,
                _: i32,
                _: *const core::ffi::c_void,
                _: u64,
                _: *mut crate::src::lib::vtls::openssl::ssl_st,
                _: *mut core::ffi::c_void,
            ) -> (),
        >,
    );
    fn SSL_CTX_new(
        meth: *const crate::src::lib::vtls::openssl::ssl_method_st,
    ) -> *mut crate::src::lib::vtls::openssl::ssl_ctx_st;
    fn TLS_client_method() -> *const crate::src::lib::vtls::openssl::ssl_method_st;
    fn SSL_pending(s: *const crate::src::lib::vtls::openssl::ssl_st) -> i32;
    fn SSL_get_shutdown(ssl: *const crate::src::lib::vtls::openssl::ssl_st) -> i32;
    fn d2i_PrivateKey_bio(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        a: *mut *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> *mut crate::src::lib::vtls::openssl::evp_pkey_st;
    fn OPENSSL_init_ssl(
        opts: u64,
        settings: *const crate::src::lib::vtls::openssl::ossl_init_settings_st,
    ) -> i32;
    fn SSL_CTX_set_options(ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st, op: u64) -> u64;
    fn SSL_CTX_set_next_proto_select_cb(
        s: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        cb: Option<
            unsafe extern "C" fn(
                _: *mut crate::src::lib::vtls::openssl::ssl_st,
                _: *mut *mut u8,
                _: *mut u8,
                _: *const u8,
                _: u32,
                _: *mut core::ffi::c_void,
            ) -> i32,
        >,
        arg: *mut core::ffi::c_void,
    );
    fn SSL_CTX_set_alpn_protos(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        protos: *const u8,
        protos_len: u32,
    ) -> i32;
    fn SSL_CTX_set_default_passwd_cb_userdata(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        u: *mut core::ffi::c_void,
    );
    fn SSL_CTX_set_default_passwd_cb(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        cb: Option<
            unsafe extern "C" fn(_: *mut i8, _: i32, _: i32, _: *mut core::ffi::c_void) -> i32,
        >,
    );
    fn PEM_read_bio_X509_AUX(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        x: *mut *mut crate::src::lib::vtls::openssl::x509_st,
        cb: Option<
            unsafe extern "C" fn(_: *mut i8, _: i32, _: i32, _: *mut core::ffi::c_void) -> i32,
        >,
        u: *mut core::ffi::c_void,
    ) -> *mut crate::src::lib::vtls::openssl::x509_st;
    fn SSL_CTX_use_certificate_chain_file(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        file: *const i8,
    ) -> i32;
    fn d2i_X509_bio(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        x509: *mut *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::x509_st;
    fn SSL_CTX_use_certificate_file(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        file: *const i8,
        type_0: i32,
    ) -> i32;
    fn SSL_CTX_use_certificate(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> i32;
    fn SSL_CTX_add_client_CA(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> i32;
    fn OPENSSL_sk_pop(st: *mut crate::src::lib::vtls::openssl::stack_st) -> *mut core::ffi::c_void;
    fn PEM_read_bio_PrivateKey(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        x: *mut *mut crate::src::lib::vtls::openssl::evp_pkey_st,
        cb: Option<
            unsafe extern "C" fn(_: *mut i8, _: i32, _: i32, _: *mut core::ffi::c_void) -> i32,
        >,
        u: *mut core::ffi::c_void,
    ) -> *mut crate::src::lib::vtls::openssl::evp_pkey_st;
    fn SSL_CTX_use_PrivateKey_file(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        file: *const i8,
        type_0: i32,
    ) -> i32;
    fn SSL_CTX_set_ciphersuites(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        str: *const i8,
    ) -> i32;
    fn SSL_CTX_use_PrivateKey(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    ) -> i32;
    fn SSL_get_certificate(
        ssl: *const crate::src::lib::vtls::openssl::ssl_st,
    ) -> *mut crate::src::lib::vtls::openssl::x509_st;
    fn RSA_flags(r: *const crate::src::lib::vtls::openssl::rsa_st) -> i32;
    fn RSA_free(r: *mut crate::src::lib::vtls::openssl::rsa_st);
    fn SSL_get_privatekey(
        ssl: *const crate::src::lib::vtls::openssl::ssl_st,
    ) -> *mut crate::src::lib::vtls::openssl::evp_pkey_st;
    fn SSL_CTX_check_private_key(ctx: *const crate::src::lib::vtls::openssl::ssl_ctx_st) -> i32;
    fn SSL_CTX_set_post_handshake_auth(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        val: i32,
    );
    fn SSL_CTX_set_srp_username(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        name: *mut i8,
    ) -> i32;
    fn SSL_CTX_set_srp_password(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        password: *mut i8,
    ) -> i32;
    fn SSL_CTX_set_cipher_list(
        _: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        str: *const i8,
    ) -> i32;
    fn PEM_X509_INFO_read_bio(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        sk: *mut crate::src::lib::vtls::openssl::stack_st_X509_INFO,
        cb: Option<
            unsafe extern "C" fn(_: *mut i8, _: i32, _: i32, _: *mut core::ffi::c_void) -> i32,
        >,
        u: *mut core::ffi::c_void,
    ) -> *mut crate::src::lib::vtls::openssl::stack_st_X509_INFO;
    fn X509_STORE_add_cert(
        ctx: *mut crate::src::lib::vtls::openssl::x509_store_st,
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> i32;
    fn X509_STORE_add_crl(
        ctx: *mut crate::src::lib::vtls::openssl::x509_store_st,
        x: *mut crate::src::lib::vtls::openssl::X509_crl_st,
    ) -> i32;
    fn OPENSSL_sk_pop_free(
        st: *mut crate::src::lib::vtls::openssl::stack_st,
        func: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    );
    fn X509_INFO_free(a: *mut crate::src::lib::vtls::openssl::X509_info_st);
    fn SSL_CTX_load_verify_locations(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        CAfile: *const i8,
        CApath: *const i8,
    ) -> i32;
    fn X509_STORE_add_lookup(
        v: *mut crate::src::lib::vtls::openssl::x509_store_st,
        m: *mut crate::src::lib::vtls::openssl::x509_lookup_method_st,
    ) -> *mut crate::src::lib::vtls::openssl::x509_lookup_st;
    fn X509_LOOKUP_file() -> *mut crate::src::lib::vtls::openssl::x509_lookup_method_st;
    fn X509_load_crl_file(
        ctx: *mut crate::src::lib::vtls::openssl::x509_lookup_st,
        file: *const i8,
        type_0: i32,
    ) -> i32;
    fn X509_STORE_set_flags(
        ctx: *mut crate::src::lib::vtls::openssl::x509_store_st,
        flags: u64,
    ) -> i32;
    fn SSL_CTX_set_verify(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        mode: i32,
        callback: Option<
            unsafe extern "C" fn(
                _: i32,
                _: *mut crate::src::lib::vtls::openssl::x509_store_ctx_st,
            ) -> i32,
        >,
    );
    fn SSL_CTX_set_keylog_callback(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        cb: Option<
            unsafe extern "C" fn(
                _: *const crate::src::lib::vtls::openssl::ssl_st,
                _: *const i8,
            ) -> (),
        >,
    );
    fn SSL_CTX_ctrl(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        cmd: i32,
        larg: i64,
        parg: *mut core::ffi::c_void,
    ) -> i64;
    fn SSL_CTX_sess_set_new_cb(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
        new_session_cb: Option<
            unsafe extern "C" fn(
                _: *mut crate::src::lib::vtls::openssl::ssl_st,
                _: *mut crate::src::lib::vtls::openssl::ssl_session_st,
            ) -> i32,
        >,
    );
    fn SSL_get_ex_data(
        ssl: *const crate::src::lib::vtls::openssl::ssl_st,
        idx: i32,
    ) -> *mut core::ffi::c_void;
    fn SSL_new(
        ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    ) -> *mut crate::src::lib::vtls::openssl::ssl_st;
    fn SSL_set_session(
        to: *mut crate::src::lib::vtls::openssl::ssl_st,
        session: *mut crate::src::lib::vtls::openssl::ssl_session_st,
    ) -> i32;
    fn SSL_set_bio(
        s: *mut crate::src::lib::vtls::openssl::ssl_st,
        rbio: *mut crate::src::lib::vtls::openssl::bio_st,
        wbio: *mut crate::src::lib::vtls::openssl::bio_st,
    );
    fn BIO_f_ssl() -> *const crate::src::lib::vtls::openssl::bio_method_st;
    fn SSL_set_fd(s: *mut crate::src::lib::vtls::openssl::ssl_st, fd: i32) -> i32;
    fn SSL_connect(ssl: *mut crate::src::lib::vtls::openssl::ssl_st) -> i32;
    fn SSL_get_version(s: *const crate::src::lib::vtls::openssl::ssl_st) -> *const i8;
    fn SSL_CIPHER_get_name(c: *const crate::src::lib::vtls::openssl::ssl_cipher_st) -> *const i8;
    fn SSL_get_current_cipher(
        s: *const crate::src::lib::vtls::openssl::ssl_st,
    ) -> *const crate::src::lib::vtls::openssl::ssl_cipher_st;
    fn SSL_get0_alpn_selected(
        ssl: *const crate::src::lib::vtls::openssl::ssl_st,
        data: *mut *const u8,
        len: *mut u32,
    );
    fn X509_get_version(x: *const crate::src::lib::vtls::openssl::x509_st) -> i64;
    fn X509_get_serialNumber(
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::asn1_string_st;
    fn BIO_puts(bp: *mut crate::src::lib::vtls::openssl::bio_st, buf: *const i8) -> i32;
    fn X509_get0_signature(
        psig: *mut *const crate::src::lib::vtls::openssl::asn1_string_st,
        palg: *mut *const crate::src::lib::vtls::openssl::X509_algor_st,
        x: *const crate::src::lib::vtls::openssl::x509_st,
    );
    fn X509_PUBKEY_get0_param(
        ppkalg: *mut *mut crate::src::lib::vtls::openssl::asn1_object_st,
        pk: *mut *const u8,
        ppklen: *mut i32,
        pa: *mut *mut crate::src::lib::vtls::openssl::X509_algor_st,
        pub_0: *mut crate::src::lib::vtls::openssl::X509_pubkey_st,
    ) -> i32;
    fn i2a_ASN1_OBJECT(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        a: *const crate::src::lib::vtls::openssl::asn1_object_st,
    ) -> i32;
    fn X509_EXTENSION_get_object(
        ex: *mut crate::src::lib::vtls::openssl::X509_extension_st,
    ) -> *mut crate::src::lib::vtls::openssl::asn1_object_st;
    fn i2t_ASN1_OBJECT(
        buf: *mut i8,
        buf_len: i32,
        a: *const crate::src::lib::vtls::openssl::asn1_object_st,
    ) -> i32;
    fn X509_get0_extensions(
        x: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *const crate::src::lib::vtls::openssl::stack_st_X509_EXTENSION;
    fn ASN1_STRING_print(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        v: *const crate::src::lib::vtls::openssl::asn1_string_st,
    ) -> i32;
    fn X509_EXTENSION_get_data(
        ne: *mut crate::src::lib::vtls::openssl::X509_extension_st,
    ) -> *mut crate::src::lib::vtls::openssl::asn1_string_st;
    fn X509_get_pubkey(
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::evp_pkey_st;
    fn RSA_get0_key(
        r: *const crate::src::lib::vtls::openssl::rsa_st,
        n: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        e: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        d: *mut *const crate::src::lib::vtls::openssl::bignum_st,
    );
    fn BN_num_bits(a: *const crate::src::lib::vtls::openssl::bignum_st) -> i32;
    fn DSA_get0_pqg(
        d: *const crate::src::lib::vtls::openssl::dsa_st,
        p: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        q: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        g: *mut *const crate::src::lib::vtls::openssl::bignum_st,
    );
    fn DSA_get0_key(
        d: *const crate::src::lib::vtls::openssl::dsa_st,
        pub_key: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        priv_key: *mut *const crate::src::lib::vtls::openssl::bignum_st,
    );
    fn DH_get0_pqg(
        dh: *const crate::src::lib::vtls::openssl::dh_st,
        p: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        q: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        g: *mut *const crate::src::lib::vtls::openssl::bignum_st,
    );
    fn DH_get0_key(
        dh: *const crate::src::lib::vtls::openssl::dh_st,
        pub_key: *mut *const crate::src::lib::vtls::openssl::bignum_st,
        priv_key: *mut *const crate::src::lib::vtls::openssl::bignum_st,
    );
    fn BN_print(
        bio: *mut crate::src::lib::vtls::openssl::bio_st,
        a: *const crate::src::lib::vtls::openssl::bignum_st,
    ) -> i32;
    fn BIO_printf(
        bio: *mut crate::src::lib::vtls::openssl::bio_st,
        format: *const i8,
        _: ...
    ) -> i32;
    fn PEM_write_bio_X509(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        x: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> i32;
    fn X509_get0_notBefore(
        x: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *const crate::src::lib::vtls::openssl::asn1_string_st;
    fn ASN1_TIME_print(
        fp: *mut crate::src::lib::vtls::openssl::bio_st,
        a: *const crate::src::lib::vtls::openssl::asn1_string_st,
    ) -> i32;
    fn X509_get0_notAfter(
        x: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *const crate::src::lib::vtls::openssl::asn1_string_st;
    fn X509_get_ext_d2i(
        x: *const crate::src::lib::vtls::openssl::x509_st,
        nid: i32,
        crit: *mut i32,
        idx: *mut i32,
    ) -> *mut core::ffi::c_void;
    fn X509_NAME_get_index_by_NID(
        name: *mut crate::src::lib::vtls::openssl::X509_name_st,
        nid: i32,
        lastpos: i32,
    ) -> i32;
    fn ASN1_STRING_type(x: *const crate::src::lib::vtls::openssl::asn1_string_st) -> i32;
    fn ASN1_STRING_length(x: *const crate::src::lib::vtls::openssl::asn1_string_st) -> i32;
    fn CRYPTO_malloc(num: u64, file: *const i8, line: i32) -> *mut core::ffi::c_void;
    fn ASN1_STRING_get0_data(x: *const crate::src::lib::vtls::openssl::asn1_string_st)
        -> *const u8;
    fn ASN1_STRING_to_UTF8(
        out: *mut *mut u8,
        in_0: *const crate::src::lib::vtls::openssl::asn1_string_st,
    ) -> i32;
    fn X509_NAME_ENTRY_get_data(
        ne: *const crate::src::lib::vtls::openssl::X509_name_entry_st,
    ) -> *mut crate::src::lib::vtls::openssl::asn1_string_st;
    fn X509_NAME_get_entry(
        name: *const crate::src::lib::vtls::openssl::X509_name_st,
        loc: i32,
    ) -> *mut crate::src::lib::vtls::openssl::X509_name_entry_st;
    fn X509_get_subject_name(
        a: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::X509_name_st;
    fn CRYPTO_free(ptr: *mut core::ffi::c_void, file: *const i8, line: i32);
    fn X509_NAME_print_ex(
        out: *mut crate::src::lib::vtls::openssl::bio_st,
        nm: *const crate::src::lib::vtls::openssl::X509_name_st,
        indent: i32,
        flags: u64,
    ) -> i32;
    fn BIO_s_mem() -> *const crate::src::lib::vtls::openssl::bio_method_st;
    fn X509_get_issuer_name(
        a: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::X509_name_st;
    fn BIO_new_mem_buf(
        buf: *const core::ffi::c_void,
        len: i32,
    ) -> *mut crate::src::lib::vtls::openssl::bio_st;
    fn BIO_new(
        type_0: *const crate::src::lib::vtls::openssl::bio_method_st,
    ) -> *mut crate::src::lib::vtls::openssl::bio_st;
    fn BIO_s_file() -> *const crate::src::lib::vtls::openssl::bio_method_st;
    fn BIO_ctrl(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        cmd: i32,
        larg: i64,
        parg: *mut core::ffi::c_void,
    ) -> i64;
    fn PEM_read_bio_X509(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        x: *mut *mut crate::src::lib::vtls::openssl::x509_st,
        cb: Option<
            unsafe extern "C" fn(_: *mut i8, _: i32, _: i32, _: *mut core::ffi::c_void) -> i32,
        >,
        u: *mut core::ffi::c_void,
    ) -> *mut crate::src::lib::vtls::openssl::x509_st;
    fn BIO_free(a: *mut crate::src::lib::vtls::openssl::bio_st) -> i32;
    fn SSL_get_verify_result(ssl: *const crate::src::lib::vtls::openssl::ssl_st) -> i64;
    fn X509_verify_cert_error_string(n: i64) -> *const i8;
    fn SSL_ctrl(
        ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
        cmd: i32,
        larg: i64,
        parg: *mut core::ffi::c_void,
    ) -> i64;
    fn SSL_get_peer_cert_chain(
        s: *const crate::src::lib::vtls::openssl::ssl_st,
    ) -> *mut crate::src::lib::vtls::openssl::stack_st_X509;
    fn SSL_CTX_get_cert_store(
        _: *const crate::src::lib::vtls::openssl::ssl_ctx_st,
    ) -> *mut crate::src::lib::vtls::openssl::x509_store_st;
    fn SSL_get_peer_certificate(
        s: *const crate::src::lib::vtls::openssl::ssl_st,
    ) -> *mut crate::src::lib::vtls::openssl::x509_st;
    fn OPENSSL_sk_num(_: *const crate::src::lib::vtls::openssl::stack_st) -> i32;
    fn OPENSSL_sk_value(
        _: *const crate::src::lib::vtls::openssl::stack_st,
        _: i32,
    ) -> *mut core::ffi::c_void;
    fn i2d_X509_PUBKEY(
        a: *mut crate::src::lib::vtls::openssl::X509_pubkey_st,
        out: *mut *mut u8,
    ) -> i32;
    fn X509_get_X509_PUBKEY(
        x: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::X509_pubkey_st;
    fn X509_free(a: *mut crate::src::lib::vtls::openssl::x509_st);
    fn SSL_write(
        ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
        buf: *const core::ffi::c_void,
        num: i32,
    ) -> i32;
    fn SSL_get_error(s: *const crate::src::lib::vtls::openssl::ssl_st, ret_code: i32) -> i32;
    fn OpenSSL_version_num() -> u64;
    fn SSL_read(
        ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
        buf: *mut core::ffi::c_void,
        num: i32,
    ) -> i32;
    fn SSL_shutdown(s: *mut crate::src::lib::vtls::openssl::ssl_st) -> i32;
    fn SSL_set_connect_state(s: *mut crate::src::lib::vtls::openssl::ssl_st);
    fn SSL_free(ssl: *mut crate::src::lib::vtls::openssl::ssl_st);
    fn SSL_CTX_free(_: *mut crate::src::lib::vtls::openssl::ssl_ctx_st);
    fn SSL_SESSION_free(ses: *mut crate::src::lib::vtls::openssl::ssl_session_st);
    fn SSL_set_ex_data(
        ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
        idx: i32,
        data: *mut core::ffi::c_void,
    ) -> i32;
    fn CRYPTO_get_ex_new_index(
        class_index: i32,
        argl: i64,
        argp: *mut core::ffi::c_void,
        new_func: Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: *mut core::ffi::c_void,
                _: *mut crate::src::lib::vtls::openssl::crypto_ex_data_st,
                _: i32,
                _: i64,
                _: *mut core::ffi::c_void,
            ) -> (),
        >,
        dup_func: Option<
            unsafe extern "C" fn(
                _: *mut crate::src::lib::vtls::openssl::crypto_ex_data_st,
                _: *const crate::src::lib::vtls::openssl::crypto_ex_data_st,
                _: *mut core::ffi::c_void,
                _: i32,
                _: i64,
                _: *mut core::ffi::c_void,
            ) -> i32,
        >,
        free_func: Option<
            unsafe extern "C" fn(
                _: *mut core::ffi::c_void,
                _: *mut core::ffi::c_void,
                _: *mut crate::src::lib::vtls::openssl::crypto_ex_data_st,
                _: i32,
                _: i64,
                _: *mut core::ffi::c_void,
            ) -> (),
        >,
    ) -> i32;
    fn RAND_bytes(buf: *mut u8, num: i32) -> i32;
    fn RAND_add(buf: *const core::ffi::c_void, num: i32, randomness: f64);
    fn RAND_load_file(file: *const i8, max_bytes: i64) -> i32;
    fn RAND_file_name(file: *mut i8, num: u64) -> *const i8;
    fn RAND_status() -> i32;
    fn GENERAL_NAMES_free(a: *mut crate::src::lib::vtls::openssl::stack_st_GENERAL_NAME);
    fn X509V3_EXT_print(
        out: *mut crate::src::lib::vtls::openssl::bio_st,
        ext: *mut crate::src::lib::vtls::openssl::X509_extension_st,
        flag: u64,
        indent: i32,
    ) -> i32;
    fn X509_check_issued(
        issuer: *mut crate::src::lib::vtls::openssl::x509_st,
        subject: *mut crate::src::lib::vtls::openssl::x509_st,
    ) -> i32;
    fn ERR_get_error() -> u64;
    fn ERR_peek_error() -> u64;
    fn ERR_peek_last_error() -> u64;
    fn ERR_clear_error();
    fn ERR_error_string_n(e: u64, buf: *mut i8, len: u64);
    fn PKCS12_free(a: *mut crate::src::lib::vtls::openssl::PKCS12_st);
    fn PKCS12_PBE_add();
    fn PKCS12_parse(
        p12: *mut crate::src::lib::vtls::openssl::PKCS12_st,
        pass: *const i8,
        pkey: *mut *mut crate::src::lib::vtls::openssl::evp_pkey_st,
        cert: *mut *mut crate::src::lib::vtls::openssl::x509_st,
        ca: *mut *mut crate::src::lib::vtls::openssl::stack_st_X509,
    ) -> i32;
    fn d2i_PKCS12_bio(
        bp: *mut crate::src::lib::vtls::openssl::bio_st,
        p12: *mut *mut crate::src::lib::vtls::openssl::PKCS12_st,
    ) -> *mut crate::src::lib::vtls::openssl::PKCS12_st;
    fn OCSP_cert_to_id(
        dgst: *const crate::src::lib::vtls::openssl::evp_md_st,
        subject: *const crate::src::lib::vtls::openssl::x509_st,
        issuer: *const crate::src::lib::vtls::openssl::x509_st,
    ) -> *mut crate::src::lib::vtls::openssl::ocsp_cert_id_st;
    fn OCSP_response_status(resp: *mut crate::src::lib::vtls::openssl::ocsp_response_st) -> i32;
    fn OCSP_response_get1_basic(
        resp: *mut crate::src::lib::vtls::openssl::ocsp_response_st,
    ) -> *mut crate::src::lib::vtls::openssl::ocsp_basic_response_st;
    fn OCSP_resp_find_status(
        bs: *mut crate::src::lib::vtls::openssl::ocsp_basic_response_st,
        id: *mut crate::src::lib::vtls::openssl::ocsp_cert_id_st,
        status: *mut i32,
        reason: *mut i32,
        revtime: *mut *mut crate::src::lib::vtls::openssl::asn1_string_st,
        thisupd: *mut *mut crate::src::lib::vtls::openssl::asn1_string_st,
        nextupd: *mut *mut crate::src::lib::vtls::openssl::asn1_string_st,
    ) -> i32;
    fn OCSP_check_validity(
        thisupd: *mut crate::src::lib::vtls::openssl::asn1_string_st,
        nextupd: *mut crate::src::lib::vtls::openssl::asn1_string_st,
        sec: i64,
        maxsec: i64,
    ) -> i32;
    fn OCSP_BASICRESP_free(a: *mut crate::src::lib::vtls::openssl::ocsp_basic_response_st);
    fn OCSP_RESPONSE_free(a: *mut crate::src::lib::vtls::openssl::ocsp_response_st);
    fn d2i_OCSP_RESPONSE(
        a: *mut *mut crate::src::lib::vtls::openssl::ocsp_response_st,
        in_0: *mut *const u8,
        len: i64,
    ) -> *mut crate::src::lib::vtls::openssl::ocsp_response_st;
    fn OCSP_CERTID_free(a: *mut crate::src::lib::vtls::openssl::ocsp_cert_id_st);
    fn OCSP_response_status_str(s: i64) -> *const i8;
    fn OCSP_cert_status_str(s: i64) -> *const i8;
    fn OCSP_basic_verify(
        bs: *mut crate::src::lib::vtls::openssl::ocsp_basic_response_st,
        certs: *mut crate::src::lib::vtls::openssl::stack_st_X509,
        st: *mut crate::src::lib::vtls::openssl::x509_store_st,
        flags: u64,
    ) -> i32;
    fn OCSP_crl_reason_str(s: i64) -> *const i8;
    fn UI_get0_user_data(ui: *mut crate::src::lib::vtls::openssl::ui_st) -> *mut core::ffi::c_void;
    fn UI_OpenSSL() -> *mut crate::src::lib::vtls::openssl::ui_method_st;
    fn UI_method_set_opener(
        method: *mut crate::src::lib::vtls::openssl::ui_method_st,
        opener: Option<unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::ui_st) -> i32>,
    ) -> i32;
    fn ENGINE_ctrl_cmd(
        e: *mut crate::src::lib::vtls::openssl::engine_st,
        cmd_name: *const i8,
        i: i64,
        p: *mut core::ffi::c_void,
        f: Option<unsafe extern "C" fn() -> ()>,
        cmd_optional: i32,
    ) -> i32;
    fn ENGINE_ctrl(
        e: *mut crate::src::lib::vtls::openssl::engine_st,
        cmd: i32,
        i: i64,
        p: *mut core::ffi::c_void,
        f: Option<unsafe extern "C" fn() -> ()>,
    ) -> i32;
    fn UI_method_get_opener(
        method: *const crate::src::lib::vtls::openssl::ui_method_st,
    ) -> Option<unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::ui_st) -> i32>;
    fn UI_method_set_closer(
        method: *mut crate::src::lib::vtls::openssl::ui_method_st,
        closer: Option<unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::ui_st) -> i32>,
    ) -> i32;
    fn UI_method_get_closer(
        method: *const crate::src::lib::vtls::openssl::ui_method_st,
    ) -> Option<unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::ui_st) -> i32>;
    fn UI_method_set_reader(
        method: *mut crate::src::lib::vtls::openssl::ui_method_st,
        reader: Option<
            unsafe extern "C" fn(
                _: *mut crate::src::lib::vtls::openssl::ui_st,
                _: *mut crate::src::lib::vtls::openssl::ui_string_st,
            ) -> i32,
        >,
    ) -> i32;
    fn UI_set_result(
        ui: *mut crate::src::lib::vtls::openssl::ui_st,
        uis: *mut crate::src::lib::vtls::openssl::ui_string_st,
        result: *const i8,
    ) -> i32;
    fn UI_method_get_reader(
        method: *const crate::src::lib::vtls::openssl::ui_method_st,
    ) -> Option<
        unsafe extern "C" fn(
            _: *mut crate::src::lib::vtls::openssl::ui_st,
            _: *mut crate::src::lib::vtls::openssl::ui_string_st,
        ) -> i32,
    >;
    fn UI_method_set_writer(
        method: *mut crate::src::lib::vtls::openssl::ui_method_st,
        writer: Option<
            unsafe extern "C" fn(
                _: *mut crate::src::lib::vtls::openssl::ui_st,
                _: *mut crate::src::lib::vtls::openssl::ui_string_st,
            ) -> i32,
        >,
    ) -> i32;
    fn UI_get_string_type(uis: *mut crate::src::lib::vtls::openssl::ui_string_st) -> u32;
    fn UI_get_input_flags(uis: *mut crate::src::lib::vtls::openssl::ui_string_st) -> i32;
    fn UI_method_get_writer(
        method: *const crate::src::lib::vtls::openssl::ui_method_st,
    ) -> Option<
        unsafe extern "C" fn(
            _: *mut crate::src::lib::vtls::openssl::ui_st,
            _: *mut crate::src::lib::vtls::openssl::ui_string_st,
        ) -> i32,
    >;
    fn UI_destroy_method(ui_method: *mut crate::src::lib::vtls::openssl::ui_method_st);
    fn UI_create_method(name: *const i8) -> *mut crate::src::lib::vtls::openssl::ui_method_st;
    fn ENGINE_by_id(id: *const i8) -> *mut crate::src::lib::vtls::openssl::engine_st;
    fn ENGINE_free(e: *mut crate::src::lib::vtls::openssl::engine_st) -> i32;
    fn ENGINE_get_next(
        e: *mut crate::src::lib::vtls::openssl::engine_st,
    ) -> *mut crate::src::lib::vtls::openssl::engine_st;
    fn ENGINE_get_id(e: *const crate::src::lib::vtls::openssl::engine_st) -> *const i8;
    fn ENGINE_get_first() -> *mut crate::src::lib::vtls::openssl::engine_st;
    fn ENGINE_init(e: *mut crate::src::lib::vtls::openssl::engine_st) -> i32;
    fn ENGINE_finish(e: *mut crate::src::lib::vtls::openssl::engine_st) -> i32;
    fn ENGINE_load_private_key(
        e: *mut crate::src::lib::vtls::openssl::engine_st,
        key_id: *const i8,
        ui_method: *mut crate::src::lib::vtls::openssl::ui_method_st,
        callback_data: *mut core::ffi::c_void,
    ) -> *mut crate::src::lib::vtls::openssl::evp_pkey_st;
    fn ENGINE_set_default(e: *mut crate::src::lib::vtls::openssl::engine_st, flags: u32) -> i32;
}
pub use crate::src::lib::altsvc::altsvcinfo;
pub use crate::src::lib::asyn_thread::thread_data;
pub use crate::src::lib::asyn_thread::Curl_share;
pub use crate::src::lib::conncache::Gsasl_session;
pub use crate::src::lib::connect::Curl_conncontrol;
pub use crate::src::lib::connect::Curl_timeleft;
pub use crate::src::lib::content_encoding::contenc_writer;
pub use crate::src::lib::easy::hsts;
pub use crate::src::lib::easy::Curl_cfree;
pub use crate::src::lib::easy::Curl_cmalloc;
pub use crate::src::lib::escape::Gsasl;
pub use crate::src::lib::ftp::http_connect_state;
pub use crate::src::lib::hostcheck::Curl_cert_hostcheck;
pub use crate::src::lib::http2::curl_pushheaders;
pub use crate::src::lib::mprintf::curl_msnprintf;
pub use crate::src::lib::mqtt::_IO_codecvt;
pub use crate::src::lib::multi::Curl_multiuse_state;
pub use crate::src::lib::multi::Curl_set_in_callback;
pub use crate::src::lib::openldap::ldapconninfo;
pub use crate::src::lib::openldap::ldapreqinfo;
pub use crate::src::lib::select::Curl_socket_check;
pub use crate::src::lib::select::Curl_wait_ms;
pub use crate::src::lib::sendf::Curl_debug;
pub use crate::src::lib::sendf::Curl_failf;
pub use crate::src::lib::sendf::Curl_infof;
pub use crate::src::lib::slist::curl_slist_append;
pub use crate::src::lib::slist::curl_slist_free_all;
pub use crate::src::lib::smb::smb_request;
pub use crate::src::lib::speedcheck::nghttp2_session;
pub use crate::src::lib::strcase::Curl_strcasecompare;
pub use crate::src::lib::strcase::Curl_strncasecompare;
pub use crate::src::lib::strcase::Curl_strntolower;
pub use crate::src::lib::strerror::Curl_strerror;
pub use crate::src::lib::telnet::TELNET;
pub use crate::src::lib::tftp::tftp_state_data;
pub use crate::src::lib::timeval::Curl_now;
pub use crate::src::lib::urlapi::psl_ctx_st;
pub use crate::src::lib::urlapi::Curl_URL;
pub use crate::src::lib::vtls::keylog::Curl_tls_keylog_close;
pub use crate::src::lib::vtls::keylog::Curl_tls_keylog_enabled;
pub use crate::src::lib::vtls::keylog::Curl_tls_keylog_open;
pub use crate::src::lib::vtls::keylog::Curl_tls_keylog_write_line;
pub use crate::src::lib::vtls::vtls::Curl_none_false_start;
pub use crate::src::lib::vtls::vtls::Curl_pin_peer_pubkey;
pub use crate::src::lib::vtls::vtls::Curl_ssl_addsessionid;
pub use crate::src::lib::vtls::vtls::Curl_ssl_delsessionid;
pub use crate::src::lib::vtls::vtls::Curl_ssl_getsessionid;
pub use crate::src::lib::vtls::vtls::Curl_ssl_getsock;
pub use crate::src::lib::vtls::vtls::Curl_ssl_init_certinfo;
pub use crate::src::lib::vtls::vtls::Curl_ssl_push_certinfo_len;
pub use crate::src::lib::vtls::vtls::Curl_ssl_sessionid_lock;
pub use crate::src::lib::vtls::vtls::Curl_ssl_sessionid_unlock;
pub use crate::src::lib::warnless::curlx_uztosi;
pub use crate::src::src::tool_cb_rea::_IO_wide_data;
pub use crate::src::src::tool_msgs::_IO_marker;
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
pub type pid_t = i32;
pub type ssize_t = i64;
pub type time_t = i64;
pub type size_t = u64;
pub type int32_t = i32;
pub type socklen_t = u32;
pub type sa_family_t = u16;
pub type sockaddr = crate::src::lib::http2::sockaddr;
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
pub type curl_socklen_t = u32;
pub type curl_off_t = i64;
pub type _IO_FILE = crate::src::lib::http2::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::lib::http2::_IO_FILE;
pub type Curl_easy = crate::src::lib::http2::Curl_easy;
pub type curl_tlssessioninfo = crate::src::lib::http2::curl_tlssessioninfo;
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
pub type PureInfo = crate::src::lib::http2::PureInfo;
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
pub type curl_certinfo = crate::src::lib::http2::curl_certinfo;
pub type curl_slist = crate::src::lib::http2::curl_slist;
pub type WildcardData = crate::src::lib::http2::WildcardData;
pub type wildcard_dtor<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type Curl_llist = crate::src::lib::http2::Curl_llist;
pub type Curl_llist_dtor<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> (),
>;
pub type Curl_llist_element = crate::src::lib::http2::Curl_llist_element;
pub type wildcard_states = u32;
pub const CURLWC_DONE: wildcard_states = 7;
pub const CURLWC_ERROR: wildcard_states = 6;
pub const CURLWC_SKIP: wildcard_states = 5;
pub const CURLWC_CLEAN: wildcard_states = 4;
pub const CURLWC_DOWNLOADING: wildcard_states = 3;
pub const CURLWC_MATCHING: wildcard_states = 2;
pub const CURLWC_INIT: wildcard_states = 1;
pub const CURLWC_CLEAR: wildcard_states = 0;
pub type UrlState = crate::src::lib::http2::UrlState;
pub type dynamically_allocated_data = crate::src::lib::http2::dynamically_allocated_data;
pub type trailers_state = u32;
pub const TRAILERS_DONE: trailers_state = 3;
pub const TRAILERS_SENDING: trailers_state = 2;
pub const TRAILERS_INITIALIZED: trailers_state = 1;
pub const TRAILERS_NONE: trailers_state = 0;
pub type dynbuf = crate::src::lib::http2::dynbuf;
pub type Curl_HttpReq = u32;
pub const HTTPREQ_HEAD: Curl_HttpReq = 5;
pub const HTTPREQ_PUT: Curl_HttpReq = 4;
pub const HTTPREQ_POST_MIME: Curl_HttpReq = 3;
pub const HTTPREQ_POST_FORM: Curl_HttpReq = 2;
pub const HTTPREQ_POST: Curl_HttpReq = 1;
pub const HTTPREQ_GET: Curl_HttpReq = 0;
pub type urlpieces = crate::src::lib::http2::urlpieces;
pub type CURLU = crate::src::lib::urlapi::Curl_URL;
pub type curl_read_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut i8>,
        _: u64,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u64,
>;
pub type time_node = crate::src::lib::http2::time_node;
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
pub type curltime = crate::src::lib::http2::curltime;
pub type Curl_tree = crate::src::lib::http2::Curl_tree;
pub type Curl_async = crate::src::lib::http2::Curl_async;
pub type Curl_dns_entry = crate::src::lib::http2::Curl_dns_entry;
pub type Curl_addrinfo = crate::src::lib::http2::Curl_addrinfo;
pub type auth = crate::src::lib::http2::auth;
pub type digestdata = crate::src::lib::http2::digestdata;
pub type tempbuf = crate::src::lib::http2::tempbuf;
pub type Curl_ssl_session = crate::src::lib::http2::Curl_ssl_session;
pub type ssl_primary_config = crate::src::lib::http2::ssl_primary_config;
pub type curl_blob = crate::src::lib::http2::curl_blob;
pub type conncache = crate::src::lib::http2::conncache;
pub type Curl_hash = crate::src::lib::http2::Curl_hash;
pub type Curl_hash_dtor<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type comp_function<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: u64,
    ) -> u64,
>;
pub type hash_function<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: u64, _: u64) -> u64>;
pub type Progress = crate::src::lib::http2::Progress;
pub type timediff_t = i64;
pub type CookieInfo = crate::src::lib::http2::CookieInfo;
pub type Cookie = crate::src::lib::http2::Cookie;
pub type UserDefined = crate::src::lib::http2::UserDefined;
pub type curl_trailer_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut Option<&'a2 mut crate::src::lib::http2::curl_slist>>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type multidone_func<'a1> = Option<
    unsafe extern "C" fn(_: Option<&'a1 mut crate::src::lib::http2::Curl_easy>, _: u32) -> i32,
>;
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
pub type curl_resolver_start_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type Curl_http2_dep = crate::src::lib::http2::Curl_http2_dep;
pub type curl_fnmatch_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: Option<&'a2 i8>,
        _: Option<&'a3 i8>,
    ) -> i32,
>;
pub type curl_chunk_end_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> i64>;
pub type curl_chunk_bgn_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 core::ffi::c_void>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: i32,
    ) -> i64,
>;
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
pub type curl_sshkeycallback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 crate::src::lib::http2::curl_khkey>,
        _: Option<&'a3 crate::src::lib::http2::curl_khkey>,
        _: u32,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type curl_khmatch = u32;
pub const CURLKHMATCH_LAST: curl_khmatch = 3;
pub const CURLKHMATCH_MISSING: curl_khmatch = 2;
pub const CURLKHMATCH_MISMATCH: curl_khmatch = 1;
pub const CURLKHMATCH_OK: curl_khmatch = 0;
pub type curl_khkey = crate::src::lib::http2::curl_khkey;
pub type curl_khtype = u32;
pub const CURLKHTYPE_ED25519: curl_khtype = 5;
pub const CURLKHTYPE_ECDSA: curl_khtype = 4;
pub const CURLKHTYPE_DSS: curl_khtype = 3;
pub const CURLKHTYPE_RSA: curl_khtype = 2;
pub const CURLKHTYPE_RSA1: curl_khtype = 1;
pub const CURLKHTYPE_UNKNOWN: curl_khtype = 0;
pub type CURL = crate::src::lib::http2::Curl_easy;
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
pub type ssl_general_config = crate::src::lib::http2::ssl_general_config;
pub type ssl_config_data = crate::src::lib::http2::ssl_config_data;
pub type CURL_TLSAUTH = u32;
pub const CURL_TLSAUTH_LAST: CURL_TLSAUTH = 2;
pub const CURL_TLSAUTH_SRP: CURL_TLSAUTH = 1;
pub const CURL_TLSAUTH_NONE: CURL_TLSAUTH = 0;
pub type curl_ssl_ctx_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> u32,
>;
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
pub type curl_mimepart = crate::src::lib::http2::curl_mimepart;
pub type mime_encoder_state = crate::src::lib::http2::mime_encoder_state;
pub type mime_encoder = crate::src::lib::http2::mime_encoder;
pub type mime_state = crate::src::lib::http2::mime_state;
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
pub type curl_free_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type curl_seek_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i64, _: i32) -> i32>;
pub type mimekind = u32;
pub const MIMEKIND_LAST: mimekind = 5;
pub const MIMEKIND_MULTIPART: mimekind = 4;
pub const MIMEKIND_CALLBACK: mimekind = 3;
pub const MIMEKIND_FILE: mimekind = 2;
pub const MIMEKIND_DATA: mimekind = 1;
pub const MIMEKIND_NONE: mimekind = 0;
pub type curl_mime = crate::src::lib::http2::curl_mime;
pub type curl_httppost = crate::src::lib::http2::curl_httppost;
pub type curl_hstswrite_callback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,
        _: Option<&'a3 mut crate::src::lib::http2::curl_index>,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curl_index = crate::src::lib::http2::curl_index;
pub type curl_hstsentry = crate::src::lib::http2::curl_hstsentry;
pub type CURLSTScode = u32;
pub const CURLSTS_FAIL: CURLSTScode = 2;
pub const CURLSTS_DONE: CURLSTScode = 1;
pub const CURLSTS_OK: CURLSTScode = 0;
pub type curl_hstsread_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::curl_hstsentry>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curl_conv_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut i8>, _: u64) -> u32>;
pub type curl_closesocket_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i32) -> i32>;
pub type curl_socket_t = i32;
pub type curl_opensocket_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: u32,
        _: Option<&'a2 mut crate::src::lib::http2::curl_sockaddr>,
    ) -> i32,
>;
pub type curl_sockaddr = crate::src::lib::http2::curl_sockaddr;
pub type curlsocktype = u32;
pub const CURLSOCKTYPE_LAST: curlsocktype = 2;
pub const CURLSOCKTYPE_ACCEPT: curlsocktype = 1;
pub const CURLSOCKTYPE_IPCXN: curlsocktype = 0;
pub type curl_sockopt_callback<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>, _: i32, _: u32) -> i32>;
pub type curl_ioctl_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: i32,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u32,
>;
pub type curlioerr = u32;
pub const CURLIOE_LAST: curlioerr = 3;
pub const CURLIOE_FAILRESTART: curlioerr = 2;
pub const CURLIOE_UNKNOWNCMD: curlioerr = 1;
pub const CURLIOE_OK: curlioerr = 0;
pub type curl_debug_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: u32,
        _: Option<&'a2 mut i8>,
        _: u64,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
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
pub type curl_xferinfo_callback<'a1> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: i64,
        _: i64,
        _: i64,
        _: i64,
    ) -> i32,
>;
pub type curl_progress_callback<'a1> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut core::ffi::c_void>,
        _: f64,
        _: f64,
        _: f64,
        _: f64,
    ) -> i32,
>;
pub type curl_write_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut i8>,
        _: u64,
        _: u64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> u64,
>;
pub type SingleRequest = crate::src::lib::http2::SingleRequest;
pub type dohdata = crate::src::lib::http2::dohdata;
pub type dnsprobe = crate::src::lib::http2::dnsprobe;
pub type C2RustUnnamed_0 = crate::src::lib::http2::C2RustUnnamed;
pub type SSHPROTO = crate::src::lib::http2::SSHPROTO;
pub type SMTP = crate::src::lib::http2::SMTP;
pub type curl_pp_transfer = u32;
pub const PPTRANSFER_NONE: curl_pp_transfer = 2;
pub const PPTRANSFER_INFO: curl_pp_transfer = 1;
pub const PPTRANSFER_BODY: curl_pp_transfer = 0;
pub type RTSP = crate::src::lib::http2::RTSP;
pub type HTTP = crate::src::lib::http2::HTTP;
pub type uint8_t = u8;
pub type uint32_t = u32;
pub type C2RustUnnamed_1 = u32;
pub const HTTPSEND_BODY: C2RustUnnamed_1 = 2;
pub const HTTPSEND_REQUEST: C2RustUnnamed_1 = 1;
pub const HTTPSEND_NADA: C2RustUnnamed_1 = 0;
pub type back = crate::src::lib::http2::back;
pub type POP3 = crate::src::lib::http2::POP3;
pub type MQTT = crate::src::lib::http2::MQTT;
pub type IMAP = crate::src::lib::http2::IMAP;
pub type FTP = crate::src::lib::http2::FTP;
pub type FILEPROTO = crate::src::lib::http2::FILEPROTO;
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
pub type PslCache = crate::src::lib::http2::PslCache;
pub type psl_ctx_t = crate::src::lib::urlapi::psl_ctx_st;
pub type Curl_multi = crate::src::lib::http2::Curl_multi;
pub type curl_multi_timer_callback<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_multi>,
        _: i64,
        _: Option<&'a2 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type CURLM = crate::src::lib::http2::Curl_multi;
pub type curl_push_callback<'a1, 'a2, 'a3, 'a4> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: Option<&'a2 mut crate::src::lib::http2::Curl_easy>,
        _: u64,
        _: Option<&'a3 mut crate::src::lib::http2::curl_pushheaders>,
        _: Option<&'a4 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type curl_socket_callback<'a1, 'a2, 'a3> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
        _: i32,
        _: i32,
        _: Option<&'a2 mut core::ffi::c_void>,
        _: Option<&'a3 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type Names = crate::src::lib::http2::Names;
pub type C2RustUnnamed_3 = u32;
pub const HCACHE_SHARED: C2RustUnnamed_3 = 2;
pub const HCACHE_MULTI: C2RustUnnamed_3 = 1;
pub const HCACHE_NONE: C2RustUnnamed_3 = 0;
pub type Curl_message = crate::src::lib::http2::Curl_message;
pub type CURLMsg = crate::src::lib::http2::CURLMsg;
pub type C2RustUnnamed_4 = crate::src::lib::http2::C2RustUnnamed_3;
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
pub type connectdata = crate::src::lib::http2::connectdata;
pub type connectbundle = crate::src::lib::http2::connectbundle;
pub type C2RustUnnamed_5 = crate::src::lib::http2::C2RustUnnamed_4;
pub type mqtt_conn = crate::src::lib::http2::mqtt_conn;
pub type mqttstate = u32;
pub const MQTT_NOSTATE: mqttstate = 7;
pub const MQTT_PUB_REMAIN: mqttstate = 6;
pub const MQTT_PUBWAIT: mqttstate = 5;
pub const MQTT_SUBACK_COMING: mqttstate = 4;
pub const MQTT_SUBACK: mqttstate = 3;
pub const MQTT_CONNACK: mqttstate = 2;
pub const MQTT_REMAINING_LENGTH: mqttstate = 1;
pub const MQTT_FIRST: mqttstate = 0;
pub type smb_conn = crate::src::lib::http2::smb_conn;
pub type smb_conn_state = u32;
pub const SMB_CONNECTED: smb_conn_state = 4;
pub const SMB_SETUP: smb_conn_state = 3;
pub const SMB_NEGOTIATE: smb_conn_state = 2;
pub const SMB_CONNECTING: smb_conn_state = 1;
pub const SMB_NOT_CONNECTED: smb_conn_state = 0;
pub type rtsp_conn = crate::src::lib::http2::rtsp_conn;
pub type smtp_conn = crate::src::lib::http2::smtp_conn;
pub type SASL = crate::src::lib::http2::SASL;
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
pub type SASLproto = crate::src::lib::http2::SASLproto;
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
pub type pingpong = crate::src::lib::http2::pingpong;
pub type pop3_conn = crate::src::lib::http2::pop3_conn;
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
pub type imap_conn = crate::src::lib::http2::imap_conn;
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
pub type ssh_conn = crate::src::lib::http2::ssh_conn;
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
pub type http_conn = crate::src::lib::http2::http_conn;
pub type nghttp2_settings_entry = crate::src::lib::http2::nghttp2_settings_entry;
pub type h2settings = crate::src::lib::http2::h2settings;
pub type Curl_recv<'a1, 'a2, 'a3> = unsafe extern "C" fn(
    _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
    _: i32,
    _: Option<&'a2 mut i8>,
    _: u64,
    _: Option<&'a3 mut u32>,
) -> i64;
pub type Curl_send<'a1, 'a2, 'a3> = unsafe extern "C" fn(
    _: Option<&'a1 mut crate::src::lib::http2::Curl_easy>,
    _: i32,
    _: Option<&'a2 core::ffi::c_void>,
    _: u64,
    _: Option<&'a3 mut u32>,
) -> i64;
pub type ftp_conn = crate::src::lib::http2::ftp_conn;
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
pub type ntlmdata = crate::src::lib::http2::ntlmdata;
pub type curlntlm = u32;
pub const NTLMSTATE_LAST: curlntlm = 4;
pub const NTLMSTATE_TYPE3: curlntlm = 3;
pub const NTLMSTATE_TYPE2: curlntlm = 2;
pub const NTLMSTATE_TYPE1: curlntlm = 1;
pub const NTLMSTATE_NONE: curlntlm = 0;
pub type gsasldata = crate::src::lib::http2::gsasldata;
pub type Curl_handler = crate::src::lib::http2::Curl_handler;
pub type ConnectBits = crate::src::lib::http2::ConnectBits;
pub type ssl_connect_data = crate::src::lib::http2::ssl_connect_data;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssl_backend_data {
    pub logger: *mut crate::src::lib::http2::Curl_easy,
    pub ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    pub handle: *mut crate::src::lib::vtls::openssl::ssl_st,
    pub server_cert: *mut crate::src::lib::vtls::openssl::x509_st,
}
impl ssl_backend_data {
    pub const fn new() -> Self {
        ssl_backend_data {
            logger: (0 as *mut crate::src::lib::http2::Curl_easy),
            ctx: (0 as *mut crate::src::lib::vtls::openssl::ssl_ctx_st),
            handle: (0 as *mut crate::src::lib::vtls::openssl::ssl_st),
            server_cert: (0 as *mut crate::src::lib::vtls::openssl::x509_st),
        }
    }
}
impl std::default::Default for ssl_backend_data {
    fn default() -> Self {
        ssl_backend_data::new()
    }
}
pub type X509 = crate::src::lib::vtls::openssl::x509_st;
pub type SSL = crate::src::lib::vtls::openssl::ssl_st;
pub type SSL_CTX = crate::src::lib::vtls::openssl::ssl_ctx_st;
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
pub type proxy_info = crate::src::lib::http2::proxy_info;
pub type hostname = crate::src::lib::http2::hostname;
pub type C2RustUnnamed_6 = u32;
pub const TRNSPRT_QUIC: C2RustUnnamed_6 = 5;
pub const TRNSPRT_UDP: C2RustUnnamed_6 = 4;
pub const TRNSPRT_TCP: C2RustUnnamed_6 = 3;
pub type Curl_chunker = crate::src::lib::http2::Curl_chunker;
pub type ChunkyState = u32;
pub const CHUNK_TRAILER_POSTCR: ChunkyState = 7;
pub const CHUNK_TRAILER_CR: ChunkyState = 6;
pub const CHUNK_TRAILER: ChunkyState = 5;
pub const CHUNK_STOP: ChunkyState = 4;
pub const CHUNK_POSTLF: ChunkyState = 3;
pub const CHUNK_DATA: ChunkyState = 2;
pub const CHUNK_LF: ChunkyState = 1;
pub const CHUNK_HEX: ChunkyState = 0;
pub type connstate = crate::src::lib::http2::connstate;
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
pub type curl_malloc_callback<'a1> =
    Option<unsafe extern "C" fn(_: u64) -> Option<&'a1 mut core::ffi::c_void>>;
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
pub type curl_ssl_backend = crate::src::lib::getinfo::curl_ssl_backend;
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
pub type uint16_t = u16;
pub type uint64_t = u64;
pub type in_addr_t = u32;
pub type in_addr = crate::src::lib::connect::in_addr;
pub type in6_addr = crate::src::lib::connect::in6_addr;
pub type C2RustUnnamed_10 = crate::src::lib::connect::C2RustUnnamed_8;
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
pub type Curl_ssl = crate::src::lib::getinfo::Curl_ssl;
pub type CRYPTO_EX_free<'a1, 'a2, 'a3, 'a4> = unsafe extern "C" fn(
    _: Option<&'a1 mut core::ffi::c_void>,
    _: Option<&'a2 mut core::ffi::c_void>,
    _: Option<&'a3 mut crate::src::lib::vtls::openssl::crypto_ex_data_st>,
    _: i32,
    _: i64,
    _: Option<&'a4 mut core::ffi::c_void>,
) -> ();
pub type CRYPTO_EX_DATA = crate::src::lib::vtls::openssl::crypto_ex_data_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub sk: *mut crate::src::lib::vtls::openssl::stack_st_void,
}
impl crypto_ex_data_st {
    pub const fn new() -> Self {
        crypto_ex_data_st {
            sk: (0 as *mut crate::src::lib::vtls::openssl::stack_st_void),
        }
    }
}
impl std::default::Default for crypto_ex_data_st {
    fn default() -> Self {
        crypto_ex_data_st::new()
    }
}
pub type CRYPTO_EX_dup<'a1, 'a2, 'a3, 'a4> = unsafe extern "C" fn(
    _: Option<&'a1 mut crate::src::lib::vtls::openssl::crypto_ex_data_st>,
    _: Option<&'a2 crate::src::lib::vtls::openssl::crypto_ex_data_st>,
    _: Option<&'a3 mut core::ffi::c_void>,
    _: i32,
    _: i64,
    _: Option<&'a4 mut core::ffi::c_void>,
) -> i32;
pub type CRYPTO_EX_new<'a1, 'a2, 'a3, 'a4> = unsafe extern "C" fn(
    _: Option<&'a1 mut core::ffi::c_void>,
    _: Option<&'a2 mut core::ffi::c_void>,
    _: Option<&'a3 mut crate::src::lib::vtls::openssl::crypto_ex_data_st>,
    _: i32,
    _: i64,
    _: Option<&'a4 mut core::ffi::c_void>,
) -> ();
pub type EVP_MD_CTX = crate::src::lib::vtls::openssl::evp_md_ctx_st;
pub type EVP_MD = crate::src::lib::vtls::openssl::evp_md_st;
pub type ENGINE = crate::src::lib::vtls::openssl::engine_st;
pub type SSL_SESSION = crate::src::lib::vtls::openssl::ssl_session_st;
pub type X509_PUBKEY = crate::src::lib::vtls::openssl::X509_pubkey_st;
pub type OCSP_RESPONSE = crate::src::lib::vtls::openssl::ocsp_response_st;
pub type OCSP_BASICRESP = crate::src::lib::vtls::openssl::ocsp_basic_response_st;
pub type ASN1_GENERALIZEDTIME = crate::src::lib::vtls::openssl::asn1_string_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: i32,
    pub type_0: i32,
    pub data: *mut u8,
    pub flags: i64,
}
impl asn1_string_st {
    pub const fn new() -> Self {
        asn1_string_st {
            length: 0,
            type_0: 0,
            data: (0 as *mut u8),
            flags: 0,
        }
    }
}
impl std::default::Default for asn1_string_st {
    fn default() -> Self {
        asn1_string_st::new()
    }
}
pub type OCSP_CERTID = crate::src::lib::vtls::openssl::ocsp_cert_id_st;
pub type OPENSSL_STACK = crate::src::lib::vtls::openssl::stack_st;
pub type X509_STORE = crate::src::lib::vtls::openssl::x509_store_st;
pub type BIO = crate::src::lib::vtls::openssl::bio_st;
pub type pem_password_cb<'a1, 'a2> = unsafe extern "C" fn(
    _: Option<&'a1 mut i8>,
    _: i32,
    _: i32,
    _: Option<&'a2 mut core::ffi::c_void>,
) -> i32;
pub type BIO_METHOD = crate::src::lib::vtls::openssl::bio_method_st;
pub type X509_NAME = crate::src::lib::vtls::openssl::X509_name_st;
pub type BUF_MEM = crate::src::lib::vtls::openssl::buf_mem_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct buf_mem_st {
    pub length: u64,
    pub data: *mut i8,
    pub max: u64,
    pub flags: u64,
}
impl buf_mem_st {
    pub const fn new() -> Self {
        buf_mem_st {
            length: 0,
            data: (0 as *mut i8),
            max: 0,
            flags: 0,
        }
    }
}
impl std::default::Default for buf_mem_st {
    fn default() -> Self {
        buf_mem_st::new()
    }
}
pub type ASN1_STRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type X509_NAME_ENTRY = crate::src::lib::vtls::openssl::X509_name_entry_st;
pub type GENERAL_NAMES = crate::src::lib::vtls::openssl::stack_st_GENERAL_NAME;
pub type ASN1_IA5STRING = crate::src::lib::vtls::openssl::asn1_string_st;
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
pub type ASN1_TYPE = crate::src::lib::vtls::openssl::asn1_type_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_type_st {
    pub type_0: i32,
    pub value: crate::src::lib::vtls::openssl::C2RustUnnamed_12,
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
pub type ASN1_VALUE = crate::src::lib::vtls::openssl::ASN1_VALUE_st;
pub type ASN1_UTF8STRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_VISIBLESTRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_UTCTIME = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_UNIVERSALSTRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_BMPSTRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_GENERALSTRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_T61STRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_PRINTABLESTRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_OCTET_STRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_BIT_STRING = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_ENUMERATED = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_INTEGER = crate::src::lib::vtls::openssl::asn1_string_st;
pub type ASN1_OBJECT = crate::src::lib::vtls::openssl::asn1_object_st;
pub type ASN1_BOOLEAN = i32;
pub type EDIPARTYNAME = crate::src::lib::vtls::openssl::EDIPartyName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EDIPartyName_st {
    pub nameAssigner: *mut crate::src::lib::vtls::openssl::asn1_string_st,
    pub partyName: *mut crate::src::lib::vtls::openssl::asn1_string_st,
}
impl EDIPartyName_st {
    pub const fn new() -> Self {
        EDIPartyName_st {
            nameAssigner: (0 as *mut crate::src::lib::vtls::openssl::asn1_string_st),
            partyName: (0 as *mut crate::src::lib::vtls::openssl::asn1_string_st),
        }
    }
}
impl std::default::Default for EDIPartyName_st {
    fn default() -> Self {
        EDIPartyName_st::new()
    }
}
pub type OTHERNAME = crate::src::lib::vtls::openssl::otherName_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct otherName_st {
    pub type_id: *mut crate::src::lib::vtls::openssl::asn1_object_st,
    pub value: *mut crate::src::lib::vtls::openssl::asn1_type_st,
}
impl otherName_st {
    pub const fn new() -> Self {
        otherName_st {
            type_id: (0 as *mut crate::src::lib::vtls::openssl::asn1_object_st),
            value: (0 as *mut crate::src::lib::vtls::openssl::asn1_type_st),
        }
    }
}
impl std::default::Default for otherName_st {
    fn default() -> Self {
        otherName_st::new()
    }
}
pub type GENERAL_NAME = crate::src::lib::vtls::openssl::GENERAL_NAME_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GENERAL_NAME_st {
    pub type_0: i32,
    pub d: crate::src::lib::vtls::openssl::C2RustUnnamed_11,
}
pub type ASN1_TIME = crate::src::lib::vtls::openssl::asn1_string_st;
pub type EVP_PKEY = crate::src::lib::vtls::openssl::evp_pkey_st;
pub type BIGNUM = crate::src::lib::vtls::openssl::bignum_st;
pub type DH = crate::src::lib::vtls::openssl::dh_st;
pub type DSA = crate::src::lib::vtls::openssl::dsa_st;
pub type RSA = crate::src::lib::vtls::openssl::rsa_st;
pub type X509_EXTENSION = crate::src::lib::vtls::openssl::X509_extension_st;
pub type X509_ALGOR = crate::src::lib::vtls::openssl::X509_algor_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_algor_st {
    pub algorithm: *mut crate::src::lib::vtls::openssl::asn1_object_st,
    pub parameter: *mut crate::src::lib::vtls::openssl::asn1_type_st,
}
impl X509_algor_st {
    pub const fn new() -> Self {
        X509_algor_st {
            algorithm: (0 as *mut crate::src::lib::vtls::openssl::asn1_object_st),
            parameter: (0 as *mut crate::src::lib::vtls::openssl::asn1_type_st),
        }
    }
}
impl std::default::Default for X509_algor_st {
    fn default() -> Self {
        X509_algor_st::new()
    }
}
pub type numcert_t = i32;
pub type SSL_CIPHER = crate::src::lib::vtls::openssl::ssl_cipher_st;
pub type SSL_CTX_keylog_cb_func<'a1, 'a2> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 crate::src::lib::vtls::openssl::ssl_st>,
        _: Option<&'a2 i8>,
    ) -> (),
>;
pub type SSL_verify_cb<'a1> = Option<
    unsafe extern "C" fn(
        _: i32,
        _: Option<&'a1 mut crate::src::lib::vtls::openssl::x509_store_ctx_st>,
    ) -> i32,
>;
pub type X509_STORE_CTX = crate::src::lib::vtls::openssl::x509_store_ctx_st;
pub type X509_LOOKUP = crate::src::lib::vtls::openssl::x509_lookup_st;
pub type X509_LOOKUP_METHOD = crate::src::lib::vtls::openssl::x509_lookup_method_st;
pub type X509_INFO = crate::src::lib::vtls::openssl::X509_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct X509_info_st {
    pub x509: *mut crate::src::lib::vtls::openssl::x509_st,
    pub crl: *mut crate::src::lib::vtls::openssl::X509_crl_st,
    pub x_pkey: *mut crate::src::lib::vtls::openssl::private_key_st,
    pub enc_cipher: crate::src::lib::vtls::openssl::evp_cipher_info_st,
    pub enc_len: i32,
    pub enc_data: *mut i8,
}
impl X509_info_st {
    pub const fn new() -> Self {
        X509_info_st {
            x509: (0 as *mut crate::src::lib::vtls::openssl::x509_st),
            crl: (0 as *mut crate::src::lib::vtls::openssl::X509_crl_st),
            x_pkey: (0 as *mut crate::src::lib::vtls::openssl::private_key_st),
            enc_cipher: crate::src::lib::vtls::openssl::evp_cipher_info_st::new(),
            enc_len: 0,
            enc_data: (0 as *mut i8),
        }
    }
}
impl std::default::Default for X509_info_st {
    fn default() -> Self {
        X509_info_st::new()
    }
}
pub type EVP_CIPHER_INFO = crate::src::lib::vtls::openssl::evp_cipher_info_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct evp_cipher_info_st {
    pub cipher: *const crate::src::lib::vtls::openssl::evp_cipher_st,
    pub iv: [u8; 16],
}
impl evp_cipher_info_st {
    pub const fn new() -> Self {
        evp_cipher_info_st {
            cipher: (0 as *const crate::src::lib::vtls::openssl::evp_cipher_st),
            iv: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}
impl std::default::Default for evp_cipher_info_st {
    fn default() -> Self {
        evp_cipher_info_st::new()
    }
}
pub type EVP_CIPHER = crate::src::lib::vtls::openssl::evp_cipher_st;
pub type X509_PKEY = crate::src::lib::vtls::openssl::private_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct private_key_st {
    pub version: i32,
    pub enc_algor: *mut crate::src::lib::vtls::openssl::X509_algor_st,
    pub enc_pkey: *mut crate::src::lib::vtls::openssl::asn1_string_st,
    pub dec_pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st,
    pub key_length: i32,
    pub key_data: *mut i8,
    pub key_free: i32,
    pub cipher: crate::src::lib::vtls::openssl::evp_cipher_info_st,
}
impl private_key_st {
    pub const fn new() -> Self {
        private_key_st {
            version: 0,
            enc_algor: (0 as *mut crate::src::lib::vtls::openssl::X509_algor_st),
            enc_pkey: (0 as *mut crate::src::lib::vtls::openssl::asn1_string_st),
            dec_pkey: (0 as *mut crate::src::lib::vtls::openssl::evp_pkey_st),
            key_length: 0,
            key_data: (0 as *mut i8),
            key_free: 0,
            cipher: crate::src::lib::vtls::openssl::evp_cipher_info_st::new(),
        }
    }
}
impl std::default::Default for private_key_st {
    fn default() -> Self {
        private_key_st::new()
    }
}
pub type X509_CRL = crate::src::lib::vtls::openssl::X509_crl_st;
pub type sk_X509_INFO_freefunc<'a1> = Option<
    unsafe extern "C" fn(_: Option<&'a1 mut crate::src::lib::vtls::openssl::X509_info_st>) -> (),
>;
pub type OPENSSL_sk_freefunc<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut core::ffi::c_void>) -> ()>;
pub type UI_METHOD = crate::src::lib::vtls::openssl::ui_method_st;
pub type UI_STRING = crate::src::lib::vtls::openssl::ui_string_st;
pub type UI = crate::src::lib::vtls::openssl::ui_st;
pub const UIT_VERIFY: UI_string_types = 2;
pub const UIT_PROMPT: UI_string_types = 1;
pub type UI_string_types = u32;
pub const UIT_ERROR: UI_string_types = 5;
pub const UIT_INFO: UI_string_types = 4;
pub const UIT_BOOLEAN: UI_string_types = 3;
pub const UIT_NONE: UI_string_types = 0;
pub type sk_X509_freefunc<'a1> =
    Option<unsafe extern "C" fn(_: Option<&'a1 mut crate::src::lib::vtls::openssl::x509_st>) -> ()>;
pub type PKCS12 = crate::src::lib::vtls::openssl::PKCS12_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_13 {
    pub cert_id: *const i8,
    pub cert: *mut crate::src::lib::vtls::openssl::x509_st,
}
impl C2RustUnnamed_13 {
    pub const fn new() -> Self {
        C2RustUnnamed_13 {
            cert_id: (0 as *const i8),
            cert: (0 as *mut crate::src::lib::vtls::openssl::x509_st),
        }
    }
}
impl std::default::Default for C2RustUnnamed_13 {
    fn default() -> Self {
        C2RustUnnamed_13::new()
    }
}
pub type SSL_CTX_npn_select_cb_func<'a1, 'a2, 'a3, 'a4, 'a5, 'a6> = Option<
    unsafe extern "C" fn(
        _: Option<&'a1 mut crate::src::lib::vtls::openssl::ssl_st>,
        _: Option<&'a2 mut Option<&'a3 mut u8>>,
        _: Option<&'a4 mut u8>,
        _: Option<&'a5 u8>,
        _: u32,
        _: Option<&'a6 mut core::ffi::c_void>,
    ) -> i32,
>;
pub type ctx_option_t = i64;
pub type SSL_METHOD = crate::src::lib::vtls::openssl::ssl_method_st;
pub type OPENSSL_INIT_SETTINGS = crate::src::lib::vtls::openssl::ossl_init_settings_st;
#[inline]
extern "C" fn sk_X509_pop(
    mut sk: *mut crate::src::lib::vtls::openssl::stack_st_X509,
) -> *mut crate::src::lib::vtls::openssl::x509_st {
    return (unsafe { OPENSSL_sk_pop(sk as *mut OPENSSL_STACK) }) as *mut X509;
}
#[inline]
extern "C" fn sk_X509_pop_free(
    mut sk: *mut crate::src::lib::vtls::openssl::stack_st_X509,
    mut freefunc: Option<
        unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::x509_st) -> (),
    >,
) {
    (unsafe { OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        core::intrinsics::transmute::<
            Option<unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::x509_st) -> ()>,
            Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
        >(freefunc),
    ) });
}
#[inline]
extern "C" fn sk_X509_INFO_num(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509_INFO,
) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_INFO_value(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509_INFO,
    mut idx: i32,
) -> *mut crate::src::lib::vtls::openssl::X509_info_st {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509_INFO;
}
#[inline]
extern "C" fn sk_X509_INFO_pop_free(
    mut sk: *mut crate::src::lib::vtls::openssl::stack_st_X509_INFO,
    mut freefunc: Option<
        unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::X509_info_st) -> (),
    >,
) {
    (unsafe { OPENSSL_sk_pop_free(
        sk as *mut OPENSSL_STACK,
        core::intrinsics::transmute::<
            Option<
                unsafe extern "C" fn(_: *mut crate::src::lib::vtls::openssl::X509_info_st) -> (),
            >,
            Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
        >(freefunc),
    ) });
}
#[inline]
extern "C" fn sk_X509_EXTENSION_num(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509_EXTENSION,
) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_EXTENSION_value(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509_EXTENSION,
    mut idx: i32,
) -> *mut crate::src::lib::vtls::openssl::X509_extension_st {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509_EXTENSION;
}
#[inline]
extern "C" fn sk_X509_num(mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_X509_value(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_X509,
    mut idx: i32,
) -> *mut crate::src::lib::vtls::openssl::x509_st {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut X509;
}
#[inline]
extern "C" fn sk_GENERAL_NAME_num(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_GENERAL_NAME,
) -> i32 {
    return unsafe { OPENSSL_sk_num(sk as *const OPENSSL_STACK) };
}
#[inline]
extern "C" fn sk_GENERAL_NAME_value(
    mut sk: *const crate::src::lib::vtls::openssl::stack_st_GENERAL_NAME,
    mut idx: i32,
) -> *mut crate::src::lib::vtls::openssl::GENERAL_NAME_st {
    return (unsafe { OPENSSL_sk_value(sk as *const OPENSSL_STACK, idx) }) as *mut GENERAL_NAME;
}
extern "C" fn ossl_keylog_callback(
    mut _ssl: *const crate::src::lib::vtls::openssl::ssl_st,
    mut line: *const i8,
) {
    Curl_tls_keylog_write_line(line);
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
extern "C" fn ossl_strerror(mut error: u64, mut buf: *mut i8, mut size: u64) -> *mut i8 {
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
    mut global_passwd: *mut core::ffi::c_void,
) -> i32 {
    if encrypting == 0 {
        let mut klen: i32 = curlx_uztosi(unsafe { strlen(global_passwd as *mut i8) });
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
extern "C" fn ossl_seed(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
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
        let mut len: u64 = ::std::mem::size_of::<[u8; 64]>() as u64;
        let mut i: u64 = 0;
        let mut i_max: u64 = 0;
        i = 0 as i32 as size_t;
        i_max = len.wrapping_div(::std::mem::size_of::<curltime>() as u64);
        while i < i_max {
            let mut tv: crate::src::lib::http2::curltime = Curl_now();
            Curl_wait_ms(1 as i32 as timediff_t);
            tv.tv_sec = (tv.tv_sec as u64).wrapping_mul(i.wrapping_add(1 as i32 as u64)) as time_t
                as time_t;
            tv.tv_usec = (tv.tv_usec as u32).wrapping_mul((i as u32).wrapping_add(2 as i32 as u32))
                as i32 as i32;
            tv.tv_sec = (tv.tv_sec as u64
                ^ (((Curl_now()).tv_sec + (Curl_now()).tv_usec as i64) as u64)
                    .wrapping_mul(i.wrapping_add(3 as i32 as u64))
                    << 8 as i32) as time_t;
            tv.tv_usec = (tv.tv_usec as u32
                ^ ((((Curl_now()).tv_sec + (Curl_now()).tv_usec as i64) as u64)
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
    if Curl_strcasecompare(type_0, b"PEM\0" as *const u8 as *const i8) != 0 {
        return 1 as i32;
    }
    if Curl_strcasecompare(type_0, b"DER\0" as *const u8 as *const i8) != 0 {
        return 2 as i32;
    }
    if Curl_strcasecompare(type_0, b"ENG\0" as *const u8 as *const i8) != 0 {
        return 42 as i32;
    }
    if Curl_strcasecompare(type_0, b"P12\0" as *const u8 as *const i8) != 0 {
        return 43 as i32;
    }
    return -(1 as i32);
}
extern "C" fn ssl_ui_reader(
    mut ui: *mut crate::src::lib::vtls::openssl::ui_st,
    mut uis: *mut crate::src::lib::vtls::openssl::ui_string_st,
) -> i32 {
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
extern "C" fn ssl_ui_writer(
    mut ui: *mut crate::src::lib::vtls::openssl::ui_st,
    mut uis: *mut crate::src::lib::vtls::openssl::ui_string_st,
) -> i32 {
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
        && Curl_strncasecompare(
            string,
            b"pkcs11:\0" as *const u8 as *const i8,
            7 as i32 as size_t,
        ) != 0;
}
extern "C" fn SSL_CTX_use_certificate_blob(
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut blob: *const crate::src::lib::http2::curl_blob,
    mut type_0: i32,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut x: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
    let mut in_0: *mut crate::src::lib::vtls::openssl::bio_st =
        unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
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
            Some(passwd_callback),
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
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut blob: *const crate::src::lib::http2::curl_blob,
    mut type_0: i32,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut pkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st = 0 as *mut EVP_PKEY;
    let mut in_0: *mut crate::src::lib::vtls::openssl::bio_st =
        unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as i32;
    }
    if type_0 == 1 as i32 {
        pkey = unsafe { PEM_read_bio_PrivateKey(
            in_0,
            0 as *mut *mut EVP_PKEY,
            Some(passwd_callback),
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
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut blob: *const crate::src::lib::http2::curl_blob,
    mut key_passwd: *const i8,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut x: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
    let mut passwd_callback_userdata: *mut core::ffi::c_void = key_passwd as *mut libc::c_void;
    let mut in_0: *mut crate::src::lib::vtls::openssl::bio_st =
        unsafe { BIO_new_mem_buf((*blob).data, (*blob).len as i32) };
    if in_0.is_null() {
        return CURLE_OUT_OF_MEMORY as i32;
    }
    (unsafe { ERR_clear_error() });
    x = unsafe { PEM_read_bio_X509_AUX(
        in_0,
        0 as *mut *mut X509,
        Some(passwd_callback),
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
            let mut ca: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
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
                        Some(passwd_callback),
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
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut cert_file: *mut i8,
    mut cert_blob: *const crate::src::lib::http2::curl_blob,
    mut cert_type: *const i8,
    mut key_file: *mut i8,
    mut key_blob: *const crate::src::lib::http2::curl_blob,
    mut key_type: *const i8,
    mut key_passwd: *mut i8,
) -> i32 {
    let mut current_block: u64;
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut check_privkey: bool = 1 as i32 != 0;
    let mut file_type: i32 = do_file_type(cert_type);
    if !cert_file.is_null() || !cert_blob.is_null() || file_type == 42 as i32 {
        let mut ssl: *mut crate::src::lib::vtls::openssl::ssl_st = 0 as *mut SSL;
        let mut x509: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
        let mut cert_done: i32 = 0 as i32;
        let mut cert_use_result: i32 = 0;
        if !key_passwd.is_null() {
            (unsafe { SSL_CTX_set_default_passwd_cb_userdata(ctx, key_passwd as *mut libc::c_void) });
            (unsafe { SSL_CTX_set_default_passwd_cb(ctx, Some(passwd_callback)) });
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
                    let mut params: crate::src::lib::vtls::openssl::C2RustUnnamed_13 =
                        C2RustUnnamed_13 {
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
                let mut cert_bio: *mut crate::src::lib::vtls::openssl::bio_st = 0 as *mut BIO;
                let mut p12: *mut crate::src::lib::vtls::openssl::PKCS12_st = 0 as *mut PKCS12;
                let mut pri: *mut crate::src::lib::vtls::openssl::evp_pkey_st = 0 as *mut EVP_PKEY;
                let mut ca: *mut crate::src::lib::vtls::openssl::stack_st_X509 =
                    0 as *mut stack_st_X509;
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
                            let mut x: *mut crate::src::lib::vtls::openssl::x509_st =
                                sk_X509_pop(ca);
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
                sk_X509_pop_free(ca, Some(X509_free));
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
                let mut priv_key: *mut crate::src::lib::vtls::openssl::evp_pkey_st =
                    0 as *mut EVP_PKEY;
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
                    let mut ui_method: *mut crate::src::lib::vtls::openssl::ui_method_st =
                        unsafe { UI_create_method(
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
                    (unsafe { UI_method_set_reader(ui_method, Some(ssl_ui_reader)) });
                    (unsafe { UI_method_set_writer(ui_method, Some(ssl_ui_writer)) });
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
            let mut pktmp: *mut crate::src::lib::vtls::openssl::evp_pkey_st = unsafe { X509_get_pubkey(x509) };
            (unsafe { EVP_PKEY_copy_parameters(pktmp, SSL_get_privatekey(ssl)) });
            (unsafe { EVP_PKEY_free(pktmp) });
        }
        let mut priv_key_0: *mut crate::src::lib::vtls::openssl::evp_pkey_st =
            unsafe { SSL_get_privatekey(ssl) };
        let mut pktype: i32 = 0;
        pktype = unsafe { EVP_PKEY_id(priv_key_0) };
        if pktype == 6 as i32 {
            let mut rsa: *mut crate::src::lib::vtls::openssl::rsa_st =
                unsafe { EVP_PKEY_get1_RSA(priv_key_0) };
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
extern "C" fn x509_name_oneline(
    mut a: *mut crate::src::lib::vtls::openssl::X509_name_st,
    mut buf: *mut i8,
    mut size: u64,
) -> i32 {
    let mut bio_out: *mut crate::src::lib::vtls::openssl::bio_st = unsafe { BIO_new(BIO_s_mem()) };
    let mut biomem: *mut crate::src::lib::vtls::openssl::buf_mem_st = 0 as *mut BUF_MEM;
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
    let flags: u64 = (0x200 as i64
        | 0x400 as i64
        | 0x1000 as i64
        | 0x2000 as i64
        | 0x4000 as i64
        | 0x40 as i64
        | 0 as i32 as i64) as uint64_t;
    (unsafe { OPENSSL_init_ssl(flags, 0 as *const OPENSSL_INIT_SETTINGS) });
    Curl_tls_keylog_open();
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
    Curl_tls_keylog_close();
}
extern "C" fn ossl_check_cxn(mut conn: *mut crate::src::lib::http2::connectdata) -> i32 {
    let mut buf: i8 = 0;
    let mut nread: i64 = 0;
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
extern "C" fn ossl_set_engine(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut engine: *const i8,
) -> u32 {
    let mut e: *mut crate::src::lib::vtls::openssl::engine_st = 0 as *mut ENGINE;
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
        let mut fresh0 = unsafe { &mut ((*data).state.engine) };
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
    let mut fresh1 = unsafe { &mut ((*data).state.engine) };
    *fresh1 = e as *mut libc::c_void;
    return CURLE_OK;
}
extern "C" fn ossl_set_engine_default(mut data: *mut crate::src::lib::http2::Curl_easy) -> u32 {
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
extern "C" fn ossl_engines_list(
    mut _data: *mut crate::src::lib::http2::Curl_easy,
) -> *mut crate::src::lib::http2::curl_slist {
    let mut list: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut beg: *mut crate::src::lib::http2::curl_slist = 0 as *mut curl_slist;
    let mut e: *mut crate::src::lib::vtls::openssl::engine_st = 0 as *mut ENGINE;
    e = unsafe { ENGINE_get_first() };
    while !e.is_null() {
        beg = curl_slist_append(list, unsafe { ENGINE_get_id(e) });
        if beg.is_null() {
            curl_slist_free_all(list);
            return 0 as *mut curl_slist;
        }
        list = beg;
        e = unsafe { ENGINE_get_next(e) };
    }
    return list;
}
extern "C" fn ossl_closeone<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut connssl: Option<&'a1 mut crate::src::lib::http2::ssl_connect_data>,
) {
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    if !(unsafe { (*backend).handle }).is_null() {
        let mut buf: [i8; 32] = [0; 32];
        let mut fresh2 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
        *fresh2 = data;
        (unsafe { SSL_read(
            (*backend).handle,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::std::mem::size_of::<[i8; 32]>() as u64 as i32,
        ) });
        (unsafe { SSL_shutdown((*backend).handle) });
        (unsafe { SSL_set_connect_state((*backend).handle) });
        (unsafe { SSL_free((*backend).handle) });
        let mut fresh3 = unsafe { &mut ((*backend).handle) };
        *fresh3 = 0 as *mut SSL;
    }
    if !(unsafe { (*backend).ctx }).is_null() {
        (unsafe { SSL_CTX_free((*backend).ctx) });
        let mut fresh4 = unsafe { &mut ((*backend).ctx) };
        *fresh4 = 0 as *mut SSL_CTX;
    }
}
extern "C" fn ossl_close(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) {
    ossl_closeone(
        data,
        conn,
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) }),
    );
    ossl_closeone(
        data,
        conn,
        Some(unsafe { &mut *((*conn).proxy_ssl).as_mut_ptr().offset(sockindex as isize) }),
    );
}
extern "C" fn ossl_shutdown(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> i32 {
    let mut retval: i32 = 0 as i32;
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut buf: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut nread: i64 = 0;
    let mut buffsize: i32 = 0;
    let mut err: i32 = 0;
    let mut done: bool = 0 as i32 != 0;
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    let mut loop_0: i32 = 10 as i32;
    if (unsafe { (*data).set.ftp_ccc }) as u32 == CURLFTPSSL_CCC_ACTIVE as i32 as u32 {
        (unsafe { SSL_shutdown((*backend).handle) });
    }
    if !(unsafe { (*backend).handle }).is_null() {
        buffsize = ::std::mem::size_of::<[i8; 256]>() as u64 as i32;
        while !done && {
            let mut fresh5 = loop_0;
            loop_0 = loop_0 - 1;
            fresh5 != 0
        } {
            let mut what: i32 = Curl_socket_check(
                unsafe { (*conn).sock[sockindex as usize] },
                -(1 as i32),
                -(1 as i32),
                10000 as i32 as timediff_t,
            );
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
        let mut fresh6 = unsafe { &mut ((*backend).handle) };
        *fresh6 = 0 as *mut SSL;
    }
    return retval;
}
extern "C" fn ossl_session_free(mut ptr: *mut core::ffi::c_void) {
    (unsafe { SSL_SESSION_free(ptr as *mut SSL_SESSION) });
}
extern "C" fn ossl_close_all(mut data: *mut crate::src::lib::http2::Curl_easy) {
    if !(unsafe { (*data).state.engine }).is_null() {
        (unsafe { ENGINE_finish((*data).state.engine as *mut ENGINE) });
        (unsafe { ENGINE_free((*data).state.engine as *mut ENGINE) });
        let mut fresh7 = unsafe { &mut ((*data).state.engine) };
        *fresh7 = 0 as *mut libc::c_void;
    }
}
extern "C" fn subj_alt_hostcheck(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut match_pattern: *const i8,
    mut hostname: *const i8,
    mut dispname: *const i8,
) -> bool {
    if Curl_cert_hostcheck(match_pattern, hostname) != 0 {
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
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut server_cert: *mut crate::src::lib::vtls::openssl::x509_st,
) -> u32 {
    let mut matched: bool = 0 as i32 != 0;
    let mut target: i32 = 2 as i32;
    let mut addrlen: u64 = 0 as i32 as size_t;
    let mut altnames: *mut crate::src::lib::vtls::openssl::stack_st_GENERAL_NAME =
        0 as *mut stack_st_GENERAL_NAME;
    let mut addr: crate::src::lib::connect::in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_10 {
            __u6_addr8: [0; 16],
        },
    };
    let mut result: u32 = CURLE_OK;
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
            let mut check: *const crate::src::lib::vtls::openssl::GENERAL_NAME_st =
                sk_GENERAL_NAME_value(altnames, i);
            if (unsafe { (*check).type_0 }) == 2 as i32 {
                dNSName = 1 as i32 != 0;
            } else if (unsafe { (*check).type_0 }) == 7 as i32 {
                iPAddress = 1 as i32 != 0;
            }
            if (unsafe { (*check).type_0 }) == target {
                let mut altptr: *const i8 = (unsafe { ASN1_STRING_get0_data((*check).d.ia5) }) as *mut i8;
                let mut altlen: u64 = (unsafe { ASN1_STRING_length((*check).d.ia5) }) as size_t;
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
            let mut name: *mut crate::src::lib::vtls::openssl::X509_name_st =
                unsafe { X509_get_subject_name(server_cert) };
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
                let mut tmp: *mut crate::src::lib::vtls::openssl::asn1_string_st =
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
                    if !peer_CN.is_null() && curlx_uztosi(unsafe { strlen(peer_CN as *mut i8) }) != j {
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
                let mut rc: u32 = CURLE_OK as i32 as CURLcode;
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
                } else if Curl_cert_hostcheck(peer_CN as *const i8, hostname) == 0 {
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
extern "C" fn verifystatus<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut connssl: Option<&'a1 mut crate::src::lib::http2::ssl_connect_data>,
) -> u32 {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut ocsp_status: i32 = 0;
    let mut status: *mut u8 = 0 as *mut u8;
    let mut p: *const u8 = 0 as *const u8;
    let mut result: u32 = CURLE_OK;
    let mut rsp: *mut crate::src::lib::vtls::openssl::ocsp_response_st = 0 as *mut OCSP_RESPONSE;
    let mut br: *mut crate::src::lib::vtls::openssl::ocsp_basic_response_st =
        0 as *mut OCSP_BASICRESP;
    let mut st: *mut crate::src::lib::vtls::openssl::x509_store_st = 0 as *mut X509_STORE;
    let mut ch: *mut crate::src::lib::vtls::openssl::stack_st_X509 = 0 as *mut stack_st_X509;
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    let mut cert: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
    let mut id: *mut crate::src::lib::vtls::openssl::ocsp_cert_id_st = 0 as *mut OCSP_CERTID;
    let mut cert_status: i32 = 0;
    let mut crl_reason: i32 = 0;
    let mut rev: *mut crate::src::lib::vtls::openssl::asn1_string_st =
        0 as *mut ASN1_GENERALIZEDTIME;
    let mut thisupd: *mut crate::src::lib::vtls::openssl::asn1_string_st =
        0 as *mut ASN1_GENERALIZEDTIME;
    let mut nextupd: *mut crate::src::lib::vtls::openssl::asn1_string_st =
        0 as *mut ASN1_GENERALIZEDTIME;
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
                                let mut issuer: *mut crate::src::lib::vtls::openssl::x509_st =
                                    sk_X509_value(ch, i);
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
    mut buf: *const core::ffi::c_void,
    mut len: u64,
    mut _ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
    mut userp: *mut core::ffi::c_void,
) {
    let mut unknown: [i8; 32] = [0; 32];
    let mut verstr: *const i8 = 0 as *const i8;
    let mut conn: *mut crate::src::lib::http2::connectdata = userp as *mut connectdata;
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(0 as i32 as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    let mut data: *mut crate::src::lib::http2::Curl_easy = unsafe { (*backend).logger };
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
            Curl_debug(data, CURLINFO_TEXT, ssl_buf.as_mut_ptr(), txt_len as size_t);
        }
    }
    Curl_debug(
        data,
        (if direction == 1 as i32 {
            CURLINFO_SSL_DATA_OUT as i32
        } else {
            CURLINFO_SSL_DATA_IN as i32
        }) as curl_infotype,
        buf as *mut i8,
        len,
    );
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
    mut _ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
    mut out: *mut *mut u8,
    mut outlen: *mut u8,
    mut in_0: *const u8,
    mut inlen: u32,
    mut arg: *mut core::ffi::c_void,
) -> i32 {
    let mut data: *mut crate::src::lib::http2::Curl_easy = arg as *mut Curl_easy;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
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
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut conn: *mut crate::src::lib::http2::connectdata,
) -> u32 {
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
extern "C" fn ossl_new_session_cb(
    mut ssl: *mut crate::src::lib::vtls::openssl::ssl_st,
    mut ssl_sessionid: *mut crate::src::lib::vtls::openssl::ssl_session_st,
) -> i32 {
    let mut res: i32 = 0 as i32;
    let mut conn: *mut crate::src::lib::http2::connectdata = 0 as *mut connectdata;
    let mut data: *mut crate::src::lib::http2::Curl_easy = 0 as *mut Curl_easy;
    let mut sockindex: i32 = 0;
    let mut sockindex_ptr: *mut i32 = 0 as *mut curl_socket_t;
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
        let mut old_ssl_sessionid: *mut core::ffi::c_void = 0 as *mut libc::c_void;
        Curl_ssl_sessionid_lock(data);
        if isproxy {
            incache = 0 as i32 != 0;
        } else {
            incache = !Curl_ssl_getsessionid(
                data,
                conn,
                isproxy,
                Some(&mut old_ssl_sessionid),
                Option::<&'_ mut u64>::None,
                sockindex,
            );
        }
        if incache {
            if old_ssl_sessionid != ssl_sessionid as *mut libc::c_void {
                (unsafe { Curl_infof(
                    data,
                    b"old SSL session ID is stale, removing\0" as *const u8 as *const i8,
                ) });
                Curl_ssl_delsessionid(data, old_ssl_sessionid);
                incache = 0 as i32 != 0;
            }
        }
        if !incache {
            if Curl_ssl_addsessionid(
                data,
                conn,
                isproxy,
                ssl_sessionid as *mut libc::c_void,
                0 as i32 as size_t,
                sockindex,
            ) as u64
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
        Curl_ssl_sessionid_unlock(data);
    }
    return res;
}
extern "C" fn load_cacert_from_memory(
    mut ctx: *mut crate::src::lib::vtls::openssl::ssl_ctx_st,
    mut ca_info_blob: *const crate::src::lib::http2::curl_blob,
) -> u32 {
    let mut cbio: *mut crate::src::lib::vtls::openssl::bio_st = 0 as *mut BIO;
    let mut inf: *mut crate::src::lib::vtls::openssl::stack_st_X509_INFO =
        0 as *mut stack_st_X509_INFO;
    let mut i: i32 = 0;
    let mut count: i32 = 0 as i32;
    let mut cts: *mut crate::src::lib::vtls::openssl::x509_store_st = 0 as *mut X509_STORE;
    let mut itmp: *mut crate::src::lib::vtls::openssl::X509_info_st =
        0 as *mut crate::src::lib::vtls::openssl::X509_info_st;
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
    sk_X509_INFO_pop_free(inf, Some(X509_INFO_free));
    (unsafe { BIO_free(cbio) });
    return (if count > 0 as i32 {
        CURLE_OK as i32
    } else {
        CURLE_SSL_CACERT_BADFILE as i32
    }) as CURLcode;
}
extern "C" fn ossl_connect_step1(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut ciphers: *mut i8 = 0 as *mut i8;
    let mut req_method: *const crate::src::lib::vtls::openssl::ssl_method_st =
        0 as *const SSL_METHOD;
    let mut lookup: *mut crate::src::lib::vtls::openssl::x509_lookup_st = 0 as *mut X509_LOOKUP;
    let mut sockfd: i32 = unsafe { (*conn).sock[sockindex as usize] };
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut ctx_options: i64 = 0 as i32 as ctx_option_t;
    let mut ssl_sessionid: *mut core::ffi::c_void = 0 as *mut libc::c_void;
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
    let mut addr: crate::src::lib::connect::in6_addr = in6_addr {
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
    let ssl_authtype: u32 = (if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
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
    let mut ssl_cert_blob: *const crate::src::lib::http2::curl_blob =
        if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
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
    let mut ca_info_blob: *const crate::src::lib::http2::curl_blob =
        if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
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
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
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
    let mut fresh8 = unsafe { &mut ((*backend).ctx) };
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
        (unsafe { SSL_CTX_set_msg_callback((*backend).ctx, Some(ossl_trace)) });
        (unsafe { SSL_CTX_ctrl(
            (*backend).ctx,
            16 as i32,
            0 as i32 as i64,
            conn as *mut libc::c_void,
        ) });
        let mut fresh9 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
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
            Some(select_next_proto_cb),
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
            let mut fresh10 = cur;
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
        let mut fresh11 = cur;
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
    if Curl_tls_keylog_enabled() {
        (unsafe { SSL_CTX_set_keylog_callback((*backend).ctx, Some(ossl_keylog_callback)) });
    }
    (unsafe { SSL_CTX_ctrl(
        (*backend).ctx,
        44 as i32,
        (0x1 as i32 | (0x100 as i32 | 0x200 as i32)) as i64,
        0 as *mut libc::c_void,
    ) });
    (unsafe { SSL_CTX_sess_set_new_cb((*backend).ctx, Some(ossl_new_session_cb)) });
    if unsafe { ((*data).set.ssl.fsslctx).is_some() } {
        Curl_set_in_callback(data, 1 as i32 != 0);
        result = unsafe { (Some(((*data).set.ssl.fsslctx).expect("non-null function pointer")))
            .expect("non-null function pointer")(
            data,
            (*backend).ctx as *mut libc::c_void,
            (*data).set.ssl.fsslctxp,
        ) };
        Curl_set_in_callback(data, 0 as i32 != 0);
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
    let mut fresh12 = unsafe { &mut ((*backend).handle) };
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
    let mut fresh13 = unsafe { &mut ((*backend).server_cert) };
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
        let mut nlen: u64 = unsafe { strlen(hostname) };
        if nlen as i64 >= (unsafe { (*data).set.buffer_size }) {
            return CURLE_SSL_CONNECT_ERROR;
        }
        Curl_strntolower(unsafe { (*data).state.buffer }, hostname, nlen);
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
    Curl_ssl_sessionid_lock(data);
    if !Curl_ssl_getsessionid(
        data,
        conn,
        if CURLPROXY_HTTPS as i32 as u32 == (unsafe { (*conn).http_proxy.proxytype }) as u32
            && ssl_connection_complete as i32 as u32
                != (unsafe { (*conn).proxy_ssl[(if (*conn).sock[1 as i32 as usize] == -(1 as i32) {
                    0 as i32
                } else {
                    1 as i32
                }) as usize]
                    .state }) as u32
        {
            1 as i32
        } else {
            0 as i32
        } != 0,
        Some(&mut ssl_sessionid),
        Option::<&'_ mut u64>::None,
        sockindex,
    ) {
        if (unsafe { SSL_set_session((*backend).handle, ssl_sessionid as *mut SSL_SESSION) }) == 0 {
            Curl_ssl_sessionid_unlock(data);
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
    Curl_ssl_sessionid_unlock(data);
    if (unsafe { ((*conn).proxy_ssl[sockindex as usize]).use_0() }) != 0 {
        let bio: *mut crate::src::lib::vtls::openssl::bio_st = unsafe { BIO_new(BIO_f_ssl()) };
        let mut handle: *mut crate::src::lib::vtls::openssl::ssl_st =
            unsafe { (*(*conn).proxy_ssl[sockindex as usize].backend).handle };
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
    (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_2;
    return CURLE_OK;
}
extern "C" fn ossl_connect_step2(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    let mut err: i32 = 0;
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    (unsafe { ERR_clear_error() });
    err = unsafe { SSL_connect((*backend).handle) };
    if 1 as i32 != err {
        let mut detail: i32 = unsafe { SSL_get_error((*backend).handle, err) };
        if 2 as i32 == detail {
            (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_2_reading;
            return CURLE_OK;
        }
        if 3 as i32 == detail {
            (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_2_writing;
            return CURLE_OK;
        }
        if 9 as i32 == detail {
            (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_2;
            return CURLE_OK;
        } else {
            let mut errdetail: u64 = 0;
            let mut error_buffer : [i8 ; 256] = * (unsafe { core :: intrinsics :: transmute :: < & '_ [u8 ; 256] , & '_ mut [i8 ; 256] > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
            let mut result: u32 = CURLE_OK;
            let mut lerr: i64 = 0;
            let mut lib: i32 = 0;
            let mut reason: i32 = 0;
            (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_2;
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
                let mut extramsg : [i8 ; 80] = * (unsafe { core :: intrinsics :: transmute :: < & '_ [u8 ; 80] , & '_ mut [i8 ; 80] > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
                let mut sockerr: i32 = unsafe { *__errno_location() };
                if sockerr != 0 && detail == 5 as i32 {
                    Curl_strerror(
                        sockerr,
                        extramsg.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 80]>() as u64,
                    );
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
        (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_3;
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
            Curl_multiuse_state(
                data,
                if (unsafe { (*conn).negnpn }) == CURL_HTTP_VERSION_2_0 as i32 {
                    2 as i32
                } else {
                    -(1 as i32)
                },
            );
        }
        return CURLE_OK;
    };
}
extern "C" fn asn1_object_dump(
    mut a: *mut crate::src::lib::vtls::openssl::asn1_object_st,
    mut buf: *mut i8,
    mut len: u64,
) -> i32 {
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
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut mem: *mut crate::src::lib::vtls::openssl::bio_st,
    mut num: i32,
    mut type_0: *const i8,
    mut name: *const i8,
    mut bn: *const crate::src::lib::vtls::openssl::bignum_st,
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
    Curl_ssl_push_certinfo_len(data, num, namebuf.as_mut_ptr(), ptr, info_len as size_t);
    let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
}
extern "C" fn X509V3_ext(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut certnum: i32,
    mut exts: *const crate::src::lib::vtls::openssl::stack_st_X509_EXTENSION,
) {
    let mut i: i32 = 0;
    if sk_X509_EXTENSION_num(exts) <= 0 as i32 {
        return;
    }
    i = 0 as i32;
    while i < sk_X509_EXTENSION_num(exts) {
        let mut obj: *mut crate::src::lib::vtls::openssl::asn1_object_st = 0 as *mut ASN1_OBJECT;
        let mut ext: *mut crate::src::lib::vtls::openssl::X509_extension_st =
            sk_X509_EXTENSION_value(exts, i);
        let mut biomem: *mut crate::src::lib::vtls::openssl::buf_mem_st = 0 as *mut BUF_MEM;
        let mut namebuf: [i8; 128] = [0; 128];
        let mut bio_out: *mut crate::src::lib::vtls::openssl::bio_st = unsafe { BIO_new(BIO_s_mem()) };
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
        Curl_ssl_push_certinfo_len(
            data,
            certnum,
            namebuf.as_mut_ptr(),
            unsafe { (*biomem).data },
            unsafe { (*biomem).length },
        );
        (unsafe { BIO_free(bio_out) });
        i += 1;
    }
}
extern "C" fn get_cert_chain<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut connssl: Option<&'a1 mut crate::src::lib::http2::ssl_connect_data>,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut sk: *mut crate::src::lib::vtls::openssl::stack_st_X509 = 0 as *mut stack_st_X509;
    let mut i: i32 = 0;
    let mut numcerts: i32 = 0;
    let mut mem: *mut crate::src::lib::vtls::openssl::bio_st = 0 as *mut BIO;
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    sk = unsafe { SSL_get_peer_cert_chain((*backend).handle) };
    if sk.is_null() {
        return CURLE_OUT_OF_MEMORY;
    }
    numcerts = sk_X509_num(sk);
    result = Curl_ssl_init_certinfo(data, numcerts);
    if result as u64 != 0 {
        return result;
    }
    mem = unsafe { BIO_new(BIO_s_mem()) };
    i = 0 as i32;
    while i < numcerts {
        let mut num: *mut crate::src::lib::vtls::openssl::asn1_string_st =
            0 as *mut crate::src::lib::vtls::openssl::asn1_string_st;
        let mut x: *mut crate::src::lib::vtls::openssl::x509_st = sk_X509_value(sk, i);
        let mut pubkey: *mut crate::src::lib::vtls::openssl::evp_pkey_st = 0 as *mut EVP_PKEY;
        let mut j: i32 = 0;
        let mut ptr: *mut i8 = 0 as *mut i8;
        let mut psig: *const crate::src::lib::vtls::openssl::asn1_string_st =
            0 as *const ASN1_BIT_STRING;
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
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Subject\0" as *const u8 as *const i8,
            ptr,
            info_len as size_t,
        );
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
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Issuer\0" as *const u8 as *const i8,
            ptr,
            info_len_0 as size_t,
        );
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        (unsafe { BIO_printf(mem, b"%lx\0" as *const u8 as *const i8, X509_get_version(x)) });
        let mut info_len_1: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Version\0" as *const u8 as *const i8,
            ptr,
            info_len_1 as size_t,
        );
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
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Serial Number\0" as *const u8 as *const i8,
            ptr,
            info_len_2 as size_t,
        );
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        let mut sigalg: *const crate::src::lib::vtls::openssl::X509_algor_st =
            0 as *const X509_ALGOR;
        let mut xpubkey: *mut crate::src::lib::vtls::openssl::X509_pubkey_st =
            0 as *mut X509_PUBKEY;
        let mut pubkeyoid: *mut crate::src::lib::vtls::openssl::asn1_object_st =
            0 as *mut ASN1_OBJECT;
        (unsafe { X509_get0_signature(&mut psig, &mut sigalg, x) });
        if !sigalg.is_null() {
            (unsafe { i2a_ASN1_OBJECT(mem, (*sigalg).algorithm) });
            let mut info_len_3: i64 = unsafe { BIO_ctrl(
                mem,
                3 as i32,
                0 as i32 as i64,
                &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
            ) };
            Curl_ssl_push_certinfo_len(
                data,
                i,
                b"Signature Algorithm\0" as *const u8 as *const i8,
                ptr,
                info_len_3 as size_t,
            );
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
                Curl_ssl_push_certinfo_len(
                    data,
                    i,
                    b"Public Key Algorithm\0" as *const u8 as *const i8,
                    ptr,
                    info_len_4 as size_t,
                );
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
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Start date\0" as *const u8 as *const i8,
            ptr,
            info_len_5 as size_t,
        );
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        (unsafe { ASN1_TIME_print(mem, X509_get0_notAfter(x)) });
        let mut info_len_6: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Expire date\0" as *const u8 as *const i8,
            ptr,
            info_len_6 as size_t,
        );
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
                    let mut rsa: *mut crate::src::lib::vtls::openssl::rsa_st = 0 as *mut RSA;
                    rsa = unsafe { EVP_PKEY_get0_RSA(pubkey) };
                    let mut n: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut e: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    (unsafe { RSA_get0_key(rsa, &mut n, &mut e, 0 as *mut *const BIGNUM) });
                    (unsafe { BIO_printf(mem, b"%d\0" as *const u8 as *const i8, BN_num_bits(n)) });
                    let mut info_len_7: i64 = unsafe { BIO_ctrl(
                        mem,
                        3 as i32,
                        0 as i32 as i64,
                        &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
                    ) };
                    Curl_ssl_push_certinfo_len(
                        data,
                        i,
                        b"RSA Public Key\0" as *const u8 as *const i8,
                        ptr,
                        info_len_7 as size_t,
                    );
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
                    let mut dsa: *mut crate::src::lib::vtls::openssl::dsa_st = 0 as *mut DSA;
                    dsa = unsafe { EVP_PKEY_get0_DSA(pubkey) };
                    let mut p: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut q: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut g: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut pub_key: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
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
                    let mut dh: *mut crate::src::lib::vtls::openssl::dh_st = 0 as *mut DH;
                    dh = unsafe { EVP_PKEY_get0_DH(pubkey) };
                    let mut p_0: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut q_0: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut g_0: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
                    let mut pub_key_0: *const crate::src::lib::vtls::openssl::bignum_st =
                        0 as *const BIGNUM;
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
            Curl_ssl_push_certinfo_len(
                data,
                i,
                b"Signature\0" as *const u8 as *const i8,
                ptr,
                info_len_8 as size_t,
            );
            let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        }
        (unsafe { PEM_write_bio_X509(mem, x) });
        let mut info_len_9: i64 = unsafe { BIO_ctrl(
            mem,
            3 as i32,
            0 as i32 as i64,
            &mut ptr as *mut *mut i8 as *mut i8 as *mut libc::c_void,
        ) };
        Curl_ssl_push_certinfo_len(
            data,
            i,
            b"Cert\0" as *const u8 as *const i8,
            ptr,
            info_len_9 as size_t,
        );
        let _ = 1 as i32 != (unsafe { BIO_ctrl(mem, 1 as i32, 0 as i32 as i64, 0 as *mut libc::c_void) }) as i32;
        i += 1;
    }
    (unsafe { BIO_free(mem) });
    return CURLE_OK;
}
extern "C" fn pkp_pin_peer_pubkey(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut cert: *mut crate::src::lib::vtls::openssl::x509_st,
    mut pinnedpubkey: *const i8,
) -> u32 {
    let mut len1: i32 = 0 as i32;
    let mut len2: i32 = 0 as i32;
    let mut buff1: *mut u8 = 0 as *mut u8;
    let mut temp: *mut u8 = 0 as *mut u8;
    let mut result: u32 = CURLE_SSL_PINNEDPUBKEYNOTMATCH;
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
                result = Curl_pin_peer_pubkey(data, pinnedpubkey, buff1, len1 as size_t);
            }
        }
    }
    if !buff1.is_null() {
        (unsafe { Curl_cfree.expect("non-null function pointer")(buff1 as *mut libc::c_void) });
    }
    return result;
}
extern "C" fn servercert<'a1>(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut connssl: Option<&'a1 mut crate::src::lib::http2::ssl_connect_data>,
    mut strict: bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut rc: i32 = 0;
    let mut lerr: i64 = 0;
    let mut issuer: *mut crate::src::lib::vtls::openssl::x509_st = 0 as *mut X509;
    let mut fp: *mut crate::src::lib::vtls::openssl::bio_st = 0 as *mut BIO;
    let mut error_buffer : [i8 ; 256] = * (unsafe { core :: intrinsics :: transmute :: < & '_ [u8 ; 256] , & '_ mut [i8 ; 256] > (b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0" ,) }) ;
    let mut buffer: [i8; 2048] = [0; 2048];
    let mut ptr: *const i8 = 0 as *const i8;
    let mut mem: *mut crate::src::lib::vtls::openssl::bio_st = unsafe { BIO_new(BIO_s_mem()) };
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    if (unsafe { ((*data).set.ssl).certinfo() }) != 0 {
        get_cert_chain(data, borrow_mut(&mut connssl));
    }
    let mut fresh14 = unsafe { &mut ((*backend).server_cert) };
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
            let mut fresh15 = unsafe { &mut ((*backend).server_cert) };
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
                    let mut fresh16 = unsafe { &mut ((*backend).server_cert) };
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
                    let mut fresh17 = unsafe { &mut ((*backend).server_cert) };
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
                let mut fresh18 = unsafe { &mut ((*backend).server_cert) };
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
                let mut fresh19 = unsafe { &mut ((*backend).server_cert) };
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
        result = verifystatus(data, borrow_mut(&mut connssl));
        if result as u64 != 0 {
            (unsafe { X509_free((*backend).server_cert) });
            let mut fresh20 = unsafe { &mut ((*backend).server_cert) };
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
    let mut fresh21 = unsafe { &mut ((*backend).server_cert) };
    *fresh21 = 0 as *mut X509;
    (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_done;
    return result;
}
extern "C" fn ossl_connect_step3(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    result = servercert(
        data,
        conn,
        borrow_mut(&mut connssl),
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
        (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_done;
    }
    return result;
}
extern "C" fn ossl_connect_common(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
    mut nonblocking: bool,
    mut done: *mut bool,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut sockfd: i32 = unsafe { (*conn).sock[sockindex as usize] };
    let mut what: i32 = 0;
    if ssl_connection_complete as i32 as u32 == (*(borrow(&connssl)).unwrap()).state as u32 {
        (unsafe { *done = 1 as i32 != 0 });
        return CURLE_OK;
    }
    if ssl_connect_1 as i32 as u32 == (*(borrow(&connssl)).unwrap()).connecting_state as u32 {
        let timeout_ms: i64 = Curl_timeleft(
            data,
            0 as *mut crate::src::lib::http2::curltime,
            1 as i32 != 0,
        );
        if timeout_ms < 0 as i32 as i64 {
            (unsafe { Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8) });
            return CURLE_OPERATION_TIMEDOUT;
        }
        result = ossl_connect_step1(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    while ssl_connect_2 as i32 as u32 == (*(borrow(&connssl)).unwrap()).connecting_state as u32
        || ssl_connect_2_reading as i32 as u32
            == (*(borrow(&connssl)).unwrap()).connecting_state as u32
        || ssl_connect_2_writing as i32 as u32
            == (*(borrow(&connssl)).unwrap()).connecting_state as u32
    {
        let timeout_ms_0: i64 = Curl_timeleft(
            data,
            0 as *mut crate::src::lib::http2::curltime,
            1 as i32 != 0,
        );
        if timeout_ms_0 < 0 as i32 as i64 {
            (unsafe { Curl_failf(data, b"SSL connection timeout\0" as *const u8 as *const i8) });
            return CURLE_OPERATION_TIMEDOUT;
        }
        if (*(borrow(&connssl)).unwrap()).connecting_state as u32
            == ssl_connect_2_reading as i32 as u32
            || (*(borrow(&connssl)).unwrap()).connecting_state as u32
                == ssl_connect_2_writing as i32 as u32
        {
            let mut writefd: i32 = if ssl_connect_2_writing as i32 as u32
                == (*(borrow(&connssl)).unwrap()).connecting_state as u32
            {
                sockfd
            } else {
                -(1 as i32)
            };
            let mut readfd: i32 = if ssl_connect_2_reading as i32 as u32
                == (*(borrow(&connssl)).unwrap()).connecting_state as u32
            {
                sockfd
            } else {
                -(1 as i32)
            };
            what = Curl_socket_check(
                readfd,
                -(1 as i32),
                writefd,
                if nonblocking as i32 != 0 {
                    0 as i32 as i64
                } else {
                    timeout_ms_0
                },
            );
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
                && (ssl_connect_2 as i32 as u32
                    == (*(borrow(&connssl)).unwrap()).connecting_state as u32
                    || ssl_connect_2_reading as i32 as u32
                        == (*(borrow(&connssl)).unwrap()).connecting_state as u32
                    || ssl_connect_2_writing as i32 as u32
                        == (*(borrow(&connssl)).unwrap()).connecting_state as u32)
        {
            return result;
        }
    }
    if ssl_connect_3 as i32 as u32 == (*(borrow(&connssl)).unwrap()).connecting_state as u32 {
        result = ossl_connect_step3(data, conn, sockindex);
        if result as u64 != 0 {
            return result;
        }
    }
    if ssl_connect_done as i32 as u32 == (*(borrow(&connssl)).unwrap()).connecting_state as u32 {
        (*(borrow_mut(&mut connssl)).unwrap()).state = ssl_connection_complete;
        let mut fresh22 = unsafe { &mut ((*conn).recv[sockindex as usize]) };
        *fresh22 = Some(ossl_recv);
        let mut fresh23 = unsafe { &mut ((*conn).send[sockindex as usize]) };
        *fresh23 = Some(ossl_send);
        (unsafe { *done = 1 as i32 != 0 });
    } else {
        (unsafe { *done = 0 as i32 != 0 });
    }
    (*(borrow_mut(&mut connssl)).unwrap()).connecting_state = ssl_connect_1;
    return CURLE_OK;
}
extern "C" fn ossl_connect_nonblocking(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
    mut done: *mut bool,
) -> u32 {
    return ossl_connect_common(data, conn, sockindex, 1 as i32 != 0, done);
}
extern "C" fn ossl_connect(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) -> u32 {
    let mut result: u32 = CURLE_OK;
    let mut done: bool = 0 as i32 != 0;
    result = ossl_connect_common(data, conn, sockindex, 0 as i32 != 0, &mut done);
    if result as u64 != 0 {
        return result;
    }
    return CURLE_OK;
}
extern "C" fn ossl_data_pending(
    mut conn: *const crate::src::lib::http2::connectdata,
    mut connindex: i32,
) -> bool {
    let mut connssl: Option<&'_ crate::src::lib::http2::ssl_connect_data> =
        (Some(unsafe { &*((*conn).ssl).as_ptr().offset(connindex as isize) })).clone();
    if !(unsafe { (*(*((connssl).clone()).unwrap()).backend).handle }).is_null()
        && (unsafe { SSL_pending((*(*((connssl).clone()).unwrap()).backend).handle) }) != 0
    {
        return 1 as i32 != 0;
    }
    let mut proxyssl: Option<&'_ crate::src::lib::http2::ssl_connect_data> =
        (Some(unsafe { &*((*conn).proxy_ssl).as_ptr().offset(connindex as isize) })).clone();
    if !(unsafe { (*(*((proxyssl).clone()).unwrap()).backend).handle }).is_null()
        && (unsafe { SSL_pending((*(*((proxyssl).clone()).unwrap()).backend).handle) }) != 0
    {
        return 1 as i32 != 0;
    }
    return 0 as i32 != 0;
}
extern "C" fn ossl_send(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sockindex: i32,
    mut mem: *const core::ffi::c_void,
    mut len: u64,
    mut curlcode: *mut u32,
) -> i64 {
    let mut err: i32 = 0;
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut memlen: i32 = 0;
    let mut rc: i32 = 0;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    (unsafe { ERR_clear_error() });
    memlen = if len > 2147483647 as i32 as size_t {
        2147483647 as i32
    } else {
        len as i32
    };
    let mut fresh24 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
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
                    Curl_strerror(
                        sockerr,
                        error_buffer.as_mut_ptr(),
                        ::std::mem::size_of::<[i8; 256]>() as u64,
                    );
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
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut num: i32,
    mut buf: *mut i8,
    mut buffersize: u64,
    mut curlcode: *mut u32,
) -> i64 {
    let mut error_buffer: [i8; 256] = [0; 256];
    let mut sslerror: u64 = 0;
    let mut nread: i64 = 0;
    let mut buffsize: i32 = 0;
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(num as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
    (unsafe { ERR_clear_error() });
    buffsize = if buffersize > 2147483647 as i32 as size_t {
        2147483647 as i32
    } else {
        buffersize as i32
    };
    let mut fresh25 = unsafe { &mut ((*(*conn).ssl[0 as i32 as usize].backend).logger) };
    *fresh25 = data;
    nread = (unsafe { SSL_read((*backend).handle, buf as *mut libc::c_void, buffsize) }) as ssize_t;
    if nread <= 0 as i32 as i64 {
        let mut err: i32 = unsafe { SSL_get_error((*backend).handle, nread as i32) };
        match err {
            0 => {}
            6 => {
                if num == 0 as i32 {
                    Curl_conncontrol(conn, 1 as i32);
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
                        Curl_strerror(
                            sockerr,
                            error_buffer.as_mut_ptr(),
                            ::std::mem::size_of::<[i8; 256]>() as u64,
                        );
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
extern "C" fn ossl_version(mut buffer: *mut i8, mut size: u64) -> u64 {
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
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut entropy: *mut u8,
    mut length: u64,
) -> u32 {
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
    mut tmplen: u64,
    mut sha256sum: *mut u8,
    mut _unused: u64,
) -> u32 {
    let mut mdctx: *mut crate::src::lib::vtls::openssl::evp_md_ctx_st = 0 as *mut EVP_MD_CTX;
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
    mut connssl: *mut crate::src::lib::http2::ssl_connect_data,
    mut info: u32,
) -> *mut core::ffi::c_void {
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data = unsafe { (*connssl).backend };
    return if info as u32 == CURLINFO_TLS_SESSION as i32 as u32 {
        (unsafe { (*backend).ctx }) as *mut libc::c_void
    } else {
        (unsafe { (*backend).handle }) as *mut libc::c_void
    };
}
extern "C" fn ossl_associate_connection(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut conn: *mut crate::src::lib::http2::connectdata,
    mut sockindex: i32,
) {
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
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
extern "C" fn ossl_disassociate_connection(
    mut data: *mut crate::src::lib::http2::Curl_easy,
    mut sockindex: i32,
) {
    let mut conn: *mut crate::src::lib::http2::connectdata = unsafe { (*data).conn };
    let mut connssl: Option<&'_ mut crate::src::lib::http2::ssl_connect_data> =
        Some(unsafe { &mut *((*conn).ssl).as_mut_ptr().offset(sockindex as isize) });
    let mut backend: *mut crate::src::lib::vtls::openssl::ssl_backend_data =
        (*(borrow_mut(&mut connssl)).unwrap()).backend;
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
pub static mut Curl_ssl_openssl: crate::src::lib::getinfo::Curl_ssl =  {
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
            init: Some(ossl_init),
            cleanup: Some(ossl_cleanup),
            version: Some(ossl_version),
            check_cxn: Some(ossl_check_cxn),
            shut_down: Some(ossl_shutdown),
            data_pending: Some(ossl_data_pending),
            random: Some(ossl_random),
            cert_status_request: Some(ossl_cert_status_request),
            connect_blocking: Some(ossl_connect),
            connect_nonblocking: Some(ossl_connect_nonblocking),
            getsock: Some(Curl_ssl_getsock),
            get_internals: Some(ossl_get_internals),
            close_one: Some(ossl_close),
            close_all: Some(ossl_close_all),
            session_free: Some(ossl_session_free),
            set_engine: Some(ossl_set_engine),
            set_engine_default: Some(ossl_set_engine_default),
            engines_list: Some(ossl_engines_list),
            false_start: Some(Curl_none_false_start),
            sha256sum: Some(ossl_sha256sum),
            associate_connection: Some(ossl_associate_connection),
            disassociate_connection: Some(ossl_disassociate_connection),
        };
        init
    }
};
use crate::laertes_rt::*;
