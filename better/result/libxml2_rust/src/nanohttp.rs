use :: libc;
extern "C" {
    pub type internal_state;
    fn xmlStrdup(cur: *const u8) -> *mut u8;
    fn xmlStrndup(cur: *const u8, len: i32) -> *mut u8;
    fn xmlCharStrndup(cur: *const i8, len: i32) -> *mut u8;
    fn xmlStrstr(str: *const u8, val: *const u8) -> *const u8;
    fn xmlStrncasecmp(str1: *const u8, str2: *const u8, len: i32) -> i32;
    fn xmlStrcat(cur: *mut u8, add: *const u8) -> *mut u8;
    fn __xmlIOErr(domain: i32, code: i32, extra: *const i8);
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memmove(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(_: *const i8, _: *const i8, _: u64) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn getenv(__name: *const i8) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn close(__fd: i32) -> i32;
    fn write(__fd: i32, __buf: *const core::ffi::c_void, __n: u64) -> i64;
    fn connect(__fd: i32, __addr: *const crate::src::nanoftp::sockaddr, __len: u32) -> i32;
    fn socket(__domain: i32, __type: i32, __protocol: i32) -> i32;
    fn send(__fd: i32, __buf: *const core::ffi::c_void, __n: u64, __flags: i32) -> i64;
    fn recv(__fd: i32, __buf: *mut core::ffi::c_void, __n: u64, __flags: i32) -> i64;
    fn getsockopt(
        __fd: i32,
        __level: i32,
        __optname: i32,
        __optval: *mut core::ffi::c_void,
        __optlen: *mut u32,
    ) -> i32;
    fn __h_errno_location() -> *mut i32;
    fn gethostbyname(__name: *const i8) -> *mut crate::src::nanoftp::hostent;
    fn getaddrinfo(
        __name: *const i8,
        __service: *const i8,
        __req: *const crate::src::nanoftp::addrinfo,
        __pai: *mut *mut crate::src::nanoftp::addrinfo,
    ) -> i32;
    fn freeaddrinfo(__ai: *mut crate::src::nanoftp::addrinfo);
    fn fcntl(__fd: i32, __cmd: i32, _: ...) -> i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn poll(__fds: *mut crate::src::nanohttp::pollfd, __nfds: u64, __timeout: i32) -> i32;
    fn inflateEnd(strm: *mut crate::src::nanohttp::z_stream_s) -> i32;
    fn inflate(strm: *mut crate::src::nanohttp::z_stream_s, flush: i32) -> i32;
    fn inflateInit2_(
        strm: *mut crate::src::nanohttp::z_stream_s,
        windowBits: i32,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    fn xmlParseURIRaw(str: *const i8, raw: i32) -> *mut crate::src::SAX2::_xmlURI;
    fn xmlFreeURI(uri: *mut crate::src::SAX2::_xmlURI);
}
pub use crate::src::dict::_xmlDict;
pub use crate::src::error::__xmlSimpleError;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlMemStrdup;
pub use crate::src::globals::xmlRealloc;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __uint8_t = u8;
pub type __uint16_t = u16;
pub type __uint32_t = u32;
pub type __ssize_t = i64;
pub type __socklen_t = u32;
pub type ssize_t = i64;
pub type socklen_t = u32;
pub type __socket_type = u32;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = u16;
pub type sockaddr = crate::src::nanoftp::sockaddr;
pub type uint8_t = u8;
pub type uint16_t = u16;
pub type uint32_t = u32;
pub type in_addr_t = u32;
pub type in_addr = crate::src::nanoftp::in_addr;
pub type C2RustUnnamed = u32;
pub const IPPROTO_MAX: C2RustUnnamed = 256;
pub const IPPROTO_RAW: C2RustUnnamed = 255;
pub const IPPROTO_MPLS: C2RustUnnamed = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed = 136;
pub const IPPROTO_SCTP: C2RustUnnamed = 132;
pub const IPPROTO_COMP: C2RustUnnamed = 108;
pub const IPPROTO_PIM: C2RustUnnamed = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed = 94;
pub const IPPROTO_MTP: C2RustUnnamed = 92;
pub const IPPROTO_AH: C2RustUnnamed = 51;
pub const IPPROTO_ESP: C2RustUnnamed = 50;
pub const IPPROTO_GRE: C2RustUnnamed = 47;
pub const IPPROTO_RSVP: C2RustUnnamed = 46;
pub const IPPROTO_IPV6: C2RustUnnamed = 41;
pub const IPPROTO_DCCP: C2RustUnnamed = 33;
pub const IPPROTO_TP: C2RustUnnamed = 29;
pub const IPPROTO_IDP: C2RustUnnamed = 22;
pub const IPPROTO_UDP: C2RustUnnamed = 17;
pub const IPPROTO_PUP: C2RustUnnamed = 12;
pub const IPPROTO_EGP: C2RustUnnamed = 8;
pub const IPPROTO_TCP: C2RustUnnamed = 6;
pub const IPPROTO_IPIP: C2RustUnnamed = 4;
pub const IPPROTO_IGMP: C2RustUnnamed = 2;
pub const IPPROTO_ICMP: C2RustUnnamed = 1;
pub const IPPROTO_IP: C2RustUnnamed = 0;
pub type in_port_t = u16;
pub type in6_addr = crate::src::nanoftp::in6_addr;
pub type C2RustUnnamed_0 = crate::src::nanoftp::C2RustUnnamed_0;
pub type sockaddr_in = crate::src::nanoftp::sockaddr_in;
pub type sockaddr_in6 = crate::src::nanoftp::sockaddr_in6;
pub type hostent = crate::src::nanoftp::hostent;
pub type addrinfo = crate::src::nanoftp::addrinfo;
pub type nfds_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
impl pollfd {
    pub const fn new() -> Self {
        pollfd {
            fd: 0,
            events: 0,
            revents: 0,
        }
    }
}
impl std::default::Default for pollfd {
    fn default() -> Self {
        pollfd::new()
    }
}
pub type Byte = u8;
pub type uInt = u32;
pub type uLong = u64;
pub type Bytef = u8;
pub type voidpf = *mut core::ffi::c_void;
pub type alloc_func = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u32, _: u32) -> *mut core::ffi::c_void,
>;
pub type free_func =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut u8,
    pub avail_in: u32,
    pub total_in: u64,
    pub next_out: *mut u8,
    pub avail_out: u32,
    pub total_out: u64,
    pub msg: *mut i8,
    pub state: *mut crate::src::nanohttp::internal_state,
    pub zalloc: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u32, _: u32) -> *mut core::ffi::c_void,
    >,
    pub zfree:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut core::ffi::c_void) -> ()>,
    pub opaque: *mut core::ffi::c_void,
    pub data_type: i32,
    pub adler: u64,
    pub reserved: u64,
}
impl z_stream_s {
    pub const fn new() -> Self {
        z_stream_s {
            next_in: (0 as *mut u8),
            avail_in: 0,
            total_in: 0,
            next_out: (0 as *mut u8),
            avail_out: 0,
            total_out: 0,
            msg: (0 as *mut i8),
            state: (0 as *mut crate::src::nanohttp::internal_state),
            zalloc: None,
            zfree: None,
            opaque: (0 as *mut core::ffi::c_void),
            data_type: 0,
            adler: 0,
            reserved: 0,
        }
    }
}
impl std::default::Default for z_stream_s {
    fn default() -> Self {
        z_stream_s::new()
    }
}
pub type z_stream = crate::src::nanohttp::z_stream_s;
pub type z_streamp = *mut crate::src::nanohttp::z_stream_s;
pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlElementType = u32;
pub const XML_XINCLUDE_END: xmlElementType = 20;
pub const XML_XINCLUDE_START: xmlElementType = 19;
pub const XML_NAMESPACE_DECL: xmlElementType = 18;
pub const XML_ENTITY_DECL: xmlElementType = 17;
pub const XML_ATTRIBUTE_DECL: xmlElementType = 16;
pub const XML_ELEMENT_DECL: xmlElementType = 15;
pub const XML_DTD_NODE: xmlElementType = 14;
pub const XML_HTML_DOCUMENT_NODE: xmlElementType = 13;
pub const XML_NOTATION_NODE: xmlElementType = 12;
pub const XML_DOCUMENT_FRAG_NODE: xmlElementType = 11;
pub const XML_DOCUMENT_TYPE_NODE: xmlElementType = 10;
pub const XML_DOCUMENT_NODE: xmlElementType = 9;
pub const XML_COMMENT_NODE: xmlElementType = 8;
pub const XML_PI_NODE: xmlElementType = 7;
pub const XML_ENTITY_NODE: xmlElementType = 6;
pub const XML_ENTITY_REF_NODE: xmlElementType = 5;
pub const XML_CDATA_SECTION_NODE: xmlElementType = 4;
pub const XML_TEXT_NODE: xmlElementType = 3;
pub const XML_ATTRIBUTE_NODE: xmlElementType = 2;
pub const XML_ELEMENT_NODE: xmlElementType = 1;
pub type xmlNsType = u32;
pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlAttributeType = u32;
pub const XML_ATTRIBUTE_NOTATION: xmlAttributeType = 10;
pub const XML_ATTRIBUTE_ENUMERATION: xmlAttributeType = 9;
pub const XML_ATTRIBUTE_NMTOKENS: xmlAttributeType = 8;
pub const XML_ATTRIBUTE_NMTOKEN: xmlAttributeType = 7;
pub const XML_ATTRIBUTE_ENTITIES: xmlAttributeType = 6;
pub const XML_ATTRIBUTE_ENTITY: xmlAttributeType = 5;
pub const XML_ATTRIBUTE_IDREFS: xmlAttributeType = 4;
pub const XML_ATTRIBUTE_IDREF: xmlAttributeType = 3;
pub const XML_ATTRIBUTE_ID: xmlAttributeType = 2;
pub const XML_ATTRIBUTE_CDATA: xmlAttributeType = 1;
pub type xmlNodePtr = *mut crate::src::HTMLparser::_xmlNode;
pub type xmlNode = crate::src::HTMLparser::_xmlNode;
pub type C2RustUnnamed_1 = u32;
pub const XML_FROM_URI: C2RustUnnamed_1 = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed_1 = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed_1 = 28;
pub const XML_FROM_I18N: C2RustUnnamed_1 = 27;
pub const XML_FROM_MODULE: C2RustUnnamed_1 = 26;
pub const XML_FROM_WRITER: C2RustUnnamed_1 = 25;
pub const XML_FROM_CHECK: C2RustUnnamed_1 = 24;
pub const XML_FROM_VALID: C2RustUnnamed_1 = 23;
pub const XML_FROM_XSLT: C2RustUnnamed_1 = 22;
pub const XML_FROM_C14N: C2RustUnnamed_1 = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed_1 = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed_1 = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed_1 = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed_1 = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed_1 = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed_1 = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed_1 = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed_1 = 13;
pub const XML_FROM_XPATH: C2RustUnnamed_1 = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed_1 = 11;
pub const XML_FROM_HTTP: C2RustUnnamed_1 = 10;
pub const XML_FROM_FTP: C2RustUnnamed_1 = 9;
pub const XML_FROM_IO: C2RustUnnamed_1 = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed_1 = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed_1 = 6;
pub const XML_FROM_HTML: C2RustUnnamed_1 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_1 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_1 = 3;
pub const XML_FROM_TREE: C2RustUnnamed_1 = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_1 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = u32;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_2 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_2 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_2 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_2 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_2 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_2 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_2 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_2 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_2 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_2 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_2 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_2 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_2 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_2 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_2 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_2 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_2 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_2 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_2 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_2 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_2 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_2 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_2 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_2 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_2 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_2 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_2 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_2 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_2 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_2 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_2 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_2 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_2 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_2 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_2 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_2 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_2 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_2 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_2 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_2 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_2 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_2 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_2 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_2 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_2 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_2 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_2 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_2 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_2 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_2 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_2 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_2 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_2 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_2 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_2 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_2 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_2 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_2 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_2 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_2 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_2 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_2 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_2 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_2 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_2 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_2 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_2 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_2 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_2 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_2 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_2 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_2 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_2 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_2 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_2 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_2 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_2 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_2 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_2 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_2 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_2 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_2 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_2 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_2 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_2 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_2 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_2 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_2 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_2 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_2 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_2 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_2 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_2 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_2 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_2 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_2 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_2 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_2 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_2 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_2 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_2 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_2 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_2 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_2 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_2 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_2 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_2 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_2 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_2 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_2 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_2 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_2 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_2 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_2 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_2 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_2 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_2 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_2 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_2 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_2 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_2 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_2 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_2 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_2 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_2 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_2 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_2 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_2 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_2 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_2 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_2 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_2 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_2 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_2 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_2 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_2 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_2 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_2 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_2 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_2 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_2 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_2 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_2 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_2 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_2 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_2 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_2 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_2 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_2 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_2 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_2 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_2 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_2 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_2 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_2 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_2 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_2 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_2 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_2 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_2 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_2 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_2 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_2 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_2 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_2 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_2 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_2 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_2 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_2 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_2 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_2 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_2 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_2 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_2 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_2 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_2 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_2 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_2 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_2 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_2 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_2 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_2 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_2 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_2 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_2 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_2 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_2 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_2 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_2 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_2 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_2 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_2 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_2 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_2 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_2 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_2 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_2 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_2 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_2 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_2 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_2 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_2 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_2 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_2 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_2 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_2 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_2 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_2 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_2 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_2 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_2 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_2 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_2 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_2 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_2 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_2 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_2 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_2 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_2 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_2 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_2 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_2 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_2 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_2 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_2 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_2 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_2 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_2 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_2 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_2 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_2 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_2 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_2 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_2 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_2 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_2 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_2 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_2 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_2 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_2 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_2 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_2 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_2 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_2 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_2 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_2 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_2 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_2 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_2 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_2 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_2 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_2 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_2 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_2 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_2 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_2 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_2 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_2 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_2 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_2 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_2 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_2 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_2 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_2 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_2 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_2 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_2 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_2 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_2 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_2 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_2 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_2 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_2 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_2 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_2 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_2 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_2 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_2 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_2 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_2 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_2 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_2 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_2 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_2 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_2 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_2 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_2 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_2 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_2 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_2 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_2 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_2 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_2 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_2 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_2 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_2 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_2 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_2 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_2 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_2 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_2 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_2 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_2 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_2 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_2 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_2 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_2 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_2 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_2 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_2 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_2 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_2 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_2 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_2 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_2 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_2 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_2 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_2 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_2 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_2 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_2 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_2 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_2 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_2 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_2 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_2 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_2 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_2 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_2 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_2 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_2 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_2 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_2 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_2 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_2 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_2 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_2 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_2 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_2 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_2 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_2 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_2 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_2 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_2 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_2 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_2 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_2 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_2 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_2 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_2 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_2 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_2 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_2 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_2 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_2 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_2 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_2 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_2 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_2 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_2 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_2 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_2 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_2 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_2 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_2 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_2 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_2 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_2 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_2 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_2 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_2 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_2 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_2 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_2 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_2 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_2 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_2 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_2 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_2 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_2 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_2 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_2 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_2 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_2 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_2 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_2 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_2 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_2 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_2 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_2 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_2 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_2 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_2 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_2 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_2 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_2 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_2 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_2 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_2 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_2 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_2 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_2 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_2 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_2 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_2 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_2 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_2 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_2 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_2 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_2 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_2 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_2 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_2 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_2 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_2 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_2 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_2 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_2 = 1500;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_2 = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_2 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_2 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_2 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_2 = 1400;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_2 = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_2 = 1302;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_2 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_2 = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_2 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_2 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_2 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_2 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_2 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_2 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_2 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_2 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_2 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_2 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_2 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_2 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_2 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_2 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_2 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_2 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_2 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_2 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_2 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_2 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_2 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_2 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_2 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_2 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_2 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_2 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_2 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_2 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_2 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_2 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_2 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_2 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_2 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_2 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_2 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_2 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_2 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_2 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_2 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_2 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_2 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_2 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_2 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_2 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_2 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_2 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_2 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_2 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_2 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_2 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_2 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_2 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_2 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_2 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_2 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_2 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_2 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_2 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_2 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_2 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_2 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_2 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_2 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_2 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_2 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_2 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_2 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_2 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_2 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_2 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_2 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_2 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_2 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_2 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_2 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_2 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_2 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_2 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_2 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_2 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_2 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_2 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_2 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_2 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_2 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_2 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_2 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_2 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_2 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_2 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_2 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_2 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_2 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_2 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_2 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_2 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_2 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_2 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_2 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_2 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_2 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_2 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_2 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_2 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_2 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_2 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_2 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_2 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_2 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_2 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_2 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_2 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_2 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_2 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_2 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_2 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_2 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_2 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_2 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_2 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_2 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_2 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_2 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_2 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_2 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_2 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_2 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_2 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_2 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_2 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_2 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_2 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_2 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_2 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_2 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_2 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_2 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_2 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_2 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_2 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_2 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_2 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_2 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_2 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_2 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_2 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_2 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_2 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_2 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_2 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_2 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_2 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_2 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_2 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_2 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_2 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_2 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_2 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_2 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_2 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_2 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_2 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_2 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_2 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_2 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_2 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_2 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_2 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_2 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_2 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_2 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_2 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_2 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_2 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_2 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_2 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_2 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_2 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_2 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_2 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_2 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_2 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_2 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_2 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_2 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_2 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_2 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_2 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_2 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_2 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_2 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_2 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_2 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_2 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_2 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_2 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_2 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_2 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_2 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_2 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_2 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_2 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_2 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_2 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_2 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_2 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_2 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_2 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_2 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_2 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_2 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_2 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_2 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_2 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_2 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_2 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_2 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_2 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_2 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_2 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_2 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_2 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_2 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_2 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_2 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_2 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_2 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_2 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_2 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_2 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_2 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_2 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_2 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_2 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_2 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_2 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_2 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_2 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_2 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_2 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_2 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_2 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_2 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_2 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_2 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_2 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_2 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_2 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_2 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_2 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_2 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_2 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_2 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_2 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_2 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_2 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_2 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_2 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_2 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_2 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_2 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_2 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_2 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_2 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_2 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_2 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_2 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_2 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_2 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_2 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_2 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_2 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_2 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_2 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_2 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_2 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_2 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_2 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_2 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_2 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_2 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_2 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_2 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_2 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_2 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_2 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_2 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_2 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_2 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_2 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_2 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_2 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_2 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_2 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_2 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_2 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_2 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_2 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_2 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_2 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_2 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_2 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_2 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_2 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_2 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_2 = 3;
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_2 = 2;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_2 = 1;
pub const XML_ERR_OK: C2RustUnnamed_2 = 0;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>;
pub type xmlURIPtr = *mut crate::src::SAX2::_xmlURI;
pub type xmlURI = crate::src::SAX2::_xmlURI;
pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlNanoHTTPCtxtPtr = *mut crate::src::nanohttp::xmlNanoHTTPCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlNanoHTTPCtxt {
    pub protocol: *mut i8,
    pub hostname: *mut i8,
    pub port: i32,
    pub path: *mut i8,
    pub query: *mut i8,
    pub fd: i32,
    pub state: i32,
    pub out: *mut i8,
    pub outptr: *mut i8,
    pub in_0: *mut i8,
    pub content: *mut i8,
    pub inptr: *mut i8,
    pub inrptr: *mut i8,
    pub inlen: i32,
    pub last: i32,
    pub returnValue: i32,
    pub version: i32,
    pub ContentLength: i32,
    pub contentType: *mut i8,
    pub location: *mut i8,
    pub authHeader: *mut i8,
    pub encoding: *mut i8,
    pub mimeType: *mut i8,
    pub strm: *mut crate::src::nanohttp::z_stream_s,
    pub usesGzip: i32,
}
impl xmlNanoHTTPCtxt {
    pub const fn new() -> Self {
        xmlNanoHTTPCtxt {
            protocol: (0 as *mut i8),
            hostname: (0 as *mut i8),
            port: 0,
            path: (0 as *mut i8),
            query: (0 as *mut i8),
            fd: 0,
            state: 0,
            out: (0 as *mut i8),
            outptr: (0 as *mut i8),
            in_0: (0 as *mut i8),
            content: (0 as *mut i8),
            inptr: (0 as *mut i8),
            inrptr: (0 as *mut i8),
            inlen: 0,
            last: 0,
            returnValue: 0,
            version: 0,
            ContentLength: 0,
            contentType: (0 as *mut i8),
            location: (0 as *mut i8),
            authHeader: (0 as *mut i8),
            encoding: (0 as *mut i8),
            mimeType: (0 as *mut i8),
            strm: (0 as *mut crate::src::nanohttp::z_stream_s),
            usesGzip: 0,
        }
    }
}
impl std::default::Default for xmlNanoHTTPCtxt {
    fn default() -> Self {
        xmlNanoHTTPCtxt::new()
    }
}
#[inline]
extern "C" fn __bswap_16(mut __bsx: u16) -> u16 {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32 | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
static mut initialized: i32 = 0 as i32;
static mut proxy: *mut i8 = 0 as *const i8 as *mut i8;
static mut proxyPort: i32 = 0;
static mut timeout: u32 = 60 as i32 as u32;
extern "C" fn xmlHTTPErrMemory(mut extra: *const i8) {
    __xmlSimpleError(
        XML_FROM_HTTP as i32,
        XML_ERR_NO_MEMORY as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
}
extern "C" fn socket_errno() -> i32 {
    return unsafe { *__errno_location() };
}
extern "C" fn have_ipv6() -> i32 {
    let mut s: i32 = 0;
    s = unsafe { socket(10 as i32, SOCK_STREAM as i32, 0 as i32) };
    if s != -(1 as i32) {
        (unsafe { close(s) });
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPInit() {
    let mut env: *const i8 = 0 as *const i8;
    if (unsafe { initialized }) != 0 {
        return;
    }
    if (unsafe { proxy }).is_null() {
        (unsafe { proxyPort = 80 as i32 });
        env = unsafe { getenv(b"no_proxy\0" as *const u8 as *const i8) };
        if !(!env.is_null()
            && ((unsafe { *env.offset(0 as i32 as isize) }) as i32 == '*' as i32
                && (unsafe { *env.offset(1 as i32 as isize) }) as i32 == 0 as i32))
        {
            env = unsafe { getenv(b"http_proxy\0" as *const u8 as *const i8) };
            if !env.is_null() {
                xmlNanoHTTPScanProxy(env);
            } else {
                env = unsafe { getenv(b"HTTP_PROXY\0" as *const u8 as *const i8) };
                if !env.is_null() {
                    xmlNanoHTTPScanProxy(env);
                }
            }
        }
    }
    (unsafe { initialized = 1 as i32 });
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPCleanup() {
    if !(unsafe { proxy }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(proxy as *mut libc::c_void) });
        (unsafe { proxy = 0 as *mut i8 });
    }
    (unsafe { initialized = 0 as i32 });
}
extern "C" fn xmlNanoHTTPScanURL(
    mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt,
    mut URL: *const i8,
) {
    let mut uri: *mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
    let mut len: i32 = 0;
    if !(unsafe { (*ctxt).protocol }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).protocol as *mut libc::c_void)
        });
        let fresh0 = unsafe { &mut ((*ctxt).protocol) };
        *fresh0 = 0 as *mut i8;
    }
    if !(unsafe { (*ctxt).hostname }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).hostname as *mut libc::c_void)
        });
        let fresh1 = unsafe { &mut ((*ctxt).hostname) };
        *fresh1 = 0 as *mut i8;
    }
    if !(unsafe { (*ctxt).path }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).path as *mut libc::c_void) });
        let fresh2 = unsafe { &mut ((*ctxt).path) };
        *fresh2 = 0 as *mut i8;
    }
    if !(unsafe { (*ctxt).query }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).query as *mut libc::c_void)
        });
        let fresh3 = unsafe { &mut ((*ctxt).query) };
        *fresh3 = 0 as *mut i8;
    }
    if URL.is_null() {
        return;
    }
    uri = unsafe { xmlParseURIRaw(URL, 1 as i32) };
    if uri.is_null() {
        return;
    }
    if (unsafe { (*uri).scheme }).is_null() || (unsafe { (*uri).server }).is_null() {
        (unsafe { xmlFreeURI(uri) });
        return;
    }
    let fresh4 = unsafe { &mut ((*ctxt).protocol) };
    *fresh4 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*uri).scheme) };
    if !(unsafe { (*uri).server }).is_null() && (unsafe { *(*uri).server }) as i32 == '[' as i32 {
        len = (unsafe { strlen((*uri).server) }) as i32;
        if len > 2 as i32
            && (unsafe { *((*uri).server).offset((len - 1 as i32) as isize) }) as i32 == ']' as i32
        {
            let fresh5 = unsafe { &mut ((*ctxt).hostname) };
            *fresh5 = (unsafe {
                xmlCharStrndup(((*uri).server).offset(1 as i32 as isize), len - 2 as i32)
            }) as *mut i8;
        } else {
            let fresh6 = unsafe { &mut ((*ctxt).hostname) };
            *fresh6 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*uri).server) };
        }
    } else {
        let fresh7 = unsafe { &mut ((*ctxt).hostname) };
        *fresh7 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*uri).server) };
    }
    if !(unsafe { (*uri).path }).is_null() {
        let fresh8 = unsafe { &mut ((*ctxt).path) };
        *fresh8 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*uri).path) };
    } else {
        let fresh9 = unsafe { &mut ((*ctxt).path) };
        *fresh9 = unsafe {
            xmlMemStrdup.expect("non-null function pointer")(b"/\0" as *const u8 as *const i8)
        };
    }
    if !(unsafe { (*uri).query }).is_null() {
        let fresh10 = unsafe { &mut ((*ctxt).query) };
        *fresh10 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*uri).query) };
    }
    if (unsafe { (*uri).port }) != 0 as i32 {
        (unsafe { (*ctxt).port = (*uri).port });
    }
    (unsafe { xmlFreeURI(uri) });
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPScanProxy(mut URL: *const i8) {
    let mut uri: *mut crate::src::SAX2::_xmlURI = 0 as *mut xmlURI;
    if !(unsafe { proxy }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(proxy as *mut libc::c_void) });
        (unsafe { proxy = 0 as *mut i8 });
    }
    (unsafe { proxyPort = 0 as i32 });
    if URL.is_null() {
        return;
    }
    uri = unsafe { xmlParseURIRaw(URL, 1 as i32) };
    if uri.is_null()
        || (unsafe { (*uri).scheme }).is_null()
        || (unsafe { strcmp((*uri).scheme, b"http\0" as *const u8 as *const i8) }) != 0
        || (unsafe { (*uri).server }).is_null()
    {
        (unsafe {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                XML_HTTP_URL_SYNTAX as i32,
                b"Syntax Error\n\0" as *const u8 as *const i8,
            )
        });
        if !uri.is_null() {
            (unsafe { xmlFreeURI(uri) });
        }
        return;
    }
    (unsafe { proxy = xmlMemStrdup.expect("non-null function pointer")((*uri).server) });
    if (unsafe { (*uri).port }) != 0 as i32 {
        (unsafe { proxyPort = (*uri).port });
    }
    (unsafe { xmlFreeURI(uri) });
}
extern "C" fn xmlNanoHTTPNewCtxt(mut URL: *const i8) -> *mut crate::src::nanohttp::xmlNanoHTTPCtxt {
    let mut ret: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = 0 as *mut xmlNanoHTTPCtxt;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            ::std::mem::size_of::<xmlNanoHTTPCtxt>() as u64
        )
    }) as xmlNanoHTTPCtxtPtr;
    if ret.is_null() {
        xmlHTTPErrMemory(b"allocating context\0" as *const u8 as *const i8);
        return 0 as xmlNanoHTTPCtxtPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNanoHTTPCtxt>() as u64,
        )
    });
    (unsafe { (*ret).port = 80 as i32 });
    (unsafe { (*ret).returnValue = 0 as i32 });
    (unsafe { (*ret).fd = -(1 as i32) });
    (unsafe { (*ret).ContentLength = -(1 as i32) });
    xmlNanoHTTPScanURL(ret, URL);
    return ret;
}
extern "C" fn xmlNanoHTTPFreeCtxt(mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt) {
    if ctxt.is_null() {
        return;
    }
    if !(unsafe { (*ctxt).hostname }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).hostname as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).protocol }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).protocol as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).path }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).path as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).query }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).query as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).out }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).out as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).in_0 }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).in_0 as *mut libc::c_void) });
    }
    if !(unsafe { (*ctxt).contentType }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).contentType as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).encoding }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).encoding as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).mimeType }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).mimeType as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).location }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).location as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).authHeader }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*ctxt).authHeader as *mut libc::c_void)
        });
    }
    if !(unsafe { (*ctxt).strm }).is_null() {
        (unsafe { inflateEnd((*ctxt).strm) });
        (unsafe { xmlFree.expect("non-null function pointer")((*ctxt).strm as *mut libc::c_void) });
    }
    (unsafe { (*ctxt).state = 4 as i32 });
    if (unsafe { (*ctxt).fd }) != -(1 as i32) {
        (unsafe { close((*ctxt).fd) });
    }
    (unsafe { (*ctxt).fd = -(1 as i32) });
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
extern "C" fn xmlNanoHTTPSend(
    mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt,
    mut xmt_ptr: *const i8,
    mut outlen: i32,
) -> i32 {
    let mut total_sent: i32 = 0 as i32;
    let mut p: crate::src::nanohttp::pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    if (unsafe { (*ctxt).state }) & 1 as i32 != 0 && !xmt_ptr.is_null() {
        while total_sent < outlen {
            let mut nsent: i32 = (unsafe {
                send(
                    (*ctxt).fd,
                    xmt_ptr.offset(total_sent as isize) as *const libc::c_void,
                    (outlen - total_sent) as size_t,
                    0 as i32,
                )
            }) as i32;
            if nsent > 0 as i32 {
                total_sent += nsent;
            } else if nsent == -(1 as i32) && socket_errno() != 11 as i32 {
                (unsafe {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"send failed\n\0" as *const u8 as *const i8,
                    )
                });
                if total_sent == 0 as i32 {
                    total_sent = -(1 as i32);
                }
                break;
            } else {
                p.fd = unsafe { (*ctxt).fd };
                p.events = 0x4 as i32 as i16;
                (unsafe {
                    poll(
                        &mut p,
                        1 as i32 as nfds_t,
                        timeout.wrapping_mul(1000 as i32 as u32) as i32,
                    )
                });
            }
        }
    }
    return total_sent;
}
extern "C" fn xmlNanoHTTPRecv(mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt) -> i32 {
    let mut p: crate::src::nanohttp::pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    while (unsafe { (*ctxt).state }) & 2 as i32 != 0 {
        if (unsafe { (*ctxt).in_0 }).is_null() {
            let fresh11 = unsafe { &mut ((*ctxt).in_0) };
            *fresh11 = (unsafe {
                xmlMallocAtomic.expect("non-null function pointer")(
                    (65000 as i32 as u64).wrapping_mul(::std::mem::size_of::<i8>() as u64),
                )
            }) as *mut i8;
            if (unsafe { (*ctxt).in_0 }).is_null() {
                xmlHTTPErrMemory(b"allocating input\0" as *const u8 as *const i8);
                (unsafe { (*ctxt).last = -(1 as i32) });
                return -(1 as i32);
            }
            (unsafe { (*ctxt).inlen = 65000 as i32 });
            let fresh12 = unsafe { &mut ((*ctxt).inrptr) };
            *fresh12 = unsafe { (*ctxt).in_0 };
            let fresh13 = unsafe { &mut ((*ctxt).content) };
            *fresh13 = *fresh12;
            let fresh14 = unsafe { &mut ((*ctxt).inptr) };
            *fresh14 = *fresh13;
        }
        if (unsafe { (*ctxt).inrptr }) > (unsafe { ((*ctxt).in_0).offset(4096 as i32 as isize) }) {
            let mut delta: i32 =
                (unsafe { ((*ctxt).inrptr).offset_from((*ctxt).in_0) }) as i64 as i32;
            let mut len: i32 =
                (unsafe { ((*ctxt).inptr).offset_from((*ctxt).inrptr) }) as i64 as i32;
            (unsafe {
                memmove(
                    (*ctxt).in_0 as *mut libc::c_void,
                    (*ctxt).inrptr as *const libc::c_void,
                    len as u64,
                )
            });
            let fresh15 = unsafe { &mut ((*ctxt).inrptr) };
            *fresh15 = unsafe { (*fresh15).offset(-(delta as isize)) };
            let fresh16 = unsafe { &mut ((*ctxt).content) };
            *fresh16 = unsafe { (*fresh16).offset(-(delta as isize)) };
            let fresh17 = unsafe { &mut ((*ctxt).inptr) };
            *fresh17 = unsafe { (*fresh17).offset(-(delta as isize)) };
        }
        if (unsafe { ((*ctxt).in_0).offset((*ctxt).inlen as isize) })
            < (unsafe { ((*ctxt).inptr).offset(4096 as i32 as isize) })
        {
            let mut d_inptr: i32 =
                (unsafe { ((*ctxt).inptr).offset_from((*ctxt).in_0) }) as i64 as i32;
            let mut d_content: i32 =
                (unsafe { ((*ctxt).content).offset_from((*ctxt).in_0) }) as i64 as i32;
            let mut d_inrptr: i32 =
                (unsafe { ((*ctxt).inrptr).offset_from((*ctxt).in_0) }) as i64 as i32;
            let mut tmp_ptr: *mut i8 = unsafe { (*ctxt).in_0 };
            (unsafe { (*ctxt).inlen *= 2 as i32 });
            let fresh18 = unsafe { &mut ((*ctxt).in_0) };
            *fresh18 = (unsafe {
                xmlRealloc.expect("non-null function pointer")(
                    tmp_ptr as *mut libc::c_void,
                    (*ctxt).inlen as size_t,
                )
            }) as *mut i8;
            if (unsafe { (*ctxt).in_0 }).is_null() {
                xmlHTTPErrMemory(b"allocating input buffer\0" as *const u8 as *const i8);
                (unsafe {
                    xmlFree.expect("non-null function pointer")(tmp_ptr as *mut libc::c_void)
                });
                (unsafe { (*ctxt).last = -(1 as i32) });
                return -(1 as i32);
            }
            let fresh19 = unsafe { &mut ((*ctxt).inptr) };
            *fresh19 = unsafe { ((*ctxt).in_0).offset(d_inptr as isize) };
            let fresh20 = unsafe { &mut ((*ctxt).content) };
            *fresh20 = unsafe { ((*ctxt).in_0).offset(d_content as isize) };
            let fresh21 = unsafe { &mut ((*ctxt).inrptr) };
            *fresh21 = unsafe { ((*ctxt).in_0).offset(d_inrptr as isize) };
        }
        (unsafe {
            (*ctxt).last = recv(
                (*ctxt).fd,
                (*ctxt).inptr as *mut libc::c_void,
                4096 as i32 as size_t,
                0 as i32,
            ) as i32
        });
        if (unsafe { (*ctxt).last }) > 0 as i32 {
            let fresh22 = unsafe { &mut ((*ctxt).inptr) };
            *fresh22 = unsafe { (*fresh22).offset((*ctxt).last as isize) };
            return unsafe { (*ctxt).last };
        }
        if (unsafe { (*ctxt).last }) == 0 as i32 {
            return 0 as i32;
        }
        if (unsafe { (*ctxt).last }) == -(1 as i32) {
            match socket_errno() {
                115 | 11 => {}
                104 | 108 => return 0 as i32,
                _ => {
                    (unsafe {
                        __xmlIOErr(
                            XML_FROM_HTTP as i32,
                            0 as i32,
                            b"recv failed\n\0" as *const u8 as *const i8,
                        )
                    });
                    return -(1 as i32);
                }
            }
        }
        p.fd = unsafe { (*ctxt).fd };
        p.events = 0x1 as i32 as i16;
        if (unsafe {
            poll(
                &mut p,
                1 as i32 as nfds_t,
                timeout.wrapping_mul(1000 as i32 as u32) as i32,
            )
        }) < 1 as i32
            && (unsafe { *__errno_location() }) != 4 as i32
        {
            return 0 as i32;
        }
    }
    return 0 as i32;
}
extern "C" fn xmlNanoHTTPReadLine(mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt) -> *mut i8 {
    let mut buf: [i8; 4096] = [0; 4096];
    let mut bp: *mut i8 = buf.as_mut_ptr();
    let mut rc: i32 = 0;
    while ((unsafe { bp.offset_from(buf.as_mut_ptr()) }) as i64) < 4095 as i32 as i64 {
        if (unsafe { (*ctxt).inrptr }) == (unsafe { (*ctxt).inptr }) {
            rc = xmlNanoHTTPRecv(ctxt);
            if rc == 0 as i32 {
                if bp == buf.as_mut_ptr() {
                    return 0 as *mut i8;
                } else {
                    (unsafe { *bp = 0 as i32 as i8 });
                }
                return unsafe {
                    xmlMemStrdup.expect("non-null function pointer")(buf.as_mut_ptr())
                };
            } else {
                if rc == -(1 as i32) {
                    return 0 as *mut i8;
                }
            }
        }
        let fresh23 = unsafe { &mut ((*ctxt).inrptr) };
        let mut fresh24 = *fresh23;
        *fresh23 = unsafe { (*fresh23).offset(1) };
        (unsafe { *bp = *fresh24 });
        if (unsafe { *bp }) as i32 == '\n' as i32 {
            (unsafe { *bp = 0 as i32 as i8 });
            return unsafe { xmlMemStrdup.expect("non-null function pointer")(buf.as_mut_ptr()) };
        }
        if (unsafe { *bp }) as i32 != '\r' as i32 {
            bp = unsafe { bp.offset(1) };
        }
    }
    buf[4095 as i32 as usize] = 0 as i32 as i8;
    return unsafe { xmlMemStrdup.expect("non-null function pointer")(buf.as_mut_ptr()) };
}
extern "C" fn xmlNanoHTTPScanAnswer(
    mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt,
    mut line: *const i8,
) {
    let mut cur: *const i8 = line;
    if line.is_null() {
        return;
    }
    if (unsafe { strncmp(line, b"HTTP/\0" as *const u8 as *const i8, 5 as i32 as u64) }) == 0 {
        let mut version: i32 = 0 as i32;
        let mut ret: i32 = 0 as i32;
        cur = unsafe { cur.offset(5 as i32 as isize) };
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            version *= 10 as i32;
            version += (unsafe { *cur }) as i32 - '0' as i32;
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 == '.' as i32 {
            cur = unsafe { cur.offset(1) };
            if (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
                version *= 10 as i32;
                version += (unsafe { *cur }) as i32 - '0' as i32;
                cur = unsafe { cur.offset(1) };
            }
            while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
                cur = unsafe { cur.offset(1) };
            }
        } else {
            version *= 10 as i32;
        }
        if (unsafe { *cur }) as i32 != ' ' as i32 && (unsafe { *cur }) as i32 != '\t' as i32 {
            return;
        }
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if ((unsafe { *cur }) as i32) < '0' as i32 || (unsafe { *cur }) as i32 > '9' as i32 {
            return;
        }
        while (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32 {
            ret *= 10 as i32;
            ret += (unsafe { *cur }) as i32 - '0' as i32;
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 != 0 as i32
            && (unsafe { *cur }) as i32 != ' ' as i32
            && (unsafe { *cur }) as i32 != '\t' as i32
        {
            return;
        }
        (unsafe { (*ctxt).returnValue = ret });
        (unsafe { (*ctxt).version = version });
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Type:\0" as *const u8 as *const i8 as *mut xmlChar,
            13 as i32,
        )
    }) == 0
    {
        let mut charset: *const u8 = 0 as *const xmlChar;
        let mut last: *const u8 = 0 as *const xmlChar;
        let mut mime: *const u8 = 0 as *const xmlChar;
        cur = unsafe { cur.offset(13 as i32 as isize) };
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if !(unsafe { (*ctxt).contentType }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*ctxt).contentType as *mut libc::c_void,
                )
            });
        }
        let fresh25 = unsafe { &mut ((*ctxt).contentType) };
        *fresh25 = unsafe { xmlMemStrdup.expect("non-null function pointer")(cur) };
        mime = cur as *const xmlChar;
        last = mime;
        while (unsafe { *last }) as i32 != 0 as i32
            && (unsafe { *last }) as i32 != ' ' as i32
            && (unsafe { *last }) as i32 != '\t' as i32
            && (unsafe { *last }) as i32 != ';' as i32
            && (unsafe { *last }) as i32 != ',' as i32
        {
            last = unsafe { last.offset(1) };
        }
        if !(unsafe { (*ctxt).mimeType }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).mimeType as *mut libc::c_void)
            });
        }
        let fresh26 = unsafe { &mut ((*ctxt).mimeType) };
        *fresh26 = (unsafe { xmlStrndup(mime, last.offset_from(mime) as i64 as i32) }) as *mut i8;
        charset = unsafe {
            xmlStrstr(
                (*ctxt).contentType as *mut xmlChar,
                b"charset=\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        };
        if !charset.is_null() {
            charset = unsafe { charset.offset(8 as i32 as isize) };
            last = charset;
            while (unsafe { *last }) as i32 != 0 as i32
                && (unsafe { *last }) as i32 != ' ' as i32
                && (unsafe { *last }) as i32 != '\t' as i32
                && (unsafe { *last }) as i32 != ';' as i32
                && (unsafe { *last }) as i32 != ',' as i32
            {
                last = unsafe { last.offset(1) };
            }
            if !(unsafe { (*ctxt).encoding }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*ctxt).encoding as *mut libc::c_void,
                    )
                });
            }
            let fresh27 = unsafe { &mut ((*ctxt).encoding) };
            *fresh27 = (unsafe { xmlStrndup(charset, last.offset_from(charset) as i64 as i32) })
                as *mut i8;
        }
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"ContentType:\0" as *const u8 as *const i8 as *mut xmlChar,
            12 as i32,
        )
    }) == 0
    {
        let mut charset_0: *const u8 = 0 as *const xmlChar;
        let mut last_0: *const u8 = 0 as *const xmlChar;
        let mut mime_0: *const u8 = 0 as *const xmlChar;
        cur = unsafe { cur.offset(12 as i32 as isize) };
        if !(unsafe { (*ctxt).contentType }).is_null() {
            return;
        }
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        let fresh28 = unsafe { &mut ((*ctxt).contentType) };
        *fresh28 = unsafe { xmlMemStrdup.expect("non-null function pointer")(cur) };
        mime_0 = cur as *const xmlChar;
        last_0 = mime_0;
        while (unsafe { *last_0 }) as i32 != 0 as i32
            && (unsafe { *last_0 }) as i32 != ' ' as i32
            && (unsafe { *last_0 }) as i32 != '\t' as i32
            && (unsafe { *last_0 }) as i32 != ';' as i32
            && (unsafe { *last_0 }) as i32 != ',' as i32
        {
            last_0 = unsafe { last_0.offset(1) };
        }
        if !(unsafe { (*ctxt).mimeType }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).mimeType as *mut libc::c_void)
            });
        }
        let fresh29 = unsafe { &mut ((*ctxt).mimeType) };
        *fresh29 =
            (unsafe { xmlStrndup(mime_0, last_0.offset_from(mime_0) as i64 as i32) }) as *mut i8;
        charset_0 = unsafe {
            xmlStrstr(
                (*ctxt).contentType as *mut xmlChar,
                b"charset=\0" as *const u8 as *const i8 as *mut xmlChar,
            )
        };
        if !charset_0.is_null() {
            charset_0 = unsafe { charset_0.offset(8 as i32 as isize) };
            last_0 = charset_0;
            while (unsafe { *last_0 }) as i32 != 0 as i32
                && (unsafe { *last_0 }) as i32 != ' ' as i32
                && (unsafe { *last_0 }) as i32 != '\t' as i32
                && (unsafe { *last_0 }) as i32 != ';' as i32
                && (unsafe { *last_0 }) as i32 != ',' as i32
            {
                last_0 = unsafe { last_0.offset(1) };
            }
            if !(unsafe { (*ctxt).encoding }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*ctxt).encoding as *mut libc::c_void,
                    )
                });
            }
            let fresh30 = unsafe { &mut ((*ctxt).encoding) };
            *fresh30 =
                (unsafe { xmlStrndup(charset_0, last_0.offset_from(charset_0) as i64 as i32) })
                    as *mut i8;
        }
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"Location:\0" as *const u8 as *const i8 as *mut xmlChar,
            9 as i32,
        )
    }) == 0
    {
        cur = unsafe { cur.offset(9 as i32 as isize) };
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if !(unsafe { (*ctxt).location }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).location as *mut libc::c_void)
            });
        }
        if (unsafe { *cur }) as i32 == '/' as i32 {
            let mut tmp_http: *mut u8 =
                unsafe { xmlStrdup(b"http://\0" as *const u8 as *const i8 as *mut xmlChar) };
            let mut tmp_loc: *mut u8 =
                unsafe { xmlStrcat(tmp_http, (*ctxt).hostname as *const xmlChar) };
            let fresh31 = unsafe { &mut ((*ctxt).location) };
            *fresh31 = (unsafe { xmlStrcat(tmp_loc, cur as *const xmlChar) }) as *mut i8;
        } else {
            let fresh32 = unsafe { &mut ((*ctxt).location) };
            *fresh32 = unsafe { xmlMemStrdup.expect("non-null function pointer")(cur) };
        }
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"WWW-Authenticate:\0" as *const u8 as *const i8 as *mut xmlChar,
            17 as i32,
        )
    }) == 0
    {
        cur = unsafe { cur.offset(17 as i32 as isize) };
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if !(unsafe { (*ctxt).authHeader }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).authHeader as *mut libc::c_void)
            });
        }
        let fresh33 = unsafe { &mut ((*ctxt).authHeader) };
        *fresh33 = unsafe { xmlMemStrdup.expect("non-null function pointer")(cur) };
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"Proxy-Authenticate:\0" as *const u8 as *const i8 as *mut xmlChar,
            19 as i32,
        )
    }) == 0
    {
        cur = unsafe { cur.offset(19 as i32 as isize) };
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if !(unsafe { (*ctxt).authHeader }).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")((*ctxt).authHeader as *mut libc::c_void)
            });
        }
        let fresh34 = unsafe { &mut ((*ctxt).authHeader) };
        *fresh34 = unsafe { xmlMemStrdup.expect("non-null function pointer")(cur) };
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Encoding:\0" as *const u8 as *const i8 as *mut xmlChar,
            17 as i32,
        )
    }) == 0
    {
        cur = unsafe { cur.offset(17 as i32 as isize) };
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == '\t' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe {
            xmlStrncasecmp(
                cur as *mut xmlChar,
                b"gzip\0" as *const u8 as *const i8 as *mut xmlChar,
                4 as i32,
            )
        }) == 0
        {
            (unsafe { (*ctxt).usesGzip = 1 as i32 });
            let fresh35 = unsafe { &mut ((*ctxt).strm) };
            *fresh35 = (unsafe {
                xmlMalloc.expect("non-null function pointer")(
                    ::std::mem::size_of::<z_stream>() as u64
                )
            }) as *mut z_stream;
            if !(unsafe { (*ctxt).strm }).is_null() {
                let fresh36 = unsafe { &mut ((*(*ctxt).strm).zalloc) };
                *fresh36 = None;
                let fresh37 = unsafe { &mut ((*(*ctxt).strm).zfree) };
                *fresh37 = None;
                let fresh38 = unsafe { &mut ((*(*ctxt).strm).opaque) };
                *fresh38 = 0 as voidpf;
                (unsafe { (*(*ctxt).strm).avail_in = 0 as i32 as uInt });
                let fresh39 = unsafe { &mut ((*(*ctxt).strm).next_in) };
                *fresh39 = 0 as *mut Bytef;
                (unsafe {
                    inflateInit2_(
                        (*ctxt).strm,
                        31 as i32,
                        b"1.2.11\0" as *const u8 as *const i8,
                        ::std::mem::size_of::<z_stream>() as u64 as i32,
                    )
                });
            }
        }
    } else if (unsafe {
        xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Length:\0" as *const u8 as *const i8 as *mut xmlChar,
            15 as i32,
        )
    }) == 0
    {
        cur = unsafe { cur.offset(15 as i32 as isize) };
        (unsafe { (*ctxt).ContentLength = strtol(cur, 0 as *mut *mut i8, 10 as i32) as i32 });
    }
}
extern "C" fn xmlNanoHTTPConnectAttempt(mut addr: *mut crate::src::nanoftp::sockaddr) -> i32 {
    let mut p: crate::src::nanohttp::pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let mut status: i32 = 0;
    let mut addrlen: i32 = 0;
    let mut s: i32 = 0;
    if (unsafe { (*addr).sa_family }) as i32 == 10 as i32 {
        s = unsafe { socket(10 as i32, SOCK_STREAM as i32, IPPROTO_TCP as i32) };
        addrlen = ::std::mem::size_of::<sockaddr_in6>() as u64 as i32;
    } else {
        s = unsafe { socket(2 as i32, SOCK_STREAM as i32, IPPROTO_TCP as i32) };
        addrlen = ::std::mem::size_of::<sockaddr_in>() as u64 as i32;
    }
    if s == -(1 as i32) {
        (unsafe {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"socket failed\n\0" as *const u8 as *const i8,
            )
        });
        return -(1 as i32);
    }
    status = unsafe { fcntl(s, 3 as i32, 0 as i32) };
    if status != -(1 as i32) {
        status |= 0o4000 as i32;
        status = unsafe { fcntl(s, 4 as i32, status) };
    }
    if status < 0 as i32 {
        (unsafe {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"error setting non-blocking IO\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { close(s) });
        return -(1 as i32);
    }
    if (unsafe { connect(s, addr, addrlen as socklen_t) }) == -(1 as i32) {
        match socket_errno() {
            115 | 11 => {}
            _ => {
                (unsafe {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"error connecting to HTTP server\0" as *const u8 as *const i8,
                    )
                });
                (unsafe { close(s) });
                return -(1 as i32);
            }
        }
    }
    p.fd = s;
    p.events = 0x4 as i32 as i16;
    match unsafe {
        poll(
            &mut p,
            1 as i32 as nfds_t,
            timeout.wrapping_mul(1000 as i32 as u32) as i32,
        )
    } {
        0 => {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"Connect attempt timed out\0" as *const u8 as *const i8,
                )
            });
            (unsafe { close(s) });
            return -(1 as i32);
        }
        -1 => {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"Connect failed\0" as *const u8 as *const i8,
                )
            });
            (unsafe { close(s) });
            return -(1 as i32);
        }
        _ => {}
    }
    if p.revents as i32 == 0x4 as i32 {
        let mut len: u32 = 0;
        len = ::std::mem::size_of::<i32>() as u64 as socklen_t;
        if (unsafe {
            getsockopt(
                s,
                1 as i32,
                4 as i32,
                &mut status as *mut i32 as *mut i8 as *mut libc::c_void,
                &mut len,
            )
        }) < 0 as i32
        {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"getsockopt failed\n\0" as *const u8 as *const i8,
                )
            });
            (unsafe { close(s) });
            return -(1 as i32);
        }
        if status != 0 {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"Error connecting to remote host\0" as *const u8 as *const i8,
                )
            });
            (unsafe { close(s) });
            (unsafe { *__errno_location() = status });
            return -(1 as i32);
        }
    } else {
        (unsafe {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"select failed\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { close(s) });
        return -(1 as i32);
    }
    return s;
}
extern "C" fn xmlNanoHTTPConnectHost(mut host: *const i8, mut port: i32) -> i32 {
    let mut addr: *mut crate::src::nanoftp::sockaddr = 0 as *mut sockaddr;
    let mut sockin: crate::src::nanoftp::sockaddr_in = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut ia6: crate::src::nanoftp::in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_0 {
            __u6_addr8: [0; 16],
        },
    };
    let mut sockin6: crate::src::nanoftp::sockaddr_in6 = sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: in6_addr {
            __in6_u: C2RustUnnamed_0 {
                __u6_addr8: [0; 16],
            },
        },
        sin6_scope_id: 0,
    };
    let mut s: i32 = 0;
    (unsafe {
        memset(
            &mut sockin as *mut sockaddr_in as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<sockaddr_in>() as u64,
        )
    });
    (unsafe {
        memset(
            &mut sockin6 as *mut sockaddr_in6 as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<sockaddr_in6>() as u64,
        )
    });
    if have_ipv6() != 0 {
        let mut status: i32 = 0;
        let mut hints: crate::src::nanoftp::addrinfo = addrinfo {
            ai_flags: 0,
            ai_family: 0,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: 0 as *mut sockaddr,
            ai_canonname: 0 as *mut i8,
            ai_next: 0 as *mut addrinfo,
        };
        let mut res: *mut crate::src::nanoftp::addrinfo = 0 as *mut addrinfo;
        let mut result: *mut crate::src::nanoftp::addrinfo = 0 as *mut addrinfo;
        result = 0 as *mut addrinfo;
        (unsafe {
            memset(
                &mut hints as *mut addrinfo as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<addrinfo>() as u64,
            )
        });
        hints.ai_socktype = SOCK_STREAM as i32;
        status = unsafe { getaddrinfo(host, 0 as *const i8, &mut hints, &mut result) };
        if status != 0 {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"getaddrinfo failed\n\0" as *const u8 as *const i8,
                )
            });
            return -(1 as i32);
        }
        let mut current_block_33: u64;
        res = result;
        while !res.is_null() {
            if (unsafe { (*res).ai_family }) == 2 as i32 {
                if (unsafe { (*res).ai_addrlen }) as size_t
                    > ::std::mem::size_of::<sockaddr_in>() as u64
                {
                    (unsafe {
                        __xmlIOErr(
                            XML_FROM_HTTP as i32,
                            0 as i32,
                            b"address size mismatch\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { freeaddrinfo(result) });
                    return -(1 as i32);
                }
                (unsafe {
                    memcpy(
                        &mut sockin as *mut sockaddr_in as *mut libc::c_void,
                        (*res).ai_addr as *const libc::c_void,
                        (*res).ai_addrlen as u64,
                    )
                });
                sockin.sin_port = __bswap_16(port as __uint16_t);
                addr = &mut sockin as *mut sockaddr_in as *mut sockaddr;
                current_block_33 = 5494826135382683477;
            } else if have_ipv6() != 0 && (unsafe { (*res).ai_family }) == 10 as i32 {
                if (unsafe { (*res).ai_addrlen }) as size_t
                    > ::std::mem::size_of::<sockaddr_in6>() as u64
                {
                    (unsafe {
                        __xmlIOErr(
                            XML_FROM_HTTP as i32,
                            0 as i32,
                            b"address size mismatch\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { freeaddrinfo(result) });
                    return -(1 as i32);
                }
                (unsafe {
                    memcpy(
                        &mut sockin6 as *mut sockaddr_in6 as *mut libc::c_void,
                        (*res).ai_addr as *const libc::c_void,
                        (*res).ai_addrlen as u64,
                    )
                });
                sockin6.sin6_port = __bswap_16(port as __uint16_t);
                addr = &mut sockin6 as *mut sockaddr_in6 as *mut sockaddr;
                current_block_33 = 5494826135382683477;
            } else {
                current_block_33 = 3512920355445576850;
            }
            match current_block_33 {
                5494826135382683477 => {
                    s = xmlNanoHTTPConnectAttempt(addr);
                    if s != -(1 as i32) {
                        (unsafe { freeaddrinfo(result) });
                        return s;
                    }
                }
                _ => {}
            }
            res = unsafe { (*res).ai_next };
        }
        if !result.is_null() {
            (unsafe { freeaddrinfo(result) });
        }
    } else {
        let mut h: *mut crate::src::nanoftp::hostent = 0 as *mut crate::src::nanoftp::hostent;
        let mut ia: crate::src::nanoftp::in_addr = in_addr { s_addr: 0 };
        let mut i: i32 = 0;
        h = unsafe { gethostbyname(host) };
        if h.is_null() {
            let mut h_err_txt: *const i8 = b"\0" as *const u8 as *const i8;
            match unsafe { *__h_errno_location() } {
                1 => {
                    h_err_txt = b"Authoritative host not found\0" as *const u8 as *const i8;
                }
                2 => {
                    h_err_txt = b"Non-authoritative host not found or server failure.\0"
                        as *const u8 as *const i8;
                }
                3 => {
                    h_err_txt = b"Non-recoverable errors:  FORMERR, REFUSED, or NOTIMP.\0"
                        as *const u8 as *const i8;
                }
                4 => {
                    h_err_txt = b"Valid name, no data record of requested type.\0" as *const u8
                        as *const i8;
                }
                _ => {
                    h_err_txt = b"No error text defined.\0" as *const u8 as *const i8;
                }
            }
            (unsafe { __xmlIOErr(XML_FROM_HTTP as i32, 0 as i32, h_err_txt) });
            return -(1 as i32);
        }
        i = 0 as i32;
        while !(unsafe { *((*h).h_addr_list).offset(i as isize) }).is_null() {
            if (unsafe { (*h).h_addrtype }) == 2 as i32 {
                if (unsafe { (*h).h_length }) as u32 as u64
                    > ::std::mem::size_of::<in_addr>() as u64
                {
                    (unsafe {
                        __xmlIOErr(
                            XML_FROM_HTTP as i32,
                            0 as i32,
                            b"address size mismatch\n\0" as *const u8 as *const i8,
                        )
                    });
                    return -(1 as i32);
                }
                (unsafe {
                    memcpy(
                        &mut ia as *mut in_addr as *mut libc::c_void,
                        *((*h).h_addr_list).offset(i as isize) as *const libc::c_void,
                        (*h).h_length as u64,
                    )
                });
                sockin.sin_family = (unsafe { (*h).h_addrtype }) as sa_family_t;
                sockin.sin_addr = ia;
                sockin.sin_port = __bswap_16(port as u16);
                addr = &mut sockin as *mut sockaddr_in as *mut sockaddr;
            } else {
                if !(have_ipv6() != 0 && (unsafe { (*h).h_addrtype }) == 10 as i32) {
                    break;
                }
                if (unsafe { (*h).h_length }) as u32 as u64
                    > ::std::mem::size_of::<in6_addr>() as u64
                {
                    (unsafe {
                        __xmlIOErr(
                            XML_FROM_HTTP as i32,
                            0 as i32,
                            b"address size mismatch\n\0" as *const u8 as *const i8,
                        )
                    });
                    return -(1 as i32);
                }
                (unsafe {
                    memcpy(
                        &mut ia6 as *mut in6_addr as *mut libc::c_void,
                        *((*h).h_addr_list).offset(i as isize) as *const libc::c_void,
                        (*h).h_length as u64,
                    )
                });
                sockin6.sin6_family = (unsafe { (*h).h_addrtype }) as sa_family_t;
                sockin6.sin6_addr = ia6;
                sockin6.sin6_port = __bswap_16(port as __uint16_t);
                addr = &mut sockin6 as *mut sockaddr_in6 as *mut sockaddr;
            }
            s = xmlNanoHTTPConnectAttempt(addr);
            if s != -(1 as i32) {
                return s;
            }
            i += 1;
        }
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPOpen<'a1>(
    mut URL: *const i8,
    mut contentType: Option<&'a1 mut *mut i8>,
) -> *mut core::ffi::c_void {
    if !borrow(&contentType).is_none() {
        *(borrow_mut(&mut contentType)).unwrap() = 0 as *mut i8;
    }
    return xmlNanoHTTPMethod(
        URL,
        0 as *const i8,
        0 as *const i8,
        borrow_mut(&mut contentType),
        0 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPOpenRedir<'a1, 'a2>(
    mut URL: *const i8,
    mut contentType: Option<&'a1 mut *mut i8>,
    mut redir: Option<&'a2 mut *mut i8>,
) -> *mut core::ffi::c_void {
    if !borrow(&contentType).is_none() {
        *(borrow_mut(&mut contentType)).unwrap() = 0 as *mut i8;
    }
    if !borrow(&redir).is_none() {
        *(borrow_mut(&mut redir)).unwrap() = 0 as *mut i8;
    }
    return xmlNanoHTTPMethodRedir(
        URL,
        0 as *const i8,
        0 as *const i8,
        borrow_mut(&mut contentType),
        borrow_mut(&mut redir),
        0 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPRead(
    mut ctx: *mut core::ffi::c_void,
    mut dest: *mut core::ffi::c_void,
    mut len: i32,
) -> i32 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    let mut bytes_read: i32 = 0 as i32;
    let mut orig_avail_in: i32 = 0;
    let mut z_ret: i32 = 0;
    if ctx.is_null() {
        return -(1 as i32);
    }
    if dest.is_null() {
        return -(1 as i32);
    }
    if len <= 0 as i32 {
        return 0 as i32;
    }
    if (unsafe { (*ctxt).usesGzip }) == 1 as i32 {
        if (unsafe { (*ctxt).strm }).is_null() {
            return 0 as i32;
        }
        let fresh40 = unsafe { &mut ((*(*ctxt).strm).next_out) };
        *fresh40 = dest as *mut Bytef;
        (unsafe { (*(*ctxt).strm).avail_out = len as uInt });
        (unsafe {
            (*(*ctxt).strm).avail_in = ((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64 as uInt
        });
        while (unsafe { (*(*ctxt).strm).avail_out }) > 0 as i32 as u32
            && ((unsafe { (*(*ctxt).strm).avail_in }) > 0 as i32 as u32
                || xmlNanoHTTPRecv(ctxt) > 0 as i32)
        {
            let fresh41 = unsafe { &mut ((*(*ctxt).strm).avail_in) };
            *fresh41 = ((unsafe { ((*ctxt).inptr).offset_from((*ctxt).inrptr) }) as i64
                - bytes_read as i64) as uInt;
            orig_avail_in = *fresh41 as i32;
            let fresh42 = unsafe { &mut ((*(*ctxt).strm).next_in) };
            *fresh42 = (unsafe { ((*ctxt).inrptr).offset(bytes_read as isize) }) as *mut xmlChar;
            z_ret = unsafe { inflate((*ctxt).strm, 0 as i32) };
            bytes_read = (bytes_read as u32).wrapping_add(
                (orig_avail_in as u32).wrapping_sub(unsafe { (*(*ctxt).strm).avail_in }),
            ) as i32 as i32;
            if z_ret != 0 as i32 {
                break;
            }
        }
        let fresh43 = unsafe { &mut ((*ctxt).inrptr) };
        *fresh43 = unsafe { (*fresh43).offset(bytes_read as isize) };
        return (len as u32).wrapping_sub(unsafe { (*(*ctxt).strm).avail_out }) as i32;
    }
    while ((unsafe { ((*ctxt).inptr).offset_from((*ctxt).inrptr) }) as i64) < len as i64 {
        if xmlNanoHTTPRecv(ctxt) <= 0 as i32 {
            break;
        }
    }
    if ((unsafe { ((*ctxt).inptr).offset_from((*ctxt).inrptr) }) as i64) < len as i64 {
        len = (unsafe { ((*ctxt).inptr).offset_from((*ctxt).inrptr) }) as i64 as i32;
    }
    (unsafe { memcpy(dest, (*ctxt).inrptr as *const libc::c_void, len as u64) });
    let fresh44 = unsafe { &mut ((*ctxt).inrptr) };
    *fresh44 = unsafe { (*fresh44).offset(len as isize) };
    return len;
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPClose(mut ctx: *mut core::ffi::c_void) {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    if ctx.is_null() {
        return;
    }
    xmlNanoHTTPFreeCtxt(ctxt);
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPMethodRedir<'a1, 'a2>(
    mut URL: *const i8,
    mut method: *const i8,
    mut input: *const i8,
    mut contentType: Option<&'a1 mut *mut i8>,
    mut redir: Option<&'a2 mut *mut i8>,
    mut headers: *const i8,
    mut ilen: i32,
) -> *mut core::ffi::c_void {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = 0 as *mut xmlNanoHTTPCtxt;
    let mut bp: *mut i8 = 0 as *mut i8;
    let mut p: *mut i8 = 0 as *mut i8;
    let mut blen: i32 = 0;
    let mut ret: i32 = 0;
    let mut nbRedirects: i32 = 0 as i32;
    let mut redirURL: *mut i8 = 0 as *mut i8;
    if URL.is_null() {
        return 0 as *mut libc::c_void;
    }
    if method.is_null() {
        method = b"GET\0" as *const u8 as *const i8;
    }
    xmlNanoHTTPInit();
    loop {
        if redirURL.is_null() {
            ctxt = xmlNanoHTTPNewCtxt(URL);
            if ctxt.is_null() {
                return 0 as *mut libc::c_void;
            }
        } else {
            ctxt = xmlNanoHTTPNewCtxt(redirURL);
            if ctxt.is_null() {
                return 0 as *mut libc::c_void;
            }
            let fresh45 = unsafe { &mut ((*ctxt).location) };
            *fresh45 = unsafe { xmlMemStrdup.expect("non-null function pointer")(redirURL) };
        }
        if (unsafe { (*ctxt).protocol }).is_null()
            || (unsafe { strcmp((*ctxt).protocol, b"http\0" as *const u8 as *const i8) }) != 0
        {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    XML_HTTP_URL_SYNTAX as i32,
                    b"Not a valid HTTP URI\0" as *const u8 as *const i8,
                )
            });
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                });
            }
            return 0 as *mut libc::c_void;
        }
        if (unsafe { (*ctxt).hostname }).is_null() {
            (unsafe {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    XML_HTTP_UNKNOWN_HOST as i32,
                    b"Failed to identify host in URI\0" as *const u8 as *const i8,
                )
            });
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                });
            }
            return 0 as *mut libc::c_void;
        }
        if !(unsafe { proxy }).is_null() {
            blen = (unsafe { strlen((*ctxt).hostname) })
                .wrapping_mul(2 as i32 as u64)
                .wrapping_add(16 as i32 as u64) as i32;
            ret = xmlNanoHTTPConnectHost(unsafe { proxy }, unsafe { proxyPort });
        } else {
            blen = (unsafe { strlen((*ctxt).hostname) }) as i32;
            ret = xmlNanoHTTPConnectHost(unsafe { (*ctxt).hostname }, unsafe { (*ctxt).port });
        }
        if ret == -(1 as i32) {
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                });
            }
            return 0 as *mut libc::c_void;
        }
        (unsafe { (*ctxt).fd = ret });
        if input.is_null() {
            ilen = 0 as i32;
        } else {
            blen += 36 as i32;
        }
        if !headers.is_null() {
            blen = (blen as u64)
                .wrapping_add((unsafe { strlen(headers) }).wrapping_add(2 as i32 as u64))
                as i32 as i32;
        }
        if !borrow(&contentType).is_none() && !(*(borrow_mut(&mut contentType)).unwrap()).is_null()
        {
            blen = (blen as u64).wrapping_add(
                (unsafe { strlen(*(borrow(&contentType)).unwrap()) })
                    .wrapping_add(16 as i32 as u64),
            ) as i32 as i32;
        }
        if !(unsafe { (*ctxt).query }).is_null() {
            blen = (blen as u64)
                .wrapping_add((unsafe { strlen((*ctxt).query) }).wrapping_add(1 as i32 as u64))
                as i32 as i32;
        }
        blen = (blen as u64).wrapping_add(
            (unsafe { strlen(method) })
                .wrapping_add(unsafe { strlen((*ctxt).path) })
                .wrapping_add(24 as i32 as u64),
        ) as i32 as i32;
        blen += 23 as i32;
        if (unsafe { (*ctxt).port }) != 80 as i32 {
            if !(unsafe { proxy }).is_null() {
                blen += 17 as i32;
            } else {
                blen += 11 as i32;
            }
        }
        bp = (unsafe { xmlMallocAtomic.expect("non-null function pointer")(blen as size_t) })
            as *mut i8;
        if bp.is_null() {
            xmlNanoHTTPFreeCtxt(ctxt);
            xmlHTTPErrMemory(b"allocating header buffer\0" as *const u8 as *const i8);
            return 0 as *mut libc::c_void;
        }
        p = bp;
        if !(unsafe { proxy }).is_null() {
            if (unsafe { (*ctxt).port }) != 80 as i32 {
                p = unsafe {
                    p.offset(snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64) as u64,
                        b"%s http://%s:%d%s\0" as *const u8 as *const i8,
                        method,
                        (*ctxt).hostname,
                        (*ctxt).port,
                        (*ctxt).path,
                    ) as isize)
                };
            } else {
                p = unsafe {
                    p.offset(snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64) as u64,
                        b"%s http://%s%s\0" as *const u8 as *const i8,
                        method,
                        (*ctxt).hostname,
                        (*ctxt).path,
                    ) as isize)
                };
            }
        } else {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"%s %s\0" as *const u8 as *const i8,
                    method,
                    (*ctxt).path,
                ) as isize)
            };
        }
        if !(unsafe { (*ctxt).query }).is_null() {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"?%s\0" as *const u8 as *const i8,
                    (*ctxt).query,
                ) as isize)
            };
        }
        if (unsafe { (*ctxt).port }) == 80 as i32 {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b" HTTP/1.0\r\nHost: %s\r\n\0" as *const u8 as *const i8,
                    (*ctxt).hostname,
                ) as isize)
            };
        } else {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b" HTTP/1.0\r\nHost: %s:%d\r\n\0" as *const u8 as *const i8,
                    (*ctxt).hostname,
                    (*ctxt).port,
                ) as isize)
            };
        }
        p = unsafe {
            p.offset(snprintf(
                p,
                (blen as i64 - p.offset_from(bp) as i64) as u64,
                b"Accept-Encoding: gzip\r\n\0" as *const u8 as *const i8,
            ) as isize)
        };
        if !borrow(&contentType).is_none() && !(*(borrow_mut(&mut contentType)).unwrap()).is_null()
        {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"Content-Type: %s\r\n\0" as *const u8 as *const i8,
                    *(borrow(&contentType)).unwrap(),
                ) as isize)
            };
        }
        if !headers.is_null() {
            p = unsafe {
                p.offset(snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"%s\0" as *const u8 as *const i8,
                    headers,
                ) as isize)
            };
        }
        if !input.is_null() {
            (unsafe {
                snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"Content-Length: %d\r\n\r\n\0" as *const u8 as *const i8,
                    ilen,
                )
            });
        } else {
            (unsafe {
                snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64) as u64,
                    b"\r\n\0" as *const u8 as *const i8,
                )
            });
        }
        let fresh46 = unsafe { &mut ((*ctxt).out) };
        *fresh46 = bp;
        let fresh47 = unsafe { &mut ((*ctxt).outptr) };
        *fresh47 = *fresh46;
        (unsafe { (*ctxt).state = 1 as i32 });
        blen = (unsafe { strlen((*ctxt).out) }) as i32;
        xmlNanoHTTPSend(ctxt, unsafe { (*ctxt).out }, blen);
        if !input.is_null() {
            xmlNanoHTTPSend(ctxt, input, ilen);
        }
        (unsafe { (*ctxt).state = 2 as i32 });
        loop {
            p = xmlNanoHTTPReadLine(ctxt);
            if p.is_null() {
                break;
            }
            if (unsafe { *p }) as i32 == 0 as i32 {
                let fresh48 = unsafe { &mut ((*ctxt).content) };
                *fresh48 = unsafe { (*ctxt).inrptr };
                (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
                break;
            } else {
                xmlNanoHTTPScanAnswer(ctxt, p);
                (unsafe { xmlFree.expect("non-null function pointer")(p as *mut libc::c_void) });
            }
        }
        if !(unsafe { (*ctxt).location }).is_null()
            && (unsafe { (*ctxt).returnValue }) >= 300 as i32
            && (unsafe { (*ctxt).returnValue }) < 400 as i32
        {
            while xmlNanoHTTPRecv(ctxt) > 0 as i32 {}
            if nbRedirects < 10 as i32 {
                nbRedirects += 1;
                if !redirURL.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                    });
                }
                redirURL =
                    unsafe { xmlMemStrdup.expect("non-null function pointer")((*ctxt).location) };
                xmlNanoHTTPFreeCtxt(ctxt);
            } else {
                xmlNanoHTTPFreeCtxt(ctxt);
                if !redirURL.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                    });
                }
                return 0 as *mut libc::c_void;
            }
        } else {
            if !borrow(&contentType).is_none() {
                if !(unsafe { (*ctxt).contentType }).is_null() {
                    *(borrow_mut(&mut contentType)).unwrap() = unsafe {
                        xmlMemStrdup.expect("non-null function pointer")((*ctxt).contentType)
                    };
                } else {
                    *(borrow_mut(&mut contentType)).unwrap() = 0 as *mut i8;
                }
            }
            if !borrow(&redir).is_none() && !redirURL.is_null() {
                *(borrow_mut(&mut redir)).unwrap() = redirURL;
            } else {
                if !redirURL.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(redirURL as *mut libc::c_void)
                    });
                }
                if !borrow(&redir).is_none() {
                    *(borrow_mut(&mut redir)).unwrap() = 0 as *mut i8;
                }
            }
            return ctxt as *mut libc::c_void;
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPMethod<'a1>(
    mut URL: *const i8,
    mut method: *const i8,
    mut input: *const i8,
    mut contentType: Option<&'a1 mut *mut i8>,
    mut headers: *const i8,
    mut ilen: i32,
) -> *mut core::ffi::c_void {
    return xmlNanoHTTPMethodRedir(
        URL,
        method,
        input,
        borrow_mut(&mut contentType),
        Option::<&'_ mut *mut i8>::None,
        headers,
        ilen,
    );
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPFetch<'a1>(
    mut URL: *const i8,
    mut filename: *const i8,
    mut contentType: Option<&'a1 mut *mut i8>,
) -> i32 {
    let mut ctxt: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    let mut buf: *mut i8 = 0 as *mut i8;
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if filename.is_null() {
        return -(1 as i32);
    }
    ctxt = xmlNanoHTTPOpen(URL, borrow_mut(&mut contentType));
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if (unsafe { strcmp(filename, b"-\0" as *const u8 as *const i8) }) == 0 {
        fd = 0 as i32;
    } else {
        fd = unsafe { open(filename, 0o100 as i32 | 0o1 as i32, 0o644 as i32) };
        if fd < 0 as i32 {
            xmlNanoHTTPClose(ctxt);
            if !borrow(&contentType).is_none()
                && !(*(borrow_mut(&mut contentType)).unwrap()).is_null()
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        *(borrow_mut(&mut contentType)).unwrap() as *mut libc::c_void,
                    )
                });
                *(borrow_mut(&mut contentType)).unwrap() = 0 as *mut i8;
            }
            return -(1 as i32);
        }
    }
    xmlNanoHTTPFetchContent(ctxt, &mut buf, &mut len);
    if len > 0 as i32 {
        if (unsafe { write(fd, buf as *const libc::c_void, len as size_t) }) == -(1 as i32) as i64 {
            ret = -(1 as i32);
        }
    }
    xmlNanoHTTPClose(ctxt);
    (unsafe { close(fd) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPSave(
    mut ctxt: *mut core::ffi::c_void,
    mut filename: *const i8,
) -> i32 {
    let mut buf: *mut i8 = 0 as *mut i8;
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if ctxt.is_null() || filename.is_null() {
        return -(1 as i32);
    }
    if (unsafe { strcmp(filename, b"-\0" as *const u8 as *const i8) }) == 0 {
        fd = 0 as i32;
    } else {
        fd = unsafe { open(filename, 0o100 as i32 | 0o1 as i32, 0o666 as i32) };
        if fd < 0 as i32 {
            xmlNanoHTTPClose(ctxt);
            return -(1 as i32);
        }
    }
    xmlNanoHTTPFetchContent(ctxt, &mut buf, &mut len);
    if len > 0 as i32 {
        if (unsafe { write(fd, buf as *const libc::c_void, len as size_t) }) == -(1 as i32) as i64 {
            ret = -(1 as i32);
        }
    }
    xmlNanoHTTPClose(ctxt);
    (unsafe { close(fd) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPReturnCode(mut ctx: *mut core::ffi::c_void) -> i32 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    return unsafe { (*ctxt).returnValue };
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPAuthHeader(mut ctx: *mut core::ffi::c_void) -> *const i8 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    if ctxt.is_null() {
        return 0 as *const i8;
    }
    return unsafe { (*ctxt).authHeader };
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPContentLength(mut ctx: *mut core::ffi::c_void) -> i32 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() {
        -(1 as i32)
    } else {
        unsafe { (*ctxt).ContentLength }
    };
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPRedir(mut ctx: *mut core::ffi::c_void) -> *const i8 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() {
        0 as *mut i8
    } else {
        unsafe { (*ctxt).location }
    };
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPEncoding(mut ctx: *mut core::ffi::c_void) -> *const i8 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() {
        0 as *mut i8
    } else {
        unsafe { (*ctxt).encoding }
    };
}
#[no_mangle]
pub extern "C" fn xmlNanoHTTPMimeType(mut ctx: *mut core::ffi::c_void) -> *const i8 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() {
        0 as *mut i8
    } else {
        unsafe { (*ctxt).mimeType }
    };
}
extern "C" fn xmlNanoHTTPFetchContent(
    mut ctx: *mut core::ffi::c_void,
    mut ptr: *mut *mut i8,
    mut len: *mut i32,
) -> i32 {
    let mut ctxt: *mut crate::src::nanohttp::xmlNanoHTTPCtxt = ctx as xmlNanoHTTPCtxtPtr;
    let mut rc: i32 = 0 as i32;
    let mut cur_lgth: i32 = 0;
    let mut rcvd_lgth: i32 = 0;
    let mut dummy_int: i32 = 0;
    let mut dummy_ptr: *mut i8 = 0 as *mut i8;
    if len.is_null() {
        len = &mut dummy_int;
    }
    if ptr.is_null() {
        ptr = &mut dummy_ptr;
    }
    if ctxt.is_null() || (unsafe { (*ctxt).content }).is_null() {
        (unsafe { *len = 0 as i32 });
        (unsafe { *ptr = 0 as *mut i8 });
        return -(1 as i32);
    }
    rcvd_lgth = (unsafe { ((*ctxt).inptr).offset_from((*ctxt).content) }) as i64 as i32;
    loop {
        cur_lgth = xmlNanoHTTPRecv(ctxt);
        if !(cur_lgth > 0 as i32) {
            break;
        }
        rcvd_lgth += cur_lgth;
        if (unsafe { (*ctxt).ContentLength }) > 0 as i32
            && rcvd_lgth >= (unsafe { (*ctxt).ContentLength })
        {
            break;
        }
    }
    (unsafe { *ptr = (*ctxt).content });
    (unsafe { *len = rcvd_lgth });
    if (unsafe { (*ctxt).ContentLength }) > 0 as i32
        && rcvd_lgth < (unsafe { (*ctxt).ContentLength })
    {
        rc = -(1 as i32);
    } else if rcvd_lgth == 0 as i32 {
        rc = -(1 as i32);
    }
    return rc;
}
use crate::laertes_rt::*;
