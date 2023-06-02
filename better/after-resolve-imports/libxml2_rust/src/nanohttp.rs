use ::libc;
extern "C" {
    pub type internal_state;
    
    
    
    
    
    
    
    
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strncmp(
        _: *const i8,
        _: *const i8,
        _: u64,
    ) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn strtol(
        _: *const i8,
        _: *mut *mut i8,
        _: i32,
    ) -> i64;
    fn getenv(__name: *const i8) -> *mut i8;
    fn __errno_location() -> *mut i32;
    fn close(__fd: i32) -> i32;
    fn write(__fd: i32, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn connect(
        __fd: i32,
        __addr: *const sockaddr,
        __len: socklen_t,
    ) -> i32;
    fn socket(
        __domain: i32,
        __type: i32,
        __protocol: i32,
    ) -> i32;
    fn send(
        __fd: i32,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: i32,
    ) -> ssize_t;
    fn recv(
        __fd: i32,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: i32,
    ) -> ssize_t;
    fn getsockopt(
        __fd: i32,
        __level: i32,
        __optname: i32,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> i32;
    fn __h_errno_location() -> *mut i32;
    fn gethostbyname(__name: *const i8) -> *mut hostent;
    fn getaddrinfo(
        __name: *const i8,
        __service: *const i8,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> i32;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn fcntl(__fd: i32, __cmd: i32, _: ...) -> i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: i32) -> i32;
    fn inflateEnd(strm: z_streamp) -> i32;
    fn inflate(strm: z_streamp, flush: i32) -> i32;
    fn inflateInit2_(
        strm: z_streamp,
        windowBits: i32,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    
    
    
    
    
    
    
    
}
pub use crate::src::error::__xmlSimpleError;
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlParseURIRaw;
pub use crate::src::xmlIO::__xmlIOErr;
pub use crate::src::xmlstring::xmlCharStrndup;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrncasecmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlstring::xmlStrstr;
pub use crate::src::dict::_xmlDict;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlMemStrdup;
pub use crate::src::globals::xmlRealloc;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __uint8_t = crate::src::nanoftp::__uint8_t;
pub type __uint16_t = crate::src::nanoftp::__uint16_t;
pub type __uint32_t = crate::src::dict::__uint32_t;
pub type __ssize_t = crate::src::catalog::__ssize_t;
pub type __socklen_t = crate::src::nanoftp::__socklen_t;
pub type ssize_t = crate::src::catalog::ssize_t;
pub type socklen_t = crate::src::nanoftp::socklen_t;
pub type __socket_type = crate::src::nanoftp::__socket_type;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = crate::src::nanoftp::sa_family_t;
// #[derive(Copy, Clone)]

pub type sockaddr = crate::src::nanoftp::sockaddr;
pub type uint8_t = crate::src::nanoftp::uint8_t;
pub type uint16_t = crate::src::nanoftp::uint16_t;
pub type uint32_t = crate::src::dict::uint32_t;
pub type in_addr_t = crate::src::nanoftp::in_addr_t;
// #[derive(Copy, Clone)]

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
pub type in_port_t = crate::src::nanoftp::in_port_t;
// #[derive(Copy, Clone)]

pub type in6_addr = crate::src::nanoftp::in6_addr;
// #[derive(Copy, Clone)]

pub type C2RustUnnamed_0 = crate::src::nanoftp::C2RustUnnamed_0;
// #[derive(Copy, Clone)]

pub type sockaddr_in = crate::src::nanoftp::sockaddr_in;
// #[derive(Copy, Clone)]

pub type sockaddr_in6 = crate::src::nanoftp::sockaddr_in6;
// #[derive(Copy, Clone)]

pub type hostent = crate::src::nanoftp::hostent;
// #[derive(Copy, Clone)]

pub type addrinfo = crate::src::nanoftp::addrinfo;
pub type nfds_t = u64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
pub type Byte = u8;
pub type uInt = u32;
pub type uLong = u64;
pub type Bytef = Byte;
pub type voidpf = *mut libc::c_void;
pub type alloc_func = Option::<unsafe extern "C" fn(voidpf, uInt, uInt) -> voidpf>;
pub type free_func = Option::<unsafe extern "C" fn(voidpf, voidpf) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut Bytef,
    pub avail_in: uInt,
    pub total_in: uLong,
    pub next_out: *mut Bytef,
    pub avail_out: uInt,
    pub total_out: uLong,
    pub msg: *mut i8,
    pub state: *mut internal_state,
    pub zalloc: alloc_func,
    pub zfree: free_func,
    pub opaque: voidpf,
    pub data_type: i32,
    pub adler: uLong,
    pub reserved: uLong,
}
pub type z_stream = z_stream_s;
pub type z_streamp = *mut z_stream;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub type _xmlDtd = crate::src::HTMLparser::_xmlDtd;
pub type xmlElementType = crate::src::HTMLparser::xmlElementType;
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
pub type xmlNsType = crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub type _xmlAttr = crate::src::HTMLparser::_xmlAttr;
pub type xmlAttributeType = crate::src::HTMLparser::xmlAttributeType;
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
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
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
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
pub type xmlStrdupFunc = crate::src::encoding::xmlStrdupFunc;
pub type xmlURIPtr = crate::src::SAX2::xmlURIPtr;
pub type xmlURI = crate::src::SAX2::xmlURI;
// #[derive(Copy, Clone)]

pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlNanoHTTPCtxtPtr = *mut xmlNanoHTTPCtxt;
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
    pub strm: *mut z_stream,
    pub usesGzip: i32,
}
#[inline]
 extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as i32 >> 8 as i32 & 0xff as i32
        | (__bsx as i32 & 0xff as i32) << 8 as i32)
        as __uint16_t;
}
static mut initialized: i32 = 0 as i32;
static mut proxy: *mut i8 = 0 as *const i8 as *mut i8;
static mut proxyPort: i32 = 0;
static mut timeout: u32 = 60 as i32 as u32;
unsafe extern "C" fn xmlHTTPErrMemory(mut extra: *const i8) {
    __xmlSimpleError(
        XML_FROM_HTTP as i32,
        XML_ERR_NO_MEMORY as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
}
unsafe extern "C" fn socket_errno() -> i32 {
    return *__errno_location();
}
unsafe extern "C" fn have_ipv6() -> i32 {
    let mut s: i32 = 0;
    s = socket(10 as i32, SOCK_STREAM as i32, 0 as i32);
    if s != -(1 as i32) {
        close(s);
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPInit() {
    let mut env: *const i8 = 0 as *const i8;
    if initialized != 0 {
        return;
    }
    if proxy.is_null() {
        proxyPort = 80 as i32;
        env = getenv(b"no_proxy\0" as *const u8 as *const i8);
        if !(!env.is_null()
            && (*env.offset(0 as i32 as isize) as i32 == '*' as i32
                && *env.offset(1 as i32 as isize) as i32
                    == 0 as i32))
        {
            env = getenv(b"http_proxy\0" as *const u8 as *const i8);
            if !env.is_null() {
                xmlNanoHTTPScanProxy(env);
            } else {
                env = getenv(b"HTTP_PROXY\0" as *const u8 as *const i8);
                if !env.is_null() {
                    xmlNanoHTTPScanProxy(env);
                }
            }
        }
    }
    initialized = 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPCleanup() {
    if !proxy.is_null() {
        xmlFree.expect("non-null function pointer")(proxy as *mut libc::c_void);
        proxy = 0 as *mut i8;
    }
    initialized = 0 as i32;
}
unsafe extern "C" fn xmlNanoHTTPScanURL(
    mut ctxt: xmlNanoHTTPCtxtPtr,
    mut URL: *const i8,
) {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut len: i32 = 0;
    if !((*ctxt).protocol).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).protocol as *mut libc::c_void);
        let fresh0 = &mut ((*ctxt).protocol);
        *fresh0 = 0 as *mut i8;
    }
    if !((*ctxt).hostname).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).hostname as *mut libc::c_void);
        let fresh1 = &mut ((*ctxt).hostname);
        *fresh1 = 0 as *mut i8;
    }
    if !((*ctxt).path).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).path as *mut libc::c_void);
        let fresh2 = &mut ((*ctxt).path);
        *fresh2 = 0 as *mut i8;
    }
    if !((*ctxt).query).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).query as *mut libc::c_void);
        let fresh3 = &mut ((*ctxt).query);
        *fresh3 = 0 as *mut i8;
    }
    if URL.is_null() {
        return;
    }
    uri = xmlParseURIRaw(URL, 1 as i32);
    if uri.is_null() {
        return;
    }
    if ((*uri).scheme).is_null() || ((*uri).server).is_null() {
        xmlFreeURI(uri);
        return;
    }
    let fresh4 = &mut ((*ctxt).protocol);
    *fresh4 = xmlMemStrdup.expect("non-null function pointer")((*uri).scheme);
    if !((*uri).server).is_null() && *(*uri).server as i32 == '[' as i32 {
        len = strlen((*uri).server) as i32;
        if len > 2 as i32
            && *((*uri).server).offset((len - 1 as i32) as isize) as i32
                == ']' as i32
        {
            let fresh5 = &mut ((*ctxt).hostname);
            *fresh5 = xmlCharStrndup(
                ((*uri).server).offset(1 as i32 as isize),
                len - 2 as i32,
            ) as *mut i8;
        } else {
            let fresh6 = &mut ((*ctxt).hostname);
            *fresh6 = xmlMemStrdup.expect("non-null function pointer")((*uri).server);
        }
    } else {
        let fresh7 = &mut ((*ctxt).hostname);
        *fresh7 = xmlMemStrdup.expect("non-null function pointer")((*uri).server);
    }
    if !((*uri).path).is_null() {
        let fresh8 = &mut ((*ctxt).path);
        *fresh8 = xmlMemStrdup.expect("non-null function pointer")((*uri).path);
    } else {
        let fresh9 = &mut ((*ctxt).path);
        *fresh9 = xmlMemStrdup
            .expect(
                "non-null function pointer",
            )(b"/\0" as *const u8 as *const i8);
    }
    if !((*uri).query).is_null() {
        let fresh10 = &mut ((*ctxt).query);
        *fresh10 = xmlMemStrdup.expect("non-null function pointer")((*uri).query);
    }
    if (*uri).port != 0 as i32 {
        (*ctxt).port = (*uri).port;
    }
    xmlFreeURI(uri);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPScanProxy(mut URL: *const i8) {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    if !proxy.is_null() {
        xmlFree.expect("non-null function pointer")(proxy as *mut libc::c_void);
        proxy = 0 as *mut i8;
    }
    proxyPort = 0 as i32;
    if URL.is_null() {
        return;
    }
    uri = xmlParseURIRaw(URL, 1 as i32);
    if uri.is_null() || ((*uri).scheme).is_null()
        || strcmp((*uri).scheme, b"http\0" as *const u8 as *const i8) != 0
        || ((*uri).server).is_null()
    {
        __xmlIOErr(
            XML_FROM_HTTP as i32,
            XML_HTTP_URL_SYNTAX as i32,
            b"Syntax Error\n\0" as *const u8 as *const i8,
        );
        if !uri.is_null() {
            xmlFreeURI(uri);
        }
        return;
    }
    proxy = xmlMemStrdup.expect("non-null function pointer")((*uri).server);
    if (*uri).port != 0 as i32 {
        proxyPort = (*uri).port;
    }
    xmlFreeURI(uri);
}
unsafe extern "C" fn xmlNanoHTTPNewCtxt(
    mut URL: *const i8,
) -> xmlNanoHTTPCtxtPtr {
    let mut ret: xmlNanoHTTPCtxtPtr = 0 as *mut xmlNanoHTTPCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNanoHTTPCtxt>() as u64)
        as xmlNanoHTTPCtxtPtr;
    if ret.is_null() {
        xmlHTTPErrMemory(b"allocating context\0" as *const u8 as *const i8);
        return 0 as xmlNanoHTTPCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlNanoHTTPCtxt>() as u64,
    );
    (*ret).port = 80 as i32;
    (*ret).returnValue = 0 as i32;
    (*ret).fd = -(1 as i32);
    (*ret).ContentLength = -(1 as i32);
    xmlNanoHTTPScanURL(ret, URL);
    return ret;
}
unsafe extern "C" fn xmlNanoHTTPFreeCtxt(mut ctxt: xmlNanoHTTPCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).hostname).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).hostname as *mut libc::c_void);
    }
    if !((*ctxt).protocol).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).protocol as *mut libc::c_void);
    }
    if !((*ctxt).path).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).path as *mut libc::c_void);
    }
    if !((*ctxt).query).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).query as *mut libc::c_void);
    }
    if !((*ctxt).out).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).out as *mut libc::c_void);
    }
    if !((*ctxt).in_0).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).in_0 as *mut libc::c_void);
    }
    if !((*ctxt).contentType).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).contentType as *mut libc::c_void);
    }
    if !((*ctxt).encoding).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).encoding as *mut libc::c_void);
    }
    if !((*ctxt).mimeType).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).mimeType as *mut libc::c_void);
    }
    if !((*ctxt).location).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).location as *mut libc::c_void);
    }
    if !((*ctxt).authHeader).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).authHeader as *mut libc::c_void);
    }
    if !((*ctxt).strm).is_null() {
        inflateEnd((*ctxt).strm);
        xmlFree.expect("non-null function pointer")((*ctxt).strm as *mut libc::c_void);
    }
    (*ctxt).state = 4 as i32;
    if (*ctxt).fd != -(1 as i32) {
        close((*ctxt).fd);
    }
    (*ctxt).fd = -(1 as i32);
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlNanoHTTPSend(
    mut ctxt: xmlNanoHTTPCtxtPtr,
    mut xmt_ptr: *const i8,
    mut outlen: i32,
) -> i32 {
    let mut total_sent: i32 = 0 as i32;
    let mut p: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    if (*ctxt).state & 1 as i32 != 0 && !xmt_ptr.is_null() {
        while total_sent < outlen {
            let mut nsent: i32 = send(
                (*ctxt).fd,
                xmt_ptr.offset(total_sent as isize) as *const libc::c_void,
                (outlen - total_sent) as size_t,
                0 as i32,
            ) as i32;
            if nsent > 0 as i32 {
                total_sent += nsent;
            } else if nsent == -(1 as i32) && socket_errno() != 11 as i32
                {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"send failed\n\0" as *const u8 as *const i8,
                );
                if total_sent == 0 as i32 {
                    total_sent = -(1 as i32);
                }
                break;
            } else {
                p.fd = (*ctxt).fd;
                p.events = 0x4 as i32 as i16;
                poll(
                    &mut p,
                    1 as i32 as nfds_t,
                    timeout.wrapping_mul(1000 as i32 as u32)
                        as i32,
                );
            }
        }
    }
    return total_sent;
}
unsafe extern "C" fn xmlNanoHTTPRecv(mut ctxt: xmlNanoHTTPCtxtPtr) -> i32 {
    let mut p: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    while (*ctxt).state & 2 as i32 != 0 {
        if ((*ctxt).in_0).is_null() {
            let fresh11 = &mut ((*ctxt).in_0);
            *fresh11 = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (65000 as i32 as u64)
                    .wrapping_mul(::std::mem::size_of::<i8>() as u64),
            ) as *mut i8;
            if ((*ctxt).in_0).is_null() {
                xmlHTTPErrMemory(
                    b"allocating input\0" as *const u8 as *const i8,
                );
                (*ctxt).last = -(1 as i32);
                return -(1 as i32);
            }
            (*ctxt).inlen = 65000 as i32;
            let fresh12 = &mut ((*ctxt).inrptr);
            *fresh12 = (*ctxt).in_0;
            let fresh13 = &mut ((*ctxt).content);
            *fresh13 = *fresh12;
            let fresh14 = &mut ((*ctxt).inptr);
            *fresh14 = *fresh13;
        }
        if (*ctxt).inrptr > ((*ctxt).in_0).offset(4096 as i32 as isize) {
            let mut delta: i32 = ((*ctxt).inrptr).offset_from((*ctxt).in_0)
                as i64 as i32;
            let mut len: i32 = ((*ctxt).inptr).offset_from((*ctxt).inrptr)
                as i64 as i32;
            memmove(
                (*ctxt).in_0 as *mut libc::c_void,
                (*ctxt).inrptr as *const libc::c_void,
                len as u64,
            );
            let fresh15 = &mut ((*ctxt).inrptr);
            *fresh15 = (*fresh15).offset(-(delta as isize));
            let fresh16 = &mut ((*ctxt).content);
            *fresh16 = (*fresh16).offset(-(delta as isize));
            let fresh17 = &mut ((*ctxt).inptr);
            *fresh17 = (*fresh17).offset(-(delta as isize));
        }
        if ((*ctxt).in_0).offset((*ctxt).inlen as isize)
            < ((*ctxt).inptr).offset(4096 as i32 as isize)
        {
            let mut d_inptr: i32 = ((*ctxt).inptr).offset_from((*ctxt).in_0)
                as i64 as i32;
            let mut d_content: i32 = ((*ctxt).content).offset_from((*ctxt).in_0)
                as i64 as i32;
            let mut d_inrptr: i32 = ((*ctxt).inrptr).offset_from((*ctxt).in_0)
                as i64 as i32;
            let mut tmp_ptr: *mut i8 = (*ctxt).in_0;
            (*ctxt).inlen *= 2 as i32;
            let fresh18 = &mut ((*ctxt).in_0);
            *fresh18 = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(tmp_ptr as *mut libc::c_void, (*ctxt).inlen as size_t)
                as *mut i8;
            if ((*ctxt).in_0).is_null() {
                xmlHTTPErrMemory(
                    b"allocating input buffer\0" as *const u8 as *const i8,
                );
                xmlFree
                    .expect("non-null function pointer")(tmp_ptr as *mut libc::c_void);
                (*ctxt).last = -(1 as i32);
                return -(1 as i32);
            }
            let fresh19 = &mut ((*ctxt).inptr);
            *fresh19 = ((*ctxt).in_0).offset(d_inptr as isize);
            let fresh20 = &mut ((*ctxt).content);
            *fresh20 = ((*ctxt).in_0).offset(d_content as isize);
            let fresh21 = &mut ((*ctxt).inrptr);
            *fresh21 = ((*ctxt).in_0).offset(d_inrptr as isize);
        }
        (*ctxt)
            .last = recv(
            (*ctxt).fd,
            (*ctxt).inptr as *mut libc::c_void,
            4096 as i32 as size_t,
            0 as i32,
        ) as i32;
        if (*ctxt).last > 0 as i32 {
            let fresh22 = &mut ((*ctxt).inptr);
            *fresh22 = (*fresh22).offset((*ctxt).last as isize);
            return (*ctxt).last;
        }
        if (*ctxt).last == 0 as i32 {
            return 0 as i32;
        }
        if (*ctxt).last == -(1 as i32) {
            match socket_errno() {
                115 | 11 => {}
                104 | 108 => return 0 as i32,
                _ => {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"recv failed\n\0" as *const u8 as *const i8,
                    );
                    return -(1 as i32);
                }
            }
        }
        p.fd = (*ctxt).fd;
        p.events = 0x1 as i32 as i16;
        if poll(
            &mut p,
            1 as i32 as nfds_t,
            timeout.wrapping_mul(1000 as i32 as u32) as i32,
        ) < 1 as i32 && *__errno_location() != 4 as i32
        {
            return 0 as i32;
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlNanoHTTPReadLine(
    mut ctxt: xmlNanoHTTPCtxtPtr,
) -> *mut i8 {
    let mut buf: [i8; 4096] = [0; 4096];
    let mut bp: *mut i8 = buf.as_mut_ptr();
    let mut rc: i32 = 0;
    while (bp.offset_from(buf.as_mut_ptr()) as i64)
        < 4095 as i32 as i64
    {
        if (*ctxt).inrptr == (*ctxt).inptr {
            rc = xmlNanoHTTPRecv(ctxt);
            if rc == 0 as i32 {
                if bp == buf.as_mut_ptr() {
                    return 0 as *mut i8
                } else {
                    *bp = 0 as i32 as i8;
                }
                return xmlMemStrdup
                    .expect("non-null function pointer")(buf.as_mut_ptr());
            } else {
                if rc == -(1 as i32) {
                    return 0 as *mut i8;
                }
            }
        }
        let fresh23 = &mut ((*ctxt).inrptr);
        let fresh24 = *fresh23;
        *fresh23 = (*fresh23).offset(1);
        *bp = *fresh24;
        if *bp as i32 == '\n' as i32 {
            *bp = 0 as i32 as i8;
            return xmlMemStrdup.expect("non-null function pointer")(buf.as_mut_ptr());
        }
        if *bp as i32 != '\r' as i32 {
            bp = bp.offset(1);
        }
    }
    buf[4095 as i32 as usize] = 0 as i32 as i8;
    return xmlMemStrdup.expect("non-null function pointer")(buf.as_mut_ptr());
}
unsafe extern "C" fn xmlNanoHTTPScanAnswer(
    mut ctxt: xmlNanoHTTPCtxtPtr,
    mut line: *const i8,
) {
    let mut cur: *const i8 = line;
    if line.is_null() {
        return;
    }
    if strncmp(
        line,
        b"HTTP/\0" as *const u8 as *const i8,
        5 as i32 as u64,
    ) == 0
    {
        let mut version: i32 = 0 as i32;
        let mut ret: i32 = 0 as i32;
        cur = cur.offset(5 as i32 as isize);
        while *cur as i32 >= '0' as i32 && *cur as i32 <= '9' as i32 {
            version *= 10 as i32;
            version += *cur as i32 - '0' as i32;
            cur = cur.offset(1);
        }
        if *cur as i32 == '.' as i32 {
            cur = cur.offset(1);
            if *cur as i32 >= '0' as i32 && *cur as i32 <= '9' as i32 {
                version *= 10 as i32;
                version += *cur as i32 - '0' as i32;
                cur = cur.offset(1);
            }
            while *cur as i32 >= '0' as i32 && *cur as i32 <= '9' as i32
            {
                cur = cur.offset(1);
            }
        } else {
            version *= 10 as i32;
        }
        if *cur as i32 != ' ' as i32 && *cur as i32 != '\t' as i32 {
            return;
        }
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if (*cur as i32) < '0' as i32 || *cur as i32 > '9' as i32 {
            return;
        }
        while *cur as i32 >= '0' as i32 && *cur as i32 <= '9' as i32 {
            ret *= 10 as i32;
            ret += *cur as i32 - '0' as i32;
            cur = cur.offset(1);
        }
        if *cur as i32 != 0 as i32 && *cur as i32 != ' ' as i32
            && *cur as i32 != '\t' as i32
        {
            return;
        }
        (*ctxt).returnValue = ret;
        (*ctxt).version = version;
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Type:\0" as *const u8 as *const i8 as *mut xmlChar,
            13 as i32,
        ) == 0
        {
        let mut charset: *const xmlChar = 0 as *const xmlChar;
        let mut last: *const xmlChar = 0 as *const xmlChar;
        let mut mime: *const xmlChar = 0 as *const xmlChar;
        cur = cur.offset(13 as i32 as isize);
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if !((*ctxt).contentType).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).contentType as *mut libc::c_void);
        }
        let fresh25 = &mut ((*ctxt).contentType);
        *fresh25 = xmlMemStrdup.expect("non-null function pointer")(cur);
        mime = cur as *const xmlChar;
        last = mime;
        while *last as i32 != 0 as i32
            && *last as i32 != ' ' as i32 && *last as i32 != '\t' as i32
            && *last as i32 != ';' as i32 && *last as i32 != ',' as i32
        {
            last = last.offset(1);
        }
        if !((*ctxt).mimeType).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).mimeType as *mut libc::c_void);
        }
        let fresh26 = &mut ((*ctxt).mimeType);
        *fresh26 = xmlStrndup(
            mime,
            last.offset_from(mime) as i64 as i32,
        ) as *mut i8;
        charset = xmlStrstr(
            (*ctxt).contentType as *mut xmlChar,
            b"charset=\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if !charset.is_null() {
            charset = charset.offset(8 as i32 as isize);
            last = charset;
            while *last as i32 != 0 as i32
                && *last as i32 != ' ' as i32
                && *last as i32 != '\t' as i32
                && *last as i32 != ';' as i32
                && *last as i32 != ',' as i32
            {
                last = last.offset(1);
            }
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut libc::c_void);
            }
            let fresh27 = &mut ((*ctxt).encoding);
            *fresh27 = xmlStrndup(
                charset,
                last.offset_from(charset) as i64 as i32,
            ) as *mut i8;
        }
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"ContentType:\0" as *const u8 as *const i8 as *mut xmlChar,
            12 as i32,
        ) == 0
        {
        let mut charset_0: *const xmlChar = 0 as *const xmlChar;
        let mut last_0: *const xmlChar = 0 as *const xmlChar;
        let mut mime_0: *const xmlChar = 0 as *const xmlChar;
        cur = cur.offset(12 as i32 as isize);
        if !((*ctxt).contentType).is_null() {
            return;
        }
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        let fresh28 = &mut ((*ctxt).contentType);
        *fresh28 = xmlMemStrdup.expect("non-null function pointer")(cur);
        mime_0 = cur as *const xmlChar;
        last_0 = mime_0;
        while *last_0 as i32 != 0 as i32
            && *last_0 as i32 != ' ' as i32
            && *last_0 as i32 != '\t' as i32
            && *last_0 as i32 != ';' as i32
            && *last_0 as i32 != ',' as i32
        {
            last_0 = last_0.offset(1);
        }
        if !((*ctxt).mimeType).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).mimeType as *mut libc::c_void);
        }
        let fresh29 = &mut ((*ctxt).mimeType);
        *fresh29 = xmlStrndup(
            mime_0,
            last_0.offset_from(mime_0) as i64 as i32,
        ) as *mut i8;
        charset_0 = xmlStrstr(
            (*ctxt).contentType as *mut xmlChar,
            b"charset=\0" as *const u8 as *const i8 as *mut xmlChar,
        );
        if !charset_0.is_null() {
            charset_0 = charset_0.offset(8 as i32 as isize);
            last_0 = charset_0;
            while *last_0 as i32 != 0 as i32
                && *last_0 as i32 != ' ' as i32
                && *last_0 as i32 != '\t' as i32
                && *last_0 as i32 != ';' as i32
                && *last_0 as i32 != ',' as i32
            {
                last_0 = last_0.offset(1);
            }
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut libc::c_void);
            }
            let fresh30 = &mut ((*ctxt).encoding);
            *fresh30 = xmlStrndup(
                charset_0,
                last_0.offset_from(charset_0) as i64 as i32,
            ) as *mut i8;
        }
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"Location:\0" as *const u8 as *const i8 as *mut xmlChar,
            9 as i32,
        ) == 0
        {
        cur = cur.offset(9 as i32 as isize);
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if !((*ctxt).location).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).location as *mut libc::c_void);
        }
        if *cur as i32 == '/' as i32 {
            let mut tmp_http: *mut xmlChar = xmlStrdup(
                b"http://\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            let mut tmp_loc: *mut xmlChar = xmlStrcat(
                tmp_http,
                (*ctxt).hostname as *const xmlChar,
            );
            let fresh31 = &mut ((*ctxt).location);
            *fresh31 = xmlStrcat(tmp_loc, cur as *const xmlChar) as *mut i8;
        } else {
            let fresh32 = &mut ((*ctxt).location);
            *fresh32 = xmlMemStrdup.expect("non-null function pointer")(cur);
        }
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"WWW-Authenticate:\0" as *const u8 as *const i8 as *mut xmlChar,
            17 as i32,
        ) == 0
        {
        cur = cur.offset(17 as i32 as isize);
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if !((*ctxt).authHeader).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).authHeader as *mut libc::c_void);
        }
        let fresh33 = &mut ((*ctxt).authHeader);
        *fresh33 = xmlMemStrdup.expect("non-null function pointer")(cur);
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"Proxy-Authenticate:\0" as *const u8 as *const i8 as *mut xmlChar,
            19 as i32,
        ) == 0
        {
        cur = cur.offset(19 as i32 as isize);
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if !((*ctxt).authHeader).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).authHeader as *mut libc::c_void);
        }
        let fresh34 = &mut ((*ctxt).authHeader);
        *fresh34 = xmlMemStrdup.expect("non-null function pointer")(cur);
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Encoding:\0" as *const u8 as *const i8 as *mut xmlChar,
            17 as i32,
        ) == 0
        {
        cur = cur.offset(17 as i32 as isize);
        while *cur as i32 == ' ' as i32 || *cur as i32 == '\t' as i32 {
            cur = cur.offset(1);
        }
        if xmlStrncasecmp(
            cur as *mut xmlChar,
            b"gzip\0" as *const u8 as *const i8 as *mut xmlChar,
            4 as i32,
        ) == 0
        {
            (*ctxt).usesGzip = 1 as i32;
            let fresh35 = &mut ((*ctxt).strm);
            *fresh35 = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(::std::mem::size_of::<z_stream>() as u64) as *mut z_stream;
            if !((*ctxt).strm).is_null() {
                let fresh36 = &mut ((*(*ctxt).strm).zalloc);
                *fresh36 = None;
                let fresh37 = &mut ((*(*ctxt).strm).zfree);
                *fresh37 = None;
                let fresh38 = &mut ((*(*ctxt).strm).opaque);
                *fresh38 = 0 as voidpf;
                (*(*ctxt).strm).avail_in = 0 as i32 as uInt;
                let fresh39 = &mut ((*(*ctxt).strm).next_in);
                *fresh39 = 0 as *mut Bytef;
                inflateInit2_(
                    (*ctxt).strm,
                    31 as i32,
                    b"1.2.11\0" as *const u8 as *const i8,
                    ::std::mem::size_of::<z_stream>() as u64 as i32,
                );
            }
        }
    } else if xmlStrncasecmp(
            line as *mut xmlChar,
            b"Content-Length:\0" as *const u8 as *const i8 as *mut xmlChar,
            15 as i32,
        ) == 0
        {
        cur = cur.offset(15 as i32 as isize);
        (*ctxt)
            .ContentLength = strtol(cur, 0 as *mut *mut i8, 10 as i32)
            as i32;
    }
}
unsafe extern "C" fn xmlNanoHTTPConnectAttempt(mut addr: *mut sockaddr) -> i32 {
    let mut p: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let mut status: i32 = 0;
    let mut addrlen: i32 = 0;
    let mut s: i32 = 0;
    if (*addr).sa_family as i32 == 10 as i32 {
        s = socket(
            10 as i32,
            SOCK_STREAM as i32,
            IPPROTO_TCP as i32,
        );
        addrlen = ::std::mem::size_of::<sockaddr_in6>() as u64 as i32;
    } else {
        s = socket(
            2 as i32,
            SOCK_STREAM as i32,
            IPPROTO_TCP as i32,
        );
        addrlen = ::std::mem::size_of::<sockaddr_in>() as u64 as i32;
    }
    if s == -(1 as i32) {
        __xmlIOErr(
            XML_FROM_HTTP as i32,
            0 as i32,
            b"socket failed\n\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    status = fcntl(s, 3 as i32, 0 as i32);
    if status != -(1 as i32) {
        status |= 0o4000 as i32;
        status = fcntl(s, 4 as i32, status);
    }
    if status < 0 as i32 {
        __xmlIOErr(
            XML_FROM_HTTP as i32,
            0 as i32,
            b"error setting non-blocking IO\n\0" as *const u8 as *const i8,
        );
        close(s);
        return -(1 as i32);
    }
    if connect(s, addr, addrlen as socklen_t) == -(1 as i32) {
        match socket_errno() {
            115 | 11 => {}
            _ => {
                __xmlIOErr(
                    XML_FROM_HTTP as i32,
                    0 as i32,
                    b"error connecting to HTTP server\0" as *const u8
                        as *const i8,
                );
                close(s);
                return -(1 as i32);
            }
        }
    }
    p.fd = s;
    p.events = 0x4 as i32 as i16;
    match poll(
        &mut p,
        1 as i32 as nfds_t,
        timeout.wrapping_mul(1000 as i32 as u32) as i32,
    ) {
        0 => {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"Connect attempt timed out\0" as *const u8 as *const i8,
            );
            close(s);
            return -(1 as i32);
        }
        -1 => {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"Connect failed\0" as *const u8 as *const i8,
            );
            close(s);
            return -(1 as i32);
        }
        _ => {}
    }
    if p.revents as i32 == 0x4 as i32 {
        let mut len: socklen_t = 0;
        len = ::std::mem::size_of::<i32>() as u64 as socklen_t;
        if getsockopt(
            s,
            1 as i32,
            4 as i32,
            &mut status as *mut i32 as *mut i8 as *mut libc::c_void,
            &mut len,
        ) < 0 as i32
        {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"getsockopt failed\n\0" as *const u8 as *const i8,
            );
            close(s);
            return -(1 as i32);
        }
        if status != 0 {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"Error connecting to remote host\0" as *const u8 as *const i8,
            );
            close(s);
            *__errno_location() = status;
            return -(1 as i32);
        }
    } else {
        __xmlIOErr(
            XML_FROM_HTTP as i32,
            0 as i32,
            b"select failed\n\0" as *const u8 as *const i8,
        );
        close(s);
        return -(1 as i32);
    }
    return s;
}
unsafe extern "C" fn xmlNanoHTTPConnectHost(
    mut host: *const i8,
    mut port: i32,
) -> i32 {
    let mut addr: *mut sockaddr = 0 as *mut sockaddr;
    let mut sockin: sockaddr_in = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut ia6: in6_addr = in6_addr {
        __in6_u: C2RustUnnamed_0 {
            __u6_addr8: [0; 16],
        },
    };
    let mut sockin6: sockaddr_in6 = sockaddr_in6 {
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
    memset(
        &mut sockin as *mut sockaddr_in as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<sockaddr_in>() as u64,
    );
    memset(
        &mut sockin6 as *mut sockaddr_in6 as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<sockaddr_in6>() as u64,
    );
    if have_ipv6() != 0 {
        let mut status: i32 = 0;
        let mut hints: addrinfo = addrinfo {
            ai_flags: 0,
            ai_family: 0,
            ai_socktype: 0,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: 0 as *mut sockaddr,
            ai_canonname: 0 as *mut i8,
            ai_next: 0 as *mut addrinfo,
        };
        let mut res: *mut addrinfo = 0 as *mut addrinfo;
        let mut result: *mut addrinfo = 0 as *mut addrinfo;
        result = 0 as *mut addrinfo;
        memset(
            &mut hints as *mut addrinfo as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<addrinfo>() as u64,
        );
        hints.ai_socktype = SOCK_STREAM as i32;
        status = getaddrinfo(host, 0 as *const i8, &mut hints, &mut result);
        if status != 0 {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                0 as i32,
                b"getaddrinfo failed\n\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        let mut current_block_33: u64;
        res = result;
        while !res.is_null() {
            if (*res).ai_family == 2 as i32 {
                if (*res).ai_addrlen as size_t
                    > ::std::mem::size_of::<sockaddr_in>() as u64
                {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"address size mismatch\n\0" as *const u8 as *const i8,
                    );
                    freeaddrinfo(result);
                    return -(1 as i32);
                }
                memcpy(
                    &mut sockin as *mut sockaddr_in as *mut libc::c_void,
                    (*res).ai_addr as *const libc::c_void,
                    (*res).ai_addrlen as u64,
                );
                sockin.sin_port = __bswap_16(port as __uint16_t);
                addr = &mut sockin as *mut sockaddr_in as *mut sockaddr;
                current_block_33 = 5494826135382683477;
            } else if have_ipv6() != 0 && (*res).ai_family == 10 as i32 {
                if (*res).ai_addrlen as size_t
                    > ::std::mem::size_of::<sockaddr_in6>() as u64
                {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"address size mismatch\n\0" as *const u8 as *const i8,
                    );
                    freeaddrinfo(result);
                    return -(1 as i32);
                }
                memcpy(
                    &mut sockin6 as *mut sockaddr_in6 as *mut libc::c_void,
                    (*res).ai_addr as *const libc::c_void,
                    (*res).ai_addrlen as u64,
                );
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
                        freeaddrinfo(result);
                        return s;
                    }
                }
                _ => {}
            }
            res = (*res).ai_next;
        }
        if !result.is_null() {
            freeaddrinfo(result);
        }
    } else {
        let mut h: *mut hostent = 0 as *mut hostent;
        let mut ia: in_addr = in_addr { s_addr: 0 };
        let mut i: i32 = 0;
        h = gethostbyname(host);
        if h.is_null() {
            let mut h_err_txt: *const i8 = b"\0" as *const u8
                as *const i8;
            match *__h_errno_location() {
                1 => {
                    h_err_txt = b"Authoritative host not found\0" as *const u8
                        as *const i8;
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
                    h_err_txt = b"Valid name, no data record of requested type.\0"
                        as *const u8 as *const i8;
                }
                _ => {
                    h_err_txt = b"No error text defined.\0" as *const u8
                        as *const i8;
                }
            }
            __xmlIOErr(XML_FROM_HTTP as i32, 0 as i32, h_err_txt);
            return -(1 as i32);
        }
        i = 0 as i32;
        while !(*((*h).h_addr_list).offset(i as isize)).is_null() {
            if (*h).h_addrtype == 2 as i32 {
                if (*h).h_length as u32 as u64
                    > ::std::mem::size_of::<in_addr>() as u64
                {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"address size mismatch\n\0" as *const u8 as *const i8,
                    );
                    return -(1 as i32);
                }
                memcpy(
                    &mut ia as *mut in_addr as *mut libc::c_void,
                    *((*h).h_addr_list).offset(i as isize) as *const libc::c_void,
                    (*h).h_length as u64,
                );
                sockin.sin_family = (*h).h_addrtype as sa_family_t;
                sockin.sin_addr = ia;
                sockin.sin_port = __bswap_16(port as u16);
                addr = &mut sockin as *mut sockaddr_in as *mut sockaddr;
            } else {
                if !(have_ipv6() != 0 && (*h).h_addrtype == 10 as i32) {
                    break;
                }
                if (*h).h_length as u32 as u64
                    > ::std::mem::size_of::<in6_addr>() as u64
                {
                    __xmlIOErr(
                        XML_FROM_HTTP as i32,
                        0 as i32,
                        b"address size mismatch\n\0" as *const u8 as *const i8,
                    );
                    return -(1 as i32);
                }
                memcpy(
                    &mut ia6 as *mut in6_addr as *mut libc::c_void,
                    *((*h).h_addr_list).offset(i as isize) as *const libc::c_void,
                    (*h).h_length as u64,
                );
                sockin6.sin6_family = (*h).h_addrtype as sa_family_t;
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
pub unsafe extern "C" fn xmlNanoHTTPOpen(
    mut URL: *const i8,
    mut contentType: *mut *mut i8,
) -> *mut libc::c_void {
    if !contentType.is_null() {
        *contentType = 0 as *mut i8;
    }
    return xmlNanoHTTPMethod(
        URL,
        0 as *const i8,
        0 as *const i8,
        contentType,
        0 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPOpenRedir(
    mut URL: *const i8,
    mut contentType: *mut *mut i8,
    mut redir: *mut *mut i8,
) -> *mut libc::c_void {
    if !contentType.is_null() {
        *contentType = 0 as *mut i8;
    }
    if !redir.is_null() {
        *redir = 0 as *mut i8;
    }
    return xmlNanoHTTPMethodRedir(
        URL,
        0 as *const i8,
        0 as *const i8,
        contentType,
        redir,
        0 as *const i8,
        0 as i32,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPRead(
    mut ctx: *mut libc::c_void,
    mut dest: *mut libc::c_void,
    mut len: i32,
) -> i32 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
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
    if (*ctxt).usesGzip == 1 as i32 {
        if ((*ctxt).strm).is_null() {
            return 0 as i32;
        }
        let fresh40 = &mut ((*(*ctxt).strm).next_out);
        *fresh40 = dest as *mut Bytef;
        (*(*ctxt).strm).avail_out = len as uInt;
        (*(*ctxt).strm)
            .avail_in = ((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64
            as uInt;
        while (*(*ctxt).strm).avail_out > 0 as i32 as u32
            && ((*(*ctxt).strm).avail_in > 0 as i32 as u32
                || xmlNanoHTTPRecv(ctxt) > 0 as i32)
        {
            let fresh41 = &mut ((*(*ctxt).strm).avail_in);
            *fresh41 = (((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64
                - bytes_read as i64) as uInt;
            orig_avail_in = *fresh41 as i32;
            let fresh42 = &mut ((*(*ctxt).strm).next_in);
            *fresh42 = ((*ctxt).inrptr).offset(bytes_read as isize) as *mut xmlChar;
            z_ret = inflate((*ctxt).strm, 0 as i32);
            bytes_read = (bytes_read as u32)
                .wrapping_add(
                    (orig_avail_in as u32)
                        .wrapping_sub((*(*ctxt).strm).avail_in),
                ) as i32 as i32;
            if z_ret != 0 as i32 {
                break;
            }
        }
        let fresh43 = &mut ((*ctxt).inrptr);
        *fresh43 = (*fresh43).offset(bytes_read as isize);
        return (len as u32).wrapping_sub((*(*ctxt).strm).avail_out)
            as i32;
    }
    while (((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64)
        < len as i64
    {
        if xmlNanoHTTPRecv(ctxt) <= 0 as i32 {
            break;
        }
    }
    if (((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64)
        < len as i64
    {
        len = ((*ctxt).inptr).offset_from((*ctxt).inrptr) as i64 as i32;
    }
    memcpy(dest, (*ctxt).inrptr as *const libc::c_void, len as u64);
    let fresh44 = &mut ((*ctxt).inrptr);
    *fresh44 = (*fresh44).offset(len as isize);
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPClose(mut ctx: *mut libc::c_void) {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    if ctx.is_null() {
        return;
    }
    xmlNanoHTTPFreeCtxt(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPMethodRedir(
    mut URL: *const i8,
    mut method: *const i8,
    mut input: *const i8,
    mut contentType: *mut *mut i8,
    mut redir: *mut *mut i8,
    mut headers: *const i8,
    mut ilen: i32,
) -> *mut libc::c_void {
    let mut ctxt: xmlNanoHTTPCtxtPtr = 0 as *mut xmlNanoHTTPCtxt;
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
            let fresh45 = &mut ((*ctxt).location);
            *fresh45 = xmlMemStrdup.expect("non-null function pointer")(redirURL);
        }
        if ((*ctxt).protocol).is_null()
            || strcmp((*ctxt).protocol, b"http\0" as *const u8 as *const i8)
                != 0
        {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                XML_HTTP_URL_SYNTAX as i32,
                b"Not a valid HTTP URI\0" as *const u8 as *const i8,
            );
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                xmlFree
                    .expect("non-null function pointer")(redirURL as *mut libc::c_void);
            }
            return 0 as *mut libc::c_void;
        }
        if ((*ctxt).hostname).is_null() {
            __xmlIOErr(
                XML_FROM_HTTP as i32,
                XML_HTTP_UNKNOWN_HOST as i32,
                b"Failed to identify host in URI\0" as *const u8 as *const i8,
            );
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                xmlFree
                    .expect("non-null function pointer")(redirURL as *mut libc::c_void);
            }
            return 0 as *mut libc::c_void;
        }
        if !proxy.is_null() {
            blen = (strlen((*ctxt).hostname))
                .wrapping_mul(2 as i32 as u64)
                .wrapping_add(16 as i32 as u64) as i32;
            ret = xmlNanoHTTPConnectHost(proxy, proxyPort);
        } else {
            blen = strlen((*ctxt).hostname) as i32;
            ret = xmlNanoHTTPConnectHost((*ctxt).hostname, (*ctxt).port);
        }
        if ret == -(1 as i32) {
            xmlNanoHTTPFreeCtxt(ctxt);
            if !redirURL.is_null() {
                xmlFree
                    .expect("non-null function pointer")(redirURL as *mut libc::c_void);
            }
            return 0 as *mut libc::c_void;
        }
        (*ctxt).fd = ret;
        if input.is_null() {
            ilen = 0 as i32;
        } else {
            blen += 36 as i32;
        }
        if !headers.is_null() {
            blen = (blen as u64)
                .wrapping_add(
                    (strlen(headers)).wrapping_add(2 as i32 as u64),
                ) as i32 as i32;
        }
        if !contentType.is_null() && !(*contentType).is_null() {
            blen = (blen as u64)
                .wrapping_add(
                    (strlen(*contentType))
                        .wrapping_add(16 as i32 as u64),
                ) as i32 as i32;
        }
        if !((*ctxt).query).is_null() {
            blen = (blen as u64)
                .wrapping_add(
                    (strlen((*ctxt).query))
                        .wrapping_add(1 as i32 as u64),
                ) as i32 as i32;
        }
        blen = (blen as u64)
            .wrapping_add(
                (strlen(method))
                    .wrapping_add(strlen((*ctxt).path))
                    .wrapping_add(24 as i32 as u64),
            ) as i32 as i32;
        blen += 23 as i32;
        if (*ctxt).port != 80 as i32 {
            if !proxy.is_null() {
                blen += 17 as i32;
            } else {
                blen += 11 as i32;
            }
        }
        bp = xmlMallocAtomic.expect("non-null function pointer")(blen as size_t)
            as *mut i8;
        if bp.is_null() {
            xmlNanoHTTPFreeCtxt(ctxt);
            xmlHTTPErrMemory(
                b"allocating header buffer\0" as *const u8 as *const i8,
            );
            return 0 as *mut libc::c_void;
        }
        p = bp;
        if !proxy.is_null() {
            if (*ctxt).port != 80 as i32 {
                p = p
                    .offset(
                        snprintf(
                            p,
                            (blen as i64 - p.offset_from(bp) as i64)
                                as u64,
                            b"%s http://%s:%d%s\0" as *const u8 as *const i8,
                            method,
                            (*ctxt).hostname,
                            (*ctxt).port,
                            (*ctxt).path,
                        ) as isize,
                    );
            } else {
                p = p
                    .offset(
                        snprintf(
                            p,
                            (blen as i64 - p.offset_from(bp) as i64)
                                as u64,
                            b"%s http://%s%s\0" as *const u8 as *const i8,
                            method,
                            (*ctxt).hostname,
                            (*ctxt).path,
                        ) as isize,
                    );
            }
        } else {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b"%s %s\0" as *const u8 as *const i8,
                        method,
                        (*ctxt).path,
                    ) as isize,
                );
        }
        if !((*ctxt).query).is_null() {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b"?%s\0" as *const u8 as *const i8,
                        (*ctxt).query,
                    ) as isize,
                );
        }
        if (*ctxt).port == 80 as i32 {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b" HTTP/1.0\r\nHost: %s\r\n\0" as *const u8
                            as *const i8,
                        (*ctxt).hostname,
                    ) as isize,
                );
        } else {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b" HTTP/1.0\r\nHost: %s:%d\r\n\0" as *const u8
                            as *const i8,
                        (*ctxt).hostname,
                        (*ctxt).port,
                    ) as isize,
                );
        }
        p = p
            .offset(
                snprintf(
                    p,
                    (blen as i64 - p.offset_from(bp) as i64)
                        as u64,
                    b"Accept-Encoding: gzip\r\n\0" as *const u8 as *const i8,
                ) as isize,
            );
        if !contentType.is_null() && !(*contentType).is_null() {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b"Content-Type: %s\r\n\0" as *const u8 as *const i8,
                        *contentType,
                    ) as isize,
                );
        }
        if !headers.is_null() {
            p = p
                .offset(
                    snprintf(
                        p,
                        (blen as i64 - p.offset_from(bp) as i64)
                            as u64,
                        b"%s\0" as *const u8 as *const i8,
                        headers,
                    ) as isize,
                );
        }
        if !input.is_null() {
            snprintf(
                p,
                (blen as i64 - p.offset_from(bp) as i64)
                    as u64,
                b"Content-Length: %d\r\n\r\n\0" as *const u8 as *const i8,
                ilen,
            );
        } else {
            snprintf(
                p,
                (blen as i64 - p.offset_from(bp) as i64)
                    as u64,
                b"\r\n\0" as *const u8 as *const i8,
            );
        }
        let fresh46 = &mut ((*ctxt).out);
        *fresh46 = bp;
        let fresh47 = &mut ((*ctxt).outptr);
        *fresh47 = *fresh46;
        (*ctxt).state = 1 as i32;
        blen = strlen((*ctxt).out) as i32;
        xmlNanoHTTPSend(ctxt, (*ctxt).out, blen);
        if !input.is_null() {
            xmlNanoHTTPSend(ctxt, input, ilen);
        }
        (*ctxt).state = 2 as i32;
        loop {
            p = xmlNanoHTTPReadLine(ctxt);
            if p.is_null() {
                break;
            }
            if *p as i32 == 0 as i32 {
                let fresh48 = &mut ((*ctxt).content);
                *fresh48 = (*ctxt).inrptr;
                xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
                break;
            } else {
                xmlNanoHTTPScanAnswer(ctxt, p);
                xmlFree.expect("non-null function pointer")(p as *mut libc::c_void);
            }
        }
        if !((*ctxt).location).is_null() && (*ctxt).returnValue >= 300 as i32
            && (*ctxt).returnValue < 400 as i32
        {
            while xmlNanoHTTPRecv(ctxt) > 0 as i32 {}
            if nbRedirects < 10 as i32 {
                nbRedirects += 1;
                if !redirURL.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(redirURL as *mut libc::c_void);
                }
                redirURL = xmlMemStrdup
                    .expect("non-null function pointer")((*ctxt).location);
                xmlNanoHTTPFreeCtxt(ctxt);
            } else {
                xmlNanoHTTPFreeCtxt(ctxt);
                if !redirURL.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(redirURL as *mut libc::c_void);
                }
                return 0 as *mut libc::c_void;
            }
        } else {
            if !contentType.is_null() {
                if !((*ctxt).contentType).is_null() {
                    *contentType = xmlMemStrdup
                        .expect("non-null function pointer")((*ctxt).contentType);
                } else {
                    *contentType = 0 as *mut i8;
                }
            }
            if !redir.is_null() && !redirURL.is_null() {
                *redir = redirURL;
            } else {
                if !redirURL.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(redirURL as *mut libc::c_void);
                }
                if !redir.is_null() {
                    *redir = 0 as *mut i8;
                }
            }
            return ctxt as *mut libc::c_void;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPMethod(
    mut URL: *const i8,
    mut method: *const i8,
    mut input: *const i8,
    mut contentType: *mut *mut i8,
    mut headers: *const i8,
    mut ilen: i32,
) -> *mut libc::c_void {
    return xmlNanoHTTPMethodRedir(
        URL,
        method,
        input,
        contentType,
        0 as *mut *mut i8,
        headers,
        ilen,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPFetch(
    mut URL: *const i8,
    mut filename: *const i8,
    mut contentType: *mut *mut i8,
) -> i32 {
    let mut ctxt: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut buf: *mut i8 = 0 as *mut i8;
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if filename.is_null() {
        return -(1 as i32);
    }
    ctxt = xmlNanoHTTPOpen(URL, contentType);
    if ctxt.is_null() {
        return -(1 as i32);
    }
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        fd = 0 as i32;
    } else {
        fd = open(
            filename,
            0o100 as i32 | 0o1 as i32,
            0o644 as i32,
        );
        if fd < 0 as i32 {
            xmlNanoHTTPClose(ctxt);
            if !contentType.is_null() && !(*contentType).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*contentType as *mut libc::c_void);
                *contentType = 0 as *mut i8;
            }
            return -(1 as i32);
        }
    }
    xmlNanoHTTPFetchContent(ctxt, &mut buf, &mut len);
    if len > 0 as i32 {
        if write(fd, buf as *const libc::c_void, len as size_t)
            == -(1 as i32) as i64
        {
            ret = -(1 as i32);
        }
    }
    xmlNanoHTTPClose(ctxt);
    close(fd);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPSave(
    mut ctxt: *mut libc::c_void,
    mut filename: *const i8,
) -> i32 {
    let mut buf: *mut i8 = 0 as *mut i8;
    let mut fd: i32 = 0;
    let mut len: i32 = 0;
    let mut ret: i32 = 0 as i32;
    if ctxt.is_null() || filename.is_null() {
        return -(1 as i32);
    }
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        fd = 0 as i32;
    } else {
        fd = open(
            filename,
            0o100 as i32 | 0o1 as i32,
            0o666 as i32,
        );
        if fd < 0 as i32 {
            xmlNanoHTTPClose(ctxt);
            return -(1 as i32);
        }
    }
    xmlNanoHTTPFetchContent(ctxt, &mut buf, &mut len);
    if len > 0 as i32 {
        if write(fd, buf as *const libc::c_void, len as size_t)
            == -(1 as i32) as i64
        {
            ret = -(1 as i32);
        }
    }
    xmlNanoHTTPClose(ctxt);
    close(fd);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPReturnCode(
    mut ctx: *mut libc::c_void,
) -> i32 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    if ctxt.is_null() {
        return -(1 as i32);
    }
    return (*ctxt).returnValue;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPAuthHeader(
    mut ctx: *mut libc::c_void,
) -> *const i8 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    if ctxt.is_null() {
        return 0 as *const i8;
    }
    return (*ctxt).authHeader;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPContentLength(
    mut ctx: *mut libc::c_void,
) -> i32 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() { -(1 as i32) } else { (*ctxt).ContentLength };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPRedir(
    mut ctx: *mut libc::c_void,
) -> *const i8 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() { 0 as *mut i8 } else { (*ctxt).location };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPEncoding(
    mut ctx: *mut libc::c_void,
) -> *const i8 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() { 0 as *mut i8 } else { (*ctxt).encoding };
}
#[no_mangle]
pub unsafe extern "C" fn xmlNanoHTTPMimeType(
    mut ctx: *mut libc::c_void,
) -> *const i8 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
    return if ctxt.is_null() { 0 as *mut i8 } else { (*ctxt).mimeType };
}
unsafe extern "C" fn xmlNanoHTTPFetchContent(
    mut ctx: *mut libc::c_void,
    mut ptr: *mut *mut i8,
    mut len: *mut i32,
) -> i32 {
    let mut ctxt: xmlNanoHTTPCtxtPtr = ctx as xmlNanoHTTPCtxtPtr;
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
    if ctxt.is_null() || ((*ctxt).content).is_null() {
        *len = 0 as i32;
        *ptr = 0 as *mut i8;
        return -(1 as i32);
    }
    rcvd_lgth = ((*ctxt).inptr).offset_from((*ctxt).content) as i64
        as i32;
    loop {
        cur_lgth = xmlNanoHTTPRecv(ctxt);
        if !(cur_lgth > 0 as i32) {
            break;
        }
        rcvd_lgth += cur_lgth;
        if (*ctxt).ContentLength > 0 as i32 && rcvd_lgth >= (*ctxt).ContentLength
        {
            break;
        }
    }
    *ptr = (*ctxt).content;
    *len = rcvd_lgth;
    if (*ctxt).ContentLength > 0 as i32 && rcvd_lgth < (*ctxt).ContentLength {
        rc = -(1 as i32);
    } else if rcvd_lgth == 0 as i32 {
        rc = -(1 as i32);
    }
    return rc;
}
