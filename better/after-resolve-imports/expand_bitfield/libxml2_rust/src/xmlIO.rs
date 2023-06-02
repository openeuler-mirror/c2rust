use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> i32;
    fn fflush(__stream: *mut FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut FILE;
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    
    fn fread(
        _: *mut libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn fwrite(
        _: *const libc::c_void,
        _: u64,
        _: u64,
        _: *mut FILE,
    ) -> u64;
    fn ferror(__stream: *mut FILE) -> i32;
    fn fileno(__stream: *mut FILE) -> i32;
    
    
    
    
    fn memset(
        _: *mut libc::c_void,
        _: i32,
        _: u64,
    ) -> *mut libc::c_void;
    fn strncpy(
        _: *mut i8,
        _: *const i8,
        _: u64,
    ) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn __errno_location() -> *mut i32;
    fn __xstat(
        __ver: i32,
        __filename: *const i8,
        __stat_buf: *mut stat,
    ) -> i32;
    fn close(__fd: i32) -> i32;
    fn read(__fd: i32, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: i32, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn getcwd(__buf: *mut i8, __size: size_t) -> *mut i8;
    fn dup(__fd: i32) -> i32;
    fn gzwrite(file: gzFile, buf: voidpc, len: u32) -> i32;
    fn gzread(file: gzFile, buf: voidp, len: u32) -> i32;
    fn gzdopen(fd: i32, mode: *const i8) -> gzFile;
    fn deflateEnd(strm: z_streamp) -> i32;
    fn deflate(strm: z_streamp, flush: i32) -> i32;
    fn gzdirect(file: gzFile) -> i32;
    fn gzclose(file: gzFile) -> i32;
    fn crc32(crc: uLong, buf: *const Bytef, len: uInt) -> uLong;
    fn deflateInit2_(
        strm: z_streamp,
        level: i32,
        method: i32,
        windowBits: i32,
        memLevel: i32,
        strategy: i32,
        version: *const i8,
        stream_size: i32,
    ) -> i32;
    fn gzopen64(_: *const i8, _: *const i8) -> gzFile;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::buf::xmlBufAdd;
pub use crate::src::buf::xmlBufAddLen;
pub use crate::src::buf::xmlBufAvail;
pub use crate::src::buf::xmlBufContent;
pub use crate::src::buf::xmlBufCreate;
pub use crate::src::buf::xmlBufCreateSize;
pub use crate::src::buf::xmlBufCreateStatic;
pub use crate::src::buf::xmlBufEnd;
pub use crate::src::buf::xmlBufFree;
pub use crate::src::buf::xmlBufGetAllocationScheme;
pub use crate::src::buf::xmlBufGrow;
pub use crate::src::buf::xmlBufSetAllocationScheme;
pub use crate::src::buf::xmlBufShrink;
pub use crate::src::buf::xmlBufUse;
pub use crate::src::catalog::xmlCatalogGetDefaults;
pub use crate::src::catalog::xmlCatalogLocalResolve;
pub use crate::src::catalog::xmlCatalogLocalResolveURI;
pub use crate::src::catalog::xmlCatalogResolve;
pub use crate::src::catalog::xmlCatalogResolveURI;
pub use crate::src::encoding::xmlCharEncCloseFunc;
pub use crate::src::encoding::xmlCharEncInput;
pub use crate::src::encoding::xmlCharEncOutput;
pub use crate::src::encoding::xmlFindCharEncodingHandler;
pub use crate::src::encoding::xmlGetCharEncodingHandler;
pub use crate::src::error::__xmlRaiseError;
pub use crate::src::error::__xmlSimpleError;
pub use crate::src::globals::__xmlDefaultBufferSize;
pub use crate::src::globals::__xmlOutputBufferCreateFilenameValue;
pub use crate::src::globals::__xmlParserInputBufferCreateFilenameValue;
pub use crate::src::nanoftp::xmlNanoFTPClose;
pub use crate::src::nanoftp::xmlNanoFTPOpen;
pub use crate::src::nanoftp::xmlNanoFTPRead;
pub use crate::src::nanohttp::xmlNanoHTTPClose;
pub use crate::src::nanohttp::xmlNanoHTTPEncoding;
pub use crate::src::nanohttp::xmlNanoHTTPMethod;
pub use crate::src::nanohttp::xmlNanoHTTPMimeType;
pub use crate::src::nanohttp::xmlNanoHTTPOpen;
pub use crate::src::nanohttp::xmlNanoHTTPRead;
pub use crate::src::nanohttp::xmlNanoHTTPRedir;
pub use crate::src::nanohttp::xmlNanoHTTPReturnCode;
pub use crate::src::parserInternals::__xmlErrEncoding;
pub use crate::src::parserInternals::xmlFreeInputStream;
pub use crate::src::parserInternals::xmlNewInputFromFile;
pub use crate::src::parserInternals::xmlSwitchInputEncoding;
pub use crate::src::tree::xmlBufferAdd;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlParseURI;
pub use crate::src::uri::xmlURIUnescapeString;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrPrintf;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrncasecmp;
pub use crate::src::xmlstring::xmlStrstr;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMemStrdup;
pub use crate::src::globals::xmlRealloc;
pub use crate::src::nanohttp::internal_state;
pub use crate::src::parserInternals::_IO_wide_data;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::uri::_IO_marker;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __dev_t = crate::src::catalog::__dev_t;
pub type __uid_t = crate::src::catalog::__uid_t;
pub type __gid_t = crate::src::catalog::__gid_t;
pub type __ino_t = crate::src::catalog::__ino_t;
pub type __mode_t = crate::src::catalog::__mode_t;
pub type __nlink_t = crate::src::catalog::__nlink_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
pub type __time_t = crate::src::catalog::__time_t;
pub type __blksize_t = crate::src::catalog::__blksize_t;
pub type __blkcnt_t = crate::src::catalog::__blkcnt_t;
pub type __ssize_t = crate::src::catalog::__ssize_t;
pub type __syscall_slong_t = crate::src::catalog::__syscall_slong_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type off_t = __off64_t;
pub type ssize_t = crate::src::catalog::ssize_t;
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
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
pub const XML_IO_UNKNOWN: xmlParserErrors = 1500;
pub const XML_IO_EAFNOSUPPORT: xmlParserErrors = 1556;
pub const XML_IO_EALREADY: xmlParserErrors = 1555;
pub const XML_IO_EINPROGRESS: xmlParserErrors = 1513;
pub const XML_IO_EADDRINUSE: xmlParserErrors = 1554;
pub const XML_IO_ENETUNREACH: xmlParserErrors = 1553;
pub const XML_IO_ETIMEDOUT: xmlParserErrors = 1541;
pub const XML_IO_ECONNREFUSED: xmlParserErrors = 1552;
pub const XML_IO_EISCONN: xmlParserErrors = 1551;
pub const XML_IO_ENOTSOCK: xmlParserErrors = 1550;
pub const XML_IO_EXDEV: xmlParserErrors = 1542;
pub const XML_IO_ESRCH: xmlParserErrors = 1540;
pub const XML_IO_ESPIPE: xmlParserErrors = 1539;
pub const XML_IO_EROFS: xmlParserErrors = 1538;
pub const XML_IO_ERANGE: xmlParserErrors = 1537;
pub const XML_IO_EPIPE: xmlParserErrors = 1536;
pub const XML_IO_EPERM: xmlParserErrors = 1535;
pub const XML_IO_ENXIO: xmlParserErrors = 1534;
pub const XML_IO_ENOTTY: xmlParserErrors = 1533;
pub const XML_IO_ENOTSUP: xmlParserErrors = 1532;
pub const XML_IO_ENOTEMPTY: xmlParserErrors = 1531;
pub const XML_IO_ENOTDIR: xmlParserErrors = 1530;
pub const XML_IO_ENOSYS: xmlParserErrors = 1529;
pub const XML_IO_ENOSPC: xmlParserErrors = 1528;
pub const XML_IO_ENOMEM: xmlParserErrors = 1527;
pub const XML_IO_ENOLCK: xmlParserErrors = 1526;
pub const XML_IO_ENOEXEC: xmlParserErrors = 1525;
pub const XML_IO_ENOENT: xmlParserErrors = 1524;
pub const XML_IO_ENODEV: xmlParserErrors = 1523;
pub const XML_IO_ENFILE: xmlParserErrors = 1522;
pub const XML_IO_ENAMETOOLONG: xmlParserErrors = 1521;
pub const XML_IO_EMSGSIZE: xmlParserErrors = 1520;
pub const XML_IO_EMLINK: xmlParserErrors = 1519;
pub const XML_IO_EMFILE: xmlParserErrors = 1518;
pub const XML_IO_EISDIR: xmlParserErrors = 1517;
pub const XML_IO_EIO: xmlParserErrors = 1516;
pub const XML_IO_EINVAL: xmlParserErrors = 1515;
pub const XML_IO_EINTR: xmlParserErrors = 1514;
pub const XML_IO_EFBIG: xmlParserErrors = 1512;
pub const XML_IO_EFAULT: xmlParserErrors = 1511;
pub const XML_IO_EEXIST: xmlParserErrors = 1510;
pub const XML_IO_EDOM: xmlParserErrors = 1509;
pub const XML_IO_EDEADLK: xmlParserErrors = 1508;
pub const XML_IO_ECHILD: xmlParserErrors = 1507;
pub const XML_IO_ECANCELED: xmlParserErrors = 1506;
pub const XML_IO_EBUSY: xmlParserErrors = 1505;
pub const XML_IO_EBADMSG: xmlParserErrors = 1504;
pub const XML_IO_EBADF: xmlParserErrors = 1503;
pub const XML_IO_EAGAIN: xmlParserErrors = 1502;
pub const XML_IO_EACCES: xmlParserErrors = 1501;
pub type xmlErrorLevel = crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub const XML_IO_LOAD_ERROR: xmlParserErrors = 1549;
pub const XML_FROM_IO: C2RustUnnamed = 8;
pub type xmlParserCtxtPtr = crate::src::HTMLparser::xmlParserCtxtPtr;
pub type xmlParserCtxt = crate::src::HTMLparser::xmlParserCtxt;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
pub type xmlParserMode = crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlAttrPtr = crate::src::HTMLparser::xmlAttrPtr;
pub type xmlAttr = crate::src::HTMLparser::xmlAttr;
pub type xmlHashTablePtr = crate::src::HTMLparser::xmlHashTablePtr;
pub type xmlHashTable = crate::src::HTMLparser::xmlHashTable;
pub type xmlStartTag = crate::src::HTMLparser::xmlStartTag;
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlParserInputPtr = crate::src::HTMLparser::xmlParserInputPtr;
pub type xmlParserInput = crate::src::HTMLparser::xmlParserInput;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = crate::src::HTMLparser::xmlParserInputDeallocate;
pub type xmlParserInputBufferPtr = crate::src::HTMLparser::xmlParserInputBufferPtr;
pub type xmlParserInputBuffer = crate::src::HTMLparser::xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = crate::src::HTMLparser::xmlBufPtr;
pub type xmlBuf = crate::src::HTMLparser::xmlBuf;
pub type xmlCharEncodingHandlerPtr = crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = crate::src::HTMLparser::iconv_t;
pub type xmlCharEncodingOutputFunc = crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub type xmlCharEncodingInputFunc = crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub type xmlInputCloseCallback = crate::src::HTMLparser::xmlInputCloseCallback;
pub type xmlInputReadCallback = crate::src::HTMLparser::xmlInputReadCallback;
pub type xmlParserInputState = crate::src::HTMLparser::xmlParserInputState;
pub const XML_PARSER_PUBLIC_LITERAL: xmlParserInputState = 16;
pub const XML_PARSER_IGNORE: xmlParserInputState = 15;
pub const XML_PARSER_EPILOG: xmlParserInputState = 14;
pub const XML_PARSER_SYSTEM_LITERAL: xmlParserInputState = 13;
pub const XML_PARSER_ATTRIBUTE_VALUE: xmlParserInputState = 12;
pub const XML_PARSER_ENTITY_VALUE: xmlParserInputState = 11;
pub const XML_PARSER_ENTITY_DECL: xmlParserInputState = 10;
pub const XML_PARSER_END_TAG: xmlParserInputState = 9;
pub const XML_PARSER_CDATA_SECTION: xmlParserInputState = 8;
pub const XML_PARSER_CONTENT: xmlParserInputState = 7;
pub const XML_PARSER_START_TAG: xmlParserInputState = 6;
pub const XML_PARSER_COMMENT: xmlParserInputState = 5;
pub const XML_PARSER_PROLOG: xmlParserInputState = 4;
pub const XML_PARSER_DTD: xmlParserInputState = 3;
pub const XML_PARSER_PI: xmlParserInputState = 2;
pub const XML_PARSER_MISC: xmlParserInputState = 1;
pub const XML_PARSER_START: xmlParserInputState = 0;
pub const XML_PARSER_EOF: xmlParserInputState = -1;
pub type xmlValidCtxt = crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = crate::src::HTMLparser::xmlAutomataStatePtr;
pub type xmlAutomataState = crate::src::HTMLparser::xmlAutomataState;
pub type xmlAutomataPtr = crate::src::HTMLparser::xmlAutomataPtr;
pub type xmlAutomata = crate::src::HTMLparser::xmlAutomata;
pub type xmlValidState = crate::src::HTMLparser::xmlValidState;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlValidityWarningFunc = crate::src::HTMLparser::xmlValidityWarningFunc;
pub type xmlValidityErrorFunc = crate::src::HTMLparser::xmlValidityErrorFunc;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
pub type endElementNsSAX2Func = crate::src::HTMLparser::endElementNsSAX2Func;
pub type startElementNsSAX2Func = crate::src::HTMLparser::startElementNsSAX2Func;
pub type externalSubsetSAXFunc = crate::src::HTMLparser::externalSubsetSAXFunc;
pub type cdataBlockSAXFunc = crate::src::HTMLparser::cdataBlockSAXFunc;
pub type getParameterEntitySAXFunc = crate::src::HTMLparser::getParameterEntitySAXFunc;
pub type xmlEntityPtr = crate::src::HTMLparser::xmlEntityPtr;
pub type xmlEntity = crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = crate::src::HTMLparser::fatalErrorSAXFunc;
pub type errorSAXFunc = crate::src::HTMLparser::errorSAXFunc;
pub type warningSAXFunc = crate::src::HTMLparser::warningSAXFunc;
pub type commentSAXFunc = crate::src::HTMLparser::commentSAXFunc;
pub type processingInstructionSAXFunc = crate::src::HTMLparser::processingInstructionSAXFunc;
pub type ignorableWhitespaceSAXFunc = crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub type charactersSAXFunc = crate::src::HTMLparser::charactersSAXFunc;
pub type referenceSAXFunc = crate::src::HTMLparser::referenceSAXFunc;
pub type endElementSAXFunc = crate::src::HTMLparser::endElementSAXFunc;
pub type startElementSAXFunc = crate::src::HTMLparser::startElementSAXFunc;
pub type endDocumentSAXFunc = crate::src::HTMLparser::endDocumentSAXFunc;
pub type startDocumentSAXFunc = crate::src::HTMLparser::startDocumentSAXFunc;
pub type setDocumentLocatorSAXFunc = crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub type xmlSAXLocatorPtr = crate::src::HTMLparser::xmlSAXLocatorPtr;
pub type xmlSAXLocator = crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub type elementDeclSAXFunc = crate::src::HTMLparser::elementDeclSAXFunc;
pub type xmlElementContentPtr = crate::src::HTMLparser::xmlElementContentPtr;
pub type xmlElementContent = crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContentOccur = crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = crate::src::HTMLparser::attributeDeclSAXFunc;
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = crate::src::HTMLparser::notationDeclSAXFunc;
pub type entityDeclSAXFunc = crate::src::HTMLparser::entityDeclSAXFunc;
pub type getEntitySAXFunc = crate::src::HTMLparser::getEntitySAXFunc;
pub type resolveEntitySAXFunc = crate::src::HTMLparser::resolveEntitySAXFunc;
pub type hasExternalSubsetSAXFunc = crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub type hasInternalSubsetSAXFunc = crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub type isStandaloneSAXFunc = crate::src::HTMLparser::isStandaloneSAXFunc;
pub type internalSubsetSAXFunc = crate::src::HTMLparser::internalSubsetSAXFunc;
pub type xmlGenericErrorFunc = crate::src::HTMLparser::xmlGenericErrorFunc;
// #[derive(Copy, Clone)]

pub type timespec = crate::src::catalog::timespec;
// #[derive(Copy, Clone)]

pub type stat = crate::src::catalog::stat;
pub type ptrdiff_t = crate::src::HTMLparser::ptrdiff_t;
pub type Byte = crate::src::nanohttp::Byte;
pub type uInt = crate::src::nanohttp::uInt;
pub type uLong = crate::src::nanohttp::uLong;
pub type Bytef = crate::src::nanohttp::Bytef;
pub type voidpc = *const libc::c_void;
pub type voidpf = crate::src::nanohttp::voidpf;
pub type voidp = *mut libc::c_void;
pub type alloc_func = crate::src::nanohttp::alloc_func;
pub type free_func = crate::src::nanohttp::free_func;
// #[derive(Copy, Clone)]

pub type z_stream_s = crate::src::nanohttp::z_stream_s;
pub type z_stream = crate::src::nanohttp::z_stream;
pub type z_streamp = crate::src::nanohttp::z_streamp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct gzFile_s {
    pub have: u32,
    pub next: *mut u8,
    pub pos: off_t,
}
pub type gzFile = *mut gzFile_s;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
pub type xmlStrdupFunc = crate::src::encoding::xmlStrdupFunc;
// #[derive(Copy, Clone)]

pub type _xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = crate::src::HTMLtree::xmlOutputCloseCallback;
pub type xmlOutputWriteCallback = crate::src::HTMLtree::xmlOutputWriteCallback;
pub type xmlOutputBuffer = crate::src::HTMLtree::xmlOutputBuffer;
pub type xmlOutputBufferPtr = crate::src::HTMLtree::xmlOutputBufferPtr;
pub type xmlBufferAllocationScheme = crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub type _xmlBuffer = crate::src::HTMLtree::_xmlBuffer;
pub type xmlBuffer = crate::src::HTMLtree::xmlBuffer;
pub type xmlBufferPtr = crate::src::HTMLtree::xmlBufferPtr;
pub type C2RustUnnamed = u32;
pub const XML_FROM_URI: C2RustUnnamed = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed = 28;
pub const XML_FROM_I18N: C2RustUnnamed = 27;
pub const XML_FROM_MODULE: C2RustUnnamed = 26;
pub const XML_FROM_WRITER: C2RustUnnamed = 25;
pub const XML_FROM_CHECK: C2RustUnnamed = 24;
pub const XML_FROM_VALID: C2RustUnnamed = 23;
pub const XML_FROM_XSLT: C2RustUnnamed = 22;
pub const XML_FROM_C14N: C2RustUnnamed = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed = 13;
pub const XML_FROM_XPATH: C2RustUnnamed = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed = 11;
pub const XML_FROM_HTTP: C2RustUnnamed = 10;
pub const XML_FROM_FTP: C2RustUnnamed = 9;
pub const XML_FROM_OUTPUT: C2RustUnnamed = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed = 6;
pub const XML_FROM_HTML: C2RustUnnamed = 5;
pub const XML_FROM_DTD: C2RustUnnamed = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed = 3;
pub const XML_FROM_TREE: C2RustUnnamed = 2;
pub const XML_FROM_PARSER: C2RustUnnamed = 1;
pub const XML_FROM_NONE: C2RustUnnamed = 0;
pub type xmlParserErrors = crate::src::HTMLparser::xmlParserErrors;
pub const XML_BUF_OVERFLOW: xmlParserErrors = 7000;
pub const XML_I18N_NO_OUTPUT: xmlParserErrors = 6004;
pub const XML_I18N_CONV_FAILED: xmlParserErrors = 6003;
pub const XML_I18N_EXCESS_HANDLER: xmlParserErrors = 6002;
pub const XML_I18N_NO_HANDLER: xmlParserErrors = 6001;
pub const XML_I18N_NO_NAME: xmlParserErrors = 6000;
pub const XML_CHECK_NAME_NOT_NULL: xmlParserErrors = 5037;
pub const XML_CHECK_WRONG_NAME: xmlParserErrors = 5036;
pub const XML_CHECK_OUTSIDE_DICT: xmlParserErrors = 5035;
pub const XML_CHECK_NOT_NCNAME: xmlParserErrors = 5034;
pub const XML_CHECK_NO_DICT: xmlParserErrors = 5033;
pub const XML_CHECK_NOT_UTF8: xmlParserErrors = 5032;
pub const XML_CHECK_NS_ANCESTOR: xmlParserErrors = 5031;
pub const XML_CHECK_NS_SCOPE: xmlParserErrors = 5030;
pub const XML_CHECK_WRONG_PARENT: xmlParserErrors = 5029;
pub const XML_CHECK_NO_HREF: xmlParserErrors = 5028;
pub const XML_CHECK_NOT_NS_DECL: xmlParserErrors = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: xmlParserErrors = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: xmlParserErrors = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: xmlParserErrors = 5024;
pub const XML_CHECK_NOT_ATTR: xmlParserErrors = 5023;
pub const XML_CHECK_NOT_DTD: xmlParserErrors = 5022;
pub const XML_CHECK_WRONG_NEXT: xmlParserErrors = 5021;
pub const XML_CHECK_NO_NEXT: xmlParserErrors = 5020;
pub const XML_CHECK_WRONG_PREV: xmlParserErrors = 5019;
pub const XML_CHECK_NO_PREV: xmlParserErrors = 5018;
pub const XML_CHECK_WRONG_DOC: xmlParserErrors = 5017;
pub const XML_CHECK_NO_ELEM: xmlParserErrors = 5016;
pub const XML_CHECK_NO_NAME: xmlParserErrors = 5015;
pub const XML_CHECK_NO_DOC: xmlParserErrors = 5014;
pub const XML_CHECK_NO_PARENT: xmlParserErrors = 5013;
pub const XML_CHECK_ENTITY_TYPE: xmlParserErrors = 5012;
pub const XML_CHECK_UNKNOWN_NODE: xmlParserErrors = 5011;
pub const XML_CHECK_FOUND_NOTATION: xmlParserErrors = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: xmlParserErrors = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: xmlParserErrors = 5008;
pub const XML_CHECK_FOUND_COMMENT: xmlParserErrors = 5007;
pub const XML_CHECK_FOUND_PI: xmlParserErrors = 5006;
pub const XML_CHECK_FOUND_ENTITY: xmlParserErrors = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: xmlParserErrors = 5004;
pub const XML_CHECK_FOUND_CDATA: xmlParserErrors = 5003;
pub const XML_CHECK_FOUND_TEXT: xmlParserErrors = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: xmlParserErrors = 5001;
pub const XML_CHECK_FOUND_ELEMENT: xmlParserErrors = 5000;
pub const XML_MODULE_CLOSE: xmlParserErrors = 4901;
pub const XML_MODULE_OPEN: xmlParserErrors = 4900;
pub const XML_SCHEMATRONV_REPORT: xmlParserErrors = 4001;
pub const XML_SCHEMATRONV_ASSERT: xmlParserErrors = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: xmlParserErrors = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: xmlParserErrors = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: xmlParserErrors = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: xmlParserErrors = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: xmlParserErrors = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: xmlParserErrors = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: xmlParserErrors = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: xmlParserErrors = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: xmlParserErrors = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: xmlParserErrors = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: xmlParserErrors = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: xmlParserErrors = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: xmlParserErrors = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: xmlParserErrors = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: xmlParserErrors = 3077;
pub const XML_SCHEMAP_SRC_CT_1: xmlParserErrors = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: xmlParserErrors = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: xmlParserErrors = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: xmlParserErrors = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: xmlParserErrors = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: xmlParserErrors = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: xmlParserErrors = 3070;
pub const XML_SCHEMAP_INTERNAL: xmlParserErrors = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: xmlParserErrors = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: xmlParserErrors = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: xmlParserErrors = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: xmlParserErrors = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: xmlParserErrors = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: xmlParserErrors = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: xmlParserErrors = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: xmlParserErrors = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: xmlParserErrors = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: xmlParserErrors = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: xmlParserErrors = 3058;
pub const XML_SCHEMAP_NO_XSI: xmlParserErrors = 3057;
pub const XML_SCHEMAP_NO_XMLNS: xmlParserErrors = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: xmlParserErrors = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: xmlParserErrors = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: xmlParserErrors = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: xmlParserErrors = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: xmlParserErrors = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: xmlParserErrors = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: xmlParserErrors = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: xmlParserErrors = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: xmlParserErrors = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: xmlParserErrors = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: xmlParserErrors = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: xmlParserErrors = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: xmlParserErrors = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: xmlParserErrors = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: xmlParserErrors = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: xmlParserErrors = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: xmlParserErrors = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: xmlParserErrors = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: xmlParserErrors = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: xmlParserErrors = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: xmlParserErrors = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: xmlParserErrors = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: xmlParserErrors = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: xmlParserErrors = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: xmlParserErrors = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: xmlParserErrors = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: xmlParserErrors = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: xmlParserErrors = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: xmlParserErrors = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: xmlParserErrors = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: xmlParserErrors = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: xmlParserErrors = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: xmlParserErrors = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: xmlParserErrors = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: xmlParserErrors = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: xmlParserErrors = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: xmlParserErrors = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: xmlParserErrors = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: xmlParserErrors = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: xmlParserErrors = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: xmlParserErrors = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: xmlParserErrors = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: xmlParserErrors = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: xmlParserErrors = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: xmlParserErrors = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: xmlParserErrors = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: xmlParserErrors = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: xmlParserErrors = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: xmlParserErrors = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: xmlParserErrors = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: xmlParserErrors = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: xmlParserErrors = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: xmlParserErrors = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: xmlParserErrors = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: xmlParserErrors = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: xmlParserErrors = 3000;
pub const XML_HTTP_UNKNOWN_HOST: xmlParserErrors = 2022;
pub const XML_HTTP_USE_IP: xmlParserErrors = 2021;
pub const XML_HTTP_URL_SYNTAX: xmlParserErrors = 2020;
pub const XML_FTP_URL_SYNTAX: xmlParserErrors = 2003;
pub const XML_FTP_ACCNT: xmlParserErrors = 2002;
pub const XML_FTP_EPSV_ANSWER: xmlParserErrors = 2001;
pub const XML_FTP_PASV_ANSWER: xmlParserErrors = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: xmlParserErrors = 1955;
pub const XML_C14N_UNKNOW_NODE: xmlParserErrors = 1954;
pub const XML_C14N_INVALID_NODE: xmlParserErrors = 1953;
pub const XML_C14N_CREATE_STACK: xmlParserErrors = 1952;
pub const XML_C14N_REQUIRES_UTF8: xmlParserErrors = 1951;
pub const XML_C14N_CREATE_CTXT: xmlParserErrors = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: xmlParserErrors = 1903;
pub const XML_XPTR_EVAL_FAILED: xmlParserErrors = 1902;
pub const XML_XPTR_CHILDSEQ_START: xmlParserErrors = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: xmlParserErrors = 1900;
pub const XML_SCHEMAV_MISC: xmlParserErrors = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: xmlParserErrors = 1878;
pub const XML_SCHEMAV_CVC_IDC: xmlParserErrors = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: xmlParserErrors = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: xmlParserErrors = 1875;
pub const XML_SCHEMAV_CVC_AU: xmlParserErrors = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: xmlParserErrors = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: xmlParserErrors = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: xmlParserErrors = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: xmlParserErrors = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: xmlParserErrors = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: xmlParserErrors = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: xmlParserErrors = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: xmlParserErrors = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: xmlParserErrors = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: xmlParserErrors = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: xmlParserErrors = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: xmlParserErrors = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: xmlParserErrors = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: xmlParserErrors = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: xmlParserErrors = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: xmlParserErrors = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: xmlParserErrors = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: xmlParserErrors = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: xmlParserErrors = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: xmlParserErrors = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: xmlParserErrors = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: xmlParserErrors = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: xmlParserErrors = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: xmlParserErrors = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: xmlParserErrors = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: xmlParserErrors = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: xmlParserErrors = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: xmlParserErrors = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: xmlParserErrors = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: xmlParserErrors = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: xmlParserErrors = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: xmlParserErrors = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: xmlParserErrors = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: xmlParserErrors = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: xmlParserErrors = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: xmlParserErrors = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: xmlParserErrors = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: xmlParserErrors = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: xmlParserErrors = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: xmlParserErrors = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: xmlParserErrors = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: xmlParserErrors = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: xmlParserErrors = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: xmlParserErrors = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: xmlParserErrors = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: xmlParserErrors = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: xmlParserErrors = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: xmlParserErrors = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: xmlParserErrors = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: xmlParserErrors = 1824;
pub const XML_SCHEMAV_FACET: xmlParserErrors = 1823;
pub const XML_SCHEMAV_VALUE: xmlParserErrors = 1822;
pub const XML_SCHEMAV_ATTRINVALID: xmlParserErrors = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: xmlParserErrors = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: xmlParserErrors = 1819;
pub const XML_SCHEMAV_INTERNAL: xmlParserErrors = 1818;
pub const XML_SCHEMAV_CONSTRUCT: xmlParserErrors = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: xmlParserErrors = 1816;
pub const XML_SCHEMAV_INVALIDELEM: xmlParserErrors = 1815;
pub const XML_SCHEMAV_INVALIDATTR: xmlParserErrors = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: xmlParserErrors = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: xmlParserErrors = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: xmlParserErrors = 1811;
pub const XML_SCHEMAV_ELEMCONT: xmlParserErrors = 1810;
pub const XML_SCHEMAV_NOTEMPTY: xmlParserErrors = 1809;
pub const XML_SCHEMAV_ISABSTRACT: xmlParserErrors = 1808;
pub const XML_SCHEMAV_NOROLLBACK: xmlParserErrors = 1807;
pub const XML_SCHEMAV_NOTYPE: xmlParserErrors = 1806;
pub const XML_SCHEMAV_WRONGELEM: xmlParserErrors = 1805;
pub const XML_SCHEMAV_MISSING: xmlParserErrors = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: xmlParserErrors = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: xmlParserErrors = 1802;
pub const XML_SCHEMAV_NOROOT: xmlParserErrors = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: xmlParserErrors = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: xmlParserErrors = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: xmlParserErrors = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: xmlParserErrors = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: xmlParserErrors = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: xmlParserErrors = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: xmlParserErrors = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: xmlParserErrors = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: xmlParserErrors = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: xmlParserErrors = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: xmlParserErrors = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: xmlParserErrors = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: xmlParserErrors = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: xmlParserErrors = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: xmlParserErrors = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: xmlParserErrors = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: xmlParserErrors = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: xmlParserErrors = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: xmlParserErrors = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: xmlParserErrors = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: xmlParserErrors = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: xmlParserErrors = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: xmlParserErrors = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: xmlParserErrors = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: xmlParserErrors = 1776;
pub const XML_SCHEMAP_RECURSIVE: xmlParserErrors = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: xmlParserErrors = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: xmlParserErrors = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: xmlParserErrors = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: xmlParserErrors = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: xmlParserErrors = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: xmlParserErrors = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: xmlParserErrors = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: xmlParserErrors = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: xmlParserErrors = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: xmlParserErrors = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: xmlParserErrors = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: xmlParserErrors = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: xmlParserErrors = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: xmlParserErrors = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: xmlParserErrors = 1760;
pub const XML_SCHEMAP_NOROOT: xmlParserErrors = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: xmlParserErrors = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: xmlParserErrors = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: xmlParserErrors = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: xmlParserErrors = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: xmlParserErrors = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: xmlParserErrors = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: xmlParserErrors = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: xmlParserErrors = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: xmlParserErrors = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: xmlParserErrors = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: xmlParserErrors = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: xmlParserErrors = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: xmlParserErrors = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: xmlParserErrors = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: xmlParserErrors = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: xmlParserErrors = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: xmlParserErrors = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: xmlParserErrors = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: xmlParserErrors = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: xmlParserErrors = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: xmlParserErrors = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: xmlParserErrors = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: xmlParserErrors = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: xmlParserErrors = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: xmlParserErrors = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: xmlParserErrors = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: xmlParserErrors = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: xmlParserErrors = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: xmlParserErrors = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: xmlParserErrors = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: xmlParserErrors = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: xmlParserErrors = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: xmlParserErrors = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: xmlParserErrors = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: xmlParserErrors = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: xmlParserErrors = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: xmlParserErrors = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: xmlParserErrors = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: xmlParserErrors = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: xmlParserErrors = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: xmlParserErrors = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: xmlParserErrors = 1717;
pub const XML_SCHEMAP_INVALID_FACET: xmlParserErrors = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: xmlParserErrors = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: xmlParserErrors = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: xmlParserErrors = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: xmlParserErrors = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: xmlParserErrors = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: xmlParserErrors = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: xmlParserErrors = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: xmlParserErrors = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: xmlParserErrors = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: xmlParserErrors = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: xmlParserErrors = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: xmlParserErrors = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: xmlParserErrors = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: xmlParserErrors = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: xmlParserErrors = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: xmlParserErrors = 1700;
pub const XML_CATALOG_RECURSION: xmlParserErrors = 1654;
pub const XML_CATALOG_NOT_CATALOG: xmlParserErrors = 1653;
pub const XML_CATALOG_PREFER_VALUE: xmlParserErrors = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: xmlParserErrors = 1651;
pub const XML_CATALOG_MISSING_ATTR: xmlParserErrors = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: xmlParserErrors = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: xmlParserErrors = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: xmlParserErrors = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: xmlParserErrors = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: xmlParserErrors = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: xmlParserErrors = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: xmlParserErrors = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: xmlParserErrors = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: xmlParserErrors = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: xmlParserErrors = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: xmlParserErrors = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: xmlParserErrors = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: xmlParserErrors = 1606;
pub const XML_XINCLUDE_HREF_URI: xmlParserErrors = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: xmlParserErrors = 1604;
pub const XML_XINCLUDE_NO_HREF: xmlParserErrors = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: xmlParserErrors = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: xmlParserErrors = 1601;
pub const XML_XINCLUDE_RECURSION: xmlParserErrors = 1600;
pub const XML_IO_BUFFER_FULL: xmlParserErrors = 1548;
pub const XML_IO_NO_INPUT: xmlParserErrors = 1547;
pub const XML_IO_WRITE: xmlParserErrors = 1546;
pub const XML_IO_FLUSH: xmlParserErrors = 1545;
pub const XML_IO_ENCODER: xmlParserErrors = 1544;
pub const XML_IO_NETWORK_ATTEMPT: xmlParserErrors = 1543;
pub const XML_REGEXP_COMPILE_ERROR: xmlParserErrors = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: xmlParserErrors = 1403;
pub const XML_SAVE_NO_DOCTYPE: xmlParserErrors = 1402;
pub const XML_SAVE_CHAR_INVALID: xmlParserErrors = 1401;
pub const XML_SAVE_NOT_UTF8: xmlParserErrors = 1400;
pub const XML_TREE_NOT_UTF8: xmlParserErrors = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: xmlParserErrors = 1302;
pub const XML_TREE_INVALID_DEC: xmlParserErrors = 1301;
pub const XML_TREE_INVALID_HEX: xmlParserErrors = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: xmlParserErrors = 1221;
pub const XML_XPATH_ENCODING_ERROR: xmlParserErrors = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: xmlParserErrors = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: xmlParserErrors = 1218;
pub const XML_XPTR_RESOURCE_ERROR: xmlParserErrors = 1217;
pub const XML_XPTR_SYNTAX_ERROR: xmlParserErrors = 1216;
pub const XML_XPATH_MEMORY_ERROR: xmlParserErrors = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: xmlParserErrors = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: xmlParserErrors = 1213;
pub const XML_XPATH_INVALID_ARITY: xmlParserErrors = 1212;
pub const XML_XPATH_INVALID_TYPE: xmlParserErrors = 1211;
pub const XML_XPATH_INVALID_OPERAND: xmlParserErrors = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: xmlParserErrors = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: xmlParserErrors = 1208;
pub const XML_XPATH_EXPR_ERROR: xmlParserErrors = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: xmlParserErrors = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: xmlParserErrors = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: xmlParserErrors = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: xmlParserErrors = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: xmlParserErrors = 1202;
pub const XML_XPATH_NUMBER_ERROR: xmlParserErrors = 1201;
pub const XML_XPATH_EXPRESSION_OK: xmlParserErrors = 1200;
pub const XML_RNGP_XML_NS: xmlParserErrors = 1122;
pub const XML_RNGP_XMLNS_NAME: xmlParserErrors = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: xmlParserErrors = 1120;
pub const XML_RNGP_VALUE_EMPTY: xmlParserErrors = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: xmlParserErrors = 1118;
pub const XML_RNGP_URI_FRAGMENT: xmlParserErrors = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: xmlParserErrors = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: xmlParserErrors = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: xmlParserErrors = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: xmlParserErrors = 1113;
pub const XML_RNGP_TYPE_VALUE: xmlParserErrors = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: xmlParserErrors = 1111;
pub const XML_RNGP_TYPE_MISSING: xmlParserErrors = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: xmlParserErrors = 1109;
pub const XML_RNGP_TEXT_EXPECTED: xmlParserErrors = 1108;
pub const XML_RNGP_START_MISSING: xmlParserErrors = 1107;
pub const XML_RNGP_START_EMPTY: xmlParserErrors = 1106;
pub const XML_RNGP_START_CONTENT: xmlParserErrors = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: xmlParserErrors = 1103;
pub const XML_RNGP_REF_NO_NAME: xmlParserErrors = 1102;
pub const XML_RNGP_REF_NO_DEF: xmlParserErrors = 1101;
pub const XML_RNGP_REF_NAME_INVALID: xmlParserErrors = 1100;
pub const XML_RNGP_REF_CYCLE: xmlParserErrors = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: xmlParserErrors = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: xmlParserErrors = 1097;
pub const XML_RNGP_PAT_START_VALUE: xmlParserErrors = 1096;
pub const XML_RNGP_PAT_START_TEXT: xmlParserErrors = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: xmlParserErrors = 1094;
pub const XML_RNGP_PAT_START_LIST: xmlParserErrors = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: xmlParserErrors = 1092;
pub const XML_RNGP_PAT_START_GROUP: xmlParserErrors = 1091;
pub const XML_RNGP_PAT_START_EMPTY: xmlParserErrors = 1090;
pub const XML_RNGP_PAT_START_DATA: xmlParserErrors = 1089;
pub const XML_RNGP_PAT_START_ATTR: xmlParserErrors = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: xmlParserErrors = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: xmlParserErrors = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: xmlParserErrors = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: xmlParserErrors = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: xmlParserErrors = 1083;
pub const XML_RNGP_PAT_LIST_REF: xmlParserErrors = 1082;
pub const XML_RNGP_PAT_LIST_LIST: xmlParserErrors = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: xmlParserErrors = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: xmlParserErrors = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: xmlParserErrors = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: xmlParserErrors = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: xmlParserErrors = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: xmlParserErrors = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: xmlParserErrors = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: xmlParserErrors = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: xmlParserErrors = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: xmlParserErrors = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: xmlParserErrors = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: xmlParserErrors = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: xmlParserErrors = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: xmlParserErrors = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: xmlParserErrors = 1066;
pub const XML_RNGP_PARSE_ERROR: xmlParserErrors = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: xmlParserErrors = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: xmlParserErrors = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: xmlParserErrors = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: xmlParserErrors = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: xmlParserErrors = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: xmlParserErrors = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: xmlParserErrors = 1058;
pub const XML_RNGP_NSNAME_NO_NS: xmlParserErrors = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: xmlParserErrors = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: xmlParserErrors = 1055;
pub const XML_RNGP_NEED_COMBINE: xmlParserErrors = 1054;
pub const XML_RNGP_NAME_MISSING: xmlParserErrors = 1053;
pub const XML_RNGP_MISSING_HREF: xmlParserErrors = 1052;
pub const XML_RNGP_INVALID_VALUE: xmlParserErrors = 1051;
pub const XML_RNGP_INVALID_URI: xmlParserErrors = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: xmlParserErrors = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: xmlParserErrors = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: xmlParserErrors = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: xmlParserErrors = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: xmlParserErrors = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: xmlParserErrors = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: xmlParserErrors = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: xmlParserErrors = 1042;
pub const XML_RNGP_HREF_ERROR: xmlParserErrors = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: xmlParserErrors = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: xmlParserErrors = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: xmlParserErrors = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: xmlParserErrors = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: xmlParserErrors = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: xmlParserErrors = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: xmlParserErrors = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: xmlParserErrors = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: xmlParserErrors = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: xmlParserErrors = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: xmlParserErrors = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: xmlParserErrors = 1029;
pub const XML_RNGP_EXCEPT_MISSING: xmlParserErrors = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: xmlParserErrors = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: xmlParserErrors = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: xmlParserErrors = 1025;
pub const XML_RNGP_EMPTY_CONTENT: xmlParserErrors = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: xmlParserErrors = 1023;
pub const XML_RNGP_EMPTY: xmlParserErrors = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: xmlParserErrors = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: xmlParserErrors = 1020;
pub const XML_RNGP_ELEMENT_NAME: xmlParserErrors = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: xmlParserErrors = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: xmlParserErrors = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: xmlParserErrors = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: xmlParserErrors = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: xmlParserErrors = 1014;
pub const XML_RNGP_DEFINE_MISSING: xmlParserErrors = 1013;
pub const XML_RNGP_DEFINE_EMPTY: xmlParserErrors = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: xmlParserErrors = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1010;
pub const XML_RNGP_DATA_CONTENT: xmlParserErrors = 1009;
pub const XML_RNGP_CREATE_FAILURE: xmlParserErrors = 1008;
pub const XML_RNGP_CHOICE_EMPTY: xmlParserErrors = 1007;
pub const XML_RNGP_CHOICE_CONTENT: xmlParserErrors = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: xmlParserErrors = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: xmlParserErrors = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: xmlParserErrors = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: xmlParserErrors = 1002;
pub const XML_RNGP_ATTR_CONFLICT: xmlParserErrors = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: xmlParserErrors = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: xmlParserErrors = 802;
pub const XML_HTML_UNKNOWN_TAG: xmlParserErrors = 801;
pub const XML_HTML_STRUCURE_ERROR: xmlParserErrors = 800;
pub const XML_DTD_DUP_TOKEN: xmlParserErrors = 541;
pub const XML_DTD_XMLID_TYPE: xmlParserErrors = 540;
pub const XML_DTD_XMLID_VALUE: xmlParserErrors = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: xmlParserErrors = 538;
pub const XML_DTD_UNKNOWN_NOTATION: xmlParserErrors = 537;
pub const XML_DTD_UNKNOWN_ID: xmlParserErrors = 536;
pub const XML_DTD_UNKNOWN_ENTITY: xmlParserErrors = 535;
pub const XML_DTD_UNKNOWN_ELEM: xmlParserErrors = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: xmlParserErrors = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: xmlParserErrors = 532;
pub const XML_DTD_ROOT_NAME: xmlParserErrors = 531;
pub const XML_DTD_NOT_STANDALONE: xmlParserErrors = 530;
pub const XML_DTD_NOT_PCDATA: xmlParserErrors = 529;
pub const XML_DTD_NOT_EMPTY: xmlParserErrors = 528;
pub const XML_DTD_NOTATION_VALUE: xmlParserErrors = 527;
pub const XML_DTD_NOTATION_REDEFINED: xmlParserErrors = 526;
pub const XML_DTD_NO_ROOT: xmlParserErrors = 525;
pub const XML_DTD_NO_PREFIX: xmlParserErrors = 524;
pub const XML_DTD_NO_ELEM_NAME: xmlParserErrors = 523;
pub const XML_DTD_NO_DTD: xmlParserErrors = 522;
pub const XML_DTD_NO_DOC: xmlParserErrors = 521;
pub const XML_DTD_MULTIPLE_ID: xmlParserErrors = 520;
pub const XML_DTD_MIXED_CORRUPT: xmlParserErrors = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: xmlParserErrors = 518;
pub const XML_DTD_LOAD_ERROR: xmlParserErrors = 517;
pub const XML_DTD_INVALID_DEFAULT: xmlParserErrors = 516;
pub const XML_DTD_INVALID_CHILD: xmlParserErrors = 515;
pub const XML_DTD_ID_SUBSET: xmlParserErrors = 514;
pub const XML_DTD_ID_REDEFINED: xmlParserErrors = 513;
pub const XML_DTD_ID_FIXED: xmlParserErrors = 512;
pub const XML_DTD_ENTITY_TYPE: xmlParserErrors = 511;
pub const XML_DTD_EMPTY_NOTATION: xmlParserErrors = 510;
pub const XML_DTD_ELEM_REDEFINED: xmlParserErrors = 509;
pub const XML_DTD_ELEM_NAMESPACE: xmlParserErrors = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: xmlParserErrors = 507;
pub const XML_DTD_DIFFERENT_PREFIX: xmlParserErrors = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: xmlParserErrors = 505;
pub const XML_DTD_CONTENT_MODEL: xmlParserErrors = 504;
pub const XML_DTD_CONTENT_ERROR: xmlParserErrors = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: xmlParserErrors = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: xmlParserErrors = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: xmlParserErrors = 500;
pub const XML_NS_ERR_COLON: xmlParserErrors = 205;
pub const XML_NS_ERR_EMPTY: xmlParserErrors = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 203;
pub const XML_NS_ERR_QNAME: xmlParserErrors = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: xmlParserErrors = 201;
pub const XML_NS_ERR_XML_NAMESPACE: xmlParserErrors = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: xmlParserErrors = 112;
pub const XML_ERR_USER_STOP: xmlParserErrors = 111;
pub const XML_ERR_NAME_TOO_LONG: xmlParserErrors = 110;
pub const XML_ERR_VERSION_MISMATCH: xmlParserErrors = 109;
pub const XML_ERR_UNKNOWN_VERSION: xmlParserErrors = 108;
pub const XML_WAR_ENTITY_REDEFINED: xmlParserErrors = 107;
pub const XML_WAR_NS_COLUMN: xmlParserErrors = 106;
pub const XML_ERR_NOTATION_PROCESSING: xmlParserErrors = 105;
pub const XML_ERR_ENTITY_PROCESSING: xmlParserErrors = 104;
pub const XML_ERR_NOT_STANDALONE: xmlParserErrors = 103;
pub const XML_WAR_SPACE_VALUE: xmlParserErrors = 102;
pub const XML_ERR_MISSING_ENCODING: xmlParserErrors = 101;
pub const XML_WAR_NS_URI_RELATIVE: xmlParserErrors = 100;
pub const XML_WAR_NS_URI: xmlParserErrors = 99;
pub const XML_WAR_LANG_VALUE: xmlParserErrors = 98;
pub const XML_WAR_UNKNOWN_VERSION: xmlParserErrors = 97;
pub const XML_ERR_VERSION_MISSING: xmlParserErrors = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: xmlParserErrors = 95;
pub const XML_ERR_NO_DTD: xmlParserErrors = 94;
pub const XML_WAR_CATALOG_PI: xmlParserErrors = 93;
pub const XML_ERR_URI_FRAGMENT: xmlParserErrors = 92;
pub const XML_ERR_INVALID_URI: xmlParserErrors = 91;
pub const XML_ERR_ENTITY_BOUNDARY: xmlParserErrors = 90;
pub const XML_ERR_ENTITY_LOOP: xmlParserErrors = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: xmlParserErrors = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: xmlParserErrors = 87;
pub const XML_ERR_EXTRA_CONTENT: xmlParserErrors = 86;
pub const XML_ERR_NOT_WELL_BALANCED: xmlParserErrors = 85;
pub const XML_ERR_VALUE_REQUIRED: xmlParserErrors = 84;
pub const XML_ERR_CONDSEC_INVALID: xmlParserErrors = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: xmlParserErrors = 82;
pub const XML_ERR_INVALID_ENCODING: xmlParserErrors = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: xmlParserErrors = 80;
pub const XML_ERR_ENCODING_NAME: xmlParserErrors = 79;
pub const XML_ERR_STANDALONE_VALUE: xmlParserErrors = 78;
pub const XML_ERR_TAG_NOT_FINISHED: xmlParserErrors = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: xmlParserErrors = 76;
pub const XML_ERR_EQUAL_REQUIRED: xmlParserErrors = 75;
pub const XML_ERR_LTSLASH_REQUIRED: xmlParserErrors = 74;
pub const XML_ERR_GT_REQUIRED: xmlParserErrors = 73;
pub const XML_ERR_LT_REQUIRED: xmlParserErrors = 72;
pub const XML_ERR_PUBID_REQUIRED: xmlParserErrors = 71;
pub const XML_ERR_URI_REQUIRED: xmlParserErrors = 70;
pub const XML_ERR_PCDATA_REQUIRED: xmlParserErrors = 69;
pub const XML_ERR_NAME_REQUIRED: xmlParserErrors = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: xmlParserErrors = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: xmlParserErrors = 66;
pub const XML_ERR_SPACE_REQUIRED: xmlParserErrors = 65;
pub const XML_ERR_RESERVED_XML_NAME: xmlParserErrors = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: xmlParserErrors = 63;
pub const XML_ERR_MISPLACED_CDATA_END: xmlParserErrors = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: xmlParserErrors = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: xmlParserErrors = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: xmlParserErrors = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: xmlParserErrors = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: xmlParserErrors = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: xmlParserErrors = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: xmlParserErrors = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: xmlParserErrors = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: xmlParserErrors = 53;
pub const XML_ERR_MIXED_NOT_STARTED: xmlParserErrors = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: xmlParserErrors = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: xmlParserErrors = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: xmlParserErrors = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: xmlParserErrors = 48;
pub const XML_ERR_PI_NOT_FINISHED: xmlParserErrors = 47;
pub const XML_ERR_PI_NOT_STARTED: xmlParserErrors = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: xmlParserErrors = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: xmlParserErrors = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: xmlParserErrors = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: xmlParserErrors = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: xmlParserErrors = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: xmlParserErrors = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: xmlParserErrors = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: xmlParserErrors = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: xmlParserErrors = 36;
pub const XML_ERR_NS_DECL_ERROR: xmlParserErrors = 35;
pub const XML_ERR_STRING_NOT_CLOSED: xmlParserErrors = 34;
pub const XML_ERR_STRING_NOT_STARTED: xmlParserErrors = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: xmlParserErrors = 32;
pub const XML_ERR_UNKNOWN_ENCODING: xmlParserErrors = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: xmlParserErrors = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: xmlParserErrors = 29;
pub const XML_ERR_UNPARSED_ENTITY: xmlParserErrors = 28;
pub const XML_WAR_UNDECLARED_ENTITY: xmlParserErrors = 27;
pub const XML_ERR_UNDECLARED_ENTITY: xmlParserErrors = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: xmlParserErrors = 25;
pub const XML_ERR_PEREF_NO_NAME: xmlParserErrors = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: xmlParserErrors = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: xmlParserErrors = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: xmlParserErrors = 21;
pub const XML_ERR_PEREF_IN_EPILOG: xmlParserErrors = 20;
pub const XML_ERR_PEREF_IN_PROLOG: xmlParserErrors = 19;
pub const XML_ERR_PEREF_AT_EOF: xmlParserErrors = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: xmlParserErrors = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: xmlParserErrors = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: xmlParserErrors = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: xmlParserErrors = 14;
pub const XML_ERR_CHARREF_IN_DTD: xmlParserErrors = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: xmlParserErrors = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: xmlParserErrors = 11;
pub const XML_ERR_CHARREF_AT_EOF: xmlParserErrors = 10;
pub const XML_ERR_INVALID_CHAR: xmlParserErrors = 9;
pub const XML_ERR_INVALID_CHARREF: xmlParserErrors = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: xmlParserErrors = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: xmlParserErrors = 6;
pub const XML_ERR_DOCUMENT_END: xmlParserErrors = 5;
pub const XML_ERR_DOCUMENT_EMPTY: xmlParserErrors = 4;
pub const XML_ERR_DOCUMENT_START: xmlParserErrors = 3;
pub const XML_ERR_NO_MEMORY: xmlParserErrors = 2;
pub const XML_ERR_INTERNAL_ERROR: xmlParserErrors = 1;
pub const XML_ERR_OK: xmlParserErrors = 0;
pub type xmlExternalEntityLoader = crate::src::python::libxml::xmlExternalEntityLoader;
pub type xmlCharEncoding = crate::src::HTMLparser::xmlCharEncoding;
pub const XML_CHAR_ENCODING_ASCII: xmlCharEncoding = 22;
pub const XML_CHAR_ENCODING_EUC_JP: xmlCharEncoding = 21;
pub const XML_CHAR_ENCODING_SHIFT_JIS: xmlCharEncoding = 20;
pub const XML_CHAR_ENCODING_2022_JP: xmlCharEncoding = 19;
pub const XML_CHAR_ENCODING_8859_9: xmlCharEncoding = 18;
pub const XML_CHAR_ENCODING_8859_8: xmlCharEncoding = 17;
pub const XML_CHAR_ENCODING_8859_7: xmlCharEncoding = 16;
pub const XML_CHAR_ENCODING_8859_6: xmlCharEncoding = 15;
pub const XML_CHAR_ENCODING_8859_5: xmlCharEncoding = 14;
pub const XML_CHAR_ENCODING_8859_4: xmlCharEncoding = 13;
pub const XML_CHAR_ENCODING_8859_3: xmlCharEncoding = 12;
pub const XML_CHAR_ENCODING_8859_2: xmlCharEncoding = 11;
pub const XML_CHAR_ENCODING_8859_1: xmlCharEncoding = 10;
pub const XML_CHAR_ENCODING_UCS2: xmlCharEncoding = 9;
pub const XML_CHAR_ENCODING_UCS4_3412: xmlCharEncoding = 8;
pub const XML_CHAR_ENCODING_UCS4_2143: xmlCharEncoding = 7;
pub const XML_CHAR_ENCODING_EBCDIC: xmlCharEncoding = 6;
pub const XML_CHAR_ENCODING_UCS4BE: xmlCharEncoding = 5;
pub const XML_CHAR_ENCODING_UCS4LE: xmlCharEncoding = 4;
pub const XML_CHAR_ENCODING_UTF16BE: xmlCharEncoding = 3;
pub const XML_CHAR_ENCODING_UTF16LE: xmlCharEncoding = 2;
pub const XML_CHAR_ENCODING_UTF8: xmlCharEncoding = 1;
pub const XML_CHAR_ENCODING_NONE: xmlCharEncoding = 0;
pub const XML_CHAR_ENCODING_ERROR: xmlCharEncoding = -1;
pub type xmlInputMatchCallback = crate::src::python::libxml::xmlInputMatchCallback;
pub type xmlInputOpenCallback = crate::src::python::libxml::xmlInputOpenCallback;
pub type xmlOutputMatchCallback = Option::<
    unsafe extern "C" fn(*const i8) -> i32,
>;
pub type xmlOutputOpenCallback = Option::<
    unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
>;
pub type xmlInputCallback = _xmlInputCallback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlInputCallback {
    pub matchcallback: xmlInputMatchCallback,
    pub opencallback: xmlInputOpenCallback,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
}
pub type xmlParserInputBufferCreateFilenameFunc = crate::src::globals::xmlParserInputBufferCreateFilenameFunc;
pub type xmlOutputCallback = _xmlOutputCallback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlOutputCallback {
    pub matchcallback: xmlOutputMatchCallback,
    pub opencallback: xmlOutputOpenCallback,
    pub writecallback: xmlOutputWriteCallback,
    pub closecallback: xmlOutputCloseCallback,
}
pub type xmlIOHTTPWriteCtxtPtr = *mut xmlIOHTTPWriteCtxt_;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlIOHTTPWriteCtxt_ {
    pub compression: i32,
    pub uri: *mut i8,
    pub doc_buff: *mut libc::c_void,
}
pub type xmlZMemBuffPtr = *mut xmlZMemBuff_;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlZMemBuff_ {
    pub size: u64,
    pub crc: u64,
    pub zbuff: *mut u8,
    pub zctrl: z_stream,
}
pub type xmlZMemBuff = xmlZMemBuff_;
pub type xmlIOHTTPWriteCtxt = xmlIOHTTPWriteCtxt_;
pub type xmlURIPtr = crate::src::SAX2::xmlURIPtr;
pub type xmlURI = crate::src::SAX2::xmlURI;
// #[derive(Copy, Clone)]

pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlOutputBufferCreateFilenameFunc = crate::src::globals::xmlOutputBufferCreateFilenameFunc;
pub const XML_CATA_ALLOW_GLOBAL: xmlCatalogAllow = 1;
pub type xmlCatalogAllow = crate::src::catalog::xmlCatalogAllow;
pub const XML_CATA_ALLOW_ALL: xmlCatalogAllow = 3;
pub const XML_CATA_ALLOW_DOCUMENT: xmlCatalogAllow = 2;
pub const XML_CATA_ALLOW_NONE: xmlCatalogAllow = 0;
pub const XML_PARSE_NONET: C2RustUnnamed_0 = 2048;
pub type C2RustUnnamed_0 = u32;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed_0 = 4194304;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed_0 = 2097152;
pub const XML_PARSE_OLDSAX: C2RustUnnamed_0 = 1048576;
pub const XML_PARSE_HUGE: C2RustUnnamed_0 = 524288;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed_0 = 262144;
pub const XML_PARSE_OLD10: C2RustUnnamed_0 = 131072;
pub const XML_PARSE_COMPACT: C2RustUnnamed_0 = 65536;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed_0 = 32768;
pub const XML_PARSE_NOCDATA: C2RustUnnamed_0 = 16384;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_0 = 8192;
pub const XML_PARSE_NODICT: C2RustUnnamed_0 = 4096;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed_0 = 1024;
pub const XML_PARSE_SAX1: C2RustUnnamed_0 = 512;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_0 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_0 = 128;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_0 = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed_0 = 32;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_0 = 16;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_0 = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_0 = 4;
pub const XML_PARSE_NOENT: C2RustUnnamed_0 = 2;
pub const XML_PARSE_RECOVER: C2RustUnnamed_0 = 1;
#[inline]
unsafe extern "C" fn stat(
    mut __path: *const i8,
    mut __statbuf: *mut stat,
) -> i32 {
    return __xstat(1 as i32, __path, __statbuf);
}
static mut xmlInputCallbackTable: [xmlInputCallback; 15] = [xmlInputCallback {
    matchcallback: None,
    opencallback: None,
    readcallback: None,
    closecallback: None,
}; 15];
static mut xmlInputCallbackNr: i32 = 0 as i32;
static mut xmlInputCallbackInitialized: i32 = 0 as i32;
static mut xmlOutputCallbackTable: [xmlOutputCallback; 15] = [xmlOutputCallback {
    matchcallback: None,
    opencallback: None,
    writecallback: None,
    closecallback: None,
}; 15];
static mut xmlOutputCallbackNr: i32 = 0 as i32;
static mut xmlOutputCallbackInitialized: i32 = 0 as i32;
static mut IOerr: [*const i8; 57] = [
    b"Unknown IO error\0" as *const u8 as *const i8,
    b"Permission denied\0" as *const u8 as *const i8,
    b"Resource temporarily unavailable\0" as *const u8 as *const i8,
    b"Bad file descriptor\0" as *const u8 as *const i8,
    b"Bad message\0" as *const u8 as *const i8,
    b"Resource busy\0" as *const u8 as *const i8,
    b"Operation canceled\0" as *const u8 as *const i8,
    b"No child processes\0" as *const u8 as *const i8,
    b"Resource deadlock avoided\0" as *const u8 as *const i8,
    b"Domain error\0" as *const u8 as *const i8,
    b"File exists\0" as *const u8 as *const i8,
    b"Bad address\0" as *const u8 as *const i8,
    b"File too large\0" as *const u8 as *const i8,
    b"Operation in progress\0" as *const u8 as *const i8,
    b"Interrupted function call\0" as *const u8 as *const i8,
    b"Invalid argument\0" as *const u8 as *const i8,
    b"Input/output error\0" as *const u8 as *const i8,
    b"Is a directory\0" as *const u8 as *const i8,
    b"Too many open files\0" as *const u8 as *const i8,
    b"Too many links\0" as *const u8 as *const i8,
    b"Inappropriate message buffer length\0" as *const u8 as *const i8,
    b"Filename too long\0" as *const u8 as *const i8,
    b"Too many open files in system\0" as *const u8 as *const i8,
    b"No such device\0" as *const u8 as *const i8,
    b"No such file or directory\0" as *const u8 as *const i8,
    b"Exec format error\0" as *const u8 as *const i8,
    b"No locks available\0" as *const u8 as *const i8,
    b"Not enough space\0" as *const u8 as *const i8,
    b"No space left on device\0" as *const u8 as *const i8,
    b"Function not implemented\0" as *const u8 as *const i8,
    b"Not a directory\0" as *const u8 as *const i8,
    b"Directory not empty\0" as *const u8 as *const i8,
    b"Not supported\0" as *const u8 as *const i8,
    b"Inappropriate I/O control operation\0" as *const u8 as *const i8,
    b"No such device or address\0" as *const u8 as *const i8,
    b"Operation not permitted\0" as *const u8 as *const i8,
    b"Broken pipe\0" as *const u8 as *const i8,
    b"Result too large\0" as *const u8 as *const i8,
    b"Read-only file system\0" as *const u8 as *const i8,
    b"Invalid seek\0" as *const u8 as *const i8,
    b"No such process\0" as *const u8 as *const i8,
    b"Operation timed out\0" as *const u8 as *const i8,
    b"Improper link\0" as *const u8 as *const i8,
    b"Attempt to load network entity %s\0" as *const u8 as *const i8,
    b"encoder error\0" as *const u8 as *const i8,
    b"flush error\0" as *const u8 as *const i8,
    b"write error\0" as *const u8 as *const i8,
    b"no input\0" as *const u8 as *const i8,
    b"buffer full\0" as *const u8 as *const i8,
    b"loading error\0" as *const u8 as *const i8,
    b"not a socket\0" as *const u8 as *const i8,
    b"already connected\0" as *const u8 as *const i8,
    b"connection refused\0" as *const u8 as *const i8,
    b"unreachable network\0" as *const u8 as *const i8,
    b"address in use\0" as *const u8 as *const i8,
    b"already in use\0" as *const u8 as *const i8,
    b"unknown address family\0" as *const u8 as *const i8,
];
unsafe extern "C" fn xmlIOErrMemory(mut extra: *const i8) {
    __xmlSimpleError(
        XML_FROM_IO as i32,
        XML_ERR_NO_MEMORY as i32,
        0 as xmlNodePtr,
        0 as *const i8,
        extra,
    );
}
#[no_mangle]
pub unsafe extern "C" fn __xmlIOErr(
    mut domain: i32,
    mut code: i32,
    mut extra: *const i8,
) {
    let mut idx: u32 = 0;
    if code == 0 as i32 {
        if *__errno_location() == 0 as i32 {
            code = 0 as i32;
        } else if *__errno_location() == 13 as i32 {
            code = XML_IO_EACCES as i32;
        } else if *__errno_location() == 11 as i32 {
            code = XML_IO_EAGAIN as i32;
        } else if *__errno_location() == 9 as i32 {
            code = XML_IO_EBADF as i32;
        } else if *__errno_location() == 74 as i32 {
            code = XML_IO_EBADMSG as i32;
        } else if *__errno_location() == 16 as i32 {
            code = XML_IO_EBUSY as i32;
        } else if *__errno_location() == 125 as i32 {
            code = XML_IO_ECANCELED as i32;
        } else if *__errno_location() == 10 as i32 {
            code = XML_IO_ECHILD as i32;
        } else if *__errno_location() == 35 as i32 {
            code = XML_IO_EDEADLK as i32;
        } else if *__errno_location() == 33 as i32 {
            code = XML_IO_EDOM as i32;
        } else if *__errno_location() == 17 as i32 {
            code = XML_IO_EEXIST as i32;
        } else if *__errno_location() == 14 as i32 {
            code = XML_IO_EFAULT as i32;
        } else if *__errno_location() == 27 as i32 {
            code = XML_IO_EFBIG as i32;
        } else if *__errno_location() == 115 as i32 {
            code = XML_IO_EINPROGRESS as i32;
        } else if *__errno_location() == 4 as i32 {
            code = XML_IO_EINTR as i32;
        } else if *__errno_location() == 22 as i32 {
            code = XML_IO_EINVAL as i32;
        } else if *__errno_location() == 5 as i32 {
            code = XML_IO_EIO as i32;
        } else if *__errno_location() == 21 as i32 {
            code = XML_IO_EISDIR as i32;
        } else if *__errno_location() == 24 as i32 {
            code = XML_IO_EMFILE as i32;
        } else if *__errno_location() == 31 as i32 {
            code = XML_IO_EMLINK as i32;
        } else if *__errno_location() == 90 as i32 {
            code = XML_IO_EMSGSIZE as i32;
        } else if *__errno_location() == 36 as i32 {
            code = XML_IO_ENAMETOOLONG as i32;
        } else if *__errno_location() == 23 as i32 {
            code = XML_IO_ENFILE as i32;
        } else if *__errno_location() == 19 as i32 {
            code = XML_IO_ENODEV as i32;
        } else if *__errno_location() == 2 as i32 {
            code = XML_IO_ENOENT as i32;
        } else if *__errno_location() == 8 as i32 {
            code = XML_IO_ENOEXEC as i32;
        } else if *__errno_location() == 37 as i32 {
            code = XML_IO_ENOLCK as i32;
        } else if *__errno_location() == 12 as i32 {
            code = XML_IO_ENOMEM as i32;
        } else if *__errno_location() == 28 as i32 {
            code = XML_IO_ENOSPC as i32;
        } else if *__errno_location() == 38 as i32 {
            code = XML_IO_ENOSYS as i32;
        } else if *__errno_location() == 20 as i32 {
            code = XML_IO_ENOTDIR as i32;
        } else if *__errno_location() == 39 as i32 {
            code = XML_IO_ENOTEMPTY as i32;
        } else if *__errno_location() == 95 as i32 {
            code = XML_IO_ENOTSUP as i32;
        } else if *__errno_location() == 25 as i32 {
            code = XML_IO_ENOTTY as i32;
        } else if *__errno_location() == 6 as i32 {
            code = XML_IO_ENXIO as i32;
        } else if *__errno_location() == 1 as i32 {
            code = XML_IO_EPERM as i32;
        } else if *__errno_location() == 32 as i32 {
            code = XML_IO_EPIPE as i32;
        } else if *__errno_location() == 34 as i32 {
            code = XML_IO_ERANGE as i32;
        } else if *__errno_location() == 30 as i32 {
            code = XML_IO_EROFS as i32;
        } else if *__errno_location() == 29 as i32 {
            code = XML_IO_ESPIPE as i32;
        } else if *__errno_location() == 3 as i32 {
            code = XML_IO_ESRCH as i32;
        } else if *__errno_location() == 110 as i32 {
            code = XML_IO_ETIMEDOUT as i32;
        } else if *__errno_location() == 18 as i32 {
            code = XML_IO_EXDEV as i32;
        } else if *__errno_location() == 88 as i32 {
            code = XML_IO_ENOTSOCK as i32;
        } else if *__errno_location() == 106 as i32 {
            code = XML_IO_EISCONN as i32;
        } else if *__errno_location() == 111 as i32 {
            code = XML_IO_ECONNREFUSED as i32;
        } else if *__errno_location() == 110 as i32 {
            code = XML_IO_ETIMEDOUT as i32;
        } else if *__errno_location() == 101 as i32 {
            code = XML_IO_ENETUNREACH as i32;
        } else if *__errno_location() == 98 as i32 {
            code = XML_IO_EADDRINUSE as i32;
        } else if *__errno_location() == 115 as i32 {
            code = XML_IO_EINPROGRESS as i32;
        } else if *__errno_location() == 114 as i32 {
            code = XML_IO_EALREADY as i32;
        } else if *__errno_location() == 97 as i32 {
            code = XML_IO_EAFNOSUPPORT as i32;
        } else {
            code = XML_IO_UNKNOWN as i32;
        }
    }
    idx = 0 as i32 as u32;
    if code >= XML_IO_UNKNOWN as i32 {
        idx = (code - XML_IO_UNKNOWN as i32) as u32;
    }
    if idx as u64
        >= (::std::mem::size_of::<[*const i8; 57]>() as u64)
            .wrapping_div(::std::mem::size_of::<*const i8>() as u64)
    {
        idx = 0 as i32 as u32;
    }
    __xmlSimpleError(domain, code, 0 as xmlNodePtr, IOerr[idx as usize], extra);
}
unsafe extern "C" fn xmlIOErr(mut code: i32, mut extra: *const i8) {
    __xmlIOErr(XML_FROM_IO as i32, code, extra);
}
#[no_mangle]
pub unsafe extern "C" fn __xmlLoaderErr(
    mut ctx: *mut libc::c_void,
    mut msg: *const i8,
    mut filename: *const i8,
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut schannel: xmlStructuredErrorFunc = None;
    let mut channel: xmlGenericErrorFunc = None;
    let mut data: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut level: xmlErrorLevel = XML_ERR_ERROR;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as i32
        && (*ctxt).instate as i32 == XML_PARSER_EOF as i32
    {
        return;
    }
    if !ctxt.is_null() && !((*ctxt).sax).is_null() {
        if (*ctxt).validate != 0 {
            channel = (*(*ctxt).sax).error;
            level = XML_ERR_ERROR;
        } else {
            channel = (*(*ctxt).sax).warning;
            level = XML_ERR_WARNING;
        }
        if (*(*ctxt).sax).initialized == 0xdeedbeaf as u32 {
            schannel = (*(*ctxt).sax).serror;
        }
        data = (*ctxt).userData;
    }
    __xmlRaiseError(
        schannel,
        channel,
        data,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_IO as i32,
        XML_IO_LOAD_ERROR as i32,
        level,
        0 as *const i8,
        0 as i32,
        filename,
        0 as *const i8,
        0 as *const i8,
        0 as i32,
        0 as i32,
        msg,
        filename,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlNormalizeWindowsPath(
    mut path: *const xmlChar,
) -> *mut xmlChar {
    return xmlCanonicPath(path);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupInputCallbacks() {
    let mut i: i32 = 0;
    if xmlInputCallbackInitialized == 0 {
        return;
    }
    i = xmlInputCallbackNr - 1 as i32;
    while i >= 0 as i32 {
        xmlInputCallbackTable[i as usize].matchcallback = None;
        xmlInputCallbackTable[i as usize].opencallback = None;
        xmlInputCallbackTable[i as usize].readcallback = None;
        xmlInputCallbackTable[i as usize].closecallback = None;
        i -= 1;
    }
    xmlInputCallbackNr = 0 as i32;
    xmlInputCallbackInitialized = 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPopInputCallbacks() -> i32 {
    if xmlInputCallbackInitialized == 0 {
        return -(1 as i32);
    }
    if xmlInputCallbackNr <= 0 as i32 {
        return -(1 as i32);
    }
    xmlInputCallbackNr -= 1;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].matchcallback = None;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].opencallback = None;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].readcallback = None;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].closecallback = None;
    return xmlInputCallbackNr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupOutputCallbacks() {
    let mut i: i32 = 0;
    if xmlOutputCallbackInitialized == 0 {
        return;
    }
    i = xmlOutputCallbackNr - 1 as i32;
    while i >= 0 as i32 {
        xmlOutputCallbackTable[i as usize].matchcallback = None;
        xmlOutputCallbackTable[i as usize].opencallback = None;
        xmlOutputCallbackTable[i as usize].writecallback = None;
        xmlOutputCallbackTable[i as usize].closecallback = None;
        i -= 1;
    }
    xmlOutputCallbackNr = 0 as i32;
    xmlOutputCallbackInitialized = 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPopOutputCallbacks() -> i32 {
    if xmlOutputCallbackInitialized == 0 {
        return -(1 as i32);
    }
    if xmlOutputCallbackNr <= 0 as i32 {
        return -(1 as i32);
    }
    xmlOutputCallbackNr -= 1;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].matchcallback = None;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].opencallback = None;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].writecallback = None;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].closecallback = None;
    return xmlOutputCallbackNr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckFilename(mut path: *const i8) -> i32 {
    let mut stat_buffer: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    if path.is_null() {
        return 0 as i32;
    }
    if stat(path, &mut stat_buffer) == -(1 as i32) {
        return 0 as i32;
    }
    if stat_buffer.st_mode & 0o170000 as i32 as u32
        == 0o40000 as i32 as u32
    {
        return 2 as i32;
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlInputReadCallbackNop(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    return 0 as i32;
}
unsafe extern "C" fn xmlFdRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    ret = read(
        context as ptrdiff_t as i32,
        &mut *buffer.offset(0 as i32 as isize) as *mut i8
            as *mut libc::c_void,
        len as size_t,
    ) as i32;
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"read()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlFdWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    if len > 0 as i32 {
        ret = write(
            context as ptrdiff_t as i32,
            &*buffer.offset(0 as i32 as isize) as *const i8
                as *const libc::c_void,
            len as size_t,
        ) as i32;
        if ret < 0 as i32 {
            xmlIOErr(0 as i32, b"write()\0" as *const u8 as *const i8);
        }
    }
    return ret;
}
unsafe extern "C" fn xmlFdClose(mut context: *mut libc::c_void) -> i32 {
    let mut ret: i32 = 0;
    ret = close(context as ptrdiff_t as i32);
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"close()\0" as *const u8 as *const i8);
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFileMatch(mut filename: *const i8) -> i32 {
    return 1 as i32;
}
unsafe extern "C" fn xmlFileOpen_real(
    mut filename: *const i8,
) -> *mut libc::c_void {
    let mut path: *const i8 = filename;
    let mut fd: *mut FILE = 0 as *mut FILE;
    if filename.is_null() {
        return 0 as *mut libc::c_void;
    }
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        fd = stdin;
        return fd as *mut libc::c_void;
    }
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"file://localhost/\0" as *const u8 as *const i8 as *mut xmlChar,
        17 as i32,
    ) == 0
    {
        path = &*filename.offset(16 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            filename as *mut xmlChar,
            b"file:///\0" as *const u8 as *const i8 as *mut xmlChar,
            8 as i32,
        ) == 0
        {
        path = &*filename.offset(7 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            filename as *mut xmlChar,
            b"file:/\0" as *const u8 as *const i8 as *mut xmlChar,
            6 as i32,
        ) == 0
        {
        path = &*filename.offset(5 as i32 as isize) as *const i8;
    }
    if xmlCheckFilename(path) == 0 {
        return 0 as *mut libc::c_void;
    }
    fd = fopen(path, b"rb\0" as *const u8 as *const i8);
    if fd.is_null() {
        xmlIOErr(0 as i32, path);
    }
    return fd as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFileOpen(
    mut filename: *const i8,
) -> *mut libc::c_void {
    let mut unescaped: *mut i8 = 0 as *mut i8;
    let mut retval: *mut libc::c_void = 0 as *mut libc::c_void;
    retval = xmlFileOpen_real(filename);
    if retval.is_null() {
        unescaped = xmlURIUnescapeString(
            filename,
            0 as i32,
            0 as *mut i8,
        );
        if !unescaped.is_null() {
            retval = xmlFileOpen_real(unescaped);
            xmlFree.expect("non-null function pointer")(unescaped as *mut libc::c_void);
        }
    }
    return retval;
}
unsafe extern "C" fn xmlFileOpenW(
    mut filename: *const i8,
) -> *mut libc::c_void {
    let mut path: *const i8 = 0 as *const i8;
    let mut fd: *mut FILE = 0 as *mut FILE;
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        fd = stdout;
        return fd as *mut libc::c_void;
    }
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"file://localhost/\0" as *const u8 as *const i8 as *mut xmlChar,
        17 as i32,
    ) == 0
    {
        path = &*filename.offset(16 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            filename as *mut xmlChar,
            b"file:///\0" as *const u8 as *const i8 as *mut xmlChar,
            8 as i32,
        ) == 0
        {
        path = &*filename.offset(7 as i32 as isize) as *const i8;
    } else {
        path = filename;
    }
    if path.is_null() {
        return 0 as *mut libc::c_void;
    }
    fd = fopen(path, b"wb\0" as *const u8 as *const i8);
    if fd.is_null() {
        xmlIOErr(0 as i32, path);
    }
    return fd as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFileRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    if context.is_null() || buffer.is_null() {
        return -(1 as i32);
    }
    ret = fread(
        &mut *buffer.offset(0 as i32 as isize) as *mut i8
            as *mut libc::c_void,
        1 as i32 as u64,
        len as u64,
        context as *mut FILE,
    ) as i32;
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"fread()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlFileWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const i8,
    mut len: i32,
) -> i32 {
    let mut items: i32 = 0;
    if context.is_null() || buffer.is_null() {
        return -(1 as i32);
    }
    items = fwrite(
        &*buffer.offset(0 as i32 as isize) as *const i8
            as *const libc::c_void,
        len as u64,
        1 as i32 as u64,
        context as *mut FILE,
    ) as i32;
    if items == 0 as i32 && ferror(context as *mut FILE) != 0 {
        xmlIOErr(0 as i32, b"fwrite()\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    return items * len;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFileClose(mut context: *mut libc::c_void) -> i32 {
    let mut fil: *mut FILE = 0 as *mut FILE;
    let mut ret: i32 = 0;
    if context.is_null() {
        return -(1 as i32);
    }
    fil = context as *mut FILE;
    if fil == stdout || fil == stderr {
        ret = fflush(fil);
        if ret < 0 as i32 {
            xmlIOErr(
                0 as i32,
                b"fflush()\0" as *const u8 as *const i8,
            );
        }
        return 0 as i32;
    }
    if fil == stdin {
        return 0 as i32;
    }
    ret = if fclose(context as *mut FILE) == -(1 as i32) {
        -(1 as i32)
    } else {
        0 as i32
    };
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"fclose()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlFileFlush(mut context: *mut libc::c_void) -> i32 {
    let mut ret: i32 = 0;
    if context.is_null() {
        return -(1 as i32);
    }
    ret = if fflush(context as *mut FILE) == -(1 as i32) {
        -(1 as i32)
    } else {
        0 as i32
    };
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"fflush()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlBufferWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    ret = xmlBufferAdd(context as xmlBufferPtr, buffer as *const xmlChar, len);
    if ret != 0 as i32 {
        return -(1 as i32);
    }
    return len;
}
 extern "C" fn xmlGzfileMatch(mut filename: *const i8) -> i32 {
    return 1 as i32;
}
unsafe extern "C" fn xmlGzfileOpen_real(
    mut filename: *const i8,
) -> *mut libc::c_void {
    let mut path: *const i8 = 0 as *const i8;
    let mut fd: gzFile = 0 as *mut gzFile_s;
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        let mut duped_fd: i32 = dup(fileno(stdin));
        fd = gzdopen(duped_fd, b"rb\0" as *const u8 as *const i8);
        if fd.is_null() && duped_fd >= 0 as i32 {
            close(duped_fd);
        }
        return fd as *mut libc::c_void;
    }
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"file://localhost/\0" as *const u8 as *const i8 as *mut xmlChar,
        17 as i32,
    ) == 0
    {
        path = &*filename.offset(16 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            filename as *mut xmlChar,
            b"file:///\0" as *const u8 as *const i8 as *mut xmlChar,
            8 as i32,
        ) == 0
        {
        path = &*filename.offset(7 as i32 as isize) as *const i8;
    } else {
        path = filename;
    }
    if path.is_null() {
        return 0 as *mut libc::c_void;
    }
    if xmlCheckFilename(path) == 0 {
        return 0 as *mut libc::c_void;
    }
    fd = gzopen64(path, b"rb\0" as *const u8 as *const i8);
    return fd as *mut libc::c_void;
}
unsafe extern "C" fn xmlGzfileOpen(
    mut filename: *const i8,
) -> *mut libc::c_void {
    let mut unescaped: *mut i8 = 0 as *mut i8;
    let mut retval: *mut libc::c_void = 0 as *mut libc::c_void;
    retval = xmlGzfileOpen_real(filename);
    if retval.is_null() {
        unescaped = xmlURIUnescapeString(
            filename,
            0 as i32,
            0 as *mut i8,
        );
        if !unescaped.is_null() {
            retval = xmlGzfileOpen_real(unescaped);
        }
        xmlFree.expect("non-null function pointer")(unescaped as *mut libc::c_void);
    }
    return retval;
}
unsafe extern "C" fn xmlGzfileOpenW(
    mut filename: *const i8,
    mut compression: i32,
) -> *mut libc::c_void {
    let mut path: *const i8 = 0 as *const i8;
    let mut mode: [i8; 15] = [0; 15];
    let mut fd: gzFile = 0 as *mut gzFile_s;
    snprintf(
        mode.as_mut_ptr(),
        ::std::mem::size_of::<[i8; 15]>() as u64,
        b"wb%d\0" as *const u8 as *const i8,
        compression,
    );
    if strcmp(filename, b"-\0" as *const u8 as *const i8) == 0 {
        let mut duped_fd: i32 = dup(fileno(stdout));
        fd = gzdopen(duped_fd, b"rb\0" as *const u8 as *const i8);
        if fd.is_null() && duped_fd >= 0 as i32 {
            close(duped_fd);
        }
        return fd as *mut libc::c_void;
    }
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"file://localhost/\0" as *const u8 as *const i8 as *mut xmlChar,
        17 as i32,
    ) == 0
    {
        path = &*filename.offset(16 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            filename as *mut xmlChar,
            b"file:///\0" as *const u8 as *const i8 as *mut xmlChar,
            8 as i32,
        ) == 0
        {
        path = &*filename.offset(7 as i32 as isize) as *const i8;
    } else {
        path = filename;
    }
    if path.is_null() {
        return 0 as *mut libc::c_void;
    }
    fd = gzopen64(path, mode.as_mut_ptr());
    return fd as *mut libc::c_void;
}
unsafe extern "C" fn xmlGzfileRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    ret = gzread(
        context as gzFile,
        &mut *buffer.offset(0 as i32 as isize) as *mut i8 as voidp,
        len as u32,
    );
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"gzread()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlGzfileWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const i8,
    mut len: i32,
) -> i32 {
    let mut ret: i32 = 0;
    ret = gzwrite(
        context as gzFile,
        &*buffer.offset(0 as i32 as isize) as *const i8
            as *mut i8 as voidpc,
        len as u32,
    );
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"gzwrite()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn xmlGzfileClose(mut context: *mut libc::c_void) -> i32 {
    let mut ret: i32 = 0;
    ret = if gzclose(context as gzFile) == 0 as i32 {
        0 as i32
    } else {
        -(1 as i32)
    };
    if ret < 0 as i32 {
        xmlIOErr(0 as i32, b"gzclose()\0" as *const u8 as *const i8);
    }
    return ret;
}
unsafe extern "C" fn append_reverse_ulong(
    mut buff: *mut xmlZMemBuff,
    mut data: u64,
) {
    let mut idx: i32 = 0;
    if buff.is_null() {
        return;
    }
    idx = 0 as i32;
    while idx < 4 as i32 {
        *(*buff).zctrl.next_out = (data & 0xff as i32 as u64) as Bytef;
        data >>= 8 as i32;
        let fresh0 = &mut ((*buff).zctrl.next_out);
        *fresh0 = (*fresh0).offset(1);
        idx += 1;
    }
}
unsafe extern "C" fn xmlFreeZMemBuff(mut buff: xmlZMemBuffPtr) {
    if buff.is_null() {
        return;
    }
    xmlFree.expect("non-null function pointer")((*buff).zbuff as *mut libc::c_void);
    deflateEnd(&mut (*buff).zctrl);
    xmlFree.expect("non-null function pointer")(buff as *mut libc::c_void);
}
unsafe extern "C" fn xmlCreateZMemBuff(
    mut compression: i32,
) -> *mut libc::c_void {
    let mut z_err: i32 = 0;
    let mut hdr_lgth: i32 = 0;
    let mut buff: xmlZMemBuffPtr = 0 as xmlZMemBuffPtr;
    if compression < 1 as i32 || compression > 9 as i32 {
        return 0 as *mut libc::c_void;
    }
    buff = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlZMemBuff>() as u64) as xmlZMemBuffPtr;
    if buff.is_null() {
        xmlIOErrMemory(b"creating buffer context\0" as *const u8 as *const i8);
        return 0 as *mut libc::c_void;
    }
    memset(
        buff as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlZMemBuff>() as u64,
    );
    (*buff).size = 32768 as i32 as u64;
    let fresh1 = &mut ((*buff).zbuff);
    *fresh1 = xmlMalloc.expect("non-null function pointer")((*buff).size)
        as *mut u8;
    if ((*buff).zbuff).is_null() {
        xmlFreeZMemBuff(buff);
        xmlIOErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return 0 as *mut libc::c_void;
    }
    z_err = deflateInit2_(
        &mut (*buff).zctrl,
        compression,
        8 as i32,
        -(15 as i32),
        8 as i32,
        0 as i32,
        b"1.2.11\0" as *const u8 as *const i8,
        ::std::mem::size_of::<z_stream>() as u64 as i32,
    );
    if z_err != 0 as i32 {
        let mut msg: [xmlChar; 500] = [0; 500];
        xmlFreeZMemBuff(buff);
        buff = 0 as xmlZMemBuffPtr;
        xmlStrPrintf(
            msg.as_mut_ptr(),
            500 as i32,
            b"xmlCreateZMemBuff:  %s %d\n\0" as *const u8 as *const i8,
            b"Error initializing compression context.  ZLIB error:\0" as *const u8
                as *const i8,
            z_err,
        );
        xmlIOErr(XML_IO_WRITE as i32, msg.as_mut_ptr() as *const i8);
        return 0 as *mut libc::c_void;
    }
    (*buff)
        .crc = crc32(
        0 as i64 as uLong,
        0 as *const Bytef,
        0 as i32 as uInt,
    );
    hdr_lgth = snprintf(
        (*buff).zbuff as *mut i8,
        (*buff).size,
        b"%c%c%c%c%c%c%c%c%c%c\0" as *const u8 as *const i8,
        0x1f as i32,
        0x8b as i32,
        8 as i32,
        0 as i32,
        0 as i32,
        0 as i32,
        0 as i32,
        0 as i32,
        0 as i32,
        0x3 as i32,
    );
    let fresh2 = &mut ((*buff).zctrl.next_out);
    *fresh2 = ((*buff).zbuff).offset(hdr_lgth as isize);
    (*buff)
        .zctrl
        .avail_out = ((*buff).size).wrapping_sub(hdr_lgth as u64) as uInt;
    return buff as *mut libc::c_void;
}
unsafe extern "C" fn xmlZMemBuffExtend(
    mut buff: xmlZMemBuffPtr,
    mut ext_amt: size_t,
) -> i32 {
    let mut rc: i32 = -(1 as i32);
    let mut new_size: size_t = 0;
    let mut cur_used: size_t = 0;
    let mut tmp_ptr: *mut u8 = 0 as *mut u8;
    if buff.is_null() {
        return -(1 as i32)
    } else {
        if ext_amt == 0 as i32 as u64 {
            return 0 as i32;
        }
    }
    cur_used = ((*buff).zctrl.next_out).offset_from((*buff).zbuff) as i64
        as size_t;
    new_size = ((*buff).size).wrapping_add(ext_amt);
    tmp_ptr = xmlRealloc
        .expect(
            "non-null function pointer",
        )((*buff).zbuff as *mut libc::c_void, new_size) as *mut u8;
    if !tmp_ptr.is_null() {
        rc = 0 as i32;
        (*buff).size = new_size;
        let fresh3 = &mut ((*buff).zbuff);
        *fresh3 = tmp_ptr;
        let fresh4 = &mut ((*buff).zctrl.next_out);
        *fresh4 = tmp_ptr.offset(cur_used as isize);
        (*buff).zctrl.avail_out = new_size.wrapping_sub(cur_used) as uInt;
    } else {
        let mut msg: [xmlChar; 500] = [0; 500];
        xmlStrPrintf(
            msg.as_mut_ptr(),
            500 as i32,
            b"xmlZMemBuffExtend:  %s %lu bytes.\n\0" as *const u8 as *const i8,
            b"Allocation failure extending output buffer to\0" as *const u8
                as *const i8,
            new_size,
        );
        xmlIOErr(XML_IO_WRITE as i32, msg.as_mut_ptr() as *const i8);
    }
    return rc;
}
unsafe extern "C" fn xmlZMemBuffAppend(
    mut buff: xmlZMemBuffPtr,
    mut src: *const i8,
    mut len: i32,
) -> i32 {
    let mut z_err: i32 = 0;
    let mut min_accept: size_t = 0;
    if buff.is_null() || src.is_null() {
        return -(1 as i32);
    }
    (*buff).zctrl.avail_in = len as uInt;
    let fresh5 = &mut ((*buff).zctrl.next_in);
    *fresh5 = src as *mut u8;
    while (*buff).zctrl.avail_in > 0 as i32 as u32 {
        min_accept = ((*buff).zctrl.avail_in)
            .wrapping_div(5 as i32 as u32) as size_t;
        if (*buff).zctrl.avail_out as u64 <= min_accept {
            if xmlZMemBuffExtend(buff, (*buff).size) == -(1 as i32) {
                return -(1 as i32);
            }
        }
        z_err = deflate(&mut (*buff).zctrl, 0 as i32);
        if z_err != 0 as i32 {
            let mut msg: [xmlChar; 500] = [0; 500];
            xmlStrPrintf(
                msg.as_mut_ptr(),
                500 as i32,
                b"xmlZMemBuffAppend:  %s %d %s - %d\0" as *const u8
                    as *const i8,
                b"Compression error while appending\0" as *const u8
                    as *const i8,
                len,
                b"bytes to buffer.  ZLIB error\0" as *const u8 as *const i8,
                z_err,
            );
            xmlIOErr(
                XML_IO_WRITE as i32,
                msg.as_mut_ptr() as *const i8,
            );
            return -(1 as i32);
        }
    }
    (*buff).crc = crc32((*buff).crc, src as *mut u8, len as uInt);
    return len;
}
unsafe extern "C" fn xmlZMemBuffGetContent(
    mut buff: xmlZMemBuffPtr,
    mut data_ref: *mut *mut i8,
) -> i32 {
    let mut zlgth: i32 = -(1 as i32);
    let mut z_err: i32 = 0;
    if buff.is_null() || data_ref.is_null() {
        return -(1 as i32);
    }
    loop {
        z_err = deflate(&mut (*buff).zctrl, 4 as i32);
        if z_err == 0 as i32 {
            if xmlZMemBuffExtend(buff, (*buff).size) == -(1 as i32) {
                return -(1 as i32);
            }
        }
        if !(z_err == 0 as i32) {
            break;
        }
    }
    if z_err == 1 as i32 {
        if ((*buff).zctrl.avail_out as u64)
            < (2 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<u64>() as u64)
        {
            if xmlZMemBuffExtend(
                buff,
                (2 as i32 as u64)
                    .wrapping_mul(
                        ::std::mem::size_of::<u64>() as u64,
                    ),
            ) == -(1 as i32)
            {
                return -(1 as i32);
            }
        }
        append_reverse_ulong(buff, (*buff).crc);
        append_reverse_ulong(buff, (*buff).zctrl.total_in);
        zlgth = ((*buff).zctrl.next_out).offset_from((*buff).zbuff) as i64
            as i32;
        *data_ref = (*buff).zbuff as *mut i8;
    } else {
        let mut msg: [xmlChar; 500] = [0; 500];
        xmlStrPrintf(
            msg.as_mut_ptr(),
            500 as i32,
            b"xmlZMemBuffGetContent:  %s - %d\n\0" as *const u8 as *const i8,
            b"Error flushing zlib buffers.  Error code\0" as *const u8
                as *const i8,
            z_err,
        );
        xmlIOErr(XML_IO_WRITE as i32, msg.as_mut_ptr() as *const i8);
    }
    return zlgth;
}
unsafe extern "C" fn xmlFreeHTTPWriteCtxt(mut ctxt: xmlIOHTTPWriteCtxtPtr) {
    if !((*ctxt).uri).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).uri as *mut libc::c_void);
    }
    if !((*ctxt).doc_buff).is_null() {
        if (*ctxt).compression > 0 as i32 {
            xmlFreeZMemBuff((*ctxt).doc_buff as xmlZMemBuffPtr);
        } else {
            xmlOutputBufferClose((*ctxt).doc_buff as xmlOutputBufferPtr);
        }
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOHTTPMatch(
    mut filename: *const i8,
) -> i32 {
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"http://\0" as *const u8 as *const i8 as *mut xmlChar,
        7 as i32,
    ) == 0
    {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOHTTPOpen(
    mut filename: *const i8,
) -> *mut libc::c_void {
    return xmlNanoHTTPOpen(filename, 0 as *mut *mut i8);
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOHTTPOpenW(
    mut post_uri: *const i8,
    mut compression: i32,
) -> *mut libc::c_void {
    let mut ctxt: xmlIOHTTPWriteCtxtPtr = 0 as xmlIOHTTPWriteCtxtPtr;
    if post_uri.is_null() {
        return 0 as *mut libc::c_void;
    }
    ctxt = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlIOHTTPWriteCtxt>() as u64)
        as xmlIOHTTPWriteCtxtPtr;
    if ctxt.is_null() {
        xmlIOErrMemory(
            b"creating HTTP output context\0" as *const u8 as *const i8,
        );
        return 0 as *mut libc::c_void;
    }
    memset(
        ctxt as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlIOHTTPWriteCtxt>() as u64,
    );
    let fresh6 = &mut ((*ctxt).uri);
    *fresh6 = xmlStrdup(post_uri as *const xmlChar) as *mut i8;
    if ((*ctxt).uri).is_null() {
        xmlIOErrMemory(b"copying URI\0" as *const u8 as *const i8);
        xmlFreeHTTPWriteCtxt(ctxt);
        return 0 as *mut libc::c_void;
    }
    if compression > 0 as i32 && compression <= 9 as i32 {
        (*ctxt).compression = compression;
        let fresh7 = &mut ((*ctxt).doc_buff);
        *fresh7 = xmlCreateZMemBuff(compression);
    } else {
        let fresh8 = &mut ((*ctxt).doc_buff);
        *fresh8 = xmlAllocOutputBufferInternal(0 as xmlCharEncodingHandlerPtr)
            as *mut libc::c_void;
    }
    if ((*ctxt).doc_buff).is_null() {
        xmlFreeHTTPWriteCtxt(ctxt);
        ctxt = 0 as xmlIOHTTPWriteCtxtPtr;
    }
    return ctxt as *mut libc::c_void;
}
unsafe extern "C" fn xmlIOHTTPDfltOpenW(
    mut post_uri: *const i8,
) -> *mut libc::c_void {
    return xmlIOHTTPOpenW(post_uri, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOHTTPRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    if buffer.is_null() || len < 0 as i32 {
        return -(1 as i32);
    }
    return xmlNanoHTTPRead(
        context,
        &mut *buffer.offset(0 as i32 as isize) as *mut i8
            as *mut libc::c_void,
        len,
    );
}
unsafe extern "C" fn xmlIOHTTPWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const i8,
    mut len: i32,
) -> i32 {
    let mut ctxt: xmlIOHTTPWriteCtxtPtr = context as xmlIOHTTPWriteCtxtPtr;
    if ctxt.is_null() || ((*ctxt).doc_buff).is_null() || buffer.is_null() {
        return -(1 as i32);
    }
    if len > 0 as i32 {
        if (*ctxt).compression > 0 as i32 {
            len = xmlZMemBuffAppend((*ctxt).doc_buff as xmlZMemBuffPtr, buffer, len);
        } else {
            len = xmlOutputBufferWrite(
                (*ctxt).doc_buff as xmlOutputBufferPtr,
                len,
                buffer,
            );
        }
        if len < 0 as i32 {
            let mut msg: [xmlChar; 500] = [0; 500];
            xmlStrPrintf(
                msg.as_mut_ptr(),
                500 as i32,
                b"xmlIOHTTPWrite:  %s\n%s '%s'.\n\0" as *const u8 as *const i8,
                b"Error appending to internal buffer.\0" as *const u8
                    as *const i8,
                b"Error sending document to URI\0" as *const u8 as *const i8,
                (*ctxt).uri,
            );
            xmlIOErr(
                XML_IO_WRITE as i32,
                msg.as_mut_ptr() as *const i8,
            );
        }
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOHTTPClose(mut context: *mut libc::c_void) -> i32 {
    xmlNanoHTTPClose(context);
    return 0 as i32;
}
unsafe extern "C" fn xmlIOHTTPCloseWrite(
    mut context: *mut libc::c_void,
    mut http_mthd: *const i8,
) -> i32 {
    let mut close_rc: i32 = -(1 as i32);
    let mut http_rtn: i32 = 0 as i32;
    let mut content_lgth: i32 = 0 as i32;
    let mut ctxt: xmlIOHTTPWriteCtxtPtr = context as xmlIOHTTPWriteCtxtPtr;
    let mut http_content: *mut i8 = 0 as *mut i8;
    let mut content_encoding: *mut i8 = 0 as *mut i8;
    let mut content_type: *mut i8 = b"text/xml\0" as *const u8
        as *const i8 as *mut i8;
    let mut http_ctxt: *mut libc::c_void = 0 as *mut libc::c_void;
    if ctxt.is_null() || http_mthd.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).compression > 0 as i32 {
        content_lgth = xmlZMemBuffGetContent(
            (*ctxt).doc_buff as xmlZMemBuffPtr,
            &mut http_content,
        );
        content_encoding = b"Content-Encoding: gzip\0" as *const u8
            as *const i8 as *mut i8;
    } else {
        let mut dctxt: xmlOutputBufferPtr = (*ctxt).doc_buff as xmlOutputBufferPtr;
        http_content = xmlBufContent((*dctxt).buffer as *const xmlBuf)
            as *mut i8;
        content_lgth = xmlBufUse((*dctxt).buffer) as i32;
    }
    if http_content.is_null() {
        let mut msg: [xmlChar; 500] = [0; 500];
        xmlStrPrintf(
            msg.as_mut_ptr(),
            500 as i32,
            b"xmlIOHTTPCloseWrite:  %s '%s' %s '%s'.\n\0" as *const u8
                as *const i8,
            b"Error retrieving content.\nUnable to\0" as *const u8
                as *const i8,
            http_mthd,
            b"data to URI\0" as *const u8 as *const i8,
            (*ctxt).uri,
        );
        xmlIOErr(XML_IO_WRITE as i32, msg.as_mut_ptr() as *const i8);
    } else {
        http_ctxt = xmlNanoHTTPMethod(
            (*ctxt).uri,
            http_mthd,
            http_content,
            &mut content_type,
            content_encoding,
            content_lgth,
        );
        if !http_ctxt.is_null() {
            http_rtn = xmlNanoHTTPReturnCode(http_ctxt);
            if http_rtn >= 200 as i32 && http_rtn < 300 as i32 {
                close_rc = 0 as i32;
            } else {
                let mut msg_0: [xmlChar; 500] = [0; 500];
                xmlStrPrintf(
                    msg_0.as_mut_ptr(),
                    500 as i32,
                    b"xmlIOHTTPCloseWrite: HTTP '%s' of %d %s\n'%s' %s %d\n\0"
                        as *const u8 as *const i8,
                    http_mthd,
                    content_lgth,
                    b"bytes to URI\0" as *const u8 as *const i8,
                    (*ctxt).uri,
                    b"failed.  HTTP return code:\0" as *const u8 as *const i8,
                    http_rtn,
                );
                xmlIOErr(
                    XML_IO_WRITE as i32,
                    msg_0.as_mut_ptr() as *const i8,
                );
            }
            xmlNanoHTTPClose(http_ctxt);
            xmlFree
                .expect("non-null function pointer")(content_type as *mut libc::c_void);
        }
    }
    xmlFreeHTTPWriteCtxt(ctxt);
    return close_rc;
}
unsafe extern "C" fn xmlIOHTTPClosePut(mut ctxt: *mut libc::c_void) -> i32 {
    return xmlIOHTTPCloseWrite(ctxt, b"PUT\0" as *const u8 as *const i8);
}
unsafe extern "C" fn xmlIOHTTPClosePost(mut ctxt: *mut libc::c_void) -> i32 {
    return xmlIOHTTPCloseWrite(ctxt, b"POST\0" as *const u8 as *const i8);
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOFTPMatch(
    mut filename: *const i8,
) -> i32 {
    if xmlStrncasecmp(
        filename as *mut xmlChar,
        b"ftp://\0" as *const u8 as *const i8 as *mut xmlChar,
        6 as i32,
    ) == 0
    {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOFTPOpen(
    mut filename: *const i8,
) -> *mut libc::c_void {
    return xmlNanoFTPOpen(filename);
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOFTPRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    if buffer.is_null() || len < 0 as i32 {
        return -(1 as i32);
    }
    return xmlNanoFTPRead(
        context,
        &mut *buffer.offset(0 as i32 as isize) as *mut i8
            as *mut libc::c_void,
        len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOFTPClose(mut context: *mut libc::c_void) -> i32 {
    return xmlNanoFTPClose(context);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterInputCallbacks(
    mut matchFunc: xmlInputMatchCallback,
    mut openFunc: xmlInputOpenCallback,
    mut readFunc: xmlInputReadCallback,
    mut closeFunc: xmlInputCloseCallback,
) -> i32 {
    if xmlInputCallbackNr >= 15 as i32 {
        return -(1 as i32);
    }
    xmlInputCallbackTable[xmlInputCallbackNr as usize].matchcallback = matchFunc;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].opencallback = openFunc;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].readcallback = readFunc;
    xmlInputCallbackTable[xmlInputCallbackNr as usize].closecallback = closeFunc;
    xmlInputCallbackInitialized = 1 as i32;
    let fresh9 = xmlInputCallbackNr;
    xmlInputCallbackNr = xmlInputCallbackNr + 1;
    return fresh9;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterOutputCallbacks(
    mut matchFunc: xmlOutputMatchCallback,
    mut openFunc: xmlOutputOpenCallback,
    mut writeFunc: xmlOutputWriteCallback,
    mut closeFunc: xmlOutputCloseCallback,
) -> i32 {
    if xmlOutputCallbackNr >= 15 as i32 {
        return -(1 as i32);
    }
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].matchcallback = matchFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].opencallback = openFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].writecallback = writeFunc;
    xmlOutputCallbackTable[xmlOutputCallbackNr as usize].closecallback = closeFunc;
    xmlOutputCallbackInitialized = 1 as i32;
    let fresh10 = xmlOutputCallbackNr;
    xmlOutputCallbackNr = xmlOutputCallbackNr + 1;
    return fresh10;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterDefaultInputCallbacks() {
    if xmlInputCallbackInitialized != 0 {
        return;
    }
    xmlRegisterInputCallbacks(
        Some(xmlFileMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlFileOpen as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlFileRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlFileClose as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlRegisterInputCallbacks(
        Some(xmlGzfileMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlGzfileOpen
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlGzfileRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlGzfileClose as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlRegisterInputCallbacks(
        Some(xmlIOHTTPMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlIOHTTPOpen
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlIOHTTPRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlIOHTTPClose as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlRegisterInputCallbacks(
        Some(xmlIOFTPMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlIOFTPOpen
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlIOFTPRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlIOFTPClose as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlInputCallbackInitialized = 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterDefaultOutputCallbacks() {
    if xmlOutputCallbackInitialized != 0 {
        return;
    }
    xmlRegisterOutputCallbacks(
        Some(xmlFileMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlFileOpenW
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlFileWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlFileClose as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlRegisterOutputCallbacks(
        Some(xmlIOHTTPMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlIOHTTPDfltOpenW
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlIOHTTPWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        ),
        Some(xmlIOHTTPClosePut as unsafe extern "C" fn(*mut libc::c_void) -> i32),
    );
    xmlOutputCallbackInitialized = 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegisterHTTPPostCallbacks() {
    if xmlOutputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultOutputCallbacks();
    }
    xmlRegisterOutputCallbacks(
        Some(xmlIOHTTPMatch as unsafe extern "C" fn(*const i8) -> i32),
        Some(
            xmlIOHTTPDfltOpenW
                as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
        ),
        Some(
            xmlIOHTTPWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        ),
        Some(
            xmlIOHTTPClosePost as unsafe extern "C" fn(*mut libc::c_void) -> i32,
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlAllocParserInputBuffer(
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlParserInputBuffer>() as u64)
        as xmlParserInputBufferPtr;
    if ret.is_null() {
        xmlIOErrMemory(b"creating input buffer\0" as *const u8 as *const i8);
        return 0 as xmlParserInputBufferPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlParserInputBuffer>() as u64,
    );
    let fresh11 = &mut ((*ret).buffer);
    *fresh11 = xmlBufCreateSize(
        (2 as i32 * *__xmlDefaultBufferSize()) as size_t,
    );
    if ((*ret).buffer).is_null() {
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlParserInputBufferPtr;
    }
    xmlBufSetAllocationScheme((*ret).buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    let fresh12 = &mut ((*ret).encoder);
    *fresh12 = xmlGetCharEncodingHandler(enc);
    if !((*ret).encoder).is_null() {
        let fresh13 = &mut ((*ret).raw);
        *fresh13 = xmlBufCreateSize(
            (2 as i32 * *__xmlDefaultBufferSize()) as size_t,
        );
    } else {
        let fresh14 = &mut ((*ret).raw);
        *fresh14 = 0 as xmlBufPtr;
    }
    let fresh15 = &mut ((*ret).readcallback);
    *fresh15 = None;
    let fresh16 = &mut ((*ret).closecallback);
    *fresh16 = None;
    let fresh17 = &mut ((*ret).context);
    *fresh17 = 0 as *mut libc::c_void;
    (*ret).compressed = -(1 as i32);
    (*ret).rawconsumed = 0 as i32 as u64;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAllocOutputBuffer(
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlOutputBuffer>() as u64)
        as xmlOutputBufferPtr;
    if ret.is_null() {
        xmlIOErrMemory(b"creating output buffer\0" as *const u8 as *const i8);
        return 0 as xmlOutputBufferPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlOutputBuffer>() as u64,
    );
    let fresh18 = &mut ((*ret).buffer);
    *fresh18 = xmlBufCreate();
    if ((*ret).buffer).is_null() {
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlOutputBufferPtr;
    }
    xmlBufSetAllocationScheme((*ret).buffer, XML_BUFFER_ALLOC_DOUBLEIT);
    let fresh19 = &mut ((*ret).encoder);
    *fresh19 = encoder;
    if !encoder.is_null() {
        let fresh20 = &mut ((*ret).conv);
        *fresh20 = xmlBufCreateSize(4000 as i32 as size_t);
        if ((*ret).conv).is_null() {
            xmlBufFree((*ret).buffer);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlOutputBufferPtr;
        }
        xmlCharEncOutput(ret, 1 as i32);
    } else {
        let fresh21 = &mut ((*ret).conv);
        *fresh21 = 0 as xmlBufPtr;
    }
    let fresh22 = &mut ((*ret).writecallback);
    *fresh22 = None;
    let fresh23 = &mut ((*ret).closecallback);
    *fresh23 = None;
    let fresh24 = &mut ((*ret).context);
    *fresh24 = 0 as *mut libc::c_void;
    (*ret).written = 0 as i32;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAllocOutputBufferInternal(
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlOutputBuffer>() as u64)
        as xmlOutputBufferPtr;
    if ret.is_null() {
        xmlIOErrMemory(b"creating output buffer\0" as *const u8 as *const i8);
        return 0 as xmlOutputBufferPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlOutputBuffer>() as u64,
    );
    let fresh25 = &mut ((*ret).buffer);
    *fresh25 = xmlBufCreate();
    if ((*ret).buffer).is_null() {
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlOutputBufferPtr;
    }
    xmlBufSetAllocationScheme((*ret).buffer, XML_BUFFER_ALLOC_IO);
    let fresh26 = &mut ((*ret).encoder);
    *fresh26 = encoder;
    if !encoder.is_null() {
        let fresh27 = &mut ((*ret).conv);
        *fresh27 = xmlBufCreateSize(4000 as i32 as size_t);
        if ((*ret).conv).is_null() {
            xmlBufFree((*ret).buffer);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlOutputBufferPtr;
        }
        xmlCharEncOutput(ret, 1 as i32);
    } else {
        let fresh28 = &mut ((*ret).conv);
        *fresh28 = 0 as xmlBufPtr;
    }
    let fresh29 = &mut ((*ret).writecallback);
    *fresh29 = None;
    let fresh30 = &mut ((*ret).closecallback);
    *fresh30 = None;
    let fresh31 = &mut ((*ret).context);
    *fresh31 = 0 as *mut libc::c_void;
    (*ret).written = 0 as i32;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeParserInputBuffer(mut in_0: xmlParserInputBufferPtr) {
    if in_0.is_null() {
        return;
    }
    if !((*in_0).raw).is_null() {
        xmlBufFree((*in_0).raw);
        let fresh32 = &mut ((*in_0).raw);
        *fresh32 = 0 as xmlBufPtr;
    }
    if !((*in_0).encoder).is_null() {
        xmlCharEncCloseFunc((*in_0).encoder);
    }
    if ((*in_0).closecallback).is_some() {
        ((*in_0).closecallback).expect("non-null function pointer")((*in_0).context);
    }
    if !((*in_0).buffer).is_null() {
        xmlBufFree((*in_0).buffer);
        let fresh33 = &mut ((*in_0).buffer);
        *fresh33 = 0 as xmlBufPtr;
    }
    xmlFree.expect("non-null function pointer")(in_0 as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferClose(
    mut out: xmlOutputBufferPtr,
) -> i32 {
    let mut written: i32 = 0;
    let mut err_rc: i32 = 0 as i32;
    if out.is_null() {
        return -(1 as i32);
    }
    if ((*out).writecallback).is_some() {
        xmlOutputBufferFlush(out);
    }
    if ((*out).closecallback).is_some() {
        err_rc = ((*out).closecallback)
            .expect("non-null function pointer")((*out).context);
    }
    written = (*out).written;
    if !((*out).conv).is_null() {
        xmlBufFree((*out).conv);
        let fresh34 = &mut ((*out).conv);
        *fresh34 = 0 as xmlBufPtr;
    }
    if !((*out).encoder).is_null() {
        xmlCharEncCloseFunc((*out).encoder);
    }
    if !((*out).buffer).is_null() {
        xmlBufFree((*out).buffer);
        let fresh35 = &mut ((*out).buffer);
        *fresh35 = 0 as xmlBufPtr;
    }
    if (*out).error != 0 {
        err_rc = -(1 as i32);
    }
    xmlFree.expect("non-null function pointer")(out as *mut libc::c_void);
    return if err_rc == 0 as i32 { written } else { err_rc };
}
#[no_mangle]
pub unsafe extern "C" fn __xmlParserInputBufferCreateFilename(
    mut URI: *const i8,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut i: i32 = 0 as i32;
    let mut context: *mut libc::c_void = 0 as *mut libc::c_void;
    if xmlInputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultInputCallbacks();
    }
    if URI.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    if context.is_null() {
        i = xmlInputCallbackNr - 1 as i32;
        while i >= 0 as i32 {
            if (xmlInputCallbackTable[i as usize].matchcallback).is_some()
                && (xmlInputCallbackTable[i as usize].matchcallback)
                    .expect("non-null function pointer")(URI) != 0 as i32
            {
                context = (xmlInputCallbackTable[i as usize].opencallback)
                    .expect("non-null function pointer")(URI);
                if !context.is_null() {
                    break;
                }
            }
            i -= 1;
        }
    }
    if context.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(enc);
    if !ret.is_null() {
        let fresh36 = &mut ((*ret).context);
        *fresh36 = context;
        let fresh37 = &mut ((*ret).readcallback);
        *fresh37 = xmlInputCallbackTable[i as usize].readcallback;
        let fresh38 = &mut ((*ret).closecallback);
        *fresh38 = xmlInputCallbackTable[i as usize].closecallback;
        if xmlInputCallbackTable[i as usize].opencallback
            == Some(
                xmlGzfileOpen
                    as unsafe extern "C" fn(*const i8) -> *mut libc::c_void,
            )
            && strcmp(URI, b"-\0" as *const u8 as *const i8)
                != 0 as i32
        {
            (*ret).compressed = (gzdirect(context as gzFile) == 0) as i32;
        }
    } else {
        (xmlInputCallbackTable[i as usize].closecallback)
            .expect("non-null function pointer")(context);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateFilename(
    mut URI: *const i8,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    if (*__xmlParserInputBufferCreateFilenameValue()).is_some() {
        return (*__xmlParserInputBufferCreateFilenameValue())
            .expect("non-null function pointer")(URI, enc);
    }
    return __xmlParserInputBufferCreateFilename(URI, enc);
}
#[no_mangle]
pub unsafe extern "C" fn __xmlOutputBufferCreateFilename(
    mut URI: *const i8,
    mut encoder: xmlCharEncodingHandlerPtr,
    mut compression: i32,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut puri: xmlURIPtr = 0 as *mut xmlURI;
    let mut i: i32 = 0 as i32;
    let mut context: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut unescaped: *mut i8 = 0 as *mut i8;
    let mut is_file_uri: i32 = 1 as i32;
    if xmlOutputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultOutputCallbacks();
    }
    if URI.is_null() {
        return 0 as xmlOutputBufferPtr;
    }
    puri = xmlParseURI(URI);
    if !puri.is_null() {
        if !((*puri).scheme).is_null()
            && xmlStrEqual(
                (*puri).scheme as *mut xmlChar,
                b"file\0" as *const u8 as *const i8 as *mut xmlChar,
            ) == 0
        {
            is_file_uri = 0 as i32;
        }
        if ((*puri).scheme).is_null()
            || xmlStrEqual(
                (*puri).scheme as *mut xmlChar,
                b"file\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
        {
            unescaped = xmlURIUnescapeString(
                URI,
                0 as i32,
                0 as *mut i8,
            );
        }
        xmlFreeURI(puri);
    }
    if !unescaped.is_null() {
        if compression > 0 as i32 && compression <= 9 as i32
            && is_file_uri == 1 as i32
        {
            context = xmlGzfileOpenW(unescaped, compression);
            if !context.is_null() {
                ret = xmlAllocOutputBufferInternal(encoder);
                if !ret.is_null() {
                    let fresh39 = &mut ((*ret).context);
                    *fresh39 = context;
                    let fresh40 = &mut ((*ret).writecallback);
                    *fresh40 = Some(
                        xmlGzfileWrite
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                *const i8,
                                i32,
                            ) -> i32,
                    );
                    let fresh41 = &mut ((*ret).closecallback);
                    *fresh41 = Some(
                        xmlGzfileClose
                            as unsafe extern "C" fn(*mut libc::c_void) -> i32,
                    );
                }
                xmlFree
                    .expect("non-null function pointer")(unescaped as *mut libc::c_void);
                return ret;
            }
        }
        i = xmlOutputCallbackNr - 1 as i32;
        while i >= 0 as i32 {
            if (xmlOutputCallbackTable[i as usize].matchcallback).is_some()
                && (xmlOutputCallbackTable[i as usize].matchcallback)
                    .expect("non-null function pointer")(unescaped) != 0 as i32
            {
                if xmlOutputCallbackTable[i as usize].matchcallback
                    == Some(
                        xmlIOHTTPMatch
                            as unsafe extern "C" fn(*const i8) -> i32,
                    )
                {
                    context = xmlIOHTTPOpenW(unescaped, compression);
                } else {
                    context = (xmlOutputCallbackTable[i as usize].opencallback)
                        .expect("non-null function pointer")(unescaped);
                }
                if !context.is_null() {
                    break;
                }
            }
            i -= 1;
        }
        xmlFree.expect("non-null function pointer")(unescaped as *mut libc::c_void);
    }
    if context.is_null() {
        if compression > 0 as i32 && compression <= 9 as i32
            && is_file_uri == 1 as i32
        {
            context = xmlGzfileOpenW(URI, compression);
            if !context.is_null() {
                ret = xmlAllocOutputBufferInternal(encoder);
                if !ret.is_null() {
                    let fresh42 = &mut ((*ret).context);
                    *fresh42 = context;
                    let fresh43 = &mut ((*ret).writecallback);
                    *fresh43 = Some(
                        xmlGzfileWrite
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                *const i8,
                                i32,
                            ) -> i32,
                    );
                    let fresh44 = &mut ((*ret).closecallback);
                    *fresh44 = Some(
                        xmlGzfileClose
                            as unsafe extern "C" fn(*mut libc::c_void) -> i32,
                    );
                } else {
                    xmlGzfileClose(context);
                }
                return ret;
            }
        }
        i = xmlOutputCallbackNr - 1 as i32;
        while i >= 0 as i32 {
            if (xmlOutputCallbackTable[i as usize].matchcallback).is_some()
                && (xmlOutputCallbackTable[i as usize].matchcallback)
                    .expect("non-null function pointer")(URI) != 0 as i32
            {
                if xmlOutputCallbackTable[i as usize].matchcallback
                    == Some(
                        xmlIOHTTPMatch
                            as unsafe extern "C" fn(*const i8) -> i32,
                    )
                {
                    context = xmlIOHTTPOpenW(URI, compression);
                } else {
                    context = (xmlOutputCallbackTable[i as usize].opencallback)
                        .expect("non-null function pointer")(URI);
                }
                if !context.is_null() {
                    break;
                }
            }
            i -= 1;
        }
    }
    if context.is_null() {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlAllocOutputBufferInternal(encoder);
    if !ret.is_null() {
        let fresh45 = &mut ((*ret).context);
        *fresh45 = context;
        let fresh46 = &mut ((*ret).writecallback);
        *fresh46 = xmlOutputCallbackTable[i as usize].writecallback;
        let fresh47 = &mut ((*ret).closecallback);
        *fresh47 = xmlOutputCallbackTable[i as usize].closecallback;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateFilename(
    mut URI: *const i8,
    mut encoder: xmlCharEncodingHandlerPtr,
    mut compression: i32,
) -> xmlOutputBufferPtr {
    if (*__xmlOutputBufferCreateFilenameValue()).is_some() {
        return (*__xmlOutputBufferCreateFilenameValue())
            .expect("non-null function pointer")(URI, encoder, compression);
    }
    return __xmlOutputBufferCreateFilename(URI, encoder, compression);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateFile(
    mut file: *mut FILE,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if xmlInputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultInputCallbacks();
    }
    if file.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(enc);
    if !ret.is_null() {
        let fresh48 = &mut ((*ret).context);
        *fresh48 = file as *mut libc::c_void;
        let fresh49 = &mut ((*ret).readcallback);
        *fresh49 = Some(
            xmlFileRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        );
        let fresh50 = &mut ((*ret).closecallback);
        *fresh50 = Some(
            xmlFileFlush as unsafe extern "C" fn(*mut libc::c_void) -> i32,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateFile(
    mut file: *mut FILE,
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if xmlOutputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultOutputCallbacks();
    }
    if file.is_null() {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlAllocOutputBufferInternal(encoder);
    if !ret.is_null() {
        let fresh51 = &mut ((*ret).context);
        *fresh51 = file as *mut libc::c_void;
        let fresh52 = &mut ((*ret).writecallback);
        *fresh52 = Some(
            xmlFileWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        );
        let fresh53 = &mut ((*ret).closecallback);
        *fresh53 = Some(
            xmlFileFlush as unsafe extern "C" fn(*mut libc::c_void) -> i32,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateBuffer(
    mut buffer: xmlBufferPtr,
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if buffer.is_null() {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlOutputBufferCreateIO(
        Some(
            xmlBufferWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        ),
        None,
        buffer as *mut libc::c_void,
        encoder,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferGetContent(
    mut out: xmlOutputBufferPtr,
) -> *const xmlChar {
    if out.is_null() || ((*out).buffer).is_null() {
        return 0 as *const xmlChar;
    }
    return xmlBufContent((*out).buffer as *const xmlBuf);
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferGetSize(mut out: xmlOutputBufferPtr) -> size_t {
    if out.is_null() || ((*out).buffer).is_null() {
        return 0 as i32 as size_t;
    }
    return xmlBufUse((*out).buffer);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateFd(
    mut fd: i32,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if fd < 0 as i32 {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(enc);
    if !ret.is_null() {
        let fresh54 = &mut ((*ret).context);
        *fresh54 = fd as ptrdiff_t as *mut libc::c_void;
        let fresh55 = &mut ((*ret).readcallback);
        *fresh55 = Some(
            xmlFdRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        );
        let fresh56 = &mut ((*ret).closecallback);
        *fresh56 = Some(
            xmlFdClose as unsafe extern "C" fn(*mut libc::c_void) -> i32,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateMem(
    mut mem: *const i8,
    mut size: i32,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut errcode: i32 = 0;
    if size < 0 as i32 {
        return 0 as xmlParserInputBufferPtr;
    }
    if mem.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(enc);
    if !ret.is_null() {
        let fresh57 = &mut ((*ret).context);
        *fresh57 = mem as *mut libc::c_void;
        let fresh58 = &mut ((*ret).readcallback);
        *fresh58 = Some(
            xmlInputReadCallbackNop
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut i8,
                    i32,
                ) -> i32,
        );
        let fresh59 = &mut ((*ret).closecallback);
        *fresh59 = None;
        errcode = xmlBufAdd((*ret).buffer, mem as *const xmlChar, size);
        if errcode != 0 as i32 {
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlParserInputBufferPtr;
        }
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateStatic(
    mut mem: *const i8,
    mut size: i32,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if size < 0 as i32 {
        return 0 as xmlParserInputBufferPtr;
    }
    if mem.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlParserInputBuffer>() as u64)
        as xmlParserInputBufferPtr;
    if ret.is_null() {
        xmlIOErrMemory(b"creating input buffer\0" as *const u8 as *const i8);
        return 0 as xmlParserInputBufferPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlParserInputBuffer>() as u64,
    );
    let fresh60 = &mut ((*ret).buffer);
    *fresh60 = xmlBufCreateStatic(mem as *mut libc::c_void, size as size_t);
    if ((*ret).buffer).is_null() {
        xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
        return 0 as xmlParserInputBufferPtr;
    }
    let fresh61 = &mut ((*ret).encoder);
    *fresh61 = xmlGetCharEncodingHandler(enc);
    if !((*ret).encoder).is_null() {
        let fresh62 = &mut ((*ret).raw);
        *fresh62 = xmlBufCreateSize(
            (2 as i32 * *__xmlDefaultBufferSize()) as size_t,
        );
    } else {
        let fresh63 = &mut ((*ret).raw);
        *fresh63 = 0 as xmlBufPtr;
    }
    (*ret).compressed = -(1 as i32);
    let fresh64 = &mut ((*ret).context);
    *fresh64 = mem as *mut libc::c_void;
    let fresh65 = &mut ((*ret).readcallback);
    *fresh65 = None;
    let fresh66 = &mut ((*ret).closecallback);
    *fresh66 = None;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateFd(
    mut fd: i32,
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if fd < 0 as i32 {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlAllocOutputBufferInternal(encoder);
    if !ret.is_null() {
        let fresh67 = &mut ((*ret).context);
        *fresh67 = fd as ptrdiff_t as *mut libc::c_void;
        let fresh68 = &mut ((*ret).writecallback);
        *fresh68 = Some(
            xmlFdWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const i8,
                    i32,
                ) -> i32,
        );
        let fresh69 = &mut ((*ret).closecallback);
        *fresh69 = None;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateIO(
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut enc: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(enc);
    if !ret.is_null() {
        let fresh70 = &mut ((*ret).context);
        *fresh70 = ioctx;
        let fresh71 = &mut ((*ret).readcallback);
        *fresh71 = ioread;
        let fresh72 = &mut ((*ret).closecallback);
        *fresh72 = ioclose;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateIO(
    mut iowrite: xmlOutputWriteCallback,
    mut ioclose: xmlOutputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if iowrite.is_none() {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlAllocOutputBufferInternal(encoder);
    if !ret.is_null() {
        let fresh73 = &mut ((*ret).context);
        *fresh73 = ioctx;
        let fresh74 = &mut ((*ret).writecallback);
        *fresh74 = iowrite;
        let fresh75 = &mut ((*ret).closecallback);
        *fresh75 = ioclose;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferCreateFilenameDefault(
    mut func: xmlParserInputBufferCreateFilenameFunc,
) -> xmlParserInputBufferCreateFilenameFunc {
    let mut old: xmlParserInputBufferCreateFilenameFunc = *__xmlParserInputBufferCreateFilenameValue();
    if old.is_none() {
        old = Some(
            __xmlParserInputBufferCreateFilename
                as unsafe extern "C" fn(
                    *const i8,
                    xmlCharEncoding,
                ) -> xmlParserInputBufferPtr,
        );
    }
    let fresh76 = &mut (*__xmlParserInputBufferCreateFilenameValue());
    *fresh76 = func;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferCreateFilenameDefault(
    mut func: xmlOutputBufferCreateFilenameFunc,
) -> xmlOutputBufferCreateFilenameFunc {
    let mut old: xmlOutputBufferCreateFilenameFunc = *__xmlOutputBufferCreateFilenameValue();
    if old.is_none() {
        old = Some(
            __xmlOutputBufferCreateFilename
                as unsafe extern "C" fn(
                    *const i8,
                    xmlCharEncodingHandlerPtr,
                    i32,
                ) -> xmlOutputBufferPtr,
        );
    }
    let fresh77 = &mut (*__xmlOutputBufferCreateFilenameValue());
    *fresh77 = func;
    return old;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferPush(
    mut in_0: xmlParserInputBufferPtr,
    mut len: i32,
    mut buf: *const i8,
) -> i32 {
    let mut nbchars: i32 = 0 as i32;
    let mut ret: i32 = 0;
    if len < 0 as i32 {
        return 0 as i32;
    }
    if in_0.is_null() || (*in_0).error != 0 {
        return -(1 as i32);
    }
    if !((*in_0).encoder).is_null() {
        let mut use_0: u32 = 0;
        if ((*in_0).raw).is_null() {
            let fresh78 = &mut ((*in_0).raw);
            *fresh78 = xmlBufCreate();
        }
        ret = xmlBufAdd((*in_0).raw, buf as *const xmlChar, len);
        if ret != 0 as i32 {
            return -(1 as i32);
        }
        use_0 = xmlBufUse((*in_0).raw) as u32;
        nbchars = xmlCharEncInput(in_0, 1 as i32);
        if nbchars < 0 as i32 {
            xmlIOErr(XML_IO_ENCODER as i32, 0 as *const i8);
            (*in_0).error = XML_IO_ENCODER as i32;
            return -(1 as i32);
        }
        let fresh79 = &mut ((*in_0).rawconsumed);
        *fresh79 = (*fresh79)
            .wrapping_add((use_0 as u64).wrapping_sub(xmlBufUse((*in_0).raw)));
    } else {
        nbchars = len;
        ret = xmlBufAdd((*in_0).buffer, buf as *mut xmlChar, nbchars);
        if ret != 0 as i32 {
            return -(1 as i32);
        }
    }
    return nbchars;
}
 extern "C" fn endOfInput(
    mut context: *mut libc::c_void,
    mut buffer: *mut i8,
    mut len: i32,
) -> i32 {
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferGrow(
    mut in_0: xmlParserInputBufferPtr,
    mut len: i32,
) -> i32 {
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut res: i32 = 0 as i32;
    let mut nbchars: i32 = 0 as i32;
    if in_0.is_null() || (*in_0).error != 0 {
        return -(1 as i32);
    }
    if len <= 4000 as i32 && len != 4 as i32 {
        len = 4000 as i32;
    }
    if xmlBufAvail((*in_0).buffer) <= 0 as i32 as u64 {
        xmlIOErr(XML_IO_BUFFER_FULL as i32, 0 as *const i8);
        (*in_0).error = XML_IO_BUFFER_FULL as i32;
        return -(1 as i32);
    }
    if xmlBufGrow((*in_0).buffer, len + 1 as i32) < 0 as i32 {
        xmlIOErrMemory(b"growing input buffer\0" as *const u8 as *const i8);
        (*in_0).error = XML_ERR_NO_MEMORY as i32;
        return -(1 as i32);
    }
    buffer = xmlBufEnd((*in_0).buffer) as *mut i8;
    if ((*in_0).readcallback).is_some() {
        res = ((*in_0).readcallback)
            .expect(
                "non-null function pointer",
            )((*in_0).context, &mut *buffer.offset(0 as i32 as isize), len);
        if res <= 0 as i32 {
            let fresh80 = &mut ((*in_0).readcallback);
            *fresh80 = Some(
                endOfInput
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut i8,
                        i32,
                    ) -> i32,
            );
        }
    } else {
        xmlIOErr(XML_IO_NO_INPUT as i32, 0 as *const i8);
        (*in_0).error = XML_IO_NO_INPUT as i32;
        return -(1 as i32);
    }
    if res < 0 as i32 {
        return -(1 as i32);
    }
    (*in_0).compressed == -(1 as i32);
    len = res;
    if !((*in_0).encoder).is_null() {
        let mut use_0: u32 = 0;
        if ((*in_0).raw).is_null() {
            let fresh81 = &mut ((*in_0).raw);
            *fresh81 = xmlBufCreate();
        }
        res = xmlBufAdd((*in_0).raw, buffer as *const xmlChar, len);
        if res != 0 as i32 {
            return -(1 as i32);
        }
        use_0 = xmlBufUse((*in_0).raw) as u32;
        nbchars = xmlCharEncInput(in_0, 1 as i32);
        if nbchars < 0 as i32 {
            xmlIOErr(XML_IO_ENCODER as i32, 0 as *const i8);
            (*in_0).error = XML_IO_ENCODER as i32;
            return -(1 as i32);
        }
        let fresh82 = &mut ((*in_0).rawconsumed);
        *fresh82 = (*fresh82)
            .wrapping_add((use_0 as u64).wrapping_sub(xmlBufUse((*in_0).raw)));
    } else {
        nbchars = len;
        xmlBufAddLen((*in_0).buffer, nbchars as size_t);
    }
    return nbchars;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserInputBufferRead(
    mut in_0: xmlParserInputBufferPtr,
    mut len: i32,
) -> i32 {
    if in_0.is_null() || (*in_0).error != 0 {
        return -(1 as i32);
    }
    if ((*in_0).readcallback).is_some() {
        return xmlParserInputBufferGrow(in_0, len)
    } else if xmlBufGetAllocationScheme((*in_0).buffer)
            == XML_BUFFER_ALLOC_IMMUTABLE as i32
        {
        return 0 as i32
    } else {
        return -(1 as i32)
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferWrite(
    mut out: xmlOutputBufferPtr,
    mut len: i32,
    mut buf: *const i8,
) -> i32 {
    let mut nbchars: i32 = 0 as i32;
    let mut ret: i32 = 0;
    let mut written: i32 = 0 as i32;
    let mut chunk: i32 = 0;
    if out.is_null() || (*out).error != 0 {
        return -(1 as i32);
    }
    if len < 0 as i32 {
        return 0 as i32;
    }
    if (*out).error != 0 {
        return -(1 as i32);
    }
    loop {
        chunk = len;
        if chunk > 4 as i32 * 4000 as i32 {
            chunk = 4 as i32 * 4000 as i32;
        }
        if !((*out).encoder).is_null() {
            if ((*out).conv).is_null() {
                let fresh83 = &mut ((*out).conv);
                *fresh83 = xmlBufCreate();
            }
            ret = xmlBufAdd((*out).buffer, buf as *const xmlChar, chunk);
            if ret != 0 as i32 {
                return -(1 as i32);
            }
            if xmlBufUse((*out).buffer) < 4000 as i32 as u64
                && chunk == len
            {
                break;
            }
            ret = xmlCharEncOutput(out, 0 as i32);
            if ret < 0 as i32 && ret != -(3 as i32) {
                xmlIOErr(XML_IO_ENCODER as i32, 0 as *const i8);
                (*out).error = XML_IO_ENCODER as i32;
                return -(1 as i32);
            }
            if ((*out).writecallback).is_some() {
                nbchars = xmlBufUse((*out).conv) as i32;
            } else {
                nbchars = if ret >= 0 as i32 { ret } else { 0 as i32 };
            }
        } else {
            ret = xmlBufAdd((*out).buffer, buf as *const xmlChar, chunk);
            if ret != 0 as i32 {
                return -(1 as i32);
            }
            if ((*out).writecallback).is_some() {
                nbchars = xmlBufUse((*out).buffer) as i32;
            } else {
                nbchars = chunk;
            }
        }
        buf = buf.offset(chunk as isize);
        len -= chunk;
        if ((*out).writecallback).is_some() {
            if nbchars < 4000 as i32 && len <= 0 as i32 {
                break;
            }
            if !((*out).encoder).is_null() {
                ret = ((*out).writecallback)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*out).context,
                    xmlBufContent((*out).conv as *const xmlBuf) as *const i8,
                    nbchars,
                );
                if ret >= 0 as i32 {
                    xmlBufShrink((*out).conv, ret as size_t);
                }
            } else {
                ret = ((*out).writecallback)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*out).context,
                    xmlBufContent((*out).buffer as *const xmlBuf) as *const i8,
                    nbchars,
                );
                if ret >= 0 as i32 {
                    xmlBufShrink((*out).buffer, ret as size_t);
                }
            }
            if ret < 0 as i32 {
                xmlIOErr(XML_IO_WRITE as i32, 0 as *const i8);
                (*out).error = XML_IO_WRITE as i32;
                return ret;
            }
            if (*out).written > 2147483647 as i32 - ret {
                (*out).written = 2147483647 as i32;
            } else {
                (*out).written += ret;
            }
        }
        written += nbchars;
        if !(len > 0 as i32) {
            break;
        }
    }
    return written;
}
unsafe extern "C" fn xmlEscapeContent(
    mut out: *mut u8,
    mut outlen: *mut i32,
    mut in_0: *const xmlChar,
    mut inlen: *mut i32,
) -> i32 {
    let mut outstart: *mut u8 = out;
    let mut base: *const u8 = in_0;
    let mut outend: *mut u8 = out.offset(*outlen as isize);
    let mut inend: *const u8 = 0 as *const u8;
    inend = in_0.offset(*inlen as isize);
    while in_0 < inend && out < outend {
        if *in_0 as i32 == '<' as i32 {
            if (outend.offset_from(out) as i64)
                < 4 as i32 as i64
            {
                break;
            }
            let fresh84 = out;
            out = out.offset(1);
            *fresh84 = '&' as i32 as u8;
            let fresh85 = out;
            out = out.offset(1);
            *fresh85 = 'l' as i32 as u8;
            let fresh86 = out;
            out = out.offset(1);
            *fresh86 = 't' as i32 as u8;
            let fresh87 = out;
            out = out.offset(1);
            *fresh87 = ';' as i32 as u8;
        } else if *in_0 as i32 == '>' as i32 {
            if (outend.offset_from(out) as i64)
                < 4 as i32 as i64
            {
                break;
            }
            let fresh88 = out;
            out = out.offset(1);
            *fresh88 = '&' as i32 as u8;
            let fresh89 = out;
            out = out.offset(1);
            *fresh89 = 'g' as i32 as u8;
            let fresh90 = out;
            out = out.offset(1);
            *fresh90 = 't' as i32 as u8;
            let fresh91 = out;
            out = out.offset(1);
            *fresh91 = ';' as i32 as u8;
        } else if *in_0 as i32 == '&' as i32 {
            if (outend.offset_from(out) as i64)
                < 5 as i32 as i64
            {
                break;
            }
            let fresh92 = out;
            out = out.offset(1);
            *fresh92 = '&' as i32 as u8;
            let fresh93 = out;
            out = out.offset(1);
            *fresh93 = 'a' as i32 as u8;
            let fresh94 = out;
            out = out.offset(1);
            *fresh94 = 'm' as i32 as u8;
            let fresh95 = out;
            out = out.offset(1);
            *fresh95 = 'p' as i32 as u8;
            let fresh96 = out;
            out = out.offset(1);
            *fresh96 = ';' as i32 as u8;
        } else if *in_0 as i32 == '\r' as i32 {
            if (outend.offset_from(out) as i64)
                < 5 as i32 as i64
            {
                break;
            }
            let fresh97 = out;
            out = out.offset(1);
            *fresh97 = '&' as i32 as u8;
            let fresh98 = out;
            out = out.offset(1);
            *fresh98 = '#' as i32 as u8;
            let fresh99 = out;
            out = out.offset(1);
            *fresh99 = '1' as i32 as u8;
            let fresh100 = out;
            out = out.offset(1);
            *fresh100 = '3' as i32 as u8;
            let fresh101 = out;
            out = out.offset(1);
            *fresh101 = ';' as i32 as u8;
        } else {
            let fresh102 = out;
            out = out.offset(1);
            *fresh102 = *in_0;
        }
        in_0 = in_0.offset(1);
    }
    *outlen = out.offset_from(outstart) as i64 as i32;
    *inlen = in_0.offset_from(base) as i64 as i32;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferWriteEscape(
    mut out: xmlOutputBufferPtr,
    mut str: *const xmlChar,
    mut escaping: xmlCharEncodingOutputFunc,
) -> i32 {
    let mut nbchars: i32 = 0 as i32;
    let mut ret: i32 = 0;
    let mut written: i32 = 0 as i32;
    let mut oldwritten: i32 = 0 as i32;
    let mut chunk: i32 = 0;
    let mut len: i32 = 0;
    let mut cons: i32 = 0;
    if out.is_null() || (*out).error != 0 || str.is_null() || ((*out).buffer).is_null()
        || xmlBufGetAllocationScheme((*out).buffer)
            == XML_BUFFER_ALLOC_IMMUTABLE as i32
    {
        return -(1 as i32);
    }
    len = strlen(str as *const i8) as i32;
    if len < 0 as i32 {
        return 0 as i32;
    }
    if (*out).error != 0 {
        return -(1 as i32);
    }
    if escaping.is_none() {
        escaping = Some(
            xmlEscapeContent
                as unsafe extern "C" fn(
                    *mut u8,
                    *mut i32,
                    *const xmlChar,
                    *mut i32,
                ) -> i32,
        );
    }
    loop {
        oldwritten = written;
        cons = len;
        chunk = xmlBufAvail((*out).buffer) as i32;
        if chunk < 40 as i32 {
            if xmlBufGrow((*out).buffer, 100 as i32) < 0 as i32 {
                return -(1 as i32);
            }
            oldwritten = -(1 as i32);
        } else {
            if !((*out).encoder).is_null() {
                if ((*out).conv).is_null() {
                    let fresh103 = &mut ((*out).conv);
                    *fresh103 = xmlBufCreate();
                }
                ret = escaping
                    .expect(
                        "non-null function pointer",
                    )(xmlBufEnd((*out).buffer), &mut chunk, str, &mut cons);
                if ret < 0 as i32 || chunk == 0 as i32 {
                    return -(1 as i32);
                }
                xmlBufAddLen((*out).buffer, chunk as size_t);
                if xmlBufUse((*out).buffer) < 4000 as i32 as u64
                    && cons == len
                {
                    break;
                }
                ret = xmlCharEncOutput(out, 0 as i32);
                if ret < 0 as i32 && ret != -(3 as i32) {
                    xmlIOErr(XML_IO_ENCODER as i32, 0 as *const i8);
                    (*out).error = XML_IO_ENCODER as i32;
                    return -(1 as i32);
                }
                if ((*out).writecallback).is_some() {
                    nbchars = xmlBufUse((*out).conv) as i32;
                } else {
                    nbchars = if ret >= 0 as i32 {
                        ret
                    } else {
                        0 as i32
                    };
                }
            } else {
                ret = escaping
                    .expect(
                        "non-null function pointer",
                    )(xmlBufEnd((*out).buffer), &mut chunk, str, &mut cons);
                if ret < 0 as i32 || chunk == 0 as i32 {
                    return -(1 as i32);
                }
                xmlBufAddLen((*out).buffer, chunk as size_t);
                if ((*out).writecallback).is_some() {
                    nbchars = xmlBufUse((*out).buffer) as i32;
                } else {
                    nbchars = chunk;
                }
            }
            str = str.offset(cons as isize);
            len -= cons;
            if ((*out).writecallback).is_some() {
                if nbchars < 4000 as i32 && len <= 0 as i32 {
                    break;
                }
                if !((*out).encoder).is_null() {
                    ret = ((*out).writecallback)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*out).context,
                        xmlBufContent((*out).conv as *const xmlBuf)
                            as *const i8,
                        nbchars,
                    );
                    if ret >= 0 as i32 {
                        xmlBufShrink((*out).conv, ret as size_t);
                    }
                } else {
                    ret = ((*out).writecallback)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*out).context,
                        xmlBufContent((*out).buffer as *const xmlBuf)
                            as *const i8,
                        nbchars,
                    );
                    if ret >= 0 as i32 {
                        xmlBufShrink((*out).buffer, ret as size_t);
                    }
                }
                if ret < 0 as i32 {
                    xmlIOErr(XML_IO_WRITE as i32, 0 as *const i8);
                    (*out).error = XML_IO_WRITE as i32;
                    return ret;
                }
                if (*out).written > 2147483647 as i32 - ret {
                    (*out).written = 2147483647 as i32;
                } else {
                    (*out).written += ret;
                }
            } else if xmlBufAvail((*out).buffer) < 4000 as i32 as u64 {
                xmlBufGrow((*out).buffer, 4000 as i32);
            }
            written += nbchars;
        }
        if !(len > 0 as i32 && oldwritten != written) {
            break;
        }
    }
    return written;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferWriteString(
    mut out: xmlOutputBufferPtr,
    mut str: *const i8,
) -> i32 {
    let mut len: i32 = 0;
    if out.is_null() || (*out).error != 0 {
        return -(1 as i32);
    }
    if str.is_null() {
        return -(1 as i32);
    }
    len = strlen(str) as i32;
    if len > 0 as i32 {
        return xmlOutputBufferWrite(out, len, str);
    }
    return len;
}
#[no_mangle]
pub unsafe extern "C" fn xmlOutputBufferFlush(
    mut out: xmlOutputBufferPtr,
) -> i32 {
    let mut nbchars: i32 = 0 as i32;
    let mut ret: i32 = 0 as i32;
    if out.is_null() || (*out).error != 0 {
        return -(1 as i32);
    }
    if !((*out).conv).is_null() && !((*out).encoder).is_null() {
        loop {
            nbchars = xmlCharEncOutput(out, 0 as i32);
            if nbchars < 0 as i32 {
                xmlIOErr(XML_IO_ENCODER as i32, 0 as *const i8);
                (*out).error = XML_IO_ENCODER as i32;
                return -(1 as i32);
            }
            if !(nbchars != 0) {
                break;
            }
        }
    }
    if !((*out).conv).is_null() && !((*out).encoder).is_null()
        && ((*out).writecallback).is_some()
    {
        ret = ((*out).writecallback)
            .expect(
                "non-null function pointer",
            )(
            (*out).context,
            xmlBufContent((*out).conv as *const xmlBuf) as *const i8,
            xmlBufUse((*out).conv) as i32,
        );
        if ret >= 0 as i32 {
            xmlBufShrink((*out).conv, ret as size_t);
        }
    } else if ((*out).writecallback).is_some() {
        ret = ((*out).writecallback)
            .expect(
                "non-null function pointer",
            )(
            (*out).context,
            xmlBufContent((*out).buffer as *const xmlBuf) as *const i8,
            xmlBufUse((*out).buffer) as i32,
        );
        if ret >= 0 as i32 {
            xmlBufShrink((*out).buffer, ret as size_t);
        }
    }
    if ret < 0 as i32 {
        xmlIOErr(XML_IO_FLUSH as i32, 0 as *const i8);
        (*out).error = XML_IO_FLUSH as i32;
        return ret;
    }
    if (*out).written > 2147483647 as i32 - ret {
        (*out).written = 2147483647 as i32;
    } else {
        (*out).written += ret;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserGetDirectory(
    mut filename: *const i8,
) -> *mut i8 {
    let mut ret: *mut i8 = 0 as *mut i8;
    let mut dir: [i8; 1024] = [0; 1024];
    let mut cur: *mut i8 = 0 as *mut i8;
    if xmlInputCallbackInitialized == 0 as i32 {
        xmlRegisterDefaultInputCallbacks();
    }
    if filename.is_null() {
        return 0 as *mut i8;
    }
    strncpy(dir.as_mut_ptr(), filename, 1023 as i32 as u64);
    dir[1023 as i32 as usize] = 0 as i32 as i8;
    cur = &mut *dir
        .as_mut_ptr()
        .offset(
            (strlen
                as unsafe extern "C" fn(
                    *const i8,
                ) -> u64)(dir.as_mut_ptr()) as isize,
        ) as *mut i8;
    while cur > dir.as_mut_ptr() {
        if *cur as i32 == '/' as i32 {
            break;
        }
        cur = cur.offset(-1);
    }
    if *cur as i32 == '/' as i32 {
        if cur == dir.as_mut_ptr() {
            dir[1 as i32 as usize] = 0 as i32 as i8;
        } else {
            *cur = 0 as i32 as i8;
        }
        ret = xmlMemStrdup.expect("non-null function pointer")(dir.as_mut_ptr());
    } else if !(getcwd(dir.as_mut_ptr(), 1024 as i32 as size_t)).is_null() {
        dir[1023 as i32 as usize] = 0 as i32 as i8;
        ret = xmlMemStrdup.expect("non-null function pointer")(dir.as_mut_ptr());
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckHTTPInput(
    mut ctxt: xmlParserCtxtPtr,
    mut ret: xmlParserInputPtr,
) -> xmlParserInputPtr {
    if !ret.is_null() && !((*ret).buf).is_null()
        && (*(*ret).buf).readcallback
            == Some(
                xmlIOHTTPRead
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut i8,
                        i32,
                    ) -> i32,
            ) && !((*(*ret).buf).context).is_null()
    {
        let mut encoding: *const i8 = 0 as *const i8;
        let mut redir: *const i8 = 0 as *const i8;
        let mut mime: *const i8 = 0 as *const i8;
        let mut code: i32 = 0;
        code = xmlNanoHTTPReturnCode((*(*ret).buf).context);
        if code >= 400 as i32 {
            if !((*ret).filename).is_null() {
                __xmlLoaderErr(
                    ctxt as *mut libc::c_void,
                    b"failed to load HTTP resource \"%s\"\n\0" as *const u8
                        as *const i8,
                    (*ret).filename,
                );
            } else {
                __xmlLoaderErr(
                    ctxt as *mut libc::c_void,
                    b"failed to load HTTP resource\n\0" as *const u8
                        as *const i8,
                    0 as *const i8,
                );
            }
            xmlFreeInputStream(ret);
            ret = 0 as xmlParserInputPtr;
        } else {
            mime = xmlNanoHTTPMimeType((*(*ret).buf).context);
            if !(xmlStrstr(
                mime as *mut xmlChar,
                b"/xml\0" as *const u8 as *const i8 as *mut xmlChar,
            ))
                .is_null()
                || !(xmlStrstr(
                    mime as *mut xmlChar,
                    b"+xml\0" as *const u8 as *const i8 as *mut xmlChar,
                ))
                    .is_null()
            {
                encoding = xmlNanoHTTPEncoding((*(*ret).buf).context);
                if !encoding.is_null() {
                    let mut handler: xmlCharEncodingHandlerPtr = 0
                        as *mut xmlCharEncodingHandler;
                    handler = xmlFindCharEncodingHandler(encoding);
                    if !handler.is_null() {
                        xmlSwitchInputEncoding(ctxt, ret, handler);
                    } else {
                        __xmlErrEncoding(
                            ctxt,
                            XML_ERR_UNKNOWN_ENCODING,
                            b"Unknown encoding %s\0" as *const u8 as *const i8,
                            encoding as *mut xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                    if ((*ret).encoding).is_null() {
                        let fresh104 = &mut ((*ret).encoding);
                        *fresh104 = xmlStrdup(encoding as *mut xmlChar);
                    }
                }
            }
            redir = xmlNanoHTTPRedir((*(*ret).buf).context);
            if !redir.is_null() {
                if !((*ret).filename).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*ret).filename as *mut xmlChar as *mut libc::c_void);
                }
                if !((*ret).directory).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*ret).directory as *mut xmlChar as *mut libc::c_void);
                    let fresh105 = &mut ((*ret).directory);
                    *fresh105 = 0 as *const i8;
                }
                let fresh106 = &mut ((*ret).filename);
                *fresh106 = xmlStrdup(redir as *const xmlChar) as *mut i8;
            }
        }
    }
    return ret;
}
unsafe extern "C" fn xmlNoNetExists(mut URL: *const i8) -> i32 {
    let mut path: *const i8 = 0 as *const i8;
    if URL.is_null() {
        return 0 as i32;
    }
    if xmlStrncasecmp(
        URL as *mut xmlChar,
        b"file://localhost/\0" as *const u8 as *const i8 as *mut xmlChar,
        17 as i32,
    ) == 0
    {
        path = &*URL.offset(16 as i32 as isize) as *const i8;
    } else if xmlStrncasecmp(
            URL as *mut xmlChar,
            b"file:///\0" as *const u8 as *const i8 as *mut xmlChar,
            8 as i32,
        ) == 0
        {
        path = &*URL.offset(7 as i32 as isize) as *const i8;
    } else {
        path = URL;
    }
    return xmlCheckFilename(path);
}
unsafe extern "C" fn xmlResolveResourceFromCatalog(
    mut URL: *const i8,
    mut ID: *const i8,
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    let mut resource: *mut xmlChar = 0 as *mut xmlChar;
    let mut pref: xmlCatalogAllow = XML_CATA_ALLOW_NONE;
    pref = xmlCatalogGetDefaults();
    if pref as u32 != XML_CATA_ALLOW_NONE as i32 as u32
        && xmlNoNetExists(URL) == 0
    {
        if !ctxt.is_null() && !((*ctxt).catalogs).is_null()
            && (pref as u32 == XML_CATA_ALLOW_ALL as i32 as u32
                || pref as u32
                    == XML_CATA_ALLOW_DOCUMENT as i32 as u32)
        {
            resource = xmlCatalogLocalResolve(
                (*ctxt).catalogs,
                ID as *const xmlChar,
                URL as *const xmlChar,
            );
        }
        if resource.is_null()
            && (pref as u32 == XML_CATA_ALLOW_ALL as i32 as u32
                || pref as u32
                    == XML_CATA_ALLOW_GLOBAL as i32 as u32)
        {
            resource = xmlCatalogResolve(ID as *const xmlChar, URL as *const xmlChar);
        }
        if resource.is_null() && !URL.is_null() {
            resource = xmlStrdup(URL as *const xmlChar);
        }
        if !resource.is_null() && xmlNoNetExists(resource as *const i8) == 0 {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if !ctxt.is_null() && !((*ctxt).catalogs).is_null()
                && (pref as u32
                    == XML_CATA_ALLOW_ALL as i32 as u32
                    || pref as u32
                        == XML_CATA_ALLOW_DOCUMENT as i32 as u32)
            {
                tmp = xmlCatalogLocalResolveURI((*ctxt).catalogs, resource);
            }
            if tmp.is_null()
                && (pref as u32
                    == XML_CATA_ALLOW_ALL as i32 as u32
                    || pref as u32
                        == XML_CATA_ALLOW_GLOBAL as i32 as u32)
            {
                tmp = xmlCatalogResolveURI(resource);
            }
            if !tmp.is_null() {
                xmlFree
                    .expect("non-null function pointer")(resource as *mut libc::c_void);
                resource = tmp;
            }
        }
    }
    return resource;
}
unsafe extern "C" fn xmlDefaultExternalEntityLoader(
    mut URL: *const i8,
    mut ID: *const i8,
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    let mut ret: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut resource: *mut xmlChar = 0 as *mut xmlChar;
    if !ctxt.is_null() && (*ctxt).options & XML_PARSE_NONET as i32 != 0 {
        let mut options: i32 = (*ctxt).options;
        (*ctxt).options -= XML_PARSE_NONET as i32;
        ret = xmlNoNetExternalEntityLoader(URL, ID, ctxt);
        (*ctxt).options = options;
        return ret;
    }
    resource = xmlResolveResourceFromCatalog(URL, ID, ctxt);
    if resource.is_null() {
        resource = URL as *mut xmlChar;
    }
    if resource.is_null() {
        if ID.is_null() {
            ID = b"NULL\0" as *const u8 as *const i8;
        }
        __xmlLoaderErr(
            ctxt as *mut libc::c_void,
            b"failed to load external entity \"%s\"\n\0" as *const u8
                as *const i8,
            ID,
        );
        return 0 as xmlParserInputPtr;
    }
    ret = xmlNewInputFromFile(ctxt, resource as *const i8);
    if !resource.is_null() && resource != URL as *mut xmlChar {
        xmlFree.expect("non-null function pointer")(resource as *mut libc::c_void);
    }
    return ret;
}
static mut xmlCurrentExternalEntityLoader: xmlExternalEntityLoader = unsafe {
    Some(
        xmlDefaultExternalEntityLoader
            as unsafe extern "C" fn(
                *const i8,
                *const i8,
                xmlParserCtxtPtr,
            ) -> xmlParserInputPtr,
    )
};
#[no_mangle]
pub unsafe extern "C" fn xmlSetExternalEntityLoader(mut f: xmlExternalEntityLoader) {
    xmlCurrentExternalEntityLoader = f;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetExternalEntityLoader() -> xmlExternalEntityLoader {
    return xmlCurrentExternalEntityLoader;
}
#[no_mangle]
pub unsafe extern "C" fn xmlLoadExternalEntity(
    mut URL: *const i8,
    mut ID: *const i8,
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    if !URL.is_null() && xmlNoNetExists(URL) == 0 as i32 {
        let mut canonicFilename: *mut i8 = 0 as *mut i8;
        let mut ret: xmlParserInputPtr = 0 as *mut xmlParserInput;
        canonicFilename = xmlCanonicPath(URL as *const xmlChar) as *mut i8;
        if canonicFilename.is_null() {
            xmlIOErrMemory(
                b"building canonical path\n\0" as *const u8 as *const i8,
            );
            return 0 as xmlParserInputPtr;
        }
        ret = xmlCurrentExternalEntityLoader
            .expect("non-null function pointer")(canonicFilename, ID, ctxt);
        xmlFree
            .expect("non-null function pointer")(canonicFilename as *mut libc::c_void);
        return ret;
    }
    return xmlCurrentExternalEntityLoader
        .expect("non-null function pointer")(URL, ID, ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNoNetExternalEntityLoader(
    mut URL: *const i8,
    mut ID: *const i8,
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    let mut input: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut resource: *mut xmlChar = 0 as *mut xmlChar;
    resource = xmlResolveResourceFromCatalog(URL, ID, ctxt);
    if resource.is_null() {
        resource = URL as *mut xmlChar;
    }
    if !resource.is_null() {
        if xmlStrncasecmp(
            resource,
            b"ftp://\0" as *const u8 as *const i8 as *mut xmlChar,
            6 as i32,
        ) == 0
            || xmlStrncasecmp(
                resource,
                b"http://\0" as *const u8 as *const i8 as *mut xmlChar,
                7 as i32,
            ) == 0
        {
            xmlIOErr(
                XML_IO_NETWORK_ATTEMPT as i32,
                resource as *const i8,
            );
            if resource != URL as *mut xmlChar {
                xmlFree
                    .expect("non-null function pointer")(resource as *mut libc::c_void);
            }
            return 0 as xmlParserInputPtr;
        }
    }
    input = xmlDefaultExternalEntityLoader(resource as *const i8, ID, ctxt);
    if resource != URL as *mut xmlChar {
        xmlFree.expect("non-null function pointer")(resource as *mut libc::c_void);
    }
    return input;
}
