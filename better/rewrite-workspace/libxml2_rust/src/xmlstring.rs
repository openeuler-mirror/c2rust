use ::libc;
extern "C" {
    
    
    
    
    
    
    
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    static mut xmlFree: xmlFreeFunc;
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    
}
pub use crate::src::parserInternals::xmlErrMemory;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::error::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::src::error::__va_list_tag;
pub use crate::src::error::va_list;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::xmlParserCtxtPtr;
pub use crate::src::HTMLparser::xmlParserCtxt;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserCtxt;
pub use crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNode;
pub use crate::src::HTMLparser::xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlDtd;
pub use crate::src::HTMLparser::xmlElementType;
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
pub use crate::src::HTMLparser::xmlNsType;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlAttr;
pub use crate::src::HTMLparser::xmlAttributeType;
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
pub use crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub use crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlError;
pub use crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub use crate::src::HTMLparser::xmlAttrPtr;
pub use crate::src::HTMLparser::xmlAttr;
pub use crate::src::HTMLparser::xmlNodePtr;
pub use crate::src::HTMLparser::xmlNode;
pub use crate::src::HTMLparser::xmlHashTablePtr;
pub use crate::src::HTMLparser::xmlHashTable;
pub use crate::src::HTMLparser::xmlStartTag;
pub use crate::src::HTMLparser::xmlDictPtr;
pub use crate::src::HTMLparser::xmlDict;
pub use crate::src::HTMLparser::xmlParserInputPtr;
pub use crate::src::HTMLparser::xmlParserInput;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputDeallocate;
pub use crate::src::HTMLparser::xmlParserInputBufferPtr;
pub use crate::src::HTMLparser::xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlBufPtr;
pub use crate::src::HTMLparser::xmlBuf;
pub use crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub use crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlCharEncodingHandler;
pub use crate::src::HTMLparser::iconv_t;
pub use crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub use crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub use crate::src::HTMLparser::xmlInputCloseCallback;
pub use crate::src::HTMLparser::xmlInputReadCallback;
pub use crate::src::HTMLparser::xmlParserInputState;
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
pub use crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlValidCtxt;
pub use crate::src::HTMLparser::xmlAutomataStatePtr;
pub use crate::src::HTMLparser::xmlAutomataState;
pub use crate::src::HTMLparser::xmlAutomataPtr;
pub use crate::src::HTMLparser::xmlAutomata;
pub use crate::src::HTMLparser::xmlValidState;
pub use crate::src::HTMLparser::xmlDocPtr;
pub use crate::src::HTMLparser::xmlDoc;
pub use crate::src::HTMLparser::xmlValidityWarningFunc;
pub use crate::src::HTMLparser::xmlValidityErrorFunc;
pub use crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXHandler;
pub use crate::src::HTMLparser::xmlStructuredErrorFunc;
pub use crate::src::HTMLparser::xmlErrorPtr;
pub use crate::src::HTMLparser::endElementNsSAX2Func;
pub use crate::src::HTMLparser::startElementNsSAX2Func;
pub use crate::src::HTMLparser::externalSubsetSAXFunc;
pub use crate::src::HTMLparser::cdataBlockSAXFunc;
pub use crate::src::HTMLparser::getParameterEntitySAXFunc;
pub use crate::src::HTMLparser::xmlEntityPtr;
pub use crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEntity;
pub use crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub use crate::src::HTMLparser::fatalErrorSAXFunc;
pub use crate::src::HTMLparser::errorSAXFunc;
pub use crate::src::HTMLparser::warningSAXFunc;
pub use crate::src::HTMLparser::commentSAXFunc;
pub use crate::src::HTMLparser::processingInstructionSAXFunc;
pub use crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub use crate::src::HTMLparser::charactersSAXFunc;
pub use crate::src::HTMLparser::referenceSAXFunc;
pub use crate::src::HTMLparser::endElementSAXFunc;
pub use crate::src::HTMLparser::startElementSAXFunc;
pub use crate::src::HTMLparser::endDocumentSAXFunc;
pub use crate::src::HTMLparser::startDocumentSAXFunc;
pub use crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub use crate::src::HTMLparser::xmlSAXLocatorPtr;
pub use crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlSAXLocator;
pub use crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub use crate::src::HTMLparser::elementDeclSAXFunc;
pub use crate::src::HTMLparser::xmlElementContentPtr;
pub use crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlElementContent;
pub use crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub use crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub use crate::src::HTMLparser::attributeDeclSAXFunc;
pub use crate::src::HTMLparser::xmlEnumerationPtr;
pub use crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlEnumeration;
pub use crate::src::HTMLparser::notationDeclSAXFunc;
pub use crate::src::HTMLparser::entityDeclSAXFunc;
pub use crate::src::HTMLparser::getEntitySAXFunc;
pub use crate::src::HTMLparser::resolveEntitySAXFunc;
pub use crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub use crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub use crate::src::HTMLparser::isStandaloneSAXFunc;
pub use crate::src::HTMLparser::internalSubsetSAXFunc;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::HTMLparser::xmlFreeFunc;
#[no_mangle]
pub unsafe extern "C" fn xmlStrndup(
    mut cur: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        cur as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset(len as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrdup(mut cur: *const xmlChar) -> *mut xmlChar {
    let mut p: *const xmlChar = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as libc::c_int != 0 as libc::c_int {
        p = p.offset(1);
    }
    return xmlStrndup(cur, p.offset_from(cur) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrndup(
    mut cur: *const libc::c_char,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < len {
        *ret.offset(i as isize) = *cur.offset(i as isize) as xmlChar;
        if *ret.offset(i as isize) as libc::c_int == 0 as libc::c_int {
            return ret;
        }
        i += 1;
    }
    *ret.offset(len as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrdup(mut cur: *const libc::c_char) -> *mut xmlChar {
    let mut p: *const libc::c_char = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as libc::c_int != '\u{0}' as i32 {
        p = p.offset(1);
    }
    return xmlCharStrndup(cur, p.offset_from(cur) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh0 = str1;
        str1 = str1.offset(1);
        let mut tmp: libc::c_int = *fresh0 as libc::c_int - *str2 as libc::c_int;
        if tmp != 0 as libc::c_int {
            return tmp;
        }
        let fresh1 = str2;
        str2 = str2.offset(1);
        if !(*fresh1 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrEqual(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    if str1 == str2 {
        return 1 as libc::c_int;
    }
    if str1.is_null() {
        return 0 as libc::c_int;
    }
    if str2.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        let fresh2 = str1;
        str1 = str1.offset(1);
        if *fresh2 as libc::c_int != *str2 as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh3 = str2;
        str2 = str2.offset(1);
        if !(*fresh3 != 0) {
            break;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrQEqual(
    mut pref: *const xmlChar,
    mut name: *const xmlChar,
    mut str: *const xmlChar,
) -> libc::c_int {
    if pref.is_null() {
        return xmlStrEqual(name, str);
    }
    if name.is_null() {
        return 0 as libc::c_int;
    }
    if str.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        let fresh4 = pref;
        pref = pref.offset(1);
        if *fresh4 as libc::c_int != *str as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh5 = str;
        str = str.offset(1);
        if !(*fresh5 as libc::c_int != 0 && *pref as libc::c_int != 0) {
            break;
        }
    }
    let fresh6 = str;
    str = str.offset(1);
    if *fresh6 as libc::c_int != ':' as i32 {
        return 0 as libc::c_int;
    }
    loop {
        let fresh7 = name;
        name = name.offset(1);
        if *fresh7 as libc::c_int != *str as libc::c_int {
            return 0 as libc::c_int;
        }
        let fresh8 = str;
        str = str.offset(1);
        if !(*fresh8 != 0) {
            break;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh9 = str1;
        str1 = str1.offset(1);
        let mut tmp: libc::c_int = *fresh9 as libc::c_int - *str2 as libc::c_int;
        if tmp != 0 as libc::c_int
            || {
                len -= 1;
                len == 0 as libc::c_int
            }
        {
            return tmp;
        }
        let fresh10 = str2;
        str2 = str2.offset(1);
        if !(*fresh10 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
static mut casemap: [xmlChar; 256] = [
    0 as libc::c_int as xmlChar,
    0x1 as libc::c_int as xmlChar,
    0x2 as libc::c_int as xmlChar,
    0x3 as libc::c_int as xmlChar,
    0x4 as libc::c_int as xmlChar,
    0x5 as libc::c_int as xmlChar,
    0x6 as libc::c_int as xmlChar,
    0x7 as libc::c_int as xmlChar,
    0x8 as libc::c_int as xmlChar,
    0x9 as libc::c_int as xmlChar,
    0xa as libc::c_int as xmlChar,
    0xb as libc::c_int as xmlChar,
    0xc as libc::c_int as xmlChar,
    0xd as libc::c_int as xmlChar,
    0xe as libc::c_int as xmlChar,
    0xf as libc::c_int as xmlChar,
    0x10 as libc::c_int as xmlChar,
    0x11 as libc::c_int as xmlChar,
    0x12 as libc::c_int as xmlChar,
    0x13 as libc::c_int as xmlChar,
    0x14 as libc::c_int as xmlChar,
    0x15 as libc::c_int as xmlChar,
    0x16 as libc::c_int as xmlChar,
    0x17 as libc::c_int as xmlChar,
    0x18 as libc::c_int as xmlChar,
    0x19 as libc::c_int as xmlChar,
    0x1a as libc::c_int as xmlChar,
    0x1b as libc::c_int as xmlChar,
    0x1c as libc::c_int as xmlChar,
    0x1d as libc::c_int as xmlChar,
    0x1e as libc::c_int as xmlChar,
    0x1f as libc::c_int as xmlChar,
    0x20 as libc::c_int as xmlChar,
    0x21 as libc::c_int as xmlChar,
    0x22 as libc::c_int as xmlChar,
    0x23 as libc::c_int as xmlChar,
    0x24 as libc::c_int as xmlChar,
    0x25 as libc::c_int as xmlChar,
    0x26 as libc::c_int as xmlChar,
    0x27 as libc::c_int as xmlChar,
    0x28 as libc::c_int as xmlChar,
    0x29 as libc::c_int as xmlChar,
    0x2a as libc::c_int as xmlChar,
    0x2b as libc::c_int as xmlChar,
    0x2c as libc::c_int as xmlChar,
    0x2d as libc::c_int as xmlChar,
    0x2e as libc::c_int as xmlChar,
    0x2f as libc::c_int as xmlChar,
    0x30 as libc::c_int as xmlChar,
    0x31 as libc::c_int as xmlChar,
    0x32 as libc::c_int as xmlChar,
    0x33 as libc::c_int as xmlChar,
    0x34 as libc::c_int as xmlChar,
    0x35 as libc::c_int as xmlChar,
    0x36 as libc::c_int as xmlChar,
    0x37 as libc::c_int as xmlChar,
    0x38 as libc::c_int as xmlChar,
    0x39 as libc::c_int as xmlChar,
    0x3a as libc::c_int as xmlChar,
    0x3b as libc::c_int as xmlChar,
    0x3c as libc::c_int as xmlChar,
    0x3d as libc::c_int as xmlChar,
    0x3e as libc::c_int as xmlChar,
    0x3f as libc::c_int as xmlChar,
    0x40 as libc::c_int as xmlChar,
    0x61 as libc::c_int as xmlChar,
    0x62 as libc::c_int as xmlChar,
    0x63 as libc::c_int as xmlChar,
    0x64 as libc::c_int as xmlChar,
    0x65 as libc::c_int as xmlChar,
    0x66 as libc::c_int as xmlChar,
    0x67 as libc::c_int as xmlChar,
    0x68 as libc::c_int as xmlChar,
    0x69 as libc::c_int as xmlChar,
    0x6a as libc::c_int as xmlChar,
    0x6b as libc::c_int as xmlChar,
    0x6c as libc::c_int as xmlChar,
    0x6d as libc::c_int as xmlChar,
    0x6e as libc::c_int as xmlChar,
    0x6f as libc::c_int as xmlChar,
    0x70 as libc::c_int as xmlChar,
    0x71 as libc::c_int as xmlChar,
    0x72 as libc::c_int as xmlChar,
    0x73 as libc::c_int as xmlChar,
    0x74 as libc::c_int as xmlChar,
    0x75 as libc::c_int as xmlChar,
    0x76 as libc::c_int as xmlChar,
    0x77 as libc::c_int as xmlChar,
    0x78 as libc::c_int as xmlChar,
    0x79 as libc::c_int as xmlChar,
    0x7a as libc::c_int as xmlChar,
    0x7b as libc::c_int as xmlChar,
    0x5c as libc::c_int as xmlChar,
    0x5d as libc::c_int as xmlChar,
    0x5e as libc::c_int as xmlChar,
    0x5f as libc::c_int as xmlChar,
    0x60 as libc::c_int as xmlChar,
    0x61 as libc::c_int as xmlChar,
    0x62 as libc::c_int as xmlChar,
    0x63 as libc::c_int as xmlChar,
    0x64 as libc::c_int as xmlChar,
    0x65 as libc::c_int as xmlChar,
    0x66 as libc::c_int as xmlChar,
    0x67 as libc::c_int as xmlChar,
    0x68 as libc::c_int as xmlChar,
    0x69 as libc::c_int as xmlChar,
    0x6a as libc::c_int as xmlChar,
    0x6b as libc::c_int as xmlChar,
    0x6c as libc::c_int as xmlChar,
    0x6d as libc::c_int as xmlChar,
    0x6e as libc::c_int as xmlChar,
    0x6f as libc::c_int as xmlChar,
    0x70 as libc::c_int as xmlChar,
    0x71 as libc::c_int as xmlChar,
    0x72 as libc::c_int as xmlChar,
    0x73 as libc::c_int as xmlChar,
    0x74 as libc::c_int as xmlChar,
    0x75 as libc::c_int as xmlChar,
    0x76 as libc::c_int as xmlChar,
    0x77 as libc::c_int as xmlChar,
    0x78 as libc::c_int as xmlChar,
    0x79 as libc::c_int as xmlChar,
    0x7a as libc::c_int as xmlChar,
    0x7b as libc::c_int as xmlChar,
    0x7c as libc::c_int as xmlChar,
    0x7d as libc::c_int as xmlChar,
    0x7e as libc::c_int as xmlChar,
    0x7f as libc::c_int as xmlChar,
    0x80 as libc::c_int as xmlChar,
    0x81 as libc::c_int as xmlChar,
    0x82 as libc::c_int as xmlChar,
    0x83 as libc::c_int as xmlChar,
    0x84 as libc::c_int as xmlChar,
    0x85 as libc::c_int as xmlChar,
    0x86 as libc::c_int as xmlChar,
    0x87 as libc::c_int as xmlChar,
    0x88 as libc::c_int as xmlChar,
    0x89 as libc::c_int as xmlChar,
    0x8a as libc::c_int as xmlChar,
    0x8b as libc::c_int as xmlChar,
    0x8c as libc::c_int as xmlChar,
    0x8d as libc::c_int as xmlChar,
    0x8e as libc::c_int as xmlChar,
    0x8f as libc::c_int as xmlChar,
    0x90 as libc::c_int as xmlChar,
    0x91 as libc::c_int as xmlChar,
    0x92 as libc::c_int as xmlChar,
    0x93 as libc::c_int as xmlChar,
    0x94 as libc::c_int as xmlChar,
    0x95 as libc::c_int as xmlChar,
    0x96 as libc::c_int as xmlChar,
    0x97 as libc::c_int as xmlChar,
    0x98 as libc::c_int as xmlChar,
    0x99 as libc::c_int as xmlChar,
    0x9a as libc::c_int as xmlChar,
    0x9b as libc::c_int as xmlChar,
    0x9c as libc::c_int as xmlChar,
    0x9d as libc::c_int as xmlChar,
    0x9e as libc::c_int as xmlChar,
    0x9f as libc::c_int as xmlChar,
    0xa0 as libc::c_int as xmlChar,
    0xa1 as libc::c_int as xmlChar,
    0xa2 as libc::c_int as xmlChar,
    0xa3 as libc::c_int as xmlChar,
    0xa4 as libc::c_int as xmlChar,
    0xa5 as libc::c_int as xmlChar,
    0xa6 as libc::c_int as xmlChar,
    0xa7 as libc::c_int as xmlChar,
    0xa8 as libc::c_int as xmlChar,
    0xa9 as libc::c_int as xmlChar,
    0xaa as libc::c_int as xmlChar,
    0xab as libc::c_int as xmlChar,
    0xac as libc::c_int as xmlChar,
    0xad as libc::c_int as xmlChar,
    0xae as libc::c_int as xmlChar,
    0xaf as libc::c_int as xmlChar,
    0xb0 as libc::c_int as xmlChar,
    0xb1 as libc::c_int as xmlChar,
    0xb2 as libc::c_int as xmlChar,
    0xb3 as libc::c_int as xmlChar,
    0xb4 as libc::c_int as xmlChar,
    0xb5 as libc::c_int as xmlChar,
    0xb6 as libc::c_int as xmlChar,
    0xb7 as libc::c_int as xmlChar,
    0xb8 as libc::c_int as xmlChar,
    0xb9 as libc::c_int as xmlChar,
    0xba as libc::c_int as xmlChar,
    0xbb as libc::c_int as xmlChar,
    0xbc as libc::c_int as xmlChar,
    0xbd as libc::c_int as xmlChar,
    0xbe as libc::c_int as xmlChar,
    0xbf as libc::c_int as xmlChar,
    0xc0 as libc::c_int as xmlChar,
    0xc1 as libc::c_int as xmlChar,
    0xc2 as libc::c_int as xmlChar,
    0xc3 as libc::c_int as xmlChar,
    0xc4 as libc::c_int as xmlChar,
    0xc5 as libc::c_int as xmlChar,
    0xc6 as libc::c_int as xmlChar,
    0xc7 as libc::c_int as xmlChar,
    0xc8 as libc::c_int as xmlChar,
    0xc9 as libc::c_int as xmlChar,
    0xca as libc::c_int as xmlChar,
    0xcb as libc::c_int as xmlChar,
    0xcc as libc::c_int as xmlChar,
    0xcd as libc::c_int as xmlChar,
    0xce as libc::c_int as xmlChar,
    0xcf as libc::c_int as xmlChar,
    0xd0 as libc::c_int as xmlChar,
    0xd1 as libc::c_int as xmlChar,
    0xd2 as libc::c_int as xmlChar,
    0xd3 as libc::c_int as xmlChar,
    0xd4 as libc::c_int as xmlChar,
    0xd5 as libc::c_int as xmlChar,
    0xd6 as libc::c_int as xmlChar,
    0xd7 as libc::c_int as xmlChar,
    0xd8 as libc::c_int as xmlChar,
    0xd9 as libc::c_int as xmlChar,
    0xda as libc::c_int as xmlChar,
    0xdb as libc::c_int as xmlChar,
    0xdc as libc::c_int as xmlChar,
    0xdd as libc::c_int as xmlChar,
    0xde as libc::c_int as xmlChar,
    0xdf as libc::c_int as xmlChar,
    0xe0 as libc::c_int as xmlChar,
    0xe1 as libc::c_int as xmlChar,
    0xe2 as libc::c_int as xmlChar,
    0xe3 as libc::c_int as xmlChar,
    0xe4 as libc::c_int as xmlChar,
    0xe5 as libc::c_int as xmlChar,
    0xe6 as libc::c_int as xmlChar,
    0xe7 as libc::c_int as xmlChar,
    0xe8 as libc::c_int as xmlChar,
    0xe9 as libc::c_int as xmlChar,
    0xea as libc::c_int as xmlChar,
    0xeb as libc::c_int as xmlChar,
    0xec as libc::c_int as xmlChar,
    0xed as libc::c_int as xmlChar,
    0xee as libc::c_int as xmlChar,
    0xef as libc::c_int as xmlChar,
    0xf0 as libc::c_int as xmlChar,
    0xf1 as libc::c_int as xmlChar,
    0xf2 as libc::c_int as xmlChar,
    0xf3 as libc::c_int as xmlChar,
    0xf4 as libc::c_int as xmlChar,
    0xf5 as libc::c_int as xmlChar,
    0xf6 as libc::c_int as xmlChar,
    0xf7 as libc::c_int as xmlChar,
    0xf8 as libc::c_int as xmlChar,
    0xf9 as libc::c_int as xmlChar,
    0xfa as libc::c_int as xmlChar,
    0xfb as libc::c_int as xmlChar,
    0xfc as libc::c_int as xmlChar,
    0xfd as libc::c_int as xmlChar,
    0xfe as libc::c_int as xmlChar,
    0xff as libc::c_int as xmlChar,
];
#[no_mangle]
pub unsafe extern "C" fn xmlStrcasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> libc::c_int {
    let mut tmp: libc::c_int = 0;
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh11 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh11 as usize] as libc::c_int
            - casemap[*str2 as usize] as libc::c_int;
        if tmp != 0 as libc::c_int {
            return tmp;
        }
        let fresh12 = str2;
        str2 = str2.offset(1);
        if !(*fresh12 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut tmp: libc::c_int = 0;
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if str1 == str2 {
        return 0 as libc::c_int;
    }
    if str1.is_null() {
        return -(1 as libc::c_int);
    }
    if str2.is_null() {
        return 1 as libc::c_int;
    }
    loop {
        let fresh13 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh13 as usize] as libc::c_int
            - casemap[*str2 as usize] as libc::c_int;
        if tmp != 0 as libc::c_int
            || {
                len -= 1;
                len == 0 as libc::c_int
            }
        {
            return tmp;
        }
        let fresh14 = str2;
        str2 = str2.offset(1);
        if !(*fresh14 as libc::c_int != 0 as libc::c_int) {
            break;
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrchr(
    mut str: *const xmlChar,
    mut val: xmlChar,
) -> *const xmlChar {
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if *str as libc::c_int == val as libc::c_int {
            return str as *mut xmlChar;
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrstr(
    mut str: *const xmlChar,
    mut val: *const xmlChar,
) -> *const xmlChar {
    let mut n: libc::c_int = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as libc::c_int {
        return str;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if *str as libc::c_int == *val as libc::c_int {
            if xmlStrncmp(str, val, n) == 0 {
                return str;
            }
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcasestr(
    mut str: *const xmlChar,
    mut val: *const xmlChar,
) -> *const xmlChar {
    let mut n: libc::c_int = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as libc::c_int {
        return str;
    }
    while *str as libc::c_int != 0 as libc::c_int {
        if casemap[*str as usize] as libc::c_int == casemap[*val as usize] as libc::c_int
        {
            if xmlStrncasecmp(str, val, n) == 0 {
                return str;
            }
        }
        str = str.offset(1);
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrsub(
    mut str: *const xmlChar,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < start {
        if *str as libc::c_int == 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
        str = str.offset(1);
        i += 1;
    }
    if *str as libc::c_int == 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(str, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrlen(mut str: *const xmlChar) -> libc::c_int {
    let mut len: size_t = if !str.is_null() {
        strlen(str as *const libc::c_char)
    } else {
        0 as libc::c_int as libc::c_ulong
    };
    return (if len > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        len
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut size: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if add.is_null() || len == 0 as libc::c_int {
        return cur;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if cur.is_null() {
        return xmlStrndup(add, len);
    }
    size = xmlStrlen(cur);
    if size < 0 as libc::c_int || size > 2147483647 as libc::c_int - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlRealloc
        .expect(
            "non-null function pointer",
        )(
        cur as *mut libc::c_void,
        (size as size_t)
            .wrapping_add(len as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return cur;
    }
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        add as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset((size + len) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncatNew(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut size: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if len < 0 as libc::c_int {
        len = xmlStrlen(str2);
        if len < 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
    }
    if str2.is_null() || len == 0 as libc::c_int {
        return xmlStrdup(str1);
    }
    if str1.is_null() {
        return xmlStrndup(str2, len);
    }
    size = xmlStrlen(str1);
    if size < 0 as libc::c_int || size > 2147483647 as libc::c_int - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (size as size_t)
            .wrapping_add(len as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return xmlStrndup(str1, size);
    }
    memcpy(
        ret as *mut libc::c_void,
        str1 as *const libc::c_void,
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        str2 as *const libc::c_void,
        (len as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset((size + len) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
) -> *mut xmlChar {
    let mut p: *const xmlChar = add;
    if add.is_null() {
        return cur;
    }
    if cur.is_null() {
        return xmlStrdup(add);
    }
    while *p as libc::c_int != 0 as libc::c_int {
        p = p.offset(1);
    }
    return xmlStrncat(cur, add, p.offset_from(add) as libc::c_long as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrPrintf(
    mut buf: *mut xmlChar,
    mut len: libc::c_int,
    mut msg: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::std::ffi::VaListImpl;
    let mut ret: libc::c_int = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as libc::c_int);
    }
    args_0 = args.clone();
    ret = vsnprintf(
        buf as *mut libc::c_char,
        len as libc::c_ulong,
        msg,
        args_0.as_va_list(),
    );
    *buf.offset((len - 1 as libc::c_int) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrVPrintf(
    mut buf: *mut xmlChar,
    mut len: libc::c_int,
    mut msg: *const libc::c_char,
    mut ap: ::std::ffi::VaList,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as libc::c_int);
    }
    ret = vsnprintf(
        buf as *mut libc::c_char,
        len as libc::c_ulong,
        msg,
        ap.as_va_list(),
    );
    *buf.offset((len - 1 as libc::c_int) as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Size(mut utf: *const xmlChar) -> libc::c_int {
    let mut mask: xmlChar = 0;
    let mut len: libc::c_int = 0;
    if utf.is_null() {
        return -(1 as libc::c_int);
    }
    if (*utf as libc::c_int) < 0x80 as libc::c_int {
        return 1 as libc::c_int;
    }
    if *utf as libc::c_int & 0x40 as libc::c_int == 0 {
        return -(1 as libc::c_int);
    }
    len = 2 as libc::c_int;
    mask = 0x20 as libc::c_int as xmlChar;
    while mask as libc::c_int != 0 as libc::c_int {
        if *utf as libc::c_int & mask as libc::c_int == 0 {
            return len;
        }
        len += 1;
        mask = (mask as libc::c_int >> 1 as libc::c_int) as xmlChar;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Charcmp(
    mut utf1: *const xmlChar,
    mut utf2: *const xmlChar,
) -> libc::c_int {
    if utf1.is_null() {
        if utf2.is_null() {
            return 0 as libc::c_int;
        }
        return -(1 as libc::c_int);
    }
    return xmlStrncmp(utf1, utf2, xmlUTF8Size(utf1));
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strlen(mut utf: *const xmlChar) -> libc::c_int {
    let mut ret: size_t = 0 as libc::c_int as size_t;
    if utf.is_null() {
        return -(1 as libc::c_int);
    }
    while *utf as libc::c_int != 0 as libc::c_int {
        if *utf.offset(0 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int
            != 0
        {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return -(1 as libc::c_int);
            }
            if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                & 0xe0 as libc::c_int == 0xe0 as libc::c_int
            {
                if *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                    & 0xf0 as libc::c_int == 0xf0 as libc::c_int
                {
                    if *utf.offset(0 as libc::c_int as isize) as libc::c_int
                        & 0xf8 as libc::c_int != 0xf0 as libc::c_int
                        || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                            & 0xc0 as libc::c_int != 0x80 as libc::c_int
                    {
                        return -(1 as libc::c_int);
                    }
                    utf = utf.offset(4 as libc::c_int as isize);
                } else {
                    utf = utf.offset(3 as libc::c_int as isize);
                }
            } else {
                utf = utf.offset(2 as libc::c_int as isize);
            }
        } else {
            utf = utf.offset(1);
        }
        ret = ret.wrapping_add(1);
    }
    return (if ret > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        ret
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetUTF8Char(
    mut utf: *const libc::c_uchar,
    mut len: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: libc::c_uint = 0;
    if !utf.is_null() {
        if !len.is_null() {
            if !(*len < 1 as libc::c_int) {
                c = *utf.offset(0 as libc::c_int as isize) as libc::c_uint;
                if c & 0x80 as libc::c_int as libc::c_uint != 0 {
                    if *len < 2 as libc::c_int {
                        current_block = 3966416321279884290;
                    } else if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                            & 0xc0 as libc::c_int != 0x80 as libc::c_int
                        {
                        current_block = 3966416321279884290;
                    } else if c & 0xe0 as libc::c_int as libc::c_uint
                            == 0xe0 as libc::c_int as libc::c_uint
                        {
                        if *len < 3 as libc::c_int {
                            current_block = 3966416321279884290;
                        } else if *utf.offset(2 as libc::c_int as isize) as libc::c_int
                                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                            {
                            current_block = 3966416321279884290;
                        } else if c & 0xf0 as libc::c_int as libc::c_uint
                                == 0xf0 as libc::c_int as libc::c_uint
                            {
                            if *len < 4 as libc::c_int {
                                current_block = 3966416321279884290;
                            } else if c & 0xf8 as libc::c_int as libc::c_uint
                                    != 0xf0 as libc::c_int as libc::c_uint
                                    || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                                        & 0xc0 as libc::c_int != 0x80 as libc::c_int
                                {
                                current_block = 3966416321279884290;
                            } else {
                                *len = 4 as libc::c_int;
                                c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                                    & 0x7 as libc::c_int) << 18 as libc::c_int) as libc::c_uint;
                                c
                                    |= ((*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) << 12 as libc::c_int)
                                        as libc::c_uint;
                                c
                                    |= ((*utf.offset(2 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                                c
                                    |= (*utf.offset(3 as libc::c_int as isize) as libc::c_int
                                        & 0x3f as libc::c_int) as libc::c_uint;
                                current_block = 11932355480408055363;
                            }
                        } else {
                            *len = 3 as libc::c_int;
                            c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                                & 0xf as libc::c_int) << 12 as libc::c_int) as libc::c_uint;
                            c
                                |= ((*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                            c
                                |= (*utf.offset(2 as libc::c_int as isize) as libc::c_int
                                    & 0x3f as libc::c_int) as libc::c_uint;
                            current_block = 11932355480408055363;
                        }
                    } else {
                        *len = 2 as libc::c_int;
                        c = ((*utf.offset(0 as libc::c_int as isize) as libc::c_int
                            & 0x1f as libc::c_int) << 6 as libc::c_int) as libc::c_uint;
                        c
                            |= (*utf.offset(1 as libc::c_int as isize) as libc::c_int
                                & 0x3f as libc::c_int) as libc::c_uint;
                        current_block = 11932355480408055363;
                    }
                } else {
                    *len = 1 as libc::c_int;
                    current_block = 11932355480408055363;
                }
                match current_block {
                    3966416321279884290 => {}
                    _ => return c as libc::c_int,
                }
            }
        }
    }
    if !len.is_null() {
        *len = 0 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckUTF8(mut utf: *const libc::c_uchar) -> libc::c_int {
    let mut ix: libc::c_int = 0;
    let mut c: libc::c_uchar = 0;
    if utf.is_null() {
        return 0 as libc::c_int;
    }
    loop {
        c = *utf.offset(0 as libc::c_int as isize);
        if !(c != 0) {
            break;
        }
        ix = 0 as libc::c_int;
        if c as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
            ix = 1 as libc::c_int;
        } else if c as libc::c_int & 0xe0 as libc::c_int == 0xc0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 2 as libc::c_int;
        } else if c as libc::c_int & 0xf0 as libc::c_int == 0xe0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 3 as libc::c_int;
        } else if c as libc::c_int & 0xf8 as libc::c_int == 0xf0 as libc::c_int {
            if *utf.offset(1 as libc::c_int as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(2 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset(3 as libc::c_int as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            ix = 4 as libc::c_int;
        } else {
            return 0 as libc::c_int
        }
        utf = utf.offset(ix as isize);
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsize(
    mut utf: *const xmlChar,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut ptr: *const xmlChar = utf;
    let mut ch: libc::c_int = 0;
    let mut ret: size_t = 0;
    if utf.is_null() {
        return 0 as libc::c_int;
    }
    if len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    loop {
        let fresh15 = len;
        len = len - 1;
        if !(fresh15 > 0 as libc::c_int) {
            break;
        }
        if *ptr == 0 {
            break;
        }
        let fresh16 = ptr;
        ptr = ptr.offset(1);
        ch = *fresh16 as libc::c_int;
        if ch & 0x80 as libc::c_int != 0 {
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                if *ptr as libc::c_int == 0 as libc::c_int {
                    break;
                }
                ptr = ptr.offset(1);
            }
        }
    }
    ret = ptr.offset_from(utf) as libc::c_long as size_t;
    return (if ret > 2147483647 as libc::c_int as libc::c_ulong {
        0 as libc::c_int as libc::c_ulong
    } else {
        ret
    }) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strndup(
    mut utf: *const xmlChar,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: libc::c_int = 0;
    if utf.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = xmlUTF8Strsize(utf, len);
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (i as size_t)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        utf as *const libc::c_void,
        (i as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    );
    *ret.offset(i as isize) = 0 as libc::c_int as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strpos(
    mut utf: *const xmlChar,
    mut pos: libc::c_int,
) -> *const xmlChar {
    let mut ch: libc::c_int = 0;
    if utf.is_null() {
        return 0 as *const xmlChar;
    }
    if pos < 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    loop {
        let fresh17 = pos;
        pos = pos - 1;
        if !(fresh17 != 0) {
            break;
        }
        let fresh18 = utf;
        utf = utf.offset(1);
        ch = *fresh18 as libc::c_int;
        if ch == 0 as libc::c_int {
            return 0 as *const xmlChar;
        }
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return 0 as *const xmlChar;
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh19 = utf;
                utf = utf.offset(1);
                if *fresh19 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return 0 as *const xmlChar;
                }
            }
        }
    }
    return utf as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strloc(
    mut utf: *const xmlChar,
    mut utfchar: *const xmlChar,
) -> libc::c_int {
    let mut i: size_t = 0;
    let mut size: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    if utf.is_null() || utfchar.is_null() {
        return -(1 as libc::c_int);
    }
    size = xmlUTF8Strsize(utfchar, 1 as libc::c_int);
    i = 0 as libc::c_int as size_t;
    loop {
        ch = *utf as libc::c_int;
        if !(ch != 0 as libc::c_int) {
            break;
        }
        if xmlStrncmp(utf, utfchar, size) == 0 as libc::c_int {
            return (if i > 2147483647 as libc::c_int as libc::c_ulong {
                0 as libc::c_int as libc::c_ulong
            } else {
                i
            }) as libc::c_int;
        }
        utf = utf.offset(1);
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return -(1 as libc::c_int);
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh20 = utf;
                utf = utf.offset(1);
                if *fresh20 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return -(1 as libc::c_int);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsub(
    mut utf: *const xmlChar,
    mut start: libc::c_int,
    mut len: libc::c_int,
) -> *mut xmlChar {
    let mut i: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    if utf.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    i = 0 as libc::c_int;
    while i < start {
        let fresh21 = utf;
        utf = utf.offset(1);
        ch = *fresh21 as libc::c_int;
        if ch == 0 as libc::c_int {
            return 0 as *mut xmlChar;
        }
        if ch & 0x80 as libc::c_int != 0 {
            if ch & 0xc0 as libc::c_int != 0xc0 as libc::c_int {
                return 0 as *mut xmlChar;
            }
            loop {
                ch <<= 1 as libc::c_int;
                if !(ch & 0x80 as libc::c_int != 0) {
                    break;
                }
                let fresh22 = utf;
                utf = utf.offset(1);
                if *fresh22 as libc::c_int & 0xc0 as libc::c_int != 0x80 as libc::c_int {
                    return 0 as *mut xmlChar;
                }
            }
        }
        i += 1;
    }
    return xmlUTF8Strndup(utf, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlEscapeFormatString(
    mut msg: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut msgPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut result: *mut xmlChar = 0 as *mut xmlChar;
    let mut resultPtr: *mut xmlChar = 0 as *mut xmlChar;
    let mut count: size_t = 0 as libc::c_int as size_t;
    let mut msgLen: size_t = 0 as libc::c_int as size_t;
    let mut resultLen: size_t = 0 as libc::c_int as size_t;
    if msg.is_null() || (*msg).is_null() {
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    while *msgPtr as libc::c_int != '\u{0}' as i32 {
        msgLen = msgLen.wrapping_add(1);
        if *msgPtr as libc::c_int == '%' as i32 {
            count = count.wrapping_add(1);
        }
        msgPtr = msgPtr.offset(1);
    }
    if count == 0 as libc::c_int as libc::c_ulong {
        return *msg;
    }
    if count > 2147483647 as libc::c_int as libc::c_ulong
        || msgLen > (2147483647 as libc::c_int as libc::c_ulong).wrapping_sub(count)
    {
        return 0 as *mut xmlChar;
    }
    resultLen = msgLen
        .wrapping_add(count)
        .wrapping_add(1 as libc::c_int as libc::c_ulong);
    result = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(resultLen.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
        as *mut xmlChar;
    if result.is_null() {
        xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
        *msg = 0 as *mut xmlChar;
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    resultPtr = result;
    while *msgPtr as libc::c_int != '\u{0}' as i32 {
        *resultPtr = *msgPtr;
        if *msgPtr as libc::c_int == '%' as i32 {
            resultPtr = resultPtr.offset(1);
            *resultPtr = '%' as i32 as xmlChar;
        }
        msgPtr = msgPtr.offset(1);
        resultPtr = resultPtr.offset(1);
    }
    *result
        .offset(
            resultLen.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
        ) = '\u{0}' as i32 as xmlChar;
    xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
    *msg = result;
    return *msg;
}
