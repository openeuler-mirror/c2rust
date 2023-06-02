use ::libc;
extern "C" {
    
    
    
    
    
    
    
    fn vsnprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ::std::ffi::VaList,
    ) -> i32;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: u64,
    ) -> *mut libc::c_void;
    fn strlen(_: *const i8) -> u64;
    
    
    
    
    
}
pub use crate::src::parserInternals::xmlErrMemory;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::globals::xmlFree;
pub use crate::src::globals::xmlMalloc;
pub use crate::src::globals::xmlMallocAtomic;
pub use crate::src::globals::xmlRealloc;
pub type __builtin_va_list = crate::src::error::__builtin_va_list;
// #[derive(Copy, Clone)]

pub type __va_list_tag = crate::src::error::__va_list_tag;
pub type va_list = crate::src::error::va_list;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type xmlParserCtxtPtr = crate::src::HTMLparser::xmlParserCtxtPtr;
pub type xmlParserCtxt = crate::src::HTMLparser::xmlParserCtxt;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
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
pub type xmlErrorLevel = crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = crate::src::HTMLparser::xmlAttrPtr;
pub type xmlAttr = crate::src::HTMLparser::xmlAttr;
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
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
pub type size_t = crate::src::HTMLparser::size_t;
pub type xmlMallocFunc = crate::src::HTMLparser::xmlMallocFunc;
pub type xmlReallocFunc = crate::src::HTMLparser::xmlReallocFunc;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
#[no_mangle]
pub unsafe extern "C" fn xmlStrndup(
    mut cur: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        cur as *const libc::c_void,
        (len as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    *ret.offset(len as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrdup(mut cur: *const xmlChar) -> *mut xmlChar {
    let mut p: *const xmlChar = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as i32 != 0 as i32 {
        p = p.offset(1);
    }
    return xmlStrndup(cur, p.offset_from(cur) as i64 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrndup(
    mut cur: *const i8,
    mut len: i32,
) -> *mut xmlChar {
    let mut i: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (len as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < len {
        *ret.offset(i as isize) = *cur.offset(i as isize) as xmlChar;
        if *ret.offset(i as isize) as i32 == 0 as i32 {
            return ret;
        }
        i += 1;
    }
    *ret.offset(len as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCharStrdup(mut cur: *const i8) -> *mut xmlChar {
    let mut p: *const i8 = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while *p as i32 != '\u{0}' as i32 {
        p = p.offset(1);
    }
    return xmlCharStrndup(cur, p.offset_from(cur) as i64 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrcmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> i32 {
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh0 = str1;
        str1 = str1.offset(1);
        let mut tmp: i32 = *fresh0 as i32 - *str2 as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let fresh1 = str2;
        str2 = str2.offset(1);
        if !(*fresh1 as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrEqual(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> i32 {
    if str1 == str2 {
        return 1 as i32;
    }
    if str1.is_null() {
        return 0 as i32;
    }
    if str2.is_null() {
        return 0 as i32;
    }
    loop {
        let fresh2 = str1;
        str1 = str1.offset(1);
        if *fresh2 as i32 != *str2 as i32 {
            return 0 as i32;
        }
        let fresh3 = str2;
        str2 = str2.offset(1);
        if !(*fresh3 != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrQEqual(
    mut pref: *const xmlChar,
    mut name: *const xmlChar,
    mut str: *const xmlChar,
) -> i32 {
    if pref.is_null() {
        return xmlStrEqual(name, str);
    }
    if name.is_null() {
        return 0 as i32;
    }
    if str.is_null() {
        return 0 as i32;
    }
    loop {
        let fresh4 = pref;
        pref = pref.offset(1);
        if *fresh4 as i32 != *str as i32 {
            return 0 as i32;
        }
        let fresh5 = str;
        str = str.offset(1);
        if !(*fresh5 as i32 != 0 && *pref as i32 != 0) {
            break;
        }
    }
    let fresh6 = str;
    str = str.offset(1);
    if *fresh6 as i32 != ':' as i32 {
        return 0 as i32;
    }
    loop {
        let fresh7 = name;
        name = name.offset(1);
        if *fresh7 as i32 != *str as i32 {
            return 0 as i32;
        }
        let fresh8 = str;
        str = str.offset(1);
        if !(*fresh8 != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> i32 {
    if len <= 0 as i32 {
        return 0 as i32;
    }
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh9 = str1;
        str1 = str1.offset(1);
        let mut tmp: i32 = *fresh9 as i32 - *str2 as i32;
        if tmp != 0 as i32
            || {
                len -= 1;
                len == 0 as i32
            }
        {
            return tmp;
        }
        let fresh10 = str2;
        str2 = str2.offset(1);
        if !(*fresh10 as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
static mut casemap: [xmlChar; 256] = [
    0 as i32 as xmlChar,
    0x1 as i32 as xmlChar,
    0x2 as i32 as xmlChar,
    0x3 as i32 as xmlChar,
    0x4 as i32 as xmlChar,
    0x5 as i32 as xmlChar,
    0x6 as i32 as xmlChar,
    0x7 as i32 as xmlChar,
    0x8 as i32 as xmlChar,
    0x9 as i32 as xmlChar,
    0xa as i32 as xmlChar,
    0xb as i32 as xmlChar,
    0xc as i32 as xmlChar,
    0xd as i32 as xmlChar,
    0xe as i32 as xmlChar,
    0xf as i32 as xmlChar,
    0x10 as i32 as xmlChar,
    0x11 as i32 as xmlChar,
    0x12 as i32 as xmlChar,
    0x13 as i32 as xmlChar,
    0x14 as i32 as xmlChar,
    0x15 as i32 as xmlChar,
    0x16 as i32 as xmlChar,
    0x17 as i32 as xmlChar,
    0x18 as i32 as xmlChar,
    0x19 as i32 as xmlChar,
    0x1a as i32 as xmlChar,
    0x1b as i32 as xmlChar,
    0x1c as i32 as xmlChar,
    0x1d as i32 as xmlChar,
    0x1e as i32 as xmlChar,
    0x1f as i32 as xmlChar,
    0x20 as i32 as xmlChar,
    0x21 as i32 as xmlChar,
    0x22 as i32 as xmlChar,
    0x23 as i32 as xmlChar,
    0x24 as i32 as xmlChar,
    0x25 as i32 as xmlChar,
    0x26 as i32 as xmlChar,
    0x27 as i32 as xmlChar,
    0x28 as i32 as xmlChar,
    0x29 as i32 as xmlChar,
    0x2a as i32 as xmlChar,
    0x2b as i32 as xmlChar,
    0x2c as i32 as xmlChar,
    0x2d as i32 as xmlChar,
    0x2e as i32 as xmlChar,
    0x2f as i32 as xmlChar,
    0x30 as i32 as xmlChar,
    0x31 as i32 as xmlChar,
    0x32 as i32 as xmlChar,
    0x33 as i32 as xmlChar,
    0x34 as i32 as xmlChar,
    0x35 as i32 as xmlChar,
    0x36 as i32 as xmlChar,
    0x37 as i32 as xmlChar,
    0x38 as i32 as xmlChar,
    0x39 as i32 as xmlChar,
    0x3a as i32 as xmlChar,
    0x3b as i32 as xmlChar,
    0x3c as i32 as xmlChar,
    0x3d as i32 as xmlChar,
    0x3e as i32 as xmlChar,
    0x3f as i32 as xmlChar,
    0x40 as i32 as xmlChar,
    0x61 as i32 as xmlChar,
    0x62 as i32 as xmlChar,
    0x63 as i32 as xmlChar,
    0x64 as i32 as xmlChar,
    0x65 as i32 as xmlChar,
    0x66 as i32 as xmlChar,
    0x67 as i32 as xmlChar,
    0x68 as i32 as xmlChar,
    0x69 as i32 as xmlChar,
    0x6a as i32 as xmlChar,
    0x6b as i32 as xmlChar,
    0x6c as i32 as xmlChar,
    0x6d as i32 as xmlChar,
    0x6e as i32 as xmlChar,
    0x6f as i32 as xmlChar,
    0x70 as i32 as xmlChar,
    0x71 as i32 as xmlChar,
    0x72 as i32 as xmlChar,
    0x73 as i32 as xmlChar,
    0x74 as i32 as xmlChar,
    0x75 as i32 as xmlChar,
    0x76 as i32 as xmlChar,
    0x77 as i32 as xmlChar,
    0x78 as i32 as xmlChar,
    0x79 as i32 as xmlChar,
    0x7a as i32 as xmlChar,
    0x7b as i32 as xmlChar,
    0x5c as i32 as xmlChar,
    0x5d as i32 as xmlChar,
    0x5e as i32 as xmlChar,
    0x5f as i32 as xmlChar,
    0x60 as i32 as xmlChar,
    0x61 as i32 as xmlChar,
    0x62 as i32 as xmlChar,
    0x63 as i32 as xmlChar,
    0x64 as i32 as xmlChar,
    0x65 as i32 as xmlChar,
    0x66 as i32 as xmlChar,
    0x67 as i32 as xmlChar,
    0x68 as i32 as xmlChar,
    0x69 as i32 as xmlChar,
    0x6a as i32 as xmlChar,
    0x6b as i32 as xmlChar,
    0x6c as i32 as xmlChar,
    0x6d as i32 as xmlChar,
    0x6e as i32 as xmlChar,
    0x6f as i32 as xmlChar,
    0x70 as i32 as xmlChar,
    0x71 as i32 as xmlChar,
    0x72 as i32 as xmlChar,
    0x73 as i32 as xmlChar,
    0x74 as i32 as xmlChar,
    0x75 as i32 as xmlChar,
    0x76 as i32 as xmlChar,
    0x77 as i32 as xmlChar,
    0x78 as i32 as xmlChar,
    0x79 as i32 as xmlChar,
    0x7a as i32 as xmlChar,
    0x7b as i32 as xmlChar,
    0x7c as i32 as xmlChar,
    0x7d as i32 as xmlChar,
    0x7e as i32 as xmlChar,
    0x7f as i32 as xmlChar,
    0x80 as i32 as xmlChar,
    0x81 as i32 as xmlChar,
    0x82 as i32 as xmlChar,
    0x83 as i32 as xmlChar,
    0x84 as i32 as xmlChar,
    0x85 as i32 as xmlChar,
    0x86 as i32 as xmlChar,
    0x87 as i32 as xmlChar,
    0x88 as i32 as xmlChar,
    0x89 as i32 as xmlChar,
    0x8a as i32 as xmlChar,
    0x8b as i32 as xmlChar,
    0x8c as i32 as xmlChar,
    0x8d as i32 as xmlChar,
    0x8e as i32 as xmlChar,
    0x8f as i32 as xmlChar,
    0x90 as i32 as xmlChar,
    0x91 as i32 as xmlChar,
    0x92 as i32 as xmlChar,
    0x93 as i32 as xmlChar,
    0x94 as i32 as xmlChar,
    0x95 as i32 as xmlChar,
    0x96 as i32 as xmlChar,
    0x97 as i32 as xmlChar,
    0x98 as i32 as xmlChar,
    0x99 as i32 as xmlChar,
    0x9a as i32 as xmlChar,
    0x9b as i32 as xmlChar,
    0x9c as i32 as xmlChar,
    0x9d as i32 as xmlChar,
    0x9e as i32 as xmlChar,
    0x9f as i32 as xmlChar,
    0xa0 as i32 as xmlChar,
    0xa1 as i32 as xmlChar,
    0xa2 as i32 as xmlChar,
    0xa3 as i32 as xmlChar,
    0xa4 as i32 as xmlChar,
    0xa5 as i32 as xmlChar,
    0xa6 as i32 as xmlChar,
    0xa7 as i32 as xmlChar,
    0xa8 as i32 as xmlChar,
    0xa9 as i32 as xmlChar,
    0xaa as i32 as xmlChar,
    0xab as i32 as xmlChar,
    0xac as i32 as xmlChar,
    0xad as i32 as xmlChar,
    0xae as i32 as xmlChar,
    0xaf as i32 as xmlChar,
    0xb0 as i32 as xmlChar,
    0xb1 as i32 as xmlChar,
    0xb2 as i32 as xmlChar,
    0xb3 as i32 as xmlChar,
    0xb4 as i32 as xmlChar,
    0xb5 as i32 as xmlChar,
    0xb6 as i32 as xmlChar,
    0xb7 as i32 as xmlChar,
    0xb8 as i32 as xmlChar,
    0xb9 as i32 as xmlChar,
    0xba as i32 as xmlChar,
    0xbb as i32 as xmlChar,
    0xbc as i32 as xmlChar,
    0xbd as i32 as xmlChar,
    0xbe as i32 as xmlChar,
    0xbf as i32 as xmlChar,
    0xc0 as i32 as xmlChar,
    0xc1 as i32 as xmlChar,
    0xc2 as i32 as xmlChar,
    0xc3 as i32 as xmlChar,
    0xc4 as i32 as xmlChar,
    0xc5 as i32 as xmlChar,
    0xc6 as i32 as xmlChar,
    0xc7 as i32 as xmlChar,
    0xc8 as i32 as xmlChar,
    0xc9 as i32 as xmlChar,
    0xca as i32 as xmlChar,
    0xcb as i32 as xmlChar,
    0xcc as i32 as xmlChar,
    0xcd as i32 as xmlChar,
    0xce as i32 as xmlChar,
    0xcf as i32 as xmlChar,
    0xd0 as i32 as xmlChar,
    0xd1 as i32 as xmlChar,
    0xd2 as i32 as xmlChar,
    0xd3 as i32 as xmlChar,
    0xd4 as i32 as xmlChar,
    0xd5 as i32 as xmlChar,
    0xd6 as i32 as xmlChar,
    0xd7 as i32 as xmlChar,
    0xd8 as i32 as xmlChar,
    0xd9 as i32 as xmlChar,
    0xda as i32 as xmlChar,
    0xdb as i32 as xmlChar,
    0xdc as i32 as xmlChar,
    0xdd as i32 as xmlChar,
    0xde as i32 as xmlChar,
    0xdf as i32 as xmlChar,
    0xe0 as i32 as xmlChar,
    0xe1 as i32 as xmlChar,
    0xe2 as i32 as xmlChar,
    0xe3 as i32 as xmlChar,
    0xe4 as i32 as xmlChar,
    0xe5 as i32 as xmlChar,
    0xe6 as i32 as xmlChar,
    0xe7 as i32 as xmlChar,
    0xe8 as i32 as xmlChar,
    0xe9 as i32 as xmlChar,
    0xea as i32 as xmlChar,
    0xeb as i32 as xmlChar,
    0xec as i32 as xmlChar,
    0xed as i32 as xmlChar,
    0xee as i32 as xmlChar,
    0xef as i32 as xmlChar,
    0xf0 as i32 as xmlChar,
    0xf1 as i32 as xmlChar,
    0xf2 as i32 as xmlChar,
    0xf3 as i32 as xmlChar,
    0xf4 as i32 as xmlChar,
    0xf5 as i32 as xmlChar,
    0xf6 as i32 as xmlChar,
    0xf7 as i32 as xmlChar,
    0xf8 as i32 as xmlChar,
    0xf9 as i32 as xmlChar,
    0xfa as i32 as xmlChar,
    0xfb as i32 as xmlChar,
    0xfc as i32 as xmlChar,
    0xfd as i32 as xmlChar,
    0xfe as i32 as xmlChar,
    0xff as i32 as xmlChar,
];
#[no_mangle]
pub unsafe extern "C" fn xmlStrcasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) -> i32 {
    let mut tmp: i32 = 0;
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh11 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh11 as usize] as i32
            - casemap[*str2 as usize] as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let fresh12 = str2;
        str2 = str2.offset(1);
        if !(*fresh12 as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncasecmp(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> i32 {
    let mut tmp: i32 = 0;
    if len <= 0 as i32 {
        return 0 as i32;
    }
    if str1 == str2 {
        return 0 as i32;
    }
    if str1.is_null() {
        return -(1 as i32);
    }
    if str2.is_null() {
        return 1 as i32;
    }
    loop {
        let fresh13 = str1;
        str1 = str1.offset(1);
        tmp = casemap[*fresh13 as usize] as i32
            - casemap[*str2 as usize] as i32;
        if tmp != 0 as i32
            || {
                len -= 1;
                len == 0 as i32
            }
        {
            return tmp;
        }
        let fresh14 = str2;
        str2 = str2.offset(1);
        if !(*fresh14 as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrchr(
    mut str: *const xmlChar,
    mut val: xmlChar,
) -> *const xmlChar {
    if str.is_null() {
        // type
        return 0 as *const libc::c_void as *const xmlChar;
    }
    while *str as i32 != 0 as i32 {
        if *str as i32 == val as i32 {
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
    let mut n: i32 = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as i32 {
        return str;
    }
    while *str as i32 != 0 as i32 {
        if *str as i32 == *val as i32 {
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
    let mut n: i32 = 0;
    if str.is_null() {
        return 0 as *const xmlChar;
    }
    if val.is_null() {
        return 0 as *const xmlChar;
    }
    n = xmlStrlen(val);
    if n == 0 as i32 {
        return str;
    }
    while *str as i32 != 0 as i32 {
        if casemap[*str as usize] as i32 == casemap[*val as usize] as i32
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
    mut start: i32,
    mut len: i32,
) -> *mut xmlChar {
    let mut i: i32 = 0;
    if str.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < start {
        if *str as i32 == 0 as i32 {
            return 0 as *mut xmlChar;
        }
        str = str.offset(1);
        i += 1;
    }
    if *str as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(str, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrlen(mut str: *const xmlChar) -> i32 {
    let mut len: size_t = if !str.is_null() {
        strlen(str as *const i8)
    } else {
        0 as i32 as u64
    };
    return (if len > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        len
    }) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncat(
    mut cur: *mut xmlChar,
    mut add: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut size: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if add.is_null() || len == 0 as i32 {
        return cur;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if cur.is_null() {
        return xmlStrndup(add, len);
    }
    size = xmlStrlen(cur as *const xmlChar);
    if size < 0 as i32 || size > 2147483647 as i32 - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlRealloc
        .expect(
            "non-null function pointer",
        )(
        cur as *mut libc::c_void,
        (size as size_t)
            .wrapping_add(len as u64)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8);
        return cur;
    }
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        add as *const libc::c_void,
        (len as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    *ret.offset((size + len) as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrncatNew(
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut size: i32 = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    if len < 0 as i32 {
        len = xmlStrlen(str2);
        if len < 0 as i32 {
            return 0 as *mut xmlChar;
        }
    }
    if str2.is_null() || len == 0 as i32 {
        return xmlStrdup(str1);
    }
    if str1.is_null() {
        return xmlStrndup(str2, len);
    }
    size = xmlStrlen(str1);
    if size < 0 as i32 || size > 2147483647 as i32 - len {
        return 0 as *mut xmlChar;
    }
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (size as size_t)
            .wrapping_add(len as u64)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if ret.is_null() {
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8);
        return xmlStrndup(str1, size);
    }
    memcpy(
        ret as *mut libc::c_void,
        str1 as *const libc::c_void,
        (size as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    memcpy(
        &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
        str2 as *const libc::c_void,
        (len as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    *ret.offset((size + len) as isize) = 0 as i32 as xmlChar;
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
    while *p as i32 != 0 as i32 {
        p = p.offset(1);
    }
    return xmlStrncat(cur, add, p.offset_from(add) as i64 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrPrintf(
    mut buf: *mut xmlChar,
    mut len: i32,
    mut msg: *const i8,
    mut args: ...
) -> i32 {
    let mut args_0: ::std::ffi::VaListImpl;
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    args_0 = args.clone();
    ret = vsnprintf(
        buf as *mut i8,
        len as u64,
        msg,
        args_0.as_va_list(),
    );
    *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrVPrintf(
    mut buf: *mut xmlChar,
    mut len: i32,
    mut msg: *const i8,
    mut ap: ::std::ffi::VaList,
) -> i32 {
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    ret = vsnprintf(
        buf as *mut i8,
        len as u64,
        msg,
        ap.as_va_list(),
    );
    *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Size(mut utf: *const xmlChar) -> i32 {
    let mut mask: xmlChar = 0;
    let mut len: i32 = 0;
    if utf.is_null() {
        return -(1 as i32);
    }
    if (*utf as i32) < 0x80 as i32 {
        return 1 as i32;
    }
    if *utf as i32 & 0x40 as i32 == 0 {
        return -(1 as i32);
    }
    len = 2 as i32;
    mask = 0x20 as i32 as xmlChar;
    while mask as i32 != 0 as i32 {
        if *utf as i32 & mask as i32 == 0 {
            return len;
        }
        len += 1;
        mask = (mask as i32 >> 1 as i32) as xmlChar;
    }
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Charcmp(
    mut utf1: *const xmlChar,
    mut utf2: *const xmlChar,
) -> i32 {
    if utf1.is_null() {
        if utf2.is_null() {
            return 0 as i32;
        }
        return -(1 as i32);
    }
    return xmlStrncmp(utf1, utf2, xmlUTF8Size(utf1));
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strlen(mut utf: *const xmlChar) -> i32 {
    let mut ret: size_t = 0 as i32 as size_t;
    if utf.is_null() {
        return -(1 as i32);
    }
    while *utf as i32 != 0 as i32 {
        if *utf.offset(0 as i32 as isize) as i32 & 0x80 as i32
            != 0
        {
            if *utf.offset(1 as i32 as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
            {
                return -(1 as i32);
            }
            if *utf.offset(0 as i32 as isize) as i32
                & 0xe0 as i32 == 0xe0 as i32
            {
                if *utf.offset(2 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
                {
                    return -(1 as i32);
                }
                if *utf.offset(0 as i32 as isize) as i32
                    & 0xf0 as i32 == 0xf0 as i32
                {
                    if *utf.offset(0 as i32 as isize) as i32
                        & 0xf8 as i32 != 0xf0 as i32
                        || *utf.offset(3 as i32 as isize) as i32
                            & 0xc0 as i32 != 0x80 as i32
                    {
                        return -(1 as i32);
                    }
                    utf = utf.offset(4 as i32 as isize);
                } else {
                    utf = utf.offset(3 as i32 as isize);
                }
            } else {
                utf = utf.offset(2 as i32 as isize);
            }
        } else {
            utf = utf.offset(1);
        }
        ret = ret.wrapping_add(1);
    }
    return (if ret > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        ret
    }) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetUTF8Char(
    mut utf: *const u8,
    mut len: *mut i32,
) -> i32 {
    let mut current_block: u64;
    let mut c: u32 = 0;
    if !utf.is_null() {
        if !len.is_null() {
            if !(*len < 1 as i32) {
                c = *utf.offset(0 as i32 as isize) as u32;
                if c & 0x80 as i32 as u32 != 0 {
                    if *len < 2 as i32 {
                        current_block = 3966416321279884290;
                    } else if *utf.offset(1 as i32 as isize) as i32
                            & 0xc0 as i32 != 0x80 as i32
                        {
                        current_block = 3966416321279884290;
                    } else if c & 0xe0 as i32 as u32
                            == 0xe0 as i32 as u32
                        {
                        if *len < 3 as i32 {
                            current_block = 3966416321279884290;
                        } else if *utf.offset(2 as i32 as isize) as i32
                                & 0xc0 as i32 != 0x80 as i32
                            {
                            current_block = 3966416321279884290;
                        } else if c & 0xf0 as i32 as u32
                                == 0xf0 as i32 as u32
                            {
                            if *len < 4 as i32 {
                                current_block = 3966416321279884290;
                            } else if c & 0xf8 as i32 as u32
                                    != 0xf0 as i32 as u32
                                    || *utf.offset(3 as i32 as isize) as i32
                                        & 0xc0 as i32 != 0x80 as i32
                                {
                                current_block = 3966416321279884290;
                            } else {
                                *len = 4 as i32;
                                c = ((*utf.offset(0 as i32 as isize) as i32
                                    & 0x7 as i32) << 18 as i32) as u32;
                                c
                                    |= ((*utf.offset(1 as i32 as isize) as i32
                                        & 0x3f as i32) << 12 as i32)
                                        as u32;
                                c
                                    |= ((*utf.offset(2 as i32 as isize) as i32
                                        & 0x3f as i32) << 6 as i32) as u32;
                                c
                                    |= (*utf.offset(3 as i32 as isize) as i32
                                        & 0x3f as i32) as u32;
                                current_block = 11932355480408055363;
                            }
                        } else {
                            *len = 3 as i32;
                            c = ((*utf.offset(0 as i32 as isize) as i32
                                & 0xf as i32) << 12 as i32) as u32;
                            c
                                |= ((*utf.offset(1 as i32 as isize) as i32
                                    & 0x3f as i32) << 6 as i32) as u32;
                            c
                                |= (*utf.offset(2 as i32 as isize) as i32
                                    & 0x3f as i32) as u32;
                            current_block = 11932355480408055363;
                        }
                    } else {
                        *len = 2 as i32;
                        c = ((*utf.offset(0 as i32 as isize) as i32
                            & 0x1f as i32) << 6 as i32) as u32;
                        c
                            |= (*utf.offset(1 as i32 as isize) as i32
                                & 0x3f as i32) as u32;
                        current_block = 11932355480408055363;
                    }
                } else {
                    *len = 1 as i32;
                    current_block = 11932355480408055363;
                }
                match current_block {
                    3966416321279884290 => {}
                    _ => return c as i32,
                }
            }
        }
    }
    if !len.is_null() {
        *len = 0 as i32;
    }
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckUTF8(mut utf: *const u8) -> i32 {
    let mut ix: i32 = 0;
    let mut c: u8 = 0;
    if utf.is_null() {
        return 0 as i32;
    }
    loop {
        c = *utf.offset(0 as i32 as isize);
        if !(c != 0) {
            break;
        }
        ix = 0 as i32;
        if c as i32 & 0x80 as i32 == 0 as i32 {
            ix = 1 as i32;
        } else if c as i32 & 0xe0 as i32 == 0xc0 as i32 {
            if *utf.offset(1 as i32 as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 2 as i32;
        } else if c as i32 & 0xf0 as i32 == 0xe0 as i32 {
            if *utf.offset(1 as i32 as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
                || *utf.offset(2 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 3 as i32;
        } else if c as i32 & 0xf8 as i32 == 0xf0 as i32 {
            if *utf.offset(1 as i32 as isize) as i32
                & 0xc0 as i32 != 0x80 as i32
                || *utf.offset(2 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
                || *utf.offset(3 as i32 as isize) as i32
                    & 0xc0 as i32 != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 4 as i32;
        } else {
            return 0 as i32
        }
        utf = utf.offset(ix as isize);
    }
    return 1 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsize(
    mut utf: *const xmlChar,
    mut len: i32,
) -> i32 {
    let mut ptr: *const xmlChar = utf;
    let mut ch: i32 = 0;
    let mut ret: size_t = 0;
    if utf.is_null() {
        return 0 as i32;
    }
    if len <= 0 as i32 {
        return 0 as i32;
    }
    loop {
        let fresh15 = len;
        len = len - 1;
        if !(fresh15 > 0 as i32) {
            break;
        }
        if *ptr == 0 {
            break;
        }
        let fresh16 = ptr;
        ptr = ptr.offset(1);
        ch = *fresh16 as i32;
        if ch & 0x80 as i32 != 0 {
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                if *ptr as i32 == 0 as i32 {
                    break;
                }
                ptr = ptr.offset(1);
            }
        }
    }
    ret = ptr.offset_from(utf) as i64 as size_t;
    return (if ret > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        ret
    }) as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strndup(
    mut utf: *const xmlChar,
    mut len: i32,
) -> *mut xmlChar {
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    if utf.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = xmlUTF8Strsize(utf, len);
    ret = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (i as size_t)
            .wrapping_add(1 as i32 as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    ) as *mut xmlChar;
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    memcpy(
        ret as *mut libc::c_void,
        utf as *const libc::c_void,
        (i as u64)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
    );
    *ret.offset(i as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strpos(
    mut utf: *const xmlChar,
    mut pos: i32,
) -> *const xmlChar {
    let mut ch: i32 = 0;
    if utf.is_null() {
        // type
        return 0 as *const libc::c_void as *const xmlChar;
    }
    if pos < 0 as i32 {
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
        ch = *fresh18 as i32;
        if ch == 0 as i32 {
            return 0 as *const xmlChar;
        }
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return 0 as *const xmlChar;
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh19 = utf;
                utf = utf.offset(1);
                if *fresh19 as i32 & 0xc0 as i32 != 0x80 as i32 {
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
) -> i32 {
    let mut i: size_t = 0;
    let mut size: i32 = 0;
    let mut ch: i32 = 0;
    if utf.is_null() || utfchar.is_null() {
        return -(1 as i32);
    }
    size = xmlUTF8Strsize(utfchar, 1 as i32);
    i = 0 as i32 as size_t;
    loop {
        ch = *utf as i32;
        if !(ch != 0 as i32) {
            break;
        }
        if xmlStrncmp(utf, utfchar, size) == 0 as i32 {
            return (if i > 2147483647 as i32 as u64 {
                0 as i32 as u64
            } else {
                i
            }) as i32;
        }
        utf = utf.offset(1);
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return -(1 as i32);
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh20 = utf;
                utf = utf.offset(1);
                if *fresh20 as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    return -(1 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlUTF8Strsub(
    mut utf: *const xmlChar,
    mut start: i32,
    mut len: i32,
) -> *mut xmlChar {
    let mut i: i32 = 0;
    let mut ch: i32 = 0;
    if utf.is_null() {
        return 0 as *mut xmlChar;
    }
    if start < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    if len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < start {
        let fresh21 = utf;
        utf = utf.offset(1);
        ch = *fresh21 as i32;
        if ch == 0 as i32 {
            return 0 as *mut xmlChar;
        }
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return 0 as *mut xmlChar;
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let fresh22 = utf;
                utf = utf.offset(1);
                if *fresh22 as i32 & 0xc0 as i32 != 0x80 as i32 {
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
    let mut count: size_t = 0 as i32 as size_t;
    let mut msgLen: size_t = 0 as i32 as size_t;
    let mut resultLen: size_t = 0 as i32 as size_t;
    if msg.is_null() || (*msg).is_null() {
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    while *msgPtr as i32 != '\u{0}' as i32 {
        msgLen = msgLen.wrapping_add(1);
        if *msgPtr as i32 == '%' as i32 {
            count = count.wrapping_add(1);
        }
        msgPtr = msgPtr.offset(1);
    }
    if count == 0 as i32 as u64 {
        return *msg;
    }
    if count > 2147483647 as i32 as u64
        || msgLen > (2147483647 as i32 as u64).wrapping_sub(count)
    {
        return 0 as *mut xmlChar;
    }
    resultLen = msgLen
        .wrapping_add(count)
        .wrapping_add(1 as i32 as u64);
    result = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(resultLen.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64))
        as *mut xmlChar;
    if result.is_null() {
        xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
        *msg = 0 as *mut xmlChar;
        xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8);
        return 0 as *mut xmlChar;
    }
    msgPtr = *msg;
    resultPtr = result;
    while *msgPtr as i32 != '\u{0}' as i32 {
        *resultPtr = *msgPtr;
        if *msgPtr as i32 == '%' as i32 {
            resultPtr = resultPtr.offset(1);
            *resultPtr = '%' as i32 as xmlChar;
        }
        msgPtr = msgPtr.offset(1);
        resultPtr = resultPtr.offset(1);
    }
    *result
        .offset(
            resultLen.wrapping_sub(1 as i32 as u64) as isize,
        ) = '\u{0}' as i32 as xmlChar;
    xmlFree.expect("non-null function pointer")(*msg as *mut libc::c_void);
    *msg = result;
    return *msg;
}
