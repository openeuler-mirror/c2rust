use :: libc;
extern "C" {
    pub type _xmlStartTag;
    pub type _xmlBuf;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: core::ffi::VaList) -> i32;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn strlen(_: *const i8) -> u64;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    static mut xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlRealloc:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
    static mut xmlMallocAtomic: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    fn xmlErrMemory(ctxt: *mut crate::src::tree::_xmlParserCtxt, extra: *const i8);
}
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xpointer::_xmlDict;
pub type __builtin_va_list = [crate::src::xmllint::__va_list_tag; 1];
pub type __va_list_tag = crate::src::xmllint::__va_list_tag;
pub type va_list = [crate::src::xmllint::__va_list_tag; 1];
pub type xmlChar = u8;
pub type xmlParserCtxtPtr = *mut crate::src::tree::_xmlParserCtxt;
pub type xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type _xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
pub type _xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
pub type _xmlNode = crate::src::threads::_xmlNode;
pub type xmlNs = crate::src::threads::_xmlNs;
pub type _xmlNs = crate::src::threads::_xmlNs;
pub type _xmlDoc = crate::src::threads::_xmlDoc;
pub type _xmlDtd = crate::src::threads::_xmlDtd;
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
pub type _xmlAttr = crate::src::threads::_xmlAttr;
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
pub type xmlParserMode = u32;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::threads::_xmlError;
pub type _xmlError = crate::src::threads::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut crate::src::threads::_xmlAttr;
pub type xmlAttr = crate::src::threads::_xmlAttr;
pub type xmlNodePtr = *mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlHashTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlHashTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlStartTag = crate::src::xmlstring::_xmlStartTag;
pub type xmlDictPtr = *mut crate::src::xpointer::_xmlDict;
pub type xmlDict = crate::src::xpointer::_xmlDict;
pub type xmlParserInputPtr = *mut crate::src::threads::_xmlParserInput;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type _xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInputBufferPtr = *mut crate::src::threads::_xmlParserInputBuffer;
pub type xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type _xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlBufPtr = *mut crate::src::xmlstring::_xmlBuf;
pub type xmlBuf = crate::src::xmlstring::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut crate::src::threads::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type _xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type iconv_t = *mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(_: *mut u8, _: *mut i32, _: *const u8, _: *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>;
pub type xmlParserInputState = i32;
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
pub type xmlValidCtxt = crate::src::tree::_xmlValidCtxt;
pub type _xmlValidCtxt = crate::src::tree::_xmlValidCtxt;
pub type xmlAutomataStatePtr = *mut crate::src::xmlregexp::_xmlAutomataState;
pub type xmlAutomataState = crate::src::xmlregexp::_xmlAutomataState;
pub type xmlAutomataPtr = *mut crate::src::xmlregexp::_xmlAutomata;
pub type xmlAutomata = crate::src::xmlregexp::_xmlAutomata;
pub type xmlValidState = crate::src::valid::_xmlValidState;
pub type xmlDocPtr = *mut crate::src::threads::_xmlDoc;
pub type xmlDoc = crate::src::threads::_xmlDoc;
pub type xmlValidityWarningFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlValidityErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
pub type _xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
pub type _xmlSAXHandler = crate::src::tree::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut crate::src::threads::_xmlError) -> (),
>;
pub type xmlErrorPtr = *mut crate::src::threads::_xmlError;
pub type endElementNsSAX2Func = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type startElementNsSAX2Func = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: *mut *const u8,
        _: i32,
        _: i32,
        _: *mut *const u8,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type getParameterEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type xmlEntityPtr = *mut crate::src::threads::_xmlEntity;
pub type xmlEntity = crate::src::threads::_xmlEntity;
pub type _xmlEntity = crate::src::threads::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type errorSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type warningSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type commentSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>;
pub type referenceSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type endElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *mut *const u8) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *mut crate::src::threads::_xmlSAXLocator,
    ) -> (),
>;
pub type xmlSAXLocatorPtr = *mut crate::src::threads::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
pub type _xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: *const u8,
        _: *const u8,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *mut crate::src::threads::_xmlElementContent,
    ) -> (),
>;
pub type xmlElementContentPtr = *mut crate::src::threads::_xmlElementContent;
pub type xmlElementContent = crate::src::threads::_xmlElementContent;
pub type _xmlElementContent = crate::src::threads::_xmlElementContent;
pub type xmlElementContentOccur = u32;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = u32;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
        _: i32,
        _: i32,
        _: *const u8,
        _: *mut crate::src::threads::_xmlEnumeration,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type _xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: i32,
        _: *const u8,
        _: *const u8,
        _: *mut u8,
    ) -> (),
>;
pub type getEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity,
>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlParserInput,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8, _: *const u8) -> (),
>;
pub type size_t = u64;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
#[no_mangle]
pub extern "C" fn xmlStrndup(mut cur: *const u8, mut len: i32) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            (len as size_t)
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    (unsafe {
        memcpy(
            ret as *mut libc::c_void,
            cur as *const libc::c_void,
            (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    (unsafe { *ret.offset(len as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrdup(mut cur: *const u8) -> *mut u8 {
    let mut p: *const u8 = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *p }) as i32 != 0 as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlStrndup(cur, (unsafe { p.offset_from(cur) }) as i64 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCharStrndup(mut cur: *const i8, mut len: i32) -> *mut u8 {
    let mut i: i32 = 0;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    ret = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            (len as size_t)
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    i = 0 as i32;
    while i < len {
        (unsafe { *ret.offset(i as isize) = *cur.offset(i as isize) as xmlChar });
        if (unsafe { *ret.offset(i as isize) }) as i32 == 0 as i32 {
            return ret;
        }
        i += 1;
    }
    (unsafe { *ret.offset(len as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCharStrdup(mut cur: *const i8) -> *mut u8 {
    let mut p: *const i8 = cur;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *p }) as i32 != '\u{0}' as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlCharStrndup(cur, (unsafe { p.offset_from(cur) }) as i64 as i32);
}
#[no_mangle]
pub extern "C" fn xmlStrcmp(mut str1: *const u8, mut str2: *const u8) -> i32 {
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
        let mut fresh0 = str1;
        str1 = unsafe { str1.offset(1) };
        let mut tmp: i32 = (unsafe { *fresh0 }) as i32 - (unsafe { *str2 }) as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let mut fresh1 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh1 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrEqual(mut str1: *const u8, mut str2: *const u8) -> i32 {
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
        let mut fresh2 = str1;
        str1 = unsafe { str1.offset(1) };
        if (unsafe { *fresh2 }) as i32 != (unsafe { *str2 }) as i32 {
            return 0 as i32;
        }
        let mut fresh3 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh3 }) != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrQEqual(
    mut pref: *const u8,
    mut name: *const u8,
    mut str: *const u8,
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
        let mut fresh4 = pref;
        pref = unsafe { pref.offset(1) };
        if (unsafe { *fresh4 }) as i32 != (unsafe { *str }) as i32 {
            return 0 as i32;
        }
        let mut fresh5 = str;
        str = unsafe { str.offset(1) };
        if !((unsafe { *fresh5 }) as i32 != 0 && (unsafe { *pref }) as i32 != 0) {
            break;
        }
    }
    let mut fresh6 = str;
    str = unsafe { str.offset(1) };
    if (unsafe { *fresh6 }) as i32 != ':' as i32 {
        return 0 as i32;
    }
    loop {
        let mut fresh7 = name;
        name = unsafe { name.offset(1) };
        if (unsafe { *fresh7 }) as i32 != (unsafe { *str }) as i32 {
            return 0 as i32;
        }
        let mut fresh8 = str;
        str = unsafe { str.offset(1) };
        if !((unsafe { *fresh8 }) != 0) {
            break;
        }
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrncmp(mut str1: *const u8, mut str2: *const u8, mut len: i32) -> i32 {
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
        let mut fresh9 = str1;
        str1 = unsafe { str1.offset(1) };
        let mut tmp: i32 = (unsafe { *fresh9 }) as i32 - (unsafe { *str2 }) as i32;
        if tmp != 0 as i32 || {
            len -= 1;
            len == 0 as i32
        } {
            return tmp;
        }
        let mut fresh10 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh10 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
static mut casemap: [u8; 256] = [
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
pub extern "C" fn xmlStrcasecmp(mut str1: *const u8, mut str2: *const u8) -> i32 {
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
        let mut fresh11 = str1;
        str1 = unsafe { str1.offset(1) };
        tmp = (unsafe { casemap[*fresh11 as usize] }) as i32
            - (unsafe { casemap[*str2 as usize] }) as i32;
        if tmp != 0 as i32 {
            return tmp;
        }
        let mut fresh12 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh12 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrncasecmp(mut str1: *const u8, mut str2: *const u8, mut len: i32) -> i32 {
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
        let mut fresh13 = str1;
        str1 = unsafe { str1.offset(1) };
        tmp = (unsafe { casemap[*fresh13 as usize] }) as i32
            - (unsafe { casemap[*str2 as usize] }) as i32;
        if tmp != 0 as i32 || {
            len -= 1;
            len == 0 as i32
        } {
            return tmp;
        }
        let mut fresh14 = str2;
        str2 = unsafe { str2.offset(1) };
        if !((unsafe { *fresh14 }) as i32 != 0 as i32) {
            break;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlStrchr(mut str: *const u8, mut val: u8) -> *const u8 {
    if str.is_null() {
        return 0 as *const libc::c_void as *const xmlChar;
    }
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { *str }) as i32 == val as i32 {
            return str as *mut xmlChar;
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrstr(mut str: *const u8, mut val: *const u8) -> *const u8 {
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
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { *str }) as i32 == (unsafe { *val }) as i32 {
            if xmlStrncmp(str, val, n) == 0 {
                return str;
            }
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrcasestr(mut str: *const u8, mut val: *const u8) -> *const u8 {
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
    while (unsafe { *str }) as i32 != 0 as i32 {
        if (unsafe { casemap[*str as usize] }) as i32 == (unsafe { casemap[*val as usize] }) as i32
        {
            if xmlStrncasecmp(str, val, n) == 0 {
                return str;
            }
        }
        str = unsafe { str.offset(1) };
    }
    return 0 as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlStrsub(mut str: *const u8, mut start: i32, mut len: i32) -> *mut u8 {
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
        if (unsafe { *str }) as i32 == 0 as i32 {
            return 0 as *mut xmlChar;
        }
        str = unsafe { str.offset(1) };
        i += 1;
    }
    if (unsafe { *str }) as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(str, len);
}
#[no_mangle]
pub extern "C" fn xmlStrlen(mut str: *const u8) -> i32 {
    let mut len: u64 = if !str.is_null() {
        unsafe { strlen(str as *const i8) }
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
pub extern "C" fn xmlStrncat(mut cur: *mut u8, mut add: *const u8, mut len: i32) -> *mut u8 {
    let mut size: i32 = 0;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
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
    ret = (unsafe {
        xmlRealloc.expect("non-null function pointer")(
            cur as *mut libc::c_void,
            (size as size_t)
                .wrapping_add(len as u64)
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return cur;
    }
    (unsafe {
        memcpy(
            &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
            add as *const libc::c_void,
            (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    (unsafe { *ret.offset((size + len) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrncatNew(mut str1: *const u8, mut str2: *const u8, mut len: i32) -> *mut u8 {
    let mut size: i32 = 0;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
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
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(
            (size as size_t)
                .wrapping_add(len as u64)
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if ret.is_null() {
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return xmlStrndup(str1, size);
    }
    (unsafe {
        memcpy(
            ret as *mut libc::c_void,
            str1 as *const libc::c_void,
            (size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    (unsafe {
        memcpy(
            &mut *ret.offset(size as isize) as *mut xmlChar as *mut libc::c_void,
            str2 as *const libc::c_void,
            (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    (unsafe { *ret.offset((size + len) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrcat(mut cur: *mut u8, mut add: *const u8) -> *mut u8 {
    let mut p: *const u8 = add;
    if add.is_null() {
        return cur;
    }
    if cur.is_null() {
        return xmlStrdup(add);
    }
    while (unsafe { *p }) as i32 != 0 as i32 {
        p = unsafe { p.offset(1) };
    }
    return xmlStrncat(cur, add, (unsafe { p.offset_from(add) }) as i64 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStrPrintf(
    mut buf: *mut u8,
    mut len: i32,
    mut msg: *const i8,
    mut args: ...
) -> i32 {
    let mut args_0: core::ffi::VaListImpl;
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    args_0 = args.clone();
    ret = vsnprintf(buf as *mut i8, len as u64, msg, args_0.as_va_list());
    *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStrVPrintf(
    mut buf: *mut u8,
    mut len: i32,
    mut msg: *const i8,
    mut ap: core::ffi::VaList,
) -> i32 {
    let mut ret: i32 = 0;
    if buf.is_null() || msg.is_null() {
        return -(1 as i32);
    }
    ret = unsafe { vsnprintf(buf as *mut i8, len as u64, msg, ap.as_va_list()) };
    (unsafe { *buf.offset((len - 1 as i32) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Size(mut utf: *const u8) -> i32 {
    let mut mask: u8 = 0;
    let mut len: i32 = 0;
    if utf.is_null() {
        return -(1 as i32);
    }
    if ((unsafe { *utf }) as i32) < 0x80 as i32 {
        return 1 as i32;
    }
    if (unsafe { *utf }) as i32 & 0x40 as i32 == 0 {
        return -(1 as i32);
    }
    len = 2 as i32;
    mask = 0x20 as i32 as xmlChar;
    while mask as i32 != 0 as i32 {
        if (unsafe { *utf }) as i32 & mask as i32 == 0 {
            return len;
        }
        len += 1;
        mask = (mask as i32 >> 1 as i32) as xmlChar;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlUTF8Charcmp(mut utf1: *const u8, mut utf2: *const u8) -> i32 {
    if utf1.is_null() {
        if utf2.is_null() {
            return 0 as i32;
        }
        return -(1 as i32);
    }
    return xmlStrncmp(utf1, utf2, xmlUTF8Size(utf1));
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strlen(mut utf: *const u8) -> i32 {
    let mut ret: u64 = 0 as i32 as size_t;
    if utf.is_null() {
        return -(1 as i32);
    }
    while (unsafe { *utf }) as i32 != 0 as i32 {
        if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0x80 as i32 != 0 {
            if (unsafe { *utf.offset(1 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                return -(1 as i32);
            }
            if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xe0 as i32 == 0xe0 as i32 {
                if (unsafe { *utf.offset(2 as i32 as isize) }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
                if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf0 as i32 == 0xf0 as i32 {
                    if (unsafe { *utf.offset(0 as i32 as isize) }) as i32 & 0xf8 as i32
                        != 0xf0 as i32
                        || (unsafe { *utf.offset(3 as i32 as isize) }) as i32 & 0xc0 as i32
                            != 0x80 as i32
                    {
                        return -(1 as i32);
                    }
                    utf = unsafe { utf.offset(4 as i32 as isize) };
                } else {
                    utf = unsafe { utf.offset(3 as i32 as isize) };
                }
            } else {
                utf = unsafe { utf.offset(2 as i32 as isize) };
            }
        } else {
            utf = unsafe { utf.offset(1) };
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
pub extern "C" fn xmlGetUTF8Char<'a1, 'a2>(
    mut utf: Option<crate::__laertes_array::CustomSlice<'a1, u8, &'a1 [u8]>>,
    mut len: Option<&'a2 mut i32>,
) -> i32 {
    let mut current_block: u64;
    let mut c: u32 = 0;
    if !crate::__laertes_array::borrow(&utf).is_none() {
        if !borrow(&len).is_none() {
            if !(*(borrow(&len)).unwrap() < 1 as i32) {
                c = (*crate::__laertes_array::Get::<&_>::get_offset(
                    utf.as_ref().unwrap(),
                    0 as i32 as isize,
                )) as u32;
                if c & 0x80 as i32 as u32 != 0 {
                    if *(borrow(&len)).unwrap() < 2 as i32 {
                        current_block = 3966416321279884290;
                    } else if (*crate::__laertes_array::Get::<&_>::get_offset(
                        crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                        1 as i32 as isize,
                    )) as i32
                        & 0xc0 as i32
                        != 0x80 as i32
                    {
                        current_block = 3966416321279884290;
                    } else if c & 0xe0 as i32 as u32 == 0xe0 as i32 as u32 {
                        if *(borrow(&len)).unwrap() < 3 as i32 {
                            current_block = 3966416321279884290;
                        } else if (*crate::__laertes_array::Get::<&_>::get_offset(
                            crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                            2 as i32 as isize,
                        )) as i32
                            & 0xc0 as i32
                            != 0x80 as i32
                        {
                            current_block = 3966416321279884290;
                        } else if c & 0xf0 as i32 as u32 == 0xf0 as i32 as u32 {
                            if *(borrow(&len)).unwrap() < 4 as i32 {
                                current_block = 3966416321279884290;
                            } else if c & 0xf8 as i32 as u32 != 0xf0 as i32 as u32
                                || (*crate::__laertes_array::Get::<&_>::get_offset(
                                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                    3 as i32 as isize,
                                )) as i32
                                    & 0xc0 as i32
                                    != 0x80 as i32
                            {
                                current_block = 3966416321279884290;
                            } else {
                                *(borrow_mut(&mut len)).unwrap() = 4 as i32;
                                c = (((*crate::__laertes_array::Get::<&_>::get_offset(
                                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                    0 as i32 as isize,
                                )) as i32
                                    & 0x7 as i32)
                                    << 18 as i32) as u32;
                                c |= (((*crate::__laertes_array::Get::<&_>::get_offset(
                                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                    1 as i32 as isize,
                                )) as i32
                                    & 0x3f as i32)
                                    << 12 as i32) as u32;
                                c |= (((*crate::__laertes_array::Get::<&_>::get_offset(
                                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                    2 as i32 as isize,
                                )) as i32
                                    & 0x3f as i32)
                                    << 6 as i32) as u32;
                                c |= ((*crate::__laertes_array::Get::<&_>::get_offset(
                                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                    3 as i32 as isize,
                                )) as i32
                                    & 0x3f as i32) as u32;
                                current_block = 11932355480408055363;
                            }
                        } else {
                            *(borrow_mut(&mut len)).unwrap() = 3 as i32;
                            c = (((*crate::__laertes_array::Get::<&_>::get_offset(
                                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                0 as i32 as isize,
                            )) as i32
                                & 0xf as i32)
                                << 12 as i32) as u32;
                            c |= (((*crate::__laertes_array::Get::<&_>::get_offset(
                                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                1 as i32 as isize,
                            )) as i32
                                & 0x3f as i32)
                                << 6 as i32) as u32;
                            c |= ((*crate::__laertes_array::Get::<&_>::get_offset(
                                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                                2 as i32 as isize,
                            )) as i32
                                & 0x3f as i32) as u32;
                            current_block = 11932355480408055363;
                        }
                    } else {
                        *(borrow_mut(&mut len)).unwrap() = 2 as i32;
                        c = (((*crate::__laertes_array::Get::<&_>::get_offset(
                            crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                            0 as i32 as isize,
                        )) as i32
                            & 0x1f as i32)
                            << 6 as i32) as u32;
                        c |= ((*crate::__laertes_array::Get::<&_>::get_offset(
                            crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                            1 as i32 as isize,
                        )) as i32
                            & 0x3f as i32) as u32;
                        current_block = 11932355480408055363;
                    }
                } else {
                    *(borrow_mut(&mut len)).unwrap() = 1 as i32;
                    current_block = 11932355480408055363;
                }
                match current_block {
                    3966416321279884290 => {}
                    _ => return c as i32,
                }
            }
        }
    }
    if !borrow(&len).is_none() {
        *(borrow_mut(&mut len)).unwrap() = 0 as i32;
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlCheckUTF8(
    mut utf: Option<crate::__laertes_array::CustomSlice<'static, u8, Box<[u8]>>>,
) -> i32 {
    let mut ix: i32 = 0;
    let mut c: u8 = 0;
    if crate::__laertes_array::borrow(&utf).is_none() {
        return 0 as i32;
    }
    loop {
        c = *crate::__laertes_array::Get::<&_>::get_offset(
            utf.as_ref().unwrap(),
            0 as i32 as isize,
        );
        if !(c != 0) {
            break;
        }
        ix = 0 as i32;
        if c as i32 & 0x80 as i32 == 0 as i32 {
            ix = 1 as i32;
        } else if c as i32 & 0xe0 as i32 == 0xc0 as i32 {
            if (*crate::__laertes_array::Get::<&_>::get_offset(
                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                1 as i32 as isize,
            )) as i32
                & 0xc0 as i32
                != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 2 as i32;
        } else if c as i32 & 0xf0 as i32 == 0xe0 as i32 {
            if (*crate::__laertes_array::Get::<&_>::get_offset(
                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                1 as i32 as isize,
            )) as i32
                & 0xc0 as i32
                != 0x80 as i32
                || (*crate::__laertes_array::Get::<&_>::get_offset(
                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                    2 as i32 as isize,
                )) as i32
                    & 0xc0 as i32
                    != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 3 as i32;
        } else if c as i32 & 0xf8 as i32 == 0xf0 as i32 {
            if (*crate::__laertes_array::Get::<&_>::get_offset(
                crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                1 as i32 as isize,
            )) as i32
                & 0xc0 as i32
                != 0x80 as i32
                || (*crate::__laertes_array::Get::<&_>::get_offset(
                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                    2 as i32 as isize,
                )) as i32
                    & 0xc0 as i32
                    != 0x80 as i32
                || (*crate::__laertes_array::Get::<&_>::get_offset(
                    crate::__laertes_array::borrow(&utf).as_ref().unwrap(),
                    3 as i32 as isize,
                )) as i32
                    & 0xc0 as i32
                    != 0x80 as i32
            {
                return 0 as i32;
            }
            ix = 4 as i32;
        } else {
            return 0 as i32;
        }
        utf = Some(crate::__laertes_array::IntoSlice::into_slice_offset(
            utf.unwrap(),
            ix as isize,
        ));
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strsize(mut utf: *const u8, mut len: i32) -> i32 {
    let mut ptr: *const u8 = utf;
    let mut ch: i32 = 0;
    let mut ret: u64 = 0;
    if utf.is_null() {
        return 0 as i32;
    }
    if len <= 0 as i32 {
        return 0 as i32;
    }
    loop {
        let mut fresh15 = len;
        len = len - 1;
        if !(fresh15 > 0 as i32) {
            break;
        }
        if (unsafe { *ptr }) == 0 {
            break;
        }
        let mut fresh16 = ptr;
        ptr = unsafe { ptr.offset(1) };
        ch = (unsafe { *fresh16 }) as i32;
        if ch & 0x80 as i32 != 0 {
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                if (unsafe { *ptr }) as i32 == 0 as i32 {
                    break;
                }
                ptr = unsafe { ptr.offset(1) };
            }
        }
    }
    ret = (unsafe { ptr.offset_from(utf) }) as i64 as size_t;
    return (if ret > 2147483647 as i32 as u64 {
        0 as i32 as u64
    } else {
        ret
    }) as i32;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strndup(mut utf: *const u8, mut len: i32) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut i: i32 = 0;
    if utf.is_null() || len < 0 as i32 {
        return 0 as *mut xmlChar;
    }
    i = xmlUTF8Strsize(utf, len);
    ret = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            (i as size_t)
                .wrapping_add(1 as i32 as u64)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if ret.is_null() {
        return 0 as *mut xmlChar;
    }
    (unsafe {
        memcpy(
            ret as *mut libc::c_void,
            utf as *const libc::c_void,
            (i as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    (unsafe { *ret.offset(i as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strpos(mut utf: *const u8, mut pos: i32) -> *const u8 {
    let mut ch: i32 = 0;
    if utf.is_null() {
        return 0 as *const u8;
    }
    if pos < 0 as i32 {
        return 0 as *const u8;
    }
    loop {
        let mut fresh17 = pos;
        pos = pos - 1;
        if !(fresh17 != 0) {
            break;
        }
        let mut fresh18 = utf;
        utf = unsafe { utf.offset(1) };
        ch = (unsafe { *fresh18 }) as i32;
        if ch == 0 as i32 {
            return 0 as *const u8;
        }
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return 0 as *const u8;
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let mut fresh19 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh19 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return 0 as *const u8;
                }
            }
        }
    }
    return utf as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strloc(mut utf: *const u8, mut utfchar: *const u8) -> i32 {
    let mut i: u64 = 0;
    let mut size: i32 = 0;
    let mut ch: i32 = 0;
    if utf.is_null() || utfchar.is_null() {
        return -(1 as i32);
    }
    size = xmlUTF8Strsize(utfchar, 1 as i32);
    i = 0 as i32 as size_t;
    loop {
        ch = (unsafe { *utf }) as i32;
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
        utf = unsafe { utf.offset(1) };
        if ch & 0x80 as i32 != 0 {
            if ch & 0xc0 as i32 != 0xc0 as i32 {
                return -(1 as i32);
            }
            loop {
                ch <<= 1 as i32;
                if !(ch & 0x80 as i32 != 0) {
                    break;
                }
                let mut fresh20 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh20 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return -(1 as i32);
                }
            }
        }
        i = i.wrapping_add(1);
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlUTF8Strsub(mut utf: *const u8, mut start: i32, mut len: i32) -> *mut u8 {
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
        let mut fresh21 = utf;
        utf = unsafe { utf.offset(1) };
        ch = (unsafe { *fresh21 }) as i32;
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
                let mut fresh22 = utf;
                utf = unsafe { utf.offset(1) };
                if (unsafe { *fresh22 }) as i32 & 0xc0 as i32 != 0x80 as i32 {
                    return 0 as *mut xmlChar;
                }
            }
        }
        i += 1;
    }
    return xmlUTF8Strndup(utf, len);
}
#[no_mangle]
pub extern "C" fn xmlEscapeFormatString<'a1>(mut msg: Option<&'a1 mut *mut u8>) -> *mut u8 {
    let mut msgPtr: *mut u8 = 0 as *mut xmlChar;
    let mut result: *mut u8 = 0 as *mut xmlChar;
    let mut resultPtr: *mut u8 = 0 as *mut xmlChar;
    let mut count: u64 = 0 as i32 as size_t;
    let mut msgLen: u64 = 0 as i32 as size_t;
    let mut resultLen: u64 = 0 as i32 as size_t;
    if borrow(&msg).is_none() || (*(borrow_mut(&mut msg)).unwrap()).is_null() {
        return 0 as *mut xmlChar;
    }
    msgPtr = *(borrow_mut(&mut msg)).unwrap();
    while (unsafe { *msgPtr }) as i32 != '\u{0}' as i32 {
        msgLen = msgLen.wrapping_add(1);
        if (unsafe { *msgPtr }) as i32 == '%' as i32 {
            count = count.wrapping_add(1);
        }
        msgPtr = unsafe { msgPtr.offset(1) };
    }
    if count == 0 as i32 as u64 {
        return *(borrow_mut(&mut msg)).unwrap();
    }
    if count > 2147483647 as i32 as u64 || msgLen > (2147483647 as i32 as u64).wrapping_sub(count) {
        return 0 as *mut xmlChar;
    }
    resultLen = msgLen.wrapping_add(count).wrapping_add(1 as i32 as u64);
    result = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            resultLen.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if result.is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                *(borrow_mut(&mut msg)).unwrap() as *mut libc::c_void
            )
        });
        *(borrow_mut(&mut msg)).unwrap() = 0 as *mut xmlChar;
        (unsafe { xmlErrMemory(0 as xmlParserCtxtPtr, 0 as *const i8) });
        return 0 as *mut xmlChar;
    }
    msgPtr = *(borrow_mut(&mut msg)).unwrap();
    resultPtr = result;
    while (unsafe { *msgPtr }) as i32 != '\u{0}' as i32 {
        (unsafe { *resultPtr = *msgPtr });
        if (unsafe { *msgPtr }) as i32 == '%' as i32 {
            resultPtr = unsafe { resultPtr.offset(1) };
            (unsafe { *resultPtr = '%' as i32 as xmlChar });
        }
        msgPtr = unsafe { msgPtr.offset(1) };
        resultPtr = unsafe { resultPtr.offset(1) };
    }
    (unsafe {
        *result.offset(resultLen.wrapping_sub(1 as i32 as u64) as isize) = '\u{0}' as i32 as xmlChar
    });
    (unsafe {
        xmlFree.expect("non-null function pointer")(
            *(borrow_mut(&mut msg)).unwrap() as *mut libc::c_void
        )
    });
    *(borrow_mut(&mut msg)).unwrap() = result;
    return *(borrow_mut(&mut msg)).unwrap();
}
use crate::laertes_rt::*;
