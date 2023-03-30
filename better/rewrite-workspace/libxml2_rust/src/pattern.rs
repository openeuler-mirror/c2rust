use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    
    
    
    static mut xmlMalloc: xmlMallocFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlFree: xmlFreeFunc;
    
    
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsExtenderGroup: xmlChRangeGroup;
}
pub use crate::src::chvalid::xmlCharInRange;
pub use crate::src::dict::xmlDictFree;
pub use crate::src::dict::xmlDictLookup;
pub use crate::src::dict::xmlDictReference;
pub use crate::src::parserInternals::xmlStringCurrentChar;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
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
pub use crate::src::HTMLparser::xmlParserInputBuffer;
pub use crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputDeallocate;
pub use crate::src::HTMLparser::xmlParserInput;
pub use crate::src::HTMLparser::xmlParserInputPtr;
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
pub use crate::src::HTMLparser::xmlParserCtxt;
pub use crate::src::HTMLparser::xmlParserCtxtPtr;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChSRange;
pub use crate::src::HTMLparser::xmlChSRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChLRange;
pub use crate::src::HTMLparser::xmlChLRange;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLparser::_xmlChRangeGroup;
pub use crate::src::HTMLparser::xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlPattern {
    pub data: *mut libc::c_void,
    pub dict: xmlDictPtr,
    pub next: *mut _xmlPattern,
    pub pattern: *const xmlChar,
    pub flags: libc::c_int,
    pub nbStep: libc::c_int,
    pub maxStep: libc::c_int,
    pub steps: xmlStepOpPtr,
    pub stream: xmlStreamCompPtr,
}
pub type xmlStreamCompPtr = *mut xmlStreamComp;
pub type xmlStreamComp = _xmlStreamComp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamComp {
    pub dict: *mut xmlDict,
    pub nbStep: libc::c_int,
    pub maxStep: libc::c_int,
    pub steps: xmlStreamStepPtr,
    pub flags: libc::c_int,
}
pub type xmlStreamStepPtr = *mut xmlStreamStep;
pub type xmlStreamStep = _xmlStreamStep;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamStep {
    pub flags: libc::c_int,
    pub name: *const xmlChar,
    pub ns: *const xmlChar,
    pub nodeType: libc::c_int,
}
pub type xmlStepOpPtr = *mut xmlStepOp;
pub type xmlStepOp = _xmlStepOp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepOp {
    pub op: xmlPatOp,
    pub value: *const xmlChar,
    pub value2: *const xmlChar,
}
pub type xmlPatOp = libc::c_uint;
pub const XML_OP_ALL: xmlPatOp = 8;
pub const XML_OP_NS: xmlPatOp = 7;
pub const XML_OP_ANCESTOR: xmlPatOp = 6;
pub const XML_OP_PARENT: xmlPatOp = 5;
pub const XML_OP_ATTR: xmlPatOp = 4;
pub const XML_OP_CHILD: xmlPatOp = 3;
pub const XML_OP_ELEM: xmlPatOp = 2;
pub const XML_OP_ROOT: xmlPatOp = 1;
pub const XML_OP_END: xmlPatOp = 0;
pub type xmlPattern = _xmlPattern;
pub type xmlPatternPtr = *mut xmlPattern;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_PATTERN_XSFIELD: C2RustUnnamed = 4;
pub const XML_PATTERN_XSSEL: C2RustUnnamed = 2;
pub const XML_PATTERN_XPATH: C2RustUnnamed = 1;
pub const XML_PATTERN_DEFAULT: C2RustUnnamed = 0;
pub type xmlPatParserContextPtr = *mut xmlPatParserContext;
pub type xmlPatParserContext = _xmlPatParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlPatParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: libc::c_int,
    pub dict: xmlDictPtr,
    pub comp: xmlPatternPtr,
    pub elem: xmlNodePtr,
    pub namespaces: *mut *const xmlChar,
    pub nb_namespaces: libc::c_int,
}
pub type xmlStepStatePtr = *mut xmlStepState;
pub type xmlStepState = _xmlStepState;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepState {
    pub step: libc::c_int,
    pub node: xmlNodePtr,
}
pub type xmlStepStates = _xmlStepStates;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStepStates {
    pub nbstates: libc::c_int,
    pub maxstates: libc::c_int,
    pub states: xmlStepStatePtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStreamCtxt {
    pub next: *mut _xmlStreamCtxt,
    pub comp: xmlStreamCompPtr,
    pub nbState: libc::c_int,
    pub maxState: libc::c_int,
    pub level: libc::c_int,
    pub states: *mut libc::c_int,
    pub flags: libc::c_int,
    pub blockLevel: libc::c_int,
}
pub type xmlStreamCtxt = _xmlStreamCtxt;
pub type xmlStreamCtxtPtr = *mut xmlStreamCtxt;
unsafe extern "C" fn xmlNewPattern() -> xmlPatternPtr {
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlPattern>() as libc::c_ulong) as xmlPatternPtr;
    if cur.is_null() {
        return 0 as xmlPatternPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlPattern>() as libc::c_ulong,
    );
    (*cur).maxStep = 10 as libc::c_int;
    let ref mut fresh0 = (*cur).steps;
    *fresh0 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        ((*cur).maxStep as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlStepOp>() as libc::c_ulong),
    ) as xmlStepOpPtr;
    if ((*cur).steps).is_null() {
        xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
        return 0 as xmlPatternPtr;
    }
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreePattern(mut comp: xmlPatternPtr) {
    xmlFreePatternList(comp);
}
unsafe extern "C" fn xmlFreePatternInternal(mut comp: xmlPatternPtr) {
    let mut op: xmlStepOpPtr = 0 as *mut xmlStepOp;
    let mut i: libc::c_int = 0;
    if comp.is_null() {
        return;
    }
    if !((*comp).stream).is_null() {
        xmlFreeStreamComp((*comp).stream);
    }
    if !((*comp).pattern).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*comp).pattern as *mut xmlChar as *mut libc::c_void);
    }
    if !((*comp).steps).is_null() {
        if ((*comp).dict).is_null() {
            i = 0 as libc::c_int;
            while i < (*comp).nbStep {
                op = &mut *((*comp).steps).offset(i as isize) as *mut xmlStepOp;
                if !((*op).value).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*op).value as *mut xmlChar as *mut libc::c_void);
                }
                if !((*op).value2).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*op).value2 as *mut xmlChar as *mut libc::c_void);
                }
                i += 1;
            }
        }
        xmlFree.expect("non-null function pointer")((*comp).steps as *mut libc::c_void);
    }
    if !((*comp).dict).is_null() {
        xmlDictFree((*comp).dict);
    }
    memset(
        comp as *mut libc::c_void,
        -(1 as libc::c_int),
        ::std::mem::size_of::<xmlPattern>() as libc::c_ulong,
    );
    xmlFree.expect("non-null function pointer")(comp as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreePatternList(mut comp: xmlPatternPtr) {
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    while !comp.is_null() {
        cur = comp;
        comp = (*comp).next;
        let ref mut fresh1 = (*cur).next;
        *fresh1 = 0 as *mut _xmlPattern;
        xmlFreePatternInternal(cur);
    }
}
unsafe extern "C" fn xmlNewPatParserContext(
    mut pattern: *const xmlChar,
    mut dict: xmlDictPtr,
    mut namespaces: *mut *const xmlChar,
) -> xmlPatParserContextPtr {
    let mut cur: xmlPatParserContextPtr = 0 as *mut xmlPatParserContext;
    if pattern.is_null() {
        return 0 as xmlPatParserContextPtr;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlPatParserContext>() as libc::c_ulong)
        as xmlPatParserContextPtr;
    if cur.is_null() {
        return 0 as xmlPatParserContextPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlPatParserContext>() as libc::c_ulong,
    );
    let ref mut fresh2 = (*cur).dict;
    *fresh2 = dict;
    let ref mut fresh3 = (*cur).cur;
    *fresh3 = pattern;
    let ref mut fresh4 = (*cur).base;
    *fresh4 = pattern;
    if !namespaces.is_null() {
        let mut i: libc::c_int = 0;
        i = 0 as libc::c_int;
        while !(*namespaces.offset((2 as libc::c_int * i) as isize)).is_null() {
            i += 1;
        }
        (*cur).nb_namespaces = i;
    } else {
        (*cur).nb_namespaces = 0 as libc::c_int;
    }
    let ref mut fresh5 = (*cur).namespaces;
    *fresh5 = namespaces;
    return cur;
}
unsafe extern "C" fn xmlFreePatParserContext(mut ctxt: xmlPatParserContextPtr) {
    if ctxt.is_null() {
        return;
    }
    memset(
        ctxt as *mut libc::c_void,
        -(1 as libc::c_int),
        ::std::mem::size_of::<xmlPatParserContext>() as libc::c_ulong,
    );
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlPatternAdd(
    mut ctxt: xmlPatParserContextPtr,
    mut comp: xmlPatternPtr,
    mut op: xmlPatOp,
    mut value: *mut xmlChar,
    mut value2: *mut xmlChar,
) -> libc::c_int {
    if (*comp).nbStep >= (*comp).maxStep {
        let mut temp: xmlStepOpPtr = 0 as *mut xmlStepOp;
        temp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStepOp>() as libc::c_ulong),
        ) as xmlStepOpPtr;
        if temp.is_null() {
            return -(1 as libc::c_int);
        }
        let ref mut fresh6 = (*comp).steps;
        *fresh6 = temp;
        (*comp).maxStep *= 2 as libc::c_int;
    }
    (*((*comp).steps).offset((*comp).nbStep as isize)).op = op;
    let ref mut fresh7 = (*((*comp).steps).offset((*comp).nbStep as isize)).value;
    *fresh7 = value;
    let ref mut fresh8 = (*((*comp).steps).offset((*comp).nbStep as isize)).value2;
    *fresh8 = value2;
    let ref mut fresh9 = (*comp).nbStep;
    *fresh9 += 1;
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlReversePattern(mut comp: xmlPatternPtr) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    if (*comp).nbStep > 0 as libc::c_int
        && (*((*comp).steps).offset(0 as libc::c_int as isize)).op as libc::c_uint
            == XML_OP_ANCESTOR as libc::c_int as libc::c_uint
    {
        i = 0 as libc::c_int;
        j = 1 as libc::c_int;
        while j < (*comp).nbStep {
            let ref mut fresh10 = (*((*comp).steps).offset(i as isize)).value;
            *fresh10 = (*((*comp).steps).offset(j as isize)).value;
            let ref mut fresh11 = (*((*comp).steps).offset(i as isize)).value2;
            *fresh11 = (*((*comp).steps).offset(j as isize)).value2;
            (*((*comp).steps).offset(i as isize))
                .op = (*((*comp).steps).offset(j as isize)).op;
            i += 1;
            j += 1;
        }
        let ref mut fresh12 = (*comp).nbStep;
        *fresh12 -= 1;
    }
    if (*comp).nbStep >= (*comp).maxStep {
        let mut temp: xmlStepOpPtr = 0 as *mut xmlStepOp;
        temp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStepOp>() as libc::c_ulong),
        ) as xmlStepOpPtr;
        if temp.is_null() {
            return -(1 as libc::c_int);
        }
        let ref mut fresh13 = (*comp).steps;
        *fresh13 = temp;
        (*comp).maxStep *= 2 as libc::c_int;
    }
    i = 0 as libc::c_int;
    j = (*comp).nbStep - 1 as libc::c_int;
    while j > i {
        let mut tmp: *const xmlChar = 0 as *const xmlChar;
        let mut op: xmlPatOp = XML_OP_END;
        tmp = (*((*comp).steps).offset(i as isize)).value;
        let ref mut fresh14 = (*((*comp).steps).offset(i as isize)).value;
        *fresh14 = (*((*comp).steps).offset(j as isize)).value;
        let ref mut fresh15 = (*((*comp).steps).offset(j as isize)).value;
        *fresh15 = tmp;
        tmp = (*((*comp).steps).offset(i as isize)).value2;
        let ref mut fresh16 = (*((*comp).steps).offset(i as isize)).value2;
        *fresh16 = (*((*comp).steps).offset(j as isize)).value2;
        let ref mut fresh17 = (*((*comp).steps).offset(j as isize)).value2;
        *fresh17 = tmp;
        op = (*((*comp).steps).offset(i as isize)).op;
        (*((*comp).steps).offset(i as isize))
            .op = (*((*comp).steps).offset(j as isize)).op;
        (*((*comp).steps).offset(j as isize)).op = op;
        j -= 1;
        i += 1;
    }
    let ref mut fresh18 = (*((*comp).steps).offset((*comp).nbStep as isize)).value;
    *fresh18 = 0 as *const xmlChar;
    let ref mut fresh19 = (*((*comp).steps).offset((*comp).nbStep as isize)).value2;
    *fresh19 = 0 as *const xmlChar;
    let ref mut fresh20 = (*comp).nbStep;
    let fresh21 = *fresh20;
    *fresh20 = *fresh20 + 1;
    (*((*comp).steps).offset(fresh21 as isize)).op = XML_OP_END;
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlPatPushState(
    mut states: *mut xmlStepStates,
    mut step: libc::c_int,
    mut node: xmlNodePtr,
) -> libc::c_int {
    if ((*states).states).is_null() || (*states).maxstates <= 0 as libc::c_int {
        (*states).maxstates = 4 as libc::c_int;
        (*states).nbstates = 0 as libc::c_int;
        let ref mut fresh22 = (*states).states;
        *fresh22 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (4 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStepState>() as libc::c_ulong),
        ) as xmlStepStatePtr;
    } else if (*states).maxstates <= (*states).nbstates {
        let mut tmp: *mut xmlStepState = 0 as *mut xmlStepState;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*states).states as *mut libc::c_void,
            ((2 as libc::c_int * (*states).maxstates) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStepState>() as libc::c_ulong),
        ) as xmlStepStatePtr;
        if tmp.is_null() {
            return -(1 as libc::c_int);
        }
        let ref mut fresh23 = (*states).states;
        *fresh23 = tmp;
        (*states).maxstates *= 2 as libc::c_int;
    }
    (*((*states).states).offset((*states).nbstates as isize)).step = step;
    let ref mut fresh24 = (*states).nbstates;
    let fresh25 = *fresh24;
    *fresh24 = *fresh24 + 1;
    let ref mut fresh26 = (*((*states).states).offset(fresh25 as isize)).node;
    *fresh26 = node;
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlPatMatch(
    mut comp: xmlPatternPtr,
    mut node: xmlNodePtr,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut step: xmlStepOpPtr = 0 as *mut xmlStepOp;
    let mut states: xmlStepStates = {
        let mut init = _xmlStepStates {
            nbstates: 0 as libc::c_int,
            maxstates: 0 as libc::c_int,
            states: 0 as xmlStepStatePtr,
        };
        init
    };
    if comp.is_null() || node.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while i < (*comp).nbStep {
        step = &mut *((*comp).steps).offset(i as isize) as *mut xmlStepOp;
        match (*step).op as libc::c_uint {
            0 => {
                break;
            }
            1 => {
                if (*node).type_0 as libc::c_uint
                    == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else {
                    node = (*node).parent;
                    if (*node).type_0 as libc::c_uint
                        == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                        || (*node).type_0 as libc::c_uint
                            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                    {
                        current_block = 820271813250567934;
                    } else {
                        current_block = 6451473480150109090;
                    }
                }
            }
            2 => {
                if (*node).type_0 as libc::c_uint
                    != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else if ((*step).value).is_null() {
                    current_block = 820271813250567934;
                } else if *((*step).value).offset(0 as libc::c_int as isize)
                        as libc::c_int
                        != *((*node).name).offset(0 as libc::c_int as isize)
                            as libc::c_int
                    {
                    current_block = 6451473480150109090;
                } else if xmlStrEqual((*step).value, (*node).name) == 0 {
                    current_block = 6451473480150109090;
                } else if ((*node).ns).is_null() {
                    if !((*step).value2).is_null() {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else if !((*(*node).ns).href).is_null() {
                    if ((*step).value2).is_null() {
                        current_block = 6451473480150109090;
                    } else if xmlStrEqual((*step).value2, (*(*node).ns).href) == 0 {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else {
                    current_block = 820271813250567934;
                }
            }
            3 => {
                let mut lst: xmlNodePtr = 0 as *mut xmlNode;
                if (*node).type_0 as libc::c_uint
                    != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                    && (*node).type_0 as libc::c_uint
                        != XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                    && (*node).type_0 as libc::c_uint
                        != XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else {
                    lst = (*node).children;
                    if !((*step).value).is_null() {
                        while !lst.is_null() {
                            if (*lst).type_0 as libc::c_uint
                                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                                && *((*step).value).offset(0 as libc::c_int as isize)
                                    as libc::c_int
                                    == *((*lst).name).offset(0 as libc::c_int as isize)
                                        as libc::c_int
                                && xmlStrEqual((*step).value, (*lst).name) != 0
                            {
                                break;
                            }
                            lst = (*lst).next;
                        }
                        if !lst.is_null() {
                            current_block = 820271813250567934;
                        } else {
                            current_block = 6451473480150109090;
                        }
                    } else {
                        current_block = 6451473480150109090;
                    }
                }
            }
            4 => {
                if (*node).type_0 as libc::c_uint
                    != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else {
                    if !((*step).value).is_null() {
                        if *((*step).value).offset(0 as libc::c_int as isize)
                            as libc::c_int
                            != *((*node).name).offset(0 as libc::c_int as isize)
                                as libc::c_int
                        {
                            current_block = 6451473480150109090;
                        } else if xmlStrEqual((*step).value, (*node).name) == 0 {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 6450597802325118133;
                        }
                    } else {
                        current_block = 6450597802325118133;
                    }
                    match current_block {
                        6451473480150109090 => {}
                        _ => {
                            if ((*node).ns).is_null() {
                                if !((*step).value2).is_null() {
                                    current_block = 6451473480150109090;
                                } else {
                                    current_block = 820271813250567934;
                                }
                            } else if !((*step).value2).is_null() {
                                if xmlStrEqual((*step).value2, (*(*node).ns).href) == 0 {
                                    current_block = 6451473480150109090;
                                } else {
                                    current_block = 820271813250567934;
                                }
                            } else {
                                current_block = 820271813250567934;
                            }
                        }
                    }
                }
            }
            5 => {
                if (*node).type_0 as libc::c_uint
                    == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                    || (*node).type_0 as libc::c_uint
                        == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                    || (*node).type_0 as libc::c_uint
                        == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else {
                    node = (*node).parent;
                    if node.is_null() {
                        current_block = 6451473480150109090;
                    } else if ((*step).value).is_null() {
                        current_block = 820271813250567934;
                    } else if *((*step).value).offset(0 as libc::c_int as isize)
                            as libc::c_int
                            != *((*node).name).offset(0 as libc::c_int as isize)
                                as libc::c_int
                        {
                        current_block = 6451473480150109090;
                    } else if xmlStrEqual((*step).value, (*node).name) == 0 {
                        current_block = 6451473480150109090;
                    } else if ((*node).ns).is_null() {
                        if !((*step).value2).is_null() {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 820271813250567934;
                        }
                    } else if !((*(*node).ns).href).is_null() {
                        if ((*step).value2).is_null() {
                            current_block = 6451473480150109090;
                        } else if xmlStrEqual((*step).value2, (*(*node).ns).href) == 0 {
                            current_block = 6451473480150109090;
                        } else {
                            current_block = 820271813250567934;
                        }
                    } else {
                        current_block = 820271813250567934;
                    }
                }
            }
            6 => {
                if ((*step).value).is_null() {
                    i += 1;
                    step = &mut *((*comp).steps).offset(i as isize) as *mut xmlStepOp;
                    if (*step).op as libc::c_uint
                        == XML_OP_ROOT as libc::c_int as libc::c_uint
                    {
                        break;
                    }
                    if (*step).op as libc::c_uint
                        != XML_OP_ELEM as libc::c_int as libc::c_uint
                    {
                        current_block = 6451473480150109090;
                    } else {
                        if ((*step).value).is_null() {
                            return -(1 as libc::c_int);
                        }
                        current_block = 10067844863897285902;
                    }
                } else {
                    current_block = 10067844863897285902;
                }
                match current_block {
                    6451473480150109090 => {}
                    _ => {
                        if node.is_null() {
                            current_block = 6451473480150109090;
                        } else if (*node).type_0 as libc::c_uint
                                == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                                || (*node).type_0 as libc::c_uint
                                    == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
                                || (*node).type_0 as libc::c_uint
                                    == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
                            {
                            current_block = 6451473480150109090;
                        } else {
                            node = (*node).parent;
                            while !node.is_null() {
                                if (*node).type_0 as libc::c_uint
                                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                                    && *((*step).value).offset(0 as libc::c_int as isize)
                                        as libc::c_int
                                        == *((*node).name).offset(0 as libc::c_int as isize)
                                            as libc::c_int
                                    && xmlStrEqual((*step).value, (*node).name) != 0
                                {
                                    if ((*node).ns).is_null() {
                                        if ((*step).value2).is_null() {
                                            break;
                                        }
                                    } else if !((*(*node).ns).href).is_null() {
                                        if !((*step).value2).is_null()
                                            && xmlStrEqual((*step).value2, (*(*node).ns).href) != 0
                                        {
                                            break;
                                        }
                                    }
                                }
                                node = (*node).parent;
                            }
                            if node.is_null() {
                                current_block = 6451473480150109090;
                            } else {
                                if (*step).op as libc::c_uint
                                    == XML_OP_ANCESTOR as libc::c_int as libc::c_uint
                                {
                                    xmlPatPushState(&mut states, i, node);
                                } else {
                                    xmlPatPushState(&mut states, i - 1 as libc::c_int, node);
                                }
                                current_block = 820271813250567934;
                            }
                        }
                    }
                }
            }
            7 => {
                if (*node).type_0 as libc::c_uint
                    != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else if ((*node).ns).is_null() {
                    if !((*step).value).is_null() {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else if !((*(*node).ns).href).is_null() {
                    if ((*step).value).is_null() {
                        current_block = 6451473480150109090;
                    } else if xmlStrEqual((*step).value, (*(*node).ns).href) == 0 {
                        current_block = 6451473480150109090;
                    } else {
                        current_block = 820271813250567934;
                    }
                } else {
                    current_block = 820271813250567934;
                }
            }
            8 => {
                if (*node).type_0 as libc::c_uint
                    != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                {
                    current_block = 6451473480150109090;
                } else {
                    current_block = 820271813250567934;
                }
            }
            _ => {
                current_block = 820271813250567934;
            }
        }
        match current_block {
            820271813250567934 => {
                i += 1;
            }
            _ => {
                if (states.states).is_null() {
                    return 0 as libc::c_int;
                }
                if states.nbstates <= 0 as libc::c_int {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(states.states as *mut libc::c_void);
                    return 0 as libc::c_int;
                }
                states.nbstates -= 1;
                i = (*(states.states).offset(states.nbstates as isize)).step;
                node = (*(states.states).offset(states.nbstates as isize)).node;
            }
        }
    }
    if !(states.states).is_null() {
        xmlFree.expect("non-null function pointer")(states.states as *mut libc::c_void);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn xmlPatScanName(mut ctxt: xmlPatParserContextPtr) -> *mut xmlChar {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh27 = (*ctxt).cur;
            *fresh27 = (*fresh27).offset(1);
        } else {};
    }
    q = (*ctxt).cur;
    cur = q;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    if !((if val < 0x100 as libc::c_int {
        (0x41 as libc::c_int <= val && val <= 0x5a as libc::c_int
            || 0x61 as libc::c_int <= val && val <= 0x7a as libc::c_int
            || 0xc0 as libc::c_int <= val && val <= 0xd6 as libc::c_int
            || 0xd8 as libc::c_int <= val && val <= 0xf6 as libc::c_int
            || 0xf8 as libc::c_int <= val) as libc::c_int
    } else {
        xmlCharInRange(val as libc::c_uint, &xmlIsBaseCharGroup)
    }) != 0
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            (0x4e00 as libc::c_int <= val && val <= 0x9fa5 as libc::c_int
                || val == 0x3007 as libc::c_int
                || 0x3021 as libc::c_int <= val && val <= 0x3029 as libc::c_int)
                as libc::c_int
        }) != 0) && val != '_' as i32 && val != ':' as i32
    {
        return 0 as *mut xmlChar;
    }
    while (if val < 0x100 as libc::c_int {
        (0x41 as libc::c_int <= val && val <= 0x5a as libc::c_int
            || 0x61 as libc::c_int <= val && val <= 0x7a as libc::c_int
            || 0xc0 as libc::c_int <= val && val <= 0xd6 as libc::c_int
            || 0xd8 as libc::c_int <= val && val <= 0xf6 as libc::c_int
            || 0xf8 as libc::c_int <= val) as libc::c_int
    } else {
        xmlCharInRange(val as libc::c_uint, &xmlIsBaseCharGroup)
    }) != 0
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            (0x4e00 as libc::c_int <= val && val <= 0x9fa5 as libc::c_int
                || val == 0x3007 as libc::c_int
                || 0x3021 as libc::c_int <= val && val <= 0x3029 as libc::c_int)
                as libc::c_int
        }) != 0
        || (if val < 0x100 as libc::c_int {
            (0x30 as libc::c_int <= val && val <= 0x39 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsDigitGroup)
        }) != 0 || val == '.' as i32 || val == '-' as i32 || val == '_' as i32
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if val < 0x100 as libc::c_int {
            (val == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(len as isize);
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    }
    if !((*ctxt).dict).is_null() {
        ret = xmlDictLookup(
            (*ctxt).dict,
            q,
            cur.offset_from(q) as libc::c_long as libc::c_int,
        ) as *mut xmlChar;
    } else {
        ret = xmlStrndup(q, cur.offset_from(q) as libc::c_long as libc::c_int);
    }
    let ref mut fresh28 = (*ctxt).cur;
    *fresh28 = cur;
    return ret;
}
unsafe extern "C" fn xmlPatScanNCName(mut ctxt: xmlPatParserContextPtr) -> *mut xmlChar {
    let mut q: *const xmlChar = 0 as *const xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh29 = (*ctxt).cur;
            *fresh29 = (*fresh29).offset(1);
        } else {};
    }
    q = (*ctxt).cur;
    cur = q;
    val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    if !((if val < 0x100 as libc::c_int {
        (0x41 as libc::c_int <= val && val <= 0x5a as libc::c_int
            || 0x61 as libc::c_int <= val && val <= 0x7a as libc::c_int
            || 0xc0 as libc::c_int <= val && val <= 0xd6 as libc::c_int
            || 0xd8 as libc::c_int <= val && val <= 0xf6 as libc::c_int
            || 0xf8 as libc::c_int <= val) as libc::c_int
    } else {
        xmlCharInRange(val as libc::c_uint, &xmlIsBaseCharGroup)
    }) != 0
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            (0x4e00 as libc::c_int <= val && val <= 0x9fa5 as libc::c_int
                || val == 0x3007 as libc::c_int
                || 0x3021 as libc::c_int <= val && val <= 0x3029 as libc::c_int)
                as libc::c_int
        }) != 0) && val != '_' as i32
    {
        return 0 as *mut xmlChar;
    }
    while (if val < 0x100 as libc::c_int {
        (0x41 as libc::c_int <= val && val <= 0x5a as libc::c_int
            || 0x61 as libc::c_int <= val && val <= 0x7a as libc::c_int
            || 0xc0 as libc::c_int <= val && val <= 0xd6 as libc::c_int
            || 0xd8 as libc::c_int <= val && val <= 0xf6 as libc::c_int
            || 0xf8 as libc::c_int <= val) as libc::c_int
    } else {
        xmlCharInRange(val as libc::c_uint, &xmlIsBaseCharGroup)
    }) != 0
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            (0x4e00 as libc::c_int <= val && val <= 0x9fa5 as libc::c_int
                || val == 0x3007 as libc::c_int
                || 0x3021 as libc::c_int <= val && val <= 0x3029 as libc::c_int)
                as libc::c_int
        }) != 0
        || (if val < 0x100 as libc::c_int {
            (0x30 as libc::c_int <= val && val <= 0x39 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsDigitGroup)
        }) != 0 || val == '.' as i32 || val == '-' as i32 || val == '_' as i32
        || (if val < 0x100 as libc::c_int {
            0 as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsCombiningGroup)
        }) != 0
        || (if val < 0x100 as libc::c_int {
            (val == 0xb7 as libc::c_int) as libc::c_int
        } else {
            xmlCharInRange(val as libc::c_uint, &xmlIsExtenderGroup)
        }) != 0
    {
        cur = cur.offset(len as isize);
        val = xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut len);
    }
    if !((*ctxt).dict).is_null() {
        ret = xmlDictLookup(
            (*ctxt).dict,
            q,
            cur.offset_from(q) as libc::c_long as libc::c_int,
        ) as *mut xmlChar;
    } else {
        ret = xmlStrndup(q, cur.offset_from(q) as libc::c_long as libc::c_int);
    }
    let ref mut fresh30 = (*ctxt).cur;
    *fresh30 = cur;
    return ret;
}
unsafe extern "C" fn xmlCompileAttributeTest(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    let mut token: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh31 = (*ctxt).cur;
            *fresh31 = (*fresh31).offset(1);
        } else {};
    }
    name = xmlPatScanNCName(ctxt);
    if name.is_null() {
        if *(*ctxt).cur as libc::c_int == '*' as i32 {
            if xmlPatternAdd(
                ctxt,
                (*ctxt).comp,
                XML_OP_ATTR,
                0 as *mut xmlChar,
                0 as *mut xmlChar,
            ) != 0
            {
                current_block = 11331548824878167032;
            } else {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh32 = (*ctxt).cur;
                    *fresh32 = (*fresh32).offset(1);
                } else {};
                current_block = 5399440093318478209;
            }
        } else {
            (*ctxt).error = 1 as libc::c_int;
            current_block = 5399440093318478209;
        }
        match current_block {
            11331548824878167032 => {}
            _ => return,
        }
    } else {
        if *(*ctxt).cur as libc::c_int == ':' as i32 {
            let mut i: libc::c_int = 0;
            let mut prefix: *mut xmlChar = name;
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh33 = (*ctxt).cur;
                *fresh33 = (*fresh33).offset(1);
            } else {};
            if *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
            {
                if ((*(*ctxt).comp).dict).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(prefix as *mut libc::c_void);
                }
                (*ctxt).error = 1 as libc::c_int;
                current_block = 11331548824878167032;
            } else {
                token = xmlPatScanName(ctxt);
                if *prefix.offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
                    && *prefix.offset(1 as libc::c_int as isize) as libc::c_int
                        == 'm' as i32
                    && *prefix.offset(2 as libc::c_int as isize) as libc::c_int
                        == 'l' as i32
                    && *prefix.offset(3 as libc::c_int as isize) as libc::c_int
                        == 0 as libc::c_int
                {
                    if !((*(*ctxt).comp).dict).is_null() {
                        URL = xmlDictLookup(
                            (*(*ctxt).comp).dict,
                            b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                as *const libc::c_char as *const xmlChar as *mut xmlChar,
                            -(1 as libc::c_int),
                        ) as *mut xmlChar;
                    } else {
                        URL = xmlStrdup(
                            b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                as *const libc::c_char as *const xmlChar as *mut xmlChar,
                        );
                    }
                    current_block = 15512526488502093901;
                } else {
                    i = 0 as libc::c_int;
                    while i < (*ctxt).nb_namespaces {
                        if xmlStrEqual(
                            *((*ctxt).namespaces)
                                .offset((2 as libc::c_int * i + 1 as libc::c_int) as isize),
                            prefix,
                        ) != 0
                        {
                            if !((*(*ctxt).comp).dict).is_null() {
                                URL = xmlDictLookup(
                                    (*(*ctxt).comp).dict,
                                    *((*ctxt).namespaces)
                                        .offset((2 as libc::c_int * i) as isize) as *mut xmlChar,
                                    -(1 as libc::c_int),
                                ) as *mut xmlChar;
                            } else {
                                URL = xmlStrdup(
                                    *((*ctxt).namespaces)
                                        .offset((2 as libc::c_int * i) as isize) as *mut xmlChar,
                                );
                            }
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    if i >= (*ctxt).nb_namespaces {
                        if ((*(*ctxt).comp).dict).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(prefix as *mut libc::c_void);
                        }
                        (*ctxt).error = 1 as libc::c_int;
                        current_block = 11331548824878167032;
                    } else {
                        current_block = 15512526488502093901;
                    }
                }
                match current_block {
                    11331548824878167032 => {}
                    _ => {
                        if ((*(*ctxt).comp).dict).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(prefix as *mut libc::c_void);
                        }
                        if token.is_null() {
                            if *(*ctxt).cur as libc::c_int == '*' as i32 {
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh34 = (*ctxt).cur;
                                    *fresh34 = (*fresh34).offset(1);
                                } else {};
                                if xmlPatternAdd(
                                    ctxt,
                                    (*ctxt).comp,
                                    XML_OP_ATTR,
                                    0 as *mut xmlChar,
                                    URL,
                                ) != 0
                                {
                                    current_block = 11331548824878167032;
                                } else {
                                    current_block = 9512719473022792396;
                                }
                            } else {
                                (*ctxt).error = 1 as libc::c_int;
                                current_block = 11331548824878167032;
                            }
                        } else if xmlPatternAdd(
                                ctxt,
                                (*ctxt).comp,
                                XML_OP_ATTR,
                                token,
                                URL,
                            ) != 0
                            {
                            current_block = 11331548824878167032;
                        } else {
                            current_block = 9512719473022792396;
                        }
                    }
                }
            }
        } else if xmlPatternAdd(ctxt, (*ctxt).comp, XML_OP_ATTR, name, 0 as *mut xmlChar)
                != 0
            {
            current_block = 11331548824878167032;
        } else {
            current_block = 9512719473022792396;
        }
        match current_block {
            11331548824878167032 => {}
            _ => return,
        }
    }
    if !URL.is_null() {
        if ((*(*ctxt).comp).dict).is_null() {
            xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void);
        }
    }
    if !token.is_null() {
        if ((*(*ctxt).comp).dict).is_null() {
            xmlFree.expect("non-null function pointer")(token as *mut libc::c_void);
        }
    }
}
unsafe extern "C" fn xmlCompileStepPattern(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    let mut token: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut hasBlanks: libc::c_int = 0 as libc::c_int;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh35 = (*ctxt).cur;
            *fresh35 = (*fresh35).offset(1);
        } else {};
    }
    if *(*ctxt).cur as libc::c_int == '.' as i32 {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh36 = (*ctxt).cur;
            *fresh36 = (*fresh36).offset(1);
        } else {};
        if !(xmlPatternAdd(
            ctxt,
            (*ctxt).comp,
            XML_OP_ELEM,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0)
        {
            return;
        }
    } else if *(*ctxt).cur as libc::c_int == '@' as i32 {
        if (*(*ctxt).comp).flags & XML_PATTERN_XSSEL as libc::c_int != 0 {
            (*ctxt).error = 1 as libc::c_int;
            return;
        }
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh37 = (*ctxt).cur;
            *fresh37 = (*fresh37).offset(1);
        } else {};
        xmlCompileAttributeTest(ctxt);
        if !((*ctxt).error != 0 as libc::c_int) {
            return;
        }
    } else {
        name = xmlPatScanNCName(ctxt);
        if name.is_null() {
            if *(*ctxt).cur as libc::c_int == '*' as i32 {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh38 = (*ctxt).cur;
                    *fresh38 = (*fresh38).offset(1);
                } else {};
                if !(xmlPatternAdd(
                    ctxt,
                    (*ctxt).comp,
                    XML_OP_ALL,
                    0 as *mut xmlChar,
                    0 as *mut xmlChar,
                ) != 0)
                {
                    return;
                }
            } else {
                (*ctxt).error = 1 as libc::c_int;
                return;
            }
        } else {
            if *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
            {
                hasBlanks = 1 as libc::c_int;
                while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                        && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                    || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                {
                    if *(*ctxt).cur as libc::c_int != 0 {
                        let ref mut fresh39 = (*ctxt).cur;
                        *fresh39 = (*fresh39).offset(1);
                    } else {};
                }
            }
            if *(*ctxt).cur as libc::c_int == ':' as i32 {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh40 = (*ctxt).cur;
                    *fresh40 = (*fresh40).offset(1);
                } else {};
                if *(*ctxt).cur as libc::c_int != ':' as i32 {
                    let mut prefix: *mut xmlChar = name;
                    let mut i: libc::c_int = 0;
                    if hasBlanks != 0
                        || (*(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                            || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                            || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int)
                    {
                        (*ctxt).error = 1 as libc::c_int;
                        current_block = 15904406811757377787;
                    } else {
                        token = xmlPatScanName(ctxt);
                        if *prefix.offset(0 as libc::c_int as isize) as libc::c_int
                            == 'x' as i32
                            && *prefix.offset(1 as libc::c_int as isize) as libc::c_int
                                == 'm' as i32
                            && *prefix.offset(2 as libc::c_int as isize) as libc::c_int
                                == 'l' as i32
                            && *prefix.offset(3 as libc::c_int as isize) as libc::c_int
                                == 0 as libc::c_int
                        {
                            if !((*(*ctxt).comp).dict).is_null() {
                                URL = xmlDictLookup(
                                    (*(*ctxt).comp).dict,
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const libc::c_char as *const xmlChar as *mut xmlChar,
                                    -(1 as libc::c_int),
                                ) as *mut xmlChar;
                            } else {
                                URL = xmlStrdup(
                                    b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                        as *const libc::c_char as *const xmlChar as *mut xmlChar,
                                );
                            }
                            current_block = 13325891313334703151;
                        } else {
                            i = 0 as libc::c_int;
                            while i < (*ctxt).nb_namespaces {
                                if xmlStrEqual(
                                    *((*ctxt).namespaces)
                                        .offset((2 as libc::c_int * i + 1 as libc::c_int) as isize),
                                    prefix,
                                ) != 0
                                {
                                    if !((*(*ctxt).comp).dict).is_null() {
                                        URL = xmlDictLookup(
                                            (*(*ctxt).comp).dict,
                                            *((*ctxt).namespaces)
                                                .offset((2 as libc::c_int * i) as isize) as *mut xmlChar,
                                            -(1 as libc::c_int),
                                        ) as *mut xmlChar;
                                    } else {
                                        URL = xmlStrdup(
                                            *((*ctxt).namespaces)
                                                .offset((2 as libc::c_int * i) as isize) as *mut xmlChar,
                                        );
                                    }
                                    break;
                                } else {
                                    i += 1;
                                }
                            }
                            if i >= (*ctxt).nb_namespaces {
                                (*ctxt).error = 1 as libc::c_int;
                                current_block = 15904406811757377787;
                            } else {
                                current_block = 13325891313334703151;
                            }
                        }
                        match current_block {
                            15904406811757377787 => {}
                            _ => {
                                if ((*(*ctxt).comp).dict).is_null() {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(prefix as *mut libc::c_void);
                                }
                                name = 0 as *mut xmlChar;
                                if token.is_null() {
                                    if *(*ctxt).cur as libc::c_int == '*' as i32 {
                                        if *(*ctxt).cur as libc::c_int != 0 {
                                            let ref mut fresh41 = (*ctxt).cur;
                                            *fresh41 = (*fresh41).offset(1);
                                        } else {};
                                        if xmlPatternAdd(
                                            ctxt,
                                            (*ctxt).comp,
                                            XML_OP_NS,
                                            URL,
                                            0 as *mut xmlChar,
                                        ) != 0
                                        {
                                            current_block = 15904406811757377787;
                                        } else {
                                            current_block = 8880031775101799352;
                                        }
                                    } else {
                                        (*ctxt).error = 1 as libc::c_int;
                                        current_block = 15904406811757377787;
                                    }
                                } else if xmlPatternAdd(
                                        ctxt,
                                        (*ctxt).comp,
                                        XML_OP_ELEM,
                                        token,
                                        URL,
                                    ) != 0
                                    {
                                    current_block = 15904406811757377787;
                                } else {
                                    current_block = 8880031775101799352;
                                }
                            }
                        }
                    }
                } else {
                    if *(*ctxt).cur as libc::c_int != 0 {
                        let ref mut fresh42 = (*ctxt).cur;
                        *fresh42 = (*fresh42).offset(1);
                    } else {};
                    if xmlStrEqual(
                        name,
                        b"child\0" as *const u8 as *const libc::c_char as *const xmlChar,
                    ) != 0
                    {
                        if ((*(*ctxt).comp).dict).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(name as *mut libc::c_void);
                        }
                        name = xmlPatScanName(ctxt);
                        if name.is_null() {
                            if *(*ctxt).cur as libc::c_int == '*' as i32 {
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh43 = (*ctxt).cur;
                                    *fresh43 = (*fresh43).offset(1);
                                } else {};
                                if !(xmlPatternAdd(
                                    ctxt,
                                    (*ctxt).comp,
                                    XML_OP_ALL,
                                    0 as *mut xmlChar,
                                    0 as *mut xmlChar,
                                ) != 0)
                                {
                                    return;
                                }
                            } else {
                                (*ctxt).error = 1 as libc::c_int;
                            }
                        } else {
                            if *(*ctxt).cur as libc::c_int == ':' as i32 {
                                let mut prefix_0: *mut xmlChar = name;
                                let mut i_0: libc::c_int = 0;
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh44 = (*ctxt).cur;
                                    *fresh44 = (*fresh44).offset(1);
                                } else {};
                                if *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                    || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                        && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                    || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                                {
                                    (*ctxt).error = 1 as libc::c_int;
                                    current_block = 15904406811757377787;
                                } else {
                                    token = xmlPatScanName(ctxt);
                                    if *prefix_0.offset(0 as libc::c_int as isize)
                                        as libc::c_int == 'x' as i32
                                        && *prefix_0.offset(1 as libc::c_int as isize)
                                            as libc::c_int == 'm' as i32
                                        && *prefix_0.offset(2 as libc::c_int as isize)
                                            as libc::c_int == 'l' as i32
                                        && *prefix_0.offset(3 as libc::c_int as isize)
                                            as libc::c_int == 0 as libc::c_int
                                    {
                                        if !((*(*ctxt).comp).dict).is_null() {
                                            URL = xmlDictLookup(
                                                (*(*ctxt).comp).dict,
                                                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                                    as *const libc::c_char as *const xmlChar as *mut xmlChar,
                                                -(1 as libc::c_int),
                                            ) as *mut xmlChar;
                                        } else {
                                            URL = xmlStrdup(
                                                b"http://www.w3.org/XML/1998/namespace\0" as *const u8
                                                    as *const libc::c_char as *const xmlChar as *mut xmlChar,
                                            );
                                        }
                                        current_block = 5706227035632243100;
                                    } else {
                                        i_0 = 0 as libc::c_int;
                                        while i_0 < (*ctxt).nb_namespaces {
                                            if xmlStrEqual(
                                                *((*ctxt).namespaces)
                                                    .offset(
                                                        (2 as libc::c_int * i_0 + 1 as libc::c_int) as isize,
                                                    ),
                                                prefix_0,
                                            ) != 0
                                            {
                                                if !((*(*ctxt).comp).dict).is_null() {
                                                    URL = xmlDictLookup(
                                                        (*(*ctxt).comp).dict,
                                                        *((*ctxt).namespaces)
                                                            .offset((2 as libc::c_int * i_0) as isize) as *mut xmlChar,
                                                        -(1 as libc::c_int),
                                                    ) as *mut xmlChar;
                                                } else {
                                                    URL = xmlStrdup(
                                                        *((*ctxt).namespaces)
                                                            .offset((2 as libc::c_int * i_0) as isize) as *mut xmlChar,
                                                    );
                                                }
                                                break;
                                            } else {
                                                i_0 += 1;
                                            }
                                        }
                                        if i_0 >= (*ctxt).nb_namespaces {
                                            (*ctxt).error = 1 as libc::c_int;
                                            current_block = 15904406811757377787;
                                        } else {
                                            current_block = 5706227035632243100;
                                        }
                                    }
                                    match current_block {
                                        15904406811757377787 => {}
                                        _ => {
                                            if ((*(*ctxt).comp).dict).is_null() {
                                                xmlFree
                                                    .expect(
                                                        "non-null function pointer",
                                                    )(prefix_0 as *mut libc::c_void);
                                            }
                                            name = 0 as *mut xmlChar;
                                            if token.is_null() {
                                                if *(*ctxt).cur as libc::c_int == '*' as i32 {
                                                    if *(*ctxt).cur as libc::c_int != 0 {
                                                        let ref mut fresh45 = (*ctxt).cur;
                                                        *fresh45 = (*fresh45).offset(1);
                                                    } else {};
                                                    if xmlPatternAdd(
                                                        ctxt,
                                                        (*ctxt).comp,
                                                        XML_OP_NS,
                                                        URL,
                                                        0 as *mut xmlChar,
                                                    ) != 0
                                                    {
                                                        current_block = 15904406811757377787;
                                                    } else {
                                                        current_block = 7337917895049117968;
                                                    }
                                                } else {
                                                    (*ctxt).error = 1 as libc::c_int;
                                                    current_block = 15904406811757377787;
                                                }
                                            } else if xmlPatternAdd(
                                                    ctxt,
                                                    (*ctxt).comp,
                                                    XML_OP_CHILD,
                                                    token,
                                                    URL,
                                                ) != 0
                                                {
                                                current_block = 15904406811757377787;
                                            } else {
                                                current_block = 7337917895049117968;
                                            }
                                        }
                                    }
                                }
                            } else if xmlPatternAdd(
                                    ctxt,
                                    (*ctxt).comp,
                                    XML_OP_CHILD,
                                    name,
                                    0 as *mut xmlChar,
                                ) != 0
                                {
                                current_block = 15904406811757377787;
                            } else {
                                current_block = 7337917895049117968;
                            }
                            match current_block {
                                15904406811757377787 => {}
                                _ => return,
                            }
                        }
                    } else if xmlStrEqual(
                            name,
                            b"attribute\0" as *const u8 as *const libc::c_char
                                as *const xmlChar,
                        ) != 0
                        {
                        if ((*(*ctxt).comp).dict).is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(name as *mut libc::c_void);
                        }
                        name = 0 as *mut xmlChar;
                        if (*(*ctxt).comp).flags & XML_PATTERN_XSSEL as libc::c_int != 0
                        {
                            (*ctxt).error = 1 as libc::c_int;
                        } else {
                            xmlCompileAttributeTest(ctxt);
                            if !((*ctxt).error != 0 as libc::c_int) {
                                return;
                            }
                        }
                    } else {
                        (*ctxt).error = 1 as libc::c_int;
                    }
                    current_block = 15904406811757377787;
                }
            } else if *(*ctxt).cur as libc::c_int == '*' as i32 {
                if !name.is_null() {
                    (*ctxt).error = 1 as libc::c_int;
                    current_block = 15904406811757377787;
                } else {
                    if *(*ctxt).cur as libc::c_int != 0 {
                        let ref mut fresh46 = (*ctxt).cur;
                        *fresh46 = (*fresh46).offset(1);
                    } else {};
                    if xmlPatternAdd(
                        ctxt,
                        (*ctxt).comp,
                        XML_OP_ALL,
                        token,
                        0 as *mut xmlChar,
                    ) != 0
                    {
                        current_block = 15904406811757377787;
                    } else {
                        current_block = 8880031775101799352;
                    }
                }
            } else if xmlPatternAdd(
                    ctxt,
                    (*ctxt).comp,
                    XML_OP_ELEM,
                    name,
                    0 as *mut xmlChar,
                ) != 0
                {
                current_block = 15904406811757377787;
            } else {
                current_block = 8880031775101799352;
            }
            match current_block {
                15904406811757377787 => {}
                _ => return,
            }
        }
    }
    if !URL.is_null() {
        if ((*(*ctxt).comp).dict).is_null() {
            xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void);
        }
    }
    if !token.is_null() {
        if ((*(*ctxt).comp).dict).is_null() {
            xmlFree.expect("non-null function pointer")(token as *mut libc::c_void);
        }
    }
    if !name.is_null() {
        if ((*(*ctxt).comp).dict).is_null() {
            xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        }
    }
}
unsafe extern "C" fn xmlCompilePathPattern(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh47 = (*ctxt).cur;
            *fresh47 = (*fresh47).offset(1);
        } else {};
    }
    if *(*ctxt).cur as libc::c_int == '/' as i32 {
        (*(*ctxt).comp).flags |= (1 as libc::c_int) << 8 as libc::c_int;
    } else if *(*ctxt).cur as libc::c_int == '.' as i32
            || (*(*ctxt).comp).flags
                & (XML_PATTERN_XPATH as libc::c_int | XML_PATTERN_XSSEL as libc::c_int
                    | XML_PATTERN_XSFIELD as libc::c_int) != 0
        {
        (*(*ctxt).comp).flags |= (1 as libc::c_int) << 9 as libc::c_int;
    }
    if *(*ctxt).cur as libc::c_int == '/' as i32
        && *((*ctxt).cur).offset(1 as libc::c_int as isize) as libc::c_int == '/' as i32
    {
        if xmlPatternAdd(
            ctxt,
            (*ctxt).comp,
            XML_OP_ANCESTOR,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0
        {
            current_block = 17489734837053406682;
        } else {
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh48 = (*ctxt).cur;
                *fresh48 = (*fresh48).offset(1);
            } else {};
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh49 = (*ctxt).cur;
                *fresh49 = (*fresh49).offset(1);
            } else {};
            current_block = 11194104282611034094;
        }
    } else if *(*ctxt).cur as libc::c_int == '.' as i32
            && *((*ctxt).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '/' as i32
            && *((*ctxt).cur).offset(2 as libc::c_int as isize) as libc::c_int
                == '/' as i32
        {
        if xmlPatternAdd(
            ctxt,
            (*ctxt).comp,
            XML_OP_ANCESTOR,
            0 as *mut xmlChar,
            0 as *mut xmlChar,
        ) != 0
        {
            current_block = 17489734837053406682;
        } else {
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh50 = (*ctxt).cur;
                *fresh50 = (*fresh50).offset(1);
            } else {};
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh51 = (*ctxt).cur;
                *fresh51 = (*fresh51).offset(1);
            } else {};
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh52 = (*ctxt).cur;
                *fresh52 = (*fresh52).offset(1);
            } else {};
            while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
            {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh53 = (*ctxt).cur;
                    *fresh53 = (*fresh53).offset(1);
                } else {};
            }
            if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                (*ctxt).error = 1 as libc::c_int;
                current_block = 17489734837053406682;
            } else {
                current_block = 11194104282611034094;
            }
        }
    } else {
        current_block = 11194104282611034094;
    }
    match current_block {
        11194104282611034094 => {
            if *(*ctxt).cur as libc::c_int == '@' as i32 {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh54 = (*ctxt).cur;
                    *fresh54 = (*fresh54).offset(1);
                } else {};
                xmlCompileAttributeTest(ctxt);
                while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                        && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                    || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                {
                    if *(*ctxt).cur as libc::c_int != 0 {
                        let ref mut fresh55 = (*ctxt).cur;
                        *fresh55 = (*fresh55).offset(1);
                    } else {};
                }
                if *(*ctxt).cur as libc::c_int != 0 as libc::c_int {
                    xmlCompileStepPattern(ctxt);
                    if (*ctxt).error != 0 as libc::c_int {
                        current_block = 17489734837053406682;
                    } else {
                        current_block = 7189308829251266000;
                    }
                } else {
                    current_block = 7189308829251266000;
                }
            } else {
                if *(*ctxt).cur as libc::c_int == '/' as i32 {
                    if xmlPatternAdd(
                        ctxt,
                        (*ctxt).comp,
                        XML_OP_ROOT,
                        0 as *mut xmlChar,
                        0 as *mut xmlChar,
                    ) != 0
                    {
                        current_block = 17489734837053406682;
                    } else {
                        if *(*ctxt).cur as libc::c_int != 0 {
                            let ref mut fresh56 = (*ctxt).cur;
                            *fresh56 = (*fresh56).offset(1);
                        } else {};
                        while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                            || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                            || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                        {
                            if *(*ctxt).cur as libc::c_int != 0 {
                                let ref mut fresh57 = (*ctxt).cur;
                                *fresh57 = (*fresh57).offset(1);
                            } else {};
                        }
                        if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                            (*ctxt).error = 1 as libc::c_int;
                            current_block = 17489734837053406682;
                        } else {
                            current_block = 15512526488502093901;
                        }
                    }
                } else {
                    current_block = 15512526488502093901;
                }
                match current_block {
                    17489734837053406682 => {}
                    _ => {
                        xmlCompileStepPattern(ctxt);
                        if (*ctxt).error != 0 as libc::c_int {
                            current_block = 17489734837053406682;
                        } else {
                            while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                            {
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh58 = (*ctxt).cur;
                                    *fresh58 = (*fresh58).offset(1);
                                } else {};
                            }
                            loop {
                                if !(*(*ctxt).cur as libc::c_int == '/' as i32) {
                                    current_block = 7189308829251266000;
                                    break;
                                }
                                if *((*ctxt).cur).offset(1 as libc::c_int as isize)
                                    as libc::c_int == '/' as i32
                                {
                                    if xmlPatternAdd(
                                        ctxt,
                                        (*ctxt).comp,
                                        XML_OP_ANCESTOR,
                                        0 as *mut xmlChar,
                                        0 as *mut xmlChar,
                                    ) != 0
                                    {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                    if *(*ctxt).cur as libc::c_int != 0 {
                                        let ref mut fresh59 = (*ctxt).cur;
                                        *fresh59 = (*fresh59).offset(1);
                                    } else {};
                                    if *(*ctxt).cur as libc::c_int != 0 {
                                        let ref mut fresh60 = (*ctxt).cur;
                                        *fresh60 = (*fresh60).offset(1);
                                    } else {};
                                    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                                    {
                                        if *(*ctxt).cur as libc::c_int != 0 {
                                            let ref mut fresh61 = (*ctxt).cur;
                                            *fresh61 = (*fresh61).offset(1);
                                        } else {};
                                    }
                                    xmlCompileStepPattern(ctxt);
                                    if (*ctxt).error != 0 as libc::c_int {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                } else {
                                    if xmlPatternAdd(
                                        ctxt,
                                        (*ctxt).comp,
                                        XML_OP_PARENT,
                                        0 as *mut xmlChar,
                                        0 as *mut xmlChar,
                                    ) != 0
                                    {
                                        current_block = 17489734837053406682;
                                        break;
                                    }
                                    if *(*ctxt).cur as libc::c_int != 0 {
                                        let ref mut fresh62 = (*ctxt).cur;
                                        *fresh62 = (*fresh62).offset(1);
                                    } else {};
                                    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                                    {
                                        if *(*ctxt).cur as libc::c_int != 0 {
                                            let ref mut fresh63 = (*ctxt).cur;
                                            *fresh63 = (*fresh63).offset(1);
                                        } else {};
                                    }
                                    if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                                        (*ctxt).error = 1 as libc::c_int;
                                        current_block = 17489734837053406682;
                                        break;
                                    } else {
                                        xmlCompileStepPattern(ctxt);
                                        if (*ctxt).error != 0 as libc::c_int {
                                            current_block = 17489734837053406682;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            match current_block {
                17489734837053406682 => {}
                _ => {
                    if *(*ctxt).cur as libc::c_int != 0 as libc::c_int {
                        (*ctxt).error = 1 as libc::c_int;
                    }
                }
            }
        }
        _ => {}
    };
}
unsafe extern "C" fn xmlCompileIDCXPathPath(mut ctxt: xmlPatParserContextPtr) {
    let mut current_block: u64;
    while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
            && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
        || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
    {
        if *(*ctxt).cur as libc::c_int != 0 {
            let ref mut fresh64 = (*ctxt).cur;
            *fresh64 = (*fresh64).offset(1);
        } else {};
    }
    if !(*(*ctxt).cur as libc::c_int == '/' as i32) {
        (*(*ctxt).comp).flags |= (1 as libc::c_int) << 9 as libc::c_int;
        if *(*ctxt).cur as libc::c_int == '.' as i32 {
            if *(*ctxt).cur as libc::c_int != 0 {
                let ref mut fresh65 = (*ctxt).cur;
                *fresh65 = (*fresh65).offset(1);
            } else {};
            while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
            {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh66 = (*ctxt).cur;
                    *fresh66 = (*fresh66).offset(1);
                } else {};
            }
            if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                if xmlPatternAdd(
                    ctxt,
                    (*ctxt).comp,
                    XML_OP_ELEM,
                    0 as *mut xmlChar,
                    0 as *mut xmlChar,
                ) != 0
                {
                    current_block = 10466991778982128886;
                } else {
                    return
                }
            } else if *(*ctxt).cur as libc::c_int != '/' as i32 {
                current_block = 10466991778982128886;
            } else {
                if *(*ctxt).cur as libc::c_int != 0 {
                    let ref mut fresh67 = (*ctxt).cur;
                    *fresh67 = (*fresh67).offset(1);
                } else {};
                while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                        && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                    || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                {
                    if *(*ctxt).cur as libc::c_int != 0 {
                        let ref mut fresh68 = (*ctxt).cur;
                        *fresh68 = (*fresh68).offset(1);
                    } else {};
                }
                if *(*ctxt).cur as libc::c_int == '/' as i32 {
                    if *((*ctxt).cur).offset(-(1 as libc::c_int) as isize) as libc::c_int
                        == 0x20 as libc::c_int
                        || 0x9 as libc::c_int
                            <= *((*ctxt).cur).offset(-(1 as libc::c_int) as isize)
                                as libc::c_int
                            && *((*ctxt).cur).offset(-(1 as libc::c_int) as isize)
                                as libc::c_int <= 0xa as libc::c_int
                        || *((*ctxt).cur).offset(-(1 as libc::c_int) as isize)
                            as libc::c_int == 0xd as libc::c_int
                    {
                        current_block = 10466991778982128886;
                    } else if xmlPatternAdd(
                            ctxt,
                            (*ctxt).comp,
                            XML_OP_ANCESTOR,
                            0 as *mut xmlChar,
                            0 as *mut xmlChar,
                        ) != 0
                        {
                        current_block = 10466991778982128886;
                    } else {
                        if *(*ctxt).cur as libc::c_int != 0 {
                            let ref mut fresh69 = (*ctxt).cur;
                            *fresh69 = (*fresh69).offset(1);
                        } else {};
                        while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                            || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                            || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                        {
                            if *(*ctxt).cur as libc::c_int != 0 {
                                let ref mut fresh70 = (*ctxt).cur;
                                *fresh70 = (*fresh70).offset(1);
                            } else {};
                        }
                        current_block = 14818589718467733107;
                    }
                } else {
                    current_block = 14818589718467733107;
                }
                match current_block {
                    10466991778982128886 => {}
                    _ => {
                        if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                            current_block = 11874738112936171638;
                        } else {
                            current_block = 11932355480408055363;
                        }
                    }
                }
            }
        } else {
            current_block = 11932355480408055363;
        }
        match current_block {
            10466991778982128886 => {}
            _ => {
                loop {
                    match current_block {
                        11874738112936171638 => {
                            (*ctxt).error = 1 as libc::c_int;
                            return;
                        }
                        _ => {
                            xmlCompileStepPattern(ctxt);
                            if (*ctxt).error != 0 as libc::c_int {
                                current_block = 10466991778982128886;
                                break;
                            }
                            while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                            {
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh71 = (*ctxt).cur;
                                    *fresh71 = (*fresh71).offset(1);
                                } else {};
                            }
                            if *(*ctxt).cur as libc::c_int != '/' as i32 {
                                current_block = 15004371738079956865;
                                break;
                            }
                            if xmlPatternAdd(
                                ctxt,
                                (*ctxt).comp,
                                XML_OP_PARENT,
                                0 as *mut xmlChar,
                                0 as *mut xmlChar,
                            ) != 0
                            {
                                current_block = 10466991778982128886;
                                break;
                            }
                            if *(*ctxt).cur as libc::c_int != 0 {
                                let ref mut fresh72 = (*ctxt).cur;
                                *fresh72 = (*fresh72).offset(1);
                            } else {};
                            while *(*ctxt).cur as libc::c_int == 0x20 as libc::c_int
                                || 0x9 as libc::c_int <= *(*ctxt).cur as libc::c_int
                                    && *(*ctxt).cur as libc::c_int <= 0xa as libc::c_int
                                || *(*ctxt).cur as libc::c_int == 0xd as libc::c_int
                            {
                                if *(*ctxt).cur as libc::c_int != 0 {
                                    let ref mut fresh73 = (*ctxt).cur;
                                    *fresh73 = (*fresh73).offset(1);
                                } else {};
                            }
                            if *(*ctxt).cur as libc::c_int == '/' as i32 {
                                current_block = 10466991778982128886;
                                break;
                            }
                            if *(*ctxt).cur as libc::c_int == 0 as libc::c_int {
                                current_block = 11874738112936171638;
                                continue;
                            }
                            if *(*ctxt).cur as libc::c_int != 0 as libc::c_int {
                                current_block = 11932355480408055363;
                            } else {
                                current_block = 15004371738079956865;
                                break;
                            }
                        }
                    }
                }
                match current_block {
                    10466991778982128886 => {}
                    _ => {
                        if *(*ctxt).cur as libc::c_int != 0 as libc::c_int {
                            (*ctxt).error = 1 as libc::c_int;
                        }
                        return;
                    }
                }
            }
        }
    }
    (*ctxt).error = 1 as libc::c_int;
}
unsafe extern "C" fn xmlNewStreamComp(mut size: libc::c_int) -> xmlStreamCompPtr {
    let mut cur: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    if size < 4 as libc::c_int {
        size = 4 as libc::c_int;
    }
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlStreamComp>() as libc::c_ulong) as xmlStreamCompPtr;
    if cur.is_null() {
        return 0 as xmlStreamCompPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlStreamComp>() as libc::c_ulong,
    );
    let ref mut fresh74 = (*cur).steps;
    *fresh74 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlStreamStep>() as libc::c_ulong),
    ) as xmlStreamStepPtr;
    if ((*cur).steps).is_null() {
        xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
        return 0 as xmlStreamCompPtr;
    }
    (*cur).nbStep = 0 as libc::c_int;
    (*cur).maxStep = size;
    return cur;
}
unsafe extern "C" fn xmlFreeStreamComp(mut comp: xmlStreamCompPtr) {
    if !comp.is_null() {
        if !((*comp).steps).is_null() {
            xmlFree
                .expect("non-null function pointer")((*comp).steps as *mut libc::c_void);
        }
        if !((*comp).dict).is_null() {
            xmlDictFree((*comp).dict);
        }
        xmlFree.expect("non-null function pointer")(comp as *mut libc::c_void);
    }
}
unsafe extern "C" fn xmlStreamCompAddStep(
    mut comp: xmlStreamCompPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: libc::c_int,
    mut flags: libc::c_int,
) -> libc::c_int {
    let mut cur: xmlStreamStepPtr = 0 as *mut xmlStreamStep;
    if (*comp).nbStep >= (*comp).maxStep {
        cur = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*comp).steps as *mut libc::c_void,
            (((*comp).maxStep * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStreamStep>() as libc::c_ulong),
        ) as xmlStreamStepPtr;
        if cur.is_null() {
            return -(1 as libc::c_int);
        }
        let ref mut fresh75 = (*comp).steps;
        *fresh75 = cur;
        (*comp).maxStep *= 2 as libc::c_int;
    }
    let ref mut fresh76 = (*comp).nbStep;
    let fresh77 = *fresh76;
    *fresh76 = *fresh76 + 1;
    cur = &mut *((*comp).steps).offset(fresh77 as isize) as *mut xmlStreamStep;
    (*cur).flags = flags;
    let ref mut fresh78 = (*cur).name;
    *fresh78 = name;
    let ref mut fresh79 = (*cur).ns;
    *fresh79 = ns;
    (*cur).nodeType = nodeType;
    return (*comp).nbStep - 1 as libc::c_int;
}
unsafe extern "C" fn xmlStreamCompile(mut comp: xmlPatternPtr) -> libc::c_int {
    let mut current_block: u64;
    let mut stream: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    let mut i: libc::c_int = 0;
    let mut s: libc::c_int = 0 as libc::c_int;
    let mut root: libc::c_int = 0 as libc::c_int;
    let mut flags: libc::c_int = 0 as libc::c_int;
    let mut prevs: libc::c_int = -(1 as libc::c_int);
    let mut step: xmlStepOp = xmlStepOp {
        op: XML_OP_END,
        value: 0 as *const xmlChar,
        value2: 0 as *const xmlChar,
    };
    if comp.is_null() || ((*comp).steps).is_null() {
        return -(1 as libc::c_int);
    }
    if (*comp).nbStep == 1 as libc::c_int
        && (*((*comp).steps).offset(0 as libc::c_int as isize)).op as libc::c_uint
            == XML_OP_ELEM as libc::c_int as libc::c_uint
        && ((*((*comp).steps).offset(0 as libc::c_int as isize)).value).is_null()
        && ((*((*comp).steps).offset(0 as libc::c_int as isize)).value2).is_null()
    {
        stream = xmlNewStreamComp(0 as libc::c_int);
        if stream.is_null() {
            return -(1 as libc::c_int);
        }
        (*stream).flags |= (1 as libc::c_int) << 14 as libc::c_int;
        let ref mut fresh80 = (*comp).stream;
        *fresh80 = stream;
        return 0 as libc::c_int;
    }
    stream = xmlNewStreamComp((*comp).nbStep / 2 as libc::c_int + 1 as libc::c_int);
    if stream.is_null() {
        return -(1 as libc::c_int);
    }
    if !((*comp).dict).is_null() {
        let ref mut fresh81 = (*stream).dict;
        *fresh81 = (*comp).dict;
        xmlDictReference((*stream).dict);
    }
    i = 0 as libc::c_int;
    if (*comp).flags & (1 as libc::c_int) << 8 as libc::c_int != 0 {
        (*stream).flags |= (1 as libc::c_int) << 15 as libc::c_int;
    }
    loop {
        if !(i < (*comp).nbStep) {
            current_block = 12264624100856317061;
            break;
        }
        step = *((*comp).steps).offset(i as isize);
        match step.op as libc::c_uint {
            1 => {
                if i != 0 as libc::c_int {
                    current_block = 9045084312945070449;
                    break;
                }
                root = 1 as libc::c_int;
            }
            7 => {
                s = xmlStreamCompAddStep(
                    stream,
                    0 as *const xmlChar,
                    step.value,
                    XML_ELEMENT_NODE as libc::c_int,
                    flags,
                );
                if s < 0 as libc::c_int {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as libc::c_int;
            }
            4 => {
                flags |= 8 as libc::c_int;
                prevs = -(1 as libc::c_int);
                s = xmlStreamCompAddStep(
                    stream,
                    step.value,
                    step.value2,
                    XML_ATTRIBUTE_NODE as libc::c_int,
                    flags,
                );
                flags = 0 as libc::c_int;
                if s < 0 as libc::c_int {
                    current_block = 9045084312945070449;
                    break;
                }
            }
            2 => {
                if (step.value).is_null() && (step.value2).is_null() {
                    if (*comp).nbStep == i + 1 as libc::c_int
                        && flags & 1 as libc::c_int != 0
                    {
                        if (*comp).nbStep == i + 1 as libc::c_int {
                            (*stream).flags |= (1 as libc::c_int) << 14 as libc::c_int;
                        }
                        flags |= 16 as libc::c_int;
                        s = xmlStreamCompAddStep(
                            stream,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            100 as libc::c_int,
                            flags,
                        );
                        if s < 0 as libc::c_int {
                            current_block = 9045084312945070449;
                            break;
                        }
                        flags = 0 as libc::c_int;
                        if prevs != -(1 as libc::c_int) {
                            (*((*stream).steps).offset(prevs as isize)).flags
                                |= 32 as libc::c_int;
                            prevs = -(1 as libc::c_int);
                        }
                    }
                } else {
                    s = xmlStreamCompAddStep(
                        stream,
                        step.value,
                        step.value2,
                        XML_ELEMENT_NODE as libc::c_int,
                        flags,
                    );
                    if s < 0 as libc::c_int {
                        current_block = 9045084312945070449;
                        break;
                    }
                    prevs = s;
                    flags = 0 as libc::c_int;
                }
            }
            3 => {
                s = xmlStreamCompAddStep(
                    stream,
                    step.value,
                    step.value2,
                    XML_ELEMENT_NODE as libc::c_int,
                    flags,
                );
                if s < 0 as libc::c_int {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as libc::c_int;
            }
            8 => {
                s = xmlStreamCompAddStep(
                    stream,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    XML_ELEMENT_NODE as libc::c_int,
                    flags,
                );
                if s < 0 as libc::c_int {
                    current_block = 9045084312945070449;
                    break;
                }
                prevs = s;
                flags = 0 as libc::c_int;
            }
            6 => {
                if !(flags & 1 as libc::c_int != 0) {
                    flags |= 1 as libc::c_int;
                    if (*stream).flags & (1 as libc::c_int) << 16 as libc::c_int
                        == 0 as libc::c_int
                    {
                        (*stream).flags |= (1 as libc::c_int) << 16 as libc::c_int;
                    }
                }
            }
            0 | 5 | _ => {}
        }
        i += 1;
    }
    match current_block {
        12264624100856317061 => {
            if root == 0
                && (*comp).flags
                    & (XML_PATTERN_XPATH as libc::c_int
                        | XML_PATTERN_XSSEL as libc::c_int
                        | XML_PATTERN_XSFIELD as libc::c_int) == 0 as libc::c_int
            {
                if (*stream).flags & (1 as libc::c_int) << 16 as libc::c_int
                    == 0 as libc::c_int
                {
                    (*stream).flags |= (1 as libc::c_int) << 16 as libc::c_int;
                }
                if (*stream).nbStep > 0 as libc::c_int {
                    if (*((*stream).steps).offset(0 as libc::c_int as isize)).flags
                        & 1 as libc::c_int == 0 as libc::c_int
                    {
                        (*((*stream).steps).offset(0 as libc::c_int as isize)).flags
                            |= 1 as libc::c_int;
                    }
                }
            }
            if !((*stream).nbStep <= s) {
                (*((*stream).steps).offset(s as isize)).flags |= 2 as libc::c_int;
                if root != 0 {
                    (*((*stream).steps).offset(0 as libc::c_int as isize)).flags
                        |= 4 as libc::c_int;
                }
                let ref mut fresh82 = (*comp).stream;
                *fresh82 = stream;
                return 0 as libc::c_int;
            }
        }
        _ => {}
    }
    xmlFreeStreamComp(stream);
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlNewStreamCtxt(mut stream: xmlStreamCompPtr) -> xmlStreamCtxtPtr {
    let mut cur: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    cur = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlStreamCtxt>() as libc::c_ulong) as xmlStreamCtxtPtr;
    if cur.is_null() {
        return 0 as xmlStreamCtxtPtr;
    }
    memset(
        cur as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlStreamCtxt>() as libc::c_ulong,
    );
    let ref mut fresh83 = (*cur).states;
    *fresh83 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        ((4 as libc::c_int * 2 as libc::c_int) as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<libc::c_int>() as libc::c_ulong),
    ) as *mut libc::c_int;
    if ((*cur).states).is_null() {
        xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void);
        return 0 as xmlStreamCtxtPtr;
    }
    (*cur).nbState = 0 as libc::c_int;
    (*cur).maxState = 4 as libc::c_int;
    (*cur).level = 0 as libc::c_int;
    let ref mut fresh84 = (*cur).comp;
    *fresh84 = stream;
    (*cur).blockLevel = -(1 as libc::c_int);
    return cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeStreamCtxt(mut stream: xmlStreamCtxtPtr) {
    let mut next: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    while !stream.is_null() {
        next = (*stream).next;
        if !((*stream).states).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*stream).states as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(stream as *mut libc::c_void);
        stream = next;
    }
}
unsafe extern "C" fn xmlStreamCtxtAddState(
    mut comp: xmlStreamCtxtPtr,
    mut idx: libc::c_int,
    mut level: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < (*comp).nbState {
        if *((*comp).states).offset((2 as libc::c_int * i) as isize) < 0 as libc::c_int {
            *((*comp).states).offset((2 as libc::c_int * i) as isize) = idx;
            *((*comp).states)
                .offset((2 as libc::c_int * i + 1 as libc::c_int) as isize) = level;
            return i;
        }
        i += 1;
    }
    if (*comp).nbState >= (*comp).maxState {
        let mut cur: *mut libc::c_int = 0 as *mut libc::c_int;
        cur = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*comp).states as *mut libc::c_void,
            (((*comp).maxState * 4 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_int>() as libc::c_ulong),
        ) as *mut libc::c_int;
        if cur.is_null() {
            return -(1 as libc::c_int);
        }
        let ref mut fresh85 = (*comp).states;
        *fresh85 = cur;
        (*comp).maxState *= 2 as libc::c_int;
    }
    *((*comp).states).offset((2 as libc::c_int * (*comp).nbState) as isize) = idx;
    let ref mut fresh86 = (*comp).nbState;
    let fresh87 = *fresh86;
    *fresh86 = *fresh86 + 1;
    *((*comp).states)
        .offset((2 as libc::c_int * fresh87 + 1 as libc::c_int) as isize) = level;
    return (*comp).nbState - 1 as libc::c_int;
}
unsafe extern "C" fn xmlStreamPushInternal(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut final_0: libc::c_int = 0 as libc::c_int;
    let mut tmp: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut m: libc::c_int = 0;
    let mut match_0: libc::c_int = 0;
    let mut stepNr: libc::c_int = 0;
    let mut desc: libc::c_int = 0;
    let mut comp: xmlStreamCompPtr = 0 as *mut xmlStreamComp;
    let mut step: xmlStreamStep = xmlStreamStep {
        flags: 0,
        name: 0 as *const xmlChar,
        ns: 0 as *const xmlChar,
        nodeType: 0,
    };
    if stream.is_null() || (*stream).nbState < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    while !stream.is_null() {
        comp = (*stream).comp;
        if nodeType == XML_ELEMENT_NODE as libc::c_int && name.is_null() && ns.is_null()
        {
            (*stream).nbState = 0 as libc::c_int;
            (*stream).level = 0 as libc::c_int;
            (*stream).blockLevel = -(1 as libc::c_int);
            if (*comp).flags & (1 as libc::c_int) << 15 as libc::c_int != 0 {
                if (*comp).nbStep == 0 as libc::c_int {
                    ret = 1 as libc::c_int;
                } else if (*comp).nbStep == 1 as libc::c_int
                        && (*((*comp).steps).offset(0 as libc::c_int as isize)).nodeType
                            == 100 as libc::c_int
                        && (*((*comp).steps).offset(0 as libc::c_int as isize)).flags
                            & 1 as libc::c_int != 0
                    {
                    ret = 1 as libc::c_int;
                } else if (*((*comp).steps).offset(0 as libc::c_int as isize)).flags
                        & 4 as libc::c_int != 0
                    {
                    tmp = xmlStreamCtxtAddState(
                        stream,
                        0 as libc::c_int,
                        0 as libc::c_int,
                    );
                    if tmp < 0 as libc::c_int {
                        err += 1;
                    }
                }
            }
            stream = (*stream).next;
        } else {
            if (*comp).nbStep == 0 as libc::c_int {
                if (*stream).flags & XML_PATTERN_XPATH as libc::c_int != 0 {
                    stream = (*stream).next;
                    continue;
                } else {
                    if nodeType != XML_ATTRIBUTE_NODE as libc::c_int
                        && ((*stream).flags
                            & (XML_PATTERN_XPATH as libc::c_int
                                | XML_PATTERN_XSSEL as libc::c_int
                                | XML_PATTERN_XSFIELD as libc::c_int) == 0 as libc::c_int
                            || (*stream).level == 0 as libc::c_int)
                    {
                        ret = 1 as libc::c_int;
                    }
                    let ref mut fresh88 = (*stream).level;
                    *fresh88 += 1;
                }
            } else if (*stream).blockLevel != -(1 as libc::c_int) {
                let ref mut fresh89 = (*stream).level;
                *fresh89 += 1;
            } else if nodeType != XML_ELEMENT_NODE as libc::c_int
                    && nodeType != XML_ATTRIBUTE_NODE as libc::c_int
                    && (*comp).flags & (1 as libc::c_int) << 14 as libc::c_int
                        == 0 as libc::c_int
                {
                let ref mut fresh90 = (*stream).level;
                *fresh90 += 1;
            } else {
                i = 0 as libc::c_int;
                m = (*stream).nbState;
                while i < m {
                    if (*comp).flags & (1 as libc::c_int) << 16 as libc::c_int
                        == 0 as libc::c_int
                    {
                        stepNr = *((*stream).states)
                            .offset(
                                (2 as libc::c_int * ((*stream).nbState - 1 as libc::c_int))
                                    as isize,
                            );
                        if *((*stream).states)
                            .offset(
                                (2 as libc::c_int * ((*stream).nbState - 1 as libc::c_int)
                                    + 1 as libc::c_int) as isize,
                            ) < (*stream).level
                        {
                            return -(1 as libc::c_int);
                        }
                        desc = 0 as libc::c_int;
                        i = m;
                        current_block = 2516253395664191498;
                    } else {
                        stepNr = *((*stream).states)
                            .offset((2 as libc::c_int * i) as isize);
                        if stepNr < 0 as libc::c_int {
                            current_block = 11581334008138293573;
                        } else {
                            tmp = *((*stream).states)
                                .offset((2 as libc::c_int * i + 1 as libc::c_int) as isize);
                            if tmp > (*stream).level {
                                current_block = 11581334008138293573;
                            } else {
                                desc = (*((*comp).steps).offset(stepNr as isize)).flags
                                    & 1 as libc::c_int;
                                if tmp < (*stream).level && desc == 0 {
                                    current_block = 11581334008138293573;
                                } else {
                                    current_block = 2516253395664191498;
                                }
                            }
                        }
                    }
                    match current_block {
                        2516253395664191498 => {
                            step = *((*comp).steps).offset(stepNr as isize);
                            if step.nodeType != nodeType {
                                if step.nodeType == XML_ATTRIBUTE_NODE as libc::c_int {
                                    if (*comp).flags & (1 as libc::c_int) << 16 as libc::c_int
                                        == 0 as libc::c_int
                                    {
                                        (*stream).blockLevel = (*stream).level + 1 as libc::c_int;
                                    }
                                    current_block = 11581334008138293573;
                                } else if step.nodeType != 100 as libc::c_int {
                                    current_block = 11581334008138293573;
                                } else {
                                    current_block = 4741994311446740739;
                                }
                            } else {
                                current_block = 4741994311446740739;
                            }
                            match current_block {
                                11581334008138293573 => {}
                                _ => {
                                    match_0 = 0 as libc::c_int;
                                    if step.nodeType == 100 as libc::c_int {
                                        match_0 = 1 as libc::c_int;
                                    } else if (step.name).is_null() {
                                        if (step.ns).is_null() {
                                            match_0 = 1 as libc::c_int;
                                        } else if !ns.is_null() {
                                            match_0 = xmlStrEqual(step.ns, ns);
                                        }
                                    } else if (step.ns
                                            != 0 as *mut libc::c_void as *const xmlChar) as libc::c_int
                                            == (ns != 0 as *mut libc::c_void as *const xmlChar)
                                                as libc::c_int && !name.is_null()
                                            && *(step.name).offset(0 as libc::c_int as isize)
                                                as libc::c_int
                                                == *name.offset(0 as libc::c_int as isize) as libc::c_int
                                            && xmlStrEqual(step.name, name) != 0
                                            && (step.ns == ns || xmlStrEqual(step.ns, ns) != 0)
                                        {
                                        match_0 = 1 as libc::c_int;
                                    }
                                    if match_0 != 0 {
                                        final_0 = step.flags & 2 as libc::c_int;
                                        if desc != 0 {
                                            if final_0 != 0 {
                                                ret = 1 as libc::c_int;
                                            } else {
                                                xmlStreamCtxtAddState(
                                                    stream,
                                                    stepNr + 1 as libc::c_int,
                                                    (*stream).level + 1 as libc::c_int,
                                                );
                                            }
                                        } else if final_0 != 0 {
                                            ret = 1 as libc::c_int;
                                        } else {
                                            xmlStreamCtxtAddState(
                                                stream,
                                                stepNr + 1 as libc::c_int,
                                                (*stream).level + 1 as libc::c_int,
                                            );
                                        }
                                        if ret != 1 as libc::c_int
                                            && step.flags & 32 as libc::c_int != 0
                                        {
                                            ret = 1 as libc::c_int;
                                        }
                                    }
                                    if (*comp).flags & (1 as libc::c_int) << 16 as libc::c_int
                                        == 0 as libc::c_int && (match_0 == 0 || final_0 != 0)
                                    {
                                        (*stream).blockLevel = (*stream).level + 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                let ref mut fresh91 = (*stream).level;
                *fresh91 += 1;
                step = *((*comp).steps).offset(0 as libc::c_int as isize);
                if !(step.flags & 4 as libc::c_int != 0) {
                    desc = step.flags & 1 as libc::c_int;
                    if (*stream).flags
                        & (XML_PATTERN_XPATH as libc::c_int
                            | XML_PATTERN_XSSEL as libc::c_int
                            | XML_PATTERN_XSFIELD as libc::c_int) != 0
                    {
                        if (*stream).level == 1 as libc::c_int {
                            if (*stream).flags
                                & (XML_PATTERN_XSSEL as libc::c_int
                                    | XML_PATTERN_XSFIELD as libc::c_int) != 0
                            {
                                current_block = 9048011128714838703;
                            } else {
                                current_block = 14442360071374423104;
                            }
                        } else if desc != 0 {
                            current_block = 14442360071374423104;
                        } else if (*stream).level == 2 as libc::c_int
                                && (*stream).flags
                                    & (XML_PATTERN_XSSEL as libc::c_int
                                        | XML_PATTERN_XSFIELD as libc::c_int) != 0
                            {
                            current_block = 14442360071374423104;
                        } else {
                            current_block = 9048011128714838703;
                        }
                    } else {
                        current_block = 14442360071374423104;
                    }
                    match current_block {
                        9048011128714838703 => {}
                        _ => {
                            if step.nodeType != nodeType {
                                if nodeType == XML_ATTRIBUTE_NODE as libc::c_int {
                                    current_block = 9048011128714838703;
                                } else if step.nodeType != 100 as libc::c_int {
                                    current_block = 9048011128714838703;
                                } else {
                                    current_block = 11674240781755647963;
                                }
                            } else {
                                current_block = 11674240781755647963;
                            }
                            match current_block {
                                9048011128714838703 => {}
                                _ => {
                                    match_0 = 0 as libc::c_int;
                                    if step.nodeType == 100 as libc::c_int {
                                        match_0 = 1 as libc::c_int;
                                    } else if (step.name).is_null() {
                                        if (step.ns).is_null() {
                                            match_0 = 1 as libc::c_int;
                                        } else if !ns.is_null() {
                                            match_0 = xmlStrEqual(step.ns, ns);
                                        }
                                    } else if (step.ns
                                            != 0 as *mut libc::c_void as *const xmlChar) as libc::c_int
                                            == (ns != 0 as *mut libc::c_void as *const xmlChar)
                                                as libc::c_int && !name.is_null()
                                            && *(step.name).offset(0 as libc::c_int as isize)
                                                as libc::c_int
                                                == *name.offset(0 as libc::c_int as isize) as libc::c_int
                                            && xmlStrEqual(step.name, name) != 0
                                            && (step.ns == ns || xmlStrEqual(step.ns, ns) != 0)
                                        {
                                        match_0 = 1 as libc::c_int;
                                    }
                                    final_0 = step.flags & 2 as libc::c_int;
                                    if match_0 != 0 {
                                        if final_0 != 0 {
                                            ret = 1 as libc::c_int;
                                        } else {
                                            xmlStreamCtxtAddState(
                                                stream,
                                                1 as libc::c_int,
                                                (*stream).level,
                                            );
                                        }
                                        if ret != 1 as libc::c_int
                                            && step.flags & 32 as libc::c_int != 0
                                        {
                                            ret = 1 as libc::c_int;
                                        }
                                    }
                                    if (*comp).flags & (1 as libc::c_int) << 16 as libc::c_int
                                        == 0 as libc::c_int && (match_0 == 0 || final_0 != 0)
                                    {
                                        (*stream).blockLevel = (*stream).level;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            stream = (*stream).next;
        }
    }
    if err > 0 as libc::c_int {
        ret = -(1 as libc::c_int);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStreamPush(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
) -> libc::c_int {
    return xmlStreamPushInternal(stream, name, ns, XML_ELEMENT_NODE as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStreamPushNode(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
    mut nodeType: libc::c_int,
) -> libc::c_int {
    return xmlStreamPushInternal(stream, name, ns, nodeType);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStreamPushAttr(
    mut stream: xmlStreamCtxtPtr,
    mut name: *const xmlChar,
    mut ns: *const xmlChar,
) -> libc::c_int {
    return xmlStreamPushInternal(stream, name, ns, XML_ATTRIBUTE_NODE as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStreamPop(mut stream: xmlStreamCtxtPtr) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut lev: libc::c_int = 0;
    if stream.is_null() {
        return -(1 as libc::c_int);
    }
    while !stream.is_null() {
        if (*stream).blockLevel == (*stream).level {
            (*stream).blockLevel = -(1 as libc::c_int);
        }
        if (*stream).level != 0 {
            let ref mut fresh92 = (*stream).level;
            *fresh92 -= 1;
        }
        i = (*stream).nbState - 1 as libc::c_int;
        while i >= 0 as libc::c_int {
            lev = *((*stream).states)
                .offset((2 as libc::c_int * i + 1 as libc::c_int) as isize);
            if lev > (*stream).level {
                let ref mut fresh93 = (*stream).nbState;
                *fresh93 -= 1;
            }
            if lev <= (*stream).level {
                break;
            }
            i -= 1;
        }
        stream = (*stream).next;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStreamWantsAnyNode(
    mut streamCtxt: xmlStreamCtxtPtr,
) -> libc::c_int {
    if streamCtxt.is_null() {
        return -(1 as libc::c_int);
    }
    while !streamCtxt.is_null() {
        if (*(*streamCtxt).comp).flags & (1 as libc::c_int) << 14 as libc::c_int != 0 {
            return 1 as libc::c_int;
        }
        streamCtxt = (*streamCtxt).next;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatterncompile(
    mut pattern: *const xmlChar,
    mut dict: *mut xmlDict,
    mut flags: libc::c_int,
    mut namespaces: *mut *const xmlChar,
) -> xmlPatternPtr {
    let mut current_block: u64;
    let mut ret: xmlPatternPtr = 0 as xmlPatternPtr;
    let mut cur: xmlPatternPtr = 0 as *mut xmlPattern;
    let mut ctxt: xmlPatParserContextPtr = 0 as xmlPatParserContextPtr;
    let mut or: *const xmlChar = 0 as *const xmlChar;
    let mut start: *const xmlChar = 0 as *const xmlChar;
    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
    let mut type_0: libc::c_int = 0 as libc::c_int;
    let mut streamable: libc::c_int = 1 as libc::c_int;
    if pattern.is_null() {
        return 0 as xmlPatternPtr;
    }
    start = pattern;
    or = start;
    loop {
        if !(*or as libc::c_int != 0 as libc::c_int) {
            current_block = 10380409671385728102;
            break;
        }
        tmp = 0 as *mut xmlChar;
        while *or as libc::c_int != 0 as libc::c_int && *or as libc::c_int != '|' as i32
        {
            or = or.offset(1);
        }
        if *or as libc::c_int == 0 as libc::c_int {
            ctxt = xmlNewPatParserContext(start, dict, namespaces);
        } else {
            tmp = xmlStrndup(
                start,
                or.offset_from(start) as libc::c_long as libc::c_int,
            );
            if !tmp.is_null() {
                ctxt = xmlNewPatParserContext(tmp, dict, namespaces);
            }
            or = or.offset(1);
        }
        if ctxt.is_null() {
            current_block = 13522574393598791978;
            break;
        }
        cur = xmlNewPattern();
        if cur.is_null() {
            current_block = 13522574393598791978;
            break;
        }
        if !dict.is_null() {
            let ref mut fresh94 = (*cur).dict;
            *fresh94 = dict;
            xmlDictReference(dict);
        }
        if ret.is_null() {
            ret = cur;
        } else {
            let ref mut fresh95 = (*cur).next;
            *fresh95 = (*ret).next;
            let ref mut fresh96 = (*ret).next;
            *fresh96 = cur;
        }
        (*cur).flags = flags;
        let ref mut fresh97 = (*ctxt).comp;
        *fresh97 = cur;
        if (*cur).flags
            & (XML_PATTERN_XSSEL as libc::c_int | XML_PATTERN_XSFIELD as libc::c_int)
            != 0
        {
            xmlCompileIDCXPathPath(ctxt);
        } else {
            xmlCompilePathPattern(ctxt);
        }
        if (*ctxt).error != 0 as libc::c_int {
            current_block = 13522574393598791978;
            break;
        }
        xmlFreePatParserContext(ctxt);
        ctxt = 0 as xmlPatParserContextPtr;
        if streamable != 0 {
            if type_0 == 0 as libc::c_int {
                type_0 = (*cur).flags
                    & ((1 as libc::c_int) << 8 as libc::c_int
                        | (1 as libc::c_int) << 9 as libc::c_int);
            } else if type_0 == (1 as libc::c_int) << 8 as libc::c_int {
                if (*cur).flags & (1 as libc::c_int) << 9 as libc::c_int != 0 {
                    streamable = 0 as libc::c_int;
                }
            } else if type_0 == (1 as libc::c_int) << 9 as libc::c_int {
                if (*cur).flags & (1 as libc::c_int) << 8 as libc::c_int != 0 {
                    streamable = 0 as libc::c_int;
                }
            }
        }
        if streamable != 0 {
            xmlStreamCompile(cur);
        }
        if xmlReversePattern(cur) < 0 as libc::c_int {
            current_block = 13522574393598791978;
            break;
        }
        if !tmp.is_null() {
            xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            tmp = 0 as *mut xmlChar;
        }
        start = or;
    }
    match current_block {
        13522574393598791978 => {
            if !ctxt.is_null() {
                xmlFreePatParserContext(ctxt);
            }
            if !ret.is_null() {
                xmlFreePattern(ret);
            }
            if !tmp.is_null() {
                xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            }
            return 0 as xmlPatternPtr;
        }
        _ => {
            if streamable == 0 as libc::c_int {
                cur = ret;
                while !cur.is_null() {
                    if !((*cur).stream).is_null() {
                        xmlFreeStreamComp((*cur).stream);
                        let ref mut fresh98 = (*cur).stream;
                        *fresh98 = 0 as xmlStreamCompPtr;
                    }
                    cur = (*cur).next;
                }
            }
            return ret;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternMatch(
    mut comp: xmlPatternPtr,
    mut node: xmlNodePtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    if comp.is_null() || node.is_null() {
        return -(1 as libc::c_int);
    }
    while !comp.is_null() {
        ret = xmlPatMatch(comp, node);
        if ret != 0 as libc::c_int {
            return ret;
        }
        comp = (*comp).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternGetStreamCtxt(
    mut comp: xmlPatternPtr,
) -> xmlStreamCtxtPtr {
    let mut current_block: u64;
    let mut ret: xmlStreamCtxtPtr = 0 as xmlStreamCtxtPtr;
    let mut cur: xmlStreamCtxtPtr = 0 as *mut xmlStreamCtxt;
    if comp.is_null() || ((*comp).stream).is_null() {
        return 0 as xmlStreamCtxtPtr;
    }
    loop {
        if comp.is_null() {
            current_block = 11050875288958768710;
            break;
        }
        if ((*comp).stream).is_null() {
            current_block = 11925268974377416611;
            break;
        }
        cur = xmlNewStreamCtxt((*comp).stream);
        if cur.is_null() {
            current_block = 11925268974377416611;
            break;
        }
        if ret.is_null() {
            ret = cur;
        } else {
            let ref mut fresh99 = (*cur).next;
            *fresh99 = (*ret).next;
            let ref mut fresh100 = (*ret).next;
            *fresh100 = cur;
        }
        (*cur).flags = (*comp).flags;
        comp = (*comp).next;
    }
    match current_block {
        11050875288958768710 => return ret,
        _ => {
            xmlFreeStreamCtxt(ret);
            return 0 as xmlStreamCtxtPtr;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternStreamable(mut comp: xmlPatternPtr) -> libc::c_int {
    if comp.is_null() {
        return -(1 as libc::c_int);
    }
    while !comp.is_null() {
        if ((*comp).stream).is_null() {
            return 0 as libc::c_int;
        }
        comp = (*comp).next;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternMaxDepth(mut comp: xmlPatternPtr) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    if comp.is_null() {
        return -(1 as libc::c_int);
    }
    while !comp.is_null() {
        if ((*comp).stream).is_null() {
            return -(1 as libc::c_int);
        }
        i = 0 as libc::c_int;
        while i < (*(*comp).stream).nbStep {
            if (*((*(*comp).stream).steps).offset(i as isize)).flags & 1 as libc::c_int
                != 0
            {
                return -(2 as libc::c_int);
            }
            i += 1;
        }
        if (*(*comp).stream).nbStep > ret {
            ret = (*(*comp).stream).nbStep;
        }
        comp = (*comp).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternMinDepth(mut comp: xmlPatternPtr) -> libc::c_int {
    let mut ret: libc::c_int = 12345678 as libc::c_int;
    if comp.is_null() {
        return -(1 as libc::c_int);
    }
    while !comp.is_null() {
        if ((*comp).stream).is_null() {
            return -(1 as libc::c_int);
        }
        if (*(*comp).stream).nbStep < ret {
            ret = (*(*comp).stream).nbStep;
        }
        if ret == 0 as libc::c_int {
            return 0 as libc::c_int;
        }
        comp = (*comp).next;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPatternFromRoot(mut comp: xmlPatternPtr) -> libc::c_int {
    if comp.is_null() {
        return -(1 as libc::c_int);
    }
    while !comp.is_null() {
        if ((*comp).stream).is_null() {
            return -(1 as libc::c_int);
        }
        if (*comp).flags & (1 as libc::c_int) << 8 as libc::c_int != 0 {
            return 1 as libc::c_int;
        }
        comp = (*comp).next;
    }
    return 0 as libc::c_int;
}
