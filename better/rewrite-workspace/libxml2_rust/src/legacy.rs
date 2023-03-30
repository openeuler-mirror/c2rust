use ::libc;
extern "C" {
    
    
    
    
    
    
    
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::SAX2::xmlSAX2AttributeDecl;
pub use crate::src::SAX2::xmlSAX2CDataBlock;
pub use crate::src::SAX2::xmlSAX2Characters;
pub use crate::src::SAX2::xmlSAX2Comment;
pub use crate::src::SAX2::xmlSAX2ElementDecl;
pub use crate::src::SAX2::xmlSAX2EndDocument;
pub use crate::src::SAX2::xmlSAX2EndElement;
pub use crate::src::SAX2::xmlSAX2EntityDecl;
pub use crate::src::SAX2::xmlSAX2ExternalSubset;
pub use crate::src::SAX2::xmlSAX2GetColumnNumber;
pub use crate::src::SAX2::xmlSAX2GetEntity;
pub use crate::src::SAX2::xmlSAX2GetLineNumber;
pub use crate::src::SAX2::xmlSAX2GetParameterEntity;
pub use crate::src::SAX2::xmlSAX2GetPublicId;
pub use crate::src::SAX2::xmlSAX2GetSystemId;
pub use crate::src::SAX2::xmlSAX2HasExternalSubset;
pub use crate::src::SAX2::xmlSAX2HasInternalSubset;
pub use crate::src::SAX2::xmlSAX2InternalSubset;
pub use crate::src::SAX2::xmlSAX2IsStandalone;
pub use crate::src::SAX2::xmlSAX2NotationDecl;
pub use crate::src::SAX2::xmlSAX2ProcessingInstruction;
pub use crate::src::SAX2::xmlSAX2Reference;
pub use crate::src::SAX2::xmlSAX2ResolveEntity;
pub use crate::src::SAX2::xmlSAX2StartDocument;
pub use crate::src::SAX2::xmlSAX2StartElement;
pub use crate::src::SAX2::xmlSAX2UnparsedEntityDecl;
pub use crate::src::error::xmlParserValidityError;
pub use crate::src::error::xmlParserValidityWarning;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::HTMLparser::xmlChar;
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
pub use crate::src::HTMLparser::xmlSAXHandler;
pub use crate::src::HTMLparser::xmlSAXHandlerPtr;
pub use crate::src::HTMLtree::xmlNsPtr;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
pub use crate::src::HTMLparser::htmlParserCtxtPtr;
#[no_mangle]
pub unsafe extern "C" fn htmlDecodeEntities(
    mut ctxt: htmlParserCtxtPtr,
    mut len: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"htmlDecodeEntities() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlInitializePredefinedEntities() {}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupPredefinedEntities() {}
static mut xmlFeaturesList: [*const libc::c_char; 42] = [
    b"validate\0" as *const u8 as *const libc::c_char,
    b"load subset\0" as *const u8 as *const libc::c_char,
    b"keep blanks\0" as *const u8 as *const libc::c_char,
    b"disable SAX\0" as *const u8 as *const libc::c_char,
    b"fetch external entities\0" as *const u8 as *const libc::c_char,
    b"substitute entities\0" as *const u8 as *const libc::c_char,
    b"gather line info\0" as *const u8 as *const libc::c_char,
    b"user data\0" as *const u8 as *const libc::c_char,
    b"is html\0" as *const u8 as *const libc::c_char,
    b"is standalone\0" as *const u8 as *const libc::c_char,
    b"stop parser\0" as *const u8 as *const libc::c_char,
    b"document\0" as *const u8 as *const libc::c_char,
    b"is well formed\0" as *const u8 as *const libc::c_char,
    b"is valid\0" as *const u8 as *const libc::c_char,
    b"SAX block\0" as *const u8 as *const libc::c_char,
    b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
    b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
    b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
    b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
    b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
    b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
    b"SAX function startElement\0" as *const u8 as *const libc::c_char,
    b"SAX function endElement\0" as *const u8 as *const libc::c_char,
    b"SAX function reference\0" as *const u8 as *const libc::c_char,
    b"SAX function characters\0" as *const u8 as *const libc::c_char,
    b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
    b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
    b"SAX function comment\0" as *const u8 as *const libc::c_char,
    b"SAX function warning\0" as *const u8 as *const libc::c_char,
    b"SAX function error\0" as *const u8 as *const libc::c_char,
    b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
    b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
    b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
    b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
];
#[no_mangle]
pub unsafe extern "C" fn xmlGetFeaturesList(
    mut len: *mut libc::c_int,
    mut result: *mut *const libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    ret = (::std::mem::size_of::<[*const libc::c_char; 42]>() as libc::c_ulong)
        .wrapping_div(::std::mem::size_of::<*const libc::c_char>() as libc::c_ulong)
        as libc::c_int;
    if len.is_null() || result.is_null() {
        return ret;
    }
    if *len < 0 as libc::c_int || *len >= 1000 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if *len > ret {
        *len = ret;
    }
    i = 0 as libc::c_int;
    while i < *len {
        let ref mut fresh0 = *result.offset(i as isize);
        *fresh0 = xmlFeaturesList[i as usize];
        i += 1;
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlGetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const libc::c_char,
    mut result: *mut libc::c_void,
) -> libc::c_int {
    if ctxt.is_null() || name.is_null() || result.is_null() {
        return -(1 as libc::c_int);
    }
    if strcmp(name, b"validate\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).validate;
    } else if strcmp(name, b"keep blanks\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).keepBlanks;
    } else if strcmp(name, b"disable SAX\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).disableSAX;
    } else if strcmp(
            name,
            b"fetch external entities\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).loadsubset;
    } else if strcmp(name, b"substitute entities\0" as *const u8 as *const libc::c_char)
            == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).replaceEntities;
    } else if strcmp(name, b"gather line info\0" as *const u8 as *const libc::c_char)
            == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).record_info;
    } else if strcmp(name, b"user data\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh1 = *(result as *mut *mut libc::c_void);
        *fresh1 = (*ctxt).userData;
    } else if strcmp(name, b"is html\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).html;
    } else if strcmp(name, b"is standalone\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).standalone;
    } else if strcmp(name, b"document\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh2 = *(result as *mut xmlDocPtr);
        *fresh2 = (*ctxt).myDoc;
    } else if strcmp(name, b"is well formed\0" as *const u8 as *const libc::c_char) == 0
        {
        *(result as *mut libc::c_int) = (*ctxt).wellFormed;
    } else if strcmp(name, b"is valid\0" as *const u8 as *const libc::c_char) == 0 {
        *(result as *mut libc::c_int) = (*ctxt).valid;
    } else if strcmp(name, b"SAX block\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh3 = *(result as *mut xmlSAXHandlerPtr);
        *fresh3 = (*ctxt).sax;
    } else if strcmp(
            name,
            b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh4 = *(result as *mut internalSubsetSAXFunc);
        *fresh4 = (*(*ctxt).sax).internalSubset;
    } else if strcmp(
            name,
            b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh5 = *(result as *mut isStandaloneSAXFunc);
        *fresh5 = (*(*ctxt).sax).isStandalone;
    } else if strcmp(
            name,
            b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh6 = *(result as *mut hasInternalSubsetSAXFunc);
        *fresh6 = (*(*ctxt).sax).hasInternalSubset;
    } else if strcmp(
            name,
            b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh7 = *(result as *mut hasExternalSubsetSAXFunc);
        *fresh7 = (*(*ctxt).sax).hasExternalSubset;
    } else if strcmp(
            name,
            b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh8 = *(result as *mut resolveEntitySAXFunc);
        *fresh8 = (*(*ctxt).sax).resolveEntity;
    } else if strcmp(
            name,
            b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh9 = *(result as *mut getEntitySAXFunc);
        *fresh9 = (*(*ctxt).sax).getEntity;
    } else if strcmp(
            name,
            b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh10 = *(result as *mut entityDeclSAXFunc);
        *fresh10 = (*(*ctxt).sax).entityDecl;
    } else if strcmp(
            name,
            b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh11 = *(result as *mut notationDeclSAXFunc);
        *fresh11 = (*(*ctxt).sax).notationDecl;
    } else if strcmp(
            name,
            b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh12 = *(result as *mut attributeDeclSAXFunc);
        *fresh12 = (*(*ctxt).sax).attributeDecl;
    } else if strcmp(
            name,
            b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh13 = *(result as *mut elementDeclSAXFunc);
        *fresh13 = (*(*ctxt).sax).elementDecl;
    } else if strcmp(
            name,
            b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh14 = *(result as *mut unparsedEntityDeclSAXFunc);
        *fresh14 = (*(*ctxt).sax).unparsedEntityDecl;
    } else if strcmp(
            name,
            b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh15 = *(result as *mut setDocumentLocatorSAXFunc);
        *fresh15 = (*(*ctxt).sax).setDocumentLocator;
    } else if strcmp(
            name,
            b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh16 = *(result as *mut startDocumentSAXFunc);
        *fresh16 = (*(*ctxt).sax).startDocument;
    } else if strcmp(
            name,
            b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh17 = *(result as *mut endDocumentSAXFunc);
        *fresh17 = (*(*ctxt).sax).endDocument;
    } else if strcmp(
            name,
            b"SAX function startElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh18 = *(result as *mut startElementSAXFunc);
        *fresh18 = (*(*ctxt).sax).startElement;
    } else if strcmp(
            name,
            b"SAX function endElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh19 = *(result as *mut endElementSAXFunc);
        *fresh19 = (*(*ctxt).sax).endElement;
    } else if strcmp(
            name,
            b"SAX function reference\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh20 = *(result as *mut referenceSAXFunc);
        *fresh20 = (*(*ctxt).sax).reference;
    } else if strcmp(
            name,
            b"SAX function characters\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh21 = *(result as *mut charactersSAXFunc);
        *fresh21 = (*(*ctxt).sax).characters;
    } else if strcmp(
            name,
            b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh22 = *(result as *mut ignorableWhitespaceSAXFunc);
        *fresh22 = (*(*ctxt).sax).ignorableWhitespace;
    } else if strcmp(
            name,
            b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh23 = *(result as *mut processingInstructionSAXFunc);
        *fresh23 = (*(*ctxt).sax).processingInstruction;
    } else if strcmp(name, b"SAX function comment\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh24 = *(result as *mut commentSAXFunc);
        *fresh24 = (*(*ctxt).sax).comment;
    } else if strcmp(name, b"SAX function warning\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh25 = *(result as *mut warningSAXFunc);
        *fresh25 = (*(*ctxt).sax).warning;
    } else if strcmp(name, b"SAX function error\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh26 = *(result as *mut errorSAXFunc);
        *fresh26 = (*(*ctxt).sax).error;
    } else if strcmp(
            name,
            b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh27 = *(result as *mut fatalErrorSAXFunc);
        *fresh27 = (*(*ctxt).sax).fatalError;
    } else if strcmp(
            name,
            b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh28 = *(result as *mut getParameterEntitySAXFunc);
        *fresh28 = (*(*ctxt).sax).getParameterEntity;
    } else if strcmp(
            name,
            b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh29 = *(result as *mut cdataBlockSAXFunc);
        *fresh29 = (*(*ctxt).sax).cdataBlock;
    } else if strcmp(
            name,
            b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh30 = *(result as *mut externalSubsetSAXFunc);
        *fresh30 = (*(*ctxt).sax).externalSubset;
    } else {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetFeature(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const libc::c_char,
    mut value: *mut libc::c_void,
) -> libc::c_int {
    if ctxt.is_null() || name.is_null() || value.is_null() {
        return -(1 as libc::c_int);
    }
    if strcmp(name, b"validate\0" as *const u8 as *const libc::c_char) == 0 {
        let mut newvalidate: libc::c_int = *(value as *mut libc::c_int);
        if (*ctxt).validate == 0 && newvalidate != 0 as libc::c_int {
            if ((*ctxt).vctxt.warning).is_none() {
                let ref mut fresh31 = (*ctxt).vctxt.warning;
                *fresh31 = Some(
                    xmlParserValidityWarning
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            ...
                        ) -> (),
                );
            }
            if ((*ctxt).vctxt.error).is_none() {
                let ref mut fresh32 = (*ctxt).vctxt.error;
                *fresh32 = Some(
                    xmlParserValidityError
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            ...
                        ) -> (),
                );
            }
            (*ctxt).vctxt.nodeMax = 0 as libc::c_int;
        }
        (*ctxt).validate = newvalidate;
    } else if strcmp(name, b"keep blanks\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).keepBlanks = *(value as *mut libc::c_int);
    } else if strcmp(name, b"disable SAX\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).disableSAX = *(value as *mut libc::c_int);
    } else if strcmp(
            name,
            b"fetch external entities\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        (*ctxt).loadsubset = *(value as *mut libc::c_int);
    } else if strcmp(name, b"substitute entities\0" as *const u8 as *const libc::c_char)
            == 0
        {
        (*ctxt).replaceEntities = *(value as *mut libc::c_int);
    } else if strcmp(name, b"gather line info\0" as *const u8 as *const libc::c_char)
            == 0
        {
        (*ctxt).record_info = *(value as *mut libc::c_int);
    } else if strcmp(name, b"user data\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh33 = (*ctxt).userData;
        *fresh33 = *(value as *mut *mut libc::c_void);
    } else if strcmp(name, b"is html\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).html = *(value as *mut libc::c_int);
    } else if strcmp(name, b"is standalone\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).standalone = *(value as *mut libc::c_int);
    } else if strcmp(name, b"document\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh34 = (*ctxt).myDoc;
        *fresh34 = *(value as *mut xmlDocPtr);
    } else if strcmp(name, b"is well formed\0" as *const u8 as *const libc::c_char) == 0
        {
        (*ctxt).wellFormed = *(value as *mut libc::c_int);
    } else if strcmp(name, b"is valid\0" as *const u8 as *const libc::c_char) == 0 {
        (*ctxt).valid = *(value as *mut libc::c_int);
    } else if strcmp(name, b"SAX block\0" as *const u8 as *const libc::c_char) == 0 {
        let ref mut fresh35 = (*ctxt).sax;
        *fresh35 = *(value as *mut xmlSAXHandlerPtr);
    } else if strcmp(
            name,
            b"SAX function internalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh36 = (*(*ctxt).sax).internalSubset;
        *fresh36 = *(value as *mut internalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function isStandalone\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh37 = (*(*ctxt).sax).isStandalone;
        *fresh37 = *(value as *mut isStandaloneSAXFunc);
    } else if strcmp(
            name,
            b"SAX function hasInternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh38 = (*(*ctxt).sax).hasInternalSubset;
        *fresh38 = *(value as *mut hasInternalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function hasExternalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh39 = (*(*ctxt).sax).hasExternalSubset;
        *fresh39 = *(value as *mut hasExternalSubsetSAXFunc);
    } else if strcmp(
            name,
            b"SAX function resolveEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh40 = (*(*ctxt).sax).resolveEntity;
        *fresh40 = *(value as *mut resolveEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function getEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh41 = (*(*ctxt).sax).getEntity;
        *fresh41 = *(value as *mut getEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function entityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh42 = (*(*ctxt).sax).entityDecl;
        *fresh42 = *(value as *mut entityDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function notationDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh43 = (*(*ctxt).sax).notationDecl;
        *fresh43 = *(value as *mut notationDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function attributeDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh44 = (*(*ctxt).sax).attributeDecl;
        *fresh44 = *(value as *mut attributeDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function elementDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh45 = (*(*ctxt).sax).elementDecl;
        *fresh45 = *(value as *mut elementDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh46 = (*(*ctxt).sax).unparsedEntityDecl;
        *fresh46 = *(value as *mut unparsedEntityDeclSAXFunc);
    } else if strcmp(
            name,
            b"SAX function setDocumentLocator\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh47 = (*(*ctxt).sax).setDocumentLocator;
        *fresh47 = *(value as *mut setDocumentLocatorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function startDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh48 = (*(*ctxt).sax).startDocument;
        *fresh48 = *(value as *mut startDocumentSAXFunc);
    } else if strcmp(
            name,
            b"SAX function endDocument\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh49 = (*(*ctxt).sax).endDocument;
        *fresh49 = *(value as *mut endDocumentSAXFunc);
    } else if strcmp(
            name,
            b"SAX function startElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh50 = (*(*ctxt).sax).startElement;
        *fresh50 = *(value as *mut startElementSAXFunc);
    } else if strcmp(
            name,
            b"SAX function endElement\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh51 = (*(*ctxt).sax).endElement;
        *fresh51 = *(value as *mut endElementSAXFunc);
    } else if strcmp(
            name,
            b"SAX function reference\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh52 = (*(*ctxt).sax).reference;
        *fresh52 = *(value as *mut referenceSAXFunc);
    } else if strcmp(
            name,
            b"SAX function characters\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh53 = (*(*ctxt).sax).characters;
        *fresh53 = *(value as *mut charactersSAXFunc);
    } else if strcmp(
            name,
            b"SAX function ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh54 = (*(*ctxt).sax).ignorableWhitespace;
        *fresh54 = *(value as *mut ignorableWhitespaceSAXFunc);
    } else if strcmp(
            name,
            b"SAX function processingInstruction\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh55 = (*(*ctxt).sax).processingInstruction;
        *fresh55 = *(value as *mut processingInstructionSAXFunc);
    } else if strcmp(name, b"SAX function comment\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh56 = (*(*ctxt).sax).comment;
        *fresh56 = *(value as *mut commentSAXFunc);
    } else if strcmp(name, b"SAX function warning\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh57 = (*(*ctxt).sax).warning;
        *fresh57 = *(value as *mut warningSAXFunc);
    } else if strcmp(name, b"SAX function error\0" as *const u8 as *const libc::c_char)
            == 0
        {
        let ref mut fresh58 = (*(*ctxt).sax).error;
        *fresh58 = *(value as *mut errorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function fatalError\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh59 = (*(*ctxt).sax).fatalError;
        *fresh59 = *(value as *mut fatalErrorSAXFunc);
    } else if strcmp(
            name,
            b"SAX function getParameterEntity\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh60 = (*(*ctxt).sax).getParameterEntity;
        *fresh60 = *(value as *mut getParameterEntitySAXFunc);
    } else if strcmp(
            name,
            b"SAX function cdataBlock\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh61 = (*(*ctxt).sax).cdataBlock;
        *fresh61 = *(value as *mut cdataBlockSAXFunc);
    } else if strcmp(
            name,
            b"SAX function externalSubset\0" as *const u8 as *const libc::c_char,
        ) == 0
        {
        let ref mut fresh62 = (*(*ctxt).sax).externalSubset;
        *fresh62 = *(value as *mut externalSubsetSAXFunc);
    } else {
        return -(1 as libc::c_int)
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut len: libc::c_int,
    mut what: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlDecodeEntities() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseNCName(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNCName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseQName(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseQName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlNamespaceParseNSDef(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNamespaceParseNSDef() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseQuotedString(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParseQuotedString() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNamespace(mut ctxt: xmlParserCtxtPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParseNamespace() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlScanName(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlScanName() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserHandleReference(mut ctxt: xmlParserCtxtPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlParserHandleReference() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlHandleEntity(
    mut ctxt: xmlParserCtxtPtr,
    mut entity: xmlEntityPtr,
) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlHandleEntity() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewGlobalNs(
    mut doc: xmlDocPtr,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) -> xmlNsPtr {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlNewGlobalNs() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub unsafe extern "C" fn xmlUpgradeOldNs(mut doc: xmlDocPtr) {
    static mut deprecated: libc::c_int = 0 as libc::c_int;
    if deprecated == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"xmlUpgradeOldNs() deprecated function reached\n\0" as *const u8
                as *const libc::c_char,
        );
        deprecated = 1 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlEncodeEntities(
    mut doc: xmlDocPtr,
    mut input: *const xmlChar,
) -> *const xmlChar {
    static mut warning: libc::c_int = 1 as libc::c_int;
    if warning != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Deprecated API xmlEncodeEntities() used\n\0" as *const u8
                as *const libc::c_char,
        );
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"   change code to use xmlEncodeEntitiesReentrant()\n\0" as *const u8
                as *const libc::c_char,
        );
        warning = 0 as libc::c_int;
    }
    return 0 as *const xmlChar;
}
static mut deprecated_v1_msg: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn getPublicId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getPublicId\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetPublicId(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getSystemId(mut ctx: *mut libc::c_void) -> *const xmlChar {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getSystemId\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetSystemId(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getLineNumber(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getLineNumber\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetLineNumber(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn getColumnNumber(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getColumnNumber\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetColumnNumber(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn isStandalone(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"isStandalone\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2IsStandalone(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn hasInternalSubset(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"hasInternalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2HasInternalSubset(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn hasExternalSubset(mut ctx: *mut libc::c_void) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"hasExternalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2HasExternalSubset(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn internalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"internalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2InternalSubset(ctx, name, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn externalSubset(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"externalSubset\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ExternalSubset(ctx, name, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn resolveEntity(
    mut ctx: *mut libc::c_void,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) -> xmlParserInputPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"resolveEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2ResolveEntity(ctx, publicId, systemId);
}
#[no_mangle]
pub unsafe extern "C" fn getEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetEntity(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn getParameterEntity(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getParameterEntity\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return xmlSAX2GetParameterEntity(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn entityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"entityDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EntityDecl(ctx, name, type_0, publicId, systemId, content);
}
#[no_mangle]
pub unsafe extern "C" fn attributeDecl(
    mut ctx: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut fullname: *const xmlChar,
    mut type_0: libc::c_int,
    mut def: libc::c_int,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"attributeDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2AttributeDecl(ctx, elem, fullname, type_0, def, defaultValue, tree);
}
#[no_mangle]
pub unsafe extern "C" fn elementDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut content: xmlElementContentPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"elementDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ElementDecl(ctx, name, type_0, content);
}
#[no_mangle]
pub unsafe extern "C" fn notationDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"notationDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2NotationDecl(ctx, name, publicId, systemId);
}
#[no_mangle]
pub unsafe extern "C" fn unparsedEntityDecl(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"unparsedEntityDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2UnparsedEntityDecl(ctx, name, publicId, systemId, notationName);
}
#[no_mangle]
pub unsafe extern "C" fn setDocumentLocator(
    mut ctx: *mut libc::c_void,
    mut loc: xmlSAXLocatorPtr,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"setDocumentLocator\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn startDocument(mut ctx: *mut libc::c_void) {
    xmlSAX2StartDocument(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn endDocument(mut ctx: *mut libc::c_void) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"endDocument\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EndDocument(ctx);
}
#[no_mangle]
pub unsafe extern "C" fn attribute(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut value: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"attribute\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn startElement(
    mut ctx: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    xmlSAX2StartElement(ctx, fullname, atts);
}
#[no_mangle]
pub unsafe extern "C" fn endElement(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"endElement\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2EndElement(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn reference(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"reference\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Reference(ctx, name);
}
#[no_mangle]
pub unsafe extern "C" fn characters(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"characters\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Characters(ctx, ch, len);
}
#[no_mangle]
pub unsafe extern "C" fn ignorableWhitespace(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"ignorableWhitespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn processingInstruction(
    mut ctx: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"processingInstruction\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2ProcessingInstruction(ctx, target, data);
}
#[no_mangle]
pub unsafe extern "C" fn globalNamespace(
    mut ctx: *mut libc::c_void,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"globalNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn setNamespace(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"setNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn getNamespace(mut ctx: *mut libc::c_void) -> xmlNsPtr {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"getNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub unsafe extern "C" fn checkNamespace(
    mut ctx: *mut libc::c_void,
    mut namespace: *mut xmlChar,
) -> libc::c_int {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"checkNamespace\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn namespaceDecl(
    mut ctx: *mut libc::c_void,
    mut href: *const xmlChar,
    mut prefix: *const xmlChar,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"namespaceDecl\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
}
#[no_mangle]
pub unsafe extern "C" fn comment(mut ctx: *mut libc::c_void, mut value: *const xmlChar) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"comment\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2Comment(ctx, value);
}
#[no_mangle]
pub unsafe extern "C" fn cdataBlock(
    mut ctx: *mut libc::c_void,
    mut value: *const xmlChar,
    mut len: libc::c_int,
) {
    if deprecated_v1_msg == 0 as libc::c_int {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Use of deprecated SAXv1 function %s\n\0" as *const u8
                as *const libc::c_char,
            b"cdataBlock\0" as *const u8 as *const libc::c_char,
        );
    }
    deprecated_v1_msg += 1;
    xmlSAX2CDataBlock(ctx, value, len);
}
