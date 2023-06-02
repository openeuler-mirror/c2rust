use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
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
pub use crate::src::SAX2::xmlSAX2GetEntity;
pub use crate::src::SAX2::xmlSAX2GetParameterEntity;
pub use crate::src::SAX2::xmlSAX2HasExternalSubset;
pub use crate::src::SAX2::xmlSAX2HasInternalSubset;
pub use crate::src::SAX2::xmlSAX2IgnorableWhitespace;
pub use crate::src::SAX2::xmlSAX2InternalSubset;
pub use crate::src::SAX2::xmlSAX2IsStandalone;
pub use crate::src::SAX2::xmlSAX2NotationDecl;
pub use crate::src::SAX2::xmlSAX2ProcessingInstruction;
pub use crate::src::SAX2::xmlSAX2Reference;
pub use crate::src::SAX2::xmlSAX2ResolveEntity;
pub use crate::src::SAX2::xmlSAX2SetDocumentLocator;
pub use crate::src::SAX2::xmlSAX2StartDocument;
pub use crate::src::SAX2::xmlSAX2StartElement;
pub use crate::src::SAX2::xmlSAX2UnparsedEntityDecl;
pub use crate::src::error::xmlParserError;
pub use crate::src::error::xmlParserWarning;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub type xmlChar = u8;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = * mut crate::src::buf::_xmlBuf;
pub type xmlBuf = crate::src::buf::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = * mut crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = * mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlCharEncodingInputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type xmlInputReadCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>;
pub type xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = * mut crate::src::HTMLparser::_xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C"  fn(_: * mut u8,) -> ()>;
pub type xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputPtr = * mut crate::src::HTMLparser::_xmlParserInput;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::HTMLparser::_xmlNode;
pub type xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::HTMLparser::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::HTMLparser::_xmlDoc;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
pub type externalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type cdataBlockSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type getParameterEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlEntity>;
pub type xmlEntityPtr = * mut crate::src::HTMLparser::_xmlEntity;
pub type xmlEntity = crate::src::HTMLparser::_xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type processingInstructionSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> ()>;
pub type ignorableWhitespaceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type charactersSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type startElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * mut * const u8,) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::HTMLparser::_xmlSAXLocator,) -> ()>;
pub type xmlSAXLocatorPtr = * mut crate::src::HTMLparser::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type elementDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * mut crate::src::HTMLparser::_xmlElementContent,) -> ()>;
pub type xmlElementContentPtr = * mut crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
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
pub type attributeDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: i32,_: i32,_: * const u8,_: * mut crate::src::HTMLparser::_xmlEnumeration,) -> ()>;
pub type xmlEnumerationPtr = * mut crate::src::HTMLparser::_xmlEnumeration;
pub type xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type entityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * const u8,_: * const u8,_: * mut u8,) -> ()>;
pub type getEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlEntity>;
pub type resolveEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> * mut crate::src::HTMLparser::_xmlParserInput>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type internalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
pub type xmlSAXHandlerV1 = crate::src::HTMLparser::_xmlSAXHandlerV1;
#[no_mangle]
pub unsafe extern "C" fn initxmlDefaultSAXHandler<'a1>(
    mut hdlr: Option<&'a1 mut crate::src::HTMLparser::_xmlSAXHandlerV1>,
    mut warning: i32,
) {
    if (*(borrow(& hdlr)).unwrap()).initialized == 1 as i32 as u32 {
        return;
    }
    let fresh0 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).internalSubset);
    *fresh0 = Some(
        xmlSAX2InternalSubset,
    );
    let fresh1 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).externalSubset);
    *fresh1 = Some(
        xmlSAX2ExternalSubset,
    );
    let fresh2 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).isStandalone);
    *fresh2 = Some(
        xmlSAX2IsStandalone,
    );
    let fresh3 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).hasInternalSubset);
    *fresh3 = Some(
        xmlSAX2HasInternalSubset,
    );
    let fresh4 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).hasExternalSubset);
    *fresh4 = Some(
        xmlSAX2HasExternalSubset,
    );
    let fresh5 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).resolveEntity);
    *fresh5 = Some(
        xmlSAX2ResolveEntity,
    );
    let fresh6 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).getEntity);
    *fresh6 = Some(
        xmlSAX2GetEntity,
    );
    let fresh7 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).getParameterEntity);
    *fresh7 = Some(
        xmlSAX2GetParameterEntity,
    );
    let fresh8 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).entityDecl);
    *fresh8 = Some(
        xmlSAX2EntityDecl,
    );
    let fresh9 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).attributeDecl);
    *fresh9 = Some(
        xmlSAX2AttributeDecl,
    );
    let fresh10 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).elementDecl);
    *fresh10 = Some(
        xmlSAX2ElementDecl,
    );
    let fresh11 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).notationDecl);
    *fresh11 = Some(
        xmlSAX2NotationDecl,
    );
    let fresh12 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).unparsedEntityDecl);
    *fresh12 = Some(
        xmlSAX2UnparsedEntityDecl,
    );
    let fresh13 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).setDocumentLocator);
    *fresh13 = Some(
        xmlSAX2SetDocumentLocator,
    );
    let fresh14 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).startDocument);
    *fresh14 = Some(
        xmlSAX2StartDocument,
    );
    let fresh15 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).endDocument);
    *fresh15 = Some(xmlSAX2EndDocument);
    let fresh16 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).startElement);
    *fresh16 = Some(
        xmlSAX2StartElement,
    );
    let fresh17 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).endElement);
    *fresh17 = Some(
        xmlSAX2EndElement,
    );
    let fresh18 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).reference);
    *fresh18 = Some(
        xmlSAX2Reference,
    );
    let fresh19 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).characters);
    *fresh19 = Some(
        xmlSAX2Characters,
    );
    let fresh20 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).cdataBlock);
    *fresh20 = Some(
        xmlSAX2CDataBlock,
    );
    let fresh21 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).ignorableWhitespace);
    *fresh21 = Some(
        xmlSAX2Characters,
    );
    let fresh22 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).processingInstruction);
    *fresh22 = Some(
        xmlSAX2ProcessingInstruction,
    );
    if warning == 0 as i32 {
        let fresh23 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).warning);
        *fresh23 = None;
    } else {
        let fresh24 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).warning);
        *fresh24 = Some(
            xmlParserWarning,
        );
    }
    let fresh25 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).error);
    *fresh25 = Some(
        xmlParserError,
    );
    let fresh26 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).fatalError);
    *fresh26 = Some(
        xmlParserError,
    );
    (*(borrow_mut(&mut hdlr)).unwrap()).initialized = 1 as i32 as u32;
}
#[no_mangle]
pub unsafe extern "C" fn inithtmlDefaultSAXHandler<'a1>(mut hdlr: Option<&'a1 mut crate::src::HTMLparser::_xmlSAXHandlerV1>) {
    if (*(borrow(& hdlr)).unwrap()).initialized == 1 as i32 as u32 {
        return;
    }
    let fresh27 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).internalSubset);
    *fresh27 = Some(
        xmlSAX2InternalSubset,
    );
    let fresh28 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).externalSubset);
    *fresh28 = None;
    let fresh29 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).isStandalone);
    *fresh29 = None;
    let fresh30 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).hasInternalSubset);
    *fresh30 = None;
    let fresh31 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).hasExternalSubset);
    *fresh31 = None;
    let fresh32 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).resolveEntity);
    *fresh32 = None;
    let fresh33 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).getEntity);
    *fresh33 = Some(
        xmlSAX2GetEntity,
    );
    let fresh34 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).getParameterEntity);
    *fresh34 = None;
    let fresh35 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).entityDecl);
    *fresh35 = None;
    let fresh36 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).attributeDecl);
    *fresh36 = None;
    let fresh37 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).elementDecl);
    *fresh37 = None;
    let fresh38 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).notationDecl);
    *fresh38 = None;
    let fresh39 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).unparsedEntityDecl);
    *fresh39 = None;
    let fresh40 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).setDocumentLocator);
    *fresh40 = Some(
        xmlSAX2SetDocumentLocator,
    );
    let fresh41 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).startDocument);
    *fresh41 = Some(
        xmlSAX2StartDocument,
    );
    let fresh42 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).endDocument);
    *fresh42 = Some(xmlSAX2EndDocument);
    let fresh43 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).startElement);
    *fresh43 = Some(
        xmlSAX2StartElement,
    );
    let fresh44 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).endElement);
    *fresh44 = Some(
        xmlSAX2EndElement,
    );
    let fresh45 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).reference);
    *fresh45 = None;
    let fresh46 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).characters);
    *fresh46 = Some(
        xmlSAX2Characters,
    );
    let fresh47 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).cdataBlock);
    *fresh47 = Some(
        xmlSAX2CDataBlock,
    );
    let fresh48 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).ignorableWhitespace);
    *fresh48 = Some(
        xmlSAX2IgnorableWhitespace,
    );
    let fresh49 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).processingInstruction);
    *fresh49 = Some(
        xmlSAX2ProcessingInstruction,
    );
    let fresh50 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).comment);
    *fresh50 = Some(
        xmlSAX2Comment,
    );
    let fresh51 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).warning);
    *fresh51 = Some(
        xmlParserWarning,
    );
    let fresh52 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).error);
    *fresh52 = Some(
        xmlParserError,
    );
    let fresh53 = &mut ((*(borrow_mut(&mut hdlr)).unwrap()).fatalError);
    *fresh53 = Some(
        xmlParserError,
    );
    (*(borrow_mut(&mut hdlr)).unwrap()).initialized = 1 as i32 as u32;
}
use crate::laertes_rt::*;
