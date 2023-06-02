use :: libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const i8, _: ...);
    fn xmlSAX2SetDocumentLocator(ctx: *mut libc::c_void, loc: xmlSAXLocatorPtr);
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> i32;
    fn xmlSAX2InternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2ExternalSubset(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlSAX2GetEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2GetParameterEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: i32,
        def: i32,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: i32,
        content: xmlElementContentPtr,
    );
    fn xmlSAX2NotationDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    );
    fn xmlSAX2UnparsedEntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        notationName: *const xmlChar,
    );
    fn xmlSAX2StartDocument(ctx: *mut libc::c_void);
    fn xmlSAX2EndDocument(ctx: *mut libc::c_void);
    fn xmlSAX2StartElement(
        ctx: *mut libc::c_void,
        fullname: *const xmlChar,
        atts: *mut *const xmlChar,
    );
    fn xmlSAX2EndElement(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Reference(ctx: *mut libc::c_void, name: *const xmlChar);
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2IgnorableWhitespace(ctx: *mut libc::c_void, ch: *const xmlChar, len: i32);
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(ctx: *mut libc::c_void, value: *const xmlChar, len: i32);
}
pub type xmlChar = u8;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: i32,
    pub error: i32,
    pub rawconsumed: u64,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut i8,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut i8, i32) -> i32>;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const i8,
    pub directory: *const i8,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: i32,
    pub line: i32,
    pub col: i32,
    pub consumed: u64,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: i32,
    pub id: i32,
}
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(*mut xmlChar) -> ()>;
pub type xmlParserInput = _xmlParserInput;
pub type xmlParserInputPtr = *mut xmlParserInput;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNode {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub content: *mut xmlChar,
    pub properties: *mut _xmlAttr,
    pub nsDef: *mut xmlNs,
    pub psvi: *mut libc::c_void,
    pub line: u16,
    pub extra: u16,
}
pub type xmlNs = _xmlNs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNs {
    pub next: *mut _xmlNs,
    pub type_0: xmlNsType,
    pub href: *const xmlChar,
    pub prefix: *const xmlChar,
    pub _private: *mut libc::c_void,
    pub context: *mut _xmlDoc,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDoc {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *mut i8,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: i32,
    pub standalone: i32,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: i32,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: i32,
    pub properties: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDtd {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDoc,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub notations: *mut libc::c_void,
    pub elements: *mut libc::c_void,
    pub attributes: *mut libc::c_void,
    pub entities: *mut libc::c_void,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub pentities: *mut libc::c_void,
}
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
pub type xmlNsType = xmlElementType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttr {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlAttr,
    pub prev: *mut _xmlAttr,
    pub doc: *mut _xmlDoc,
    pub ns: *mut xmlNs,
    pub atype: xmlAttributeType,
    pub psvi: *mut libc::c_void,
}
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
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type getParameterEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type xmlEntityPtr = *mut xmlEntity;
pub type xmlEntity = _xmlEntity;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEntity {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub orig: *mut xmlChar,
    pub content: *mut xmlChar,
    pub length: i32,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: i32,
    pub checked: i32,
}
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> ()>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
    pub getColumnNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
}
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32, xmlElementContentPtr) -> (),
>;
pub type xmlElementContentPtr = *mut xmlElementContent;
pub type xmlElementContent = _xmlElementContent;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElementContent {
    pub type_0: xmlElementContentType,
    pub ocur: xmlElementContentOccur,
    pub name: *const xmlChar,
    pub c1: *mut _xmlElementContent,
    pub c2: *mut _xmlElementContent,
    pub parent: *mut _xmlElementContent,
    pub prefix: *const xmlChar,
}
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
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        i32,
        i32,
        *const xmlChar,
        xmlEnumerationPtr,
    ) -> (),
>;
pub type xmlEnumerationPtr = *mut xmlEnumeration;
pub type xmlEnumeration = _xmlEnumeration;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlEnumeration {
    pub next: *mut _xmlEnumeration,
    pub name: *const xmlChar,
}
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        i32,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandlerV1 {
    pub internalSubset: internalSubsetSAXFunc,
    pub isStandalone: isStandaloneSAXFunc,
    pub hasInternalSubset: hasInternalSubsetSAXFunc,
    pub hasExternalSubset: hasExternalSubsetSAXFunc,
    pub resolveEntity: resolveEntitySAXFunc,
    pub getEntity: getEntitySAXFunc,
    pub entityDecl: entityDeclSAXFunc,
    pub notationDecl: notationDeclSAXFunc,
    pub attributeDecl: attributeDeclSAXFunc,
    pub elementDecl: elementDeclSAXFunc,
    pub unparsedEntityDecl: unparsedEntityDeclSAXFunc,
    pub setDocumentLocator: setDocumentLocatorSAXFunc,
    pub startDocument: startDocumentSAXFunc,
    pub endDocument: endDocumentSAXFunc,
    pub startElement: startElementSAXFunc,
    pub endElement: endElementSAXFunc,
    pub reference: referenceSAXFunc,
    pub characters: charactersSAXFunc,
    pub ignorableWhitespace: ignorableWhitespaceSAXFunc,
    pub processingInstruction: processingInstructionSAXFunc,
    pub comment: commentSAXFunc,
    pub warning: warningSAXFunc,
    pub error: errorSAXFunc,
    pub fatalError: fatalErrorSAXFunc,
    pub getParameterEntity: getParameterEntitySAXFunc,
    pub cdataBlock: cdataBlockSAXFunc,
    pub externalSubset: externalSubsetSAXFunc,
    pub initialized: u32,
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
#[no_mangle]
pub extern "C" fn initxmlDefaultSAXHandler(mut hdlr: *mut xmlSAXHandlerV1, mut warning: i32) {
    if (unsafe { (*hdlr).initialized }) == 1 as i32 as u32 {
        return;
    }
    let fresh0 = unsafe { &mut ((*hdlr).internalSubset) };
    *fresh0 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh1 = unsafe { &mut ((*hdlr).externalSubset) };
    *fresh1 = Some(
        xmlSAX2ExternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh2 = unsafe { &mut ((*hdlr).isStandalone) };
    *fresh2 = Some(xmlSAX2IsStandalone as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh3 = unsafe { &mut ((*hdlr).hasInternalSubset) };
    *fresh3 = Some(xmlSAX2HasInternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh4 = unsafe { &mut ((*hdlr).hasExternalSubset) };
    *fresh4 = Some(xmlSAX2HasExternalSubset as unsafe extern "C" fn(*mut libc::c_void) -> i32);
    let fresh5 = unsafe { &mut ((*hdlr).resolveEntity) };
    *fresh5 = Some(
        xmlSAX2ResolveEntity
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> xmlParserInputPtr,
    );
    let fresh6 = unsafe { &mut ((*hdlr).getEntity) };
    *fresh6 = Some(
        xmlSAX2GetEntity as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh7 = unsafe { &mut ((*hdlr).getParameterEntity) };
    *fresh7 = Some(
        xmlSAX2GetParameterEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh8 = unsafe { &mut ((*hdlr).entityDecl) };
    *fresh8 = Some(
        xmlSAX2EntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                *const xmlChar,
                *const xmlChar,
                *mut xmlChar,
            ) -> (),
    );
    let fresh9 = unsafe { &mut ((*hdlr).attributeDecl) };
    *fresh9 = Some(
        xmlSAX2AttributeDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                i32,
                i32,
                *const xmlChar,
                xmlEnumerationPtr,
            ) -> (),
    );
    let fresh10 = unsafe { &mut ((*hdlr).elementDecl) };
    *fresh10 = Some(
        xmlSAX2ElementDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                i32,
                xmlElementContentPtr,
            ) -> (),
    );
    let fresh11 = unsafe { &mut ((*hdlr).notationDecl) };
    *fresh11 = Some(
        xmlSAX2NotationDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh12 = unsafe { &mut ((*hdlr).unparsedEntityDecl) };
    *fresh12 = Some(
        xmlSAX2UnparsedEntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh13 = unsafe { &mut ((*hdlr).setDocumentLocator) };
    *fresh13 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh14 = unsafe { &mut ((*hdlr).startDocument) };
    *fresh14 = Some(xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh15 = unsafe { &mut ((*hdlr).endDocument) };
    *fresh15 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh16 = unsafe { &mut ((*hdlr).startElement) };
    *fresh16 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
    );
    let fresh17 = unsafe { &mut ((*hdlr).endElement) };
    *fresh17 =
        Some(xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh18 = unsafe { &mut ((*hdlr).reference) };
    *fresh18 =
        Some(xmlSAX2Reference as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh19 = unsafe { &mut ((*hdlr).characters) };
    *fresh19 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh20 = unsafe { &mut ((*hdlr).cdataBlock) };
    *fresh20 = Some(
        xmlSAX2CDataBlock as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh21 = unsafe { &mut ((*hdlr).ignorableWhitespace) };
    *fresh21 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh22 = unsafe { &mut ((*hdlr).processingInstruction) };
    *fresh22 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
    );
    if warning == 0 as i32 {
        let fresh23 = unsafe { &mut ((*hdlr).warning) };
        *fresh23 = None;
    } else {
        let fresh24 = unsafe { &mut ((*hdlr).warning) };
        *fresh24 =
            Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    }
    let fresh25 = unsafe { &mut ((*hdlr).error) };
    *fresh25 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh26 = unsafe { &mut ((*hdlr).fatalError) };
    *fresh26 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    (unsafe { (*hdlr).initialized = 1 as i32 as u32 });
}
#[no_mangle]
pub extern "C" fn inithtmlDefaultSAXHandler(mut hdlr: *mut xmlSAXHandlerV1) {
    if (unsafe { (*hdlr).initialized }) == 1 as i32 as u32 {
        return;
    }
    let fresh27 = unsafe { &mut ((*hdlr).internalSubset) };
    *fresh27 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let fresh28 = unsafe { &mut ((*hdlr).externalSubset) };
    *fresh28 = None;
    let fresh29 = unsafe { &mut ((*hdlr).isStandalone) };
    *fresh29 = None;
    let fresh30 = unsafe { &mut ((*hdlr).hasInternalSubset) };
    *fresh30 = None;
    let fresh31 = unsafe { &mut ((*hdlr).hasExternalSubset) };
    *fresh31 = None;
    let fresh32 = unsafe { &mut ((*hdlr).resolveEntity) };
    *fresh32 = None;
    let fresh33 = unsafe { &mut ((*hdlr).getEntity) };
    *fresh33 = Some(
        xmlSAX2GetEntity as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let fresh34 = unsafe { &mut ((*hdlr).getParameterEntity) };
    *fresh34 = None;
    let fresh35 = unsafe { &mut ((*hdlr).entityDecl) };
    *fresh35 = None;
    let fresh36 = unsafe { &mut ((*hdlr).attributeDecl) };
    *fresh36 = None;
    let fresh37 = unsafe { &mut ((*hdlr).elementDecl) };
    *fresh37 = None;
    let fresh38 = unsafe { &mut ((*hdlr).notationDecl) };
    *fresh38 = None;
    let fresh39 = unsafe { &mut ((*hdlr).unparsedEntityDecl) };
    *fresh39 = None;
    let fresh40 = unsafe { &mut ((*hdlr).setDocumentLocator) };
    *fresh40 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let fresh41 = unsafe { &mut ((*hdlr).startDocument) };
    *fresh41 = Some(xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh42 = unsafe { &mut ((*hdlr).endDocument) };
    *fresh42 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let fresh43 = unsafe { &mut ((*hdlr).startElement) };
    *fresh43 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
    );
    let fresh44 = unsafe { &mut ((*hdlr).endElement) };
    *fresh44 =
        Some(xmlSAX2EndElement as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh45 = unsafe { &mut ((*hdlr).reference) };
    *fresh45 = None;
    let fresh46 = unsafe { &mut ((*hdlr).characters) };
    *fresh46 = Some(
        xmlSAX2Characters as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh47 = unsafe { &mut ((*hdlr).cdataBlock) };
    *fresh47 = Some(
        xmlSAX2CDataBlock as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh48 = unsafe { &mut ((*hdlr).ignorableWhitespace) };
    *fresh48 = Some(
        xmlSAX2IgnorableWhitespace
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> (),
    );
    let fresh49 = unsafe { &mut ((*hdlr).processingInstruction) };
    *fresh49 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
    );
    let fresh50 = unsafe { &mut ((*hdlr).comment) };
    *fresh50 =
        Some(xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ());
    let fresh51 = unsafe { &mut ((*hdlr).warning) };
    *fresh51 =
        Some(xmlParserWarning as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh52 = unsafe { &mut ((*hdlr).error) };
    *fresh52 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    let fresh53 = unsafe { &mut ((*hdlr).fatalError) };
    *fresh53 =
        Some(xmlParserError as unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ());
    (unsafe { (*hdlr).initialized = 1 as i32 as u32 });
}
