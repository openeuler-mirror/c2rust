use ::libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    fn xmlParserError(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlParserWarning(ctx: *mut libc::c_void, msg: *const libc::c_char, _: ...);
    fn xmlSAX2SetDocumentLocator(ctx: *mut libc::c_void, loc: xmlSAXLocatorPtr);
    fn xmlSAX2IsStandalone(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasInternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
    fn xmlSAX2HasExternalSubset(ctx: *mut libc::c_void) -> libc::c_int;
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
    fn xmlSAX2GetParameterEntity(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlSAX2ResolveEntity(
        ctx: *mut libc::c_void,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    fn xmlSAX2AttributeDecl(
        ctx: *mut libc::c_void,
        elem: *const xmlChar,
        fullname: *const xmlChar,
        type_0: libc::c_int,
        def: libc::c_int,
        defaultValue: *const xmlChar,
        tree: xmlEnumerationPtr,
    );
    fn xmlSAX2ElementDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
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
    fn xmlSAX2Characters(ctx: *mut libc::c_void, ch: *const xmlChar, len: libc::c_int);
    fn xmlSAX2IgnorableWhitespace(
        ctx: *mut libc::c_void,
        ch: *const xmlChar,
        len: libc::c_int,
    );
    fn xmlSAX2ProcessingInstruction(
        ctx: *mut libc::c_void,
        target: *const xmlChar,
        data: *const xmlChar,
    );
    fn xmlSAX2Comment(ctx: *mut libc::c_void, value: *const xmlChar);
    fn xmlSAX2CDataBlock(
        ctx: *mut libc::c_void,
        value: *const xmlChar,
        len: libc::c_int,
    );
}
pub type xmlChar = libc::c_uchar;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: libc::c_int,
    pub error: libc::c_int,
    pub rawconsumed: libc::c_ulong,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut libc::c_char,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlCharEncodingInputFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_uchar,
        *mut libc::c_int,
        *const libc::c_uchar,
        *mut libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlInputCloseCallback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type xmlInputReadCallback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_char,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const libc::c_char,
    pub directory: *const libc::c_char,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: libc::c_int,
    pub line: libc::c_int,
    pub col: libc::c_int,
    pub consumed: libc::c_ulong,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: libc::c_int,
    pub id: libc::c_int,
}
pub type xmlParserInputDeallocate = Option::<unsafe extern "C" fn(*mut xmlChar) -> ()>;
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
    pub line: libc::c_ushort,
    pub extra: libc::c_ushort,
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
    pub name: *mut libc::c_char,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: libc::c_int,
    pub standalone: libc::c_int,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: libc::c_int,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: libc::c_int,
    pub properties: libc::c_int,
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
pub type xmlElementType = libc::c_uint;
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
pub type xmlAttributeType = libc::c_uint;
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
pub type externalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type cdataBlockSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type getParameterEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
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
    pub length: libc::c_int,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: libc::c_int,
    pub checked: libc::c_int,
}
pub type xmlEntityType = libc::c_uint;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type errorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type warningSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type commentSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type processingInstructionSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> (),
>;
pub type ignorableWhitespaceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type charactersSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
>;
pub type referenceSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type endElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type startElementSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> (),
>;
pub type endDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option::<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option::<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>,
    pub getColumnNumber: Option::<
        unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    >,
}
pub type unparsedEntityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        xmlElementContentPtr,
    ) -> (),
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
pub type xmlElementContentOccur = libc::c_uint;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = libc::c_uint;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        libc::c_int,
        libc::c_int,
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
pub type notationDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type entityDeclSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        libc::c_int,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
>;
pub type resolveEntitySAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type hasInternalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type isStandaloneSAXFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type internalSubsetSAXFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
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
    pub initialized: libc::c_uint,
}
pub type xmlSAXHandlerV1 = _xmlSAXHandlerV1;
#[no_mangle]
pub unsafe extern "C" fn initxmlDefaultSAXHandler(
    mut hdlr: *mut xmlSAXHandlerV1,
    mut warning: libc::c_int,
) {
    if (*hdlr).initialized == 1 as libc::c_int as libc::c_uint {
        return;
    }
    let ref mut fresh0 = (*hdlr).internalSubset;
    *fresh0 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let ref mut fresh1 = (*hdlr).externalSubset;
    *fresh1 = Some(
        xmlSAX2ExternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let ref mut fresh2 = (*hdlr).isStandalone;
    *fresh2 = Some(
        xmlSAX2IsStandalone as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    let ref mut fresh3 = (*hdlr).hasInternalSubset;
    *fresh3 = Some(
        xmlSAX2HasInternalSubset
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    let ref mut fresh4 = (*hdlr).hasExternalSubset;
    *fresh4 = Some(
        xmlSAX2HasExternalSubset
            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
    );
    let ref mut fresh5 = (*hdlr).resolveEntity;
    *fresh5 = Some(
        xmlSAX2ResolveEntity
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> xmlParserInputPtr,
    );
    let ref mut fresh6 = (*hdlr).getEntity;
    *fresh6 = Some(
        xmlSAX2GetEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let ref mut fresh7 = (*hdlr).getParameterEntity;
    *fresh7 = Some(
        xmlSAX2GetParameterEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let ref mut fresh8 = (*hdlr).entityDecl;
    *fresh8 = Some(
        xmlSAX2EntityDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                libc::c_int,
                *const xmlChar,
                *const xmlChar,
                *mut xmlChar,
            ) -> (),
    );
    let ref mut fresh9 = (*hdlr).attributeDecl;
    *fresh9 = Some(
        xmlSAX2AttributeDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                libc::c_int,
                libc::c_int,
                *const xmlChar,
                xmlEnumerationPtr,
            ) -> (),
    );
    let ref mut fresh10 = (*hdlr).elementDecl;
    *fresh10 = Some(
        xmlSAX2ElementDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                libc::c_int,
                xmlElementContentPtr,
            ) -> (),
    );
    let ref mut fresh11 = (*hdlr).notationDecl;
    *fresh11 = Some(
        xmlSAX2NotationDecl
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let ref mut fresh12 = (*hdlr).unparsedEntityDecl;
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
    let ref mut fresh13 = (*hdlr).setDocumentLocator;
    *fresh13 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let ref mut fresh14 = (*hdlr).startDocument;
    *fresh14 = Some(
        xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    let ref mut fresh15 = (*hdlr).endDocument;
    *fresh15 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let ref mut fresh16 = (*hdlr).startElement;
    *fresh16 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    let ref mut fresh17 = (*hdlr).endElement;
    *fresh17 = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let ref mut fresh18 = (*hdlr).reference;
    *fresh18 = Some(
        xmlSAX2Reference as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let ref mut fresh19 = (*hdlr).characters;
    *fresh19 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh20 = (*hdlr).cdataBlock;
    *fresh20 = Some(
        xmlSAX2CDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh21 = (*hdlr).ignorableWhitespace;
    *fresh21 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh22 = (*hdlr).processingInstruction;
    *fresh22 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    if warning == 0 as libc::c_int {
        let ref mut fresh23 = (*hdlr).warning;
        *fresh23 = None;
    } else {
        let ref mut fresh24 = (*hdlr).warning;
        *fresh24 = Some(
            xmlParserWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
    }
    let ref mut fresh25 = (*hdlr).error;
    *fresh25 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh26 = (*hdlr).fatalError;
    *fresh26 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    (*hdlr).initialized = 1 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn inithtmlDefaultSAXHandler(mut hdlr: *mut xmlSAXHandlerV1) {
    if (*hdlr).initialized == 1 as libc::c_int as libc::c_uint {
        return;
    }
    let ref mut fresh27 = (*hdlr).internalSubset;
    *fresh27 = Some(
        xmlSAX2InternalSubset
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let ref mut fresh28 = (*hdlr).externalSubset;
    *fresh28 = None;
    let ref mut fresh29 = (*hdlr).isStandalone;
    *fresh29 = None;
    let ref mut fresh30 = (*hdlr).hasInternalSubset;
    *fresh30 = None;
    let ref mut fresh31 = (*hdlr).hasExternalSubset;
    *fresh31 = None;
    let ref mut fresh32 = (*hdlr).resolveEntity;
    *fresh32 = None;
    let ref mut fresh33 = (*hdlr).getEntity;
    *fresh33 = Some(
        xmlSAX2GetEntity
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr,
    );
    let ref mut fresh34 = (*hdlr).getParameterEntity;
    *fresh34 = None;
    let ref mut fresh35 = (*hdlr).entityDecl;
    *fresh35 = None;
    let ref mut fresh36 = (*hdlr).attributeDecl;
    *fresh36 = None;
    let ref mut fresh37 = (*hdlr).elementDecl;
    *fresh37 = None;
    let ref mut fresh38 = (*hdlr).notationDecl;
    *fresh38 = None;
    let ref mut fresh39 = (*hdlr).unparsedEntityDecl;
    *fresh39 = None;
    let ref mut fresh40 = (*hdlr).setDocumentLocator;
    *fresh40 = Some(
        xmlSAX2SetDocumentLocator
            as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
    );
    let ref mut fresh41 = (*hdlr).startDocument;
    *fresh41 = Some(
        xmlSAX2StartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
    );
    let ref mut fresh42 = (*hdlr).endDocument;
    *fresh42 = Some(xmlSAX2EndDocument as unsafe extern "C" fn(*mut libc::c_void) -> ());
    let ref mut fresh43 = (*hdlr).startElement;
    *fresh43 = Some(
        xmlSAX2StartElement
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *mut *const xmlChar,
            ) -> (),
    );
    let ref mut fresh44 = (*hdlr).endElement;
    *fresh44 = Some(
        xmlSAX2EndElement
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let ref mut fresh45 = (*hdlr).reference;
    *fresh45 = None;
    let ref mut fresh46 = (*hdlr).characters;
    *fresh46 = Some(
        xmlSAX2Characters
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh47 = (*hdlr).cdataBlock;
    *fresh47 = Some(
        xmlSAX2CDataBlock
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh48 = (*hdlr).ignorableWhitespace;
    *fresh48 = Some(
        xmlSAX2IgnorableWhitespace
            as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, libc::c_int) -> (),
    );
    let ref mut fresh49 = (*hdlr).processingInstruction;
    *fresh49 = Some(
        xmlSAX2ProcessingInstruction
            as unsafe extern "C" fn(
                *mut libc::c_void,
                *const xmlChar,
                *const xmlChar,
            ) -> (),
    );
    let ref mut fresh50 = (*hdlr).comment;
    *fresh50 = Some(
        xmlSAX2Comment as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
    );
    let ref mut fresh51 = (*hdlr).warning;
    *fresh51 = Some(
        xmlParserWarning
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh52 = (*hdlr).error;
    *fresh52 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh53 = (*hdlr).fatalError;
    *fresh53 = Some(
        xmlParserError
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    (*hdlr).initialized = 1 as libc::c_int as libc::c_uint;
}
