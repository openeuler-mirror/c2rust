use ::libc;
extern "C" {
    pub type _xmlDict;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn xmlSearchNs(
        doc: xmlDocPtr,
        node: xmlNodePtr,
        nameSpace: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlGetNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        nameSpace: *const xmlChar,
    ) -> *mut xmlChar;
    static mut xmlFree: xmlFreeFunc;
}
pub type xmlChar = libc::c_uchar;
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
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
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlDocPtr = *mut xmlDoc;
pub type xmlDoc = _xmlDoc;
pub type xmlNsPtr = *mut xmlNs;
pub type xlinkHRef = *mut xmlChar;
pub type xlinkRole = *mut xmlChar;
pub type xlinkTitle = *mut xmlChar;
pub type xlinkType = libc::c_uint;
pub const XLINK_TYPE_EXTENDED_SET: xlinkType = 3;
pub const XLINK_TYPE_EXTENDED: xlinkType = 2;
pub const XLINK_TYPE_SIMPLE: xlinkType = 1;
pub const XLINK_TYPE_NONE: xlinkType = 0;
pub type xlinkShow = libc::c_uint;
pub const XLINK_SHOW_REPLACE: xlinkShow = 3;
pub const XLINK_SHOW_EMBED: xlinkShow = 2;
pub const XLINK_SHOW_NEW: xlinkShow = 1;
pub const XLINK_SHOW_NONE: xlinkShow = 0;
pub type xlinkActuate = libc::c_uint;
pub const XLINK_ACTUATE_ONREQUEST: xlinkActuate = 2;
pub const XLINK_ACTUATE_AUTO: xlinkActuate = 1;
pub const XLINK_ACTUATE_NONE: xlinkActuate = 0;
pub type xlinkNodeDetectFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlNodePtr) -> (),
>;
pub type xlinkSimpleLinkFunk = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        xmlNodePtr,
        xlinkHRef,
        xlinkRole,
        xlinkTitle,
    ) -> (),
>;
pub type xlinkExtendedLinkFunk = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        xmlNodePtr,
        libc::c_int,
        *const xlinkHRef,
        *const xlinkRole,
        libc::c_int,
        *const xlinkRole,
        *const xlinkRole,
        *mut xlinkShow,
        *mut xlinkActuate,
        libc::c_int,
        *const xlinkTitle,
        *mut *const xmlChar,
    ) -> (),
>;
pub type xlinkExtendedLinkSetFunk = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        xmlNodePtr,
        libc::c_int,
        *const xlinkHRef,
        *const xlinkRole,
        libc::c_int,
        *const xlinkTitle,
        *mut *const xmlChar,
    ) -> (),
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xlinkHandler {
    pub simple: xlinkSimpleLinkFunk,
    pub extended: xlinkExtendedLinkFunk,
    pub set: xlinkExtendedLinkSetFunk,
}
pub type xlinkHandler = _xlinkHandler;
pub type xlinkHandlerPtr = *mut xlinkHandler;
static mut xlinkDefaultHandler: xlinkHandlerPtr = 0 as *const xlinkHandler
    as xlinkHandlerPtr;
static mut xlinkDefaultDetect: xlinkNodeDetectFunc = None;
#[no_mangle]
pub unsafe extern "C" fn xlinkGetDefaultHandler() -> xlinkHandlerPtr {
    return xlinkDefaultHandler;
}
#[no_mangle]
pub unsafe extern "C" fn xlinkSetDefaultHandler(mut handler: xlinkHandlerPtr) {
    xlinkDefaultHandler = handler;
}
#[no_mangle]
pub unsafe extern "C" fn xlinkGetDefaultDetect() -> xlinkNodeDetectFunc {
    return xlinkDefaultDetect;
}
#[no_mangle]
pub unsafe extern "C" fn xlinkSetDefaultDetect(mut func: xlinkNodeDetectFunc) {
    xlinkDefaultDetect = func;
}
#[no_mangle]
pub unsafe extern "C" fn xlinkIsLink(
    mut doc: xmlDocPtr,
    mut node: xmlNodePtr,
) -> xlinkType {
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut role: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: xlinkType = XLINK_TYPE_NONE;
    if node.is_null() {
        return XLINK_TYPE_NONE;
    }
    if doc.is_null() {
        doc = (*node).doc;
    }
    if !(!doc.is_null()
        && (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint)
    {
        !((*node).ns).is_null()
            && xmlStrEqual(
                (*(*node).ns).href,
                b"http://www.w3.org/1999/xhtml/\0" as *const u8 as *const libc::c_char
                    as *mut xmlChar,
            ) != 0;
    }
    type_0 = xmlGetNsProp(
        node as *const xmlNode,
        b"type\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8 as *const libc::c_char
            as *mut xmlChar,
    );
    if !type_0.is_null() {
        if xmlStrEqual(
            type_0,
            b"simple\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
        {
            ret = XLINK_TYPE_SIMPLE;
        } else if xmlStrEqual(
                type_0,
                b"extended\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
            role = xmlGetNsProp(
                node as *const xmlNode,
                b"role\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8
                    as *const libc::c_char as *mut xmlChar,
            );
            if !role.is_null() {
                let mut xlink: xmlNsPtr = 0 as *mut xmlNs;
                xlink = xmlSearchNs(
                    doc,
                    node,
                    b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8
                        as *const libc::c_char as *mut xmlChar,
                );
                if xlink.is_null() {
                    if xmlStrEqual(
                        role,
                        b"xlink:external-linkset\0" as *const u8 as *const libc::c_char
                            as *mut xmlChar,
                    ) != 0
                    {
                        ret = XLINK_TYPE_EXTENDED_SET;
                    }
                } else {
                    let mut buf: [xmlChar; 200] = [0; 200];
                    snprintf(
                        buf.as_mut_ptr() as *mut libc::c_char,
                        ::std::mem::size_of::<[xmlChar; 200]>() as libc::c_ulong,
                        b"%s:external-linkset\0" as *const u8 as *const libc::c_char,
                        (*xlink).prefix as *mut libc::c_char,
                    );
                    buf[(::std::mem::size_of::<[xmlChar; 200]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as usize] = 0 as libc::c_int as xmlChar;
                    if xmlStrEqual(role, buf.as_mut_ptr()) != 0 {
                        ret = XLINK_TYPE_EXTENDED_SET;
                    }
                }
            }
            ret = XLINK_TYPE_EXTENDED;
        }
    }
    if !type_0.is_null() {
        xmlFree.expect("non-null function pointer")(type_0 as *mut libc::c_void);
    }
    if !role.is_null() {
        xmlFree.expect("non-null function pointer")(role as *mut libc::c_void);
    }
    return ret;
}
