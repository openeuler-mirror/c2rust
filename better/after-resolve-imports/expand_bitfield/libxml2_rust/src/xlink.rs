use ::libc;
extern "C" {
    
    
    fn snprintf(
        _: *mut i8,
        _: u64,
        _: *const i8,
        _: ...
    ) -> i32;
    
    
    
}
pub use crate::src::tree::xmlGetNsProp;
pub use crate::src::tree::xmlSearchNs;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::dict::_xmlDict;
pub use crate::src::globals::xmlFree;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
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
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlNsPtr = crate::src::HTMLtree::xmlNsPtr;
pub type xlinkHRef = *mut xmlChar;
pub type xlinkRole = *mut xmlChar;
pub type xlinkTitle = *mut xmlChar;
pub type xlinkType = u32;
pub const XLINK_TYPE_EXTENDED_SET: xlinkType = 3;
pub const XLINK_TYPE_EXTENDED: xlinkType = 2;
pub const XLINK_TYPE_SIMPLE: xlinkType = 1;
pub const XLINK_TYPE_NONE: xlinkType = 0;
pub type xlinkShow = u32;
pub const XLINK_SHOW_REPLACE: xlinkShow = 3;
pub const XLINK_SHOW_EMBED: xlinkShow = 2;
pub const XLINK_SHOW_NEW: xlinkShow = 1;
pub const XLINK_SHOW_NONE: xlinkShow = 0;
pub type xlinkActuate = u32;
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
        i32,
        *const xlinkHRef,
        *const xlinkRole,
        i32,
        *const xlinkRole,
        *const xlinkRole,
        *mut xlinkShow,
        *mut xlinkActuate,
        i32,
        *const xlinkTitle,
        *mut *const xmlChar,
    ) -> (),
>;
pub type xlinkExtendedLinkSetFunk = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        xmlNodePtr,
        i32,
        *const xlinkHRef,
        *const xlinkRole,
        i32,
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
        && (*doc).type_0 as u32
            == XML_HTML_DOCUMENT_NODE as i32 as u32)
    {
        !((*node).ns).is_null()
            && xmlStrEqual(
                (*(*node).ns).href,
                b"http://www.w3.org/1999/xhtml/\0" as *const u8 as *const i8
                    as *mut xmlChar,
            ) != 0;
    }
    type_0 = xmlGetNsProp(
        node as *const xmlNode,
        b"type\0" as *const u8 as *const i8 as *mut xmlChar,
        b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8 as *const i8
            as *mut xmlChar,
    );
    if !type_0.is_null() {
        if xmlStrEqual(
            type_0,
            b"simple\0" as *const u8 as *const i8 as *mut xmlChar,
        ) != 0
        {
            ret = XLINK_TYPE_SIMPLE;
        } else if xmlStrEqual(
                type_0,
                b"extended\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
            role = xmlGetNsProp(
                node as *const xmlNode,
                b"role\0" as *const u8 as *const i8 as *mut xmlChar,
                b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8
                    as *const i8 as *mut xmlChar,
            );
            if !role.is_null() {
                let mut xlink: xmlNsPtr = 0 as *mut xmlNs;
                xlink = xmlSearchNs(
                    doc,
                    node,
                    b"http://www.w3.org/1999/xlink/namespace/\0" as *const u8
                        as *const i8 as *mut xmlChar,
                );
                if xlink.is_null() {
                    if xmlStrEqual(
                        role,
                        b"xlink:external-linkset\0" as *const u8 as *const i8
                            as *mut xmlChar,
                    ) != 0
                    {
                        ret = XLINK_TYPE_EXTENDED_SET;
                    }
                } else {
                    let mut buf: [xmlChar; 200] = [0; 200];
                    snprintf(
                        buf.as_mut_ptr() as *mut i8,
                        ::std::mem::size_of::<[xmlChar; 200]>() as u64,
                        b"%s:external-linkset\0" as *const u8 as *const i8,
                        (*xlink).prefix as *mut i8,
                    );
                    buf[(::std::mem::size_of::<[xmlChar; 200]>() as u64)
                        .wrapping_sub(1 as i32 as u64)
                        as usize] = 0 as i32 as xmlChar;
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
