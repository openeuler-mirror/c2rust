use :: libc;
extern "C" {
    static mut stdout: *mut crate::src::tree::_IO_FILE;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn fwrite(
        _: *const core::ffi::c_void,
        _: u64,
        _: u64,
        _: *mut crate::src::tree::_IO_FILE,
    ) -> u64;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memmove(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strlen(_: *const i8) -> u64;
    static mut xmlMalloc: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlMallocAtomic: Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
    static mut xmlRealloc:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    static mut xmlMemStrdup: Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>;
    fn __xmlBufferAllocScheme() -> *mut u32;
    fn __xmlDefaultBufferSize() -> *mut i32;
    fn __xmlRegisterNodeDefaultValue(
    ) -> *mut Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
    fn xmlDictFree(dict: *mut crate::src::xpointer::_xmlDict);
    fn xmlDictLookup(
        dict: *mut crate::src::xpointer::_xmlDict,
        name: *const u8,
        len: i32,
    ) -> *const u8;
    fn xmlDictOwns(dict: *mut crate::src::xpointer::_xmlDict, str: *const u8) -> i32;
    fn __xmlSimpleError(
        domain: i32,
        code: i32,
        node: *mut crate::src::threads::_xmlNode,
        msg: *const i8,
        extra: *const i8,
    );
    fn xmlFreeEntitiesTable(table: *mut crate::src::xmlsave::_xmlHashTable);
    fn __xmlDeregisterNodeDefaultValue(
    ) -> *mut Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
    fn xmlHashRemoveEntry(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
        f: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    ) -> i32;
    fn xmlHashLookup(
        table: *mut crate::src::xmlsave::_xmlHashTable,
        name: *const u8,
    ) -> *mut core::ffi::c_void;
    fn xmlGetDocEntity(
        doc: *const crate::src::threads::_xmlDoc,
        name: *const u8,
    ) -> *mut crate::src::threads::_xmlEntity;
    fn xmlEncodeEntitiesReentrant(
        doc: *mut crate::src::threads::_xmlDoc,
        input: *const u8,
    ) -> *mut u8;
    fn xmlCopyEntitiesTable(
        table: *mut crate::src::xmlsave::_xmlHashTable,
    ) -> *mut crate::src::xmlsave::_xmlHashTable;
    fn xmlEncodeSpecialChars(doc: *const crate::src::threads::_xmlDoc, input: *const u8)
        -> *mut u8;
    fn xmlStringCurrentChar(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        cur: *const u8,
        len: *mut i32,
    ) -> i32;
    fn xmlCopyCharMultiByte(out: *mut u8, val: i32) -> i32;
    static xmlIsBaseCharGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsDigitGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsCombiningGroup: crate::src::tree::_xmlChRangeGroup;
    fn xmlCharInRange(val: u32, group: *const crate::src::tree::_xmlChRangeGroup) -> i32;
    static xmlIsExtenderGroup: crate::src::tree::_xmlChRangeGroup;
    fn xmlBufCreate() -> *mut crate::src::xmlstring::_xmlBuf;
    fn xmlBufCreateSize(size: u64) -> *mut crate::src::xmlstring::_xmlBuf;
    fn xmlBufSetAllocationScheme(buf: *mut crate::src::xmlstring::_xmlBuf, scheme: u32) -> i32;
    fn xmlBufFree(buf: *mut crate::src::xmlstring::_xmlBuf);
    fn xmlBufAdd(buf: *mut crate::src::xmlstring::_xmlBuf, str: *const u8, len: i32) -> i32;
    fn xmlBufCat(buf: *mut crate::src::xmlstring::_xmlBuf, str: *const u8) -> i32;
    fn xmlBufIsEmpty(buf: *mut crate::src::xmlstring::_xmlBuf) -> i32;
    fn xmlBufDetach(buf: *mut crate::src::xmlstring::_xmlBuf) -> *mut u8;
    fn xmlBufFromBuffer(
        buffer: *mut crate::src::tree::_xmlBuffer,
    ) -> *mut crate::src::xmlstring::_xmlBuf;
    fn xmlBufBackToBuffer(
        buf: *mut crate::src::xmlstring::_xmlBuf,
    ) -> *mut crate::src::tree::_xmlBuffer;
    fn xmlEncodeAttributeEntities(
        doc: *mut crate::src::threads::_xmlDoc,
        input: *const u8,
    ) -> *mut u8;
}
pub use crate::src::uri::xmlBuildURI;
pub use crate::src::uri::xmlPathToURI;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::valid::xmlAddID;
pub use crate::src::valid::xmlCopyAttributeTable;
pub use crate::src::valid::xmlCopyElementTable;
pub use crate::src::valid::xmlCopyNotationTable;
pub use crate::src::valid::xmlFreeAttributeTable;
pub use crate::src::valid::xmlFreeElementTable;
pub use crate::src::valid::xmlFreeIDTable;
pub use crate::src::valid::xmlFreeNotationTable;
pub use crate::src::valid::xmlFreeRefTable;
pub use crate::src::valid::xmlGetDtdAttrDesc;
pub use crate::src::valid::xmlGetDtdQAttrDesc;
pub use crate::src::valid::xmlGetDtdQElementDesc;
pub use crate::src::valid::xmlIsID;
pub use crate::src::valid::xmlRemoveID;
pub use crate::src::xmllint::_IO_marker;
pub use crate::src::xmlmemory::_IO_wide_data;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::xmlsave::_IO_codecvt;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xmlstring::_xmlStartTag;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrcasecmp;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrchr;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrncat;
pub use crate::src::xmlstring::xmlStrncatNew;
pub use crate::src::xmlstring::xmlStrncmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut crate::src::xmllint::_IO_marker,
    pub _chain: *mut crate::src::tree::_IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: i64,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut core::ffi::c_void,
    pub _offset: i64,
    pub _codecvt: *mut crate::src::xmlsave::_IO_codecvt,
    pub _wide_data: *mut crate::src::xmlmemory::_IO_wide_data,
    pub _freeres_list: *mut crate::src::tree::_IO_FILE,
    pub _freeres_buf: *mut core::ffi::c_void,
    pub __pad5: u64,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
impl _IO_FILE {
    pub const fn new() -> Self {
        _IO_FILE {
            _flags: 0,
            _IO_read_ptr: (0 as *mut i8),
            _IO_read_end: (0 as *mut i8),
            _IO_read_base: (0 as *mut i8),
            _IO_write_base: (0 as *mut i8),
            _IO_write_ptr: (0 as *mut i8),
            _IO_write_end: (0 as *mut i8),
            _IO_buf_base: (0 as *mut i8),
            _IO_buf_end: (0 as *mut i8),
            _IO_save_base: (0 as *mut i8),
            _IO_backup_base: (0 as *mut i8),
            _IO_save_end: (0 as *mut i8),
            _markers: (0 as *mut crate::src::xmllint::_IO_marker),
            _chain: (0 as *mut crate::src::tree::_IO_FILE),
            _fileno: 0,
            _flags2: 0,
            _old_offset: 0,
            _cur_column: 0,
            _vtable_offset: 0,
            _shortbuf: [0],
            _lock: (0 as *mut core::ffi::c_void),
            _offset: 0,
            _codecvt: (0 as *mut crate::src::xmlsave::_IO_codecvt),
            _wide_data: (0 as *mut crate::src::xmlmemory::_IO_wide_data),
            _freeres_list: (0 as *mut crate::src::tree::_IO_FILE),
            _freeres_buf: (0 as *mut core::ffi::c_void),
            __pad5: 0,
            _mode: 0,
            _unused2: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }
}
impl std::default::Default for _IO_FILE {
    fn default() -> Self {
        _IO_FILE::new()
    }
}
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
pub type ptrdiff_t = i64;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C" fn(_: u64) -> *mut core::ffi::c_void>;
pub type xmlReallocFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: u64) -> *mut core::ffi::c_void>;
pub type xmlStrdupFunc = Option<unsafe extern "C" fn(_: *const i8) -> *mut i8>;
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
pub type xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut crate::src::threads::_xmlParserInputBuffer;
pub type _xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputPtr = *mut crate::src::threads::_xmlParserInput;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserCtxt {
    pub sax: *mut crate::src::tree::_xmlSAXHandler,
    pub userData: *mut core::ffi::c_void,
    pub myDoc: *mut crate::src::threads::_xmlDoc,
    pub wellFormed: i32,
    pub replaceEntities: i32,
    pub version: *const u8,
    pub encoding: *const u8,
    pub standalone: i32,
    pub html: i32,
    pub input: *mut crate::src::threads::_xmlParserInput,
    pub inputNr: i32,
    pub inputMax: i32,
    pub inputTab: *mut *mut crate::src::threads::_xmlParserInput,
    pub node: *mut crate::src::threads::_xmlNode,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut *mut crate::src::threads::_xmlNode,
    pub record_info: i32,
    pub node_seq: crate::src::tree::_xmlParserNodeInfoSeq,
    pub errNo: i32,
    pub hasExternalSubset: i32,
    pub hasPErefs: i32,
    pub external: i32,
    pub valid: i32,
    pub validate: i32,
    pub vctxt: crate::src::tree::_xmlValidCtxt,
    pub instate: i32,
    pub token: i32,
    pub directory: *mut i8,
    pub name: *const u8,
    pub nameNr: i32,
    pub nameMax: i32,
    pub nameTab: *mut *const u8,
    pub nbChars: i64,
    pub checkIndex: i64,
    pub keepBlanks: i32,
    pub disableSAX: i32,
    pub inSubset: i32,
    pub intSubName: *const u8,
    pub extSubURI: *mut u8,
    pub extSubSystem: *mut u8,
    pub space: *mut i32,
    pub spaceNr: i32,
    pub spaceMax: i32,
    pub spaceTab: *mut i32,
    pub depth: i32,
    pub entity: *mut crate::src::threads::_xmlParserInput,
    pub charset: i32,
    pub nodelen: i32,
    pub nodemem: i32,
    pub pedantic: i32,
    pub _private: *mut core::ffi::c_void,
    pub loadsubset: i32,
    pub linenumbers: i32,
    pub catalogs: *mut core::ffi::c_void,
    pub recovery: i32,
    pub progressive: i32,
    pub dict: *mut crate::src::xpointer::_xmlDict,
    pub atts: *mut *const u8,
    pub maxatts: i32,
    pub docdict: i32,
    pub str_xml: *const u8,
    pub str_xmlns: *const u8,
    pub str_xml_ns: *const u8,
    pub sax2: i32,
    pub nsNr: i32,
    pub nsMax: i32,
    pub nsTab: *mut *const u8,
    pub attallocs: *mut i32,
    pub pushTab: *mut crate::src::xmlstring::_xmlStartTag,
    pub attsDefault: *mut crate::src::xmlsave::_xmlHashTable,
    pub attsSpecial: *mut crate::src::xmlsave::_xmlHashTable,
    pub nsWellFormed: i32,
    pub options: i32,
    pub dictNames: i32,
    pub freeElemsNr: i32,
    pub freeElems: *mut crate::src::threads::_xmlNode,
    pub freeAttrsNr: i32,
    pub freeAttrs: *mut crate::src::threads::_xmlAttr,
    pub lastError: crate::src::threads::_xmlError,
    pub parseMode: u32,
    pub nbentities: u64,
    pub sizeentities: u64,
    pub nodeInfo: *mut crate::src::tree::_xmlParserNodeInfo,
    pub nodeInfoNr: i32,
    pub nodeInfoMax: i32,
    pub nodeInfoTab: *mut crate::src::tree::_xmlParserNodeInfo,
    pub input_id: i32,
    pub sizeentcopy: u64,
}
impl _xmlParserCtxt {
    pub const fn new() -> Self {
        _xmlParserCtxt {
            sax: (0 as *mut crate::src::tree::_xmlSAXHandler),
            userData: (0 as *mut core::ffi::c_void),
            myDoc: (0 as *mut crate::src::threads::_xmlDoc),
            wellFormed: 0,
            replaceEntities: 0,
            version: (0 as *const u8),
            encoding: (0 as *const u8),
            standalone: 0,
            html: 0,
            input: (0 as *mut crate::src::threads::_xmlParserInput),
            inputNr: 0,
            inputMax: 0,
            inputTab: (0 as *mut *mut crate::src::threads::_xmlParserInput),
            node: (0 as *mut crate::src::threads::_xmlNode),
            nodeNr: 0,
            nodeMax: 0,
            nodeTab: (0 as *mut *mut crate::src::threads::_xmlNode),
            record_info: 0,
            node_seq: crate::src::tree::_xmlParserNodeInfoSeq::new(),
            errNo: 0,
            hasExternalSubset: 0,
            hasPErefs: 0,
            external: 0,
            valid: 0,
            validate: 0,
            vctxt: crate::src::tree::_xmlValidCtxt::new(),
            instate: 0,
            token: 0,
            directory: (0 as *mut i8),
            name: (0 as *const u8),
            nameNr: 0,
            nameMax: 0,
            nameTab: (0 as *mut *const u8),
            nbChars: 0,
            checkIndex: 0,
            keepBlanks: 0,
            disableSAX: 0,
            inSubset: 0,
            intSubName: (0 as *const u8),
            extSubURI: (0 as *mut u8),
            extSubSystem: (0 as *mut u8),
            space: (0 as *mut i32),
            spaceNr: 0,
            spaceMax: 0,
            spaceTab: (0 as *mut i32),
            depth: 0,
            entity: (0 as *mut crate::src::threads::_xmlParserInput),
            charset: 0,
            nodelen: 0,
            nodemem: 0,
            pedantic: 0,
            _private: (0 as *mut core::ffi::c_void),
            loadsubset: 0,
            linenumbers: 0,
            catalogs: (0 as *mut core::ffi::c_void),
            recovery: 0,
            progressive: 0,
            dict: (0 as *mut crate::src::xpointer::_xmlDict),
            atts: (0 as *mut *const u8),
            maxatts: 0,
            docdict: 0,
            str_xml: (0 as *const u8),
            str_xmlns: (0 as *const u8),
            str_xml_ns: (0 as *const u8),
            sax2: 0,
            nsNr: 0,
            nsMax: 0,
            nsTab: (0 as *mut *const u8),
            attallocs: (0 as *mut i32),
            pushTab: (0 as *mut crate::src::xmlstring::_xmlStartTag),
            attsDefault: (0 as *mut crate::src::xmlsave::_xmlHashTable),
            attsSpecial: (0 as *mut crate::src::xmlsave::_xmlHashTable),
            nsWellFormed: 0,
            options: 0,
            dictNames: 0,
            freeElemsNr: 0,
            freeElems: (0 as *mut crate::src::threads::_xmlNode),
            freeAttrsNr: 0,
            freeAttrs: (0 as *mut crate::src::threads::_xmlAttr),
            lastError: crate::src::threads::_xmlError::new(),
            parseMode: 0,
            nbentities: 0,
            sizeentities: 0,
            nodeInfo: (0 as *mut crate::src::tree::_xmlParserNodeInfo),
            nodeInfoNr: 0,
            nodeInfoMax: 0,
            nodeInfoTab: (0 as *mut crate::src::tree::_xmlParserNodeInfo),
            input_id: 0,
            sizeentcopy: 0,
        }
    }
}
impl std::default::Default for _xmlParserCtxt {
    fn default() -> Self {
        _xmlParserCtxt::new()
    }
}
pub type xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfo {
    pub node: *const crate::src::threads::_xmlNode,
    pub begin_pos: u64,
    pub begin_line: u64,
    pub end_pos: u64,
    pub end_line: u64,
}
impl _xmlParserNodeInfo {
    pub const fn new() -> Self {
        _xmlParserNodeInfo {
            node: (0 as *const crate::src::threads::_xmlNode),
            begin_pos: 0,
            begin_line: 0,
            end_pos: 0,
            end_line: 0,
        }
    }
}
impl std::default::Default for _xmlParserNodeInfo {
    fn default() -> Self {
        _xmlParserNodeInfo::new()
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidCtxt {
    pub userData: *mut core::ffi::c_void,
    pub error: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub warning: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub node: *mut crate::src::threads::_xmlNode,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut *mut crate::src::threads::_xmlNode,
    pub flags: u32,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub valid: i32,
    pub vstate: *mut crate::src::valid::_xmlValidState,
    pub vstateNr: i32,
    pub vstateMax: i32,
    pub vstateTab: *mut crate::src::valid::_xmlValidState,
    pub am: *mut crate::src::xmlregexp::_xmlAutomata,
    pub state: *mut crate::src::xmlregexp::_xmlAutomataState,
}
impl _xmlValidCtxt {
    pub const fn new() -> Self {
        _xmlValidCtxt {
            userData: (0 as *mut core::ffi::c_void),
            error: None,
            warning: None,
            node: (0 as *mut crate::src::threads::_xmlNode),
            nodeNr: 0,
            nodeMax: 0,
            nodeTab: (0 as *mut *mut crate::src::threads::_xmlNode),
            flags: 0,
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            valid: 0,
            vstate: (0 as *mut crate::src::valid::_xmlValidState),
            vstateNr: 0,
            vstateMax: 0,
            vstateTab: (0 as *mut crate::src::valid::_xmlValidState),
            am: (0 as *mut crate::src::xmlregexp::_xmlAutomata),
            state: (0 as *mut crate::src::xmlregexp::_xmlAutomataState),
        }
    }
}
impl std::default::Default for _xmlValidCtxt {
    fn default() -> Self {
        _xmlValidCtxt::new()
    }
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfoSeq {
    pub maximum: u64,
    pub length: u64,
    pub buffer: *mut crate::src::tree::_xmlParserNodeInfo,
}
impl _xmlParserNodeInfoSeq {
    pub const fn new() -> Self {
        _xmlParserNodeInfoSeq {
            maximum: 0,
            length: 0,
            buffer: (0 as *mut crate::src::tree::_xmlParserNodeInfo),
        }
    }
}
impl std::default::Default for _xmlParserNodeInfoSeq {
    fn default() -> Self {
        _xmlParserNodeInfoSeq::new()
    }
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandler {
    pub internalSubset: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub isStandalone: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub hasInternalSubset: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub hasExternalSubset: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
    pub resolveEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlParserInput,
    >,
    pub getEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlEntity,
    >,
    pub entityDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: i32,
            _: *const u8,
            _: *const u8,
            _: *mut u8,
        ) -> (),
    >,
    pub notationDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub attributeDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: i32,
            _: i32,
            _: *const u8,
            _: *mut crate::src::threads::_xmlEnumeration,
        ) -> (),
    >,
    pub elementDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: i32,
            _: *mut crate::src::threads::_xmlElementContent,
        ) -> (),
    >,
    pub unparsedEntityDecl: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub setDocumentLocator: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlSAXLocator,
        ) -> (),
    >,
    pub startDocument: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    pub endDocument: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>,
    pub startElement: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *mut *const u8) -> (),
    >,
    pub endElement: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub reference: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub characters:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub ignorableWhitespace:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub processingInstruction:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: *const u8) -> ()>,
    pub comment: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>,
    pub warning: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub error: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub fatalError:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
    pub getParameterEntity: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlEntity,
    >,
    pub cdataBlock:
        Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8, _: i32) -> ()>,
    pub externalSubset: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub initialized: u32,
    pub _private: *mut core::ffi::c_void,
    pub startElementNs: Option<
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
    >,
    pub endElementNs: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *const u8,
            _: *const u8,
            _: *const u8,
        ) -> (),
    >,
    pub serror: Option<
        unsafe extern "C" fn(
            _: *mut core::ffi::c_void,
            _: *mut crate::src::threads::_xmlError,
        ) -> (),
    >,
}
impl _xmlSAXHandler {
    pub const fn new() -> Self {
        _xmlSAXHandler {
            internalSubset: None,
            isStandalone: None,
            hasInternalSubset: None,
            hasExternalSubset: None,
            resolveEntity: None,
            getEntity: None,
            entityDecl: None,
            notationDecl: None,
            attributeDecl: None,
            elementDecl: None,
            unparsedEntityDecl: None,
            setDocumentLocator: None,
            startDocument: None,
            endDocument: None,
            startElement: None,
            endElement: None,
            reference: None,
            characters: None,
            ignorableWhitespace: None,
            processingInstruction: None,
            comment: None,
            warning: None,
            error: None,
            fatalError: None,
            getParameterEntity: None,
            cdataBlock: None,
            externalSubset: None,
            initialized: 0,
            _private: (0 as *mut core::ffi::c_void),
            startElementNs: None,
            endElementNs: None,
            serror: None,
        }
    }
}
impl std::default::Default for _xmlSAXHandler {
    fn default() -> Self {
        _xmlSAXHandler::new()
    }
}
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
pub type xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut crate::src::tree::_xmlParserCtxt;
pub type xmlBufferAllocationScheme = u32;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlBuffer {
    pub content: *mut u8,
    pub use_0: u32,
    pub size: u32,
    pub alloc: u32,
    pub contentIO: *mut u8,
}
impl _xmlBuffer {
    pub const fn new() -> Self {
        _xmlBuffer {
            content: (0 as *mut u8),
            use_0: 0,
            size: 0,
            alloc: 0,
            contentIO: (0 as *mut u8),
        }
    }
}
impl std::default::Default for _xmlBuffer {
    fn default() -> Self {
        _xmlBuffer::new()
    }
}
pub type xmlBuffer = crate::src::tree::_xmlBuffer;
pub type xmlBufferPtr = *mut crate::src::tree::_xmlBuffer;
pub type xmlAttributeDefault = u32;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttribute {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlDtd,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub nexth: *mut crate::src::tree::_xmlAttribute,
    pub atype: u32,
    pub def: u32,
    pub defaultValue: *const u8,
    pub tree: *mut crate::src::threads::_xmlEnumeration,
    pub prefix: *const u8,
    pub elem: *const u8,
}
impl _xmlAttribute {
    pub const fn new() -> Self {
        _xmlAttribute {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlDtd),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            nexth: (0 as *mut crate::src::tree::_xmlAttribute),
            atype: 0,
            def: 0,
            defaultValue: (0 as *const u8),
            tree: (0 as *mut crate::src::threads::_xmlEnumeration),
            prefix: (0 as *const u8),
            elem: (0 as *const u8),
        }
    }
}
impl std::default::Default for _xmlAttribute {
    fn default() -> Self {
        _xmlAttribute::new()
    }
}
pub type xmlAttribute = crate::src::tree::_xmlAttribute;
pub type xmlAttributePtr = *mut crate::src::tree::_xmlAttribute;
pub type xmlElementTypeVal = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = crate::src::xmlregexp::_xmlRegexp;
pub type xmlRegexpPtr = *mut crate::src::xmlregexp::_xmlRegexp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElement {
    pub _private: *mut core::ffi::c_void,
    pub type_0: u32,
    pub name: *const u8,
    pub children: *mut crate::src::threads::_xmlNode,
    pub last: *mut crate::src::threads::_xmlNode,
    pub parent: *mut crate::src::threads::_xmlDtd,
    pub next: *mut crate::src::threads::_xmlNode,
    pub prev: *mut crate::src::threads::_xmlNode,
    pub doc: *mut crate::src::threads::_xmlDoc,
    pub etype: u32,
    pub content: *mut crate::src::threads::_xmlElementContent,
    pub attributes: *mut crate::src::tree::_xmlAttribute,
    pub prefix: *const u8,
    pub contModel: *mut crate::src::xmlregexp::_xmlRegexp,
}
impl _xmlElement {
    pub const fn new() -> Self {
        _xmlElement {
            _private: (0 as *mut core::ffi::c_void),
            type_0: 0,
            name: (0 as *const u8),
            children: (0 as *mut crate::src::threads::_xmlNode),
            last: (0 as *mut crate::src::threads::_xmlNode),
            parent: (0 as *mut crate::src::threads::_xmlDtd),
            next: (0 as *mut crate::src::threads::_xmlNode),
            prev: (0 as *mut crate::src::threads::_xmlNode),
            doc: (0 as *mut crate::src::threads::_xmlDoc),
            etype: 0,
            content: (0 as *mut crate::src::threads::_xmlElementContent),
            attributes: (0 as *mut crate::src::tree::_xmlAttribute),
            prefix: (0 as *const u8),
            contModel: (0 as *mut crate::src::xmlregexp::_xmlRegexp),
        }
    }
}
impl std::default::Default for _xmlElement {
    fn default() -> Self {
        _xmlElement::new()
    }
}
pub type xmlElement = crate::src::tree::_xmlElement;
pub type xmlElementPtr = *mut crate::src::tree::_xmlElement;
pub type xmlNsPtr = *mut crate::src::threads::_xmlNs;
pub type xmlDtd = crate::src::threads::_xmlDtd;
pub type xmlDtdPtr = *mut crate::src::threads::_xmlDtd;
#[repr(C)]
pub struct _xmlID<'a> {
    pub next: Option<&'a mut crate::src::tree::_xmlID<'a>>,
    pub value: *const u8,
    pub attr: *mut crate::src::threads::_xmlAttr,
    pub name: *const u8,
    pub lineno: i32,
    pub doc: *mut crate::src::threads::_xmlDoc,
}
impl<'a> _xmlID<'a> {
    pub const fn new() -> Self {
        _xmlID {
            next: None,
            value: (0 as *const u8),
            attr: (0 as *mut crate::src::threads::_xmlAttr),
            name: (0 as *const u8),
            lineno: 0,
            doc: (0 as *mut crate::src::threads::_xmlDoc),
        }
    }
}
impl<'a> std::default::Default for _xmlID<'a> {
    fn default() -> Self {
        _xmlID::new()
    }
}
pub type xmlID<'a> = crate::src::tree::_xmlID<'a>;
pub type xmlIDPtr<'a> = *mut crate::src::tree::_xmlID<'a>;
pub type C2RustUnnamed = u32;
pub const XML_DOC_HTML: C2RustUnnamed = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed = 8;
pub const XML_DOC_OLD10: C2RustUnnamed = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed = 1;
#[repr(C)]
pub struct _xmlDOMWrapCtxt<'a> {
    pub _private: Option<&'a mut core::ffi::c_void>,
    pub type_0: i32,
    pub namespaceMap: *mut core::ffi::c_void,
    pub getNsForNodeFunc: Option<
        unsafe extern "C" fn(
            _: *mut crate::src::tree::_xmlDOMWrapCtxt<'a>,
            _: *mut crate::src::threads::_xmlNode,
            _: *const u8,
            _: *const u8,
        ) -> *mut crate::src::threads::_xmlNs,
    >,
}
impl<'a> _xmlDOMWrapCtxt<'a> {
    pub const fn new() -> Self {
        _xmlDOMWrapCtxt {
            _private: None,
            type_0: 0,
            namespaceMap: (0 as *mut core::ffi::c_void),
            getNsForNodeFunc: None,
        }
    }
}
impl<'a> std::default::Default for _xmlDOMWrapCtxt<'a> {
    fn default() -> Self {
        _xmlDOMWrapCtxt::new()
    }
}
pub type xmlDOMWrapAcquireNsFunction = Option<
    unsafe extern "C" fn(
        _: *mut crate::src::tree::_xmlDOMWrapCtxt,
        _: *mut crate::src::threads::_xmlNode,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::threads::_xmlNs,
>;
pub type xmlDOMWrapCtxtPtr<'a> = *mut crate::src::tree::_xmlDOMWrapCtxt<'a>;
pub type xmlDOMWrapCtxt<'a> = crate::src::tree::_xmlDOMWrapCtxt<'a>;
pub type xmlChRangeGroup = crate::src::tree::_xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: i32,
    pub nbLongRange: i32,
    pub shortRange: *const crate::src::tree::_xmlChSRange,
    pub longRange: *const crate::src::tree::_xmlChLRange,
}
impl _xmlChRangeGroup {
    pub const fn new() -> Self {
        _xmlChRangeGroup {
            nbShortRange: 0,
            nbLongRange: 0,
            shortRange: (0 as *const crate::src::tree::_xmlChSRange),
            longRange: (0 as *const crate::src::tree::_xmlChLRange),
        }
    }
}
impl std::default::Default for _xmlChRangeGroup {
    fn default() -> Self {
        _xmlChRangeGroup::new()
    }
}
pub type xmlChLRange = crate::src::tree::_xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: u32,
    pub high: u32,
}
impl _xmlChLRange {
    pub const fn new() -> Self {
        _xmlChLRange { low: 0, high: 0 }
    }
}
impl std::default::Default for _xmlChLRange {
    fn default() -> Self {
        _xmlChLRange::new()
    }
}
pub type xmlChSRange = crate::src::tree::_xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: u16,
    pub high: u16,
}
impl _xmlChSRange {
    pub const fn new() -> Self {
        _xmlChSRange { low: 0, high: 0 }
    }
}
impl std::default::Default for _xmlChSRange {
    fn default() -> Self {
        _xmlChSRange::new()
    }
}
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_1 = 2;
pub const XML_FROM_TREE: C2RustUnnamed_0 = 2;
pub type xmlRegisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
pub type xmlEntitiesTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlEntitiesTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlAttributeTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlAttributeTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlElementTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlElementTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlNotationTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlNotationTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlDeregisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
pub type xmlHashDeallocator =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const u8) -> ()>;
pub type xmlRefTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlRefTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlIDTablePtr = *mut crate::src::xmlsave::_xmlHashTable;
pub type xmlIDTable = crate::src::xmlsave::_xmlHashTable;
pub const XML_CHAR_ENCODING_UTF8: C2RustUnnamed_2 = 1;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_1 = 1302;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_1 = 1303;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_1 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_1 = 1300;
pub type xmlValidCtxtPtr = *mut crate::src::tree::_xmlValidCtxt;
pub type xmlNsMapPtr = *mut crate::src::tree::xmlNsMap;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlNsMap {
    pub first: *mut crate::src::tree::xmlNsMapItem,
    pub last: *mut crate::src::tree::xmlNsMapItem,
    pub pool: *mut crate::src::tree::xmlNsMapItem,
}
impl xmlNsMap {
    pub const fn new() -> Self {
        xmlNsMap {
            first: (0 as *mut crate::src::tree::xmlNsMapItem),
            last: (0 as *mut crate::src::tree::xmlNsMapItem),
            pool: (0 as *mut crate::src::tree::xmlNsMapItem),
        }
    }
}
impl std::default::Default for xmlNsMap {
    fn default() -> Self {
        xmlNsMap::new()
    }
}
pub type xmlNsMapItemPtr = *mut crate::src::tree::xmlNsMapItem;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlNsMapItem {
    pub next: *mut crate::src::tree::xmlNsMapItem,
    pub prev: *mut crate::src::tree::xmlNsMapItem,
    pub oldNs: *mut crate::src::threads::_xmlNs,
    pub newNs: *mut crate::src::threads::_xmlNs,
    pub shadowDepth: i32,
    pub depth: i32,
}
impl xmlNsMapItem {
    pub const fn new() -> Self {
        xmlNsMapItem {
            next: (0 as *mut crate::src::tree::xmlNsMapItem),
            prev: (0 as *mut crate::src::tree::xmlNsMapItem),
            oldNs: (0 as *mut crate::src::threads::_xmlNs),
            newNs: (0 as *mut crate::src::threads::_xmlNs),
            shadowDepth: 0,
            depth: 0,
        }
    }
}
impl std::default::Default for xmlNsMapItem {
    fn default() -> Self {
        xmlNsMapItem::new()
    }
}
pub const XML_DOM_RECONNS_REMOVEREDUND: xmlDOMReconcileNSOptions = 1;
pub type xmlDOMReconcileNSOptions = u32;
pub type C2RustUnnamed_0 = u32;
pub const XML_FROM_URI: C2RustUnnamed_0 = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed_0 = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed_0 = 28;
pub const XML_FROM_I18N: C2RustUnnamed_0 = 27;
pub const XML_FROM_MODULE: C2RustUnnamed_0 = 26;
pub const XML_FROM_WRITER: C2RustUnnamed_0 = 25;
pub const XML_FROM_CHECK: C2RustUnnamed_0 = 24;
pub const XML_FROM_VALID: C2RustUnnamed_0 = 23;
pub const XML_FROM_XSLT: C2RustUnnamed_0 = 22;
pub const XML_FROM_C14N: C2RustUnnamed_0 = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed_0 = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed_0 = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed_0 = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed_0 = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed_0 = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed_0 = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed_0 = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed_0 = 13;
pub const XML_FROM_XPATH: C2RustUnnamed_0 = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed_0 = 11;
pub const XML_FROM_HTTP: C2RustUnnamed_0 = 10;
pub const XML_FROM_FTP: C2RustUnnamed_0 = 9;
pub const XML_FROM_IO: C2RustUnnamed_0 = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed_0 = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed_0 = 6;
pub const XML_FROM_HTML: C2RustUnnamed_0 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_0 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_0 = 3;
pub const XML_FROM_PARSER: C2RustUnnamed_0 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_0 = 0;
pub type C2RustUnnamed_1 = u32;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_1 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_1 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_1 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_1 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_1 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_1 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_1 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_1 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_1 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_1 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_1 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_1 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_1 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_1 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_1 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_1 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_1 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_1 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_1 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_1 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_1 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_1 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_1 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_1 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_1 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_1 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_1 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_1 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_1 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_1 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_1 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_1 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_1 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_1 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_1 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_1 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_1 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_1 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_1 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_1 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_1 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_1 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_1 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_1 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_1 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_1 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_1 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_1 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_1 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_1 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_1 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_1 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_1 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_1 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_1 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_1 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_1 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_1 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_1 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_1 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_1 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_1 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_1 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_1 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_1 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_1 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_1 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_1 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_1 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_1 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_1 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_1 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_1 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_1 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_1 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_1 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_1 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_1 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_1 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_1 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_1 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_1 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_1 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_1 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_1 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_1 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_1 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_1 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_1 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_1 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_1 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_1 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_1 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_1 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_1 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_1 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_1 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_1 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_1 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_1 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_1 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_1 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_1 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_1 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_1 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_1 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_1 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_1 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_1 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_1 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_1 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_1 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_1 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_1 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_1 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_1 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_1 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_1 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_1 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_1 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_1 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_1 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_1 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_1 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_1 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_1 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_1 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_1 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_1 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_1 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_1 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_1 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_1 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_1 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_1 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_1 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_1 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_1 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_1 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_1 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_1 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_1 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_1 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_1 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_1 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_1 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_1 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_1 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_1 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_1 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_1 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_1 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_1 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_1 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_1 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_1 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_1 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_1 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_1 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_1 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_1 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_1 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_1 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_1 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_1 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_1 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_1 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_1 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_1 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_1 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_1 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_1 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_1 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_1 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_1 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_1 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_1 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_1 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_1 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_1 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_1 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_1 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_1 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_1 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_1 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_1 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_1 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_1 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_1 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_1 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_1 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_1 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_1 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_1 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_1 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_1 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_1 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_1 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_1 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_1 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_1 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_1 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_1 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_1 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_1 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_1 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_1 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_1 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_1 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_1 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_1 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_1 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_1 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_1 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_1 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_1 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_1 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_1 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_1 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_1 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_1 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_1 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_1 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_1 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_1 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_1 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_1 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_1 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_1 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_1 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_1 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_1 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_1 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_1 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_1 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_1 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_1 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_1 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_1 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_1 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_1 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_1 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_1 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_1 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_1 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_1 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_1 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_1 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_1 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_1 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_1 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_1 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_1 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_1 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_1 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_1 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_1 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_1 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_1 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_1 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_1 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_1 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_1 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_1 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_1 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_1 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_1 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_1 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_1 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_1 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_1 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_1 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_1 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_1 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_1 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_1 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_1 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_1 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_1 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_1 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_1 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_1 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_1 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_1 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_1 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_1 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_1 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_1 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_1 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_1 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_1 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_1 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_1 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_1 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_1 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_1 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_1 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_1 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_1 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_1 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_1 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_1 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_1 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_1 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_1 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_1 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_1 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_1 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_1 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_1 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_1 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_1 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_1 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_1 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_1 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_1 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_1 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_1 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_1 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_1 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_1 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_1 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_1 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_1 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_1 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_1 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_1 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_1 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_1 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_1 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_1 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_1 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_1 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_1 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_1 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_1 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_1 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_1 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_1 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_1 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_1 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_1 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_1 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_1 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_1 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_1 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_1 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_1 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_1 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_1 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_1 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_1 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_1 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_1 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_1 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_1 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_1 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_1 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_1 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_1 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_1 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_1 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_1 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_1 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_1 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_1 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_1 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_1 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_1 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_1 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_1 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_1 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_1 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_1 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_1 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_1 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_1 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_1 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_1 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_1 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_1 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_1 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_1 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_1 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_1 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_1 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_1 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_1 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_1 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_1 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_1 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_1 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_1 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_1 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_1 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_1 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_1 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_1 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_1 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_1 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_1 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_1 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_1 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_1 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_1 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_1 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_1 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_1 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_1 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_1 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_1 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_1 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_1 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_1 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_1 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_1 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_1 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_1 = 1500;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_1 = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_1 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_1 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_1 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_1 = 1400;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_1 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_1 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_1 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_1 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_1 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_1 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_1 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_1 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_1 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_1 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_1 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_1 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_1 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_1 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_1 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_1 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_1 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_1 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_1 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_1 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_1 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_1 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_1 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_1 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_1 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_1 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_1 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_1 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_1 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_1 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_1 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_1 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_1 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_1 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_1 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_1 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_1 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_1 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_1 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_1 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_1 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_1 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_1 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_1 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_1 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_1 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_1 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_1 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_1 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_1 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_1 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_1 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_1 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_1 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_1 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_1 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_1 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_1 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_1 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_1 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_1 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_1 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_1 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_1 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_1 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_1 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_1 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_1 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_1 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_1 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_1 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_1 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_1 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_1 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_1 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_1 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_1 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_1 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_1 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_1 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_1 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_1 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_1 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_1 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_1 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_1 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_1 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_1 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_1 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_1 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_1 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_1 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_1 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_1 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_1 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_1 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_1 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_1 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_1 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_1 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_1 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_1 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_1 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_1 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_1 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_1 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_1 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_1 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_1 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_1 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_1 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_1 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_1 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_1 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_1 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_1 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_1 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_1 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_1 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_1 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_1 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_1 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_1 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_1 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_1 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_1 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_1 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_1 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_1 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_1 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_1 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_1 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_1 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_1 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_1 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_1 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_1 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_1 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_1 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_1 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_1 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_1 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_1 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_1 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_1 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_1 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_1 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_1 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_1 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_1 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_1 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_1 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_1 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_1 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_1 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_1 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_1 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_1 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_1 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_1 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_1 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_1 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_1 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_1 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_1 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_1 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_1 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_1 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_1 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_1 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_1 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_1 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_1 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_1 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_1 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_1 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_1 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_1 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_1 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_1 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_1 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_1 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_1 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_1 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_1 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_1 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_1 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_1 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_1 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_1 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_1 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_1 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_1 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_1 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_1 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_1 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_1 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_1 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_1 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_1 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_1 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_1 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_1 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_1 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_1 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_1 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_1 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_1 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_1 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_1 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_1 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_1 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_1 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_1 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_1 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_1 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_1 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_1 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_1 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_1 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_1 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_1 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_1 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_1 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_1 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_1 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_1 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_1 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_1 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_1 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_1 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_1 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_1 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_1 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_1 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_1 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_1 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_1 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_1 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_1 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_1 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_1 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_1 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_1 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_1 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_1 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_1 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_1 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_1 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_1 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_1 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_1 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_1 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_1 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_1 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_1 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_1 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_1 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_1 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_1 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_1 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_1 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_1 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_1 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_1 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_1 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_1 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_1 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_1 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_1 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_1 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_1 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_1 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_1 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_1 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_1 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_1 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_1 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_1 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_1 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_1 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_1 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_1 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_1 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_1 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_1 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_1 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_1 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_1 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_1 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_1 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_1 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_1 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_1 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_1 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_1 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_1 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_1 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_1 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_1 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_1 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_1 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_1 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_1 = 3;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_1 = 1;
pub const XML_ERR_OK: C2RustUnnamed_1 = 0;
pub type C2RustUnnamed_2 = i32;
pub const XML_CHAR_ENCODING_ASCII: C2RustUnnamed_2 = 22;
pub const XML_CHAR_ENCODING_EUC_JP: C2RustUnnamed_2 = 21;
pub const XML_CHAR_ENCODING_SHIFT_JIS: C2RustUnnamed_2 = 20;
pub const XML_CHAR_ENCODING_2022_JP: C2RustUnnamed_2 = 19;
pub const XML_CHAR_ENCODING_8859_9: C2RustUnnamed_2 = 18;
pub const XML_CHAR_ENCODING_8859_8: C2RustUnnamed_2 = 17;
pub const XML_CHAR_ENCODING_8859_7: C2RustUnnamed_2 = 16;
pub const XML_CHAR_ENCODING_8859_6: C2RustUnnamed_2 = 15;
pub const XML_CHAR_ENCODING_8859_5: C2RustUnnamed_2 = 14;
pub const XML_CHAR_ENCODING_8859_4: C2RustUnnamed_2 = 13;
pub const XML_CHAR_ENCODING_8859_3: C2RustUnnamed_2 = 12;
pub const XML_CHAR_ENCODING_8859_2: C2RustUnnamed_2 = 11;
pub const XML_CHAR_ENCODING_8859_1: C2RustUnnamed_2 = 10;
pub const XML_CHAR_ENCODING_UCS2: C2RustUnnamed_2 = 9;
pub const XML_CHAR_ENCODING_UCS4_3412: C2RustUnnamed_2 = 8;
pub const XML_CHAR_ENCODING_UCS4_2143: C2RustUnnamed_2 = 7;
pub const XML_CHAR_ENCODING_EBCDIC: C2RustUnnamed_2 = 6;
pub const XML_CHAR_ENCODING_UCS4BE: C2RustUnnamed_2 = 5;
pub const XML_CHAR_ENCODING_UCS4LE: C2RustUnnamed_2 = 4;
pub const XML_CHAR_ENCODING_UTF16BE: C2RustUnnamed_2 = 3;
pub const XML_CHAR_ENCODING_UTF16LE: C2RustUnnamed_2 = 2;
pub const XML_CHAR_ENCODING_NONE: C2RustUnnamed_2 = 0;
pub const XML_CHAR_ENCODING_ERROR: C2RustUnnamed_2 = -1;
#[no_mangle]
pub static mut __xmlRegisterCallbacks: i32 = 0 as i32;
extern "C" fn xmlTreeErrMemory(mut extra: *const i8) {
    (unsafe {
        __xmlSimpleError(
            XML_FROM_TREE as i32,
            XML_ERR_NO_MEMORY as i32,
            0 as xmlNodePtr,
            0 as *const i8,
            extra,
        )
    });
}
extern "C" fn xmlTreeErr(
    mut code: i32,
    mut node: *mut crate::src::threads::_xmlNode,
    mut extra: *const i8,
) {
    let mut msg: *const i8 = 0 as *const i8;
    match code {
        1300 => {
            msg = b"invalid hexadecimal character value\n\0" as *const u8 as *const i8;
        }
        1301 => {
            msg = b"invalid decimal character value\n\0" as *const u8 as *const i8;
        }
        1302 => {
            msg = b"unterminated entity reference %15s\n\0" as *const u8 as *const i8;
        }
        1303 => {
            msg = b"string is not in UTF-8\n\0" as *const u8 as *const i8;
        }
        _ => {
            msg = b"unexpected error number\n\0" as *const u8 as *const i8;
        }
    }
    (unsafe { __xmlSimpleError(XML_FROM_TREE as i32, code, node, msg, extra) });
}
#[no_mangle]
pub static mut xmlStringText: [u8; 5] = [
    't' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'x' as i32 as xmlChar,
    't' as i32 as xmlChar,
    0 as i32 as xmlChar,
];
#[no_mangle]
pub static mut xmlStringTextNoenc: [u8; 10] = [
    't' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'x' as i32 as xmlChar,
    't' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    'o' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    'c' as i32 as xmlChar,
    0 as i32 as xmlChar,
];
#[no_mangle]
pub static mut xmlStringComment: [u8; 8] = [
    'c' as i32 as xmlChar,
    'o' as i32 as xmlChar,
    'm' as i32 as xmlChar,
    'm' as i32 as xmlChar,
    'e' as i32 as xmlChar,
    'n' as i32 as xmlChar,
    't' as i32 as xmlChar,
    0 as i32 as xmlChar,
];
static mut xmlCompressMode: i32 = 0 as i32;
static mut xmlCheckDTD: i32 = 1 as i32;
extern "C" fn xmlGetEntityFromDtd(
    mut dtd: *const crate::src::threads::_xmlDtd,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlEntity {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlEntitiesTable;
    if !dtd.is_null() && !(unsafe { (*dtd).entities }).is_null() {
        table = (unsafe { (*dtd).entities }) as xmlEntitiesTablePtr;
        return (unsafe { xmlHashLookup(table, name) }) as xmlEntityPtr;
    }
    return 0 as xmlEntityPtr;
}
extern "C" fn xmlGetParameterEntityFromDtd(
    mut dtd: *const crate::src::threads::_xmlDtd,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlEntity {
    let mut table: *mut crate::src::xmlsave::_xmlHashTable = 0 as *mut xmlEntitiesTable;
    if !dtd.is_null() && !(unsafe { (*dtd).pentities }).is_null() {
        table = (unsafe { (*dtd).pentities }) as xmlEntitiesTablePtr;
        return (unsafe { xmlHashLookup(table, name) }) as xmlEntityPtr;
    }
    return 0 as xmlEntityPtr;
}
#[no_mangle]
pub extern "C" fn xmlBuildQName(
    mut ncname: *const u8,
    mut prefix: *const u8,
    mut memory: *mut u8,
    mut len: i32,
) -> *mut u8 {
    let mut lenn: i32 = 0;
    let mut lenp: i32 = 0;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if ncname.is_null() {
        return 0 as *mut xmlChar;
    }
    if prefix.is_null() {
        return ncname as *mut xmlChar;
    }
    lenn = (unsafe { strlen(ncname as *mut i8) }) as i32;
    lenp = (unsafe { strlen(prefix as *mut i8) }) as i32;
    if memory.is_null() || len < lenn + lenp + 2 as i32 {
        ret = (unsafe {
            xmlMallocAtomic.expect("non-null function pointer")((lenn + lenp + 2 as i32) as size_t)
        }) as *mut xmlChar;
        if ret.is_null() {
            xmlTreeErrMemory(b"building QName\0" as *const u8 as *const i8);
            return 0 as *mut xmlChar;
        }
    } else {
        ret = memory;
    }
    (unsafe {
        memcpy(
            &mut *ret.offset(0 as i32 as isize) as *mut xmlChar as *mut libc::c_void,
            prefix as *const libc::c_void,
            lenp as u64,
        )
    });
    (unsafe { *ret.offset(lenp as isize) = ':' as i32 as xmlChar });
    (unsafe {
        memcpy(
            &mut *ret.offset((lenp + 1 as i32) as isize) as *mut xmlChar as *mut libc::c_void,
            ncname as *const libc::c_void,
            lenn as u64,
        )
    });
    (unsafe { *ret.offset((lenn + lenp + 1 as i32) as isize) = 0 as i32 as xmlChar });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSplitQName2<'a1>(
    mut name: *const u8,
    mut prefix: Option<&'a1 mut *mut u8>,
) -> *mut u8 {
    let mut len: i32 = 0 as i32;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if borrow(&prefix).is_none() {
        return 0 as *mut xmlChar;
    }
    *(borrow_mut(&mut prefix)).unwrap() = 0 as *mut xmlChar;
    if name.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == ':' as i32 {
        return 0 as *mut xmlChar;
    }
    while (unsafe { *name.offset(len as isize) }) as i32 != 0 as i32
        && (unsafe { *name.offset(len as isize) }) as i32 != ':' as i32
    {
        len += 1;
    }
    if (unsafe { *name.offset(len as isize) }) as i32 == 0 as i32 {
        return 0 as *mut xmlChar;
    }
    *(borrow_mut(&mut prefix)).unwrap() = xmlStrndup(name, len);
    if (*(borrow_mut(&mut prefix)).unwrap()).is_null() {
        xmlTreeErrMemory(b"QName split\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    ret = xmlStrdup(unsafe { &*name.offset((len + 1 as i32) as isize) });
    if ret.is_null() {
        xmlTreeErrMemory(b"QName split\0" as *const u8 as *const i8);
        if !(*(borrow_mut(&mut prefix)).unwrap()).is_null() {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    *(borrow_mut(&mut prefix)).unwrap() as *mut libc::c_void
                )
            });
            *(borrow_mut(&mut prefix)).unwrap() = 0 as *mut xmlChar;
        }
        return 0 as *mut xmlChar;
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlSplitQName3<'a1>(
    mut name: *const u8,
    mut len: Option<&'a1 mut i32>,
) -> *const u8 {
    let mut l: i32 = 0 as i32;
    if name.is_null() {
        return 0 as *const xmlChar;
    }
    if borrow(&len).is_none() {
        return 0 as *const xmlChar;
    }
    if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == ':' as i32 {
        return 0 as *const xmlChar;
    }
    while (unsafe { *name.offset(l as isize) }) as i32 != 0 as i32
        && (unsafe { *name.offset(l as isize) }) as i32 != ':' as i32
    {
        l += 1;
    }
    if (unsafe { *name.offset(l as isize) }) as i32 == 0 as i32 {
        return 0 as *const xmlChar;
    }
    *(borrow_mut(&mut len)).unwrap() = l;
    return (unsafe { &*name.offset((l + 1 as i32) as isize) }) as *const xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlValidateNCName(mut value: *const u8, mut space: i32) -> i32 {
    let mut cur: *const u8 = value;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if value.is_null() {
        return -(1 as i32);
    }
    if space != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
    {
        cur = unsafe { cur.offset(1) };
        while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
            || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
            || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
            || (unsafe { *cur }) as i32 == '_' as i32
            || (unsafe { *cur }) as i32 == '-' as i32
            || (unsafe { *cur }) as i32 == '.' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if space != 0 {
            while (unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32
            {
                cur = unsafe { cur.offset(1) };
            }
        }
        if (unsafe { *cur }) as i32 == 0 as i32 {
            return 0 as i32;
        }
    }
    cur = value;
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0)
        && c != '_' as i32
    {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(l as isize) };
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    while (if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    }
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if c != 0 as i32 {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateQName(mut value: *const u8, mut space: i32) -> i32 {
    let mut current_block: u64;
    let mut cur: *const u8 = value;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if value.is_null() {
        return -(1 as i32);
    }
    if space != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
    {
        cur = unsafe { cur.offset(1) };
        while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
            || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
            || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
            || (unsafe { *cur }) as i32 == '_' as i32
            || (unsafe { *cur }) as i32 == '-' as i32
            || (unsafe { *cur }) as i32 == '.' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if (unsafe { *cur }) as i32 == ':' as i32 {
            cur = unsafe { cur.offset(1) };
            if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
                || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
                || (unsafe { *cur }) as i32 == '_' as i32
            {
                cur = unsafe { cur.offset(1) };
                while (unsafe { *cur }) as i32 >= 'a' as i32
                    && (unsafe { *cur }) as i32 <= 'z' as i32
                    || (unsafe { *cur }) as i32 >= 'A' as i32
                        && (unsafe { *cur }) as i32 <= 'Z' as i32
                    || (unsafe { *cur }) as i32 >= '0' as i32
                        && (unsafe { *cur }) as i32 <= '9' as i32
                    || (unsafe { *cur }) as i32 == '_' as i32
                    || (unsafe { *cur }) as i32 == '-' as i32
                    || (unsafe { *cur }) as i32 == '.' as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                current_block = 1054647088692577877;
            } else {
                current_block = 9464916090564301178;
            }
        } else {
            current_block = 1054647088692577877;
        }
        match current_block {
            9464916090564301178 => {}
            _ => {
                if space != 0 {
                    while (unsafe { *cur }) as i32 == 0x20 as i32
                        || 0x9 as i32 <= (unsafe { *cur }) as i32
                            && (unsafe { *cur }) as i32 <= 0xa as i32
                        || (unsafe { *cur }) as i32 == 0xd as i32
                    {
                        cur = unsafe { cur.offset(1) };
                    }
                }
                if (unsafe { *cur }) as i32 == 0 as i32 {
                    return 0 as i32;
                }
            }
        }
    }
    cur = value;
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0)
        && c != '_' as i32
    {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(l as isize) };
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    while (if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    }
    if c == ':' as i32 {
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        if !((if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0)
            && c != '_' as i32
        {
            return 1 as i32;
        }
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        while (if c < 0x100 as i32 {
            (0x41 as i32 <= c && c <= 0x5a as i32
                || 0x61 as i32 <= c && c <= 0x7a as i32
                || 0xc0 as i32 <= c && c <= 0xd6 as i32
                || 0xd8 as i32 <= c && c <= 0xf6 as i32
                || 0xf8 as i32 <= c) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
        }) != 0
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                    || c == 0x3007 as i32
                    || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
            }) != 0
            || (if c < 0x100 as i32 {
                (0x30 as i32 <= c && c <= 0x39 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
            }) != 0
            || c == '.' as i32
            || c == '-' as i32
            || c == '_' as i32
            || (if c < 0x100 as i32 {
                0 as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
            }) != 0
            || (if c < 0x100 as i32 {
                (c == 0xb7 as i32) as i32
            } else {
                unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
            }) != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if c != 0 as i32 {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateName(mut value: *const u8, mut space: i32) -> i32 {
    let mut cur: *const u8 = value;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if value.is_null() {
        return -(1 as i32);
    }
    if space != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == ':' as i32
    {
        cur = unsafe { cur.offset(1) };
        while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
            || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
            || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
            || (unsafe { *cur }) as i32 == '_' as i32
            || (unsafe { *cur }) as i32 == '-' as i32
            || (unsafe { *cur }) as i32 == '.' as i32
            || (unsafe { *cur }) as i32 == ':' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if space != 0 {
            while (unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32
            {
                cur = unsafe { cur.offset(1) };
            }
        }
        if (unsafe { *cur }) as i32 == 0 as i32 {
            return 0 as i32;
        }
    }
    cur = value;
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0)
        && c != '_' as i32
        && c != ':' as i32
    {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(l as isize) };
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    while (if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == ':' as i32
        || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    }
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if c != 0 as i32 {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlValidateNMToken(mut value: *const u8, mut space: i32) -> i32 {
    let mut cur: *const u8 = value;
    let mut c: i32 = 0;
    let mut l: i32 = 0;
    if value.is_null() {
        return -(1 as i32);
    }
    if space != 0 {
        while (unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32
        {
            cur = unsafe { cur.offset(1) };
        }
    }
    if (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
        || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
        || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
        || (unsafe { *cur }) as i32 == '_' as i32
        || (unsafe { *cur }) as i32 == '-' as i32
        || (unsafe { *cur }) as i32 == '.' as i32
        || (unsafe { *cur }) as i32 == ':' as i32
    {
        cur = unsafe { cur.offset(1) };
        while (unsafe { *cur }) as i32 >= 'a' as i32 && (unsafe { *cur }) as i32 <= 'z' as i32
            || (unsafe { *cur }) as i32 >= 'A' as i32 && (unsafe { *cur }) as i32 <= 'Z' as i32
            || (unsafe { *cur }) as i32 >= '0' as i32 && (unsafe { *cur }) as i32 <= '9' as i32
            || (unsafe { *cur }) as i32 == '_' as i32
            || (unsafe { *cur }) as i32 == '-' as i32
            || (unsafe { *cur }) as i32 == '.' as i32
            || (unsafe { *cur }) as i32 == ':' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if space != 0 {
            while (unsafe { *cur }) as i32 == 0x20 as i32
                || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
                || (unsafe { *cur }) as i32 == 0xd as i32
            {
                cur = unsafe { cur.offset(1) };
            }
        }
        if (unsafe { *cur }) as i32 == 0 as i32 {
            return 0 as i32;
        }
    }
    cur = value;
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if !((if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == ':' as i32
        || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0)
    {
        return 1 as i32;
    }
    cur = unsafe { cur.offset(l as isize) };
    c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    while (if c < 0x100 as i32 {
        (0x41 as i32 <= c && c <= 0x5a as i32
            || 0x61 as i32 <= c && c <= 0x7a as i32
            || 0xc0 as i32 <= c && c <= 0xd6 as i32
            || 0xd8 as i32 <= c && c <= 0xf6 as i32
            || 0xf8 as i32 <= c) as i32
    } else {
        unsafe { xmlCharInRange(c as u32, &xmlIsBaseCharGroup) }
    }) != 0
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            (0x4e00 as i32 <= c && c <= 0x9fa5 as i32
                || c == 0x3007 as i32
                || 0x3021 as i32 <= c && c <= 0x3029 as i32) as i32
        }) != 0
        || (if c < 0x100 as i32 {
            (0x30 as i32 <= c && c <= 0x39 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsDigitGroup) }
        }) != 0
        || c == '.' as i32
        || c == ':' as i32
        || c == '-' as i32
        || c == '_' as i32
        || (if c < 0x100 as i32 {
            0 as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsCombiningGroup) }
        }) != 0
        || (if c < 0x100 as i32 {
            (c == 0xb7 as i32) as i32
        } else {
            unsafe { xmlCharInRange(c as u32, &xmlIsExtenderGroup) }
        }) != 0
    {
        cur = unsafe { cur.offset(l as isize) };
        c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
    }
    if space != 0 {
        while if c < 0x100 as i32 {
            (c == 0x20 as i32 || 0x9 as i32 <= c && c <= 0xa as i32 || c == 0xd as i32) as i32
        } else {
            0 as i32
        } != 0
        {
            cur = unsafe { cur.offset(l as isize) };
            c = unsafe { xmlStringCurrentChar(0 as xmlParserCtxtPtr, cur, &mut l) };
        }
    }
    if c != 0 as i32 {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSetBufferAllocationScheme(mut scheme: u32) {
    if scheme as u32 == XML_BUFFER_ALLOC_EXACT as i32 as u32
        || scheme as u32 == XML_BUFFER_ALLOC_DOUBLEIT as i32 as u32
        || scheme as u32 == XML_BUFFER_ALLOC_HYBRID as i32 as u32
    {
        (unsafe { *__xmlBufferAllocScheme() = scheme });
    }
}
#[no_mangle]
pub extern "C" fn xmlGetBufferAllocationScheme() -> u32 {
    return unsafe { *__xmlBufferAllocScheme() };
}
#[no_mangle]
pub extern "C" fn xmlNewNs(
    mut node: *mut crate::src::threads::_xmlNode,
    mut href: *const u8,
    mut prefix: *const u8,
) -> *mut crate::src::threads::_xmlNs {
    let mut cur: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if !node.is_null() && (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlNsPtr;
    }
    if !prefix.is_null()
        && xmlStrEqual(prefix, b"xml\0" as *const u8 as *const i8 as *mut xmlChar) != 0
    {
        if xmlStrEqual(
            href,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
            return 0 as xmlNsPtr;
        }
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNs>() as u64)
    }) as xmlNsPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building namespace\0" as *const u8 as *const i8);
        return 0 as xmlNsPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNs>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_NAMESPACE_DECL });
    if !href.is_null() {
        let fresh0 = unsafe { &mut ((*cur).href) };
        *fresh0 = xmlStrdup(href);
    }
    if !prefix.is_null() {
        let fresh1 = unsafe { &mut ((*cur).prefix) };
        *fresh1 = xmlStrdup(prefix);
    }
    if !node.is_null() {
        if (unsafe { (*node).nsDef }).is_null() {
            let fresh2 = unsafe { &mut ((*node).nsDef) };
            *fresh2 = cur;
        } else {
            let mut prev: *mut crate::src::threads::_xmlNs = unsafe { (*node).nsDef };
            if (unsafe { (*prev).prefix }).is_null() && (unsafe { (*cur).prefix }).is_null()
                || xmlStrEqual(unsafe { (*prev).prefix }, unsafe { (*cur).prefix }) != 0
            {
                xmlFreeNs(cur);
                return 0 as xmlNsPtr;
            }
            while !(unsafe { (*prev).next }).is_null() {
                prev = unsafe { (*prev).next };
                if (unsafe { (*prev).prefix }).is_null() && (unsafe { (*cur).prefix }).is_null()
                    || xmlStrEqual(unsafe { (*prev).prefix }, unsafe { (*cur).prefix }) != 0
                {
                    xmlFreeNs(cur);
                    return 0 as xmlNsPtr;
                }
            }
            let fresh3 = unsafe { &mut ((*prev).next) };
            *fresh3 = cur;
        }
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlSetNs<'a1>(
    mut node: Option<&'a1 mut crate::src::threads::_xmlNode>,
    mut ns: *mut crate::src::threads::_xmlNs,
) {
    if borrow(&node).is_none() {
        return;
    }
    if (*(borrow(&node)).unwrap()).type_0 as u32 == XML_ELEMENT_NODE as i32 as u32
        || (*(borrow(&node)).unwrap()).type_0 as u32 == XML_ATTRIBUTE_NODE as i32 as u32
    {
        let fresh4 = &mut ((*(borrow_mut(&mut node)).unwrap()).ns);
        *fresh4 = ns;
    }
}
#[no_mangle]
pub extern "C" fn xmlFreeNs(mut cur: *mut crate::src::threads::_xmlNs) {
    if cur.is_null() {
        return;
    }
    if !(unsafe { (*cur).href }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).href as *mut i8 as *mut libc::c_void)
        });
    }
    if !(unsafe { (*cur).prefix }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).prefix as *mut i8 as *mut libc::c_void,
            )
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlFreeNsList(mut cur: *mut crate::src::threads::_xmlNs) {
    let mut next: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    while !cur.is_null() {
        next = unsafe { (*cur).next };
        xmlFreeNs(cur);
        cur = next;
    }
}
#[no_mangle]
pub extern "C" fn xmlNewDtd(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
    mut ExternalID: *const u8,
    mut SystemID: *const u8,
) -> *mut crate::src::threads::_xmlDtd {
    let mut cur: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    if !doc.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlDtd>() as u64)
    }) as xmlDtdPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building DTD\0" as *const u8 as *const i8);
        return 0 as xmlDtdPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlDtd>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_DTD_NODE });
    if !name.is_null() {
        let fresh5 = unsafe { &mut ((*cur).name) };
        *fresh5 = xmlStrdup(name);
    }
    if !ExternalID.is_null() {
        let fresh6 = unsafe { &mut ((*cur).ExternalID) };
        *fresh6 = xmlStrdup(ExternalID);
    }
    if !SystemID.is_null() {
        let fresh7 = unsafe { &mut ((*cur).SystemID) };
        *fresh7 = xmlStrdup(SystemID);
    }
    if !doc.is_null() {
        let fresh8 = unsafe { &mut ((*doc).extSubset) };
        *fresh8 = cur;
    }
    let fresh9 = unsafe { &mut ((*cur).doc) };
    *fresh9 = doc;
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlGetIntSubset(
    mut doc: *const crate::src::threads::_xmlDoc,
) -> *mut crate::src::threads::_xmlDtd {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = unsafe { (*doc).children };
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
            return cur as xmlDtdPtr;
        }
        cur = unsafe { (*cur).next };
    }
    return (unsafe { (*doc).intSubset }) as xmlDtdPtr;
}
#[no_mangle]
pub extern "C" fn xmlCreateIntSubset(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
    mut ExternalID: *const u8,
    mut SystemID: *const u8,
) -> *mut crate::src::threads::_xmlDtd {
    let mut cur: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    if !doc.is_null() && !(xmlGetIntSubset(doc as *const xmlDoc)).is_null() {
        return 0 as xmlDtdPtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlDtd>() as u64)
    }) as xmlDtdPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building internal subset\0" as *const u8 as *const i8);
        return 0 as xmlDtdPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlDtd>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_DTD_NODE });
    if !name.is_null() {
        let fresh10 = unsafe { &mut ((*cur).name) };
        *fresh10 = xmlStrdup(name);
        if (unsafe { (*cur).name }).is_null() {
            xmlTreeErrMemory(b"building internal subset\0" as *const u8 as *const i8);
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            return 0 as xmlDtdPtr;
        }
    }
    if !ExternalID.is_null() {
        let fresh11 = unsafe { &mut ((*cur).ExternalID) };
        *fresh11 = xmlStrdup(ExternalID);
        if (unsafe { (*cur).ExternalID }).is_null() {
            xmlTreeErrMemory(b"building internal subset\0" as *const u8 as *const i8);
            if !(unsafe { (*cur).name }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).name as *mut i8 as *mut libc::c_void,
                    )
                });
            }
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            return 0 as xmlDtdPtr;
        }
    }
    if !SystemID.is_null() {
        let fresh12 = unsafe { &mut ((*cur).SystemID) };
        *fresh12 = xmlStrdup(SystemID);
        if (unsafe { (*cur).SystemID }).is_null() {
            xmlTreeErrMemory(b"building internal subset\0" as *const u8 as *const i8);
            if !(unsafe { (*cur).name }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).name as *mut i8 as *mut libc::c_void,
                    )
                });
            }
            if !(unsafe { (*cur).ExternalID }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*cur).ExternalID as *mut i8 as *mut libc::c_void,
                    )
                });
            }
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
            return 0 as xmlDtdPtr;
        }
    }
    if !doc.is_null() {
        let fresh13 = unsafe { &mut ((*doc).intSubset) };
        *fresh13 = cur;
        let fresh14 = unsafe { &mut ((*cur).parent) };
        *fresh14 = doc;
        let fresh15 = unsafe { &mut ((*cur).doc) };
        *fresh15 = doc;
        if (unsafe { (*doc).children }).is_null() {
            let fresh16 = unsafe { &mut ((*doc).children) };
            *fresh16 = cur as xmlNodePtr;
            let fresh17 = unsafe { &mut ((*doc).last) };
            *fresh17 = cur as xmlNodePtr;
        } else if (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
            let mut prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            prev = unsafe { (*doc).children };
            let fresh18 = unsafe { &mut ((*prev).prev) };
            *fresh18 = cur as xmlNodePtr;
            let fresh19 = unsafe { &mut ((*cur).next) };
            *fresh19 = prev;
            let fresh20 = unsafe { &mut ((*doc).children) };
            *fresh20 = cur as xmlNodePtr;
        } else {
            let mut next: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            next = unsafe { (*doc).children };
            while !next.is_null()
                && (unsafe { (*next).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
            {
                next = unsafe { (*next).next };
            }
            if next.is_null() {
                let fresh21 = unsafe { &mut ((*cur).prev) };
                *fresh21 = unsafe { (*doc).last };
                let fresh22 = unsafe { &mut ((*(*cur).prev).next) };
                *fresh22 = cur as xmlNodePtr;
                let fresh23 = unsafe { &mut ((*cur).next) };
                *fresh23 = 0 as *mut _xmlNode;
                let fresh24 = unsafe { &mut ((*doc).last) };
                *fresh24 = cur as xmlNodePtr;
            } else {
                let fresh25 = unsafe { &mut ((*cur).next) };
                *fresh25 = next;
                let fresh26 = unsafe { &mut ((*cur).prev) };
                *fresh26 = unsafe { (*next).prev };
                if (unsafe { (*cur).prev }).is_null() {
                    let fresh27 = unsafe { &mut ((*doc).children) };
                    *fresh27 = cur as xmlNodePtr;
                } else {
                    let fresh28 = unsafe { &mut ((*(*cur).prev).next) };
                    *fresh28 = cur as xmlNodePtr;
                }
                let fresh29 = unsafe { &mut ((*next).prev) };
                *fresh29 = cur as xmlNodePtr;
            }
        }
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlFreeDtd(mut cur: *mut crate::src::threads::_xmlDtd) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !(unsafe { (*cur).doc }).is_null() {
        dict = unsafe { (*(*cur).doc).dict };
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    if !(unsafe { (*cur).children }).is_null() {
        let mut next: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        let mut c: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
        while !c.is_null() {
            next = unsafe { (*c).next };
            if (unsafe { (*c).type_0 }) as u32 != XML_NOTATION_NODE as i32 as u32
                && (unsafe { (*c).type_0 }) as u32 != XML_ELEMENT_DECL as i32 as u32
                && (unsafe { (*c).type_0 }) as u32 != XML_ATTRIBUTE_DECL as i32 as u32
                && (unsafe { (*c).type_0 }) as u32 != XML_ENTITY_DECL as i32 as u32
            {
                xmlUnlinkNode(c);
                xmlFreeNode(c);
            }
            c = next;
        }
    }
    if !(unsafe { (*cur).name }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).name as *mut i8 as *mut libc::c_void)
        });
    }
    if !(unsafe { (*cur).SystemID }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).SystemID) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).SystemID as *mut i8 as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*cur).ExternalID }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).ExternalID) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).ExternalID as *mut i8 as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*cur).notations }).is_null() {
        xmlFreeNotationTable((unsafe { (*cur).notations }) as xmlNotationTablePtr);
    }
    if !(unsafe { (*cur).elements }).is_null() {
        xmlFreeElementTable((unsafe { (*cur).elements }) as xmlElementTablePtr);
    }
    if !(unsafe { (*cur).attributes }).is_null() {
        xmlFreeAttributeTable((unsafe { (*cur).attributes }) as xmlAttributeTablePtr);
    }
    if !(unsafe { (*cur).entities }).is_null() {
        (unsafe { xmlFreeEntitiesTable((*cur).entities as xmlEntitiesTablePtr) });
    }
    if !(unsafe { (*cur).pentities }).is_null() {
        (unsafe { xmlFreeEntitiesTable((*cur).pentities as xmlEntitiesTablePtr) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlNewDoc(mut version: *const u8) -> *mut crate::src::threads::_xmlDoc {
    let mut cur: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    if version.is_null() {
        version = b"1.0\0" as *const u8 as *const i8 as *const xmlChar;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlDoc>() as u64)
    }) as xmlDocPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building doc\0" as *const u8 as *const i8);
        return 0 as xmlDocPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlDoc>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_DOCUMENT_NODE });
    let fresh30 = unsafe { &mut ((*cur).version) };
    *fresh30 = xmlStrdup(version);
    if (unsafe { (*cur).version }).is_null() {
        xmlTreeErrMemory(b"building doc\0" as *const u8 as *const i8);
        (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        return 0 as xmlDocPtr;
    }
    (unsafe { (*cur).standalone = -(1 as i32) });
    (unsafe { (*cur).compression = -(1 as i32) });
    let fresh31 = unsafe { &mut ((*cur).doc) };
    *fresh31 = cur;
    (unsafe { (*cur).parseFlags = 0 as i32 });
    (unsafe { (*cur).properties = XML_DOC_USERBUILT as i32 });
    (unsafe { (*cur).charset = XML_CHAR_ENCODING_UTF8 as i32 });
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlFreeDoc(mut cur: *mut crate::src::threads::_xmlDoc) {
    let mut extSubset: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut intSubset: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !cur.is_null() {
        dict = unsafe { (*cur).dict };
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    if !(unsafe { (*cur).ids }).is_null() {
        xmlFreeIDTable((unsafe { (*cur).ids }) as xmlIDTablePtr);
    }
    let fresh32 = unsafe { &mut ((*cur).ids) };
    *fresh32 = 0 as *mut libc::c_void;
    if !(unsafe { (*cur).refs }).is_null() {
        xmlFreeRefTable((unsafe { (*cur).refs }) as xmlRefTablePtr);
    }
    let fresh33 = unsafe { &mut ((*cur).refs) };
    *fresh33 = 0 as *mut libc::c_void;
    extSubset = unsafe { (*cur).extSubset };
    intSubset = unsafe { (*cur).intSubset };
    if intSubset == extSubset {
        extSubset = 0 as xmlDtdPtr;
    }
    if !extSubset.is_null() {
        xmlUnlinkNode((unsafe { (*cur).extSubset }) as xmlNodePtr);
        let fresh34 = unsafe { &mut ((*cur).extSubset) };
        *fresh34 = 0 as *mut _xmlDtd;
        xmlFreeDtd(extSubset);
    }
    if !intSubset.is_null() {
        xmlUnlinkNode((unsafe { (*cur).intSubset }) as xmlNodePtr);
        let fresh35 = unsafe { &mut ((*cur).intSubset) };
        *fresh35 = 0 as *mut _xmlDtd;
        xmlFreeDtd(intSubset);
    }
    if !(unsafe { (*cur).children }).is_null() {
        xmlFreeNodeList(unsafe { (*cur).children });
    }
    if !(unsafe { (*cur).oldNs }).is_null() {
        xmlFreeNsList(unsafe { (*cur).oldNs });
    }
    if !(unsafe { (*cur).version }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).version) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).version as *mut i8 as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*cur).name }).is_null()
        && (dict.is_null()
            || (unsafe { xmlDictOwns(dict, (*cur).name as *const xmlChar) }) == 0 as i32)
    {
        (unsafe { xmlFree.expect("non-null function pointer")((*cur).name as *mut libc::c_void) });
    }
    if !(unsafe { (*cur).encoding }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).encoding) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")(
                (*cur).encoding as *mut i8 as *mut libc::c_void,
            )
        });
    }
    if !(unsafe { (*cur).URL }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).URL) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).URL as *mut i8 as *mut libc::c_void)
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
    if !dict.is_null() {
        (unsafe { xmlDictFree(dict) });
    }
}
#[no_mangle]
pub extern "C" fn xmlStringLenGetNodeList(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut value: *const u8,
    mut len: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut current_block: u64;
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut last: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut val: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut end: *const u8 = 0 as *const xmlChar;
    let mut q: *const u8 = 0 as *const xmlChar;
    let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
    let mut buf: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
    if value.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = value;
    end = unsafe { cur.offset(len as isize) };
    buf = unsafe { xmlBufCreateSize(0 as i32 as size_t) };
    if buf.is_null() {
        return 0 as xmlNodePtr;
    }
    (unsafe { xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT) });
    q = cur;
    loop {
        if !(cur < end && (unsafe { *cur }) as i32 != 0 as i32) {
            current_block = 8656139126282042408;
            break;
        }
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '&' as i32 {
            let mut charval: i32 = 0 as i32;
            let mut tmp: u8 = 0;
            if cur != q {
                if (unsafe { xmlBufAdd(buf, q, cur.offset_from(q) as i64 as i32) }) != 0 {
                    current_block = 13579860642496470364;
                    break;
                }
            }
            q = cur;
            if (unsafe { cur.offset(2 as i32 as isize) }) < end
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '#' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 == 'x' as i32
            {
                cur = unsafe { cur.offset(3 as i32 as isize) };
                if cur < end {
                    tmp = unsafe { *cur };
                } else {
                    tmp = 0 as i32 as xmlChar;
                }
                while tmp as i32 != ';' as i32 {
                    if tmp as i32 >= '0' as i32 && tmp as i32 <= '9' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - '0' as i32);
                    } else if tmp as i32 >= 'a' as i32 && tmp as i32 <= 'f' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - 'a' as i32) + 10 as i32;
                    } else if tmp as i32 >= 'A' as i32 && tmp as i32 <= 'F' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - 'A' as i32) + 10 as i32;
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_HEX as i32,
                            doc as xmlNodePtr,
                            0 as *const i8,
                        );
                        charval = 0 as i32;
                        break;
                    }
                    cur = unsafe { cur.offset(1) };
                    if cur < end {
                        tmp = unsafe { *cur };
                    } else {
                        tmp = 0 as i32 as xmlChar;
                    }
                }
                if tmp as i32 == ';' as i32 {
                    cur = unsafe { cur.offset(1) };
                }
                q = cur;
            } else if (unsafe { cur.offset(1 as i32 as isize) }) < end
                && (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '#' as i32
            {
                cur = unsafe { cur.offset(2 as i32 as isize) };
                if cur < end {
                    tmp = unsafe { *cur };
                } else {
                    tmp = 0 as i32 as xmlChar;
                }
                while tmp as i32 != ';' as i32 {
                    if tmp as i32 >= '0' as i32 && tmp as i32 <= '9' as i32 {
                        charval = charval * 10 as i32 + (tmp as i32 - '0' as i32);
                        cur = unsafe { cur.offset(1) };
                        if cur < end {
                            tmp = unsafe { *cur };
                        } else {
                            tmp = 0 as i32 as xmlChar;
                        }
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_DEC as i32,
                            doc as xmlNodePtr,
                            0 as *const i8,
                        );
                        charval = 0 as i32;
                        break;
                    }
                }
                if tmp as i32 == ';' as i32 {
                    cur = unsafe { cur.offset(1) };
                }
                q = cur;
            } else {
                cur = unsafe { cur.offset(1) };
                q = cur;
                while cur < end
                    && (unsafe { *cur }) as i32 != 0 as i32
                    && (unsafe { *cur }) as i32 != ';' as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                if cur >= end || (unsafe { *cur }) as i32 == 0 as i32 {
                    xmlTreeErr(
                        XML_TREE_UNTERMINATED_ENTITY as i32,
                        doc as xmlNodePtr,
                        q as *const i8,
                    );
                    current_block = 13579860642496470364;
                    break;
                } else {
                    if cur != q {
                        val = xmlStrndup(q, (unsafe { cur.offset_from(q) }) as i64 as i32);
                        ent = unsafe { xmlGetDocEntity(doc, val) };
                        if !ent.is_null()
                            && (unsafe { (*ent).etype }) as u32
                                == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                        {
                            if (unsafe { xmlBufCat(buf, (*ent).content) }) != 0 {
                                current_block = 13579860642496470364;
                                break;
                            }
                        } else {
                            if (unsafe { xmlBufIsEmpty(buf) }) == 0 {
                                node = xmlNewDocText(doc, 0 as *const xmlChar);
                                if node.is_null() {
                                    if !val.is_null() {
                                        (unsafe {
                                            xmlFree.expect("non-null function pointer")(
                                                val as *mut libc::c_void,
                                            )
                                        });
                                    }
                                    current_block = 13579860642496470364;
                                    break;
                                } else {
                                    let fresh36 = unsafe { &mut ((*node).content) };
                                    *fresh36 = unsafe { xmlBufDetach(buf) };
                                    if last.is_null() {
                                        ret = node;
                                        last = ret;
                                    } else {
                                        last = xmlAddNextSibling(last, node);
                                    }
                                }
                            }
                            node = xmlNewReference(doc, val);
                            if node.is_null() {
                                if !val.is_null() {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            val as *mut libc::c_void,
                                        )
                                    });
                                }
                                current_block = 13579860642496470364;
                                break;
                            } else {
                                if !ent.is_null() && (unsafe { (*ent).children }).is_null() {
                                    let mut temp: *mut crate::src::threads::_xmlNode =
                                        0 as *mut xmlNode;
                                    let fresh37 = unsafe { &mut ((*ent).children) };
                                    *fresh37 = -(1 as i32) as xmlNodePtr;
                                    let fresh38 = unsafe { &mut ((*ent).children) };
                                    *fresh38 = xmlStringGetNodeList(
                                        doc,
                                        (unsafe { (*node).content }) as *const xmlChar,
                                    );
                                    (unsafe { (*ent).owner = 1 as i32 });
                                    temp = unsafe { (*ent).children };
                                    while !temp.is_null() {
                                        let fresh39 = unsafe { &mut ((*temp).parent) };
                                        *fresh39 = ent as xmlNodePtr;
                                        let fresh40 = unsafe { &mut ((*ent).last) };
                                        *fresh40 = temp;
                                        temp = unsafe { (*temp).next };
                                    }
                                }
                                if last.is_null() {
                                    ret = node;
                                    last = ret;
                                } else {
                                    last = xmlAddNextSibling(last, node);
                                }
                            }
                        }
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(val as *mut libc::c_void)
                        });
                    }
                    cur = unsafe { cur.offset(1) };
                    q = cur;
                }
            }
            if !(charval != 0 as i32) {
                continue;
            }
            let mut buffer: [u8; 10] = [0; 10];
            let mut l: i32 = 0;
            l = unsafe { xmlCopyCharMultiByte(buffer.as_mut_ptr(), charval) };
            buffer[l as usize] = 0 as i32 as xmlChar;
            if (unsafe { xmlBufCat(buf, buffer.as_mut_ptr()) }) != 0 {
                current_block = 13579860642496470364;
                break;
            }
            charval = 0 as i32;
        } else {
            cur = unsafe { cur.offset(1) };
        }
    }
    match current_block {
        8656139126282042408 => {
            if cur != q {
                if (unsafe { xmlBufAdd(buf, q, cur.offset_from(q) as i64 as i32) }) != 0 {
                    current_block = 13579860642496470364;
                } else {
                    current_block = 14953815020842398287;
                }
            } else {
                current_block = 14953815020842398287;
            }
            match current_block {
                13579860642496470364 => {}
                _ => {
                    if (unsafe { xmlBufIsEmpty(buf) }) == 0 {
                        node = xmlNewDocText(doc, 0 as *const xmlChar);
                        if !node.is_null() {
                            let fresh41 = unsafe { &mut ((*node).content) };
                            *fresh41 = unsafe { xmlBufDetach(buf) };
                            if last.is_null() {
                                ret = node;
                            } else {
                                xmlAddNextSibling(last, node);
                            }
                        }
                    } else if ret.is_null() {
                        ret = xmlNewDocText(doc, b"\0" as *const u8 as *const i8 as *mut xmlChar);
                    }
                }
            }
        }
        _ => {}
    }
    (unsafe { xmlBufFree(buf) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlStringGetNodeList(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut current_block: u64;
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut last: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut val: *mut u8 = 0 as *mut xmlChar;
    let mut cur: *const u8 = value;
    let mut q: *const u8 = 0 as *const xmlChar;
    let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
    let mut buf: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
    if value.is_null() {
        return 0 as xmlNodePtr;
    }
    buf = unsafe { xmlBufCreateSize(0 as i32 as size_t) };
    if buf.is_null() {
        return 0 as xmlNodePtr;
    }
    (unsafe { xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT) });
    q = cur;
    loop {
        if !((unsafe { *cur }) as i32 != 0 as i32) {
            current_block = 3217137713928741134;
            break;
        }
        if (unsafe { *cur.offset(0 as i32 as isize) }) as i32 == '&' as i32 {
            let mut charval: i32 = 0 as i32;
            let mut tmp: u8 = 0;
            if cur != q {
                if (unsafe { xmlBufAdd(buf, q, cur.offset_from(q) as i64 as i32) }) != 0 {
                    current_block = 16011119045367533822;
                    break;
                }
            }
            q = cur;
            if (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '#' as i32
                && (unsafe { *cur.offset(2 as i32 as isize) }) as i32 == 'x' as i32
            {
                cur = unsafe { cur.offset(3 as i32 as isize) };
                tmp = unsafe { *cur };
                while tmp as i32 != ';' as i32 {
                    if tmp as i32 >= '0' as i32 && tmp as i32 <= '9' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - '0' as i32);
                    } else if tmp as i32 >= 'a' as i32 && tmp as i32 <= 'f' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - 'a' as i32) + 10 as i32;
                    } else if tmp as i32 >= 'A' as i32 && tmp as i32 <= 'F' as i32 {
                        charval = charval * 16 as i32 + (tmp as i32 - 'A' as i32) + 10 as i32;
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_HEX as i32,
                            doc as xmlNodePtr,
                            0 as *const i8,
                        );
                        charval = 0 as i32;
                        break;
                    }
                    cur = unsafe { cur.offset(1) };
                    tmp = unsafe { *cur };
                }
                if tmp as i32 == ';' as i32 {
                    cur = unsafe { cur.offset(1) };
                }
                q = cur;
            } else if (unsafe { *cur.offset(1 as i32 as isize) }) as i32 == '#' as i32 {
                cur = unsafe { cur.offset(2 as i32 as isize) };
                tmp = unsafe { *cur };
                while tmp as i32 != ';' as i32 {
                    if tmp as i32 >= '0' as i32 && tmp as i32 <= '9' as i32 {
                        charval = charval * 10 as i32 + (tmp as i32 - '0' as i32);
                        cur = unsafe { cur.offset(1) };
                        tmp = unsafe { *cur };
                    } else {
                        xmlTreeErr(
                            XML_TREE_INVALID_DEC as i32,
                            doc as xmlNodePtr,
                            0 as *const i8,
                        );
                        charval = 0 as i32;
                        break;
                    }
                }
                if tmp as i32 == ';' as i32 {
                    cur = unsafe { cur.offset(1) };
                }
                q = cur;
            } else {
                cur = unsafe { cur.offset(1) };
                q = cur;
                while (unsafe { *cur }) as i32 != 0 as i32 && (unsafe { *cur }) as i32 != ';' as i32
                {
                    cur = unsafe { cur.offset(1) };
                }
                if (unsafe { *cur }) as i32 == 0 as i32 {
                    xmlTreeErr(
                        XML_TREE_UNTERMINATED_ENTITY as i32,
                        doc as xmlNodePtr,
                        q as *const i8,
                    );
                    current_block = 16011119045367533822;
                    break;
                } else {
                    if cur != q {
                        val = xmlStrndup(q, (unsafe { cur.offset_from(q) }) as i64 as i32);
                        ent = unsafe { xmlGetDocEntity(doc, val) };
                        if !ent.is_null()
                            && (unsafe { (*ent).etype }) as u32
                                == XML_INTERNAL_PREDEFINED_ENTITY as i32 as u32
                        {
                            if (unsafe { xmlBufCat(buf, (*ent).content) }) != 0 {
                                current_block = 16011119045367533822;
                                break;
                            }
                        } else {
                            if (unsafe { xmlBufIsEmpty(buf) }) == 0 {
                                node = xmlNewDocText(doc, 0 as *const xmlChar);
                                if node.is_null() {
                                    if !val.is_null() {
                                        (unsafe {
                                            xmlFree.expect("non-null function pointer")(
                                                val as *mut libc::c_void,
                                            )
                                        });
                                    }
                                    current_block = 16011119045367533822;
                                    break;
                                } else {
                                    let fresh42 = unsafe { &mut ((*node).content) };
                                    *fresh42 = unsafe { xmlBufDetach(buf) };
                                    if last.is_null() {
                                        ret = node;
                                        last = ret;
                                    } else {
                                        last = xmlAddNextSibling(last, node);
                                    }
                                }
                            }
                            node = xmlNewReference(doc, val);
                            if node.is_null() {
                                if !val.is_null() {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            val as *mut libc::c_void,
                                        )
                                    });
                                }
                                current_block = 16011119045367533822;
                                break;
                            } else {
                                if !ent.is_null() && (unsafe { (*ent).children }).is_null() {
                                    let mut temp: *mut crate::src::threads::_xmlNode =
                                        0 as *mut xmlNode;
                                    let fresh43 = unsafe { &mut ((*ent).children) };
                                    *fresh43 = -(1 as i32) as xmlNodePtr;
                                    let fresh44 = unsafe { &mut ((*ent).children) };
                                    *fresh44 = xmlStringGetNodeList(
                                        doc,
                                        (unsafe { (*node).content }) as *const xmlChar,
                                    );
                                    (unsafe { (*ent).owner = 1 as i32 });
                                    temp = unsafe { (*ent).children };
                                    while !temp.is_null() {
                                        let fresh45 = unsafe { &mut ((*temp).parent) };
                                        *fresh45 = ent as xmlNodePtr;
                                        let fresh46 = unsafe { &mut ((*ent).last) };
                                        *fresh46 = temp;
                                        temp = unsafe { (*temp).next };
                                    }
                                }
                                if last.is_null() {
                                    ret = node;
                                    last = ret;
                                } else {
                                    last = xmlAddNextSibling(last, node);
                                }
                            }
                        }
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(val as *mut libc::c_void)
                        });
                    }
                    cur = unsafe { cur.offset(1) };
                    q = cur;
                }
            }
            if !(charval != 0 as i32) {
                continue;
            }
            let mut buffer: [u8; 10] = [0; 10];
            let mut len: i32 = 0;
            len = unsafe { xmlCopyCharMultiByte(buffer.as_mut_ptr(), charval) };
            buffer[len as usize] = 0 as i32 as xmlChar;
            if (unsafe { xmlBufCat(buf, buffer.as_mut_ptr()) }) != 0 {
                current_block = 16011119045367533822;
                break;
            }
            charval = 0 as i32;
        } else {
            cur = unsafe { cur.offset(1) };
        }
    }
    match current_block {
        3217137713928741134 => {
            if cur != q || ret.is_null() {
                (unsafe { xmlBufAdd(buf, q, cur.offset_from(q) as i64 as i32) });
            }
            if (unsafe { xmlBufIsEmpty(buf) }) == 0 {
                node = xmlNewDocText(doc, 0 as *const xmlChar);
                if node.is_null() {
                    (unsafe { xmlBufFree(buf) });
                    return 0 as xmlNodePtr;
                }
                let fresh47 = unsafe { &mut ((*node).content) };
                *fresh47 = unsafe { xmlBufDetach(buf) };
                if last.is_null() {
                    ret = node;
                } else {
                    xmlAddNextSibling(last, node);
                }
            }
        }
        _ => {}
    }
    (unsafe { xmlBufFree(buf) });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNodeListGetString(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut list: *const crate::src::threads::_xmlNode,
    mut inLine: i32,
) -> *mut u8 {
    let mut node: *const crate::src::threads::_xmlNode = list;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
    let mut attr: i32 = 0;
    if list.is_null() {
        return 0 as *mut xmlChar;
    }
    if !(unsafe { (*list).parent }).is_null()
        && (unsafe { (*(*list).parent).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
    {
        attr = 1 as i32;
    } else {
        attr = 0 as i32;
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
        {
            if inLine != 0 {
                ret = xmlStrcat(ret, unsafe { (*node).content });
            } else {
                let mut buffer: *mut u8 = 0 as *mut xmlChar;
                if attr != 0 {
                    buffer = unsafe { xmlEncodeAttributeEntities(doc, (*node).content) };
                } else {
                    buffer = unsafe { xmlEncodeEntitiesReentrant(doc, (*node).content) };
                }
                if !buffer.is_null() {
                    ret = xmlStrcat(ret, buffer);
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void)
                    });
                }
            }
        } else if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
            if inLine != 0 {
                ent = unsafe { xmlGetDocEntity(doc as *const xmlDoc, (*node).name) };
                if !ent.is_null() {
                    let mut buffer_0: *mut u8 = 0 as *mut xmlChar;
                    buffer_0 = xmlNodeListGetString(doc, unsafe { (*ent).children }, 1 as i32);
                    if !buffer_0.is_null() {
                        ret = xmlStrcat(ret, buffer_0);
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                buffer_0 as *mut libc::c_void,
                            )
                        });
                    }
                } else {
                    ret = xmlStrcat(ret, unsafe { (*node).content });
                }
            } else {
                let mut buf: [u8; 2] = [0; 2];
                buf[0 as i32 as usize] = '&' as i32 as xmlChar;
                buf[1 as i32 as usize] = 0 as i32 as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as i32);
                ret = xmlStrcat(ret, unsafe { (*node).name });
                buf[0 as i32 as usize] = ';' as i32 as xmlChar;
                buf[1 as i32 as usize] = 0 as i32 as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as i32);
            }
        }
        node = unsafe { (*node).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlNodeListGetRawString(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut list: *const crate::src::threads::_xmlNode,
    mut inLine: i32,
) -> *mut u8 {
    let mut node: *const crate::src::threads::_xmlNode = list;
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
    if list.is_null() {
        return 0 as *mut xmlChar;
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
        {
            if inLine != 0 {
                ret = xmlStrcat(ret, unsafe { (*node).content });
            } else {
                let mut buffer: *mut u8 = 0 as *mut xmlChar;
                buffer = unsafe { xmlEncodeSpecialChars(doc, (*node).content) };
                if !buffer.is_null() {
                    ret = xmlStrcat(ret, buffer);
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void)
                    });
                }
            }
        } else if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
            if inLine != 0 {
                ent = unsafe { xmlGetDocEntity(doc, (*node).name) };
                if !ent.is_null() {
                    let mut buffer_0: *mut u8 = 0 as *mut xmlChar;
                    buffer_0 = xmlNodeListGetRawString(doc, unsafe { (*ent).children }, 1 as i32);
                    if !buffer_0.is_null() {
                        ret = xmlStrcat(ret, buffer_0);
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                buffer_0 as *mut libc::c_void,
                            )
                        });
                    }
                } else {
                    ret = xmlStrcat(ret, unsafe { (*node).content });
                }
            } else {
                let mut buf: [u8; 2] = [0; 2];
                buf[0 as i32 as usize] = '&' as i32 as xmlChar;
                buf[1 as i32 as usize] = 0 as i32 as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as i32);
                ret = xmlStrcat(ret, unsafe { (*node).name });
                buf[0 as i32 as usize] = ';' as i32 as xmlChar;
                buf[1 as i32 as usize] = 0 as i32 as xmlChar;
                ret = xmlStrncat(ret, buf.as_mut_ptr(), 1 as i32);
            }
        }
        node = unsafe { (*node).next };
    }
    return ret;
}
extern "C" fn xmlNewPropInternal(
    mut node: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut value: *const u8,
    mut eatname: i32,
) -> *mut crate::src::threads::_xmlAttr {
    let mut cur: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as xmlDocPtr;
    if !node.is_null() && (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        if eatname == 1 as i32
            && ((unsafe { (*node).doc }).is_null()
                || (unsafe { xmlDictOwns((*(*node).doc).dict, name) }) == 0)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    name as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        return 0 as xmlAttrPtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlAttr>() as u64)
    }) as xmlAttrPtr;
    if cur.is_null() {
        if eatname == 1 as i32
            && (node.is_null()
                || (unsafe { (*node).doc }).is_null()
                || (unsafe { xmlDictOwns((*(*node).doc).dict, name) }) == 0)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    name as *mut xmlChar as *mut libc::c_void,
                )
            });
        }
        xmlTreeErrMemory(b"building attribute\0" as *const u8 as *const i8);
        return 0 as xmlAttrPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlAttr>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ATTRIBUTE_NODE });
    let fresh48 = unsafe { &mut ((*cur).parent) };
    *fresh48 = node;
    if !node.is_null() {
        doc = unsafe { (*node).doc };
        let fresh49 = unsafe { &mut ((*cur).doc) };
        *fresh49 = doc;
    }
    let fresh50 = unsafe { &mut ((*cur).ns) };
    *fresh50 = ns;
    if eatname == 0 as i32 {
        if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
            let fresh51 = unsafe { &mut ((*cur).name) };
            *fresh51 = (unsafe { xmlDictLookup((*doc).dict, name, -(1 as i32)) }) as *mut xmlChar;
        } else {
            let fresh52 = unsafe { &mut ((*cur).name) };
            *fresh52 = xmlStrdup(name);
        }
    } else {
        let fresh53 = unsafe { &mut ((*cur).name) };
        *fresh53 = name;
    }
    if !value.is_null() {
        let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        let fresh54 = unsafe { &mut ((*cur).children) };
        *fresh54 = xmlNewDocText(doc as *const xmlDoc, value);
        let fresh55 = unsafe { &mut ((*cur).last) };
        *fresh55 = 0 as *mut _xmlNode;
        tmp = unsafe { (*cur).children };
        while !tmp.is_null() {
            let fresh56 = unsafe { &mut ((*tmp).parent) };
            *fresh56 = cur as xmlNodePtr;
            if (unsafe { (*tmp).next }).is_null() {
                let fresh57 = unsafe { &mut ((*cur).last) };
                *fresh57 = tmp;
            }
            tmp = unsafe { (*tmp).next };
        }
    }
    if !node.is_null() {
        if (unsafe { (*node).properties }).is_null() {
            let fresh58 = unsafe { &mut ((*node).properties) };
            *fresh58 = cur;
        } else {
            let mut prev: *mut crate::src::threads::_xmlAttr = unsafe { (*node).properties };
            while !(unsafe { (*prev).next }).is_null() {
                prev = unsafe { (*prev).next };
            }
            let fresh59 = unsafe { &mut ((*prev).next) };
            *fresh59 = cur;
            let fresh60 = unsafe { &mut ((*cur).prev) };
            *fresh60 = prev;
        }
    }
    if !value.is_null()
        && !node.is_null()
        && xmlIsID(unsafe { (*node).doc }, node, cur) == 1 as i32
    {
        xmlAddID(0 as xmlValidCtxtPtr, unsafe { (*node).doc }, value, cur);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewProp(
    mut node: *mut crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, 0 as xmlNsPtr, name, value, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNewNsProp(
    mut node: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, ns, name, value, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNewNsPropEatName(
    mut node: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *mut u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    return xmlNewPropInternal(node, ns, name, value, 1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNewDocProp(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    let mut cur: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if name.is_null() {
        return 0 as xmlAttrPtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlAttr>() as u64)
    }) as xmlAttrPtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building attribute\0" as *const u8 as *const i8);
        return 0 as xmlAttrPtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlAttr>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ATTRIBUTE_NODE });
    if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
        let fresh61 = unsafe { &mut ((*cur).name) };
        *fresh61 = unsafe { xmlDictLookup((*doc).dict, name, -(1 as i32)) };
    } else {
        let fresh62 = unsafe { &mut ((*cur).name) };
        *fresh62 = xmlStrdup(name);
    }
    let fresh63 = unsafe { &mut ((*cur).doc) };
    *fresh63 = doc;
    if !value.is_null() {
        let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        let fresh64 = unsafe { &mut ((*cur).children) };
        *fresh64 = xmlStringGetNodeList(doc as *const xmlDoc, value);
        let fresh65 = unsafe { &mut ((*cur).last) };
        *fresh65 = 0 as *mut _xmlNode;
        tmp = unsafe { (*cur).children };
        while !tmp.is_null() {
            let fresh66 = unsafe { &mut ((*tmp).parent) };
            *fresh66 = cur as xmlNodePtr;
            if (unsafe { (*tmp).next }).is_null() {
                let fresh67 = unsafe { &mut ((*cur).last) };
                *fresh67 = tmp;
            }
            tmp = unsafe { (*tmp).next };
        }
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlFreePropList(mut cur: *mut crate::src::threads::_xmlAttr) {
    let mut next: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return;
    }
    while !cur.is_null() {
        next = unsafe { (*cur).next };
        xmlFreeProp(cur);
        cur = next;
    }
}
#[no_mangle]
pub extern "C" fn xmlFreeProp(mut cur: *mut crate::src::threads::_xmlAttr) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if !(unsafe { (*cur).doc }).is_null() {
        dict = unsafe { (*(*cur).doc).dict };
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() })
    {
        (unsafe {
            (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(
                cur as xmlNodePtr,
            )
        });
    }
    if !(unsafe { (*cur).doc }).is_null()
        && (unsafe { (*cur).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32
    {
        xmlRemoveID(unsafe { (*cur).doc }, cur);
    }
    if !(unsafe { (*cur).children }).is_null() {
        xmlFreeNodeList(unsafe { (*cur).children });
    }
    if !(unsafe { (*cur).name }).is_null()
        && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*cur).name as *mut i8 as *mut libc::c_void)
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlRemoveProp(mut cur: *mut crate::src::threads::_xmlAttr) -> i32 {
    let mut tmp: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*cur).parent }).is_null() {
        return -(1 as i32);
    }
    tmp = unsafe { (*(*cur).parent).properties };
    if tmp == cur {
        let fresh68 = unsafe { &mut ((*(*cur).parent).properties) };
        *fresh68 = unsafe { (*cur).next };
        if !(unsafe { (*cur).next }).is_null() {
            let fresh69 = unsafe { &mut ((*(*cur).next).prev) };
            *fresh69 = 0 as *mut _xmlAttr;
        }
        xmlFreeProp(cur);
        return 0 as i32;
    }
    while !tmp.is_null() {
        if (unsafe { (*tmp).next }) == cur {
            let fresh70 = unsafe { &mut ((*tmp).next) };
            *fresh70 = unsafe { (*cur).next };
            if !(unsafe { (*tmp).next }).is_null() {
                let fresh71 = unsafe { &mut ((*(*tmp).next).prev) };
                *fresh71 = tmp;
            }
            xmlFreeProp(cur);
            return 0 as i32;
        }
        tmp = unsafe { (*tmp).next };
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNewDocPI(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building PI\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_PI_NODE });
    if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
        let fresh72 = unsafe { &mut ((*cur).name) };
        *fresh72 = unsafe { xmlDictLookup((*doc).dict, name, -(1 as i32)) };
    } else {
        let fresh73 = unsafe { &mut ((*cur).name) };
        *fresh73 = xmlStrdup(name);
    }
    if !content.is_null() {
        let fresh74 = unsafe { &mut ((*cur).content) };
        *fresh74 = xmlStrdup(content);
    }
    let fresh75 = unsafe { &mut ((*cur).doc) };
    *fresh75 = doc;
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewPI(
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    return xmlNewDocPI(0 as xmlDocPtr, name, content);
}
#[no_mangle]
pub extern "C" fn xmlNewNode(
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building node\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ELEMENT_NODE });
    let fresh76 = unsafe { &mut ((*cur).name) };
    *fresh76 = xmlStrdup(name);
    let fresh77 = unsafe { &mut ((*cur).ns) };
    *fresh77 = ns;
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewNodeEatName(
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *mut u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building node\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ELEMENT_NODE });
    let fresh78 = unsafe { &mut ((*cur).name) };
    *fresh78 = name;
    let fresh79 = unsafe { &mut ((*cur).ns) };
    *fresh79 = ns;
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocNode(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
        cur = xmlNewNodeEatName(
            ns,
            (unsafe { xmlDictLookup((*doc).dict, name, -(1 as i32)) }) as *mut xmlChar,
        );
    } else {
        cur = xmlNewNode(ns, name);
    }
    if !cur.is_null() {
        let fresh80 = unsafe { &mut ((*cur).doc) };
        *fresh80 = doc;
        if !content.is_null() {
            let fresh81 = unsafe { &mut ((*cur).children) };
            *fresh81 = xmlStringGetNodeList(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
                if ulccur.is_null() {
                    let fresh82 = unsafe { &mut ((*cur).last) };
                    *fresh82 = 0 as *mut _xmlNode;
                } else {
                    while !(unsafe { (*ulccur).next }).is_null() {
                        let fresh83 = unsafe { &mut ((*ulccur).parent) };
                        *fresh83 = cur;
                        ulccur = unsafe { (*ulccur).next };
                    }
                    let fresh84 = unsafe { &mut ((*ulccur).parent) };
                    *fresh84 = cur;
                    let fresh85 = unsafe { &mut ((*cur).last) };
                    *fresh85 = ulccur;
                }
            }
        }
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocNodeEatName(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *mut u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = xmlNewNodeEatName(ns, name);
    if !cur.is_null() {
        let fresh86 = unsafe { &mut ((*cur).doc) };
        *fresh86 = doc;
        if !content.is_null() {
            let fresh87 = unsafe { &mut ((*cur).children) };
            *fresh87 = xmlStringGetNodeList(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
                if ulccur.is_null() {
                    let fresh88 = unsafe { &mut ((*cur).last) };
                    *fresh88 = 0 as *mut _xmlNode;
                } else {
                    while !(unsafe { (*ulccur).next }).is_null() {
                        let fresh89 = unsafe { &mut ((*ulccur).parent) };
                        *fresh89 = cur;
                        ulccur = unsafe { (*ulccur).next };
                    }
                    let fresh90 = unsafe { &mut ((*ulccur).parent) };
                    *fresh90 = cur;
                    let fresh91 = unsafe { &mut ((*cur).last) };
                    *fresh91 = ulccur;
                }
            }
        }
    } else if !name.is_null() && !doc.is_null() && (unsafe { xmlDictOwns((*doc).dict, name) }) == 0
    {
        (unsafe { xmlFree.expect("non-null function pointer")(name as *mut libc::c_void) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocRawNode(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = xmlNewDocNode(doc, ns, name, 0 as *const xmlChar);
    if !cur.is_null() {
        let fresh92 = unsafe { &mut ((*cur).doc) };
        *fresh92 = doc;
        if !content.is_null() {
            let fresh93 = unsafe { &mut ((*cur).children) };
            *fresh93 = xmlNewDocText(doc as *const xmlDoc, content);
            if !cur.is_null() {
                let mut ulccur: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
                if ulccur.is_null() {
                    let fresh94 = unsafe { &mut ((*cur).last) };
                    *fresh94 = 0 as *mut _xmlNode;
                } else {
                    while !(unsafe { (*ulccur).next }).is_null() {
                        let fresh95 = unsafe { &mut ((*ulccur).parent) };
                        *fresh95 = cur;
                        ulccur = unsafe { (*ulccur).next };
                    }
                    let fresh96 = unsafe { &mut ((*ulccur).parent) };
                    *fresh96 = cur;
                    let fresh97 = unsafe { &mut ((*cur).last) };
                    *fresh97 = ulccur;
                }
            }
        }
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocFragment(
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building fragment\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_DOCUMENT_FRAG_NODE });
    let fresh98 = unsafe { &mut ((*cur).doc) };
    *fresh98 = doc;
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewText(mut content: *const u8) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building text\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_TEXT_NODE });
    let fresh99 = unsafe { &mut ((*cur).name) };
    *fresh99 = unsafe { xmlStringText.as_ptr() };
    if !content.is_null() {
        let fresh100 = unsafe { &mut ((*cur).content) };
        *fresh100 = xmlStrdup(content);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewTextChild(
    mut parent: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        if ns.is_null() {
            cur = xmlNewDocRawNode(
                unsafe { (*parent).doc },
                unsafe { (*parent).ns },
                name,
                content,
            );
        } else {
            cur = xmlNewDocRawNode(unsafe { (*parent).doc }, ns, name, content);
        }
    } else if (unsafe { (*parent).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (unsafe { (*parent).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        if ns.is_null() {
            cur = xmlNewDocRawNode(parent as xmlDocPtr, 0 as xmlNsPtr, name, content);
        } else {
            cur = xmlNewDocRawNode(parent as xmlDocPtr, ns, name, content);
        }
    } else if (unsafe { (*parent).type_0 }) as u32 == XML_DOCUMENT_FRAG_NODE as i32 as u32 {
        cur = xmlNewDocRawNode(unsafe { (*parent).doc }, ns, name, content);
    } else {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    (unsafe { (*cur).type_0 = XML_ELEMENT_NODE });
    let fresh101 = unsafe { &mut ((*cur).parent) };
    *fresh101 = parent;
    let fresh102 = unsafe { &mut ((*cur).doc) };
    *fresh102 = unsafe { (*parent).doc };
    if (unsafe { (*parent).children }).is_null() {
        let fresh103 = unsafe { &mut ((*parent).children) };
        *fresh103 = cur;
        let fresh104 = unsafe { &mut ((*parent).last) };
        *fresh104 = cur;
    } else {
        prev = unsafe { (*parent).last };
        let fresh105 = unsafe { &mut ((*prev).next) };
        *fresh105 = cur;
        let fresh106 = unsafe { &mut ((*cur).prev) };
        *fresh106 = prev;
        let fresh107 = unsafe { &mut ((*parent).last) };
        *fresh107 = cur;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewCharRef(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building character reference\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ENTITY_REF_NODE });
    let fresh108 = unsafe { &mut ((*cur).doc) };
    *fresh108 = doc;
    if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == '&' as i32 {
        let mut len: i32 = 0;
        name = unsafe { name.offset(1) };
        len = xmlStrlen(name);
        if (unsafe { *name.offset((len - 1 as i32) as isize) }) as i32 == ';' as i32 {
            let fresh109 = unsafe { &mut ((*cur).name) };
            *fresh109 = xmlStrndup(name, len - 1 as i32);
        } else {
            let fresh110 = unsafe { &mut ((*cur).name) };
            *fresh110 = xmlStrndup(name, len);
        }
    } else {
        let fresh111 = unsafe { &mut ((*cur).name) };
        *fresh111 = xmlStrdup(name);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewReference(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building reference\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_ENTITY_REF_NODE });
    let fresh112 = unsafe { &mut ((*cur).doc) };
    *fresh112 = doc as *mut xmlDoc;
    if (unsafe { *name.offset(0 as i32 as isize) }) as i32 == '&' as i32 {
        let mut len: i32 = 0;
        name = unsafe { name.offset(1) };
        len = xmlStrlen(name);
        if (unsafe { *name.offset((len - 1 as i32) as isize) }) as i32 == ';' as i32 {
            let fresh113 = unsafe { &mut ((*cur).name) };
            *fresh113 = xmlStrndup(name, len - 1 as i32);
        } else {
            let fresh114 = unsafe { &mut ((*cur).name) };
            *fresh114 = xmlStrndup(name, len);
        }
    } else {
        let fresh115 = unsafe { &mut ((*cur).name) };
        *fresh115 = xmlStrdup(name);
    }
    ent = unsafe { xmlGetDocEntity(doc, (*cur).name) };
    if !ent.is_null() {
        let fresh116 = unsafe { &mut ((*cur).content) };
        *fresh116 = unsafe { (*ent).content };
        let fresh117 = unsafe { &mut ((*cur).children) };
        *fresh117 = ent as xmlNodePtr;
        let fresh118 = unsafe { &mut ((*cur).last) };
        *fresh118 = ent as xmlNodePtr;
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocText(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = xmlNewText(content);
    if !cur.is_null() {
        let fresh119 = unsafe { &mut ((*cur).doc) };
        *fresh119 = doc as *mut xmlDoc;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewTextLen(
    mut content: *const u8,
    mut len: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building text\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_TEXT_NODE });
    let fresh120 = unsafe { &mut ((*cur).name) };
    *fresh120 = unsafe { xmlStringText.as_ptr() };
    if !content.is_null() {
        let fresh121 = unsafe { &mut ((*cur).content) };
        *fresh121 = xmlStrndup(content, len);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocTextLen(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut content: *const u8,
    mut len: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = xmlNewTextLen(content, len);
    if !cur.is_null() {
        let fresh122 = unsafe { &mut ((*cur).doc) };
        *fresh122 = doc;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewComment(mut content: *const u8) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building comment\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_COMMENT_NODE });
    let fresh123 = unsafe { &mut ((*cur).name) };
    *fresh123 = unsafe { xmlStringComment.as_ptr() };
    if !content.is_null() {
        let fresh124 = unsafe { &mut ((*cur).content) };
        *fresh124 = xmlStrdup(content);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewCDataBlock(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut content: *const u8,
    mut len: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if cur.is_null() {
        xmlTreeErrMemory(b"building CDATA\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            cur as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*cur).type_0 = XML_CDATA_SECTION_NODE });
    let fresh125 = unsafe { &mut ((*cur).doc) };
    *fresh125 = doc;
    if !content.is_null() {
        let fresh126 = unsafe { &mut ((*cur).content) };
        *fresh126 = xmlStrndup(content, len);
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlNewDocComment(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    cur = xmlNewComment(content);
    if !cur.is_null() {
        let fresh127 = unsafe { &mut ((*cur).doc) };
        *fresh127 = doc;
    }
    return cur;
}
extern "C" fn _copyStringForNewDictIfNeeded(
    mut oldDict: *mut crate::src::xpointer::_xmlDict,
    mut newDict: *mut crate::src::xpointer::_xmlDict,
    mut oldValue: *const u8,
) -> *const u8 {
    let mut newValue: *const u8 = oldValue;
    if !oldValue.is_null() {
        let mut oldDictOwnsOldValue: i32 =
            (!oldDict.is_null() && (unsafe { xmlDictOwns(oldDict, oldValue) }) == 1 as i32) as i32;
        if oldDictOwnsOldValue != 0 {
            if !newDict.is_null() {
                newValue = unsafe { xmlDictLookup(newDict, oldValue, -(1 as i32)) };
            } else {
                newValue = xmlStrdup(oldValue);
            }
        }
    }
    return newValue;
}
#[no_mangle]
pub extern "C" fn xmlSetTreeDoc(
    mut tree: *mut crate::src::threads::_xmlNode,
    mut doc: *mut crate::src::threads::_xmlDoc,
) {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if tree.is_null() || (unsafe { (*tree).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return;
    }
    if (unsafe { (*tree).doc }) != doc {
        let mut oldTreeDict: *mut crate::src::xpointer::_xmlDict =
            if !(unsafe { (*tree).doc }).is_null() {
                unsafe { (*(*tree).doc).dict }
            } else {
                0 as *mut _xmlDict
            };
        let mut newDict: *mut crate::src::xpointer::_xmlDict = if !doc.is_null() {
            unsafe { (*doc).dict }
        } else {
            0 as *mut _xmlDict
        };
        if (unsafe { (*tree).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            prop = unsafe { (*tree).properties };
            while !prop.is_null() {
                if (unsafe { (*prop).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
                    xmlRemoveID(unsafe { (*tree).doc }, prop);
                }
                if (unsafe { (*prop).doc }) != doc {
                    let mut oldPropDict: *mut crate::src::xpointer::_xmlDict =
                        if !(unsafe { (*prop).doc }).is_null() {
                            unsafe { (*(*prop).doc).dict }
                        } else {
                            0 as *mut _xmlDict
                        };
                    let fresh128 = unsafe { &mut ((*prop).name) };
                    *fresh128 = _copyStringForNewDictIfNeeded(
                        oldPropDict,
                        newDict,
                        unsafe { (*prop).name },
                    );
                    let fresh129 = unsafe { &mut ((*prop).doc) };
                    *fresh129 = doc;
                }
                xmlSetListDoc(unsafe { (*prop).children }, doc);
                prop = unsafe { (*prop).next };
            }
        }
        if (unsafe { (*tree).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
            let fresh130 = unsafe { &mut ((*tree).children) };
            *fresh130 = 0 as *mut _xmlNode;
        } else if !(unsafe { (*tree).children }).is_null() {
            xmlSetListDoc(unsafe { (*tree).children }, doc);
        }
        let fresh131 = unsafe { &mut ((*tree).name) };
        *fresh131 = _copyStringForNewDictIfNeeded(oldTreeDict, newDict, unsafe { (*tree).name });
        let fresh132 = unsafe { &mut ((*tree).content) };
        *fresh132 = _copyStringForNewDictIfNeeded(
            oldTreeDict,
            0 as xmlDictPtr,
            unsafe { (*tree).content },
        ) as *mut xmlChar;
        let fresh133 = unsafe { &mut ((*tree).doc) };
        *fresh133 = doc;
    }
}
#[no_mangle]
pub extern "C" fn xmlSetListDoc(
    mut list: *mut crate::src::threads::_xmlNode,
    mut doc: *mut crate::src::threads::_xmlDoc,
) {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if list.is_null() || (unsafe { (*list).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return;
    }
    cur = list;
    while !cur.is_null() {
        if (unsafe { (*cur).doc }) != doc {
            xmlSetTreeDoc(cur, doc);
        }
        cur = unsafe { (*cur).next };
    }
}
#[no_mangle]
pub extern "C" fn xmlNewChild(
    mut parent: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut content: *const u8,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if parent.is_null() {
        return 0 as xmlNodePtr;
    }
    if name.is_null() {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        if ns.is_null() {
            cur = xmlNewDocNode(
                unsafe { (*parent).doc },
                unsafe { (*parent).ns },
                name,
                content,
            );
        } else {
            cur = xmlNewDocNode(unsafe { (*parent).doc }, ns, name, content);
        }
    } else if (unsafe { (*parent).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
        || (unsafe { (*parent).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
    {
        if ns.is_null() {
            cur = xmlNewDocNode(parent as xmlDocPtr, 0 as xmlNsPtr, name, content);
        } else {
            cur = xmlNewDocNode(parent as xmlDocPtr, ns, name, content);
        }
    } else if (unsafe { (*parent).type_0 }) as u32 == XML_DOCUMENT_FRAG_NODE as i32 as u32 {
        cur = xmlNewDocNode(unsafe { (*parent).doc }, ns, name, content);
    } else {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() {
        return 0 as xmlNodePtr;
    }
    (unsafe { (*cur).type_0 = XML_ELEMENT_NODE });
    let fresh134 = unsafe { &mut ((*cur).parent) };
    *fresh134 = parent;
    let fresh135 = unsafe { &mut ((*cur).doc) };
    *fresh135 = unsafe { (*parent).doc };
    if (unsafe { (*parent).children }).is_null() {
        let fresh136 = unsafe { &mut ((*parent).children) };
        *fresh136 = cur;
        let fresh137 = unsafe { &mut ((*parent).last) };
        *fresh137 = cur;
    } else {
        prev = unsafe { (*parent).last };
        let fresh138 = unsafe { &mut ((*prev).next) };
        *fresh138 = cur;
        let fresh139 = unsafe { &mut ((*cur).prev) };
        *fresh139 = prev;
        let fresh140 = unsafe { &mut ((*parent).last) };
        *fresh140 = cur;
    }
    return cur;
}
extern "C" fn xmlAddPropSibling(
    mut prev: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlNode,
    mut prop: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut attr: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if cur.is_null()
        || (unsafe { (*cur).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
        || prop.is_null()
        || (unsafe { (*prop).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
        || !prev.is_null() && (unsafe { (*prev).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*prop).ns }).is_null() {
        attr = xmlHasNsProp(
            unsafe { (*cur).parent },
            unsafe { (*prop).name },
            0 as *const xmlChar,
        );
    } else {
        attr = xmlHasNsProp(
            unsafe { (*cur).parent },
            unsafe { (*prop).name },
            unsafe { (*(*prop).ns).href },
        );
    }
    if (unsafe { (*prop).doc }) != (unsafe { (*cur).doc }) {
        xmlSetTreeDoc(prop, unsafe { (*cur).doc });
    }
    let fresh141 = unsafe { &mut ((*prop).parent) };
    *fresh141 = unsafe { (*cur).parent };
    let fresh142 = unsafe { &mut ((*prop).prev) };
    *fresh142 = prev;
    if !prev.is_null() {
        let fresh143 = unsafe { &mut ((*prop).next) };
        *fresh143 = unsafe { (*prev).next };
        let fresh144 = unsafe { &mut ((*prev).next) };
        *fresh144 = prop;
        if !(unsafe { (*prop).next }).is_null() {
            let fresh145 = unsafe { &mut ((*(*prop).next).prev) };
            *fresh145 = prop;
        }
    } else {
        let fresh146 = unsafe { &mut ((*prop).next) };
        *fresh146 = cur;
        let fresh147 = unsafe { &mut ((*cur).prev) };
        *fresh147 = prop;
    }
    if (unsafe { (*prop).prev }).is_null() && !(unsafe { (*prop).parent }).is_null() {
        let fresh148 = unsafe { &mut ((*(*prop).parent).properties) };
        *fresh148 = prop as xmlAttrPtr;
    }
    if !attr.is_null() && (unsafe { (*attr).type_0 }) as u32 != XML_ATTRIBUTE_DECL as i32 as u32 {
        xmlRemoveProp(attr);
    }
    return prop;
}
#[no_mangle]
pub extern "C" fn xmlAddNextSibling(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if elem.is_null() || (unsafe { (*elem).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(elem);
    if (unsafe { (*elem).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
        if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
            xmlNodeAddContent(cur, unsafe { (*elem).content });
            xmlFreeNode(elem);
            return cur;
        }
        if !(unsafe { (*cur).next }).is_null()
            && (unsafe { (*(*cur).next).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && (unsafe { (*cur).name }) == (unsafe { (*(*cur).next).name })
        {
            let mut tmp: *mut u8 = 0 as *mut xmlChar;
            tmp = xmlStrdup(unsafe { (*elem).content });
            tmp = xmlStrcat(tmp, unsafe { (*(*cur).next).content });
            xmlNodeSetContent(unsafe { (*cur).next }, tmp);
            (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            xmlFreeNode(elem);
            return unsafe { (*cur).next };
        }
    } else if (unsafe { (*elem).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        return xmlAddPropSibling(cur, cur, elem);
    }
    if (unsafe { (*elem).doc }) != (unsafe { (*cur).doc }) {
        xmlSetTreeDoc(elem, unsafe { (*cur).doc });
    }
    let fresh149 = unsafe { &mut ((*elem).parent) };
    *fresh149 = unsafe { (*cur).parent };
    let fresh150 = unsafe { &mut ((*elem).prev) };
    *fresh150 = cur;
    let fresh151 = unsafe { &mut ((*elem).next) };
    *fresh151 = unsafe { (*cur).next };
    let fresh152 = unsafe { &mut ((*cur).next) };
    *fresh152 = elem;
    if !(unsafe { (*elem).next }).is_null() {
        let fresh153 = unsafe { &mut ((*(*elem).next).prev) };
        *fresh153 = elem;
    }
    if !(unsafe { (*elem).parent }).is_null() && (unsafe { (*(*elem).parent).last }) == cur {
        let fresh154 = unsafe { &mut ((*(*elem).parent).last) };
        *fresh154 = elem;
    }
    return elem;
}
#[no_mangle]
pub extern "C" fn xmlAddPrevSibling(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if elem.is_null() || (unsafe { (*elem).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(elem);
    if (unsafe { (*elem).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
        if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
            let mut tmp: *mut u8 = 0 as *mut xmlChar;
            tmp = xmlStrdup(unsafe { (*elem).content });
            tmp = xmlStrcat(tmp, unsafe { (*cur).content });
            xmlNodeSetContent(cur, tmp);
            (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
            xmlFreeNode(elem);
            return cur;
        }
        if !(unsafe { (*cur).prev }).is_null()
            && (unsafe { (*(*cur).prev).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && (unsafe { (*cur).name }) == (unsafe { (*(*cur).prev).name })
        {
            xmlNodeAddContent(unsafe { (*cur).prev }, unsafe { (*elem).content });
            xmlFreeNode(elem);
            return unsafe { (*cur).prev };
        }
    } else if (unsafe { (*elem).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        return xmlAddPropSibling(unsafe { (*cur).prev }, cur, elem);
    }
    if (unsafe { (*elem).doc }) != (unsafe { (*cur).doc }) {
        xmlSetTreeDoc(elem, unsafe { (*cur).doc });
    }
    let fresh155 = unsafe { &mut ((*elem).parent) };
    *fresh155 = unsafe { (*cur).parent };
    let fresh156 = unsafe { &mut ((*elem).next) };
    *fresh156 = cur;
    let fresh157 = unsafe { &mut ((*elem).prev) };
    *fresh157 = unsafe { (*cur).prev };
    let fresh158 = unsafe { &mut ((*cur).prev) };
    *fresh158 = elem;
    if !(unsafe { (*elem).prev }).is_null() {
        let fresh159 = unsafe { &mut ((*(*elem).prev).next) };
        *fresh159 = elem;
    }
    if !(unsafe { (*elem).parent }).is_null() && (unsafe { (*(*elem).parent).children }) == cur {
        let fresh160 = unsafe { &mut ((*(*elem).parent).children) };
        *fresh160 = elem;
    }
    return elem;
}
#[no_mangle]
pub extern "C" fn xmlAddSibling(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut elem: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut parent: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if elem.is_null() || (unsafe { (*elem).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if cur == elem {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*cur).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
        && !(unsafe { (*cur).parent }).is_null()
        && !(unsafe { (*(*cur).parent).children }).is_null()
        && !(unsafe { (*(*cur).parent).last }).is_null()
        && (unsafe { (*(*(*cur).parent).last).next }).is_null()
    {
        cur = unsafe { (*(*cur).parent).last };
    } else {
        while !(unsafe { (*cur).next }).is_null() {
            cur = unsafe { (*cur).next };
        }
    }
    xmlUnlinkNode(elem);
    if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
        && (unsafe { (*elem).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
        && (unsafe { (*cur).name }) == (unsafe { (*elem).name })
    {
        xmlNodeAddContent(cur, unsafe { (*elem).content });
        xmlFreeNode(elem);
        return cur;
    } else {
        if (unsafe { (*elem).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            return xmlAddPropSibling(cur, cur, elem);
        }
    }
    if (unsafe { (*elem).doc }) != (unsafe { (*cur).doc }) {
        xmlSetTreeDoc(elem, unsafe { (*cur).doc });
    }
    parent = unsafe { (*cur).parent };
    let fresh161 = unsafe { &mut ((*elem).prev) };
    *fresh161 = cur;
    let fresh162 = unsafe { &mut ((*elem).next) };
    *fresh162 = 0 as *mut _xmlNode;
    let fresh163 = unsafe { &mut ((*elem).parent) };
    *fresh163 = parent;
    let fresh164 = unsafe { &mut ((*cur).next) };
    *fresh164 = elem;
    if !parent.is_null() {
        let fresh165 = unsafe { &mut ((*parent).last) };
        *fresh165 = elem;
    }
    return elem;
}
#[no_mangle]
pub extern "C" fn xmlAddChildList(
    mut parent: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if parent.is_null() || (unsafe { (*parent).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    let _ = !(unsafe { (*cur).doc }).is_null()
        && !(unsafe { (*parent).doc }).is_null()
        && (unsafe { (*cur).doc }) != (unsafe { (*parent).doc });
    if (unsafe { (*parent).children }).is_null() {
        let fresh166 = unsafe { &mut ((*parent).children) };
        *fresh166 = cur;
    } else {
        if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && (unsafe { (*(*parent).last).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && (unsafe { (*cur).name }) == (unsafe { (*(*parent).last).name })
        {
            xmlNodeAddContent(unsafe { (*parent).last }, unsafe { (*cur).content });
            if (unsafe { (*cur).next }).is_null() {
                xmlFreeNode(cur);
                return unsafe { (*parent).last };
            }
            prev = cur;
            cur = unsafe { (*cur).next };
            xmlFreeNode(prev);
        }
        prev = unsafe { (*parent).last };
        let fresh167 = unsafe { &mut ((*prev).next) };
        *fresh167 = cur;
        let fresh168 = unsafe { &mut ((*cur).prev) };
        *fresh168 = prev;
    }
    while !(unsafe { (*cur).next }).is_null() {
        let fresh169 = unsafe { &mut ((*cur).parent) };
        *fresh169 = parent;
        if (unsafe { (*cur).doc }) != (unsafe { (*parent).doc }) {
            xmlSetTreeDoc(cur, unsafe { (*parent).doc });
        }
        cur = unsafe { (*cur).next };
    }
    let fresh170 = unsafe { &mut ((*cur).parent) };
    *fresh170 = parent;
    if (unsafe { (*cur).doc }) != (unsafe { (*parent).doc }) {
        xmlSetTreeDoc(cur, unsafe { (*parent).doc });
    }
    let fresh171 = unsafe { &mut ((*parent).last) };
    *fresh171 = cur;
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlAddChild(
    mut parent: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut prev: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if parent.is_null() || (unsafe { (*parent).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    if parent == cur {
        return 0 as xmlNodePtr;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
        if (unsafe { (*parent).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && !(unsafe { (*parent).content }).is_null()
            && (unsafe { (*parent).name }) == (unsafe { (*cur).name })
        {
            xmlNodeAddContent(parent, unsafe { (*cur).content });
            xmlFreeNode(cur);
            return parent;
        }
        if !(unsafe { (*parent).last }).is_null()
            && (unsafe { (*(*parent).last).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            && (unsafe { (*(*parent).last).name }) == (unsafe { (*cur).name })
            && (unsafe { (*parent).last }) != cur
        {
            xmlNodeAddContent(unsafe { (*parent).last }, unsafe { (*cur).content });
            xmlFreeNode(cur);
            return unsafe { (*parent).last };
        }
    }
    prev = unsafe { (*cur).parent };
    let fresh172 = unsafe { &mut ((*cur).parent) };
    *fresh172 = parent;
    if (unsafe { (*cur).doc }) != (unsafe { (*parent).doc }) {
        xmlSetTreeDoc(cur, unsafe { (*parent).doc });
    }
    if prev == parent {
        return cur;
    }
    if (unsafe { (*parent).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
        && !(unsafe { (*parent).content }).is_null()
        && parent != cur
    {
        xmlNodeAddContent(parent, unsafe { (*cur).content });
        xmlFreeNode(cur);
        return parent;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        if (unsafe { (*parent).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
            return 0 as xmlNodePtr;
        }
        if !(unsafe { (*parent).properties }).is_null() {
            let mut lastattr: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
            if (unsafe { (*cur).ns }).is_null() {
                lastattr = xmlHasNsProp(
                    parent as *const xmlNode,
                    unsafe { (*cur).name },
                    0 as *const xmlChar,
                );
            } else {
                lastattr = xmlHasNsProp(
                    parent as *const xmlNode,
                    unsafe { (*cur).name },
                    unsafe { (*(*cur).ns).href },
                );
            }
            if !lastattr.is_null()
                && lastattr != cur as xmlAttrPtr
                && (unsafe { (*lastattr).type_0 }) as u32 != XML_ATTRIBUTE_DECL as i32 as u32
            {
                xmlUnlinkNode(lastattr as xmlNodePtr);
                xmlFreeProp(lastattr);
            }
            if lastattr == cur as xmlAttrPtr {
                return cur;
            }
        }
        if (unsafe { (*parent).properties }).is_null() {
            let fresh173 = unsafe { &mut ((*parent).properties) };
            *fresh173 = cur as xmlAttrPtr;
        } else {
            let mut lastattr_0: *mut crate::src::threads::_xmlAttr =
                unsafe { (*parent).properties };
            while !(unsafe { (*lastattr_0).next }).is_null() {
                lastattr_0 = unsafe { (*lastattr_0).next };
            }
            let fresh174 = unsafe { &mut ((*lastattr_0).next) };
            *fresh174 = cur as xmlAttrPtr;
            let fresh175 = unsafe { &mut ((*(cur as xmlAttrPtr)).prev) };
            *fresh175 = lastattr_0;
        }
    } else if (unsafe { (*parent).children }).is_null() {
        let fresh176 = unsafe { &mut ((*parent).children) };
        *fresh176 = cur;
        let fresh177 = unsafe { &mut ((*parent).last) };
        *fresh177 = cur;
    } else {
        prev = unsafe { (*parent).last };
        let fresh178 = unsafe { &mut ((*prev).next) };
        *fresh178 = cur;
        let fresh179 = unsafe { &mut ((*cur).prev) };
        *fresh179 = prev;
        let fresh180 = unsafe { &mut ((*parent).last) };
        *fresh180 = cur;
    }
    return cur;
}
#[no_mangle]
pub extern "C" fn xmlGetLastChild<'a1>(
    mut parent: Option<&'a1 crate::src::threads::_xmlNode>,
) -> *mut crate::src::threads::_xmlNode {
    if (parent).clone().is_none()
        || (*((parent).clone()).unwrap()).type_0 as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return 0 as xmlNodePtr;
    }
    return (*((parent).clone()).unwrap()).last;
}
#[no_mangle]
pub extern "C" fn xmlChildElementCount<'a1>(
    mut parent: Option<&'a1 mut crate::src::threads::_xmlNode>,
) -> u64 {
    let mut ret: u64 = 0 as i32 as u64;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    if borrow(&parent).is_none() {
        return 0 as i32 as u64;
    }
    match (*(borrow(&parent)).unwrap()).type_0 as u32 {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*(borrow_mut(&mut parent)).unwrap()).children;
        }
        _ => return 0 as i32 as u64,
    }
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            ret = ret.wrapping_add(1);
        }
        cur = unsafe { (*cur).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlFirstElementChild<'a1>(
    mut parent: Option<&'a1 mut crate::src::threads::_xmlNode>,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    if borrow(&parent).is_none() {
        return 0 as xmlNodePtr;
    }
    match (*(borrow(&parent)).unwrap()).type_0 as u32 {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*(borrow_mut(&mut parent)).unwrap()).children;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return cur;
        }
        cur = unsafe { (*cur).next };
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlLastElementChild<'a1>(
    mut parent: Option<&'a1 mut crate::src::threads::_xmlNode>,
) -> *mut crate::src::threads::_xmlNode {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    if borrow(&parent).is_none() {
        return 0 as xmlNodePtr;
    }
    match (*(borrow(&parent)).unwrap()).type_0 as u32 {
        1 | 6 | 9 | 11 | 13 => {
            cur = (*(borrow_mut(&mut parent)).unwrap()).last;
        }
        _ => return 0 as xmlNodePtr,
    }
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return cur;
        }
        cur = unsafe { (*cur).prev };
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlPreviousElementSibling(
    mut node: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 19 | 20 => {
            node = unsafe { (*node).prev };
        }
        _ => return 0 as xmlNodePtr,
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return node;
        }
        node = unsafe { (*node).prev };
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlNextElementSibling(
    mut node: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 3 | 4 | 5 | 6 | 7 | 8 | 14 | 19 | 20 => {
            node = unsafe { (*node).next };
        }
        _ => return 0 as xmlNodePtr,
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return node;
        }
        node = unsafe { (*node).next };
    }
    return 0 as xmlNodePtr;
}
#[no_mangle]
pub extern "C" fn xmlFreeNodeList(mut cur: *mut crate::src::threads::_xmlNode) {
    let mut next: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut parent: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    let mut depth: u64 = 0 as i32 as size_t;
    if cur.is_null() {
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        xmlFreeNsList(cur as xmlNsPtr);
        return;
    }
    if !(unsafe { (*cur).doc }).is_null() {
        dict = unsafe { (*(*cur).doc).dict };
    }
    loop {
        while !(unsafe { (*cur).children }).is_null()
            && (unsafe { (*cur).type_0 }) as u32 != XML_DOCUMENT_NODE as i32 as u32
            && (unsafe { (*cur).type_0 }) as u32 != XML_HTML_DOCUMENT_NODE as i32 as u32
            && (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32
            && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
        {
            cur = unsafe { (*cur).children };
            depth = (depth as u64).wrapping_add(1 as i32 as u64) as size_t as size_t;
        }
        next = unsafe { (*cur).next };
        parent = unsafe { (*cur).parent };
        if (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
            || (unsafe { (*cur).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            xmlFreeDoc(cur as xmlDocPtr);
        } else if (unsafe { (*cur).type_0 }) as u32 != XML_DTD_NODE as i32 as u32 {
            if (unsafe { __xmlRegisterCallbacks }) != 0
                && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() })
            {
                (unsafe {
                    (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur)
                });
            }
            if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
                && !(unsafe { (*cur).properties }).is_null()
            {
                xmlFreePropList(unsafe { (*cur).properties });
            }
            if (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_XINCLUDE_END as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
                && (unsafe { (*cur).content })
                    != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !(unsafe { (*cur).content }).is_null()
                    && (dict.is_null()
                        || (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) })
                            == 0 as i32)
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*cur).content as *mut i8 as *mut libc::c_void,
                        )
                    });
                }
            }
            if ((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32)
                && !(unsafe { (*cur).nsDef }).is_null()
            {
                xmlFreeNsList(unsafe { (*cur).nsDef });
            }
            if !(unsafe { (*cur).name }).is_null()
                && (unsafe { (*cur).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
                && (unsafe { (*cur).type_0 }) as u32 != XML_COMMENT_NODE as i32 as u32
            {
                if !(unsafe { (*cur).name }).is_null()
                    && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*cur).name as *mut i8 as *mut libc::c_void,
                        )
                    });
                }
            }
            (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
        }
        if !next.is_null() {
            cur = next;
        } else {
            if depth == 0 as i32 as u64 || parent.is_null() {
                break;
            }
            depth = (depth as u64).wrapping_sub(1 as i32 as u64) as size_t as size_t;
            cur = parent;
            let fresh181 = unsafe { &mut ((*cur).children) };
            *fresh181 = 0 as *mut _xmlNode;
        }
    }
}
#[no_mangle]
pub extern "C" fn xmlFreeNode(mut cur: *mut crate::src::threads::_xmlNode) {
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as xmlDictPtr;
    if cur.is_null() {
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        xmlFreeDtd(cur as xmlDtdPtr);
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        xmlFreeNs(cur as xmlNsPtr);
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        xmlFreeProp(cur as xmlAttrPtr);
        return;
    }
    if (unsafe { __xmlRegisterCallbacks }) != 0
        && (unsafe { (*__xmlDeregisterNodeDefaultValue()).is_some() })
    {
        (unsafe { (*__xmlDeregisterNodeDefaultValue()).expect("non-null function pointer")(cur) });
    }
    if !(unsafe { (*cur).doc }).is_null() {
        dict = unsafe { (*(*cur).doc).dict };
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32 {
        let mut ent: *mut crate::src::threads::_xmlEntity = cur as xmlEntityPtr;
        if !(unsafe { (*ent).SystemID }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ent).SystemID) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*ent).SystemID as *mut i8 as *mut libc::c_void,
                )
            });
        }
        if !(unsafe { (*ent).ExternalID }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*ent).ExternalID) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*ent).ExternalID as *mut i8 as *mut libc::c_void,
                )
            });
        }
    }
    if !(unsafe { (*cur).children }).is_null()
        && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
    {
        xmlFreeNodeList(unsafe { (*cur).children });
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
    {
        if !(unsafe { (*cur).properties }).is_null() {
            xmlFreePropList(unsafe { (*cur).properties });
        }
        if !(unsafe { (*cur).nsDef }).is_null() {
            xmlFreeNsList(unsafe { (*cur).nsDef });
        }
    } else if !(unsafe { (*cur).content }).is_null()
        && (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
        && (unsafe { (*cur).content })
            != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
    {
        if !(unsafe { (*cur).content }).is_null()
            && (dict.is_null()
                || (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*cur).content as *mut i8 as *mut libc::c_void,
                )
            });
        }
    }
    if !(unsafe { (*cur).name }).is_null()
        && (unsafe { (*cur).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_COMMENT_NODE as i32 as u32
    {
        if !(unsafe { (*cur).name }).is_null()
            && (dict.is_null() || (unsafe { xmlDictOwns(dict, (*cur).name) }) == 0 as i32)
        {
            (unsafe {
                xmlFree.expect("non-null function pointer")(
                    (*cur).name as *mut i8 as *mut libc::c_void,
                )
            });
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(cur as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlUnlinkNode(mut cur: *mut crate::src::threads::_xmlNode) {
    if cur.is_null() {
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
        let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
        doc = unsafe { (*cur).doc };
        if !doc.is_null() {
            if (unsafe { (*doc).intSubset }) == cur as xmlDtdPtr {
                let fresh182 = unsafe { &mut ((*doc).intSubset) };
                *fresh182 = 0 as *mut _xmlDtd;
            }
            if (unsafe { (*doc).extSubset }) == cur as xmlDtdPtr {
                let fresh183 = unsafe { &mut ((*doc).extSubset) };
                *fresh183 = 0 as *mut _xmlDtd;
            }
        }
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32 {
        let mut doc_0: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
        doc_0 = unsafe { (*cur).doc };
        if !doc_0.is_null() {
            if !(unsafe { (*doc_0).intSubset }).is_null() {
                if (unsafe {
                    xmlHashLookup(
                        (*(*doc_0).intSubset).entities as xmlHashTablePtr,
                        (*cur).name,
                    )
                }) == cur as *mut libc::c_void
                {
                    (unsafe {
                        xmlHashRemoveEntry(
                            (*(*doc_0).intSubset).entities as xmlHashTablePtr,
                            (*cur).name,
                            None,
                        )
                    });
                }
                if (unsafe {
                    xmlHashLookup(
                        (*(*doc_0).intSubset).pentities as xmlHashTablePtr,
                        (*cur).name,
                    )
                }) == cur as *mut libc::c_void
                {
                    (unsafe {
                        xmlHashRemoveEntry(
                            (*(*doc_0).intSubset).pentities as xmlHashTablePtr,
                            (*cur).name,
                            None,
                        )
                    });
                }
            }
            if !(unsafe { (*doc_0).extSubset }).is_null() {
                if (unsafe {
                    xmlHashLookup(
                        (*(*doc_0).extSubset).entities as xmlHashTablePtr,
                        (*cur).name,
                    )
                }) == cur as *mut libc::c_void
                {
                    (unsafe {
                        xmlHashRemoveEntry(
                            (*(*doc_0).extSubset).entities as xmlHashTablePtr,
                            (*cur).name,
                            None,
                        )
                    });
                }
                if (unsafe {
                    xmlHashLookup(
                        (*(*doc_0).extSubset).pentities as xmlHashTablePtr,
                        (*cur).name,
                    )
                }) == cur as *mut libc::c_void
                {
                    (unsafe {
                        xmlHashRemoveEntry(
                            (*(*doc_0).extSubset).pentities as xmlHashTablePtr,
                            (*cur).name,
                            None,
                        )
                    });
                }
            }
        }
    }
    if !(unsafe { (*cur).parent }).is_null() {
        let mut parent: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        parent = unsafe { (*cur).parent };
        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            if (unsafe { (*parent).properties }) == cur as xmlAttrPtr {
                let fresh184 = unsafe { &mut ((*parent).properties) };
                *fresh184 = unsafe { (*(cur as xmlAttrPtr)).next };
            }
        } else {
            if (unsafe { (*parent).children }) == cur {
                let fresh185 = unsafe { &mut ((*parent).children) };
                *fresh185 = unsafe { (*cur).next };
            }
            if (unsafe { (*parent).last }) == cur {
                let fresh186 = unsafe { &mut ((*parent).last) };
                *fresh186 = unsafe { (*cur).prev };
            }
        }
        let fresh187 = unsafe { &mut ((*cur).parent) };
        *fresh187 = 0 as *mut _xmlNode;
    }
    if !(unsafe { (*cur).next }).is_null() {
        let fresh188 = unsafe { &mut ((*(*cur).next).prev) };
        *fresh188 = unsafe { (*cur).prev };
    }
    if !(unsafe { (*cur).prev }).is_null() {
        let fresh189 = unsafe { &mut ((*(*cur).prev).next) };
        *fresh189 = unsafe { (*cur).next };
    }
    let fresh190 = unsafe { &mut ((*cur).prev) };
    *fresh190 = 0 as *mut _xmlNode;
    let fresh191 = unsafe { &mut ((*cur).next) };
    *fresh191 = *fresh190;
}
#[no_mangle]
pub extern "C" fn xmlReplaceNode(
    mut old: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if old == cur {
        return 0 as xmlNodePtr;
    }
    if old.is_null()
        || (unsafe { (*old).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || (unsafe { (*old).parent }).is_null()
    {
        return 0 as xmlNodePtr;
    }
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        xmlUnlinkNode(old);
        return old;
    }
    if cur == old {
        return old;
    }
    if (unsafe { (*old).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
        && (unsafe { (*cur).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return old;
    }
    if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
        && (unsafe { (*old).type_0 }) as u32 != XML_ATTRIBUTE_NODE as i32 as u32
    {
        return old;
    }
    xmlUnlinkNode(cur);
    xmlSetTreeDoc(cur, unsafe { (*old).doc });
    let fresh192 = unsafe { &mut ((*cur).parent) };
    *fresh192 = unsafe { (*old).parent };
    let fresh193 = unsafe { &mut ((*cur).next) };
    *fresh193 = unsafe { (*old).next };
    if !(unsafe { (*cur).next }).is_null() {
        let fresh194 = unsafe { &mut ((*(*cur).next).prev) };
        *fresh194 = cur;
    }
    let fresh195 = unsafe { &mut ((*cur).prev) };
    *fresh195 = unsafe { (*old).prev };
    if !(unsafe { (*cur).prev }).is_null() {
        let fresh196 = unsafe { &mut ((*(*cur).prev).next) };
        *fresh196 = cur;
    }
    if !(unsafe { (*cur).parent }).is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            if (unsafe { (*(*cur).parent).properties }) == old as xmlAttrPtr {
                let fresh197 = unsafe { &mut ((*(*cur).parent).properties) };
                *fresh197 = cur as xmlAttrPtr;
            }
        } else {
            if (unsafe { (*(*cur).parent).children }) == old {
                let fresh198 = unsafe { &mut ((*(*cur).parent).children) };
                *fresh198 = cur;
            }
            if (unsafe { (*(*cur).parent).last }) == old {
                let fresh199 = unsafe { &mut ((*(*cur).parent).last) };
                *fresh199 = cur;
            }
        }
    }
    let fresh200 = unsafe { &mut ((*old).prev) };
    *fresh200 = 0 as *mut _xmlNode;
    let fresh201 = unsafe { &mut ((*old).next) };
    *fresh201 = *fresh200;
    let fresh202 = unsafe { &mut ((*old).parent) };
    *fresh202 = 0 as *mut _xmlNode;
    return old;
}
#[no_mangle]
pub extern "C" fn xmlCopyNamespace(
    mut cur: *mut crate::src::threads::_xmlNs,
) -> *mut crate::src::threads::_xmlNs {
    let mut ret: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if cur.is_null() {
        return 0 as xmlNsPtr;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        18 => {
            ret = xmlNewNs(
                0 as xmlNodePtr,
                unsafe { (*cur).href },
                unsafe { (*cur).prefix },
            );
        }
        _ => return 0 as xmlNsPtr,
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyNamespaceList(
    mut cur: *mut crate::src::threads::_xmlNs,
) -> *mut crate::src::threads::_xmlNs {
    let mut ret: *mut crate::src::threads::_xmlNs = 0 as xmlNsPtr;
    let mut p: *mut crate::src::threads::_xmlNs = 0 as xmlNsPtr;
    let mut q: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    while !cur.is_null() {
        q = xmlCopyNamespace(cur);
        if p.is_null() {
            p = q;
            ret = p;
        } else {
            let fresh203 = unsafe { &mut ((*p).next) };
            *fresh203 = q;
            p = q;
        }
        cur = unsafe { (*cur).next };
    }
    return ret;
}
extern "C" fn xmlCopyPropInternal(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut target: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlAttr,
) -> *mut crate::src::threads::_xmlAttr {
    let mut ret: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if cur.is_null() {
        return 0 as xmlAttrPtr;
    }
    if !target.is_null() && (unsafe { (*target).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlAttrPtr;
    }
    if !target.is_null() {
        ret = xmlNewDocProp(
            unsafe { (*target).doc },
            unsafe { (*cur).name },
            0 as *const xmlChar,
        );
    } else if !doc.is_null() {
        ret = xmlNewDocProp(doc, unsafe { (*cur).name }, 0 as *const xmlChar);
    } else if !(unsafe { (*cur).parent }).is_null() {
        ret = xmlNewDocProp(
            unsafe { (*(*cur).parent).doc },
            unsafe { (*cur).name },
            0 as *const xmlChar,
        );
    } else if !(unsafe { (*cur).children }).is_null() {
        ret = xmlNewDocProp(
            unsafe { (*(*cur).children).doc },
            unsafe { (*cur).name },
            0 as *const xmlChar,
        );
    } else {
        ret = xmlNewDocProp(
            0 as xmlDocPtr,
            unsafe { (*cur).name },
            0 as *const xmlChar,
        );
    }
    if ret.is_null() {
        return 0 as xmlAttrPtr;
    }
    let fresh204 = unsafe { &mut ((*ret).parent) };
    *fresh204 = target;
    if !(unsafe { (*cur).ns }).is_null() && !target.is_null() {
        let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
        ns = xmlSearchNs(
            unsafe { (*target).doc },
            target,
            unsafe { (*(*cur).ns).prefix },
        );
        if ns.is_null() {
            ns = xmlSearchNs(
                unsafe { (*cur).doc },
                unsafe { (*cur).parent },
                unsafe { (*(*cur).ns).prefix },
            );
            if !ns.is_null() {
                let mut root: *mut crate::src::threads::_xmlNode = target;
                let mut pred: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
                while !(unsafe { (*root).parent }).is_null() {
                    pred = root;
                    root = unsafe { (*root).parent };
                }
                if root == (unsafe { (*target).doc }) as xmlNodePtr {
                    root = pred;
                }
                let fresh205 = unsafe { &mut ((*ret).ns) };
                *fresh205 = xmlNewNs(root, unsafe { (*ns).href }, unsafe { (*ns).prefix });
            }
        } else if xmlStrEqual(unsafe { (*ns).href }, unsafe { (*(*cur).ns).href }) != 0 {
            let fresh206 = unsafe { &mut ((*ret).ns) };
            *fresh206 = ns;
        } else {
            let fresh207 = unsafe { &mut ((*ret).ns) };
            *fresh207 =
                xmlNewReconciledNs(unsafe { (*target).doc }, target, unsafe { (*cur).ns });
        }
    } else {
        let fresh208 = unsafe { &mut ((*ret).ns) };
        *fresh208 = 0 as *mut xmlNs;
    }
    if !(unsafe { (*cur).children }).is_null() {
        let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        let fresh209 = unsafe { &mut ((*ret).children) };
        *fresh209 = xmlStaticCopyNodeList(
            unsafe { (*cur).children },
            unsafe { (*ret).doc },
            ret as xmlNodePtr,
        );
        let fresh210 = unsafe { &mut ((*ret).last) };
        *fresh210 = 0 as *mut _xmlNode;
        tmp = unsafe { (*ret).children };
        while !tmp.is_null() {
            if (unsafe { (*tmp).next }).is_null() {
                let fresh211 = unsafe { &mut ((*ret).last) };
                *fresh211 = tmp;
            }
            tmp = unsafe { (*tmp).next };
        }
    }
    if !target.is_null()
        && !cur.is_null()
        && !(unsafe { (*target).doc }).is_null()
        && !(unsafe { (*cur).doc }).is_null()
        && !(unsafe { (*(*cur).doc).ids }).is_null()
        && !(unsafe { (*cur).parent }).is_null()
    {
        if xmlIsID(unsafe { (*cur).doc }, unsafe { (*cur).parent }, cur) != 0 {
            let mut id: *mut u8 = 0 as *mut xmlChar;
            id = xmlNodeListGetString(
                unsafe { (*cur).doc },
                unsafe { (*cur).children },
                1 as i32,
            );
            if !id.is_null() {
                xmlAddID(0 as xmlValidCtxtPtr, unsafe { (*target).doc }, id, ret);
                (unsafe { xmlFree.expect("non-null function pointer")(id as *mut libc::c_void) });
            }
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyProp(
    mut target: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlAttr,
) -> *mut crate::src::threads::_xmlAttr {
    return xmlCopyPropInternal(0 as xmlDocPtr, target, cur);
}
#[no_mangle]
pub extern "C" fn xmlCopyPropList(
    mut target: *mut crate::src::threads::_xmlNode,
    mut cur: *mut crate::src::threads::_xmlAttr,
) -> *mut crate::src::threads::_xmlAttr {
    let mut ret: *mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut p: *mut crate::src::threads::_xmlAttr = 0 as xmlAttrPtr;
    let mut q: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if !target.is_null() && (unsafe { (*target).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlAttrPtr;
    }
    while !cur.is_null() {
        q = xmlCopyProp(target, cur);
        if q.is_null() {
            return 0 as xmlAttrPtr;
        }
        if p.is_null() {
            p = q;
            ret = p;
        } else {
            let fresh212 = unsafe { &mut ((*p).next) };
            *fresh212 = q;
            let fresh213 = unsafe { &mut ((*q).prev) };
            *fresh213 = p;
            p = q;
        }
        cur = unsafe { (*cur).next };
    }
    return ret;
}
extern "C" fn xmlStaticCopyNode(
    mut node: *mut crate::src::threads::_xmlNode,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut parent: *mut crate::src::threads::_xmlNode,
    mut extended: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if node.is_null() {
        return 0 as xmlNodePtr;
    }
    match (unsafe { (*node).type_0 }) as u32 {
        2 => return xmlCopyPropInternal(doc, parent, node as xmlAttrPtr) as xmlNodePtr,
        18 => return xmlCopyNamespaceList(node as xmlNsPtr) as xmlNodePtr,
        9 | 13 => return xmlCopyDoc(node as xmlDocPtr, extended) as xmlNodePtr,
        10 | 12 | 14 | 15 | 16 | 17 => return 0 as xmlNodePtr,
        3 | 4 | 1 | 11 | 5 | 6 | 7 | 8 | 19 | 20 | _ => {}
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNode>() as u64)
    }) as xmlNodePtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"copying node\0" as *const u8 as *const i8);
        return 0 as xmlNodePtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNode>() as u64,
        )
    });
    (unsafe { (*ret).type_0 = (*node).type_0 });
    let fresh214 = unsafe { &mut ((*ret).doc) };
    *fresh214 = doc;
    let fresh215 = unsafe { &mut ((*ret).parent) };
    *fresh215 = parent;
    if (unsafe { (*node).name }) == (unsafe { xmlStringText.as_ptr() }) {
        let fresh216 = unsafe { &mut ((*ret).name) };
        *fresh216 = unsafe { xmlStringText.as_ptr() };
    } else if (unsafe { (*node).name }) == (unsafe { xmlStringTextNoenc.as_ptr() }) {
        let fresh217 = unsafe { &mut ((*ret).name) };
        *fresh217 = unsafe { xmlStringTextNoenc.as_ptr() };
    } else if (unsafe { (*node).name }) == (unsafe { xmlStringComment.as_ptr() }) {
        let fresh218 = unsafe { &mut ((*ret).name) };
        *fresh218 = unsafe { xmlStringComment.as_ptr() };
    } else if !(unsafe { (*node).name }).is_null() {
        if !doc.is_null() && !(unsafe { (*doc).dict }).is_null() {
            let fresh219 = unsafe { &mut ((*ret).name) };
            *fresh219 = unsafe { xmlDictLookup((*doc).dict, (*node).name, -(1 as i32)) };
        } else {
            let fresh220 = unsafe { &mut ((*ret).name) };
            *fresh220 = xmlStrdup(unsafe { (*node).name });
        }
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        && !(unsafe { (*node).content }).is_null()
        && (unsafe { (*node).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_XINCLUDE_END as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_XINCLUDE_START as i32 as u32
    {
        let fresh221 = unsafe { &mut ((*ret).content) };
        *fresh221 = xmlStrdup(unsafe { (*node).content });
    } else if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        (unsafe { (*ret).line = (*node).line });
    }
    if !parent.is_null() {
        let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        if (unsafe { __xmlRegisterCallbacks }) != 0
            && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() })
        {
            (unsafe {
                (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret)
            });
        }
        tmp = xmlAddChild(parent, ret);
        if tmp != ret {
            return tmp;
        }
    }
    if !(extended == 0) {
        if ((unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32)
            && !(unsafe { (*node).nsDef }).is_null()
        {
            let fresh222 = unsafe { &mut ((*ret).nsDef) };
            *fresh222 = xmlCopyNamespaceList(unsafe { (*node).nsDef });
        }
        if !(unsafe { (*node).ns }).is_null() {
            let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
            ns = xmlSearchNs(doc, ret, unsafe { (*(*node).ns).prefix });
            if ns.is_null() {
                ns = xmlSearchNs(
                    unsafe { (*node).doc },
                    node,
                    unsafe { (*(*node).ns).prefix },
                );
                if !ns.is_null() {
                    let mut root: *mut crate::src::threads::_xmlNode = ret;
                    while !(unsafe { (*root).parent }).is_null() {
                        root = unsafe { (*root).parent };
                    }
                    let fresh223 = unsafe { &mut ((*ret).ns) };
                    *fresh223 = xmlNewNs(root, unsafe { (*ns).href }, unsafe { (*ns).prefix });
                } else {
                    let fresh224 = unsafe { &mut ((*ret).ns) };
                    *fresh224 = xmlNewReconciledNs(doc, ret, unsafe { (*node).ns });
                }
            } else {
                let fresh225 = unsafe { &mut ((*ret).ns) };
                *fresh225 = ns;
            }
        }
        if ((unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32)
            && !(unsafe { (*node).properties }).is_null()
        {
            let fresh226 = unsafe { &mut ((*ret).properties) };
            *fresh226 = xmlCopyPropList(ret, unsafe { (*node).properties });
        }
        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32 {
            if doc.is_null() || (unsafe { (*node).doc }) != doc {
                let fresh227 = unsafe { &mut ((*ret).children) };
                *fresh227 =
                    (unsafe { xmlGetDocEntity(doc as *const xmlDoc, (*ret).name) }) as xmlNodePtr;
            } else {
                let fresh228 = unsafe { &mut ((*ret).children) };
                *fresh228 = unsafe { (*node).children };
            }
            let fresh229 = unsafe { &mut ((*ret).last) };
            *fresh229 = unsafe { (*ret).children };
        } else if !(unsafe { (*node).children }).is_null() && extended != 2 as i32 {
            let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            let mut insert: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            cur = unsafe { (*node).children };
            insert = ret;
            while !cur.is_null() {
                let mut copy: *mut crate::src::threads::_xmlNode =
                    xmlStaticCopyNode(cur, doc, insert, 2 as i32);
                if copy.is_null() {
                    xmlFreeNode(ret);
                    return 0 as xmlNodePtr;
                }
                if (unsafe { (*insert).last }) != copy {
                    if (unsafe { (*insert).last }).is_null() {
                        let fresh230 = unsafe { &mut ((*insert).children) };
                        *fresh230 = copy;
                    } else {
                        let fresh231 = unsafe { &mut ((*copy).prev) };
                        *fresh231 = unsafe { (*insert).last };
                        let fresh232 = unsafe { &mut ((*(*insert).last).next) };
                        *fresh232 = copy;
                    }
                    let fresh233 = unsafe { &mut ((*insert).last) };
                    *fresh233 = copy;
                }
                if (unsafe { (*cur).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
                    && !(unsafe { (*cur).children }).is_null()
                {
                    cur = unsafe { (*cur).children };
                    insert = copy;
                } else {
                    loop {
                        if !(unsafe { (*cur).next }).is_null() {
                            cur = unsafe { (*cur).next };
                            break;
                        } else {
                            cur = unsafe { (*cur).parent };
                            insert = unsafe { (*insert).parent };
                            if !(cur == node) {
                                continue;
                            }
                            cur = 0 as xmlNodePtr;
                            break;
                        }
                    }
                }
            }
        }
    }
    if parent.is_null()
        && ((unsafe { __xmlRegisterCallbacks }) != 0
            && (unsafe { (*__xmlRegisterNodeDefaultValue()).is_some() }))
    {
        (unsafe { (*__xmlRegisterNodeDefaultValue()).expect("non-null function pointer")(ret) });
    }
    return ret;
}
extern "C" fn xmlStaticCopyNodeList(
    mut node: *mut crate::src::threads::_xmlNode,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut parent: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut p: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut q: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_DTD_NODE as i32 as u32 {
            if doc.is_null() {
                node = unsafe { (*node).next };
                continue;
            } else if (unsafe { (*doc).intSubset }).is_null() {
                q = xmlCopyDtd(node as xmlDtdPtr) as xmlNodePtr;
                if q.is_null() {
                    return 0 as xmlNodePtr;
                }
                let fresh234 = unsafe { &mut ((*q).doc) };
                *fresh234 = doc;
                let fresh235 = unsafe { &mut ((*q).parent) };
                *fresh235 = parent;
                let fresh236 = unsafe { &mut ((*doc).intSubset) };
                *fresh236 = q as xmlDtdPtr;
                xmlAddChild(parent, q);
            } else {
                q = (unsafe { (*doc).intSubset }) as xmlNodePtr;
                xmlAddChild(parent, q);
            }
        } else {
            q = xmlStaticCopyNode(node, doc, parent, 1 as i32);
        }
        if q.is_null() {
            return 0 as xmlNodePtr;
        }
        if ret.is_null() {
            let fresh237 = unsafe { &mut ((*q).prev) };
            *fresh237 = 0 as *mut _xmlNode;
            p = q;
            ret = p;
        } else if p != q {
            let fresh238 = unsafe { &mut ((*p).next) };
            *fresh238 = q;
            let fresh239 = unsafe { &mut ((*q).prev) };
            *fresh239 = p;
            p = q;
        }
        node = unsafe { (*node).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyNode(
    mut node: *mut crate::src::threads::_xmlNode,
    mut extended: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    ret = xmlStaticCopyNode(node, 0 as xmlDocPtr, 0 as xmlNodePtr, extended);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDocCopyNode(
    mut node: *mut crate::src::threads::_xmlNode,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut extended: i32,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    ret = xmlStaticCopyNode(node, doc, 0 as xmlNodePtr, extended);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDocCopyNodeList(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode =
        xmlStaticCopyNodeList(node, doc, 0 as xmlNodePtr);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyNodeList(
    mut node: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode =
        xmlStaticCopyNodeList(node, 0 as xmlDocPtr, 0 as xmlNodePtr);
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyDtd(
    mut dtd: *mut crate::src::threads::_xmlDtd,
) -> *mut crate::src::threads::_xmlDtd {
    let mut ret: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut p: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut q: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if dtd.is_null() {
        return 0 as xmlDtdPtr;
    }
    ret = xmlNewDtd(
        0 as xmlDocPtr,
        unsafe { (*dtd).name },
        unsafe { (*dtd).ExternalID },
        unsafe { (*dtd).SystemID },
    );
    if ret.is_null() {
        return 0 as xmlDtdPtr;
    }
    if !(unsafe { (*dtd).entities }).is_null() {
        let fresh240 = unsafe { &mut ((*ret).entities) };
        *fresh240 = (unsafe { xmlCopyEntitiesTable((*dtd).entities as xmlEntitiesTablePtr) })
            as *mut libc::c_void;
    }
    if !(unsafe { (*dtd).notations }).is_null() {
        let fresh241 = unsafe { &mut ((*ret).notations) };
        *fresh241 = xmlCopyNotationTable((unsafe { (*dtd).notations }) as xmlNotationTablePtr)
            as *mut libc::c_void;
    }
    if !(unsafe { (*dtd).elements }).is_null() {
        let fresh242 = unsafe { &mut ((*ret).elements) };
        *fresh242 = xmlCopyElementTable((unsafe { (*dtd).elements }) as xmlElementTablePtr)
            as *mut libc::c_void;
    }
    if !(unsafe { (*dtd).attributes }).is_null() {
        let fresh243 = unsafe { &mut ((*ret).attributes) };
        *fresh243 = xmlCopyAttributeTable((unsafe { (*dtd).attributes }) as xmlAttributeTablePtr)
            as *mut libc::c_void;
    }
    if !(unsafe { (*dtd).pentities }).is_null() {
        let fresh244 = unsafe { &mut ((*ret).pentities) };
        *fresh244 = (unsafe { xmlCopyEntitiesTable((*dtd).pentities as xmlEntitiesTablePtr) })
            as *mut libc::c_void;
    }
    cur = unsafe { (*dtd).children };
    while !cur.is_null() {
        q = 0 as xmlNodePtr;
        if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32 {
            let mut tmp: *mut crate::src::threads::_xmlEntity = cur as xmlEntityPtr;
            match (unsafe { (*tmp).etype }) as u32 {
                1 | 2 | 3 => {
                    q = xmlGetEntityFromDtd(ret as *const xmlDtd, unsafe { (*tmp).name })
                        as xmlNodePtr;
                }
                4 | 5 => {
                    q = xmlGetParameterEntityFromDtd(ret as *const xmlDtd, unsafe { (*tmp).name })
                        as xmlNodePtr;
                }
                6 | _ => {}
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_DECL as i32 as u32 {
            let mut tmp_0: *mut crate::src::tree::_xmlElement = cur as xmlElementPtr;
            q = xmlGetDtdQElementDesc(
                ret,
                unsafe { (*tmp_0).name },
                unsafe { (*tmp_0).prefix },
            ) as xmlNodePtr;
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_DECL as i32 as u32 {
            let mut tmp_1: *mut crate::src::tree::_xmlAttribute = cur as xmlAttributePtr;
            q = xmlGetDtdQAttrDesc(
                ret,
                unsafe { (*tmp_1).elem },
                unsafe { (*tmp_1).name },
                unsafe { (*tmp_1).prefix },
            ) as xmlNodePtr;
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32 {
            q = xmlCopyNode(cur, 0 as i32);
        }
        if q.is_null() {
            cur = unsafe { (*cur).next };
        } else {
            if p.is_null() {
                let fresh245 = unsafe { &mut ((*ret).children) };
                *fresh245 = q;
            } else {
                let fresh246 = unsafe { &mut ((*p).next) };
                *fresh246 = q;
            }
            let fresh247 = unsafe { &mut ((*q).prev) };
            *fresh247 = p;
            let fresh248 = unsafe { &mut ((*q).parent) };
            *fresh248 = ret as xmlNodePtr;
            let fresh249 = unsafe { &mut ((*q).next) };
            *fresh249 = 0 as *mut _xmlNode;
            let fresh250 = unsafe { &mut ((*ret).last) };
            *fresh250 = q;
            p = q;
            cur = unsafe { (*cur).next };
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlCopyDoc(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut recursive: i32,
) -> *mut crate::src::threads::_xmlDoc {
    let mut ret: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    if doc.is_null() {
        return 0 as xmlDocPtr;
    }
    ret = xmlNewDoc(unsafe { (*doc).version });
    if ret.is_null() {
        return 0 as xmlDocPtr;
    }
    (unsafe { (*ret).type_0 = (*doc).type_0 });
    if !(unsafe { (*doc).name }).is_null() {
        let fresh251 = unsafe { &mut ((*ret).name) };
        *fresh251 = unsafe { xmlMemStrdup.expect("non-null function pointer")((*doc).name) };
    }
    if !(unsafe { (*doc).encoding }).is_null() {
        let fresh252 = unsafe { &mut ((*ret).encoding) };
        *fresh252 = xmlStrdup(unsafe { (*doc).encoding });
    }
    if !(unsafe { (*doc).URL }).is_null() {
        let fresh253 = unsafe { &mut ((*ret).URL) };
        *fresh253 = xmlStrdup(unsafe { (*doc).URL });
    }
    (unsafe { (*ret).charset = (*doc).charset });
    (unsafe { (*ret).compression = (*doc).compression });
    (unsafe { (*ret).standalone = (*doc).standalone });
    if recursive == 0 {
        return ret;
    }
    let fresh254 = unsafe { &mut ((*ret).last) };
    *fresh254 = 0 as *mut _xmlNode;
    let fresh255 = unsafe { &mut ((*ret).children) };
    *fresh255 = 0 as *mut _xmlNode;
    if !(unsafe { (*doc).intSubset }).is_null() {
        let fresh256 = unsafe { &mut ((*ret).intSubset) };
        *fresh256 = xmlCopyDtd(unsafe { (*doc).intSubset });
        if (unsafe { (*ret).intSubset }).is_null() {
            xmlFreeDoc(ret);
            return 0 as xmlDocPtr;
        }
        xmlSetTreeDoc((unsafe { (*ret).intSubset }) as xmlNodePtr, ret);
        let fresh257 = unsafe { &mut ((*(*ret).intSubset).parent) };
        *fresh257 = ret;
    }
    if !(unsafe { (*doc).oldNs }).is_null() {
        let fresh258 = unsafe { &mut ((*ret).oldNs) };
        *fresh258 = xmlCopyNamespaceList(unsafe { (*doc).oldNs });
    }
    if !(unsafe { (*doc).children }).is_null() {
        let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        let fresh259 = unsafe { &mut ((*ret).children) };
        *fresh259 = xmlStaticCopyNodeList(unsafe { (*doc).children }, ret, ret as xmlNodePtr);
        let fresh260 = unsafe { &mut ((*ret).last) };
        *fresh260 = 0 as *mut _xmlNode;
        tmp = unsafe { (*ret).children };
        while !tmp.is_null() {
            if (unsafe { (*tmp).next }).is_null() {
                let fresh261 = unsafe { &mut ((*ret).last) };
                *fresh261 = tmp;
            }
            tmp = unsafe { (*tmp).next };
        }
    }
    return ret;
}
extern "C" fn xmlGetLineNoInternal(
    mut node: *const crate::src::threads::_xmlNode,
    mut depth: i32,
) -> i64 {
    let mut result: i64 = -(1 as i32) as i64;
    if depth >= 5 as i32 {
        return -(1 as i32) as i64;
    }
    if node.is_null() {
        return result;
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
        || (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
        || (unsafe { (*node).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32
        || (unsafe { (*node).type_0 }) as u32 == XML_PI_NODE as i32 as u32
    {
        if (unsafe { (*node).line }) as i32 == 65535 as i32 {
            if (unsafe { (*node).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                && !(unsafe { (*node).psvi }).is_null()
            {
                result = (unsafe { (*node).psvi }) as ptrdiff_t;
            } else if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                && !(unsafe { (*node).children }).is_null()
            {
                result = xmlGetLineNoInternal(unsafe { (*node).children }, depth + 1 as i32);
            } else if !(unsafe { (*node).next }).is_null() {
                result = xmlGetLineNoInternal(unsafe { (*node).next }, depth + 1 as i32);
            } else if !(unsafe { (*node).prev }).is_null() {
                result = xmlGetLineNoInternal(unsafe { (*node).prev }, depth + 1 as i32);
            }
        }
        if result == -(1 as i32) as i64 || result == 65535 as i32 as i64 {
            result = (unsafe { (*node).line }) as i64;
        }
    } else if !(unsafe { (*node).prev }).is_null()
        && ((unsafe { (*(*node).prev).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
            || (unsafe { (*(*node).prev).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            || (unsafe { (*(*node).prev).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32
            || (unsafe { (*(*node).prev).type_0 }) as u32 == XML_PI_NODE as i32 as u32)
    {
        result = xmlGetLineNoInternal(unsafe { (*node).prev }, depth + 1 as i32);
    } else if !(unsafe { (*node).parent }).is_null()
        && (unsafe { (*(*node).parent).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
    {
        result = xmlGetLineNoInternal(unsafe { (*node).parent }, depth + 1 as i32);
    }
    return result;
}
#[no_mangle]
pub extern "C" fn xmlGetLineNo(mut node: *const crate::src::threads::_xmlNode) -> i64 {
    return xmlGetLineNoInternal(node, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlGetNodePath(mut node: *const crate::src::threads::_xmlNode) -> *mut u8 {
    let mut cur: *const crate::src::threads::_xmlNode = 0 as *const xmlNode;
    let mut tmp: *const crate::src::threads::_xmlNode = 0 as *const xmlNode;
    let mut next: *const crate::src::threads::_xmlNode = 0 as *const xmlNode;
    let mut buffer: *mut u8 = 0 as *mut xmlChar;
    let mut temp: *mut u8 = 0 as *mut xmlChar;
    let mut buf_len: u64 = 0;
    let mut buf: *mut u8 = 0 as *mut xmlChar;
    let mut sep: *const i8 = 0 as *const i8;
    let mut name: *const i8 = 0 as *const i8;
    let mut nametemp: [i8; 100] = [0; 100];
    let mut occur: i32 = 0 as i32;
    let mut generic: i32 = 0;
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    buf_len = 500 as i32 as size_t;
    buffer = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            buf_len.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if buffer.is_null() {
        xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const i8);
        return 0 as *mut xmlChar;
    }
    buf = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            buf_len.wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if buf.is_null() {
        xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const i8);
        (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
        return 0 as *mut xmlChar;
    }
    (unsafe { *buffer.offset(0 as i32 as isize) = 0 as i32 as xmlChar });
    cur = node;
    loop {
        name = b"\0" as *const u8 as *const i8;
        sep = b"?\0" as *const u8 as *const i8;
        occur = 0 as i32;
        if (unsafe { (*cur).type_0 }) as u32 == XML_DOCUMENT_NODE as i32 as u32
            || (unsafe { (*cur).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32
        {
            if (unsafe { *buffer.offset(0 as i32 as isize) }) as i32 == '/' as i32 {
                break;
            }
            sep = b"/\0" as *const u8 as *const i8;
            next = 0 as *const xmlNode;
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            generic = 0 as i32;
            sep = b"/\0" as *const u8 as *const i8;
            name = (unsafe { (*cur).name }) as *const i8;
            if !(unsafe { (*cur).ns }).is_null() {
                if !(unsafe { (*(*cur).ns).prefix }).is_null() {
                    (unsafe {
                        snprintf(
                            nametemp.as_mut_ptr(),
                            (::std::mem::size_of::<[i8; 100]>() as u64)
                                .wrapping_sub(1 as i32 as u64),
                            b"%s:%s\0" as *const u8 as *const i8,
                            (*(*cur).ns).prefix as *mut i8,
                            (*cur).name as *mut i8,
                        )
                    });
                    nametemp[(::std::mem::size_of::<[i8; 100]>() as u64)
                        .wrapping_sub(1 as i32 as u64) as usize] = 0 as i32 as i8;
                    name = nametemp.as_mut_ptr();
                } else {
                    generic = 1 as i32;
                    name = b"*\0" as *const u8 as *const i8;
                }
            }
            next = unsafe { (*cur).parent };
            tmp = unsafe { (*cur).prev };
            while !tmp.is_null() {
                if (unsafe { (*tmp).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    && (generic != 0
                        || xmlStrEqual(unsafe { (*cur).name }, unsafe { (*tmp).name }) != 0
                            && ((unsafe { (*tmp).ns }) == (unsafe { (*cur).ns })
                                || !(unsafe { (*tmp).ns }).is_null()
                                    && !(unsafe { (*cur).ns }).is_null()
                                    && xmlStrEqual(
                                        unsafe { (*(*cur).ns).prefix },
                                        unsafe { (*(*tmp).ns).prefix },
                                    ) != 0))
                {
                    occur += 1;
                }
                tmp = unsafe { (*tmp).prev };
            }
            if occur == 0 as i32 {
                tmp = unsafe { (*cur).next };
                while !tmp.is_null() && occur == 0 as i32 {
                    if (unsafe { (*tmp).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        && (generic != 0
                            || xmlStrEqual(unsafe { (*cur).name }, unsafe { (*tmp).name }) != 0
                                && ((unsafe { (*tmp).ns }) == (unsafe { (*cur).ns })
                                    || !(unsafe { (*tmp).ns }).is_null()
                                        && !(unsafe { (*cur).ns }).is_null()
                                        && xmlStrEqual(
                                            unsafe { (*(*cur).ns).prefix },
                                            unsafe { (*(*tmp).ns).prefix },
                                        ) != 0))
                    {
                        occur += 1;
                    }
                    tmp = unsafe { (*tmp).next };
                }
                if occur != 0 as i32 {
                    occur = 1 as i32;
                }
            } else {
                occur += 1;
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32 {
            sep = b"/\0" as *const u8 as *const i8;
            name = b"comment()\0" as *const u8 as *const i8;
            next = unsafe { (*cur).parent };
            tmp = unsafe { (*cur).prev };
            while !tmp.is_null() {
                if (unsafe { (*tmp).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32 {
                    occur += 1;
                }
                tmp = unsafe { (*tmp).prev };
            }
            if occur == 0 as i32 {
                tmp = unsafe { (*cur).next };
                while !tmp.is_null() && occur == 0 as i32 {
                    if (unsafe { (*tmp).type_0 }) as u32 == XML_COMMENT_NODE as i32 as u32 {
                        occur += 1;
                    }
                    tmp = unsafe { (*tmp).next };
                }
                if occur != 0 as i32 {
                    occur = 1 as i32;
                }
            } else {
                occur += 1;
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
            || (unsafe { (*cur).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
        {
            sep = b"/\0" as *const u8 as *const i8;
            name = b"text()\0" as *const u8 as *const i8;
            next = unsafe { (*cur).parent };
            tmp = unsafe { (*cur).prev };
            while !tmp.is_null() {
                if (unsafe { (*tmp).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                    || (unsafe { (*tmp).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
                {
                    occur += 1;
                }
                tmp = unsafe { (*tmp).prev };
            }
            if occur == 0 as i32 {
                tmp = unsafe { (*cur).next };
                while !tmp.is_null() {
                    if (unsafe { (*tmp).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                        || (unsafe { (*tmp).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
                    {
                        occur = 1 as i32;
                        break;
                    } else {
                        tmp = unsafe { (*tmp).next };
                    }
                }
            } else {
                occur += 1;
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_PI_NODE as i32 as u32 {
            sep = b"/\0" as *const u8 as *const i8;
            (unsafe {
                snprintf(
                    nametemp.as_mut_ptr(),
                    (::std::mem::size_of::<[i8; 100]>() as u64).wrapping_sub(1 as i32 as u64),
                    b"processing-instruction('%s')\0" as *const u8 as *const i8,
                    (*cur).name as *mut i8,
                )
            });
            nametemp[(::std::mem::size_of::<[i8; 100]>() as u64).wrapping_sub(1 as i32 as u64)
                as usize] = 0 as i32 as i8;
            name = nametemp.as_mut_ptr();
            next = unsafe { (*cur).parent };
            tmp = unsafe { (*cur).prev };
            while !tmp.is_null() {
                if (unsafe { (*tmp).type_0 }) as u32 == XML_PI_NODE as i32 as u32
                    && xmlStrEqual(unsafe { (*cur).name }, unsafe { (*tmp).name }) != 0
                {
                    occur += 1;
                }
                tmp = unsafe { (*tmp).prev };
            }
            if occur == 0 as i32 {
                tmp = unsafe { (*cur).next };
                while !tmp.is_null() && occur == 0 as i32 {
                    if (unsafe { (*tmp).type_0 }) as u32 == XML_PI_NODE as i32 as u32
                        && xmlStrEqual(unsafe { (*cur).name }, unsafe { (*tmp).name }) != 0
                    {
                        occur += 1;
                    }
                    tmp = unsafe { (*tmp).next };
                }
                if occur != 0 as i32 {
                    occur = 1 as i32;
                }
            } else {
                occur += 1;
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            sep = b"/@\0" as *const u8 as *const i8;
            name = (unsafe { (*(cur as xmlAttrPtr)).name }) as *const i8;
            if !(unsafe { (*cur).ns }).is_null() {
                if !(unsafe { (*(*cur).ns).prefix }).is_null() {
                    (unsafe {
                        snprintf(
                            nametemp.as_mut_ptr(),
                            (::std::mem::size_of::<[i8; 100]>() as u64)
                                .wrapping_sub(1 as i32 as u64),
                            b"%s:%s\0" as *const u8 as *const i8,
                            (*(*cur).ns).prefix as *mut i8,
                            (*cur).name as *mut i8,
                        )
                    });
                } else {
                    (unsafe {
                        snprintf(
                            nametemp.as_mut_ptr(),
                            (::std::mem::size_of::<[i8; 100]>() as u64)
                                .wrapping_sub(1 as i32 as u64),
                            b"%s\0" as *const u8 as *const i8,
                            (*cur).name as *mut i8,
                        )
                    });
                }
                nametemp[(::std::mem::size_of::<[i8; 100]>() as u64).wrapping_sub(1 as i32 as u64)
                    as usize] = 0 as i32 as i8;
                name = nametemp.as_mut_ptr();
            }
            next = unsafe { (*(cur as xmlAttrPtr)).parent };
        } else {
            (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
            (unsafe { xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void) });
            return 0 as *mut xmlChar;
        }
        if (xmlStrlen(buffer) as u64)
            .wrapping_add(::std::mem::size_of::<[i8; 100]>() as u64)
            .wrapping_add(20 as i32 as u64)
            > buf_len
        {
            buf_len = (2 as i32 as u64)
                .wrapping_mul(buf_len)
                .wrapping_add(xmlStrlen(buffer) as u64)
                .wrapping_add(::std::mem::size_of::<[i8; 100]>() as u64)
                .wrapping_add(20 as i32 as u64);
            temp = (unsafe {
                xmlRealloc.expect("non-null function pointer")(buffer as *mut libc::c_void, buf_len)
            }) as *mut xmlChar;
            if temp.is_null() {
                xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe {
                    xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void)
                });
                return 0 as *mut xmlChar;
            }
            buffer = temp;
            temp = (unsafe {
                xmlRealloc.expect("non-null function pointer")(buf as *mut libc::c_void, buf_len)
            }) as *mut xmlChar;
            if temp.is_null() {
                xmlTreeErrMemory(b"getting node path\0" as *const u8 as *const i8);
                (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
                (unsafe {
                    xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void)
                });
                return 0 as *mut xmlChar;
            }
            buf = temp;
        }
        if occur == 0 as i32 {
            (unsafe {
                snprintf(
                    buf as *mut i8,
                    buf_len,
                    b"%s%s%s\0" as *const u8 as *const i8,
                    sep,
                    name,
                    buffer as *mut i8,
                )
            });
        } else {
            (unsafe {
                snprintf(
                    buf as *mut i8,
                    buf_len,
                    b"%s%s[%d]%s\0" as *const u8 as *const i8,
                    sep,
                    name,
                    occur,
                    buffer as *mut i8,
                )
            });
        }
        (unsafe {
            snprintf(
                buffer as *mut i8,
                buf_len,
                b"%s\0" as *const u8 as *const i8,
                buf as *mut i8,
            )
        });
        cur = next;
        if cur.is_null() {
            break;
        }
    }
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
    return buffer;
}
#[no_mangle]
pub extern "C" fn xmlDocGetRootElement(
    mut doc: *const crate::src::threads::_xmlDoc,
) -> *mut crate::src::threads::_xmlNode {
    let mut ret: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    if doc.is_null() {
        return 0 as xmlNodePtr;
    }
    ret = unsafe { (*doc).children };
    while !ret.is_null() {
        if (unsafe { (*ret).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            return ret;
        }
        ret = unsafe { (*ret).next };
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDocSetRootElement(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut root: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    let mut old: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    if doc.is_null() {
        return 0 as xmlNodePtr;
    }
    if root.is_null() || (unsafe { (*root).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNodePtr;
    }
    xmlUnlinkNode(root);
    xmlSetTreeDoc(root, doc);
    let fresh262 = unsafe { &mut ((*root).parent) };
    *fresh262 = doc as xmlNodePtr;
    old = unsafe { (*doc).children };
    while !old.is_null() {
        if (unsafe { (*old).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            break;
        }
        old = unsafe { (*old).next };
    }
    if old.is_null() {
        if (unsafe { (*doc).children }).is_null() {
            let fresh263 = unsafe { &mut ((*doc).children) };
            *fresh263 = root;
            let fresh264 = unsafe { &mut ((*doc).last) };
            *fresh264 = root;
        } else {
            xmlAddSibling(unsafe { (*doc).children }, root);
        }
    } else {
        xmlReplaceNode(old, root);
    }
    return old;
}
#[no_mangle]
pub extern "C" fn xmlNodeSetLang(mut cur: *mut crate::src::threads::_xmlNode, mut lang: *const u8) {
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        3 | 4 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19 | 20 => return,
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        unsafe { (*cur).doc },
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    xmlSetNsProp(
        cur,
        ns,
        b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
        lang,
    );
}
#[no_mangle]
pub extern "C" fn xmlNodeGetLang(mut cur: *const crate::src::threads::_xmlNode) -> *mut u8 {
    let mut lang: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    while !cur.is_null() {
        lang = xmlGetNsProp(
            cur,
            b"lang\0" as *const u8 as *const i8 as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        );
        if !lang.is_null() {
            return lang;
        }
        cur = unsafe { (*cur).parent };
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlNodeSetSpacePreserve(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut val: i32,
) {
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        3 | 4 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19 | 20 => return,
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        unsafe { (*cur).doc },
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    match val {
        0 => {
            xmlSetNsProp(
                cur,
                ns,
                b"space\0" as *const u8 as *const i8 as *mut xmlChar,
                b"default\0" as *const u8 as *const i8 as *mut xmlChar,
            );
        }
        1 => {
            xmlSetNsProp(
                cur,
                ns,
                b"space\0" as *const u8 as *const i8 as *mut xmlChar,
                b"preserve\0" as *const u8 as *const i8 as *mut xmlChar,
            );
        }
        _ => {}
    };
}
#[no_mangle]
pub extern "C" fn xmlNodeGetSpacePreserve(mut cur: *const crate::src::threads::_xmlNode) -> i32 {
    let mut space: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() || (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return -(1 as i32);
    }
    while !cur.is_null() {
        space = xmlGetNsProp(
            cur,
            b"space\0" as *const u8 as *const i8 as *mut xmlChar,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        );
        if !space.is_null() {
            if xmlStrEqual(
                space,
                b"preserve\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(space as *mut libc::c_void)
                });
                return 1 as i32;
            }
            if xmlStrEqual(
                space,
                b"default\0" as *const u8 as *const i8 as *mut xmlChar,
            ) != 0
            {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(space as *mut libc::c_void)
                });
                return 0 as i32;
            }
            (unsafe { xmlFree.expect("non-null function pointer")(space as *mut libc::c_void) });
        }
        cur = unsafe { (*cur).parent };
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNodeSetName<'a1>(
    mut cur: Option<&'a1 mut crate::src::threads::_xmlNode>,
    mut name: *const u8,
) {
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as *mut xmlDict;
    let mut freeme: *const u8 = 0 as *const xmlChar;
    if borrow(&cur).is_none() {
        return;
    }
    if name.is_null() {
        return;
    }
    match (*(borrow(&cur)).unwrap()).type_0 as u32 {
        3 | 4 | 8 | 10 | 11 | 12 | 13 | 18 | 19 | 20 => return,
        1 | 2 | 7 | 5 | 6 | 14 | 9 | 15 | 16 | 17 | _ => {}
    }
    doc = (*(borrow_mut(&mut cur)).unwrap()).doc;
    if !doc.is_null() {
        dict = unsafe { (*doc).dict };
    } else {
        dict = 0 as xmlDictPtr;
    }
    if !dict.is_null() {
        if !((*(borrow(&cur)).unwrap()).name).is_null()
            && (unsafe { xmlDictOwns(dict, (*(borrow(&cur)).unwrap()).name) }) == 0
        {
            freeme = (*(borrow(&cur)).unwrap()).name;
        }
        let fresh265 = &mut ((*(borrow_mut(&mut cur)).unwrap()).name);
        *fresh265 = unsafe { xmlDictLookup(dict, name, -(1 as i32)) };
    } else {
        if !((*(borrow_mut(&mut cur)).unwrap()).name).is_null() {
            freeme = (*(borrow(&cur)).unwrap()).name;
        }
        let fresh266 = &mut ((*(borrow_mut(&mut cur)).unwrap()).name);
        *fresh266 = xmlStrdup(name);
    }
    if !freeme.is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")(freeme as *mut xmlChar as *mut libc::c_void)
        });
    }
}
#[no_mangle]
pub extern "C" fn xmlNodeSetBase(mut cur: *mut crate::src::threads::_xmlNode, mut uri: *const u8) {
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut fixed: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        3 | 4 | 8 | 10 | 11 | 12 | 14 | 15 | 16 | 17 | 7 | 5 | 6 | 18 | 19 | 20 => return,
        9 | 13 => {
            let mut doc: *mut crate::src::threads::_xmlDoc = cur as xmlDocPtr;
            if !(unsafe { (*doc).URL }).is_null() {
                (unsafe {
                    xmlFree.expect("non-null function pointer")(
                        (*doc).URL as *mut xmlChar as *mut libc::c_void,
                    )
                });
            }
            if uri.is_null() {
                let fresh267 = unsafe { &mut ((*doc).URL) };
                *fresh267 = 0 as *const xmlChar;
            } else {
                let fresh268 = unsafe { &mut ((*doc).URL) };
                *fresh268 = xmlPathToURI(uri);
            }
            return;
        }
        1 | 2 | _ => {}
    }
    ns = xmlSearchNsByHref(
        unsafe { (*cur).doc },
        cur,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    );
    if ns.is_null() {
        return;
    }
    fixed = xmlPathToURI(uri);
    if !fixed.is_null() {
        xmlSetNsProp(
            cur,
            ns,
            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            fixed,
        );
        (unsafe { xmlFree.expect("non-null function pointer")(fixed as *mut libc::c_void) });
    } else {
        xmlSetNsProp(
            cur,
            ns,
            b"base\0" as *const u8 as *const i8 as *mut xmlChar,
            uri,
        );
    };
}
#[no_mangle]
pub extern "C" fn xmlNodeGetBase(
    mut doc: *const crate::src::threads::_xmlDoc,
    mut cur: *const crate::src::threads::_xmlNode,
) -> *mut u8 {
    let mut oldbase: *mut u8 = 0 as *mut xmlChar;
    let mut base: *mut u8 = 0 as *mut xmlChar;
    let mut newbase: *mut u8 = 0 as *mut xmlChar;
    if cur.is_null() && doc.is_null() {
        return 0 as *mut xmlChar;
    }
    if !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    if doc.is_null() {
        doc = unsafe { (*cur).doc };
    }
    if !doc.is_null() && (unsafe { (*doc).type_0 }) as u32 == XML_HTML_DOCUMENT_NODE as i32 as u32 {
        cur = unsafe { (*doc).children };
        while !cur.is_null() && !(unsafe { (*cur).name }).is_null() {
            if (unsafe { (*cur).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
                cur = unsafe { (*cur).next };
            } else if xmlStrcasecmp(
                unsafe { (*cur).name },
                b"html\0" as *const u8 as *const i8 as *mut xmlChar,
            ) == 0
            {
                cur = unsafe { (*cur).children };
            } else if xmlStrcasecmp(
                unsafe { (*cur).name },
                b"head\0" as *const u8 as *const i8 as *mut xmlChar,
            ) == 0
            {
                cur = unsafe { (*cur).children };
            } else {
                if xmlStrcasecmp(
                    unsafe { (*cur).name },
                    b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                ) == 0
                {
                    return xmlGetProp(cur, b"href\0" as *const u8 as *const i8 as *mut xmlChar);
                }
                cur = unsafe { (*cur).next };
            }
        }
        return 0 as *mut xmlChar;
    }
    while !cur.is_null() {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32 {
            let mut ent: *mut crate::src::threads::_xmlEntity = cur as xmlEntityPtr;
            return xmlStrdup(unsafe { (*ent).URI });
        }
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            base = xmlGetNsProp(
                cur,
                b"base\0" as *const u8 as *const i8 as *mut xmlChar,
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            );
            if !base.is_null() {
                if !oldbase.is_null() {
                    newbase = xmlBuildURI(oldbase, base);
                    if !newbase.is_null() {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                oldbase as *mut libc::c_void,
                            )
                        });
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(base as *mut libc::c_void)
                        });
                        oldbase = newbase;
                    } else {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                oldbase as *mut libc::c_void,
                            )
                        });
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(base as *mut libc::c_void)
                        });
                        return 0 as *mut xmlChar;
                    }
                } else {
                    oldbase = base;
                }
                if xmlStrncmp(
                    oldbase,
                    b"http://\0" as *const u8 as *const i8 as *mut xmlChar,
                    7 as i32,
                ) == 0
                    || xmlStrncmp(
                        oldbase,
                        b"ftp://\0" as *const u8 as *const i8 as *mut xmlChar,
                        6 as i32,
                    ) == 0
                    || xmlStrncmp(
                        oldbase,
                        b"urn:\0" as *const u8 as *const i8 as *mut xmlChar,
                        4 as i32,
                    ) == 0
                {
                    return oldbase;
                }
            }
        }
        cur = unsafe { (*cur).parent };
    }
    if !doc.is_null() && !(unsafe { (*doc).URL }).is_null() {
        if oldbase.is_null() {
            return xmlStrdup(unsafe { (*doc).URL });
        }
        newbase = xmlBuildURI(oldbase, unsafe { (*doc).URL });
        (unsafe { xmlFree.expect("non-null function pointer")(oldbase as *mut libc::c_void) });
        return newbase;
    }
    return oldbase;
}
#[no_mangle]
pub extern "C" fn xmlNodeBufGetContent(
    mut buffer: *mut crate::src::tree::_xmlBuffer,
    mut cur: *const crate::src::threads::_xmlNode,
) -> i32 {
    let mut buf: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
    let mut ret: i32 = 0;
    if cur.is_null() || buffer.is_null() {
        return -(1 as i32);
    }
    buf = unsafe { xmlBufFromBuffer(buffer) };
    ret = xmlBufGetNodeContent(buf, cur);
    buffer = unsafe { xmlBufBackToBuffer(buf) };
    if ret < 0 as i32 || buffer.is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufGetNodeContent(
    mut buf: *mut crate::src::xmlstring::_xmlBuf,
    mut cur: *const crate::src::threads::_xmlNode,
) -> i32 {
    if cur.is_null() || buf.is_null() {
        return -(1 as i32);
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        4 | 3 => {
            (unsafe { xmlBufCat(buf, (*cur).content) });
        }
        11 | 1 => {
            let mut tmp: *const crate::src::threads::_xmlNode = cur;
            while !tmp.is_null() {
                match (unsafe { (*tmp).type_0 }) as u32 {
                    4 | 3 => {
                        if !(unsafe { (*tmp).content }).is_null() {
                            (unsafe { xmlBufCat(buf, (*tmp).content) });
                        }
                    }
                    5 => {
                        xmlBufGetNodeContent(buf, tmp);
                    }
                    _ => {}
                }
                if !(unsafe { (*tmp).children }).is_null() {
                    if (unsafe { (*(*tmp).children).type_0 }) as u32
                        != XML_ENTITY_DECL as i32 as u32
                    {
                        tmp = unsafe { (*tmp).children };
                        continue;
                    }
                }
                if tmp == cur {
                    break;
                }
                if !(unsafe { (*tmp).next }).is_null() {
                    tmp = unsafe { (*tmp).next };
                } else {
                    loop {
                        tmp = unsafe { (*tmp).parent };
                        if tmp.is_null() {
                            break;
                        }
                        if tmp == cur {
                            tmp = 0 as *const xmlNode;
                            break;
                        } else if !(unsafe { (*tmp).next }).is_null() {
                            tmp = unsafe { (*tmp).next };
                            break;
                        } else if tmp.is_null() {
                            break;
                        }
                    }
                }
            }
        }
        2 => {
            let mut attr: *mut crate::src::threads::_xmlAttr = cur as xmlAttrPtr;
            let mut tmp_0: *mut crate::src::threads::_xmlNode = unsafe { (*attr).children };
            while !tmp_0.is_null() {
                if (unsafe { (*tmp_0).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32 {
                    (unsafe { xmlBufCat(buf, (*tmp_0).content) });
                } else {
                    xmlBufGetNodeContent(buf, tmp_0 as *const xmlNode);
                }
                tmp_0 = unsafe { (*tmp_0).next };
            }
        }
        8 | 7 => {
            (unsafe { xmlBufCat(buf, (*cur).content) });
        }
        5 => {
            let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
            let mut tmp_1: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            ent = unsafe { xmlGetDocEntity((*cur).doc, (*cur).name) };
            if ent.is_null() {
                return -(1 as i32);
            }
            tmp_1 = unsafe { (*ent).children };
            while !tmp_1.is_null() {
                xmlBufGetNodeContent(buf, tmp_1 as *const xmlNode);
                tmp_1 = unsafe { (*tmp_1).next };
            }
        }
        9 | 13 => {
            cur = unsafe { (*cur).children };
            while !cur.is_null() {
                if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    || (unsafe { (*cur).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                    || (unsafe { (*cur).type_0 }) as u32 == XML_CDATA_SECTION_NODE as i32 as u32
                {
                    xmlBufGetNodeContent(buf, cur);
                }
                cur = unsafe { (*cur).next };
            }
        }
        18 => {
            (unsafe { xmlBufCat(buf, (*(cur as xmlNsPtr)).href) });
        }
        6 | 10 | 12 | 14 | 19 | 20 | 15 | 16 | 17 | _ => {}
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlNodeGetContent(mut cur: *const crate::src::threads::_xmlNode) -> *mut u8 {
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        11 | 1 => {
            let mut buf: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
            let mut ret: *mut u8 = 0 as *mut xmlChar;
            buf = unsafe { xmlBufCreateSize(64 as i32 as size_t) };
            if buf.is_null() {
                return 0 as *mut xmlChar;
            }
            (unsafe { xmlBufSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT) });
            xmlBufGetNodeContent(buf, cur);
            ret = unsafe { xmlBufDetach(buf) };
            (unsafe { xmlBufFree(buf) });
            return ret;
        }
        2 => return xmlGetPropNodeValueInternal(cur as xmlAttrPtr as *const xmlAttr),
        8 | 7 => {
            if !(unsafe { (*cur).content }).is_null() {
                return xmlStrdup(unsafe { (*cur).content });
            }
            return 0 as *mut xmlChar;
        }
        5 => {
            let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
            let mut buf_0: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
            let mut ret_0: *mut u8 = 0 as *mut xmlChar;
            ent = unsafe { xmlGetDocEntity((*cur).doc, (*cur).name) };
            if ent.is_null() {
                return 0 as *mut xmlChar;
            }
            buf_0 = unsafe { xmlBufCreate() };
            if buf_0.is_null() {
                return 0 as *mut xmlChar;
            }
            (unsafe { xmlBufSetAllocationScheme(buf_0, XML_BUFFER_ALLOC_DOUBLEIT) });
            xmlBufGetNodeContent(buf_0, cur);
            ret_0 = unsafe { xmlBufDetach(buf_0) };
            (unsafe { xmlBufFree(buf_0) });
            return ret_0;
        }
        6 | 10 | 12 | 14 | 19 | 20 => return 0 as *mut xmlChar,
        9 | 13 => {
            let mut buf_1: *mut crate::src::xmlstring::_xmlBuf = 0 as *mut xmlBuf;
            let mut ret_1: *mut u8 = 0 as *mut xmlChar;
            buf_1 = unsafe { xmlBufCreate() };
            if buf_1.is_null() {
                return 0 as *mut xmlChar;
            }
            (unsafe { xmlBufSetAllocationScheme(buf_1, XML_BUFFER_ALLOC_DOUBLEIT) });
            xmlBufGetNodeContent(buf_1, cur as xmlNodePtr as *const xmlNode);
            ret_1 = unsafe { xmlBufDetach(buf_1) };
            (unsafe { xmlBufFree(buf_1) });
            return ret_1;
        }
        18 => {
            let mut tmp: *mut u8 = 0 as *mut xmlChar;
            tmp = xmlStrdup(unsafe { (*(cur as xmlNsPtr)).href });
            return tmp;
        }
        15 => return 0 as *mut xmlChar,
        16 => return 0 as *mut xmlChar,
        17 => return 0 as *mut xmlChar,
        4 | 3 => {
            if !(unsafe { (*cur).content }).is_null() {
                return xmlStrdup(unsafe { (*cur).content });
            }
            return 0 as *mut xmlChar;
        }
        _ => {}
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlNodeSetContent(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut content: *const u8,
) {
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        11 | 1 | 2 => {
            if !(unsafe { (*cur).children }).is_null() {
                xmlFreeNodeList(unsafe { (*cur).children });
            }
            let fresh269 = unsafe { &mut ((*cur).children) };
            *fresh269 = xmlStringGetNodeList(unsafe { (*cur).doc }, content);
            if !cur.is_null() {
                let mut ulccur: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
                if ulccur.is_null() {
                    let fresh270 = unsafe { &mut ((*cur).last) };
                    *fresh270 = 0 as *mut _xmlNode;
                } else {
                    while !(unsafe { (*ulccur).next }).is_null() {
                        let fresh271 = unsafe { &mut ((*ulccur).parent) };
                        *fresh271 = cur;
                        ulccur = unsafe { (*ulccur).next };
                    }
                    let fresh272 = unsafe { &mut ((*ulccur).parent) };
                    *fresh272 = cur;
                    let fresh273 = unsafe { &mut ((*cur).last) };
                    *fresh273 = ulccur;
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 => {
            if !(unsafe { (*cur).content }).is_null()
                && (unsafe { (*cur).content })
                    != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !(!(unsafe { (*cur).doc }).is_null()
                    && !(unsafe { (*(*cur).doc).dict }).is_null()
                    && (unsafe { xmlDictOwns((*(*cur).doc).dict, (*cur).content) }) != 0)
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*cur).content as *mut libc::c_void,
                        )
                    });
                }
            }
            if !(unsafe { (*cur).children }).is_null() {
                xmlFreeNodeList(unsafe { (*cur).children });
            }
            let fresh274 = unsafe { &mut ((*cur).children) };
            *fresh274 = 0 as *mut _xmlNode;
            let fresh275 = unsafe { &mut ((*cur).last) };
            *fresh275 = *fresh274;
            if !content.is_null() {
                let fresh276 = unsafe { &mut ((*cur).content) };
                *fresh276 = xmlStrdup(content);
            } else {
                let fresh277 = unsafe { &mut ((*cur).content) };
                *fresh277 = 0 as *mut xmlChar;
            }
            let fresh278 = unsafe { &mut ((*cur).properties) };
            *fresh278 = 0 as *mut _xmlAttr;
        }
        15 => {}
        17 => {}
        9 | 13 | 10 | 19 | 20 | 12 | 14 | 18 | 16 | _ => {}
    };
}
#[no_mangle]
pub extern "C" fn xmlNodeSetContentLen(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut content: *const u8,
    mut len: i32,
) {
    if cur.is_null() {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        11 | 1 | 2 => {
            if !(unsafe { (*cur).children }).is_null() {
                xmlFreeNodeList(unsafe { (*cur).children });
            }
            let fresh279 = unsafe { &mut ((*cur).children) };
            *fresh279 = xmlStringLenGetNodeList(unsafe { (*cur).doc }, content, len);
            if !cur.is_null() {
                let mut ulccur: *mut crate::src::threads::_xmlNode = unsafe { (*cur).children };
                if ulccur.is_null() {
                    let fresh280 = unsafe { &mut ((*cur).last) };
                    *fresh280 = 0 as *mut _xmlNode;
                } else {
                    while !(unsafe { (*ulccur).next }).is_null() {
                        let fresh281 = unsafe { &mut ((*ulccur).parent) };
                        *fresh281 = cur;
                        ulccur = unsafe { (*ulccur).next };
                    }
                    let fresh282 = unsafe { &mut ((*ulccur).parent) };
                    *fresh282 = cur;
                    let fresh283 = unsafe { &mut ((*cur).last) };
                    *fresh283 = ulccur;
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 | 12 => {
            if !(unsafe { (*cur).content }).is_null()
                && (unsafe { (*cur).content })
                    != (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
            {
                if !(!(unsafe { (*cur).doc }).is_null()
                    && !(unsafe { (*(*cur).doc).dict }).is_null()
                    && (unsafe { xmlDictOwns((*(*cur).doc).dict, (*cur).content) }) != 0)
                {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(
                            (*cur).content as *mut libc::c_void,
                        )
                    });
                }
            }
            if !(unsafe { (*cur).children }).is_null() {
                xmlFreeNodeList(unsafe { (*cur).children });
            }
            let fresh284 = unsafe { &mut ((*cur).last) };
            *fresh284 = 0 as *mut _xmlNode;
            let fresh285 = unsafe { &mut ((*cur).children) };
            *fresh285 = *fresh284;
            if !content.is_null() {
                let fresh286 = unsafe { &mut ((*cur).content) };
                *fresh286 = xmlStrndup(content, len);
            } else {
                let fresh287 = unsafe { &mut ((*cur).content) };
                *fresh287 = 0 as *mut xmlChar;
            }
            let fresh288 = unsafe { &mut ((*cur).properties) };
            *fresh288 = 0 as *mut _xmlAttr;
        }
        15 => {}
        17 => {}
        9 | 14 | 13 | 10 | 18 | 19 | 20 | 16 | _ => {}
    };
}
#[no_mangle]
pub extern "C" fn xmlNodeAddContentLen(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut content: *const u8,
    mut len: i32,
) {
    if cur.is_null() {
        return;
    }
    if len <= 0 as i32 {
        return;
    }
    match (unsafe { (*cur).type_0 }) as u32 {
        11 | 1 => {
            let mut last: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            let mut newNode: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            last = unsafe { (*cur).last };
            newNode = xmlNewDocTextLen(unsafe { (*cur).doc }, content, len);
            if !newNode.is_null() {
                tmp = xmlAddChild(cur, newNode);
                if tmp != newNode {
                    return;
                }
                if !last.is_null() && (unsafe { (*last).next }) == newNode {
                    xmlTextMerge(last, newNode);
                }
            }
        }
        3 | 4 | 5 | 6 | 7 | 8 | 12 => {
            if !content.is_null() {
                if (unsafe { (*cur).content })
                    == (unsafe { &mut (*cur).properties }) as *mut *mut _xmlAttr as *mut xmlChar
                    || !(unsafe { (*cur).doc }).is_null()
                        && !(unsafe { (*(*cur).doc).dict }).is_null()
                        && (unsafe { xmlDictOwns((*(*cur).doc).dict, (*cur).content) }) != 0
                {
                    let fresh289 = unsafe { &mut ((*cur).content) };
                    *fresh289 = xmlStrncatNew(unsafe { (*cur).content }, content, len);
                    let fresh290 = unsafe { &mut ((*cur).properties) };
                    *fresh290 = 0 as *mut _xmlAttr;
                } else {
                    let fresh291 = unsafe { &mut ((*cur).content) };
                    *fresh291 = xmlStrncat(unsafe { (*cur).content }, content, len);
                }
            }
        }
        2 | 9 | 14 | 13 | 10 | 18 | 19 | 20 | 15 | 16 | 17 | _ => {}
    };
}
#[no_mangle]
pub extern "C" fn xmlNodeAddContent(
    mut cur: *mut crate::src::threads::_xmlNode,
    mut content: *const u8,
) {
    let mut len: i32 = 0;
    if cur.is_null() {
        return;
    }
    if content.is_null() {
        return;
    }
    len = xmlStrlen(content);
    xmlNodeAddContentLen(cur, content, len);
}
#[no_mangle]
pub extern "C" fn xmlTextMerge(
    mut first: *mut crate::src::threads::_xmlNode,
    mut second: *mut crate::src::threads::_xmlNode,
) -> *mut crate::src::threads::_xmlNode {
    if first.is_null() {
        return second;
    }
    if second.is_null() {
        return first;
    }
    if (unsafe { (*first).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32 {
        return first;
    }
    if (unsafe { (*second).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32 {
        return first;
    }
    if (unsafe { (*second).name }) != (unsafe { (*first).name }) {
        return first;
    }
    xmlNodeAddContent(first, unsafe { (*second).content });
    xmlUnlinkNode(second);
    xmlFreeNode(second);
    return first;
}
#[no_mangle]
pub extern "C" fn xmlGetNsList(
    mut _doc: *const crate::src::threads::_xmlDoc,
    mut node: *const crate::src::threads::_xmlNode,
) -> *mut *mut crate::src::threads::_xmlNs {
    let mut cur: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut ret: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
    let mut nbns: i32 = 0 as i32;
    let mut maxns: i32 = 10 as i32;
    let mut i: i32 = 0;
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as *mut xmlNsPtr;
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            cur = unsafe { (*node).nsDef };
            while !cur.is_null() {
                if ret.is_null() {
                    ret = (unsafe {
                        xmlMalloc.expect("non-null function pointer")(
                            ((maxns + 1 as i32) as u64)
                                .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                        )
                    }) as *mut xmlNsPtr;
                    if ret.is_null() {
                        xmlTreeErrMemory(b"getting namespace list\0" as *const u8 as *const i8);
                        return 0 as *mut xmlNsPtr;
                    }
                    let fresh292 = unsafe { &mut (*ret.offset(nbns as isize)) };
                    *fresh292 = 0 as xmlNsPtr;
                }
                i = 0 as i32;
                while i < nbns {
                    if (unsafe { (*cur).prefix }) == (unsafe { (**ret.offset(i as isize)).prefix })
                        || xmlStrEqual(
                            unsafe { (*cur).prefix },
                            unsafe { (**ret.offset(i as isize)).prefix },
                        ) != 0
                    {
                        break;
                    }
                    i += 1;
                }
                if i >= nbns {
                    if nbns >= maxns {
                        maxns *= 2 as i32;
                        ret =
                            (unsafe {
                                xmlRealloc.expect("non-null function pointer")(
                                    ret as *mut libc::c_void,
                                    ((maxns + 1 as i32) as u64)
                                        .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                                )
                            }) as *mut xmlNsPtr;
                        if ret.is_null() {
                            xmlTreeErrMemory(b"getting namespace list\0" as *const u8 as *const i8);
                            return 0 as *mut xmlNsPtr;
                        }
                    }
                    let mut fresh293 = nbns;
                    nbns = nbns + 1;
                    let fresh294 = unsafe { &mut (*ret.offset(fresh293 as isize)) };
                    *fresh294 = cur;
                    let fresh295 = unsafe { &mut (*ret.offset(nbns as isize)) };
                    *fresh295 = 0 as xmlNsPtr;
                }
                cur = unsafe { (*cur).next };
            }
        }
        node = unsafe { (*node).parent };
    }
    return ret;
}
extern "C" fn xmlTreeEnsureXMLDecl(
    mut doc: *mut crate::src::threads::_xmlDoc,
) -> *mut crate::src::threads::_xmlNs {
    if doc.is_null() {
        return 0 as xmlNsPtr;
    }
    if !(unsafe { (*doc).oldNs }).is_null() {
        return unsafe { (*doc).oldNs };
    }
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    ns = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNs>() as u64)
    }) as xmlNsPtr;
    if ns.is_null() {
        xmlTreeErrMemory(b"allocating the XML namespace\0" as *const u8 as *const i8);
        return 0 as xmlNsPtr;
    }
    (unsafe {
        memset(
            ns as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlNs>() as u64,
        )
    });
    (unsafe { (*ns).type_0 = XML_NAMESPACE_DECL });
    let fresh296 = unsafe { &mut ((*ns).href) };
    *fresh296 = xmlStrdup(
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    );
    let fresh297 = unsafe { &mut ((*ns).prefix) };
    *fresh297 = xmlStrdup(b"xml\0" as *const u8 as *const i8 as *const xmlChar);
    let fresh298 = unsafe { &mut ((*doc).oldNs) };
    *fresh298 = ns;
    return ns;
}
#[no_mangle]
pub extern "C" fn xmlSearchNs(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut nameSpace: *const u8,
) -> *mut crate::src::threads::_xmlNs {
    let mut cur: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut orig: *const crate::src::threads::_xmlNode = node as *const xmlNode;
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNsPtr;
    }
    if !nameSpace.is_null()
        && xmlStrEqual(
            nameSpace,
            b"xml\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
    {
        if doc.is_null() && (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            cur = (unsafe {
                xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNs>() as u64)
            }) as xmlNsPtr;
            if cur.is_null() {
                xmlTreeErrMemory(b"searching namespace\0" as *const u8 as *const i8);
                return 0 as xmlNsPtr;
            }
            (unsafe {
                memset(
                    cur as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<xmlNs>() as u64,
                )
            });
            (unsafe { (*cur).type_0 = XML_NAMESPACE_DECL });
            let fresh299 = unsafe { &mut ((*cur).href) };
            *fresh299 = xmlStrdup(
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            );
            let fresh300 = unsafe { &mut ((*cur).prefix) };
            *fresh300 = xmlStrdup(b"xml\0" as *const u8 as *const i8 as *const xmlChar);
            let fresh301 = unsafe { &mut ((*cur).next) };
            *fresh301 = unsafe { (*node).nsDef };
            let fresh302 = unsafe { &mut ((*node).nsDef) };
            *fresh302 = cur;
            return cur;
        }
        if doc.is_null() {
            doc = unsafe { (*node).doc };
            if doc.is_null() {
                return 0 as xmlNsPtr;
            }
        }
        if (unsafe { (*doc).oldNs }).is_null() {
            return xmlTreeEnsureXMLDecl(doc);
        } else {
            return unsafe { (*doc).oldNs };
        }
    }
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
        {
            return 0 as xmlNsPtr;
        }
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            cur = unsafe { (*node).nsDef };
            while !cur.is_null() {
                if (unsafe { (*cur).prefix }).is_null()
                    && nameSpace.is_null()
                    && !(unsafe { (*cur).href }).is_null()
                {
                    return cur;
                }
                if !(unsafe { (*cur).prefix }).is_null()
                    && !nameSpace.is_null()
                    && !(unsafe { (*cur).href }).is_null()
                    && xmlStrEqual(unsafe { (*cur).prefix }, nameSpace) != 0
                {
                    return cur;
                }
                cur = unsafe { (*cur).next };
            }
            if orig != node as *const xmlNode {
                cur = unsafe { (*node).ns };
                if !cur.is_null() {
                    if (unsafe { (*cur).prefix }).is_null()
                        && nameSpace.is_null()
                        && !(unsafe { (*cur).href }).is_null()
                    {
                        return cur;
                    }
                    if !(unsafe { (*cur).prefix }).is_null()
                        && !nameSpace.is_null()
                        && !(unsafe { (*cur).href }).is_null()
                        && xmlStrEqual(unsafe { (*cur).prefix }, nameSpace) != 0
                    {
                        return cur;
                    }
                }
            }
        }
        node = unsafe { (*node).parent };
    }
    return 0 as xmlNsPtr;
}
extern "C" fn xmlNsInScope(
    mut _doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut ancestor: *mut crate::src::threads::_xmlNode,
    mut prefix: *const u8,
) -> i32 {
    let mut tst: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    while !node.is_null() && node != ancestor {
        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
        {
            return -(1 as i32);
        }
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            tst = unsafe { (*node).nsDef };
            while !tst.is_null() {
                if (unsafe { (*tst).prefix }).is_null() && prefix.is_null() {
                    return 0 as i32;
                }
                if !(unsafe { (*tst).prefix }).is_null()
                    && !prefix.is_null()
                    && xmlStrEqual(unsafe { (*tst).prefix }, prefix) != 0
                {
                    return 0 as i32;
                }
                tst = unsafe { (*tst).next };
            }
        }
        node = unsafe { (*node).parent };
    }
    if node != ancestor {
        return -(1 as i32);
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSearchNsByHref(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut href: *const u8,
) -> *mut crate::src::threads::_xmlNs {
    let mut cur: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut orig: *mut crate::src::threads::_xmlNode = node;
    let mut is_attr: i32 = 0;
    if node.is_null()
        || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || href.is_null()
    {
        return 0 as xmlNsPtr;
    }
    if xmlStrEqual(
        href,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    ) != 0
    {
        if doc.is_null() && (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            cur = (unsafe {
                xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNs>() as u64)
            }) as xmlNsPtr;
            if cur.is_null() {
                xmlTreeErrMemory(b"searching namespace\0" as *const u8 as *const i8);
                return 0 as xmlNsPtr;
            }
            (unsafe {
                memset(
                    cur as *mut libc::c_void,
                    0 as i32,
                    ::std::mem::size_of::<xmlNs>() as u64,
                )
            });
            (unsafe { (*cur).type_0 = XML_NAMESPACE_DECL });
            let fresh303 = unsafe { &mut ((*cur).href) };
            *fresh303 = xmlStrdup(
                b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8
                    as *const xmlChar,
            );
            let fresh304 = unsafe { &mut ((*cur).prefix) };
            *fresh304 = xmlStrdup(b"xml\0" as *const u8 as *const i8 as *const xmlChar);
            let fresh305 = unsafe { &mut ((*cur).next) };
            *fresh305 = unsafe { (*node).nsDef };
            let fresh306 = unsafe { &mut ((*node).nsDef) };
            *fresh306 = cur;
            return cur;
        }
        if doc.is_null() {
            doc = unsafe { (*node).doc };
            if doc.is_null() {
                return 0 as xmlNsPtr;
            }
        }
        if (unsafe { (*doc).oldNs }).is_null() {
            return xmlTreeEnsureXMLDecl(doc);
        } else {
            return unsafe { (*doc).oldNs };
        }
    }
    is_attr = ((unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32) as i32;
    while !node.is_null() {
        if (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_REF_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_NODE as i32 as u32
            || (unsafe { (*node).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
        {
            return 0 as xmlNsPtr;
        }
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            cur = unsafe { (*node).nsDef };
            while !cur.is_null() {
                if !(unsafe { (*cur).href }).is_null()
                    && !href.is_null()
                    && xmlStrEqual(unsafe { (*cur).href }, href) != 0
                {
                    if (is_attr == 0 || !(unsafe { (*cur).prefix }).is_null())
                        && xmlNsInScope(doc, orig, node, unsafe { (*cur).prefix }) == 1 as i32
                    {
                        return cur;
                    }
                }
                cur = unsafe { (*cur).next };
            }
            if orig != node {
                cur = unsafe { (*node).ns };
                if !cur.is_null() {
                    if !(unsafe { (*cur).href }).is_null()
                        && !href.is_null()
                        && xmlStrEqual(unsafe { (*cur).href }, href) != 0
                    {
                        if (is_attr == 0 || !(unsafe { (*cur).prefix }).is_null())
                            && xmlNsInScope(doc, orig, node, unsafe { (*cur).prefix }) == 1 as i32
                        {
                            return cur;
                        }
                    }
                }
            }
        }
        node = unsafe { (*node).parent };
    }
    return 0 as xmlNsPtr;
}
extern "C" fn xmlNewReconciledNs(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut tree: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
) -> *mut crate::src::threads::_xmlNs {
    let mut def: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut prefix: [u8; 50] = [0; 50];
    let mut counter: i32 = 1 as i32;
    if tree.is_null() || (unsafe { (*tree).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 0 as xmlNsPtr;
    }
    if ns.is_null() || (unsafe { (*ns).type_0 }) as u32 != XML_NAMESPACE_DECL as i32 as u32 {
        return 0 as xmlNsPtr;
    }
    def = xmlSearchNsByHref(doc, tree, unsafe { (*ns).href });
    if !def.is_null() {
        return def;
    }
    if (unsafe { (*ns).prefix }).is_null() {
        (unsafe {
            snprintf(
                prefix.as_mut_ptr() as *mut i8,
                ::std::mem::size_of::<[xmlChar; 50]>() as u64,
                b"default\0" as *const u8 as *const i8,
            )
        });
    } else {
        (unsafe {
            snprintf(
                prefix.as_mut_ptr() as *mut i8,
                ::std::mem::size_of::<[xmlChar; 50]>() as u64,
                b"%.20s\0" as *const u8 as *const i8,
                (*ns).prefix as *mut i8,
            )
        });
    }
    def = xmlSearchNs(doc, tree, prefix.as_mut_ptr());
    while !def.is_null() {
        if counter > 1000 as i32 {
            return 0 as xmlNsPtr;
        }
        if (unsafe { (*ns).prefix }).is_null() {
            let mut fresh307 = counter;
            counter = counter + 1;
            (unsafe {
                snprintf(
                    prefix.as_mut_ptr() as *mut i8,
                    ::std::mem::size_of::<[xmlChar; 50]>() as u64,
                    b"default%d\0" as *const u8 as *const i8,
                    fresh307,
                )
            });
        } else {
            let mut fresh308 = counter;
            counter = counter + 1;
            (unsafe {
                snprintf(
                    prefix.as_mut_ptr() as *mut i8,
                    ::std::mem::size_of::<[xmlChar; 50]>() as u64,
                    b"%.20s%d\0" as *const u8 as *const i8,
                    (*ns).prefix as *mut i8,
                    fresh308,
                )
            });
        }
        def = xmlSearchNs(doc, tree, prefix.as_mut_ptr());
    }
    def = xmlNewNs(tree, unsafe { (*ns).href }, prefix.as_mut_ptr());
    return def;
}
#[no_mangle]
pub extern "C" fn xmlReconciliateNs(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut tree: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut oldNs: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
    let mut newNs: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
    let mut sizeCache: i32 = 0 as i32;
    let mut nbCache: i32 = 0 as i32;
    let mut n: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut node: *mut crate::src::threads::_xmlNode = tree;
    let mut attr: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut ret: i32 = 0 as i32;
    let mut i: i32 = 0;
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return -(1 as i32);
    }
    if doc.is_null() || (unsafe { (*doc).type_0 }) as u32 != XML_DOCUMENT_NODE as i32 as u32 {
        return -(1 as i32);
    }
    if (unsafe { (*node).doc }) != doc {
        return -(1 as i32);
    }
    while !node.is_null() {
        if !(unsafe { (*node).ns }).is_null() {
            if sizeCache == 0 as i32 {
                sizeCache = 10 as i32;
                oldNs = (unsafe {
                    xmlMalloc.expect("non-null function pointer")(
                        (sizeCache as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                    )
                }) as *mut xmlNsPtr;
                if oldNs.is_null() {
                    xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                    return -(1 as i32);
                }
                newNs = (unsafe {
                    xmlMalloc.expect("non-null function pointer")(
                        (sizeCache as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                    )
                }) as *mut xmlNsPtr;
                if newNs.is_null() {
                    xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(oldNs as *mut libc::c_void)
                    });
                    return -(1 as i32);
                }
            }
            i = 0 as i32;
            while i < nbCache {
                if (unsafe { *oldNs.offset(i as isize) }) == (unsafe { (*node).ns }) {
                    let fresh309 = unsafe { &mut ((*node).ns) };
                    *fresh309 = unsafe { *newNs.offset(i as isize) };
                    break;
                } else {
                    i += 1;
                }
            }
            if i == nbCache {
                n = xmlNewReconciledNs(doc, tree, unsafe { (*node).ns });
                if !n.is_null() {
                    if sizeCache <= nbCache {
                        sizeCache *= 2 as i32;
                        oldNs = (unsafe {
                            xmlRealloc.expect("non-null function pointer")(
                                oldNs as *mut libc::c_void,
                                (sizeCache as u64)
                                    .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                            )
                        }) as *mut xmlNsPtr;
                        if oldNs.is_null() {
                            xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    newNs as *mut libc::c_void,
                                )
                            });
                            return -(1 as i32);
                        }
                        newNs = (unsafe {
                            xmlRealloc.expect("non-null function pointer")(
                                newNs as *mut libc::c_void,
                                (sizeCache as u64)
                                    .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                            )
                        }) as *mut xmlNsPtr;
                        if newNs.is_null() {
                            xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    oldNs as *mut libc::c_void,
                                )
                            });
                            return -(1 as i32);
                        }
                    }
                    let fresh310 = unsafe { &mut (*newNs.offset(nbCache as isize)) };
                    *fresh310 = n;
                    let mut fresh311 = nbCache;
                    nbCache = nbCache + 1;
                    let fresh312 = unsafe { &mut (*oldNs.offset(fresh311 as isize)) };
                    *fresh312 = unsafe { (*node).ns };
                    let fresh313 = unsafe { &mut ((*node).ns) };
                    *fresh313 = n;
                }
            }
        }
        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            attr = unsafe { (*node).properties };
            while !attr.is_null() {
                if !(unsafe { (*attr).ns }).is_null() {
                    if sizeCache == 0 as i32 {
                        sizeCache = 10 as i32;
                        oldNs = (unsafe {
                            xmlMalloc.expect("non-null function pointer")(
                                (sizeCache as u64)
                                    .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                            )
                        }) as *mut xmlNsPtr;
                        if oldNs.is_null() {
                            xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                            return -(1 as i32);
                        }
                        newNs = (unsafe {
                            xmlMalloc.expect("non-null function pointer")(
                                (sizeCache as u64)
                                    .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
                            )
                        }) as *mut xmlNsPtr;
                        if newNs.is_null() {
                            xmlTreeErrMemory(b"fixing namespaces\0" as *const u8 as *const i8);
                            (unsafe {
                                xmlFree.expect("non-null function pointer")(
                                    oldNs as *mut libc::c_void,
                                )
                            });
                            return -(1 as i32);
                        }
                    }
                    i = 0 as i32;
                    while i < nbCache {
                        if (unsafe { *oldNs.offset(i as isize) }) == (unsafe { (*attr).ns }) {
                            let fresh314 = unsafe { &mut ((*attr).ns) };
                            *fresh314 = unsafe { *newNs.offset(i as isize) };
                            break;
                        } else {
                            i += 1;
                        }
                    }
                    if i == nbCache {
                        n = xmlNewReconciledNs(doc, tree, unsafe { (*attr).ns });
                        if !n.is_null() {
                            if sizeCache <= nbCache {
                                sizeCache *= 2 as i32;
                                oldNs = (unsafe {
                                    xmlRealloc.expect("non-null function pointer")(
                                        oldNs as *mut libc::c_void,
                                        (sizeCache as u64).wrapping_mul(::std::mem::size_of::<
                                            xmlNsPtr,
                                        >(
                                        )
                                            as u64),
                                    )
                                }) as *mut xmlNsPtr;
                                if oldNs.is_null() {
                                    xmlTreeErrMemory(
                                        b"fixing namespaces\0" as *const u8 as *const i8,
                                    );
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            newNs as *mut libc::c_void,
                                        )
                                    });
                                    return -(1 as i32);
                                }
                                newNs = (unsafe {
                                    xmlRealloc.expect("non-null function pointer")(
                                        newNs as *mut libc::c_void,
                                        (sizeCache as u64).wrapping_mul(::std::mem::size_of::<
                                            xmlNsPtr,
                                        >(
                                        )
                                            as u64),
                                    )
                                }) as *mut xmlNsPtr;
                                if newNs.is_null() {
                                    xmlTreeErrMemory(
                                        b"fixing namespaces\0" as *const u8 as *const i8,
                                    );
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            oldNs as *mut libc::c_void,
                                        )
                                    });
                                    return -(1 as i32);
                                }
                            }
                            let fresh315 = unsafe { &mut (*newNs.offset(nbCache as isize)) };
                            *fresh315 = n;
                            let mut fresh316 = nbCache;
                            nbCache = nbCache + 1;
                            let fresh317 = unsafe { &mut (*oldNs.offset(fresh316 as isize)) };
                            *fresh317 = unsafe { (*attr).ns };
                            let fresh318 = unsafe { &mut ((*attr).ns) };
                            *fresh318 = n;
                        }
                    }
                }
                attr = unsafe { (*attr).next };
            }
        }
        if !(unsafe { (*node).children }).is_null()
            && (unsafe { (*node).type_0 }) as u32 != XML_ENTITY_REF_NODE as i32 as u32
        {
            node = unsafe { (*node).children };
        } else if node != tree && !(unsafe { (*node).next }).is_null() {
            node = unsafe { (*node).next };
        } else {
            if !(node != tree) {
                break;
            }
            while node != tree {
                if !(unsafe { (*node).parent }).is_null() {
                    node = unsafe { (*node).parent };
                }
                if node != tree && !(unsafe { (*node).next }).is_null() {
                    node = unsafe { (*node).next };
                    break;
                } else {
                    if !(unsafe { (*node).parent }).is_null() {
                        continue;
                    }
                    node = 0 as xmlNodePtr;
                    break;
                }
            }
            if node == tree {
                node = 0 as xmlNodePtr;
            }
        }
    }
    if !oldNs.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(oldNs as *mut libc::c_void) });
    }
    if !newNs.is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")(newNs as *mut libc::c_void) });
    }
    return ret;
}
extern "C" fn xmlGetPropNodeInternal(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut nsName: *const u8,
    mut useDTD: i32,
) -> *mut crate::src::threads::_xmlAttr {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if node.is_null()
        || (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        || name.is_null()
    {
        return 0 as xmlAttrPtr;
    }
    if !(unsafe { (*node).properties }).is_null() {
        prop = unsafe { (*node).properties };
        if nsName.is_null() {
            loop {
                if (unsafe { (*prop).ns }).is_null()
                    && xmlStrEqual(unsafe { (*prop).name }, name) != 0
                {
                    return prop;
                }
                prop = unsafe { (*prop).next };
                if prop.is_null() {
                    break;
                }
            }
        } else {
            loop {
                if !(unsafe { (*prop).ns }).is_null()
                    && xmlStrEqual(unsafe { (*prop).name }, name) != 0
                    && ((unsafe { (*(*prop).ns).href }) == nsName
                        || xmlStrEqual(unsafe { (*(*prop).ns).href }, nsName) != 0)
                {
                    return prop;
                }
                prop = unsafe { (*prop).next };
                if prop.is_null() {
                    break;
                }
            }
        }
    }
    if useDTD == 0 {
        return 0 as xmlAttrPtr;
    }
    if !(unsafe { (*node).doc }).is_null() && !(unsafe { (*(*node).doc).intSubset }).is_null() {
        let mut doc: *mut crate::src::threads::_xmlDoc = unsafe { (*node).doc };
        let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as xmlAttributePtr;
        let mut elemQName: *mut u8 = 0 as *mut xmlChar;
        let mut tmpstr: *mut u8 = 0 as *mut xmlChar;
        if !(unsafe { (*node).ns }).is_null() && !(unsafe { (*(*node).ns).prefix }).is_null() {
            tmpstr = xmlStrdup(unsafe { (*(*node).ns).prefix });
            tmpstr = xmlStrcat(tmpstr, b":\0" as *const u8 as *const i8 as *mut xmlChar);
            tmpstr = xmlStrcat(tmpstr, unsafe { (*node).name });
            if tmpstr.is_null() {
                return 0 as xmlAttrPtr;
            }
            elemQName = tmpstr;
        } else {
            elemQName = (unsafe { (*node).name }) as *mut xmlChar;
        }
        if nsName.is_null() {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                elemQName,
                name,
                0 as *const xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    elemQName,
                    name,
                    0 as *const xmlChar,
                );
            }
        } else if xmlStrEqual(
            nsName,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
        ) != 0
        {
            attrDecl = xmlGetDtdQAttrDesc(
                unsafe { (*doc).intSubset },
                elemQName,
                name,
                b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdQAttrDesc(
                    unsafe { (*doc).extSubset },
                    elemQName,
                    name,
                    b"xml\0" as *const u8 as *const i8 as *mut xmlChar,
                );
            }
        } else {
            let mut nsList: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
            let mut cur: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
            nsList = xmlGetNsList(unsafe { (*node).doc }, node);
            if nsList.is_null() {
                if !tmpstr.is_null() {
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(tmpstr as *mut libc::c_void)
                    });
                }
                return 0 as xmlAttrPtr;
            }
            cur = nsList;
            while !(unsafe { *cur }).is_null() {
                if xmlStrEqual(unsafe { (**cur).href }, nsName) != 0 {
                    attrDecl = xmlGetDtdQAttrDesc(
                        unsafe { (*doc).intSubset },
                        elemQName,
                        name,
                        unsafe { (**cur).prefix },
                    );
                    if !attrDecl.is_null() {
                        break;
                    }
                    if !(unsafe { (*doc).extSubset }).is_null() {
                        attrDecl = xmlGetDtdQAttrDesc(
                            unsafe { (*doc).extSubset },
                            elemQName,
                            name,
                            unsafe { (**cur).prefix },
                        );
                        if !attrDecl.is_null() {
                            break;
                        }
                    }
                }
                cur = unsafe { cur.offset(1) };
            }
            (unsafe { xmlFree.expect("non-null function pointer")(nsList as *mut libc::c_void) });
        }
        if !tmpstr.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(tmpstr as *mut libc::c_void) });
        }
        if !attrDecl.is_null() && !(unsafe { (*attrDecl).defaultValue }).is_null() {
            return attrDecl as xmlAttrPtr;
        }
    }
    return 0 as xmlAttrPtr;
}
extern "C" fn xmlGetPropNodeValueInternal(
    mut prop: *const crate::src::threads::_xmlAttr,
) -> *mut u8 {
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    if (unsafe { (*prop).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
        if !(unsafe { (*prop).children }).is_null() {
            if (unsafe { (*(*prop).children).next }).is_null()
                && ((unsafe { (*(*prop).children).type_0 }) as u32 == XML_TEXT_NODE as i32 as u32
                    || (unsafe { (*(*prop).children).type_0 }) as u32
                        == XML_CDATA_SECTION_NODE as i32 as u32)
            {
                return xmlStrdup(unsafe { (*(*prop).children).content });
            } else {
                let mut ret: *mut u8 = 0 as *mut xmlChar;
                ret = xmlNodeListGetString(
                    unsafe { (*prop).doc },
                    unsafe { (*prop).children },
                    1 as i32,
                );
                if !ret.is_null() {
                    return ret;
                }
            }
        }
        return xmlStrdup(b"\0" as *const u8 as *const i8 as *mut xmlChar);
    } else {
        if (unsafe { (*prop).type_0 }) as u32 == XML_ATTRIBUTE_DECL as i32 as u32 {
            return xmlStrdup(unsafe { (*(prop as xmlAttributePtr)).defaultValue });
        }
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub extern "C" fn xmlHasProp(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    if node.is_null()
        || (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
        || name.is_null()
    {
        return 0 as xmlAttrPtr;
    }
    prop = unsafe { (*node).properties };
    while !prop.is_null() {
        if xmlStrEqual(unsafe { (*prop).name }, name) != 0 {
            return prop;
        }
        prop = unsafe { (*prop).next };
    }
    if (unsafe { xmlCheckDTD }) == 0 {
        return 0 as xmlAttrPtr;
    }
    doc = unsafe { (*node).doc };
    if !doc.is_null() {
        let mut attrDecl: *mut crate::src::tree::_xmlAttribute = 0 as *mut xmlAttribute;
        if !(unsafe { (*doc).intSubset }).is_null() {
            attrDecl = xmlGetDtdAttrDesc(
                unsafe { (*doc).intSubset },
                unsafe { (*node).name },
                name,
            );
            if attrDecl.is_null() && !(unsafe { (*doc).extSubset }).is_null() {
                attrDecl = xmlGetDtdAttrDesc(
                    unsafe { (*doc).extSubset },
                    unsafe { (*node).name },
                    name,
                );
            }
            if !attrDecl.is_null() && !(unsafe { (*attrDecl).defaultValue }).is_null() {
                return attrDecl as xmlAttrPtr;
            }
        }
    }
    return 0 as xmlAttrPtr;
}
#[no_mangle]
pub extern "C" fn xmlHasNsProp(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut nameSpace: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    return xmlGetPropNodeInternal(node, name, nameSpace, unsafe { xmlCheckDTD });
}
#[no_mangle]
pub extern "C" fn xmlGetProp(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
) -> *mut u8 {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    prop = xmlHasProp(node, name);
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub extern "C" fn xmlGetNoNsProp(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
) -> *mut u8 {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(node, name, 0 as *const xmlChar, unsafe { xmlCheckDTD });
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub extern "C" fn xmlGetNsProp(
    mut node: *const crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut nameSpace: *const u8,
) -> *mut u8 {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(node, name, nameSpace, unsafe { xmlCheckDTD });
    if prop.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlGetPropNodeValueInternal(prop as *const xmlAttr);
}
#[no_mangle]
pub extern "C" fn xmlUnsetProp(
    mut node: *mut crate::src::threads::_xmlNode,
    mut name: *const u8,
) -> i32 {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(node as *const xmlNode, name, 0 as *const xmlChar, 0 as i32);
    if prop.is_null() {
        return -(1 as i32);
    }
    xmlUnlinkNode(prop as xmlNodePtr);
    xmlFreeProp(prop);
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlUnsetNsProp<'a1>(
    mut node: *mut crate::src::threads::_xmlNode,
    mut ns: Option<&'a1 mut crate::src::threads::_xmlNs>,
    mut name: *const u8,
) -> i32 {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    prop = xmlGetPropNodeInternal(
        node as *const xmlNode,
        name,
        if !borrow(&ns).is_none() {
            (*(borrow(&ns)).unwrap()).href
        } else {
            0 as *const xmlChar
        },
        0 as i32,
    );
    if prop.is_null() {
        return -(1 as i32);
    }
    xmlUnlinkNode(prop as xmlNodePtr);
    xmlFreeProp(prop);
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlSetProp(
    mut node: *mut crate::src::threads::_xmlNode,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    let mut len: i32 = 0;
    let mut nqname: *const u8 = 0 as *const xmlChar;
    if node.is_null()
        || name.is_null()
        || (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return 0 as xmlAttrPtr;
    }
    nqname = xmlSplitQName3(name, Some(&mut len));
    if !nqname.is_null() {
        let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
        let mut prefix: *mut u8 = xmlStrndup(name, len);
        ns = xmlSearchNs(unsafe { (*node).doc }, node, prefix);
        if !prefix.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(prefix as *mut libc::c_void) });
        }
        if !ns.is_null() {
            return xmlSetNsProp(node, ns, nqname, value);
        }
    }
    return xmlSetNsProp(node, 0 as xmlNsPtr, name, value);
}
#[no_mangle]
pub extern "C" fn xmlSetNsProp(
    mut node: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut name: *const u8,
    mut value: *const u8,
) -> *mut crate::src::threads::_xmlAttr {
    let mut prop: *mut crate::src::threads::_xmlAttr = 0 as *mut xmlAttr;
    if !ns.is_null() && (unsafe { (*ns).href }).is_null() {
        return 0 as xmlAttrPtr;
    }
    prop = xmlGetPropNodeInternal(
        node as *const xmlNode,
        name,
        if !ns.is_null() {
            unsafe { (*ns).href }
        } else {
            0 as *const xmlChar
        },
        0 as i32,
    );
    if !prop.is_null() {
        if (unsafe { (*prop).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
            xmlRemoveID(unsafe { (*node).doc }, prop);
            (unsafe { (*prop).atype = XML_ATTRIBUTE_ID });
        }
        if !(unsafe { (*prop).children }).is_null() {
            xmlFreeNodeList(unsafe { (*prop).children });
        }
        let fresh319 = unsafe { &mut ((*prop).children) };
        *fresh319 = 0 as *mut _xmlNode;
        let fresh320 = unsafe { &mut ((*prop).last) };
        *fresh320 = 0 as *mut _xmlNode;
        let fresh321 = unsafe { &mut ((*prop).ns) };
        *fresh321 = ns;
        if !value.is_null() {
            let mut tmp: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            let fresh322 = unsafe { &mut ((*prop).children) };
            *fresh322 = xmlNewDocText(unsafe { (*node).doc }, value);
            let fresh323 = unsafe { &mut ((*prop).last) };
            *fresh323 = 0 as *mut _xmlNode;
            tmp = unsafe { (*prop).children };
            while !tmp.is_null() {
                let fresh324 = unsafe { &mut ((*tmp).parent) };
                *fresh324 = prop as xmlNodePtr;
                if (unsafe { (*tmp).next }).is_null() {
                    let fresh325 = unsafe { &mut ((*prop).last) };
                    *fresh325 = tmp;
                }
                tmp = unsafe { (*tmp).next };
            }
        }
        if (unsafe { (*prop).atype }) as u32 == XML_ATTRIBUTE_ID as i32 as u32 {
            xmlAddID(0 as xmlValidCtxtPtr, unsafe { (*node).doc }, value, prop);
        }
        return prop;
    }
    return xmlNewPropInternal(node, ns, name, value, 0 as i32);
}
#[no_mangle]
pub extern "C" fn xmlNodeIsText<'a1>(mut node: Option<&'a1 crate::src::threads::_xmlNode>) -> i32 {
    if (node).clone().is_none() {
        return 0 as i32;
    }
    if (*((node).clone()).unwrap()).type_0 as u32 == XML_TEXT_NODE as i32 as u32 {
        return 1 as i32;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlIsBlankNode(mut node: *const crate::src::threads::_xmlNode) -> i32 {
    let mut cur: *const u8 = 0 as *const xmlChar;
    if node.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_CDATA_SECTION_NODE as i32 as u32
    {
        return 0 as i32;
    }
    if (unsafe { (*node).content }).is_null() {
        return 1 as i32;
    }
    cur = unsafe { (*node).content };
    while (unsafe { *cur }) as i32 != 0 as i32 {
        if !((unsafe { *cur }) as i32 == 0x20 as i32
            || 0x9 as i32 <= (unsafe { *cur }) as i32 && (unsafe { *cur }) as i32 <= 0xa as i32
            || (unsafe { *cur }) as i32 == 0xd as i32)
        {
            return 0 as i32;
        }
        cur = unsafe { cur.offset(1) };
    }
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlTextConcat(
    mut node: *mut crate::src::threads::_xmlNode,
    mut content: *const u8,
    mut len: i32,
) -> i32 {
    if node.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_TEXT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_CDATA_SECTION_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_COMMENT_NODE as i32 as u32
        && (unsafe { (*node).type_0 }) as u32 != XML_PI_NODE as i32 as u32
    {
        return -(1 as i32);
    }
    if (unsafe { (*node).content })
        == (unsafe { &mut (*node).properties }) as *mut *mut _xmlAttr as *mut xmlChar
        || !(unsafe { (*node).doc }).is_null()
            && !(unsafe { (*(*node).doc).dict }).is_null()
            && (unsafe { xmlDictOwns((*(*node).doc).dict, (*node).content) }) != 0
    {
        let fresh326 = unsafe { &mut ((*node).content) };
        *fresh326 = xmlStrncatNew(unsafe { (*node).content }, content, len);
    } else {
        let fresh327 = unsafe { &mut ((*node).content) };
        *fresh327 = xmlStrncat(unsafe { (*node).content }, content, len);
    }
    let fresh328 = unsafe { &mut ((*node).properties) };
    *fresh328 = 0 as *mut _xmlAttr;
    if (unsafe { (*node).content }).is_null() {
        return -(1 as i32);
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferCreate() -> *mut crate::src::tree::_xmlBuffer {
    let mut ret: *mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlBuffer>() as u64)
    }) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return 0 as xmlBufferPtr;
    }
    (unsafe { (*ret).use_0 = 0 as i32 as u32 });
    (unsafe { (*ret).size = *__xmlDefaultBufferSize() as u32 });
    (unsafe { (*ret).alloc = *__xmlBufferAllocScheme() });
    let fresh329 = unsafe { &mut ((*ret).content) };
    *fresh329 = (unsafe {
        xmlMallocAtomic.expect("non-null function pointer")(
            ((*ret).size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    }) as *mut xmlChar;
    if (unsafe { (*ret).content }).is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
        return 0 as xmlBufferPtr;
    }
    (unsafe { *((*ret).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
    let fresh330 = unsafe { &mut ((*ret).contentIO) };
    *fresh330 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlBufferCreateSize(mut size: u64) -> *mut crate::src::tree::_xmlBuffer {
    let mut ret: *mut crate::src::tree::_xmlBuffer = 0 as *mut xmlBuffer;
    if size
        >= (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32) as u64
    {
        return 0 as xmlBufferPtr;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlBuffer>() as u64)
    }) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return 0 as xmlBufferPtr;
    }
    (unsafe { (*ret).use_0 = 0 as i32 as u32 });
    (unsafe { (*ret).alloc = *__xmlBufferAllocScheme() });
    (unsafe {
        (*ret).size = (if size != 0 {
            size.wrapping_add(1 as i32 as u64)
        } else {
            0 as i32 as u64
        }) as u32
    });
    if (unsafe { (*ret).size }) != 0 {
        let fresh331 = unsafe { &mut ((*ret).content) };
        *fresh331 = (unsafe {
            xmlMallocAtomic.expect("non-null function pointer")(
                ((*ret).size as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
            )
        }) as *mut xmlChar;
        if (unsafe { (*ret).content }).is_null() {
            xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const i8);
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as xmlBufferPtr;
        }
        (unsafe { *((*ret).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
    } else {
        let fresh332 = unsafe { &mut ((*ret).content) };
        *fresh332 = 0 as *mut xmlChar;
    }
    let fresh333 = unsafe { &mut ((*ret).contentIO) };
    *fresh333 = 0 as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlBufferDetach<'a1>(
    mut buf: Option<&'a1 mut crate::src::tree::_xmlBuffer>,
) -> *mut u8 {
    let mut ret: *mut u8 = 0 as *mut xmlChar;
    if borrow(&buf).is_none() {
        return 0 as *mut xmlChar;
    }
    if (*(borrow(&buf)).unwrap()).alloc as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return 0 as *mut xmlChar;
    }
    ret = (*(borrow_mut(&mut buf)).unwrap()).content;
    let fresh334 = &mut ((*(borrow_mut(&mut buf)).unwrap()).content);
    *fresh334 = 0 as *mut xmlChar;
    (*(borrow_mut(&mut buf)).unwrap()).size = 0 as i32 as u32;
    (*(borrow_mut(&mut buf)).unwrap()).use_0 = 0 as i32 as u32;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlBufferCreateStatic(
    mut mem: *mut core::ffi::c_void,
    mut size: u64,
) -> *mut crate::src::tree::_xmlBuffer {
    let mut ret: *mut crate::src::tree::_xmlBuffer = 0 as *mut crate::src::tree::_xmlBuffer;
    if mem.is_null() || size == 0 as i32 as u64 {
        return 0 as *mut crate::src::tree::_xmlBuffer;
    }
    if size
        > (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32) as u64
    {
        return 0 as *mut crate::src::tree::_xmlBuffer;
    }
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlBuffer>() as u64)
    }) as xmlBufferPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"creating buffer\0" as *const u8 as *const i8);
        return 0 as *mut crate::src::tree::_xmlBuffer;
    }
    (unsafe { (*ret).use_0 = size as u32 });
    (unsafe { (*ret).size = size as u32 });
    (unsafe { (*ret).alloc = XML_BUFFER_ALLOC_IMMUTABLE });
    let fresh335 = unsafe { &mut ((*ret).content) };
    *fresh335 = mem as *mut xmlChar;
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlBufferSetAllocationScheme(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut scheme: u32,
) {
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        || (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
    {
        return;
    }
    if scheme as u32 == XML_BUFFER_ALLOC_DOUBLEIT as i32 as u32
        || scheme as u32 == XML_BUFFER_ALLOC_EXACT as i32 as u32
        || scheme as u32 == XML_BUFFER_ALLOC_HYBRID as i32 as u32
        || scheme as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        (unsafe { (*buf).alloc = scheme });
    }
}
#[no_mangle]
pub extern "C" fn xmlBufferFree(mut buf: *mut crate::src::tree::_xmlBuffer) {
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !(unsafe { (*buf).contentIO }).is_null()
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*buf).contentIO as *mut libc::c_void)
        });
    } else if !(unsafe { (*buf).content }).is_null()
        && (unsafe { (*buf).alloc }) as u32 != XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
    {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*buf).content as *mut libc::c_void)
        });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void) });
}
#[no_mangle]
pub extern "C" fn xmlBufferEmpty(mut buf: *mut crate::src::tree::_xmlBuffer) {
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).content }).is_null() {
        return;
    }
    (unsafe { (*buf).use_0 = 0 as i32 as u32 });
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        let fresh336 = unsafe { &mut ((*buf).content) };
        *fresh336 = b"\0" as *const u8 as *const i8 as *mut xmlChar;
    } else if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !(unsafe { (*buf).contentIO }).is_null()
    {
        let mut start_buf: u64 =
            (unsafe { ((*buf).content).offset_from((*buf).contentIO) }) as i64 as size_t;
        let fresh337 = unsafe { &mut ((*buf).size) };
        *fresh337 = (*fresh337 as u64).wrapping_add(start_buf) as u32 as u32;
        let fresh338 = unsafe { &mut ((*buf).content) };
        *fresh338 = unsafe { (*buf).contentIO };
        (unsafe { *((*buf).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
    } else {
        (unsafe { *((*buf).content).offset(0 as i32 as isize) = 0 as i32 as xmlChar });
    };
}
#[no_mangle]
pub extern "C" fn xmlBufferShrink(mut buf: *mut crate::src::tree::_xmlBuffer, mut len: u32) -> i32 {
    if buf.is_null() {
        return -(1 as i32);
    }
    if len == 0 as i32 as u32 {
        return 0 as i32;
    }
    if len > (unsafe { (*buf).use_0 }) {
        return -(1 as i32);
    }
    let fresh339 = unsafe { &mut ((*buf).use_0) };
    *fresh339 = (*fresh339).wrapping_sub(len);
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32
        || (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
            && !(unsafe { (*buf).contentIO }).is_null()
    {
        let fresh340 = unsafe { &mut ((*buf).content) };
        *fresh340 = unsafe { (*fresh340).offset(len as isize) };
        let fresh341 = unsafe { &mut ((*buf).size) };
        *fresh341 = (*fresh341).wrapping_sub(len);
        if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
            && !(unsafe { (*buf).contentIO }).is_null()
        {
            let mut start_buf: u64 =
                (unsafe { ((*buf).content).offset_from((*buf).contentIO) }) as i64 as size_t;
            if start_buf >= (unsafe { (*buf).size }) as u64 {
                (unsafe {
                    memmove(
                        (*buf).contentIO as *mut libc::c_void,
                        &mut *((*buf).content).offset(0 as i32 as isize) as *mut xmlChar
                            as *const libc::c_void,
                        (*buf).use_0 as u64,
                    )
                });
                let fresh342 = unsafe { &mut ((*buf).content) };
                *fresh342 = unsafe { (*buf).contentIO };
                (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
                let fresh343 = unsafe { &mut ((*buf).size) };
                *fresh343 = (*fresh343 as u64).wrapping_add(start_buf) as u32 as u32;
            }
        }
    } else {
        (unsafe {
            memmove(
                (*buf).content as *mut libc::c_void,
                &mut *((*buf).content).offset(len as isize) as *mut xmlChar as *const libc::c_void,
                (*buf).use_0 as u64,
            )
        });
        (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
    }
    return len as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferGrow<'a1>(
    mut buf: Option<&'a1 mut crate::src::tree::_xmlBuffer>,
    mut len: u32,
) -> i32 {
    let mut size: u32 = 0;
    let mut newbuf: *mut u8 = 0 as *mut xmlChar;
    if borrow(&buf).is_none() {
        return -(1 as i32);
    }
    if (*(borrow(&buf)).unwrap()).alloc as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return 0 as i32;
    }
    if len < ((*(borrow(&buf)).unwrap()).size).wrapping_sub((*(borrow(&buf)).unwrap()).use_0) {
        return 0 as i32;
    }
    if len
        >= (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32)
            .wrapping_sub((*(borrow(&buf)).unwrap()).use_0)
    {
        xmlTreeErrMemory(b"growing buffer past UINT_MAX\0" as *const u8 as *const i8);
        return -(1 as i32);
    }
    if (*(borrow(&buf)).unwrap()).size as u64 > len as size_t {
        size = if (*(borrow(&buf)).unwrap()).size
            > (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
                .wrapping_div(2 as i32 as u32)
        {
            (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
        } else {
            ((*(borrow(&buf)).unwrap()).size).wrapping_mul(2 as i32 as u32)
        };
    } else {
        size = ((*(borrow(&buf)).unwrap()).use_0).wrapping_add(len);
        size = if size
            > (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
                .wrapping_sub(100 as i32 as u32)
        {
            (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
        } else {
            size.wrapping_add(100 as i32 as u32)
        };
    }
    if (*(borrow(&buf)).unwrap()).alloc as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !((*(borrow(&buf)).unwrap()).contentIO).is_null()
    {
        let mut start_buf: u64 = (unsafe {
            ((*(borrow(&buf)).unwrap()).content).offset_from((*(borrow(&buf)).unwrap()).contentIO)
        }) as i64 as size_t;
        newbuf = (unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*(borrow_mut(&mut buf)).unwrap()).contentIO as *mut libc::c_void,
                start_buf.wrapping_add(size as u64),
            )
        }) as *mut xmlChar;
        if newbuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        let fresh344 = &mut ((*(borrow_mut(&mut buf)).unwrap()).contentIO);
        *fresh344 = newbuf;
        let fresh345 = &mut ((*(borrow_mut(&mut buf)).unwrap()).content);
        *fresh345 = unsafe { newbuf.offset(start_buf as isize) };
    } else {
        newbuf = (unsafe {
            xmlRealloc.expect("non-null function pointer")(
                (*(borrow_mut(&mut buf)).unwrap()).content as *mut libc::c_void,
                size as size_t,
            )
        }) as *mut xmlChar;
        if newbuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        let fresh346 = &mut ((*(borrow_mut(&mut buf)).unwrap()).content);
        *fresh346 = newbuf;
    }
    (*(borrow_mut(&mut buf)).unwrap()).size = size;
    return ((*(borrow(&buf)).unwrap()).size)
        .wrapping_sub((*(borrow(&buf)).unwrap()).use_0)
        .wrapping_sub(1 as i32 as u32) as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferDump<'a1>(
    mut file: *mut crate::src::tree::_IO_FILE,
    mut buf: Option<&'a1 mut crate::src::tree::_xmlBuffer>,
) -> i32 {
    let mut ret: u64 = 0;
    if borrow(&buf).is_none() {
        return 0 as i32;
    }
    if ((*(borrow_mut(&mut buf)).unwrap()).content).is_null() {
        return 0 as i32;
    }
    if file.is_null() {
        file = unsafe { stdout };
    }
    ret = unsafe {
        fwrite(
            (*(borrow(&buf)).unwrap()).content as *const libc::c_void,
            ::std::mem::size_of::<xmlChar>() as u64,
            (*(borrow_mut(&mut buf)).unwrap()).use_0 as u64,
            file,
        )
    };
    return if ret > 2147483647 as i32 as u64 {
        2147483647 as i32
    } else {
        ret as i32
    };
}
#[no_mangle]
pub extern "C" fn xmlBufferContent<'a1>(
    mut buf: Option<&'a1 crate::src::tree::_xmlBuffer>,
) -> *const u8 {
    if (buf).clone().is_none() {
        return 0 as *const xmlChar;
    }
    return (*((buf).clone()).unwrap()).content;
}
#[no_mangle]
pub extern "C" fn xmlBufferLength<'a1>(mut buf: Option<&'a1 crate::src::tree::_xmlBuffer>) -> i32 {
    if (buf).clone().is_none() {
        return 0 as i32;
    }
    return (*((buf).clone()).unwrap()).use_0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferResize(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut size: u32,
) -> i32 {
    let mut newSize: u32 = 0;
    let mut rebuf: *mut u8 = 0 as *mut xmlChar;
    let mut start_buf: u64 = 0;
    if buf.is_null() {
        return 0 as i32;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return 0 as i32;
    }
    if size < (unsafe { (*buf).size }) {
        return 1 as i32;
    }
    if size
        > (2147483647 as i32 as u32)
            .wrapping_mul(2 as u32)
            .wrapping_add(1 as u32)
            .wrapping_sub(10 as i32 as u32)
    {
        xmlTreeErrMemory(b"growing buffer past UINT_MAX\0" as *const u8 as *const i8);
        return 0 as i32;
    }
    match (unsafe { (*buf).alloc }) as u32 {
        3 | 0 => {
            if (unsafe { (*buf).size }) == 0 as i32 as u32 {
                newSize = if size
                    > (2147483647 as i32 as u32)
                        .wrapping_mul(2 as u32)
                        .wrapping_add(1 as u32)
                        .wrapping_sub(10 as i32 as u32)
                {
                    (2147483647 as i32 as u32)
                        .wrapping_mul(2 as u32)
                        .wrapping_add(1 as u32)
                } else {
                    size.wrapping_add(10 as i32 as u32)
                };
            } else {
                newSize = unsafe { (*buf).size };
            }
            while size > newSize {
                if newSize
                    > (2147483647 as i32 as u32)
                        .wrapping_mul(2 as u32)
                        .wrapping_add(1 as u32)
                        .wrapping_div(2 as i32 as u32)
                {
                    xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
                    return 0 as i32;
                }
                newSize = newSize.wrapping_mul(2 as i32 as u32);
            }
        }
        1 => {
            newSize = if size
                > (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32)
                    .wrapping_sub(10 as i32 as u32)
            {
                (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32)
            } else {
                size.wrapping_add(10 as i32 as u32)
            };
        }
        4 => {
            if (unsafe { (*buf).use_0 }) < 4096 as i32 as u32 {
                newSize = size;
            } else {
                newSize = unsafe { (*buf).size };
                while size > newSize {
                    if newSize
                        > (2147483647 as i32 as u32)
                            .wrapping_mul(2 as u32)
                            .wrapping_add(1 as u32)
                            .wrapping_div(2 as i32 as u32)
                    {
                        xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
                        return 0 as i32;
                    }
                    newSize = newSize.wrapping_mul(2 as i32 as u32);
                }
            }
        }
        _ => {
            newSize = if size
                > (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32)
                    .wrapping_sub(10 as i32 as u32)
            {
                (2147483647 as i32 as u32)
                    .wrapping_mul(2 as u32)
                    .wrapping_add(1 as u32)
            } else {
                size.wrapping_add(10 as i32 as u32)
            };
        }
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !(unsafe { (*buf).contentIO }).is_null()
    {
        start_buf = (unsafe { ((*buf).content).offset_from((*buf).contentIO) }) as i64 as size_t;
        if start_buf > newSize as u64 {
            (unsafe {
                memmove(
                    (*buf).contentIO as *mut libc::c_void,
                    (*buf).content as *const libc::c_void,
                    (*buf).use_0 as u64,
                )
            });
            let fresh347 = unsafe { &mut ((*buf).content) };
            *fresh347 = unsafe { (*buf).contentIO };
            (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
            let fresh348 = unsafe { &mut ((*buf).size) };
            *fresh348 = (*fresh348 as u64).wrapping_add(start_buf) as u32 as u32;
        } else {
            rebuf = (unsafe {
                xmlRealloc.expect("non-null function pointer")(
                    (*buf).contentIO as *mut libc::c_void,
                    start_buf.wrapping_add(newSize as u64),
                )
            }) as *mut xmlChar;
            if rebuf.is_null() {
                xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
                return 0 as i32;
            }
            let fresh349 = unsafe { &mut ((*buf).contentIO) };
            *fresh349 = rebuf;
            let fresh350 = unsafe { &mut ((*buf).content) };
            *fresh350 = unsafe { rebuf.offset(start_buf as isize) };
        }
    } else {
        if (unsafe { (*buf).content }).is_null() {
            rebuf =
                (unsafe { xmlMallocAtomic.expect("non-null function pointer")(newSize as size_t) })
                    as *mut xmlChar;
            (unsafe { (*buf).use_0 = 0 as i32 as u32 });
            (unsafe { *rebuf.offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
        } else if (unsafe { (*buf).size }).wrapping_sub(unsafe { (*buf).use_0 })
            < 100 as i32 as u32
        {
            rebuf = (unsafe {
                xmlRealloc.expect("non-null function pointer")(
                    (*buf).content as *mut libc::c_void,
                    newSize as size_t,
                )
            }) as *mut xmlChar;
        } else {
            rebuf =
                (unsafe { xmlMallocAtomic.expect("non-null function pointer")(newSize as size_t) })
                    as *mut xmlChar;
            if !rebuf.is_null() {
                (unsafe {
                    memcpy(
                        rebuf as *mut libc::c_void,
                        (*buf).content as *const libc::c_void,
                        (*buf).use_0 as u64,
                    )
                });
                (unsafe {
                    xmlFree.expect("non-null function pointer")((*buf).content as *mut libc::c_void)
                });
                (unsafe { *rebuf.offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
            }
        }
        if rebuf.is_null() {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
            return 0 as i32;
        }
        let fresh351 = unsafe { &mut ((*buf).content) };
        *fresh351 = rebuf;
    }
    (unsafe { (*buf).size = newSize });
    return 1 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferAdd(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut str: *const u8,
    mut len: i32,
) -> i32 {
    let mut needSize: u32 = 0;
    if str.is_null() || buf.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return -(1 as i32);
    }
    if len < -(1 as i32) {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    if len < 0 as i32 {
        len = xmlStrlen(str);
    }
    if len < 0 as i32 {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    if len as u32 >= (unsafe { (*buf).size }).wrapping_sub(unsafe { (*buf).use_0 }) {
        if len as u32
            >= (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
                .wrapping_sub(unsafe { (*buf).use_0 })
        {
            xmlTreeErrMemory(b"growing buffer past UINT_MAX\0" as *const u8 as *const i8);
            return XML_ERR_NO_MEMORY as i32;
        }
        needSize = (unsafe { (*buf).use_0 })
            .wrapping_add(len as u32)
            .wrapping_add(1 as i32 as u32);
        if xmlBufferResize(buf, needSize) == 0 {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
            return XML_ERR_NO_MEMORY as i32;
        }
    }
    (unsafe {
        memmove(
            &mut *((*buf).content).offset((*buf).use_0 as isize) as *mut xmlChar
                as *mut libc::c_void,
            str as *const libc::c_void,
            (len as u64).wrapping_mul(::std::mem::size_of::<xmlChar>() as u64),
        )
    });
    let fresh352 = unsafe { &mut ((*buf).use_0) };
    *fresh352 = (*fresh352).wrapping_add(len as u32);
    (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferAddHead(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut str: *const u8,
    mut len: i32,
) -> i32 {
    let mut needSize: u32 = 0;
    if buf.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return -(1 as i32);
    }
    if str.is_null() {
        return -(1 as i32);
    }
    if len < -(1 as i32) {
        return -(1 as i32);
    }
    if len == 0 as i32 {
        return 0 as i32;
    }
    if len < 0 as i32 {
        len = xmlStrlen(str);
    }
    if len <= 0 as i32 {
        return -(1 as i32);
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IO as i32 as u32
        && !(unsafe { (*buf).contentIO }).is_null()
    {
        let mut start_buf: u64 =
            (unsafe { ((*buf).content).offset_from((*buf).contentIO) }) as i64 as size_t;
        if start_buf > len as u32 as u64 {
            let fresh353 = unsafe { &mut ((*buf).content) };
            *fresh353 = unsafe { (*fresh353).offset(-(len as isize)) };
            (unsafe {
                memmove(
                    &mut *((*buf).content).offset(0 as i32 as isize) as *mut xmlChar
                        as *mut libc::c_void,
                    str as *const libc::c_void,
                    len as u64,
                )
            });
            let fresh354 = unsafe { &mut ((*buf).use_0) };
            *fresh354 = (*fresh354).wrapping_add(len as u32);
            let fresh355 = unsafe { &mut ((*buf).size) };
            *fresh355 = (*fresh355).wrapping_add(len as u32);
            (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
            return 0 as i32;
        }
    }
    if len as u32 >= (unsafe { (*buf).size }).wrapping_sub(unsafe { (*buf).use_0 }) {
        if len as u32
            >= (2147483647 as i32 as u32)
                .wrapping_mul(2 as u32)
                .wrapping_add(1 as u32)
                .wrapping_sub(unsafe { (*buf).use_0 })
        {
            xmlTreeErrMemory(b"growing buffer past UINT_MAX\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        needSize = (unsafe { (*buf).use_0 })
            .wrapping_add(len as u32)
            .wrapping_add(1 as i32 as u32);
        if xmlBufferResize(buf, needSize) == 0 {
            xmlTreeErrMemory(b"growing buffer\0" as *const u8 as *const i8);
            return XML_ERR_NO_MEMORY as i32;
        }
    }
    (unsafe {
        memmove(
            &mut *((*buf).content).offset(len as isize) as *mut xmlChar as *mut libc::c_void,
            &mut *((*buf).content).offset(0 as i32 as isize) as *mut xmlChar as *const libc::c_void,
            (*buf).use_0 as u64,
        )
    });
    (unsafe {
        memmove(
            &mut *((*buf).content).offset(0 as i32 as isize) as *mut xmlChar as *mut libc::c_void,
            str as *const libc::c_void,
            len as u64,
        )
    });
    let fresh356 = unsafe { &mut ((*buf).use_0) };
    *fresh356 = (*fresh356).wrapping_add(len as u32);
    (unsafe { *((*buf).content).offset((*buf).use_0 as isize) = 0 as i32 as xmlChar });
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlBufferCat(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut str: *const u8,
) -> i32 {
    if buf.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return -(1 as i32);
    }
    if str.is_null() {
        return -(1 as i32);
    }
    return xmlBufferAdd(buf, str, -(1 as i32));
}
#[no_mangle]
pub extern "C" fn xmlBufferCCat(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut str: *const i8,
) -> i32 {
    return xmlBufferCat(buf, str as *const xmlChar);
}
#[no_mangle]
pub extern "C" fn xmlBufferWriteCHAR(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut string: *const u8,
) {
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return;
    }
    xmlBufferCat(buf, string);
}
#[no_mangle]
pub extern "C" fn xmlBufferWriteChar(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut string: *const i8,
) {
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return;
    }
    xmlBufferCCat(buf, string);
}
#[no_mangle]
pub extern "C" fn xmlBufferWriteQuotedString(
    mut buf: *mut crate::src::tree::_xmlBuffer,
    mut string: *const u8,
) {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut base: *const u8 = 0 as *const xmlChar;
    if buf.is_null() {
        return;
    }
    if (unsafe { (*buf).alloc }) as u32 == XML_BUFFER_ALLOC_IMMUTABLE as i32 as u32 {
        return;
    }
    if !(xmlStrchr(string, '"' as i32 as xmlChar)).is_null() {
        if !(xmlStrchr(string, '\'' as i32 as xmlChar)).is_null() {
            xmlBufferCCat(buf, b"\"\0" as *const u8 as *const i8);
            cur = string;
            base = cur;
            while (unsafe { *cur }) as i32 != 0 as i32 {
                if (unsafe { *cur }) as i32 == '"' as i32 {
                    if base != cur {
                        xmlBufferAdd(buf, base, (unsafe { cur.offset_from(base) }) as i64 as i32);
                    }
                    xmlBufferAdd(
                        buf,
                        b"&quot;\0" as *const u8 as *const i8 as *mut xmlChar,
                        6 as i32,
                    );
                    cur = unsafe { cur.offset(1) };
                    base = cur;
                } else {
                    cur = unsafe { cur.offset(1) };
                }
            }
            if base != cur {
                xmlBufferAdd(buf, base, (unsafe { cur.offset_from(base) }) as i64 as i32);
            }
            xmlBufferCCat(buf, b"\"\0" as *const u8 as *const i8);
        } else {
            xmlBufferCCat(buf, b"'\0" as *const u8 as *const i8);
            xmlBufferCat(buf, string);
            xmlBufferCCat(buf, b"'\0" as *const u8 as *const i8);
        }
    } else {
        xmlBufferCCat(buf, b"\"\0" as *const u8 as *const i8);
        xmlBufferCat(buf, string);
        xmlBufferCCat(buf, b"\"\0" as *const u8 as *const i8);
    };
}
#[no_mangle]
pub extern "C" fn xmlGetDocCompressMode<'a1>(
    mut doc: Option<&'a1 crate::src::threads::_xmlDoc>,
) -> i32 {
    if (doc).clone().is_none() {
        return -(1 as i32);
    }
    return (*((doc).clone()).unwrap()).compression;
}
#[no_mangle]
pub extern "C" fn xmlSetDocCompressMode(mut doc: *mut crate::src::threads::_xmlDoc, mut mode: i32) {
    if doc.is_null() {
        return;
    }
    if mode < 0 as i32 {
        (unsafe { (*doc).compression = 0 as i32 });
    } else if mode > 9 as i32 {
        (unsafe { (*doc).compression = 9 as i32 });
    } else {
        (unsafe { (*doc).compression = mode });
    };
}
#[no_mangle]
pub extern "C" fn xmlGetCompressMode() -> i32 {
    return unsafe { xmlCompressMode };
}
#[no_mangle]
pub extern "C" fn xmlSetCompressMode(mut mode: i32) {
    if mode < 0 as i32 {
        (unsafe { xmlCompressMode = 0 as i32 });
    } else if mode > 9 as i32 {
        (unsafe { xmlCompressMode = 9 as i32 });
    } else {
        (unsafe { xmlCompressMode = mode });
    };
}
extern "C" fn xmlDOMWrapNsMapFree(mut nsmap: *mut crate::src::tree::xmlNsMap) {
    let mut cur: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut tmp: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    if nsmap.is_null() {
        return;
    }
    cur = unsafe { (*nsmap).pool };
    while !cur.is_null() {
        tmp = cur;
        cur = unsafe { (*cur).next };
        (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
    }
    cur = unsafe { (*nsmap).first };
    while !cur.is_null() {
        tmp = cur;
        cur = unsafe { (*cur).next };
        (unsafe { xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void) });
    }
    (unsafe { xmlFree.expect("non-null function pointer")(nsmap as *mut libc::c_void) });
}
extern "C" fn xmlDOMWrapNsMapAddItem<'a1>(
    mut nsmap: Option<&'a1 mut *mut crate::src::tree::xmlNsMap>,
    mut position: i32,
    mut oldNs: *mut crate::src::threads::_xmlNs,
    mut newNs: *mut crate::src::threads::_xmlNs,
    mut depth: i32,
) -> *mut crate::src::tree::xmlNsMapItem {
    let mut ret: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut map: *mut crate::src::tree::xmlNsMap = 0 as *mut xmlNsMap;
    if borrow(&nsmap).is_none() {
        return 0 as xmlNsMapItemPtr;
    }
    if position != -(1 as i32) && position != 0 as i32 {
        return 0 as xmlNsMapItemPtr;
    }
    map = *(borrow_mut(&mut nsmap)).unwrap();
    if map.is_null() {
        map = (unsafe {
            xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlNsMap>() as u64)
        }) as xmlNsMapPtr;
        if map.is_null() {
            xmlTreeErrMemory(b"allocating namespace map\0" as *const u8 as *const i8);
            return 0 as xmlNsMapItemPtr;
        }
        (unsafe {
            memset(
                map as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNsMap>() as u64,
            )
        });
        *(borrow_mut(&mut nsmap)).unwrap() = map;
    }
    if !(unsafe { (*map).pool }).is_null() {
        ret = unsafe { (*map).pool };
        let fresh357 = unsafe { &mut ((*map).pool) };
        *fresh357 = unsafe { (*ret).next };
        (unsafe {
            memset(
                ret as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNsMapItem>() as u64,
            )
        });
    } else {
        ret = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                ::std::mem::size_of::<xmlNsMapItem>() as u64
            )
        }) as xmlNsMapItemPtr;
        if ret.is_null() {
            xmlTreeErrMemory(b"allocating namespace map item\0" as *const u8 as *const i8);
            return 0 as xmlNsMapItemPtr;
        }
        (unsafe {
            memset(
                ret as *mut libc::c_void,
                0 as i32,
                ::std::mem::size_of::<xmlNsMapItem>() as u64,
            )
        });
    }
    if (unsafe { (*map).first }).is_null() {
        let fresh358 = unsafe { &mut ((*map).first) };
        *fresh358 = ret;
        let fresh359 = unsafe { &mut ((*map).last) };
        *fresh359 = ret;
    } else if position == -(1 as i32) {
        let fresh360 = unsafe { &mut ((*ret).prev) };
        *fresh360 = unsafe { (*map).last };
        let fresh361 = unsafe { &mut ((*(*map).last).next) };
        *fresh361 = ret;
        let fresh362 = unsafe { &mut ((*map).last) };
        *fresh362 = ret;
    } else if position == 0 as i32 {
        let fresh363 = unsafe { &mut ((*(*map).first).prev) };
        *fresh363 = ret;
        let fresh364 = unsafe { &mut ((*ret).next) };
        *fresh364 = unsafe { (*map).first };
        let fresh365 = unsafe { &mut ((*map).first) };
        *fresh365 = ret;
    }
    let fresh366 = unsafe { &mut ((*ret).oldNs) };
    *fresh366 = oldNs;
    let fresh367 = unsafe { &mut ((*ret).newNs) };
    *fresh367 = newNs;
    (unsafe { (*ret).shadowDepth = -(1 as i32) });
    (unsafe { (*ret).depth = depth });
    return ret;
}
extern "C" fn xmlDOMWrapStoreNs(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut nsName: *const u8,
    mut prefix: *const u8,
) -> *mut crate::src::threads::_xmlNs {
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if doc.is_null() {
        return 0 as xmlNsPtr;
    }
    ns = xmlTreeEnsureXMLDecl(doc);
    if ns.is_null() {
        return 0 as xmlNsPtr;
    }
    if !(unsafe { (*ns).next }).is_null() {
        ns = unsafe { (*ns).next };
        while !ns.is_null() {
            if ((unsafe { (*ns).prefix }) == prefix
                || xmlStrEqual(unsafe { (*ns).prefix }, prefix) != 0)
                && xmlStrEqual(unsafe { (*ns).href }, nsName) != 0
            {
                return ns;
            }
            if (unsafe { (*ns).next }).is_null() {
                break;
            }
            ns = unsafe { (*ns).next };
        }
    }
    if !ns.is_null() {
        let fresh368 = unsafe { &mut ((*ns).next) };
        *fresh368 = xmlNewNs(0 as xmlNodePtr, nsName, prefix);
        return unsafe { (*ns).next };
    }
    return 0 as xmlNsPtr;
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapNewCtxt<'a1>() -> *mut crate::src::tree::_xmlDOMWrapCtxt<'a1> {
    let mut ret: *mut crate::src::tree::_xmlDOMWrapCtxt<'_> = 0 as *mut xmlDOMWrapCtxt;
    ret = (unsafe {
        xmlMalloc.expect("non-null function pointer")(::std::mem::size_of::<xmlDOMWrapCtxt>() as u64)
    }) as xmlDOMWrapCtxtPtr;
    if ret.is_null() {
        xmlTreeErrMemory(b"allocating DOM-wrapper context\0" as *const u8 as *const i8);
        return 0 as xmlDOMWrapCtxtPtr;
    }
    (unsafe {
        memset(
            ret as *mut libc::c_void,
            0 as i32,
            ::std::mem::size_of::<xmlDOMWrapCtxt>() as u64,
        )
    });
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapFreeCtxt<'a1>(mut ctxt: *mut crate::src::tree::_xmlDOMWrapCtxt<'a1>) {
    if ctxt.is_null() {
        return;
    }
    if !(unsafe { (*ctxt).namespaceMap }).is_null() {
        xmlDOMWrapNsMapFree((unsafe { (*ctxt).namespaceMap }) as xmlNsMapPtr);
    }
    (unsafe { xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void) });
}
extern "C" fn xmlTreeNSListLookupByPrefix(
    mut nsList: *mut crate::src::threads::_xmlNs,
    mut prefix: *const u8,
) -> *mut crate::src::threads::_xmlNs {
    if nsList.is_null() {
        return 0 as xmlNsPtr;
    }
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    ns = nsList;
    loop {
        if prefix == (unsafe { (*ns).prefix })
            || xmlStrEqual(prefix, unsafe { (*ns).prefix }) != 0
        {
            return ns;
        }
        ns = unsafe { (*ns).next };
        if ns.is_null() {
            break;
        }
    }
    return 0 as xmlNsPtr;
}
extern "C" fn xmlDOMWrapNSNormGatherInScopeNs<'a1>(
    mut map: Option<&'a1 mut *mut crate::src::tree::xmlNsMap>,
    mut node: *mut crate::src::threads::_xmlNode,
) -> i32 {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut mi: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut shadowed: i32 = 0;
    if borrow(&map).is_none() || !(*(borrow_mut(&mut map)).unwrap()).is_null() {
        return -(1 as i32);
    }
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return -(1 as i32);
    }
    cur = node;
    while !cur.is_null() && cur != (unsafe { (*cur).doc }) as xmlNodePtr {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            if !(unsafe { (*cur).nsDef }).is_null() {
                ns = unsafe { (*cur).nsDef };
                loop {
                    shadowed = 0 as i32;
                    if !(*(borrow_mut(&mut map)).unwrap()).is_null()
                        && !(unsafe { (**(borrow_mut(&mut map)).unwrap()).first }).is_null()
                    {
                        mi = unsafe { (**(borrow_mut(&mut map)).unwrap()).first };
                        while !mi.is_null() {
                            if (unsafe { (*ns).prefix }) == (unsafe { (*(*mi).newNs).prefix })
                                || xmlStrEqual(
                                    unsafe { (*ns).prefix },
                                    unsafe { (*(*mi).newNs).prefix },
                                ) != 0
                            {
                                shadowed = 1 as i32;
                                break;
                            } else {
                                mi = unsafe { (*mi).next };
                            }
                        }
                    }
                    mi = xmlDOMWrapNsMapAddItem(
                        borrow_mut(&mut map),
                        0 as i32,
                        0 as xmlNsPtr,
                        ns,
                        -(1 as i32),
                    );
                    if mi.is_null() {
                        return -(1 as i32);
                    }
                    if shadowed != 0 {
                        (unsafe { (*mi).shadowDepth = 0 as i32 });
                    }
                    ns = unsafe { (*ns).next };
                    if ns.is_null() {
                        break;
                    }
                }
            }
        }
        cur = unsafe { (*cur).parent };
    }
    return 0 as i32;
}
extern "C" fn xmlDOMWrapNSNormAddNsMapItem2<'a1, 'a2, 'a3>(
    mut list: Option<&'a1 mut *mut *mut crate::src::threads::_xmlNs>,
    mut size: Option<&'a2 mut i32>,
    mut number: Option<&'a3 mut i32>,
    mut oldNs: *mut crate::src::threads::_xmlNs,
    mut newNs: *mut crate::src::threads::_xmlNs,
) -> i32 {
    if (*(borrow(&list)).unwrap()).is_null() {
        *(borrow_mut(&mut list)).unwrap() = (unsafe {
            xmlMalloc.expect("non-null function pointer")(
                (6 as i32 as u64).wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        }) as *mut xmlNsPtr;
        if (*(borrow_mut(&mut list)).unwrap()).is_null() {
            xmlTreeErrMemory(b"alloc ns map item\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        *(borrow_mut(&mut size)).unwrap() = 3 as i32;
        *(borrow_mut(&mut number)).unwrap() = 0 as i32;
    } else if *(borrow(&number)).unwrap() >= *(borrow(&size)).unwrap() {
        *(borrow_mut(&mut size)).unwrap() *= 2 as i32;
        *(borrow_mut(&mut list)).unwrap() = (unsafe {
            xmlRealloc.expect("non-null function pointer")(
                *(borrow_mut(&mut list)).unwrap() as *mut libc::c_void,
                ((*(borrow(&size)).unwrap() * 2 as i32) as u64)
                    .wrapping_mul(::std::mem::size_of::<xmlNsPtr>() as u64),
            )
        }) as *mut xmlNsPtr;
        if (*(borrow(&list)).unwrap()).is_null() {
            xmlTreeErrMemory(b"realloc ns map item\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
    }
    let fresh369 = unsafe {
        &mut (*(*(borrow(&list)).unwrap())
            .offset((2 as i32 * *(borrow(&number)).unwrap()) as isize))
    };
    *fresh369 = oldNs;
    let fresh370 = unsafe {
        &mut (*(*(borrow(&list)).unwrap())
            .offset((2 as i32 * *(borrow(&number)).unwrap() + 1 as i32) as isize))
    };
    *fresh370 = newNs;
    *(borrow_mut(&mut number)).unwrap() += 1;
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapRemoveNode<'a1, 'a2>(
    mut ctxt: Option<&'a1 mut crate::src::tree::_xmlDOMWrapCtxt<'a2>>,
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut _options: i32,
) -> i32 {
    let mut current_block: u64;
    let mut list: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
    let mut sizeList: i32 = 0;
    let mut nbList: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if node.is_null() || doc.is_null() || (unsafe { (*node).doc }) != doc {
        return -(1 as i32);
    }
    if (unsafe { (*node).parent }).is_null() {
        return 0 as i32;
    }
    match (unsafe { (*node).type_0 }) as u32 {
        3 | 4 | 5 | 7 | 8 => {
            xmlUnlinkNode(node);
            return 0 as i32;
        }
        1 | 2 => {}
        _ => return 1 as i32,
    }
    xmlUnlinkNode(node);
    's_67: loop {
        match (unsafe { (*node).type_0 }) as u32 {
            1 => {
                if borrow(&ctxt).is_none() && !(unsafe { (*node).nsDef }).is_null() {
                    ns = unsafe { (*node).nsDef };
                    loop {
                        if xmlDOMWrapNSNormAddNsMapItem2(
                            Some(&mut list),
                            Some(&mut sizeList),
                            Some(&mut nbList),
                            ns,
                            ns,
                        ) == -(1 as i32)
                        {
                            current_block = 1967415137939254181;
                            break 's_67;
                        }
                        ns = unsafe { (*ns).next };
                        if ns.is_null() {
                            break;
                        }
                    }
                    current_block = 2762306430282308233;
                } else {
                    current_block = 2762306430282308233;
                }
            }
            2 => {
                current_block = 2762306430282308233;
            }
            _ => {
                current_block = 17781479925825957363;
            }
        }
        match current_block {
            2762306430282308233 => {
                if !(unsafe { (*node).ns }).is_null() {
                    if !list.is_null() {
                        i = 0 as i32;
                        j = 0 as i32;
                        loop {
                            if !(i < nbList) {
                                current_block = 3437258052017859086;
                                break;
                            }
                            if (unsafe { (*node).ns }) == (unsafe { *list.offset(j as isize) }) {
                                j += 1;
                                let fresh371 = unsafe { &mut ((*node).ns) };
                                *fresh371 = unsafe { *list.offset(j as isize) };
                                current_block = 7143145737794049375;
                                break;
                            } else {
                                i += 1;
                                j += 2 as i32;
                            }
                        }
                    } else {
                        current_block = 3437258052017859086;
                    }
                    match current_block {
                        7143145737794049375 => {}
                        _ => {
                            ns = 0 as xmlNsPtr;
                            if borrow(&ctxt).is_none() {
                                ns = xmlDOMWrapStoreNs(
                                    doc,
                                    unsafe { (*(*node).ns).href },
                                    unsafe { (*(*node).ns).prefix },
                                );
                                if ns.is_null() {
                                    current_block = 1967415137939254181;
                                    break;
                                }
                            }
                            if !ns.is_null() {
                                if xmlDOMWrapNSNormAddNsMapItem2(
                                    Some(&mut list),
                                    Some(&mut sizeList),
                                    Some(&mut nbList),
                                    unsafe { (*node).ns },
                                    ns,
                                ) == -(1 as i32)
                                {
                                    current_block = 1967415137939254181;
                                    break;
                                }
                            }
                            let fresh372 = unsafe { &mut ((*node).ns) };
                            *fresh372 = ns;
                            current_block = 3123434771885419771;
                        }
                    }
                } else {
                    current_block = 3123434771885419771;
                }
                match current_block {
                    3123434771885419771 => {
                        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                            && !(unsafe { (*node).properties }).is_null()
                        {
                            node = (unsafe { (*node).properties }) as xmlNodePtr;
                            current_block = 2979737022853876585;
                        } else {
                            current_block = 7143145737794049375;
                        }
                    }
                    _ => {}
                }
                match current_block {
                    2979737022853876585 => {}
                    _ => {
                        if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                            && !(unsafe { (*node).children }).is_null()
                        {
                            node = unsafe { (*node).children };
                            current_block = 2979737022853876585;
                        } else {
                            current_block = 17781479925825957363;
                        }
                    }
                }
            }
            _ => {}
        }
        loop {
            match current_block {
                2979737022853876585 => {
                    if !node.is_null() {
                        break;
                    } else {
                        current_block = 10095721787123848864;
                        break 's_67;
                    }
                }
                _ => {
                    if node.is_null() {
                        current_block = 10095721787123848864;
                        break 's_67;
                    }
                    if !(unsafe { (*node).next }).is_null() {
                        node = unsafe { (*node).next };
                        current_block = 2979737022853876585;
                    } else {
                        node = unsafe { (*node).parent };
                        current_block = 17781479925825957363;
                    }
                }
            }
        }
    }
    match current_block {
        1967415137939254181 => {
            if !list.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(list as *mut libc::c_void) });
            }
            return -(1 as i32);
        }
        _ => {
            if !list.is_null() {
                (unsafe { xmlFree.expect("non-null function pointer")(list as *mut libc::c_void) });
            }
            return 0 as i32;
        }
    };
}
extern "C" fn xmlSearchNsByNamespaceStrict<'a1>(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut nsName: *const u8,
    mut retNs: Option<&'a1 mut *mut crate::src::threads::_xmlNs>,
    mut prefixed: i32,
) -> i32 {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut prev: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut out: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut prevns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if doc.is_null() || nsName.is_null() || borrow(&retNs).is_none() {
        return -(1 as i32);
    }
    if node.is_null() || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return -(1 as i32);
    }
    *(borrow_mut(&mut retNs)).unwrap() = 0 as xmlNsPtr;
    if xmlStrEqual(
        nsName,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const i8 as *const xmlChar,
    ) != 0
    {
        *(borrow_mut(&mut retNs)).unwrap() = xmlTreeEnsureXMLDecl(doc);
        if (*(borrow_mut(&mut retNs)).unwrap()).is_null() {
            return -(1 as i32);
        }
        return 1 as i32;
    }
    cur = node;
    loop {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            if !(unsafe { (*cur).nsDef }).is_null() {
                let mut current_block_20: u64;
                ns = unsafe { (*cur).nsDef };
                while !ns.is_null() {
                    if !(prefixed != 0 && (unsafe { (*ns).prefix }).is_null()) {
                        if !prev.is_null() {
                            prevns = unsafe { (*prev).nsDef };
                            while !((unsafe { (*prevns).prefix }) == (unsafe { (*ns).prefix })
                                || !(unsafe { (*prevns).prefix }).is_null()
                                    && !(unsafe { (*ns).prefix }).is_null()
                                    && xmlStrEqual(
                                        unsafe { (*prevns).prefix },
                                        unsafe { (*ns).prefix },
                                    ) != 0)
                            {
                                prevns = unsafe { (*prevns).next };
                                if prevns.is_null() {
                                    break;
                                }
                            }
                            if !prevns.is_null() {
                                current_block_20 = 12349973810996921269;
                            } else {
                                current_block_20 = 2719512138335094285;
                            }
                        } else {
                            current_block_20 = 2719512138335094285;
                        }
                        match current_block_20 {
                            12349973810996921269 => {}
                            _ => {
                                if nsName == (unsafe { (*ns).href })
                                    || xmlStrEqual(nsName, unsafe { (*ns).href }) != 0
                                {
                                    if !out.is_null() {
                                        let mut ret: i32 = 0;
                                        ret = xmlNsInScope(
                                            doc,
                                            node,
                                            prev,
                                            unsafe { (*ns).prefix },
                                        );
                                        if ret < 0 as i32 {
                                            return -(1 as i32);
                                        }
                                        if ret == 0 {
                                            current_block_20 = 12349973810996921269;
                                        } else {
                                            current_block_20 = 17281240262373992796;
                                        }
                                    } else {
                                        current_block_20 = 17281240262373992796;
                                    }
                                    match current_block_20 {
                                        12349973810996921269 => {}
                                        _ => {
                                            *(borrow_mut(&mut retNs)).unwrap() = ns;
                                            return 1 as i32;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    ns = unsafe { (*ns).next };
                }
                out = prev;
                prev = cur;
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_NODE as i32 as u32
            || (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
        {
            return 0 as i32;
        }
        cur = unsafe { (*cur).parent };
        if !(!cur.is_null() && (unsafe { (*cur).doc }) != cur as xmlDocPtr) {
            break;
        }
    }
    return 0 as i32;
}
extern "C" fn xmlSearchNsByPrefixStrict<'a1>(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut prefix: *const u8,
    mut retNs: Option<&'a1 mut *mut crate::src::threads::_xmlNs>,
) -> i32 {
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    if doc.is_null()
        || node.is_null()
        || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
    {
        return -(1 as i32);
    }
    if !borrow(&retNs).is_none() {
        *(borrow_mut(&mut retNs)).unwrap() = 0 as xmlNsPtr;
    }
    if !prefix.is_null()
        && (unsafe { *prefix.offset(0 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *prefix.offset(1 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *prefix.offset(2 as i32 as isize) }) as i32 == 'l' as i32
        && (unsafe { *prefix.offset(3 as i32 as isize) }) as i32 == 0 as i32
    {
        if !borrow(&retNs).is_none() {
            *(borrow_mut(&mut retNs)).unwrap() = xmlTreeEnsureXMLDecl(doc);
            if (*(borrow_mut(&mut retNs)).unwrap()).is_null() {
                return -(1 as i32);
            }
        }
        return 1 as i32;
    }
    cur = node;
    loop {
        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
            if !(unsafe { (*cur).nsDef }).is_null() {
                ns = unsafe { (*cur).nsDef };
                loop {
                    if prefix == (unsafe { (*ns).prefix })
                        || xmlStrEqual(prefix, unsafe { (*ns).prefix }) != 0
                    {
                        if (unsafe { (*ns).href }).is_null() {
                            return 0 as i32;
                        }
                        if !borrow(&retNs).is_none() {
                            *(borrow_mut(&mut retNs)).unwrap() = ns;
                        }
                        return 1 as i32;
                    }
                    ns = unsafe { (*ns).next };
                    if ns.is_null() {
                        break;
                    }
                }
            }
        } else if (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_NODE as i32 as u32
            || (unsafe { (*cur).type_0 }) as u32 == XML_ENTITY_DECL as i32 as u32
        {
            return 0 as i32;
        }
        cur = unsafe { (*cur).parent };
        if !(!cur.is_null() && (unsafe { (*cur).doc }) != cur as xmlDocPtr) {
            break;
        }
    }
    return 0 as i32;
}
extern "C" fn xmlDOMWrapNSNormDeclareNsForced(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut nsName: *const u8,
    mut prefix: *const u8,
    mut checkShadow: i32,
) -> *mut crate::src::threads::_xmlNs {
    let mut current_block: u64;
    let mut ret: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut buf: [i8; 50] = [0; 50];
    let mut pref: *const u8 = 0 as *const xmlChar;
    let mut counter: i32 = 0 as i32;
    if doc.is_null()
        || elem.is_null()
        || (unsafe { (*elem).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return 0 as xmlNsPtr;
    }
    pref = prefix;
    loop {
        if !(!(unsafe { (*elem).nsDef }).is_null()
            && !(xmlTreeNSListLookupByPrefix(unsafe { (*elem).nsDef }, pref)).is_null())
        {
            if checkShadow != 0
                && !(unsafe { (*elem).parent }).is_null()
                && (unsafe { (*(*elem).parent).doc }) as xmlNodePtr != (unsafe { (*elem).parent })
            {
                if xmlSearchNsByPrefixStrict(
                    doc,
                    unsafe { (*elem).parent },
                    pref,
                    Option::<&'_ mut *mut crate::src::threads::_xmlNs>::None,
                ) == 1 as i32
                {
                    current_block = 15495627227377452971;
                } else {
                    current_block = 1394248824506584008;
                }
            } else {
                current_block = 1394248824506584008;
            }
            match current_block {
                15495627227377452971 => {}
                _ => {
                    ret = xmlNewNs(0 as xmlNodePtr, nsName, pref);
                    if ret.is_null() {
                        return 0 as xmlNsPtr;
                    }
                    if (unsafe { (*elem).nsDef }).is_null() {
                        let fresh373 = unsafe { &mut ((*elem).nsDef) };
                        *fresh373 = ret;
                    } else {
                        let mut ns2: *mut crate::src::threads::_xmlNs = unsafe { (*elem).nsDef };
                        while !(unsafe { (*ns2).next }).is_null() {
                            ns2 = unsafe { (*ns2).next };
                        }
                        let fresh374 = unsafe { &mut ((*ns2).next) };
                        *fresh374 = ret;
                    }
                    return ret;
                }
            }
        }
        counter += 1;
        if counter > 1000 as i32 {
            return 0 as xmlNsPtr;
        }
        if prefix.is_null() {
            (unsafe {
                snprintf(
                    buf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 50]>() as u64,
                    b"ns_%d\0" as *const u8 as *const i8,
                    counter,
                )
            });
        } else {
            (unsafe {
                snprintf(
                    buf.as_mut_ptr(),
                    ::std::mem::size_of::<[i8; 50]>() as u64,
                    b"%.30s_%d\0" as *const u8 as *const i8,
                    prefix as *mut i8,
                    counter,
                )
            });
        }
        pref = buf.as_mut_ptr() as *mut xmlChar;
    }
}
extern "C" fn xmlDOMWrapNSNormAcquireNormalizedNs<'a1, 'a2>(
    mut doc: *mut crate::src::threads::_xmlDoc,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut ns: *mut crate::src::threads::_xmlNs,
    mut retNs: Option<&'a1 mut *mut crate::src::threads::_xmlNs>,
    mut nsMap: Option<&'a2 mut *mut crate::src::tree::xmlNsMap>,
    mut depth: i32,
    mut ancestorsOnly: i32,
    mut prefixed: i32,
) -> i32 {
    let mut mi: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    if doc.is_null() || ns.is_null() || borrow(&retNs).is_none() || borrow(&nsMap).is_none() {
        return -(1 as i32);
    }
    *(borrow_mut(&mut retNs)).unwrap() = 0 as xmlNsPtr;
    if !(unsafe { (*ns).prefix }).is_null()
        && (unsafe { *((*ns).prefix).offset(0 as i32 as isize) }) as i32 == 'x' as i32
        && (unsafe { *((*ns).prefix).offset(1 as i32 as isize) }) as i32 == 'm' as i32
        && (unsafe { *((*ns).prefix).offset(2 as i32 as isize) }) as i32 == 'l' as i32
        && (unsafe { *((*ns).prefix).offset(3 as i32 as isize) }) as i32 == 0 as i32
    {
        *(borrow_mut(&mut retNs)).unwrap() = xmlTreeEnsureXMLDecl(doc);
        if (*(borrow_mut(&mut retNs)).unwrap()).is_null() {
            return -(1 as i32);
        }
        return 0 as i32;
    }
    if !(*(borrow(&nsMap)).unwrap()).is_null()
        && !(unsafe { (**(borrow(&nsMap)).unwrap()).first }).is_null()
        && !(ancestorsOnly != 0 && elem.is_null())
    {
        mi = unsafe { (**(borrow_mut(&mut nsMap)).unwrap()).first };
        while !mi.is_null() {
            if (unsafe { (*mi).depth }) >= -(1 as i32)
                && (ancestorsOnly == 0 || (unsafe { (*mi).depth }) == -(1 as i32))
                && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                && (!(unsafe { (*(*mi).newNs).href }).is_null()
                    && (unsafe { *((*(*mi).newNs).href).offset(0 as i32 as isize) }) as i32
                        != 0 as i32)
                && (prefixed == 0 || !(unsafe { (*(*mi).newNs).prefix }).is_null())
                && ((unsafe { (*(*mi).newNs).href }) == (unsafe { (*ns).href })
                    || xmlStrEqual(unsafe { (*(*mi).newNs).href }, unsafe { (*ns).href }) != 0)
            {
                let fresh375 = unsafe { &mut ((*mi).oldNs) };
                *fresh375 = ns;
                *(borrow_mut(&mut retNs)).unwrap() = unsafe { (*mi).newNs };
                return 0 as i32;
            }
            mi = unsafe { (*mi).next };
        }
    }
    if elem.is_null() {
        let mut tmpns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
        tmpns = xmlDOMWrapStoreNs(doc, unsafe { (*ns).href }, unsafe { (*ns).prefix });
        if tmpns.is_null() {
            return -(1 as i32);
        }
        if (xmlDOMWrapNsMapAddItem(borrow_mut(&mut nsMap), -(1 as i32), ns, tmpns, -(3 as i32)))
            .is_null()
        {
            xmlFreeNs(tmpns);
            return -(1 as i32);
        }
        *(borrow_mut(&mut retNs)).unwrap() = tmpns;
    } else {
        let mut tmpns_0: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
        tmpns_0 = xmlDOMWrapNSNormDeclareNsForced(
            doc,
            elem,
            unsafe { (*ns).href },
            unsafe { (*ns).prefix },
            0 as i32,
        );
        if tmpns_0.is_null() {
            return -(1 as i32);
        }
        if !(*(borrow_mut(&mut nsMap)).unwrap()).is_null() {
            mi = unsafe { (**(borrow_mut(&mut nsMap)).unwrap()).first };
            while !mi.is_null() {
                if (unsafe { (*mi).depth }) < depth
                    && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                    && ((unsafe { (*ns).prefix }) == (unsafe { (*(*mi).newNs).prefix })
                        || xmlStrEqual(
                            unsafe { (*ns).prefix },
                            unsafe { (*(*mi).newNs).prefix },
                        ) != 0)
                {
                    (unsafe { (*mi).shadowDepth = depth });
                    break;
                } else {
                    mi = unsafe { (*mi).next };
                }
            }
        }
        if (xmlDOMWrapNsMapAddItem(borrow_mut(&mut nsMap), -(1 as i32), ns, tmpns_0, depth))
            .is_null()
        {
            xmlFreeNs(tmpns_0);
            return -(1 as i32);
        }
        *(borrow_mut(&mut retNs)).unwrap() = tmpns_0;
    }
    return 0 as i32;
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapReconcileNamespaces<'a1, 'a2>(
    mut _ctxt: Option<&'a1 mut crate::src::tree::_xmlDOMWrapCtxt<'a2>>,
    mut elem: *mut crate::src::threads::_xmlNode,
    mut options: i32,
) -> i32 {
    let mut current_block: u64;
    let mut depth: i32 = -(1 as i32);
    let mut adoptns: i32 = 0 as i32;
    let mut parnsdone: i32 = 0 as i32;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut prevns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut curElem: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut nsMap: *mut crate::src::tree::xmlNsMap = 0 as xmlNsMapPtr;
    let mut mi: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut ancestorsOnly: i32 = 0 as i32;
    let mut optRemoveRedundantNS: i32 = if options as xmlDOMReconcileNSOptions as u32
        & XML_DOM_RECONNS_REMOVEREDUND as i32 as u32
        != 0
    {
        1 as i32
    } else {
        0 as i32
    };
    let mut listRedund: *mut *mut crate::src::threads::_xmlNs = 0 as *mut xmlNsPtr;
    let mut sizeRedund: i32 = 0 as i32;
    let mut nbRedund: i32 = 0 as i32;
    let mut ret: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    if elem.is_null()
        || (unsafe { (*elem).doc }).is_null()
        || (unsafe { (*elem).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32
    {
        return -(1 as i32);
    }
    doc = unsafe { (*elem).doc };
    cur = elem;
    's_51: loop {
        match (unsafe { (*cur).type_0 }) as u32 {
            1 => {
                adoptns = 1 as i32;
                curElem = cur;
                depth += 1;
                if !(unsafe { (*cur).nsDef }).is_null() {
                    prevns = 0 as xmlNsPtr;
                    ns = unsafe { (*cur).nsDef };
                    while !ns.is_null() {
                        if parnsdone == 0 {
                            if !(unsafe { (*elem).parent }).is_null()
                                && (unsafe { (*(*elem).parent).doc }) as xmlNodePtr
                                    != (unsafe { (*elem).parent })
                            {
                                if xmlDOMWrapNSNormGatherInScopeNs(
                                    Some(&mut nsMap),
                                    unsafe { (*elem).parent },
                                ) == -(1 as i32)
                                {
                                    current_block = 3912784260007845398;
                                    break 's_51;
                                }
                            }
                            parnsdone = 1 as i32;
                        }
                        if optRemoveRedundantNS != 0
                            && (!nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null())
                        {
                            mi = unsafe { (*nsMap).first };
                            loop {
                                if mi.is_null() {
                                    current_block = 652864300344834934;
                                    break;
                                }
                                if (unsafe { (*mi).depth }) >= -(1 as i32)
                                    && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                    && ((unsafe { (*ns).prefix })
                                        == (unsafe { (*(*mi).newNs).prefix })
                                        || xmlStrEqual(
                                            unsafe { (*ns).prefix },
                                            unsafe { (*(*mi).newNs).prefix },
                                        ) != 0)
                                    && ((unsafe { (*ns).href }) == (unsafe { (*(*mi).newNs).href })
                                        || xmlStrEqual(
                                            unsafe { (*ns).href },
                                            unsafe { (*(*mi).newNs).href },
                                        ) != 0)
                                {
                                    if xmlDOMWrapNSNormAddNsMapItem2(
                                        Some(&mut listRedund),
                                        Some(&mut sizeRedund),
                                        Some(&mut nbRedund),
                                        ns,
                                        unsafe { (*mi).newNs },
                                    ) == -(1 as i32)
                                    {
                                        current_block = 3912784260007845398;
                                        break 's_51;
                                    }
                                    if !prevns.is_null() {
                                        let fresh376 = unsafe { &mut ((*prevns).next) };
                                        *fresh376 = unsafe { (*ns).next };
                                    } else {
                                        let fresh377 = unsafe { &mut ((*cur).nsDef) };
                                        *fresh377 = unsafe { (*ns).next };
                                    }
                                    current_block = 18339261097437597264;
                                    break;
                                } else {
                                    mi = unsafe { (*mi).next };
                                }
                            }
                        } else {
                            current_block = 652864300344834934;
                        }
                        match current_block {
                            652864300344834934 => {
                                if !(unsafe { (*cur).ns }).is_null()
                                    && adoptns != 0
                                    && (unsafe { (*cur).ns }) == ns
                                {
                                    adoptns = 0 as i32;
                                }
                                if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                                    mi = unsafe { (*nsMap).first };
                                    while !mi.is_null() {
                                        if (unsafe { (*mi).depth }) >= -(1 as i32)
                                            && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                            && ((unsafe { (*ns).prefix })
                                                == (unsafe { (*(*mi).newNs).prefix })
                                                || xmlStrEqual(
                                                    unsafe { (*ns).prefix },
                                                    unsafe { (*(*mi).newNs).prefix },
                                                ) != 0)
                                        {
                                            (unsafe { (*mi).shadowDepth = depth });
                                        }
                                        mi = unsafe { (*mi).next };
                                    }
                                }
                                if (xmlDOMWrapNsMapAddItem(
                                    Some(&mut nsMap),
                                    -(1 as i32),
                                    ns,
                                    ns,
                                    depth,
                                ))
                                .is_null()
                                {
                                    current_block = 3912784260007845398;
                                    break 's_51;
                                }
                                prevns = ns;
                            }
                            _ => {}
                        }
                        ns = unsafe { (*ns).next };
                    }
                }
                if adoptns == 0 {
                    current_block = 11129218233486035409;
                } else {
                    current_block = 14349190553367373684;
                }
            }
            2 => {
                current_block = 14349190553367373684;
            }
            _ => {
                current_block = 15166383349133654314;
            }
        }
        match current_block {
            14349190553367373684 => {
                if (unsafe { (*cur).ns }).is_null() {
                    current_block = 11129218233486035409;
                } else {
                    if parnsdone == 0 {
                        if !(unsafe { (*elem).parent }).is_null()
                            && (unsafe { (*(*elem).parent).doc }) as xmlNodePtr
                                != (unsafe { (*elem).parent })
                        {
                            if xmlDOMWrapNSNormGatherInScopeNs(
                                Some(&mut nsMap),
                                unsafe { (*elem).parent },
                            ) == -(1 as i32)
                            {
                                current_block = 3912784260007845398;
                                break;
                            }
                        }
                        parnsdone = 1 as i32;
                    }
                    if !listRedund.is_null() {
                        i = 0 as i32;
                        j = 0 as i32;
                        while i < nbRedund {
                            if (unsafe { (*cur).ns }) == (unsafe { *listRedund.offset(j as isize) })
                            {
                                j += 1;
                                let fresh378 = unsafe { &mut ((*cur).ns) };
                                *fresh378 = unsafe { *listRedund.offset(j as isize) };
                                break;
                            } else {
                                i += 1;
                                j += 2 as i32;
                            }
                        }
                    }
                    if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                        mi = unsafe { (*nsMap).first };
                        loop {
                            if mi.is_null() {
                                current_block = 7189308829251266000;
                                break;
                            }
                            if (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                && (unsafe { (*cur).ns }) == (unsafe { (*mi).oldNs })
                            {
                                let fresh379 = unsafe { &mut ((*cur).ns) };
                                *fresh379 = unsafe { (*mi).newNs };
                                current_block = 11129218233486035409;
                                break;
                            } else {
                                mi = unsafe { (*mi).next };
                            }
                        }
                    } else {
                        current_block = 7189308829251266000;
                    }
                    match current_block {
                        11129218233486035409 => {}
                        _ => {
                            if xmlDOMWrapNSNormAcquireNormalizedNs(
                                doc,
                                curElem,
                                unsafe { (*cur).ns },
                                Some(&mut ns),
                                Some(&mut nsMap),
                                depth,
                                ancestorsOnly,
                                if (unsafe { (*cur).type_0 }) as u32
                                    == XML_ATTRIBUTE_NODE as i32 as u32
                                {
                                    1 as i32
                                } else {
                                    0 as i32
                                },
                            ) == -(1 as i32)
                            {
                                current_block = 3912784260007845398;
                                break;
                            }
                            let fresh380 = unsafe { &mut ((*cur).ns) };
                            *fresh380 = ns;
                            current_block = 11129218233486035409;
                        }
                    }
                }
            }
            _ => {}
        }
        match current_block {
            11129218233486035409 => {
                if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                    && !(unsafe { (*cur).properties }).is_null()
                {
                    cur = (unsafe { (*cur).properties }) as xmlNodePtr;
                    current_block = 1394248824506584008;
                } else {
                    current_block = 456721507831113532;
                }
            }
            _ => {}
        }
        loop {
            match current_block {
                1394248824506584008 => {
                    if !cur.is_null() {
                        break;
                    } else {
                        current_block = 7739940392431776979;
                        break 's_51;
                    }
                }
                15166383349133654314 => {
                    if cur == elem {
                        current_block = 7739940392431776979;
                        break 's_51;
                    }
                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
                        if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                            while !(unsafe { (*nsMap).last }).is_null()
                                && (unsafe { (*(*nsMap).last).depth }) >= depth
                            {
                                mi = unsafe { (*nsMap).last };
                                let fresh381 = unsafe { &mut ((*nsMap).last) };
                                *fresh381 = unsafe { (*mi).prev };
                                if (unsafe { (*nsMap).last }).is_null() {
                                    let fresh382 = unsafe { &mut ((*nsMap).first) };
                                    *fresh382 = 0 as xmlNsMapItemPtr;
                                } else {
                                    let fresh383 = unsafe { &mut ((*(*nsMap).last).next) };
                                    *fresh383 = 0 as xmlNsMapItemPtr;
                                }
                                let fresh384 = unsafe { &mut ((*mi).next) };
                                *fresh384 = unsafe { (*nsMap).pool };
                                let fresh385 = unsafe { &mut ((*nsMap).pool) };
                                *fresh385 = mi;
                            }
                            mi = unsafe { (*nsMap).first };
                            while !mi.is_null() {
                                if (unsafe { (*mi).shadowDepth }) >= depth {
                                    (unsafe { (*mi).shadowDepth = -(1 as i32) });
                                }
                                mi = unsafe { (*mi).next };
                            }
                        }
                        depth -= 1;
                    }
                    if !(unsafe { (*cur).next }).is_null() {
                        cur = unsafe { (*cur).next };
                        current_block = 1394248824506584008;
                    } else if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                    {
                        cur = unsafe { (*cur).parent };
                        current_block = 456721507831113532;
                    } else {
                        cur = unsafe { (*cur).parent };
                        current_block = 15166383349133654314;
                    }
                }
                _ => {
                    if !((unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        && !(unsafe { (*cur).children }).is_null())
                    {
                        current_block = 15166383349133654314;
                        continue;
                    }
                    cur = unsafe { (*cur).children };
                    current_block = 1394248824506584008;
                }
            }
        }
    }
    match current_block {
        3912784260007845398 => {
            ret = -(1 as i32);
        }
        _ => {
            ret = 0 as i32;
        }
    }
    if !listRedund.is_null() {
        i = 0 as i32;
        j = 0 as i32;
        while i < nbRedund {
            xmlFreeNs(unsafe { *listRedund.offset(j as isize) });
            i += 1;
            j += 2 as i32;
        }
        (unsafe { xmlFree.expect("non-null function pointer")(listRedund as *mut libc::c_void) });
    }
    if !nsMap.is_null() {
        xmlDOMWrapNsMapFree(nsMap);
    }
    return ret;
}
extern "C" fn xmlDOMWrapAdoptBranch<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlDOMWrapCtxt<'a1>,
    mut sourceDoc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut destDoc: *mut crate::src::threads::_xmlDoc,
    mut destParent: *mut crate::src::threads::_xmlNode,
    mut _options: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut curElem: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut nsMap: *mut crate::src::tree::xmlNsMap = 0 as xmlNsMapPtr;
    let mut mi: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as xmlNsPtr;
    let mut depth: i32 = -(1 as i32);
    let mut adoptStr: i32 = 1 as i32;
    let mut parnsdone: i32 = 0;
    let mut ancestorsOnly: i32 = 0 as i32;
    if !sourceDoc.is_null() && (unsafe { (*sourceDoc).dict }) == (unsafe { (*destDoc).dict }) {
        adoptStr = 0 as i32;
    } else {
        adoptStr = 1 as i32;
    }
    if !ctxt.is_null() {
        nsMap = (unsafe { (*ctxt).namespaceMap }) as xmlNsMapPtr;
    }
    if destParent.is_null() || !ctxt.is_null() && (unsafe { ((*ctxt).getNsForNodeFunc).is_some() })
    {
        parnsdone = 1 as i32;
    } else {
        parnsdone = 0 as i32;
    }
    cur = node;
    if !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        current_block = 11057361962272637943;
    } else {
        current_block = 17860125682698302841;
    }
    'c_44681: loop {
        match current_block {
            11057361962272637943 => {
                ret = -(1 as i32);
                break;
            }
            _ => {
                if cur.is_null() {
                    break;
                }
                if (unsafe { (*cur).doc }) != sourceDoc {
                    if (unsafe { (*cur).next }).is_null() {
                        current_block = 16447908953907659923;
                    } else {
                        loop {
                            cur = unsafe { (*cur).next };
                            if (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
                                || (unsafe { (*cur).doc }) == (unsafe { (*node).doc })
                            {
                                break;
                            }
                            if (unsafe { (*cur).next }).is_null() {
                                break;
                            }
                        }
                        if (unsafe { (*cur).doc }) != (unsafe { (*node).doc }) {
                            current_block = 16447908953907659923;
                        } else {
                            current_block = 11298138898191919651;
                        }
                    }
                } else {
                    current_block = 11298138898191919651;
                }
                match current_block {
                    11298138898191919651 => {
                        let fresh386 = unsafe { &mut ((*cur).doc) };
                        *fresh386 = destDoc;
                        match (unsafe { (*cur).type_0 }) as u32 {
                            19 | 20 => return -(1 as i32),
                            1 => {
                                curElem = cur;
                                depth += 1;
                                if !(unsafe { (*cur).nsDef }).is_null()
                                    && (ctxt.is_null()
                                        || (unsafe { ((*ctxt).getNsForNodeFunc).is_none() }))
                                {
                                    if parnsdone == 0 {
                                        if xmlDOMWrapNSNormGatherInScopeNs(
                                            Some(&mut nsMap),
                                            destParent,
                                        ) == -(1 as i32)
                                        {
                                            current_block = 11057361962272637943;
                                            continue;
                                        }
                                        parnsdone = 1 as i32;
                                    }
                                    ns = unsafe { (*cur).nsDef };
                                    while !ns.is_null() {
                                        if !nsMap.is_null()
                                            && !(unsafe { (*nsMap).first }).is_null()
                                        {
                                            mi = unsafe { (*nsMap).first };
                                            while !mi.is_null() {
                                                if (unsafe { (*mi).depth }) >= -(1 as i32)
                                                    && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                                    && ((unsafe { (*ns).prefix })
                                                        == (unsafe { (*(*mi).newNs).prefix })
                                                        || xmlStrEqual(
                                                            unsafe { (*ns).prefix },
                                                            unsafe { (*(*mi).newNs).prefix },
                                                        ) != 0)
                                                {
                                                    (unsafe { (*mi).shadowDepth = depth });
                                                }
                                                mi = unsafe { (*mi).next };
                                            }
                                        }
                                        if (xmlDOMWrapNsMapAddItem(
                                            Some(&mut nsMap),
                                            -(1 as i32),
                                            ns,
                                            ns,
                                            depth,
                                        ))
                                        .is_null()
                                        {
                                            current_block = 11057361962272637943;
                                            continue 'c_44681;
                                        }
                                        ns = unsafe { (*ns).next };
                                    }
                                }
                                current_block = 14835353632257566941;
                            }
                            2 => {
                                current_block = 14835353632257566941;
                            }
                            3 | 4 => {
                                if adoptStr != 0
                                    && !(unsafe { (*cur).content }).is_null()
                                    && !sourceDoc.is_null()
                                    && !(unsafe { (*sourceDoc).dict }).is_null()
                                    && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).content) })
                                        != 0
                                {
                                    if !(unsafe { (*destDoc).dict }).is_null() {
                                        let fresh394 = unsafe { &mut ((*cur).content) };
                                        *fresh394 = (unsafe {
                                            xmlDictLookup(
                                                (*destDoc).dict,
                                                (*cur).content,
                                                -(1 as i32),
                                            )
                                        })
                                            as *mut xmlChar;
                                    } else {
                                        let fresh395 = unsafe { &mut ((*cur).content) };
                                        *fresh395 = xmlStrdup(unsafe { (*cur).content });
                                    }
                                }
                                current_block = 16447908953907659923;
                            }
                            5 => {
                                let fresh396 = unsafe { &mut ((*cur).content) };
                                *fresh396 = 0 as *mut xmlChar;
                                let fresh397 = unsafe { &mut ((*cur).children) };
                                *fresh397 = 0 as *mut _xmlNode;
                                let fresh398 = unsafe { &mut ((*cur).last) };
                                *fresh398 = 0 as *mut _xmlNode;
                                if !(unsafe { (*destDoc).intSubset }).is_null()
                                    || !(unsafe { (*destDoc).extSubset }).is_null()
                                {
                                    let mut ent: *mut crate::src::threads::_xmlEntity =
                                        0 as *mut xmlEntity;
                                    ent = unsafe {
                                        xmlGetDocEntity(destDoc as *const xmlDoc, (*cur).name)
                                    };
                                    if !ent.is_null() {
                                        let fresh399 = unsafe { &mut ((*cur).content) };
                                        *fresh399 = unsafe { (*ent).content };
                                        let fresh400 = unsafe { &mut ((*cur).children) };
                                        *fresh400 = ent as xmlNodePtr;
                                        let fresh401 = unsafe { &mut ((*cur).last) };
                                        *fresh401 = ent as xmlNodePtr;
                                    }
                                }
                                current_block = 16447908953907659923;
                            }
                            7 => {
                                if adoptStr != 0 && !(unsafe { (*cur).name }).is_null() {
                                    if !(unsafe { (*destDoc).dict }).is_null() {
                                        let mut old_0: *const u8 = unsafe { (*cur).name };
                                        let fresh402 = unsafe { &mut ((*cur).name) };
                                        *fresh402 = unsafe {
                                            xmlDictLookup((*destDoc).dict, (*cur).name, -(1 as i32))
                                        };
                                        if sourceDoc.is_null()
                                            || (unsafe { (*sourceDoc).dict }).is_null()
                                            || (unsafe { xmlDictOwns((*sourceDoc).dict, old_0) })
                                                == 0
                                        {
                                            (unsafe {
                                                xmlFree.expect("non-null function pointer")(
                                                    old_0 as *mut i8 as *mut libc::c_void,
                                                )
                                            });
                                        }
                                    } else if !sourceDoc.is_null()
                                        && !(unsafe { (*sourceDoc).dict }).is_null()
                                        && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).name) })
                                            != 0
                                    {
                                        let fresh403 = unsafe { &mut ((*cur).name) };
                                        *fresh403 = xmlStrdup(unsafe { (*cur).name });
                                    }
                                }
                                if adoptStr != 0
                                    && !(unsafe { (*cur).content }).is_null()
                                    && !sourceDoc.is_null()
                                    && !(unsafe { (*sourceDoc).dict }).is_null()
                                    && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).content) })
                                        != 0
                                {
                                    if !(unsafe { (*destDoc).dict }).is_null() {
                                        let fresh404 = unsafe { &mut ((*cur).content) };
                                        *fresh404 = (unsafe {
                                            xmlDictLookup(
                                                (*destDoc).dict,
                                                (*cur).content,
                                                -(1 as i32),
                                            )
                                        })
                                            as *mut xmlChar;
                                    } else {
                                        let fresh405 = unsafe { &mut ((*cur).content) };
                                        *fresh405 = xmlStrdup(unsafe { (*cur).content });
                                    }
                                }
                                current_block = 11162283542402356847;
                            }
                            8 => {
                                current_block = 11162283542402356847;
                            }
                            _ => {
                                current_block = 11057361962272637943;
                                continue;
                            }
                        }
                        match current_block {
                            16447908953907659923 => {}
                            _ => {
                                match current_block {
                                    14835353632257566941 => {
                                        if !(unsafe { (*cur).ns }).is_null() {
                                            if parnsdone == 0 {
                                                if xmlDOMWrapNSNormGatherInScopeNs(
                                                    Some(&mut nsMap),
                                                    destParent,
                                                ) == -(1 as i32)
                                                {
                                                    current_block = 11057361962272637943;
                                                    continue;
                                                }
                                                parnsdone = 1 as i32;
                                            }
                                            if !nsMap.is_null()
                                                && !(unsafe { (*nsMap).first }).is_null()
                                            {
                                                mi = unsafe { (*nsMap).first };
                                                loop {
                                                    if mi.is_null() {
                                                        current_block = 2520131295878969859;
                                                        break;
                                                    }
                                                    if (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                                        && (unsafe { (*cur).ns })
                                                            == (unsafe { (*mi).oldNs })
                                                    {
                                                        let fresh387 =
                                                            unsafe { &mut ((*cur).ns) };
                                                        *fresh387 = unsafe { (*mi).newNs };
                                                        current_block = 4936991246711566589;
                                                        break;
                                                    } else {
                                                        mi = unsafe { (*mi).next };
                                                    }
                                                }
                                            } else {
                                                current_block = 2520131295878969859;
                                            }
                                            match current_block {
                                                4936991246711566589 => {}
                                                _ => {
                                                    if !ctxt.is_null()
                                                        && (unsafe {
                                                            ((*ctxt).getNsForNodeFunc).is_some()
                                                        })
                                                    {
                                                        ns = unsafe {
                                                            ((*ctxt).getNsForNodeFunc)
                                                                .expect("non-null function pointer")(
                                                                ctxt,
                                                                cur,
                                                                (*(*cur).ns).href,
                                                                (*(*cur).ns).prefix,
                                                            )
                                                        };
                                                        if (xmlDOMWrapNsMapAddItem(
                                                            Some(&mut nsMap),
                                                            -(1 as i32),
                                                            unsafe { (*cur).ns },
                                                            ns,
                                                            -(4 as i32),
                                                        ))
                                                        .is_null()
                                                        {
                                                            current_block = 11057361962272637943;
                                                            continue;
                                                        }
                                                        let fresh388 =
                                                            unsafe { &mut ((*cur).ns) };
                                                        *fresh388 = ns;
                                                    } else {
                                                        if xmlDOMWrapNSNormAcquireNormalizedNs(
                                                            destDoc,
                                                            if !destParent.is_null() {
                                                                curElem
                                                            } else {
                                                                0 as xmlNodePtr
                                                            },
                                                            unsafe { (*cur).ns },
                                                            Some(&mut ns),
                                                            Some(&mut nsMap),
                                                            depth,
                                                            ancestorsOnly,
                                                            if (unsafe { (*cur).type_0 }) as u32
                                                                == XML_ATTRIBUTE_NODE as i32 as u32
                                                            {
                                                                1 as i32
                                                            } else {
                                                                0 as i32
                                                            },
                                                        ) == -(1 as i32)
                                                        {
                                                            current_block = 11057361962272637943;
                                                            continue;
                                                        }
                                                        let fresh389 =
                                                            unsafe { &mut ((*cur).ns) };
                                                        *fresh389 = ns;
                                                    }
                                                }
                                            }
                                        }
                                        if adoptStr != 0 && !(unsafe { (*cur).name }).is_null() {
                                            if !(unsafe { (*destDoc).dict }).is_null() {
                                                let mut old: *const u8 = unsafe { (*cur).name };
                                                let fresh390 = unsafe { &mut ((*cur).name) };
                                                *fresh390 = unsafe {
                                                    xmlDictLookup(
                                                        (*destDoc).dict,
                                                        (*cur).name,
                                                        -(1 as i32),
                                                    )
                                                };
                                                if sourceDoc.is_null()
                                                    || (unsafe { (*sourceDoc).dict }).is_null()
                                                    || (unsafe {
                                                        xmlDictOwns((*sourceDoc).dict, old)
                                                    }) == 0
                                                {
                                                    (unsafe {
                                                        xmlFree.expect("non-null function pointer")(
                                                            old as *mut i8 as *mut libc::c_void,
                                                        )
                                                    });
                                                }
                                            } else if !sourceDoc.is_null()
                                                && !(unsafe { (*sourceDoc).dict }).is_null()
                                                && (unsafe {
                                                    xmlDictOwns((*sourceDoc).dict, (*cur).name)
                                                }) != 0
                                            {
                                                let fresh391 = unsafe { &mut ((*cur).name) };
                                                *fresh391 = xmlStrdup(unsafe { (*cur).name });
                                            }
                                        }
                                        if (unsafe { (*cur).type_0 }) as u32
                                            == XML_ELEMENT_NODE as i32 as u32
                                        {
                                            let fresh392 = unsafe { &mut ((*cur).psvi) };
                                            *fresh392 = 0 as *mut libc::c_void;
                                            (unsafe { (*cur).line = 0 as i32 as u16 });
                                            (unsafe { (*cur).extra = 0 as i32 as u16 });
                                            if !(unsafe { (*cur).properties }).is_null() {
                                                cur = (unsafe { (*cur).properties }) as xmlNodePtr;
                                                current_block = 17860125682698302841;
                                                continue;
                                            }
                                        } else {
                                            if !sourceDoc.is_null()
                                                && (unsafe { (*(cur as xmlAttrPtr)).atype }) as u32
                                                    == XML_ATTRIBUTE_ID as i32 as u32
                                            {
                                                xmlRemoveID(sourceDoc, cur as xmlAttrPtr);
                                            }
                                            (unsafe {
                                                (*(cur as xmlAttrPtr)).atype = 0 as xmlAttributeType
                                            });
                                            let fresh393 =
                                                unsafe { &mut ((*(cur as xmlAttrPtr)).psvi) };
                                            *fresh393 = 0 as *mut libc::c_void;
                                        }
                                    }
                                    _ => {}
                                }
                                if !(unsafe { (*cur).children }).is_null() {
                                    cur = unsafe { (*cur).children };
                                    current_block = 17860125682698302841;
                                    continue;
                                }
                            }
                        }
                    }
                    _ => {}
                }
                loop {
                    if cur == node {
                        break 'c_44681;
                    }
                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                        || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
                    {
                        if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                            while !(unsafe { (*nsMap).last }).is_null()
                                && (unsafe { (*(*nsMap).last).depth }) >= depth
                            {
                                mi = unsafe { (*nsMap).last };
                                let fresh406 = unsafe { &mut ((*nsMap).last) };
                                *fresh406 = unsafe { (*mi).prev };
                                if (unsafe { (*nsMap).last }).is_null() {
                                    let fresh407 = unsafe { &mut ((*nsMap).first) };
                                    *fresh407 = 0 as xmlNsMapItemPtr;
                                } else {
                                    let fresh408 = unsafe { &mut ((*(*nsMap).last).next) };
                                    *fresh408 = 0 as xmlNsMapItemPtr;
                                }
                                let fresh409 = unsafe { &mut ((*mi).next) };
                                *fresh409 = unsafe { (*nsMap).pool };
                                let fresh410 = unsafe { &mut ((*nsMap).pool) };
                                *fresh410 = mi;
                            }
                            mi = unsafe { (*nsMap).first };
                            while !mi.is_null() {
                                if (unsafe { (*mi).shadowDepth }) >= depth {
                                    (unsafe { (*mi).shadowDepth = -(1 as i32) });
                                }
                                mi = unsafe { (*mi).next };
                            }
                        }
                        depth -= 1;
                    }
                    if !(unsafe { (*cur).next }).is_null() {
                        cur = unsafe { (*cur).next };
                        current_block = 17860125682698302841;
                        break;
                    } else if (unsafe { (*cur).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                        && !(unsafe { (*(*cur).parent).children }).is_null()
                    {
                        cur = unsafe { (*(*cur).parent).children };
                        current_block = 17860125682698302841;
                        break;
                    } else {
                        cur = unsafe { (*cur).parent };
                    }
                }
            }
        }
    }
    if !nsMap.is_null() {
        if !ctxt.is_null() && (unsafe { (*ctxt).namespaceMap }) == nsMap as *mut libc::c_void {
            if !(unsafe { (*nsMap).first }).is_null() {
                if !(unsafe { (*nsMap).pool }).is_null() {
                    let fresh411 = unsafe { &mut ((*(*nsMap).last).next) };
                    *fresh411 = unsafe { (*nsMap).pool };
                }
                let fresh412 = unsafe { &mut ((*nsMap).pool) };
                *fresh412 = unsafe { (*nsMap).first };
                let fresh413 = unsafe { &mut ((*nsMap).first) };
                *fresh413 = 0 as xmlNsMapItemPtr;
            }
        } else {
            xmlDOMWrapNsMapFree(nsMap);
        }
    }
    return ret;
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapCloneNode<'a1, 'a2>(
    mut ctxt: *mut crate::src::tree::_xmlDOMWrapCtxt<'a1>,
    mut sourceDoc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut resNode: Option<&'a2 mut *mut crate::src::threads::_xmlNode>,
    mut destDoc: *mut crate::src::threads::_xmlDoc,
    mut destParent: *mut crate::src::threads::_xmlNode,
    mut deep: i32,
    mut _options: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 0 as i32;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut curElem: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut nsMap: *mut crate::src::tree::xmlNsMap = 0 as xmlNsMapPtr;
    let mut mi: *mut crate::src::tree::xmlNsMapItem = 0 as *mut xmlNsMapItem;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    let mut depth: i32 = -(1 as i32);
    let mut parnsdone: i32 = 0 as i32;
    let mut ancestorsOnly: i32 = 0 as i32;
    let mut resultClone: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut clone: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut parentClone: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut prevClone: *mut crate::src::threads::_xmlNode = 0 as xmlNodePtr;
    let mut cloneNs: *mut crate::src::threads::_xmlNs = 0 as xmlNsPtr;
    let mut cloneNsDefSlot: Option<&'_ mut *mut crate::src::threads::_xmlNs> =
        Option::<&'_ mut *mut crate::src::threads::_xmlNs>::None;
    let mut dict: *mut crate::src::xpointer::_xmlDict = 0 as *mut xmlDict;
    if node.is_null() || borrow(&resNode).is_none() || destDoc.is_null() {
        return -(1 as i32);
    }
    if (unsafe { (*node).type_0 }) as u32 != XML_ELEMENT_NODE as i32 as u32 {
        return 1 as i32;
    }
    if !(unsafe { (*node).doc }).is_null()
        && !sourceDoc.is_null()
        && (unsafe { (*node).doc }) != sourceDoc
    {
        return -(1 as i32);
    }
    if sourceDoc.is_null() {
        sourceDoc = unsafe { (*node).doc };
    }
    if sourceDoc.is_null() {
        return -(1 as i32);
    }
    dict = unsafe { (*destDoc).dict };
    if !ctxt.is_null() {
        nsMap = (unsafe { (*ctxt).namespaceMap }) as xmlNsMapPtr;
    }
    *(borrow_mut(&mut resNode)).unwrap() = 0 as xmlNodePtr;
    cur = node;
    if !cur.is_null() && (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32 {
        return -(1 as i32);
    }
    's_109: loop {
        if cur.is_null() {
            current_block = 11128556818017063193;
            break;
        }
        if (unsafe { (*cur).doc }) != sourceDoc {
            current_block = 9881238597775047924;
            break;
        } else {
            match (unsafe { (*cur).type_0 }) as u32 {
                19 | 20 => {
                    current_block = 9881238597775047924;
                    break;
                }
                1 | 3 | 4 | 8 | 7 | 11 | 5 | 6 => {
                    clone = (unsafe {
                        xmlMalloc.expect("non-null function pointer")(
                            ::std::mem::size_of::<xmlNode>() as u64,
                        )
                    }) as xmlNodePtr;
                    if clone.is_null() {
                        xmlTreeErrMemory(
                            b"xmlDOMWrapCloneNode(): allocating a node\0" as *const u8 as *const i8,
                        );
                        current_block = 9881238597775047924;
                        break;
                    } else {
                        (unsafe {
                            memset(
                                clone as *mut libc::c_void,
                                0 as i32,
                                ::std::mem::size_of::<xmlNode>() as u64,
                            )
                        });
                        if !resultClone.is_null() {
                            let fresh414 = unsafe { &mut ((*clone).parent) };
                            *fresh414 = parentClone;
                            if !prevClone.is_null() {
                                let fresh415 = unsafe { &mut ((*prevClone).next) };
                                *fresh415 = clone;
                                let fresh416 = unsafe { &mut ((*clone).prev) };
                                *fresh416 = prevClone;
                            } else {
                                let fresh417 = unsafe { &mut ((*parentClone).children) };
                                *fresh417 = clone;
                            }
                        } else {
                            resultClone = clone;
                        }
                    }
                }
                2 => {
                    clone = (unsafe {
                        xmlMalloc.expect("non-null function pointer")(
                            ::std::mem::size_of::<xmlAttr>() as u64,
                        )
                    }) as xmlNodePtr;
                    if clone.is_null() {
                        xmlTreeErrMemory(
                            b"xmlDOMWrapCloneNode(): allocating an attr-node\0" as *const u8
                                as *const i8,
                        );
                        current_block = 9881238597775047924;
                        break;
                    } else {
                        (unsafe {
                            memset(
                                clone as *mut libc::c_void,
                                0 as i32,
                                ::std::mem::size_of::<xmlAttr>() as u64,
                            )
                        });
                        if !resultClone.is_null() {
                            let fresh418 = unsafe { &mut ((*clone).parent) };
                            *fresh418 = parentClone;
                            if !prevClone.is_null() {
                                let fresh419 = unsafe { &mut ((*prevClone).next) };
                                *fresh419 = clone;
                                let fresh420 = unsafe { &mut ((*clone).prev) };
                                *fresh420 = prevClone;
                            } else {
                                let fresh421 = unsafe { &mut ((*parentClone).properties) };
                                *fresh421 = clone as xmlAttrPtr;
                            }
                        } else {
                            resultClone = clone;
                        }
                    }
                }
                _ => {
                    current_block = 9881238597775047924;
                    break;
                }
            }
            (unsafe { (*clone).type_0 = (*cur).type_0 });
            let fresh422 = unsafe { &mut ((*clone).doc) };
            *fresh422 = destDoc;
            if (unsafe { (*cur).name }) == (unsafe { xmlStringText.as_ptr() }) {
                let fresh423 = unsafe { &mut ((*clone).name) };
                *fresh423 = unsafe { xmlStringText.as_ptr() };
            } else if (unsafe { (*cur).name }) == (unsafe { xmlStringTextNoenc.as_ptr() }) {
                let fresh424 = unsafe { &mut ((*clone).name) };
                *fresh424 = unsafe { xmlStringTextNoenc.as_ptr() };
            } else if (unsafe { (*cur).name }) == (unsafe { xmlStringComment.as_ptr() }) {
                let fresh425 = unsafe { &mut ((*clone).name) };
                *fresh425 = unsafe { xmlStringComment.as_ptr() };
            } else if !(unsafe { (*cur).name }).is_null() {
                if !(unsafe { (*cur).name }).is_null() {
                    if !dict.is_null() {
                        if (unsafe { xmlDictOwns(dict, (*cur).name) }) != 0 {
                            let fresh426 = unsafe { &mut ((*clone).name) };
                            *fresh426 = unsafe { (*cur).name };
                        } else {
                            let fresh427 = unsafe { &mut ((*clone).name) };
                            *fresh427 = unsafe { xmlDictLookup(dict, (*cur).name, -(1 as i32)) };
                        }
                    } else {
                        let fresh428 = unsafe { &mut ((*clone).name) };
                        *fresh428 = xmlStrdup(unsafe { (*cur).name }) as *const xmlChar;
                    }
                }
            }
            match (unsafe { (*cur).type_0 }) as u32 {
                19 | 20 => return -(1 as i32),
                1 => {
                    curElem = cur;
                    depth += 1;
                    if !(unsafe { (*cur).nsDef }).is_null() {
                        if parnsdone == 0 {
                            if !destParent.is_null() && ctxt.is_null() {
                                if xmlDOMWrapNSNormGatherInScopeNs(Some(&mut nsMap), destParent)
                                    == -(1 as i32)
                                {
                                    current_block = 9881238597775047924;
                                    break;
                                }
                            }
                            parnsdone = 1 as i32;
                        }
                        cloneNsDefSlot = Some(unsafe { &mut (*clone).nsDef });
                        ns = unsafe { (*cur).nsDef };
                        while !ns.is_null() {
                            cloneNs = (unsafe {
                                xmlMalloc.expect("non-null function pointer")(
                                    ::std::mem::size_of::<xmlNs>() as u64,
                                )
                            }) as xmlNsPtr;
                            if cloneNs.is_null() {
                                xmlTreeErrMemory(
                                    b"xmlDOMWrapCloneNode(): allocating namespace\0" as *const u8
                                        as *const i8,
                                );
                                return -(1 as i32);
                            }
                            (unsafe {
                                memset(
                                    cloneNs as *mut libc::c_void,
                                    0 as i32,
                                    ::std::mem::size_of::<xmlNs>() as u64,
                                )
                            });
                            (unsafe { (*cloneNs).type_0 = XML_NAMESPACE_DECL });
                            if !(unsafe { (*ns).href }).is_null() {
                                let fresh429 = unsafe { &mut ((*cloneNs).href) };
                                *fresh429 = xmlStrdup(unsafe { (*ns).href });
                            }
                            if !(unsafe { (*ns).prefix }).is_null() {
                                let fresh430 = unsafe { &mut ((*cloneNs).prefix) };
                                *fresh430 = xmlStrdup(unsafe { (*ns).prefix });
                            }
                            *(borrow_mut(&mut cloneNsDefSlot)).unwrap() = cloneNs;
                            cloneNsDefSlot = Some(unsafe { &mut (*cloneNs).next });
                            if ctxt.is_null() || (unsafe { ((*ctxt).getNsForNodeFunc).is_none() }) {
                                if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                                    mi = unsafe { (*nsMap).first };
                                    while !mi.is_null() {
                                        if (unsafe { (*mi).depth }) >= -(1 as i32)
                                            && (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                            && ((unsafe { (*ns).prefix })
                                                == (unsafe { (*(*mi).newNs).prefix })
                                                || xmlStrEqual(
                                                    unsafe { (*ns).prefix },
                                                    unsafe { (*(*mi).newNs).prefix },
                                                ) != 0)
                                        {
                                            (unsafe { (*mi).shadowDepth = depth });
                                        }
                                        mi = unsafe { (*mi).next };
                                    }
                                }
                                if (xmlDOMWrapNsMapAddItem(
                                    Some(&mut nsMap),
                                    -(1 as i32),
                                    ns,
                                    cloneNs,
                                    depth,
                                ))
                                .is_null()
                                {
                                    current_block = 9881238597775047924;
                                    break 's_109;
                                }
                            }
                            ns = unsafe { (*ns).next };
                        }
                    }
                    current_block = 2544535129495155983;
                }
                2 => {
                    current_block = 2544535129495155983;
                }
                3 | 4 => {
                    if !(unsafe { (*cur).content }).is_null() {
                        if !dict.is_null() {
                            if (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) != 0
                            {
                                let fresh431 = unsafe { &mut ((*clone).content) };
                                *fresh431 = unsafe { (*cur).content };
                            } else {
                                let fresh432 = unsafe { &mut ((*clone).content) };
                                *fresh432 = (unsafe {
                                    xmlDictLookup(
                                        dict,
                                        (*cur).content as *const xmlChar,
                                        -(1 as i32),
                                    )
                                }) as *mut xmlChar;
                            }
                        } else {
                            let fresh433 = unsafe { &mut ((*clone).content) };
                            *fresh433 = xmlStrdup((unsafe { (*cur).content }) as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                6 => {
                    current_block = 17418631935567976705;
                }
                5 => {
                    if sourceDoc != destDoc {
                        if !(unsafe { (*destDoc).intSubset }).is_null()
                            || !(unsafe { (*destDoc).extSubset }).is_null()
                        {
                            let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
                            ent =
                                unsafe { xmlGetDocEntity(destDoc as *const xmlDoc, (*cur).name) };
                            if !ent.is_null() {
                                let fresh434 = unsafe { &mut ((*clone).content) };
                                *fresh434 = unsafe { (*ent).content };
                                let fresh435 = unsafe { &mut ((*clone).children) };
                                *fresh435 = ent as xmlNodePtr;
                                let fresh436 = unsafe { &mut ((*clone).last) };
                                *fresh436 = ent as xmlNodePtr;
                            }
                        }
                    } else {
                        let fresh437 = unsafe { &mut ((*clone).content) };
                        *fresh437 = unsafe { (*cur).content };
                        let fresh438 = unsafe { &mut ((*clone).children) };
                        *fresh438 = unsafe { (*cur).children };
                        let fresh439 = unsafe { &mut ((*clone).last) };
                        *fresh439 = unsafe { (*cur).last };
                    }
                    current_block = 17418631935567976705;
                }
                7 => {
                    if !(unsafe { (*cur).content }).is_null() {
                        if !dict.is_null() {
                            if (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) != 0
                            {
                                let fresh440 = unsafe { &mut ((*clone).content) };
                                *fresh440 = unsafe { (*cur).content };
                            } else {
                                let fresh441 = unsafe { &mut ((*clone).content) };
                                *fresh441 = (unsafe {
                                    xmlDictLookup(
                                        dict,
                                        (*cur).content as *const xmlChar,
                                        -(1 as i32),
                                    )
                                }) as *mut xmlChar;
                            }
                        } else {
                            let fresh442 = unsafe { &mut ((*clone).content) };
                            *fresh442 = xmlStrdup((unsafe { (*cur).content }) as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                8 => {
                    if !(unsafe { (*cur).content }).is_null() {
                        if !dict.is_null() {
                            if (unsafe { xmlDictOwns(dict, (*cur).content as *const xmlChar) }) != 0
                            {
                                let fresh443 = unsafe { &mut ((*clone).content) };
                                *fresh443 = unsafe { (*cur).content };
                            } else {
                                let fresh444 = unsafe { &mut ((*clone).content) };
                                *fresh444 = (unsafe {
                                    xmlDictLookup(
                                        dict,
                                        (*cur).content as *const xmlChar,
                                        -(1 as i32),
                                    )
                                }) as *mut xmlChar;
                            }
                        } else {
                            let fresh445 = unsafe { &mut ((*clone).content) };
                            *fresh445 = xmlStrdup((unsafe { (*cur).content }) as *const xmlChar);
                        }
                    }
                    current_block = 17418631935567976705;
                }
                _ => {
                    current_block = 9881238597775047924;
                    break;
                }
            }
            match current_block {
                2544535129495155983 => {
                    if !(unsafe { (*cur).ns }).is_null() {
                        if parnsdone == 0 {
                            if !destParent.is_null() && ctxt.is_null() {
                                if xmlDOMWrapNSNormGatherInScopeNs(Some(&mut nsMap), destParent)
                                    == -(1 as i32)
                                {
                                    current_block = 9881238597775047924;
                                    break;
                                }
                            }
                            parnsdone = 1 as i32;
                        }
                        if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                            mi = unsafe { (*nsMap).first };
                            loop {
                                if mi.is_null() {
                                    current_block = 9657096306311191688;
                                    break;
                                }
                                if (unsafe { (*mi).shadowDepth }) == -(1 as i32)
                                    && (unsafe { (*cur).ns }) == (unsafe { (*mi).oldNs })
                                {
                                    let fresh446 = unsafe { &mut ((*clone).ns) };
                                    *fresh446 = unsafe { (*mi).newNs };
                                    current_block = 2484559367671746789;
                                    break;
                                } else {
                                    mi = unsafe { (*mi).next };
                                }
                            }
                        } else {
                            current_block = 9657096306311191688;
                        }
                        match current_block {
                            2484559367671746789 => {}
                            _ => {
                                if !ctxt.is_null()
                                    && (unsafe { ((*ctxt).getNsForNodeFunc).is_some() })
                                {
                                    ns = unsafe {
                                        ((*ctxt).getNsForNodeFunc)
                                            .expect("non-null function pointer")(
                                            ctxt,
                                            cur,
                                            (*(*cur).ns).href,
                                            (*(*cur).ns).prefix,
                                        )
                                    };
                                    if (xmlDOMWrapNsMapAddItem(
                                        Some(&mut nsMap),
                                        -(1 as i32),
                                        unsafe { (*cur).ns },
                                        ns,
                                        -(4 as i32),
                                    ))
                                    .is_null()
                                    {
                                        current_block = 9881238597775047924;
                                        break;
                                    }
                                    let fresh447 = unsafe { &mut ((*clone).ns) };
                                    *fresh447 = ns;
                                } else {
                                    if xmlDOMWrapNSNormAcquireNormalizedNs(
                                        destDoc,
                                        if !destParent.is_null() {
                                            curElem
                                        } else {
                                            0 as xmlNodePtr
                                        },
                                        unsafe { (*cur).ns },
                                        Some(&mut ns),
                                        Some(&mut nsMap),
                                        depth,
                                        ancestorsOnly,
                                        if (unsafe { (*cur).type_0 }) as u32
                                            == XML_ATTRIBUTE_NODE as i32 as u32
                                        {
                                            1 as i32
                                        } else {
                                            0 as i32
                                        },
                                    ) == -(1 as i32)
                                    {
                                        current_block = 9881238597775047924;
                                        break;
                                    }
                                    let fresh448 = unsafe { &mut ((*clone).ns) };
                                    *fresh448 = ns;
                                }
                            }
                        }
                    }
                    if (unsafe { (*clone).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32
                        && !(unsafe { (*clone).parent }).is_null()
                    {
                        if xmlIsID(destDoc, unsafe { (*clone).parent }, clone as xmlAttrPtr) != 0
                        {
                            let mut idVal: *mut u8 = 0 as *mut xmlChar;
                            idVal = xmlNodeListGetString(
                                unsafe { (*cur).doc },
                                unsafe { (*cur).children },
                                1 as i32,
                            );
                            if !idVal.is_null() {
                                if (xmlAddID(
                                    0 as xmlValidCtxtPtr,
                                    destDoc,
                                    idVal,
                                    cur as xmlAttrPtr,
                                ))
                                .is_null()
                                {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            idVal as *mut libc::c_void,
                                        )
                                    });
                                    current_block = 9881238597775047924;
                                    break;
                                } else {
                                    (unsafe {
                                        xmlFree.expect("non-null function pointer")(
                                            idVal as *mut libc::c_void,
                                        )
                                    });
                                }
                            }
                        }
                    }
                    if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                        && !(unsafe { (*cur).properties }).is_null()
                    {
                        prevClone = 0 as xmlNodePtr;
                        parentClone = clone;
                        cur = (unsafe { (*cur).properties }) as xmlNodePtr;
                        continue;
                    } else {
                        current_block = 16134469364361965152;
                    }
                }
                _ => {}
            }
            loop {
                match current_block {
                    17418631935567976705 => {
                        if cur == node {
                            current_block = 11128556818017063193;
                            break 's_109;
                        }
                        if (unsafe { (*cur).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32
                            || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_START as i32 as u32
                            || (unsafe { (*cur).type_0 }) as u32 == XML_XINCLUDE_END as i32 as u32
                        {
                            if !nsMap.is_null() && !(unsafe { (*nsMap).first }).is_null() {
                                while !(unsafe { (*nsMap).last }).is_null()
                                    && (unsafe { (*(*nsMap).last).depth }) >= depth
                                {
                                    mi = unsafe { (*nsMap).last };
                                    let fresh449 = unsafe { &mut ((*nsMap).last) };
                                    *fresh449 = unsafe { (*mi).prev };
                                    if (unsafe { (*nsMap).last }).is_null() {
                                        let fresh450 = unsafe { &mut ((*nsMap).first) };
                                        *fresh450 = 0 as xmlNsMapItemPtr;
                                    } else {
                                        let fresh451 = unsafe { &mut ((*(*nsMap).last).next) };
                                        *fresh451 = 0 as xmlNsMapItemPtr;
                                    }
                                    let fresh452 = unsafe { &mut ((*mi).next) };
                                    *fresh452 = unsafe { (*nsMap).pool };
                                    let fresh453 = unsafe { &mut ((*nsMap).pool) };
                                    *fresh453 = mi;
                                }
                                mi = unsafe { (*nsMap).first };
                                while !mi.is_null() {
                                    if (unsafe { (*mi).shadowDepth }) >= depth {
                                        (unsafe { (*mi).shadowDepth = -(1 as i32) });
                                    }
                                    mi = unsafe { (*mi).next };
                                }
                            }
                            depth -= 1;
                        }
                        if !(unsafe { (*cur).next }).is_null() {
                            prevClone = clone;
                            cur = unsafe { (*cur).next };
                            break;
                        } else if (unsafe { (*cur).type_0 }) as u32
                            != XML_ATTRIBUTE_NODE as i32 as u32
                        {
                            if !(unsafe { (*clone).parent }).is_null() {
                                let fresh454 = unsafe { &mut ((*(*clone).parent).last) };
                                *fresh454 = clone;
                            }
                            clone = unsafe { (*clone).parent };
                            if !clone.is_null() {
                                parentClone = unsafe { (*clone).parent };
                            }
                            cur = unsafe { (*cur).parent };
                            current_block = 17418631935567976705;
                        } else {
                            clone = unsafe { (*clone).parent };
                            parentClone = unsafe { (*clone).parent };
                            cur = unsafe { (*cur).parent };
                            current_block = 16134469364361965152;
                        }
                    }
                    _ => {
                        if (unsafe { (*cur).children }).is_null() {
                            current_block = 17418631935567976705;
                            continue;
                        }
                        if !(deep != 0
                            || (unsafe { (*cur).type_0 }) as u32
                                == XML_ATTRIBUTE_NODE as i32 as u32)
                        {
                            current_block = 17418631935567976705;
                            continue;
                        }
                        prevClone = 0 as xmlNodePtr;
                        parentClone = clone;
                        cur = unsafe { (*cur).children };
                        break;
                    }
                }
            }
        }
    }
    match current_block {
        9881238597775047924 => {
            ret = -(1 as i32);
        }
        _ => {}
    }
    if !nsMap.is_null() {
        if !ctxt.is_null() && (unsafe { (*ctxt).namespaceMap }) == nsMap as *mut libc::c_void {
            if !(unsafe { (*nsMap).first }).is_null() {
                if !(unsafe { (*nsMap).pool }).is_null() {
                    let fresh455 = unsafe { &mut ((*(*nsMap).last).next) };
                    *fresh455 = unsafe { (*nsMap).pool };
                }
                let fresh456 = unsafe { &mut ((*nsMap).pool) };
                *fresh456 = unsafe { (*nsMap).first };
                let fresh457 = unsafe { &mut ((*nsMap).first) };
                *fresh457 = 0 as xmlNsMapItemPtr;
            }
        } else {
            xmlDOMWrapNsMapFree(nsMap);
        }
    }
    *(borrow_mut(&mut resNode)).unwrap() = resultClone;
    return ret;
}
extern "C" fn xmlDOMWrapAdoptAttr<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlDOMWrapCtxt<'a1>,
    mut sourceDoc: *mut crate::src::threads::_xmlDoc,
    mut attr: *mut crate::src::threads::_xmlAttr,
    mut destDoc: *mut crate::src::threads::_xmlDoc,
    mut destParent: *mut crate::src::threads::_xmlNode,
    mut _options: i32,
) -> i32 {
    let mut current_block: u64;
    let mut cur: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut adoptStr: i32 = 1 as i32;
    if attr.is_null() || destDoc.is_null() {
        return -(1 as i32);
    }
    let fresh458 = unsafe { &mut ((*attr).doc) };
    *fresh458 = destDoc;
    if !(unsafe { (*attr).ns }).is_null() {
        let mut ns: *mut crate::src::threads::_xmlNs = 0 as xmlNsPtr;
        let _ = !ctxt.is_null();
        if !(unsafe { (*(*attr).ns).prefix }).is_null()
            && (unsafe { *((*(*attr).ns).prefix).offset(0 as i32 as isize) }) as i32 == 'x' as i32
            && (unsafe { *((*(*attr).ns).prefix).offset(1 as i32 as isize) }) as i32 == 'm' as i32
            && (unsafe { *((*(*attr).ns).prefix).offset(2 as i32 as isize) }) as i32 == 'l' as i32
            && (unsafe { *((*(*attr).ns).prefix).offset(3 as i32 as isize) }) as i32 == 0 as i32
        {
            ns = xmlTreeEnsureXMLDecl(destDoc);
            current_block = 5143058163439228106;
        } else if destParent.is_null() {
            ns = xmlDOMWrapStoreNs(
                destDoc,
                unsafe { (*(*attr).ns).href },
                unsafe { (*(*attr).ns).prefix },
            );
            current_block = 5143058163439228106;
        } else if xmlSearchNsByNamespaceStrict(
            destDoc,
            destParent,
            unsafe { (*(*attr).ns).href },
            Some(&mut ns),
            1 as i32,
        ) == -(1 as i32)
        {
            current_block = 10866158498708961612;
        } else {
            if ns.is_null() {
                ns = xmlDOMWrapNSNormDeclareNsForced(
                    destDoc,
                    destParent,
                    unsafe { (*(*attr).ns).href },
                    unsafe { (*(*attr).ns).prefix },
                    1 as i32,
                );
            }
            current_block = 5143058163439228106;
        }
        match current_block {
            10866158498708961612 => {}
            _ => {
                if ns.is_null() {
                    current_block = 10866158498708961612;
                } else {
                    let fresh459 = unsafe { &mut ((*attr).ns) };
                    *fresh459 = ns;
                    current_block = 12124785117276362961;
                }
            }
        }
    } else {
        current_block = 12124785117276362961;
    }
    match current_block {
        12124785117276362961 => {
            if adoptStr != 0 && !(unsafe { (*attr).name }).is_null() {
                if !(unsafe { (*destDoc).dict }).is_null() {
                    let mut old: *const u8 = unsafe { (*attr).name };
                    let fresh460 = unsafe { &mut ((*attr).name) };
                    *fresh460 =
                        unsafe { xmlDictLookup((*destDoc).dict, (*attr).name, -(1 as i32)) };
                    if sourceDoc.is_null()
                        || (unsafe { (*sourceDoc).dict }).is_null()
                        || (unsafe { xmlDictOwns((*sourceDoc).dict, old) }) == 0
                    {
                        (unsafe {
                            xmlFree.expect("non-null function pointer")(
                                old as *mut i8 as *mut libc::c_void,
                            )
                        });
                    }
                } else if !sourceDoc.is_null()
                    && !(unsafe { (*sourceDoc).dict }).is_null()
                    && (unsafe { xmlDictOwns((*sourceDoc).dict, (*attr).name) }) != 0
                {
                    let fresh461 = unsafe { &mut ((*attr).name) };
                    *fresh461 = xmlStrdup(unsafe { (*attr).name });
                }
            }
            (unsafe { (*attr).atype = 0 as xmlAttributeType });
            let fresh462 = unsafe { &mut ((*attr).psvi) };
            *fresh462 = 0 as *mut libc::c_void;
            if (unsafe { (*attr).children }).is_null() {
                return 0 as i32;
            }
            cur = unsafe { (*attr).children };
            if !(!cur.is_null()
                && (unsafe { (*cur).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32)
            {
                's_181: while !cur.is_null() {
                    let fresh463 = unsafe { &mut ((*cur).doc) };
                    *fresh463 = destDoc;
                    match (unsafe { (*cur).type_0 }) as u32 {
                        3 | 4 => {
                            if adoptStr != 0
                                && !(unsafe { (*cur).content }).is_null()
                                && !sourceDoc.is_null()
                                && !(unsafe { (*sourceDoc).dict }).is_null()
                                && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).content) }) != 0
                            {
                                if !(unsafe { (*destDoc).dict }).is_null() {
                                    let fresh464 = unsafe { &mut ((*cur).content) };
                                    *fresh464 = (unsafe {
                                        xmlDictLookup((*destDoc).dict, (*cur).content, -(1 as i32))
                                    })
                                        as *mut xmlChar;
                                } else {
                                    let fresh465 = unsafe { &mut ((*cur).content) };
                                    *fresh465 = xmlStrdup(unsafe { (*cur).content });
                                }
                            }
                        }
                        5 => {
                            let fresh466 = unsafe { &mut ((*cur).content) };
                            *fresh466 = 0 as *mut xmlChar;
                            let fresh467 = unsafe { &mut ((*cur).children) };
                            *fresh467 = 0 as *mut _xmlNode;
                            let fresh468 = unsafe { &mut ((*cur).last) };
                            *fresh468 = 0 as *mut _xmlNode;
                            if !(unsafe { (*destDoc).intSubset }).is_null()
                                || !(unsafe { (*destDoc).extSubset }).is_null()
                            {
                                let mut ent: *mut crate::src::threads::_xmlEntity =
                                    0 as *mut xmlEntity;
                                ent = unsafe {
                                    xmlGetDocEntity(destDoc as *const xmlDoc, (*cur).name)
                                };
                                if !ent.is_null() {
                                    let fresh469 = unsafe { &mut ((*cur).content) };
                                    *fresh469 = unsafe { (*ent).content };
                                    let fresh470 = unsafe { &mut ((*cur).children) };
                                    *fresh470 = ent as xmlNodePtr;
                                    let fresh471 = unsafe { &mut ((*cur).last) };
                                    *fresh471 = ent as xmlNodePtr;
                                }
                            }
                        }
                        _ => {}
                    }
                    if !(unsafe { (*cur).children }).is_null() {
                        cur = unsafe { (*cur).children };
                    } else {
                        loop {
                            if cur == attr as xmlNodePtr {
                                break 's_181;
                            }
                            if !(unsafe { (*cur).next }).is_null() {
                                break;
                            }
                            cur = unsafe { (*cur).parent };
                        }
                        cur = unsafe { (*cur).next };
                    }
                }
                return 0 as i32;
            }
        }
        _ => {}
    }
    return -(1 as i32);
}
#[no_mangle]
pub extern "C" fn xmlDOMWrapAdoptNode<'a1>(
    mut ctxt: *mut crate::src::tree::_xmlDOMWrapCtxt<'a1>,
    mut sourceDoc: *mut crate::src::threads::_xmlDoc,
    mut node: *mut crate::src::threads::_xmlNode,
    mut destDoc: *mut crate::src::threads::_xmlDoc,
    mut destParent: *mut crate::src::threads::_xmlNode,
    mut options: i32,
) -> i32 {
    if node.is_null()
        || (unsafe { (*node).type_0 }) as u32 == XML_NAMESPACE_DECL as i32 as u32
        || destDoc.is_null()
        || !destParent.is_null() && (unsafe { (*destParent).doc }) != destDoc
    {
        return -(1 as i32);
    }
    if !(unsafe { (*node).doc }).is_null()
        && !sourceDoc.is_null()
        && (unsafe { (*node).doc }) != sourceDoc
    {
        return -(1 as i32);
    }
    if sourceDoc.is_null() {
        sourceDoc = unsafe { (*node).doc };
    }
    if sourceDoc == destDoc {
        return -(1 as i32);
    }
    match (unsafe { (*node).type_0 }) as u32 {
        1 | 2 | 3 | 4 | 5 | 7 | 8 => {}
        11 => return 2 as i32,
        _ => return 1 as i32,
    }
    if !(unsafe { (*node).parent }).is_null() && destParent != (unsafe { (*node).parent }) {
        xmlUnlinkNode(node);
    }
    if (unsafe { (*node).type_0 }) as u32 == XML_ELEMENT_NODE as i32 as u32 {
        return xmlDOMWrapAdoptBranch(ctxt, sourceDoc, node, destDoc, destParent, options);
    } else {
        if (unsafe { (*node).type_0 }) as u32 == XML_ATTRIBUTE_NODE as i32 as u32 {
            return xmlDOMWrapAdoptAttr(
                ctxt,
                sourceDoc,
                node as xmlAttrPtr,
                destDoc,
                destParent,
                options,
            );
        } else {
            let mut cur: *mut crate::src::threads::_xmlNode = node;
            let mut adoptStr: i32 = 1 as i32;
            let fresh472 = unsafe { &mut ((*cur).doc) };
            *fresh472 = destDoc;
            if !sourceDoc.is_null()
                && (unsafe { (*sourceDoc).dict }) == (unsafe { (*destDoc).dict })
            {
                adoptStr = 0 as i32;
            }
            match (unsafe { (*node).type_0 }) as u32 {
                3 | 4 => {
                    if adoptStr != 0
                        && !(unsafe { (*node).content }).is_null()
                        && !sourceDoc.is_null()
                        && !(unsafe { (*sourceDoc).dict }).is_null()
                        && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).content) }) != 0
                    {
                        if !(unsafe { (*destDoc).dict }).is_null() {
                            let fresh473 = unsafe { &mut ((*cur).content) };
                            *fresh473 = (unsafe {
                                xmlDictLookup((*destDoc).dict, (*cur).content, -(1 as i32))
                            }) as *mut xmlChar;
                        } else {
                            let fresh474 = unsafe { &mut ((*cur).content) };
                            *fresh474 = xmlStrdup(unsafe { (*cur).content });
                        }
                    }
                }
                5 => {
                    let fresh475 = unsafe { &mut ((*node).content) };
                    *fresh475 = 0 as *mut xmlChar;
                    let fresh476 = unsafe { &mut ((*node).children) };
                    *fresh476 = 0 as *mut _xmlNode;
                    let fresh477 = unsafe { &mut ((*node).last) };
                    *fresh477 = 0 as *mut _xmlNode;
                    if !(unsafe { (*destDoc).intSubset }).is_null()
                        || !(unsafe { (*destDoc).extSubset }).is_null()
                    {
                        let mut ent: *mut crate::src::threads::_xmlEntity = 0 as *mut xmlEntity;
                        ent = unsafe { xmlGetDocEntity(destDoc as *const xmlDoc, (*node).name) };
                        if !ent.is_null() {
                            let fresh478 = unsafe { &mut ((*node).content) };
                            *fresh478 = unsafe { (*ent).content };
                            let fresh479 = unsafe { &mut ((*node).children) };
                            *fresh479 = ent as xmlNodePtr;
                            let fresh480 = unsafe { &mut ((*node).last) };
                            *fresh480 = ent as xmlNodePtr;
                        }
                    }
                    if adoptStr != 0 && !(unsafe { (*node).name }).is_null() {
                        if !(unsafe { (*destDoc).dict }).is_null() {
                            let mut old: *const u8 = unsafe { (*node).name };
                            let fresh481 = unsafe { &mut ((*node).name) };
                            *fresh481 = unsafe {
                                xmlDictLookup((*destDoc).dict, (*node).name, -(1 as i32))
                            };
                            if sourceDoc.is_null()
                                || (unsafe { (*sourceDoc).dict }).is_null()
                                || (unsafe { xmlDictOwns((*sourceDoc).dict, old) }) == 0
                            {
                                (unsafe {
                                    xmlFree.expect("non-null function pointer")(
                                        old as *mut i8 as *mut libc::c_void,
                                    )
                                });
                            }
                        } else if !sourceDoc.is_null()
                            && !(unsafe { (*sourceDoc).dict }).is_null()
                            && (unsafe { xmlDictOwns((*sourceDoc).dict, (*node).name) }) != 0
                        {
                            let fresh482 = unsafe { &mut ((*node).name) };
                            *fresh482 = xmlStrdup(unsafe { (*node).name });
                        }
                    }
                }
                7 => {
                    if adoptStr != 0 && !(unsafe { (*node).name }).is_null() {
                        if !(unsafe { (*destDoc).dict }).is_null() {
                            let mut old_0: *const u8 = unsafe { (*node).name };
                            let fresh483 = unsafe { &mut ((*node).name) };
                            *fresh483 = unsafe {
                                xmlDictLookup((*destDoc).dict, (*node).name, -(1 as i32))
                            };
                            if sourceDoc.is_null()
                                || (unsafe { (*sourceDoc).dict }).is_null()
                                || (unsafe { xmlDictOwns((*sourceDoc).dict, old_0) }) == 0
                            {
                                (unsafe {
                                    xmlFree.expect("non-null function pointer")(
                                        old_0 as *mut i8 as *mut libc::c_void,
                                    )
                                });
                            }
                        } else if !sourceDoc.is_null()
                            && !(unsafe { (*sourceDoc).dict }).is_null()
                            && (unsafe { xmlDictOwns((*sourceDoc).dict, (*node).name) }) != 0
                        {
                            let fresh484 = unsafe { &mut ((*node).name) };
                            *fresh484 = xmlStrdup(unsafe { (*node).name });
                        }
                    }
                    if adoptStr != 0
                        && !(unsafe { (*node).content }).is_null()
                        && !sourceDoc.is_null()
                        && !(unsafe { (*sourceDoc).dict }).is_null()
                        && (unsafe { xmlDictOwns((*sourceDoc).dict, (*cur).content) }) != 0
                    {
                        if !(unsafe { (*destDoc).dict }).is_null() {
                            let fresh485 = unsafe { &mut ((*cur).content) };
                            *fresh485 = (unsafe {
                                xmlDictLookup((*destDoc).dict, (*cur).content, -(1 as i32))
                            }) as *mut xmlChar;
                        } else {
                            let fresh486 = unsafe { &mut ((*cur).content) };
                            *fresh486 = xmlStrdup(unsafe { (*cur).content });
                        }
                    }
                }
                _ => {}
            }
        }
    }
    return 0 as i32;
}
use crate::laertes_rt::*;
