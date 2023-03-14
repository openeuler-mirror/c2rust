use ::libc;
extern "C" {
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    fn xmlStrlen(str: *const xmlChar) -> libc::c_int;
    fn xmlCharStrdup(cur: *const libc::c_char) -> *mut xmlChar;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrncmp(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrcasestr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: libc::c_int) -> *mut xmlChar;
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn __htmlParseContent(ctx: *mut libc::c_void);
    fn __xmlGlobalInitMutexLock();
    fn __xmlGlobalInitMutexUnlock();
    fn xmlInputReadCallbackNop(
        context: *mut libc::c_void,
        buffer: *mut libc::c_char,
        len: libc::c_int,
    ) -> libc::c_int;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memmove(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memchr(
        _: *const libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn xmlNewDocElementContent(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: xmlElementContentType,
    ) -> xmlElementContentPtr;
    fn xmlFreeDocElementContent(doc: xmlDocPtr, cur: xmlElementContentPtr);
    fn xmlCreateEnumeration(name: *const xmlChar) -> xmlEnumerationPtr;
    fn xmlFreeEnumeration(cur: xmlEnumerationPtr);
    fn xmlBufContent(buf: *const xmlBuf) -> *mut xmlChar;
    fn xmlBufUse(buf: xmlBufPtr) -> size_t;
    fn xmlInitializeDict() -> libc::c_int;
    fn xmlDictSetLimit(dict: xmlDictPtr, limit: size_t) -> size_t;
    fn xmlDictReference(dict: xmlDictPtr) -> libc::c_int;
    fn xmlDictFree(dict: xmlDictPtr);
    fn xmlDictLookup(
        dict: xmlDictPtr,
        name: *const xmlChar,
        len: libc::c_int,
    ) -> *const xmlChar;
    fn xmlDictOwns(dict: xmlDictPtr, str: *const xmlChar) -> libc::c_int;
    fn xmlDictCleanup();
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlSplitQName3(name: *const xmlChar, len: *mut libc::c_int) -> *const xmlChar;
    fn xmlBufferCreate() -> xmlBufferPtr;
    fn xmlBufferFree(buf: xmlBufferPtr);
    fn xmlBufferAdd(
        buf: xmlBufferPtr,
        str: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlBufferSetAllocationScheme(
        buf: xmlBufferPtr,
        scheme: xmlBufferAllocationScheme,
    );
    fn xmlCreateIntSubset(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlNewDtd(
        doc: xmlDocPtr,
        name: *const xmlChar,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    ) -> xmlDtdPtr;
    fn xmlNewDoc(version: *const xmlChar) -> xmlDocPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlNewDocNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocComment(doc: xmlDocPtr, content: *const xmlChar) -> xmlNodePtr;
    fn xmlDocCopyNode(
        node: xmlNodePtr,
        doc: xmlDocPtr,
        recursive: libc::c_int,
    ) -> xmlNodePtr;
    fn xmlGetLastChild(parent: *const xmlNode) -> xmlNodePtr;
    fn xmlNodeIsText(node: *const xmlNode) -> libc::c_int;
    fn xmlAddChild(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddChildList(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSetTreeDoc(tree: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSearchNsByHref(
        doc: xmlDocPtr,
        node: xmlNodePtr,
        href: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlHashCreateDict(size: libc::c_int, dict: xmlDictPtr) -> xmlHashTablePtr;
    fn xmlHashFree(table: xmlHashTablePtr, f: xmlHashDeallocator);
    fn xmlHashDefaultDeallocator(entry: *mut libc::c_void, name: *const xmlChar);
    fn xmlHashAddEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
    ) -> libc::c_int;
    fn xmlHashUpdateEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        userdata: *mut libc::c_void,
        f: xmlHashDeallocator,
    ) -> libc::c_int;
    fn xmlHashRemoveEntry2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
        f: xmlHashDeallocator,
    ) -> libc::c_int;
    fn xmlHashLookup2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        name2: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlHashQLookup2(
        table: xmlHashTablePtr,
        name: *const xmlChar,
        prefix: *const xmlChar,
        name2: *const xmlChar,
        prefix2: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlHashSize(table: xmlHashTablePtr) -> libc::c_int;
    fn xmlHashScanFull(
        table: xmlHashTablePtr,
        f: xmlHashScannerFull,
        data: *mut libc::c_void,
    );
    fn initGenericErrorDefaultFunc(handler: *mut xmlGenericErrorFunc);
    fn xmlResetError(err: xmlErrorPtr);
    fn xmlCopyError(from: xmlErrorPtr, to: xmlErrorPtr) -> libc::c_int;
    fn __xmlRaiseError(
        schannel: xmlStructuredErrorFunc,
        channel: xmlGenericErrorFunc,
        data: *mut libc::c_void,
        ctx: *mut libc::c_void,
        node: *mut libc::c_void,
        domain: libc::c_int,
        code: libc::c_int,
        level: xmlErrorLevel,
        file: *const libc::c_char,
        line: libc::c_int,
        str1: *const libc::c_char,
        str2: *const libc::c_char,
        str3: *const libc::c_char,
        int1: libc::c_int,
        col: libc::c_int,
        msg: *const libc::c_char,
        _: ...
    );
    fn xmlCleanupMemory();
    fn xmlInitMemory() -> libc::c_int;
    fn xmlValidateRoot(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> libc::c_int;
    fn xmlValidateElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlIsMixedElement(doc: xmlDocPtr, name: *const xmlChar) -> libc::c_int;
    fn xmlGetPredefinedEntity(name: *const xmlChar) -> xmlEntityPtr;
    fn xmlInitCharEncodingHandlers();
    fn xmlCleanupCharEncodingHandlers();
    fn xmlFindCharEncodingHandler(
        name: *const libc::c_char,
    ) -> xmlCharEncodingHandlerPtr;
    fn xmlDetectCharEncoding(
        in_0: *const libc::c_uchar,
        len: libc::c_int,
    ) -> xmlCharEncoding;
    fn xmlCleanupInputCallbacks();
    fn xmlRegisterDefaultInputCallbacks();
    fn xmlAllocParserInputBuffer(enc: xmlCharEncoding) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateFd(
        fd: libc::c_int,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateMem(
        mem: *const libc::c_char,
        size: libc::c_int,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferCreateIO(
        ioread: xmlInputReadCallback,
        ioclose: xmlInputCloseCallback,
        ioctx: *mut libc::c_void,
        enc: xmlCharEncoding,
    ) -> xmlParserInputBufferPtr;
    fn xmlParserInputBufferPush(
        in_0: xmlParserInputBufferPtr,
        len: libc::c_int,
        buf: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const libc::c_char) -> *mut libc::c_char;
    fn xmlCleanupOutputCallbacks();
    fn xmlRegisterDefaultOutputCallbacks();
    fn htmlDefaultSAXHandlerInit();
    fn xmlDefaultSAXHandlerInit();
    fn __xmlGenericError() -> *mut xmlGenericErrorFunc;
    fn xmlInitGlobals();
    fn xmlInitThreads();
    fn xmlCleanupThreads();
    fn xmlCleanupGlobals();
    static mut xmlFree: xmlFreeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMallocAtomic: xmlMallocFunc;
    fn __xmlGenericErrorContext() -> *mut *mut libc::c_void;
    fn __xmlParserDebugEntities() -> *mut libc::c_int;
    fn __xmlDefaultSAXHandler() -> *mut xmlSAXHandlerV1;
    fn xmlSAX2IgnorableWhitespace(
        ctx: *mut libc::c_void,
        ch: *const xmlChar,
        len: libc::c_int,
    );
    fn xmlSAX2StartElement(
        ctx: *mut libc::c_void,
        fullname: *const xmlChar,
        atts: *mut *const xmlChar,
    );
    fn xmlSAX2EndElement(ctx: *mut libc::c_void, name: *const xmlChar);
    fn __xmlDefaultSAXLocator() -> *mut xmlSAXLocator;
    fn xmlSAX2EntityDecl(
        ctx: *mut libc::c_void,
        name: *const xmlChar,
        type_0: libc::c_int,
        publicId: *const xmlChar,
        systemId: *const xmlChar,
        content: *mut xmlChar,
    );
    static mut xmlMalloc: xmlMallocFunc;
    fn xmlSAX2GetEntity(ctx: *mut libc::c_void, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlParserInputGrow(in_0: xmlParserInputPtr, len: libc::c_int) -> libc::c_int;
    fn xmlClearParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlFreeParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlNewParserCtxt() -> xmlParserCtxtPtr;
    fn xmlNewIOInputStream(
        ctxt: xmlParserCtxtPtr,
        input: xmlParserInputBufferPtr,
        enc: xmlCharEncoding,
    ) -> xmlParserInputPtr;
    fn xmlParserAddNodeInfo(ctxt: xmlParserCtxtPtr, info: xmlParserNodeInfoPtr);
    fn xmlLoadExternalEntity(
        URL: *const libc::c_char,
        ID: *const libc::c_char,
        ctxt: xmlParserCtxtPtr,
    ) -> xmlParserInputPtr;
    fn xmlInitNodeInfoSeq(seq: xmlParserNodeInfoSeqPtr);
    fn xmlSwitchEncoding(ctxt: xmlParserCtxtPtr, enc: xmlCharEncoding) -> libc::c_int;
    fn xmlSwitchToEncoding(
        ctxt: xmlParserCtxtPtr,
        handler: xmlCharEncodingHandlerPtr,
    ) -> libc::c_int;
    fn __xmlErrEncoding(
        ctxt: xmlParserCtxtPtr,
        xmlerr: xmlParserErrors,
        msg: *const libc::c_char,
        str1: *const xmlChar,
        str2: *const xmlChar,
    );
    fn xmlNewStringInputStream(
        ctxt: xmlParserCtxtPtr,
        buffer: *const xmlChar,
    ) -> xmlParserInputPtr;
    fn xmlNewEntityInputStream(
        ctxt: xmlParserCtxtPtr,
        entity: xmlEntityPtr,
    ) -> xmlParserInputPtr;
    fn xmlFreeInputStream(input: xmlParserInputPtr);
    fn xmlNewInputStream(ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr;
    fn xmlCopyChar(len: libc::c_int, out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    fn xmlStringCurrentChar(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        len: *mut libc::c_int,
    ) -> libc::c_int;
    fn htmlCreateMemoryParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> htmlParserCtxtPtr;
    fn htmlInitAutoClose();
    fn xmlErrMemory(ctxt: xmlParserCtxtPtr, extra: *const libc::c_char);
    fn xmlCopyCharMultiByte(out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    fn xmlParserInputShrink(in_0: xmlParserInputPtr);
    fn xmlCurrentChar(ctxt: xmlParserCtxtPtr, len: *mut libc::c_int) -> libc::c_int;
    fn xmlNextChar(ctxt: xmlParserCtxtPtr);
    static xmlIsDigitGroup: xmlChRangeGroup;
    static xmlIsCombiningGroup: xmlChRangeGroup;
    static xmlIsBaseCharGroup: xmlChRangeGroup;
    fn xmlCharInRange(val: libc::c_uint, group: *const xmlChRangeGroup) -> libc::c_int;
    static xmlIsExtenderGroup: xmlChRangeGroup;
    static xmlIsPubidChar_tab: [libc::c_uchar; 256];
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const libc::c_char) -> xmlURIPtr;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogCleanup();
    fn xmlCatalogFreeLocal(catalogs: *mut libc::c_void);
    fn xmlCatalogAddLocal(
        catalogs: *mut libc::c_void,
        URL: *const xmlChar,
    ) -> *mut libc::c_void;
    fn xmlCatalogGetDefaults() -> xmlCatalogAllow;
    fn xmlSchemaCleanupTypes();
    fn xmlRelaxNGCleanupTypes();
    fn xmlBufIsEmpty(buf: xmlBufPtr) -> libc::c_int;
    fn xmlBufResetInput(buf: xmlBufPtr, input: xmlParserInputPtr) -> libc::c_int;
    fn xmlBufGetInputBase(buf: xmlBufPtr, input: xmlParserInputPtr) -> size_t;
    fn xmlBufSetInputBaseCur(
        buf: xmlBufPtr,
        input: xmlParserInputPtr,
        base: size_t,
        cur: size_t,
    ) -> libc::c_int;
    fn xmlCharEncInput(
        input: xmlParserInputBufferPtr,
        flush: libc::c_int,
    ) -> libc::c_int;
    fn xmlXPathInit();
    fn xmlGenericErrorDefaultFunc(
        ctx: *mut libc::c_void,
        msg: *const libc::c_char,
        _: ...
    );
}
pub type xmlChar = libc::c_uchar;
pub type size_t = libc::c_ulong;
pub type ptrdiff_t = libc::c_long;
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlMallocFunc = Option::<unsafe extern "C" fn(size_t) -> *mut libc::c_void>;
pub type xmlReallocFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, size_t) -> *mut libc::c_void,
>;
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
pub struct _xmlParserCtxt {
    pub sax: *mut _xmlSAXHandler,
    pub userData: *mut libc::c_void,
    pub myDoc: xmlDocPtr,
    pub wellFormed: libc::c_int,
    pub replaceEntities: libc::c_int,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub standalone: libc::c_int,
    pub html: libc::c_int,
    pub input: xmlParserInputPtr,
    pub inputNr: libc::c_int,
    pub inputMax: libc::c_int,
    pub inputTab: *mut xmlParserInputPtr,
    pub node: xmlNodePtr,
    pub nodeNr: libc::c_int,
    pub nodeMax: libc::c_int,
    pub nodeTab: *mut xmlNodePtr,
    pub record_info: libc::c_int,
    pub node_seq: xmlParserNodeInfoSeq,
    pub errNo: libc::c_int,
    pub hasExternalSubset: libc::c_int,
    pub hasPErefs: libc::c_int,
    pub external: libc::c_int,
    pub valid: libc::c_int,
    pub validate: libc::c_int,
    pub vctxt: xmlValidCtxt,
    pub instate: xmlParserInputState,
    pub token: libc::c_int,
    pub directory: *mut libc::c_char,
    pub name: *const xmlChar,
    pub nameNr: libc::c_int,
    pub nameMax: libc::c_int,
    pub nameTab: *mut *const xmlChar,
    pub nbChars: libc::c_long,
    pub checkIndex: libc::c_long,
    pub keepBlanks: libc::c_int,
    pub disableSAX: libc::c_int,
    pub inSubset: libc::c_int,
    pub intSubName: *const xmlChar,
    pub extSubURI: *mut xmlChar,
    pub extSubSystem: *mut xmlChar,
    pub space: *mut libc::c_int,
    pub spaceNr: libc::c_int,
    pub spaceMax: libc::c_int,
    pub spaceTab: *mut libc::c_int,
    pub depth: libc::c_int,
    pub entity: xmlParserInputPtr,
    pub charset: libc::c_int,
    pub nodelen: libc::c_int,
    pub nodemem: libc::c_int,
    pub pedantic: libc::c_int,
    pub _private: *mut libc::c_void,
    pub loadsubset: libc::c_int,
    pub linenumbers: libc::c_int,
    pub catalogs: *mut libc::c_void,
    pub recovery: libc::c_int,
    pub progressive: libc::c_int,
    pub dict: xmlDictPtr,
    pub atts: *mut *const xmlChar,
    pub maxatts: libc::c_int,
    pub docdict: libc::c_int,
    pub str_xml: *const xmlChar,
    pub str_xmlns: *const xmlChar,
    pub str_xml_ns: *const xmlChar,
    pub sax2: libc::c_int,
    pub nsNr: libc::c_int,
    pub nsMax: libc::c_int,
    pub nsTab: *mut *const xmlChar,
    pub attallocs: *mut libc::c_int,
    pub pushTab: *mut xmlStartTag,
    pub attsDefault: xmlHashTablePtr,
    pub attsSpecial: xmlHashTablePtr,
    pub nsWellFormed: libc::c_int,
    pub options: libc::c_int,
    pub dictNames: libc::c_int,
    pub freeElemsNr: libc::c_int,
    pub freeElems: xmlNodePtr,
    pub freeAttrsNr: libc::c_int,
    pub freeAttrs: xmlAttrPtr,
    pub lastError: xmlError,
    pub parseMode: xmlParserMode,
    pub nbentities: libc::c_ulong,
    pub sizeentities: libc::c_ulong,
    pub nodeInfo: *mut xmlParserNodeInfo,
    pub nodeInfoNr: libc::c_int,
    pub nodeInfoMax: libc::c_int,
    pub nodeInfoTab: *mut xmlParserNodeInfo,
    pub input_id: libc::c_int,
    pub sizeentcopy: libc::c_ulong,
}
pub type xmlParserNodeInfo = _xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfo {
    pub node: *const _xmlNode,
    pub begin_pos: libc::c_ulong,
    pub begin_line: libc::c_ulong,
    pub end_pos: libc::c_ulong,
    pub end_line: libc::c_ulong,
}
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
pub type xmlParserMode = libc::c_uint;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = _xmlError;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlError {
    pub domain: libc::c_int,
    pub code: libc::c_int,
    pub message: *mut libc::c_char,
    pub level: xmlErrorLevel,
    pub file: *mut libc::c_char,
    pub line: libc::c_int,
    pub str1: *mut libc::c_char,
    pub str2: *mut libc::c_char,
    pub str3: *mut libc::c_char,
    pub int1: libc::c_int,
    pub int2: libc::c_int,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = libc::c_uint;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = *mut xmlAttr;
pub type xmlAttr = _xmlAttr;
pub type xmlNodePtr = *mut xmlNode;
pub type xmlNode = _xmlNode;
pub type xmlHashTablePtr = *mut xmlHashTable;
pub type xmlHashTable = _xmlHashTable;
pub type xmlStartTag = _xmlStartTag;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlStartTag {
    pub prefix: *const xmlChar,
    pub URI: *const xmlChar,
    pub line: libc::c_int,
    pub nsNr: libc::c_int,
}
pub type xmlDictPtr = *mut xmlDict;
pub type xmlDict = _xmlDict;
pub type xmlParserInputState = libc::c_int;
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
pub type xmlValidCtxt = _xmlValidCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidCtxt {
    pub userData: *mut libc::c_void,
    pub error: xmlValidityErrorFunc,
    pub warning: xmlValidityWarningFunc,
    pub node: xmlNodePtr,
    pub nodeNr: libc::c_int,
    pub nodeMax: libc::c_int,
    pub nodeTab: *mut xmlNodePtr,
    pub flags: libc::c_uint,
    pub doc: xmlDocPtr,
    pub valid: libc::c_int,
    pub vstate: *mut xmlValidState,
    pub vstateNr: libc::c_int,
    pub vstateMax: libc::c_int,
    pub vstateTab: *mut xmlValidState,
    pub am: xmlAutomataPtr,
    pub state: xmlAutomataStatePtr,
}
pub type xmlAutomataStatePtr = *mut xmlAutomataState;
pub type xmlAutomataState = _xmlAutomataState;
pub type xmlAutomataPtr = *mut xmlAutomata;
pub type xmlAutomata = _xmlAutomata;
pub type xmlValidState = _xmlValidState;
pub type xmlDocPtr = *mut xmlDoc;
pub type xmlDoc = _xmlDoc;
pub type xmlValidityWarningFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlValidityErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlParserNodeInfoSeq = _xmlParserNodeInfoSeq;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfoSeq {
    pub maximum: libc::c_ulong,
    pub length: libc::c_ulong,
    pub buffer: *mut xmlParserNodeInfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXHandler {
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
    pub _private: *mut libc::c_void,
    pub startElementNs: startElementNsSAX2Func,
    pub endElementNs: endElementNsSAX2Func,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlStructuredErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> (),
>;
pub type xmlErrorPtr = *mut xmlError;
pub type endElementNsSAX2Func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type startElementNsSAX2Func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        libc::c_int,
        *mut *const xmlChar,
        libc::c_int,
        libc::c_int,
        *mut *const xmlChar,
    ) -> (),
>;
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
pub type xmlParserCtxt = _xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
pub type xmlSAXHandler = _xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut xmlSAXHandler;
pub type xmlBufferAllocationScheme = libc::c_uint;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlBuffer {
    pub content: *mut xmlChar,
    pub use_0: libc::c_uint,
    pub size: libc::c_uint,
    pub alloc: xmlBufferAllocationScheme,
    pub contentIO: *mut xmlChar,
}
pub type xmlBuffer = _xmlBuffer;
pub type xmlBufferPtr = *mut xmlBuffer;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_ATTRIBUTE_FIXED: C2RustUnnamed = 4;
pub const XML_ATTRIBUTE_IMPLIED: C2RustUnnamed = 3;
pub const XML_ATTRIBUTE_REQUIRED: C2RustUnnamed = 2;
pub const XML_ATTRIBUTE_NONE: C2RustUnnamed = 1;
pub type C2RustUnnamed_0 = libc::c_uint;
pub const XML_ELEMENT_TYPE_ELEMENT: C2RustUnnamed_0 = 4;
pub const XML_ELEMENT_TYPE_MIXED: C2RustUnnamed_0 = 3;
pub const XML_ELEMENT_TYPE_ANY: C2RustUnnamed_0 = 2;
pub const XML_ELEMENT_TYPE_EMPTY: C2RustUnnamed_0 = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: C2RustUnnamed_0 = 0;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const XML_DOC_HTML: C2RustUnnamed_1 = 128;
pub const XML_DOC_INTERNAL: C2RustUnnamed_1 = 64;
pub const XML_DOC_USERBUILT: C2RustUnnamed_1 = 32;
pub const XML_DOC_XINCLUDE: C2RustUnnamed_1 = 16;
pub const XML_DOC_DTDVALID: C2RustUnnamed_1 = 8;
pub const XML_DOC_OLD10: C2RustUnnamed_1 = 4;
pub const XML_DOC_NSVALID: C2RustUnnamed_1 = 2;
pub const XML_DOC_WELLFORMED: C2RustUnnamed_1 = 1;
pub type xmlHashDeallocator = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
>;
pub type xmlHashScannerFull = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type C2RustUnnamed_2 = libc::c_uint;
pub const XML_FROM_URI: C2RustUnnamed_2 = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed_2 = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed_2 = 28;
pub const XML_FROM_I18N: C2RustUnnamed_2 = 27;
pub const XML_FROM_MODULE: C2RustUnnamed_2 = 26;
pub const XML_FROM_WRITER: C2RustUnnamed_2 = 25;
pub const XML_FROM_CHECK: C2RustUnnamed_2 = 24;
pub const XML_FROM_VALID: C2RustUnnamed_2 = 23;
pub const XML_FROM_XSLT: C2RustUnnamed_2 = 22;
pub const XML_FROM_C14N: C2RustUnnamed_2 = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed_2 = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed_2 = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed_2 = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed_2 = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed_2 = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed_2 = 15;
pub const XML_FROM_REGEXP: C2RustUnnamed_2 = 14;
pub const XML_FROM_XPOINTER: C2RustUnnamed_2 = 13;
pub const XML_FROM_XPATH: C2RustUnnamed_2 = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed_2 = 11;
pub const XML_FROM_HTTP: C2RustUnnamed_2 = 10;
pub const XML_FROM_FTP: C2RustUnnamed_2 = 9;
pub const XML_FROM_IO: C2RustUnnamed_2 = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed_2 = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed_2 = 6;
pub const XML_FROM_HTML: C2RustUnnamed_2 = 5;
pub const XML_FROM_DTD: C2RustUnnamed_2 = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed_2 = 3;
pub const XML_FROM_TREE: C2RustUnnamed_2 = 2;
pub const XML_FROM_PARSER: C2RustUnnamed_2 = 1;
pub const XML_FROM_NONE: C2RustUnnamed_2 = 0;
pub type xmlParserErrors = libc::c_uint;
pub const XML_BUF_OVERFLOW: xmlParserErrors = 7000;
pub const XML_I18N_NO_OUTPUT: xmlParserErrors = 6004;
pub const XML_I18N_CONV_FAILED: xmlParserErrors = 6003;
pub const XML_I18N_EXCESS_HANDLER: xmlParserErrors = 6002;
pub const XML_I18N_NO_HANDLER: xmlParserErrors = 6001;
pub const XML_I18N_NO_NAME: xmlParserErrors = 6000;
pub const XML_CHECK_NAME_NOT_NULL: xmlParserErrors = 5037;
pub const XML_CHECK_WRONG_NAME: xmlParserErrors = 5036;
pub const XML_CHECK_OUTSIDE_DICT: xmlParserErrors = 5035;
pub const XML_CHECK_NOT_NCNAME: xmlParserErrors = 5034;
pub const XML_CHECK_NO_DICT: xmlParserErrors = 5033;
pub const XML_CHECK_NOT_UTF8: xmlParserErrors = 5032;
pub const XML_CHECK_NS_ANCESTOR: xmlParserErrors = 5031;
pub const XML_CHECK_NS_SCOPE: xmlParserErrors = 5030;
pub const XML_CHECK_WRONG_PARENT: xmlParserErrors = 5029;
pub const XML_CHECK_NO_HREF: xmlParserErrors = 5028;
pub const XML_CHECK_NOT_NS_DECL: xmlParserErrors = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: xmlParserErrors = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: xmlParserErrors = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: xmlParserErrors = 5024;
pub const XML_CHECK_NOT_ATTR: xmlParserErrors = 5023;
pub const XML_CHECK_NOT_DTD: xmlParserErrors = 5022;
pub const XML_CHECK_WRONG_NEXT: xmlParserErrors = 5021;
pub const XML_CHECK_NO_NEXT: xmlParserErrors = 5020;
pub const XML_CHECK_WRONG_PREV: xmlParserErrors = 5019;
pub const XML_CHECK_NO_PREV: xmlParserErrors = 5018;
pub const XML_CHECK_WRONG_DOC: xmlParserErrors = 5017;
pub const XML_CHECK_NO_ELEM: xmlParserErrors = 5016;
pub const XML_CHECK_NO_NAME: xmlParserErrors = 5015;
pub const XML_CHECK_NO_DOC: xmlParserErrors = 5014;
pub const XML_CHECK_NO_PARENT: xmlParserErrors = 5013;
pub const XML_CHECK_ENTITY_TYPE: xmlParserErrors = 5012;
pub const XML_CHECK_UNKNOWN_NODE: xmlParserErrors = 5011;
pub const XML_CHECK_FOUND_NOTATION: xmlParserErrors = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: xmlParserErrors = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: xmlParserErrors = 5008;
pub const XML_CHECK_FOUND_COMMENT: xmlParserErrors = 5007;
pub const XML_CHECK_FOUND_PI: xmlParserErrors = 5006;
pub const XML_CHECK_FOUND_ENTITY: xmlParserErrors = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: xmlParserErrors = 5004;
pub const XML_CHECK_FOUND_CDATA: xmlParserErrors = 5003;
pub const XML_CHECK_FOUND_TEXT: xmlParserErrors = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: xmlParserErrors = 5001;
pub const XML_CHECK_FOUND_ELEMENT: xmlParserErrors = 5000;
pub const XML_MODULE_CLOSE: xmlParserErrors = 4901;
pub const XML_MODULE_OPEN: xmlParserErrors = 4900;
pub const XML_SCHEMATRONV_REPORT: xmlParserErrors = 4001;
pub const XML_SCHEMATRONV_ASSERT: xmlParserErrors = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: xmlParserErrors = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: xmlParserErrors = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: xmlParserErrors = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: xmlParserErrors = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: xmlParserErrors = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: xmlParserErrors = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: xmlParserErrors = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: xmlParserErrors = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: xmlParserErrors = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: xmlParserErrors = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: xmlParserErrors = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: xmlParserErrors = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: xmlParserErrors = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: xmlParserErrors = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: xmlParserErrors = 3077;
pub const XML_SCHEMAP_SRC_CT_1: xmlParserErrors = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: xmlParserErrors = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: xmlParserErrors = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: xmlParserErrors = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: xmlParserErrors = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: xmlParserErrors = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: xmlParserErrors = 3070;
pub const XML_SCHEMAP_INTERNAL: xmlParserErrors = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: xmlParserErrors = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: xmlParserErrors = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: xmlParserErrors = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: xmlParserErrors = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: xmlParserErrors = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: xmlParserErrors = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: xmlParserErrors = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: xmlParserErrors = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: xmlParserErrors = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: xmlParserErrors = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: xmlParserErrors = 3058;
pub const XML_SCHEMAP_NO_XSI: xmlParserErrors = 3057;
pub const XML_SCHEMAP_NO_XMLNS: xmlParserErrors = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: xmlParserErrors = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: xmlParserErrors = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: xmlParserErrors = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: xmlParserErrors = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: xmlParserErrors = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: xmlParserErrors = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: xmlParserErrors = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: xmlParserErrors = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: xmlParserErrors = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: xmlParserErrors = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: xmlParserErrors = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: xmlParserErrors = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: xmlParserErrors = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: xmlParserErrors = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: xmlParserErrors = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: xmlParserErrors = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: xmlParserErrors = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: xmlParserErrors = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: xmlParserErrors = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: xmlParserErrors = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: xmlParserErrors = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: xmlParserErrors = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: xmlParserErrors = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: xmlParserErrors = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: xmlParserErrors = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: xmlParserErrors = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: xmlParserErrors = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: xmlParserErrors = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: xmlParserErrors = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: xmlParserErrors = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: xmlParserErrors = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: xmlParserErrors = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: xmlParserErrors = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: xmlParserErrors = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: xmlParserErrors = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: xmlParserErrors = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: xmlParserErrors = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: xmlParserErrors = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: xmlParserErrors = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: xmlParserErrors = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: xmlParserErrors = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: xmlParserErrors = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: xmlParserErrors = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: xmlParserErrors = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: xmlParserErrors = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: xmlParserErrors = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: xmlParserErrors = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: xmlParserErrors = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: xmlParserErrors = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: xmlParserErrors = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: xmlParserErrors = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: xmlParserErrors = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: xmlParserErrors = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: xmlParserErrors = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: xmlParserErrors = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: xmlParserErrors = 3000;
pub const XML_HTTP_UNKNOWN_HOST: xmlParserErrors = 2022;
pub const XML_HTTP_USE_IP: xmlParserErrors = 2021;
pub const XML_HTTP_URL_SYNTAX: xmlParserErrors = 2020;
pub const XML_FTP_URL_SYNTAX: xmlParserErrors = 2003;
pub const XML_FTP_ACCNT: xmlParserErrors = 2002;
pub const XML_FTP_EPSV_ANSWER: xmlParserErrors = 2001;
pub const XML_FTP_PASV_ANSWER: xmlParserErrors = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: xmlParserErrors = 1955;
pub const XML_C14N_UNKNOW_NODE: xmlParserErrors = 1954;
pub const XML_C14N_INVALID_NODE: xmlParserErrors = 1953;
pub const XML_C14N_CREATE_STACK: xmlParserErrors = 1952;
pub const XML_C14N_REQUIRES_UTF8: xmlParserErrors = 1951;
pub const XML_C14N_CREATE_CTXT: xmlParserErrors = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: xmlParserErrors = 1903;
pub const XML_XPTR_EVAL_FAILED: xmlParserErrors = 1902;
pub const XML_XPTR_CHILDSEQ_START: xmlParserErrors = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: xmlParserErrors = 1900;
pub const XML_SCHEMAV_MISC: xmlParserErrors = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: xmlParserErrors = 1878;
pub const XML_SCHEMAV_CVC_IDC: xmlParserErrors = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: xmlParserErrors = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: xmlParserErrors = 1875;
pub const XML_SCHEMAV_CVC_AU: xmlParserErrors = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: xmlParserErrors = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: xmlParserErrors = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: xmlParserErrors = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: xmlParserErrors = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: xmlParserErrors = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: xmlParserErrors = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: xmlParserErrors = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: xmlParserErrors = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: xmlParserErrors = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: xmlParserErrors = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: xmlParserErrors = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: xmlParserErrors = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: xmlParserErrors = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: xmlParserErrors = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: xmlParserErrors = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: xmlParserErrors = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: xmlParserErrors = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: xmlParserErrors = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: xmlParserErrors = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: xmlParserErrors = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: xmlParserErrors = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: xmlParserErrors = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: xmlParserErrors = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: xmlParserErrors = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: xmlParserErrors = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: xmlParserErrors = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: xmlParserErrors = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: xmlParserErrors = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: xmlParserErrors = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: xmlParserErrors = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: xmlParserErrors = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: xmlParserErrors = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: xmlParserErrors = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: xmlParserErrors = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: xmlParserErrors = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: xmlParserErrors = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: xmlParserErrors = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: xmlParserErrors = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: xmlParserErrors = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: xmlParserErrors = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: xmlParserErrors = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: xmlParserErrors = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: xmlParserErrors = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: xmlParserErrors = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: xmlParserErrors = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: xmlParserErrors = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: xmlParserErrors = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: xmlParserErrors = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: xmlParserErrors = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: xmlParserErrors = 1824;
pub const XML_SCHEMAV_FACET: xmlParserErrors = 1823;
pub const XML_SCHEMAV_VALUE: xmlParserErrors = 1822;
pub const XML_SCHEMAV_ATTRINVALID: xmlParserErrors = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: xmlParserErrors = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: xmlParserErrors = 1819;
pub const XML_SCHEMAV_INTERNAL: xmlParserErrors = 1818;
pub const XML_SCHEMAV_CONSTRUCT: xmlParserErrors = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: xmlParserErrors = 1816;
pub const XML_SCHEMAV_INVALIDELEM: xmlParserErrors = 1815;
pub const XML_SCHEMAV_INVALIDATTR: xmlParserErrors = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: xmlParserErrors = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: xmlParserErrors = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: xmlParserErrors = 1811;
pub const XML_SCHEMAV_ELEMCONT: xmlParserErrors = 1810;
pub const XML_SCHEMAV_NOTEMPTY: xmlParserErrors = 1809;
pub const XML_SCHEMAV_ISABSTRACT: xmlParserErrors = 1808;
pub const XML_SCHEMAV_NOROLLBACK: xmlParserErrors = 1807;
pub const XML_SCHEMAV_NOTYPE: xmlParserErrors = 1806;
pub const XML_SCHEMAV_WRONGELEM: xmlParserErrors = 1805;
pub const XML_SCHEMAV_MISSING: xmlParserErrors = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: xmlParserErrors = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: xmlParserErrors = 1802;
pub const XML_SCHEMAV_NOROOT: xmlParserErrors = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: xmlParserErrors = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: xmlParserErrors = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: xmlParserErrors = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: xmlParserErrors = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: xmlParserErrors = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: xmlParserErrors = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: xmlParserErrors = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: xmlParserErrors = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: xmlParserErrors = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: xmlParserErrors = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: xmlParserErrors = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: xmlParserErrors = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: xmlParserErrors = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: xmlParserErrors = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: xmlParserErrors = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: xmlParserErrors = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: xmlParserErrors = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: xmlParserErrors = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: xmlParserErrors = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: xmlParserErrors = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: xmlParserErrors = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: xmlParserErrors = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: xmlParserErrors = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: xmlParserErrors = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: xmlParserErrors = 1776;
pub const XML_SCHEMAP_RECURSIVE: xmlParserErrors = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: xmlParserErrors = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: xmlParserErrors = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: xmlParserErrors = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: xmlParserErrors = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: xmlParserErrors = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: xmlParserErrors = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: xmlParserErrors = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: xmlParserErrors = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: xmlParserErrors = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: xmlParserErrors = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: xmlParserErrors = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: xmlParserErrors = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: xmlParserErrors = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: xmlParserErrors = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: xmlParserErrors = 1760;
pub const XML_SCHEMAP_NOROOT: xmlParserErrors = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: xmlParserErrors = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: xmlParserErrors = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: xmlParserErrors = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: xmlParserErrors = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: xmlParserErrors = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: xmlParserErrors = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: xmlParserErrors = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: xmlParserErrors = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: xmlParserErrors = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: xmlParserErrors = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: xmlParserErrors = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: xmlParserErrors = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: xmlParserErrors = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: xmlParserErrors = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: xmlParserErrors = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: xmlParserErrors = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: xmlParserErrors = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: xmlParserErrors = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: xmlParserErrors = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: xmlParserErrors = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: xmlParserErrors = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: xmlParserErrors = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: xmlParserErrors = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: xmlParserErrors = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: xmlParserErrors = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: xmlParserErrors = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: xmlParserErrors = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: xmlParserErrors = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: xmlParserErrors = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: xmlParserErrors = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: xmlParserErrors = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: xmlParserErrors = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: xmlParserErrors = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: xmlParserErrors = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: xmlParserErrors = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: xmlParserErrors = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: xmlParserErrors = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: xmlParserErrors = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: xmlParserErrors = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: xmlParserErrors = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: xmlParserErrors = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: xmlParserErrors = 1717;
pub const XML_SCHEMAP_INVALID_FACET: xmlParserErrors = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: xmlParserErrors = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: xmlParserErrors = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: xmlParserErrors = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: xmlParserErrors = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: xmlParserErrors = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: xmlParserErrors = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: xmlParserErrors = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: xmlParserErrors = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: xmlParserErrors = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: xmlParserErrors = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: xmlParserErrors = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: xmlParserErrors = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: xmlParserErrors = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: xmlParserErrors = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: xmlParserErrors = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: xmlParserErrors = 1700;
pub const XML_CATALOG_RECURSION: xmlParserErrors = 1654;
pub const XML_CATALOG_NOT_CATALOG: xmlParserErrors = 1653;
pub const XML_CATALOG_PREFER_VALUE: xmlParserErrors = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: xmlParserErrors = 1651;
pub const XML_CATALOG_MISSING_ATTR: xmlParserErrors = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: xmlParserErrors = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: xmlParserErrors = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: xmlParserErrors = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: xmlParserErrors = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: xmlParserErrors = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: xmlParserErrors = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: xmlParserErrors = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: xmlParserErrors = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: xmlParserErrors = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: xmlParserErrors = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: xmlParserErrors = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: xmlParserErrors = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: xmlParserErrors = 1606;
pub const XML_XINCLUDE_HREF_URI: xmlParserErrors = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: xmlParserErrors = 1604;
pub const XML_XINCLUDE_NO_HREF: xmlParserErrors = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: xmlParserErrors = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: xmlParserErrors = 1601;
pub const XML_XINCLUDE_RECURSION: xmlParserErrors = 1600;
pub const XML_IO_EAFNOSUPPORT: xmlParserErrors = 1556;
pub const XML_IO_EALREADY: xmlParserErrors = 1555;
pub const XML_IO_EADDRINUSE: xmlParserErrors = 1554;
pub const XML_IO_ENETUNREACH: xmlParserErrors = 1553;
pub const XML_IO_ECONNREFUSED: xmlParserErrors = 1552;
pub const XML_IO_EISCONN: xmlParserErrors = 1551;
pub const XML_IO_ENOTSOCK: xmlParserErrors = 1550;
pub const XML_IO_LOAD_ERROR: xmlParserErrors = 1549;
pub const XML_IO_BUFFER_FULL: xmlParserErrors = 1548;
pub const XML_IO_NO_INPUT: xmlParserErrors = 1547;
pub const XML_IO_WRITE: xmlParserErrors = 1546;
pub const XML_IO_FLUSH: xmlParserErrors = 1545;
pub const XML_IO_ENCODER: xmlParserErrors = 1544;
pub const XML_IO_NETWORK_ATTEMPT: xmlParserErrors = 1543;
pub const XML_IO_EXDEV: xmlParserErrors = 1542;
pub const XML_IO_ETIMEDOUT: xmlParserErrors = 1541;
pub const XML_IO_ESRCH: xmlParserErrors = 1540;
pub const XML_IO_ESPIPE: xmlParserErrors = 1539;
pub const XML_IO_EROFS: xmlParserErrors = 1538;
pub const XML_IO_ERANGE: xmlParserErrors = 1537;
pub const XML_IO_EPIPE: xmlParserErrors = 1536;
pub const XML_IO_EPERM: xmlParserErrors = 1535;
pub const XML_IO_ENXIO: xmlParserErrors = 1534;
pub const XML_IO_ENOTTY: xmlParserErrors = 1533;
pub const XML_IO_ENOTSUP: xmlParserErrors = 1532;
pub const XML_IO_ENOTEMPTY: xmlParserErrors = 1531;
pub const XML_IO_ENOTDIR: xmlParserErrors = 1530;
pub const XML_IO_ENOSYS: xmlParserErrors = 1529;
pub const XML_IO_ENOSPC: xmlParserErrors = 1528;
pub const XML_IO_ENOMEM: xmlParserErrors = 1527;
pub const XML_IO_ENOLCK: xmlParserErrors = 1526;
pub const XML_IO_ENOEXEC: xmlParserErrors = 1525;
pub const XML_IO_ENOENT: xmlParserErrors = 1524;
pub const XML_IO_ENODEV: xmlParserErrors = 1523;
pub const XML_IO_ENFILE: xmlParserErrors = 1522;
pub const XML_IO_ENAMETOOLONG: xmlParserErrors = 1521;
pub const XML_IO_EMSGSIZE: xmlParserErrors = 1520;
pub const XML_IO_EMLINK: xmlParserErrors = 1519;
pub const XML_IO_EMFILE: xmlParserErrors = 1518;
pub const XML_IO_EISDIR: xmlParserErrors = 1517;
pub const XML_IO_EIO: xmlParserErrors = 1516;
pub const XML_IO_EINVAL: xmlParserErrors = 1515;
pub const XML_IO_EINTR: xmlParserErrors = 1514;
pub const XML_IO_EINPROGRESS: xmlParserErrors = 1513;
pub const XML_IO_EFBIG: xmlParserErrors = 1512;
pub const XML_IO_EFAULT: xmlParserErrors = 1511;
pub const XML_IO_EEXIST: xmlParserErrors = 1510;
pub const XML_IO_EDOM: xmlParserErrors = 1509;
pub const XML_IO_EDEADLK: xmlParserErrors = 1508;
pub const XML_IO_ECHILD: xmlParserErrors = 1507;
pub const XML_IO_ECANCELED: xmlParserErrors = 1506;
pub const XML_IO_EBUSY: xmlParserErrors = 1505;
pub const XML_IO_EBADMSG: xmlParserErrors = 1504;
pub const XML_IO_EBADF: xmlParserErrors = 1503;
pub const XML_IO_EAGAIN: xmlParserErrors = 1502;
pub const XML_IO_EACCES: xmlParserErrors = 1501;
pub const XML_IO_UNKNOWN: xmlParserErrors = 1500;
pub const XML_REGEXP_COMPILE_ERROR: xmlParserErrors = 1450;
pub const XML_SAVE_UNKNOWN_ENCODING: xmlParserErrors = 1403;
pub const XML_SAVE_NO_DOCTYPE: xmlParserErrors = 1402;
pub const XML_SAVE_CHAR_INVALID: xmlParserErrors = 1401;
pub const XML_SAVE_NOT_UTF8: xmlParserErrors = 1400;
pub const XML_TREE_NOT_UTF8: xmlParserErrors = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: xmlParserErrors = 1302;
pub const XML_TREE_INVALID_DEC: xmlParserErrors = 1301;
pub const XML_TREE_INVALID_HEX: xmlParserErrors = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: xmlParserErrors = 1221;
pub const XML_XPATH_ENCODING_ERROR: xmlParserErrors = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: xmlParserErrors = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: xmlParserErrors = 1218;
pub const XML_XPTR_RESOURCE_ERROR: xmlParserErrors = 1217;
pub const XML_XPTR_SYNTAX_ERROR: xmlParserErrors = 1216;
pub const XML_XPATH_MEMORY_ERROR: xmlParserErrors = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: xmlParserErrors = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: xmlParserErrors = 1213;
pub const XML_XPATH_INVALID_ARITY: xmlParserErrors = 1212;
pub const XML_XPATH_INVALID_TYPE: xmlParserErrors = 1211;
pub const XML_XPATH_INVALID_OPERAND: xmlParserErrors = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: xmlParserErrors = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: xmlParserErrors = 1208;
pub const XML_XPATH_EXPR_ERROR: xmlParserErrors = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: xmlParserErrors = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: xmlParserErrors = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: xmlParserErrors = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: xmlParserErrors = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: xmlParserErrors = 1202;
pub const XML_XPATH_NUMBER_ERROR: xmlParserErrors = 1201;
pub const XML_XPATH_EXPRESSION_OK: xmlParserErrors = 1200;
pub const XML_RNGP_XML_NS: xmlParserErrors = 1122;
pub const XML_RNGP_XMLNS_NAME: xmlParserErrors = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: xmlParserErrors = 1120;
pub const XML_RNGP_VALUE_EMPTY: xmlParserErrors = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: xmlParserErrors = 1118;
pub const XML_RNGP_URI_FRAGMENT: xmlParserErrors = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: xmlParserErrors = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: xmlParserErrors = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: xmlParserErrors = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: xmlParserErrors = 1113;
pub const XML_RNGP_TYPE_VALUE: xmlParserErrors = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: xmlParserErrors = 1111;
pub const XML_RNGP_TYPE_MISSING: xmlParserErrors = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: xmlParserErrors = 1109;
pub const XML_RNGP_TEXT_EXPECTED: xmlParserErrors = 1108;
pub const XML_RNGP_START_MISSING: xmlParserErrors = 1107;
pub const XML_RNGP_START_EMPTY: xmlParserErrors = 1106;
pub const XML_RNGP_START_CONTENT: xmlParserErrors = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: xmlParserErrors = 1103;
pub const XML_RNGP_REF_NO_NAME: xmlParserErrors = 1102;
pub const XML_RNGP_REF_NO_DEF: xmlParserErrors = 1101;
pub const XML_RNGP_REF_NAME_INVALID: xmlParserErrors = 1100;
pub const XML_RNGP_REF_CYCLE: xmlParserErrors = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: xmlParserErrors = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: xmlParserErrors = 1097;
pub const XML_RNGP_PAT_START_VALUE: xmlParserErrors = 1096;
pub const XML_RNGP_PAT_START_TEXT: xmlParserErrors = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: xmlParserErrors = 1094;
pub const XML_RNGP_PAT_START_LIST: xmlParserErrors = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: xmlParserErrors = 1092;
pub const XML_RNGP_PAT_START_GROUP: xmlParserErrors = 1091;
pub const XML_RNGP_PAT_START_EMPTY: xmlParserErrors = 1090;
pub const XML_RNGP_PAT_START_DATA: xmlParserErrors = 1089;
pub const XML_RNGP_PAT_START_ATTR: xmlParserErrors = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: xmlParserErrors = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: xmlParserErrors = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: xmlParserErrors = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: xmlParserErrors = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: xmlParserErrors = 1083;
pub const XML_RNGP_PAT_LIST_REF: xmlParserErrors = 1082;
pub const XML_RNGP_PAT_LIST_LIST: xmlParserErrors = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: xmlParserErrors = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: xmlParserErrors = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: xmlParserErrors = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: xmlParserErrors = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: xmlParserErrors = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: xmlParserErrors = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: xmlParserErrors = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: xmlParserErrors = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: xmlParserErrors = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: xmlParserErrors = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: xmlParserErrors = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: xmlParserErrors = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: xmlParserErrors = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: xmlParserErrors = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: xmlParserErrors = 1066;
pub const XML_RNGP_PARSE_ERROR: xmlParserErrors = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: xmlParserErrors = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: xmlParserErrors = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: xmlParserErrors = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: xmlParserErrors = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: xmlParserErrors = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: xmlParserErrors = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: xmlParserErrors = 1058;
pub const XML_RNGP_NSNAME_NO_NS: xmlParserErrors = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: xmlParserErrors = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: xmlParserErrors = 1055;
pub const XML_RNGP_NEED_COMBINE: xmlParserErrors = 1054;
pub const XML_RNGP_NAME_MISSING: xmlParserErrors = 1053;
pub const XML_RNGP_MISSING_HREF: xmlParserErrors = 1052;
pub const XML_RNGP_INVALID_VALUE: xmlParserErrors = 1051;
pub const XML_RNGP_INVALID_URI: xmlParserErrors = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: xmlParserErrors = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: xmlParserErrors = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: xmlParserErrors = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: xmlParserErrors = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: xmlParserErrors = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: xmlParserErrors = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: xmlParserErrors = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: xmlParserErrors = 1042;
pub const XML_RNGP_HREF_ERROR: xmlParserErrors = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: xmlParserErrors = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: xmlParserErrors = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: xmlParserErrors = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: xmlParserErrors = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: xmlParserErrors = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: xmlParserErrors = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: xmlParserErrors = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: xmlParserErrors = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: xmlParserErrors = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: xmlParserErrors = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: xmlParserErrors = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: xmlParserErrors = 1029;
pub const XML_RNGP_EXCEPT_MISSING: xmlParserErrors = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: xmlParserErrors = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: xmlParserErrors = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: xmlParserErrors = 1025;
pub const XML_RNGP_EMPTY_CONTENT: xmlParserErrors = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: xmlParserErrors = 1023;
pub const XML_RNGP_EMPTY: xmlParserErrors = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: xmlParserErrors = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: xmlParserErrors = 1020;
pub const XML_RNGP_ELEMENT_NAME: xmlParserErrors = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: xmlParserErrors = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: xmlParserErrors = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: xmlParserErrors = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: xmlParserErrors = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: xmlParserErrors = 1014;
pub const XML_RNGP_DEFINE_MISSING: xmlParserErrors = 1013;
pub const XML_RNGP_DEFINE_EMPTY: xmlParserErrors = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: xmlParserErrors = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: xmlParserErrors = 1010;
pub const XML_RNGP_DATA_CONTENT: xmlParserErrors = 1009;
pub const XML_RNGP_CREATE_FAILURE: xmlParserErrors = 1008;
pub const XML_RNGP_CHOICE_EMPTY: xmlParserErrors = 1007;
pub const XML_RNGP_CHOICE_CONTENT: xmlParserErrors = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: xmlParserErrors = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: xmlParserErrors = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: xmlParserErrors = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: xmlParserErrors = 1002;
pub const XML_RNGP_ATTR_CONFLICT: xmlParserErrors = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: xmlParserErrors = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: xmlParserErrors = 802;
pub const XML_HTML_UNKNOWN_TAG: xmlParserErrors = 801;
pub const XML_HTML_STRUCURE_ERROR: xmlParserErrors = 800;
pub const XML_DTD_DUP_TOKEN: xmlParserErrors = 541;
pub const XML_DTD_XMLID_TYPE: xmlParserErrors = 540;
pub const XML_DTD_XMLID_VALUE: xmlParserErrors = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: xmlParserErrors = 538;
pub const XML_DTD_UNKNOWN_NOTATION: xmlParserErrors = 537;
pub const XML_DTD_UNKNOWN_ID: xmlParserErrors = 536;
pub const XML_DTD_UNKNOWN_ENTITY: xmlParserErrors = 535;
pub const XML_DTD_UNKNOWN_ELEM: xmlParserErrors = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: xmlParserErrors = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: xmlParserErrors = 532;
pub const XML_DTD_ROOT_NAME: xmlParserErrors = 531;
pub const XML_DTD_NOT_STANDALONE: xmlParserErrors = 530;
pub const XML_DTD_NOT_PCDATA: xmlParserErrors = 529;
pub const XML_DTD_NOT_EMPTY: xmlParserErrors = 528;
pub const XML_DTD_NOTATION_VALUE: xmlParserErrors = 527;
pub const XML_DTD_NOTATION_REDEFINED: xmlParserErrors = 526;
pub const XML_DTD_NO_ROOT: xmlParserErrors = 525;
pub const XML_DTD_NO_PREFIX: xmlParserErrors = 524;
pub const XML_DTD_NO_ELEM_NAME: xmlParserErrors = 523;
pub const XML_DTD_NO_DTD: xmlParserErrors = 522;
pub const XML_DTD_NO_DOC: xmlParserErrors = 521;
pub const XML_DTD_MULTIPLE_ID: xmlParserErrors = 520;
pub const XML_DTD_MIXED_CORRUPT: xmlParserErrors = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: xmlParserErrors = 518;
pub const XML_DTD_LOAD_ERROR: xmlParserErrors = 517;
pub const XML_DTD_INVALID_DEFAULT: xmlParserErrors = 516;
pub const XML_DTD_INVALID_CHILD: xmlParserErrors = 515;
pub const XML_DTD_ID_SUBSET: xmlParserErrors = 514;
pub const XML_DTD_ID_REDEFINED: xmlParserErrors = 513;
pub const XML_DTD_ID_FIXED: xmlParserErrors = 512;
pub const XML_DTD_ENTITY_TYPE: xmlParserErrors = 511;
pub const XML_DTD_EMPTY_NOTATION: xmlParserErrors = 510;
pub const XML_DTD_ELEM_REDEFINED: xmlParserErrors = 509;
pub const XML_DTD_ELEM_NAMESPACE: xmlParserErrors = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: xmlParserErrors = 507;
pub const XML_DTD_DIFFERENT_PREFIX: xmlParserErrors = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: xmlParserErrors = 505;
pub const XML_DTD_CONTENT_MODEL: xmlParserErrors = 504;
pub const XML_DTD_CONTENT_ERROR: xmlParserErrors = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: xmlParserErrors = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: xmlParserErrors = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: xmlParserErrors = 500;
pub const XML_NS_ERR_COLON: xmlParserErrors = 205;
pub const XML_NS_ERR_EMPTY: xmlParserErrors = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 203;
pub const XML_NS_ERR_QNAME: xmlParserErrors = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: xmlParserErrors = 201;
pub const XML_NS_ERR_XML_NAMESPACE: xmlParserErrors = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: xmlParserErrors = 112;
pub const XML_ERR_USER_STOP: xmlParserErrors = 111;
pub const XML_ERR_NAME_TOO_LONG: xmlParserErrors = 110;
pub const XML_ERR_VERSION_MISMATCH: xmlParserErrors = 109;
pub const XML_ERR_UNKNOWN_VERSION: xmlParserErrors = 108;
pub const XML_WAR_ENTITY_REDEFINED: xmlParserErrors = 107;
pub const XML_WAR_NS_COLUMN: xmlParserErrors = 106;
pub const XML_ERR_NOTATION_PROCESSING: xmlParserErrors = 105;
pub const XML_ERR_ENTITY_PROCESSING: xmlParserErrors = 104;
pub const XML_ERR_NOT_STANDALONE: xmlParserErrors = 103;
pub const XML_WAR_SPACE_VALUE: xmlParserErrors = 102;
pub const XML_ERR_MISSING_ENCODING: xmlParserErrors = 101;
pub const XML_WAR_NS_URI_RELATIVE: xmlParserErrors = 100;
pub const XML_WAR_NS_URI: xmlParserErrors = 99;
pub const XML_WAR_LANG_VALUE: xmlParserErrors = 98;
pub const XML_WAR_UNKNOWN_VERSION: xmlParserErrors = 97;
pub const XML_ERR_VERSION_MISSING: xmlParserErrors = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: xmlParserErrors = 95;
pub const XML_ERR_NO_DTD: xmlParserErrors = 94;
pub const XML_WAR_CATALOG_PI: xmlParserErrors = 93;
pub const XML_ERR_URI_FRAGMENT: xmlParserErrors = 92;
pub const XML_ERR_INVALID_URI: xmlParserErrors = 91;
pub const XML_ERR_ENTITY_BOUNDARY: xmlParserErrors = 90;
pub const XML_ERR_ENTITY_LOOP: xmlParserErrors = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: xmlParserErrors = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: xmlParserErrors = 87;
pub const XML_ERR_EXTRA_CONTENT: xmlParserErrors = 86;
pub const XML_ERR_NOT_WELL_BALANCED: xmlParserErrors = 85;
pub const XML_ERR_VALUE_REQUIRED: xmlParserErrors = 84;
pub const XML_ERR_CONDSEC_INVALID: xmlParserErrors = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: xmlParserErrors = 82;
pub const XML_ERR_INVALID_ENCODING: xmlParserErrors = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: xmlParserErrors = 80;
pub const XML_ERR_ENCODING_NAME: xmlParserErrors = 79;
pub const XML_ERR_STANDALONE_VALUE: xmlParserErrors = 78;
pub const XML_ERR_TAG_NOT_FINISHED: xmlParserErrors = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: xmlParserErrors = 76;
pub const XML_ERR_EQUAL_REQUIRED: xmlParserErrors = 75;
pub const XML_ERR_LTSLASH_REQUIRED: xmlParserErrors = 74;
pub const XML_ERR_GT_REQUIRED: xmlParserErrors = 73;
pub const XML_ERR_LT_REQUIRED: xmlParserErrors = 72;
pub const XML_ERR_PUBID_REQUIRED: xmlParserErrors = 71;
pub const XML_ERR_URI_REQUIRED: xmlParserErrors = 70;
pub const XML_ERR_PCDATA_REQUIRED: xmlParserErrors = 69;
pub const XML_ERR_NAME_REQUIRED: xmlParserErrors = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: xmlParserErrors = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: xmlParserErrors = 66;
pub const XML_ERR_SPACE_REQUIRED: xmlParserErrors = 65;
pub const XML_ERR_RESERVED_XML_NAME: xmlParserErrors = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: xmlParserErrors = 63;
pub const XML_ERR_MISPLACED_CDATA_END: xmlParserErrors = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: xmlParserErrors = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: xmlParserErrors = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: xmlParserErrors = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: xmlParserErrors = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: xmlParserErrors = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: xmlParserErrors = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: xmlParserErrors = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: xmlParserErrors = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: xmlParserErrors = 53;
pub const XML_ERR_MIXED_NOT_STARTED: xmlParserErrors = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: xmlParserErrors = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: xmlParserErrors = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: xmlParserErrors = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: xmlParserErrors = 48;
pub const XML_ERR_PI_NOT_FINISHED: xmlParserErrors = 47;
pub const XML_ERR_PI_NOT_STARTED: xmlParserErrors = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: xmlParserErrors = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: xmlParserErrors = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: xmlParserErrors = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: xmlParserErrors = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: xmlParserErrors = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: xmlParserErrors = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: xmlParserErrors = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: xmlParserErrors = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: xmlParserErrors = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: xmlParserErrors = 36;
pub const XML_ERR_NS_DECL_ERROR: xmlParserErrors = 35;
pub const XML_ERR_STRING_NOT_CLOSED: xmlParserErrors = 34;
pub const XML_ERR_STRING_NOT_STARTED: xmlParserErrors = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: xmlParserErrors = 32;
pub const XML_ERR_UNKNOWN_ENCODING: xmlParserErrors = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: xmlParserErrors = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: xmlParserErrors = 29;
pub const XML_ERR_UNPARSED_ENTITY: xmlParserErrors = 28;
pub const XML_WAR_UNDECLARED_ENTITY: xmlParserErrors = 27;
pub const XML_ERR_UNDECLARED_ENTITY: xmlParserErrors = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: xmlParserErrors = 25;
pub const XML_ERR_PEREF_NO_NAME: xmlParserErrors = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: xmlParserErrors = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: xmlParserErrors = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: xmlParserErrors = 21;
pub const XML_ERR_PEREF_IN_EPILOG: xmlParserErrors = 20;
pub const XML_ERR_PEREF_IN_PROLOG: xmlParserErrors = 19;
pub const XML_ERR_PEREF_AT_EOF: xmlParserErrors = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: xmlParserErrors = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: xmlParserErrors = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: xmlParserErrors = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: xmlParserErrors = 14;
pub const XML_ERR_CHARREF_IN_DTD: xmlParserErrors = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: xmlParserErrors = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: xmlParserErrors = 11;
pub const XML_ERR_CHARREF_AT_EOF: xmlParserErrors = 10;
pub const XML_ERR_INVALID_CHAR: xmlParserErrors = 9;
pub const XML_ERR_INVALID_CHARREF: xmlParserErrors = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: xmlParserErrors = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: xmlParserErrors = 6;
pub const XML_ERR_DOCUMENT_END: xmlParserErrors = 5;
pub const XML_ERR_DOCUMENT_EMPTY: xmlParserErrors = 4;
pub const XML_ERR_DOCUMENT_START: xmlParserErrors = 3;
pub const XML_ERR_NO_MEMORY: xmlParserErrors = 2;
pub const XML_ERR_INTERNAL_ERROR: xmlParserErrors = 1;
pub const XML_ERR_OK: xmlParserErrors = 0;
pub type xmlGenericErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlParserNodeInfoPtr = *mut xmlParserNodeInfo;
pub type xmlParserNodeInfoSeqPtr = *mut xmlParserNodeInfoSeq;
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
pub type xmlCharEncoding = libc::c_int;
pub const XML_CHAR_ENCODING_ASCII: xmlCharEncoding = 22;
pub const XML_CHAR_ENCODING_EUC_JP: xmlCharEncoding = 21;
pub const XML_CHAR_ENCODING_SHIFT_JIS: xmlCharEncoding = 20;
pub const XML_CHAR_ENCODING_2022_JP: xmlCharEncoding = 19;
pub const XML_CHAR_ENCODING_8859_9: xmlCharEncoding = 18;
pub const XML_CHAR_ENCODING_8859_8: xmlCharEncoding = 17;
pub const XML_CHAR_ENCODING_8859_7: xmlCharEncoding = 16;
pub const XML_CHAR_ENCODING_8859_6: xmlCharEncoding = 15;
pub const XML_CHAR_ENCODING_8859_5: xmlCharEncoding = 14;
pub const XML_CHAR_ENCODING_8859_4: xmlCharEncoding = 13;
pub const XML_CHAR_ENCODING_8859_3: xmlCharEncoding = 12;
pub const XML_CHAR_ENCODING_8859_2: xmlCharEncoding = 11;
pub const XML_CHAR_ENCODING_8859_1: xmlCharEncoding = 10;
pub const XML_CHAR_ENCODING_UCS2: xmlCharEncoding = 9;
pub const XML_CHAR_ENCODING_UCS4_3412: xmlCharEncoding = 8;
pub const XML_CHAR_ENCODING_UCS4_2143: xmlCharEncoding = 7;
pub const XML_CHAR_ENCODING_EBCDIC: xmlCharEncoding = 6;
pub const XML_CHAR_ENCODING_UCS4BE: xmlCharEncoding = 5;
pub const XML_CHAR_ENCODING_UCS4LE: xmlCharEncoding = 4;
pub const XML_CHAR_ENCODING_UTF16BE: xmlCharEncoding = 3;
pub const XML_CHAR_ENCODING_UTF16LE: xmlCharEncoding = 2;
pub const XML_CHAR_ENCODING_UTF8: xmlCharEncoding = 1;
pub const XML_CHAR_ENCODING_NONE: xmlCharEncoding = 0;
pub const XML_CHAR_ENCODING_ERROR: xmlCharEncoding = -1;
pub const XML_PARSE_OLD10: C2RustUnnamed_3 = 131072;
pub const XML_PARSE_HUGE: C2RustUnnamed_3 = 524288;
pub const XML_CATA_ALLOW_ALL: xmlCatalogAllow = 3;
pub type xmlCatalogAllow = libc::c_uint;
pub const XML_CATA_ALLOW_DOCUMENT: xmlCatalogAllow = 2;
pub const XML_CATA_ALLOW_GLOBAL: xmlCatalogAllow = 1;
pub const XML_CATA_ALLOW_NONE: xmlCatalogAllow = 0;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed_3 = 2097152;
pub const XML_PARSE_DTDATTR: C2RustUnnamed_3 = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed_3 = 4;
pub const XML_PARSE_DTDVALID: C2RustUnnamed_3 = 16;
pub const XML_PARSE_NOENT: C2RustUnnamed_3 = 2;
pub type xmlChRangeGroup = _xmlChRangeGroup;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChRangeGroup {
    pub nbShortRange: libc::c_int,
    pub nbLongRange: libc::c_int,
    pub shortRange: *const xmlChSRange,
    pub longRange: *const xmlChLRange,
}
pub type xmlChLRange = _xmlChLRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChLRange {
    pub low: libc::c_uint,
    pub high: libc::c_uint,
}
pub type xmlChSRange = _xmlChSRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlChSRange {
    pub low: libc::c_ushort,
    pub high: libc::c_ushort,
}
pub const XML_PARSE_OLDSAX: C2RustUnnamed_3 = 1048576;
pub type xmlEntityReferenceFunc = Option::<
    unsafe extern "C" fn(xmlEntityPtr, xmlNodePtr, xmlNodePtr) -> (),
>;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed_3 = 8192;
pub type xmlDefAttrsPtr = *mut xmlDefAttrs;
pub type xmlDefAttrs = _xmlDefAttrs;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlDefAttrs {
    pub nbAttrs: libc::c_int,
    pub maxAttrs: libc::c_int,
    pub values: [*const xmlChar; 0],
}
pub type xmlURIPtr = *mut xmlURI;
pub type xmlURI = _xmlURI;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlURI {
    pub scheme: *mut libc::c_char,
    pub opaque: *mut libc::c_char,
    pub authority: *mut libc::c_char,
    pub server: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub port: libc::c_int,
    pub path: *mut libc::c_char,
    pub query: *mut libc::c_char,
    pub fragment: *mut libc::c_char,
    pub cleanup: libc::c_int,
    pub query_raw: *mut libc::c_char,
}
pub const XML_PARSE_BIG_LINES: C2RustUnnamed_3 = 4194304;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed_3 = 262144;
pub const XML_PARSE_COMPACT: C2RustUnnamed_3 = 65536;
pub const XML_PARSE_NONET: C2RustUnnamed_3 = 2048;
pub const XML_PARSE_NOCDATA: C2RustUnnamed_3 = 16384;
pub const XML_PARSE_NODICT: C2RustUnnamed_3 = 4096;
pub const XML_PARSE_SAX1: C2RustUnnamed_3 = 512;
pub const XML_PARSE_NOERROR: C2RustUnnamed_3 = 32;
pub const XML_PARSE_NOWARNING: C2RustUnnamed_3 = 64;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed_3 = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed_3 = 128;
pub const XML_PARSE_RECOVER: C2RustUnnamed_3 = 1;
pub const HTML_PARSE_NOIMPLIED: C2RustUnnamed_4 = 8192;
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
pub type C2RustUnnamed_3 = libc::c_uint;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed_3 = 32768;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed_3 = 1024;
pub type xmlFeature = libc::c_uint;
pub const XML_WITH_NONE: xmlFeature = 99999;
pub const XML_WITH_LZMA: xmlFeature = 33;
pub const XML_WITH_ICU: xmlFeature = 32;
pub const XML_WITH_ZLIB: xmlFeature = 31;
pub const XML_WITH_DEBUG_RUN: xmlFeature = 30;
pub const XML_WITH_DEBUG_MEM: xmlFeature = 29;
pub const XML_WITH_DEBUG: xmlFeature = 28;
pub const XML_WITH_MODULES: xmlFeature = 27;
pub const XML_WITH_SCHEMATRON: xmlFeature = 26;
pub const XML_WITH_SCHEMAS: xmlFeature = 25;
pub const XML_WITH_EXPR: xmlFeature = 24;
pub const XML_WITH_AUTOMATA: xmlFeature = 23;
pub const XML_WITH_REGEXP: xmlFeature = 22;
pub const XML_WITH_UNICODE: xmlFeature = 21;
pub const XML_WITH_ISO8859X: xmlFeature = 20;
pub const XML_WITH_ICONV: xmlFeature = 19;
pub const XML_WITH_XINCLUDE: xmlFeature = 18;
pub const XML_WITH_XPTR: xmlFeature = 17;
pub const XML_WITH_XPATH: xmlFeature = 16;
pub const XML_WITH_CATALOG: xmlFeature = 15;
pub const XML_WITH_C14N: xmlFeature = 14;
pub const XML_WITH_LEGACY: xmlFeature = 13;
pub const XML_WITH_HTML: xmlFeature = 12;
pub const XML_WITH_VALID: xmlFeature = 11;
pub const XML_WITH_HTTP: xmlFeature = 10;
pub const XML_WITH_FTP: xmlFeature = 9;
pub const XML_WITH_SAX1: xmlFeature = 8;
pub const XML_WITH_WRITER: xmlFeature = 7;
pub const XML_WITH_PATTERN: xmlFeature = 6;
pub const XML_WITH_READER: xmlFeature = 5;
pub const XML_WITH_PUSH: xmlFeature = 4;
pub const XML_WITH_OUTPUT: xmlFeature = 3;
pub const XML_WITH_TREE: xmlFeature = 2;
pub const XML_WITH_THREAD: xmlFeature = 1;
pub type C2RustUnnamed_4 = libc::c_uint;
pub const HTML_PARSE_IGNORE_ENC: C2RustUnnamed_4 = 2097152;
pub const HTML_PARSE_COMPACT: C2RustUnnamed_4 = 65536;
pub const HTML_PARSE_NONET: C2RustUnnamed_4 = 2048;
pub const HTML_PARSE_NOBLANKS: C2RustUnnamed_4 = 256;
pub const HTML_PARSE_PEDANTIC: C2RustUnnamed_4 = 128;
pub const HTML_PARSE_NOWARNING: C2RustUnnamed_4 = 64;
pub const HTML_PARSE_NOERROR: C2RustUnnamed_4 = 32;
pub const HTML_PARSE_NODEFDTD: C2RustUnnamed_4 = 4;
pub const HTML_PARSE_RECOVER: C2RustUnnamed_4 = 1;
unsafe extern "C" fn xmlParserEntityCheck(
    mut ctxt: xmlParserCtxtPtr,
    mut size: size_t,
    mut ent: xmlEntityPtr,
    mut replacement: size_t,
) -> libc::c_int {
    let mut consumed: size_t = 0 as libc::c_int as size_t;
    let mut i: libc::c_int = 0;
    if ctxt.is_null() || (*ctxt).options & XML_PARSE_HUGE as libc::c_int != 0 {
        return 0 as libc::c_int;
    }
    if (*ctxt).lastError.code == XML_ERR_ENTITY_LOOP as libc::c_int {
        return 1 as libc::c_int;
    }
    if !ent.is_null()
        && (*ent).etype as libc::c_uint
            != XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int as libc::c_uint
        && !((*ent).content).is_null() && (*ent).checked == 0 as libc::c_int
        && (*ctxt).errNo != XML_ERR_ENTITY_LOOP as libc::c_int
    {
        let mut oldnbent: libc::c_ulong = (*ctxt).nbentities;
        let mut diff: libc::c_ulong = 0;
        let mut rep: *mut xmlChar = 0 as *mut xmlChar;
        (*ent).checked = 1 as libc::c_int;
        let ref mut fresh0 = (*ctxt).depth;
        *fresh0 += 1;
        rep = xmlStringDecodeEntities(
            ctxt,
            (*ent).content,
            1 as libc::c_int,
            0 as libc::c_int as xmlChar,
            0 as libc::c_int as xmlChar,
            0 as libc::c_int as xmlChar,
        );
        let ref mut fresh1 = (*ctxt).depth;
        *fresh1 -= 1;
        if rep.is_null() || (*ctxt).errNo == XML_ERR_ENTITY_LOOP as libc::c_int {
            *((*ent).content)
                .offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
        }
        diff = ((*ctxt).nbentities)
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as libc::c_int as libc::c_ulong);
        if diff > (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_ulong {
            diff = (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_ulong;
        }
        (*ent)
            .checked = diff.wrapping_mul(2 as libc::c_int as libc::c_ulong)
            as libc::c_int;
        if !rep.is_null() {
            if !(xmlStrchr(rep, '<' as i32 as xmlChar)).is_null() {
                (*ent).checked |= 1 as libc::c_int;
            }
            xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
            rep = 0 as *mut xmlChar;
        }
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_DTD as libc::c_int
        && (*ctxt).nbentities > 10000 as libc::c_int as libc::c_ulong
        && ((*ctxt).nbentities).wrapping_rem(1024 as libc::c_int as libc::c_ulong)
            == 0 as libc::c_int as libc::c_ulong
    {
        i = 0 as libc::c_int;
        while i < (*ctxt).inputNr {
            consumed = (consumed as libc::c_ulong)
                .wrapping_add(
                    ((**((*ctxt).inputTab).offset(i as isize)).consumed)
                        .wrapping_add(
                            ((**((*ctxt).inputTab).offset(i as isize)).cur)
                                .offset_from((**((*ctxt).inputTab).offset(i as isize)).base)
                                as libc::c_long as libc::c_ulong,
                        ),
                ) as size_t as size_t;
            i += 1;
        }
        if (*ctxt).nbentities > consumed.wrapping_mul(10 as libc::c_int as libc::c_ulong)
        {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
            (*ctxt).instate = XML_PARSER_EOF;
            return 1 as libc::c_int;
        }
        consumed = 0 as libc::c_int as size_t;
    }
    if replacement != 0 as libc::c_int as libc::c_ulong {
        if replacement < 10000000 as libc::c_int as libc::c_ulong {
            return 0 as libc::c_int;
        }
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
        }
        consumed = (consumed as libc::c_ulong).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if replacement < (10 as libc::c_int as libc::c_ulong).wrapping_mul(consumed) {
            return 0 as libc::c_int;
        }
    } else if size != 0 as libc::c_int as libc::c_ulong {
        if size < 1000 as libc::c_int as libc::c_ulong {
            return 0 as libc::c_int;
        }
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
        }
        consumed = (consumed as libc::c_ulong).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if size < (10 as libc::c_int as libc::c_ulong).wrapping_mul(consumed)
            && ((*ctxt).nbentities).wrapping_mul(3 as libc::c_int as libc::c_ulong)
                < (10 as libc::c_int as libc::c_ulong).wrapping_mul(consumed)
        {
            return 0 as libc::c_int;
        }
    } else if !ent.is_null() {
        size = ((*ent).checked / 2 as libc::c_int) as size_t;
        if !((*ctxt).input).is_null() {
            consumed = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
        }
        consumed = (consumed as libc::c_ulong).wrapping_add((*ctxt).sizeentities)
            as size_t as size_t;
        if size.wrapping_mul(3 as libc::c_int as libc::c_ulong)
            < consumed.wrapping_mul(10 as libc::c_int as libc::c_ulong)
        {
            return 0 as libc::c_int;
        }
    } else if (*ctxt).lastError.code != XML_ERR_UNDECLARED_ENTITY as libc::c_int
            && (*ctxt).lastError.code != XML_WAR_UNDECLARED_ENTITY as libc::c_int
            || (*ctxt).nbentities <= 10000 as libc::c_int as libc::c_ulong
        {
        return 0 as libc::c_int
    }
    xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
    return 1 as libc::c_int;
}
#[no_mangle]
pub static mut xmlParserMaxDepth: libc::c_uint = 256 as libc::c_int as libc::c_uint;
static mut xmlW3CPIs: [*const libc::c_char; 3] = [
    b"xml-stylesheet\0" as *const u8 as *const libc::c_char,
    b"xml-model\0" as *const u8 as *const libc::c_char,
    0 as *const libc::c_char,
];
unsafe extern "C" fn xmlErrAttributeDup(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
    mut localname: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = XML_ERR_ATTRIBUTE_REDEFINED as libc::c_int;
    }
    if prefix.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            XML_ERR_ATTRIBUTE_REDEFINED as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            localname as *const libc::c_char,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"Attribute %s redefined\n\0" as *const u8 as *const libc::c_char,
            localname,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            XML_ERR_ATTRIBUTE_REDEFINED as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            prefix as *const libc::c_char,
            localname as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"Attribute %s:%s redefined\n\0" as *const u8 as *const libc::c_char,
            prefix,
            localname,
        );
    }
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlFatalErr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut info: *const libc::c_char,
) {
    let mut errmsg: *const libc::c_char = 0 as *const libc::c_char;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    match error as libc::c_uint {
        6 => {
            errmsg = b"CharRef: invalid hexadecimal value\0" as *const u8
                as *const libc::c_char;
        }
        7 => {
            errmsg = b"CharRef: invalid decimal value\0" as *const u8
                as *const libc::c_char;
        }
        8 => {
            errmsg = b"CharRef: invalid value\0" as *const u8 as *const libc::c_char;
        }
        1 => {
            errmsg = b"internal error\0" as *const u8 as *const libc::c_char;
        }
        18 => {
            errmsg = b"PEReference at end of document\0" as *const u8
                as *const libc::c_char;
        }
        19 => {
            errmsg = b"PEReference in prolog\0" as *const u8 as *const libc::c_char;
        }
        20 => {
            errmsg = b"PEReference in epilog\0" as *const u8 as *const libc::c_char;
        }
        24 => {
            errmsg = b"PEReference: no name\0" as *const u8 as *const libc::c_char;
        }
        25 => {
            errmsg = b"PEReference: expecting ';'\0" as *const u8 as *const libc::c_char;
        }
        89 => {
            errmsg = b"Detected an entity reference loop\0" as *const u8
                as *const libc::c_char;
        }
        36 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8
                as *const libc::c_char;
        }
        88 => {
            errmsg = b"PEReferences forbidden in internal subset\0" as *const u8
                as *const libc::c_char;
        }
        37 => {
            errmsg = b"EntityValue: \" or ' expected\0" as *const u8
                as *const libc::c_char;
        }
        39 => {
            errmsg = b"AttValue: \" or ' expected\0" as *const u8 as *const libc::c_char;
        }
        38 => {
            errmsg = b"Unescaped '<' not allowed in attributes values\0" as *const u8
                as *const libc::c_char;
        }
        43 => {
            errmsg = b"SystemLiteral \" or ' expected\0" as *const u8
                as *const libc::c_char;
        }
        44 => {
            errmsg = b"Unfinished System or Public ID \" or ' expected\0" as *const u8
                as *const libc::c_char;
        }
        62 => {
            errmsg = b"Sequence ']]>' not allowed in content\0" as *const u8
                as *const libc::c_char;
        }
        70 => {
            errmsg = b"SYSTEM or PUBLIC, the URI is missing\0" as *const u8
                as *const libc::c_char;
        }
        71 => {
            errmsg = b"PUBLIC, the Public Identifier is missing\0" as *const u8
                as *const libc::c_char;
        }
        80 => {
            errmsg = b"Comment must not contain '--' (double-hyphen)\0" as *const u8
                as *const libc::c_char;
        }
        46 => {
            errmsg = b"xmlParsePI : no target name\0" as *const u8
                as *const libc::c_char;
        }
        64 => {
            errmsg = b"Invalid PI name\0" as *const u8 as *const libc::c_char;
        }
        48 => {
            errmsg = b"NOTATION: Name expected here\0" as *const u8
                as *const libc::c_char;
        }
        49 => {
            errmsg = b"'>' required to close NOTATION declaration\0" as *const u8
                as *const libc::c_char;
        }
        84 => {
            errmsg = b"Entity value required\0" as *const u8 as *const libc::c_char;
        }
        92 => {
            errmsg = b"Fragment not allowed\0" as *const u8 as *const libc::c_char;
        }
        50 => {
            errmsg = b"'(' required to start ATTLIST enumeration\0" as *const u8
                as *const libc::c_char;
        }
        67 => {
            errmsg = b"NmToken expected in ATTLIST enumeration\0" as *const u8
                as *const libc::c_char;
        }
        51 => {
            errmsg = b"')' required to finish ATTLIST enumeration\0" as *const u8
                as *const libc::c_char;
        }
        52 => {
            errmsg = b"MixedContentDecl : '|' or ')*' expected\0" as *const u8
                as *const libc::c_char;
        }
        69 => {
            errmsg = b"MixedContentDecl : '#PCDATA' expected\0" as *const u8
                as *const libc::c_char;
        }
        54 => {
            errmsg = b"ContentDecl : Name or '(' expected\0" as *const u8
                as *const libc::c_char;
        }
        55 => {
            errmsg = b"ContentDecl : ',' '|' or ')' expected\0" as *const u8
                as *const libc::c_char;
        }
        21 => {
            errmsg = b"PEReference: forbidden within markup decl in internal subset\0"
                as *const u8 as *const libc::c_char;
        }
        73 => {
            errmsg = b"expected '>'\0" as *const u8 as *const libc::c_char;
        }
        83 => {
            errmsg = b"XML conditional section '[' expected\0" as *const u8
                as *const libc::c_char;
        }
        60 => {
            errmsg = b"Content error in the external subset\0" as *const u8
                as *const libc::c_char;
        }
        95 => {
            errmsg = b"conditional section INCLUDE or IGNORE keyword expected\0"
                as *const u8 as *const libc::c_char;
        }
        59 => {
            errmsg = b"XML conditional section not closed\0" as *const u8
                as *const libc::c_char;
        }
        56 => {
            errmsg = b"Text declaration '<?xml' required\0" as *const u8
                as *const libc::c_char;
        }
        57 => {
            errmsg = b"parsing XML declaration: '?>' expected\0" as *const u8
                as *const libc::c_char;
        }
        82 => {
            errmsg = b"external parsed entities cannot be standalone\0" as *const u8
                as *const libc::c_char;
        }
        23 => {
            errmsg = b"EntityRef: expecting ';'\0" as *const u8 as *const libc::c_char;
        }
        61 => {
            errmsg = b"DOCTYPE improperly terminated\0" as *const u8
                as *const libc::c_char;
        }
        74 => {
            errmsg = b"EndTag: '</' not found\0" as *const u8 as *const libc::c_char;
        }
        75 => {
            errmsg = b"expected '='\0" as *const u8 as *const libc::c_char;
        }
        34 => {
            errmsg = b"String not closed expecting \" or '\0" as *const u8
                as *const libc::c_char;
        }
        33 => {
            errmsg = b"String not started expecting ' or \"\0" as *const u8
                as *const libc::c_char;
        }
        79 => {
            errmsg = b"Invalid XML encoding name\0" as *const u8 as *const libc::c_char;
        }
        78 => {
            errmsg = b"standalone accepts only 'yes' or 'no'\0" as *const u8
                as *const libc::c_char;
        }
        4 => {
            errmsg = b"Document is empty\0" as *const u8 as *const libc::c_char;
        }
        5 => {
            errmsg = b"Extra content at the end of the document\0" as *const u8
                as *const libc::c_char;
        }
        85 => {
            errmsg = b"chunk is not well balanced\0" as *const u8 as *const libc::c_char;
        }
        86 => {
            errmsg = b"extra content at the end of well balanced chunk\0" as *const u8
                as *const libc::c_char;
        }
        96 => {
            errmsg = b"Malformed declaration expecting version\0" as *const u8
                as *const libc::c_char;
        }
        110 => {
            errmsg = b"Name too long use XML_PARSE_HUGE option\0" as *const u8
                as *const libc::c_char;
        }
        _ => {
            errmsg = b"Unregistered error message\0" as *const u8 as *const libc::c_char;
        }
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    if info.is_null() {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            info,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"%s\n\0" as *const u8 as *const libc::c_char,
            errmsg,
        );
    } else {
        __xmlRaiseError(
            None,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            error as libc::c_int,
            XML_ERR_FATAL,
            0 as *const libc::c_char,
            0 as libc::c_int,
            info,
            0 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            b"%s: %s\n\0" as *const u8 as *const libc::c_char,
            errmsg,
            info,
        );
    }
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as libc::c_int,
        error as libc::c_int,
        XML_ERR_FATAL,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        b"%s\0" as *const u8 as *const libc::c_char,
        msg,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlWarningMsg(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() && !((*ctxt).sax).is_null()
        && (*(*ctxt).sax).initialized == 0xdeedbeaf as libc::c_uint
    {
        schannel = (*(*ctxt).sax).serror;
    }
    if !ctxt.is_null() {
        __xmlRaiseError(
            schannel,
            if !((*ctxt).sax).is_null() { (*(*ctxt).sax).warning } else { None },
            (*ctxt).userData,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            error as libc::c_int,
            XML_ERR_WARNING,
            0 as *const libc::c_char,
            0 as libc::c_int,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            msg,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
        );
    } else {
        __xmlRaiseError(
            schannel,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_PARSER as libc::c_int,
            error as libc::c_int,
            XML_ERR_WARNING,
            0 as *const libc::c_char,
            0 as libc::c_int,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            msg,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
        );
    };
}
unsafe extern "C" fn xmlValidityError(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut str2: *const xmlChar,
) {
    let mut schannel: xmlStructuredErrorFunc = None;
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
        if !((*ctxt).sax).is_null()
            && (*(*ctxt).sax).initialized == 0xdeedbeaf as libc::c_uint
        {
            schannel = (*(*ctxt).sax).serror;
        }
    }
    if !ctxt.is_null() {
        __xmlRaiseError(
            schannel,
            (*ctxt).vctxt.error,
            (*ctxt).vctxt.userData,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_DTD as libc::c_int,
            error as libc::c_int,
            XML_ERR_ERROR,
            0 as *const libc::c_char,
            0 as libc::c_int,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            msg,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
        );
        (*ctxt).valid = 0 as libc::c_int;
    } else {
        __xmlRaiseError(
            schannel,
            None,
            0 as *mut libc::c_void,
            ctxt as *mut libc::c_void,
            0 as *mut libc::c_void,
            XML_FROM_DTD as libc::c_int,
            error as libc::c_int,
            XML_ERR_ERROR,
            0 as *const libc::c_char,
            0 as libc::c_int,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
            0 as *const libc::c_char,
            0 as libc::c_int,
            0 as libc::c_int,
            msg,
            str1 as *const libc::c_char,
            str2 as *const libc::c_char,
        );
    };
}
unsafe extern "C" fn xmlFatalErrMsgInt(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut val: libc::c_int,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as libc::c_int,
        error as libc::c_int,
        XML_ERR_FATAL,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        val,
        0 as libc::c_int,
        msg,
        val,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsgStrIntStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut str1: *const xmlChar,
    mut val: libc::c_int,
    mut str2: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as libc::c_int,
        error as libc::c_int,
        XML_ERR_FATAL,
        0 as *const libc::c_char,
        0 as libc::c_int,
        str1 as *const libc::c_char,
        str2 as *const libc::c_char,
        0 as *const libc::c_char,
        val,
        0 as libc::c_int,
        msg,
        str1,
        val,
        str2,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlFatalErrMsgStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut val: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as libc::c_int,
        error as libc::c_int,
        XML_ERR_FATAL,
        0 as *const libc::c_char,
        0 as libc::c_int,
        val as *const libc::c_char,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        val,
    );
    if !ctxt.is_null() {
        (*ctxt).wellFormed = 0 as libc::c_int;
        if (*ctxt).recovery == 0 as libc::c_int {
            (*ctxt).disableSAX = 1 as libc::c_int;
        }
    }
}
unsafe extern "C" fn xmlErrMsgStr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut val: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_PARSER as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        val as *const libc::c_char,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        val,
    );
}
unsafe extern "C" fn xmlNsErr(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut info1: *const xmlChar,
    mut info2: *const xmlChar,
    mut info3: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !ctxt.is_null() {
        (*ctxt).errNo = error as libc::c_int;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_NAMESPACE as libc::c_int,
        error as libc::c_int,
        XML_ERR_ERROR,
        0 as *const libc::c_char,
        0 as libc::c_int,
        info1 as *const libc::c_char,
        info2 as *const libc::c_char,
        info3 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        info1,
        info2,
        info3,
    );
    if !ctxt.is_null() {
        (*ctxt).nsWellFormed = 0 as libc::c_int;
    }
}
unsafe extern "C" fn xmlNsWarn(
    mut ctxt: xmlParserCtxtPtr,
    mut error: xmlParserErrors,
    mut msg: *const libc::c_char,
    mut info1: *const xmlChar,
    mut info2: *const xmlChar,
    mut info3: *const xmlChar,
) {
    if !ctxt.is_null() && (*ctxt).disableSAX != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        ctxt as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_NAMESPACE as libc::c_int,
        error as libc::c_int,
        XML_ERR_WARNING,
        0 as *const libc::c_char,
        0 as libc::c_int,
        info1 as *const libc::c_char,
        info2 as *const libc::c_char,
        info3 as *const libc::c_char,
        0 as libc::c_int,
        0 as libc::c_int,
        msg,
        info1,
        info2,
        info3,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlHasFeature(mut feature: xmlFeature) -> libc::c_int {
    match feature as libc::c_uint {
        1 => return 1 as libc::c_int,
        2 => return 1 as libc::c_int,
        3 => return 1 as libc::c_int,
        4 => return 1 as libc::c_int,
        5 => return 1 as libc::c_int,
        6 => return 1 as libc::c_int,
        7 => return 1 as libc::c_int,
        8 => return 1 as libc::c_int,
        9 => return 1 as libc::c_int,
        10 => return 1 as libc::c_int,
        11 => return 1 as libc::c_int,
        12 => return 1 as libc::c_int,
        13 => return 1 as libc::c_int,
        14 => return 1 as libc::c_int,
        15 => return 1 as libc::c_int,
        16 => return 1 as libc::c_int,
        17 => return 1 as libc::c_int,
        18 => return 1 as libc::c_int,
        19 => return 1 as libc::c_int,
        20 => return 1 as libc::c_int,
        21 => return 1 as libc::c_int,
        22 => return 1 as libc::c_int,
        23 => return 1 as libc::c_int,
        24 => return 0 as libc::c_int,
        25 => return 1 as libc::c_int,
        26 => return 1 as libc::c_int,
        27 => return 1 as libc::c_int,
        28 => return 1 as libc::c_int,
        29 => return 0 as libc::c_int,
        30 => return 0 as libc::c_int,
        31 => return 1 as libc::c_int,
        33 => return 0 as libc::c_int,
        32 => return 0 as libc::c_int,
        _ => {}
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlDetectSAX2(mut ctxt: xmlParserCtxtPtr) {
    let mut sax: xmlSAXHandlerPtr = 0 as *mut xmlSAXHandler;
    if ctxt.is_null() {
        return;
    }
    sax = (*ctxt).sax;
    if !sax.is_null() && (*sax).initialized == 0xdeedbeaf as libc::c_uint
        && (((*sax).startElementNs).is_some() || ((*sax).endElementNs).is_some()
            || ((*sax).startElement).is_none() && ((*sax).endElement).is_none())
    {
        (*ctxt).sax2 = 1 as libc::c_int;
    }
    let ref mut fresh2 = (*ctxt).str_xml;
    *fresh2 = xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        3 as libc::c_int,
    );
    let ref mut fresh3 = (*ctxt).str_xmlns;
    *fresh3 = xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        5 as libc::c_int,
    );
    let ref mut fresh4 = (*ctxt).str_xml_ns;
    *fresh4 = xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
        36 as libc::c_int,
    );
    if ((*ctxt).str_xml).is_null() || ((*ctxt).str_xmlns).is_null()
        || ((*ctxt).str_xml_ns).is_null()
    {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
    }
}
unsafe extern "C" fn xmlAttrNormalizeSpace(
    mut src: *const xmlChar,
    mut dst: *mut xmlChar,
) -> *mut xmlChar {
    if src.is_null() || dst.is_null() {
        return 0 as *mut xmlChar;
    }
    while *src as libc::c_int == 0x20 as libc::c_int {
        src = src.offset(1);
    }
    while *src as libc::c_int != 0 as libc::c_int {
        if *src as libc::c_int == 0x20 as libc::c_int {
            while *src as libc::c_int == 0x20 as libc::c_int {
                src = src.offset(1);
            }
            if *src as libc::c_int != 0 as libc::c_int {
                let fresh5 = dst;
                dst = dst.offset(1);
                *fresh5 = 0x20 as libc::c_int as xmlChar;
            }
        } else {
            let fresh6 = src;
            src = src.offset(1);
            let fresh7 = dst;
            dst = dst.offset(1);
            *fresh7 = *fresh6;
        }
    }
    *dst = 0 as libc::c_int as xmlChar;
    if dst == src as *mut xmlChar {
        return 0 as *mut xmlChar;
    }
    return dst;
}
unsafe extern "C" fn xmlAttrNormalizeSpace2(
    mut ctxt: xmlParserCtxtPtr,
    mut src: *mut xmlChar,
    mut len: *mut libc::c_int,
) -> *const xmlChar {
    let mut i: libc::c_int = 0;
    let mut remove_head: libc::c_int = 0 as libc::c_int;
    let mut need_realloc: libc::c_int = 0 as libc::c_int;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || src.is_null() || len.is_null() {
        return 0 as *const xmlChar;
    }
    i = *len;
    if i <= 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    cur = src;
    while *cur as libc::c_int == 0x20 as libc::c_int {
        cur = cur.offset(1);
        remove_head += 1;
    }
    while *cur as libc::c_int != 0 as libc::c_int {
        if *cur as libc::c_int == 0x20 as libc::c_int {
            cur = cur.offset(1);
            if !(*cur as libc::c_int == 0x20 as libc::c_int
                || *cur as libc::c_int == 0 as libc::c_int)
            {
                continue;
            }
            need_realloc = 1 as libc::c_int;
            break;
        } else {
            cur = cur.offset(1);
        }
    }
    if need_realloc != 0 {
        let mut ret: *mut xmlChar = 0 as *mut xmlChar;
        ret = xmlStrndup(
            src.offset(remove_head as isize),
            i - remove_head + 1 as libc::c_int,
        );
        if ret.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as *const xmlChar;
        }
        xmlAttrNormalizeSpace(ret, ret);
        *len = strlen(ret as *const libc::c_char) as libc::c_int;
        return ret;
    } else {
        if remove_head != 0 {
            *len -= remove_head;
            memmove(
                src as *mut libc::c_void,
                src.offset(remove_head as isize) as *const libc::c_void,
                (1 as libc::c_int + *len) as libc::c_ulong,
            );
            return src;
        }
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlAddDefAttrs(
    mut ctxt: xmlParserCtxtPtr,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut value: *const xmlChar,
) {
    let mut current_block: u64;
    let mut defaults: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
    let mut len: libc::c_int = 0;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    if !((*ctxt).attsSpecial).is_null() {
        if !(xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr)).is_null() {
            return;
        }
    }
    if ((*ctxt).attsDefault).is_null() {
        let ref mut fresh8 = (*ctxt).attsDefault;
        *fresh8 = xmlHashCreateDict(10 as libc::c_int, (*ctxt).dict);
        if ((*ctxt).attsDefault).is_null() {
            current_block = 15121983726504061653;
        } else {
            current_block = 13183875560443969876;
        }
    } else {
        current_block = 13183875560443969876;
    }
    match current_block {
        13183875560443969876 => {
            name = xmlSplitQName3(fullname, &mut len);
            if name.is_null() {
                name = xmlDictLookup((*ctxt).dict, fullname, -(1 as libc::c_int));
                prefix = 0 as *const xmlChar;
            } else {
                name = xmlDictLookup((*ctxt).dict, name, -(1 as libc::c_int));
                prefix = xmlDictLookup((*ctxt).dict, fullname, len);
            }
            defaults = xmlHashLookup2((*ctxt).attsDefault, name, prefix)
                as xmlDefAttrsPtr;
            if defaults.is_null() {
                defaults = xmlMalloc
                    .expect(
                        "non-null function pointer",
                    )(
                    (::std::mem::size_of::<xmlDefAttrs>() as libc::c_ulong)
                        .wrapping_add(
                            ((4 as libc::c_int * 5 as libc::c_int) as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as libc::c_ulong,
                                ),
                        ),
                ) as xmlDefAttrsPtr;
                if defaults.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    (*defaults).nbAttrs = 0 as libc::c_int;
                    (*defaults).maxAttrs = 4 as libc::c_int;
                    if xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) < 0 as libc::c_int
                    {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(defaults as *mut libc::c_void);
                        current_block = 15121983726504061653;
                    } else {
                        current_block = 8704759739624374314;
                    }
                }
            } else if (*defaults).nbAttrs >= (*defaults).maxAttrs {
                let mut temp: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
                temp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    defaults as *mut libc::c_void,
                    (::std::mem::size_of::<xmlDefAttrs>() as libc::c_ulong)
                        .wrapping_add(
                            ((2 as libc::c_int * (*defaults).maxAttrs * 5 as libc::c_int)
                                as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as libc::c_ulong,
                                ),
                        ),
                ) as xmlDefAttrsPtr;
                if temp.is_null() {
                    current_block = 15121983726504061653;
                } else {
                    defaults = temp;
                    (*defaults).maxAttrs *= 2 as libc::c_int;
                    if xmlHashUpdateEntry2(
                        (*ctxt).attsDefault,
                        name,
                        prefix,
                        defaults as *mut libc::c_void,
                        None,
                    ) < 0 as libc::c_int
                    {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(defaults as *mut libc::c_void);
                        current_block = 15121983726504061653;
                    } else {
                        current_block = 8704759739624374314;
                    }
                }
            } else {
                current_block = 8704759739624374314;
            }
            match current_block {
                15121983726504061653 => {}
                _ => {
                    name = xmlSplitQName3(fullattr, &mut len);
                    if name.is_null() {
                        name = xmlDictLookup(
                            (*ctxt).dict,
                            fullattr,
                            -(1 as libc::c_int),
                        );
                        prefix = 0 as *const xmlChar;
                    } else {
                        name = xmlDictLookup((*ctxt).dict, name, -(1 as libc::c_int));
                        prefix = xmlDictLookup((*ctxt).dict, fullattr, len);
                    }
                    let ref mut fresh9 = *((*defaults).values)
                        .as_mut_ptr()
                        .offset((5 as libc::c_int * (*defaults).nbAttrs) as isize);
                    *fresh9 = name;
                    let ref mut fresh10 = *((*defaults).values)
                        .as_mut_ptr()
                        .offset(
                            (5 as libc::c_int * (*defaults).nbAttrs + 1 as libc::c_int)
                                as isize,
                        );
                    *fresh10 = prefix;
                    len = xmlStrlen(value);
                    value = xmlDictLookup((*ctxt).dict, value, len);
                    let ref mut fresh11 = *((*defaults).values)
                        .as_mut_ptr()
                        .offset(
                            (5 as libc::c_int * (*defaults).nbAttrs + 2 as libc::c_int)
                                as isize,
                        );
                    *fresh11 = value;
                    let ref mut fresh12 = *((*defaults).values)
                        .as_mut_ptr()
                        .offset(
                            (5 as libc::c_int * (*defaults).nbAttrs + 3 as libc::c_int)
                                as isize,
                        );
                    *fresh12 = value.offset(len as isize);
                    if (*ctxt).external != 0 {
                        let ref mut fresh13 = *((*defaults).values)
                            .as_mut_ptr()
                            .offset(
                                (5 as libc::c_int * (*defaults).nbAttrs + 4 as libc::c_int)
                                    as isize,
                            );
                        *fresh13 = b"external\0" as *const u8 as *const libc::c_char
                            as *mut xmlChar;
                    } else {
                        let ref mut fresh14 = *((*defaults).values)
                            .as_mut_ptr()
                            .offset(
                                (5 as libc::c_int * (*defaults).nbAttrs + 4 as libc::c_int)
                                    as isize,
                            );
                        *fresh14 = 0 as *const xmlChar;
                    }
                    let ref mut fresh15 = (*defaults).nbAttrs;
                    *fresh15 += 1;
                    return;
                }
            }
        }
        _ => {}
    }
    xmlErrMemory(ctxt, 0 as *const libc::c_char);
}
unsafe extern "C" fn xmlAddSpecialAttr(
    mut ctxt: xmlParserCtxtPtr,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut type_0: libc::c_int,
) {
    if ((*ctxt).attsSpecial).is_null() {
        let ref mut fresh16 = (*ctxt).attsSpecial;
        *fresh16 = xmlHashCreateDict(10 as libc::c_int, (*ctxt).dict);
        if ((*ctxt).attsSpecial).is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return;
        }
    }
    if !(xmlHashLookup2((*ctxt).attsSpecial, fullname, fullattr)).is_null() {
        return;
    }
    xmlHashAddEntry2(
        (*ctxt).attsSpecial,
        fullname,
        fullattr,
        type_0 as ptrdiff_t as *mut libc::c_void,
    );
}
unsafe extern "C" fn xmlCleanSpecialAttrCallback(
    mut payload: *mut libc::c_void,
    mut data: *mut libc::c_void,
    mut fullname: *const xmlChar,
    mut fullattr: *const xmlChar,
    mut unused: *const xmlChar,
) {
    let mut ctxt: xmlParserCtxtPtr = data as xmlParserCtxtPtr;
    if payload as ptrdiff_t == XML_ATTRIBUTE_CDATA as libc::c_int as libc::c_long {
        xmlHashRemoveEntry2((*ctxt).attsSpecial, fullname, fullattr, None);
    }
}
unsafe extern "C" fn xmlCleanSpecialAttr(mut ctxt: xmlParserCtxtPtr) {
    if ((*ctxt).attsSpecial).is_null() {
        return;
    }
    xmlHashScanFull(
        (*ctxt).attsSpecial,
        Some(
            xmlCleanSpecialAttrCallback
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                    *const xmlChar,
                ) -> (),
        ),
        ctxt as *mut libc::c_void,
    );
    if xmlHashSize((*ctxt).attsSpecial) == 0 as libc::c_int {
        xmlHashFree((*ctxt).attsSpecial, None);
        let ref mut fresh17 = (*ctxt).attsSpecial;
        *fresh17 = 0 as xmlHashTablePtr;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCheckLanguageID(mut lang: *const xmlChar) -> libc::c_int {
    let mut current_block: u64;
    let mut cur: *const xmlChar = lang;
    let mut nxt: *const xmlChar = 0 as *const xmlChar;
    if cur.is_null() {
        return 0 as libc::c_int;
    }
    if *cur.offset(0 as libc::c_int as isize) as libc::c_int == 'i' as i32
        && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '-' as i32
        || *cur.offset(0 as libc::c_int as isize) as libc::c_int == 'I' as i32
            && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '-' as i32
        || *cur.offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
            && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '-' as i32
        || *cur.offset(0 as libc::c_int as isize) as libc::c_int == 'X' as i32
            && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '-' as i32
    {
        cur = cur.offset(2 as libc::c_int as isize);
        while *cur.offset(0 as libc::c_int as isize) as libc::c_int >= 'A' as i32
            && *cur.offset(0 as libc::c_int as isize) as libc::c_int <= 'Z' as i32
            || *cur.offset(0 as libc::c_int as isize) as libc::c_int >= 'a' as i32
                && *cur.offset(0 as libc::c_int as isize) as libc::c_int <= 'z' as i32
        {
            cur = cur.offset(1);
        }
        return (*cur.offset(0 as libc::c_int as isize) as libc::c_int
            == 0 as libc::c_int) as libc::c_int;
    }
    nxt = cur;
    while *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'A' as i32
        && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= 'Z' as i32
        || *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'a' as i32
            && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= 'z' as i32
    {
        nxt = nxt.offset(1);
    }
    if nxt.offset_from(cur) as libc::c_long >= 4 as libc::c_int as libc::c_long {
        if nxt.offset_from(cur) as libc::c_long > 8 as libc::c_int as libc::c_long
            || *nxt.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        return 1 as libc::c_int;
    }
    if (nxt.offset_from(cur) as libc::c_long) < 2 as libc::c_int as libc::c_long {
        return 0 as libc::c_int;
    }
    if *nxt.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if *nxt.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
        return 0 as libc::c_int;
    }
    nxt = nxt.offset(1);
    cur = nxt;
    if *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= '0' as i32
        && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= '9' as i32
    {
        current_block = 16811467638080314455;
    } else {
        while *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'A' as i32
            && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= 'Z' as i32
            || *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'a' as i32
                && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= 'z' as i32
        {
            nxt = nxt.offset(1);
        }
        if nxt.offset_from(cur) as libc::c_long == 4 as libc::c_int as libc::c_long {
            current_block = 9144990194416275176;
        } else if nxt.offset_from(cur) as libc::c_long
                == 2 as libc::c_int as libc::c_long
            {
            current_block = 8704481894642172821;
        } else if nxt.offset_from(cur) as libc::c_long
                >= 5 as libc::c_int as libc::c_long
                && nxt.offset_from(cur) as libc::c_long
                    <= 8 as libc::c_int as libc::c_long
            {
            current_block = 9213009941721548937;
        } else {
            if nxt.offset_from(cur) as libc::c_long != 3 as libc::c_int as libc::c_long {
                return 0 as libc::c_int;
            }
            if *nxt.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
            {
                return 1 as libc::c_int;
            }
            if *nxt.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
                return 0 as libc::c_int;
            }
            nxt = nxt.offset(1);
            cur = nxt;
            if *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= '0' as i32
                && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= '9' as i32
            {
                current_block = 16811467638080314455;
            } else {
                while *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'A' as i32
                    && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                        <= 'Z' as i32
                    || *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                        >= 'a' as i32
                        && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                            <= 'z' as i32
                {
                    nxt = nxt.offset(1);
                }
                if nxt.offset_from(cur) as libc::c_long
                    == 2 as libc::c_int as libc::c_long
                {
                    current_block = 8704481894642172821;
                } else if nxt.offset_from(cur) as libc::c_long
                        >= 5 as libc::c_int as libc::c_long
                        && nxt.offset_from(cur) as libc::c_long
                            <= 8 as libc::c_int as libc::c_long
                    {
                    current_block = 9213009941721548937;
                } else {
                    if nxt.offset_from(cur) as libc::c_long
                        != 4 as libc::c_int as libc::c_long
                    {
                        return 0 as libc::c_int;
                    }
                    current_block = 9144990194416275176;
                }
            }
        }
        match current_block {
            8704481894642172821 => {}
            9213009941721548937 => {}
            16811467638080314455 => {}
            _ => {
                if *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                    == 0 as libc::c_int
                {
                    return 1 as libc::c_int;
                }
                if *nxt.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
                    return 0 as libc::c_int;
                }
                nxt = nxt.offset(1);
                cur = nxt;
                if *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= '0' as i32
                    && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                        <= '9' as i32
                {
                    current_block = 16811467638080314455;
                } else {
                    while *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                        >= 'A' as i32
                        && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                            <= 'Z' as i32
                        || *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                            >= 'a' as i32
                            && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                                <= 'z' as i32
                    {
                        nxt = nxt.offset(1);
                    }
                    if nxt.offset_from(cur) as libc::c_long
                        >= 5 as libc::c_int as libc::c_long
                        && nxt.offset_from(cur) as libc::c_long
                            <= 8 as libc::c_int as libc::c_long
                    {
                        current_block = 9213009941721548937;
                    } else {
                        if nxt.offset_from(cur) as libc::c_long
                            != 2 as libc::c_int as libc::c_long
                        {
                            return 0 as libc::c_int;
                        }
                        current_block = 8704481894642172821;
                    }
                }
            }
        }
    }
    match current_block {
        16811467638080314455 => {
            if *nxt.offset(1 as libc::c_int as isize) as libc::c_int >= '0' as i32
                && *nxt.offset(1 as libc::c_int as isize) as libc::c_int <= '9' as i32
                && (*nxt.offset(2 as libc::c_int as isize) as libc::c_int >= '0' as i32
                    && *nxt.offset(2 as libc::c_int as isize) as libc::c_int
                        <= '9' as i32)
            {
                nxt = nxt.offset(3 as libc::c_int as isize);
            } else {
                return 0 as libc::c_int
            }
            current_block = 8704481894642172821;
        }
        _ => {}
    }
    match current_block {
        8704481894642172821 => {
            if *nxt.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
            {
                return 1 as libc::c_int;
            }
            if *nxt.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
                return 0 as libc::c_int;
            }
            nxt = nxt.offset(1);
            cur = nxt;
            while *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'A' as i32
                && *nxt.offset(0 as libc::c_int as isize) as libc::c_int <= 'Z' as i32
                || *nxt.offset(0 as libc::c_int as isize) as libc::c_int >= 'a' as i32
                    && *nxt.offset(0 as libc::c_int as isize) as libc::c_int
                        <= 'z' as i32
            {
                nxt = nxt.offset(1);
            }
            if (nxt.offset_from(cur) as libc::c_long) < 5 as libc::c_int as libc::c_long
                || nxt.offset_from(cur) as libc::c_long
                    > 8 as libc::c_int as libc::c_long
            {
                return 0 as libc::c_int;
            }
        }
        _ => {}
    }
    if *nxt.offset(0 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if *nxt.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn nsPush(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
    mut URL: *const xmlChar,
) -> libc::c_int {
    if (*ctxt).options & XML_PARSE_NSCLEAN as libc::c_int != 0 {
        let mut i: libc::c_int = 0;
        i = (*ctxt).nsNr - 2 as libc::c_int;
        while i >= 0 as libc::c_int {
            if *((*ctxt).nsTab).offset(i as isize) == prefix {
                if *((*ctxt).nsTab).offset((i + 1 as libc::c_int) as isize) == URL {
                    return -(2 as libc::c_int);
                }
                break;
            } else {
                i -= 2 as libc::c_int;
            }
        }
    }
    if (*ctxt).nsMax == 0 as libc::c_int || ((*ctxt).nsTab).is_null() {
        (*ctxt).nsMax = 10 as libc::c_int;
        (*ctxt).nsNr = 0 as libc::c_int;
        let ref mut fresh18 = (*ctxt).nsTab;
        *fresh18 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).nsMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if ((*ctxt).nsTab).is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            (*ctxt).nsMax = 0 as libc::c_int;
            return -(1 as libc::c_int);
        }
    } else if (*ctxt).nsNr >= (*ctxt).nsMax {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        (*ctxt).nsMax *= 2 as libc::c_int;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nsTab as *mut libc::c_char as *mut libc::c_void,
            ((*ctxt).nsMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            (*ctxt).nsMax /= 2 as libc::c_int;
            return -(1 as libc::c_int);
        }
        let ref mut fresh19 = (*ctxt).nsTab;
        *fresh19 = tmp;
    }
    let ref mut fresh20 = (*ctxt).nsNr;
    let fresh21 = *fresh20;
    *fresh20 = *fresh20 + 1;
    let ref mut fresh22 = *((*ctxt).nsTab).offset(fresh21 as isize);
    *fresh22 = prefix;
    let ref mut fresh23 = (*ctxt).nsNr;
    let fresh24 = *fresh23;
    *fresh23 = *fresh23 + 1;
    let ref mut fresh25 = *((*ctxt).nsTab).offset(fresh24 as isize);
    *fresh25 = URL;
    return (*ctxt).nsNr;
}
unsafe extern "C" fn nsPop(
    mut ctxt: xmlParserCtxtPtr,
    mut nr: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if ((*ctxt).nsTab).is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).nsNr < nr {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Pbm popping %d NS\n\0" as *const u8 as *const libc::c_char,
            nr,
        );
        nr = (*ctxt).nsNr;
    }
    if (*ctxt).nsNr <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < nr {
        let ref mut fresh26 = (*ctxt).nsNr;
        *fresh26 -= 1;
        let ref mut fresh27 = *((*ctxt).nsTab).offset((*ctxt).nsNr as isize);
        *fresh27 = 0 as *const xmlChar;
        i += 1;
    }
    return nr;
}
unsafe extern "C" fn xmlCtxtGrowAttrs(
    mut ctxt: xmlParserCtxtPtr,
    mut nr: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut atts: *mut *const xmlChar = 0 as *mut *const xmlChar;
    let mut attallocs: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut maxatts: libc::c_int = 0;
    if ((*ctxt).atts).is_null() {
        maxatts = 55 as libc::c_int;
        atts = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (maxatts as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let ref mut fresh28 = (*ctxt).atts;
            *fresh28 = atts;
            attallocs = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(
                ((maxatts / 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<libc::c_int>() as libc::c_ulong),
            ) as *mut libc::c_int;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let ref mut fresh29 = (*ctxt).attallocs;
                *fresh29 = attallocs;
                (*ctxt).maxatts = maxatts;
                current_block = 13242334135786603907;
            }
        }
    } else if nr + 5 as libc::c_int > (*ctxt).maxatts {
        maxatts = (nr + 5 as libc::c_int) * 2 as libc::c_int;
        atts = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).atts as *mut libc::c_void,
            (maxatts as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if atts.is_null() {
            current_block = 15593660875440590097;
        } else {
            let ref mut fresh30 = (*ctxt).atts;
            *fresh30 = atts;
            attallocs = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).attallocs as *mut libc::c_void,
                ((maxatts / 5 as libc::c_int) as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<libc::c_int>() as libc::c_ulong),
            ) as *mut libc::c_int;
            if attallocs.is_null() {
                current_block = 15593660875440590097;
            } else {
                let ref mut fresh31 = (*ctxt).attallocs;
                *fresh31 = attallocs;
                (*ctxt).maxatts = maxatts;
                current_block = 13242334135786603907;
            }
        }
    } else {
        current_block = 13242334135786603907;
    }
    match current_block {
        13242334135786603907 => return (*ctxt).maxatts,
        _ => {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn inputPush(
    mut ctxt: xmlParserCtxtPtr,
    mut value: xmlParserInputPtr,
) -> libc::c_int {
    if ctxt.is_null() || value.is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctxt).inputNr >= (*ctxt).inputMax {
        (*ctxt).inputMax *= 2 as libc::c_int;
        let ref mut fresh32 = (*ctxt).inputTab;
        *fresh32 = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).inputTab as *mut libc::c_void,
            ((*ctxt).inputMax as libc::c_ulong)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlParserInputPtr>() as libc::c_ulong,
                ),
        ) as *mut xmlParserInputPtr;
        if ((*ctxt).inputTab).is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            (*ctxt).inputMax /= 2 as libc::c_int;
            return -(1 as libc::c_int);
        }
    }
    let ref mut fresh33 = *((*ctxt).inputTab).offset((*ctxt).inputNr as isize);
    *fresh33 = value;
    let ref mut fresh34 = (*ctxt).input;
    *fresh34 = value;
    let ref mut fresh35 = (*ctxt).inputNr;
    let fresh36 = *fresh35;
    *fresh35 = *fresh35 + 1;
    return fresh36;
}
#[no_mangle]
pub unsafe extern "C" fn inputPop(mut ctxt: xmlParserCtxtPtr) -> xmlParserInputPtr {
    let mut ret: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlParserInputPtr;
    }
    if (*ctxt).inputNr <= 0 as libc::c_int {
        return 0 as xmlParserInputPtr;
    }
    let ref mut fresh37 = (*ctxt).inputNr;
    *fresh37 -= 1;
    if (*ctxt).inputNr > 0 as libc::c_int {
        let ref mut fresh38 = (*ctxt).input;
        *fresh38 = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh39 = (*ctxt).input;
        *fresh39 = 0 as xmlParserInputPtr;
    }
    ret = *((*ctxt).inputTab).offset((*ctxt).inputNr as isize);
    let ref mut fresh40 = *((*ctxt).inputTab).offset((*ctxt).inputNr as isize);
    *fresh40 = 0 as xmlParserInputPtr;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn nodePush(
    mut ctxt: xmlParserCtxtPtr,
    mut value: xmlNodePtr,
) -> libc::c_int {
    if ctxt.is_null() {
        return 0 as libc::c_int;
    }
    if (*ctxt).nodeNr >= (*ctxt).nodeMax {
        let mut tmp: *mut xmlNodePtr = 0 as *mut xmlNodePtr;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nodeTab as *mut libc::c_void,
            (((*ctxt).nodeMax * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as libc::c_ulong),
        ) as *mut xmlNodePtr;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        let ref mut fresh41 = (*ctxt).nodeTab;
        *fresh41 = tmp;
        (*ctxt).nodeMax *= 2 as libc::c_int;
    }
    if (*ctxt).nodeNr as libc::c_uint > xmlParserMaxDepth
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const libc::c_char,
            xmlParserMaxDepth as libc::c_int,
        );
        xmlHaltParser(ctxt);
        return -(1 as libc::c_int);
    }
    let ref mut fresh42 = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    *fresh42 = value;
    let ref mut fresh43 = (*ctxt).node;
    *fresh43 = value;
    let ref mut fresh44 = (*ctxt).nodeNr;
    let fresh45 = *fresh44;
    *fresh44 = *fresh44 + 1;
    return fresh45;
}
#[no_mangle]
pub unsafe extern "C" fn nodePop(mut ctxt: xmlParserCtxtPtr) -> xmlNodePtr {
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    if ctxt.is_null() {
        return 0 as xmlNodePtr;
    }
    if (*ctxt).nodeNr <= 0 as libc::c_int {
        return 0 as xmlNodePtr;
    }
    let ref mut fresh46 = (*ctxt).nodeNr;
    *fresh46 -= 1;
    if (*ctxt).nodeNr > 0 as libc::c_int {
        let ref mut fresh47 = (*ctxt).node;
        *fresh47 = *((*ctxt).nodeTab)
            .offset(((*ctxt).nodeNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh48 = (*ctxt).node;
        *fresh48 = 0 as xmlNodePtr;
    }
    ret = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    let ref mut fresh49 = *((*ctxt).nodeTab).offset((*ctxt).nodeNr as isize);
    *fresh49 = 0 as xmlNodePtr;
    return ret;
}
unsafe extern "C" fn nameNsPush(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
    mut line: libc::c_int,
    mut nsNr: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut tag: *mut xmlStartTag = 0 as *mut xmlStartTag;
    if (*ctxt).nameNr >= (*ctxt).nameMax {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        let mut tmp2: *mut xmlStartTag = 0 as *mut xmlStartTag;
        (*ctxt).nameMax *= 2 as libc::c_int;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            ((*ctxt).nameMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            (*ctxt).nameMax /= 2 as libc::c_int;
            current_block = 17671332882901204954;
        } else {
            let ref mut fresh50 = (*ctxt).nameTab;
            *fresh50 = tmp;
            tmp2 = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).pushTab as *mut *mut libc::c_void as *mut libc::c_void,
                ((*ctxt).nameMax as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlStartTag>() as libc::c_ulong),
            ) as *mut xmlStartTag;
            if tmp2.is_null() {
                (*ctxt).nameMax /= 2 as libc::c_int;
                current_block = 17671332882901204954;
            } else {
                let ref mut fresh51 = (*ctxt).pushTab;
                *fresh51 = tmp2;
                current_block = 1054647088692577877;
            }
        }
    } else if ((*ctxt).pushTab).is_null() {
        let ref mut fresh52 = (*ctxt).pushTab;
        *fresh52 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).nameMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlStartTag>() as libc::c_ulong),
        ) as *mut xmlStartTag;
        if ((*ctxt).pushTab).is_null() {
            current_block = 17671332882901204954;
        } else {
            current_block = 1054647088692577877;
        }
    } else {
        current_block = 1054647088692577877;
    }
    match current_block {
        17671332882901204954 => {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return -(1 as libc::c_int);
        }
        _ => {
            let ref mut fresh53 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
            *fresh53 = value;
            let ref mut fresh54 = (*ctxt).name;
            *fresh54 = value;
            tag = &mut *((*ctxt).pushTab).offset((*ctxt).nameNr as isize)
                as *mut xmlStartTag;
            let ref mut fresh55 = (*tag).prefix;
            *fresh55 = prefix;
            let ref mut fresh56 = (*tag).URI;
            *fresh56 = URI;
            (*tag).line = line;
            (*tag).nsNr = nsNr;
            let ref mut fresh57 = (*ctxt).nameNr;
            let fresh58 = *fresh57;
            *fresh57 = *fresh57 + 1;
            return fresh58;
        }
    };
}
unsafe extern "C" fn nameNsPop(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).nameNr <= 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    let ref mut fresh59 = (*ctxt).nameNr;
    *fresh59 -= 1;
    if (*ctxt).nameNr > 0 as libc::c_int {
        let ref mut fresh60 = (*ctxt).name;
        *fresh60 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh61 = (*ctxt).name;
        *fresh61 = 0 as *const xmlChar;
    }
    ret = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    let ref mut fresh62 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    *fresh62 = 0 as *const xmlChar;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn namePush(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *const xmlChar,
) -> libc::c_int {
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctxt).nameNr >= (*ctxt).nameMax {
        let mut tmp: *mut *const xmlChar = 0 as *mut *const xmlChar;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).nameTab as *mut *mut xmlChar as *mut libc::c_void,
            (((*ctxt).nameMax * 2 as libc::c_int) as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<*const xmlChar>() as libc::c_ulong),
        ) as *mut *const xmlChar;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return -(1 as libc::c_int);
        } else {
            let ref mut fresh63 = (*ctxt).nameTab;
            *fresh63 = tmp;
            (*ctxt).nameMax *= 2 as libc::c_int;
        }
    }
    let ref mut fresh64 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    *fresh64 = value;
    let ref mut fresh65 = (*ctxt).name;
    *fresh65 = value;
    let ref mut fresh66 = (*ctxt).nameNr;
    let fresh67 = *fresh66;
    *fresh66 = *fresh66 + 1;
    return fresh67;
}
#[no_mangle]
pub unsafe extern "C" fn namePop(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || (*ctxt).nameNr <= 0 as libc::c_int {
        return 0 as *const xmlChar;
    }
    let ref mut fresh68 = (*ctxt).nameNr;
    *fresh68 -= 1;
    if (*ctxt).nameNr > 0 as libc::c_int {
        let ref mut fresh69 = (*ctxt).name;
        *fresh69 = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize);
    } else {
        let ref mut fresh70 = (*ctxt).name;
        *fresh70 = 0 as *const xmlChar;
    }
    ret = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    let ref mut fresh71 = *((*ctxt).nameTab).offset((*ctxt).nameNr as isize);
    *fresh71 = 0 as *const xmlChar;
    return ret;
}
unsafe extern "C" fn spacePush(
    mut ctxt: xmlParserCtxtPtr,
    mut val: libc::c_int,
) -> libc::c_int {
    if (*ctxt).spaceNr >= (*ctxt).spaceMax {
        let mut tmp: *mut libc::c_int = 0 as *mut libc::c_int;
        (*ctxt).spaceMax *= 2 as libc::c_int;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).spaceTab as *mut libc::c_void,
            ((*ctxt).spaceMax as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<libc::c_int>() as libc::c_ulong),
        ) as *mut libc::c_int;
        if tmp.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            (*ctxt).spaceMax /= 2 as libc::c_int;
            return -(1 as libc::c_int);
        }
        let ref mut fresh72 = (*ctxt).spaceTab;
        *fresh72 = tmp;
    }
    *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = val;
    let ref mut fresh73 = (*ctxt).space;
    *fresh73 = &mut *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize)
        as *mut libc::c_int;
    let ref mut fresh74 = (*ctxt).spaceNr;
    let fresh75 = *fresh74;
    *fresh74 = *fresh74 + 1;
    return fresh75;
}
unsafe extern "C" fn spacePop(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if (*ctxt).spaceNr <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    let ref mut fresh76 = (*ctxt).spaceNr;
    *fresh76 -= 1;
    if (*ctxt).spaceNr > 0 as libc::c_int {
        let ref mut fresh77 = (*ctxt).space;
        *fresh77 = &mut *((*ctxt).spaceTab)
            .offset(((*ctxt).spaceNr - 1 as libc::c_int) as isize) as *mut libc::c_int;
    } else {
        let ref mut fresh78 = (*ctxt).space;
        *fresh78 = &mut *((*ctxt).spaceTab).offset(0 as libc::c_int as isize)
            as *mut libc::c_int;
    }
    ret = *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize);
    *((*ctxt).spaceTab).offset((*ctxt).spaceNr as isize) = -(1 as libc::c_int);
    return ret;
}
unsafe extern "C" fn xmlSHRINK(mut ctxt: xmlParserCtxtPtr) {
    xmlParserInputShrink((*ctxt).input);
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
}
unsafe extern "C" fn xmlGROW(mut ctxt: xmlParserCtxtPtr) {
    let mut curEnd: ptrdiff_t = ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
        as libc::c_long;
    let mut curBase: ptrdiff_t = ((*(*ctxt).input).cur)
        .offset_from((*(*ctxt).input).base) as libc::c_long;
    if (curEnd > 10000000 as libc::c_int as libc::c_long
        || curBase > 10000000 as libc::c_int as libc::c_long)
        && (!((*(*ctxt).input).buf).is_null()
            && (*(*(*ctxt).input).buf).readcallback
                != Some(
                    xmlInputReadCallbackNop
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *mut libc::c_char,
                            libc::c_int,
                        ) -> libc::c_int,
                )) && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Huge input lookup\0" as *const u8 as *const libc::c_char,
        );
        xmlHaltParser(ctxt);
        return;
    }
    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    if (*(*ctxt).input).cur > (*(*ctxt).input).end
        || (*(*ctxt).input).cur < (*(*ctxt).input).base
    {
        xmlHaltParser(ctxt);
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"cur index out of bound\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if !((*(*ctxt).input).cur).is_null()
        && *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
    {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSkipBlankChars(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut res: libc::c_int = 0 as libc::c_int;
    if (*ctxt).inputNr == 1 as libc::c_int
        && (*ctxt).instate as libc::c_int != XML_PARSER_DTD as libc::c_int
        || (*ctxt).instate as libc::c_int == XML_PARSER_START as libc::c_int
    {
        let mut cur: *const xmlChar = 0 as *const xmlChar;
        cur = (*(*ctxt).input).cur;
        while *cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *cur as libc::c_int
                && *cur as libc::c_int <= 0xa as libc::c_int
            || *cur as libc::c_int == 0xd as libc::c_int
        {
            if *cur as libc::c_int == '\n' as i32 {
                let ref mut fresh79 = (*(*ctxt).input).line;
                *fresh79 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh80 = (*(*ctxt).input).col;
                *fresh80 += 1;
            }
            cur = cur.offset(1);
            if res < 2147483647 as libc::c_int {
                res += 1;
            }
            if *cur as libc::c_int == 0 as libc::c_int {
                let ref mut fresh81 = (*(*ctxt).input).cur;
                *fresh81 = cur;
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                cur = (*(*ctxt).input).cur;
            }
        }
        let ref mut fresh82 = (*(*ctxt).input).cur;
        *fresh82 = cur;
    } else {
        let mut expandPE: libc::c_int = ((*ctxt).external != 0 as libc::c_int
            || (*ctxt).inputNr != 1 as libc::c_int) as libc::c_int;
        loop {
            if *(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                    && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
                || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
            {
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '%' as i32 {
                if expandPE == 0 as libc::c_int
                    || (*((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == 0x20 as libc::c_int
                        || 0x9 as libc::c_int
                            <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int <= 0xa as libc::c_int
                        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                            as libc::c_int == 0xd as libc::c_int)
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == 0 as libc::c_int
                {
                    break;
                }
                xmlParsePEReference(ctxt);
            } else {
                if !(*(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int) {
                    break;
                }
                if (*ctxt).inputNr <= 1 as libc::c_int {
                    break;
                }
                xmlPopInput(ctxt);
            }
            if res < 2147483647 as libc::c_int {
                res += 1;
            }
        }
    }
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPopInput(mut ctxt: xmlParserCtxtPtr) -> xmlChar {
    if ctxt.is_null() || (*ctxt).inputNr <= 1 as libc::c_int {
        return 0 as libc::c_int as xmlChar;
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Popping input %d\n\0" as *const u8 as *const libc::c_char,
            (*ctxt).inputNr,
        );
    }
    if (*ctxt).inputNr > 1 as libc::c_int && (*ctxt).inSubset == 0 as libc::c_int
        && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Unfinished entity outside the DTD\0" as *const u8 as *const libc::c_char,
        );
    }
    xmlFreeInputStream(inputPop(ctxt));
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    return *(*(*ctxt).input).cur;
}
#[no_mangle]
pub unsafe extern "C" fn xmlPushInput(
    mut ctxt: xmlParserCtxtPtr,
    mut input: xmlParserInputPtr,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    if input.is_null() {
        return -(1 as libc::c_int);
    }
    if *__xmlParserDebugEntities() != 0 {
        if !((*ctxt).input).is_null() && !((*(*ctxt).input).filename).is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"%s(%d): \0" as *const u8 as *const libc::c_char,
                (*(*ctxt).input).filename,
                (*(*ctxt).input).line,
            );
        }
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Pushing input %d : %.30s\n\0" as *const u8 as *const libc::c_char,
            (*ctxt).inputNr + 1 as libc::c_int,
            (*input).cur,
        );
    }
    if (*ctxt).inputNr > 40 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        || (*ctxt).inputNr > 1024 as libc::c_int
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
        while (*ctxt).inputNr > 1 as libc::c_int {
            xmlFreeInputStream(inputPop(ctxt));
        }
        return -(1 as libc::c_int);
    }
    ret = inputPush(ctxt, input);
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCharRef(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut val: libc::c_int = 0 as libc::c_int;
    let mut count: libc::c_int = 0 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == '&' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '#' as i32
        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            == 'x' as i32
    {
        let ref mut fresh83 = (*(*ctxt).input).cur;
        *fresh83 = (*fresh83).offset(3 as libc::c_int as isize);
        (*(*ctxt).input).col += 3 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
            let fresh84 = count;
            count = count + 1;
            if fresh84 > 20 as libc::c_int {
                count = 0 as libc::c_int;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as libc::c_int;
                }
            }
            if *(*(*ctxt).input).cur as libc::c_int >= '0' as i32
                && *(*(*ctxt).input).cur as libc::c_int <= '9' as i32
            {
                val = val * 16 as libc::c_int
                    + (*(*(*ctxt).input).cur as libc::c_int - '0' as i32);
            } else if *(*(*ctxt).input).cur as libc::c_int >= 'a' as i32
                    && *(*(*ctxt).input).cur as libc::c_int <= 'f' as i32
                    && count < 20 as libc::c_int
                {
                val = val * 16 as libc::c_int
                    + (*(*(*ctxt).input).cur as libc::c_int - 'a' as i32)
                    + 10 as libc::c_int;
            } else if *(*(*ctxt).input).cur as libc::c_int >= 'A' as i32
                    && *(*(*ctxt).input).cur as libc::c_int <= 'F' as i32
                    && count < 20 as libc::c_int
                {
                val = val * 16 as libc::c_int
                    + (*(*(*ctxt).input).cur as libc::c_int - 'A' as i32)
                    + 10 as libc::c_int;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const libc::c_char);
                val = 0 as libc::c_int;
                break;
            }
            if val > 0x110000 as libc::c_int {
                val = 0x110000 as libc::c_int;
            }
            xmlNextChar(ctxt);
            count += 1;
        }
        if *(*(*ctxt).input).cur as libc::c_int == ';' as i32 {
            let ref mut fresh85 = (*(*ctxt).input).col;
            *fresh85 += 1;
            let ref mut fresh86 = (*(*ctxt).input).cur;
            *fresh86 = (*fresh86).offset(1);
        }
    } else if *(*(*ctxt).input).cur as libc::c_int == '&' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '#' as i32
        {
        let ref mut fresh87 = (*(*ctxt).input).cur;
        *fresh87 = (*fresh87).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
            let fresh88 = count;
            count = count + 1;
            if fresh88 > 20 as libc::c_int {
                count = 0 as libc::c_int;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as libc::c_int;
                }
            }
            if *(*(*ctxt).input).cur as libc::c_int >= '0' as i32
                && *(*(*ctxt).input).cur as libc::c_int <= '9' as i32
            {
                val = val * 10 as libc::c_int
                    + (*(*(*ctxt).input).cur as libc::c_int - '0' as i32);
                if val > 0x110000 as libc::c_int {
                    val = 0x110000 as libc::c_int;
                }
                xmlNextChar(ctxt);
                count += 1;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const libc::c_char);
                val = 0 as libc::c_int;
                break;
            }
        }
        if *(*(*ctxt).input).cur as libc::c_int == ';' as i32 {
            let ref mut fresh89 = (*(*ctxt).input).col;
            *fresh89 += 1;
            let ref mut fresh90 = (*(*ctxt).input).cur;
            *fresh90 = (*fresh90).offset(1);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const libc::c_char);
    }
    if val >= 0x110000 as libc::c_int {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: character reference out of bounds\n\0" as *const u8
                as *const libc::c_char,
            val,
        );
    } else if if val < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= val && val <= 0xa as libc::c_int
                || val == 0xd as libc::c_int || 0x20 as libc::c_int <= val)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= val && val <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= val && val <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= val && val <= 0x10ffff as libc::c_int)
                as libc::c_int
        } != 0
        {
        return val
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseCharRef: invalid xmlChar value %d\n\0" as *const u8
                as *const libc::c_char,
            val,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlParseStringCharRef(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> libc::c_int {
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut val: libc::c_int = 0 as libc::c_int;
    if str.is_null() || (*str).is_null() {
        return 0 as libc::c_int;
    }
    ptr = *str;
    cur = *ptr;
    if cur as libc::c_int == '&' as i32
        && *ptr.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
        && *ptr.offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
    {
        ptr = ptr.offset(3 as libc::c_int as isize);
        cur = *ptr;
        while cur as libc::c_int != ';' as i32 {
            if cur as libc::c_int >= '0' as i32 && cur as libc::c_int <= '9' as i32 {
                val = val * 16 as libc::c_int + (cur as libc::c_int - '0' as i32);
            } else if cur as libc::c_int >= 'a' as i32
                    && cur as libc::c_int <= 'f' as i32
                {
                val = val * 16 as libc::c_int + (cur as libc::c_int - 'a' as i32)
                    + 10 as libc::c_int;
            } else if cur as libc::c_int >= 'A' as i32
                    && cur as libc::c_int <= 'F' as i32
                {
                val = val * 16 as libc::c_int + (cur as libc::c_int - 'A' as i32)
                    + 10 as libc::c_int;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_HEX_CHARREF, 0 as *const libc::c_char);
                val = 0 as libc::c_int;
                break;
            }
            if val > 0x110000 as libc::c_int {
                val = 0x110000 as libc::c_int;
            }
            ptr = ptr.offset(1);
            cur = *ptr;
        }
        if cur as libc::c_int == ';' as i32 {
            ptr = ptr.offset(1);
        }
    } else if cur as libc::c_int == '&' as i32
            && *ptr.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
        {
        ptr = ptr.offset(2 as libc::c_int as isize);
        cur = *ptr;
        while cur as libc::c_int != ';' as i32 {
            if cur as libc::c_int >= '0' as i32 && cur as libc::c_int <= '9' as i32 {
                val = val * 10 as libc::c_int + (cur as libc::c_int - '0' as i32);
                if val > 0x110000 as libc::c_int {
                    val = 0x110000 as libc::c_int;
                }
                ptr = ptr.offset(1);
                cur = *ptr;
            } else {
                xmlFatalErr(ctxt, XML_ERR_INVALID_DEC_CHARREF, 0 as *const libc::c_char);
                val = 0 as libc::c_int;
                break;
            }
        }
        if cur as libc::c_int == ';' as i32 {
            ptr = ptr.offset(1);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_INVALID_CHARREF, 0 as *const libc::c_char);
        return 0 as libc::c_int;
    }
    *str = ptr;
    if val >= 0x110000 as libc::c_int {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: character reference out of bounds\n\0" as *const u8
                as *const libc::c_char,
            val,
        );
    } else if if val < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= val && val <= 0xa as libc::c_int
                || val == 0xd as libc::c_int || 0x20 as libc::c_int <= val)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= val && val <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= val && val <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= val && val <= 0x10ffff as libc::c_int)
                as libc::c_int
        } != 0
        {
        return val
    } else {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlParseStringCharRef: invalid xmlChar value %d\n\0" as *const u8
                as *const libc::c_char,
            val,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParserHandlePEReference(mut ctxt: xmlParserCtxtPtr) {
    match (*ctxt).instate as libc::c_int {
        8 => return,
        5 => return,
        6 => return,
        9 => return,
        -1 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_AT_EOF, 0 as *const libc::c_char);
            return;
        }
        4 | 0 | 1 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_IN_PROLOG, 0 as *const libc::c_char);
            return;
        }
        10 | 7 | 12 | 2 | 13 | 16 => return,
        14 => {
            xmlFatalErr(ctxt, XML_ERR_PEREF_IN_EPILOG, 0 as *const libc::c_char);
            return;
        }
        11 => return,
        3 => {
            if (*ctxt).external == 0 as libc::c_int
                && (*ctxt).inputNr == 1 as libc::c_int
            {
                return;
            }
            if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == 0x20 as libc::c_int
                || 0x9 as libc::c_int
                    <= *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int <= 0xa as libc::c_int
                || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == 0xd as libc::c_int
                || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == 0 as libc::c_int
            {
                return;
            }
        }
        15 => return,
        _ => {}
    }
    xmlParsePEReference(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringLenDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: libc::c_int,
    mut what: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut buffer_size: size_t = 0 as libc::c_int as size_t;
    let mut nbchars: size_t = 0 as libc::c_int as size_t;
    let mut current: *mut xmlChar = 0 as *mut xmlChar;
    let mut rep: *mut xmlChar = 0 as *mut xmlChar;
    let mut last: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    if ctxt.is_null() || str.is_null() || len < 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    last = str.offset(len as isize);
    if (*ctxt).depth > 40 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        || (*ctxt).depth > 1024 as libc::c_int
    {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buffer_size = 300 as libc::c_int as size_t;
    buffer = xmlMallocAtomic.expect("non-null function pointer")(buffer_size)
        as *mut xmlChar;
    if buffer.is_null() {
        current_block = 12997678243655494442;
    } else {
        if str < last {
            c = xmlStringCurrentChar(ctxt, str, &mut l);
        } else {
            c = 0 as libc::c_int;
        }
        's_81: loop {
            if !(c != 0 as libc::c_int && c != end as libc::c_int
                && c != end2 as libc::c_int && c != end3 as libc::c_int
                && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int)
            {
                current_block = 13810333397648094191;
                break;
            }
            if c == 0 as libc::c_int {
                current_block = 13810333397648094191;
                break;
            }
            if c == '&' as i32
                && *str.offset(1 as libc::c_int as isize) as libc::c_int == '#' as i32
            {
                let mut val: libc::c_int = xmlParseStringCharRef(ctxt, &mut str);
                if val == 0 as libc::c_int {
                    current_block = 15857547771987096737;
                    break;
                }
                if 0 as libc::c_int == 1 as libc::c_int {
                    let fresh91 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh91 as isize) = val as xmlChar;
                } else {
                    nbchars = (nbchars as libc::c_ulong)
                        .wrapping_add(
                            xmlCopyCharMultiByte(
                                &mut *buffer.offset(nbchars as isize),
                                val,
                            ) as libc::c_ulong,
                        ) as size_t as size_t;
                }
                if nbchars.wrapping_add(100 as libc::c_int as libc::c_ulong)
                    > buffer_size
                {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size: size_t = buffer_size
                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                        .wrapping_add(100 as libc::c_int as libc::c_ulong);
                    if new_size < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void, new_size) as *mut xmlChar;
                    if tmp.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp;
                    buffer_size = new_size;
                }
            } else if c == '&' as i32 && what & 1 as libc::c_int != 0 {
                if *__xmlParserDebugEntities() != 0 {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"String decoding Entity Reference: %.30s\n\0" as *const u8
                            as *const libc::c_char,
                        str,
                    );
                }
                ent = xmlParseStringEntityRef(ctxt, &mut str);
                xmlParserEntityCheck(
                    ctxt,
                    0 as libc::c_int as size_t,
                    ent,
                    0 as libc::c_int as size_t,
                );
                if !ent.is_null() {
                    let ref mut fresh92 = (*ctxt).nbentities;
                    *fresh92 = (*fresh92)
                        .wrapping_add(
                            ((*ent).checked / 2 as libc::c_int) as libc::c_ulong,
                        );
                }
                if !ent.is_null()
                    && (*ent).etype as libc::c_uint
                        == XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int as libc::c_uint
                {
                    if !((*ent).content).is_null() {
                        if 0 as libc::c_int == 1 as libc::c_int {
                            let fresh93 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer
                                .offset(
                                    fresh93 as isize,
                                ) = *((*ent).content).offset(0 as libc::c_int as isize);
                        } else {
                            nbchars = (nbchars as libc::c_ulong)
                                .wrapping_add(
                                    xmlCopyCharMultiByte(
                                        &mut *buffer.offset(nbchars as isize),
                                        *((*ent).content).offset(0 as libc::c_int as isize)
                                            as libc::c_int,
                                    ) as libc::c_ulong,
                                ) as size_t as size_t;
                        }
                        if nbchars.wrapping_add(100 as libc::c_int as libc::c_ulong)
                            > buffer_size
                        {
                            let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_0: size_t = buffer_size
                                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                .wrapping_add(100 as libc::c_int as libc::c_ulong);
                            if new_size_0 < buffer_size {
                                current_block = 12997678243655494442;
                                break;
                            }
                            tmp_0 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_0) as *mut xmlChar;
                            if tmp_0.is_null() {
                                current_block = 12997678243655494442;
                                break;
                            }
                            buffer = tmp_0;
                            buffer_size = new_size_0;
                        }
                    } else {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_INTERNAL_ERROR,
                            b"predefined entity has no content\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        current_block = 15857547771987096737;
                        break;
                    }
                } else if !ent.is_null() && !((*ent).content).is_null() {
                    let ref mut fresh94 = (*ctxt).depth;
                    *fresh94 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        (*ent).content,
                        what,
                        0 as libc::c_int as xmlChar,
                        0 as libc::c_int as xmlChar,
                        0 as libc::c_int as xmlChar,
                    );
                    let ref mut fresh95 = (*ctxt).depth;
                    *fresh95 -= 1;
                    if rep.is_null() {
                        *((*ent).content)
                            .offset(
                                0 as libc::c_int as isize,
                            ) = 0 as libc::c_int as xmlChar;
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while *current as libc::c_int != 0 as libc::c_int {
                            let fresh96 = current;
                            current = current.offset(1);
                            let fresh97 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer.offset(fresh97 as isize) = *fresh96;
                            if !(nbchars
                                .wrapping_add(100 as libc::c_int as libc::c_ulong)
                                > buffer_size)
                            {
                                continue;
                            }
                            if xmlParserEntityCheck(
                                ctxt,
                                nbchars,
                                ent,
                                0 as libc::c_int as size_t,
                            ) != 0
                            {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_1: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_1: size_t = buffer_size
                                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                .wrapping_add(100 as libc::c_int as libc::c_ulong);
                            if new_size_1 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_1 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_1) as *mut xmlChar;
                            if tmp_1.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_1;
                            buffer_size = new_size_1;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(rep as *mut libc::c_void);
                        rep = 0 as *mut xmlChar;
                    }
                } else if !ent.is_null() {
                    let mut i: libc::c_int = xmlStrlen((*ent).name);
                    let mut cur: *const xmlChar = (*ent).name;
                    let fresh98 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh98 as isize) = '&' as i32 as xmlChar;
                    if nbchars
                        .wrapping_add(i as libc::c_ulong)
                        .wrapping_add(100 as libc::c_int as libc::c_ulong) > buffer_size
                    {
                        let mut tmp_2: *mut xmlChar = 0 as *mut xmlChar;
                        let mut new_size_2: size_t = buffer_size
                            .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                            .wrapping_add(i as libc::c_ulong)
                            .wrapping_add(100 as libc::c_int as libc::c_ulong);
                        if new_size_2 < buffer_size {
                            current_block = 12997678243655494442;
                            break;
                        }
                        tmp_2 = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void, new_size_2) as *mut xmlChar;
                        if tmp_2.is_null() {
                            current_block = 12997678243655494442;
                            break;
                        }
                        buffer = tmp_2;
                        buffer_size = new_size_2;
                    }
                    while i > 0 as libc::c_int {
                        let fresh99 = cur;
                        cur = cur.offset(1);
                        let fresh100 = nbchars;
                        nbchars = nbchars.wrapping_add(1);
                        *buffer.offset(fresh100 as isize) = *fresh99;
                        i -= 1;
                    }
                    let fresh101 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh101 as isize) = ';' as i32 as xmlChar;
                }
            } else if c == '%' as i32 && what & 2 as libc::c_int != 0 {
                if *__xmlParserDebugEntities() != 0 {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"String decoding PE Reference: %.30s\n\0" as *const u8
                            as *const libc::c_char,
                        str,
                    );
                }
                ent = xmlParseStringPEReference(ctxt, &mut str);
                xmlParserEntityCheck(
                    ctxt,
                    0 as libc::c_int as size_t,
                    ent,
                    0 as libc::c_int as size_t,
                );
                if !ent.is_null() {
                    let ref mut fresh102 = (*ctxt).nbentities;
                    *fresh102 = (*fresh102)
                        .wrapping_add(
                            ((*ent).checked / 2 as libc::c_int) as libc::c_ulong,
                        );
                }
                if !ent.is_null() {
                    if ((*ent).content).is_null() {
                        if (*ctxt).options & XML_PARSE_NOENT as libc::c_int
                            != 0 as libc::c_int
                            || (*ctxt).options & XML_PARSE_DTDVALID as libc::c_int
                                != 0 as libc::c_int || (*ctxt).validate != 0 as libc::c_int
                        {
                            xmlLoadEntityContent(ctxt, ent);
                        } else {
                            xmlWarningMsg(
                                ctxt,
                                XML_ERR_ENTITY_PROCESSING,
                                b"not validating will not read content for PE entity %s\n\0"
                                    as *const u8 as *const libc::c_char,
                                (*ent).name,
                                0 as *const xmlChar,
                            );
                        }
                    }
                    let ref mut fresh103 = (*ctxt).depth;
                    *fresh103 += 1;
                    rep = xmlStringDecodeEntities(
                        ctxt,
                        (*ent).content,
                        what,
                        0 as libc::c_int as xmlChar,
                        0 as libc::c_int as xmlChar,
                        0 as libc::c_int as xmlChar,
                    );
                    let ref mut fresh104 = (*ctxt).depth;
                    *fresh104 -= 1;
                    if rep.is_null() {
                        if !((*ent).content).is_null() {
                            *((*ent).content)
                                .offset(
                                    0 as libc::c_int as isize,
                                ) = 0 as libc::c_int as xmlChar;
                        }
                        current_block = 15857547771987096737;
                        break;
                    } else {
                        current = rep;
                        while *current as libc::c_int != 0 as libc::c_int {
                            let fresh105 = current;
                            current = current.offset(1);
                            let fresh106 = nbchars;
                            nbchars = nbchars.wrapping_add(1);
                            *buffer.offset(fresh106 as isize) = *fresh105;
                            if !(nbchars
                                .wrapping_add(100 as libc::c_int as libc::c_ulong)
                                > buffer_size)
                            {
                                continue;
                            }
                            if xmlParserEntityCheck(
                                ctxt,
                                nbchars,
                                ent,
                                0 as libc::c_int as size_t,
                            ) != 0
                            {
                                current_block = 15857547771987096737;
                                break 's_81;
                            }
                            let mut tmp_3: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_3: size_t = buffer_size
                                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                .wrapping_add(100 as libc::c_int as libc::c_ulong);
                            if new_size_3 < buffer_size {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            tmp_3 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buffer as *mut libc::c_void, new_size_3) as *mut xmlChar;
                            if tmp_3.is_null() {
                                current_block = 12997678243655494442;
                                break 's_81;
                            }
                            buffer = tmp_3;
                            buffer_size = new_size_3;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(rep as *mut libc::c_void);
                        rep = 0 as *mut xmlChar;
                    }
                }
            } else {
                if l == 1 as libc::c_int {
                    let fresh107 = nbchars;
                    nbchars = nbchars.wrapping_add(1);
                    *buffer.offset(fresh107 as isize) = c as xmlChar;
                } else {
                    nbchars = (nbchars as libc::c_ulong)
                        .wrapping_add(
                            xmlCopyCharMultiByte(
                                &mut *buffer.offset(nbchars as isize),
                                c,
                            ) as libc::c_ulong,
                        ) as size_t as size_t;
                }
                str = str.offset(l as isize);
                if nbchars.wrapping_add(100 as libc::c_int as libc::c_ulong)
                    > buffer_size
                {
                    let mut tmp_4: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size_4: size_t = buffer_size
                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                        .wrapping_add(100 as libc::c_int as libc::c_ulong);
                    if new_size_4 < buffer_size {
                        current_block = 12997678243655494442;
                        break;
                    }
                    tmp_4 = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void, new_size_4) as *mut xmlChar;
                    if tmp_4.is_null() {
                        current_block = 12997678243655494442;
                        break;
                    }
                    buffer = tmp_4;
                    buffer_size = new_size_4;
                }
            }
            if str < last {
                c = xmlStringCurrentChar(ctxt, str, &mut l);
            } else {
                c = 0 as libc::c_int;
            }
        }
        match current_block {
            12997678243655494442 => {}
            15857547771987096737 => {}
            _ => {
                *buffer.offset(nbchars as isize) = 0 as libc::c_int as xmlChar;
                return buffer;
            }
        }
    }
    match current_block {
        12997678243655494442 => {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
        }
        _ => {}
    }
    if !rep.is_null() {
        xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
    }
    if !buffer.is_null() {
        xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlStringDecodeEntities(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut what: libc::c_int,
    mut end: xmlChar,
    mut end2: xmlChar,
    mut end3: xmlChar,
) -> *mut xmlChar {
    if ctxt.is_null() || str.is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlStringLenDecodeEntities(ctxt, str, xmlStrlen(str), what, end, end2, end3);
}
unsafe extern "C" fn areBlanks(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *const xmlChar,
    mut len: libc::c_int,
    mut blank_chars: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut lastChild: xmlNodePtr = 0 as *mut xmlNode;
    if (*(*ctxt).sax).ignorableWhitespace == (*(*ctxt).sax).characters {
        return 0 as libc::c_int;
    }
    if ((*ctxt).space).is_null() || *(*ctxt).space == 1 as libc::c_int
        || *(*ctxt).space == -(2 as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    if blank_chars == 0 as libc::c_int {
        i = 0 as libc::c_int;
        while i < len {
            if !(*str.offset(i as isize) as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *str.offset(i as isize) as libc::c_int
                    && *str.offset(i as isize) as libc::c_int <= 0xa as libc::c_int
                || *str.offset(i as isize) as libc::c_int == 0xd as libc::c_int)
            {
                return 0 as libc::c_int;
            }
            i += 1;
        }
    }
    if ((*ctxt).node).is_null() {
        return 0 as libc::c_int;
    }
    if !((*ctxt).myDoc).is_null() {
        ret = xmlIsMixedElement((*ctxt).myDoc, (*(*ctxt).node).name);
        if ret == 0 as libc::c_int {
            return 1 as libc::c_int;
        }
        if ret == 1 as libc::c_int {
            return 0 as libc::c_int;
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32
        && *(*(*ctxt).input).cur as libc::c_int != 0xd as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if ((*(*ctxt).node).children).is_null()
        && *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        return 0 as libc::c_int;
    }
    lastChild = xmlGetLastChild((*ctxt).node as *const xmlNode);
    if lastChild.is_null() {
        if (*(*ctxt).node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            && !((*(*ctxt).node).content).is_null()
        {
            return 0 as libc::c_int;
        }
    } else if xmlNodeIsText(lastChild as *const xmlNode) != 0 {
        return 0 as libc::c_int
    } else {
        if !((*(*ctxt).node).children).is_null()
            && xmlNodeIsText((*(*ctxt).node).children) != 0
        {
            return 0 as libc::c_int;
        }
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSplitQName(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut prefix: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut max: libc::c_int = 100 as libc::c_int;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = name;
    let mut c: libc::c_int = 0;
    if prefix.is_null() {
        return 0 as *mut xmlChar;
    }
    *prefix = 0 as *mut xmlChar;
    if cur.is_null() {
        return 0 as *mut xmlChar;
    }
    if *cur.offset(0 as libc::c_int as isize) as libc::c_int == ':' as i32 {
        return xmlStrdup(name);
    }
    let fresh108 = cur;
    cur = cur.offset(1);
    c = *fresh108 as libc::c_int;
    while c != 0 as libc::c_int && c != ':' as i32 && len < max {
        let fresh109 = len;
        len = len + 1;
        buf[fresh109 as usize] = c as xmlChar;
        let fresh110 = cur;
        cur = cur.offset(1);
        c = *fresh110 as libc::c_int;
    }
    if len >= max {
        max = len * 2 as libc::c_int;
        buffer = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            (max as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
        ) as *mut xmlChar;
        if buffer.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as *mut xmlChar;
        }
        memcpy(
            buffer as *mut libc::c_void,
            buf.as_mut_ptr() as *const libc::c_void,
            len as libc::c_ulong,
        );
        while c != 0 as libc::c_int && c != ':' as i32 {
            if len + 10 as libc::c_int > max {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                max *= 2 as libc::c_int;
                tmp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    buffer as *mut libc::c_void,
                    (max as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
                ) as *mut xmlChar;
                if tmp.is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(buffer as *mut libc::c_void);
                    xmlErrMemory(ctxt, 0 as *const libc::c_char);
                    return 0 as *mut xmlChar;
                }
                buffer = tmp;
            }
            let fresh111 = len;
            len = len + 1;
            *buffer.offset(fresh111 as isize) = c as xmlChar;
            let fresh112 = cur;
            cur = cur.offset(1);
            c = *fresh112 as libc::c_int;
        }
        *buffer.offset(len as isize) = 0 as libc::c_int as xmlChar;
    }
    if c == ':' as i32 && *cur as libc::c_int == 0 as libc::c_int {
        if !buffer.is_null() {
            xmlFree.expect("non-null function pointer")(buffer as *mut libc::c_void);
        }
        *prefix = 0 as *mut xmlChar;
        return xmlStrdup(name);
    }
    if buffer.is_null() {
        ret = xmlStrndup(buf.as_mut_ptr(), len);
    } else {
        ret = buffer;
        buffer = 0 as *mut xmlChar;
        max = 100 as libc::c_int;
    }
    if c == ':' as i32 {
        c = *cur as libc::c_int;
        *prefix = ret;
        if c == 0 as libc::c_int {
            return xmlStrndup(
                b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as libc::c_int,
            );
        }
        len = 0 as libc::c_int;
        if !(c >= 0x61 as libc::c_int && c <= 0x7a as libc::c_int
            || c >= 0x41 as libc::c_int && c <= 0x5a as libc::c_int || c == '_' as i32
            || c == ':' as i32)
        {
            let mut l: libc::c_int = 0;
            let mut first: libc::c_int = xmlStringCurrentChar(ctxt, cur, &mut l);
            if !((if first < 0x100 as libc::c_int {
                (0x41 as libc::c_int <= first && first <= 0x5a as libc::c_int
                    || 0x61 as libc::c_int <= first && first <= 0x7a as libc::c_int
                    || 0xc0 as libc::c_int <= first && first <= 0xd6 as libc::c_int
                    || 0xd8 as libc::c_int <= first && first <= 0xf6 as libc::c_int
                    || 0xf8 as libc::c_int <= first) as libc::c_int
            } else {
                xmlCharInRange(first as libc::c_uint, &xmlIsBaseCharGroup)
            }) != 0
                || (if first < 0x100 as libc::c_int {
                    0 as libc::c_int
                } else {
                    (0x4e00 as libc::c_int <= first && first <= 0x9fa5 as libc::c_int
                        || first == 0x3007 as libc::c_int
                        || 0x3021 as libc::c_int <= first
                            && first <= 0x3029 as libc::c_int) as libc::c_int
                }) != 0) && first != '_' as i32
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Name %s is not XML Namespace compliant\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
            }
        }
        cur = cur.offset(1);
        while c != 0 as libc::c_int && len < max {
            let fresh113 = len;
            len = len + 1;
            buf[fresh113 as usize] = c as xmlChar;
            let fresh114 = cur;
            cur = cur.offset(1);
            c = *fresh114 as libc::c_int;
        }
        if len >= max {
            max = len * 2 as libc::c_int;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as libc::c_ulong,
            );
            while c != 0 as libc::c_int {
                if len + 10 as libc::c_int > max {
                    let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                    max *= 2 as libc::c_int;
                    tmp_0 = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                            ),
                    ) as *mut xmlChar;
                    if tmp_0.is_null() {
                        xmlErrMemory(ctxt, 0 as *const libc::c_char);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp_0;
                }
                let fresh115 = len;
                len = len + 1;
                *buffer.offset(fresh115 as isize) = c as xmlChar;
                let fresh116 = cur;
                cur = cur.offset(1);
                c = *fresh116 as libc::c_int;
            }
            *buffer.offset(len as isize) = 0 as libc::c_int as xmlChar;
        }
        if buffer.is_null() {
            ret = xmlStrndup(buf.as_mut_ptr(), len);
        } else {
            ret = buffer;
        }
    }
    return ret;
}
unsafe extern "C" fn xmlIsNameStartChar(
    mut ctxt: xmlParserCtxtPtr,
    mut c: libc::c_int,
) -> libc::c_int {
    if (*ctxt).options & XML_PARSE_OLD10 as libc::c_int == 0 as libc::c_int {
        if c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32 || c == ':' as i32
                || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
                || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
                || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
                || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
                || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
                || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
                || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
                || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
                || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
                || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
                || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
                || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int)
        {
            return 1 as libc::c_int;
        }
    } else if (if c < 0x100 as libc::c_int {
            (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                || 0xf8 as libc::c_int <= c) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
        }) != 0
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                    || c == 0x3007 as libc::c_int
                    || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                    as libc::c_int
            }) != 0 || c == '_' as i32 || c == ':' as i32
        {
        return 1 as libc::c_int
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlIsNameChar(
    mut ctxt: xmlParserCtxtPtr,
    mut c: libc::c_int,
) -> libc::c_int {
    if (*ctxt).options & XML_PARSE_OLD10 as libc::c_int == 0 as libc::c_int {
        if c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32 || c == '_' as i32
                || c == ':' as i32 || c == '-' as i32 || c == '.' as i32
                || c == 0xb7 as libc::c_int
                || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
                || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
                || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
                || c >= 0x300 as libc::c_int && c <= 0x36f as libc::c_int
                || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
                || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
                || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
                || c >= 0x203f as libc::c_int && c <= 0x2040 as libc::c_int
                || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
                || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
                || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
                || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
                || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
                || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int)
        {
            return 1 as libc::c_int;
        }
    } else if (if c < 0x100 as libc::c_int {
            (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                || 0xf8 as libc::c_int <= c) as libc::c_int
        } else {
            xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
        }) != 0
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                    || c == 0x3007 as libc::c_int
                    || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                    as libc::c_int
            }) != 0
            || (if c < 0x100 as libc::c_int {
                (0x30 as libc::c_int <= c && c <= 0x39 as libc::c_int) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsDigitGroup)
            }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
            || c == ':' as i32
            || (if c < 0x100 as libc::c_int {
                0 as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
            }) != 0
            || (if c < 0x100 as libc::c_int {
                (c == 0xb7 as libc::c_int) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
            }) != 0
        {
        return 1 as libc::c_int
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlParseNameComplex(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as *const xmlChar;
    }
    c = xmlCurrentChar(ctxt, &mut l);
    if (*ctxt).options & XML_PARSE_OLD10 as libc::c_int == 0 as libc::c_int {
        if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
            || !(c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c == '_' as i32 || c == ':' as i32
                || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
                || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
                || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
                || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
                || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
                || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
                || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
                || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
                || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
                || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
                || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
                || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int)
        {
            return 0 as *const xmlChar;
        }
        len += l;
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh117 = (*(*ctxt).input).line;
            *fresh117 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh118 = (*(*ctxt).input).col;
            *fresh118 += 1;
        }
        let ref mut fresh119 = (*(*ctxt).input).cur;
        *fresh119 = (*fresh119).offset(l as isize);
        c = xmlCurrentChar(ctxt, &mut l);
        while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && (c >= 'a' as i32 && c <= 'z' as i32 || c >= 'A' as i32 && c <= 'Z' as i32
                || c >= '0' as i32 && c <= '9' as i32 || c == '_' as i32
                || c == ':' as i32 || c == '-' as i32 || c == '.' as i32
                || c == 0xb7 as libc::c_int
                || c >= 0xc0 as libc::c_int && c <= 0xd6 as libc::c_int
                || c >= 0xd8 as libc::c_int && c <= 0xf6 as libc::c_int
                || c >= 0xf8 as libc::c_int && c <= 0x2ff as libc::c_int
                || c >= 0x300 as libc::c_int && c <= 0x36f as libc::c_int
                || c >= 0x370 as libc::c_int && c <= 0x37d as libc::c_int
                || c >= 0x37f as libc::c_int && c <= 0x1fff as libc::c_int
                || c >= 0x200c as libc::c_int && c <= 0x200d as libc::c_int
                || c >= 0x203f as libc::c_int && c <= 0x2040 as libc::c_int
                || c >= 0x2070 as libc::c_int && c <= 0x218f as libc::c_int
                || c >= 0x2c00 as libc::c_int && c <= 0x2fef as libc::c_int
                || c >= 0x3001 as libc::c_int && c <= 0xd7ff as libc::c_int
                || c >= 0xf900 as libc::c_int && c <= 0xfdcf as libc::c_int
                || c >= 0xfdf0 as libc::c_int && c <= 0xfffd as libc::c_int
                || c >= 0x10000 as libc::c_int && c <= 0xeffff as libc::c_int)
        {
            let fresh120 = count;
            count = count + 1;
            if fresh120 > 100 as libc::c_int {
                count = 0 as libc::c_int;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh121 = (*(*ctxt).input).line;
                *fresh121 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh122 = (*(*ctxt).input).col;
                *fresh122 += 1;
            }
            let ref mut fresh123 = (*(*ctxt).input).cur;
            *fresh123 = (*fresh123).offset(l as isize);
            c = xmlCurrentChar(ctxt, &mut l);
        }
    } else {
        if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
            || !((if c < 0x100 as libc::c_int {
                (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                    || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                    || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                    || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                    || 0xf8 as libc::c_int <= c) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
            }) != 0
                || (if c < 0x100 as libc::c_int {
                    0 as libc::c_int
                } else {
                    (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                        || c == 0x3007 as libc::c_int
                        || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                        as libc::c_int
                }) != 0) && c != '_' as i32 && c != ':' as i32
        {
            return 0 as *const xmlChar;
        }
        len += l;
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh124 = (*(*ctxt).input).line;
            *fresh124 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh125 = (*(*ctxt).input).col;
            *fresh125 += 1;
        }
        let ref mut fresh126 = (*(*ctxt).input).cur;
        *fresh126 = (*fresh126).offset(l as isize);
        c = xmlCurrentChar(ctxt, &mut l);
        while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
            && ((if c < 0x100 as libc::c_int {
                (0x41 as libc::c_int <= c && c <= 0x5a as libc::c_int
                    || 0x61 as libc::c_int <= c && c <= 0x7a as libc::c_int
                    || 0xc0 as libc::c_int <= c && c <= 0xd6 as libc::c_int
                    || 0xd8 as libc::c_int <= c && c <= 0xf6 as libc::c_int
                    || 0xf8 as libc::c_int <= c) as libc::c_int
            } else {
                xmlCharInRange(c as libc::c_uint, &xmlIsBaseCharGroup)
            }) != 0
                || (if c < 0x100 as libc::c_int {
                    0 as libc::c_int
                } else {
                    (0x4e00 as libc::c_int <= c && c <= 0x9fa5 as libc::c_int
                        || c == 0x3007 as libc::c_int
                        || 0x3021 as libc::c_int <= c && c <= 0x3029 as libc::c_int)
                        as libc::c_int
                }) != 0
                || (if c < 0x100 as libc::c_int {
                    (0x30 as libc::c_int <= c && c <= 0x39 as libc::c_int) as libc::c_int
                } else {
                    xmlCharInRange(c as libc::c_uint, &xmlIsDigitGroup)
                }) != 0 || c == '.' as i32 || c == '-' as i32 || c == '_' as i32
                || c == ':' as i32
                || (if c < 0x100 as libc::c_int {
                    0 as libc::c_int
                } else {
                    xmlCharInRange(c as libc::c_uint, &xmlIsCombiningGroup)
                }) != 0
                || (if c < 0x100 as libc::c_int {
                    (c == 0xb7 as libc::c_int) as libc::c_int
                } else {
                    xmlCharInRange(c as libc::c_uint, &xmlIsExtenderGroup)
                }) != 0)
        {
            let fresh127 = count;
            count = count + 1;
            if fresh127 > 100 as libc::c_int {
                count = 0 as libc::c_int;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *const xmlChar;
                }
            }
            len += l;
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh128 = (*(*ctxt).input).line;
                *fresh128 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh129 = (*(*ctxt).input).col;
                *fresh129 += 1;
            }
            let ref mut fresh130 = (*(*ctxt).input).cur;
            *fresh130 = (*fresh130).offset(l as isize);
            c = xmlCurrentChar(ctxt, &mut l);
        }
    }
    if len > 50000 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"Name\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    if (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long)
        < len as libc::c_long
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"unexpected change of input buffer\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32
        && *((*(*ctxt).input).cur).offset(-(1 as libc::c_int) as isize) as libc::c_int
            == '\r' as i32
    {
        return xmlDictLookup(
            (*ctxt).dict,
            ((*(*ctxt).input).cur).offset(-((len + 1 as libc::c_int) as isize)),
            len,
        );
    }
    return xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).cur).offset(-(len as isize)),
        len,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseName(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    if *in_0 as libc::c_int >= 0x61 as libc::c_int
        && *in_0 as libc::c_int <= 0x7a as libc::c_int
        || *in_0 as libc::c_int >= 0x41 as libc::c_int
            && *in_0 as libc::c_int <= 0x5a as libc::c_int
        || *in_0 as libc::c_int == '_' as i32 || *in_0 as libc::c_int == ':' as i32
    {
        in_0 = in_0.offset(1);
        while *in_0 as libc::c_int >= 0x61 as libc::c_int
            && *in_0 as libc::c_int <= 0x7a as libc::c_int
            || *in_0 as libc::c_int >= 0x41 as libc::c_int
                && *in_0 as libc::c_int <= 0x5a as libc::c_int
            || *in_0 as libc::c_int >= 0x30 as libc::c_int
                && *in_0 as libc::c_int <= 0x39 as libc::c_int
            || *in_0 as libc::c_int == '_' as i32 || *in_0 as libc::c_int == '-' as i32
            || *in_0 as libc::c_int == ':' as i32 || *in_0 as libc::c_int == '.' as i32
        {
            in_0 = in_0.offset(1);
        }
        if *in_0 as libc::c_int > 0 as libc::c_int
            && (*in_0 as libc::c_int) < 0x80 as libc::c_int
        {
            count = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                as libc::c_int;
            if count > 50000 as libc::c_int
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Name\0" as *const u8 as *const libc::c_char,
                );
                return 0 as *const xmlChar;
            }
            ret = xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count);
            let ref mut fresh131 = (*(*ctxt).input).cur;
            *fresh131 = in_0;
            (*(*ctxt).input).col += count;
            if ret.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
            }
            return ret;
        }
    }
    return xmlParseNameComplex(ctxt);
}
unsafe extern "C" fn xmlParseNCNameComplex(
    mut ctxt: xmlParserCtxtPtr,
) -> *const xmlChar {
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut startPosition: size_t = 0 as libc::c_int as size_t;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    startPosition = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
        as libc::c_long as size_t;
    c = xmlCurrentChar(ctxt, &mut l);
    if c == ' ' as i32 || c == '>' as i32 || c == '/' as i32
        || (xmlIsNameStartChar(ctxt, c) == 0 || c == ':' as i32)
    {
        return 0 as *const xmlChar;
    }
    while c != ' ' as i32 && c != '>' as i32 && c != '/' as i32
        && (xmlIsNameChar(ctxt, c) != 0 && c != ':' as i32)
    {
        let fresh132 = count;
        count = count + 1;
        if fresh132 > 100 as libc::c_int {
            if len > 50000 as libc::c_int
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"NCName\0" as *const u8 as *const libc::c_char,
                );
                return 0 as *const xmlChar;
            }
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return 0 as *const xmlChar;
            }
        }
        len += l;
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh133 = (*(*ctxt).input).line;
            *fresh133 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh134 = (*(*ctxt).input).col;
            *fresh134 += 1;
        }
        let ref mut fresh135 = (*(*ctxt).input).cur;
        *fresh135 = (*fresh135).offset(l as isize);
        c = xmlCurrentChar(ctxt, &mut l);
        if c == 0 as libc::c_int {
            count = 0 as libc::c_int;
            let ref mut fresh136 = (*(*ctxt).input).cur;
            *fresh136 = (*fresh136).offset(-(l as isize));
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return 0 as *const xmlChar;
            }
            let ref mut fresh137 = (*(*ctxt).input).cur;
            *fresh137 = (*fresh137).offset(l as isize);
            c = xmlCurrentChar(ctxt, &mut l);
        }
    }
    if len > 50000 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    return xmlDictLookup(
        (*ctxt).dict,
        ((*(*ctxt).input).base).offset(startPosition as isize),
        len,
    );
}
unsafe extern "C" fn xmlParseNCName(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut e: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut count: libc::c_int = 0 as libc::c_int;
    in_0 = (*(*ctxt).input).cur;
    e = (*(*ctxt).input).end;
    if (*in_0 as libc::c_int >= 0x61 as libc::c_int
        && *in_0 as libc::c_int <= 0x7a as libc::c_int
        || *in_0 as libc::c_int >= 0x41 as libc::c_int
            && *in_0 as libc::c_int <= 0x5a as libc::c_int
        || *in_0 as libc::c_int == '_' as i32) && in_0 < e
    {
        in_0 = in_0.offset(1);
        while (*in_0 as libc::c_int >= 0x61 as libc::c_int
            && *in_0 as libc::c_int <= 0x7a as libc::c_int
            || *in_0 as libc::c_int >= 0x41 as libc::c_int
                && *in_0 as libc::c_int <= 0x5a as libc::c_int
            || *in_0 as libc::c_int >= 0x30 as libc::c_int
                && *in_0 as libc::c_int <= 0x39 as libc::c_int
            || *in_0 as libc::c_int == '_' as i32 || *in_0 as libc::c_int == '-' as i32
            || *in_0 as libc::c_int == '.' as i32) && in_0 < e
        {
            in_0 = in_0.offset(1);
        }
        if !(in_0 >= e) {
            if *in_0 as libc::c_int > 0 as libc::c_int
                && (*in_0 as libc::c_int) < 0x80 as libc::c_int
            {
                count = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                    as libc::c_int;
                if count > 50000 as libc::c_int
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_NAME_TOO_LONG,
                        b"NCName\0" as *const u8 as *const libc::c_char,
                    );
                    return 0 as *const xmlChar;
                }
                ret = xmlDictLookup((*ctxt).dict, (*(*ctxt).input).cur, count);
                let ref mut fresh138 = (*(*ctxt).input).cur;
                *fresh138 = in_0;
                (*(*ctxt).input).col += count;
                if ret.is_null() {
                    xmlErrMemory(ctxt, 0 as *const libc::c_char);
                }
                return ret;
            }
        }
    }
    return xmlParseNCNameComplex(ctxt);
}
unsafe extern "C" fn xmlParseNameAndCompare(
    mut ctxt: xmlParserCtxtPtr,
    mut other: *const xmlChar,
) -> *const xmlChar {
    let mut cmp: *const xmlChar = other;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as *const xmlChar;
    }
    in_0 = (*(*ctxt).input).cur;
    while *in_0 as libc::c_int != 0 as libc::c_int
        && *in_0 as libc::c_int == *cmp as libc::c_int
    {
        in_0 = in_0.offset(1);
        cmp = cmp.offset(1);
    }
    if *cmp as libc::c_int == 0 as libc::c_int
        && (*in_0 as libc::c_int == '>' as i32
            || (*in_0 as libc::c_int == 0x20 as libc::c_int
                || 0x9 as libc::c_int <= *in_0 as libc::c_int
                    && *in_0 as libc::c_int <= 0xa as libc::c_int
                || *in_0 as libc::c_int == 0xd as libc::c_int))
    {
        let ref mut fresh139 = (*(*ctxt).input).col;
        *fresh139 = (*fresh139 as libc::c_long
            + in_0.offset_from((*(*ctxt).input).cur) as libc::c_long) as libc::c_int;
        let ref mut fresh140 = (*(*ctxt).input).cur;
        *fresh140 = in_0;
        return 1 as libc::c_int as *const xmlChar;
    }
    ret = xmlParseName(ctxt);
    if ret == other {
        return 1 as libc::c_int as *const xmlChar;
    }
    return ret;
}
unsafe extern "C" fn xmlParseStringName(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut cur: *const xmlChar = *str;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    c = xmlStringCurrentChar(ctxt, cur, &mut l);
    if xmlIsNameStartChar(ctxt, c) == 0 {
        return 0 as *mut xmlChar;
    }
    if l == 1 as libc::c_int {
        let fresh141 = len;
        len = len + 1;
        buf[fresh141 as usize] = c as xmlChar;
    } else {
        len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
    }
    cur = cur.offset(l as isize);
    c = xmlStringCurrentChar(ctxt, cur, &mut l);
    while xmlIsNameChar(ctxt, c) != 0 {
        if l == 1 as libc::c_int {
            let fresh142 = len;
            len = len + 1;
            buf[fresh142 as usize] = c as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
        }
        cur = cur.offset(l as isize);
        c = xmlStringCurrentChar(ctxt, cur, &mut l);
        if len >= 100 as libc::c_int {
            let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
            let mut max: libc::c_int = len * 2 as libc::c_int;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as libc::c_ulong,
            );
            while xmlIsNameChar(ctxt, c) != 0 {
                if len + 10 as libc::c_int > max {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    if len > 50000 as libc::c_int
                        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                            == 0 as libc::c_int
                    {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NCName\0" as *const u8 as *const libc::c_char,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as libc::c_int;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const libc::c_char);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as libc::c_int {
                    let fresh143 = len;
                    len = len + 1;
                    *buffer.offset(fresh143 as isize) = c as xmlChar;
                } else {
                    len += xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c);
                }
                cur = cur.offset(l as isize);
                c = xmlStringCurrentChar(ctxt, cur, &mut l);
            }
            *buffer.offset(len as isize) = 0 as libc::c_int as xmlChar;
            *str = cur;
            return buffer;
        }
    }
    if len > 50000 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NCName\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut xmlChar;
    }
    *str = cur;
    return xmlStrndup(buf.as_mut_ptr(), len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNmtoken(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: [xmlChar; 105] = [0; 105];
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as *mut xmlChar;
    }
    c = xmlCurrentChar(ctxt, &mut l);
    while xmlIsNameChar(ctxt, c) != 0 {
        let fresh144 = count;
        count = count + 1;
        if fresh144 > 100 as libc::c_int {
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
        }
        if l == 1 as libc::c_int {
            let fresh145 = len;
            len = len + 1;
            buf[fresh145 as usize] = c as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.as_mut_ptr().offset(len as isize), c);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh146 = (*(*ctxt).input).line;
            *fresh146 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh147 = (*(*ctxt).input).col;
            *fresh147 += 1;
        }
        let ref mut fresh148 = (*(*ctxt).input).cur;
        *fresh148 = (*fresh148).offset(l as isize);
        c = xmlCurrentChar(ctxt, &mut l);
        if c == 0 as libc::c_int {
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return 0 as *mut xmlChar;
            }
            c = xmlCurrentChar(ctxt, &mut l);
        }
        if len >= 100 as libc::c_int {
            let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
            let mut max: libc::c_int = len * 2 as libc::c_int;
            buffer = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(
                (max as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if buffer.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                return 0 as *mut xmlChar;
            }
            memcpy(
                buffer as *mut libc::c_void,
                buf.as_mut_ptr() as *const libc::c_void,
                len as libc::c_ulong,
            );
            while xmlIsNameChar(ctxt, c) != 0 {
                let fresh149 = count;
                count = count + 1;
                if fresh149 > 100 as libc::c_int {
                    count = 0 as libc::c_int;
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlGROW(ctxt);
                    }
                    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                }
                if len + 10 as libc::c_int > max {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    if max > 50000 as libc::c_int
                        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                            == 0 as libc::c_int
                    {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_NAME_TOO_LONG,
                            b"NmToken\0" as *const u8 as *const libc::c_char,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    max *= 2 as libc::c_int;
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(
                        buffer as *mut libc::c_void,
                        (max as libc::c_ulong)
                            .wrapping_mul(
                                ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                            ),
                    ) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const libc::c_char);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buffer as *mut libc::c_void);
                        return 0 as *mut xmlChar;
                    }
                    buffer = tmp;
                }
                if l == 1 as libc::c_int {
                    let fresh150 = len;
                    len = len + 1;
                    *buffer.offset(fresh150 as isize) = c as xmlChar;
                } else {
                    len += xmlCopyCharMultiByte(&mut *buffer.offset(len as isize), c);
                }
                if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                    let ref mut fresh151 = (*(*ctxt).input).line;
                    *fresh151 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                } else {
                    let ref mut fresh152 = (*(*ctxt).input).col;
                    *fresh152 += 1;
                }
                let ref mut fresh153 = (*(*ctxt).input).cur;
                *fresh153 = (*fresh153).offset(l as isize);
                c = xmlCurrentChar(ctxt, &mut l);
            }
            *buffer.offset(len as isize) = 0 as libc::c_int as xmlChar;
            return buffer;
        }
    }
    if len == 0 as libc::c_int {
        return 0 as *mut xmlChar;
    }
    if len > 50000 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_NAME_TOO_LONG,
            b"NmToken\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut xmlChar;
    }
    return xmlStrndup(buf.as_mut_ptr(), len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityValue(
    mut ctxt: xmlParserCtxtPtr,
    mut orig: *mut *mut xmlChar,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut stop: xmlChar = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENTITY_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_ENTITY_VALUE;
    input = (*ctxt).input;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if !((*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int) {
        xmlNextChar(ctxt);
        c = xmlCurrentChar(ctxt, &mut l);
        loop {
            if !((if c < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                    || c == 0xd as libc::c_int || 0x20 as libc::c_int <= c)
                    as libc::c_int
            } else {
                (0x100 as libc::c_int <= c && c <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= c && c <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= c && c <= 0x10ffff as libc::c_int)
                    as libc::c_int
            }) != 0 && (c != stop as libc::c_int || (*ctxt).input != input)
                && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int)
            {
                current_block = 13460095289871124136;
                break;
            }
            if len + 5 as libc::c_int >= size {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                size *= 2 as libc::c_int;
                tmp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    buf as *mut libc::c_void,
                    (size as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
                ) as *mut xmlChar;
                if tmp.is_null() {
                    xmlErrMemory(ctxt, 0 as *const libc::c_char);
                    current_block = 1959508989248982327;
                    break;
                } else {
                    buf = tmp;
                }
            }
            if l == 1 as libc::c_int {
                let fresh154 = len;
                len = len + 1;
                *buf.offset(fresh154 as isize) = c as xmlChar;
            } else {
                len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), c);
            }
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh155 = (*(*ctxt).input).line;
                *fresh155 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh156 = (*(*ctxt).input).col;
                *fresh156 += 1;
            }
            let ref mut fresh157 = (*(*ctxt).input).cur;
            *fresh157 = (*fresh157).offset(l as isize);
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            c = xmlCurrentChar(ctxt, &mut l);
            if c == 0 as libc::c_int {
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                c = xmlCurrentChar(ctxt, &mut l);
            }
        }
        match current_block {
            1959508989248982327 => {}
            _ => {
                *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
                if !((*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int) {
                    if c != stop as libc::c_int {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_ENTITY_NOT_FINISHED,
                            0 as *const libc::c_char,
                        );
                    } else {
                        xmlNextChar(ctxt);
                        cur = buf;
                        loop {
                            if !(*cur as libc::c_int != 0 as libc::c_int) {
                                current_block = 7158658067966855297;
                                break;
                            }
                            if *cur as libc::c_int == '%' as i32
                                || *cur as libc::c_int == '&' as i32
                                    && *cur.offset(1 as libc::c_int as isize) as libc::c_int
                                        != '#' as i32
                            {
                                let mut name: *mut xmlChar = 0 as *mut xmlChar;
                                let mut tmp_0: xmlChar = *cur;
                                let mut nameOk: libc::c_int = 0 as libc::c_int;
                                cur = cur.offset(1);
                                name = xmlParseStringName(ctxt, &mut cur);
                                if !name.is_null() {
                                    nameOk = 1 as libc::c_int;
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(name as *mut libc::c_void);
                                }
                                if nameOk == 0 as libc::c_int
                                    || *cur as libc::c_int != ';' as i32
                                {
                                    xmlFatalErrMsgInt(
                                        ctxt,
                                        XML_ERR_ENTITY_CHAR_ERROR,
                                        b"EntityValue: '%c' forbidden except for entities references\n\0"
                                            as *const u8 as *const libc::c_char,
                                        tmp_0 as libc::c_int,
                                    );
                                    current_block = 1959508989248982327;
                                    break;
                                } else if tmp_0 as libc::c_int == '%' as i32
                                        && (*ctxt).inSubset == 1 as libc::c_int
                                        && (*ctxt).inputNr == 1 as libc::c_int
                                    {
                                    xmlFatalErr(
                                        ctxt,
                                        XML_ERR_ENTITY_PE_INTERNAL,
                                        0 as *const libc::c_char,
                                    );
                                    current_block = 1959508989248982327;
                                    break;
                                } else if *cur as libc::c_int == 0 as libc::c_int {
                                    current_block = 7158658067966855297;
                                    break;
                                }
                            }
                            cur = cur.offset(1);
                        }
                        match current_block {
                            1959508989248982327 => {}
                            _ => {
                                let ref mut fresh158 = (*ctxt).depth;
                                *fresh158 += 1;
                                ret = xmlStringDecodeEntities(
                                    ctxt,
                                    buf,
                                    2 as libc::c_int,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                );
                                let ref mut fresh159 = (*ctxt).depth;
                                *fresh159 -= 1;
                                if !orig.is_null() {
                                    *orig = buf;
                                    buf = 0 as *mut xmlChar;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if !buf.is_null() {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlParseAttValueComplex(
    mut ctxt: xmlParserCtxtPtr,
    mut attlen: *mut libc::c_int,
    mut normalize: libc::c_int,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut limit: xmlChar = 0 as libc::c_int as xmlChar;
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut rep: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut buf_size: size_t = 0 as libc::c_int as size_t;
    let mut c: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut in_space: libc::c_int = 0 as libc::c_int;
    let mut current: *mut xmlChar = 0 as *mut xmlChar;
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    if *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int
        == '"' as i32
    {
        (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
        limit = '"' as i32 as xmlChar;
        xmlNextChar(ctxt);
    } else if *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int
            == '\'' as i32
        {
        limit = '\'' as i32 as xmlChar;
        (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buf_size = 100 as libc::c_int as size_t;
    buf = xmlMallocAtomic.expect("non-null function pointer")(buf_size) as *mut xmlChar;
    if buf.is_null() {
        current_block = 4728557498262148097;
    } else {
        c = xmlCurrentChar(ctxt, &mut l);
        's_99: loop {
            if !(*((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int
                != limit as libc::c_int
                && (if c < 0x100 as libc::c_int {
                    (0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                        || c == 0xd as libc::c_int || 0x20 as libc::c_int <= c)
                        as libc::c_int
                } else {
                    (0x100 as libc::c_int <= c && c <= 0xd7ff as libc::c_int
                        || 0xe000 as libc::c_int <= c && c <= 0xfffd as libc::c_int
                        || 0x10000 as libc::c_int <= c && c <= 0x10ffff as libc::c_int)
                        as libc::c_int
                }) != 0 && c != '<' as i32
                && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int)
            {
                current_block = 3166194604430448652;
                break;
            }
            if len > 10000000 as libc::c_int as libc::c_ulong
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ATTRIBUTE_NOT_FINISHED,
                    b"AttValue length too long\n\0" as *const u8 as *const libc::c_char,
                );
                current_block = 4728557498262148097;
                break;
            } else {
                if c == '&' as i32 {
                    in_space = 0 as libc::c_int;
                    if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == '#' as i32
                    {
                        let mut val: libc::c_int = xmlParseCharRef(ctxt);
                        if val == '&' as i32 {
                            if (*ctxt).replaceEntities != 0 {
                                if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                    > buf_size
                                {
                                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size: size_t = buf_size
                                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                        .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                    if new_size < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                                    if tmp.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp;
                                    buf_size = new_size;
                                }
                                let fresh160 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh160 as isize) = '&' as i32 as xmlChar;
                            } else {
                                if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                    > buf_size
                                {
                                    let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_0: size_t = buf_size
                                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                        .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                    if new_size_0 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_0 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_0) as *mut xmlChar;
                                    if tmp_0.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_0;
                                    buf_size = new_size_0;
                                }
                                let fresh161 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh161 as isize) = '&' as i32 as xmlChar;
                                let fresh162 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh162 as isize) = '#' as i32 as xmlChar;
                                let fresh163 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh163 as isize) = '3' as i32 as xmlChar;
                                let fresh164 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh164 as isize) = '8' as i32 as xmlChar;
                                let fresh165 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh165 as isize) = ';' as i32 as xmlChar;
                            }
                        } else if val != 0 as libc::c_int {
                            if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                > buf_size
                            {
                                let mut tmp_1: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_1: size_t = buf_size
                                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                    .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                if new_size_1 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_1 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_1) as *mut xmlChar;
                                if tmp_1.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_1;
                                buf_size = new_size_1;
                            }
                            len = (len as libc::c_ulong)
                                .wrapping_add(
                                    xmlCopyChar(
                                        0 as libc::c_int,
                                        &mut *buf.offset(len as isize),
                                        val,
                                    ) as libc::c_ulong,
                                ) as size_t as size_t;
                        }
                    } else {
                        ent = xmlParseEntityRef(ctxt);
                        let ref mut fresh166 = (*ctxt).nbentities;
                        *fresh166 = (*fresh166).wrapping_add(1);
                        if !ent.is_null() {
                            let ref mut fresh167 = (*ctxt).nbentities;
                            *fresh167 = (*fresh167)
                                .wrapping_add((*ent).owner as libc::c_ulong);
                        }
                        if !ent.is_null()
                            && (*ent).etype as libc::c_uint
                                == XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int
                                    as libc::c_uint
                        {
                            if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                > buf_size
                            {
                                let mut tmp_2: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_2: size_t = buf_size
                                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                    .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                if new_size_2 < buf_size {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                tmp_2 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_2) as *mut xmlChar;
                                if tmp_2.is_null() {
                                    current_block = 4728557498262148097;
                                    break;
                                }
                                buf = tmp_2;
                                buf_size = new_size_2;
                            }
                            if (*ctxt).replaceEntities == 0 as libc::c_int
                                && *((*ent).content).offset(0 as libc::c_int as isize)
                                    as libc::c_int == '&' as i32
                            {
                                let fresh168 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh168 as isize) = '&' as i32 as xmlChar;
                                let fresh169 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh169 as isize) = '#' as i32 as xmlChar;
                                let fresh170 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh170 as isize) = '3' as i32 as xmlChar;
                                let fresh171 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh171 as isize) = '8' as i32 as xmlChar;
                                let fresh172 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh172 as isize) = ';' as i32 as xmlChar;
                            } else {
                                let fresh173 = len;
                                len = len.wrapping_add(1);
                                *buf
                                    .offset(
                                        fresh173 as isize,
                                    ) = *((*ent).content).offset(0 as libc::c_int as isize);
                            }
                        } else if !ent.is_null()
                                && (*ctxt).replaceEntities != 0 as libc::c_int
                            {
                            if (*ent).etype as libc::c_uint
                                != XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int
                                    as libc::c_uint
                            {
                                let ref mut fresh174 = (*ctxt).depth;
                                *fresh174 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    (*ent).content,
                                    1 as libc::c_int,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                );
                                let ref mut fresh175 = (*ctxt).depth;
                                *fresh175 -= 1;
                                if !rep.is_null() {
                                    current = rep;
                                    while *current as libc::c_int != 0 as libc::c_int {
                                        if *current as libc::c_int == 0xd as libc::c_int
                                            || *current as libc::c_int == 0xa as libc::c_int
                                            || *current as libc::c_int == 0x9 as libc::c_int
                                        {
                                            let fresh176 = len;
                                            len = len.wrapping_add(1);
                                            *buf
                                                .offset(fresh176 as isize) = 0x20 as libc::c_int as xmlChar;
                                            current = current.offset(1);
                                        } else {
                                            let fresh177 = current;
                                            current = current.offset(1);
                                            let fresh178 = len;
                                            len = len.wrapping_add(1);
                                            *buf.offset(fresh178 as isize) = *fresh177;
                                        }
                                        if !(len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                            > buf_size)
                                        {
                                            continue;
                                        }
                                        let mut tmp_3: *mut xmlChar = 0 as *mut xmlChar;
                                        let mut new_size_3: size_t = buf_size
                                            .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                            .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                        if new_size_3 < buf_size {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        tmp_3 = xmlRealloc
                                            .expect(
                                                "non-null function pointer",
                                            )(buf as *mut libc::c_void, new_size_3) as *mut xmlChar;
                                        if tmp_3.is_null() {
                                            current_block = 4728557498262148097;
                                            break 's_99;
                                        }
                                        buf = tmp_3;
                                        buf_size = new_size_3;
                                    }
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(rep as *mut libc::c_void);
                                    rep = 0 as *mut xmlChar;
                                }
                            } else {
                                if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                    > buf_size
                                {
                                    let mut tmp_4: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_4: size_t = buf_size
                                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                        .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                    if new_size_4 < buf_size {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    tmp_4 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_4) as *mut xmlChar;
                                    if tmp_4.is_null() {
                                        current_block = 4728557498262148097;
                                        break;
                                    }
                                    buf = tmp_4;
                                    buf_size = new_size_4;
                                }
                                if !((*ent).content).is_null() {
                                    let fresh179 = len;
                                    len = len.wrapping_add(1);
                                    *buf
                                        .offset(
                                            fresh179 as isize,
                                        ) = *((*ent).content).offset(0 as libc::c_int as isize);
                                }
                            }
                        } else if !ent.is_null() {
                            let mut i: libc::c_int = xmlStrlen((*ent).name);
                            let mut cur: *const xmlChar = (*ent).name;
                            if (*ent).etype as libc::c_uint
                                != XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int
                                    as libc::c_uint && !((*ent).content).is_null()
                                && (*ent).checked == 0 as libc::c_int
                            {
                                let mut oldnbent: libc::c_ulong = (*ctxt).nbentities;
                                let mut diff: libc::c_ulong = 0;
                                let ref mut fresh180 = (*ctxt).depth;
                                *fresh180 += 1;
                                rep = xmlStringDecodeEntities(
                                    ctxt,
                                    (*ent).content,
                                    1 as libc::c_int,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                );
                                let ref mut fresh181 = (*ctxt).depth;
                                *fresh181 -= 1;
                                diff = ((*ctxt).nbentities)
                                    .wrapping_sub(oldnbent)
                                    .wrapping_add(1 as libc::c_int as libc::c_ulong);
                                if diff
                                    > (2147483647 as libc::c_int / 2 as libc::c_int)
                                        as libc::c_ulong
                                {
                                    diff = (2147483647 as libc::c_int / 2 as libc::c_int)
                                        as libc::c_ulong;
                                }
                                (*ent)
                                    .checked = diff
                                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                    as libc::c_int;
                                if !rep.is_null() {
                                    if !(xmlStrchr(rep, '<' as i32 as xmlChar)).is_null() {
                                        (*ent).checked |= 1 as libc::c_int;
                                    }
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(rep as *mut libc::c_void);
                                    rep = 0 as *mut xmlChar;
                                } else {
                                    *((*ent).content)
                                        .offset(
                                            0 as libc::c_int as isize,
                                        ) = 0 as libc::c_int as xmlChar;
                                }
                            }
                            let fresh182 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh182 as isize) = '&' as i32 as xmlChar;
                            while len
                                .wrapping_add(i as libc::c_ulong)
                                .wrapping_add(10 as libc::c_int as libc::c_ulong) > buf_size
                            {
                                let mut tmp_5: *mut xmlChar = 0 as *mut xmlChar;
                                let mut new_size_5: size_t = buf_size
                                    .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                    .wrapping_add(i as libc::c_ulong)
                                    .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                if new_size_5 < buf_size {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                tmp_5 = xmlRealloc
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void, new_size_5) as *mut xmlChar;
                                if tmp_5.is_null() {
                                    current_block = 4728557498262148097;
                                    break 's_99;
                                }
                                buf = tmp_5;
                                buf_size = new_size_5;
                            }
                            while i > 0 as libc::c_int {
                                let fresh183 = cur;
                                cur = cur.offset(1);
                                let fresh184 = len;
                                len = len.wrapping_add(1);
                                *buf.offset(fresh184 as isize) = *fresh183;
                                i -= 1;
                            }
                            let fresh185 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh185 as isize) = ';' as i32 as xmlChar;
                        }
                    }
                } else {
                    if c == 0x20 as libc::c_int || c == 0xd as libc::c_int
                        || c == 0xa as libc::c_int || c == 0x9 as libc::c_int
                    {
                        if len != 0 as libc::c_int as libc::c_ulong || normalize == 0 {
                            if normalize == 0 || in_space == 0 {
                                if l == 1 as libc::c_int {
                                    let fresh186 = len;
                                    len = len.wrapping_add(1);
                                    *buf
                                        .offset(fresh186 as isize) = 0x20 as libc::c_int as xmlChar;
                                } else {
                                    len = (len as libc::c_ulong)
                                        .wrapping_add(
                                            xmlCopyCharMultiByte(
                                                &mut *buf.offset(len as isize),
                                                0x20 as libc::c_int,
                                            ) as libc::c_ulong,
                                        ) as size_t as size_t;
                                }
                                while len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                                    > buf_size
                                {
                                    let mut tmp_6: *mut xmlChar = 0 as *mut xmlChar;
                                    let mut new_size_6: size_t = buf_size
                                        .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                        .wrapping_add(10 as libc::c_int as libc::c_ulong);
                                    if new_size_6 < buf_size {
                                        current_block = 4728557498262148097;
                                        break 's_99;
                                    }
                                    tmp_6 = xmlRealloc
                                        .expect(
                                            "non-null function pointer",
                                        )(buf as *mut libc::c_void, new_size_6) as *mut xmlChar;
                                    if tmp_6.is_null() {
                                        current_block = 4728557498262148097;
                                        break 's_99;
                                    }
                                    buf = tmp_6;
                                    buf_size = new_size_6;
                                }
                            }
                            in_space = 1 as libc::c_int;
                        }
                    } else {
                        in_space = 0 as libc::c_int;
                        if l == 1 as libc::c_int {
                            let fresh187 = len;
                            len = len.wrapping_add(1);
                            *buf.offset(fresh187 as isize) = c as xmlChar;
                        } else {
                            len = (len as libc::c_ulong)
                                .wrapping_add(
                                    xmlCopyCharMultiByte(&mut *buf.offset(len as isize), c)
                                        as libc::c_ulong,
                                ) as size_t as size_t;
                        }
                        if len.wrapping_add(10 as libc::c_int as libc::c_ulong)
                            > buf_size
                        {
                            let mut tmp_7: *mut xmlChar = 0 as *mut xmlChar;
                            let mut new_size_7: size_t = buf_size
                                .wrapping_mul(2 as libc::c_int as libc::c_ulong)
                                .wrapping_add(10 as libc::c_int as libc::c_ulong);
                            if new_size_7 < buf_size {
                                current_block = 4728557498262148097;
                                break;
                            }
                            tmp_7 = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void, new_size_7) as *mut xmlChar;
                            if tmp_7.is_null() {
                                current_block = 4728557498262148097;
                                break;
                            }
                            buf = tmp_7;
                            buf_size = new_size_7;
                        }
                    }
                    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                        let ref mut fresh188 = (*(*ctxt).input).line;
                        *fresh188 += 1;
                        (*(*ctxt).input).col = 1 as libc::c_int;
                    } else {
                        let ref mut fresh189 = (*(*ctxt).input).col;
                        *fresh189 += 1;
                    }
                    let ref mut fresh190 = (*(*ctxt).input).cur;
                    *fresh190 = (*fresh190).offset(l as isize);
                }
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                c = xmlCurrentChar(ctxt, &mut l);
            }
        }
        match current_block {
            4728557498262148097 => {}
            _ => {
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    current_block = 7833996145497313433;
                } else {
                    if in_space != 0 && normalize != 0 {
                        while len > 0 as libc::c_int as libc::c_ulong
                            && *buf
                                .offset(
                                    len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
                                ) as libc::c_int == 0x20 as libc::c_int
                        {
                            len = len.wrapping_sub(1);
                        }
                    }
                    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
                    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_LT_IN_ATTRIBUTE,
                            0 as *const libc::c_char,
                        );
                    } else if *(*(*ctxt).input).cur as libc::c_int
                            != limit as libc::c_int
                        {
                        if c != 0 as libc::c_int
                            && (if c < 0x100 as libc::c_int {
                                (0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                                    || c == 0xd as libc::c_int || 0x20 as libc::c_int <= c)
                                    as libc::c_int
                            } else {
                                (0x100 as libc::c_int <= c && c <= 0xd7ff as libc::c_int
                                    || 0xe000 as libc::c_int <= c && c <= 0xfffd as libc::c_int
                                    || 0x10000 as libc::c_int <= c
                                        && c <= 0x10ffff as libc::c_int) as libc::c_int
                            }) == 0
                        {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_INVALID_CHAR,
                                b"invalid character in attribute value\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                                b"AttValue: ' expected\n\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    } else {
                        xmlNextChar(ctxt);
                    }
                    if len >= 2147483647 as libc::c_int as libc::c_ulong {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ATTRIBUTE_NOT_FINISHED,
                            b"AttValue length too long\n\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        if !attlen.is_null() {
                            *attlen = len as libc::c_int;
                        }
                        return buf;
                    }
                    current_block = 4728557498262148097;
                }
            }
        }
    }
    match current_block {
        4728557498262148097 => {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
        }
        _ => {}
    }
    if !buf.is_null() {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
    }
    if !rep.is_null() {
        xmlFree.expect("non-null function pointer")(rep as *mut libc::c_void);
    }
    return 0 as *mut xmlChar;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttValue(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return 0 as *mut xmlChar;
    }
    return xmlParseAttValueInternal(
        ctxt,
        0 as *mut libc::c_int,
        0 as *mut libc::c_int,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseSystemLiteral(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut stop: xmlChar = 0;
    let mut state: libc::c_int = (*ctxt).instate as libc::c_int;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
        xmlNextChar(ctxt);
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
        xmlNextChar(ctxt);
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_SYSTEM_LITERAL;
    cur = xmlCurrentChar(ctxt, &mut l);
    while (if cur < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
            || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur) as libc::c_int
    } else {
        (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
            as libc::c_int
    }) != 0 && cur != stop as libc::c_int
    {
        if len + 5 as libc::c_int >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 50000 as libc::c_int
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"SystemLiteral\0" as *const u8 as *const libc::c_char,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                (*ctxt).instate = state as xmlParserInputState;
                return 0 as *mut xmlChar;
            }
            size *= 2 as libc::c_int;
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                (size as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                (*ctxt).instate = state as xmlParserInputState;
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        count += 1;
        if count > 50 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            count = 0 as libc::c_int;
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
        }
        if l == 1 as libc::c_int {
            let fresh191 = len;
            len = len + 1;
            *buf.offset(fresh191 as isize) = cur as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh192 = (*(*ctxt).input).line;
            *fresh192 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh193 = (*(*ctxt).input).col;
            *fresh193 += 1;
        }
        let ref mut fresh194 = (*(*ctxt).input).cur;
        *fresh194 = (*fresh194).offset(l as isize);
        cur = xmlCurrentChar(ctxt, &mut l);
        if cur == 0 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            cur = xmlCurrentChar(ctxt, &mut l);
        }
    }
    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    (*ctxt).instate = state as xmlParserInputState;
    if if cur < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
            || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur) as libc::c_int
    } else {
        (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
            as libc::c_int
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const libc::c_char);
    } else {
        xmlNextChar(ctxt);
    }
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePubidLiteral(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut cur: xmlChar = 0;
    let mut stop: xmlChar = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    let mut oldstate: xmlParserInputState = (*ctxt).instate;
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
        xmlNextChar(ctxt);
        stop = '"' as i32 as xmlChar;
    } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
        xmlNextChar(ctxt);
        stop = '\'' as i32 as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_PUBLIC_LITERAL;
    cur = *(*(*ctxt).input).cur;
    while xmlIsPubidChar_tab[cur as usize] as libc::c_int != 0
        && cur as libc::c_int != stop as libc::c_int
    {
        if len + 1 as libc::c_int >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 50000 as libc::c_int
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_NAME_TOO_LONG,
                    b"Public ID\0" as *const u8 as *const libc::c_char,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
            size *= 2 as libc::c_int;
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                (size as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let fresh195 = len;
        len = len + 1;
        *buf.offset(fresh195 as isize) = cur;
        count += 1;
        if count > 50 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            count = 0 as libc::c_int;
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return 0 as *mut xmlChar;
            }
        }
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
        if cur as libc::c_int == 0 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            cur = *(*(*ctxt).input).cur;
        }
    }
    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    if cur as libc::c_int != stop as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_LITERAL_NOT_FINISHED, 0 as *const libc::c_char);
    } else {
        xmlNextChar(ctxt);
    }
    (*ctxt).instate = oldstate;
    return buf;
}
static mut test_char_data: [libc::c_uchar; 256] = [
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x9 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x20 as libc::c_int as libc::c_uchar,
    0x21 as libc::c_int as libc::c_uchar,
    0x22 as libc::c_int as libc::c_uchar,
    0x23 as libc::c_int as libc::c_uchar,
    0x24 as libc::c_int as libc::c_uchar,
    0x25 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x27 as libc::c_int as libc::c_uchar,
    0x28 as libc::c_int as libc::c_uchar,
    0x29 as libc::c_int as libc::c_uchar,
    0x2a as libc::c_int as libc::c_uchar,
    0x2b as libc::c_int as libc::c_uchar,
    0x2c as libc::c_int as libc::c_uchar,
    0x2d as libc::c_int as libc::c_uchar,
    0x2e as libc::c_int as libc::c_uchar,
    0x2f as libc::c_int as libc::c_uchar,
    0x30 as libc::c_int as libc::c_uchar,
    0x31 as libc::c_int as libc::c_uchar,
    0x32 as libc::c_int as libc::c_uchar,
    0x33 as libc::c_int as libc::c_uchar,
    0x34 as libc::c_int as libc::c_uchar,
    0x35 as libc::c_int as libc::c_uchar,
    0x36 as libc::c_int as libc::c_uchar,
    0x37 as libc::c_int as libc::c_uchar,
    0x38 as libc::c_int as libc::c_uchar,
    0x39 as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0x3b as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x3d as libc::c_int as libc::c_uchar,
    0x3e as libc::c_int as libc::c_uchar,
    0x3f as libc::c_int as libc::c_uchar,
    0x40 as libc::c_int as libc::c_uchar,
    0x41 as libc::c_int as libc::c_uchar,
    0x42 as libc::c_int as libc::c_uchar,
    0x43 as libc::c_int as libc::c_uchar,
    0x44 as libc::c_int as libc::c_uchar,
    0x45 as libc::c_int as libc::c_uchar,
    0x46 as libc::c_int as libc::c_uchar,
    0x47 as libc::c_int as libc::c_uchar,
    0x48 as libc::c_int as libc::c_uchar,
    0x49 as libc::c_int as libc::c_uchar,
    0x4a as libc::c_int as libc::c_uchar,
    0x4b as libc::c_int as libc::c_uchar,
    0x4c as libc::c_int as libc::c_uchar,
    0x4d as libc::c_int as libc::c_uchar,
    0x4e as libc::c_int as libc::c_uchar,
    0x4f as libc::c_int as libc::c_uchar,
    0x50 as libc::c_int as libc::c_uchar,
    0x51 as libc::c_int as libc::c_uchar,
    0x52 as libc::c_int as libc::c_uchar,
    0x53 as libc::c_int as libc::c_uchar,
    0x54 as libc::c_int as libc::c_uchar,
    0x55 as libc::c_int as libc::c_uchar,
    0x56 as libc::c_int as libc::c_uchar,
    0x57 as libc::c_int as libc::c_uchar,
    0x58 as libc::c_int as libc::c_uchar,
    0x59 as libc::c_int as libc::c_uchar,
    0x5a as libc::c_int as libc::c_uchar,
    0x5b as libc::c_int as libc::c_uchar,
    0x5c as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0x5e as libc::c_int as libc::c_uchar,
    0x5f as libc::c_int as libc::c_uchar,
    0x60 as libc::c_int as libc::c_uchar,
    0x61 as libc::c_int as libc::c_uchar,
    0x62 as libc::c_int as libc::c_uchar,
    0x63 as libc::c_int as libc::c_uchar,
    0x64 as libc::c_int as libc::c_uchar,
    0x65 as libc::c_int as libc::c_uchar,
    0x66 as libc::c_int as libc::c_uchar,
    0x67 as libc::c_int as libc::c_uchar,
    0x68 as libc::c_int as libc::c_uchar,
    0x69 as libc::c_int as libc::c_uchar,
    0x6a as libc::c_int as libc::c_uchar,
    0x6b as libc::c_int as libc::c_uchar,
    0x6c as libc::c_int as libc::c_uchar,
    0x6d as libc::c_int as libc::c_uchar,
    0x6e as libc::c_int as libc::c_uchar,
    0x6f as libc::c_int as libc::c_uchar,
    0x70 as libc::c_int as libc::c_uchar,
    0x71 as libc::c_int as libc::c_uchar,
    0x72 as libc::c_int as libc::c_uchar,
    0x73 as libc::c_int as libc::c_uchar,
    0x74 as libc::c_int as libc::c_uchar,
    0x75 as libc::c_int as libc::c_uchar,
    0x76 as libc::c_int as libc::c_uchar,
    0x77 as libc::c_int as libc::c_uchar,
    0x78 as libc::c_int as libc::c_uchar,
    0x79 as libc::c_int as libc::c_uchar,
    0x7a as libc::c_int as libc::c_uchar,
    0x7b as libc::c_int as libc::c_uchar,
    0x7c as libc::c_int as libc::c_uchar,
    0x7d as libc::c_int as libc::c_uchar,
    0x7e as libc::c_int as libc::c_uchar,
    0x7f as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
    0 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub unsafe extern "C" fn xmlParseCharData(
    mut ctxt: xmlParserCtxtPtr,
    mut cdata: libc::c_int,
) {
    let mut current_block: u64;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut nbchar: libc::c_int = 0 as libc::c_int;
    let mut line: libc::c_int = (*(*ctxt).input).line;
    let mut col: libc::c_int = (*(*ctxt).input).col;
    let mut ccol: libc::c_int = 0;
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if cdata == 0 {
        in_0 = (*(*ctxt).input).cur;
        loop {
            while *in_0 as libc::c_int == 0x20 as libc::c_int {
                in_0 = in_0.offset(1);
                let ref mut fresh196 = (*(*ctxt).input).col;
                *fresh196 += 1;
            }
            if *in_0 as libc::c_int == 0xa as libc::c_int {
                loop {
                    let ref mut fresh197 = (*(*ctxt).input).line;
                    *fresh197 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                    in_0 = in_0.offset(1);
                    if !(*in_0 as libc::c_int == 0xa as libc::c_int) {
                        break;
                    }
                }
            } else {
                if *in_0 as libc::c_int == '<' as i32 {
                    nbchar = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                        as libc::c_int;
                    if nbchar > 0 as libc::c_int {
                        let mut tmp: *const xmlChar = (*(*ctxt).input).cur;
                        let ref mut fresh198 = (*(*ctxt).input).cur;
                        *fresh198 = in_0;
                        if !((*ctxt).sax).is_null()
                            && (*(*ctxt).sax).ignorableWhitespace
                                != (*(*ctxt).sax).characters
                        {
                            if areBlanks(ctxt, tmp, nbchar, 1 as libc::c_int) != 0 {
                                if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                                    ((*(*ctxt).sax).ignorableWhitespace)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, tmp, nbchar);
                                }
                            } else {
                                if ((*(*ctxt).sax).characters).is_some() {
                                    ((*(*ctxt).sax).characters)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, tmp, nbchar);
                                }
                                if *(*ctxt).space == -(1 as libc::c_int) {
                                    *(*ctxt).space = -(2 as libc::c_int);
                                }
                            }
                        } else if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).characters).is_some()
                            {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, tmp, nbchar);
                        }
                    }
                    return;
                }
                loop {
                    ccol = (*(*ctxt).input).col;
                    while test_char_data[*in_0 as usize] != 0 {
                        in_0 = in_0.offset(1);
                        ccol += 1;
                    }
                    (*(*ctxt).input).col = ccol;
                    if *in_0 as libc::c_int == 0xa as libc::c_int {
                        loop {
                            let ref mut fresh199 = (*(*ctxt).input).line;
                            *fresh199 += 1;
                            (*(*ctxt).input).col = 1 as libc::c_int;
                            in_0 = in_0.offset(1);
                            if !(*in_0 as libc::c_int == 0xa as libc::c_int) {
                                break;
                            }
                        }
                    } else {
                        if !(*in_0 as libc::c_int == ']' as i32) {
                            break;
                        }
                        if *in_0.offset(1 as libc::c_int as isize) as libc::c_int
                            == ']' as i32
                            && *in_0.offset(2 as libc::c_int as isize) as libc::c_int
                                == '>' as i32
                        {
                            xmlFatalErr(
                                ctxt,
                                XML_ERR_MISPLACED_CDATA_END,
                                0 as *const libc::c_char,
                            );
                            let ref mut fresh200 = (*(*ctxt).input).cur;
                            *fresh200 = in_0.offset(1 as libc::c_int as isize);
                            return;
                        }
                        in_0 = in_0.offset(1);
                        let ref mut fresh201 = (*(*ctxt).input).col;
                        *fresh201 += 1;
                    }
                }
                nbchar = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                    as libc::c_int;
                if nbchar > 0 as libc::c_int {
                    if !((*ctxt).sax).is_null()
                        && (*(*ctxt).sax).ignorableWhitespace
                            != (*(*ctxt).sax).characters
                        && (*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
                            || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                                && *(*(*ctxt).input).cur as libc::c_int
                                    <= 0xa as libc::c_int
                            || *(*(*ctxt).input).cur as libc::c_int
                                == 0xd as libc::c_int)
                    {
                        let mut tmp_0: *const xmlChar = (*(*ctxt).input).cur;
                        let ref mut fresh202 = (*(*ctxt).input).cur;
                        *fresh202 = in_0;
                        if areBlanks(ctxt, tmp_0, nbchar, 0 as libc::c_int) != 0 {
                            if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                                ((*(*ctxt).sax).ignorableWhitespace)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, tmp_0, nbchar);
                            }
                        } else {
                            if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, tmp_0, nbchar);
                            }
                            if *(*ctxt).space == -(1 as libc::c_int) {
                                *(*ctxt).space = -(2 as libc::c_int);
                            }
                        }
                        line = (*(*ctxt).input).line;
                        col = (*(*ctxt).input).col;
                    } else if !((*ctxt).sax).is_null() {
                        if ((*(*ctxt).sax).characters).is_some() {
                            ((*(*ctxt).sax).characters)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, (*(*ctxt).input).cur, nbchar);
                        }
                        line = (*(*ctxt).input).line;
                        col = (*(*ctxt).input).col;
                    }
                    if (*ctxt).instate as libc::c_int
                        != XML_PARSER_CONTENT as libc::c_int
                    {
                        return;
                    }
                }
                let ref mut fresh203 = (*(*ctxt).input).cur;
                *fresh203 = in_0;
                if *in_0 as libc::c_int == 0xd as libc::c_int {
                    in_0 = in_0.offset(1);
                    if *in_0 as libc::c_int == 0xa as libc::c_int {
                        let ref mut fresh204 = (*(*ctxt).input).cur;
                        *fresh204 = in_0;
                        in_0 = in_0.offset(1);
                        let ref mut fresh205 = (*(*ctxt).input).line;
                        *fresh205 += 1;
                        (*(*ctxt).input).col = 1 as libc::c_int;
                        current_block = 1917311967535052937;
                    } else {
                        in_0 = in_0.offset(-1);
                        current_block = 17769492591016358583;
                    }
                } else {
                    current_block = 17769492591016358583;
                }
                match current_block {
                    17769492591016358583 => {
                        if *in_0 as libc::c_int == '<' as i32 {
                            return;
                        }
                        if *in_0 as libc::c_int == '&' as i32 {
                            return;
                        }
                        if (*ctxt).progressive == 0 as libc::c_int
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long
                                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long)
                                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as libc::c_int
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long) < 250 as libc::c_int as libc::c_long
                        {
                            xmlGROW(ctxt);
                        }
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            return;
                        }
                        in_0 = (*(*ctxt).input).cur;
                    }
                    _ => {}
                }
                if !(*in_0 as libc::c_int >= 0x20 as libc::c_int
                    && *in_0 as libc::c_int <= 0x7f as libc::c_int
                    || *in_0 as libc::c_int == 0x9 as libc::c_int
                    || *in_0 as libc::c_int == 0xa as libc::c_int)
                {
                    break;
                }
            }
        }
        nbchar = 0 as libc::c_int;
    }
    (*(*ctxt).input).line = line;
    (*(*ctxt).input).col = col;
    xmlParseCharDataComplex(ctxt, cdata);
}
unsafe extern "C" fn xmlParseCharDataComplex(
    mut ctxt: xmlParserCtxtPtr,
    mut cdata: libc::c_int,
) {
    let mut buf: [xmlChar; 305] = [0; 305];
    let mut nbchar: libc::c_int = 0 as libc::c_int;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    cur = xmlCurrentChar(ctxt, &mut l);
    while cur != '<' as i32 && cur != '&' as i32
        && (if cur < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
                as libc::c_int
        }) != 0
    {
        if cur == ']' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == ']' as i32
            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
                == '>' as i32
        {
            if cdata != 0 {
                break;
            }
            xmlFatalErr(ctxt, XML_ERR_MISPLACED_CDATA_END, 0 as *const libc::c_char);
        }
        if l == 1 as libc::c_int {
            let fresh206 = nbchar;
            nbchar = nbchar + 1;
            buf[fresh206 as usize] = cur as xmlChar;
        } else {
            nbchar
                += xmlCopyCharMultiByte(
                    &mut *buf.as_mut_ptr().offset(nbchar as isize),
                    cur,
                );
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh207 = (*(*ctxt).input).line;
            *fresh207 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh208 = (*(*ctxt).input).col;
            *fresh208 += 1;
        }
        let ref mut fresh209 = (*(*ctxt).input).cur;
        *fresh209 = (*fresh209).offset(l as isize);
        cur = xmlCurrentChar(ctxt, &mut l);
        if nbchar >= 300 as libc::c_int {
            buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
                if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as libc::c_int) != 0 {
                    if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                        ((*(*ctxt).sax).ignorableWhitespace)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                } else {
                    if ((*(*ctxt).sax).characters).is_some() {
                        ((*(*ctxt).sax).characters)
                            .expect(
                                "non-null function pointer",
                            )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                    }
                    if (*(*ctxt).sax).characters != (*(*ctxt).sax).ignorableWhitespace
                        && *(*ctxt).space == -(1 as libc::c_int)
                    {
                        *(*ctxt).space = -(2 as libc::c_int);
                    }
                }
            }
            nbchar = 0 as libc::c_int;
            if (*ctxt).instate as libc::c_int != XML_PARSER_CONTENT as libc::c_int {
                return;
            }
        }
        count += 1;
        if count > 50 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            count = 0 as libc::c_int;
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return;
            }
        }
    }
    if nbchar != 0 as libc::c_int {
        buf[nbchar as usize] = 0 as libc::c_int as xmlChar;
        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
            if areBlanks(ctxt, buf.as_mut_ptr(), nbchar, 0 as libc::c_int) != 0 {
                if ((*(*ctxt).sax).ignorableWhitespace).is_some() {
                    ((*(*ctxt).sax).ignorableWhitespace)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
            } else {
                if ((*(*ctxt).sax).characters).is_some() {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, buf.as_mut_ptr(), nbchar);
                }
                if (*(*ctxt).sax).characters != (*(*ctxt).sax).ignorableWhitespace
                    && *(*ctxt).space == -(1 as libc::c_int)
                {
                    *(*ctxt).space = -(2 as libc::c_int);
                }
            }
        }
    }
    if cur != 0 as libc::c_int
        && (if cur < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                as libc::c_int
        } else {
            (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
                as libc::c_int
        }) == 0
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"PCDATA invalid Char value %d\n\0" as *const u8 as *const libc::c_char,
            cur,
        );
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh210 = (*(*ctxt).input).line;
            *fresh210 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh211 = (*(*ctxt).input).col;
            *fresh211 += 1;
        }
        let ref mut fresh212 = (*(*ctxt).input).cur;
        *fresh212 = (*fresh212).offset(l as isize);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalID(
    mut ctxt: xmlParserCtxtPtr,
    mut publicID: *mut *mut xmlChar,
    mut strict: libc::c_int,
) -> *mut xmlChar {
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    *publicID = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 'S' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'Y' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'S' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'M' as i32
    {
        let ref mut fresh213 = (*(*ctxt).input).cur;
        *fresh213 = (*fresh213).offset(6 as libc::c_int as isize);
        (*(*ctxt).input).col += 6 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'SYSTEM'\n\0" as *const u8 as *const libc::c_char,
            );
        }
        URI = xmlParseSystemLiteral(ctxt);
        if URI.is_null() {
            xmlFatalErr(ctxt, XML_ERR_URI_REQUIRED, 0 as *const libc::c_char);
        }
    } else if *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(0 as libc::c_int as isize) as libc::c_int == 'P' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(1 as libc::c_int as isize) as libc::c_int == 'U' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(2 as libc::c_int as isize) as libc::c_int == 'B' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(3 as libc::c_int as isize) as libc::c_int == 'L' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(4 as libc::c_int as isize) as libc::c_int == 'I' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(5 as libc::c_int as isize) as libc::c_int == 'C' as i32
        {
        let ref mut fresh214 = (*(*ctxt).input).cur;
        *fresh214 = (*fresh214).offset(6 as libc::c_int as isize);
        (*(*ctxt).input).col += 6 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'PUBLIC'\n\0" as *const u8 as *const libc::c_char,
            );
        }
        *publicID = xmlParsePubidLiteral(ctxt);
        if (*publicID).is_null() {
            xmlFatalErr(ctxt, XML_ERR_PUBID_REQUIRED, 0 as *const libc::c_char);
        }
        if strict != 0 {
            if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required after the Public Identifier\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
        } else {
            if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                return 0 as *mut xmlChar;
            }
            if *(*(*ctxt).input).cur as libc::c_int != '\'' as i32
                && *(*(*ctxt).input).cur as libc::c_int != '"' as i32
            {
                return 0 as *mut xmlChar;
            }
        }
        URI = xmlParseSystemLiteral(ctxt);
        if URI.is_null() {
            xmlFatalErr(ctxt, XML_ERR_URI_REQUIRED, 0 as *const libc::c_char);
        }
    }
    return URI;
}
unsafe extern "C" fn xmlParseCommentComplex(
    mut ctxt: xmlParserCtxtPtr,
    mut buf: *mut xmlChar,
    mut len: size_t,
    mut size: size_t,
) {
    let mut q: libc::c_int = 0;
    let mut ql: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut rl: libc::c_int = 0;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut count: size_t = 0 as libc::c_int as size_t;
    let mut inputid: libc::c_int = 0;
    inputid = (*(*ctxt).input).id;
    if buf.is_null() {
        len = 0 as libc::c_int as size_t;
        size = 100 as libc::c_int as size_t;
        buf = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(size.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
            as *mut xmlChar;
        if buf.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return;
        }
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    q = xmlCurrentChar(ctxt, &mut ql);
    if !(q == 0 as libc::c_int) {
        if if q < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= q && q <= 0xa as libc::c_int
                || q == 0xd as libc::c_int || 0x20 as libc::c_int <= q) as libc::c_int
        } else {
            (0x100 as libc::c_int <= q && q <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= q && q <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= q && q <= 0x10ffff as libc::c_int)
                as libc::c_int
        } == 0
        {
            xmlFatalErrMsgInt(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                    as *const libc::c_char,
                q,
            );
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
            return;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh215 = (*(*ctxt).input).line;
            *fresh215 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh216 = (*(*ctxt).input).col;
            *fresh216 += 1;
        }
        let ref mut fresh217 = (*(*ctxt).input).cur;
        *fresh217 = (*fresh217).offset(ql as isize);
        r = xmlCurrentChar(ctxt, &mut rl);
        if !(r == 0 as libc::c_int) {
            if if r < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= r && r <= 0xa as libc::c_int
                    || r == 0xd as libc::c_int || 0x20 as libc::c_int <= r)
                    as libc::c_int
            } else {
                (0x100 as libc::c_int <= r && r <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= r && r <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= r && r <= 0x10ffff as libc::c_int)
                    as libc::c_int
            } == 0
            {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_INVALID_CHAR,
                    b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                        as *const libc::c_char,
                    q,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                let ref mut fresh218 = (*(*ctxt).input).line;
                *fresh218 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
            } else {
                let ref mut fresh219 = (*(*ctxt).input).col;
                *fresh219 += 1;
            }
            let ref mut fresh220 = (*(*ctxt).input).cur;
            *fresh220 = (*fresh220).offset(rl as isize);
            cur = xmlCurrentChar(ctxt, &mut l);
            if !(cur == 0 as libc::c_int) {
                while (if cur < 0x100 as libc::c_int {
                    (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                        || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                        as libc::c_int
                } else {
                    (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                        || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                        || 0x10000 as libc::c_int <= cur
                            && cur <= 0x10ffff as libc::c_int) as libc::c_int
                }) != 0 && (cur != '>' as i32 || r != '-' as i32 || q != '-' as i32)
                {
                    if r == '-' as i32 && q == '-' as i32 {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            0 as *const libc::c_char,
                        );
                    }
                    if len > 10000000 as libc::c_int as libc::c_ulong
                        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                            == 0 as libc::c_int
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_COMMENT_NOT_FINISHED,
                            b"Comment too big found\0" as *const u8
                                as *const libc::c_char,
                            0 as *const xmlChar,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    if len.wrapping_add(5 as libc::c_int as libc::c_ulong) >= size {
                        let mut new_buf: *mut xmlChar = 0 as *mut xmlChar;
                        let mut new_size: size_t = 0;
                        new_size = size.wrapping_mul(2 as libc::c_int as libc::c_ulong);
                        new_buf = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                        if new_buf.is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                            return;
                        }
                        buf = new_buf;
                        size = new_size;
                    }
                    if ql == 1 as libc::c_int {
                        let fresh221 = len;
                        len = len.wrapping_add(1);
                        *buf.offset(fresh221 as isize) = q as xmlChar;
                    } else {
                        len = (len as libc::c_ulong)
                            .wrapping_add(
                                xmlCopyCharMultiByte(&mut *buf.offset(len as isize), q)
                                    as libc::c_ulong,
                            ) as size_t as size_t;
                    }
                    q = r;
                    ql = rl;
                    r = cur;
                    rl = l;
                    count = count.wrapping_add(1);
                    if count > 50 as libc::c_int as libc::c_ulong {
                        if (*ctxt).progressive == 0 as libc::c_int
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long
                                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long)
                                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as libc::c_int
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long) < 250 as libc::c_int as libc::c_long
                        {
                            xmlGROW(ctxt);
                        }
                        count = 0 as libc::c_int as size_t;
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                            return;
                        }
                    }
                    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                        let ref mut fresh222 = (*(*ctxt).input).line;
                        *fresh222 += 1;
                        (*(*ctxt).input).col = 1 as libc::c_int;
                    } else {
                        let ref mut fresh223 = (*(*ctxt).input).col;
                        *fresh223 += 1;
                    }
                    let ref mut fresh224 = (*(*ctxt).input).cur;
                    *fresh224 = (*fresh224).offset(l as isize);
                    cur = xmlCurrentChar(ctxt, &mut l);
                    if cur == 0 as libc::c_int {
                        if (*ctxt).progressive == 0 as libc::c_int
                            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long
                                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long)
                                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        {
                            xmlSHRINK(ctxt);
                        }
                        if (*ctxt).progressive == 0 as libc::c_int
                            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                as libc::c_long) < 250 as libc::c_int as libc::c_long
                        {
                            xmlGROW(ctxt);
                        }
                        cur = xmlCurrentChar(ctxt, &mut l);
                    }
                }
                *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
                if cur == 0 as libc::c_int {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment not terminated \n<!--%.50s\n\0" as *const u8
                            as *const libc::c_char,
                        buf,
                    );
                } else if if cur < 0x100 as libc::c_int {
                        (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                            || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                            as libc::c_int
                    } else {
                        (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                            || 0xe000 as libc::c_int <= cur
                                && cur <= 0xfffd as libc::c_int
                            || 0x10000 as libc::c_int <= cur
                                && cur <= 0x10ffff as libc::c_int) as libc::c_int
                    } == 0
                    {
                    xmlFatalErrMsgInt(
                        ctxt,
                        XML_ERR_INVALID_CHAR,
                        b"xmlParseComment: invalid xmlChar value %d\n\0" as *const u8
                            as *const libc::c_char,
                        cur,
                    );
                } else {
                    if inputid != (*(*ctxt).input).id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"Comment doesn't start and stop in the same entity\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlNextChar(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some()
                        && (*ctxt).disableSAX == 0
                    {
                        ((*(*ctxt).sax).comment)
                            .expect("non-null function pointer")((*ctxt).userData, buf);
                    }
                }
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
        }
    }
    xmlFatalErrMsgStr(
        ctxt,
        XML_ERR_COMMENT_NOT_FINISHED,
        b"Comment not terminated\n\0" as *const u8 as *const libc::c_char,
        0 as *const xmlChar,
    );
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseComment(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut size: size_t = 100 as libc::c_int as size_t;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut state: xmlParserInputState = XML_PARSER_START;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut nbchar: size_t = 0 as libc::c_int as size_t;
    let mut ccol: libc::c_int = 0;
    let mut inputid: libc::c_int = 0;
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '!' as i32
        || *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
            != '-' as i32
        || *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int
            != '-' as i32
    {
        return;
    }
    state = (*ctxt).instate;
    (*ctxt).instate = XML_PARSER_COMMENT;
    inputid = (*(*ctxt).input).id;
    let ref mut fresh225 = (*(*ctxt).input).cur;
    *fresh225 = (*fresh225).offset(4 as libc::c_int as isize);
    (*(*ctxt).input).col += 4 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    loop {
        if *in_0 as libc::c_int == 0xa as libc::c_int {
            loop {
                let ref mut fresh226 = (*(*ctxt).input).line;
                *fresh226 += 1;
                (*(*ctxt).input).col = 1 as libc::c_int;
                in_0 = in_0.offset(1);
                if !(*in_0 as libc::c_int == 0xa as libc::c_int) {
                    break;
                }
            }
        }
        loop {
            ccol = (*(*ctxt).input).col;
            while *in_0 as libc::c_int > '-' as i32
                && *in_0 as libc::c_int <= 0x7f as libc::c_int
                || *in_0 as libc::c_int >= 0x20 as libc::c_int
                    && (*in_0 as libc::c_int) < '-' as i32
                || *in_0 as libc::c_int == 0x9 as libc::c_int
            {
                in_0 = in_0.offset(1);
                ccol += 1;
            }
            (*(*ctxt).input).col = ccol;
            if *in_0 as libc::c_int == 0xa as libc::c_int {
                loop {
                    let ref mut fresh227 = (*(*ctxt).input).line;
                    *fresh227 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                    in_0 = in_0.offset(1);
                    if !(*in_0 as libc::c_int == 0xa as libc::c_int) {
                        break;
                    }
                }
            } else {
                nbchar = in_0.offset_from((*(*ctxt).input).cur) as libc::c_long
                    as size_t;
                if nbchar > 0 as libc::c_int as libc::c_ulong {
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some() {
                        if buf.is_null() {
                            if *in_0 as libc::c_int == '-' as i32
                                && *in_0.offset(1 as libc::c_int as isize) as libc::c_int
                                    == '-' as i32
                            {
                                size = nbchar
                                    .wrapping_add(1 as libc::c_int as libc::c_ulong);
                            } else {
                                size = (100 as libc::c_int as libc::c_ulong)
                                    .wrapping_add(nbchar);
                            }
                            buf = xmlMallocAtomic
                                .expect(
                                    "non-null function pointer",
                                )(
                                size
                                    .wrapping_mul(
                                        ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                    ),
                            ) as *mut xmlChar;
                            if buf.is_null() {
                                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                                (*ctxt).instate = state;
                                return;
                            }
                            len = 0 as libc::c_int as size_t;
                        } else if len
                                .wrapping_add(nbchar)
                                .wrapping_add(1 as libc::c_int as libc::c_ulong) >= size
                            {
                            let mut new_buf: *mut xmlChar = 0 as *mut xmlChar;
                            size = (size as libc::c_ulong)
                                .wrapping_add(
                                    len
                                        .wrapping_add(nbchar)
                                        .wrapping_add(100 as libc::c_int as libc::c_ulong),
                                ) as size_t as size_t;
                            new_buf = xmlRealloc
                                .expect(
                                    "non-null function pointer",
                                )(
                                buf as *mut libc::c_void,
                                size
                                    .wrapping_mul(
                                        ::std::mem::size_of::<xmlChar>() as libc::c_ulong,
                                    ),
                            ) as *mut xmlChar;
                            if new_buf.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(buf as *mut libc::c_void);
                                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                                (*ctxt).instate = state;
                                return;
                            }
                            buf = new_buf;
                        }
                        memcpy(
                            &mut *buf.offset(len as isize) as *mut xmlChar
                                as *mut libc::c_void,
                            (*(*ctxt).input).cur as *const libc::c_void,
                            nbchar,
                        );
                        len = (len as libc::c_ulong).wrapping_add(nbchar) as size_t
                            as size_t;
                        *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
                    }
                }
                if len > 10000000 as libc::c_int as libc::c_ulong
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErrMsgStr(
                        ctxt,
                        XML_ERR_COMMENT_NOT_FINISHED,
                        b"Comment too big found\0" as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                    );
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return;
                }
                let ref mut fresh228 = (*(*ctxt).input).cur;
                *fresh228 = in_0;
                if *in_0 as libc::c_int == 0xa as libc::c_int {
                    in_0 = in_0.offset(1);
                    let ref mut fresh229 = (*(*ctxt).input).line;
                    *fresh229 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                }
                if *in_0 as libc::c_int == 0xd as libc::c_int {
                    in_0 = in_0.offset(1);
                    if *in_0 as libc::c_int == 0xa as libc::c_int {
                        let ref mut fresh230 = (*(*ctxt).input).cur;
                        *fresh230 = in_0;
                        in_0 = in_0.offset(1);
                        let ref mut fresh231 = (*(*ctxt).input).line;
                        *fresh231 += 1;
                        (*(*ctxt).input).col = 1 as libc::c_int;
                        continue;
                    } else {
                        in_0 = in_0.offset(-1);
                    }
                }
                if (*ctxt).progressive == 0 as libc::c_int
                    && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long
                        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long)
                        < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                {
                    xmlSHRINK(ctxt);
                }
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return;
                }
                in_0 = (*(*ctxt).input).cur;
                if !(*in_0 as libc::c_int == '-' as i32) {
                    break;
                }
                if *in_0.offset(1 as libc::c_int as isize) as libc::c_int == '-' as i32 {
                    if *in_0.offset(2 as libc::c_int as isize) as libc::c_int
                        == '>' as i32
                    {
                        if (*(*ctxt).input).id != inputid {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ENTITY_BOUNDARY,
                                b"comment doesn't start and stop in the same entity\n\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        let ref mut fresh232 = (*(*ctxt).input).cur;
                        *fresh232 = (*fresh232).offset(3 as libc::c_int as isize);
                        (*(*ctxt).input).col += 3 as libc::c_int;
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).comment).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if !buf.is_null() {
                                ((*(*ctxt).sax).comment)
                                    .expect("non-null function pointer")((*ctxt).userData, buf);
                            } else {
                                ((*(*ctxt).sax).comment)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                                );
                            }
                        }
                        if !buf.is_null() {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(buf as *mut libc::c_void);
                        }
                        if (*ctxt).instate as libc::c_int
                            != XML_PARSER_EOF as libc::c_int
                        {
                            (*ctxt).instate = state;
                        }
                        return;
                    }
                    if !buf.is_null() {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            b"Double hyphen within comment: <!--%.50s\n\0" as *const u8
                                as *const libc::c_char,
                            buf,
                        );
                    } else {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_HYPHEN_IN_COMMENT,
                            b"Double hyphen within comment\n\0" as *const u8
                                as *const libc::c_char,
                            0 as *const xmlChar,
                        );
                    }
                    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    in_0 = in_0.offset(1);
                    let ref mut fresh233 = (*(*ctxt).input).col;
                    *fresh233 += 1;
                }
                in_0 = in_0.offset(1);
                let ref mut fresh234 = (*(*ctxt).input).col;
                *fresh234 += 1;
            }
        }
        if !(*in_0 as libc::c_int >= 0x20 as libc::c_int
            && *in_0 as libc::c_int <= 0x7f as libc::c_int
            || *in_0 as libc::c_int == 0x9 as libc::c_int
            || *in_0 as libc::c_int == 0xa as libc::c_int)
        {
            break;
        }
    }
    xmlParseCommentComplex(ctxt, buf, len, size);
    (*ctxt).instate = state;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePITarget(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    name = xmlParseName(ctxt);
    if !name.is_null()
        && (*name.offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
            || *name.offset(0 as libc::c_int as isize) as libc::c_int == 'X' as i32)
        && (*name.offset(1 as libc::c_int as isize) as libc::c_int == 'm' as i32
            || *name.offset(1 as libc::c_int as isize) as libc::c_int == 'M' as i32)
        && (*name.offset(2 as libc::c_int as isize) as libc::c_int == 'l' as i32
            || *name.offset(2 as libc::c_int as isize) as libc::c_int == 'L' as i32)
    {
        let mut i: libc::c_int = 0;
        if *name.offset(0 as libc::c_int as isize) as libc::c_int == 'x' as i32
            && *name.offset(1 as libc::c_int as isize) as libc::c_int == 'm' as i32
            && *name.offset(2 as libc::c_int as isize) as libc::c_int == 'l' as i32
            && *name.offset(3 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_RESERVED_XML_NAME,
                b"XML declaration allowed only at the start of the document\n\0"
                    as *const u8 as *const libc::c_char,
            );
            return name;
        } else {
            if *name.offset(3 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErr(ctxt, XML_ERR_RESERVED_XML_NAME, 0 as *const libc::c_char);
                return name;
            }
        }
        i = 0 as libc::c_int;
        while !(xmlW3CPIs[i as usize]).is_null() {
            if xmlStrEqual(name, xmlW3CPIs[i as usize] as *const xmlChar) != 0 {
                return name;
            }
            i += 1;
        }
        xmlWarningMsg(
            ctxt,
            XML_ERR_RESERVED_XML_NAME,
            b"xmlParsePITarget: invalid name prefix 'xml'\n\0" as *const u8
                as *const libc::c_char,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    if !name.is_null() && !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
        xmlNsErr(
            ctxt,
            XML_NS_ERR_COLON,
            b"colons are forbidden from PI names '%s'\n\0" as *const u8
                as *const libc::c_char,
            name,
            0 as *const xmlChar,
            0 as *const xmlChar,
        );
    }
    return name;
}
unsafe extern "C" fn xmlParseCatalogPI(
    mut ctxt: xmlParserCtxtPtr,
    mut catalog: *const xmlChar,
) {
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut tmp: *const xmlChar = 0 as *const xmlChar;
    let mut base: *const xmlChar = 0 as *const xmlChar;
    let mut marker: xmlChar = 0;
    tmp = catalog;
    while *tmp as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *tmp as libc::c_int
            && *tmp as libc::c_int <= 0xa as libc::c_int
        || *tmp as libc::c_int == 0xd as libc::c_int
    {
        tmp = tmp.offset(1);
    }
    if !(xmlStrncmp(
        tmp,
        b"catalog\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        7 as libc::c_int,
    ) != 0)
    {
        tmp = tmp.offset(7 as libc::c_int as isize);
        while *tmp as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *tmp as libc::c_int
                && *tmp as libc::c_int <= 0xa as libc::c_int
            || *tmp as libc::c_int == 0xd as libc::c_int
        {
            tmp = tmp.offset(1);
        }
        if *tmp as libc::c_int != '=' as i32 {
            return;
        }
        tmp = tmp.offset(1);
        while *tmp as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *tmp as libc::c_int
                && *tmp as libc::c_int <= 0xa as libc::c_int
            || *tmp as libc::c_int == 0xd as libc::c_int
        {
            tmp = tmp.offset(1);
        }
        marker = *tmp;
        if !(marker as libc::c_int != '\'' as i32 && marker as libc::c_int != '"' as i32)
        {
            tmp = tmp.offset(1);
            base = tmp;
            while *tmp as libc::c_int != 0 as libc::c_int
                && *tmp as libc::c_int != marker as libc::c_int
            {
                tmp = tmp.offset(1);
            }
            if !(*tmp as libc::c_int == 0 as libc::c_int) {
                URL = xmlStrndup(
                    base,
                    tmp.offset_from(base) as libc::c_long as libc::c_int,
                );
                tmp = tmp.offset(1);
                while *tmp as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *tmp as libc::c_int
                        && *tmp as libc::c_int <= 0xa as libc::c_int
                    || *tmp as libc::c_int == 0xd as libc::c_int
                {
                    tmp = tmp.offset(1);
                }
                if !(*tmp as libc::c_int != 0 as libc::c_int) {
                    if !URL.is_null() {
                        let ref mut fresh235 = (*ctxt).catalogs;
                        *fresh235 = xmlCatalogAddLocal((*ctxt).catalogs, URL);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(URL as *mut libc::c_void);
                    }
                    return;
                }
            }
        }
    }
    xmlWarningMsg(
        ctxt,
        XML_WAR_CATALOG_PI,
        b"Catalog PI syntax error: %s\n\0" as *const u8 as *const libc::c_char,
        catalog,
        0 as *const xmlChar,
    );
    if !URL.is_null() {
        xmlFree.expect("non-null function pointer")(URL as *mut libc::c_void);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePI(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut size: size_t = 100 as libc::c_int as size_t;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut target: *const xmlChar = 0 as *const xmlChar;
    let mut state: xmlParserInputState = XML_PARSER_START;
    let mut count: libc::c_int = 0 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '?' as i32
    {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        state = (*ctxt).instate;
        (*ctxt).instate = XML_PARSER_PI;
        let ref mut fresh236 = (*(*ctxt).input).cur;
        *fresh236 = (*fresh236).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlSHRINK(ctxt);
        }
        target = xmlParsePITarget(ctxt);
        if !target.is_null() {
            if *(*(*ctxt).input).cur as libc::c_int == '?' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == '>' as i32
            {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
                let ref mut fresh237 = (*(*ctxt).input).cur;
                *fresh237 = (*fresh237).offset(2 as libc::c_int as isize);
                (*(*ctxt).input).col += 2 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).processingInstruction).is_some()
                {
                    ((*(*ctxt).sax).processingInstruction)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, target, 0 as *const xmlChar);
                }
                if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
                    (*ctxt).instate = state;
                }
                return;
            }
            buf = xmlMallocAtomic
                .expect(
                    "non-null function pointer",
                )(size.wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong))
                as *mut xmlChar;
            if buf.is_null() {
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                (*ctxt).instate = state;
                return;
            }
            if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"ParsePI: PI %s space expected\n\0" as *const u8
                        as *const libc::c_char,
                    target,
                );
            }
            cur = xmlCurrentChar(ctxt, &mut l);
            while (if cur < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
                    || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur)
                    as libc::c_int
            } else {
                (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
                    as libc::c_int
            }) != 0
                && (cur != '?' as i32
                    || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int != '>' as i32)
            {
                if len.wrapping_add(5 as libc::c_int as libc::c_ulong) >= size {
                    let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                    let mut new_size: size_t = size
                        .wrapping_mul(2 as libc::c_int as libc::c_ulong);
                    tmp = xmlRealloc
                        .expect(
                            "non-null function pointer",
                        )(buf as *mut libc::c_void, new_size) as *mut xmlChar;
                    if tmp.is_null() {
                        xmlErrMemory(ctxt, 0 as *const libc::c_char);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        (*ctxt).instate = state;
                        return;
                    }
                    buf = tmp;
                    size = new_size;
                }
                count += 1;
                if count > 50 as libc::c_int {
                    if (*ctxt).progressive == 0 as libc::c_int
                        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long
                            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long)
                            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlGROW(ctxt);
                    }
                    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        return;
                    }
                    count = 0 as libc::c_int;
                    if len > 10000000 as libc::c_int as libc::c_ulong
                        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                            == 0 as libc::c_int
                    {
                        xmlFatalErrMsgStr(
                            ctxt,
                            XML_ERR_PI_NOT_FINISHED,
                            b"PI %s too big found\0" as *const u8 as *const libc::c_char,
                            target,
                        );
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(buf as *mut libc::c_void);
                        (*ctxt).instate = state;
                        return;
                    }
                }
                if l == 1 as libc::c_int {
                    let fresh238 = len;
                    len = len.wrapping_add(1);
                    *buf.offset(fresh238 as isize) = cur as xmlChar;
                } else {
                    len = (len as libc::c_ulong)
                        .wrapping_add(
                            xmlCopyCharMultiByte(&mut *buf.offset(len as isize), cur)
                                as libc::c_ulong,
                        ) as size_t as size_t;
                }
                if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                    let ref mut fresh239 = (*(*ctxt).input).line;
                    *fresh239 += 1;
                    (*(*ctxt).input).col = 1 as libc::c_int;
                } else {
                    let ref mut fresh240 = (*(*ctxt).input).col;
                    *fresh240 += 1;
                }
                let ref mut fresh241 = (*(*ctxt).input).cur;
                *fresh241 = (*fresh241).offset(l as isize);
                cur = xmlCurrentChar(ctxt, &mut l);
                if cur == 0 as libc::c_int {
                    if (*ctxt).progressive == 0 as libc::c_int
                        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long
                            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long)
                            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                    {
                        xmlSHRINK(ctxt);
                    }
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlGROW(ctxt);
                    }
                    cur = xmlCurrentChar(ctxt, &mut l);
                }
            }
            if len > 10000000 as libc::c_int as libc::c_ulong
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"PI %s too big found\0" as *const u8 as *const libc::c_char,
                    target,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                (*ctxt).instate = state;
                return;
            }
            *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
            if cur != '?' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_PI_NOT_FINISHED,
                    b"ParsePI: PI %s never end ...\n\0" as *const u8
                        as *const libc::c_char,
                    target,
                );
            } else {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"PI declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
                let ref mut fresh242 = (*(*ctxt).input).cur;
                *fresh242 = (*fresh242).offset(2 as libc::c_int as isize);
                (*(*ctxt).input).col += 2 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                if (state as libc::c_int == XML_PARSER_MISC as libc::c_int
                    || state as libc::c_int == XML_PARSER_START as libc::c_int)
                    && xmlStrEqual(
                        target,
                        b"oasis-xml-catalog\0" as *const u8 as *const libc::c_char
                            as *const xmlChar,
                    ) != 0
                {
                    let mut allow: xmlCatalogAllow = xmlCatalogGetDefaults();
                    if allow as libc::c_uint
                        == XML_CATA_ALLOW_DOCUMENT as libc::c_int as libc::c_uint
                        || allow as libc::c_uint
                            == XML_CATA_ALLOW_ALL as libc::c_int as libc::c_uint
                    {
                        xmlParseCatalogPI(ctxt, buf);
                    }
                }
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).processingInstruction).is_some()
                {
                    ((*(*ctxt).sax).processingInstruction)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, target, buf);
                }
            }
            xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        } else {
            xmlFatalErr(ctxt, XML_ERR_PI_NOT_STARTED, 0 as *const libc::c_char);
        }
        if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
            (*ctxt).instate = state;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNotationDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut Pubid: *mut xmlChar = 0 as *mut xmlChar;
    let mut Systemid: *mut xmlChar = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'N' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'O' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'O' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(9 as libc::c_int as isize) as libc::c_int == 'N' as i32
    {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        if (*ctxt).progressive == 0 as libc::c_int
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlSHRINK(ctxt);
        }
        let ref mut fresh243 = (*(*ctxt).input).cur;
        *fresh243 = (*fresh243).offset(10 as libc::c_int as isize);
        (*(*ctxt).input).col += 10 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!NOTATION'\n\0" as *const u8
                    as *const libc::c_char,
            );
            return;
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const libc::c_char);
            return;
        }
        if !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from notation names '%s'\n\0" as *const u8
                    as *const libc::c_char,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the NOTATION name'\n\0" as *const u8
                    as *const libc::c_char,
            );
            return;
        }
        Systemid = xmlParseExternalID(ctxt, &mut Pubid, 0 as libc::c_int);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Notation declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            xmlNextChar(ctxt);
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).notationDecl).is_some()
            {
                ((*(*ctxt).sax).notationDecl)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, Pubid, Systemid);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const libc::c_char);
        }
        if !Systemid.is_null() {
            xmlFree.expect("non-null function pointer")(Systemid as *mut libc::c_void);
        }
        if !Pubid.is_null() {
            xmlFree.expect("non-null function pointer")(Pubid as *mut libc::c_void);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut literal: *mut xmlChar = 0 as *mut xmlChar;
    let mut ndata: *const xmlChar = 0 as *const xmlChar;
    let mut isParameter: libc::c_int = 0 as libc::c_int;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'N' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'Y' as i32
    {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        if (*ctxt).progressive == 0 as libc::c_int
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlSHRINK(ctxt);
        }
        let ref mut fresh244 = (*(*ctxt).input).cur;
        *fresh244 = (*fresh244).offset(8 as libc::c_int as isize);
        (*(*ctxt).input).col += 8 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ENTITY'\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
        if *(*(*ctxt).input).cur as libc::c_int == '%' as i32 {
            xmlNextChar(ctxt);
            if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required after '%%'\n\0" as *const u8 as *const libc::c_char,
                );
            }
            isParameter = 1 as libc::c_int;
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"xmlParseEntityDecl: no name\n\0" as *const u8 as *const libc::c_char,
            );
            return;
        }
        if !(xmlStrchr(name, ':' as i32 as xmlChar)).is_null() {
            xmlNsErr(
                ctxt,
                XML_NS_ERR_COLON,
                b"colons are forbidden from entities names '%s'\n\0" as *const u8
                    as *const libc::c_char,
                name,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the entity name\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
        (*ctxt).instate = XML_PARSER_ENTITY_DECL;
        if isParameter != 0 {
            if *(*(*ctxt).input).cur as libc::c_int == '"' as i32
                || *(*(*ctxt).input).cur as libc::c_int == '\'' as i32
            {
                value = xmlParseEntityValue(ctxt, &mut orig);
                if !value.is_null() {
                    if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                        && ((*(*ctxt).sax).entityDecl).is_some()
                    {
                        ((*(*ctxt).sax).entityDecl)
                            .expect(
                                "non-null function pointer",
                            )(
                            (*ctxt).userData,
                            name,
                            XML_INTERNAL_PARAMETER_ENTITY as libc::c_int,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            value,
                        );
                    }
                }
            } else {
                URI = xmlParseExternalID(ctxt, &mut literal, 1 as libc::c_int);
                if URI.is_null() && literal.is_null() {
                    xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const libc::c_char);
                }
                if !URI.is_null() {
                    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
                    uri = xmlParseURI(URI as *const libc::c_char);
                    if uri.is_null() {
                        xmlErrMsgStr(
                            ctxt,
                            XML_ERR_INVALID_URI,
                            b"Invalid URI: %s\n\0" as *const u8 as *const libc::c_char,
                            URI,
                        );
                    } else {
                        if !((*uri).fragment).is_null() {
                            xmlFatalErr(
                                ctxt,
                                XML_ERR_URI_FRAGMENT,
                                0 as *const libc::c_char,
                            );
                        } else if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).entityDecl).is_some()
                            {
                            ((*(*ctxt).sax).entityDecl)
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*ctxt).userData,
                                name,
                                XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int,
                                literal,
                                URI,
                                0 as *mut xmlChar,
                            );
                        }
                        xmlFreeURI(uri);
                    }
                }
            }
        } else if *(*(*ctxt).input).cur as libc::c_int == '"' as i32
                || *(*(*ctxt).input).cur as libc::c_int == '\'' as i32
            {
            value = xmlParseEntityValue(ctxt, &mut orig);
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).entityDecl).is_some()
            {
                ((*(*ctxt).sax).entityDecl)
                    .expect(
                        "non-null function pointer",
                    )(
                    (*ctxt).userData,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as libc::c_int,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                );
            }
            if ((*ctxt).myDoc).is_null()
                || xmlStrEqual(
                    (*(*ctxt).myDoc).version,
                    b"SAX compatibility mode document\0" as *const u8
                        as *const libc::c_char as *mut xmlChar,
                ) != 0
            {
                if ((*ctxt).myDoc).is_null() {
                    let ref mut fresh245 = (*ctxt).myDoc;
                    *fresh245 = xmlNewDoc(
                        b"SAX compatibility mode document\0" as *const u8
                            as *const libc::c_char as *mut xmlChar,
                    );
                    if ((*ctxt).myDoc).is_null() {
                        xmlErrMemory(
                            ctxt,
                            b"New Doc failed\0" as *const u8 as *const libc::c_char,
                        );
                        return;
                    }
                    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as libc::c_int;
                }
                if ((*(*ctxt).myDoc).intSubset).is_null() {
                    let ref mut fresh246 = (*(*ctxt).myDoc).intSubset;
                    *fresh246 = xmlNewDtd(
                        (*ctxt).myDoc,
                        b"fake\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                }
                xmlSAX2EntityDecl(
                    ctxt as *mut libc::c_void,
                    name,
                    XML_INTERNAL_GENERAL_ENTITY as libc::c_int,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                    value,
                );
            }
        } else {
            URI = xmlParseExternalID(ctxt, &mut literal, 1 as libc::c_int);
            if URI.is_null() && literal.is_null() {
                xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, 0 as *const libc::c_char);
            }
            if !URI.is_null() {
                let mut uri_0: xmlURIPtr = 0 as *mut xmlURI;
                uri_0 = xmlParseURI(URI as *const libc::c_char);
                if uri_0.is_null() {
                    xmlErrMsgStr(
                        ctxt,
                        XML_ERR_INVALID_URI,
                        b"Invalid URI: %s\n\0" as *const u8 as *const libc::c_char,
                        URI,
                    );
                } else {
                    if !((*uri_0).fragment).is_null() {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_URI_FRAGMENT,
                            0 as *const libc::c_char,
                        );
                    }
                    xmlFreeURI(uri_0);
                }
            }
            if *(*(*ctxt).input).cur as libc::c_int != '>' as i32
                && xmlSkipBlankChars(ctxt) == 0 as libc::c_int
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_SPACE_REQUIRED,
                    b"Space required before 'NDATA'\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == 'N' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == 'D' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == 'A' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == 'T' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(4 as libc::c_int as isize) as libc::c_int == 'A' as i32
            {
                let ref mut fresh247 = (*(*ctxt).input).cur;
                *fresh247 = (*fresh247).offset(5 as libc::c_int as isize);
                (*(*ctxt).input).col += 5 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after 'NDATA'\n\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                ndata = xmlParseName(ctxt);
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).unparsedEntityDecl).is_some()
                {
                    ((*(*ctxt).sax).unparsedEntityDecl)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, name, literal, URI, ndata);
                }
            } else {
                if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                    && ((*(*ctxt).sax).entityDecl).is_some()
                {
                    ((*(*ctxt).sax).entityDecl)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*ctxt).userData,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    );
                }
                if (*ctxt).replaceEntities != 0 as libc::c_int
                    && (((*ctxt).myDoc).is_null()
                        || xmlStrEqual(
                            (*(*ctxt).myDoc).version,
                            b"SAX compatibility mode document\0" as *const u8
                                as *const libc::c_char as *mut xmlChar,
                        ) != 0)
                {
                    if ((*ctxt).myDoc).is_null() {
                        let ref mut fresh248 = (*ctxt).myDoc;
                        *fresh248 = xmlNewDoc(
                            b"SAX compatibility mode document\0" as *const u8
                                as *const libc::c_char as *mut xmlChar,
                        );
                        if ((*ctxt).myDoc).is_null() {
                            xmlErrMemory(
                                ctxt,
                                b"New Doc failed\0" as *const u8 as *const libc::c_char,
                            );
                            return;
                        }
                        (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as libc::c_int;
                    }
                    if ((*(*ctxt).myDoc).intSubset).is_null() {
                        let ref mut fresh249 = (*(*ctxt).myDoc).intSubset;
                        *fresh249 = xmlNewDtd(
                            (*ctxt).myDoc,
                            b"fake\0" as *const u8 as *const libc::c_char
                                as *mut xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                    xmlSAX2EntityDecl(
                        ctxt as *mut libc::c_void,
                        name,
                        XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int,
                        literal,
                        URI,
                        0 as *mut xmlChar,
                    );
                }
            }
        }
        if !((*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int) {
            xmlSkipBlankChars(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_NOT_FINISHED,
                    b"xmlParseEntityDecl: entity %s not terminated\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
                xmlHaltParser(ctxt);
            } else {
                if inputid != (*(*ctxt).input).id {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ENTITY_BOUNDARY,
                        b"Entity declaration doesn't start and stop in the same entity\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
                xmlNextChar(ctxt);
            }
            if !orig.is_null() {
                let mut cur: xmlEntityPtr = 0 as xmlEntityPtr;
                if isParameter != 0 {
                    if !((*ctxt).sax).is_null()
                        && ((*(*ctxt).sax).getParameterEntity).is_some()
                    {
                        cur = ((*(*ctxt).sax).getParameterEntity)
                            .expect("non-null function pointer")((*ctxt).userData, name);
                    }
                } else {
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getEntity).is_some() {
                        cur = ((*(*ctxt).sax).getEntity)
                            .expect("non-null function pointer")((*ctxt).userData, name);
                    }
                    if cur.is_null() && (*ctxt).userData == ctxt as *mut libc::c_void {
                        cur = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
                    }
                }
                if !cur.is_null() && ((*cur).orig).is_null() {
                    let ref mut fresh250 = (*cur).orig;
                    *fresh250 = orig;
                    orig = 0 as *mut xmlChar;
                }
            }
        }
        if !value.is_null() {
            xmlFree.expect("non-null function pointer")(value as *mut libc::c_void);
        }
        if !URI.is_null() {
            xmlFree.expect("non-null function pointer")(URI as *mut libc::c_void);
        }
        if !literal.is_null() {
            xmlFree.expect("non-null function pointer")(literal as *mut libc::c_void);
        }
        if !orig.is_null() {
            xmlFree.expect("non-null function pointer")(orig as *mut libc::c_void);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDefaultDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *mut *mut xmlChar,
) -> libc::c_int {
    let mut val: libc::c_int = 0;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    *value = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '#' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'R' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'Q' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'U' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'R' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'D' as i32
    {
        let ref mut fresh251 = (*(*ctxt).input).cur;
        *fresh251 = (*fresh251).offset(9 as libc::c_int as isize);
        (*(*ctxt).input).col += 9 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        return XML_ATTRIBUTE_REQUIRED as libc::c_int;
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '#' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'M' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'P' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'L' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'D' as i32
    {
        let ref mut fresh252 = (*(*ctxt).input).cur;
        *fresh252 = (*fresh252).offset(8 as libc::c_int as isize);
        (*(*ctxt).input).col += 8 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        return XML_ATTRIBUTE_IMPLIED as libc::c_int;
    }
    val = XML_ATTRIBUTE_NONE as libc::c_int;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '#' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'F' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'X' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'D' as i32
    {
        let ref mut fresh253 = (*(*ctxt).input).cur;
        *fresh253 = (*fresh253).offset(6 as libc::c_int as isize);
        (*(*ctxt).input).col += 6 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        val = XML_ATTRIBUTE_FIXED as libc::c_int;
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '#FIXED'\n\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    ret = xmlParseAttValue(ctxt);
    (*ctxt).instate = XML_PARSER_DTD;
    if ret.is_null() {
        xmlFatalErrMsg(
            ctxt,
            (*ctxt).errNo as xmlParserErrors,
            b"Attribute default value declaration error\n\0" as *const u8
                as *const libc::c_char,
        );
    } else {
        *value = ret;
    }
    return val;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseNotationType(
    mut ctxt: xmlParserCtxtPtr,
) -> xmlEnumerationPtr {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ret: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut last: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut cur: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    let mut tmp: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if *(*(*ctxt).input).cur as libc::c_int != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as xmlEnumerationPtr;
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    loop {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"Name expected in NOTATION declaration\n\0" as *const u8
                    as *const libc::c_char,
            );
            xmlFreeEnumeration(ret);
            return 0 as xmlEnumerationPtr;
        }
        tmp = ret;
        while !tmp.is_null() {
            if xmlStrEqual(name, (*tmp).name) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute notation value token %s duplicated\n\0"
                        as *const u8 as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                );
                if xmlDictOwns((*ctxt).dict, name) == 0 {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(name as *mut xmlChar as *mut libc::c_void);
                }
                break;
            } else {
                tmp = (*tmp).next;
            }
        }
        if tmp.is_null() {
            cur = xmlCreateEnumeration(name);
            if cur.is_null() {
                xmlFreeEnumeration(ret);
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let ref mut fresh254 = (*last).next;
                *fresh254 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !(*(*(*ctxt).input).cur as libc::c_int == '|' as i32) {
            break;
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_NOTATION_NOT_FINISHED, 0 as *const libc::c_char);
        xmlFreeEnumeration(ret);
        return 0 as xmlEnumerationPtr;
    }
    xmlNextChar(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEnumerationType(
    mut ctxt: xmlParserCtxtPtr,
) -> xmlEnumerationPtr {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ret: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut last: xmlEnumerationPtr = 0 as xmlEnumerationPtr;
    let mut cur: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    let mut tmp: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if *(*(*ctxt).input).cur as libc::c_int != '(' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as xmlEnumerationPtr;
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    loop {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        name = xmlParseNmtoken(ctxt);
        if name.is_null() {
            xmlFatalErr(ctxt, XML_ERR_NMTOKEN_REQUIRED, 0 as *const libc::c_char);
            return ret;
        }
        tmp = ret;
        while !tmp.is_null() {
            if xmlStrEqual(name, (*tmp).name) != 0 {
                xmlValidityError(
                    ctxt,
                    XML_DTD_DUP_TOKEN,
                    b"standalone: attribute enumeration value token %s duplicated\n\0"
                        as *const u8 as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                );
                if xmlDictOwns((*ctxt).dict, name) == 0 {
                    xmlFree
                        .expect("non-null function pointer")(name as *mut libc::c_void);
                }
                break;
            } else {
                tmp = (*tmp).next;
            }
        }
        if tmp.is_null() {
            cur = xmlCreateEnumeration(name);
            if xmlDictOwns((*ctxt).dict, name) == 0 {
                xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
            }
            if cur.is_null() {
                xmlFreeEnumeration(ret);
                return 0 as xmlEnumerationPtr;
            }
            if last.is_null() {
                last = cur;
                ret = last;
            } else {
                let ref mut fresh255 = (*last).next;
                *fresh255 = cur;
                last = cur;
            }
        }
        xmlSkipBlankChars(ctxt);
        if !(*(*(*ctxt).input).cur as libc::c_int == '|' as i32) {
            break;
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int != ')' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTLIST_NOT_FINISHED, 0 as *const libc::c_char);
        return ret;
    }
    xmlNextChar(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEnumeratedType(
    mut ctxt: xmlParserCtxtPtr,
    mut tree: *mut xmlEnumerationPtr,
) -> libc::c_int {
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 'N' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'O' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'O' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'N' as i32
    {
        let ref mut fresh256 = (*(*ctxt).input).cur;
        *fresh256 = (*fresh256).offset(8 as libc::c_int as isize);
        (*(*ctxt).input).col += 8 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'NOTATION'\n\0" as *const u8
                    as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
        *tree = xmlParseNotationType(ctxt);
        if (*tree).is_null() {
            return 0 as libc::c_int;
        }
        return XML_ATTRIBUTE_NOTATION as libc::c_int;
    }
    *tree = xmlParseEnumerationType(ctxt);
    if (*tree).is_null() {
        return 0 as libc::c_int;
    }
    return XML_ATTRIBUTE_ENUMERATION as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttributeType(
    mut ctxt: xmlParserCtxtPtr,
    mut tree: *mut xmlEnumerationPtr,
) -> libc::c_int {
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 'C' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'D' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'A' as i32
    {
        let ref mut fresh257 = (*(*ctxt).input).cur;
        *fresh257 = (*fresh257).offset(5 as libc::c_int as isize);
        (*(*ctxt).input).col += 5 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        return XML_ATTRIBUTE_CDATA as libc::c_int;
    } else {
        if *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(0 as libc::c_int as isize) as libc::c_int == 'I' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(1 as libc::c_int as isize) as libc::c_int == 'D' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(2 as libc::c_int as isize) as libc::c_int == 'R' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(3 as libc::c_int as isize) as libc::c_int == 'E' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(4 as libc::c_int as isize) as libc::c_int == 'F' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(5 as libc::c_int as isize) as libc::c_int == 'S' as i32
        {
            let ref mut fresh258 = (*(*ctxt).input).cur;
            *fresh258 = (*fresh258).offset(6 as libc::c_int as isize);
            (*(*ctxt).input).col += 6 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            return XML_ATTRIBUTE_IDREFS as libc::c_int;
        } else {
            if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == 'I' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == 'D' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == 'R' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == 'E' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(4 as libc::c_int as isize) as libc::c_int == 'F' as i32
            {
                let ref mut fresh259 = (*(*ctxt).input).cur;
                *fresh259 = (*fresh259).offset(5 as libc::c_int as isize);
                (*(*ctxt).input).col += 5 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                return XML_ATTRIBUTE_IDREF as libc::c_int;
            } else {
                if *(*(*ctxt).input).cur as libc::c_int == 'I' as i32
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == 'D' as i32
                {
                    let ref mut fresh260 = (*(*ctxt).input).cur;
                    *fresh260 = (*fresh260).offset(2 as libc::c_int as isize);
                    (*(*ctxt).input).col += 2 as libc::c_int;
                    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                    }
                    return XML_ATTRIBUTE_ID as libc::c_int;
                } else {
                    if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(0 as libc::c_int as isize) as libc::c_int == 'E' as i32
                        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(1 as libc::c_int as isize) as libc::c_int
                            == 'N' as i32
                        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(2 as libc::c_int as isize) as libc::c_int
                            == 'T' as i32
                        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(3 as libc::c_int as isize) as libc::c_int
                            == 'I' as i32
                        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(4 as libc::c_int as isize) as libc::c_int
                            == 'T' as i32
                        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(5 as libc::c_int as isize) as libc::c_int
                            == 'Y' as i32
                    {
                        let ref mut fresh261 = (*(*ctxt).input).cur;
                        *fresh261 = (*fresh261).offset(6 as libc::c_int as isize);
                        (*(*ctxt).input).col += 6 as libc::c_int;
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                        return XML_ATTRIBUTE_ENTITY as libc::c_int;
                    } else {
                        if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                            .offset(0 as libc::c_int as isize) as libc::c_int
                            == 'E' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(1 as libc::c_int as isize) as libc::c_int
                                == 'N' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(2 as libc::c_int as isize) as libc::c_int
                                == 'T' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(3 as libc::c_int as isize) as libc::c_int
                                == 'I' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(4 as libc::c_int as isize) as libc::c_int
                                == 'T' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(5 as libc::c_int as isize) as libc::c_int
                                == 'I' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(6 as libc::c_int as isize) as libc::c_int
                                == 'E' as i32
                            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(7 as libc::c_int as isize) as libc::c_int
                                == 'S' as i32
                        {
                            let ref mut fresh262 = (*(*ctxt).input).cur;
                            *fresh262 = (*fresh262).offset(8 as libc::c_int as isize);
                            (*(*ctxt).input).col += 8 as libc::c_int;
                            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            }
                            return XML_ATTRIBUTE_ENTITIES as libc::c_int;
                        } else {
                            if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                .offset(0 as libc::c_int as isize) as libc::c_int
                                == 'N' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(1 as libc::c_int as isize) as libc::c_int
                                    == 'M' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(2 as libc::c_int as isize) as libc::c_int
                                    == 'T' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(3 as libc::c_int as isize) as libc::c_int
                                    == 'O' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(4 as libc::c_int as isize) as libc::c_int
                                    == 'K' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(5 as libc::c_int as isize) as libc::c_int
                                    == 'E' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(6 as libc::c_int as isize) as libc::c_int
                                    == 'N' as i32
                                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(7 as libc::c_int as isize) as libc::c_int
                                    == 'S' as i32
                            {
                                let ref mut fresh263 = (*(*ctxt).input).cur;
                                *fresh263 = (*fresh263).offset(8 as libc::c_int as isize);
                                (*(*ctxt).input).col += 8 as libc::c_int;
                                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
                                {
                                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                                }
                                return XML_ATTRIBUTE_NMTOKENS as libc::c_int;
                            } else {
                                if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                    .offset(0 as libc::c_int as isize) as libc::c_int
                                    == 'N' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(1 as libc::c_int as isize) as libc::c_int
                                        == 'M' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(2 as libc::c_int as isize) as libc::c_int
                                        == 'T' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(3 as libc::c_int as isize) as libc::c_int
                                        == 'O' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(4 as libc::c_int as isize) as libc::c_int
                                        == 'K' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(5 as libc::c_int as isize) as libc::c_int
                                        == 'E' as i32
                                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                                        .offset(6 as libc::c_int as isize) as libc::c_int
                                        == 'N' as i32
                                {
                                    let ref mut fresh264 = (*(*ctxt).input).cur;
                                    *fresh264 = (*fresh264).offset(7 as libc::c_int as isize);
                                    (*(*ctxt).input).col += 7 as libc::c_int;
                                    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int
                                    {
                                        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                                    }
                                    return XML_ATTRIBUTE_NMTOKEN as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return xmlParseEnumeratedType(ctxt, tree);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttributeListDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut elemName: *const xmlChar = 0 as *const xmlChar;
    let mut attrName: *const xmlChar = 0 as *const xmlChar;
    let mut tree: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'L' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'I' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'S' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'T' as i32
    {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        let ref mut fresh265 = (*(*ctxt).input).cur;
        *fresh265 = (*fresh265).offset(9 as libc::c_int as isize);
        (*(*ctxt).input).col += 9 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after '<!ATTLIST'\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
        elemName = xmlParseName(ctxt);
        if elemName.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"ATTLIST: no name for Element\n\0" as *const u8 as *const libc::c_char,
            );
            return;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        while *(*(*ctxt).input).cur as libc::c_int != '>' as i32
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            let mut type_0: libc::c_int = 0;
            let mut def: libc::c_int = 0;
            let mut defaultValue: *mut xmlChar = 0 as *mut xmlChar;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            tree = 0 as xmlEnumerationPtr;
            attrName = xmlParseName(ctxt);
            if attrName.is_null() {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_NAME_REQUIRED,
                    b"ATTLIST: no name for Attribute\n\0" as *const u8
                        as *const libc::c_char,
                );
                break;
            } else {
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_SPACE_REQUIRED,
                        b"Space required after the attribute name\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    break;
                } else {
                    type_0 = xmlParseAttributeType(ctxt, &mut tree);
                    if type_0 <= 0 as libc::c_int {
                        break;
                    }
                    if (*ctxt).progressive == 0 as libc::c_int
                        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                            as libc::c_long) < 250 as libc::c_int as libc::c_long
                    {
                        xmlGROW(ctxt);
                    }
                    if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_SPACE_REQUIRED,
                            b"Space required after the attribute type\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        if !tree.is_null() {
                            xmlFreeEnumeration(tree);
                        }
                        break;
                    } else {
                        def = xmlParseDefaultDecl(ctxt, &mut defaultValue);
                        if def <= 0 as libc::c_int {
                            if !defaultValue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(defaultValue as *mut libc::c_void);
                            }
                            if !tree.is_null() {
                                xmlFreeEnumeration(tree);
                            }
                            break;
                        } else {
                            if type_0 != XML_ATTRIBUTE_CDATA as libc::c_int
                                && !defaultValue.is_null()
                            {
                                xmlAttrNormalizeSpace(defaultValue, defaultValue);
                            }
                            if (*ctxt).progressive == 0 as libc::c_int
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as libc::c_long) < 250 as libc::c_int as libc::c_long
                            {
                                xmlGROW(ctxt);
                            }
                            if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
                                if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
                                    xmlFatalErrMsg(
                                        ctxt,
                                        XML_ERR_SPACE_REQUIRED,
                                        b"Space required after the attribute default value\n\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                    if !defaultValue.is_null() {
                                        xmlFree
                                            .expect(
                                                "non-null function pointer",
                                            )(defaultValue as *mut libc::c_void);
                                    }
                                    if !tree.is_null() {
                                        xmlFreeEnumeration(tree);
                                    }
                                    break;
                                }
                            }
                            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).attributeDecl).is_some()
                            {
                                ((*(*ctxt).sax).attributeDecl)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    elemName,
                                    attrName,
                                    type_0,
                                    def,
                                    defaultValue,
                                    tree,
                                );
                            } else if !tree.is_null() {
                                xmlFreeEnumeration(tree);
                            }
                            if (*ctxt).sax2 != 0 && !defaultValue.is_null()
                                && def != XML_ATTRIBUTE_IMPLIED as libc::c_int
                                && def != XML_ATTRIBUTE_REQUIRED as libc::c_int
                            {
                                xmlAddDefAttrs(ctxt, elemName, attrName, defaultValue);
                            }
                            if (*ctxt).sax2 != 0 {
                                xmlAddSpecialAttr(ctxt, elemName, attrName, type_0);
                            }
                            if !defaultValue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(defaultValue as *mut libc::c_void);
                            }
                            if (*ctxt).progressive == 0 as libc::c_int
                                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                                    as libc::c_long) < 250 as libc::c_int as libc::c_long
                            {
                                xmlGROW(ctxt);
                            }
                        }
                    }
                }
            }
        }
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Attribute list declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            xmlNextChar(ctxt);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementMixedContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: libc::c_int,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut cur: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut n: xmlElementContentPtr = 0 as *mut xmlElementContent;
    let mut elem: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '#' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'P' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'C' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'D' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'A' as i32
    {
        let ref mut fresh266 = (*(*ctxt).input).cur;
        *fresh266 = (*fresh266).offset(7 as libc::c_int as isize);
        (*(*ctxt).input).col += 7 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlSHRINK(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == ')' as i32 {
            if (*(*ctxt).input).id != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            xmlNextChar(ctxt);
            ret = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            );
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
            if *(*(*ctxt).input).cur as libc::c_int == '*' as i32 {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
                xmlNextChar(ctxt);
            }
            return ret;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '(' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '|' as i32
        {
            cur = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_PCDATA,
            );
            ret = cur;
            if ret.is_null() {
                return 0 as xmlElementContentPtr;
            }
        }
        while *(*(*ctxt).input).cur as libc::c_int == '|' as i32
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            xmlNextChar(ctxt);
            if elem.is_null() {
                ret = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                );
                if ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, cur);
                    return 0 as xmlElementContentPtr;
                }
                let ref mut fresh267 = (*ret).c1;
                *fresh267 = cur;
                if !cur.is_null() {
                    let ref mut fresh268 = (*cur).parent;
                    *fresh268 = ret;
                }
                cur = ret;
            } else {
                n = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    0 as *const xmlChar,
                    XML_ELEMENT_CONTENT_OR,
                );
                if n.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                    return 0 as xmlElementContentPtr;
                }
                let ref mut fresh269 = (*n).c1;
                *fresh269 = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    elem,
                    XML_ELEMENT_CONTENT_ELEMENT,
                );
                if !((*n).c1).is_null() {
                    let ref mut fresh270 = (*(*n).c1).parent;
                    *fresh270 = n;
                }
                let ref mut fresh271 = (*cur).c2;
                *fresh271 = n;
                if !n.is_null() {
                    let ref mut fresh272 = (*n).parent;
                    *fresh272 = cur;
                }
                cur = n;
            }
            xmlSkipBlankChars(ctxt);
            elem = xmlParseName(ctxt);
            if elem.is_null() {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_NAME_REQUIRED,
                    b"xmlParseElementMixedContentDecl : Name expected\n\0" as *const u8
                        as *const libc::c_char,
                );
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
        }
        if *(*(*ctxt).input).cur as libc::c_int == ')' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '*' as i32
        {
            if !elem.is_null() {
                let ref mut fresh273 = (*cur).c2;
                *fresh273 = xmlNewDocElementContent(
                    (*ctxt).myDoc,
                    elem,
                    XML_ELEMENT_CONTENT_ELEMENT,
                );
                if !((*cur).c2).is_null() {
                    let ref mut fresh274 = (*(*cur).c2).parent;
                    *fresh274 = cur;
                }
            }
            if !ret.is_null() {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            }
            if (*(*ctxt).input).id != inputchk {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element content declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            let ref mut fresh275 = (*(*ctxt).input).cur;
            *fresh275 = (*fresh275).offset(2 as libc::c_int as isize);
            (*(*ctxt).input).col += 2 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        } else {
            xmlFreeDocElementContent((*ctxt).myDoc, ret);
            xmlFatalErr(ctxt, XML_ERR_MIXED_NOT_STARTED, 0 as *const libc::c_char);
            return 0 as xmlElementContentPtr;
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_PCDATA_REQUIRED, 0 as *const libc::c_char);
    }
    return ret;
}
unsafe extern "C" fn xmlParseElementChildrenContentDeclPriv(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: libc::c_int,
    mut depth: libc::c_int,
) -> xmlElementContentPtr {
    let mut ret: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut cur: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut last: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut op: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut elem: *const xmlChar = 0 as *const xmlChar;
    let mut type_0: xmlChar = 0 as libc::c_int as xmlChar;
    if depth > 128 as libc::c_int
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        || depth > 2048 as libc::c_int
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_ELEMCONTENT_NOT_FINISHED,
            b"xmlParseElementChildrenContentDecl : depth %d too deep, use XML_PARSE_HUGE\n\0"
                as *const u8 as *const libc::c_char,
            depth,
        );
        return 0 as xmlElementContentPtr;
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '(' as i32 {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        ret = xmlParseElementChildrenContentDeclPriv(
            ctxt,
            inputid,
            depth + 1 as libc::c_int,
        );
        cur = ret;
        if cur.is_null() {
            return 0 as xmlElementContentPtr;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
    } else {
        elem = xmlParseName(ctxt);
        if elem.is_null() {
            xmlFatalErr(ctxt, XML_ERR_ELEMCONTENT_NOT_STARTED, 0 as *const libc::c_char);
            return 0 as xmlElementContentPtr;
        }
        ret = xmlNewDocElementContent((*ctxt).myDoc, elem, XML_ELEMENT_CONTENT_ELEMENT);
        cur = ret;
        if cur.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as xmlElementContentPtr;
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '?' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_OPT;
            xmlNextChar(ctxt);
        } else if *(*(*ctxt).input).cur as libc::c_int == '*' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_MULT;
            xmlNextChar(ctxt);
        } else if *(*(*ctxt).input).cur as libc::c_int == '+' as i32 {
            (*cur).ocur = XML_ELEMENT_CONTENT_PLUS;
            xmlNextChar(ctxt);
        } else {
            (*cur).ocur = XML_ELEMENT_CONTENT_ONCE;
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    while *(*(*ctxt).input).cur as libc::c_int != ')' as i32
        && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
    {
        if *(*(*ctxt).input).cur as libc::c_int == ',' as i32 {
            if type_0 as libc::c_int == 0 as libc::c_int {
                type_0 = *(*(*ctxt).input).cur;
            } else if type_0 as libc::c_int != *(*(*ctxt).input).cur as libc::c_int {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0"
                        as *const u8 as *const libc::c_char,
                    type_0 as libc::c_int,
                );
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlNextChar(ctxt);
            op = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_SEQ,
            );
            if op.is_null() {
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let ref mut fresh276 = (*op).c1;
                *fresh276 = ret;
                if !ret.is_null() {
                    let ref mut fresh277 = (*ret).parent;
                    *fresh277 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let ref mut fresh278 = (*cur).c2;
                *fresh278 = op;
                if !op.is_null() {
                    let ref mut fresh279 = (*op).parent;
                    *fresh279 = cur;
                }
                let ref mut fresh280 = (*op).c1;
                *fresh280 = last;
                if !last.is_null() {
                    let ref mut fresh281 = (*last).parent;
                    *fresh281 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else if *(*(*ctxt).input).cur as libc::c_int == '|' as i32 {
            if type_0 as libc::c_int == 0 as libc::c_int {
                type_0 = *(*(*ctxt).input).cur;
            } else if type_0 as libc::c_int != *(*(*ctxt).input).cur as libc::c_int {
                xmlFatalErrMsgInt(
                    ctxt,
                    XML_ERR_SEPARATOR_REQUIRED,
                    b"xmlParseElementChildrenContentDecl : '%c' expected\n\0"
                        as *const u8 as *const libc::c_char,
                    type_0 as libc::c_int,
                );
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlNextChar(ctxt);
            op = xmlNewDocElementContent(
                (*ctxt).myDoc,
                0 as *const xmlChar,
                XML_ELEMENT_CONTENT_OR,
            );
            if op.is_null() {
                if !last.is_null() && last != ret {
                    xmlFreeDocElementContent((*ctxt).myDoc, last);
                }
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            if last.is_null() {
                let ref mut fresh282 = (*op).c1;
                *fresh282 = ret;
                if !ret.is_null() {
                    let ref mut fresh283 = (*ret).parent;
                    *fresh283 = op;
                }
                cur = op;
                ret = cur;
            } else {
                let ref mut fresh284 = (*cur).c2;
                *fresh284 = op;
                if !op.is_null() {
                    let ref mut fresh285 = (*op).parent;
                    *fresh285 = cur;
                }
                let ref mut fresh286 = (*op).c1;
                *fresh286 = last;
                if !last.is_null() {
                    let ref mut fresh287 = (*last).parent;
                    *fresh287 = op;
                }
                cur = op;
                last = 0 as xmlElementContentPtr;
            }
        } else {
            xmlFatalErr(
                ctxt,
                XML_ERR_ELEMCONTENT_NOT_FINISHED,
                0 as *const libc::c_char,
            );
            if !last.is_null() && last != ret {
                xmlFreeDocElementContent((*ctxt).myDoc, last);
            }
            if !ret.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, ret);
            }
            return 0 as xmlElementContentPtr;
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '(' as i32 {
            let mut inputid_0: libc::c_int = (*(*ctxt).input).id;
            xmlNextChar(ctxt);
            xmlSkipBlankChars(ctxt);
            last = xmlParseElementChildrenContentDeclPriv(
                ctxt,
                inputid_0,
                depth + 1 as libc::c_int,
            );
            if last.is_null() {
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            xmlSkipBlankChars(ctxt);
        } else {
            elem = xmlParseName(ctxt);
            if elem.is_null() {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_ELEMCONTENT_NOT_STARTED,
                    0 as *const libc::c_char,
                );
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            last = xmlNewDocElementContent(
                (*ctxt).myDoc,
                elem,
                XML_ELEMENT_CONTENT_ELEMENT,
            );
            if last.is_null() {
                if !ret.is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, ret);
                }
                return 0 as xmlElementContentPtr;
            }
            if *(*(*ctxt).input).cur as libc::c_int == '?' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_OPT;
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '*' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_MULT;
                xmlNextChar(ctxt);
            } else if *(*(*ctxt).input).cur as libc::c_int == '+' as i32 {
                (*last).ocur = XML_ELEMENT_CONTENT_PLUS;
                xmlNextChar(ctxt);
            } else {
                (*last).ocur = XML_ELEMENT_CONTENT_ONCE;
            }
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
    }
    if !cur.is_null() && !last.is_null() {
        let ref mut fresh288 = (*cur).c2;
        *fresh288 = last;
        if !last.is_null() {
            let ref mut fresh289 = (*last).parent;
            *fresh289 = cur;
        }
    }
    if (*(*ctxt).input).id != inputchk {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_ENTITY_BOUNDARY,
            b"Element content declaration doesn't start and stop in the same entity\n\0"
                as *const u8 as *const libc::c_char,
        );
    }
    xmlNextChar(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '?' as i32 {
        if !ret.is_null() {
            if (*ret).ocur as libc::c_uint
                == XML_ELEMENT_CONTENT_PLUS as libc::c_int as libc::c_uint
                || (*ret).ocur as libc::c_uint
                    == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint
            {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            } else {
                (*ret).ocur = XML_ELEMENT_CONTENT_OPT;
            }
        }
        xmlNextChar(ctxt);
    } else if *(*(*ctxt).input).cur as libc::c_int == '*' as i32 {
        if !ret.is_null() {
            (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            cur = ret;
            while !cur.is_null()
                && (*cur).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
            {
                if !((*cur).c1).is_null()
                    && ((*(*cur).c1).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_OPT as libc::c_int as libc::c_uint
                        || (*(*cur).c1).ocur as libc::c_uint
                            == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint)
                {
                    (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE;
                }
                if !((*cur).c2).is_null()
                    && ((*(*cur).c2).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_OPT as libc::c_int as libc::c_uint
                        || (*(*cur).c2).ocur as libc::c_uint
                            == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint)
                {
                    (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE;
                }
                cur = (*cur).c2;
            }
        }
        xmlNextChar(ctxt);
    } else if *(*(*ctxt).input).cur as libc::c_int == '+' as i32 {
        if !ret.is_null() {
            let mut found: libc::c_int = 0 as libc::c_int;
            if (*ret).ocur as libc::c_uint
                == XML_ELEMENT_CONTENT_OPT as libc::c_int as libc::c_uint
                || (*ret).ocur as libc::c_uint
                    == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint
            {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            } else {
                (*ret).ocur = XML_ELEMENT_CONTENT_PLUS;
            }
            while !cur.is_null()
                && (*cur).type_0 as libc::c_uint
                    == XML_ELEMENT_CONTENT_OR as libc::c_int as libc::c_uint
            {
                if !((*cur).c1).is_null()
                    && ((*(*cur).c1).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_OPT as libc::c_int as libc::c_uint
                        || (*(*cur).c1).ocur as libc::c_uint
                            == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint)
                {
                    (*(*cur).c1).ocur = XML_ELEMENT_CONTENT_ONCE;
                    found = 1 as libc::c_int;
                }
                if !((*cur).c2).is_null()
                    && ((*(*cur).c2).ocur as libc::c_uint
                        == XML_ELEMENT_CONTENT_OPT as libc::c_int as libc::c_uint
                        || (*(*cur).c2).ocur as libc::c_uint
                            == XML_ELEMENT_CONTENT_MULT as libc::c_int as libc::c_uint)
                {
                    (*(*cur).c2).ocur = XML_ELEMENT_CONTENT_ONCE;
                    found = 1 as libc::c_int;
                }
                cur = (*cur).c2;
            }
            if found != 0 {
                (*ret).ocur = XML_ELEMENT_CONTENT_MULT;
            }
        }
        xmlNextChar(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementChildrenContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut inputchk: libc::c_int,
) -> xmlElementContentPtr {
    return xmlParseElementChildrenContentDeclPriv(ctxt, inputchk, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementContentDecl(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut result: *mut xmlElementContentPtr,
) -> libc::c_int {
    let mut tree: xmlElementContentPtr = 0 as xmlElementContentPtr;
    let mut inputid: libc::c_int = (*(*ctxt).input).id;
    let mut res: libc::c_int = 0;
    *result = 0 as xmlElementContentPtr;
    if *(*(*ctxt).input).cur as libc::c_int != '(' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ELEMCONTENT_NOT_STARTED,
            b"xmlParseElementContentDecl : %s '(' expected\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
        return -(1 as libc::c_int);
    }
    xmlNextChar(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '#' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'P' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'C' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'D' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'A' as i32
    {
        tree = xmlParseElementMixedContentDecl(ctxt, inputid);
        res = XML_ELEMENT_TYPE_MIXED as libc::c_int;
    } else {
        tree = xmlParseElementChildrenContentDeclPriv(ctxt, inputid, 1 as libc::c_int);
        res = XML_ELEMENT_TYPE_ELEMENT as libc::c_int;
    }
    xmlSkipBlankChars(ctxt);
    *result = tree;
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElementDecl(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut content: xmlElementContentPtr = 0 as xmlElementContentPtr;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'L' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'M' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'E' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'N' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'T' as i32
    {
        let mut inputid: libc::c_int = (*(*ctxt).input).id;
        let ref mut fresh290 = (*(*ctxt).input).cur;
        *fresh290 = (*fresh290).offset(9 as libc::c_int as isize);
        (*(*ctxt).input).col += 9 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after 'ELEMENT'\n\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        name = xmlParseName(ctxt);
        if name.is_null() {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_NAME_REQUIRED,
                b"xmlParseElementDecl: no name for Element\n\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"Space required after the element name\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
        if *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(0 as libc::c_int as isize) as libc::c_int == 'E' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(1 as libc::c_int as isize) as libc::c_int == 'M' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(2 as libc::c_int as isize) as libc::c_int == 'P' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(3 as libc::c_int as isize) as libc::c_int == 'T' as i32
            && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(4 as libc::c_int as isize) as libc::c_int == 'Y' as i32
        {
            let ref mut fresh291 = (*(*ctxt).input).cur;
            *fresh291 = (*fresh291).offset(5 as libc::c_int as isize);
            (*(*ctxt).input).col += 5 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            ret = XML_ELEMENT_TYPE_EMPTY as libc::c_int;
        } else if *(*(*ctxt).input).cur as libc::c_int == 'A' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == 'N' as i32
                && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                    as libc::c_int == 'Y' as i32
            {
            let ref mut fresh292 = (*(*ctxt).input).cur;
            *fresh292 = (*fresh292).offset(3 as libc::c_int as isize);
            (*(*ctxt).input).col += 3 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            ret = XML_ELEMENT_TYPE_ANY as libc::c_int;
        } else if *(*(*ctxt).input).cur as libc::c_int == '(' as i32 {
            ret = xmlParseElementContentDecl(ctxt, name, &mut content);
        } else {
            if *(*(*ctxt).input).cur as libc::c_int == '%' as i32
                && (*ctxt).external == 0 as libc::c_int
                && (*ctxt).inputNr == 1 as libc::c_int
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_PEREF_IN_INT_SUBSET,
                    b"PEReference: forbidden within markup decl in internal subset\n\0"
                        as *const u8 as *const libc::c_char,
                );
            } else {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ELEMCONTENT_NOT_STARTED,
                    b"xmlParseElementDecl: 'EMPTY', 'ANY' or '(' expected\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            return -(1 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
            xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const libc::c_char);
            if !content.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, content);
            }
        } else {
            if inputid != (*(*ctxt).input).id {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"Element declaration doesn't start and stop in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            xmlNextChar(ctxt);
            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                && ((*(*ctxt).sax).elementDecl).is_some()
            {
                if !content.is_null() {
                    let ref mut fresh293 = (*content).parent;
                    *fresh293 = 0 as *mut _xmlElementContent;
                }
                ((*(*ctxt).sax).elementDecl)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, ret, content);
                if !content.is_null() && ((*content).parent).is_null() {
                    xmlFreeDocElementContent((*ctxt).myDoc, content);
                }
            } else if !content.is_null() {
                xmlFreeDocElementContent((*ctxt).myDoc, content);
            }
        }
    }
    return ret;
}
unsafe extern "C" fn xmlParseConditionalSections(mut ctxt: xmlParserCtxtPtr) {
    let mut inputIds: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut inputIdsSize: size_t = 0 as libc::c_int as size_t;
    let mut depth: size_t = 0 as libc::c_int as size_t;
    's_11: while (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '!' as i32
            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
                == '[' as i32
        {
            let mut id: libc::c_int = (*(*ctxt).input).id;
            let ref mut fresh294 = (*(*ctxt).input).cur;
            *fresh294 = (*fresh294).offset(3 as libc::c_int as isize);
            (*(*ctxt).input).col += 3 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            xmlSkipBlankChars(ctxt);
            if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == 'I' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == 'N' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == 'C' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == 'L' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(4 as libc::c_int as isize) as libc::c_int == 'U' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(5 as libc::c_int as isize) as libc::c_int == 'D' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(6 as libc::c_int as isize) as libc::c_int == 'E' as i32
            {
                let ref mut fresh295 = (*(*ctxt).input).cur;
                *fresh295 = (*fresh295).offset(7 as libc::c_int as isize);
                (*(*ctxt).input).col += 7 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                xmlSkipBlankChars(ctxt);
                if *(*(*ctxt).input).cur as libc::c_int != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const libc::c_char);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (*(*ctxt).input).id != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlNextChar(ctxt);
                    if inputIdsSize <= depth {
                        let mut tmp: *mut libc::c_int = 0 as *mut libc::c_int;
                        inputIdsSize = if inputIdsSize
                            == 0 as libc::c_int as libc::c_ulong
                        {
                            4 as libc::c_int as libc::c_ulong
                        } else {
                            inputIdsSize.wrapping_mul(2 as libc::c_int as libc::c_ulong)
                        };
                        tmp = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            inputIds as *mut libc::c_void,
                            inputIdsSize
                                .wrapping_mul(
                                    ::std::mem::size_of::<libc::c_int>() as libc::c_ulong,
                                ),
                        ) as *mut libc::c_int;
                        if tmp.is_null() {
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                            break;
                        } else {
                            inputIds = tmp;
                        }
                    }
                    *inputIds.offset(depth as isize) = id;
                    depth = depth.wrapping_add(1);
                }
            } else if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(0 as libc::c_int as isize) as libc::c_int == 'I' as i32
                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(1 as libc::c_int as isize) as libc::c_int == 'G' as i32
                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(2 as libc::c_int as isize) as libc::c_int == 'N' as i32
                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(3 as libc::c_int as isize) as libc::c_int == 'O' as i32
                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(4 as libc::c_int as isize) as libc::c_int == 'R' as i32
                    && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                        .offset(5 as libc::c_int as isize) as libc::c_int == 'E' as i32
                {
                let mut state: libc::c_int = 0;
                let mut instate: xmlParserInputState = XML_PARSER_START;
                let mut ignoreDepth: size_t = 0 as libc::c_int as size_t;
                let ref mut fresh296 = (*(*ctxt).input).cur;
                *fresh296 = (*fresh296).offset(6 as libc::c_int as isize);
                (*(*ctxt).input).col += 6 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
                xmlSkipBlankChars(ctxt);
                if *(*(*ctxt).input).cur as libc::c_int != '[' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_CONDSEC_INVALID, 0 as *const libc::c_char);
                    xmlHaltParser(ctxt);
                    break;
                } else {
                    if (*(*ctxt).input).id != id {
                        xmlFatalErrMsg(
                            ctxt,
                            XML_ERR_ENTITY_BOUNDARY,
                            b"All markup of the conditional section is not in the same entity\n\0"
                                as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlNextChar(ctxt);
                    state = (*ctxt).disableSAX;
                    instate = (*ctxt).instate;
                    if (*ctxt).recovery == 0 as libc::c_int {
                        (*ctxt).disableSAX = 1 as libc::c_int;
                    }
                    (*ctxt).instate = XML_PARSER_IGNORE;
                    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
                        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int == '[' as i32
                        {
                            let ref mut fresh297 = (*(*ctxt).input).cur;
                            *fresh297 = (*fresh297).offset(3 as libc::c_int as isize);
                            (*(*ctxt).input).col += 3 as libc::c_int;
                            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            }
                            ignoreDepth = ignoreDepth.wrapping_add(1);
                            if !(ignoreDepth == 0 as libc::c_int as libc::c_ulong) {
                                continue;
                            }
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                            break 's_11;
                        } else if *(*(*ctxt).input).cur as libc::c_int == ']' as i32
                                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                    as libc::c_int == ']' as i32
                                && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                    as libc::c_int == '>' as i32
                            {
                            if ignoreDepth == 0 as libc::c_int as libc::c_ulong {
                                break;
                            }
                            let ref mut fresh298 = (*(*ctxt).input).cur;
                            *fresh298 = (*fresh298).offset(3 as libc::c_int as isize);
                            (*(*ctxt).input).col += 3 as libc::c_int;
                            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            }
                            ignoreDepth = ignoreDepth.wrapping_sub(1);
                        } else {
                            xmlNextChar(ctxt);
                        }
                    }
                    (*ctxt).disableSAX = state;
                    (*ctxt).instate = instate;
                    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_CONDSEC_NOT_FINISHED,
                            0 as *const libc::c_char,
                        );
                        break;
                    } else {
                        if (*(*ctxt).input).id != id {
                            xmlFatalErrMsg(
                                ctxt,
                                XML_ERR_ENTITY_BOUNDARY,
                                b"All markup of the conditional section is not in the same entity\n\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        let ref mut fresh299 = (*(*ctxt).input).cur;
                        *fresh299 = (*fresh299).offset(3 as libc::c_int as isize);
                        (*(*ctxt).input).col += 3 as libc::c_int;
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                    }
                }
            } else {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_CONDSEC_INVALID_KEYWORD,
                    0 as *const libc::c_char,
                );
                xmlHaltParser(ctxt);
                break;
            }
        } else if depth > 0 as libc::c_int as libc::c_ulong
                && *(*(*ctxt).input).cur as libc::c_int == ']' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == ']' as i32
                && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                    as libc::c_int == '>' as i32
            {
            depth = depth.wrapping_sub(1);
            if (*(*ctxt).input).id != *inputIds.offset(depth as isize) {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_ENTITY_BOUNDARY,
                    b"All markup of the conditional section is not in the same entity\n\0"
                        as *const u8 as *const libc::c_char,
                );
            }
            let ref mut fresh300 = (*(*ctxt).input).cur;
            *fresh300 = (*fresh300).offset(3 as libc::c_int as isize);
            (*(*ctxt).input).col += 3 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
        } else {
            let mut id_0: libc::c_int = (*(*ctxt).input).id;
            let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
            xmlParseMarkupDecl(ctxt);
            if id_0 == (*(*ctxt).input).id
                && cons
                    == ((*(*ctxt).input).consumed)
                        .wrapping_add(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long as libc::c_ulong,
                        )
            {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_EXT_SUBSET_NOT_FINISHED,
                    0 as *const libc::c_char,
                );
                xmlHaltParser(ctxt);
                break;
            }
        }
        if depth == 0 as libc::c_int as libc::c_ulong {
            break;
        }
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
    }
    xmlFree.expect("non-null function pointer")(inputIds as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMarkupDecl(mut ctxt: xmlParserCtxtPtr) {
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32 {
        if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '!' as i32
        {
            match *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                as libc::c_int
            {
                69 => {
                    if *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                        as libc::c_int == 'L' as i32
                    {
                        xmlParseElementDecl(ctxt);
                    } else if *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == 'N' as i32
                        {
                        xmlParseEntityDecl(ctxt);
                    }
                }
                65 => {
                    xmlParseAttributeListDecl(ctxt);
                }
                78 => {
                    xmlParseNotationDecl(ctxt);
                }
                45 => {
                    xmlParseComment(ctxt);
                }
                _ => {}
            }
        } else if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                as libc::c_int == '?' as i32
            {
            xmlParsePI(ctxt);
        }
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    (*ctxt).instate = XML_PARSER_DTD;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseTextDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    let mut encoding: *const xmlChar = 0 as *const xmlChar;
    let mut oldstate: libc::c_int = 0;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
            == 0x20 as libc::c_int
            || 0x9 as libc::c_int
                <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int <= 0xa as libc::c_int
            || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
                == 0xd as libc::c_int)
    {
        let ref mut fresh301 = (*(*ctxt).input).cur;
        *fresh301 = (*fresh301).offset(5 as libc::c_int as isize);
        (*(*ctxt).input).col += 5 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_STARTED, 0 as *const libc::c_char);
        return;
    }
    oldstate = (*ctxt).instate as libc::c_int;
    (*ctxt).instate = XML_PARSER_START;
    if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed after '<?xml'\n\0" as *const u8 as *const libc::c_char,
        );
    }
    version = xmlParseVersionInfo(ctxt);
    if version.is_null() {
        version = xmlCharStrdup(b"1.0\0" as *const u8 as *const libc::c_char);
    } else if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Space needed here\n\0" as *const u8 as *const libc::c_char,
        );
    }
    let ref mut fresh302 = (*(*ctxt).input).version;
    *fresh302 = version;
    encoding = xmlParseEncodingDecl(ctxt);
    if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int {
        (*ctxt).instate = oldstate as xmlParserInputState;
        return;
    }
    if encoding.is_null() && (*ctxt).errNo == XML_ERR_OK as libc::c_int {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_MISSING_ENCODING,
            b"Missing encoding in text declaration\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '>' as i32
    {
        let ref mut fresh303 = (*(*ctxt).input).cur;
        *fresh303 = (*fresh303).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    } else if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const libc::c_char);
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const libc::c_char);
        while *(*(*ctxt).input).cur as libc::c_int != 0
            && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        {
            let ref mut fresh304 = (*(*ctxt).input).cur;
            *fresh304 = (*fresh304).offset(1);
        }
        xmlNextChar(ctxt);
    }
    (*ctxt).instate = oldstate as xmlParserInputState;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalSubset(
    mut ctxt: xmlParserCtxtPtr,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    xmlDetectSAX2(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if ((*ctxt).encoding).is_null()
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
            >= 4 as libc::c_int as libc::c_long
    {
        let mut start: [xmlChar; 4] = [0; 4];
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
    {
        xmlParseTextDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int {
            xmlHaltParser(ctxt);
            return;
        }
    }
    if ((*ctxt).myDoc).is_null() {
        let ref mut fresh305 = (*ctxt).myDoc;
        *fresh305 = xmlNewDoc(
            b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        );
        if ((*ctxt).myDoc).is_null() {
            xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const libc::c_char);
            return;
        }
        (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as libc::c_int;
    }
    if !((*ctxt).myDoc).is_null() && ((*(*ctxt).myDoc).intSubset).is_null() {
        xmlCreateIntSubset((*ctxt).myDoc, 0 as *const xmlChar, ExternalID, SystemID);
    }
    (*ctxt).instate = XML_PARSER_DTD;
    (*ctxt).external = 1 as libc::c_int;
    xmlSkipBlankChars(ctxt);
    while *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '?' as i32
        || *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '!' as i32 || *(*(*ctxt).input).cur as libc::c_int == '%' as i32
    {
        let mut id: libc::c_int = (*(*ctxt).input).id;
        let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '!' as i32
            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int
                == '[' as i32
        {
            xmlParseConditionalSections(ctxt);
        } else {
            xmlParseMarkupDecl(ctxt);
        }
        xmlSkipBlankChars(ctxt);
        if !(id == (*(*ctxt).input).id
            && cons
                == ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long as libc::c_ulong,
                    ))
        {
            continue;
        }
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const libc::c_char);
        break;
    }
    if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXT_SUBSET_NOT_FINISHED, 0 as *const libc::c_char);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseReference(mut ctxt: xmlParserCtxtPtr) {
    let mut ent: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut was_checked: libc::c_int = 0;
    let mut list: xmlNodePtr = 0 as xmlNodePtr;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    if *(*(*ctxt).input).cur as libc::c_int != '&' as i32 {
        return;
    }
    if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
        == '#' as i32
    {
        let mut i: libc::c_int = 0 as libc::c_int;
        let mut out: [xmlChar; 16] = [0; 16];
        let mut hex: libc::c_int = *((*(*ctxt).input).cur)
            .offset(2 as libc::c_int as isize) as libc::c_int;
        let mut value: libc::c_int = xmlParseCharRef(ctxt);
        if value == 0 as libc::c_int {
            return;
        }
        if (*ctxt).charset != XML_CHAR_ENCODING_UTF8 as libc::c_int {
            if value <= 0xff as libc::c_int {
                out[0 as libc::c_int as usize] = value as xmlChar;
                out[1 as libc::c_int as usize] = 0 as libc::c_int as xmlChar;
                if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
                    && (*ctxt).disableSAX == 0
                {
                    ((*(*ctxt).sax).characters)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, out.as_mut_ptr(), 1 as libc::c_int);
                }
            } else {
                if hex == 'x' as i32 || hex == 'X' as i32 {
                    snprintf(
                        out.as_mut_ptr() as *mut libc::c_char,
                        ::std::mem::size_of::<[xmlChar; 16]>() as libc::c_ulong,
                        b"#x%X\0" as *const u8 as *const libc::c_char,
                        value,
                    );
                } else {
                    snprintf(
                        out.as_mut_ptr() as *mut libc::c_char,
                        ::std::mem::size_of::<[xmlChar; 16]>() as libc::c_ulong,
                        b"#%d\0" as *const u8 as *const libc::c_char,
                        value,
                    );
                }
                if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
                    && (*ctxt).disableSAX == 0
                {
                    ((*(*ctxt).sax).reference)
                        .expect(
                            "non-null function pointer",
                        )((*ctxt).userData, out.as_mut_ptr());
                }
            }
        } else {
            if 0 as libc::c_int == 1 as libc::c_int {
                let fresh306 = i;
                i = i + 1;
                out[fresh306 as usize] = value as xmlChar;
            } else {
                i
                    += xmlCopyCharMultiByte(
                        &mut *out.as_mut_ptr().offset(i as isize),
                        value,
                    );
            }
            out[i as usize] = 0 as libc::c_int as xmlChar;
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
                && (*ctxt).disableSAX == 0
            {
                ((*(*ctxt).sax).characters)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, out.as_mut_ptr(), i);
            }
        }
        return;
    }
    ent = xmlParseEntityRef(ctxt);
    if ent.is_null() {
        return;
    }
    if (*ctxt).wellFormed == 0 {
        return;
    }
    was_checked = (*ent).checked;
    if ((*ent).name).is_null()
        || (*ent).etype as libc::c_uint
            == XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int as libc::c_uint
    {
        val = (*ent).content;
        if val.is_null() {
            return;
        }
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).characters).is_some()
            && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).characters)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, val, xmlStrlen(val));
        }
        return;
    }
    if ((*ent).checked == 0 as libc::c_int
        || ((*ent).children).is_null()
            && (*ctxt).options & XML_PARSE_NOENT as libc::c_int != 0)
        && ((*ent).etype as libc::c_uint
            != XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
            || (*ctxt).options
                & (XML_PARSE_NOENT as libc::c_int | XML_PARSE_DTDVALID as libc::c_int)
                != 0)
    {
        let mut oldnbent: libc::c_ulong = (*ctxt).nbentities;
        let mut diff: libc::c_ulong = 0;
        let mut user_data: *mut libc::c_void = 0 as *mut libc::c_void;
        if (*ctxt).userData == ctxt as *mut libc::c_void {
            user_data = 0 as *mut libc::c_void;
        } else {
            user_data = (*ctxt).userData;
        }
        if (*ent).etype as libc::c_uint
            == XML_INTERNAL_GENERAL_ENTITY as libc::c_int as libc::c_uint
        {
            let ref mut fresh307 = (*ctxt).depth;
            *fresh307 += 1;
            ret = xmlParseBalancedChunkMemoryInternal(
                ctxt,
                (*ent).content,
                user_data,
                &mut list,
            );
            let ref mut fresh308 = (*ctxt).depth;
            *fresh308 -= 1;
        } else if (*ent).etype as libc::c_uint
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
            {
            let ref mut fresh309 = (*ctxt).depth;
            *fresh309 += 1;
            ret = xmlParseExternalEntityPrivate(
                (*ctxt).myDoc,
                ctxt,
                (*ctxt).sax,
                user_data,
                (*ctxt).depth,
                (*ent).URI,
                (*ent).ExternalID,
                &mut list,
            );
            let ref mut fresh310 = (*ctxt).depth;
            *fresh310 -= 1;
        } else {
            ret = XML_ERR_ENTITY_PE_INTERNAL;
            xmlErrMsgStr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"invalid entity type found\n\0" as *const u8 as *const libc::c_char,
                0 as *const xmlChar,
            );
        }
        diff = ((*ctxt).nbentities)
            .wrapping_sub(oldnbent)
            .wrapping_add(1 as libc::c_int as libc::c_ulong);
        if diff > (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_ulong {
            diff = (2147483647 as libc::c_int / 2 as libc::c_int) as libc::c_ulong;
        }
        (*ent)
            .checked = diff.wrapping_mul(2 as libc::c_int as libc::c_ulong)
            as libc::c_int;
        if !((*ent).content).is_null()
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
            (*ent).checked |= 1 as libc::c_int;
        }
        if ret as libc::c_uint == XML_ERR_ENTITY_LOOP as libc::c_int as libc::c_uint {
            xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
            xmlHaltParser(ctxt);
            xmlFreeNodeList(list);
            return;
        }
        if xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            ent,
            0 as libc::c_int as size_t,
        ) != 0
        {
            xmlFreeNodeList(list);
            return;
        }
        if ret as libc::c_uint == XML_ERR_OK as libc::c_int as libc::c_uint
            && !list.is_null()
        {
            if ((*ent).etype as libc::c_uint
                == XML_INTERNAL_GENERAL_ENTITY as libc::c_int as libc::c_uint
                || (*ent).etype as libc::c_uint
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint)
                && ((*ent).children).is_null()
            {
                let ref mut fresh311 = (*ent).children;
                *fresh311 = list;
                if (*ctxt).replaceEntities == 0 as libc::c_int
                    || (*ctxt).parseMode as libc::c_uint
                        == XML_PARSE_READER as libc::c_int as libc::c_uint
                    || (*list).type_0 as libc::c_uint
                        == XML_TEXT_NODE as libc::c_int as libc::c_uint
                        && ((*list).next).is_null()
                {
                    (*ent).owner = 1 as libc::c_int;
                    while !list.is_null() {
                        let ref mut fresh312 = (*list).parent;
                        *fresh312 = ent as xmlNodePtr;
                        if (*list).doc != (*ent).doc {
                            xmlSetTreeDoc(list, (*ent).doc);
                        }
                        if ((*list).next).is_null() {
                            let ref mut fresh313 = (*ent).last;
                            *fresh313 = list;
                        }
                        list = (*list).next;
                    }
                    list = 0 as xmlNodePtr;
                } else {
                    (*ent).owner = 0 as libc::c_int;
                    while !list.is_null() {
                        let ref mut fresh314 = (*list).parent;
                        *fresh314 = (*ctxt).node;
                        let ref mut fresh315 = (*list).doc;
                        *fresh315 = (*ctxt).myDoc;
                        if ((*list).next).is_null() {
                            let ref mut fresh316 = (*ent).last;
                            *fresh316 = list;
                        }
                        list = (*list).next;
                    }
                    list = (*ent).children;
                    if (*ent).etype as libc::c_uint
                        == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int
                            as libc::c_uint
                    {
                        xmlAddEntityReference(ent, list, 0 as xmlNodePtr);
                    }
                }
            } else {
                xmlFreeNodeList(list);
                list = 0 as xmlNodePtr;
            }
        } else if ret as libc::c_uint != XML_ERR_OK as libc::c_int as libc::c_uint
                && ret as libc::c_uint
                    != XML_WAR_UNDECLARED_ENTITY as libc::c_int as libc::c_uint
            {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' failed to parse\n\0" as *const u8 as *const libc::c_char,
                (*ent).name,
            );
            if !((*ent).content).is_null() {
                *((*ent).content)
                    .offset(0 as libc::c_int as isize) = 0 as libc::c_int as xmlChar;
            }
            xmlParserEntityCheck(
                ctxt,
                0 as libc::c_int as size_t,
                ent,
                0 as libc::c_int as size_t,
            );
        } else if !list.is_null() {
            xmlFreeNodeList(list);
            list = 0 as xmlNodePtr;
        }
        if (*ent).checked == 0 as libc::c_int {
            (*ent).checked = 2 as libc::c_int;
        }
        was_checked = 0 as libc::c_int;
    } else if (*ent).checked != 1 as libc::c_int {
        let ref mut fresh317 = (*ctxt).nbentities;
        *fresh317 = (*fresh317)
            .wrapping_add(((*ent).checked / 2 as libc::c_int) as libc::c_ulong);
    }
    if ((*ent).children).is_null() {
        if was_checked != 0 as libc::c_int {
            let mut user_data_0: *mut libc::c_void = 0 as *mut libc::c_void;
            if (*ctxt).userData == ctxt as *mut libc::c_void {
                user_data_0 = 0 as *mut libc::c_void;
            } else {
                user_data_0 = (*ctxt).userData;
            }
            if (*ent).etype as libc::c_uint
                == XML_INTERNAL_GENERAL_ENTITY as libc::c_int as libc::c_uint
            {
                let ref mut fresh318 = (*ctxt).depth;
                *fresh318 += 1;
                ret = xmlParseBalancedChunkMemoryInternal(
                    ctxt,
                    (*ent).content,
                    user_data_0,
                    0 as *mut xmlNodePtr,
                );
                let ref mut fresh319 = (*ctxt).depth;
                *fresh319 -= 1;
            } else if (*ent).etype as libc::c_uint
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
                {
                let ref mut fresh320 = (*ctxt).depth;
                *fresh320 += 1;
                ret = xmlParseExternalEntityPrivate(
                    (*ctxt).myDoc,
                    ctxt,
                    (*ctxt).sax,
                    user_data_0,
                    (*ctxt).depth,
                    (*ent).URI,
                    (*ent).ExternalID,
                    0 as *mut xmlNodePtr,
                );
                let ref mut fresh321 = (*ctxt).depth;
                *fresh321 -= 1;
            } else {
                ret = XML_ERR_ENTITY_PE_INTERNAL;
                xmlErrMsgStr(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"invalid entity type found\n\0" as *const u8 as *const libc::c_char,
                    0 as *const xmlChar,
                );
            }
            if ret as libc::c_uint == XML_ERR_ENTITY_LOOP as libc::c_int as libc::c_uint
            {
                xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, 0 as *const libc::c_char);
                return;
            }
        }
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
            && (*ctxt).replaceEntities == 0 as libc::c_int && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).reference)
                .expect("non-null function pointer")((*ctxt).userData, (*ent).name);
        }
        return;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).reference).is_some()
        && (*ctxt).replaceEntities == 0 as libc::c_int && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).reference)
            .expect("non-null function pointer")((*ctxt).userData, (*ent).name);
        return;
    }
    if (*ctxt).replaceEntities != 0 || ((*ent).children).is_null() {
        if !((*ctxt).node).is_null() && !((*ent).children).is_null() {
            if list.is_null() && (*ent).owner == 0 as libc::c_int
                || (*ctxt).parseMode as libc::c_uint
                    == XML_PARSE_READER as libc::c_int as libc::c_uint
            {
                let mut nw: xmlNodePtr = 0 as xmlNodePtr;
                let mut cur: xmlNodePtr = 0 as *mut xmlNode;
                let mut firstChild: xmlNodePtr = 0 as xmlNodePtr;
                let ref mut fresh322 = (*ctxt).sizeentcopy;
                *fresh322 = (*fresh322)
                    .wrapping_add(((*ent).length + 5 as libc::c_int) as libc::c_ulong);
                if xmlParserEntityCheck(
                    ctxt,
                    0 as libc::c_int as size_t,
                    ent,
                    (*ctxt).sizeentcopy,
                ) != 0
                {
                    return;
                }
                cur = (*ent).children;
                while !cur.is_null() {
                    nw = xmlDocCopyNode(cur, (*ctxt).myDoc, 1 as libc::c_int);
                    if !nw.is_null() {
                        if ((*nw)._private).is_null() {
                            let ref mut fresh323 = (*nw)._private;
                            *fresh323 = (*cur)._private;
                        }
                        if firstChild.is_null() {
                            firstChild = nw;
                        }
                        nw = xmlAddChild((*ctxt).node, nw);
                    }
                    if cur == (*ent).last {
                        if (*ctxt).parseMode as libc::c_uint
                            == XML_PARSE_READER as libc::c_int as libc::c_uint
                            && !nw.is_null()
                            && (*nw).type_0 as libc::c_uint
                                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
                            && ((*nw).children).is_null()
                        {
                            (*nw).extra = 1 as libc::c_int as libc::c_ushort;
                        }
                        break;
                    } else {
                        cur = (*cur).next;
                    }
                }
                if (*ent).etype as libc::c_uint
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
                {
                    xmlAddEntityReference(ent, firstChild, nw);
                }
            } else if list.is_null() || (*ctxt).inputNr > 0 as libc::c_int {
                let mut nw_0: xmlNodePtr = 0 as xmlNodePtr;
                let mut cur_0: xmlNodePtr = 0 as *mut xmlNode;
                let mut next: xmlNodePtr = 0 as *mut xmlNode;
                let mut last: xmlNodePtr = 0 as *mut xmlNode;
                let mut firstChild_0: xmlNodePtr = 0 as xmlNodePtr;
                let ref mut fresh324 = (*ctxt).sizeentcopy;
                *fresh324 = (*fresh324)
                    .wrapping_add(((*ent).length + 5 as libc::c_int) as libc::c_ulong);
                if xmlParserEntityCheck(
                    ctxt,
                    0 as libc::c_int as size_t,
                    ent,
                    (*ctxt).sizeentcopy,
                ) != 0
                {
                    return;
                }
                cur_0 = (*ent).children;
                let ref mut fresh325 = (*ent).children;
                *fresh325 = 0 as *mut _xmlNode;
                last = (*ent).last;
                let ref mut fresh326 = (*ent).last;
                *fresh326 = 0 as *mut _xmlNode;
                while !cur_0.is_null() {
                    next = (*cur_0).next;
                    let ref mut fresh327 = (*cur_0).next;
                    *fresh327 = 0 as *mut _xmlNode;
                    let ref mut fresh328 = (*cur_0).parent;
                    *fresh328 = 0 as *mut _xmlNode;
                    nw_0 = xmlDocCopyNode(cur_0, (*ctxt).myDoc, 1 as libc::c_int);
                    if !nw_0.is_null() {
                        if ((*nw_0)._private).is_null() {
                            let ref mut fresh329 = (*nw_0)._private;
                            *fresh329 = (*cur_0)._private;
                        }
                        if firstChild_0.is_null() {
                            firstChild_0 = cur_0;
                        }
                        xmlAddChild(ent as xmlNodePtr, nw_0);
                        xmlAddChild((*ctxt).node, cur_0);
                    }
                    if cur_0 == last {
                        break;
                    }
                    cur_0 = next;
                }
                if (*ent).owner == 0 as libc::c_int {
                    (*ent).owner = 1 as libc::c_int;
                }
                if (*ent).etype as libc::c_uint
                    == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
                {
                    xmlAddEntityReference(ent, firstChild_0, nw_0);
                }
            } else {
                let mut nbktext: *const xmlChar = 0 as *const xmlChar;
                nbktext = xmlDictLookup(
                    (*ctxt).dict,
                    b"nbktext\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    -(1 as libc::c_int),
                );
                if (*(*ent).children).type_0 as libc::c_uint
                    == XML_TEXT_NODE as libc::c_int as libc::c_uint
                {
                    let ref mut fresh330 = (*(*ent).children).name;
                    *fresh330 = nbktext;
                }
                if (*ent).last != (*ent).children
                    && (*(*ent).last).type_0 as libc::c_uint
                        == XML_TEXT_NODE as libc::c_int as libc::c_uint
                {
                    let ref mut fresh331 = (*(*ent).last).name;
                    *fresh331 = nbktext;
                }
                xmlAddChildList((*ctxt).node, (*ent).children);
            }
            (*ctxt).nodemem = 0 as libc::c_int;
            (*ctxt).nodelen = 0 as libc::c_int;
            return;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntityRef(mut ctxt: xmlParserCtxtPtr) -> xmlEntityPtr {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ent: xmlEntityPtr = 0 as xmlEntityPtr;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as xmlEntityPtr;
    }
    if *(*(*ctxt).input).cur as libc::c_int != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    xmlNextChar(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseEntityRef: no name\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlEntityPtr;
    }
    if *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const libc::c_char);
        return 0 as xmlEntityPtr;
    }
    xmlNextChar(ctxt);
    if (*ctxt).options & XML_PARSE_OLDSAX as libc::c_int == 0 as libc::c_int {
        ent = xmlGetPredefinedEntity(name);
        if !ent.is_null() {
            return ent;
        }
    }
    let ref mut fresh332 = (*ctxt).nbentities;
    *fresh332 = (*fresh332).wrapping_add(1);
    if !((*ctxt).sax).is_null() {
        if ((*(*ctxt).sax).getEntity).is_some() {
            ent = ((*(*ctxt).sax).getEntity)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        if (*ctxt).wellFormed == 1 as libc::c_int && ent.is_null()
            && (*ctxt).options & XML_PARSE_OLDSAX as libc::c_int != 0
        {
            ent = xmlGetPredefinedEntity(name);
        }
        if (*ctxt).wellFormed == 1 as libc::c_int && ent.is_null()
            && (*ctxt).userData == ctxt as *mut libc::c_void
        {
            ent = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
        }
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (*ctxt).standalone == 1 as libc::c_int
            || (*ctxt).hasExternalSubset == 0 as libc::c_int
                && (*ctxt).hasPErefs == 0 as libc::c_int
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const libc::c_char,
                name,
            );
        } else {
            xmlErrMsgStr(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const libc::c_char,
                name,
            );
            if (*ctxt).inSubset == 0 as libc::c_int && !((*ctxt).sax).is_null()
                && ((*(*ctxt).sax).reference).is_some()
            {
                ((*(*ctxt).sax).reference)
                    .expect("non-null function pointer")((*ctxt).userData, name);
            }
        }
        xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            ent,
            0 as libc::c_int as size_t,
        );
        (*ctxt).valid = 0 as libc::c_int;
    } else if (*ent).etype as libc::c_uint
            == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as libc::c_int as libc::c_uint
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else if (*ctxt).instate as libc::c_int == XML_PARSER_ATTRIBUTE_VALUE as libc::c_int
            && (*ent).etype as libc::c_uint
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else if (*ctxt).instate as libc::c_int == XML_PARSER_ATTRIBUTE_VALUE as libc::c_int
            && !ent.is_null()
            && (*ent).etype as libc::c_uint
                != XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int as libc::c_uint
        {
        if ((*ent).checked & 1 as libc::c_int != 0 || (*ent).checked == 0 as libc::c_int)
            && !((*ent).content).is_null()
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_LT_IN_ATTRIBUTE,
                b"'<' in entity '%s' is not allowed in attributes values\n\0"
                    as *const u8 as *const libc::c_char,
                name,
            );
        }
    } else {
        match (*ent).etype as libc::c_uint {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
            }
            _ => {}
        }
    }
    return ent;
}
unsafe extern "C" fn xmlParseStringEntityRef(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> xmlEntityPtr {
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut ent: xmlEntityPtr = 0 as xmlEntityPtr;
    if str.is_null() || (*str).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = *str;
    cur = *ptr;
    if cur as libc::c_int != '&' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    name = xmlParseStringName(ctxt, &mut ptr);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringEntityRef: no name\n\0" as *const u8 as *const libc::c_char,
        );
        *str = ptr;
        return 0 as xmlEntityPtr;
    }
    if *ptr as libc::c_int != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const libc::c_char);
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *str = ptr;
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    if (*ctxt).options & XML_PARSE_OLDSAX as libc::c_int == 0 as libc::c_int {
        ent = xmlGetPredefinedEntity(name);
        if !ent.is_null() {
            xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
            *str = ptr;
            return ent;
        }
    }
    let ref mut fresh333 = (*ctxt).nbentities;
    *fresh333 = (*fresh333).wrapping_add(1);
    if !((*ctxt).sax).is_null() {
        if ((*(*ctxt).sax).getEntity).is_some() {
            ent = ((*(*ctxt).sax).getEntity)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        if ent.is_null() && (*ctxt).options & XML_PARSE_OLDSAX as libc::c_int != 0 {
            ent = xmlGetPredefinedEntity(name);
        }
        if ent.is_null() && (*ctxt).userData == ctxt as *mut libc::c_void {
            ent = xmlSAX2GetEntity(ctxt as *mut libc::c_void, name);
        }
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        return 0 as xmlEntityPtr;
    }
    if ent.is_null() {
        if (*ctxt).standalone == 1 as libc::c_int
            || (*ctxt).hasExternalSubset == 0 as libc::c_int
                && (*ctxt).hasPErefs == 0 as libc::c_int
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const libc::c_char,
                name,
            );
        } else {
            xmlErrMsgStr(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"Entity '%s' not defined\n\0" as *const u8 as *const libc::c_char,
                name,
            );
        }
        xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            ent,
            0 as libc::c_int as size_t,
        );
    } else if (*ent).etype as libc::c_uint
            == XML_EXTERNAL_GENERAL_UNPARSED_ENTITY as libc::c_int as libc::c_uint
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_UNPARSED_ENTITY,
            b"Entity reference to unparsed entity %s\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else if (*ctxt).instate as libc::c_int == XML_PARSER_ATTRIBUTE_VALUE as libc::c_int
            && (*ent).etype as libc::c_uint
                == XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ENTITY_IS_EXTERNAL,
            b"Attribute references external entity '%s'\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else if (*ctxt).instate as libc::c_int == XML_PARSER_ATTRIBUTE_VALUE as libc::c_int
            && !ent.is_null() && !((*ent).content).is_null()
            && (*ent).etype as libc::c_uint
                != XML_INTERNAL_PREDEFINED_ENTITY as libc::c_int as libc::c_uint
            && !(xmlStrchr((*ent).content, '<' as i32 as xmlChar)).is_null()
        {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_LT_IN_ATTRIBUTE,
            b"'<' in entity '%s' is not allowed in attributes values\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
    } else {
        match (*ent).etype as libc::c_uint {
            4 | 5 => {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_ENTITY_IS_PARAMETER,
                    b"Attempt to reference the parameter entity '%s'\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                );
            }
            _ => {}
        }
    }
    xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
    *str = ptr;
    return ent;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParsePEReference(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut entity: xmlEntityPtr = 0 as xmlEntityPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if *(*(*ctxt).input).cur as libc::c_int != '%' as i32 {
        return;
    }
    xmlNextChar(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_PEREF_NO_NAME,
            b"PEReference: no name\n\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"PEReference: %s\n\0" as *const u8 as *const libc::c_char,
            name,
        );
    }
    if *(*(*ctxt).input).cur as libc::c_int != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_PEREF_SEMICOL_MISSING, 0 as *const libc::c_char);
        return;
    }
    xmlNextChar(ctxt);
    let ref mut fresh334 = (*ctxt).nbentities;
    *fresh334 = (*fresh334).wrapping_add(1);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getParameterEntity).is_some() {
        entity = ((*(*ctxt).sax).getParameterEntity)
            .expect("non-null function pointer")((*ctxt).userData, name);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    if entity.is_null() {
        if (*ctxt).standalone == 1 as libc::c_int
            || (*ctxt).hasExternalSubset == 0 as libc::c_int
                && (*ctxt).hasPErefs == 0 as libc::c_int
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const libc::c_char,
                name,
            );
        } else {
            if (*ctxt).validate != 0 && ((*ctxt).vctxt.error).is_some() {
                xmlValidityError(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                );
            } else {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_UNDECLARED_ENTITY,
                    b"PEReference: %%%s; not found\n\0" as *const u8
                        as *const libc::c_char,
                    name,
                    0 as *const xmlChar,
                );
            }
            (*ctxt).valid = 0 as libc::c_int;
        }
        xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            0 as xmlEntityPtr,
            0 as libc::c_int as size_t,
        );
    } else if (*entity).etype as libc::c_uint
            != XML_INTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
            && (*entity).etype as libc::c_uint
                != XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
        {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"Internal: %%%s; is not a parameter entity\n\0" as *const u8
                as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
    } else {
        let mut start: [xmlChar; 4] = [0; 4];
        let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
        if xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            entity,
            0 as libc::c_int as size_t,
        ) != 0
        {
            return;
        }
        if (*entity).etype as libc::c_uint
            == XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
            && (*ctxt).options & XML_PARSE_NOENT as libc::c_int == 0 as libc::c_int
            && (*ctxt).options & XML_PARSE_DTDVALID as libc::c_int == 0 as libc::c_int
            && (*ctxt).options & XML_PARSE_DTDLOAD as libc::c_int == 0 as libc::c_int
            && (*ctxt).options & XML_PARSE_DTDATTR as libc::c_int == 0 as libc::c_int
            && (*ctxt).replaceEntities == 0 as libc::c_int
            && (*ctxt).validate == 0 as libc::c_int
        {
            return;
        }
        input = xmlNewEntityInputStream(ctxt, entity);
        if xmlPushInput(ctxt, input) < 0 as libc::c_int {
            xmlFreeInputStream(input);
            return;
        }
        if (*entity).etype as libc::c_uint
            == XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
        {
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return;
            }
            if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
                >= 4 as libc::c_int as libc::c_long
            {
                start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
                start[1 as libc::c_int
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(1 as libc::c_int as isize);
                start[2 as libc::c_int
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(2 as libc::c_int as isize);
                start[3 as libc::c_int
                    as usize] = *((*(*ctxt).input).cur)
                    .offset(3 as libc::c_int as isize);
                enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
                if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
                    xmlSwitchEncoding(ctxt, enc);
                }
            }
            if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == '<' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
                && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int
                        <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int
                        && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int <= 0xa as libc::c_int
                    || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                        as libc::c_int == 0xd as libc::c_int)
            {
                xmlParseTextDecl(ctxt);
            }
        }
    }
    (*ctxt).hasPErefs = 1 as libc::c_int;
}
unsafe extern "C" fn xmlLoadEntityContent(
    mut ctxt: xmlParserCtxtPtr,
    mut entity: xmlEntityPtr,
) -> libc::c_int {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut l: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if ctxt.is_null() || entity.is_null()
        || (*entity).etype as libc::c_uint
            != XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
            && (*entity).etype as libc::c_uint
                != XML_EXTERNAL_GENERAL_PARSED_ENTITY as libc::c_int as libc::c_uint
        || !((*entity).content).is_null()
    {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if *__xmlParserDebugEntities() != 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Reading %s entity content input\n\0" as *const u8 as *const libc::c_char,
            (*entity).name,
        );
    }
    buf = xmlBufferCreate();
    if buf.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent parameter error\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    xmlBufferSetAllocationScheme(buf, XML_BUFFER_ALLOC_DOUBLEIT);
    input = xmlNewEntityInputStream(ctxt, entity);
    if input.is_null() {
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"xmlLoadEntityContent input error\0" as *const u8 as *const libc::c_char,
        );
        xmlBufferFree(buf);
        return -(1 as libc::c_int);
    }
    if xmlPushInput(ctxt, input) < 0 as libc::c_int {
        xmlBufferFree(buf);
        xmlFreeInputStream(input);
        return -(1 as libc::c_int);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    c = xmlCurrentChar(ctxt, &mut l);
    while (*ctxt).input == input && (*(*ctxt).input).cur < (*(*ctxt).input).end
        && (if c < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int || 0x20 as libc::c_int <= c) as libc::c_int
        } else {
            (0x100 as libc::c_int <= c && c <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= c && c <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= c && c <= 0x10ffff as libc::c_int)
                as libc::c_int
        }) != 0
    {
        xmlBufferAdd(buf, (*(*ctxt).input).cur, l);
        let fresh335 = count;
        count = count + 1;
        if fresh335 > 100 as libc::c_int {
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                xmlBufferFree(buf);
                return -(1 as libc::c_int);
            }
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh336 = (*(*ctxt).input).line;
            *fresh336 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh337 = (*(*ctxt).input).col;
            *fresh337 += 1;
        }
        let ref mut fresh338 = (*(*ctxt).input).cur;
        *fresh338 = (*fresh338).offset(l as isize);
        c = xmlCurrentChar(ctxt, &mut l);
        if c == 0 as libc::c_int {
            count = 0 as libc::c_int;
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                xmlBufferFree(buf);
                return -(1 as libc::c_int);
            }
            c = xmlCurrentChar(ctxt, &mut l);
        }
    }
    if (*ctxt).input == input && (*(*ctxt).input).cur >= (*(*ctxt).input).end {
        xmlPopInput(ctxt);
    } else if if c < 0x100 as libc::c_int {
            (0x9 as libc::c_int <= c && c <= 0xa as libc::c_int
                || c == 0xd as libc::c_int || 0x20 as libc::c_int <= c) as libc::c_int
        } else {
            (0x100 as libc::c_int <= c && c <= 0xd7ff as libc::c_int
                || 0xe000 as libc::c_int <= c && c <= 0xfffd as libc::c_int
                || 0x10000 as libc::c_int <= c && c <= 0x10ffff as libc::c_int)
                as libc::c_int
        } == 0
        {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INVALID_CHAR,
            b"xmlLoadEntityContent: invalid char value %d\n\0" as *const u8
                as *const libc::c_char,
            c,
        );
        xmlBufferFree(buf);
        return -(1 as libc::c_int);
    }
    let ref mut fresh339 = (*entity).content;
    *fresh339 = (*buf).content;
    let ref mut fresh340 = (*buf).content;
    *fresh340 = 0 as *mut xmlChar;
    xmlBufferFree(buf);
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlParseStringPEReference(
    mut ctxt: xmlParserCtxtPtr,
    mut str: *mut *const xmlChar,
) -> xmlEntityPtr {
    let mut ptr: *const xmlChar = 0 as *const xmlChar;
    let mut cur: xmlChar = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut entity: xmlEntityPtr = 0 as xmlEntityPtr;
    if str.is_null() || (*str).is_null() {
        return 0 as xmlEntityPtr;
    }
    ptr = *str;
    cur = *ptr;
    if cur as libc::c_int != '%' as i32 {
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    name = xmlParseStringName(ctxt, &mut ptr);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStringPEReference: no name\n\0" as *const u8 as *const libc::c_char,
        );
        *str = ptr;
        return 0 as xmlEntityPtr;
    }
    cur = *ptr;
    if cur as libc::c_int != ';' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ENTITYREF_SEMICOL_MISSING, 0 as *const libc::c_char);
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *str = ptr;
        return 0 as xmlEntityPtr;
    }
    ptr = ptr.offset(1);
    let ref mut fresh341 = (*ctxt).nbentities;
    *fresh341 = (*fresh341).wrapping_add(1);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).getParameterEntity).is_some() {
        entity = ((*(*ctxt).sax).getParameterEntity)
            .expect("non-null function pointer")((*ctxt).userData, name);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
        *str = ptr;
        return 0 as xmlEntityPtr;
    }
    if entity.is_null() {
        if (*ctxt).standalone == 1 as libc::c_int
            || (*ctxt).hasExternalSubset == 0 as libc::c_int
                && (*ctxt).hasPErefs == 0 as libc::c_int
        {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const libc::c_char,
                name,
            );
        } else {
            xmlWarningMsg(
                ctxt,
                XML_WAR_UNDECLARED_ENTITY,
                b"PEReference: %%%s; not found\n\0" as *const u8 as *const libc::c_char,
                name,
                0 as *const xmlChar,
            );
            (*ctxt).valid = 0 as libc::c_int;
        }
        xmlParserEntityCheck(
            ctxt,
            0 as libc::c_int as size_t,
            0 as xmlEntityPtr,
            0 as libc::c_int as size_t,
        );
    } else if (*entity).etype as libc::c_uint
            != XML_INTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
            && (*entity).etype as libc::c_uint
                != XML_EXTERNAL_PARAMETER_ENTITY as libc::c_int as libc::c_uint
        {
        xmlWarningMsg(
            ctxt,
            XML_WAR_UNDECLARED_ENTITY,
            b"%%%s; is not a parameter entity\n\0" as *const u8 as *const libc::c_char,
            name,
            0 as *const xmlChar,
        );
    }
    (*ctxt).hasPErefs = 1 as libc::c_int;
    xmlFree.expect("non-null function pointer")(name as *mut libc::c_void);
    *str = ptr;
    return entity;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDocTypeDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let ref mut fresh342 = (*(*ctxt).input).cur;
    *fresh342 = (*fresh342).offset(9 as libc::c_int as isize);
    (*(*ctxt).input).col += 9 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    xmlSkipBlankChars(ctxt);
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseDocTypeDecl : no DOCTYPE name !\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    let ref mut fresh343 = (*ctxt).intSubName;
    *fresh343 = name;
    xmlSkipBlankChars(ctxt);
    URI = xmlParseExternalID(ctxt, &mut ExternalID, 1 as libc::c_int);
    if !URI.is_null() || !ExternalID.is_null() {
        (*ctxt).hasExternalSubset = 1 as libc::c_int;
    }
    let ref mut fresh344 = (*ctxt).extSubURI;
    *fresh344 = URI;
    let ref mut fresh345 = (*ctxt).extSubSystem;
    *fresh345 = ExternalID;
    xmlSkipBlankChars(ctxt);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).internalSubset).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).internalSubset)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, name, ExternalID, URI);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '[' as i32 {
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const libc::c_char);
    }
    xmlNextChar(ctxt);
}
unsafe extern "C" fn xmlParseInternalSubset(mut ctxt: xmlParserCtxtPtr) {
    if *(*(*ctxt).input).cur as libc::c_int == '[' as i32 {
        let mut baseInputNr: libc::c_int = (*ctxt).inputNr;
        (*ctxt).instate = XML_PARSER_DTD;
        xmlNextChar(ctxt);
        while (*(*(*ctxt).input).cur as libc::c_int != ']' as i32
            || (*ctxt).inputNr > baseInputNr)
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            let mut id: libc::c_int = (*(*ctxt).input).id;
            let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
            xmlSkipBlankChars(ctxt);
            xmlParseMarkupDecl(ctxt);
            xmlParsePEReference(ctxt);
            if (*ctxt).inputNr > 1 as libc::c_int
                && !((*(*ctxt).input).filename).is_null()
                && *(*(*ctxt).input).cur as libc::c_int == '<' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == '!' as i32
                && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                    as libc::c_int == '[' as i32
            {
                xmlParseConditionalSections(ctxt);
            }
            if !(id == (*(*ctxt).input).id
                && cons
                    == ((*(*ctxt).input).consumed)
                        .wrapping_add(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long as libc::c_ulong,
                        ))
            {
                continue;
            }
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseInternalSubset: error detected in Markup declaration\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if !((*ctxt).inputNr > baseInputNr) {
                break;
            }
            xmlPopInput(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == ']' as i32 {
            xmlNextChar(ctxt);
            xmlSkipBlankChars(ctxt);
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int != '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, 0 as *const libc::c_char);
        return;
    }
    xmlNextChar(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseAttribute(
    mut ctxt: xmlParserCtxtPtr,
    mut value: *mut *mut xmlChar,
) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    *value = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '=' as i32 {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValue(ctxt);
        (*ctxt).instate = XML_PARSER_CONTENT;
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
        return 0 as *const xmlChar;
    }
    if (*ctxt).pedantic != 0
        && xmlStrEqual(
            name,
            b"xml:lang\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
    {
        if xmlCheckLanguageID(val) == 0 {
            xmlWarningMsg(
                ctxt,
                XML_WAR_LANG_VALUE,
                b"Malformed value for xml:lang : %s\n\0" as *const u8
                    as *const libc::c_char,
                val,
                0 as *const xmlChar,
            );
        }
    }
    if xmlStrEqual(
        name,
        b"xml:space\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    ) != 0
    {
        if xmlStrEqual(
            val,
            b"default\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
        {
            *(*ctxt).space = 0 as libc::c_int;
        } else if xmlStrEqual(
                val,
                b"preserve\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
            *(*ctxt).space = 1 as libc::c_int;
        } else {
            xmlWarningMsg(
                ctxt,
                XML_WAR_SPACE_VALUE,
                b"Invalid value \"%s\" for xml:space : \"default\" or \"preserve\" expected\n\0"
                    as *const u8 as *const libc::c_char,
                val,
                0 as *const xmlChar,
            );
        }
    }
    *value = val;
    return name;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseStartTag(mut ctxt: xmlParserCtxtPtr) -> *const xmlChar {
    let mut current_block: u64;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut attname: *const xmlChar = 0 as *const xmlChar;
    let mut attvalue: *mut xmlChar = 0 as *mut xmlChar;
    let mut atts: *mut *const xmlChar = (*ctxt).atts;
    let mut nbatts: libc::c_int = 0 as libc::c_int;
    let mut maxatts: libc::c_int = (*ctxt).maxatts;
    let mut i: libc::c_int = 0;
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let ref mut fresh346 = (*(*ctxt).input).col;
    *fresh346 += 1;
    let ref mut fresh347 = (*(*ctxt).input).cur;
    *fresh347 = (*fresh347).offset(1);
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    name = xmlParseName(ctxt);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"xmlParseStartTag: invalid element name\n\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    while *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        && (*(*(*ctxt).input).cur as libc::c_int != '/' as i32
            || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                != '>' as i32)
        && (0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
            || 0x20 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int)
        && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
    {
        let mut id: libc::c_int = (*(*ctxt).input).id;
        let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        attname = xmlParseAttribute(ctxt, &mut attvalue);
        if !attname.is_null() && !attvalue.is_null() {
            i = 0 as libc::c_int;
            loop {
                if !(i < nbatts) {
                    current_block = 3437258052017859086;
                    break;
                }
                if xmlStrEqual(*atts.offset(i as isize), attname) != 0 {
                    xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(attvalue as *mut libc::c_void);
                    current_block = 16521494893250375975;
                    break;
                } else {
                    i += 2 as libc::c_int;
                }
            }
            match current_block {
                16521494893250375975 => {}
                _ => {
                    if atts.is_null() {
                        maxatts = 22 as libc::c_int;
                        atts = xmlMalloc
                            .expect(
                                "non-null function pointer",
                            )(
                            (maxatts as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut *const xmlChar;
                        if atts.is_null() {
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 16521494893250375975;
                        } else {
                            let ref mut fresh348 = (*ctxt).atts;
                            *fresh348 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 11763295167351361500;
                        }
                    } else if nbatts + 4 as libc::c_int > maxatts {
                        let mut n: *mut *const xmlChar = 0 as *mut *const xmlChar;
                        maxatts *= 2 as libc::c_int;
                        n = xmlRealloc
                            .expect(
                                "non-null function pointer",
                            )(
                            atts as *mut libc::c_void,
                            (maxatts as libc::c_ulong)
                                .wrapping_mul(
                                    ::std::mem::size_of::<*const xmlChar>() as libc::c_ulong,
                                ),
                        ) as *mut *const xmlChar;
                        if n.is_null() {
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                            if !attvalue.is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(attvalue as *mut libc::c_void);
                            }
                            current_block = 16521494893250375975;
                        } else {
                            atts = n;
                            let ref mut fresh349 = (*ctxt).atts;
                            *fresh349 = atts;
                            (*ctxt).maxatts = maxatts;
                            current_block = 11763295167351361500;
                        }
                    } else {
                        current_block = 11763295167351361500;
                    }
                    match current_block {
                        16521494893250375975 => {}
                        _ => {
                            let fresh350 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh351 = *atts.offset(fresh350 as isize);
                            *fresh351 = attname;
                            let fresh352 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh353 = *atts.offset(fresh352 as isize);
                            *fresh353 = attvalue;
                            let ref mut fresh354 = *atts.offset(nbatts as isize);
                            *fresh354 = 0 as *const xmlChar;
                            let ref mut fresh355 = *atts
                                .offset((nbatts + 1 as libc::c_int) as isize);
                            *fresh355 = 0 as *const xmlChar;
                        }
                    }
                }
            }
        } else if !attvalue.is_null() {
            xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '/' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == '>' as i32
        {
            break;
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"attributes construct error\n\0" as *const u8 as *const libc::c_char,
            );
        }
        if cons
            == ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                ) && id == (*(*ctxt).input).id && attname.is_null() && attvalue.is_null()
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8
                    as *const libc::c_char,
            );
            break;
        } else {
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
        }
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startElement).is_some()
        && (*ctxt).disableSAX == 0
    {
        if nbatts > 0 as libc::c_int {
            ((*(*ctxt).sax).startElement)
                .expect("non-null function pointer")((*ctxt).userData, name, atts);
        } else {
            ((*(*ctxt).sax).startElement)
                .expect(
                    "non-null function pointer",
                )((*ctxt).userData, name, 0 as *mut *const xmlChar);
        }
    }
    if !atts.is_null() {
        i = 1 as libc::c_int;
        while i < nbatts {
            if !(*atts.offset(i as isize)).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void);
            }
            i += 2 as libc::c_int;
        }
    }
    return name;
}
unsafe extern "C" fn xmlParseEndTag1(mut ctxt: xmlParserCtxtPtr, mut line: libc::c_int) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '/' as i32
    {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_LTSLASH_REQUIRED,
            b"xmlParseEndTag: '</' not found\n\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    let ref mut fresh356 = (*(*ctxt).input).cur;
    *fresh356 = (*fresh356).offset(2 as libc::c_int as isize);
    (*(*ctxt).input).col += 2 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    name = xmlParseNameAndCompare(ctxt, (*ctxt).name);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
        || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
        || 0x20 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int)
        || *(*(*ctxt).input).cur as libc::c_int != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const libc::c_char);
    } else {
        let ref mut fresh357 = (*(*ctxt).input).col;
        *fresh357 += 1;
        let ref mut fresh358 = (*(*ctxt).input).cur;
        *fresh358 = (*fresh358).offset(1);
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    }
    if name != 1 as libc::c_int as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const libc::c_char as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8
                as *const libc::c_char,
            (*ctxt).name,
            line,
            name,
        );
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).endElement)
            .expect("non-null function pointer")((*ctxt).userData, (*ctxt).name);
    }
    namePop(ctxt);
    spacePop(ctxt);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEndTag(mut ctxt: xmlParserCtxtPtr) {
    xmlParseEndTag1(ctxt, 0 as libc::c_int);
}
unsafe extern "C" fn xmlGetNamespace(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *const xmlChar,
) -> *const xmlChar {
    let mut i: libc::c_int = 0;
    if prefix == (*ctxt).str_xml {
        return (*ctxt).str_xml_ns;
    }
    i = (*ctxt).nsNr - 2 as libc::c_int;
    while i >= 0 as libc::c_int {
        if *((*ctxt).nsTab).offset(i as isize) == prefix {
            if prefix.is_null()
                && **((*ctxt).nsTab).offset((i + 1 as libc::c_int) as isize)
                    as libc::c_int == 0 as libc::c_int
            {
                return 0 as *const xmlChar;
            }
            return *((*ctxt).nsTab).offset((i + 1 as libc::c_int) as isize);
        }
        i -= 2 as libc::c_int;
    }
    return 0 as *const xmlChar;
}
unsafe extern "C" fn xmlParseQName(
    mut ctxt: xmlParserCtxtPtr,
    mut prefix: *mut *const xmlChar,
) -> *const xmlChar {
    let mut l: *const xmlChar = 0 as *const xmlChar;
    let mut p: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    l = xmlParseNCName(ctxt);
    if l.is_null() {
        if *(*(*ctxt).input).cur as libc::c_int == ':' as i32 {
            l = xmlParseName(ctxt);
            if !l.is_null() {
                xmlNsErr(
                    ctxt,
                    XML_NS_ERR_QNAME,
                    b"Failed to parse QName '%s'\n\0" as *const u8
                        as *const libc::c_char,
                    l,
                    0 as *const xmlChar,
                    0 as *const xmlChar,
                );
                *prefix = 0 as *const xmlChar;
                return l;
            }
        }
        return 0 as *const xmlChar;
    }
    if *(*(*ctxt).input).cur as libc::c_int == ':' as i32 {
        xmlNextChar(ctxt);
        p = l;
        l = xmlParseNCName(ctxt);
        if l.is_null() {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return 0 as *const xmlChar;
            }
            xmlNsErr(
                ctxt,
                XML_NS_ERR_QNAME,
                b"Failed to parse QName '%s:'\n\0" as *const u8 as *const libc::c_char,
                p,
                0 as *const xmlChar,
                0 as *const xmlChar,
            );
            l = xmlParseNmtoken(ctxt);
            if l.is_null() {
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *const xmlChar;
                }
                tmp = xmlBuildQName(
                    b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    p,
                    0 as *mut xmlChar,
                    0 as libc::c_int,
                );
            } else {
                tmp = xmlBuildQName(l, p, 0 as *mut xmlChar, 0 as libc::c_int);
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(l as *mut libc::c_char as *mut libc::c_void);
            }
            p = xmlDictLookup((*ctxt).dict, tmp, -(1 as libc::c_int));
            if !tmp.is_null() {
                xmlFree.expect("non-null function pointer")(tmp as *mut libc::c_void);
            }
            *prefix = 0 as *const xmlChar;
            return p;
        }
        if *(*(*ctxt).input).cur as libc::c_int == ':' as i32 {
            let mut tmp_0: *mut xmlChar = 0 as *mut xmlChar;
            xmlNsErr(
                ctxt,
                XML_NS_ERR_QNAME,
                b"Failed to parse QName '%s:%s:'\n\0" as *const u8
                    as *const libc::c_char,
                p,
                l,
                0 as *const xmlChar,
            );
            xmlNextChar(ctxt);
            tmp_0 = xmlParseName(ctxt) as *mut xmlChar;
            if !tmp_0.is_null() {
                tmp_0 = xmlBuildQName(tmp_0, l, 0 as *mut xmlChar, 0 as libc::c_int);
                l = xmlDictLookup((*ctxt).dict, tmp_0, -(1 as libc::c_int));
                if !tmp_0.is_null() {
                    xmlFree
                        .expect("non-null function pointer")(tmp_0 as *mut libc::c_void);
                }
                *prefix = p;
                return l;
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return 0 as *const xmlChar;
            }
            tmp_0 = xmlBuildQName(
                b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                l,
                0 as *mut xmlChar,
                0 as libc::c_int,
            );
            l = xmlDictLookup((*ctxt).dict, tmp_0, -(1 as libc::c_int));
            if !tmp_0.is_null() {
                xmlFree.expect("non-null function pointer")(tmp_0 as *mut libc::c_void);
            }
            *prefix = p;
            return l;
        }
        *prefix = p;
    } else {
        *prefix = 0 as *const xmlChar;
    }
    return l;
}
unsafe extern "C" fn xmlParseQNameAndCompare(
    mut ctxt: xmlParserCtxtPtr,
    mut name: *const xmlChar,
    mut prefix: *const xmlChar,
) -> *const xmlChar {
    let mut cmp: *const xmlChar = 0 as *const xmlChar;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *const xmlChar = 0 as *const xmlChar;
    let mut prefix2: *const xmlChar = 0 as *const xmlChar;
    if prefix.is_null() {
        return xmlParseNameAndCompare(ctxt, name);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur;
    cmp = prefix;
    while *in_0 as libc::c_int != 0 as libc::c_int
        && *in_0 as libc::c_int == *cmp as libc::c_int
    {
        in_0 = in_0.offset(1);
        cmp = cmp.offset(1);
    }
    if *cmp as libc::c_int == 0 as libc::c_int && *in_0 as libc::c_int == ':' as i32 {
        in_0 = in_0.offset(1);
        cmp = name;
        while *in_0 as libc::c_int != 0 as libc::c_int
            && *in_0 as libc::c_int == *cmp as libc::c_int
        {
            in_0 = in_0.offset(1);
            cmp = cmp.offset(1);
        }
        if *cmp as libc::c_int == 0 as libc::c_int
            && (*in_0 as libc::c_int == '>' as i32
                || (*in_0 as libc::c_int == 0x20 as libc::c_int
                    || 0x9 as libc::c_int <= *in_0 as libc::c_int
                        && *in_0 as libc::c_int <= 0xa as libc::c_int
                    || *in_0 as libc::c_int == 0xd as libc::c_int))
        {
            let ref mut fresh359 = (*(*ctxt).input).col;
            *fresh359 = (*fresh359 as libc::c_long
                + in_0.offset_from((*(*ctxt).input).cur) as libc::c_long) as libc::c_int;
            let ref mut fresh360 = (*(*ctxt).input).cur;
            *fresh360 = in_0;
            return 1 as libc::c_int as *const xmlChar;
        }
    }
    ret = xmlParseQName(ctxt, &mut prefix2);
    if ret == name && prefix == prefix2 {
        return 1 as libc::c_int as *const xmlChar;
    }
    return ret;
}
unsafe extern "C" fn xmlParseAttValueInternal(
    mut ctxt: xmlParserCtxtPtr,
    mut len: *mut libc::c_int,
    mut alloc: *mut libc::c_int,
    mut normalize: libc::c_int,
) -> *mut xmlChar {
    let mut current_block: u64;
    let mut limit: xmlChar = 0 as libc::c_int as xmlChar;
    let mut in_0: *const xmlChar = 0 as *const xmlChar;
    let mut start: *const xmlChar = 0 as *const xmlChar;
    let mut end: *const xmlChar = 0 as *const xmlChar;
    let mut last: *const xmlChar = 0 as *const xmlChar;
    let mut ret: *mut xmlChar = 0 as *mut xmlChar;
    let mut line: libc::c_int = 0;
    let mut col: libc::c_int = 0;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    in_0 = (*(*ctxt).input).cur as *mut xmlChar;
    line = (*(*ctxt).input).line;
    col = (*(*ctxt).input).col;
    if *in_0 as libc::c_int != '"' as i32 && *in_0 as libc::c_int != '\'' as i32 {
        xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    (*ctxt).instate = XML_PARSER_ATTRIBUTE_VALUE;
    let fresh361 = in_0;
    in_0 = in_0.offset(1);
    limit = *fresh361;
    col += 1;
    end = (*(*ctxt).input).end;
    start = in_0;
    if in_0 >= end {
        let mut oldbase: *const xmlChar = (*(*ctxt).input).base;
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            return 0 as *mut xmlChar;
        }
        if oldbase != (*(*ctxt).input).base {
            let mut delta: ptrdiff_t = ((*(*ctxt).input).base).offset_from(oldbase)
                as libc::c_long;
            start = start.offset(delta as isize);
            in_0 = in_0.offset(delta as isize);
        }
        end = (*(*ctxt).input).end;
    }
    if normalize != 0 {
        while in_0 < end && *in_0 as libc::c_int != limit as libc::c_int
            && (*in_0 as libc::c_int == 0x20 as libc::c_int
                || *in_0 as libc::c_int == 0x9 as libc::c_int
                || *in_0 as libc::c_int == 0xa as libc::c_int
                || *in_0 as libc::c_int == 0xd as libc::c_int)
        {
            if *in_0 as libc::c_int == 0xa as libc::c_int {
                line += 1;
                col = 1 as libc::c_int;
            } else {
                col += 1;
            }
            in_0 = in_0.offset(1);
            start = in_0;
            if in_0 >= end {
                let mut oldbase_0: *const xmlChar = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *mut xmlChar;
                }
                if oldbase_0 != (*(*ctxt).input).base {
                    let mut delta_0: ptrdiff_t = ((*(*ctxt).input).base)
                        .offset_from(oldbase_0) as libc::c_long;
                    start = start.offset(delta_0 as isize);
                    in_0 = in_0.offset(delta_0 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as libc::c_long
                    > 10000000 as libc::c_int as libc::c_long
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        while in_0 < end && *in_0 as libc::c_int != limit as libc::c_int
            && *in_0 as libc::c_int >= 0x20 as libc::c_int
            && *in_0 as libc::c_int <= 0x7f as libc::c_int
            && *in_0 as libc::c_int != '&' as i32 && *in_0 as libc::c_int != '<' as i32
        {
            col += 1;
            let fresh362 = in_0;
            in_0 = in_0.offset(1);
            if *fresh362 as libc::c_int == 0x20 as libc::c_int
                && *in_0 as libc::c_int == 0x20 as libc::c_int
            {
                break;
            }
            if in_0 >= end {
                let mut oldbase_1: *const xmlChar = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *mut xmlChar;
                }
                if oldbase_1 != (*(*ctxt).input).base {
                    let mut delta_1: ptrdiff_t = ((*(*ctxt).input).base)
                        .offset_from(oldbase_1) as libc::c_long;
                    start = start.offset(delta_1 as isize);
                    in_0 = in_0.offset(delta_1 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as libc::c_long
                    > 10000000 as libc::c_int as libc::c_long
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        while *last.offset(-(1 as libc::c_int) as isize) as libc::c_int
            == 0x20 as libc::c_int && last > start
        {
            last = last.offset(-1);
        }
        while in_0 < end && *in_0 as libc::c_int != limit as libc::c_int
            && (*in_0 as libc::c_int == 0x20 as libc::c_int
                || *in_0 as libc::c_int == 0x9 as libc::c_int
                || *in_0 as libc::c_int == 0xa as libc::c_int
                || *in_0 as libc::c_int == 0xd as libc::c_int)
        {
            if *in_0 as libc::c_int == 0xa as libc::c_int {
                line += 1;
                col = 1 as libc::c_int;
            } else {
                col += 1;
            }
            in_0 = in_0.offset(1);
            if in_0 >= end {
                let mut oldbase_2: *const xmlChar = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *mut xmlChar;
                }
                if oldbase_2 != (*(*ctxt).input).base {
                    let mut delta_2: ptrdiff_t = ((*(*ctxt).input).base)
                        .offset_from(oldbase_2) as libc::c_long;
                    start = start.offset(delta_2 as isize);
                    in_0 = in_0.offset(delta_2 as isize);
                    last = last.offset(delta_2 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as libc::c_long
                    > 10000000 as libc::c_int as libc::c_long
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        if in_0.offset_from(start) as libc::c_long
            > 10000000 as libc::c_int as libc::c_long
            && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const libc::c_char,
            );
            return 0 as *mut xmlChar;
        }
        if *in_0 as libc::c_int != limit as libc::c_int {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    } else {
        while in_0 < end && *in_0 as libc::c_int != limit as libc::c_int
            && *in_0 as libc::c_int >= 0x20 as libc::c_int
            && *in_0 as libc::c_int <= 0x7f as libc::c_int
            && *in_0 as libc::c_int != '&' as i32 && *in_0 as libc::c_int != '<' as i32
        {
            in_0 = in_0.offset(1);
            col += 1;
            if in_0 >= end {
                let mut oldbase_3: *const xmlChar = (*(*ctxt).input).base;
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                    return 0 as *mut xmlChar;
                }
                if oldbase_3 != (*(*ctxt).input).base {
                    let mut delta_3: ptrdiff_t = ((*(*ctxt).input).base)
                        .offset_from(oldbase_3) as libc::c_long;
                    start = start.offset(delta_3 as isize);
                    in_0 = in_0.offset(delta_3 as isize);
                }
                end = (*(*ctxt).input).end;
                if in_0.offset_from(start) as libc::c_long
                    > 10000000 as libc::c_int as libc::c_long
                    && (*ctxt).options & XML_PARSE_HUGE as libc::c_int
                        == 0 as libc::c_int
                {
                    xmlFatalErrMsg(
                        ctxt,
                        XML_ERR_ATTRIBUTE_NOT_FINISHED,
                        b"AttValue length too long\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    return 0 as *mut xmlChar;
                }
            }
        }
        last = in_0;
        if in_0.offset_from(start) as libc::c_long
            > 10000000 as libc::c_int as libc::c_long
            && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_ATTRIBUTE_NOT_FINISHED,
                b"AttValue length too long\n\0" as *const u8 as *const libc::c_char,
            );
            return 0 as *mut xmlChar;
        }
        if *in_0 as libc::c_int != limit as libc::c_int {
            current_block = 9760041004302091864;
        } else {
            current_block = 17736998403848444560;
        }
    }
    match current_block {
        9760041004302091864 => {
            if !alloc.is_null() {
                *alloc = 1 as libc::c_int;
            }
            return xmlParseAttValueComplex(ctxt, len, normalize);
        }
        _ => {
            in_0 = in_0.offset(1);
            col += 1;
            if !len.is_null() {
                *len = last.offset_from(start) as libc::c_long as libc::c_int;
                ret = start as *mut xmlChar;
            } else {
                if !alloc.is_null() {
                    *alloc = 1 as libc::c_int;
                }
                ret = xmlStrndup(
                    start,
                    last.offset_from(start) as libc::c_long as libc::c_int,
                );
            }
            let ref mut fresh363 = (*(*ctxt).input).cur;
            *fresh363 = in_0;
            (*(*ctxt).input).line = line;
            (*(*ctxt).input).col = col;
            if !alloc.is_null() {
                *alloc = 0 as libc::c_int;
            }
            return ret;
        }
    };
}
unsafe extern "C" fn xmlParseAttribute2(
    mut ctxt: xmlParserCtxtPtr,
    mut pref: *const xmlChar,
    mut elem: *const xmlChar,
    mut prefix: *mut *const xmlChar,
    mut value: *mut *mut xmlChar,
    mut len: *mut libc::c_int,
    mut alloc: *mut libc::c_int,
) -> *const xmlChar {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    let mut internal_val: *mut xmlChar = 0 as *mut xmlChar;
    let mut normalize: libc::c_int = 0 as libc::c_int;
    *value = 0 as *mut xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    name = xmlParseQName(ctxt, prefix);
    if name.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"error parsing attribute name\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    if !((*ctxt).attsSpecial).is_null() {
        let mut type_0: libc::c_int = 0;
        type_0 = xmlHashQLookup2((*ctxt).attsSpecial, pref, elem, *prefix, name)
            as ptrdiff_t as libc::c_int;
        if type_0 != 0 as libc::c_int {
            normalize = 1 as libc::c_int;
        }
    }
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '=' as i32 {
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        val = xmlParseAttValueInternal(ctxt, len, alloc, normalize);
        if normalize != 0 {
            if *alloc != 0 {
                let mut val2: *const xmlChar = 0 as *const xmlChar;
                val2 = xmlAttrNormalizeSpace2(ctxt, val, len);
                if !val2.is_null() && val2 != val as *const xmlChar {
                    xmlFree
                        .expect("non-null function pointer")(val as *mut libc::c_void);
                    val = val2 as *mut xmlChar;
                }
            }
        }
        (*ctxt).instate = XML_PARSER_CONTENT;
    } else {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_ATTRIBUTE_WITHOUT_VALUE,
            b"Specification mandates value for attribute %s\n\0" as *const u8
                as *const libc::c_char,
            name,
        );
        return 0 as *const xmlChar;
    }
    if *prefix == (*ctxt).str_xml {
        if (*ctxt).pedantic != 0
            && xmlStrEqual(
                name,
                b"lang\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
        {
            internal_val = xmlStrndup(val, *len);
            if xmlCheckLanguageID(internal_val) == 0 {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_LANG_VALUE,
                    b"Malformed value for xml:lang : %s\n\0" as *const u8
                        as *const libc::c_char,
                    internal_val,
                    0 as *const xmlChar,
                );
            }
        }
        if xmlStrEqual(
            name,
            b"space\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
        {
            internal_val = xmlStrndup(val, *len);
            if xmlStrEqual(
                internal_val,
                b"default\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) != 0
            {
                *(*ctxt).space = 0 as libc::c_int;
            } else if xmlStrEqual(
                    internal_val,
                    b"preserve\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) != 0
                {
                *(*ctxt).space = 1 as libc::c_int;
            } else {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_SPACE_VALUE,
                    b"Invalid value \"%s\" for xml:space : \"default\" or \"preserve\" expected\n\0"
                        as *const u8 as *const libc::c_char,
                    internal_val,
                    0 as *const xmlChar,
                );
            }
        }
        if !internal_val.is_null() {
            xmlFree
                .expect("non-null function pointer")(internal_val as *mut libc::c_void);
        }
    }
    *value = val;
    return name;
}
unsafe extern "C" fn xmlParseStartTag2(
    mut ctxt: xmlParserCtxtPtr,
    mut pref: *mut *const xmlChar,
    mut URI: *mut *const xmlChar,
    mut tlen: *mut libc::c_int,
) -> *const xmlChar {
    let mut current_block: u64;
    let mut localname: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    let mut attname: *const xmlChar = 0 as *const xmlChar;
    let mut aprefix: *const xmlChar = 0 as *const xmlChar;
    let mut nsname: *const xmlChar = 0 as *const xmlChar;
    let mut attvalue: *mut xmlChar = 0 as *mut xmlChar;
    let mut atts: *mut *const xmlChar = (*ctxt).atts;
    let mut maxatts: libc::c_int = (*ctxt).maxatts;
    let mut nratts: libc::c_int = 0;
    let mut nbatts: libc::c_int = 0;
    let mut nbdef: libc::c_int = 0;
    let mut inputid: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut nbNs: libc::c_int = 0;
    let mut attval: libc::c_int = 0;
    let mut cur: libc::c_ulong = 0;
    let mut nsNr: libc::c_int = (*ctxt).nsNr;
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32 {
        return 0 as *const xmlChar;
    }
    let ref mut fresh364 = (*(*ctxt).input).col;
    *fresh364 += 1;
    let ref mut fresh365 = (*(*ctxt).input).cur;
    *fresh365 = (*fresh365).offset(1);
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
    {
        xmlSHRINK(ctxt);
    }
    cur = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
        as libc::c_ulong;
    inputid = (*(*ctxt).input).id;
    nbatts = 0 as libc::c_int;
    nratts = 0 as libc::c_int;
    nbdef = 0 as libc::c_int;
    nbNs = 0 as libc::c_int;
    attval = 0 as libc::c_int;
    (*ctxt).nsNr = nsNr;
    localname = xmlParseQName(ctxt, &mut prefix);
    if localname.is_null() {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_NAME_REQUIRED,
            b"StartTag: invalid element name\n\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *const xmlChar;
    }
    *tlen = (((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
        as libc::c_ulong)
        .wrapping_sub(cur) as libc::c_int;
    xmlSkipBlankChars(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    loop {
        if !(*(*(*ctxt).input).cur as libc::c_int != '>' as i32
            && (*(*(*ctxt).input).cur as libc::c_int != '/' as i32
                || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int != '>' as i32)
            && (0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
                || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
                || 0x20 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int)
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int)
        {
            current_block = 9587810615301548814;
            break;
        }
        let mut id: libc::c_int = (*(*ctxt).input).id;
        let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        let mut len: libc::c_int = -(1 as libc::c_int);
        let mut alloc: libc::c_int = 0 as libc::c_int;
        attname = xmlParseAttribute2(
            ctxt,
            prefix,
            localname,
            &mut aprefix,
            &mut attvalue,
            &mut len,
            &mut alloc,
        );
        if !(attname.is_null() || attvalue.is_null()) {
            if len < 0 as libc::c_int {
                len = xmlStrlen(attvalue);
            }
            if attname == (*ctxt).str_xmlns && aprefix.is_null() {
                let mut URL: *const xmlChar = xmlDictLookup((*ctxt).dict, attvalue, len);
                let mut uri: xmlURIPtr = 0 as *mut xmlURI;
                if URL.is_null() {
                    xmlErrMemory(
                        ctxt,
                        b"dictionary allocation failure\0" as *const u8
                            as *const libc::c_char,
                    );
                    if !attvalue.is_null() && alloc != 0 as libc::c_int {
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(attvalue as *mut libc::c_void);
                    }
                    localname = 0 as *const xmlChar;
                    current_block = 11274969702264896952;
                    break;
                } else {
                    if *URL as libc::c_int != 0 as libc::c_int {
                        uri = xmlParseURI(URL as *const libc::c_char);
                        if uri.is_null() {
                            xmlNsErr(
                                ctxt,
                                XML_WAR_NS_URI,
                                b"xmlns: '%s' is not a valid URI\n\0" as *const u8
                                    as *const libc::c_char,
                                URL,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                        } else {
                            if ((*uri).scheme).is_null() {
                                xmlNsWarn(
                                    ctxt,
                                    XML_WAR_NS_URI_RELATIVE,
                                    b"xmlns: URI %s is not absolute\n\0" as *const u8
                                        as *const libc::c_char,
                                    URL,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            xmlFreeURI(uri);
                        }
                        if URL == (*ctxt).str_xml_ns {
                            if attname != (*ctxt).str_xml {
                                xmlNsErr(
                                    ctxt,
                                    XML_NS_ERR_XML_NAMESPACE,
                                    b"xml namespace URI cannot be the default namespace\n\0"
                                        as *const u8 as *const libc::c_char,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                    0 as *const xmlChar,
                                );
                            }
                            current_block = 7554104004771910880;
                        } else if len == 29 as libc::c_int
                                && xmlStrEqual(
                                    URL,
                                    b"http://www.w3.org/2000/xmlns/\0" as *const u8
                                        as *const libc::c_char as *mut xmlChar,
                                ) != 0
                            {
                            xmlNsErr(
                                ctxt,
                                XML_NS_ERR_XML_NAMESPACE,
                                b"reuse of the xmlns namespace name is forbidden\n\0"
                                    as *const u8 as *const libc::c_char,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                                0 as *const xmlChar,
                            );
                            current_block = 7554104004771910880;
                        } else {
                            current_block = 1623252117315916725;
                        }
                    } else {
                        current_block = 1623252117315916725;
                    }
                    match current_block {
                        7554104004771910880 => {}
                        _ => {
                            j = 1 as libc::c_int;
                            while j <= nbNs {
                                if (*((*ctxt).nsTab)
                                    .offset(((*ctxt).nsNr - 2 as libc::c_int * j) as isize))
                                    .is_null()
                                {
                                    break;
                                }
                                j += 1;
                            }
                            if j <= nbNs {
                                xmlErrAttributeDup(ctxt, 0 as *const xmlChar, attname);
                            } else if nsPush(ctxt, 0 as *const xmlChar, URL)
                                    > 0 as libc::c_int
                                {
                                nbNs += 1;
                            }
                        }
                    }
                }
            } else if aprefix == (*ctxt).str_xmlns {
                let mut URL_0: *const xmlChar = xmlDictLookup(
                    (*ctxt).dict,
                    attvalue,
                    len,
                );
                let mut uri_0: xmlURIPtr = 0 as *mut xmlURI;
                if attname == (*ctxt).str_xml {
                    if URL_0 != (*ctxt).str_xml_ns {
                        xmlNsErr(
                            ctxt,
                            XML_NS_ERR_XML_NAMESPACE,
                            b"xml namespace prefix mapped to wrong URI\n\0" as *const u8
                                as *const libc::c_char,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else if URL_0 == (*ctxt).str_xml_ns {
                    if attname != (*ctxt).str_xml {
                        xmlNsErr(
                            ctxt,
                            XML_NS_ERR_XML_NAMESPACE,
                            b"xml namespace URI mapped to wrong prefix\n\0" as *const u8
                                as *const libc::c_char,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                            0 as *const xmlChar,
                        );
                    }
                } else if attname == (*ctxt).str_xmlns {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"redefinition of the xmlns prefix is forbidden\n\0" as *const u8
                            as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else if len == 29 as libc::c_int
                        && xmlStrEqual(
                            URL_0,
                            b"http://www.w3.org/2000/xmlns/\0" as *const u8
                                as *const libc::c_char as *mut xmlChar,
                        ) != 0
                    {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"reuse of the xmlns namespace name is forbidden\n\0"
                            as *const u8 as *const libc::c_char,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else if URL_0.is_null()
                        || *URL_0.offset(0 as libc::c_int as isize) as libc::c_int
                            == 0 as libc::c_int
                    {
                    xmlNsErr(
                        ctxt,
                        XML_NS_ERR_XML_NAMESPACE,
                        b"xmlns:%s: Empty XML namespace is not allowed\n\0" as *const u8
                            as *const libc::c_char,
                        attname,
                        0 as *const xmlChar,
                        0 as *const xmlChar,
                    );
                } else {
                    uri_0 = xmlParseURI(URL_0 as *const libc::c_char);
                    if uri_0.is_null() {
                        xmlNsErr(
                            ctxt,
                            XML_WAR_NS_URI,
                            b"xmlns:%s: '%s' is not a valid URI\n\0" as *const u8
                                as *const libc::c_char,
                            attname,
                            URL_0,
                            0 as *const xmlChar,
                        );
                    } else {
                        if (*ctxt).pedantic != 0 && ((*uri_0).scheme).is_null() {
                            xmlNsWarn(
                                ctxt,
                                XML_WAR_NS_URI_RELATIVE,
                                b"xmlns:%s: URI %s is not absolute\n\0" as *const u8
                                    as *const libc::c_char,
                                attname,
                                URL_0,
                                0 as *const xmlChar,
                            );
                        }
                        xmlFreeURI(uri_0);
                    }
                    j = 1 as libc::c_int;
                    while j <= nbNs {
                        if *((*ctxt).nsTab)
                            .offset(((*ctxt).nsNr - 2 as libc::c_int * j) as isize)
                            == attname
                        {
                            break;
                        }
                        j += 1;
                    }
                    if j <= nbNs {
                        xmlErrAttributeDup(ctxt, aprefix, attname);
                    } else if nsPush(ctxt, attname, URL_0) > 0 as libc::c_int {
                        nbNs += 1;
                    }
                }
            } else {
                if atts.is_null() || nbatts + 5 as libc::c_int > maxatts {
                    if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as libc::c_int)
                        < 0 as libc::c_int
                    {
                        current_block = 7554104004771910880;
                    } else {
                        maxatts = (*ctxt).maxatts;
                        atts = (*ctxt).atts;
                        current_block = 2463987395154258233;
                    }
                } else {
                    current_block = 2463987395154258233;
                }
                match current_block {
                    7554104004771910880 => {}
                    _ => {
                        let fresh366 = nratts;
                        nratts = nratts + 1;
                        *((*ctxt).attallocs).offset(fresh366 as isize) = alloc;
                        let fresh367 = nbatts;
                        nbatts = nbatts + 1;
                        let ref mut fresh368 = *atts.offset(fresh367 as isize);
                        *fresh368 = attname;
                        let fresh369 = nbatts;
                        nbatts = nbatts + 1;
                        let ref mut fresh370 = *atts.offset(fresh369 as isize);
                        *fresh370 = aprefix;
                        if alloc != 0 {
                            let fresh371 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh372 = *atts.offset(fresh371 as isize);
                            *fresh372 = 0 as *const xmlChar;
                        } else {
                            let fresh373 = nbatts;
                            nbatts = nbatts + 1;
                            let ref mut fresh374 = *atts.offset(fresh373 as isize);
                            *fresh374 = (*(*ctxt).input).base;
                        }
                        let fresh375 = nbatts;
                        nbatts = nbatts + 1;
                        let ref mut fresh376 = *atts.offset(fresh375 as isize);
                        *fresh376 = attvalue;
                        attvalue = attvalue.offset(len as isize);
                        let fresh377 = nbatts;
                        nbatts = nbatts + 1;
                        let ref mut fresh378 = *atts.offset(fresh377 as isize);
                        *fresh378 = attvalue;
                        if alloc != 0 as libc::c_int {
                            attval = 1 as libc::c_int;
                        }
                        attvalue = 0 as *mut xmlChar;
                    }
                }
            }
        }
        if !attvalue.is_null() && alloc != 0 as libc::c_int {
            xmlFree.expect("non-null function pointer")(attvalue as *mut libc::c_void);
            attvalue = 0 as *mut xmlChar;
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            current_block = 9587810615301548814;
            break;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '>' as i32
            || *(*(*ctxt).input).cur as libc::c_int == '/' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == '>' as i32
        {
            current_block = 9587810615301548814;
            break;
        }
        if xmlSkipBlankChars(ctxt) == 0 as libc::c_int {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_SPACE_REQUIRED,
                b"attributes construct error\n\0" as *const u8 as *const libc::c_char,
            );
            current_block = 9587810615301548814;
            break;
        } else if cons
                == ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long as libc::c_ulong,
                    ) && id == (*(*ctxt).input).id && attname.is_null()
                && attvalue.is_null()
            {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"xmlParseStartTag: problem parsing attributes\n\0" as *const u8
                    as *const libc::c_char,
            );
            current_block = 9587810615301548814;
            break;
        } else if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
            xmlGROW(ctxt);
        }
    }
    match current_block {
        9587810615301548814 => {
            if (*(*ctxt).input).id != inputid {
                xmlFatalErr(
                    ctxt,
                    XML_ERR_INTERNAL_ERROR,
                    b"Unexpected change of input\n\0" as *const u8 as *const libc::c_char,
                );
                localname = 0 as *const xmlChar;
            } else {
                i = 0 as libc::c_int;
                j = 0 as libc::c_int;
                while j < nratts {
                    if !(*atts.offset((i + 2 as libc::c_int) as isize)).is_null() {
                        let mut offset: ptrdiff_t = ((*(*ctxt).input).base)
                            .offset_from(*atts.offset((i + 2 as libc::c_int) as isize))
                            as libc::c_long;
                        let ref mut fresh379 = *atts
                            .offset((i + 2 as libc::c_int) as isize);
                        *fresh379 = 0 as *const xmlChar;
                        let ref mut fresh380 = *atts
                            .offset((i + 3 as libc::c_int) as isize);
                        *fresh380 = (*fresh380).offset(offset as isize);
                        let ref mut fresh381 = *atts
                            .offset((i + 4 as libc::c_int) as isize);
                        *fresh381 = (*fresh381).offset(offset as isize);
                    }
                    i += 5 as libc::c_int;
                    j += 1;
                }
                if !((*ctxt).attsDefault).is_null() {
                    let mut defaults: xmlDefAttrsPtr = 0 as *mut xmlDefAttrs;
                    defaults = xmlHashLookup2((*ctxt).attsDefault, localname, prefix)
                        as xmlDefAttrsPtr;
                    if !defaults.is_null() {
                        i = 0 as libc::c_int;
                        loop {
                            if !(i < (*defaults).nbAttrs) {
                                current_block = 981657943452992752;
                                break;
                            }
                            attname = *((*defaults).values)
                                .as_mut_ptr()
                                .offset((5 as libc::c_int * i) as isize);
                            aprefix = *((*defaults).values)
                                .as_mut_ptr()
                                .offset((5 as libc::c_int * i + 1 as libc::c_int) as isize);
                            if attname == (*ctxt).str_xmlns && aprefix.is_null() {
                                j = 1 as libc::c_int;
                                while j <= nbNs {
                                    if (*((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as libc::c_int * j) as isize))
                                        .is_null()
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, 0 as *const xmlChar);
                                    if nsname
                                        != *((*defaults).values)
                                            .as_mut_ptr()
                                            .offset((5 as libc::c_int * i + 2 as libc::c_int) as isize)
                                    {
                                        if nsPush(
                                            ctxt,
                                            0 as *const xmlChar,
                                            *((*defaults).values)
                                                .as_mut_ptr()
                                                .offset((5 as libc::c_int * i + 2 as libc::c_int) as isize),
                                        ) > 0 as libc::c_int
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else if aprefix == (*ctxt).str_xmlns {
                                j = 1 as libc::c_int;
                                while j <= nbNs {
                                    if *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as libc::c_int * j) as isize)
                                        == attname
                                    {
                                        break;
                                    }
                                    j += 1;
                                }
                                if !(j <= nbNs) {
                                    nsname = xmlGetNamespace(ctxt, attname);
                                    if nsname
                                        != *((*defaults).values)
                                            .as_mut_ptr()
                                            .offset(2 as libc::c_int as isize)
                                    {
                                        if nsPush(
                                            ctxt,
                                            attname,
                                            *((*defaults).values)
                                                .as_mut_ptr()
                                                .offset((5 as libc::c_int * i + 2 as libc::c_int) as isize),
                                        ) > 0 as libc::c_int
                                        {
                                            nbNs += 1;
                                        }
                                    }
                                }
                            } else {
                                j = 0 as libc::c_int;
                                while j < nbatts {
                                    if attname == *atts.offset(j as isize)
                                        && aprefix == *atts.offset((j + 1 as libc::c_int) as isize)
                                    {
                                        break;
                                    }
                                    j += 5 as libc::c_int;
                                }
                                if !(j < nbatts) {
                                    if atts.is_null() || nbatts + 5 as libc::c_int > maxatts {
                                        if xmlCtxtGrowAttrs(ctxt, nbatts + 5 as libc::c_int)
                                            < 0 as libc::c_int
                                        {
                                            localname = 0 as *const xmlChar;
                                            current_block = 11274969702264896952;
                                            break;
                                        } else {
                                            maxatts = (*ctxt).maxatts;
                                            atts = (*ctxt).atts;
                                        }
                                    }
                                    let fresh382 = nbatts;
                                    nbatts = nbatts + 1;
                                    let ref mut fresh383 = *atts.offset(fresh382 as isize);
                                    *fresh383 = attname;
                                    let fresh384 = nbatts;
                                    nbatts = nbatts + 1;
                                    let ref mut fresh385 = *atts.offset(fresh384 as isize);
                                    *fresh385 = aprefix;
                                    if aprefix.is_null() {
                                        let fresh386 = nbatts;
                                        nbatts = nbatts + 1;
                                        let ref mut fresh387 = *atts.offset(fresh386 as isize);
                                        *fresh387 = 0 as *const xmlChar;
                                    } else {
                                        let fresh388 = nbatts;
                                        nbatts = nbatts + 1;
                                        let ref mut fresh389 = *atts.offset(fresh388 as isize);
                                        *fresh389 = xmlGetNamespace(ctxt, aprefix);
                                    }
                                    let fresh390 = nbatts;
                                    nbatts = nbatts + 1;
                                    let ref mut fresh391 = *atts.offset(fresh390 as isize);
                                    *fresh391 = *((*defaults).values)
                                        .as_mut_ptr()
                                        .offset((5 as libc::c_int * i + 2 as libc::c_int) as isize);
                                    let fresh392 = nbatts;
                                    nbatts = nbatts + 1;
                                    let ref mut fresh393 = *atts.offset(fresh392 as isize);
                                    *fresh393 = *((*defaults).values)
                                        .as_mut_ptr()
                                        .offset((5 as libc::c_int * i + 3 as libc::c_int) as isize);
                                    if (*ctxt).standalone == 1 as libc::c_int
                                        && !(*((*defaults).values)
                                            .as_mut_ptr()
                                            .offset((5 as libc::c_int * i + 4 as libc::c_int) as isize))
                                            .is_null()
                                    {
                                        xmlValidityError(
                                            ctxt,
                                            XML_DTD_STANDALONE_DEFAULTED,
                                            b"standalone: attribute %s on %s defaulted from external subset\n\0"
                                                as *const u8 as *const libc::c_char,
                                            attname,
                                            localname,
                                        );
                                    }
                                    nbdef += 1;
                                }
                            }
                            i += 1;
                        }
                    } else {
                        current_block = 981657943452992752;
                    }
                } else {
                    current_block = 981657943452992752;
                }
                match current_block {
                    11274969702264896952 => {}
                    _ => {
                        i = 0 as libc::c_int;
                        while i < nbatts {
                            if !(*atts.offset((i + 1 as libc::c_int) as isize)).is_null()
                            {
                                nsname = xmlGetNamespace(
                                    ctxt,
                                    *atts.offset((i + 1 as libc::c_int) as isize),
                                );
                                if nsname.is_null() {
                                    xmlNsErr(
                                        ctxt,
                                        XML_NS_ERR_UNDEFINED_NAMESPACE,
                                        b"Namespace prefix %s for %s on %s is not defined\n\0"
                                            as *const u8 as *const libc::c_char,
                                        *atts.offset((i + 1 as libc::c_int) as isize),
                                        *atts.offset(i as isize),
                                        localname,
                                    );
                                }
                                let ref mut fresh394 = *atts
                                    .offset((i + 2 as libc::c_int) as isize);
                                *fresh394 = nsname;
                            } else {
                                nsname = 0 as *const xmlChar;
                            }
                            j = 0 as libc::c_int;
                            while j < i {
                                if *atts.offset(i as isize) == *atts.offset(j as isize) {
                                    if *atts.offset((i + 1 as libc::c_int) as isize)
                                        == *atts.offset((j + 1 as libc::c_int) as isize)
                                    {
                                        xmlErrAttributeDup(
                                            ctxt,
                                            *atts.offset((i + 1 as libc::c_int) as isize),
                                            *atts.offset(i as isize),
                                        );
                                        break;
                                    } else if !nsname.is_null()
                                            && *atts.offset((j + 2 as libc::c_int) as isize) == nsname
                                        {
                                        xmlNsErr(
                                            ctxt,
                                            XML_NS_ERR_ATTRIBUTE_REDEFINED,
                                            b"Namespaced Attribute %s in '%s' redefined\n\0"
                                                as *const u8 as *const libc::c_char,
                                            *atts.offset(i as isize),
                                            nsname,
                                            0 as *const xmlChar,
                                        );
                                        break;
                                    }
                                }
                                j += 5 as libc::c_int;
                            }
                            i += 5 as libc::c_int;
                        }
                        nsname = xmlGetNamespace(ctxt, prefix);
                        if !prefix.is_null() && nsname.is_null() {
                            xmlNsErr(
                                ctxt,
                                XML_NS_ERR_UNDEFINED_NAMESPACE,
                                b"Namespace prefix %s on %s is not defined\n\0" as *const u8
                                    as *const libc::c_char,
                                prefix,
                                localname,
                                0 as *const xmlChar,
                            );
                        }
                        *pref = prefix;
                        *URI = nsname;
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).startElementNs).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if nbNs > 0 as libc::c_int {
                                ((*(*ctxt).sax).startElementNs)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    localname,
                                    prefix,
                                    nsname,
                                    nbNs,
                                    &mut *((*ctxt).nsTab)
                                        .offset(((*ctxt).nsNr - 2 as libc::c_int * nbNs) as isize),
                                    nbatts / 5 as libc::c_int,
                                    nbdef,
                                    atts,
                                );
                            } else {
                                ((*(*ctxt).sax).startElementNs)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    localname,
                                    prefix,
                                    nsname,
                                    0 as libc::c_int,
                                    0 as *mut *const xmlChar,
                                    nbatts / 5 as libc::c_int,
                                    nbdef,
                                    atts,
                                );
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if attval != 0 as libc::c_int {
        i = 3 as libc::c_int;
        j = 0 as libc::c_int;
        while j < nratts {
            if *((*ctxt).attallocs).offset(j as isize) != 0 as libc::c_int
                && !(*atts.offset(i as isize)).is_null()
            {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*atts.offset(i as isize) as *mut xmlChar as *mut libc::c_void);
            }
            i += 5 as libc::c_int;
            j += 1;
        }
    }
    return localname;
}
unsafe extern "C" fn xmlParseEndTag2(
    mut ctxt: xmlParserCtxtPtr,
    mut tag: *const xmlStartTag,
) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32
        || *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            != '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_LTSLASH_REQUIRED, 0 as *const libc::c_char);
        return;
    }
    let ref mut fresh395 = (*(*ctxt).input).cur;
    *fresh395 = (*fresh395).offset(2 as libc::c_int as isize);
    (*(*ctxt).input).col += 2 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    if ((*tag).prefix).is_null() {
        name = xmlParseNameAndCompare(ctxt, (*ctxt).name);
    } else {
        name = xmlParseQNameAndCompare(ctxt, (*ctxt).name, (*tag).prefix);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    xmlSkipBlankChars(ctxt);
    if !(0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
        && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
        || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int
        || 0x20 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int)
        || *(*(*ctxt).input).cur as libc::c_int != '>' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_GT_REQUIRED, 0 as *const libc::c_char);
    } else {
        let ref mut fresh396 = (*(*ctxt).input).col;
        *fresh396 += 1;
        let ref mut fresh397 = (*(*ctxt).input).cur;
        *fresh397 = (*fresh397).offset(1);
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    }
    if name != 1 as libc::c_int as *mut xmlChar as *const xmlChar {
        if name.is_null() {
            name = b"unparsable\0" as *const u8 as *const libc::c_char as *mut xmlChar;
        }
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NAME_MISMATCH,
            b"Opening and ending tag mismatch: %s line %d and %s\n\0" as *const u8
                as *const libc::c_char,
            (*ctxt).name,
            (*tag).line,
            name,
        );
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElementNs).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).endElementNs)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, (*ctxt).name, (*tag).prefix, (*tag).URI);
    }
    spacePop(ctxt);
    if (*tag).nsNr != 0 as libc::c_int {
        nsPop(ctxt, (*tag).nsNr);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCDSect(mut ctxt: xmlParserCtxtPtr) {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 100 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut rl: libc::c_int = 0;
    let mut s: libc::c_int = 0;
    let mut sl: libc::c_int = 0;
    let mut cur: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut count: libc::c_int = 0 as libc::c_int;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == '[' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'C' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'D' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'A' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == '[' as i32
    {
        let ref mut fresh398 = (*(*ctxt).input).cur;
        *fresh398 = (*fresh398).offset(9 as libc::c_int as isize);
        (*(*ctxt).input).col += 9 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    } else {
        return
    }
    (*ctxt).instate = XML_PARSER_CDATA_SECTION;
    r = xmlCurrentChar(ctxt, &mut rl);
    if if r < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= r && r <= 0xa as libc::c_int || r == 0xd as libc::c_int
            || 0x20 as libc::c_int <= r) as libc::c_int
    } else {
        (0x100 as libc::c_int <= r && r <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= r && r <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= r && r <= 0x10ffff as libc::c_int)
            as libc::c_int
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const libc::c_char);
        (*ctxt).instate = XML_PARSER_CONTENT;
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
        let ref mut fresh399 = (*(*ctxt).input).line;
        *fresh399 += 1;
        (*(*ctxt).input).col = 1 as libc::c_int;
    } else {
        let ref mut fresh400 = (*(*ctxt).input).col;
        *fresh400 += 1;
    }
    let ref mut fresh401 = (*(*ctxt).input).cur;
    *fresh401 = (*fresh401).offset(rl as isize);
    s = xmlCurrentChar(ctxt, &mut sl);
    if if s < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= s && s <= 0xa as libc::c_int || s == 0xd as libc::c_int
            || 0x20 as libc::c_int <= s) as libc::c_int
    } else {
        (0x100 as libc::c_int <= s && s <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= s && s <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= s && s <= 0x10ffff as libc::c_int)
            as libc::c_int
    } == 0
    {
        xmlFatalErr(ctxt, XML_ERR_CDATA_NOT_FINISHED, 0 as *const libc::c_char);
        (*ctxt).instate = XML_PARSER_CONTENT;
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
        let ref mut fresh402 = (*(*ctxt).input).line;
        *fresh402 += 1;
        (*(*ctxt).input).col = 1 as libc::c_int;
    } else {
        let ref mut fresh403 = (*(*ctxt).input).col;
        *fresh403 += 1;
    }
    let ref mut fresh404 = (*(*ctxt).input).cur;
    *fresh404 = (*fresh404).offset(sl as isize);
    cur = xmlCurrentChar(ctxt, &mut l);
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
        return;
    }
    while (if cur < 0x100 as libc::c_int {
        (0x9 as libc::c_int <= cur && cur <= 0xa as libc::c_int
            || cur == 0xd as libc::c_int || 0x20 as libc::c_int <= cur) as libc::c_int
    } else {
        (0x100 as libc::c_int <= cur && cur <= 0xd7ff as libc::c_int
            || 0xe000 as libc::c_int <= cur && cur <= 0xfffd as libc::c_int
            || 0x10000 as libc::c_int <= cur && cur <= 0x10ffff as libc::c_int)
            as libc::c_int
    }) != 0 && (r != ']' as i32 || s != ']' as i32 || cur != '>' as i32)
    {
        if len + 5 as libc::c_int >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            if size > 10000000 as libc::c_int
                && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
            {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_CDATA_NOT_FINISHED,
                    b"CData section too big found\0" as *const u8 as *const libc::c_char,
                    0 as *const xmlChar,
                );
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                ((size * 2 as libc::c_int) as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                return;
            }
            buf = tmp;
            size *= 2 as libc::c_int;
        }
        if rl == 1 as libc::c_int {
            let fresh405 = len;
            len = len + 1;
            *buf.offset(fresh405 as isize) = r as xmlChar;
        } else {
            len += xmlCopyCharMultiByte(&mut *buf.offset(len as isize), r);
        }
        r = s;
        rl = sl;
        s = cur;
        sl = l;
        count += 1;
        if count > 50 as libc::c_int {
            if (*ctxt).progressive == 0 as libc::c_int
                && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long
                    > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long)
                    < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            {
                xmlSHRINK(ctxt);
            }
            if (*ctxt).progressive == 0 as libc::c_int
                && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                    as libc::c_long) < 250 as libc::c_int as libc::c_long
            {
                xmlGROW(ctxt);
            }
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                return;
            }
            count = 0 as libc::c_int;
        }
        if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
            let ref mut fresh406 = (*(*ctxt).input).line;
            *fresh406 += 1;
            (*(*ctxt).input).col = 1 as libc::c_int;
        } else {
            let ref mut fresh407 = (*(*ctxt).input).col;
            *fresh407 += 1;
        }
        let ref mut fresh408 = (*(*ctxt).input).cur;
        *fresh408 = (*fresh408).offset(l as isize);
        cur = xmlCurrentChar(ctxt, &mut l);
    }
    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    (*ctxt).instate = XML_PARSER_CONTENT;
    if cur != '>' as i32 {
        xmlFatalErrMsgStr(
            ctxt,
            XML_ERR_CDATA_NOT_FINISHED,
            b"CData section not finished\n%.50s\n\0" as *const u8 as *const libc::c_char,
            buf,
        );
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
        let ref mut fresh409 = (*(*ctxt).input).line;
        *fresh409 += 1;
        (*(*ctxt).input).col = 1 as libc::c_int;
    } else {
        let ref mut fresh410 = (*(*ctxt).input).col;
        *fresh410 += 1;
    }
    let ref mut fresh411 = (*(*ctxt).input).cur;
    *fresh411 = (*fresh411).offset(l as isize);
    if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
        if ((*(*ctxt).sax).cdataBlock).is_some() {
            ((*(*ctxt).sax).cdataBlock)
                .expect("non-null function pointer")((*ctxt).userData, buf, len);
        } else if ((*(*ctxt).sax).characters).is_some() {
            ((*(*ctxt).sax).characters)
                .expect("non-null function pointer")((*ctxt).userData, buf, len);
        }
    }
    xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
}
unsafe extern "C" fn xmlParseContentInternal(mut ctxt: xmlParserCtxtPtr) {
    let mut nameNr: libc::c_int = (*ctxt).nameNr;
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    while *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int
        && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
    {
        let mut id: libc::c_int = (*(*ctxt).input).id;
        let mut cons: libc::c_ulong = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        let mut cur: *const xmlChar = (*(*ctxt).input).cur;
        if *cur as libc::c_int == '<' as i32
            && *cur.offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        {
            xmlParsePI(ctxt);
        } else if *((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == '<' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == '[' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == 'C' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(4 as libc::c_int as isize) as libc::c_int == 'D' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(5 as libc::c_int as isize) as libc::c_int == 'A' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(6 as libc::c_int as isize) as libc::c_int == 'T' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(7 as libc::c_int as isize) as libc::c_int == 'A' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(8 as libc::c_int as isize) as libc::c_int == '[' as i32
            {
            xmlParseCDSect(ctxt);
        } else if *cur as libc::c_int == '<' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == '!' as i32
                && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                    as libc::c_int == '-' as i32
                && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                    as libc::c_int == '-' as i32
            {
            xmlParseComment(ctxt);
            (*ctxt).instate = XML_PARSER_CONTENT;
        } else if *cur as libc::c_int == '<' as i32 {
            if *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '/' as i32
            {
                if (*ctxt).nameNr <= nameNr {
                    break;
                }
                xmlParseElementEnd(ctxt);
            } else {
                xmlParseElementStart(ctxt);
            }
        } else if *cur as libc::c_int == '&' as i32 {
            xmlParseReference(ctxt);
        } else {
            xmlParseCharData(ctxt, 0 as libc::c_int);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if (*ctxt).progressive == 0 as libc::c_int
            && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
        {
            xmlSHRINK(ctxt);
        }
        if !(cons
            == ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                ) && id == (*(*ctxt).input).id)
        {
            continue;
        }
        xmlFatalErr(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"detected an error in element content\n\0" as *const u8
                as *const libc::c_char,
        );
        xmlHaltParser(ctxt);
        break;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseContent(mut ctxt: xmlParserCtxtPtr) {
    let mut nameNr: libc::c_int = (*ctxt).nameNr;
    xmlParseContentInternal(ctxt);
    if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        && (*ctxt).nameNr > nameNr
    {
        let mut name: *const xmlChar = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize);
        let mut line: libc::c_int = (*((*ctxt).pushTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize))
            .line;
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8
                as *const libc::c_char,
            name,
            line,
            0 as *const xmlChar,
        );
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseElement(mut ctxt: xmlParserCtxtPtr) {
    if xmlParseElementStart(ctxt) != 0 as libc::c_int {
        return;
    }
    xmlParseContentInternal(ctxt);
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return;
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        let mut name: *const xmlChar = *((*ctxt).nameTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize);
        let mut line: libc::c_int = (*((*ctxt).pushTab)
            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize))
            .line;
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_TAG_NOT_FINISHED,
            b"Premature end of data in tag %s line %d\n\0" as *const u8
                as *const libc::c_char,
            name,
            line,
            0 as *const xmlChar,
        );
        return;
    }
    xmlParseElementEnd(ctxt);
}
unsafe extern "C" fn xmlParseElementStart(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut prefix: *const xmlChar = 0 as *const xmlChar;
    let mut URI: *const xmlChar = 0 as *const xmlChar;
    let mut node_info: xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut line: libc::c_int = 0;
    let mut tlen: libc::c_int = 0 as libc::c_int;
    let mut ret: xmlNodePtr = 0 as *mut xmlNode;
    let mut nsNr: libc::c_int = (*ctxt).nsNr;
    if (*ctxt).nameNr as libc::c_uint > xmlParserMaxDepth
        && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
    {
        xmlFatalErrMsgInt(
            ctxt,
            XML_ERR_INTERNAL_ERROR,
            b"Excessive depth in document: %d use XML_PARSE_HUGE option\n\0" as *const u8
                as *const libc::c_char,
            xmlParserMaxDepth as libc::c_int,
        );
        xmlHaltParser(ctxt);
        return -(1 as libc::c_int);
    }
    if (*ctxt).record_info != 0 {
        node_info
            .begin_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        node_info.begin_line = (*(*ctxt).input).line as libc::c_ulong;
    }
    if (*ctxt).spaceNr == 0 as libc::c_int {
        spacePush(ctxt, -(1 as libc::c_int));
    } else if *(*ctxt).space == -(2 as libc::c_int) {
        spacePush(ctxt, -(1 as libc::c_int));
    } else {
        spacePush(ctxt, *(*ctxt).space);
    }
    line = (*(*ctxt).input).line;
    if (*ctxt).sax2 != 0 {
        name = xmlParseStartTag2(ctxt, &mut prefix, &mut URI, &mut tlen);
    } else {
        name = xmlParseStartTag(ctxt);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if name.is_null() {
        spacePop(ctxt);
        return -(1 as libc::c_int);
    }
    nameNsPush(ctxt, name, prefix, URI, line, (*ctxt).nsNr - nsNr);
    ret = (*ctxt).node;
    if (*ctxt).validate != 0 && (*ctxt).wellFormed != 0 && !((*ctxt).myDoc).is_null()
        && !((*ctxt).node).is_null() && (*ctxt).node == (*(*ctxt).myDoc).children
    {
        (*ctxt).valid &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '/' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '>' as i32
    {
        let ref mut fresh412 = (*(*ctxt).input).cur;
        *fresh412 = (*fresh412).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        if (*ctxt).sax2 != 0 {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElementNs).is_some()
                && (*ctxt).disableSAX == 0
            {
                ((*(*ctxt).sax).endElementNs)
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).userData, name, prefix, URI);
            }
        } else if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endElement).is_some()
                && (*ctxt).disableSAX == 0
            {
            ((*(*ctxt).sax).endElement)
                .expect("non-null function pointer")((*ctxt).userData, name);
        }
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (*ctxt).nsNr {
            nsPop(ctxt, (*ctxt).nsNr - nsNr);
        }
        if !ret.is_null() && (*ctxt).record_info != 0 {
            node_info
                .end_pos = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
            node_info.end_line = (*(*ctxt).input).line as libc::c_ulong;
            node_info.node = ret as *const _xmlNode;
            xmlParserAddNodeInfo(ctxt, &mut node_info);
        }
        return 1 as libc::c_int;
    }
    if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        let ref mut fresh413 = (*(*ctxt).input).col;
        *fresh413 += 1;
        let ref mut fresh414 = (*(*ctxt).input).cur;
        *fresh414 = (*fresh414).offset(1);
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    } else {
        xmlFatalErrMsgStrIntStr(
            ctxt,
            XML_ERR_GT_REQUIRED,
            b"Couldn't find end of Start Tag %s line %d\n\0" as *const u8
                as *const libc::c_char,
            name,
            line,
            0 as *const xmlChar,
        );
        nodePop(ctxt);
        namePop(ctxt);
        spacePop(ctxt);
        if nsNr != (*ctxt).nsNr {
            nsPop(ctxt, (*ctxt).nsNr - nsNr);
        }
        if !ret.is_null() && (*ctxt).record_info != 0 {
            node_info
                .end_pos = ((*(*ctxt).input).consumed)
                .wrapping_add(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                );
            node_info.end_line = (*(*ctxt).input).line as libc::c_ulong;
            node_info.node = ret as *const _xmlNode;
            xmlParserAddNodeInfo(ctxt, &mut node_info);
        }
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlParseElementEnd(mut ctxt: xmlParserCtxtPtr) {
    let mut node_info: xmlParserNodeInfo = xmlParserNodeInfo {
        node: 0 as *const _xmlNode,
        begin_pos: 0,
        begin_line: 0,
        end_pos: 0,
        end_line: 0,
    };
    let mut ret: xmlNodePtr = (*ctxt).node;
    if (*ctxt).nameNr <= 0 as libc::c_int {
        return;
    }
    if (*ctxt).sax2 != 0 {
        xmlParseEndTag2(
            ctxt,
            &mut *((*ctxt).pushTab).offset(((*ctxt).nameNr - 1 as libc::c_int) as isize),
        );
        namePop(ctxt);
    } else {
        xmlParseEndTag1(ctxt, 0 as libc::c_int);
    }
    if !ret.is_null() && (*ctxt).record_info != 0 {
        node_info
            .end_pos = ((*(*ctxt).input).consumed)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
        node_info.end_line = (*(*ctxt).input).line as libc::c_ulong;
        node_info.node = ret as *const _xmlNode;
        xmlParserAddNodeInfo(ctxt, &mut node_info);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseVersionNum(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 10 as libc::c_int;
    let mut cur: xmlChar = 0;
    buf = xmlMallocAtomic
        .expect(
            "non-null function pointer",
        )(
        (size as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
    ) as *mut xmlChar;
    if buf.is_null() {
        xmlErrMemory(ctxt, 0 as *const libc::c_char);
        return 0 as *mut xmlChar;
    }
    cur = *(*(*ctxt).input).cur;
    if !(cur as libc::c_int >= '0' as i32 && cur as libc::c_int <= '9' as i32) {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    let fresh415 = len;
    len = len + 1;
    *buf.offset(fresh415 as isize) = cur;
    xmlNextChar(ctxt);
    cur = *(*(*ctxt).input).cur;
    if cur as libc::c_int != '.' as i32 {
        xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
        return 0 as *mut xmlChar;
    }
    let fresh416 = len;
    len = len + 1;
    *buf.offset(fresh416 as isize) = cur;
    xmlNextChar(ctxt);
    cur = *(*(*ctxt).input).cur;
    while cur as libc::c_int >= '0' as i32 && cur as libc::c_int <= '9' as i32 {
        if len + 1 as libc::c_int >= size {
            let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
            size *= 2 as libc::c_int;
            tmp = xmlRealloc
                .expect(
                    "non-null function pointer",
                )(
                buf as *mut libc::c_void,
                (size as libc::c_ulong)
                    .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
            ) as *mut xmlChar;
            if tmp.is_null() {
                xmlFree.expect("non-null function pointer")(buf as *mut libc::c_void);
                xmlErrMemory(ctxt, 0 as *const libc::c_char);
                return 0 as *mut xmlChar;
            }
            buf = tmp;
        }
        let fresh417 = len;
        len = len + 1;
        *buf.offset(fresh417 as isize) = cur;
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
    }
    *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseVersionInfo(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut xmlChar {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 'v' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'e' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'r' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 's' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'i' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'o' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'n' as i32
    {
        let ref mut fresh418 = (*(*ctxt).input).cur;
        *fresh418 = (*fresh418).offset(7 as libc::c_int as isize);
        (*(*ctxt).input).col += 7 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const libc::c_char);
            return 0 as *mut xmlChar;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
            xmlNextChar(ctxt);
            version = xmlParseVersionNum(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
            xmlNextChar(ctxt);
            version = xmlParseVersionNum(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const libc::c_char);
        }
    }
    return version;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEncName(mut ctxt: xmlParserCtxtPtr) -> *mut xmlChar {
    let mut buf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0 as libc::c_int;
    let mut size: libc::c_int = 10 as libc::c_int;
    let mut cur: xmlChar = 0;
    cur = *(*(*ctxt).input).cur;
    if cur as libc::c_int >= 'a' as i32 && cur as libc::c_int <= 'z' as i32
        || cur as libc::c_int >= 'A' as i32 && cur as libc::c_int <= 'Z' as i32
    {
        buf = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )(
            (size as libc::c_ulong)
                .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
        ) as *mut xmlChar;
        if buf.is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            return 0 as *mut xmlChar;
        }
        let fresh419 = len;
        len = len + 1;
        *buf.offset(fresh419 as isize) = cur;
        xmlNextChar(ctxt);
        cur = *(*(*ctxt).input).cur;
        while cur as libc::c_int >= 'a' as i32 && cur as libc::c_int <= 'z' as i32
            || cur as libc::c_int >= 'A' as i32 && cur as libc::c_int <= 'Z' as i32
            || cur as libc::c_int >= '0' as i32 && cur as libc::c_int <= '9' as i32
            || cur as libc::c_int == '.' as i32 || cur as libc::c_int == '_' as i32
            || cur as libc::c_int == '-' as i32
        {
            if len + 1 as libc::c_int >= size {
                let mut tmp: *mut xmlChar = 0 as *mut xmlChar;
                size *= 2 as libc::c_int;
                tmp = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    buf as *mut libc::c_void,
                    (size as libc::c_ulong)
                        .wrapping_mul(::std::mem::size_of::<xmlChar>() as libc::c_ulong),
                ) as *mut xmlChar;
                if tmp.is_null() {
                    xmlErrMemory(ctxt, 0 as *const libc::c_char);
                    xmlFree
                        .expect("non-null function pointer")(buf as *mut libc::c_void);
                    return 0 as *mut xmlChar;
                }
                buf = tmp;
            }
            let fresh420 = len;
            len = len + 1;
            *buf.offset(fresh420 as isize) = cur;
            xmlNextChar(ctxt);
            cur = *(*(*ctxt).input).cur;
            if cur as libc::c_int == 0 as libc::c_int {
                if (*ctxt).progressive == 0 as libc::c_int
                    && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long
                        > (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long)
                        < (2 as libc::c_int * 250 as libc::c_int) as libc::c_long
                {
                    xmlSHRINK(ctxt);
                }
                if (*ctxt).progressive == 0 as libc::c_int
                    && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur)
                        as libc::c_long) < 250 as libc::c_int as libc::c_long
                {
                    xmlGROW(ctxt);
                }
                cur = *(*(*ctxt).input).cur;
            }
        }
        *buf.offset(len as isize) = 0 as libc::c_int as xmlChar;
    } else {
        xmlFatalErr(ctxt, XML_ERR_ENCODING_NAME, 0 as *const libc::c_char);
    }
    return buf;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEncodingDecl(
    mut ctxt: xmlParserCtxtPtr,
) -> *const xmlChar {
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 'e' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 'n' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'c' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'o' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'd' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'i' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'n' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'g' as i32
    {
        let ref mut fresh421 = (*(*ctxt).input).cur;
        *fresh421 = (*fresh421).offset(8 as libc::c_int as isize);
        (*(*ctxt).input).col += 8 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const libc::c_char);
            return 0 as *const xmlChar;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
            xmlNextChar(ctxt);
            encoding = xmlParseEncName(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
                xmlFree
                    .expect("non-null function pointer")(encoding as *mut libc::c_void);
                return 0 as *const xmlChar;
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
            xmlNextChar(ctxt);
            encoding = xmlParseEncName(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
                xmlFree
                    .expect("non-null function pointer")(encoding as *mut libc::c_void);
                return 0 as *const xmlChar;
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const libc::c_char);
        }
        if (*ctxt).options & XML_PARSE_IGNORE_ENC as libc::c_int != 0 {
            xmlFree.expect("non-null function pointer")(encoding as *mut libc::c_void);
            return 0 as *const xmlChar;
        }
        if !encoding.is_null()
            && (xmlStrcasecmp(
                encoding,
                b"UTF-16\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
                || xmlStrcasecmp(
                    encoding,
                    b"UTF16\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0)
        {
            if ((*ctxt).encoding).is_null() && !((*(*ctxt).input).buf).is_null()
                && ((*(*(*ctxt).input).buf).encoder).is_null()
            {
                xmlFatalErrMsg(
                    ctxt,
                    XML_ERR_INVALID_ENCODING,
                    b"Document labelled UTF-16 but has UTF-8 content\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let ref mut fresh422 = (*ctxt).encoding;
            *fresh422 = encoding;
        } else if !encoding.is_null()
                && (xmlStrcasecmp(
                    encoding,
                    b"UTF-8\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ) == 0
                    || xmlStrcasecmp(
                        encoding,
                        b"UTF8\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ) == 0)
            {
            if !((*ctxt).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let ref mut fresh423 = (*ctxt).encoding;
            *fresh423 = encoding;
        } else if !encoding.is_null() {
            let mut handler: xmlCharEncodingHandlerPtr = 0
                as *mut xmlCharEncodingHandler;
            if !((*(*ctxt).input).encoding).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*(*ctxt).input).encoding as *mut xmlChar as *mut libc::c_void);
            }
            let ref mut fresh424 = (*(*ctxt).input).encoding;
            *fresh424 = encoding;
            handler = xmlFindCharEncodingHandler(encoding as *const libc::c_char);
            if !handler.is_null() {
                if xmlSwitchToEncoding(ctxt, handler) < 0 as libc::c_int {
                    (*ctxt).errNo = XML_ERR_UNSUPPORTED_ENCODING as libc::c_int;
                    return 0 as *const xmlChar;
                }
            } else {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNSUPPORTED_ENCODING,
                    b"Unsupported encoding %s\n\0" as *const u8 as *const libc::c_char,
                    encoding,
                );
                return 0 as *const xmlChar;
            }
        }
    }
    return encoding;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseSDDecl(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut standalone: libc::c_int = -(2 as libc::c_int);
    xmlSkipBlankChars(ctxt);
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == 's' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == 't' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'a' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'n' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'd' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'a' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'o' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'n' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(9 as libc::c_int as isize) as libc::c_int == 'e' as i32
    {
        let ref mut fresh425 = (*(*ctxt).input).cur;
        *fresh425 = (*fresh425).offset(10 as libc::c_int as isize);
        (*(*ctxt).input).col += 10 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int != '=' as i32 {
            xmlFatalErr(ctxt, XML_ERR_EQUAL_REQUIRED, 0 as *const libc::c_char);
            return standalone;
        }
        xmlNextChar(ctxt);
        xmlSkipBlankChars(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '\'' as i32 {
            xmlNextChar(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int == 'n' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == 'o' as i32
            {
                standalone = 0 as libc::c_int;
                let ref mut fresh426 = (*(*ctxt).input).cur;
                *fresh426 = (*fresh426).offset(2 as libc::c_int as isize);
                (*(*ctxt).input).col += 2 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
            } else if *(*(*ctxt).input).cur as libc::c_int == 'y' as i32
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == 'e' as i32
                    && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                        as libc::c_int == 's' as i32
                {
                standalone = 1 as libc::c_int;
                let ref mut fresh427 = (*(*ctxt).input).cur;
                *fresh427 = (*fresh427).offset(3 as libc::c_int as isize);
                (*(*ctxt).input).col += 3 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const libc::c_char);
            }
            if *(*(*ctxt).input).cur as libc::c_int != '\'' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
            } else {
                xmlNextChar(ctxt);
            }
        } else if *(*(*ctxt).input).cur as libc::c_int == '"' as i32 {
            xmlNextChar(ctxt);
            if *(*(*ctxt).input).cur as libc::c_int == 'n' as i32
                && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                    as libc::c_int == 'o' as i32
            {
                standalone = 0 as libc::c_int;
                let ref mut fresh428 = (*(*ctxt).input).cur;
                *fresh428 = (*fresh428).offset(2 as libc::c_int as isize);
                (*(*ctxt).input).col += 2 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
            } else if *(*(*ctxt).input).cur as libc::c_int == 'y' as i32
                    && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                        as libc::c_int == 'e' as i32
                    && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                        as libc::c_int == 's' as i32
                {
                standalone = 1 as libc::c_int;
                let ref mut fresh429 = (*(*ctxt).input).cur;
                *fresh429 = (*fresh429).offset(3 as libc::c_int as isize);
                (*(*ctxt).input).col += 3 as libc::c_int;
                if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                    xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                }
            } else {
                xmlFatalErr(ctxt, XML_ERR_STANDALONE_VALUE, 0 as *const libc::c_char);
            }
            if *(*(*ctxt).input).cur as libc::c_int != '"' as i32 {
                xmlFatalErr(ctxt, XML_ERR_STRING_NOT_CLOSED, 0 as *const libc::c_char);
            } else {
                xmlNextChar(ctxt);
            }
        } else {
            xmlFatalErr(ctxt, XML_ERR_STRING_NOT_STARTED, 0 as *const libc::c_char);
        }
    }
    return standalone;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseXMLDecl(mut ctxt: xmlParserCtxtPtr) {
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    (*(*ctxt).input).standalone = -(2 as libc::c_int);
    let ref mut fresh430 = (*(*ctxt).input).cur;
    *fresh430 = (*fresh430).offset(5 as libc::c_int as isize);
    (*(*ctxt).input).col += 5 as libc::c_int;
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
    }
    if !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
        || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
    {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed after '<?xml'\n\0" as *const u8 as *const libc::c_char,
        );
    }
    xmlSkipBlankChars(ctxt);
    version = xmlParseVersionInfo(ctxt);
    if version.is_null() {
        xmlFatalErr(ctxt, XML_ERR_VERSION_MISSING, 0 as *const libc::c_char);
    } else {
        if xmlStrEqual(
            version,
            b"1.0\0" as *const u8 as *const libc::c_char as *const xmlChar,
        ) == 0
        {
            if (*ctxt).options & XML_PARSE_OLD10 as libc::c_int != 0 {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const libc::c_char,
                    version,
                );
            } else if *version.offset(0 as libc::c_int as isize) as libc::c_int
                    == '1' as i32
                    && *version.offset(1 as libc::c_int as isize) as libc::c_int
                        == '.' as i32
                {
                xmlWarningMsg(
                    ctxt,
                    XML_WAR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const libc::c_char,
                    version,
                    0 as *const xmlChar,
                );
            } else {
                xmlFatalErrMsgStr(
                    ctxt,
                    XML_ERR_UNKNOWN_VERSION,
                    b"Unsupported version '%s'\n\0" as *const u8 as *const libc::c_char,
                    version,
                );
            }
        }
        if !((*ctxt).version).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).version as *mut libc::c_void);
        }
        let ref mut fresh431 = (*ctxt).version;
        *fresh431 = version;
    }
    if !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
        || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
            && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
        || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
    {
        if *(*(*ctxt).input).cur as libc::c_int == '?' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '>' as i32
        {
            let ref mut fresh432 = (*(*ctxt).input).cur;
            *fresh432 = (*fresh432).offset(2 as libc::c_int as isize);
            (*(*ctxt).input).col += 2 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            return;
        }
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed here\n\0" as *const u8 as *const libc::c_char,
        );
    }
    xmlParseEncodingDecl(ctxt);
    if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int
        || (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
    {
        return;
    }
    if !((*(*ctxt).input).encoding).is_null()
        && !(*(*(*ctxt).input).cur as libc::c_int == 0x20 as libc::c_int
            || 0x9 as libc::c_int <= *(*(*ctxt).input).cur as libc::c_int
                && *(*(*ctxt).input).cur as libc::c_int <= 0xa as libc::c_int
            || *(*(*ctxt).input).cur as libc::c_int == 0xd as libc::c_int)
    {
        if *(*(*ctxt).input).cur as libc::c_int == '?' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '>' as i32
        {
            let ref mut fresh433 = (*(*ctxt).input).cur;
            *fresh433 = (*fresh433).offset(2 as libc::c_int as isize);
            (*(*ctxt).input).col += 2 as libc::c_int;
            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
            }
            return;
        }
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_SPACE_REQUIRED,
            b"Blank needed here\n\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    xmlSkipBlankChars(ctxt);
    (*(*ctxt).input).standalone = xmlParseSDDecl(ctxt);
    xmlSkipBlankChars(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '>' as i32
    {
        let ref mut fresh434 = (*(*ctxt).input).cur;
        *fresh434 = (*fresh434).offset(2 as libc::c_int as isize);
        (*(*ctxt).input).col += 2 as libc::c_int;
        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
        }
    } else if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const libc::c_char);
        xmlNextChar(ctxt);
    } else {
        xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, 0 as *const libc::c_char);
        while *(*(*ctxt).input).cur as libc::c_int != 0
            && *(*(*ctxt).input).cur as libc::c_int != '>' as i32
        {
            let ref mut fresh435 = (*(*ctxt).input).cur;
            *fresh435 = (*fresh435).offset(1);
        }
        xmlNextChar(ctxt);
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMisc(mut ctxt: xmlParserCtxtPtr) {
    while (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
        xmlSkipBlankChars(ctxt);
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
        if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
                == '?' as i32
        {
            xmlParsePI(ctxt);
        } else {
            if !(*((*(*ctxt).input).cur as *mut libc::c_uchar)
                .offset(0 as libc::c_int as isize) as libc::c_int == '<' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(2 as libc::c_int as isize) as libc::c_int == '-' as i32
                && *((*(*ctxt).input).cur as *mut libc::c_uchar)
                    .offset(3 as libc::c_int as isize) as libc::c_int == '-' as i32)
            {
                break;
            }
            xmlParseComment(ctxt);
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDocument(mut ctxt: xmlParserCtxtPtr) -> libc::c_int {
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    xmlInitParser();
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    xmlDetectSAX2(ctxt);
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).setDocumentLocator).is_some() {
        ((*(*ctxt).sax).setDocumentLocator)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, __xmlDefaultSAXLocator());
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if ((*ctxt).encoding).is_null()
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
            >= 4 as libc::c_int as libc::c_long
    {
        start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(
            &mut *start.as_mut_ptr().offset(0 as libc::c_int as isize),
            4 as libc::c_int,
        );
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    if (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
        < 35 as libc::c_int as libc::c_long
    {
        if (*ctxt).progressive == 0 as libc::c_int
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
                < 250 as libc::c_int as libc::c_long
        {
            xmlGROW(ctxt);
        }
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
            == 0x20 as libc::c_int
            || 0x9 as libc::c_int
                <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int <= 0xa as libc::c_int
            || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
                == 0xd as libc::c_int)
    {
        xmlParseXMLDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int
            || (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int
        {
            return -(1 as libc::c_int);
        }
        (*ctxt).standalone = (*(*ctxt).input).standalone;
        xmlSkipBlankChars(ctxt);
    } else {
        let ref mut fresh436 = (*ctxt).version;
        *fresh436 = xmlCharStrdup(b"1.0\0" as *const u8 as *const libc::c_char);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startDocument).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).startDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if !((*ctxt).myDoc).is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
        && (*(*(*ctxt).input).buf).compressed >= 0 as libc::c_int
    {
        (*(*ctxt).myDoc).compression = (*(*(*ctxt).input).buf).compressed;
    }
    xmlParseMisc(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '!' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'D' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'O' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'C' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(5 as libc::c_int as isize) as libc::c_int == 'T' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(6 as libc::c_int as isize) as libc::c_int == 'Y' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(7 as libc::c_int as isize) as libc::c_int == 'P' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(8 as libc::c_int as isize) as libc::c_int == 'E' as i32
    {
        (*ctxt).inSubset = 1 as libc::c_int;
        xmlParseDocTypeDecl(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int == '[' as i32 {
            (*ctxt).instate = XML_PARSER_DTD;
            xmlParseInternalSubset(ctxt);
            if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                return -(1 as libc::c_int);
            }
        }
        (*ctxt).inSubset = 2 as libc::c_int;
        if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).externalSubset).is_some()
            && (*ctxt).disableSAX == 0
        {
            ((*(*ctxt).sax).externalSubset)
                .expect(
                    "non-null function pointer",
                )(
                (*ctxt).userData,
                (*ctxt).intSubName,
                (*ctxt).extSubSystem,
                (*ctxt).extSubURI,
            );
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            return -(1 as libc::c_int);
        }
        (*ctxt).inSubset = 0 as libc::c_int;
        xmlCleanSpecialAttr(ctxt);
        (*ctxt).instate = XML_PARSER_PROLOG;
        xmlParseMisc(ctxt);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int != '<' as i32 {
        xmlFatalErrMsg(
            ctxt,
            XML_ERR_DOCUMENT_EMPTY,
            b"Start tag expected, '<' not found\n\0" as *const u8 as *const libc::c_char,
        );
    } else {
        (*ctxt).instate = XML_PARSER_CONTENT;
        xmlParseElement(ctxt);
        (*ctxt).instate = XML_PARSER_EPILOG;
        xmlParseMisc(ctxt);
        if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const libc::c_char);
        }
        (*ctxt).instate = XML_PARSER_EOF;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
        ((*(*ctxt).sax).endDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if !((*ctxt).myDoc).is_null()
        && xmlStrEqual(
            (*(*ctxt).myDoc).version,
            b"SAX compatibility mode document\0" as *const u8 as *const libc::c_char
                as *mut xmlChar,
        ) != 0
    {
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh437 = (*ctxt).myDoc;
        *fresh437 = 0 as xmlDocPtr;
    }
    if (*ctxt).wellFormed != 0 && !((*ctxt).myDoc).is_null() {
        (*(*ctxt).myDoc).properties |= XML_DOC_WELLFORMED as libc::c_int;
        if (*ctxt).valid != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_DTDVALID as libc::c_int;
        }
        if (*ctxt).nsWellFormed != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_NSVALID as libc::c_int;
        }
        if (*ctxt).options & XML_PARSE_OLD10 as libc::c_int != 0 {
            (*(*ctxt).myDoc).properties |= XML_DOC_OLD10 as libc::c_int;
        }
    }
    if (*ctxt).wellFormed == 0 {
        (*ctxt).valid = 0 as libc::c_int;
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExtParsedEnt(
    mut ctxt: xmlParserCtxtPtr,
) -> libc::c_int {
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() || ((*ctxt).input).is_null() {
        return -(1 as libc::c_int);
    }
    xmlDetectSAX2(ctxt);
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).setDocumentLocator).is_some() {
        ((*(*ctxt).sax).setDocumentLocator)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, __xmlDefaultSAXLocator());
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
        >= 4 as libc::c_int as libc::c_long
    {
        start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const libc::c_char);
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
            == 0x20 as libc::c_int
            || 0x9 as libc::c_int
                <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int <= 0xa as libc::c_int
            || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
                == 0xd as libc::c_int)
    {
        xmlParseXMLDecl(ctxt);
        if (*ctxt).errNo == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int {
            return -(1 as libc::c_int);
        }
        xmlSkipBlankChars(ctxt);
    } else {
        let ref mut fresh438 = (*ctxt).version;
        *fresh438 = xmlCharStrdup(b"1.0\0" as *const u8 as *const libc::c_char);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).startDocument).is_some()
        && (*ctxt).disableSAX == 0
    {
        ((*(*ctxt).sax).startDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).validate = 0 as libc::c_int;
    (*ctxt).loadsubset = 0 as libc::c_int;
    (*ctxt).depth = 0 as libc::c_int;
    xmlParseContent(ctxt);
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    } else if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const libc::c_char);
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
        ((*(*ctxt).sax).endDocument)
            .expect("non-null function pointer")((*ctxt).userData);
    }
    if (*ctxt).wellFormed == 0 {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlParseLookupSequence(
    mut ctxt: xmlParserCtxtPtr,
    mut first: xmlChar,
    mut next: xmlChar,
    mut third: xmlChar,
) -> libc::c_int {
    let mut base: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut in_0: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: *const xmlChar = 0 as *const xmlChar;
    in_0 = (*ctxt).input;
    if in_0.is_null() {
        return -(1 as libc::c_int);
    }
    base = ((*in_0).cur).offset_from((*in_0).base) as libc::c_long as libc::c_int;
    if base < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*ctxt).checkIndex > base as libc::c_long {
        base = (*ctxt).checkIndex as libc::c_int;
    }
    if ((*in_0).buf).is_null() {
        buf = (*in_0).base;
        len = (*in_0).length;
    } else {
        buf = xmlBufContent((*(*in_0).buf).buffer as *const xmlBuf);
        len = xmlBufUse((*(*in_0).buf).buffer) as libc::c_int;
    }
    if third != 0 {
        len -= 2 as libc::c_int;
    } else if next != 0 {
        len -= 1;
    }
    let mut current_block_20: u64;
    while base < len {
        if *buf.offset(base as isize) as libc::c_int == first as libc::c_int {
            if third as libc::c_int != 0 as libc::c_int {
                if *buf.offset((base + 1 as libc::c_int) as isize) as libc::c_int
                    != next as libc::c_int
                    || *buf.offset((base + 2 as libc::c_int) as isize) as libc::c_int
                        != third as libc::c_int
                {
                    current_block_20 = 2370887241019905314;
                } else {
                    current_block_20 = 18386322304582297246;
                }
            } else if next as libc::c_int != 0 as libc::c_int {
                if *buf.offset((base + 1 as libc::c_int) as isize) as libc::c_int
                    != next as libc::c_int
                {
                    current_block_20 = 2370887241019905314;
                } else {
                    current_block_20 = 18386322304582297246;
                }
            } else {
                current_block_20 = 18386322304582297246;
            }
            match current_block_20 {
                2370887241019905314 => {}
                _ => {
                    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    return (base as libc::c_long
                        - ((*in_0).cur).offset_from((*in_0).base) as libc::c_long)
                        as libc::c_int;
                }
            }
        }
        base += 1;
    }
    (*ctxt).checkIndex = base as libc::c_long;
    return -(1 as libc::c_int);
}
unsafe extern "C" fn xmlParseGetLasts(
    mut ctxt: xmlParserCtxtPtr,
    mut lastlt: *mut *const xmlChar,
    mut lastgt: *mut *const xmlChar,
) {
    let mut tmp: *const xmlChar = 0 as *const xmlChar;
    if ctxt.is_null() || lastlt.is_null() || lastgt.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Internal error: xmlParseGetLasts\n\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if (*ctxt).progressive != 0 as libc::c_int && (*ctxt).inputNr == 1 as libc::c_int {
        tmp = (*(*ctxt).input).end;
        tmp = tmp.offset(-1);
        while tmp >= (*(*ctxt).input).base && *tmp as libc::c_int != '<' as i32 {
            tmp = tmp.offset(-1);
        }
        if tmp < (*(*ctxt).input).base {
            *lastlt = 0 as *const xmlChar;
            *lastgt = 0 as *const xmlChar;
        } else {
            *lastlt = tmp;
            tmp = tmp.offset(1);
            while tmp < (*(*ctxt).input).end && *tmp as libc::c_int != '>' as i32 {
                if *tmp as libc::c_int == '\'' as i32 {
                    tmp = tmp.offset(1);
                    while tmp < (*(*ctxt).input).end
                        && *tmp as libc::c_int != '\'' as i32
                    {
                        tmp = tmp.offset(1);
                    }
                    if tmp < (*(*ctxt).input).end {
                        tmp = tmp.offset(1);
                    }
                } else if *tmp as libc::c_int == '"' as i32 {
                    tmp = tmp.offset(1);
                    while tmp < (*(*ctxt).input).end && *tmp as libc::c_int != '"' as i32
                    {
                        tmp = tmp.offset(1);
                    }
                    if tmp < (*(*ctxt).input).end {
                        tmp = tmp.offset(1);
                    }
                } else {
                    tmp = tmp.offset(1);
                }
            }
            if tmp < (*(*ctxt).input).end {
                *lastgt = tmp;
            } else {
                tmp = *lastlt;
                tmp = tmp.offset(-1);
                while tmp >= (*(*ctxt).input).base && *tmp as libc::c_int != '>' as i32 {
                    tmp = tmp.offset(-1);
                }
                if tmp >= (*(*ctxt).input).base {
                    *lastgt = tmp;
                } else {
                    *lastgt = 0 as *const xmlChar;
                }
            }
        }
    } else {
        *lastlt = 0 as *const xmlChar;
        *lastgt = 0 as *const xmlChar;
    };
}
unsafe extern "C" fn xmlCheckCdataPush(
    mut utf: *const xmlChar,
    mut len: libc::c_int,
    mut complete: libc::c_int,
) -> libc::c_int {
    let mut ix: libc::c_int = 0;
    let mut c: libc::c_uchar = 0;
    let mut codepoint: libc::c_int = 0;
    if utf.is_null() || len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    ix = 0 as libc::c_int;
    while ix < len {
        c = *utf.offset(ix as isize);
        if c as libc::c_int & 0x80 as libc::c_int == 0 as libc::c_int {
            if c as libc::c_int >= 0x20 as libc::c_int {
                ix += 1;
            } else if c as libc::c_int == 0xa as libc::c_int
                    || c as libc::c_int == 0xd as libc::c_int
                    || c as libc::c_int == 0x9 as libc::c_int
                {
                ix += 1;
            } else {
                return -ix
            }
        } else if c as libc::c_int & 0xe0 as libc::c_int == 0xc0 as libc::c_int {
            if ix + 2 as libc::c_int > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as libc::c_int & 0x1f as libc::c_int)
                << 6 as libc::c_int;
            codepoint
                |= *utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int;
            if if codepoint < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= codepoint && codepoint <= 0xa as libc::c_int
                    || codepoint == 0xd as libc::c_int
                    || 0x20 as libc::c_int <= codepoint) as libc::c_int
            } else {
                (0x100 as libc::c_int <= codepoint && codepoint <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= codepoint
                        && codepoint <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= codepoint
                        && codepoint <= 0x10ffff as libc::c_int) as libc::c_int
            } == 0
            {
                return -ix;
            }
            ix += 2 as libc::c_int;
        } else if c as libc::c_int & 0xf0 as libc::c_int == 0xe0 as libc::c_int {
            if ix + 3 as libc::c_int > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset((ix + 2 as libc::c_int) as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as libc::c_int & 0xf as libc::c_int)
                << 12 as libc::c_int;
            codepoint
                |= (*utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int) << 6 as libc::c_int;
            codepoint
                |= *utf.offset((ix + 2 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int;
            if if codepoint < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= codepoint && codepoint <= 0xa as libc::c_int
                    || codepoint == 0xd as libc::c_int
                    || 0x20 as libc::c_int <= codepoint) as libc::c_int
            } else {
                (0x100 as libc::c_int <= codepoint && codepoint <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= codepoint
                        && codepoint <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= codepoint
                        && codepoint <= 0x10ffff as libc::c_int) as libc::c_int
            } == 0
            {
                return -ix;
            }
            ix += 3 as libc::c_int;
        } else if c as libc::c_int & 0xf8 as libc::c_int == 0xf0 as libc::c_int {
            if ix + 4 as libc::c_int > len {
                return if complete != 0 { -ix } else { ix };
            }
            if *utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset((ix + 2 as libc::c_int) as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
                || *utf.offset((ix + 3 as libc::c_int) as isize) as libc::c_int
                    & 0xc0 as libc::c_int != 0x80 as libc::c_int
            {
                return -ix;
            }
            codepoint = (*utf.offset(ix as isize) as libc::c_int & 0x7 as libc::c_int)
                << 18 as libc::c_int;
            codepoint
                |= (*utf.offset((ix + 1 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int) << 12 as libc::c_int;
            codepoint
                |= (*utf.offset((ix + 2 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int) << 6 as libc::c_int;
            codepoint
                |= *utf.offset((ix + 3 as libc::c_int) as isize) as libc::c_int
                    & 0x3f as libc::c_int;
            if if codepoint < 0x100 as libc::c_int {
                (0x9 as libc::c_int <= codepoint && codepoint <= 0xa as libc::c_int
                    || codepoint == 0xd as libc::c_int
                    || 0x20 as libc::c_int <= codepoint) as libc::c_int
            } else {
                (0x100 as libc::c_int <= codepoint && codepoint <= 0xd7ff as libc::c_int
                    || 0xe000 as libc::c_int <= codepoint
                        && codepoint <= 0xfffd as libc::c_int
                    || 0x10000 as libc::c_int <= codepoint
                        && codepoint <= 0x10ffff as libc::c_int) as libc::c_int
            } == 0
            {
                return -ix;
            }
            ix += 4 as libc::c_int;
        } else {
            return -ix
        }
    }
    return ix;
}
unsafe extern "C" fn xmlParseTryOrFinish(
    mut ctxt: xmlParserCtxtPtr,
    mut terminate: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut avail: libc::c_int = 0;
    let mut tlen: libc::c_int = 0;
    let mut cur: xmlChar = 0;
    let mut next: xmlChar = 0;
    let mut lastlt: *const xmlChar = 0 as *const xmlChar;
    let mut lastgt: *const xmlChar = 0 as *const xmlChar;
    if ((*ctxt).input).is_null() {
        return 0 as libc::c_int;
    }
    if !((*ctxt).input).is_null()
        && ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
            > 4096 as libc::c_int as libc::c_long
    {
        xmlSHRINK(ctxt);
        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
    }
    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
    loop {
        if !((*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int) {
            current_block = 2814621064645850728;
            break;
        }
        if (*ctxt).errNo != XML_ERR_OK as libc::c_int
            && (*ctxt).disableSAX == 1 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if ((*ctxt).input).is_null() {
            current_block = 2814621064645850728;
            break;
        }
        if ((*(*ctxt).input).buf).is_null() {
            avail = ((*(*ctxt).input).length as libc::c_long
                - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long) as libc::c_int;
        } else {
            if (*ctxt).instate as libc::c_int != XML_PARSER_START as libc::c_int
                && !((*(*(*ctxt).input).buf).raw).is_null()
                && xmlBufIsEmpty((*(*(*ctxt).input).buf).raw) == 0 as libc::c_int
            {
                let mut base: size_t = xmlBufGetInputBase(
                    (*(*(*ctxt).input).buf).buffer,
                    (*ctxt).input,
                );
                let mut current: size_t = ((*(*ctxt).input).cur)
                    .offset_from((*(*ctxt).input).base) as libc::c_long as size_t;
                xmlParserInputBufferPush(
                    (*(*ctxt).input).buf,
                    0 as libc::c_int,
                    b"\0" as *const u8 as *const libc::c_char,
                );
                xmlBufSetInputBaseCur(
                    (*(*(*ctxt).input).buf).buffer,
                    (*ctxt).input,
                    base,
                    current,
                );
            }
            avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                .wrapping_sub(
                    ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long as libc::c_ulong,
                ) as libc::c_int;
        }
        if avail < 1 as libc::c_int {
            current_block = 2814621064645850728;
            break;
        }
        match (*ctxt).instate as libc::c_int {
            -1 => {
                current_block = 2814621064645850728;
                break;
            }
            0 => {
                if (*ctxt).charset == XML_CHAR_ENCODING_NONE as libc::c_int {
                    let mut start: [xmlChar; 4] = [0; 4];
                    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
                    if avail < 4 as libc::c_int {
                        current_block = 2814621064645850728;
                        break;
                    }
                    start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
                    start[1 as libc::c_int
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(1 as libc::c_int as isize);
                    start[2 as libc::c_int
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(2 as libc::c_int as isize);
                    start[3 as libc::c_int
                        as usize] = *((*(*ctxt).input).cur)
                        .offset(3 as libc::c_int as isize);
                    enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
                    xmlSwitchEncoding(ctxt, enc);
                } else {
                    if avail < 2 as libc::c_int {
                        current_block = 2814621064645850728;
                        break;
                    }
                    cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                    next = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
                    if cur as libc::c_int == 0 as libc::c_int {
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        xmlFatalErr(
                            ctxt,
                            XML_ERR_DOCUMENT_EMPTY,
                            0 as *const libc::c_char,
                        );
                        xmlHaltParser(ctxt);
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).endDocument).is_some()
                        {
                            ((*(*ctxt).sax).endDocument)
                                .expect("non-null function pointer")((*ctxt).userData);
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '?' as i32
                        {
                        if avail < 5 as libc::c_int {
                            return ret;
                        }
                        if terminate == 0
                            && xmlParseLookupSequence(
                                ctxt,
                                '?' as i32 as xmlChar,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                            ) < 0 as libc::c_int
                        {
                            return ret;
                        }
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        if *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == 'x' as i32
                            && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int == 'm' as i32
                            && *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                as libc::c_int == 'l' as i32
                            && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                as libc::c_int == 0x20 as libc::c_int
                                || 0x9 as libc::c_int
                                    <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                        as libc::c_int
                                    && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                        as libc::c_int <= 0xa as libc::c_int
                                || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                    as libc::c_int == 0xd as libc::c_int)
                        {
                            ret += 5 as libc::c_int;
                            xmlParseXMLDecl(ctxt);
                            if (*ctxt).errNo
                                == XML_ERR_UNSUPPORTED_ENCODING as libc::c_int
                            {
                                xmlHaltParser(ctxt);
                                return 0 as libc::c_int;
                            }
                            (*ctxt).standalone = (*(*ctxt).input).standalone;
                            if ((*ctxt).encoding).is_null()
                                && !((*(*ctxt).input).encoding).is_null()
                            {
                                let ref mut fresh439 = (*ctxt).encoding;
                                *fresh439 = xmlStrdup((*(*ctxt).input).encoding);
                            }
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        } else {
                            let ref mut fresh440 = (*ctxt).version;
                            *fresh440 = xmlCharStrdup(
                                b"1.0\0" as *const u8 as *const libc::c_char,
                            );
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        }
                    } else {
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).setDocumentLocator).is_some()
                        {
                            ((*(*ctxt).sax).setDocumentLocator)
                                .expect(
                                    "non-null function pointer",
                                )((*ctxt).userData, __xmlDefaultSAXLocator());
                        }
                        let ref mut fresh441 = (*ctxt).version;
                        *fresh441 = xmlCharStrdup(
                            b"1.0\0" as *const u8 as *const libc::c_char,
                        );
                        if ((*ctxt).version).is_null() {
                            xmlErrMemory(ctxt, 0 as *const libc::c_char);
                        } else {
                            if !((*ctxt).sax).is_null()
                                && ((*(*ctxt).sax).startDocument).is_some()
                                && (*ctxt).disableSAX == 0
                            {
                                ((*(*ctxt).sax).startDocument)
                                    .expect("non-null function pointer")((*ctxt).userData);
                            }
                            (*ctxt).instate = XML_PARSER_MISC;
                        }
                    }
                }
            }
            6 => {
                let mut name: *const xmlChar = 0 as *const xmlChar;
                let mut prefix: *const xmlChar = 0 as *const xmlChar;
                let mut URI: *const xmlChar = 0 as *const xmlChar;
                let mut line: libc::c_int = (*(*ctxt).input).line;
                let mut nsNr: libc::c_int = (*ctxt).nsNr;
                if avail < 2 as libc::c_int && (*ctxt).inputNr == 1 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                if cur as libc::c_int != '<' as i32 {
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_EMPTY, 0 as *const libc::c_char);
                    xmlHaltParser(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some()
                    {
                        ((*(*ctxt).sax).endDocument)
                            .expect("non-null function pointer")((*ctxt).userData);
                    }
                    current_block = 2814621064645850728;
                    break;
                } else {
                    if terminate == 0 {
                        if (*ctxt).progressive != 0 {
                            if lastgt.is_null() || (*(*ctxt).input).cur >= lastgt {
                                current_block = 2814621064645850728;
                                break;
                            }
                        } else if xmlParseLookupSequence(
                                ctxt,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                                0 as libc::c_int as xmlChar,
                            ) < 0 as libc::c_int
                            {
                            current_block = 2814621064645850728;
                            break;
                        }
                    }
                    if (*ctxt).spaceNr == 0 as libc::c_int {
                        spacePush(ctxt, -(1 as libc::c_int));
                    } else if *(*ctxt).space == -(2 as libc::c_int) {
                        spacePush(ctxt, -(1 as libc::c_int));
                    } else {
                        spacePush(ctxt, *(*ctxt).space);
                    }
                    if (*ctxt).sax2 != 0 {
                        name = xmlParseStartTag2(ctxt, &mut prefix, &mut URI, &mut tlen);
                    } else {
                        name = xmlParseStartTag(ctxt);
                    }
                    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
                        current_block = 2814621064645850728;
                        break;
                    }
                    if name.is_null() {
                        spacePop(ctxt);
                        xmlHaltParser(ctxt);
                        if !((*ctxt).sax).is_null()
                            && ((*(*ctxt).sax).endDocument).is_some()
                        {
                            ((*(*ctxt).sax).endDocument)
                                .expect("non-null function pointer")((*ctxt).userData);
                        }
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        if (*ctxt).validate != 0 && (*ctxt).wellFormed != 0
                            && !((*ctxt).myDoc).is_null() && !((*ctxt).node).is_null()
                            && (*ctxt).node == (*(*ctxt).myDoc).children
                        {
                            (*ctxt).valid
                                &= xmlValidateRoot(&mut (*ctxt).vctxt, (*ctxt).myDoc);
                        }
                        if *(*(*ctxt).input).cur as libc::c_int == '/' as i32
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int == '>' as i32
                        {
                            let ref mut fresh442 = (*(*ctxt).input).cur;
                            *fresh442 = (*fresh442).offset(2 as libc::c_int as isize);
                            (*(*ctxt).input).col += 2 as libc::c_int;
                            if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                                xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                            }
                            if (*ctxt).sax2 != 0 {
                                if !((*ctxt).sax).is_null()
                                    && ((*(*ctxt).sax).endElementNs).is_some()
                                    && (*ctxt).disableSAX == 0
                                {
                                    ((*(*ctxt).sax).endElementNs)
                                        .expect(
                                            "non-null function pointer",
                                        )((*ctxt).userData, name, prefix, URI);
                                }
                                if (*ctxt).nsNr - nsNr > 0 as libc::c_int {
                                    nsPop(ctxt, (*ctxt).nsNr - nsNr);
                                }
                            } else if !((*ctxt).sax).is_null()
                                    && ((*(*ctxt).sax).endElement).is_some()
                                    && (*ctxt).disableSAX == 0
                                {
                                ((*(*ctxt).sax).endElement)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, name);
                            }
                            if (*ctxt).instate as libc::c_int
                                == XML_PARSER_EOF as libc::c_int
                            {
                                current_block = 2814621064645850728;
                                break;
                            }
                            spacePop(ctxt);
                            if (*ctxt).nameNr == 0 as libc::c_int {
                                (*ctxt).instate = XML_PARSER_EPILOG;
                            } else {
                                (*ctxt).instate = XML_PARSER_CONTENT;
                            }
                            (*ctxt).progressive = 1 as libc::c_int;
                        } else {
                            if *(*(*ctxt).input).cur as libc::c_int == '>' as i32 {
                                xmlNextChar(ctxt);
                            } else {
                                xmlFatalErrMsgStr(
                                    ctxt,
                                    XML_ERR_GT_REQUIRED,
                                    b"Couldn't find end of Start Tag %s\n\0" as *const u8
                                        as *const libc::c_char,
                                    name,
                                );
                                nodePop(ctxt);
                                spacePop(ctxt);
                            }
                            nameNsPush(
                                ctxt,
                                name,
                                prefix,
                                URI,
                                line,
                                (*ctxt).nsNr - nsNr,
                            );
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as libc::c_int;
                        }
                    }
                }
            }
            7 => {
                let mut id: libc::c_int = 0;
                let mut cons: libc::c_ulong = 0;
                if avail < 2 as libc::c_int && (*ctxt).inputNr == 1 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                next = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
                id = (*(*ctxt).input).id;
                cons = ((*(*ctxt).input).consumed)
                    .wrapping_add(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long as libc::c_ulong,
                    );
                if cur as libc::c_int == '<' as i32 && next as libc::c_int == '/' as i32
                {
                    (*ctxt).instate = XML_PARSER_END_TAG;
                } else {
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '?' as i32
                    {
                        if terminate == 0
                            && xmlParseLookupSequence(
                                ctxt,
                                '?' as i32 as xmlChar,
                                '>' as i32 as xmlChar,
                                0 as libc::c_int as xmlChar,
                            ) < 0 as libc::c_int
                        {
                            (*ctxt).progressive = XML_PARSER_PI as libc::c_int;
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParsePI(ctxt);
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as libc::c_int;
                        }
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int != '!' as i32
                        {
                        (*ctxt).instate = XML_PARSER_START_TAG;
                        continue;
                    } else if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                            && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int == '-' as i32
                        {
                        let mut term: libc::c_int = 0;
                        if avail < 4 as libc::c_int {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let ref mut fresh443 = (*(*ctxt).input).cur;
                        *fresh443 = (*fresh443).offset(4 as libc::c_int as isize);
                        term = xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        );
                        let ref mut fresh444 = (*(*ctxt).input).cur;
                        *fresh444 = (*fresh444).offset(-(4 as libc::c_int as isize));
                        if terminate == 0 && term < 0 as libc::c_int {
                            (*ctxt).progressive = XML_PARSER_COMMENT as libc::c_int;
                            current_block = 2814621064645850728;
                            break;
                        } else {
                            xmlParseComment(ctxt);
                            (*ctxt).instate = XML_PARSER_CONTENT;
                            (*ctxt).progressive = 1 as libc::c_int;
                        }
                    } else if cur as libc::c_int == '<' as i32
                            && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize)
                                as libc::c_int == '!' as i32
                            && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                                as libc::c_int == '[' as i32
                            && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                                as libc::c_int == 'C' as i32
                            && *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                                as libc::c_int == 'D' as i32
                            && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                                as libc::c_int == 'A' as i32
                            && *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                                as libc::c_int == 'T' as i32
                            && *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                                as libc::c_int == 'A' as i32
                            && *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                                as libc::c_int == '[' as i32
                        {
                        let ref mut fresh445 = (*(*ctxt).input).cur;
                        *fresh445 = (*fresh445).offset(9 as libc::c_int as isize);
                        (*(*ctxt).input).col += 9 as libc::c_int;
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                        (*ctxt).instate = XML_PARSER_CDATA_SECTION;
                        continue;
                    } else {
                        if cur as libc::c_int == '<' as i32
                            && next as libc::c_int == '!' as i32
                            && avail < 9 as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        if cur as libc::c_int == '&' as i32 {
                            if terminate == 0
                                && xmlParseLookupSequence(
                                    ctxt,
                                    ';' as i32 as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                    0 as libc::c_int as xmlChar,
                                ) < 0 as libc::c_int
                            {
                                current_block = 2814621064645850728;
                                break;
                            }
                            xmlParseReference(ctxt);
                        } else {
                            if (*ctxt).inputNr == 1 as libc::c_int
                                && avail < 300 as libc::c_int
                            {
                                if terminate == 0 {
                                    if (*ctxt).progressive != 0 {
                                        if lastlt.is_null() || (*(*ctxt).input).cur > lastlt {
                                            current_block = 2814621064645850728;
                                            break;
                                        }
                                    } else if xmlParseLookupSequence(
                                            ctxt,
                                            '<' as i32 as xmlChar,
                                            0 as libc::c_int as xmlChar,
                                            0 as libc::c_int as xmlChar,
                                        ) < 0 as libc::c_int
                                        {
                                        current_block = 2814621064645850728;
                                        break;
                                    }
                                }
                            }
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                            xmlParseCharData(ctxt, 0 as libc::c_int);
                        }
                    }
                    if !(cons
                        == ((*(*ctxt).input).consumed)
                            .wrapping_add(
                                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                    as libc::c_long as libc::c_ulong,
                            ) && id == (*(*ctxt).input).id)
                    {
                        continue;
                    }
                    xmlFatalErr(
                        ctxt,
                        XML_ERR_INTERNAL_ERROR,
                        b"detected an error in element content\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    xmlHaltParser(ctxt);
                }
            }
            9 => {
                if avail < 2 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                if terminate == 0 {
                    if (*ctxt).progressive != 0 {
                        if lastgt.is_null() || (*(*ctxt).input).cur >= lastgt {
                            current_block = 2814621064645850728;
                            break;
                        }
                    } else if xmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                            0 as libc::c_int as xmlChar,
                        ) < 0 as libc::c_int
                        {
                        current_block = 2814621064645850728;
                        break;
                    }
                }
                if (*ctxt).sax2 != 0 {
                    xmlParseEndTag2(
                        ctxt,
                        &mut *((*ctxt).pushTab)
                            .offset(((*ctxt).nameNr - 1 as libc::c_int) as isize),
                    );
                    nameNsPop(ctxt);
                } else {
                    xmlParseEndTag1(ctxt, 0 as libc::c_int);
                }
                if !((*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int) {
                    if (*ctxt).nameNr == 0 as libc::c_int {
                        (*ctxt).instate = XML_PARSER_EPILOG;
                    } else {
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
            }
            8 => {
                let mut base_0: libc::c_int = 0;
                base_0 = xmlParseLookupSequence(
                    ctxt,
                    ']' as i32 as xmlChar,
                    ']' as i32 as xmlChar,
                    '>' as i32 as xmlChar,
                );
                if base_0 < 0 as libc::c_int {
                    if !(avail >= 300 as libc::c_int + 2 as libc::c_int) {
                        current_block = 2814621064645850728;
                        break;
                    }
                    let mut tmp: libc::c_int = 0;
                    tmp = xmlCheckCdataPush(
                        (*(*ctxt).input).cur,
                        300 as libc::c_int,
                        0 as libc::c_int,
                    );
                    if tmp < 0 as libc::c_int {
                        tmp = -tmp;
                        let ref mut fresh446 = (*(*ctxt).input).cur;
                        *fresh446 = (*fresh446).offset(tmp as isize);
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0 {
                            if ((*(*ctxt).sax).cdataBlock).is_some() {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, tmp);
                            } else if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, tmp);
                            }
                        }
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl: libc::c_int = 0;
                        skipl = 0 as libc::c_int;
                        while skipl < tmp {
                            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                                let ref mut fresh447 = (*(*ctxt).input).line;
                                *fresh447 += 1;
                                (*(*ctxt).input).col = 1 as libc::c_int;
                            } else {
                                let ref mut fresh448 = (*(*ctxt).input).col;
                                *fresh448 += 1;
                            }
                            let ref mut fresh449 = (*(*ctxt).input).cur;
                            *fresh449 = (*fresh449).offset(1);
                            skipl += 1;
                        }
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        current_block = 2814621064645850728;
                        break;
                    }
                } else {
                    let mut tmp_0: libc::c_int = 0;
                    tmp_0 = xmlCheckCdataPush(
                        (*(*ctxt).input).cur,
                        base_0,
                        1 as libc::c_int,
                    );
                    if tmp_0 < 0 as libc::c_int || tmp_0 != base_0 {
                        tmp_0 = -tmp_0;
                        let ref mut fresh450 = (*(*ctxt).input).cur;
                        *fresh450 = (*fresh450).offset(tmp_0 as isize);
                        current_block = 2885357499145876431;
                        break;
                    } else {
                        if !((*ctxt).sax).is_null() && base_0 == 0 as libc::c_int
                            && ((*(*ctxt).sax).cdataBlock).is_some()
                            && (*ctxt).disableSAX == 0
                        {
                            if ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long >= 9 as libc::c_int as libc::c_long
                                && strncmp(
                                    &*((*(*ctxt).input).cur)
                                        .offset(-(9 as libc::c_int) as isize) as *const xmlChar
                                        as *const libc::c_char,
                                    b"<![CDATA[\0" as *const u8 as *const libc::c_char,
                                    9 as libc::c_int as libc::c_ulong,
                                ) == 0
                            {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    b"\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                                    0 as libc::c_int,
                                );
                            }
                        } else if !((*ctxt).sax).is_null() && base_0 > 0 as libc::c_int
                                && (*ctxt).disableSAX == 0
                            {
                            if ((*(*ctxt).sax).cdataBlock).is_some() {
                                ((*(*ctxt).sax).cdataBlock)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, base_0);
                            } else if ((*(*ctxt).sax).characters).is_some() {
                                ((*(*ctxt).sax).characters)
                                    .expect(
                                        "non-null function pointer",
                                    )((*ctxt).userData, (*(*ctxt).input).cur, base_0);
                            }
                        }
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        let mut skipl_0: libc::c_int = 0;
                        skipl_0 = 0 as libc::c_int;
                        while skipl_0 < base_0 + 3 as libc::c_int {
                            if *(*(*ctxt).input).cur as libc::c_int == '\n' as i32 {
                                let ref mut fresh451 = (*(*ctxt).input).line;
                                *fresh451 += 1;
                                (*(*ctxt).input).col = 1 as libc::c_int;
                            } else {
                                let ref mut fresh452 = (*(*ctxt).input).col;
                                *fresh452 += 1;
                            }
                            let ref mut fresh453 = (*(*ctxt).input).cur;
                            *fresh453 = (*fresh453).offset(1);
                            skipl_0 += 1;
                        }
                        if *(*(*ctxt).input).cur as libc::c_int == 0 as libc::c_int {
                            xmlParserInputGrow((*ctxt).input, 250 as libc::c_int);
                        }
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        (*ctxt).instate = XML_PARSER_CONTENT;
                    }
                }
            }
            1 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as libc::c_long
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long) as libc::c_int;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long as libc::c_ulong,
                        ) as libc::c_int;
                }
                if avail < 2 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                next = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
                if cur as libc::c_int == '<' as i32 && next as libc::c_int == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_PI as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_MISC;
                        (*ctxt).progressive = 1 as libc::c_int;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    }
                } else if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_MISC;
                        (*ctxt).progressive = 1 as libc::c_int;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    }
                } else if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == 'D' as i32
                        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == 'O' as i32
                        && *((*(*ctxt).input).cur).offset(4 as libc::c_int as isize)
                            as libc::c_int == 'C' as i32
                        && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                            as libc::c_int == 'T' as i32
                        && *((*(*ctxt).input).cur).offset(6 as libc::c_int as isize)
                            as libc::c_int == 'Y' as i32
                        && *((*(*ctxt).input).cur).offset(7 as libc::c_int as isize)
                            as libc::c_int == 'P' as i32
                        && *((*(*ctxt).input).cur).offset(8 as libc::c_int as isize)
                            as libc::c_int == 'E' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                            0 as libc::c_int as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_DTD as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        (*ctxt).inSubset = 1 as libc::c_int;
                        (*ctxt).progressive = 0 as libc::c_int;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        xmlParseDocTypeDecl(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        if *(*(*ctxt).input).cur as libc::c_int == '[' as i32 {
                            (*ctxt).instate = XML_PARSER_DTD;
                        } else {
                            (*ctxt).inSubset = 2 as libc::c_int;
                            if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                                && ((*(*ctxt).sax).externalSubset).is_some()
                            {
                                ((*(*ctxt).sax).externalSubset)
                                    .expect(
                                        "non-null function pointer",
                                    )(
                                    (*ctxt).userData,
                                    (*ctxt).intSubName,
                                    (*ctxt).extSubSystem,
                                    (*ctxt).extSubURI,
                                );
                            }
                            (*ctxt).inSubset = 0 as libc::c_int;
                            xmlCleanSpecialAttr(ctxt);
                            (*ctxt).instate = XML_PARSER_PROLOG;
                        }
                    }
                } else {
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32 && avail < 9 as libc::c_int
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (*ctxt).instate = XML_PARSER_START_TAG;
                    (*ctxt).progressive = XML_PARSER_START_TAG as libc::c_int;
                    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
                }
            }
            4 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as libc::c_long
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long) as libc::c_int;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long as libc::c_ulong,
                        ) as libc::c_int;
                }
                if avail < 2 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                next = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
                if cur as libc::c_int == '<' as i32 && next as libc::c_int == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_PI as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).progressive = 1 as libc::c_int;
                    }
                } else if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).progressive = 1 as libc::c_int;
                    }
                } else {
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32 && avail < 4 as libc::c_int
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    (*ctxt).instate = XML_PARSER_START_TAG;
                    if (*ctxt).progressive == 0 as libc::c_int {
                        (*ctxt).progressive = XML_PARSER_START_TAG as libc::c_int;
                    }
                    xmlParseGetLasts(ctxt, &mut lastlt, &mut lastgt);
                }
            }
            14 => {
                xmlSkipBlankChars(ctxt);
                if ((*(*ctxt).input).buf).is_null() {
                    avail = ((*(*ctxt).input).length as libc::c_long
                        - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long) as libc::c_int;
                } else {
                    avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                        .wrapping_sub(
                            ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                                as libc::c_long as libc::c_ulong,
                        ) as libc::c_int;
                }
                if avail < 2 as libc::c_int {
                    current_block = 2814621064645850728;
                    break;
                }
                cur = *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize);
                next = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
                if cur as libc::c_int == '<' as i32 && next as libc::c_int == '?' as i32
                {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '?' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                            0 as libc::c_int as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_PI as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParsePI(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_EPILOG;
                        (*ctxt).progressive = 1 as libc::c_int;
                    }
                } else if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32
                        && *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                        && *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize)
                            as libc::c_int == '-' as i32
                    {
                    if terminate == 0
                        && xmlParseLookupSequence(
                            ctxt,
                            '-' as i32 as xmlChar,
                            '-' as i32 as xmlChar,
                            '>' as i32 as xmlChar,
                        ) < 0 as libc::c_int
                    {
                        (*ctxt).progressive = XML_PARSER_COMMENT as libc::c_int;
                        current_block = 2814621064645850728;
                        break;
                    } else {
                        xmlParseComment(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_EPILOG;
                        (*ctxt).progressive = 1 as libc::c_int;
                    }
                } else {
                    if cur as libc::c_int == '<' as i32
                        && next as libc::c_int == '!' as i32 && avail < 4 as libc::c_int
                    {
                        current_block = 2814621064645850728;
                        break;
                    }
                    xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const libc::c_char);
                    xmlHaltParser(ctxt);
                    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some()
                    {
                        ((*(*ctxt).sax).endDocument)
                            .expect("non-null function pointer")((*ctxt).userData);
                    }
                    current_block = 2814621064645850728;
                    break;
                }
            }
            3 => {
                let mut base_1: libc::c_int = 0;
                let mut i: libc::c_int = 0;
                let mut buf: *mut xmlChar = 0 as *mut xmlChar;
                let mut quote: xmlChar = 0 as libc::c_int as xmlChar;
                let mut use_0: size_t = 0;
                base_1 = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long as libc::c_int;
                if base_1 < 0 as libc::c_int {
                    return 0 as libc::c_int;
                }
                if (*ctxt).checkIndex > base_1 as libc::c_long {
                    base_1 = (*ctxt).checkIndex as libc::c_int;
                }
                buf = xmlBufContent((*(*(*ctxt).input).buf).buffer as *const xmlBuf);
                use_0 = xmlBufUse((*(*(*ctxt).input).buf).buffer);
                's_1946: loop {
                    if !((base_1 as libc::c_uint as libc::c_ulong) < use_0) {
                        current_block = 10059826840140668507;
                        break;
                    }
                    if quote as libc::c_int != 0 as libc::c_int {
                        if *buf.offset(base_1 as isize) as libc::c_int
                            == quote as libc::c_int
                        {
                            quote = 0 as libc::c_int as xmlChar;
                        }
                    } else {
                        if quote as libc::c_int == 0 as libc::c_int
                            && *buf.offset(base_1 as isize) as libc::c_int == '<' as i32
                        {
                            let mut found: libc::c_int = 0 as libc::c_int;
                            if ((base_1 as libc::c_uint)
                                .wrapping_add(4 as libc::c_int as libc::c_uint)
                                as libc::c_ulong) < use_0
                                && *buf.offset((base_1 + 1 as libc::c_int) as isize)
                                    as libc::c_int == '!' as i32
                                && *buf.offset((base_1 + 2 as libc::c_int) as isize)
                                    as libc::c_int == '-' as i32
                                && *buf.offset((base_1 + 3 as libc::c_int) as isize)
                                    as libc::c_int == '-' as i32
                            {
                                while ((base_1 as libc::c_uint)
                                    .wrapping_add(3 as libc::c_int as libc::c_uint)
                                    as libc::c_ulong) < use_0
                                {
                                    if *buf.offset(base_1 as isize) as libc::c_int == '-' as i32
                                        && *buf.offset((base_1 + 1 as libc::c_int) as isize)
                                            as libc::c_int == '-' as i32
                                        && *buf.offset((base_1 + 2 as libc::c_int) as isize)
                                            as libc::c_int == '>' as i32
                                    {
                                        found = 1 as libc::c_int;
                                        base_1 += 2 as libc::c_int;
                                        break;
                                    } else {
                                        base_1 += 1;
                                    }
                                }
                                if found == 0 {
                                    current_block = 10059826840140668507;
                                    break;
                                }
                                current_block = 16936879297222305916;
                            } else {
                                current_block = 9828016697359808143;
                            }
                        } else {
                            current_block = 9828016697359808143;
                        }
                        match current_block {
                            16936879297222305916 => {}
                            _ => {
                                if *buf.offset(base_1 as isize) as libc::c_int == '"' as i32
                                {
                                    quote = '"' as i32 as xmlChar;
                                } else if *buf.offset(base_1 as isize) as libc::c_int
                                        == '\'' as i32
                                    {
                                    quote = '\'' as i32 as xmlChar;
                                } else if *buf.offset(base_1 as isize) as libc::c_int
                                        == ']' as i32
                                    {
                                    if (base_1 as libc::c_uint)
                                        .wrapping_add(1 as libc::c_int as libc::c_uint)
                                        as libc::c_ulong >= use_0
                                    {
                                        current_block = 10059826840140668507;
                                        break;
                                    }
                                    if *buf.offset((base_1 + 1 as libc::c_int) as isize)
                                        as libc::c_int == ']' as i32
                                    {
                                        base_1 += 1;
                                    } else {
                                        i = 1 as libc::c_int;
                                        loop {
                                            if !(((base_1 as libc::c_uint)
                                                .wrapping_add(i as libc::c_uint) as libc::c_ulong) < use_0)
                                            {
                                                current_block = 10059826840140668507;
                                                break 's_1946;
                                            }
                                            if *buf.offset((base_1 + i) as isize) as libc::c_int
                                                == '>' as i32
                                            {
                                                current_block = 16939792823138094123;
                                                break 's_1946;
                                            }
                                            if !(*buf.offset((base_1 + i) as isize) as libc::c_int
                                                == 0x20 as libc::c_int
                                                || 0x9 as libc::c_int
                                                    <= *buf.offset((base_1 + i) as isize) as libc::c_int
                                                    && *buf.offset((base_1 + i) as isize) as libc::c_int
                                                        <= 0xa as libc::c_int
                                                || *buf.offset((base_1 + i) as isize) as libc::c_int
                                                    == 0xd as libc::c_int)
                                            {
                                                break;
                                            }
                                            i += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    base_1 += 1;
                }
                match current_block {
                    10059826840140668507 => {
                        if quote as libc::c_int == 0 as libc::c_int {
                            (*ctxt).checkIndex = base_1 as libc::c_long;
                        } else {
                            (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        }
                        current_block = 2814621064645850728;
                        break;
                    }
                    _ => {
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                        xmlParseInternalSubset(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).inSubset = 2 as libc::c_int;
                        if !((*ctxt).sax).is_null() && (*ctxt).disableSAX == 0
                            && ((*(*ctxt).sax).externalSubset).is_some()
                        {
                            ((*(*ctxt).sax).externalSubset)
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*ctxt).userData,
                                (*ctxt).intSubName,
                                (*ctxt).extSubSystem,
                                (*ctxt).extSubURI,
                            );
                        }
                        (*ctxt).inSubset = 0 as libc::c_int;
                        xmlCleanSpecialAttr(ctxt);
                        if (*ctxt).instate as libc::c_int
                            == XML_PARSER_EOF as libc::c_int
                        {
                            current_block = 2814621064645850728;
                            break;
                        }
                        (*ctxt).instate = XML_PARSER_PROLOG;
                        (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
                    }
                }
            }
            5 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == COMMENT\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            15 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == IGNORE\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_DTD;
            }
            2 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == PI\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            10 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ENTITY_DECL\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_DTD;
            }
            11 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ENTITY_VALUE\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_CONTENT;
            }
            12 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == ATTRIBUTE_VALUE\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            13 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == SYSTEM_LITERAL\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            16 => {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"PP: internal error, state == PUBLIC_LITERAL\n\0" as *const u8
                        as *const libc::c_char,
                );
                (*ctxt).instate = XML_PARSER_START_TAG;
            }
            _ => {}
        }
    }
    match current_block {
        2814621064645850728 => return ret,
        _ => {
            let mut buffer: [libc::c_char; 150] = [0; 150];
            snprintf(
                buffer.as_mut_ptr(),
                149 as libc::c_int as libc::c_ulong,
                b"Bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n\0" as *const u8
                    as *const libc::c_char,
                *((*(*ctxt).input).cur).offset(0 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize) as libc::c_int,
                *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize) as libc::c_int,
            );
            __xmlErrEncoding(
                ctxt,
                XML_ERR_INVALID_CHAR,
                b"Input is not proper UTF-8, indicate encoding !\n%s\0" as *const u8
                    as *const libc::c_char,
                buffer.as_mut_ptr() as *mut xmlChar,
                0 as *const xmlChar,
            );
            return 0 as libc::c_int;
        }
    };
}
unsafe extern "C" fn xmlParseCheckTransition(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    if ctxt.is_null() || chunk.is_null() || size < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_START_TAG as libc::c_int {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctxt).progressive == XML_PARSER_COMMENT as libc::c_int {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_CDATA_SECTION as libc::c_int {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctxt).progressive == XML_PARSER_PI as libc::c_int {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_END_TAG as libc::c_int {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    if (*ctxt).progressive == XML_PARSER_DTD as libc::c_int
        || (*ctxt).instate as libc::c_int == XML_PARSER_DTD as libc::c_int
    {
        if !(memchr(chunk as *const libc::c_void, '>' as i32, size as libc::c_ulong))
            .is_null()
        {
            return 1 as libc::c_int;
        }
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseChunk(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
    mut terminate: libc::c_int,
) -> libc::c_int {
    let mut end_in_lf: libc::c_int = 0 as libc::c_int;
    let mut remain: libc::c_int = 0 as libc::c_int;
    let mut old_avail: size_t = 0 as libc::c_int as size_t;
    let mut avail: size_t = 0 as libc::c_int as size_t;
    if ctxt.is_null() {
        return XML_ERR_INTERNAL_ERROR as libc::c_int;
    }
    if (*ctxt).errNo != XML_ERR_OK as libc::c_int
        && (*ctxt).disableSAX == 1 as libc::c_int
    {
        return (*ctxt).errNo;
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
        return -(1 as libc::c_int);
    }
    if (*ctxt).instate as libc::c_int == XML_PARSER_START as libc::c_int {
        xmlDetectSAX2(ctxt);
    }
    if size > 0 as libc::c_int && !chunk.is_null() && terminate == 0
        && *chunk.offset((size - 1 as libc::c_int) as isize) as libc::c_int
            == '\r' as i32
    {
        end_in_lf = 1 as libc::c_int;
        size -= 1;
    }
    loop {
        if size > 0 as libc::c_int && !chunk.is_null() && !((*ctxt).input).is_null()
            && !((*(*ctxt).input).buf).is_null()
            && (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
        {
            let mut base: size_t = xmlBufGetInputBase(
                (*(*(*ctxt).input).buf).buffer,
                (*ctxt).input,
            );
            let mut cur: size_t = ((*(*ctxt).input).cur)
                .offset_from((*(*ctxt).input).base) as libc::c_long as size_t;
            let mut res: libc::c_int = 0;
            old_avail = xmlBufUse((*(*(*ctxt).input).buf).buffer);
            if (*ctxt).instate as libc::c_int == XML_PARSER_START as libc::c_int
                && !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null()
                && !((*(*(*ctxt).input).buf).encoder).is_null()
            {
                let mut len: libc::c_uint = 45 as libc::c_int as libc::c_uint;
                if !(xmlStrcasestr(
                    (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                    b"UTF-16\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                ))
                    .is_null()
                    || !(xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UTF16\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ))
                        .is_null()
                {
                    len = 90 as libc::c_int as libc::c_uint;
                } else if !(xmlStrcasestr(
                        (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                        b"UCS-4\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                    ))
                        .is_null()
                        || !(xmlStrcasestr(
                            (*(*(*(*ctxt).input).buf).encoder).name as *mut xmlChar,
                            b"UCS4\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                        ))
                            .is_null()
                    {
                    len = 180 as libc::c_int as libc::c_uint;
                }
                if (*(*(*ctxt).input).buf).rawconsumed < len as libc::c_ulong {
                    len = (len as libc::c_ulong)
                        .wrapping_sub((*(*(*ctxt).input).buf).rawconsumed)
                        as libc::c_uint as libc::c_uint;
                }
                if size as libc::c_uint > len {
                    remain = (size as libc::c_uint).wrapping_sub(len) as libc::c_int;
                    size = len as libc::c_int;
                } else {
                    remain = 0 as libc::c_int;
                }
            }
            res = xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
            xmlBufSetInputBaseCur(
                (*(*(*ctxt).input).buf).buffer,
                (*ctxt).input,
                base,
                cur,
            );
            if res < 0 as libc::c_int {
                (*ctxt).errNo = XML_PARSER_EOF as libc::c_int;
                xmlHaltParser(ctxt);
                return XML_PARSER_EOF as libc::c_int;
            }
        } else if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
            if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
                let mut in_0: xmlParserInputBufferPtr = (*(*ctxt).input).buf;
                if !((*in_0).encoder).is_null() && !((*in_0).buffer).is_null()
                    && !((*in_0).raw).is_null()
                {
                    let mut nbchars: libc::c_int = 0;
                    let mut base_0: size_t = xmlBufGetInputBase(
                        (*in_0).buffer,
                        (*ctxt).input,
                    );
                    let mut current: size_t = ((*(*ctxt).input).cur)
                        .offset_from((*(*ctxt).input).base) as libc::c_long as size_t;
                    nbchars = xmlCharEncInput(in_0, terminate);
                    xmlBufSetInputBaseCur(
                        (*in_0).buffer,
                        (*ctxt).input,
                        base_0,
                        current,
                    );
                    if nbchars < 0 as libc::c_int {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"xmlParseChunk: encoder error\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        xmlHaltParser(ctxt);
                        return XML_ERR_INVALID_ENCODING as libc::c_int;
                    }
                }
            }
        }
        if remain != 0 as libc::c_int {
            xmlParseTryOrFinish(ctxt, 0 as libc::c_int);
        } else {
            if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
                avail = xmlBufUse((*(*(*ctxt).input).buf).buffer);
            }
            if terminate != 0 || avail > 10000000 as libc::c_int as libc::c_ulong
                || old_avail == 0 as libc::c_int as libc::c_ulong
                || avail == 0 as libc::c_int as libc::c_ulong
                || xmlParseCheckTransition(
                    ctxt,
                    &*((*(*ctxt).input).base).offset(old_avail as isize)
                        as *const xmlChar as *const libc::c_char,
                    avail.wrapping_sub(old_avail) as libc::c_int,
                ) != 0
            {
                xmlParseTryOrFinish(ctxt, terminate);
            }
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EOF as libc::c_int {
            return (*ctxt).errNo;
        }
        if !((*ctxt).input).is_null()
            && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
                > 10000000 as libc::c_int as libc::c_long
                || ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                    as libc::c_long > 10000000 as libc::c_int as libc::c_long)
            && (*ctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        {
            xmlFatalErr(
                ctxt,
                XML_ERR_INTERNAL_ERROR,
                b"Huge input lookup\0" as *const u8 as *const libc::c_char,
            );
            xmlHaltParser(ctxt);
        }
        if (*ctxt).errNo != XML_ERR_OK as libc::c_int
            && (*ctxt).disableSAX == 1 as libc::c_int
        {
            return (*ctxt).errNo;
        }
        if !(remain != 0 as libc::c_int) {
            break;
        }
        chunk = chunk.offset(size as isize);
        size = remain;
        remain = 0 as libc::c_int;
    }
    if end_in_lf == 1 as libc::c_int && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
    {
        let mut base_1: size_t = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut current_0: size_t = ((*(*ctxt).input).cur)
            .offset_from((*(*ctxt).input).base) as libc::c_long as size_t;
        xmlParserInputBufferPush(
            (*(*ctxt).input).buf,
            1 as libc::c_int,
            b"\r\0" as *const u8 as *const libc::c_char,
        );
        xmlBufSetInputBaseCur(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
            base_1,
            current_0,
        );
    }
    if terminate != 0 {
        let mut cur_avail: libc::c_int = 0 as libc::c_int;
        if !((*ctxt).input).is_null() {
            if ((*(*ctxt).input).buf).is_null() {
                cur_avail = ((*(*ctxt).input).length as libc::c_long
                    - ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                        as libc::c_long) as libc::c_int;
            } else {
                cur_avail = (xmlBufUse((*(*(*ctxt).input).buf).buffer))
                    .wrapping_sub(
                        ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
                            as libc::c_long as libc::c_ulong,
                    ) as libc::c_int;
            }
        }
        if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int
            && (*ctxt).instate as libc::c_int != XML_PARSER_EPILOG as libc::c_int
        {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const libc::c_char);
        }
        if (*ctxt).instate as libc::c_int == XML_PARSER_EPILOG as libc::c_int
            && cur_avail > 0 as libc::c_int
        {
            xmlFatalErr(ctxt, XML_ERR_DOCUMENT_END, 0 as *const libc::c_char);
        }
        if (*ctxt).instate as libc::c_int != XML_PARSER_EOF as libc::c_int {
            if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).endDocument).is_some() {
                ((*(*ctxt).sax).endDocument)
                    .expect("non-null function pointer")((*ctxt).userData);
            }
        }
        (*ctxt).instate = XML_PARSER_EOF;
    }
    if (*ctxt).wellFormed == 0 as libc::c_int {
        return (*ctxt).errNo as xmlParserErrors as libc::c_int
    } else {
        return 0 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreatePushParserCtxt(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
    mut filename: *const libc::c_char,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if !chunk.is_null() && size >= 4 as libc::c_int {
        enc = xmlDetectCharEncoding(chunk as *const xmlChar, size);
    }
    buf = xmlAllocParserInputBuffer(enc);
    if buf.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"creating parser: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    (*ctxt).dictNames = 1 as libc::c_int;
    if !sax.is_null() {
        if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh454 = (*ctxt).sax;
        *fresh454 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong)
            as xmlSAXHandlerPtr;
        if ((*ctxt).sax).is_null() {
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            xmlFreeParserInputBuffer(buf);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
        );
        if (*sax).initialized == 0xdeedbeaf as libc::c_uint {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
            );
        } else {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as libc::c_ulong,
            );
        }
        if !user_data.is_null() {
            let ref mut fresh455 = (*ctxt).userData;
            *fresh455 = user_data;
        }
    }
    if filename.is_null() {
        let ref mut fresh456 = (*ctxt).directory;
        *fresh456 = 0 as *mut libc::c_char;
    } else {
        let ref mut fresh457 = (*ctxt).directory;
        *fresh457 = xmlParserGetDirectory(filename);
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    if filename.is_null() {
        let ref mut fresh458 = (*inputStream).filename;
        *fresh458 = 0 as *const libc::c_char;
    } else {
        let ref mut fresh459 = (*inputStream).filename;
        *fresh459 = xmlCanonicPath(filename as *const xmlChar) as *mut libc::c_char;
        if ((*inputStream).filename).is_null() {
            xmlFreeParserCtxt(ctxt);
            xmlFreeParserInputBuffer(buf);
            return 0 as xmlParserCtxtPtr;
        }
    }
    let ref mut fresh460 = (*inputStream).buf;
    *fresh460 = buf;
    xmlBufResetInput((*(*inputStream).buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if size == 0 as libc::c_int || chunk.is_null() {
        (*ctxt).charset = XML_CHAR_ENCODING_NONE as libc::c_int;
    } else if !((*ctxt).input).is_null() && !((*(*ctxt).input).buf).is_null() {
        let mut base: size_t = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: size_t = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as libc::c_long as size_t;
        xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
    }
    if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
        xmlSwitchEncoding(ctxt, enc);
    }
    return ctxt;
}
unsafe extern "C" fn xmlHaltParser(mut ctxt: xmlParserCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    (*ctxt).instate = XML_PARSER_EOF;
    (*ctxt).disableSAX = 1 as libc::c_int;
    while (*ctxt).inputNr > 1 as libc::c_int {
        xmlFreeInputStream(inputPop(ctxt));
    }
    if !((*ctxt).input).is_null() {
        if ((*(*ctxt).input).free).is_some() {
            ((*(*ctxt).input).free)
                .expect(
                    "non-null function pointer",
                )((*(*ctxt).input).base as *mut xmlChar);
            let ref mut fresh461 = (*(*ctxt).input).free;
            *fresh461 = None;
        }
        if !((*(*ctxt).input).buf).is_null() {
            xmlFreeParserInputBuffer((*(*ctxt).input).buf);
            let ref mut fresh462 = (*(*ctxt).input).buf;
            *fresh462 = 0 as xmlParserInputBufferPtr;
        }
        let ref mut fresh463 = (*(*ctxt).input).cur;
        *fresh463 = b"\0" as *const u8 as *const libc::c_char as *mut xmlChar;
        (*(*ctxt).input).length = 0 as libc::c_int;
        let ref mut fresh464 = (*(*ctxt).input).base;
        *fresh464 = (*(*ctxt).input).cur;
        let ref mut fresh465 = (*(*ctxt).input).end;
        *fresh465 = (*(*ctxt).input).cur;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlStopParser(mut ctxt: xmlParserCtxtPtr) {
    if ctxt.is_null() {
        return;
    }
    xmlHaltParser(ctxt);
    (*ctxt).errNo = XML_ERR_USER_STOP as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateIOParserCtxt(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut enc: xmlCharEncoding,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if ioread.is_none() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, enc);
    if buf.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 0 as xmlParserCtxtPtr;
    }
    if !sax.is_null() {
        if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh466 = (*ctxt).sax;
        *fresh466 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong)
            as xmlSAXHandlerPtr;
        if ((*ctxt).sax).is_null() {
            xmlFreeParserInputBuffer(buf);
            xmlErrMemory(ctxt, 0 as *const libc::c_char);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        memset(
            (*ctxt).sax as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
        );
        if (*sax).initialized == 0xdeedbeaf as libc::c_uint {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandler>() as libc::c_ulong,
            );
        } else {
            memcpy(
                (*ctxt).sax as *mut libc::c_void,
                sax as *const libc::c_void,
                ::std::mem::size_of::<xmlSAXHandlerV1>() as libc::c_ulong,
            );
        }
        if !user_data.is_null() {
            let ref mut fresh467 = (*ctxt).userData;
            *fresh467 = user_data;
        }
    }
    inputStream = xmlNewIOInputStream(ctxt, buf, enc);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlIOParseDTD(
    mut sax: xmlSAXHandlerPtr,
    mut input: xmlParserInputBufferPtr,
    mut enc: xmlCharEncoding,
) -> xmlDtdPtr {
    let mut ret: xmlDtdPtr = 0 as xmlDtdPtr;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pinput: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut start: [xmlChar; 4] = [0; 4];
    if input.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDtdPtr;
    }
    (*ctxt).options |= XML_PARSE_DTDLOAD as libc::c_int;
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh468 = (*ctxt).sax;
        *fresh468 = sax;
        let ref mut fresh469 = (*ctxt).userData;
        *fresh469 = ctxt as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    pinput = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if pinput.is_null() {
        if !sax.is_null() {
            let ref mut fresh470 = (*ctxt).sax;
            *fresh470 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, pinput) < 0 as libc::c_int {
        if !sax.is_null() {
            let ref mut fresh471 = (*ctxt).sax;
            *fresh471 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
        xmlSwitchEncoding(ctxt, enc);
    }
    let ref mut fresh472 = (*pinput).filename;
    *fresh472 = 0 as *const libc::c_char;
    (*pinput).line = 1 as libc::c_int;
    (*pinput).col = 1 as libc::c_int;
    let ref mut fresh473 = (*pinput).base;
    *fresh473 = (*(*ctxt).input).cur;
    let ref mut fresh474 = (*pinput).cur;
    *fresh474 = (*(*ctxt).input).cur;
    let ref mut fresh475 = (*pinput).free;
    *fresh475 = None;
    (*ctxt).inSubset = 2 as libc::c_int;
    let ref mut fresh476 = (*ctxt).myDoc;
    *fresh476 = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    if ((*ctxt).myDoc).is_null() {
        xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const libc::c_char);
        return 0 as xmlDtdPtr;
    }
    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as libc::c_int;
    let ref mut fresh477 = (*(*ctxt).myDoc).extSubset;
    *fresh477 = xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if enc as libc::c_int == XML_CHAR_ENCODING_NONE as libc::c_int
        && ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
            >= 4 as libc::c_int as libc::c_long
    {
        start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    xmlParseExternalSubset(
        ctxt,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
    );
    if !((*ctxt).myDoc).is_null() {
        if (*ctxt).wellFormed != 0 {
            ret = (*(*ctxt).myDoc).extSubset;
            let ref mut fresh478 = (*(*ctxt).myDoc).extSubset;
            *fresh478 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                let ref mut fresh479 = (*ret).doc;
                *fresh479 = 0 as *mut _xmlDoc;
                tmp = (*ret).children;
                while !tmp.is_null() {
                    let ref mut fresh480 = (*tmp).doc;
                    *fresh480 = 0 as *mut _xmlDoc;
                    tmp = (*tmp).next;
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh481 = (*ctxt).myDoc;
        *fresh481 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh482 = (*ctxt).sax;
        *fresh482 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseDTD(
    mut sax: xmlSAXHandlerPtr,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    let mut ret: xmlDtdPtr = 0 as xmlDtdPtr;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputPtr = 0 as xmlParserInputPtr;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    let mut systemIdCanonic: *mut xmlChar = 0 as *mut xmlChar;
    if ExternalID.is_null() && SystemID.is_null() {
        return 0 as xmlDtdPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlDtdPtr;
    }
    (*ctxt).options |= XML_PARSE_DTDLOAD as libc::c_int;
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh483 = (*ctxt).sax;
        *fresh483 = sax;
        let ref mut fresh484 = (*ctxt).userData;
        *fresh484 = ctxt as *mut libc::c_void;
    }
    systemIdCanonic = xmlCanonicPath(SystemID);
    if !SystemID.is_null() && systemIdCanonic.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    if !((*ctxt).sax).is_null() && ((*(*ctxt).sax).resolveEntity).is_some() {
        input = ((*(*ctxt).sax).resolveEntity)
            .expect(
                "non-null function pointer",
            )((*ctxt).userData, ExternalID, systemIdCanonic);
    }
    if input.is_null() {
        if !sax.is_null() {
            let ref mut fresh485 = (*ctxt).sax;
            *fresh485 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        if !systemIdCanonic.is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(systemIdCanonic as *mut libc::c_void);
        }
        return 0 as xmlDtdPtr;
    }
    if xmlPushInput(ctxt, input) < 0 as libc::c_int {
        if !sax.is_null() {
            let ref mut fresh486 = (*ctxt).sax;
            *fresh486 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        if !systemIdCanonic.is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(systemIdCanonic as *mut libc::c_void);
        }
        return 0 as xmlDtdPtr;
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
        >= 4 as libc::c_int as libc::c_long
    {
        enc = xmlDetectCharEncoding((*(*ctxt).input).cur, 4 as libc::c_int);
        xmlSwitchEncoding(ctxt, enc);
    }
    if ((*input).filename).is_null() {
        let ref mut fresh487 = (*input).filename;
        *fresh487 = systemIdCanonic as *mut libc::c_char;
    } else {
        xmlFree
            .expect("non-null function pointer")(systemIdCanonic as *mut libc::c_void);
    }
    (*input).line = 1 as libc::c_int;
    (*input).col = 1 as libc::c_int;
    let ref mut fresh488 = (*input).base;
    *fresh488 = (*(*ctxt).input).cur;
    let ref mut fresh489 = (*input).cur;
    *fresh489 = (*(*ctxt).input).cur;
    let ref mut fresh490 = (*input).free;
    *fresh490 = None;
    (*ctxt).inSubset = 2 as libc::c_int;
    let ref mut fresh491 = (*ctxt).myDoc;
    *fresh491 = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    if ((*ctxt).myDoc).is_null() {
        xmlErrMemory(ctxt, b"New Doc failed\0" as *const u8 as *const libc::c_char);
        if !sax.is_null() {
            let ref mut fresh492 = (*ctxt).sax;
            *fresh492 = 0 as *mut _xmlSAXHandler;
        }
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDtdPtr;
    }
    (*(*ctxt).myDoc).properties = XML_DOC_INTERNAL as libc::c_int;
    let ref mut fresh493 = (*(*ctxt).myDoc).extSubset;
    *fresh493 = xmlNewDtd(
        (*ctxt).myDoc,
        b"none\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ExternalID,
        SystemID,
    );
    xmlParseExternalSubset(ctxt, ExternalID, SystemID);
    if !((*ctxt).myDoc).is_null() {
        if (*ctxt).wellFormed != 0 {
            ret = (*(*ctxt).myDoc).extSubset;
            let ref mut fresh494 = (*(*ctxt).myDoc).extSubset;
            *fresh494 = 0 as *mut _xmlDtd;
            if !ret.is_null() {
                let mut tmp: xmlNodePtr = 0 as *mut xmlNode;
                let ref mut fresh495 = (*ret).doc;
                *fresh495 = 0 as *mut _xmlDoc;
                tmp = (*ret).children;
                while !tmp.is_null() {
                    let ref mut fresh496 = (*tmp).doc;
                    *fresh496 = 0 as *mut _xmlDoc;
                    tmp = (*tmp).next;
                }
            }
        } else {
            ret = 0 as xmlDtdPtr;
        }
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh497 = (*ctxt).myDoc;
        *fresh497 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh498 = (*ctxt).sax;
        *fresh498 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDTD(
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) -> xmlDtdPtr {
    return xmlSAXParseDTD(0 as xmlSAXHandlerPtr, ExternalID, SystemID);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseCtxtExternalEntity(
    mut ctx: xmlParserCtxtPtr,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> libc::c_int {
    let mut userData: *mut libc::c_void = 0 as *mut libc::c_void;
    if ctx.is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctx).userData == ctx as *mut libc::c_void {
        userData = 0 as *mut libc::c_void;
    } else {
        userData = (*ctx).userData;
    }
    return xmlParseExternalEntityPrivate(
        (*ctx).myDoc,
        ctx,
        (*ctx).sax,
        userData,
        (*ctx).depth + 1 as libc::c_int,
        URL,
        ID,
        lst,
    ) as libc::c_int;
}
unsafe extern "C" fn xmlParseExternalEntityPrivate(
    mut doc: xmlDocPtr,
    mut oldctxt: xmlParserCtxtPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: libc::c_int,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut list: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    let mut start: [xmlChar; 4] = [0; 4];
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if depth > 40 as libc::c_int
        && (oldctxt.is_null()
            || (*oldctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int)
        || depth > 1024 as libc::c_int
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !list.is_null() {
        *list = 0 as xmlNodePtr;
    }
    if URL.is_null() && ID.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if doc.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    ctxt = xmlCreateEntityParserCtxtInternal(URL, ID, 0 as *const xmlChar, oldctxt);
    if ctxt.is_null() {
        return XML_WAR_UNDECLARED_ENTITY;
    }
    let ref mut fresh499 = (*ctxt).userData;
    *fresh499 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let ref mut fresh500 = (*ctxt).sax;
        *fresh500 = sax;
        if !user_data.is_null() {
            let ref mut fresh501 = (*ctxt).userData;
            *fresh501 = user_data;
        }
    }
    xmlDetectSAX2(ctxt);
    newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    if newDoc.is_null() {
        xmlFreeParserCtxt(ctxt);
        return XML_ERR_INTERNAL_ERROR;
    }
    (*newDoc).properties = XML_DOC_INTERNAL as libc::c_int;
    if !doc.is_null() {
        let ref mut fresh502 = (*newDoc).intSubset;
        *fresh502 = (*doc).intSubset;
        let ref mut fresh503 = (*newDoc).extSubset;
        *fresh503 = (*doc).extSubset;
        if !((*doc).dict).is_null() {
            let ref mut fresh504 = (*newDoc).dict;
            *fresh504 = (*doc).dict;
            xmlDictReference((*newDoc).dict);
        }
        if !((*doc).URL).is_null() {
            let ref mut fresh505 = (*newDoc).URL;
            *fresh505 = xmlStrdup((*doc).URL);
        }
    }
    newRoot = xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        if !sax.is_null() {
            let ref mut fresh506 = (*ctxt).sax;
            *fresh506 = oldsax;
        }
        xmlFreeParserCtxt(ctxt);
        let ref mut fresh507 = (*newDoc).intSubset;
        *fresh507 = 0 as *mut _xmlDtd;
        let ref mut fresh508 = (*newDoc).extSubset;
        *fresh508 = 0 as *mut _xmlDtd;
        xmlFreeDoc(newDoc);
        return XML_ERR_INTERNAL_ERROR;
    }
    xmlAddChild(newDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, (*newDoc).children);
    if doc.is_null() {
        let ref mut fresh509 = (*ctxt).myDoc;
        *fresh509 = newDoc;
    } else {
        let ref mut fresh510 = (*ctxt).myDoc;
        *fresh510 = doc;
        let ref mut fresh511 = (*newRoot).doc;
        *fresh511 = doc;
    }
    if (*ctxt).progressive == 0 as libc::c_int
        && (((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long)
            < 250 as libc::c_int as libc::c_long
    {
        xmlGROW(ctxt);
    }
    if ((*(*ctxt).input).end).offset_from((*(*ctxt).input).cur) as libc::c_long
        >= 4 as libc::c_int as libc::c_long
    {
        start[0 as libc::c_int as usize] = *(*(*ctxt).input).cur;
        start[1 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize);
        start[2 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(2 as libc::c_int as isize);
        start[3 as libc::c_int
            as usize] = *((*(*ctxt).input).cur).offset(3 as libc::c_int as isize);
        enc = xmlDetectCharEncoding(start.as_mut_ptr(), 4 as libc::c_int);
        if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
            xmlSwitchEncoding(ctxt, enc);
        }
    }
    if *((*(*ctxt).input).cur as *mut libc::c_uchar).offset(0 as libc::c_int as isize)
        as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(1 as libc::c_int as isize) as libc::c_int == '?' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(2 as libc::c_int as isize) as libc::c_int == 'x' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(3 as libc::c_int as isize) as libc::c_int == 'm' as i32
        && *((*(*ctxt).input).cur as *mut libc::c_uchar)
            .offset(4 as libc::c_int as isize) as libc::c_int == 'l' as i32
        && (*((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
            == 0x20 as libc::c_int
            || 0x9 as libc::c_int
                <= *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int
                && *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize)
                    as libc::c_int <= 0xa as libc::c_int
            || *((*(*ctxt).input).cur).offset(5 as libc::c_int as isize) as libc::c_int
                == 0xd as libc::c_int)
    {
        xmlParseTextDecl(ctxt);
        if xmlStrEqual(
            (*oldctxt).version,
            b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        ) != 0
            && xmlStrEqual(
                (*(*ctxt).input).version,
                b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            ) == 0
        {
            xmlFatalErrMsg(
                ctxt,
                XML_ERR_VERSION_MISMATCH,
                b"Version mismatch between document and entity\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).depth = depth;
    if !oldctxt.is_null() {
        let ref mut fresh512 = (*ctxt)._private;
        *fresh512 = (*oldctxt)._private;
        (*ctxt).loadsubset = (*oldctxt).loadsubset;
        (*ctxt).validate = (*oldctxt).validate;
        (*ctxt).valid = (*oldctxt).valid;
        (*ctxt).replaceEntities = (*oldctxt).replaceEntities;
        if (*oldctxt).validate != 0 {
            let ref mut fresh513 = (*ctxt).vctxt.error;
            *fresh513 = (*oldctxt).vctxt.error;
            let ref mut fresh514 = (*ctxt).vctxt.warning;
            *fresh514 = (*oldctxt).vctxt.warning;
            let ref mut fresh515 = (*ctxt).vctxt.userData;
            *fresh515 = (*oldctxt).vctxt.userData;
        }
        (*ctxt).external = (*oldctxt).external;
        if !((*ctxt).dict).is_null() {
            xmlDictFree((*ctxt).dict);
        }
        let ref mut fresh516 = (*ctxt).dict;
        *fresh516 = (*oldctxt).dict;
        let ref mut fresh517 = (*ctxt).str_xml;
        *fresh517 = xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            3 as libc::c_int,
        );
        let ref mut fresh518 = (*ctxt).str_xmlns;
        *fresh518 = xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            5 as libc::c_int,
        );
        let ref mut fresh519 = (*ctxt).str_xml_ns;
        *fresh519 = xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
            36 as libc::c_int,
        );
        (*ctxt).dictNames = (*oldctxt).dictNames;
        let ref mut fresh520 = (*ctxt).attsDefault;
        *fresh520 = (*oldctxt).attsDefault;
        let ref mut fresh521 = (*ctxt).attsSpecial;
        *fresh521 = (*oldctxt).attsSpecial;
        (*ctxt).linenumbers = (*oldctxt).linenumbers;
        (*ctxt).record_info = (*oldctxt).record_info;
        (*ctxt).node_seq.maximum = (*oldctxt).node_seq.maximum;
        (*ctxt).node_seq.length = (*oldctxt).node_seq.length;
        let ref mut fresh522 = (*ctxt).node_seq.buffer;
        *fresh522 = (*oldctxt).node_seq.buffer;
    } else {
        let ref mut fresh523 = (*ctxt)._private;
        *fresh523 = 0 as *mut libc::c_void;
        (*ctxt).validate = 0 as libc::c_int;
        (*ctxt).external = 2 as libc::c_int;
        (*ctxt).loadsubset = 0 as libc::c_int;
    }
    xmlParseContent(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    } else if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const libc::c_char);
    }
    if (*ctxt).node != (*newDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as libc::c_int {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        if !list.is_null() {
            let mut cur: xmlNodePtr = 0 as *mut xmlNode;
            cur = (*(*newDoc).children).children;
            *list = cur;
            while !cur.is_null() {
                let ref mut fresh524 = (*cur).parent;
                *fresh524 = 0 as *mut _xmlNode;
                cur = (*cur).next;
            }
            let ref mut fresh525 = (*(*newDoc).children).children;
            *fresh525 = 0 as *mut _xmlNode;
        }
        ret = XML_ERR_OK;
    }
    if !oldctxt.is_null() {
        let ref mut fresh526 = (*oldctxt).nbentities;
        *fresh526 = (*fresh526).wrapping_add((*ctxt).nbentities);
    }
    if !((*ctxt).input).is_null() && !oldctxt.is_null() {
        let ref mut fresh527 = (*oldctxt).sizeentities;
        *fresh527 = (*fresh527).wrapping_add((*(*ctxt).input).consumed);
        let ref mut fresh528 = (*oldctxt).sizeentities;
        *fresh528 = (*fresh528)
            .wrapping_add(
                ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base) as libc::c_long
                    as libc::c_ulong,
            );
    }
    if !oldctxt.is_null() && (*ctxt).lastError.code != XML_ERR_OK as libc::c_int {
        xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError);
    }
    if !sax.is_null() {
        let ref mut fresh529 = (*ctxt).sax;
        *fresh529 = oldsax;
    }
    if !oldctxt.is_null() {
        let ref mut fresh530 = (*ctxt).dict;
        *fresh530 = 0 as xmlDictPtr;
        let ref mut fresh531 = (*ctxt).attsDefault;
        *fresh531 = 0 as xmlHashTablePtr;
        let ref mut fresh532 = (*ctxt).attsSpecial;
        *fresh532 = 0 as xmlHashTablePtr;
        (*oldctxt).validate = (*ctxt).validate;
        (*oldctxt).valid = (*ctxt).valid;
        (*oldctxt).node_seq.maximum = (*ctxt).node_seq.maximum;
        (*oldctxt).node_seq.length = (*ctxt).node_seq.length;
        let ref mut fresh533 = (*oldctxt).node_seq.buffer;
        *fresh533 = (*ctxt).node_seq.buffer;
    }
    (*ctxt).node_seq.maximum = 0 as libc::c_int as libc::c_ulong;
    (*ctxt).node_seq.length = 0 as libc::c_int as libc::c_ulong;
    let ref mut fresh534 = (*ctxt).node_seq.buffer;
    *fresh534 = 0 as *mut xmlParserNodeInfo;
    xmlFreeParserCtxt(ctxt);
    let ref mut fresh535 = (*newDoc).intSubset;
    *fresh535 = 0 as *mut _xmlDtd;
    let ref mut fresh536 = (*newDoc).extSubset;
    *fresh536 = 0 as *mut _xmlDtd;
    xmlFreeDoc(newDoc);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseExternalEntity(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: libc::c_int,
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> libc::c_int {
    return xmlParseExternalEntityPrivate(
        doc,
        0 as xmlParserCtxtPtr,
        sax,
        user_data,
        depth,
        URL,
        ID,
        lst,
    ) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseBalancedChunkMemory(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: libc::c_int,
    mut string: *const xmlChar,
    mut lst: *mut xmlNodePtr,
) -> libc::c_int {
    return xmlParseBalancedChunkMemoryRecover(
        doc,
        sax,
        user_data,
        depth,
        string,
        lst,
        0 as libc::c_int,
    );
}
unsafe extern "C" fn xmlParseBalancedChunkMemoryInternal(
    mut oldctxt: xmlParserCtxtPtr,
    mut string: *const xmlChar,
    mut user_data: *mut libc::c_void,
    mut lst: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as xmlDocPtr;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut content: xmlNodePtr = 0 as xmlNodePtr;
    let mut last: xmlNodePtr = 0 as xmlNodePtr;
    let mut size: libc::c_int = 0;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    let mut i: libc::c_int = 0;
    if (*oldctxt).depth > 40 as libc::c_int
        && (*oldctxt).options & XML_PARSE_HUGE as libc::c_int == 0 as libc::c_int
        || (*oldctxt).depth > 1024 as libc::c_int
    {
        return XML_ERR_ENTITY_LOOP;
    }
    if !lst.is_null() {
        *lst = 0 as xmlNodePtr;
    }
    if string.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    size = xmlStrlen(string);
    ctxt = xmlCreateMemoryParserCtxt(string as *mut libc::c_char, size);
    if ctxt.is_null() {
        return XML_WAR_UNDECLARED_ENTITY;
    }
    if !user_data.is_null() {
        let ref mut fresh537 = (*ctxt).userData;
        *fresh537 = user_data;
    } else {
        let ref mut fresh538 = (*ctxt).userData;
        *fresh538 = ctxt as *mut libc::c_void;
    }
    if !((*ctxt).dict).is_null() {
        xmlDictFree((*ctxt).dict);
    }
    let ref mut fresh539 = (*ctxt).dict;
    *fresh539 = (*oldctxt).dict;
    (*ctxt).input_id = (*oldctxt).input_id + 1 as libc::c_int;
    let ref mut fresh540 = (*ctxt).str_xml;
    *fresh540 = xmlDictLookup(
        (*ctxt).dict,
        b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        3 as libc::c_int,
    );
    let ref mut fresh541 = (*ctxt).str_xmlns;
    *fresh541 = xmlDictLookup(
        (*ctxt).dict,
        b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        5 as libc::c_int,
    );
    let ref mut fresh542 = (*ctxt).str_xml_ns;
    *fresh542 = xmlDictLookup(
        (*ctxt).dict,
        b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
            as *const xmlChar,
        36 as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < (*oldctxt).nsNr {
        nsPush(
            ctxt,
            *((*oldctxt).nsTab).offset(i as isize),
            *((*oldctxt).nsTab).offset((i + 1 as libc::c_int) as isize),
        );
        i += 2 as libc::c_int;
    }
    oldsax = (*ctxt).sax;
    let ref mut fresh543 = (*ctxt).sax;
    *fresh543 = (*oldctxt).sax;
    xmlDetectSAX2(ctxt);
    (*ctxt).replaceEntities = (*oldctxt).replaceEntities;
    (*ctxt).options = (*oldctxt).options;
    let ref mut fresh544 = (*ctxt)._private;
    *fresh544 = (*oldctxt)._private;
    if ((*oldctxt).myDoc).is_null() {
        newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
        if newDoc.is_null() {
            let ref mut fresh545 = (*ctxt).sax;
            *fresh545 = oldsax;
            let ref mut fresh546 = (*ctxt).dict;
            *fresh546 = 0 as xmlDictPtr;
            xmlFreeParserCtxt(ctxt);
            return XML_ERR_INTERNAL_ERROR;
        }
        (*newDoc).properties = XML_DOC_INTERNAL as libc::c_int;
        let ref mut fresh547 = (*newDoc).dict;
        *fresh547 = (*ctxt).dict;
        xmlDictReference((*newDoc).dict);
        let ref mut fresh548 = (*ctxt).myDoc;
        *fresh548 = newDoc;
    } else {
        let ref mut fresh549 = (*ctxt).myDoc;
        *fresh549 = (*oldctxt).myDoc;
        content = (*(*ctxt).myDoc).children;
        last = (*(*ctxt).myDoc).last;
    }
    newRoot = xmlNewDocNode(
        (*ctxt).myDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        let ref mut fresh550 = (*ctxt).sax;
        *fresh550 = oldsax;
        let ref mut fresh551 = (*ctxt).dict;
        *fresh551 = 0 as xmlDictPtr;
        xmlFreeParserCtxt(ctxt);
        if !newDoc.is_null() {
            xmlFreeDoc(newDoc);
        }
        return XML_ERR_INTERNAL_ERROR;
    }
    let ref mut fresh552 = (*(*ctxt).myDoc).children;
    *fresh552 = 0 as *mut _xmlNode;
    let ref mut fresh553 = (*(*ctxt).myDoc).last;
    *fresh553 = 0 as *mut _xmlNode;
    xmlAddChild((*ctxt).myDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, (*(*ctxt).myDoc).children);
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).depth = (*oldctxt).depth + 1 as libc::c_int;
    (*ctxt).validate = 0 as libc::c_int;
    (*ctxt).loadsubset = (*oldctxt).loadsubset;
    if (*oldctxt).validate != 0 || (*oldctxt).replaceEntities != 0 as libc::c_int {
        (*ctxt).loadsubset |= 8 as libc::c_int;
    }
    (*ctxt).dictNames = (*oldctxt).dictNames;
    let ref mut fresh554 = (*ctxt).attsDefault;
    *fresh554 = (*oldctxt).attsDefault;
    let ref mut fresh555 = (*ctxt).attsSpecial;
    *fresh555 = (*oldctxt).attsSpecial;
    xmlParseContent(ctxt);
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    } else if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const libc::c_char);
    }
    if (*ctxt).node != (*(*ctxt).myDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as libc::c_int {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    if !lst.is_null() && ret as libc::c_uint == XML_ERR_OK as libc::c_int as libc::c_uint
    {
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        cur = (*(*(*ctxt).myDoc).children).children;
        *lst = cur;
        while !cur.is_null() {
            if (*oldctxt).validate != 0 && (*oldctxt).wellFormed != 0
                && !((*oldctxt).myDoc).is_null()
                && !((*(*oldctxt).myDoc).intSubset).is_null()
                && (*cur).type_0 as libc::c_uint
                    == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            {
                (*oldctxt).valid
                    &= xmlValidateElement(&mut (*oldctxt).vctxt, (*oldctxt).myDoc, cur);
            }
            let ref mut fresh556 = (*cur).parent;
            *fresh556 = 0 as *mut _xmlNode;
            cur = (*cur).next;
        }
        let ref mut fresh557 = (*(*(*ctxt).myDoc).children).children;
        *fresh557 = 0 as *mut _xmlNode;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeNode((*(*ctxt).myDoc).children);
        let ref mut fresh558 = (*(*ctxt).myDoc).children;
        *fresh558 = content;
        let ref mut fresh559 = (*(*ctxt).myDoc).last;
        *fresh559 = last;
    }
    if !oldctxt.is_null() {
        let ref mut fresh560 = (*oldctxt).nbentities;
        *fresh560 = (*fresh560).wrapping_add((*ctxt).nbentities);
    }
    if (*ctxt).lastError.code != XML_ERR_OK as libc::c_int {
        xmlCopyError(&mut (*ctxt).lastError, &mut (*oldctxt).lastError);
    }
    let ref mut fresh561 = (*ctxt).sax;
    *fresh561 = oldsax;
    let ref mut fresh562 = (*ctxt).dict;
    *fresh562 = 0 as xmlDictPtr;
    let ref mut fresh563 = (*ctxt).attsDefault;
    *fresh563 = 0 as xmlHashTablePtr;
    let ref mut fresh564 = (*ctxt).attsSpecial;
    *fresh564 = 0 as xmlHashTablePtr;
    xmlFreeParserCtxt(ctxt);
    if !newDoc.is_null() {
        xmlFreeDoc(newDoc);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseInNodeContext(
    mut node: xmlNodePtr,
    mut data: *const libc::c_char,
    mut datalen: libc::c_int,
    mut options: libc::c_int,
    mut lst: *mut xmlNodePtr,
) -> xmlParserErrors {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    let mut fake: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut nsnr: libc::c_int = 0 as libc::c_int;
    let mut ret: xmlParserErrors = XML_ERR_OK;
    if lst.is_null() || node.is_null() || data.is_null() || datalen < 0 as libc::c_int {
        return XML_ERR_INTERNAL_ERROR;
    }
    match (*node).type_0 as libc::c_uint {
        1 | 2 | 3 | 4 | 5 | 7 | 8 | 9 | 13 => {}
        _ => return XML_ERR_INTERNAL_ERROR,
    }
    while !node.is_null()
        && (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        && (*node).type_0 as libc::c_uint
            != XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        node = (*node).parent;
    }
    if node.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (*node).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        doc = (*node).doc;
    } else {
        doc = node as xmlDocPtr;
    }
    if doc.is_null() {
        return XML_ERR_INTERNAL_ERROR;
    }
    if (*doc).type_0 as libc::c_uint == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        ctxt = xmlCreateMemoryParserCtxt(data as *mut libc::c_char, datalen);
    } else if (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        ctxt = htmlCreateMemoryParserCtxt(data as *mut libc::c_char, datalen);
        options |= HTML_PARSE_NOIMPLIED as libc::c_int;
    } else {
        return XML_ERR_INTERNAL_ERROR
    }
    if ctxt.is_null() {
        return XML_ERR_NO_MEMORY;
    }
    if !((*doc).dict).is_null() {
        if !((*ctxt).dict).is_null() {
            xmlDictFree((*ctxt).dict);
        }
        let ref mut fresh565 = (*ctxt).dict;
        *fresh565 = (*doc).dict;
    } else {
        options |= XML_PARSE_NODICT as libc::c_int;
    }
    if !((*doc).encoding).is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let ref mut fresh566 = (*ctxt).encoding;
        *fresh566 = xmlStrdup((*doc).encoding);
        hdlr = xmlFindCharEncodingHandler((*doc).encoding as *const libc::c_char);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        } else {
            return XML_ERR_UNSUPPORTED_ENCODING
        }
    }
    xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const libc::c_char);
    xmlDetectSAX2(ctxt);
    let ref mut fresh567 = (*ctxt).myDoc;
    *fresh567 = doc;
    (*ctxt).input_id = 2 as libc::c_int;
    (*ctxt).instate = XML_PARSER_CONTENT;
    fake = xmlNewDocComment((*node).doc, 0 as *const xmlChar);
    if fake.is_null() {
        xmlFreeParserCtxt(ctxt);
        return XML_ERR_NO_MEMORY;
    }
    xmlAddChild(node, fake);
    if (*node).type_0 as libc::c_uint == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        nodePush(ctxt, node);
        cur = node;
        while !cur.is_null()
            && (*cur).type_0 as libc::c_uint
                == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
        {
            let mut ns: xmlNsPtr = (*cur).nsDef;
            let mut iprefix: *const xmlChar = 0 as *const xmlChar;
            let mut ihref: *const xmlChar = 0 as *const xmlChar;
            while !ns.is_null() {
                if !((*ctxt).dict).is_null() {
                    iprefix = xmlDictLookup(
                        (*ctxt).dict,
                        (*ns).prefix,
                        -(1 as libc::c_int),
                    );
                    ihref = xmlDictLookup((*ctxt).dict, (*ns).href, -(1 as libc::c_int));
                } else {
                    iprefix = (*ns).prefix;
                    ihref = (*ns).href;
                }
                if (xmlGetNamespace(ctxt, iprefix)).is_null() {
                    nsPush(ctxt, iprefix, ihref);
                    nsnr += 1;
                }
                ns = (*ns).next;
            }
            cur = (*cur).parent;
        }
    }
    if (*ctxt).validate != 0 || (*ctxt).replaceEntities != 0 as libc::c_int {
        (*ctxt).loadsubset |= 8 as libc::c_int;
    }
    if (*doc).type_0 as libc::c_uint
        == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        __htmlParseContent(ctxt as *mut libc::c_void);
    } else {
        xmlParseContent(ctxt);
    }
    nsPop(ctxt, nsnr);
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    } else if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const libc::c_char);
    }
    if !((*ctxt).node).is_null() && (*ctxt).node != node {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
        (*ctxt).wellFormed = 0 as libc::c_int;
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as libc::c_int {
            ret = XML_ERR_INTERNAL_ERROR;
        } else {
            ret = (*ctxt).errNo as xmlParserErrors;
        }
    } else {
        ret = XML_ERR_OK;
    }
    cur = (*fake).next;
    let ref mut fresh568 = (*fake).next;
    *fresh568 = 0 as *mut _xmlNode;
    let ref mut fresh569 = (*node).last;
    *fresh569 = fake;
    if !cur.is_null() {
        let ref mut fresh570 = (*cur).prev;
        *fresh570 = 0 as *mut _xmlNode;
    }
    *lst = cur;
    while !cur.is_null() {
        let ref mut fresh571 = (*cur).parent;
        *fresh571 = 0 as *mut _xmlNode;
        cur = (*cur).next;
    }
    xmlUnlinkNode(fake);
    xmlFreeNode(fake);
    if ret as libc::c_uint != XML_ERR_OK as libc::c_int as libc::c_uint {
        xmlFreeNodeList(*lst);
        *lst = 0 as xmlNodePtr;
    }
    if !((*doc).dict).is_null() {
        let ref mut fresh572 = (*ctxt).dict;
        *fresh572 = 0 as xmlDictPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseBalancedChunkMemoryRecover(
    mut doc: xmlDocPtr,
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut depth: libc::c_int,
    mut string: *const xmlChar,
    mut lst: *mut xmlNodePtr,
    mut recover: libc::c_int,
) -> libc::c_int {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut newDoc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut content: xmlNodePtr = 0 as *mut xmlNode;
    let mut newRoot: xmlNodePtr = 0 as *mut xmlNode;
    let mut size: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    if depth > 40 as libc::c_int {
        return XML_ERR_ENTITY_LOOP as libc::c_int;
    }
    if !lst.is_null() {
        *lst = 0 as xmlNodePtr;
    }
    if string.is_null() {
        return -(1 as libc::c_int);
    }
    size = xmlStrlen(string);
    ctxt = xmlCreateMemoryParserCtxt(string as *mut libc::c_char, size);
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh573 = (*ctxt).userData;
    *fresh573 = ctxt as *mut libc::c_void;
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let ref mut fresh574 = (*ctxt).sax;
        *fresh574 = sax;
        if !user_data.is_null() {
            let ref mut fresh575 = (*ctxt).userData;
            *fresh575 = user_data;
        }
    }
    newDoc = xmlNewDoc(b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar);
    if newDoc.is_null() {
        xmlFreeParserCtxt(ctxt);
        return -(1 as libc::c_int);
    }
    (*newDoc).properties = XML_DOC_INTERNAL as libc::c_int;
    if !doc.is_null() && !((*doc).dict).is_null() {
        xmlDictFree((*ctxt).dict);
        let ref mut fresh576 = (*ctxt).dict;
        *fresh576 = (*doc).dict;
        xmlDictReference((*ctxt).dict);
        let ref mut fresh577 = (*ctxt).str_xml;
        *fresh577 = xmlDictLookup(
            (*ctxt).dict,
            b"xml\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            3 as libc::c_int,
        );
        let ref mut fresh578 = (*ctxt).str_xmlns;
        *fresh578 = xmlDictLookup(
            (*ctxt).dict,
            b"xmlns\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            5 as libc::c_int,
        );
        let ref mut fresh579 = (*ctxt).str_xml_ns;
        *fresh579 = xmlDictLookup(
            (*ctxt).dict,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
            36 as libc::c_int,
        );
        (*ctxt).dictNames = 1 as libc::c_int;
    } else {
        xmlCtxtUseOptionsInternal(
            ctxt,
            XML_PARSE_NODICT as libc::c_int,
            0 as *const libc::c_char,
        );
    }
    if !doc.is_null() {
        let ref mut fresh580 = (*newDoc).intSubset;
        *fresh580 = (*doc).intSubset;
        let ref mut fresh581 = (*newDoc).extSubset;
        *fresh581 = (*doc).extSubset;
    }
    newRoot = xmlNewDocNode(
        newDoc,
        0 as xmlNsPtr,
        b"pseudoroot\0" as *const u8 as *const libc::c_char as *mut xmlChar,
        0 as *const xmlChar,
    );
    if newRoot.is_null() {
        if !sax.is_null() {
            let ref mut fresh582 = (*ctxt).sax;
            *fresh582 = oldsax;
        }
        xmlFreeParserCtxt(ctxt);
        let ref mut fresh583 = (*newDoc).intSubset;
        *fresh583 = 0 as *mut _xmlDtd;
        let ref mut fresh584 = (*newDoc).extSubset;
        *fresh584 = 0 as *mut _xmlDtd;
        xmlFreeDoc(newDoc);
        return -(1 as libc::c_int);
    }
    xmlAddChild(newDoc as xmlNodePtr, newRoot);
    nodePush(ctxt, newRoot);
    if doc.is_null() {
        let ref mut fresh585 = (*ctxt).myDoc;
        *fresh585 = newDoc;
    } else {
        let ref mut fresh586 = (*ctxt).myDoc;
        *fresh586 = newDoc;
        let ref mut fresh587 = (*(*newDoc).children).doc;
        *fresh587 = doc;
        xmlSearchNsByHref(
            doc,
            doc as xmlNodePtr,
            b"http://www.w3.org/XML/1998/namespace\0" as *const u8 as *const libc::c_char
                as *const xmlChar,
        );
        let ref mut fresh588 = (*newDoc).oldNs;
        *fresh588 = (*doc).oldNs;
    }
    (*ctxt).instate = XML_PARSER_CONTENT;
    (*ctxt).input_id = 2 as libc::c_int;
    (*ctxt).depth = depth;
    (*ctxt).validate = 0 as libc::c_int;
    (*ctxt).loadsubset = 0 as libc::c_int;
    xmlDetectSAX2(ctxt);
    if !doc.is_null() {
        content = (*doc).children;
        let ref mut fresh589 = (*doc).children;
        *fresh589 = 0 as *mut _xmlNode;
        xmlParseContent(ctxt);
        let ref mut fresh590 = (*doc).children;
        *fresh590 = content;
    } else {
        xmlParseContent(ctxt);
    }
    if *(*(*ctxt).input).cur as libc::c_int == '<' as i32
        && *((*(*ctxt).input).cur).offset(1 as libc::c_int as isize) as libc::c_int
            == '/' as i32
    {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    } else if *(*(*ctxt).input).cur as libc::c_int != 0 as libc::c_int {
        xmlFatalErr(ctxt, XML_ERR_EXTRA_CONTENT, 0 as *const libc::c_char);
    }
    if (*ctxt).node != (*newDoc).children {
        xmlFatalErr(ctxt, XML_ERR_NOT_WELL_BALANCED, 0 as *const libc::c_char);
    }
    if (*ctxt).wellFormed == 0 {
        if (*ctxt).errNo == 0 as libc::c_int {
            ret = 1 as libc::c_int;
        } else {
            ret = (*ctxt).errNo;
        }
    } else {
        ret = 0 as libc::c_int;
    }
    if !lst.is_null() && (ret == 0 as libc::c_int || recover == 1 as libc::c_int) {
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        cur = (*(*newDoc).children).children;
        *lst = cur;
        while !cur.is_null() {
            xmlSetTreeDoc(cur, doc);
            let ref mut fresh591 = (*cur).parent;
            *fresh591 = 0 as *mut _xmlNode;
            cur = (*cur).next;
        }
        let ref mut fresh592 = (*(*newDoc).children).children;
        *fresh592 = 0 as *mut _xmlNode;
    }
    if !sax.is_null() {
        let ref mut fresh593 = (*ctxt).sax;
        *fresh593 = oldsax;
    }
    xmlFreeParserCtxt(ctxt);
    let ref mut fresh594 = (*newDoc).intSubset;
    *fresh594 = 0 as *mut _xmlDtd;
    let ref mut fresh595 = (*newDoc).extSubset;
    *fresh595 = 0 as *mut _xmlDtd;
    let ref mut fresh596 = (*newDoc).oldNs;
    *fresh596 = 0 as *mut _xmlNs;
    xmlFreeDoc(newDoc);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseEntity(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const libc::c_char,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh597 = (*ctxt).sax;
        *fresh597 = sax;
        let ref mut fresh598 = (*ctxt).userData;
        *fresh598 = 0 as *mut libc::c_void;
    }
    xmlParseExtParsedEnt(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh599 = (*ctxt).myDoc;
        *fresh599 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh600 = (*ctxt).sax;
        *fresh600 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseEntity(mut filename: *const libc::c_char) -> xmlDocPtr {
    return xmlSAXParseEntity(0 as xmlSAXHandlerPtr, filename);
}
unsafe extern "C" fn xmlCreateEntityParserCtxtInternal(
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut base: *const xmlChar,
    mut pctx: xmlParserCtxtPtr,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut directory: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut uri: *mut xmlChar = 0 as *mut xmlChar;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if !pctx.is_null() {
        (*ctxt).options = (*pctx).options;
        let ref mut fresh601 = (*ctxt)._private;
        *fresh601 = (*pctx)._private;
        (*ctxt).input_id = (*pctx).input_id + 1 as libc::c_int;
    }
    if xmlStrcmp(URL, b"-\0" as *const u8 as *const libc::c_char as *mut xmlChar)
        == 0 as libc::c_int
    {
        URL = b"./-\0" as *const u8 as *const libc::c_char as *mut xmlChar;
    }
    uri = xmlBuildURI(URL, base);
    if uri.is_null() {
        inputStream = xmlLoadExternalEntity(
            URL as *mut libc::c_char,
            ID as *mut libc::c_char,
            ctxt,
        );
        if inputStream.is_null() {
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if ((*ctxt).directory).is_null() && directory.is_null() {
            directory = xmlParserGetDirectory(URL as *mut libc::c_char);
        }
        if ((*ctxt).directory).is_null() && !directory.is_null() {
            let ref mut fresh602 = (*ctxt).directory;
            *fresh602 = directory;
        }
    } else {
        inputStream = xmlLoadExternalEntity(
            uri as *mut libc::c_char,
            ID as *mut libc::c_char,
            ctxt,
        );
        if inputStream.is_null() {
            xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void);
            xmlFreeParserCtxt(ctxt);
            return 0 as xmlParserCtxtPtr;
        }
        inputPush(ctxt, inputStream);
        if ((*ctxt).directory).is_null() && directory.is_null() {
            directory = xmlParserGetDirectory(uri as *mut libc::c_char);
        }
        if ((*ctxt).directory).is_null() && !directory.is_null() {
            let ref mut fresh603 = (*ctxt).directory;
            *fresh603 = directory;
        }
        xmlFree.expect("non-null function pointer")(uri as *mut libc::c_void);
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateEntityParserCtxt(
    mut URL: *const xmlChar,
    mut ID: *const xmlChar,
    mut base: *const xmlChar,
) -> xmlParserCtxtPtr {
    return xmlCreateEntityParserCtxtInternal(URL, ID, base, 0 as xmlParserCtxtPtr);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateURLParserCtxt(
    mut filename: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut directory: *mut libc::c_char = 0 as *mut libc::c_char;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"cannot allocate parser context\0" as *const u8 as *const libc::c_char,
        );
        return 0 as xmlParserCtxtPtr;
    }
    if options != 0 {
        xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const libc::c_char);
    }
    (*ctxt).linenumbers = 1 as libc::c_int;
    inputStream = xmlLoadExternalEntity(filename, 0 as *const libc::c_char, ctxt);
    if inputStream.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    inputPush(ctxt, inputStream);
    if ((*ctxt).directory).is_null() && directory.is_null() {
        directory = xmlParserGetDirectory(filename);
    }
    if ((*ctxt).directory).is_null() && !directory.is_null() {
        let ref mut fresh604 = (*ctxt).directory;
        *fresh604 = directory;
    }
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateFileParserCtxt(
    mut filename: *const libc::c_char,
) -> xmlParserCtxtPtr {
    return xmlCreateURLParserCtxt(filename, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseFileWithData(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const libc::c_char,
    mut recovery: libc::c_int,
    mut data: *mut libc::c_void,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh605 = (*ctxt).sax;
        *fresh605 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let ref mut fresh606 = (*ctxt)._private;
        *fresh606 = data;
    }
    if ((*ctxt).directory).is_null() {
        let ref mut fresh607 = (*ctxt).directory;
        *fresh607 = xmlParserGetDirectory(filename);
    }
    (*ctxt).recovery = recovery;
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
        if !ret.is_null() && !((*(*ctxt).input).buf).is_null() {
            if (*(*(*ctxt).input).buf).compressed > 0 as libc::c_int {
                (*ret).compression = 9 as libc::c_int;
            } else {
                (*ret).compression = (*(*(*ctxt).input).buf).compressed;
            }
        }
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh608 = (*ctxt).myDoc;
        *fresh608 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh609 = (*ctxt).sax;
        *fresh609 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseFile(
    mut sax: xmlSAXHandlerPtr,
    mut filename: *const libc::c_char,
    mut recovery: libc::c_int,
) -> xmlDocPtr {
    return xmlSAXParseFileWithData(sax, filename, recovery, 0 as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverDoc(mut cur: *const xmlChar) -> xmlDocPtr {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseFile(mut filename: *const libc::c_char) -> xmlDocPtr {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverFile(mut filename: *const libc::c_char) -> xmlDocPtr {
    return xmlSAXParseFile(0 as xmlSAXHandlerPtr, filename, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetupParserForBuffer(
    mut ctxt: xmlParserCtxtPtr,
    mut buffer: *const xmlChar,
    mut filename: *const libc::c_char,
) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() || buffer.is_null() {
        return;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlErrMemory(
            0 as xmlParserCtxtPtr,
            b"parsing new buffer: out of memory\n\0" as *const u8 as *const libc::c_char,
        );
        xmlClearParserCtxt(ctxt);
        return;
    }
    xmlClearParserCtxt(ctxt);
    if !filename.is_null() {
        let ref mut fresh610 = (*input).filename;
        *fresh610 = xmlCanonicPath(filename as *const xmlChar) as *mut libc::c_char;
    }
    let ref mut fresh611 = (*input).base;
    *fresh611 = buffer;
    let ref mut fresh612 = (*input).cur;
    *fresh612 = buffer;
    let ref mut fresh613 = (*input).end;
    *fresh613 = &*buffer
        .offset(
            (xmlStrlen as unsafe extern "C" fn(*const xmlChar) -> libc::c_int)(buffer)
                as isize,
        ) as *const xmlChar;
    inputPush(ctxt, input);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXUserParseFile(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    ctxt = xmlCreateFileParserCtxt(filename);
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
        xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
    }
    let ref mut fresh614 = (*ctxt).sax;
    *fresh614 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let ref mut fresh615 = (*ctxt).userData;
        *fresh615 = user_data;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = 0 as libc::c_int;
    } else if (*ctxt).errNo != 0 as libc::c_int {
        ret = (*ctxt).errNo;
    } else {
        ret = -(1 as libc::c_int);
    }
    if !sax.is_null() {
        let ref mut fresh616 = (*ctxt).sax;
        *fresh616 = 0 as *mut _xmlSAXHandler;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh617 = (*ctxt).myDoc;
        *fresh617 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateMemoryParserCtxt(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
) -> xmlParserCtxtPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if buffer.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    if size <= 0 as libc::c_int {
        return 0 as xmlParserCtxtPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    buf = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if buf.is_null() {
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    input = xmlNewInputStream(ctxt);
    if input.is_null() {
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlParserCtxtPtr;
    }
    let ref mut fresh618 = (*input).filename;
    *fresh618 = 0 as *const libc::c_char;
    let ref mut fresh619 = (*input).buf;
    *fresh619 = buf;
    xmlBufResetInput((*(*input).buf).buffer, input);
    inputPush(ctxt, input);
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseMemoryWithData(
    mut sax: xmlSAXHandlerPtr,
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut recovery: libc::c_int,
    mut data: *mut libc::c_void,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        if !((*ctxt).sax).is_null() {
            xmlFree
                .expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
        }
        let ref mut fresh620 = (*ctxt).sax;
        *fresh620 = sax;
    }
    xmlDetectSAX2(ctxt);
    if !data.is_null() {
        let ref mut fresh621 = (*ctxt)._private;
        *fresh621 = data;
    }
    (*ctxt).recovery = recovery;
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh622 = (*ctxt).myDoc;
        *fresh622 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh623 = (*ctxt).sax;
        *fresh623 = 0 as *mut _xmlSAXHandler;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseMemory(
    mut sax: xmlSAXHandlerPtr,
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut recovery: libc::c_int,
) -> xmlDocPtr {
    return xmlSAXParseMemoryWithData(
        sax,
        buffer,
        size,
        recovery,
        0 as *mut libc::c_void,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseMemory(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
) -> xmlDocPtr {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRecoverMemory(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
) -> xmlDocPtr {
    return xmlSAXParseMemory(0 as xmlSAXHandlerPtr, buffer, size, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXUserParseMemory(
    mut sax: xmlSAXHandlerPtr,
    mut user_data: *mut libc::c_void,
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    if (*ctxt).sax != __xmlDefaultSAXHandler() as xmlSAXHandlerPtr {
        xmlFree.expect("non-null function pointer")((*ctxt).sax as *mut libc::c_void);
    }
    let ref mut fresh624 = (*ctxt).sax;
    *fresh624 = sax;
    xmlDetectSAX2(ctxt);
    if !user_data.is_null() {
        let ref mut fresh625 = (*ctxt).userData;
        *fresh625 = user_data;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 {
        ret = 0 as libc::c_int;
    } else if (*ctxt).errNo != 0 as libc::c_int {
        ret = (*ctxt).errNo;
    } else {
        ret = -(1 as libc::c_int);
    }
    if !sax.is_null() {
        let ref mut fresh626 = (*ctxt).sax;
        *fresh626 = 0 as *mut _xmlSAXHandler;
    }
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh627 = (*ctxt).myDoc;
        *fresh627 = 0 as xmlDocPtr;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCreateDocParserCtxt(
    mut cur: *const xmlChar,
) -> xmlParserCtxtPtr {
    let mut len: libc::c_int = 0;
    if cur.is_null() {
        return 0 as xmlParserCtxtPtr;
    }
    len = xmlStrlen(cur);
    return xmlCreateMemoryParserCtxt(cur as *const libc::c_char, len);
}
#[no_mangle]
pub unsafe extern "C" fn xmlSAXParseDoc(
    mut sax: xmlSAXHandlerPtr,
    mut cur: *const xmlChar,
    mut recovery: libc::c_int,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut oldsax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    ctxt = xmlCreateDocParserCtxt(cur);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        oldsax = (*ctxt).sax;
        let ref mut fresh628 = (*ctxt).sax;
        *fresh628 = sax;
        let ref mut fresh629 = (*ctxt).userData;
        *fresh629 = 0 as *mut libc::c_void;
    }
    xmlDetectSAX2(ctxt);
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        xmlFreeDoc((*ctxt).myDoc);
        let ref mut fresh630 = (*ctxt).myDoc;
        *fresh630 = 0 as xmlDocPtr;
    }
    if !sax.is_null() {
        let ref mut fresh631 = (*ctxt).sax;
        *fresh631 = oldsax;
    }
    xmlFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlParseDoc(mut cur: *const xmlChar) -> xmlDocPtr {
    return xmlSAXParseDoc(0 as xmlSAXHandlerPtr, cur, 0 as libc::c_int);
}
static mut xmlEntityRefFunc: xmlEntityReferenceFunc = None;
unsafe extern "C" fn xmlAddEntityReference(
    mut ent: xmlEntityPtr,
    mut firstNode: xmlNodePtr,
    mut lastNode: xmlNodePtr,
) {
    if xmlEntityRefFunc.is_some() {
        (Some(xmlEntityRefFunc.expect("non-null function pointer")))
            .expect("non-null function pointer")(ent, firstNode, lastNode);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlSetEntityReferenceFunc(mut func: xmlEntityReferenceFunc) {
    xmlEntityRefFunc = func;
}
static mut xmlParserInitialized: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub unsafe extern "C" fn xmlInitParser() {
    if xmlParserInitialized != 0 as libc::c_int {
        return;
    }
    __xmlGlobalInitMutexLock();
    if xmlParserInitialized == 0 as libc::c_int {
        xmlInitThreads();
        xmlInitGlobals();
        if *__xmlGenericError()
            == Some(
                xmlGenericErrorDefaultFunc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ) || (*__xmlGenericError()).is_none()
        {
            initGenericErrorDefaultFunc(0 as *mut xmlGenericErrorFunc);
        }
        xmlInitMemory();
        xmlInitializeDict();
        xmlInitCharEncodingHandlers();
        xmlDefaultSAXHandlerInit();
        xmlRegisterDefaultInputCallbacks();
        xmlRegisterDefaultOutputCallbacks();
        htmlInitAutoClose();
        htmlDefaultSAXHandlerInit();
        xmlXPathInit();
        xmlParserInitialized = 1 as libc::c_int;
    }
    __xmlGlobalInitMutexUnlock();
}
#[no_mangle]
pub unsafe extern "C" fn xmlCleanupParser() {
    if xmlParserInitialized == 0 {
        return;
    }
    xmlCleanupCharEncodingHandlers();
    xmlCatalogCleanup();
    xmlDictCleanup();
    xmlCleanupInputCallbacks();
    xmlCleanupOutputCallbacks();
    xmlSchemaCleanupTypes();
    xmlRelaxNGCleanupTypes();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    xmlCleanupMemory();
    xmlParserInitialized = 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReset(mut ctxt: xmlParserCtxtPtr) {
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut dict: xmlDictPtr = 0 as *mut xmlDict;
    if ctxt.is_null() {
        return;
    }
    dict = (*ctxt).dict;
    loop {
        input = inputPop(ctxt);
        if input.is_null() {
            break;
        }
        xmlFreeInputStream(input);
    }
    (*ctxt).inputNr = 0 as libc::c_int;
    let ref mut fresh632 = (*ctxt).input;
    *fresh632 = 0 as xmlParserInputPtr;
    (*ctxt).spaceNr = 0 as libc::c_int;
    if !((*ctxt).spaceTab).is_null() {
        *((*ctxt).spaceTab).offset(0 as libc::c_int as isize) = -(1 as libc::c_int);
        let ref mut fresh633 = (*ctxt).space;
        *fresh633 = &mut *((*ctxt).spaceTab).offset(0 as libc::c_int as isize)
            as *mut libc::c_int;
    } else {
        let ref mut fresh634 = (*ctxt).space;
        *fresh634 = 0 as *mut libc::c_int;
    }
    (*ctxt).nodeNr = 0 as libc::c_int;
    let ref mut fresh635 = (*ctxt).node;
    *fresh635 = 0 as xmlNodePtr;
    (*ctxt).nameNr = 0 as libc::c_int;
    let ref mut fresh636 = (*ctxt).name;
    *fresh636 = 0 as *const xmlChar;
    (*ctxt).nsNr = 0 as libc::c_int;
    if !((*ctxt).version).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).version) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).version as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh637 = (*ctxt).version;
    *fresh637 = 0 as *const xmlChar;
    if !((*ctxt).encoding).is_null()
        && (dict.is_null() || xmlDictOwns(dict, (*ctxt).encoding) == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).encoding as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh638 = (*ctxt).encoding;
    *fresh638 = 0 as *const xmlChar;
    if !((*ctxt).directory).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).directory as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect("non-null function pointer")((*ctxt).directory as *mut libc::c_void);
    }
    let ref mut fresh639 = (*ctxt).directory;
    *fresh639 = 0 as *mut libc::c_char;
    if !((*ctxt).extSubURI).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubURI as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubURI as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh640 = (*ctxt).extSubURI;
    *fresh640 = 0 as *mut xmlChar;
    if !((*ctxt).extSubSystem).is_null()
        && (dict.is_null()
            || xmlDictOwns(dict, (*ctxt).extSubSystem as *const xmlChar)
                == 0 as libc::c_int)
    {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*ctxt).extSubSystem as *mut libc::c_char as *mut libc::c_void);
    }
    let ref mut fresh641 = (*ctxt).extSubSystem;
    *fresh641 = 0 as *mut xmlChar;
    if !((*ctxt).myDoc).is_null() {
        xmlFreeDoc((*ctxt).myDoc);
    }
    let ref mut fresh642 = (*ctxt).myDoc;
    *fresh642 = 0 as xmlDocPtr;
    (*ctxt).standalone = -(1 as libc::c_int);
    (*ctxt).hasExternalSubset = 0 as libc::c_int;
    (*ctxt).hasPErefs = 0 as libc::c_int;
    (*ctxt).html = 0 as libc::c_int;
    (*ctxt).external = 0 as libc::c_int;
    (*ctxt).instate = XML_PARSER_START;
    (*ctxt).token = 0 as libc::c_int;
    (*ctxt).wellFormed = 1 as libc::c_int;
    (*ctxt).nsWellFormed = 1 as libc::c_int;
    (*ctxt).disableSAX = 0 as libc::c_int;
    (*ctxt).valid = 1 as libc::c_int;
    (*ctxt).record_info = 0 as libc::c_int;
    (*ctxt).checkIndex = 0 as libc::c_int as libc::c_long;
    (*ctxt).inSubset = 0 as libc::c_int;
    (*ctxt).errNo = XML_ERR_OK as libc::c_int;
    (*ctxt).depth = 0 as libc::c_int;
    (*ctxt).charset = XML_CHAR_ENCODING_UTF8 as libc::c_int;
    let ref mut fresh643 = (*ctxt).catalogs;
    *fresh643 = 0 as *mut libc::c_void;
    (*ctxt).nbentities = 0 as libc::c_int as libc::c_ulong;
    (*ctxt).sizeentities = 0 as libc::c_int as libc::c_ulong;
    (*ctxt).sizeentcopy = 0 as libc::c_int as libc::c_ulong;
    xmlInitNodeInfoSeq(&mut (*ctxt).node_seq);
    if !((*ctxt).attsDefault).is_null() {
        xmlHashFree(
            (*ctxt).attsDefault,
            Some(
                xmlHashDefaultDeallocator
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
        );
        let ref mut fresh644 = (*ctxt).attsDefault;
        *fresh644 = 0 as xmlHashTablePtr;
    }
    if !((*ctxt).attsSpecial).is_null() {
        xmlHashFree((*ctxt).attsSpecial, None);
        let ref mut fresh645 = (*ctxt).attsSpecial;
        *fresh645 = 0 as xmlHashTablePtr;
    }
    if !((*ctxt).catalogs).is_null() {
        xmlCatalogFreeLocal((*ctxt).catalogs);
    }
    if (*ctxt).lastError.code != XML_ERR_OK as libc::c_int {
        xmlResetError(&mut (*ctxt).lastError);
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtResetPush(
    mut ctxt: xmlParserCtxtPtr,
    mut chunk: *const libc::c_char,
    mut size: libc::c_int,
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
) -> libc::c_int {
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    if ctxt.is_null() {
        return 1 as libc::c_int;
    }
    if encoding.is_null() && !chunk.is_null() && size >= 4 as libc::c_int {
        enc = xmlDetectCharEncoding(chunk as *const xmlChar, size);
    }
    buf = xmlAllocParserInputBuffer(enc);
    if buf.is_null() {
        return 1 as libc::c_int;
    }
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 1 as libc::c_int;
    }
    xmlCtxtReset(ctxt);
    if filename.is_null() {
        let ref mut fresh646 = (*ctxt).directory;
        *fresh646 = 0 as *mut libc::c_char;
    } else {
        let ref mut fresh647 = (*ctxt).directory;
        *fresh647 = xmlParserGetDirectory(filename);
    }
    inputStream = xmlNewInputStream(ctxt);
    if inputStream.is_null() {
        xmlFreeParserInputBuffer(buf);
        return 1 as libc::c_int;
    }
    if filename.is_null() {
        let ref mut fresh648 = (*inputStream).filename;
        *fresh648 = 0 as *const libc::c_char;
    } else {
        let ref mut fresh649 = (*inputStream).filename;
        *fresh649 = xmlCanonicPath(filename as *const xmlChar) as *mut libc::c_char;
    }
    let ref mut fresh650 = (*inputStream).buf;
    *fresh650 = buf;
    xmlBufResetInput((*buf).buffer, inputStream);
    inputPush(ctxt, inputStream);
    if size > 0 as libc::c_int && !chunk.is_null() && !((*ctxt).input).is_null()
        && !((*(*ctxt).input).buf).is_null()
    {
        let mut base: size_t = xmlBufGetInputBase(
            (*(*(*ctxt).input).buf).buffer,
            (*ctxt).input,
        );
        let mut cur: size_t = ((*(*ctxt).input).cur).offset_from((*(*ctxt).input).base)
            as libc::c_long as size_t;
        xmlParserInputBufferPush((*(*ctxt).input).buf, size, chunk);
        xmlBufSetInputBaseCur((*(*(*ctxt).input).buf).buffer, (*ctxt).input, base, cur);
    }
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let ref mut fresh651 = (*ctxt).encoding;
        *fresh651 = xmlStrdup(encoding as *const xmlChar);
        hdlr = xmlFindCharEncodingHandler(encoding);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        } else {
            xmlFatalErrMsgStr(
                ctxt,
                XML_ERR_UNSUPPORTED_ENCODING,
                b"Unsupported encoding %s\n\0" as *const u8 as *const libc::c_char,
                encoding as *mut xmlChar,
            );
        }
    } else if enc as libc::c_int != XML_CHAR_ENCODING_NONE as libc::c_int {
        xmlSwitchEncoding(ctxt, enc);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlCtxtUseOptionsInternal(
    mut ctxt: xmlParserCtxtPtr,
    mut options: libc::c_int,
    mut encoding: *const libc::c_char,
) -> libc::c_int {
    if ctxt.is_null() {
        return -(1 as libc::c_int);
    }
    if !encoding.is_null() {
        if !((*ctxt).encoding).is_null() {
            xmlFree
                .expect(
                    "non-null function pointer",
                )((*ctxt).encoding as *mut xmlChar as *mut libc::c_void);
        }
        let ref mut fresh652 = (*ctxt).encoding;
        *fresh652 = xmlStrdup(encoding as *const xmlChar);
    }
    if options & XML_PARSE_RECOVER as libc::c_int != 0 {
        (*ctxt).recovery = 1 as libc::c_int;
        options -= XML_PARSE_RECOVER as libc::c_int;
        (*ctxt).options |= XML_PARSE_RECOVER as libc::c_int;
    } else {
        (*ctxt).recovery = 0 as libc::c_int;
    }
    if options & XML_PARSE_DTDLOAD as libc::c_int != 0 {
        (*ctxt).loadsubset = 2 as libc::c_int;
        options -= XML_PARSE_DTDLOAD as libc::c_int;
        (*ctxt).options |= XML_PARSE_DTDLOAD as libc::c_int;
    } else {
        (*ctxt).loadsubset = 0 as libc::c_int;
    }
    if options & XML_PARSE_DTDATTR as libc::c_int != 0 {
        (*ctxt).loadsubset |= 4 as libc::c_int;
        options -= XML_PARSE_DTDATTR as libc::c_int;
        (*ctxt).options |= XML_PARSE_DTDATTR as libc::c_int;
    }
    if options & XML_PARSE_NOENT as libc::c_int != 0 {
        (*ctxt).replaceEntities = 1 as libc::c_int;
        options -= XML_PARSE_NOENT as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOENT as libc::c_int;
    } else {
        (*ctxt).replaceEntities = 0 as libc::c_int;
    }
    if options & XML_PARSE_PEDANTIC as libc::c_int != 0 {
        (*ctxt).pedantic = 1 as libc::c_int;
        options -= XML_PARSE_PEDANTIC as libc::c_int;
        (*ctxt).options |= XML_PARSE_PEDANTIC as libc::c_int;
    } else {
        (*ctxt).pedantic = 0 as libc::c_int;
    }
    if options & XML_PARSE_NOBLANKS as libc::c_int != 0 {
        (*ctxt).keepBlanks = 0 as libc::c_int;
        let ref mut fresh653 = (*(*ctxt).sax).ignorableWhitespace;
        *fresh653 = Some(
            xmlSAX2IgnorableWhitespace
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    libc::c_int,
                ) -> (),
        );
        options -= XML_PARSE_NOBLANKS as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOBLANKS as libc::c_int;
    } else {
        (*ctxt).keepBlanks = 1 as libc::c_int;
    }
    if options & XML_PARSE_DTDVALID as libc::c_int != 0 {
        (*ctxt).validate = 1 as libc::c_int;
        if options & XML_PARSE_NOWARNING as libc::c_int != 0 {
            let ref mut fresh654 = (*ctxt).vctxt.warning;
            *fresh654 = None;
        }
        if options & XML_PARSE_NOERROR as libc::c_int != 0 {
            let ref mut fresh655 = (*ctxt).vctxt.error;
            *fresh655 = None;
        }
        options -= XML_PARSE_DTDVALID as libc::c_int;
        (*ctxt).options |= XML_PARSE_DTDVALID as libc::c_int;
    } else {
        (*ctxt).validate = 0 as libc::c_int;
    }
    if options & XML_PARSE_NOWARNING as libc::c_int != 0 {
        let ref mut fresh656 = (*(*ctxt).sax).warning;
        *fresh656 = None;
        options -= XML_PARSE_NOWARNING as libc::c_int;
    }
    if options & XML_PARSE_NOERROR as libc::c_int != 0 {
        let ref mut fresh657 = (*(*ctxt).sax).error;
        *fresh657 = None;
        let ref mut fresh658 = (*(*ctxt).sax).fatalError;
        *fresh658 = None;
        options -= XML_PARSE_NOERROR as libc::c_int;
    }
    if options & XML_PARSE_SAX1 as libc::c_int != 0 {
        let ref mut fresh659 = (*(*ctxt).sax).startElement;
        *fresh659 = Some(
            xmlSAX2StartElement
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *mut *const xmlChar,
                ) -> (),
        );
        let ref mut fresh660 = (*(*ctxt).sax).endElement;
        *fresh660 = Some(
            xmlSAX2EndElement
                as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
        );
        let ref mut fresh661 = (*(*ctxt).sax).startElementNs;
        *fresh661 = None;
        let ref mut fresh662 = (*(*ctxt).sax).endElementNs;
        *fresh662 = None;
        (*(*ctxt).sax).initialized = 1 as libc::c_int as libc::c_uint;
        options -= XML_PARSE_SAX1 as libc::c_int;
        (*ctxt).options |= XML_PARSE_SAX1 as libc::c_int;
    }
    if options & XML_PARSE_NODICT as libc::c_int != 0 {
        (*ctxt).dictNames = 0 as libc::c_int;
        options -= XML_PARSE_NODICT as libc::c_int;
        (*ctxt).options |= XML_PARSE_NODICT as libc::c_int;
    } else {
        (*ctxt).dictNames = 1 as libc::c_int;
    }
    if options & XML_PARSE_NOCDATA as libc::c_int != 0 {
        let ref mut fresh663 = (*(*ctxt).sax).cdataBlock;
        *fresh663 = None;
        options -= XML_PARSE_NOCDATA as libc::c_int;
        (*ctxt).options |= XML_PARSE_NOCDATA as libc::c_int;
    }
    if options & XML_PARSE_NSCLEAN as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_NSCLEAN as libc::c_int;
        options -= XML_PARSE_NSCLEAN as libc::c_int;
    }
    if options & XML_PARSE_NONET as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_NONET as libc::c_int;
        options -= XML_PARSE_NONET as libc::c_int;
    }
    if options & XML_PARSE_COMPACT as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_COMPACT as libc::c_int;
        options -= XML_PARSE_COMPACT as libc::c_int;
    }
    if options & XML_PARSE_OLD10 as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_OLD10 as libc::c_int;
        options -= XML_PARSE_OLD10 as libc::c_int;
    }
    if options & XML_PARSE_NOBASEFIX as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_NOBASEFIX as libc::c_int;
        options -= XML_PARSE_NOBASEFIX as libc::c_int;
    }
    if options & XML_PARSE_HUGE as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_HUGE as libc::c_int;
        options -= XML_PARSE_HUGE as libc::c_int;
        if !((*ctxt).dict).is_null() {
            xmlDictSetLimit((*ctxt).dict, 0 as libc::c_int as size_t);
        }
    }
    if options & XML_PARSE_OLDSAX as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_OLDSAX as libc::c_int;
        options -= XML_PARSE_OLDSAX as libc::c_int;
    }
    if options & XML_PARSE_IGNORE_ENC as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_IGNORE_ENC as libc::c_int;
        options -= XML_PARSE_IGNORE_ENC as libc::c_int;
    }
    if options & XML_PARSE_BIG_LINES as libc::c_int != 0 {
        (*ctxt).options |= XML_PARSE_BIG_LINES as libc::c_int;
        options -= XML_PARSE_BIG_LINES as libc::c_int;
    }
    (*ctxt).linenumbers = 1 as libc::c_int;
    return options;
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtUseOptions(
    mut ctxt: xmlParserCtxtPtr,
    mut options: libc::c_int,
) -> libc::c_int {
    return xmlCtxtUseOptionsInternal(ctxt, options, 0 as *const libc::c_char);
}
unsafe extern "C" fn xmlDoRead(
    mut ctxt: xmlParserCtxtPtr,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
    mut reuse: libc::c_int,
) -> xmlDocPtr {
    let mut ret: xmlDocPtr = 0 as *mut xmlDoc;
    xmlCtxtUseOptionsInternal(ctxt, options, encoding);
    if !encoding.is_null() {
        let mut hdlr: xmlCharEncodingHandlerPtr = 0 as *mut xmlCharEncodingHandler;
        hdlr = xmlFindCharEncodingHandler(encoding);
        if !hdlr.is_null() {
            xmlSwitchToEncoding(ctxt, hdlr);
        }
    }
    if !URL.is_null() && !((*ctxt).input).is_null()
        && ((*(*ctxt).input).filename).is_null()
    {
        let ref mut fresh664 = (*(*ctxt).input).filename;
        *fresh664 = xmlStrdup(URL as *const xmlChar) as *mut libc::c_char;
    }
    xmlParseDocument(ctxt);
    if (*ctxt).wellFormed != 0 || (*ctxt).recovery != 0 {
        ret = (*ctxt).myDoc;
    } else {
        ret = 0 as xmlDocPtr;
        if !((*ctxt).myDoc).is_null() {
            xmlFreeDoc((*ctxt).myDoc);
        }
    }
    let ref mut fresh665 = (*ctxt).myDoc;
    *fresh665 = 0 as xmlDocPtr;
    if reuse == 0 {
        xmlFreeParserCtxt(ctxt);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadDoc(
    mut cur: *const xmlChar,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    ctxt = xmlCreateDocParserCtxt(cur);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadFile(
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateURLParserCtxt(filename, options);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(
        ctxt,
        0 as *const libc::c_char,
        encoding,
        options,
        0 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadMemory(
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    xmlInitParser();
    ctxt = xmlCreateMemoryParserCtxt(buffer, size);
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    return xmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadFd(
    mut fd: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as libc::c_int {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let ref mut fresh666 = (*input).closecallback;
    *fresh666 = None;
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlReadIO(
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlDocPtr;
    }
    ctxt = xmlNewParserCtxt();
    if ctxt.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        xmlFreeParserCtxt(ctxt);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadDoc(
    mut ctxt: xmlParserCtxtPtr,
    mut cur: *const xmlChar,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if cur.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = xmlNewStringInputStream(ctxt, cur);
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadFile(
    mut ctxt: xmlParserCtxtPtr,
    mut filename: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if filename.is_null() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    stream = xmlLoadExternalEntity(filename, 0 as *const libc::c_char, ctxt);
    if stream.is_null() {
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(
        ctxt,
        0 as *const libc::c_char,
        encoding,
        options,
        1 as libc::c_int,
    );
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadMemory(
    mut ctxt: xmlParserCtxtPtr,
    mut buffer: *const libc::c_char,
    mut size: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    if buffer.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateMem(buffer, size, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadFd(
    mut ctxt: xmlParserCtxtPtr,
    mut fd: libc::c_int,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if fd < 0 as libc::c_int {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateFd(fd, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        return 0 as xmlDocPtr;
    }
    let ref mut fresh667 = (*input).closecallback;
    *fresh667 = None;
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn xmlCtxtReadIO(
    mut ctxt: xmlParserCtxtPtr,
    mut ioread: xmlInputReadCallback,
    mut ioclose: xmlInputCloseCallback,
    mut ioctx: *mut libc::c_void,
    mut URL: *const libc::c_char,
    mut encoding: *const libc::c_char,
    mut options: libc::c_int,
) -> xmlDocPtr {
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut stream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    if ioread.is_none() {
        return 0 as xmlDocPtr;
    }
    if ctxt.is_null() {
        return 0 as xmlDocPtr;
    }
    xmlInitParser();
    xmlCtxtReset(ctxt);
    input = xmlParserInputBufferCreateIO(ioread, ioclose, ioctx, XML_CHAR_ENCODING_NONE);
    if input.is_null() {
        if ioclose.is_some() {
            ioclose.expect("non-null function pointer")(ioctx);
        }
        return 0 as xmlDocPtr;
    }
    stream = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
    if stream.is_null() {
        xmlFreeParserInputBuffer(input);
        return 0 as xmlDocPtr;
    }
    inputPush(ctxt, stream);
    return xmlDoRead(ctxt, URL, encoding, options, 1 as libc::c_int);
}
