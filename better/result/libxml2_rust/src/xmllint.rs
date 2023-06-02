use :: libc;
extern "C" {
    pub type _IO_marker;
    pub type _xmlXPathCompExpr;
    pub type _xmlRelaxNG;
    pub type _xmlRelaxNGValidCtxt;
    pub type _xmlSchematron;
    pub type _xmlSchematronParserCtxt;
    pub type _xmlSchematronValidCtxt;
    pub type _xmlStreamCtxt;
    fn xmlCheckVersion(version: i32);
    static mut stdin: *mut crate::src::tree::_IO_FILE;
    static mut stdout: *mut crate::src::tree::_IO_FILE;
    static mut stderr: *mut crate::src::tree::_IO_FILE;
    fn fclose(__stream: *mut crate::src::tree::_IO_FILE) -> i32;
    fn fflush(__stream: *mut crate::src::tree::_IO_FILE) -> i32;
    fn fopen(_: *const i8, _: *const i8) -> *mut crate::src::tree::_IO_FILE;
    fn fprintf(_: *mut crate::src::tree::_IO_FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn vfprintf(_: *mut crate::src::tree::_IO_FILE, _: *const i8, _: core::ffi::VaList) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn vsnprintf(_: *mut i8, _: u64, _: *const i8, _: core::ffi::VaList) -> i32;
    fn sscanf(_: *const i8, _: *const i8, _: ...) -> i32;
    fn fgets(__s: *mut i8, __n: i32, __stream: *mut crate::src::tree::_IO_FILE) -> *mut i8;
    fn fread(_: *mut core::ffi::c_void, _: u64, _: u64, _: *mut crate::src::tree::_IO_FILE) -> u64;
    fn memcpy(
        _: *mut core::ffi::c_void,
        _: *const core::ffi::c_void,
        _: u64,
    ) -> *mut core::ffi::c_void;
    fn memset(_: *mut core::ffi::c_void, _: i32, _: u64) -> *mut core::ffi::c_void;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn strtol(_: *const i8, _: *mut *mut i8, _: i32) -> i64;
    fn malloc(_: u64) -> *mut core::ffi::c_void;
    fn free(__ptr: *mut core::ffi::c_void);
    fn exit(_: i32) -> !;
    fn getenv(__name: *const i8) -> *mut i8;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    fn gettimeofday(__tv: *mut crate::src::xmllint::timeval, __tz: *mut core::ffi::c_void) -> i32;
    fn __xstat(__ver: i32, __filename: *const i8, __stat_buf: *mut crate::src::xmlIO::stat) -> i32;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn close(__fd: i32) -> i32;
    fn write(__fd: i32, __buf: *const core::ffi::c_void, __n: u64) -> i64;
    fn mmap(
        __addr: *mut core::ffi::c_void,
        __len: u64,
        __prot: i32,
        __flags: i32,
        __fd: i32,
        __offset: i64,
    ) -> *mut core::ffi::c_void;
    fn munmap(__addr: *mut core::ffi::c_void, __len: u64) -> i32;
    fn __xmlGenericErrorContext() -> *mut *mut core::ffi::c_void;
    fn xmlEncodeEntitiesReentrant(
        doc: *mut crate::src::threads::_xmlDoc,
        input: *const u8,
    ) -> *mut u8;
    fn xmlAddEncodingAlias(name: *const i8, alias: *const i8) -> i32;
    fn xmlCleanupParser();
    fn xmlParseFile(filename: *const i8) -> *mut crate::src::threads::_xmlDoc;
    fn xmlSubstituteEntitiesDefault(val: i32) -> i32;
    fn xmlKeepBlanksDefault(val: i32) -> i32;
    fn xmlPedanticParserDefault(val: i32) -> i32;
    fn xmlLineNumbersDefault(val: i32) -> i32;
    fn xmlParseDocument(ctxt: *mut crate::src::tree::_xmlParserCtxt) -> i32;
    fn xmlParseDTD(ExternalID: *const u8, SystemID: *const u8)
        -> *mut crate::src::threads::_xmlDtd;
    fn xmlNewParserCtxt() -> *mut crate::src::tree::_xmlParserCtxt;
    fn xmlFreeParserCtxt(ctxt: *mut crate::src::tree::_xmlParserCtxt);
    fn xmlCreatePushParserCtxt(
        sax_0: *mut crate::src::tree::_xmlSAXHandler,
        user_data: *mut core::ffi::c_void,
        chunk: *const i8,
        size: i32,
        filename: *const i8,
    ) -> *mut crate::src::tree::_xmlParserCtxt;
    fn xmlParseChunk(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        chunk: *const i8,
        size: i32,
        terminate: i32,
    ) -> i32;
    fn xmlNewIOInputStream(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        input: *mut crate::src::threads::_xmlParserInputBuffer,
        enc: i32,
    ) -> *mut crate::src::threads::_xmlParserInput;
    fn xmlCtxtUseOptions(ctxt: *mut crate::src::tree::_xmlParserCtxt, options_0: i32) -> i32;
    fn xmlReadFile(
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlReadMemory(
        buffer_0: *const i8,
        size: i32,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlReadFd(
        fd: i32,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlReadIO(
        ioread: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>,
        ioclose: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
        ioctx: *mut core::ffi::c_void,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlCtxtReadFile(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        filename: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlCtxtReadMemory(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        buffer_0: *const i8,
        size: i32,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlCtxtReadIO(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        ioread: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *mut i8, _: i32) -> i32>,
        ioclose: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>,
        ioctx: *mut core::ffi::c_void,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn xmlHasFeature(feature: u32) -> i32;
    fn xmlSAXDefaultVersion(version: i32) -> i32;
    fn xmlRegisterNodeDefault(
        func: Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>,
    ) -> Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
    fn xmlDeregisterNodeDefault(
        func: Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>,
    ) -> Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
    static mut xmlFree: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> ()>;
    fn __xmlDoValidityCheckingDefaultValue() -> *mut i32;
    fn __xmlGenericError(
    ) -> *mut Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
    fn __xmlLoadExtDtdDefaultValue() -> *mut i32;
    fn __xmlTreeIndentString() -> *mut *const i8;
    fn __xmlGetWarningsDefaultValue() -> *mut i32;
    fn __xmlParserDebugEntities() -> *mut i32;
    fn __xmlParserVersion() -> *mut *const i8;
    fn htmlCtxtUseOptions(ctxt: *mut crate::src::tree::_xmlParserCtxt, options_0: i32) -> i32;
    fn htmlReadFile(
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn htmlReadMemory(
        buffer_0: *const i8,
        size: i32,
        URL: *const i8,
        encoding_0: *const i8,
        options_0: i32,
    ) -> *mut crate::src::threads::_xmlDoc;
    fn htmlFreeParserCtxt(ctxt: *mut crate::src::tree::_xmlParserCtxt);
    fn htmlParseChunk(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        chunk: *const i8,
        size: i32,
        terminate: i32,
    ) -> i32;
    fn htmlCreatePushParserCtxt(
        sax_0: *mut crate::src::tree::_xmlSAXHandler,
        user_data: *mut core::ffi::c_void,
        chunk: *const i8,
        size: i32,
        filename: *const i8,
        enc: i32,
    ) -> *mut crate::src::tree::_xmlParserCtxt;
    fn inputPush(
        ctxt: *mut crate::src::tree::_xmlParserCtxt,
        value: *mut crate::src::threads::_xmlParserInput,
    ) -> i32;
    fn htmlDocDump(
        f: *mut crate::src::tree::_IO_FILE,
        cur: *mut crate::src::threads::_xmlDoc,
    ) -> i32;
    fn htmlSaveFile(filename: *const i8, cur: *mut crate::src::threads::_xmlDoc) -> i32;
    fn htmlSaveFileFormat(
        filename: *const i8,
        cur: *mut crate::src::threads::_xmlDoc,
        encoding_0: *const i8,
        format_0: i32,
    ) -> i32;
    fn xmlXPathFreeObject(obj: *mut crate::src::xinclude::_xmlXPathObject);
    fn xmlXPathNewContext(
        doc: *mut crate::src::threads::_xmlDoc,
    ) -> *mut crate::src::xinclude::_xmlXPathContext;
    fn xmlXPathFreeContext(ctxt: *mut crate::src::xinclude::_xmlXPathContext);
    fn xmlXPathOrderDocElems(doc: *mut crate::src::threads::_xmlDoc) -> i64;
    fn xmlXPathEval(
        str: *const u8,
        ctx: *mut crate::src::xinclude::_xmlXPathContext,
    ) -> *mut crate::src::xinclude::_xmlXPathObject;
    fn xmlXPathIsNaN(val: f64) -> i32;
    fn xmlXPathIsInf(val: f64) -> i32;
    fn xmlDebugDumpDocument(
        output_0: *mut crate::src::tree::_IO_FILE,
        doc: *mut crate::src::threads::_xmlDoc,
    );
    fn xmlDebugDumpEntities(
        output_0: *mut crate::src::tree::_IO_FILE,
        doc: *mut crate::src::threads::_xmlDoc,
    );
    fn xmlShell(
        doc: *mut crate::src::threads::_xmlDoc,
        filename: *mut i8,
        input: Option<unsafe extern "C" fn(_: *mut i8) -> *mut i8>,
        output_0: *mut crate::src::tree::_IO_FILE,
    );
    fn xmlLoadCatalogs(paths_0: *const i8);
    fn xmlRelaxNGSetValidErrors(
        ctxt: *mut crate::src::xmllint::_xmlRelaxNGValidCtxt,
        err: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
        warn: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
        ctx: *mut core::ffi::c_void,
    );
    fn xmlRelaxNGNewValidCtxt(
        schema_0: *mut crate::src::xmllint::_xmlRelaxNG,
    ) -> *mut crate::src::xmllint::_xmlRelaxNGValidCtxt;
    fn xmlRelaxNGFreeValidCtxt(ctxt: *mut crate::src::xmllint::_xmlRelaxNGValidCtxt);
    fn xmlRelaxNGValidateDoc(
        ctxt: *mut crate::src::xmllint::_xmlRelaxNGValidCtxt,
        doc: *mut crate::src::threads::_xmlDoc,
    ) -> i32;
    fn xmlRelaxNGFree(schema_0: *mut crate::src::xmllint::_xmlRelaxNG);
    fn xmlRelaxNGParse(
        ctxt: *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt,
    ) -> *mut crate::src::xmllint::_xmlRelaxNG;
    fn xmlRelaxNGSetParserErrors(
        ctxt: *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt,
        err: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
        warn: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>,
        ctx: *mut core::ffi::c_void,
    );
    fn xmlRelaxNGFreeParserCtxt(ctxt: *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt);
    fn xmlRelaxNGNewParserCtxt(URL: *const i8)
        -> *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt;
    fn xmlSchematronNewParserCtxt(
        URL: *const i8,
    ) -> *mut crate::src::xmllint::_xmlSchematronParserCtxt;
    fn xmlSchematronFreeParserCtxt(ctxt: *mut crate::src::xmllint::_xmlSchematronParserCtxt);
    fn xmlSchematronParse(
        ctxt: *mut crate::src::xmllint::_xmlSchematronParserCtxt,
    ) -> *mut crate::src::xmllint::_xmlSchematron;
    fn xmlSchematronFree(schema_0: *mut crate::src::xmllint::_xmlSchematron);
    fn xmlSchematronNewValidCtxt(
        schema_0: *mut crate::src::xmllint::_xmlSchematron,
        options_0: i32,
    ) -> *mut crate::src::xmllint::_xmlSchematronValidCtxt;
    fn xmlSchematronFreeValidCtxt(ctxt: *mut crate::src::xmllint::_xmlSchematronValidCtxt);
    fn xmlSchematronValidateDoc(
        ctxt: *mut crate::src::xmllint::_xmlSchematronValidCtxt,
        instance: *mut crate::src::threads::_xmlDoc,
    ) -> i32;
    fn xmlFreePattern(comp: *mut crate::src::xmlreader::_xmlPattern);
    fn xmlPatterncompile(
        pattern_0: *const u8,
        dict: *mut crate::src::xpointer::_xmlDict,
        flags: i32,
        namespaces: *mut *const u8,
    ) -> *mut crate::src::xmlreader::_xmlPattern;
    fn xmlPatternMatch(
        comp: *mut crate::src::xmlreader::_xmlPattern,
        node: *mut crate::src::threads::_xmlNode,
    ) -> i32;
    fn xmlPatternGetStreamCtxt(
        comp: *mut crate::src::xmlreader::_xmlPattern,
    ) -> *mut crate::src::xmllint::_xmlStreamCtxt;
    fn xmlFreeStreamCtxt(stream_0: *mut crate::src::xmllint::_xmlStreamCtxt);
    fn xmlStreamPush(
        stream_0: *mut crate::src::xmllint::_xmlStreamCtxt,
        name: *const u8,
        ns: *const u8,
    ) -> i32;
    fn xmlStreamPop(stream_0: *mut crate::src::xmllint::_xmlStreamCtxt) -> i32;
    fn xmlC14NDocDumpMemory(
        doc: *mut crate::src::threads::_xmlDoc,
        nodes: *mut crate::src::xinclude::_xmlNodeSet,
        mode: i32,
        inclusive_ns_prefixes: *mut *mut u8,
        with_comments: i32,
        doc_txt_ptr: *mut *mut u8,
    ) -> i32;
}
pub use crate::src::tree::xmlCopyDoc;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlDocSetRootElement;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlFreeDtd;
pub use crate::src::tree::xmlGetIntSubset;
pub use crate::src::tree::xmlGetNodePath;
pub use crate::src::tree::xmlNewDoc;
pub use crate::src::tree::xmlNewDocNode;
pub use crate::src::tree::xmlNodeSetContent;
pub use crate::src::tree::xmlSetCompressMode;
pub use crate::src::tree::xmlUnlinkNode;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::valid::xmlFreeEnumeration;
pub use crate::src::valid::xmlFreeValidCtxt;
pub use crate::src::valid::xmlNewValidCtxt;
pub use crate::src::valid::xmlValidGetValidElements;
pub use crate::src::valid::xmlValidateDocument;
pub use crate::src::valid::xmlValidateDtd;
pub use crate::src::xinclude::xmlXIncludeProcessFlags;
pub use crate::src::xmlIO::xmlFreeParserInputBuffer;
pub use crate::src::xmlIO::xmlGetExternalEntityLoader;
pub use crate::src::xmlIO::xmlNoNetExternalEntityLoader;
pub use crate::src::xmlIO::xmlOutputBufferClose;
pub use crate::src::xmlIO::xmlOutputBufferCreateFile;
pub use crate::src::xmlIO::xmlOutputBufferWrite;
pub use crate::src::xmlIO::xmlParserInputBufferCreateFilename;
pub use crate::src::xmlIO::xmlSetExternalEntityLoader;
pub use crate::src::xmlmemory::_IO_wide_data;
pub use crate::src::xmlmemory::xmlMemFree;
pub use crate::src::xmlmemory::xmlMemMalloc;
pub use crate::src::xmlmemory::xmlMemRealloc;
pub use crate::src::xmlmemory::xmlMemSetup;
pub use crate::src::xmlmemory::xmlMemUsed;
pub use crate::src::xmlmemory::xmlMemoryDump;
pub use crate::src::xmlmemory::xmlMemoryStrdup;
pub use crate::src::xmlreader::_xmlPattern;
pub use crate::src::xmlreader::_xmlRelaxNGParserCtxt;
pub use crate::src::xmlreader::_xmlTextReader;
pub use crate::src::xmlreader::xmlFreeTextReader;
pub use crate::src::xmlreader::xmlReaderForFile;
pub use crate::src::xmlreader::xmlReaderForMemory;
pub use crate::src::xmlreader::xmlReaderWalker;
pub use crate::src::xmlreader::xmlTextReaderConstLocalName;
pub use crate::src::xmlreader::xmlTextReaderConstName;
pub use crate::src::xmlreader::xmlTextReaderConstNamespaceUri;
pub use crate::src::xmlreader::xmlTextReaderConstValue;
pub use crate::src::xmlreader::xmlTextReaderCurrentNode;
pub use crate::src::xmlreader::xmlTextReaderDepth;
pub use crate::src::xmlreader::xmlTextReaderHasValue;
pub use crate::src::xmlreader::xmlTextReaderIsEmptyElement;
pub use crate::src::xmlreader::xmlTextReaderIsValid;
pub use crate::src::xmlreader::xmlTextReaderNodeType;
pub use crate::src::xmlreader::xmlTextReaderRead;
pub use crate::src::xmlreader::xmlTextReaderRelaxNGValidate;
pub use crate::src::xmlreader::xmlTextReaderSchemaValidate;
pub use crate::src::xmlreader::xmlTextReaderSetParserProp;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlsave::_IO_codecvt;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlsave::_xmlSaveCtxt;
pub use crate::src::xmlsave::xmlDocDump;
pub use crate::src::xmlsave::xmlDocDumpFormatMemory;
pub use crate::src::xmlsave::xmlDocDumpFormatMemoryEnc;
pub use crate::src::xmlsave::xmlDocDumpMemory;
pub use crate::src::xmlsave::xmlDocDumpMemoryEnc;
pub use crate::src::xmlsave::xmlNodeDumpOutput;
pub use crate::src::xmlsave::xmlSaveClose;
pub use crate::src::xmlsave::xmlSaveDoc;
pub use crate::src::xmlsave::xmlSaveFile;
pub use crate::src::xmlsave::xmlSaveFileEnc;
pub use crate::src::xmlsave::xmlSaveFormatFile;
pub use crate::src::xmlsave::xmlSaveFormatFileEnc;
pub use crate::src::xmlsave::xmlSaveToFd;
pub use crate::src::xmlsave::xmlSaveToFilename;
pub use crate::src::xmlschemas::_xmlSchema;
pub use crate::src::xmlschemas::_xmlSchemaParserCtxt;
pub use crate::src::xmlschemas::_xmlSchemaValidCtxt;
pub use crate::src::xmlschemas::xmlSchemaFree;
pub use crate::src::xmlschemas::xmlSchemaFreeParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaFreeValidCtxt;
pub use crate::src::xmlschemas::xmlSchemaNewParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaNewValidCtxt;
pub use crate::src::xmlschemas::xmlSchemaParse;
pub use crate::src::xmlschemas::xmlSchemaSetParserErrors;
pub use crate::src::xmlschemas::xmlSchemaSetValidErrors;
pub use crate::src::xmlschemas::xmlSchemaValidateDoc;
pub use crate::src::xmlschemas::xmlSchemaValidateSetFilename;
pub use crate::src::xmlschemas::xmlSchemaValidateStream;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xmlstring::_xmlStartTag;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xpointer::_xmlDict;
pub type __builtin_va_list = [crate::src::xmllint::__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: u32,
    pub fp_offset: u32,
    pub overflow_arg_area: *mut core::ffi::c_void,
    pub reg_save_area: *mut core::ffi::c_void,
}
impl __va_list_tag {
    pub const fn new() -> Self {
        __va_list_tag {
            gp_offset: 0,
            fp_offset: 0,
            overflow_arg_area: (0 as *mut core::ffi::c_void),
            reg_save_area: (0 as *mut core::ffi::c_void),
        }
    }
}
impl std::default::Default for __va_list_tag {
    fn default() -> Self {
        __va_list_tag::new()
    }
}
pub type va_list = [crate::src::xmllint::__va_list_tag; 1];
pub type xmlChar = u8;
pub type size_t = u64;
pub type __dev_t = u64;
pub type __uid_t = u32;
pub type __gid_t = u32;
pub type __ino_t = u64;
pub type __mode_t = u32;
pub type __nlink_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __time_t = i64;
pub type __suseconds_t = i64;
pub type __blksize_t = i64;
pub type __blkcnt_t = i64;
pub type __ssize_t = i64;
pub type __syscall_slong_t = i64;
pub type _IO_FILE = crate::src::tree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
pub type ssize_t = i64;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
impl timeval {
    pub const fn new() -> Self {
        timeval {
            tv_sec: 0,
            tv_usec: 0,
        }
    }
}
impl std::default::Default for timeval {
    fn default() -> Self {
        timeval::new()
    }
}
pub type timespec = crate::src::xmlIO::timespec;
pub type stat = crate::src::xmlIO::stat;
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
pub type _xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(_: *mut core::ffi::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, _: i32) -> i32>;
pub type xmlOutputBuffer = crate::src::threads::_xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut crate::src::threads::_xmlOutputBuffer;
pub type _xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(_: *mut u8) -> ()>;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputPtr = *mut crate::src::threads::_xmlParserInput;
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
pub type xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut crate::src::tree::_xmlParserCtxt;
pub type xmlSAXHandler = crate::src::tree::_xmlSAXHandler;
pub type xmlSAXHandlerPtr = *mut crate::src::tree::_xmlSAXHandler;
pub type xmlNsPtr = *mut crate::src::threads::_xmlNs;
pub type xmlDtd = crate::src::threads::_xmlDtd;
pub type xmlDtdPtr = *mut crate::src::threads::_xmlDtd;
pub type xmlGenericErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlValidCtxtPtr = *mut crate::src::tree::_xmlValidCtxt;
pub type xmlExternalEntityLoader = Option<
    unsafe extern "C" fn(
        _: *const i8,
        _: *const i8,
        _: *mut crate::src::tree::_xmlParserCtxt,
    ) -> *mut crate::src::threads::_xmlParserInput,
>;
pub type xmlCharEncoding = i32;
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
pub type C2RustUnnamed = u32;
pub const XML_PARSE_BIG_LINES: C2RustUnnamed = 4194304;
pub const XML_PARSE_IGNORE_ENC: C2RustUnnamed = 2097152;
pub const XML_PARSE_OLDSAX: C2RustUnnamed = 1048576;
pub const XML_PARSE_HUGE: C2RustUnnamed = 524288;
pub const XML_PARSE_NOBASEFIX: C2RustUnnamed = 262144;
pub const XML_PARSE_OLD10: C2RustUnnamed = 131072;
pub const XML_PARSE_COMPACT: C2RustUnnamed = 65536;
pub const XML_PARSE_NOXINCNODE: C2RustUnnamed = 32768;
pub const XML_PARSE_NOCDATA: C2RustUnnamed = 16384;
pub const XML_PARSE_NSCLEAN: C2RustUnnamed = 8192;
pub const XML_PARSE_NODICT: C2RustUnnamed = 4096;
pub const XML_PARSE_NONET: C2RustUnnamed = 2048;
pub const XML_PARSE_XINCLUDE: C2RustUnnamed = 1024;
pub const XML_PARSE_SAX1: C2RustUnnamed = 512;
pub const XML_PARSE_NOBLANKS: C2RustUnnamed = 256;
pub const XML_PARSE_PEDANTIC: C2RustUnnamed = 128;
pub const XML_PARSE_NOWARNING: C2RustUnnamed = 64;
pub const XML_PARSE_NOERROR: C2RustUnnamed = 32;
pub const XML_PARSE_DTDVALID: C2RustUnnamed = 16;
pub const XML_PARSE_DTDATTR: C2RustUnnamed = 8;
pub const XML_PARSE_DTDLOAD: C2RustUnnamed = 4;
pub const XML_PARSE_NOENT: C2RustUnnamed = 2;
pub const XML_PARSE_RECOVER: C2RustUnnamed = 1;
pub type xmlFeature = u32;
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
pub type xmlRegisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
pub type xmlDeregisterNodeFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::threads::_xmlNode) -> ()>;
pub type htmlParserCtxtPtr = *mut crate::src::tree::_xmlParserCtxt;
pub type htmlSAXHandlerPtr = *mut crate::src::tree::_xmlSAXHandler;
pub type htmlDocPtr = *mut crate::src::threads::_xmlDoc;
pub type C2RustUnnamed_0 = u32;
pub const HTML_PARSE_IGNORE_ENC: C2RustUnnamed_0 = 2097152;
pub const HTML_PARSE_COMPACT: C2RustUnnamed_0 = 65536;
pub const HTML_PARSE_NOIMPLIED: C2RustUnnamed_0 = 8192;
pub const HTML_PARSE_NONET: C2RustUnnamed_0 = 2048;
pub const HTML_PARSE_NOBLANKS: C2RustUnnamed_0 = 256;
pub const HTML_PARSE_PEDANTIC: C2RustUnnamed_0 = 128;
pub const HTML_PARSE_NOWARNING: C2RustUnnamed_0 = 64;
pub const HTML_PARSE_NOERROR: C2RustUnnamed_0 = 32;
pub const HTML_PARSE_NODEFDTD: C2RustUnnamed_0 = 4;
pub const HTML_PARSE_RECOVER: C2RustUnnamed_0 = 1;
pub type _xmlXPathContext = crate::src::xinclude::_xmlXPathContext;
pub type xmlXPathFuncLookupFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> Option<
        unsafe extern "C" fn(_: *mut crate::src::xinclude::_xmlXPathParserContext, _: i32) -> (),
    >,
>;
pub type xmlXPathFunction = Option<
    unsafe extern "C" fn(_: *mut crate::src::xinclude::_xmlXPathParserContext, _: i32) -> (),
>;
pub type xmlXPathParserContextPtr = *mut crate::src::xinclude::_xmlXPathParserContext;
pub type xmlXPathParserContext = crate::src::xinclude::_xmlXPathParserContext;
pub type _xmlXPathParserContext = crate::src::xinclude::_xmlXPathParserContext;
pub type xmlXPathCompExprPtr = *mut crate::src::xmllint::_xmlXPathCompExpr;
pub type xmlXPathCompExpr = crate::src::xmllint::_xmlXPathCompExpr;
pub type xmlXPathObjectPtr = *mut crate::src::xinclude::_xmlXPathObject;
pub type xmlXPathObject = crate::src::xinclude::_xmlXPathObject;
pub type _xmlXPathObject = crate::src::xinclude::_xmlXPathObject;
pub type xmlNodeSetPtr = *mut crate::src::xinclude::_xmlNodeSet;
pub type xmlNodeSet = crate::src::xinclude::_xmlNodeSet;
pub type _xmlNodeSet = crate::src::xinclude::_xmlNodeSet;
pub type xmlXPathObjectType = u32;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = *mut crate::src::xinclude::_xmlXPathContext;
pub type xmlXPathContext = crate::src::xinclude::_xmlXPathContext;
pub type xmlXPathVariableLookupFunc = Option<
    unsafe extern "C" fn(
        _: *mut core::ffi::c_void,
        _: *const u8,
        _: *const u8,
    ) -> *mut crate::src::xinclude::_xmlXPathObject,
>;
pub type xmlXPathAxisPtr = *mut crate::src::xinclude::_xmlXPathAxis;
pub type xmlXPathAxis = crate::src::xinclude::_xmlXPathAxis;
pub type _xmlXPathAxis = crate::src::xinclude::_xmlXPathAxis;
pub type xmlXPathAxisFunc = Option<
    unsafe extern "C" fn(
        _: *mut crate::src::xinclude::_xmlXPathParserContext,
        _: *mut crate::src::xinclude::_xmlXPathObject,
    ) -> *mut crate::src::xinclude::_xmlXPathObject,
>;
pub type xmlXPathTypePtr = *mut crate::src::xinclude::_xmlXPathType;
pub type xmlXPathType = crate::src::xinclude::_xmlXPathType;
pub type _xmlXPathType = crate::src::xinclude::_xmlXPathType;
pub type xmlXPathConvertFunc =
    Option<unsafe extern "C" fn(_: *mut crate::src::xinclude::_xmlXPathObject, _: i32) -> i32>;
pub type xmlShellReadlineFunc = Option<unsafe extern "C" fn(_: *mut i8) -> *mut i8>;
pub type xmlRelaxNG = crate::src::xmllint::_xmlRelaxNG;
pub type xmlRelaxNGPtr = *mut crate::src::xmllint::_xmlRelaxNG;
pub type xmlRelaxNGValidityErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlRelaxNGValidityWarningFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlRelaxNGParserCtxt = crate::src::xmlreader::_xmlRelaxNGParserCtxt;
pub type xmlRelaxNGParserCtxtPtr = *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt;
pub type xmlRelaxNGValidCtxt = crate::src::xmllint::_xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidCtxtPtr = *mut crate::src::xmllint::_xmlRelaxNGValidCtxt;
pub type xmlSchema<'a> = crate::src::xmlschemas::_xmlSchema<'a>;
pub type xmlSchemaPtr<'a> = *mut crate::src::xmlschemas::_xmlSchema<'a>;
pub type xmlSchemaValidityErrorFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlSchemaValidityWarningFunc =
    Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()>;
pub type xmlSchemaParserCtxt<'a> = crate::src::xmlschemas::_xmlSchemaParserCtxt<'a>;
pub type xmlSchemaParserCtxtPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaParserCtxt<'a>;
pub type xmlSchemaValidCtxt<'a> = crate::src::xmlschemas::_xmlSchemaValidCtxt<'a>;
pub type xmlSchemaValidCtxtPtr<'a> = *mut crate::src::xmlschemas::_xmlSchemaValidCtxt<'a>;
pub type C2RustUnnamed_1 = u32;
pub const XML_PARSER_SUBST_ENTITIES: C2RustUnnamed_1 = 4;
pub const XML_PARSER_VALIDATE: C2RustUnnamed_1 = 3;
pub const XML_PARSER_DEFAULTATTRS: C2RustUnnamed_1 = 2;
pub const XML_PARSER_LOADDTD: C2RustUnnamed_1 = 1;
pub type C2RustUnnamed_2 = u32;
pub const XML_READER_TYPE_XML_DECLARATION: C2RustUnnamed_2 = 17;
pub const XML_READER_TYPE_END_ENTITY: C2RustUnnamed_2 = 16;
pub const XML_READER_TYPE_END_ELEMENT: C2RustUnnamed_2 = 15;
pub const XML_READER_TYPE_SIGNIFICANT_WHITESPACE: C2RustUnnamed_2 = 14;
pub const XML_READER_TYPE_WHITESPACE: C2RustUnnamed_2 = 13;
pub const XML_READER_TYPE_NOTATION: C2RustUnnamed_2 = 12;
pub const XML_READER_TYPE_DOCUMENT_FRAGMENT: C2RustUnnamed_2 = 11;
pub const XML_READER_TYPE_DOCUMENT_TYPE: C2RustUnnamed_2 = 10;
pub const XML_READER_TYPE_DOCUMENT: C2RustUnnamed_2 = 9;
pub const XML_READER_TYPE_COMMENT: C2RustUnnamed_2 = 8;
pub const XML_READER_TYPE_PROCESSING_INSTRUCTION: C2RustUnnamed_2 = 7;
pub const XML_READER_TYPE_ENTITY: C2RustUnnamed_2 = 6;
pub const XML_READER_TYPE_ENTITY_REFERENCE: C2RustUnnamed_2 = 5;
pub const XML_READER_TYPE_CDATA: C2RustUnnamed_2 = 4;
pub const XML_READER_TYPE_TEXT: C2RustUnnamed_2 = 3;
pub const XML_READER_TYPE_ATTRIBUTE: C2RustUnnamed_2 = 2;
pub const XML_READER_TYPE_ELEMENT: C2RustUnnamed_2 = 1;
pub const XML_READER_TYPE_NONE: C2RustUnnamed_2 = 0;
pub type xmlTextReader<'a> = crate::src::xmlreader::_xmlTextReader<'a>;
pub type xmlTextReaderPtr<'a> = *mut crate::src::xmlreader::_xmlTextReader<'a>;
pub type C2RustUnnamed_3 = u32;
pub const XML_SCHEMATRON_OUT_IO: C2RustUnnamed_3 = 1024;
pub const XML_SCHEMATRON_OUT_BUFFER: C2RustUnnamed_3 = 512;
pub const XML_SCHEMATRON_OUT_FILE: C2RustUnnamed_3 = 256;
pub const XML_SCHEMATRON_OUT_ERROR: C2RustUnnamed_3 = 8;
pub const XML_SCHEMATRON_OUT_XML: C2RustUnnamed_3 = 4;
pub const XML_SCHEMATRON_OUT_TEXT: C2RustUnnamed_3 = 2;
pub const XML_SCHEMATRON_OUT_QUIET: C2RustUnnamed_3 = 1;
pub type xmlSchematron = crate::src::xmllint::_xmlSchematron;
pub type xmlSchematronPtr = *mut crate::src::xmllint::_xmlSchematron;
pub type xmlSchematronParserCtxt = crate::src::xmllint::_xmlSchematronParserCtxt;
pub type xmlSchematronParserCtxtPtr = *mut crate::src::xmllint::_xmlSchematronParserCtxt;
pub type xmlSchematronValidCtxt = crate::src::xmllint::_xmlSchematronValidCtxt;
pub type xmlSchematronValidCtxtPtr = *mut crate::src::xmllint::_xmlSchematronValidCtxt;
pub type xmlPattern = crate::src::xmlreader::_xmlPattern;
pub type xmlPatternPtr = *mut crate::src::xmlreader::_xmlPattern;
pub type xmlStreamCtxt = crate::src::xmllint::_xmlStreamCtxt;
pub type xmlStreamCtxtPtr = *mut crate::src::xmllint::_xmlStreamCtxt;
pub type C2RustUnnamed_4 = u32;
pub const XML_C14N_1_1: C2RustUnnamed_4 = 2;
pub const XML_C14N_EXCLUSIVE_1_0: C2RustUnnamed_4 = 1;
pub const XML_C14N_1_0: C2RustUnnamed_4 = 0;
pub type C2RustUnnamed_5 = u32;
pub const XML_SAVE_WSNONSIG: C2RustUnnamed_5 = 128;
pub const XML_SAVE_AS_HTML: C2RustUnnamed_5 = 64;
pub const XML_SAVE_AS_XML: C2RustUnnamed_5 = 32;
pub const XML_SAVE_XHTML: C2RustUnnamed_5 = 16;
pub const XML_SAVE_NO_XHTML: C2RustUnnamed_5 = 8;
pub const XML_SAVE_NO_EMPTY: C2RustUnnamed_5 = 4;
pub const XML_SAVE_NO_DECL: C2RustUnnamed_5 = 2;
pub const XML_SAVE_FORMAT: C2RustUnnamed_5 = 1;
pub type xmlSaveCtxt<'a> = crate::src::xmlsave::_xmlSaveCtxt<'a>;
pub type xmlSaveCtxtPtr<'a> = *mut crate::src::xmlsave::_xmlSaveCtxt<'a>;
pub type xmllintReturnCode = u32;
pub const XMLLINT_ERR_XPATH: xmllintReturnCode = 10;
pub const XMLLINT_ERR_MEM: xmllintReturnCode = 9;
pub const XMLLINT_ERR_RDREGIS: xmllintReturnCode = 8;
pub const XMLLINT_ERR_SCHEMAPAT: xmllintReturnCode = 7;
pub const XMLLINT_ERR_OUT: xmllintReturnCode = 6;
pub const XMLLINT_ERR_SCHEMACOMP: xmllintReturnCode = 5;
pub const XMLLINT_ERR_RDFILE: xmllintReturnCode = 4;
pub const XMLLINT_ERR_VALID: xmllintReturnCode = 3;
pub const XMLLINT_ERR_DTD: xmllintReturnCode = 2;
pub const XMLLINT_ERR_UNCLASS: xmllintReturnCode = 1;
pub const XMLLINT_RETURN_OK: xmllintReturnCode = 0;
#[inline]
extern "C" fn atoi(mut __nptr: *const i8) -> i32 {
    return (unsafe { strtol(__nptr, 0 as *mut libc::c_void as *mut *mut i8, 10 as i32) }) as i32;
}
#[inline]
extern "C" fn stat(mut __path: *const i8, mut __statbuf: *mut crate::src::xmlIO::stat) -> i32 {
    return unsafe { __xstat(1 as i32, __path, __statbuf) };
}
static mut shell: i32 = 0 as i32;
static mut debugent: i32 = 0 as i32;
static mut debug: i32 = 0 as i32;
static mut maxmem: i32 = 0 as i32;
static mut copy: i32 = 0 as i32;
static mut recovery: i32 = 0 as i32;
static mut noent: i32 = 0 as i32;
static mut noenc: i32 = 0 as i32;
static mut noblanks: i32 = 0 as i32;
static mut noout: i32 = 0 as i32;
static mut nowrap: i32 = 0 as i32;
static mut format: i32 = 0 as i32;
static mut output: *const i8 = 0 as *const i8;
static mut compress: i32 = 0 as i32;
static mut oldout: i32 = 0 as i32;
static mut valid: i32 = 0 as i32;
static mut postvalid: i32 = 0 as i32;
static mut dtdvalid: *mut i8 = 0 as *const i8 as *mut i8;
static mut dtdvalidfpi: *mut i8 = 0 as *const i8 as *mut i8;
static mut relaxng: *mut i8 = 0 as *const i8 as *mut i8;
static mut relaxngschemas: *mut crate::src::xmllint::_xmlRelaxNG =
    0 as *const xmlRelaxNG as xmlRelaxNGPtr;
static mut schema: *mut i8 = 0 as *const i8 as *mut i8;
static mut wxschemas: *mut crate::src::xmlschemas::_xmlSchema<'static> =
    0 as *const xmlSchema as xmlSchemaPtr;
static mut schematron: *mut i8 = 0 as *const i8 as *mut i8;
static mut wxschematron: *mut crate::src::xmllint::_xmlSchematron =
    0 as *const xmlSchematron as xmlSchematronPtr;
static mut repeat: i32 = 0 as i32;
static mut insert: i32 = 0 as i32;
static mut html: i32 = 0 as i32;
static mut xmlout: i32 = 0 as i32;
static mut htmlout: i32 = 0 as i32;
static mut nodefdtd: i32 = 0 as i32;
static mut push: i32 = 0 as i32;
static mut pushsize: i32 = 4096 as i32;
static mut memory: i32 = 0 as i32;
static mut testIO: i32 = 0 as i32;
static mut encoding: *mut i8 = 0 as *const i8 as *mut i8;
static mut xinclude: i32 = 0 as i32;
static mut dtdattrs: i32 = 0 as i32;
static mut loaddtd: i32 = 0 as i32;
static mut progresult: u32 = XMLLINT_RETURN_OK;
static mut quiet: i32 = 0 as i32;
static mut timing: i32 = 0 as i32;
static mut generate: i32 = 0 as i32;
static mut dropdtd: i32 = 0 as i32;
static mut catalogs: i32 = 0 as i32;
static mut nocatalogs: i32 = 0 as i32;
static mut canonical: i32 = 0 as i32;
static mut canonical_11: i32 = 0 as i32;
static mut exc_canonical: i32 = 0 as i32;
static mut stream: i32 = 0 as i32;
static mut walker: i32 = 0 as i32;
static mut pattern: *const i8 = 0 as *const i8;
static mut patternc: *mut crate::src::xmlreader::_xmlPattern =
    0 as *const xmlPattern as xmlPatternPtr;
static mut patstream: *mut crate::src::xmllint::_xmlStreamCtxt =
    0 as *const xmlStreamCtxt as xmlStreamCtxtPtr;
static mut chkregister: i32 = 0 as i32;
static mut nbregister: i32 = 0 as i32;
static mut sax1: i32 = 0 as i32;
static mut xpathquery: *const i8 = 0 as *const i8;
static mut options: i32 = XML_PARSE_COMPACT as i32 | XML_PARSE_BIG_LINES as i32;
static mut sax: i32 = 0 as i32;
static mut oldxml10: i32 = 0 as i32;
static mut paths: [*mut u8; 65] = [0 as *const xmlChar as *mut xmlChar; 65];
static mut nbpaths: i32 = 0 as i32;
static mut load_trace: i32 = 0 as i32;
extern "C" fn parsePath(mut path: *const u8) {
    let mut cur: *const u8 = 0 as *const xmlChar;
    if path.is_null() {
        return;
    }
    while (unsafe { *path }) as i32 != 0 as i32 {
        if (unsafe { nbpaths }) >= 64 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"MAX_PATHS reached: too many paths\n\0" as *const u8 as *const i8,
                )
            });
            return;
        }
        cur = path;
        while (unsafe { *cur }) as i32 == ' ' as i32 || (unsafe { *cur }) as i32 == ':' as i32 {
            cur = unsafe { cur.offset(1) };
        }
        path = cur;
        while (unsafe { *cur }) as i32 != 0 as i32
            && (unsafe { *cur }) as i32 != ' ' as i32
            && (unsafe { *cur }) as i32 != ':' as i32
        {
            cur = unsafe { cur.offset(1) };
        }
        if cur != path {
            (unsafe {
                paths[nbpaths as usize] = xmlStrndup(path, cur.offset_from(path) as i64 as i32)
            });
            if !(unsafe { paths[nbpaths as usize] }).is_null() {
                (unsafe { nbpaths += 1 });
            }
            path = cur;
        }
    }
}
static mut defaultEntityLoader: Option<
    unsafe extern "C" fn(
        _: *const i8,
        _: *const i8,
        _: *mut crate::src::tree::_xmlParserCtxt,
    ) -> *mut crate::src::threads::_xmlParserInput,
> = None;
extern "C" fn xmllintExternalEntityLoader(
    mut URL: *const i8,
    mut ID: *const i8,
    mut ctxt: *mut crate::src::tree::_xmlParserCtxt,
) -> *mut crate::src::threads::_xmlParserInput {
    let mut ret: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut warning: Option<
        unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> (),
    > = None;
    let mut err: Option<unsafe extern "C" fn(_: *mut core::ffi::c_void, _: *const i8, ...) -> ()> =
        None;
    let mut i: i32 = 0;
    let mut lastsegment: *const i8 = URL;
    let mut iter: *const i8 = URL;
    if (unsafe { nbpaths }) > 0 as i32 && !iter.is_null() {
        while (unsafe { *iter }) as i32 != 0 as i32 {
            if (unsafe { *iter }) as i32 == '/' as i32 {
                lastsegment = unsafe { iter.offset(1 as i32 as isize) };
            }
            iter = unsafe { iter.offset(1) };
        }
    }
    if !ctxt.is_null() && !(unsafe { (*ctxt).sax }).is_null() {
        warning = unsafe { (*(*ctxt).sax).warning };
        err = unsafe { (*(*ctxt).sax).error };
        let fresh0 = unsafe { &mut ((*(*ctxt).sax).warning) };
        *fresh0 = None;
        let fresh1 = unsafe { &mut ((*(*ctxt).sax).error) };
        *fresh1 = None;
    }
    if unsafe { defaultEntityLoader.is_some() } {
        ret = unsafe { defaultEntityLoader.expect("non-null function pointer")(URL, ID, ctxt) };
        if !ret.is_null() {
            if warning.is_some() {
                let fresh2 = unsafe { &mut ((*(*ctxt).sax).warning) };
                *fresh2 = warning;
            }
            if err.is_some() {
                let fresh3 = unsafe { &mut ((*(*ctxt).sax).error) };
                *fresh3 = err;
            }
            if (unsafe { load_trace }) != 0 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"Loaded URL=\"%s\" ID=\"%s\"\n\0" as *const u8 as *const i8,
                        if !URL.is_null() {
                            URL
                        } else {
                            b"(null)\0" as *const u8 as *const i8
                        },
                        if !ID.is_null() {
                            ID
                        } else {
                            b"(null)\0" as *const u8 as *const i8
                        },
                    )
                });
            }
            return ret;
        }
    }
    i = 0 as i32;
    while i < (unsafe { nbpaths }) {
        let mut newURL: *mut u8 = 0 as *mut xmlChar;
        newURL = xmlStrdup((unsafe { paths[i as usize] }) as *const xmlChar);
        newURL = xmlStrcat(newURL, b"/\0" as *const u8 as *const i8 as *const xmlChar);
        newURL = xmlStrcat(newURL, lastsegment as *const xmlChar);
        if !newURL.is_null() {
            ret = unsafe {
                defaultEntityLoader.expect("non-null function pointer")(
                    newURL as *const i8,
                    ID,
                    ctxt,
                )
            };
            if !ret.is_null() {
                if warning.is_some() {
                    let fresh4 = unsafe { &mut ((*(*ctxt).sax).warning) };
                    *fresh4 = warning;
                }
                if err.is_some() {
                    let fresh5 = unsafe { &mut ((*(*ctxt).sax).error) };
                    *fresh5 = err;
                }
                if (unsafe { load_trace }) != 0 {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"Loaded URL=\"%s\" ID=\"%s\"\n\0" as *const u8 as *const i8,
                            newURL,
                            if !ID.is_null() {
                                ID
                            } else {
                                b"(null)\0" as *const u8 as *const i8
                            },
                        )
                    });
                }
                (unsafe {
                    xmlFree.expect("non-null function pointer")(newURL as *mut libc::c_void)
                });
                return ret;
            }
            (unsafe { xmlFree.expect("non-null function pointer")(newURL as *mut libc::c_void) });
        }
        i += 1;
    }
    if err.is_some() {
        let fresh6 = unsafe { &mut ((*(*ctxt).sax).error) };
        *fresh6 = err;
    }
    if warning.is_some() {
        let fresh7 = unsafe { &mut ((*(*ctxt).sax).warning) };
        *fresh7 = warning;
        if !URL.is_null() {
            (unsafe {
                warning.expect("non-null function pointer")(
                    ctxt as *mut libc::c_void,
                    b"failed to load external entity \"%s\"\n\0" as *const u8 as *const i8,
                    URL,
                )
            });
        } else if !ID.is_null() {
            (unsafe {
                warning.expect("non-null function pointer")(
                    ctxt as *mut libc::c_void,
                    b"failed to load external entity \"%s\"\n\0" as *const u8 as *const i8,
                    ID,
                )
            });
        }
    }
    return 0 as xmlParserInputPtr;
}
extern "C" fn OOM() {
    (unsafe {
        fprintf(
            stderr,
            b"Ran out of memory needs > %d bytes\n\0" as *const u8 as *const i8,
            maxmem,
        )
    });
    (unsafe { progresult = XMLLINT_ERR_MEM });
}
extern "C" fn myFreeFunc(mut mem: *mut core::ffi::c_void) {
    xmlMemFree(mem);
}
extern "C" fn myMallocFunc(mut size: u64) -> *mut core::ffi::c_void {
    let mut ret: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    ret = xmlMemMalloc(size);
    if !ret.is_null() {
        if xmlMemUsed() > (unsafe { maxmem }) {
            OOM();
            xmlMemFree(ret);
            return 0 as *mut libc::c_void;
        }
    }
    return ret;
}
extern "C" fn myReallocFunc(
    mut mem: *mut core::ffi::c_void,
    mut size: u64,
) -> *mut core::ffi::c_void {
    let mut ret: *mut core::ffi::c_void = 0 as *mut libc::c_void;
    ret = xmlMemRealloc(mem, size);
    if !ret.is_null() {
        if xmlMemUsed() > (unsafe { maxmem }) {
            OOM();
            xmlMemFree(ret);
            return 0 as *mut libc::c_void;
        }
    }
    return ret;
}
extern "C" fn myStrdupFunc(mut str: *const i8) -> *mut i8 {
    let mut ret: *mut i8 = 0 as *mut i8;
    ret = xmlMemoryStrdup(str);
    if !ret.is_null() {
        if xmlMemUsed() > (unsafe { maxmem }) {
            OOM();
            (unsafe { xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void) });
            return 0 as *mut i8;
        }
    }
    return ret;
}
static mut begin: crate::src::xmllint::timeval = timeval {
    tv_sec: 0,
    tv_usec: 0,
};
static mut end: crate::src::xmllint::timeval = timeval {
    tv_sec: 0,
    tv_usec: 0,
};
extern "C" fn startTimer() {
    (unsafe { gettimeofday(&mut begin, 0 as *mut libc::c_void) });
}
unsafe extern "C" fn endTimer(mut fmt: *const i8, mut args: ...) {
    let mut msec: i64 = 0;
    let mut ap: core::ffi::VaListImpl;
    gettimeofday(&mut end, 0 as *mut libc::c_void);
    msec = end.tv_sec - begin.tv_sec;
    msec *= 1000 as i32 as i64;
    msec += (end.tv_usec - begin.tv_usec) / 1000 as i32 as i64;
    ap = args.clone();
    vfprintf(stderr, fmt, ap.as_va_list());
    fprintf(stderr, b" took %ld ms\n\0" as *const u8 as *const i8, msec);
}
static mut buffer: [i8; 50000] = [0; 50000];
extern "C" fn xmlHTMLEncodeSend() {
    let mut result: *mut i8 = 0 as *mut i8;
    (unsafe {
        memset(
            &mut *buffer.as_mut_ptr().offset(
                (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(4 as i32 as u64)
                    as isize,
            ) as *mut i8 as *mut libc::c_void,
            0 as i32,
            4 as i32 as u64,
        )
    });
    result = (unsafe {
        xmlEncodeEntitiesReentrant(0 as xmlDocPtr, buffer.as_mut_ptr() as *mut xmlChar)
    }) as *mut i8;
    if !result.is_null() {
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"%s\0" as *const u8 as *const i8,
                result,
            )
        });
        (unsafe { xmlFree.expect("non-null function pointer")(result as *mut libc::c_void) });
    }
    (unsafe { buffer[0 as i32 as usize] = 0 as i32 as i8 });
}
extern "C" fn xmlHTMLPrintFileInfo(mut input: *mut crate::src::threads::_xmlParserInput) {
    let mut len: i32 = 0;
    (unsafe {
        (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"<p>\0" as *const u8 as *const i8,
        )
    });
    len = (unsafe { strlen(buffer.as_mut_ptr()) }) as i32;
    if !input.is_null() {
        if !(unsafe { (*input).filename }).is_null() {
            (unsafe {
                snprintf(
                    &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
                    (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
                    b"%s:%d: \0" as *const u8 as *const i8,
                    (*input).filename,
                    (*input).line,
                )
            });
        } else {
            (unsafe {
                snprintf(
                    &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
                    (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
                    b"Entity: line %d: \0" as *const u8 as *const i8,
                    (*input).line,
                )
            });
        }
    }
    xmlHTMLEncodeSend();
}
extern "C" fn xmlHTMLPrintFileContext(mut input: *mut crate::src::threads::_xmlParserInput) {
    let mut cur: *const u8 = 0 as *const xmlChar;
    let mut base: *const u8 = 0 as *const xmlChar;
    let mut len: i32 = 0;
    let mut n: i32 = 0;
    if input.is_null() {
        return;
    }
    (unsafe {
        (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"<pre>\n\0" as *const u8 as *const i8,
        )
    });
    cur = unsafe { (*input).cur };
    base = unsafe { (*input).base };
    while cur > base
        && ((unsafe { *cur }) as i32 == '\n' as i32 || (unsafe { *cur }) as i32 == '\r' as i32)
    {
        cur = unsafe { cur.offset(-1) };
    }
    n = 0 as i32;
    loop {
        let mut fresh8 = n;
        n = n + 1;
        if !(fresh8 < 80 as i32
            && cur > base
            && (unsafe { *cur }) as i32 != '\n' as i32
            && (unsafe { *cur }) as i32 != '\r' as i32)
        {
            break;
        }
        cur = unsafe { cur.offset(-1) };
    }
    if (unsafe { *cur }) as i32 == '\n' as i32 || (unsafe { *cur }) as i32 == '\r' as i32 {
        cur = unsafe { cur.offset(1) };
    }
    base = cur;
    n = 0 as i32;
    while (unsafe { *cur }) as i32 != 0 as i32
        && (unsafe { *cur }) as i32 != '\n' as i32
        && (unsafe { *cur }) as i32 != '\r' as i32
        && n < 79 as i32
    {
        len = (unsafe { strlen(buffer.as_mut_ptr()) }) as i32;
        let mut fresh9 = cur;
        cur = unsafe { cur.offset(1) };
        (unsafe {
            snprintf(
                &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
                (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
                b"%c\0" as *const u8 as *const i8,
                *fresh9 as i32,
            )
        });
        n += 1;
    }
    len = (unsafe { strlen(buffer.as_mut_ptr()) }) as i32;
    (unsafe {
        snprintf(
            &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
            (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
            b"\n\0" as *const u8 as *const i8,
        )
    });
    cur = unsafe { (*input).cur };
    while (unsafe { *cur }) as i32 == '\n' as i32 || (unsafe { *cur }) as i32 == '\r' as i32 {
        cur = unsafe { cur.offset(-1) };
    }
    n = 0 as i32;
    while cur != base && {
        let mut fresh10 = n;
        n = n + 1;
        fresh10 < 80 as i32
    } {
        len = (unsafe { strlen(buffer.as_mut_ptr()) }) as i32;
        (unsafe {
            snprintf(
                &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
                (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
                b" \0" as *const u8 as *const i8,
            )
        });
        base = unsafe { base.offset(1) };
    }
    len = (unsafe { strlen(buffer.as_mut_ptr()) }) as i32;
    (unsafe {
        snprintf(
            &mut *buffer.as_mut_ptr().offset(len as isize) as *mut i8,
            (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
            b"^\n\0" as *const u8 as *const i8,
        )
    });
    xmlHTMLEncodeSend();
    (unsafe {
        (*__xmlGenericError()).expect("non-null function pointer")(
            *__xmlGenericErrorContext(),
            b"</pre>\0" as *const u8 as *const i8,
        )
    });
}
unsafe extern "C" fn xmlHTMLError(
    mut ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = ctx as xmlParserCtxtPtr;
    let mut input: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut args_0: core::ffi::VaListImpl;
    let mut len: i32 = 0;
    buffer[0 as i32 as usize] = 0 as i32 as i8;
    input = (*ctxt).input;
    if !input.is_null() && ((*input).filename).is_null() && (*ctxt).inputNr > 1 as i32 {
        input = *((*ctxt).inputTab).offset(((*ctxt).inputNr - 2 as i32) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"<b>error</b>: \0" as *const u8 as *const i8,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as i32;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"</p>\n\0" as *const u8 as *const i8,
    );
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlHTMLWarning(
    mut ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = ctx as xmlParserCtxtPtr;
    let mut input: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut args_0: core::ffi::VaListImpl;
    let mut len: i32 = 0;
    buffer[0 as i32 as usize] = 0 as i32 as i8;
    input = (*ctxt).input;
    if !input.is_null() && ((*input).filename).is_null() && (*ctxt).inputNr > 1 as i32 {
        input = *((*ctxt).inputTab).offset(((*ctxt).inputNr - 2 as i32) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"<b>warning</b>: \0" as *const u8 as *const i8,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as i32;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"</p>\n\0" as *const u8 as *const i8,
    );
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlHTMLValidityError(
    mut ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = ctx as xmlParserCtxtPtr;
    let mut input: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut args_0: core::ffi::VaListImpl;
    let mut len: i32 = 0;
    buffer[0 as i32 as usize] = 0 as i32 as i8;
    input = (*ctxt).input;
    if ((*input).filename).is_null() && (*ctxt).inputNr > 1 as i32 {
        input = *((*ctxt).inputTab).offset(((*ctxt).inputNr - 2 as i32) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"<b>validity error</b>: \0" as *const u8 as *const i8,
    );
    len = strlen(buffer.as_mut_ptr()) as i32;
    args_0 = args.clone();
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"</p>\n\0" as *const u8 as *const i8,
    );
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
    progresult = XMLLINT_ERR_VALID;
}
unsafe extern "C" fn xmlHTMLValidityWarning(
    mut ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = ctx as xmlParserCtxtPtr;
    let mut input: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut args_0: core::ffi::VaListImpl;
    let mut len: i32 = 0;
    buffer[0 as i32 as usize] = 0 as i32 as i8;
    input = (*ctxt).input;
    if ((*input).filename).is_null() && (*ctxt).inputNr > 1 as i32 {
        input = *((*ctxt).inputTab).offset(((*ctxt).inputNr - 2 as i32) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"<b>validity warning</b>: \0" as *const u8 as *const i8,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as i32;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[i8; 50000]>() as u64).wrapping_sub(len as u64),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError()).expect("non-null function pointer")(
        *__xmlGenericErrorContext(),
        b"</p>\n\0" as *const u8 as *const i8,
    );
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
extern "C" fn xmlShellReadline(mut prompt: *mut i8) -> *mut i8 {
    let mut line_read: [i8; 501] = [0; 501];
    let mut ret: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    if !prompt.is_null() {
        (unsafe { fprintf(stdout, b"%s\0" as *const u8 as *const i8, prompt) });
    }
    (unsafe { fflush(stdout) });
    if (unsafe { fgets(line_read.as_mut_ptr(), 500 as i32, stdin) }).is_null() {
        return 0 as *mut i8;
    }
    line_read[500 as i32 as usize] = 0 as i32 as i8;
    len = (unsafe { strlen(line_read.as_mut_ptr()) }) as i32;
    ret = (unsafe { malloc((len + 1 as i32) as u64) }) as *mut i8;
    if !ret.is_null() {
        (unsafe {
            memcpy(
                ret as *mut libc::c_void,
                line_read.as_mut_ptr() as *const libc::c_void,
                (len + 1 as i32) as u64,
            )
        });
    }
    return ret;
}
extern "C" fn myRead(mut f: *mut core::ffi::c_void, mut buf: *mut i8, mut len: i32) -> i32 {
    return (unsafe {
        fread(
            buf as *mut libc::c_void,
            1 as i32 as u64,
            len as u64,
            f as *mut FILE,
        )
    }) as i32;
}
extern "C" fn myClose(mut context: *mut core::ffi::c_void) -> i32 {
    let mut f: *mut crate::src::tree::_IO_FILE = context as *mut FILE;
    if f == (unsafe { stdin }) {
        return 0 as i32;
    }
    return unsafe { fclose(f) };
}
static mut emptySAXHandlerStruct: crate::src::tree::_xmlSAXHandler = {
    let mut init = _xmlSAXHandler {
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
        initialized: 0xdeedbeaf as u32,
        _private: 0 as *const libc::c_void as *mut libc::c_void,
        startElementNs: None,
        endElementNs: None,
        serror: None,
    };
    init
};
static mut emptySAXHandler: *mut crate::src::tree::_xmlSAXHandler =
    unsafe { &emptySAXHandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler };
static mut callbacks: i32 = 0;
extern "C" fn isStandaloneDebug(mut _ctx: *mut core::ffi::c_void) -> i32 {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as i32;
    }
    (unsafe { fprintf(stdout, b"SAX.isStandalone()\n\0" as *const u8 as *const i8) });
    return 0 as i32;
}
extern "C" fn hasInternalSubsetDebug(mut _ctx: *mut core::ffi::c_void) -> i32 {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as i32;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.hasInternalSubset()\n\0" as *const u8 as *const i8,
        )
    });
    return 0 as i32;
}
extern "C" fn hasExternalSubsetDebug(mut _ctx: *mut core::ffi::c_void) -> i32 {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as i32;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.hasExternalSubset()\n\0" as *const u8 as *const i8,
        )
    });
    return 0 as i32;
}
extern "C" fn internalSubsetDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut ExternalID: *const u8,
    mut SystemID: *const u8,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.internalSubset(%s,\0" as *const u8 as *const i8,
            name,
        )
    });
    if ExternalID.is_null() {
        (unsafe { fprintf(stdout, b" ,\0" as *const u8 as *const i8) });
    } else {
        (unsafe { fprintf(stdout, b" %s,\0" as *const u8 as *const i8, ExternalID) });
    }
    if SystemID.is_null() {
        (unsafe { fprintf(stdout, b" )\n\0" as *const u8 as *const i8) });
    } else {
        (unsafe { fprintf(stdout, b" %s)\n\0" as *const u8 as *const i8, SystemID) });
    };
}
extern "C" fn externalSubsetDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut ExternalID: *const u8,
    mut SystemID: *const u8,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.externalSubset(%s,\0" as *const u8 as *const i8,
            name,
        )
    });
    if ExternalID.is_null() {
        (unsafe { fprintf(stdout, b" ,\0" as *const u8 as *const i8) });
    } else {
        (unsafe { fprintf(stdout, b" %s,\0" as *const u8 as *const i8, ExternalID) });
    }
    if SystemID.is_null() {
        (unsafe { fprintf(stdout, b" )\n\0" as *const u8 as *const i8) });
    } else {
        (unsafe { fprintf(stdout, b" %s)\n\0" as *const u8 as *const i8, SystemID) });
    };
}
extern "C" fn resolveEntityDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut publicId: *const u8,
    mut systemId: *const u8,
) -> *mut crate::src::threads::_xmlParserInput {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as xmlParserInputPtr;
    }
    (unsafe { fprintf(stdout, b"SAX.resolveEntity(\0" as *const u8 as *const i8) });
    if !publicId.is_null() {
        (unsafe {
            fprintf(
                stdout,
                b"%s\0" as *const u8 as *const i8,
                publicId as *mut i8,
            )
        });
    } else {
        (unsafe { fprintf(stdout, b" \0" as *const u8 as *const i8) });
    }
    if !systemId.is_null() {
        (unsafe {
            fprintf(
                stdout,
                b", %s)\n\0" as *const u8 as *const i8,
                systemId as *mut i8,
            )
        });
    } else {
        (unsafe { fprintf(stdout, b", )\n\0" as *const u8 as *const i8) });
    }
    return 0 as xmlParserInputPtr;
}
extern "C" fn getEntityDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlEntity {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as xmlEntityPtr;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.getEntity(%s)\n\0" as *const u8 as *const i8,
            name,
        )
    });
    return 0 as xmlEntityPtr;
}
extern "C" fn getParameterEntityDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
) -> *mut crate::src::threads::_xmlEntity {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return 0 as xmlEntityPtr;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.getParameterEntity(%s)\n\0" as *const u8 as *const i8,
            name,
        )
    });
    return 0 as xmlEntityPtr;
}
extern "C" fn entityDeclDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut type_0: i32,
    mut publicId: *const u8,
    mut systemId: *const u8,
    mut content: *mut u8,
) {
    let mut nullstr: *const u8 = b"(null)\0" as *const u8 as *const i8 as *mut xmlChar;
    if publicId.is_null() {
        publicId = nullstr;
    }
    if systemId.is_null() {
        systemId = nullstr;
    }
    if content.is_null() {
        content = nullstr as *mut xmlChar;
    }
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.entityDecl(%s, %d, %s, %s, %s)\n\0" as *const u8 as *const i8,
            name,
            type_0,
            publicId,
            systemId,
            content,
        )
    });
}
extern "C" fn attributeDeclDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut elem: *const u8,
    mut name: *const u8,
    mut type_0: i32,
    mut def: i32,
    mut defaultValue: *const u8,
    mut tree: *mut crate::src::threads::_xmlEnumeration,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    if defaultValue.is_null() {
        (unsafe {
            fprintf(
                stdout,
                b"SAX.attributeDecl(%s, %s, %d, %d, NULL, ...)\n\0" as *const u8 as *const i8,
                elem,
                name,
                type_0,
                def,
            )
        });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b"SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n\0" as *const u8 as *const i8,
                elem,
                name,
                type_0,
                def,
                defaultValue,
            )
        });
    }
    xmlFreeEnumeration(tree);
}
extern "C" fn elementDeclDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut type_0: i32,
    mut _content: *mut crate::src::threads::_xmlElementContent,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.elementDecl(%s, %d, ...)\n\0" as *const u8 as *const i8,
            name,
            type_0,
        )
    });
}
extern "C" fn notationDeclDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut publicId: *const u8,
    mut systemId: *const u8,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.notationDecl(%s, %s, %s)\n\0" as *const u8 as *const i8,
            name as *mut i8,
            publicId as *mut i8,
            systemId as *mut i8,
        )
    });
}
extern "C" fn unparsedEntityDeclDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut publicId: *const u8,
    mut systemId: *const u8,
    mut notationName: *const u8,
) {
    let mut nullstr: *const u8 = b"(null)\0" as *const u8 as *const i8 as *mut xmlChar;
    if publicId.is_null() {
        publicId = nullstr;
    }
    if systemId.is_null() {
        systemId = nullstr;
    }
    if notationName.is_null() {
        notationName = nullstr;
    }
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.unparsedEntityDecl(%s, %s, %s, %s)\n\0" as *const u8 as *const i8,
            name as *mut i8,
            publicId as *mut i8,
            systemId as *mut i8,
            notationName as *mut i8,
        )
    });
}
extern "C" fn setDocumentLocatorDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut _loc: *mut crate::src::threads::_xmlSAXLocator,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.setDocumentLocator()\n\0" as *const u8 as *const i8,
        )
    });
}
extern "C" fn startDocumentDebug(mut _ctx: *mut core::ffi::c_void) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe { fprintf(stdout, b"SAX.startDocument()\n\0" as *const u8 as *const i8) });
}
extern "C" fn endDocumentDebug(mut _ctx: *mut core::ffi::c_void) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe { fprintf(stdout, b"SAX.endDocument()\n\0" as *const u8 as *const i8) });
}
extern "C" fn startElementDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut name: *const u8,
    mut atts: *mut *const u8,
) {
    let mut i: i32 = 0;
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.startElement(%s\0" as *const u8 as *const i8,
            name as *mut i8,
        )
    });
    if !atts.is_null() {
        i = 0 as i32;
        while !(unsafe { *atts.offset(i as isize) }).is_null() {
            let mut fresh11 = i;
            i = i + 1;
            (unsafe {
                fprintf(
                    stdout,
                    b", %s='\0" as *const u8 as *const i8,
                    *atts.offset(fresh11 as isize),
                )
            });
            if !(unsafe { *atts.offset(i as isize) }).is_null() {
                (unsafe {
                    fprintf(
                        stdout,
                        b"%s'\0" as *const u8 as *const i8,
                        *atts.offset(i as isize),
                    )
                });
            }
            i += 1;
        }
    }
    (unsafe { fprintf(stdout, b")\n\0" as *const u8 as *const i8) });
}
extern "C" fn endElementDebug(mut _ctx: *mut core::ffi::c_void, mut name: *const u8) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.endElement(%s)\n\0" as *const u8 as *const i8,
            name as *mut i8,
        )
    });
}
extern "C" fn charactersDebug(mut _ctx: *mut core::ffi::c_void, mut ch: *const u8, mut len: i32) {
    let mut out: [i8; 40] = [0; 40];
    let mut i: i32 = 0;
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    i = 0 as i32;
    while i < len && i < 30 as i32 {
        out[i as usize] = (unsafe { *ch.offset(i as isize) }) as i8;
        i += 1;
    }
    out[i as usize] = 0 as i32 as i8;
    (unsafe {
        fprintf(
            stdout,
            b"SAX.characters(%s, %d)\n\0" as *const u8 as *const i8,
            out.as_mut_ptr(),
            len,
        )
    });
}
extern "C" fn referenceDebug(mut _ctx: *mut core::ffi::c_void, mut name: *const u8) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.reference(%s)\n\0" as *const u8 as *const i8,
            name,
        )
    });
}
extern "C" fn ignorableWhitespaceDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut ch: *const u8,
    mut len: i32,
) {
    let mut out: [i8; 40] = [0; 40];
    let mut i: i32 = 0;
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    i = 0 as i32;
    while i < len && i < 30 as i32 {
        out[i as usize] = (unsafe { *ch.offset(i as isize) }) as i8;
        i += 1;
    }
    out[i as usize] = 0 as i32 as i8;
    (unsafe {
        fprintf(
            stdout,
            b"SAX.ignorableWhitespace(%s, %d)\n\0" as *const u8 as *const i8,
            out.as_mut_ptr(),
            len,
        )
    });
}
extern "C" fn processingInstructionDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut target: *const u8,
    mut data: *const u8,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    if !data.is_null() {
        (unsafe {
            fprintf(
                stdout,
                b"SAX.processingInstruction(%s, %s)\n\0" as *const u8 as *const i8,
                target as *mut i8,
                data as *mut i8,
            )
        });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b"SAX.processingInstruction(%s, NULL)\n\0" as *const u8 as *const i8,
                target as *mut i8,
            )
        });
    };
}
extern "C" fn cdataBlockDebug(mut _ctx: *mut core::ffi::c_void, mut value: *const u8, mut len: i32) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.pcdata(%.20s, %d)\n\0" as *const u8 as *const i8,
            value as *mut i8,
            len,
        )
    });
}
extern "C" fn commentDebug(mut _ctx: *mut core::ffi::c_void, mut value: *const u8) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.comment(%s)\n\0" as *const u8 as *const i8,
            value,
        )
    });
}
unsafe extern "C" fn warningDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut args_0: core::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.warning: \0" as *const u8 as *const i8);
    vfprintf(stdout, msg, args_0.as_va_list());
}
unsafe extern "C" fn errorDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut args_0: core::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.error: \0" as *const u8 as *const i8);
    vfprintf(stdout, msg, args_0.as_va_list());
}
unsafe extern "C" fn fatalErrorDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut msg: *const i8,
    mut args: ...
) {
    let mut args_0: core::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.fatalError: \0" as *const u8 as *const i8);
    vfprintf(stdout, msg, args_0.as_va_list());
}
static mut debugSAXHandlerStruct: crate::src::tree::_xmlSAXHandler =  {
    {
        let mut init = _xmlSAXHandler {
            internalSubset: Some(internalSubsetDebug),
            isStandalone: Some(isStandaloneDebug),
            hasInternalSubset: Some(hasInternalSubsetDebug),
            hasExternalSubset: Some(hasExternalSubsetDebug),
            resolveEntity: Some(resolveEntityDebug),
            getEntity: Some(getEntityDebug),
            entityDecl: Some(entityDeclDebug),
            notationDecl: Some(notationDeclDebug),
            attributeDecl: Some(attributeDeclDebug),
            elementDecl: Some(elementDeclDebug),
            unparsedEntityDecl: Some(unparsedEntityDeclDebug),
            setDocumentLocator: Some(setDocumentLocatorDebug),
            startDocument: Some(startDocumentDebug),
            endDocument: Some(endDocumentDebug),
            startElement: Some(startElementDebug),
            endElement: Some(endElementDebug),
            reference: Some(referenceDebug),
            characters: Some(charactersDebug),
            ignorableWhitespace: Some(ignorableWhitespaceDebug),
            processingInstruction: Some(processingInstructionDebug),
            comment: Some(commentDebug),
            warning: Some(warningDebug),
            error: Some(errorDebug),
            fatalError: Some(fatalErrorDebug),
            getParameterEntity: Some(getParameterEntityDebug),
            cdataBlock: Some(cdataBlockDebug),
            externalSubset: Some(externalSubsetDebug),
            initialized: 1 as i32 as u32,
            _private: 0 as *const libc::c_void as *mut libc::c_void,
            startElementNs: None,
            endElementNs: None,
            serror: None,
        };
        init
    }
};
#[no_mangle]
pub static mut debugSAXHandler: *mut crate::src::tree::_xmlSAXHandler =
    unsafe { &debugSAXHandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler };
extern "C" fn startElementNsDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut localname: *const u8,
    mut prefix: *const u8,
    mut URI: *const u8,
    mut nb_namespaces: i32,
    mut namespaces: *mut *const u8,
    mut nb_attributes: i32,
    mut nb_defaulted: i32,
    mut attributes: *mut *const u8,
) {
    let mut i: i32 = 0;
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.startElementNs(%s\0" as *const u8 as *const i8,
            localname as *mut i8,
        )
    });
    if prefix.is_null() {
        (unsafe { fprintf(stdout, b", NULL\0" as *const u8 as *const i8) });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b", %s\0" as *const u8 as *const i8,
                prefix as *mut i8,
            )
        });
    }
    if URI.is_null() {
        (unsafe { fprintf(stdout, b", NULL\0" as *const u8 as *const i8) });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b", '%s'\0" as *const u8 as *const i8,
                URI as *mut i8,
            )
        });
    }
    (unsafe { fprintf(stdout, b", %d\0" as *const u8 as *const i8, nb_namespaces) });
    if !namespaces.is_null() {
        i = 0 as i32;
        while i < nb_namespaces * 2 as i32 {
            (unsafe { fprintf(stdout, b", xmlns\0" as *const u8 as *const i8) });
            if !(unsafe { *namespaces.offset(i as isize) }).is_null() {
                (unsafe {
                    fprintf(
                        stdout,
                        b":%s\0" as *const u8 as *const i8,
                        *namespaces.offset(i as isize),
                    )
                });
            }
            i += 1;
            (unsafe {
                fprintf(
                    stdout,
                    b"='%s'\0" as *const u8 as *const i8,
                    *namespaces.offset(i as isize),
                )
            });
            i += 1;
        }
    }
    (unsafe {
        fprintf(
            stdout,
            b", %d, %d\0" as *const u8 as *const i8,
            nb_attributes,
            nb_defaulted,
        )
    });
    if !attributes.is_null() {
        i = 0 as i32;
        while i < nb_attributes * 5 as i32 {
            if !(unsafe { *attributes.offset((i + 1 as i32) as isize) }).is_null() {
                (unsafe {
                    fprintf(
                        stdout,
                        b", %s:%s='\0" as *const u8 as *const i8,
                        *attributes.offset((i + 1 as i32) as isize),
                        *attributes.offset(i as isize),
                    )
                });
            } else {
                (unsafe {
                    fprintf(
                        stdout,
                        b", %s='\0" as *const u8 as *const i8,
                        *attributes.offset(i as isize),
                    )
                });
            }
            (unsafe {
                fprintf(
                    stdout,
                    b"%.4s...', %d\0" as *const u8 as *const i8,
                    *attributes.offset((i + 3 as i32) as isize),
                    (*attributes.offset((i + 4 as i32) as isize))
                        .offset_from(*attributes.offset((i + 3 as i32) as isize))
                        as i64 as i32,
                )
            });
            i += 5 as i32;
        }
    }
    (unsafe { fprintf(stdout, b")\n\0" as *const u8 as *const i8) });
}
extern "C" fn endElementNsDebug(
    mut _ctx: *mut core::ffi::c_void,
    mut localname: *const u8,
    mut prefix: *const u8,
    mut URI: *const u8,
) {
    (unsafe { callbacks += 1 });
    if (unsafe { noout }) != 0 {
        return;
    }
    (unsafe {
        fprintf(
            stdout,
            b"SAX.endElementNs(%s\0" as *const u8 as *const i8,
            localname as *mut i8,
        )
    });
    if prefix.is_null() {
        (unsafe { fprintf(stdout, b", NULL\0" as *const u8 as *const i8) });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b", %s\0" as *const u8 as *const i8,
                prefix as *mut i8,
            )
        });
    }
    if URI.is_null() {
        (unsafe { fprintf(stdout, b", NULL)\n\0" as *const u8 as *const i8) });
    } else {
        (unsafe {
            fprintf(
                stdout,
                b", '%s')\n\0" as *const u8 as *const i8,
                URI as *mut i8,
            )
        });
    };
}
static mut debugSAX2HandlerStruct: crate::src::tree::_xmlSAXHandler =  {
    {
        let mut init = _xmlSAXHandler {
            internalSubset: Some(internalSubsetDebug),
            isStandalone: Some(isStandaloneDebug),
            hasInternalSubset: Some(hasInternalSubsetDebug),
            hasExternalSubset: Some(hasExternalSubsetDebug),
            resolveEntity: Some(resolveEntityDebug),
            getEntity: Some(getEntityDebug),
            entityDecl: Some(entityDeclDebug),
            notationDecl: Some(notationDeclDebug),
            attributeDecl: Some(attributeDeclDebug),
            elementDecl: Some(elementDeclDebug),
            unparsedEntityDecl: Some(unparsedEntityDeclDebug),
            setDocumentLocator: Some(setDocumentLocatorDebug),
            startDocument: Some(startDocumentDebug),
            endDocument: Some(endDocumentDebug),
            startElement: None,
            endElement: None,
            reference: Some(referenceDebug),
            characters: Some(charactersDebug),
            ignorableWhitespace: Some(ignorableWhitespaceDebug),
            processingInstruction: Some(processingInstructionDebug),
            comment: Some(commentDebug),
            warning: Some(warningDebug),
            error: Some(errorDebug),
            fatalError: Some(fatalErrorDebug),
            getParameterEntity: Some(getParameterEntityDebug),
            cdataBlock: Some(cdataBlockDebug),
            externalSubset: Some(externalSubsetDebug),
            initialized: 0xdeedbeaf as u32,
            _private: 0 as *const libc::c_void as *mut libc::c_void,
            startElementNs: Some(startElementNsDebug),
            endElementNs: Some(endElementNsDebug),
            serror: None,
        };
        init
    }
};
static mut debugSAX2Handler: *mut crate::src::tree::_xmlSAXHandler =
    unsafe { &debugSAX2HandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler };
extern "C" fn testSAX(mut filename: *const i8) {
    let mut handler: *mut crate::src::tree::_xmlSAXHandler = 0 as *mut xmlSAXHandler;
    let mut user_data: *const i8 = b"user_data\0" as *const u8 as *const i8;
    let mut buf: *mut crate::src::threads::_xmlParserInputBuffer = 0 as xmlParserInputBufferPtr;
    let mut inputStream: *mut crate::src::threads::_xmlParserInput = 0 as *mut xmlParserInput;
    let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
    let mut old_sax: *mut crate::src::tree::_xmlSAXHandler = 0 as xmlSAXHandlerPtr;
    (unsafe { callbacks = 0 as i32 });
    if (unsafe { noout }) != 0 {
        handler = unsafe { emptySAXHandler };
    } else if (unsafe { sax1 }) != 0 {
        handler = unsafe { debugSAXHandler };
    } else {
        handler = unsafe { debugSAX2Handler };
    }
    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if !buf.is_null() {
        if !(unsafe { wxschemas }).is_null() {
            let mut ret: i32 = 0;
            let mut vctxt: *mut crate::src::xmlschemas::_xmlSchemaValidCtxt<'_> =
                0 as *mut xmlSchemaValidCtxt;
            vctxt = xmlSchemaNewValidCtxt(unsafe { wxschemas });
            if vctxt.is_null() {
                (unsafe { progresult = XMLLINT_ERR_MEM });
                xmlFreeParserInputBuffer(buf);
            } else {
                xmlSchemaSetValidErrors(
                    vctxt,
                    unsafe { *__xmlGenericError() },
                    unsafe { *__xmlGenericError() },
                    0 as *mut libc::c_void,
                );
                xmlSchemaValidateSetFilename(vctxt, filename);
                ret = xmlSchemaValidateStream(
                    vctxt,
                    buf,
                    XML_CHAR_ENCODING_NONE,
                    handler,
                    user_data as *mut libc::c_void,
                );
                if (unsafe { repeat }) == 0 as i32 {
                    if ret == 0 as i32 {
                        if (unsafe { quiet }) == 0 {
                            (unsafe {
                                fprintf(
                                    stderr,
                                    b"%s validates\n\0" as *const u8 as *const i8,
                                    filename,
                                )
                            });
                        }
                    } else if ret > 0 as i32 {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"%s fails to validate\n\0" as *const u8 as *const i8,
                                filename,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_VALID });
                    } else {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"%s validation generated an internal error\n\0" as *const u8
                                    as *const i8,
                                filename,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_VALID });
                    }
                }
                xmlSchemaFreeValidCtxt(vctxt);
            }
        } else {
            ctxt = unsafe { xmlNewParserCtxt() };
            if ctxt.is_null() {
                (unsafe { progresult = XMLLINT_ERR_MEM });
                xmlFreeParserInputBuffer(buf);
            } else {
                old_sax = unsafe { (*ctxt).sax };
                let fresh12 = unsafe { &mut ((*ctxt).sax) };
                *fresh12 = handler;
                let fresh13 = unsafe { &mut ((*ctxt).userData) };
                *fresh13 = user_data as *mut libc::c_void;
                inputStream = unsafe { xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE) };
                if inputStream.is_null() {
                    xmlFreeParserInputBuffer(buf);
                } else {
                    (unsafe { inputPush(ctxt, inputStream) });
                    (unsafe { xmlParseDocument(ctxt) });
                    if !(unsafe { (*ctxt).myDoc }).is_null() {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"SAX generated a doc !\n\0" as *const u8 as *const i8,
                            )
                        });
                        xmlFreeDoc(unsafe { (*ctxt).myDoc });
                        let fresh14 = unsafe { &mut ((*ctxt).myDoc) };
                        *fresh14 = 0 as xmlDocPtr;
                    }
                }
            }
        }
    }
    if !ctxt.is_null() {
        let fresh15 = unsafe { &mut ((*ctxt).sax) };
        *fresh15 = old_sax;
        (unsafe { xmlFreeParserCtxt(ctxt) });
    }
}
extern "C" fn processNode<'a1>(mut reader: *mut crate::src::xmlreader::_xmlTextReader<'a1>) {
    let mut name: *const u8 = 0 as *const xmlChar;
    let mut value: *const u8 = 0 as *const xmlChar;
    let mut type_0: i32 = 0;
    let mut empty: i32 = 0;
    type_0 = xmlTextReaderNodeType(reader);
    empty = xmlTextReaderIsEmptyElement(reader);
    if (unsafe { debug }) != 0 {
        name = xmlTextReaderConstName(reader);
        if name.is_null() {
            name = b"--\0" as *const u8 as *const i8 as *mut xmlChar;
        }
        value = xmlTextReaderConstValue(reader);
        (unsafe {
            printf(
                b"%d %d %s %d %d\0" as *const u8 as *const i8,
                xmlTextReaderDepth(reader),
                type_0,
                name,
                empty,
                xmlTextReaderHasValue(reader),
            )
        });
        if value.is_null() {
            (unsafe { printf(b"\n\0" as *const u8 as *const i8) });
        } else {
            (unsafe { printf(b" %s\n\0" as *const u8 as *const i8, value) });
        }
    }
    if !(unsafe { patternc }).is_null() {
        let mut path: *mut u8 = 0 as *mut xmlChar;
        let mut match_0: i32 = -(1 as i32);
        if type_0 == XML_READER_TYPE_ELEMENT as i32 {
            match_0 = unsafe { xmlPatternMatch(patternc, xmlTextReaderCurrentNode(reader)) };
            if match_0 != 0 {
                path = xmlGetNodePath(xmlTextReaderCurrentNode(reader) as *const xmlNode);
                (unsafe {
                    printf(
                        b"Node %s matches pattern %s\n\0" as *const u8 as *const i8,
                        path,
                        pattern,
                    )
                });
            }
        }
        if !(unsafe { patstream }).is_null() {
            let mut ret: i32 = 0;
            if type_0 == XML_READER_TYPE_ELEMENT as i32 {
                ret = unsafe {
                    xmlStreamPush(
                        patstream,
                        xmlTextReaderConstLocalName(reader),
                        xmlTextReaderConstNamespaceUri(reader),
                    )
                };
                if ret < 0 as i32 {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"xmlStreamPush() failure\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { xmlFreeStreamCtxt(patstream) });
                    (unsafe { patstream = 0 as xmlStreamCtxtPtr });
                } else if ret != match_0 {
                    if path.is_null() {
                        path = xmlGetNodePath(xmlTextReaderCurrentNode(reader) as *const xmlNode);
                    }
                    (unsafe {
                        fprintf(
                            stderr,
                            b"xmlPatternMatch and xmlStreamPush disagree\n\0" as *const u8
                                as *const i8,
                        )
                    });
                    if !path.is_null() {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"  pattern %s node %s\n\0" as *const u8 as *const i8,
                                pattern,
                                path,
                            )
                        });
                    } else {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"  pattern %s node %s\n\0" as *const u8 as *const i8,
                                pattern,
                                xmlTextReaderConstName(reader),
                            )
                        });
                    }
                }
            }
            if type_0 == XML_READER_TYPE_END_ELEMENT as i32
                || type_0 == XML_READER_TYPE_ELEMENT as i32 && empty != 0
            {
                ret = unsafe { xmlStreamPop(patstream) };
                if ret < 0 as i32 {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"xmlStreamPop() failure\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { xmlFreeStreamCtxt(patstream) });
                    (unsafe { patstream = 0 as xmlStreamCtxtPtr });
                }
            }
        }
        if !path.is_null() {
            (unsafe { xmlFree.expect("non-null function pointer")(path as *mut libc::c_void) });
        }
    }
}
extern "C" fn streamFile(mut filename: *mut i8) {
    let mut reader: *mut crate::src::xmlreader::_xmlTextReader<'_> = 0 as *mut xmlTextReader;
    let mut ret: i32 = 0;
    let mut fd: i32 = -(1 as i32);
    let mut info: crate::src::xmlIO::stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    let mut base: *const i8 = 0 as *const i8;
    let mut input: *mut crate::src::threads::_xmlParserInputBuffer = 0 as xmlParserInputBufferPtr;
    if (unsafe { memory }) != 0 {
        if stat(filename, &mut info) < 0 as i32 {
            return;
        }
        fd = unsafe { open(filename, 0 as i32) };
        if fd < 0 as i32 {
            return;
        }
        base = (unsafe {
            mmap(
                0 as *mut libc::c_void,
                info.st_size as size_t,
                0x1 as i32,
                0x1 as i32,
                fd,
                0 as i32 as __off64_t,
            )
        }) as *const i8;
        if base == -(1 as i32) as *mut libc::c_void as *const i8 {
            (unsafe { close(fd) });
            (unsafe {
                fprintf(
                    stderr,
                    b"mmap failure for file %s\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_RDFILE });
            return;
        }
        reader = xmlReaderForMemory(
            base,
            info.st_size as i32,
            filename,
            0 as *const i8,
            unsafe { options },
        );
    } else {
        reader = xmlReaderForFile(filename, 0 as *const i8, unsafe { options });
    }
    if !(unsafe { pattern }).is_null() {
        (unsafe {
            patternc = xmlPatterncompile(
                pattern as *const xmlChar,
                0 as *mut xmlDict,
                0 as i32,
                0 as *mut *const xmlChar,
            )
        });
        if (unsafe { patternc }).is_null() {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Pattern %s failed to compile\n\0" as *const u8 as *const i8,
                    pattern,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_SCHEMAPAT });
            (unsafe { pattern = 0 as *const i8 });
        }
    }
    if !(unsafe { patternc }).is_null() {
        (unsafe { patstream = xmlPatternGetStreamCtxt(patternc) });
        if !(unsafe { patstream }).is_null() {
            ret = unsafe { xmlStreamPush(patstream, 0 as *const xmlChar, 0 as *const xmlChar) };
            if ret < 0 as i32 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"xmlStreamPush() failure\n\0" as *const u8 as *const i8,
                    )
                });
                (unsafe { xmlFreeStreamCtxt(patstream) });
                (unsafe { patstream = 0 as xmlStreamCtxtPtr });
            }
        }
    }
    if !reader.is_null() {
        if (unsafe { valid }) != 0 {
            xmlTextReaderSetParserProp(reader, XML_PARSER_VALIDATE as i32, 1 as i32);
        } else if (unsafe { loaddtd }) != 0 {
            xmlTextReaderSetParserProp(reader, XML_PARSER_LOADDTD as i32, 1 as i32);
        }
        if !(unsafe { relaxng }).is_null() {
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                startTimer();
            }
            ret = xmlTextReaderRelaxNGValidate(reader, unsafe { relaxng });
            if ret < 0 as i32 {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Relax-NG schema %s failed to compile\n\0" as *const u8 as *const i8,
                        relaxng,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_SCHEMACOMP });
                (unsafe { relaxng = 0 as *mut i8 });
            }
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                (unsafe { endTimer(b"Compiling the schemas\0" as *const u8 as *const i8) });
            }
        }
        if !(unsafe { schema }).is_null() {
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                startTimer();
            }
            ret = xmlTextReaderSchemaValidate(reader, unsafe { schema });
            if ret < 0 as i32 {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"XSD schema %s failed to compile\n\0" as *const u8 as *const i8,
                        schema,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_SCHEMACOMP });
                (unsafe { schema = 0 as *mut i8 });
            }
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                (unsafe { endTimer(b"Compiling the schemas\0" as *const u8 as *const i8) });
            }
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        ret = xmlTextReaderRead(reader);
        while ret == 1 as i32 {
            if (unsafe { debug }) != 0 || !(unsafe { patternc }).is_null() {
                processNode(reader);
            }
            ret = xmlTextReaderRead(reader);
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            if !(unsafe { relaxng }).is_null() {
                (unsafe { endTimer(b"Parsing and validating\0" as *const u8 as *const i8) });
            } else if (unsafe { valid }) != 0 {
                (unsafe { endTimer(b"Parsing and validating\0" as *const u8 as *const i8) });
            } else {
                (unsafe { endTimer(b"Parsing\0" as *const u8 as *const i8) });
            }
        }
        if (unsafe { valid }) != 0 {
            if xmlTextReaderIsValid(reader) != 1 as i32 {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Document %s does not validate\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_VALID });
            }
        }
        if !(unsafe { relaxng }).is_null() || !(unsafe { schema }).is_null() {
            if xmlTextReaderIsValid(reader) != 1 as i32 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"%s fails to validate\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_VALID });
            } else if (unsafe { quiet }) == 0 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"%s validates\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
            }
        }
        xmlFreeTextReader(reader);
        if ret != 0 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s : failed to parse\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_UNCLASS });
        }
    } else {
        (unsafe {
            fprintf(
                stderr,
                b"Unable to open %s\n\0" as *const u8 as *const i8,
                filename,
            )
        });
        (unsafe { progresult = XMLLINT_ERR_UNCLASS });
    }
    if !(unsafe { patstream }).is_null() {
        (unsafe { xmlFreeStreamCtxt(patstream) });
        (unsafe { patstream = 0 as xmlStreamCtxtPtr });
    }
    if (unsafe { memory }) != 0 {
        xmlFreeParserInputBuffer(input);
        (unsafe { munmap(base as *mut i8 as *mut libc::c_void, info.st_size as size_t) });
        (unsafe { close(fd) });
    }
}
extern "C" fn walkDoc(mut doc: *mut crate::src::threads::_xmlDoc) {
    let mut reader: *mut crate::src::xmlreader::_xmlTextReader<'_> = 0 as *mut xmlTextReader;
    let mut ret: i32 = 0;
    let mut root: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
    let mut namespaces: Option<
        crate::__laertes_array::CustomSlice<'static, *const u8, [*const u8; 22]>,
    > = Some(crate::__laertes_array::CustomSlice::new(
        [0 as *const xmlChar; 22],
    ));
    let mut i: i32 = 0;
    let mut ns: *mut crate::src::threads::_xmlNs = 0 as *mut xmlNs;
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    if root.is_null() {
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"Document does not have a root element\0" as *const u8 as *const i8,
            )
        });
        (unsafe { progresult = XMLLINT_ERR_UNCLASS });
        return;
    }
    ns = unsafe { (*root).nsDef };
    i = 0 as i32;
    while !ns.is_null() && i < 20 as i32 {
        let mut fresh16 = i;
        i = i + 1;
        (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
            (namespaces).as_mut().unwrap(),
            fresh16 as usize,
        )) = unsafe { (*ns).href };
        let mut fresh17 = i;
        i = i + 1;
        (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
            (namespaces).as_mut().unwrap(),
            fresh17 as usize,
        )) = unsafe { (*ns).prefix };
        ns = unsafe { (*ns).next };
    }
    let mut fresh18 = i;
    i = i + 1;
    (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
        (namespaces).as_mut().unwrap(),
        fresh18 as usize,
    )) = 0 as *const xmlChar;
    (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
        (namespaces).as_mut().unwrap(),
        i as usize,
    )) = 0 as *const xmlChar;
    if !(unsafe { pattern }).is_null() {
        (unsafe {
            patternc = xmlPatterncompile(
                pattern as *const xmlChar,
                (*doc).dict,
                0 as i32,
                &mut (*crate::__laertes_array::GetMut::<&mut _>::get_offset_mut(
                    namespaces.as_mut().unwrap(),
                    0 as i32 as isize,
                )),
            )
        });
        if (unsafe { patternc }).is_null() {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Pattern %s failed to compile\n\0" as *const u8 as *const i8,
                    pattern,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_SCHEMAPAT });
            (unsafe { pattern = 0 as *const i8 });
        }
    }
    if !(unsafe { patternc }).is_null() {
        (unsafe { patstream = xmlPatternGetStreamCtxt(patternc) });
        if !(unsafe { patstream }).is_null() {
            ret = unsafe { xmlStreamPush(patstream, 0 as *const xmlChar, 0 as *const xmlChar) };
            if ret < 0 as i32 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"xmlStreamPush() failure\n\0" as *const u8 as *const i8,
                    )
                });
                (unsafe { xmlFreeStreamCtxt(patstream) });
                (unsafe { patstream = 0 as xmlStreamCtxtPtr });
            }
        }
    }
    reader = xmlReaderWalker(doc);
    if !reader.is_null() {
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        ret = xmlTextReaderRead(reader);
        while ret == 1 as i32 {
            if (unsafe { debug }) != 0 || !(unsafe { patternc }).is_null() {
                processNode(reader);
            }
            ret = xmlTextReaderRead(reader);
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"walking through the doc\0" as *const u8 as *const i8) });
        }
        xmlFreeTextReader(reader);
        if ret != 0 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"failed to walk through the doc\n\0" as *const u8 as *const i8,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_UNCLASS });
        }
    } else {
        (unsafe {
            fprintf(
                stderr,
                b"Failed to crate a reader from the document\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { progresult = XMLLINT_ERR_UNCLASS });
    }
    if !(unsafe { patstream }).is_null() {
        (unsafe { xmlFreeStreamCtxt(patstream) });
        (unsafe { patstream = 0 as xmlStreamCtxtPtr });
    }
}
extern "C" fn doXPathDump(mut cur: *mut crate::src::xinclude::_xmlXPathObject) {
    match (unsafe { (*cur).type_0 }) as u32 {
        1 => {
            let mut i: i32 = 0;
            let mut node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            let mut buf: *mut crate::src::threads::_xmlOutputBuffer = 0 as *mut xmlOutputBuffer;
            if (unsafe { (*cur).nodesetval }).is_null()
                || (unsafe { (*(*cur).nodesetval).nodeNr }) <= 0 as i32
            {
                (unsafe { fprintf(stderr, b"XPath set is empty\n\0" as *const u8 as *const i8) });
                (unsafe { progresult = XMLLINT_ERR_XPATH });
            } else {
                buf =
                    xmlOutputBufferCreateFile(unsafe { stdout }, 0 as xmlCharEncodingHandlerPtr);
                if buf.is_null() {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"Out of memory for XPath\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { progresult = XMLLINT_ERR_MEM });
                    return;
                }
                i = 0 as i32;
                while i < (unsafe { (*(*cur).nodesetval).nodeNr }) {
                    node = unsafe { *((*(*cur).nodesetval).nodeTab).offset(i as isize) };
                    xmlNodeDumpOutput(
                        buf,
                        0 as xmlDocPtr,
                        node,
                        0 as i32,
                        0 as i32,
                        0 as *const i8,
                    );
                    xmlOutputBufferWrite(buf, 1 as i32, b"\n\0" as *const u8 as *const i8);
                    i += 1;
                }
                xmlOutputBufferClose(buf);
            }
        }
        2 => {
            if (unsafe { (*cur).boolval }) != 0 {
                (unsafe { printf(b"true\n\0" as *const u8 as *const i8) });
            } else {
                (unsafe { printf(b"false\n\0" as *const u8 as *const i8) });
            }
        }
        3 => match unsafe { xmlXPathIsInf((*cur).floatval) } {
            1 => {
                (unsafe { printf(b"Infinity\n\0" as *const u8 as *const i8) });
            }
            -1 => {
                (unsafe { printf(b"-Infinity\n\0" as *const u8 as *const i8) });
            }
            _ => {
                if (unsafe { xmlXPathIsNaN((*cur).floatval) }) != 0 {
                    (unsafe { printf(b"NaN\n\0" as *const u8 as *const i8) });
                } else {
                    (unsafe { printf(b"%0g\n\0" as *const u8 as *const i8, (*cur).floatval) });
                }
            }
        },
        4 => {
            (unsafe {
                printf(
                    b"%s\n\0" as *const u8 as *const i8,
                    (*cur).stringval as *const i8,
                )
            });
        }
        0 => {
            (unsafe {
                fprintf(
                    stderr,
                    b"XPath Object is uninitialized\n\0" as *const u8 as *const i8,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_XPATH });
        }
        _ => {
            (unsafe {
                fprintf(
                    stderr,
                    b"XPath object of unexpected type\n\0" as *const u8 as *const i8,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_XPATH });
        }
    };
}
extern "C" fn doXPathQuery(mut doc: *mut crate::src::threads::_xmlDoc, mut query: *const i8) {
    let mut ctxt: *mut crate::src::xinclude::_xmlXPathContext = 0 as *mut xmlXPathContext;
    let mut res: *mut crate::src::xinclude::_xmlXPathObject = 0 as *mut xmlXPathObject;
    ctxt = unsafe { xmlXPathNewContext(doc) };
    if ctxt.is_null() {
        (unsafe {
            fprintf(
                stderr,
                b"Out of memory for XPath\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { progresult = XMLLINT_ERR_MEM });
        return;
    }
    let fresh19 = unsafe { &mut ((*ctxt).node) };
    *fresh19 = doc as xmlNodePtr;
    res = unsafe { xmlXPathEval(query as *mut xmlChar, ctxt) };
    (unsafe { xmlXPathFreeContext(ctxt) });
    if res.is_null() {
        (unsafe {
            fprintf(
                stderr,
                b"XPath evaluation failure\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { progresult = XMLLINT_ERR_XPATH });
        return;
    }
    doXPathDump(res);
    (unsafe { xmlXPathFreeObject(res) });
}
extern "C" fn parseAndPrintFile(
    mut filename: *mut i8,
    mut rectxt: *mut crate::src::tree::_xmlParserCtxt,
) {
    let mut doc: *mut crate::src::threads::_xmlDoc = 0 as xmlDocPtr;
    let mut tmp: *mut crate::src::threads::_xmlDoc = 0 as *mut xmlDoc;
    if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
        startTimer();
    }
    if filename.is_null() {
        if (unsafe { generate }) != 0 {
            let mut n: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
            doc = xmlNewDoc(b"1.0\0" as *const u8 as *const i8 as *mut xmlChar);
            n = xmlNewDocNode(
                doc,
                0 as xmlNsPtr,
                b"info\0" as *const u8 as *const i8 as *mut xmlChar,
                0 as *const xmlChar,
            );
            xmlNodeSetContent(n, b"abc\0" as *const u8 as *const i8 as *mut xmlChar);
            xmlDocSetRootElement(doc, n);
        }
    } else if (unsafe { html }) != 0 && (unsafe { push }) != 0 {
        let mut f: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
        if (unsafe { *filename.offset(0 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *filename.offset(1 as i32 as isize) }) as i32 == 0 as i32
        {
            f = unsafe { stdin };
        } else {
            f = unsafe { fopen(filename, b"rb\0" as *const u8 as *const i8) };
        }
        if !f.is_null() {
            let mut res: i32 = 0;
            let mut chars: [i8; 4096] = [0; 4096];
            let mut ctxt: *mut crate::src::tree::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
            res = (unsafe {
                fread(
                    chars.as_mut_ptr() as *mut libc::c_void,
                    1 as i32 as u64,
                    4 as i32 as u64,
                    f,
                )
            }) as i32;
            if res > 0 as i32 {
                ctxt = unsafe {
                    htmlCreatePushParserCtxt(
                        0 as htmlSAXHandlerPtr,
                        0 as *mut libc::c_void,
                        chars.as_mut_ptr(),
                        res,
                        filename,
                        XML_CHAR_ENCODING_NONE,
                    )
                };
                if ctxt.is_null() {
                    (unsafe { progresult = XMLLINT_ERR_MEM });
                    if f != (unsafe { stdin }) {
                        (unsafe { fclose(f) });
                    }
                    return;
                }
                (unsafe { htmlCtxtUseOptions(ctxt, options) });
                loop {
                    res = (unsafe {
                        fread(
                            chars.as_mut_ptr() as *mut libc::c_void,
                            1 as i32 as u64,
                            pushsize as u64,
                            f,
                        )
                    }) as i32;
                    if !(res > 0 as i32) {
                        break;
                    }
                    (unsafe { htmlParseChunk(ctxt, chars.as_mut_ptr(), res, 0 as i32) });
                }
                (unsafe { htmlParseChunk(ctxt, chars.as_mut_ptr(), 0 as i32, 1 as i32) });
                doc = unsafe { (*ctxt).myDoc };
                (unsafe { htmlFreeParserCtxt(ctxt) });
            }
            if f != (unsafe { stdin }) {
                (unsafe { fclose(f) });
            }
        }
    } else if (unsafe { html }) != 0 && (unsafe { memory }) != 0 {
        let mut fd: i32 = 0;
        let mut info: crate::src::xmlIO::stat = stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            __glibc_reserved: [0; 3],
        };
        let mut base: *const i8 = 0 as *const i8;
        if stat(filename, &mut info) < 0 as i32 {
            return;
        }
        fd = unsafe { open(filename, 0 as i32) };
        if fd < 0 as i32 {
            return;
        }
        base = (unsafe {
            mmap(
                0 as *mut libc::c_void,
                info.st_size as size_t,
                0x1 as i32,
                0x1 as i32,
                fd,
                0 as i32 as __off64_t,
            )
        }) as *const i8;
        if base == -(1 as i32) as *mut libc::c_void as *const i8 {
            (unsafe { close(fd) });
            (unsafe {
                fprintf(
                    stderr,
                    b"mmap failure for file %s\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_RDFILE });
            return;
        }
        doc = unsafe {
            htmlReadMemory(
                base as *mut i8,
                info.st_size as i32,
                filename,
                0 as *const i8,
                options,
            )
        };
        (unsafe { munmap(base as *mut i8 as *mut libc::c_void, info.st_size as size_t) });
        (unsafe { close(fd) });
    } else if (unsafe { html }) != 0 {
        doc = unsafe { htmlReadFile(filename, 0 as *const i8, options) };
    } else if (unsafe { push }) != 0 {
        let mut f_0: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
        if (unsafe { *filename.offset(0 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *filename.offset(1 as i32 as isize) }) as i32 == 0 as i32
        {
            f_0 = unsafe { stdin };
        } else {
            f_0 = unsafe { fopen(filename, b"rb\0" as *const u8 as *const i8) };
        }
        if !f_0.is_null() {
            let mut ret: i32 = 0;
            let mut res_0: i32 = 0;
            let mut size: i32 = 1024 as i32;
            let mut chars_0: [i8; 1024] = [0; 1024];
            let mut ctxt_0: *mut crate::src::tree::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
            res_0 = (unsafe {
                fread(
                    chars_0.as_mut_ptr() as *mut libc::c_void,
                    1 as i32 as u64,
                    4 as i32 as u64,
                    f_0,
                )
            }) as i32;
            if res_0 > 0 as i32 {
                ctxt_0 = unsafe {
                    xmlCreatePushParserCtxt(
                        0 as xmlSAXHandlerPtr,
                        0 as *mut libc::c_void,
                        chars_0.as_mut_ptr(),
                        res_0,
                        filename,
                    )
                };
                if ctxt_0.is_null() {
                    (unsafe { progresult = XMLLINT_ERR_MEM });
                    if f_0 != (unsafe { stdin }) {
                        (unsafe { fclose(f_0) });
                    }
                    return;
                }
                (unsafe { xmlCtxtUseOptions(ctxt_0, options) });
                loop {
                    res_0 = (unsafe {
                        fread(
                            chars_0.as_mut_ptr() as *mut libc::c_void,
                            1 as i32 as u64,
                            size as u64,
                            f_0,
                        )
                    }) as i32;
                    if !(res_0 > 0 as i32) {
                        break;
                    }
                    (unsafe { xmlParseChunk(ctxt_0, chars_0.as_mut_ptr(), res_0, 0 as i32) });
                }
                (unsafe { xmlParseChunk(ctxt_0, chars_0.as_mut_ptr(), 0 as i32, 1 as i32) });
                doc = unsafe { (*ctxt_0).myDoc };
                ret = unsafe { (*ctxt_0).wellFormed };
                (unsafe { xmlFreeParserCtxt(ctxt_0) });
                if ret == 0 && (unsafe { recovery }) == 0 {
                    xmlFreeDoc(doc);
                    doc = 0 as xmlDocPtr;
                }
            }
            if f_0 != (unsafe { stdin }) {
                (unsafe { fclose(f_0) });
            }
        }
    } else if (unsafe { testIO }) != 0 {
        if (unsafe { *filename.offset(0 as i32 as isize) }) as i32 == '-' as i32
            && (unsafe { *filename.offset(1 as i32 as isize) }) as i32 == 0 as i32
        {
            doc = unsafe { xmlReadFd(0 as i32, 0 as *const i8, 0 as *const i8, options) };
        } else {
            let mut f_1: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
            f_1 = unsafe { fopen(filename, b"rb\0" as *const u8 as *const i8) };
            if !f_1.is_null() {
                if rectxt.is_null() {
                    doc = unsafe {
                        xmlReadIO(
                            Some(myRead),
                            Some(myClose),
                            f_1 as *mut libc::c_void,
                            filename,
                            0 as *const i8,
                            options,
                        )
                    };
                } else {
                    doc = unsafe {
                        xmlCtxtReadIO(
                            rectxt,
                            Some(myRead),
                            Some(myClose),
                            f_1 as *mut libc::c_void,
                            filename,
                            0 as *const i8,
                            options,
                        )
                    };
                }
            } else {
                doc = 0 as xmlDocPtr;
            }
        }
    } else if (unsafe { htmlout }) != 0 {
        let mut ctxt_1: *mut crate::src::tree::_xmlParserCtxt = 0 as *mut xmlParserCtxt;
        if rectxt.is_null() {
            ctxt_1 = unsafe { xmlNewParserCtxt() };
            if ctxt_1.is_null() {
                (unsafe { progresult = XMLLINT_ERR_MEM });
                return;
            }
        } else {
            ctxt_1 = rectxt;
        }
        let fresh20 = unsafe { &mut ((*(*ctxt_1).sax).error) };
        *fresh20 = Some(xmlHTMLError);
        let fresh21 = unsafe { &mut ((*(*ctxt_1).sax).warning) };
        *fresh21 = Some(xmlHTMLWarning);
        let fresh22 = unsafe { &mut ((*ctxt_1).vctxt.error) };
        *fresh22 = Some(xmlHTMLValidityError);
        let fresh23 = unsafe { &mut ((*ctxt_1).vctxt.warning) };
        *fresh23 = Some(xmlHTMLValidityWarning);
        doc = unsafe { xmlCtxtReadFile(ctxt_1, filename, 0 as *const i8, options) };
        if rectxt.is_null() {
            (unsafe { xmlFreeParserCtxt(ctxt_1) });
        }
    } else if (unsafe { memory }) != 0 {
        let mut fd_0: i32 = 0;
        let mut info_0: crate::src::xmlIO::stat = stat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctim: timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            __glibc_reserved: [0; 3],
        };
        let mut base_0: *const i8 = 0 as *const i8;
        if stat(filename, &mut info_0) < 0 as i32 {
            return;
        }
        fd_0 = unsafe { open(filename, 0 as i32) };
        if fd_0 < 0 as i32 {
            return;
        }
        base_0 = (unsafe {
            mmap(
                0 as *mut libc::c_void,
                info_0.st_size as size_t,
                0x1 as i32,
                0x1 as i32,
                fd_0,
                0 as i32 as __off64_t,
            )
        }) as *const i8;
        if base_0 == -(1 as i32) as *mut libc::c_void as *const i8 {
            (unsafe { close(fd_0) });
            (unsafe {
                fprintf(
                    stderr,
                    b"mmap failure for file %s\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_RDFILE });
            return;
        }
        if rectxt.is_null() {
            doc = unsafe {
                xmlReadMemory(
                    base_0 as *mut i8,
                    info_0.st_size as i32,
                    filename,
                    0 as *const i8,
                    options,
                )
            };
        } else {
            doc = unsafe {
                xmlCtxtReadMemory(
                    rectxt,
                    base_0 as *mut i8,
                    info_0.st_size as i32,
                    filename,
                    0 as *const i8,
                    options,
                )
            };
        }
        (unsafe {
            munmap(
                base_0 as *mut i8 as *mut libc::c_void,
                info_0.st_size as size_t,
            )
        });
        (unsafe { close(fd_0) });
    } else if (unsafe { valid }) != 0 {
        let mut ctxt_2: *mut crate::src::tree::_xmlParserCtxt = 0 as xmlParserCtxtPtr;
        if rectxt.is_null() {
            ctxt_2 = unsafe { xmlNewParserCtxt() };
            if ctxt_2.is_null() {
                (unsafe { progresult = XMLLINT_ERR_MEM });
                return;
            }
        } else {
            ctxt_2 = rectxt;
        }
        doc = unsafe { xmlCtxtReadFile(ctxt_2, filename, 0 as *const i8, options) };
        if (unsafe { (*ctxt_2).valid }) == 0 as i32 {
            (unsafe { progresult = XMLLINT_ERR_RDFILE });
        }
        if rectxt.is_null() {
            (unsafe { xmlFreeParserCtxt(ctxt_2) });
        }
    } else if !rectxt.is_null() {
        doc = unsafe { xmlCtxtReadFile(rectxt, filename, 0 as *const i8, options) };
    } else if (unsafe { sax1 }) != 0 {
        doc = unsafe { xmlParseFile(filename) };
    } else {
        doc = unsafe { xmlReadFile(filename, 0 as *const i8, options) };
    }
    if doc.is_null() {
        (unsafe { progresult = XMLLINT_ERR_UNCLASS });
        return;
    }
    if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
        (unsafe { endTimer(b"Parsing\0" as *const u8 as *const i8) });
    }
    if (unsafe { dropdtd }) != 0 {
        let mut dtd: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
        dtd = xmlGetIntSubset(doc as *const xmlDoc);
        if !dtd.is_null() {
            xmlUnlinkNode(dtd as xmlNodePtr);
            let fresh24 = unsafe { &mut ((*doc).intSubset) };
            *fresh24 = 0 as *mut _xmlDtd;
            xmlFreeDtd(dtd);
        }
    }
    if (unsafe { xinclude }) != 0 {
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        if xmlXIncludeProcessFlags(doc, unsafe { options }) < 0 as i32 {
            (unsafe { progresult = XMLLINT_ERR_UNCLASS });
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Xinclude processing\0" as *const u8 as *const i8) });
        }
    }
    if !(unsafe { xpathquery }).is_null() {
        doXPathQuery(doc, unsafe { xpathquery });
    }
    if (unsafe { shell }) != 0 {
        (unsafe { xmlXPathOrderDocElems(doc) });
        (unsafe { xmlShell(doc, filename, Some(xmlShellReadline), stdout) });
    }
    if (unsafe { copy }) != 0 {
        tmp = doc;
        if (unsafe { timing }) != 0 {
            startTimer();
        }
        doc = xmlCopyDoc(doc, 1 as i32);
        if (unsafe { timing }) != 0 {
            (unsafe { endTimer(b"Copying\0" as *const u8 as *const i8) });
        }
        if (unsafe { timing }) != 0 {
            startTimer();
        }
        xmlFreeDoc(tmp);
        if (unsafe { timing }) != 0 {
            (unsafe { endTimer(b"Freeing original\0" as *const u8 as *const i8) });
        }
    }
    if (unsafe { insert }) != 0 && (unsafe { html }) == 0 {
        let mut list: Option<
            crate::__laertes_array::CustomSlice<'static, *const u8, [*const u8; 256]>,
        > = Some(crate::__laertes_array::CustomSlice::new(
            [0 as *const xmlChar; 256],
        ));
        let mut nb: i32 = 0;
        let mut i: i32 = 0;
        let mut node: *mut crate::src::threads::_xmlNode = 0 as *mut xmlNode;
        if !(unsafe { (*doc).children }).is_null() {
            node = unsafe { (*doc).children };
            while !node.is_null() && (unsafe { (*node).last }).is_null() {
                node = unsafe { (*node).next };
            }
            if !node.is_null() {
                nb = xmlValidGetValidElements(
                    unsafe { (*node).last },
                    0 as *mut xmlNode,
                    Some(crate::__laertes_array::SliceMut::slice_add_mut(
                        list.as_mut().unwrap(),
                        0,
                    )),
                    256 as i32,
                );
                if nb < 0 as i32 {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"could not get valid list of elements\n\0" as *const u8 as *const i8,
                        )
                    });
                } else if nb == 0 as i32 {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"No element can be inserted under root\n\0" as *const u8 as *const i8,
                        )
                    });
                } else {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"%d element types can be inserted under root:\n\0" as *const u8
                                as *const i8,
                            nb,
                        )
                    });
                    i = 0 as i32;
                    while i < nb {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"%s\n\0" as *const u8 as *const i8,
                                (*crate::__laertes_array::GetMut::<&mut _>::get_add_mut(
                                    (list).as_mut().unwrap(),
                                    i as usize,
                                )) as *mut i8,
                            )
                        });
                        i += 1;
                    }
                }
            }
        }
    } else if (unsafe { walker }) != 0 {
        walkDoc(doc);
    }
    if (unsafe { noout }) == 0 as i32 {
        let mut ret_0: i32 = 0;
        if (unsafe { debug }) == 0 {
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                startTimer();
            }
            if (unsafe { html }) != 0 && (unsafe { xmlout }) == 0 {
                if (unsafe { compress }) != 0 {
                    (unsafe {
                        htmlSaveFile(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const i8
                            },
                            doc,
                        )
                    });
                } else if !(unsafe { encoding }).is_null() {
                    if (unsafe { format }) == 1 as i32 {
                        (unsafe {
                            htmlSaveFileFormat(
                                if !output.is_null() {
                                    output
                                } else {
                                    b"-\0" as *const u8 as *const i8
                                },
                                doc,
                                encoding,
                                1 as i32,
                            )
                        });
                    } else {
                        (unsafe {
                            htmlSaveFileFormat(
                                if !output.is_null() {
                                    output
                                } else {
                                    b"-\0" as *const u8 as *const i8
                                },
                                doc,
                                encoding,
                                0 as i32,
                            )
                        });
                    }
                } else if (unsafe { format }) == 1 as i32 {
                    (unsafe {
                        htmlSaveFileFormat(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const i8
                            },
                            doc,
                            0 as *const i8,
                            1 as i32,
                        )
                    });
                } else {
                    let mut out: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
                    if (unsafe { output }).is_null() {
                        out = unsafe { stdout };
                    } else {
                        out = unsafe { fopen(output, b"wb\0" as *const u8 as *const i8) };
                    }
                    if !out.is_null() {
                        if (unsafe { htmlDocDump(out, doc) }) < 0 as i32 {
                            (unsafe { progresult = XMLLINT_ERR_OUT });
                        }
                        if !(unsafe { output }).is_null() {
                            (unsafe { fclose(out) });
                        }
                    } else {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"failed to open %s\n\0" as *const u8 as *const i8,
                                output,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_OUT });
                    }
                }
                if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                    (unsafe { endTimer(b"Saving\0" as *const u8 as *const i8) });
                }
            } else if (unsafe { canonical }) != 0 {
                let mut result: *mut u8 = 0 as *mut xmlChar;
                let mut size_0: i32 = 0;
                let prefix_0: *mut *mut u8 = 0 as *mut *mut xmlChar;
                size_0 = unsafe {
                    xmlC14NDocDumpMemory(
                        doc,
                        0 as xmlNodeSetPtr,
                        XML_C14N_1_0 as i32,
                        prefix_0,
                        1 as i32,
                        &mut result,
                    )
                };
                if size_0 >= 0 as i32 {
                    if (unsafe { write(1 as i32, result as *const libc::c_void, size_0 as size_t) })
                        == -(1 as i32) as i64
                    {
                        (unsafe {
                            fprintf(stderr, b"Can't write data\n\0" as *const u8 as *const i8)
                        });
                    }
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(result as *mut libc::c_void)
                    });
                } else {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"Failed to canonicalize\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { progresult = XMLLINT_ERR_OUT });
                }
            } else if (unsafe { canonical_11 }) != 0 {
                let mut result_0: *mut u8 = 0 as *mut xmlChar;
                let mut size_1: i32 = 0;
                let prefix_1: *mut *mut u8 = 0 as *mut *mut xmlChar;
                size_1 = unsafe {
                    xmlC14NDocDumpMemory(
                        doc,
                        0 as xmlNodeSetPtr,
                        XML_C14N_1_1 as i32,
                        prefix_1,
                        1 as i32,
                        &mut result_0,
                    )
                };
                if size_1 >= 0 as i32 {
                    if (unsafe {
                        write(1 as i32, result_0 as *const libc::c_void, size_1 as size_t)
                    }) == -(1 as i32) as i64
                    {
                        (unsafe {
                            fprintf(stderr, b"Can't write data\n\0" as *const u8 as *const i8)
                        });
                    }
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(result_0 as *mut libc::c_void)
                    });
                } else {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"Failed to canonicalize\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { progresult = XMLLINT_ERR_OUT });
                }
            } else if (unsafe { exc_canonical }) != 0 {
                let mut result_1: *mut u8 = 0 as *mut xmlChar;
                let mut size_2: i32 = 0;
                let prefix_2: *mut *mut u8 = 0 as *mut *mut xmlChar;
                size_2 = unsafe {
                    xmlC14NDocDumpMemory(
                        doc,
                        0 as xmlNodeSetPtr,
                        XML_C14N_EXCLUSIVE_1_0 as i32,
                        prefix_2,
                        1 as i32,
                        &mut result_1,
                    )
                };
                if size_2 >= 0 as i32 {
                    if (unsafe {
                        write(1 as i32, result_1 as *const libc::c_void, size_2 as size_t)
                    }) == -(1 as i32) as i64
                    {
                        (unsafe {
                            fprintf(stderr, b"Can't write data\n\0" as *const u8 as *const i8)
                        });
                    }
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(result_1 as *mut libc::c_void)
                    });
                } else {
                    (unsafe {
                        fprintf(
                            stderr,
                            b"Failed to canonicalize\n\0" as *const u8 as *const i8,
                        )
                    });
                    (unsafe { progresult = XMLLINT_ERR_OUT });
                }
            } else if (unsafe { memory }) != 0 {
                let mut result_2: *mut u8 = 0 as *mut xmlChar;
                let mut len: i32 = 0;
                if !(unsafe { encoding }).is_null() {
                    if (unsafe { format }) == 1 as i32 {
                        xmlDocDumpFormatMemoryEnc(
                            doc,
                            Some(&mut result_2),
                            &mut len,
                            unsafe { encoding },
                            1 as i32,
                        );
                    } else {
                        xmlDocDumpMemoryEnc(
                            doc,
                            Some(&mut result_2),
                            &mut len,
                            unsafe { encoding },
                        );
                    }
                } else if (unsafe { format }) == 1 as i32 {
                    xmlDocDumpFormatMemory(doc, Some(&mut result_2), &mut len, 1 as i32);
                } else {
                    xmlDocDumpMemory(doc, Some(&mut result_2), &mut len);
                }
                if result_2.is_null() {
                    (unsafe { fprintf(stderr, b"Failed to save\n\0" as *const u8 as *const i8) });
                    (unsafe { progresult = XMLLINT_ERR_OUT });
                } else {
                    if (unsafe { write(1 as i32, result_2 as *const libc::c_void, len as size_t) })
                        == -(1 as i32) as i64
                    {
                        (unsafe {
                            fprintf(stderr, b"Can't write data\n\0" as *const u8 as *const i8)
                        });
                    }
                    (unsafe {
                        xmlFree.expect("non-null function pointer")(result_2 as *mut libc::c_void)
                    });
                }
            } else if (unsafe { compress }) != 0 {
                xmlSaveFile(
                    if !(unsafe { output }).is_null() {
                        unsafe { output }
                    } else {
                        b"-\0" as *const u8 as *const i8
                    },
                    doc,
                );
            } else if (unsafe { oldout }) != 0 {
                if !(unsafe { encoding }).is_null() {
                    if (unsafe { format }) == 1 as i32 {
                        ret_0 = xmlSaveFormatFileEnc(
                            if !(unsafe { output }).is_null() {
                                unsafe { output }
                            } else {
                                b"-\0" as *const u8 as *const i8
                            },
                            doc,
                            unsafe { encoding },
                            1 as i32,
                        );
                    } else {
                        ret_0 = xmlSaveFileEnc(
                            if !(unsafe { output }).is_null() {
                                unsafe { output }
                            } else {
                                b"-\0" as *const u8 as *const i8
                            },
                            doc,
                            unsafe { encoding },
                        );
                    }
                    if ret_0 < 0 as i32 {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"failed save to %s\n\0" as *const u8 as *const i8,
                                if !output.is_null() {
                                    output
                                } else {
                                    b"-\0" as *const u8 as *const i8
                                },
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_OUT });
                    }
                } else if (unsafe { format }) == 1 as i32 {
                    ret_0 = xmlSaveFormatFile(
                        if !(unsafe { output }).is_null() {
                            unsafe { output }
                        } else {
                            b"-\0" as *const u8 as *const i8
                        },
                        doc,
                        1 as i32,
                    );
                    if ret_0 < 0 as i32 {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"failed save to %s\n\0" as *const u8 as *const i8,
                                if !output.is_null() {
                                    output
                                } else {
                                    b"-\0" as *const u8 as *const i8
                                },
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_OUT });
                    }
                } else {
                    let mut out_0: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
                    if (unsafe { output }).is_null() {
                        out_0 = unsafe { stdout };
                    } else {
                        out_0 = unsafe { fopen(output, b"wb\0" as *const u8 as *const i8) };
                    }
                    if !out_0.is_null() {
                        if xmlDocDump(out_0, doc) < 0 as i32 {
                            (unsafe { progresult = XMLLINT_ERR_OUT });
                        }
                        if !(unsafe { output }).is_null() {
                            (unsafe { fclose(out_0) });
                        }
                    } else {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"failed to open %s\n\0" as *const u8 as *const i8,
                                output,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_OUT });
                    }
                }
            } else {
                let mut ctxt_3: *mut crate::src::xmlsave::_xmlSaveCtxt<'_> = 0 as *mut xmlSaveCtxt;
                let mut saveOpts: i32 = 0 as i32;
                if (unsafe { format }) == 1 as i32 {
                    saveOpts |= XML_SAVE_FORMAT as i32;
                } else if (unsafe { format }) == 2 as i32 {
                    saveOpts |= XML_SAVE_WSNONSIG as i32;
                }
                if (unsafe { xmlout }) != 0 {
                    saveOpts |= XML_SAVE_AS_XML as i32;
                }
                if (unsafe { output }).is_null() {
                    ctxt_3 = xmlSaveToFd(1 as i32, unsafe { encoding }, saveOpts);
                } else {
                    ctxt_3 =
                        xmlSaveToFilename(unsafe { output }, unsafe { encoding }, saveOpts);
                }
                if !ctxt_3.is_null() {
                    if xmlSaveDoc(ctxt_3, doc) < 0 as i32 as i64 {
                        (unsafe {
                            fprintf(
                                stderr,
                                b"failed save to %s\n\0" as *const u8 as *const i8,
                                if !output.is_null() {
                                    output
                                } else {
                                    b"-\0" as *const u8 as *const i8
                                },
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_OUT });
                    }
                    xmlSaveClose(ctxt_3);
                } else {
                    (unsafe { progresult = XMLLINT_ERR_OUT });
                }
            }
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                (unsafe { endTimer(b"Saving\0" as *const u8 as *const i8) });
            }
        } else {
            let mut out_1: *mut crate::src::tree::_IO_FILE = 0 as *mut FILE;
            if (unsafe { output }).is_null() {
                out_1 = unsafe { stdout };
            } else {
                out_1 = unsafe { fopen(output, b"wb\0" as *const u8 as *const i8) };
            }
            if !out_1.is_null() {
                (unsafe { xmlDebugDumpDocument(out_1, doc) });
                if !(unsafe { output }).is_null() {
                    (unsafe { fclose(out_1) });
                }
            } else {
                (unsafe {
                    fprintf(
                        stderr,
                        b"failed to open %s\n\0" as *const u8 as *const i8,
                        output,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_OUT });
            }
        }
    }
    if !(unsafe { dtdvalid }).is_null() || !(unsafe { dtdvalidfpi }).is_null() {
        let mut dtd_0: *mut crate::src::threads::_xmlDtd = 0 as *mut xmlDtd;
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        if !(unsafe { dtdvalid }).is_null() {
            dtd_0 = unsafe { xmlParseDTD(0 as *const xmlChar, dtdvalid as *const xmlChar) };
        } else {
            dtd_0 = unsafe { xmlParseDTD(dtdvalidfpi as *const xmlChar, 0 as *const xmlChar) };
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Parsing DTD\0" as *const u8 as *const i8) });
        }
        if dtd_0.is_null() {
            if !(unsafe { dtdvalid }).is_null() {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Could not parse DTD %s\n\0" as *const u8 as *const i8,
                        dtdvalid,
                    )
                });
            } else {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Could not parse DTD %s\n\0" as *const u8 as *const i8,
                        dtdvalidfpi,
                    )
                });
            }
            (unsafe { progresult = XMLLINT_ERR_DTD });
        } else {
            let mut cvp: *mut crate::src::tree::_xmlValidCtxt = 0 as *mut xmlValidCtxt;
            cvp = xmlNewValidCtxt();
            if cvp.is_null() {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Couldn't allocate validation context\n\0" as *const u8 as *const i8,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_MEM });
                xmlFreeDtd(dtd_0);
                return;
            }
            let fresh25 = unsafe { &mut ((*cvp).userData) };
            *fresh25 = 0 as *mut libc::c_void;
            let fresh26 = unsafe { &mut ((*cvp).error) };
            *fresh26 = unsafe { *__xmlGenericError() };
            let fresh27 = unsafe { &mut ((*cvp).warning) };
            *fresh27 = unsafe { *__xmlGenericError() };
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                startTimer();
            }
            if xmlValidateDtd(cvp, doc, dtd_0) == 0 {
                if !(unsafe { dtdvalid }).is_null() {
                    (unsafe {
                        (*__xmlGenericError()).expect("non-null function pointer")(
                            *__xmlGenericErrorContext(),
                            b"Document %s does not validate against %s\n\0" as *const u8
                                as *const i8,
                            filename,
                            dtdvalid,
                        )
                    });
                } else {
                    (unsafe {
                        (*__xmlGenericError()).expect("non-null function pointer")(
                            *__xmlGenericErrorContext(),
                            b"Document %s does not validate against %s\n\0" as *const u8
                                as *const i8,
                            filename,
                            dtdvalidfpi,
                        )
                    });
                }
                (unsafe { progresult = XMLLINT_ERR_VALID });
            }
            if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
                (unsafe { endTimer(b"Validating against DTD\0" as *const u8 as *const i8) });
            }
            xmlFreeValidCtxt(cvp);
            xmlFreeDtd(dtd_0);
        }
    } else if (unsafe { postvalid }) != 0 {
        let mut cvp_0: *mut crate::src::tree::_xmlValidCtxt = 0 as *mut xmlValidCtxt;
        cvp_0 = xmlNewValidCtxt();
        if cvp_0.is_null() {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Couldn't allocate validation context\n\0" as *const u8 as *const i8,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_MEM });
            xmlFreeDoc(doc);
            return;
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        let fresh28 = unsafe { &mut ((*cvp_0).userData) };
        *fresh28 = 0 as *mut libc::c_void;
        let fresh29 = unsafe { &mut ((*cvp_0).error) };
        *fresh29 = unsafe { *__xmlGenericError() };
        let fresh30 = unsafe { &mut ((*cvp_0).warning) };
        *fresh30 = unsafe { *__xmlGenericError() };
        if xmlValidateDocument(cvp_0, doc) == 0 {
            (unsafe {
                (*__xmlGenericError()).expect("non-null function pointer")(
                    *__xmlGenericErrorContext(),
                    b"Document %s does not validate\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        }
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Validating\0" as *const u8 as *const i8) });
        }
        xmlFreeValidCtxt(cvp_0);
    }
    if !(unsafe { wxschematron }).is_null() {
        let mut ctxt_4: *mut crate::src::xmllint::_xmlSchematronValidCtxt =
            0 as *mut xmlSchematronValidCtxt;
        let mut ret_1: i32 = 0;
        let mut flag: i32 = 0;
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        if (unsafe { debug }) != 0 {
            flag = XML_SCHEMATRON_OUT_XML as i32;
        } else {
            flag = XML_SCHEMATRON_OUT_TEXT as i32;
        }
        if (unsafe { noout }) != 0 {
            flag |= XML_SCHEMATRON_OUT_QUIET as i32;
        }
        ctxt_4 = unsafe { xmlSchematronNewValidCtxt(wxschematron, flag) };
        if ctxt_4.is_null() {
            (unsafe { progresult = XMLLINT_ERR_MEM });
            xmlFreeDoc(doc);
            return;
        }
        ret_1 = unsafe { xmlSchematronValidateDoc(ctxt_4, doc) };
        if ret_1 == 0 as i32 {
            if (unsafe { quiet }) == 0 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"%s validates\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
            }
        } else if ret_1 > 0 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s fails to validate\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        } else {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s validation generated an internal error\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        }
        (unsafe { xmlSchematronFreeValidCtxt(ctxt_4) });
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Validating\0" as *const u8 as *const i8) });
        }
    }
    if !(unsafe { relaxngschemas }).is_null() {
        let mut ctxt_5: *mut crate::src::xmllint::_xmlRelaxNGValidCtxt =
            0 as *mut xmlRelaxNGValidCtxt;
        let mut ret_2: i32 = 0;
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        ctxt_5 = unsafe { xmlRelaxNGNewValidCtxt(relaxngschemas) };
        if ctxt_5.is_null() {
            (unsafe { progresult = XMLLINT_ERR_MEM });
            xmlFreeDoc(doc);
            return;
        }
        (unsafe {
            xmlRelaxNGSetValidErrors(
                ctxt_5,
                *__xmlGenericError(),
                *__xmlGenericError(),
                0 as *mut libc::c_void,
            )
        });
        ret_2 = unsafe { xmlRelaxNGValidateDoc(ctxt_5, doc) };
        if ret_2 == 0 as i32 {
            if (unsafe { quiet }) == 0 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"%s validates\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
            }
        } else if ret_2 > 0 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s fails to validate\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        } else {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s validation generated an internal error\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        }
        (unsafe { xmlRelaxNGFreeValidCtxt(ctxt_5) });
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Validating\0" as *const u8 as *const i8) });
        }
    } else if !(unsafe { wxschemas }).is_null() {
        let mut ctxt_6: *mut crate::src::xmlschemas::_xmlSchemaValidCtxt<'_> =
            0 as *mut xmlSchemaValidCtxt;
        let mut ret_3: i32 = 0;
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            startTimer();
        }
        ctxt_6 = xmlSchemaNewValidCtxt(unsafe { wxschemas });
        if ctxt_6.is_null() {
            (unsafe { progresult = XMLLINT_ERR_MEM });
            xmlFreeDoc(doc);
            return;
        }
        xmlSchemaSetValidErrors(
            ctxt_6,
            unsafe { *__xmlGenericError() },
            unsafe { *__xmlGenericError() },
            0 as *mut libc::c_void,
        );
        ret_3 = xmlSchemaValidateDoc(ctxt_6, doc);
        if ret_3 == 0 as i32 {
            if (unsafe { quiet }) == 0 {
                (unsafe {
                    fprintf(
                        stderr,
                        b"%s validates\n\0" as *const u8 as *const i8,
                        filename,
                    )
                });
            }
        } else if ret_3 > 0 as i32 {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s fails to validate\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        } else {
            (unsafe {
                fprintf(
                    stderr,
                    b"%s validation generated an internal error\n\0" as *const u8 as *const i8,
                    filename,
                )
            });
            (unsafe { progresult = XMLLINT_ERR_VALID });
        }
        xmlSchemaFreeValidCtxt(ctxt_6);
        if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
            (unsafe { endTimer(b"Validating\0" as *const u8 as *const i8) });
        }
    }
    if (unsafe { debugent }) != 0 && (unsafe { html }) == 0 {
        (unsafe { xmlDebugDumpEntities(stderr, doc) });
    }
    if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
        startTimer();
    }
    xmlFreeDoc(doc);
    if (unsafe { timing }) != 0 && (unsafe { repeat }) == 0 {
        (unsafe { endTimer(b"Freeing\0" as *const u8 as *const i8) });
    }
}
extern "C" fn showVersion(mut name: *const i8) {
    (unsafe {
        fprintf(
            stderr,
            b"%s: using libxml version %s\n\0" as *const u8 as *const i8,
            name,
            *__xmlParserVersion(),
        )
    });
    (unsafe { fprintf(stderr, b"   compiled with: \0" as *const u8 as *const i8) });
    if (unsafe { xmlHasFeature(XML_WITH_THREAD) }) != 0 {
        (unsafe { fprintf(stderr, b"Threads \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_TREE) }) != 0 {
        (unsafe { fprintf(stderr, b"Tree \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_OUTPUT) }) != 0 {
        (unsafe { fprintf(stderr, b"Output \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_PUSH) }) != 0 {
        (unsafe { fprintf(stderr, b"Push \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_READER) }) != 0 {
        (unsafe { fprintf(stderr, b"Reader \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_PATTERN) }) != 0 {
        (unsafe { fprintf(stderr, b"Patterns \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_WRITER) }) != 0 {
        (unsafe { fprintf(stderr, b"Writer \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_SAX1) }) != 0 {
        (unsafe { fprintf(stderr, b"SAXv1 \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_FTP) }) != 0 {
        (unsafe { fprintf(stderr, b"FTP \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_HTTP) }) != 0 {
        (unsafe { fprintf(stderr, b"HTTP \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_VALID) }) != 0 {
        (unsafe { fprintf(stderr, b"DTDValid \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_HTML) }) != 0 {
        (unsafe { fprintf(stderr, b"HTML \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_LEGACY) }) != 0 {
        (unsafe { fprintf(stderr, b"Legacy \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_C14N) }) != 0 {
        (unsafe { fprintf(stderr, b"C14N \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_CATALOG) }) != 0 {
        (unsafe { fprintf(stderr, b"Catalog \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_XPATH) }) != 0 {
        (unsafe { fprintf(stderr, b"XPath \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_XPTR) }) != 0 {
        (unsafe { fprintf(stderr, b"XPointer \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_XINCLUDE) }) != 0 {
        (unsafe { fprintf(stderr, b"XInclude \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_ICONV) }) != 0 {
        (unsafe { fprintf(stderr, b"Iconv \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_ICU) }) != 0 {
        (unsafe { fprintf(stderr, b"ICU \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_ISO8859X) }) != 0 {
        (unsafe { fprintf(stderr, b"ISO8859X \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_UNICODE) }) != 0 {
        (unsafe { fprintf(stderr, b"Unicode \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_REGEXP) }) != 0 {
        (unsafe { fprintf(stderr, b"Regexps \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_AUTOMATA) }) != 0 {
        (unsafe { fprintf(stderr, b"Automata \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_EXPR) }) != 0 {
        (unsafe { fprintf(stderr, b"Expr \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_SCHEMAS) }) != 0 {
        (unsafe { fprintf(stderr, b"Schemas \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_SCHEMATRON) }) != 0 {
        (unsafe { fprintf(stderr, b"Schematron \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_MODULES) }) != 0 {
        (unsafe { fprintf(stderr, b"Modules \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_DEBUG) }) != 0 {
        (unsafe { fprintf(stderr, b"Debug \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_DEBUG_MEM) }) != 0 {
        (unsafe { fprintf(stderr, b"MemDebug \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_DEBUG_RUN) }) != 0 {
        (unsafe { fprintf(stderr, b"RunDebug \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_ZLIB) }) != 0 {
        (unsafe { fprintf(stderr, b"Zlib \0" as *const u8 as *const i8) });
    }
    if (unsafe { xmlHasFeature(XML_WITH_LZMA) }) != 0 {
        (unsafe { fprintf(stderr, b"Lzma \0" as *const u8 as *const i8) });
    }
    (unsafe { fprintf(stderr, b"\n\0" as *const u8 as *const i8) });
}
extern "C" fn usage(mut f: *mut crate::src::tree::_IO_FILE, mut name: *const i8) {
    (unsafe {
        fprintf(
            f,
            b"Usage : %s [options] XMLfiles ...\n\0" as *const u8 as *const i8,
            name,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\tParse the XML files and output the result of the parsing\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--version : display the version of the XML library used\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--debug : dump a debug tree of the in-memory document\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--shell : run a navigating shell\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--debugent : debug the entities defined in the document\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--copy : used to test the internal copy implementation\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--recover : output what was parsable on broken XML documents\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--huge : remove any internal arbitrary parser limits\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--noent : substitute entity references by their value\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--noenc : ignore any encoding specified inside the document\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--noout : don't output the result tree\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--path 'paths': provide a set of paths for resources\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--load-trace : print trace of all external entities loaded\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nonet : refuse to fetch DTDs or entities over network\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nocompact : do not generate compact text nodes\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--htmlout : output results as HTML\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nowrap : do not put HTML doc wrapper\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--valid : validate the document in addition to std well-formed check\n\0"
                as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--postvalid : do a posteriori validation, i.e after parsing\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--dtdvalid URL : do a posteriori validation against a given DTD\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--dtdvalidfpi FPI : same but name the DTD with a Public Identifier\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--quiet : be quiet when succeeded\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--timing : print some timings\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--output file or -o file: save to a given file\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--repeat : repeat 100 times, for timing or profiling\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--insert : ad-hoc test for valid insertions\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--compress : turn on gzip compression of output\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--html : use the HTML parser\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--xmlout : force to use the XML serializer when using --html\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nodefdtd : do not default HTML doctype\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--push : use the push mode of the parser\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--pushsmall : use the push mode of the parser using tiny increments\n\0"
                as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--memory : parse from memory\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--maxmem nbbytes : limits memory allocation to nbbytes bytes\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nowarning : do not emit warnings from parser/validator\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--noblanks : drop (ignorable?) blanks spaces\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nocdata : replace cdata section with text nodes\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--format : reformat/reindent the output\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--encode encoding : output in the given encoding\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--dropdtd : remove the DOCTYPE of the input docs\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--pretty STYLE : pretty-print in a particular style\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t                 0 Do not pretty print\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t                 1 Format the XML content, as --format\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t                 2 Add whitespace inside tags, preserving content\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--c14n : save in W3C canonical format v1.0 (with comments)\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--c14n11 : save in W3C canonical format v1.1 (with comments)\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--exc-c14n : save in W3C exclusive canonical format (with comments)\n\0"
                as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nsclean : remove redundant namespace declarations\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--testIO : test user I/O support\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--catalogs : use SGML catalogs from $SGML_CATALOG_FILES\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t             otherwise XML Catalogs starting from \n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t         %s are activated by default\n\0" as *const u8 as *const i8,
            b"file:///usr/local/etc/xml/catalog\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nocatalogs: deactivate all catalogs\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--auto : generate a small doc on the fly\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--xinclude : do XInclude processing\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--noxincludenode : same but do not generate XInclude nodes\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--nofixup-base-uris : do not fixup xml:base uris\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--loaddtd : fetch external DTD\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--dtdattr : loaddtd + populate the tree with inherited attributes \n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--stream : use the streaming interface to process very large files\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--walker : create a reader and walk though the resulting doc\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--pattern pattern_value : test the pattern support\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--chkregister : verify the node registration code\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--relaxng schema : do RelaxNG validation against the schema\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--schema schema : do validation against the WXS schema\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--schematron schema : do validation against a schematron\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--sax1: use the old SAX1 interfaces for processing\n\0" as *const u8 as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--sax: do not build a tree but work just at the SAX level\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--oldxml10: use XML-1.0 parsing rules before the 5th edition\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\t--xpath expr: evaluate the XPath expression, imply --noout\n\0" as *const u8
                as *const i8,
        )
    });
    (unsafe {
        fprintf(
            f,
            b"\nLibxml project home page: https://gitlab.gnome.org/GNOME/libxml2\n\0" as *const u8
                as *const i8,
        )
    });
}
extern "C" fn registerNode(mut node: *mut crate::src::threads::_xmlNode) {
    let fresh31 = unsafe { &mut ((*node)._private) };
    *fresh31 = unsafe { malloc(::std::mem::size_of::<i64>() as u64) };
    if (unsafe { (*node)._private }).is_null() {
        (unsafe {
            fprintf(
                stderr,
                b"Out of memory in xmllint:registerNode()\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe { exit(XMLLINT_ERR_MEM as i32) });
    }
    (unsafe { *((*node)._private as *mut i64) = 0x81726354 as u32 as i64 });
    (unsafe { nbregister += 1 });
}
extern "C" fn deregisterNode(mut node: *mut crate::src::threads::_xmlNode) {
    if !(unsafe { (*node)._private }).is_null() {
    } else {
        (unsafe {
            __assert_fail(
                b"node->_private != NULL\0" as *const u8 as *const i8,
                b"xmllint.c\0" as *const u8 as *const i8,
                3103 as i32 as u32,
                (*core::intrinsics::transmute::<&'_ [u8; 32], &'_ [i8; 32]>(
                    b"void deregisterNode(xmlNodePtr)\0",
                ))
                .as_ptr(),
            )
        });
    }
    if (unsafe { *((*node)._private as *mut i64) }) == 0x81726354 as u32 as i64 {
    } else {
        (unsafe {
            __assert_fail(
                b"*(long*)node->_private == (long) 0x81726354\0" as *const u8 as *const i8,
                b"xmllint.c\0" as *const u8 as *const i8,
                3104 as i32 as u32,
                (*core::intrinsics::transmute::<&'_ [u8; 32], &'_ [i8; 32]>(
                    b"void deregisterNode(xmlNodePtr)\0",
                ))
                .as_ptr(),
            )
        });
    }
    (unsafe { free((*node)._private) });
    (unsafe { nbregister -= 1 });
}
fn main_0(mut argc: i32, mut argv: *mut *mut i8) -> i32 {
    let mut current_block: u64;
    let mut i: i32 = 0;
    let mut acount: i32 = 0;
    let mut files: i32 = 0 as i32;
    let mut version: i32 = 0 as i32;
    let mut indent: *const i8 = 0 as *const i8;
    if argc <= 1 as i32 {
        usage(
            unsafe { stderr },
            unsafe { *argv.offset(0 as i32 as isize) },
        );
        return XMLLINT_ERR_UNCLASS as i32;
    }
    i = 1 as i32;
    while i < argc {
        if !((unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32
            != '-' as i32)
        {
            if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-maxmem\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--maxmem\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                if i >= argc
                    || (unsafe {
                        sscanf(
                            *argv.offset(i as isize),
                            b"%d\0" as *const u8 as *const i8,
                            &mut maxmem as *mut i32,
                        )
                    }) != 1 as i32
                {
                    (unsafe { maxmem = 0 as i32 });
                }
            }
        }
        i += 1;
    }
    if (unsafe { maxmem }) != 0 as i32 {
        xmlMemSetup(
            Some(myFreeFunc),
            Some(myMallocFunc),
            Some(myReallocFunc),
            Some(myStrdupFunc),
        );
    }
    (unsafe { xmlCheckVersion(21000 as i32) });
    i = 1 as i32;
    while i < argc {
        if !((unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) }) as i32
            != '-' as i32
            || (unsafe { *(*argv.offset(i as isize)).offset(1 as i32 as isize) }) as i32
                == 0 as i32)
        {
            if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-debug\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--debug\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { debug += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-shell\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--shell\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { shell += 1 });
                (unsafe { noout = 1 as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-copy\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--copy\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { copy += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-recover\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--recover\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { recovery += 1 });
                (unsafe { options |= XML_PARSE_RECOVER as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-huge\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--huge\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options |= XML_PARSE_HUGE as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-noent\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--noent\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { noent += 1 });
                (unsafe { options |= XML_PARSE_NOENT as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-noenc\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--noenc\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { noenc += 1 });
                (unsafe { options |= XML_PARSE_IGNORE_ENC as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nsclean\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nsclean\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options |= XML_PARSE_NSCLEAN as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nocdata\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nocdata\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options |= XML_PARSE_NOCDATA as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nodict\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nodict\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options |= XML_PARSE_NODICT as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-version\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--version\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                showVersion(unsafe { *argv.offset(0 as i32 as isize) });
                version = 1 as i32;
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-noout\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--noout\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { noout += 1 });
            } else if (unsafe {
                strcmp(*argv.offset(i as isize), b"-o\0" as *const u8 as *const i8)
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"-output\0" as *const u8 as *const i8,
                    )
                }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--output\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { output = *argv.offset(i as isize) });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-htmlout\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--htmlout\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { htmlout += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nowrap\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nowrap\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { nowrap += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-html\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--html\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { html += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-xmlout\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--xmlout\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { xmlout += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nodefdtd\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nodefdtd\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { nodefdtd += 1 });
                (unsafe { options |= HTML_PARSE_NODEFDTD as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-loaddtd\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--loaddtd\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { loaddtd += 1 });
                (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-dtdattr\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--dtdattr\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { loaddtd += 1 });
                (unsafe { dtdattrs += 1 });
                (unsafe { options |= XML_PARSE_DTDATTR as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-valid\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--valid\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { valid += 1 });
                (unsafe { options |= XML_PARSE_DTDVALID as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-postvalid\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--postvalid\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { postvalid += 1 });
                (unsafe { loaddtd += 1 });
                (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-dtdvalid\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--dtdvalid\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { dtdvalid = *argv.offset(i as isize) });
                (unsafe { loaddtd += 1 });
                (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-dtdvalidfpi\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--dtdvalidfpi\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { dtdvalidfpi = *argv.offset(i as isize) });
                (unsafe { loaddtd += 1 });
                (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-dropdtd\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--dropdtd\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { dropdtd += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-insert\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--insert\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { insert += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-quiet\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--quiet\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { quiet += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-timing\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--timing\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { timing += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-auto\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--auto\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { generate += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-repeat\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--repeat\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                if (unsafe { repeat }) != 0 {
                    (unsafe { repeat *= 10 as i32 });
                } else {
                    (unsafe { repeat = 100 as i32 });
                }
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-push\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--push\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { push += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-pushsmall\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--pushsmall\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { push += 1 });
                (unsafe { pushsize = 10 as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-memory\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--memory\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { memory += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-testIO\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--testIO\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { testIO += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-xinclude\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--xinclude\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { xinclude += 1 });
                (unsafe { options |= XML_PARSE_XINCLUDE as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-noxincludenode\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--noxincludenode\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { xinclude += 1 });
                (unsafe { options |= XML_PARSE_XINCLUDE as i32 });
                (unsafe { options |= XML_PARSE_NOXINCNODE as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nofixup-base-uris\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nofixup-base-uris\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { xinclude += 1 });
                (unsafe { options |= XML_PARSE_XINCLUDE as i32 });
                (unsafe { options |= XML_PARSE_NOBASEFIX as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-compress\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--compress\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { compress += 1 });
                xmlSetCompressMode(9 as i32);
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nowarning\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nowarning\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { *__xmlGetWarningsDefaultValue() = 0 as i32 });
                (unsafe { xmlPedanticParserDefault(0 as i32) });
                (unsafe { options |= XML_PARSE_NOWARNING as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-pedantic\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--pedantic\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { *__xmlGetWarningsDefaultValue() = 1 as i32 });
                (unsafe { xmlPedanticParserDefault(1 as i32) });
                (unsafe { options |= XML_PARSE_PEDANTIC as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-debugent\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--debugent\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { debugent += 1 });
                (unsafe { *__xmlParserDebugEntities() = 1 as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-c14n\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--c14n\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { canonical += 1 });
                (unsafe {
                    options |=
                        XML_PARSE_NOENT as i32 | XML_PARSE_DTDATTR as i32 | XML_PARSE_DTDLOAD as i32
                });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-c14n11\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--c14n11\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { canonical_11 += 1 });
                (unsafe {
                    options |=
                        XML_PARSE_NOENT as i32 | XML_PARSE_DTDATTR as i32 | XML_PARSE_DTDLOAD as i32
                });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-exc-c14n\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--exc-c14n\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { exc_canonical += 1 });
                (unsafe {
                    options |=
                        XML_PARSE_NOENT as i32 | XML_PARSE_DTDATTR as i32 | XML_PARSE_DTDLOAD as i32
                });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-catalogs\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--catalogs\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { catalogs += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nocatalogs\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nocatalogs\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { nocatalogs += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-encode\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--encode\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { encoding = *argv.offset(i as isize) });
                (unsafe {
                    xmlAddEncodingAlias(
                        b"UTF-8\0" as *const u8 as *const i8,
                        b"DVEnc\0" as *const u8 as *const i8,
                    )
                });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-noblanks\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--noblanks\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { noblanks += 1 });
                (unsafe { xmlKeepBlanksDefault(0 as i32) });
                (unsafe { options |= XML_PARSE_NOBLANKS as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-maxmem\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--maxmem\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-format\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--format\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { noblanks += 1 });
                (unsafe { format = 1 as i32 });
                (unsafe { xmlKeepBlanksDefault(0 as i32) });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-pretty\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--pretty\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                if !(unsafe { *argv.offset(i as isize) }).is_null() {
                    (unsafe { format = atoi(*argv.offset(i as isize)) });
                    if (unsafe { format }) == 1 as i32 {
                        (unsafe { noblanks += 1 });
                        (unsafe { xmlKeepBlanksDefault(0 as i32) });
                    }
                }
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-stream\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--stream\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { stream += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-walker\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--walker\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { walker += 1 });
                (unsafe { noout += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-pattern\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--pattern\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { pattern = *argv.offset(i as isize) });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-sax1\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--sax1\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { sax1 += 1 });
                (unsafe { options |= XML_PARSE_SAX1 as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-sax\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--sax\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { sax += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-chkregister\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--chkregister\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { chkregister += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-relaxng\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--relaxng\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { relaxng = *argv.offset(i as isize) });
                (unsafe { noent += 1 });
                (unsafe { options |= XML_PARSE_NOENT as i32 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-schema\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--schema\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { schema = *argv.offset(i as isize) });
                (unsafe { noent += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-schematron\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--schematron\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { schematron = *argv.offset(i as isize) });
                (unsafe { noent += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nonet\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nonet\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options |= XML_PARSE_NONET as i32 });
                xmlSetExternalEntityLoader(Some(xmlNoNetExternalEntityLoader));
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-nocompact\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--nocompact\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { options &= !(XML_PARSE_COMPACT as i32) });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-load-trace\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--load-trace\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { load_trace += 1 });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-path\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--path\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                parsePath((unsafe { *argv.offset(i as isize) }) as *mut xmlChar);
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-xpath\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--xpath\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                i += 1;
                (unsafe { noout += 1 });
                (unsafe { xpathquery = *argv.offset(i as isize) });
            } else if (unsafe {
                strcmp(
                    *argv.offset(i as isize),
                    b"-oldxml10\0" as *const u8 as *const i8,
                )
            }) == 0
                || (unsafe {
                    strcmp(
                        *argv.offset(i as isize),
                        b"--oldxml10\0" as *const u8 as *const i8,
                    )
                }) == 0
            {
                (unsafe { oldxml10 += 1 });
                (unsafe { options |= XML_PARSE_OLD10 as i32 });
            } else {
                (unsafe {
                    fprintf(
                        stderr,
                        b"Unknown option %s\n\0" as *const u8 as *const i8,
                        *argv.offset(i as isize),
                    )
                });
                usage(
                    unsafe { stderr },
                    unsafe { *argv.offset(0 as i32 as isize) },
                );
                return XMLLINT_ERR_UNCLASS as i32;
            }
        }
        i += 1;
    }
    if (unsafe { nocatalogs }) == 0 as i32 {
        if (unsafe { catalogs }) != 0 {
            let mut catal: *const i8 = 0 as *const i8;
            catal = unsafe { getenv(b"SGML_CATALOG_FILES\0" as *const u8 as *const i8) };
            if !catal.is_null() {
                (unsafe { xmlLoadCatalogs(catal) });
            } else {
                (unsafe {
                    fprintf(
                        stderr,
                        b"Variable $SGML_CATALOG_FILES not set\n\0" as *const u8 as *const i8,
                    )
                });
            }
        }
    }
    if (unsafe { sax1 }) != 0 {
        (unsafe { xmlSAXDefaultVersion(1 as i32) });
    } else {
        (unsafe { xmlSAXDefaultVersion(2 as i32) });
    }
    if (unsafe { chkregister }) != 0 {
        (unsafe { xmlRegisterNodeDefault(Some(registerNode)) });
        (unsafe { xmlDeregisterNodeDefault(Some(deregisterNode)) });
    }
    indent = unsafe { getenv(b"XMLLINT_INDENT\0" as *const u8 as *const i8) };
    if !indent.is_null() {
        let fresh32 = unsafe { &mut (*__xmlTreeIndentString()) };
        *fresh32 = indent;
    }
    (unsafe { defaultEntityLoader = xmlGetExternalEntityLoader() });
    xmlSetExternalEntityLoader(Some(xmllintExternalEntityLoader));
    (unsafe { xmlLineNumbersDefault(1 as i32) });
    if (unsafe { loaddtd }) != 0 as i32 {
        (unsafe { *__xmlLoadExtDtdDefaultValue() |= 2 as i32 });
    }
    if (unsafe { dtdattrs }) != 0 {
        (unsafe { *__xmlLoadExtDtdDefaultValue() |= 4 as i32 });
    }
    if (unsafe { noent }) != 0 as i32 {
        (unsafe { xmlSubstituteEntitiesDefault(1 as i32) });
    }
    if (unsafe { valid }) != 0 as i32 {
        (unsafe { *__xmlDoValidityCheckingDefaultValue() = 1 as i32 });
    }
    if (unsafe { htmlout }) != 0 && (unsafe { nowrap }) == 0 {
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n\0" as *const u8
                    as *const i8,
            )
        });
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n\0" as *const u8 as *const i8,
            )
        });
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"<html><head><title>%s output</title></head>\n\0" as *const u8 as *const i8,
                *argv.offset(0 as i32 as isize),
            )
        });
        (unsafe {
            (*__xmlGenericError()).expect("non-null function pointer")(
                *__xmlGenericErrorContext(),
                b"<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n\0" as *const u8
                    as *const i8,
                *argv.offset(0 as i32 as isize),
            )
        });
    }
    if !(unsafe { schematron }).is_null()
        && (unsafe { sax }) == 0 as i32
        && (unsafe { stream }) == 0 as i32
    {
        let mut ctxt: *mut crate::src::xmllint::_xmlSchematronParserCtxt =
            0 as *mut xmlSchematronParserCtxt;
        (unsafe { *__xmlLoadExtDtdDefaultValue() |= 1 as i32 });
        (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
        if (unsafe { timing }) != 0 {
            startTimer();
        }
        ctxt = unsafe { xmlSchematronNewParserCtxt(schematron) };
        if ctxt.is_null() {
            (unsafe { progresult = XMLLINT_ERR_MEM });
            current_block = 10779620755688928994;
        } else {
            (unsafe { wxschematron = xmlSchematronParse(ctxt) });
            if (unsafe { wxschematron }).is_null() {
                (unsafe {
                    (*__xmlGenericError()).expect("non-null function pointer")(
                        *__xmlGenericErrorContext(),
                        b"Schematron schema %s failed to compile\n\0" as *const u8 as *const i8,
                        schematron,
                    )
                });
                (unsafe { progresult = XMLLINT_ERR_SCHEMACOMP });
                (unsafe { schematron = 0 as *mut i8 });
            }
            (unsafe { xmlSchematronFreeParserCtxt(ctxt) });
            if (unsafe { timing }) != 0 {
                (unsafe { endTimer(b"Compiling the schemas\0" as *const u8 as *const i8) });
            }
            current_block = 8158038653727582745;
        }
    } else {
        current_block = 8158038653727582745;
    }
    match current_block {
        8158038653727582745 => {
            if !(unsafe { relaxng }).is_null()
                && (unsafe { sax }) == 0 as i32
                && (unsafe { stream }) == 0 as i32
            {
                let mut ctxt_0: *mut crate::src::xmlreader::_xmlRelaxNGParserCtxt =
                    0 as *mut xmlRelaxNGParserCtxt;
                (unsafe { *__xmlLoadExtDtdDefaultValue() |= 1 as i32 });
                (unsafe { options |= XML_PARSE_DTDLOAD as i32 });
                if (unsafe { timing }) != 0 {
                    startTimer();
                }
                ctxt_0 = unsafe { xmlRelaxNGNewParserCtxt(relaxng) };
                if ctxt_0.is_null() {
                    (unsafe { progresult = XMLLINT_ERR_MEM });
                    current_block = 10779620755688928994;
                } else {
                    (unsafe {
                        xmlRelaxNGSetParserErrors(
                            ctxt_0,
                            *__xmlGenericError(),
                            *__xmlGenericError(),
                            0 as *mut libc::c_void,
                        )
                    });
                    (unsafe { relaxngschemas = xmlRelaxNGParse(ctxt_0) });
                    if (unsafe { relaxngschemas }).is_null() {
                        (unsafe {
                            (*__xmlGenericError()).expect("non-null function pointer")(
                                *__xmlGenericErrorContext(),
                                b"Relax-NG schema %s failed to compile\n\0" as *const u8
                                    as *const i8,
                                relaxng,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_SCHEMACOMP });
                        (unsafe { relaxng = 0 as *mut i8 });
                    }
                    (unsafe { xmlRelaxNGFreeParserCtxt(ctxt_0) });
                    if (unsafe { timing }) != 0 {
                        (unsafe { endTimer(b"Compiling the schemas\0" as *const u8 as *const i8) });
                    }
                    current_block = 12431460683607164915;
                }
            } else if !(unsafe { schema }).is_null() && (unsafe { stream }) == 0 as i32 {
                let mut ctxt_1: *mut crate::src::xmlschemas::_xmlSchemaParserCtxt<'_> =
                    0 as *mut xmlSchemaParserCtxt;
                if (unsafe { timing }) != 0 {
                    startTimer();
                }
                ctxt_1 = xmlSchemaNewParserCtxt(unsafe { schema });
                if ctxt_1.is_null() {
                    (unsafe { progresult = XMLLINT_ERR_MEM });
                    current_block = 10779620755688928994;
                } else {
                    xmlSchemaSetParserErrors(
                        ctxt_1,
                        unsafe { *__xmlGenericError() },
                        unsafe { *__xmlGenericError() },
                        0 as *mut libc::c_void,
                    );
                    (unsafe { wxschemas = xmlSchemaParse(ctxt_1) });
                    if (unsafe { wxschemas }).is_null() {
                        (unsafe {
                            (*__xmlGenericError()).expect("non-null function pointer")(
                                *__xmlGenericErrorContext(),
                                b"WXS schema %s failed to compile\n\0" as *const u8 as *const i8,
                                schema,
                            )
                        });
                        (unsafe { progresult = XMLLINT_ERR_SCHEMACOMP });
                        (unsafe { schema = 0 as *mut i8 });
                    }
                    xmlSchemaFreeParserCtxt(ctxt_1);
                    if (unsafe { timing }) != 0 {
                        (unsafe { endTimer(b"Compiling the schemas\0" as *const u8 as *const i8) });
                    }
                    current_block = 12431460683607164915;
                }
            } else {
                current_block = 12431460683607164915;
            }
            match current_block {
                10779620755688928994 => {}
                _ => {
                    if !(unsafe { pattern }).is_null() && (unsafe { walker }) == 0 as i32 {
                        (unsafe {
                            patternc = xmlPatterncompile(
                                pattern as *const xmlChar,
                                0 as *mut xmlDict,
                                0 as i32,
                                0 as *mut *const xmlChar,
                            )
                        });
                        if (unsafe { patternc }).is_null() {
                            (unsafe {
                                (*__xmlGenericError()).expect("non-null function pointer")(
                                    *__xmlGenericErrorContext(),
                                    b"Pattern %s failed to compile\n\0" as *const u8 as *const i8,
                                    pattern,
                                )
                            });
                            (unsafe { progresult = XMLLINT_ERR_SCHEMAPAT });
                            (unsafe { pattern = 0 as *const i8 });
                        }
                    }
                    i = 1 as i32;
                    while i < argc {
                        if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-encode\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--encode\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(*argv.offset(i as isize), b"-o\0" as *const u8 as *const i8)
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"-output\0" as *const u8 as *const i8,
                                )
                            }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--output\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-dtdvalid\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--dtdvalid\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-path\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--path\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-dtdvalidfpi\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--dtdvalidfpi\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-relaxng\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--relaxng\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-maxmem\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--maxmem\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-pretty\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--pretty\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-schema\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--schema\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-schematron\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--schematron\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-pattern\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--pattern\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else if (unsafe {
                            strcmp(
                                *argv.offset(i as isize),
                                b"-xpath\0" as *const u8 as *const i8,
                            )
                        }) == 0
                            || (unsafe {
                                strcmp(
                                    *argv.offset(i as isize),
                                    b"--xpath\0" as *const u8 as *const i8,
                                )
                            }) == 0
                        {
                            i += 1;
                        } else {
                            if (unsafe { timing }) != 0 && (unsafe { repeat }) != 0 {
                                startTimer();
                            }
                            if (unsafe { *(*argv.offset(i as isize)).offset(0 as i32 as isize) })
                                as i32
                                != '-' as i32
                                || (unsafe {
                                    strcmp(
                                        *argv.offset(i as isize),
                                        b"-\0" as *const u8 as *const i8,
                                    )
                                }) == 0 as i32
                            {
                                if (unsafe { repeat }) != 0 {
                                    let mut ctxt_2: *mut crate::src::tree::_xmlParserCtxt =
                                        0 as xmlParserCtxtPtr;
                                    acount = 0 as i32;
                                    while acount < (unsafe { repeat }) {
                                        if (unsafe { stream }) != 0 as i32 {
                                            streamFile(unsafe { *argv.offset(i as isize) });
                                        } else if (unsafe { sax }) != 0 {
                                            testSAX(unsafe { *argv.offset(i as isize) });
                                        } else {
                                            if ctxt_2.is_null() {
                                                ctxt_2 = unsafe { xmlNewParserCtxt() };
                                            }
                                            parseAndPrintFile(
                                                unsafe { *argv.offset(i as isize) },
                                                ctxt_2,
                                            );
                                        }
                                        acount += 1;
                                    }
                                    if !ctxt_2.is_null() {
                                        (unsafe { xmlFreeParserCtxt(ctxt_2) });
                                    }
                                } else {
                                    (unsafe { nbregister = 0 as i32 });
                                    if (unsafe { stream }) != 0 as i32 {
                                        streamFile(unsafe { *argv.offset(i as isize) });
                                    } else if (unsafe { sax }) != 0 {
                                        testSAX(unsafe { *argv.offset(i as isize) });
                                    } else {
                                        parseAndPrintFile(
                                            unsafe { *argv.offset(i as isize) },
                                            0 as xmlParserCtxtPtr,
                                        );
                                    }
                                    if (unsafe { chkregister }) != 0
                                        && (unsafe { nbregister }) != 0 as i32
                                    {
                                        (unsafe {
                                            fprintf(
                                                stderr,
                                                b"Registration count off: %d\n\0" as *const u8
                                                    as *const i8,
                                                nbregister,
                                            )
                                        });
                                        (unsafe { progresult = XMLLINT_ERR_RDREGIS });
                                    }
                                }
                                files += 1;
                                if (unsafe { timing }) != 0 && (unsafe { repeat }) != 0 {
                                    (unsafe {
                                        endTimer(
                                            b"%d iterations\0" as *const u8 as *const i8,
                                            repeat,
                                        )
                                    });
                                }
                            }
                        }
                        i += 1;
                    }
                    if (unsafe { generate }) != 0 {
                        parseAndPrintFile(0 as *mut i8, 0 as xmlParserCtxtPtr);
                    }
                    if (unsafe { htmlout }) != 0 && (unsafe { nowrap }) == 0 {
                        (unsafe {
                            (*__xmlGenericError()).expect("non-null function pointer")(
                                *__xmlGenericErrorContext(),
                                b"</body></html>\n\0" as *const u8 as *const i8,
                            )
                        });
                    }
                    if files == 0 as i32 && (unsafe { generate }) == 0 && version == 0 as i32 {
                        usage(
                            unsafe { stderr },
                            unsafe { *argv.offset(0 as i32 as isize) },
                        );
                        (unsafe { progresult = XMLLINT_ERR_UNCLASS });
                    }
                    if !(unsafe { wxschematron }).is_null() {
                        (unsafe { xmlSchematronFree(wxschematron) });
                    }
                    if !(unsafe { relaxngschemas }).is_null() {
                        (unsafe { xmlRelaxNGFree(relaxngschemas) });
                    }
                    if !(unsafe { wxschemas }).is_null() {
                        xmlSchemaFree(unsafe { wxschemas });
                    }
                    if !(unsafe { patternc }).is_null() {
                        (unsafe { xmlFreePattern(patternc) });
                    }
                }
            }
        }
        _ => {}
    }
    (unsafe { xmlCleanupParser() });
    xmlMemoryDump();
    return (unsafe { progresult }) as i32;
}
pub fn main() {
    let mut args: Vec<*mut i8> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
     {
        ::std::process::exit(
            main_0((args.len() - 1) as i32, args.as_mut_ptr() as *mut *mut i8) as i32,
        )
    }
}

