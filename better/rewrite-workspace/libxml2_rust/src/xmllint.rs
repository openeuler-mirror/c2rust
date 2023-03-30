use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stdin: *mut FILE;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn vfprintf(
        _: *mut FILE,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    
    
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn fread(
        _: *mut libc::c_void,
        _: libc::c_ulong,
        _: libc::c_ulong,
        _: *mut FILE,
    ) -> libc::c_ulong;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(__ptr: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    fn gettimeofday(__tv: *mut timeval, __tz: *mut libc::c_void) -> libc::c_int;
    fn __xstat(
        __ver: libc::c_int,
        __filename: *const libc::c_char,
        __stat_buf: *mut stat,
    ) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn mmap(
        __addr: *mut libc::c_void,
        __len: size_t,
        __prot: libc::c_int,
        __flags: libc::c_int,
        __fd: libc::c_int,
        __offset: __off64_t,
    ) -> *mut libc::c_void;
    fn munmap(__addr: *mut libc::c_void, __len: size_t) -> libc::c_int;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut xmlFree: xmlFreeFunc;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::HTMLparser::htmlCreatePushParserCtxt;
pub use crate::src::HTMLparser::htmlCtxtUseOptions;
pub use crate::src::HTMLparser::htmlFreeParserCtxt;
pub use crate::src::HTMLparser::htmlParseChunk;
pub use crate::src::HTMLparser::htmlReadFile;
pub use crate::src::HTMLparser::htmlReadMemory;
pub use crate::src::HTMLtree::htmlDocDump;
pub use crate::src::HTMLtree::htmlSaveFile;
pub use crate::src::HTMLtree::htmlSaveFileFormat;
pub use crate::src::SAX2::xmlSAXDefaultVersion;
pub use crate::src::c14n::xmlC14NDocDumpMemory;
pub use crate::src::catalog::xmlLoadCatalogs;
pub use crate::src::debugXML::xmlDebugDumpDocument;
pub use crate::src::debugXML::xmlDebugDumpEntities;
pub use crate::src::debugXML::xmlShell;
pub use crate::src::encoding::xmlAddEncodingAlias;
pub use crate::src::entities::xmlEncodeEntitiesReentrant;
pub use crate::src::globals::__xmlDoValidityCheckingDefaultValue;
pub use crate::src::globals::__xmlGenericError;
pub use crate::src::globals::__xmlGenericErrorContext;
pub use crate::src::globals::__xmlGetWarningsDefaultValue;
pub use crate::src::globals::__xmlLoadExtDtdDefaultValue;
pub use crate::src::globals::__xmlParserDebugEntities;
pub use crate::src::globals::__xmlParserVersion;
pub use crate::src::globals::__xmlTreeIndentString;
pub use crate::src::globals::xmlDeregisterNodeDefault;
pub use crate::src::globals::xmlRegisterNodeDefault;
pub use crate::src::parser::inputPush;
pub use crate::src::parser::xmlCleanupParser;
pub use crate::src::parser::xmlCreatePushParserCtxt;
pub use crate::src::parser::xmlCtxtReadFile;
pub use crate::src::parser::xmlCtxtReadIO;
pub use crate::src::parser::xmlCtxtReadMemory;
pub use crate::src::parser::xmlCtxtUseOptions;
pub use crate::src::parser::xmlHasFeature;
pub use crate::src::parser::xmlParseChunk;
pub use crate::src::parser::xmlParseDTD;
pub use crate::src::parser::xmlParseDocument;
pub use crate::src::parser::xmlParseFile;
pub use crate::src::parser::xmlReadFd;
pub use crate::src::parser::xmlReadFile;
pub use crate::src::parser::xmlReadIO;
pub use crate::src::parser::xmlReadMemory;
pub use crate::src::parserInternals::xmlCheckVersion;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::parserInternals::xmlKeepBlanksDefault;
pub use crate::src::parserInternals::xmlLineNumbersDefault;
pub use crate::src::parserInternals::xmlNewIOInputStream;
pub use crate::src::parserInternals::xmlNewParserCtxt;
pub use crate::src::parserInternals::xmlPedanticParserDefault;
pub use crate::src::parserInternals::xmlSubstituteEntitiesDefault;
pub use crate::src::pattern::xmlFreePattern;
pub use crate::src::pattern::xmlFreeStreamCtxt;
pub use crate::src::pattern::xmlPatternGetStreamCtxt;
pub use crate::src::pattern::xmlPatternMatch;
pub use crate::src::pattern::xmlPatterncompile;
pub use crate::src::pattern::xmlStreamPop;
pub use crate::src::pattern::xmlStreamPush;
pub use crate::src::relaxng::xmlRelaxNGFree;
pub use crate::src::relaxng::xmlRelaxNGFreeParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGFreeValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGParse;
pub use crate::src::relaxng::xmlRelaxNGSetParserErrors;
pub use crate::src::relaxng::xmlRelaxNGSetValidErrors;
pub use crate::src::relaxng::xmlRelaxNGValidateDoc;
pub use crate::src::schematron::xmlSchematronFree;
pub use crate::src::schematron::xmlSchematronFreeParserCtxt;
pub use crate::src::schematron::xmlSchematronFreeValidCtxt;
pub use crate::src::schematron::xmlSchematronNewParserCtxt;
pub use crate::src::schematron::xmlSchematronNewValidCtxt;
pub use crate::src::schematron::xmlSchematronParse;
pub use crate::src::schematron::xmlSchematronValidateDoc;
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
pub use crate::src::xmlmemory::xmlMemFree;
pub use crate::src::xmlmemory::xmlMemMalloc;
pub use crate::src::xmlmemory::xmlMemRealloc;
pub use crate::src::xmlmemory::xmlMemSetup;
pub use crate::src::xmlmemory::xmlMemUsed;
pub use crate::src::xmlmemory::xmlMemoryDump;
pub use crate::src::xmlmemory::xmlMemoryStrdup;
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
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xpath::xmlXPathEval;
pub use crate::src::xpath::xmlXPathFreeContext;
pub use crate::src::xpath::xmlXPathFreeObject;
pub use crate::src::xpath::xmlXPathIsInf;
pub use crate::src::xpath::xmlXPathIsNaN;
pub use crate::src::xpath::xmlXPathNewContext;
pub use crate::src::xpath::xmlXPathOrderDocElems;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::pattern::_xmlPattern;
pub use crate::src::pattern::_xmlStreamCtxt;
pub use crate::src::python::libxml2_py::_xmlSchema;
pub use crate::src::relaxng::_xmlRelaxNG;
pub use crate::src::relaxng::_xmlRelaxNGParserCtxt;
pub use crate::src::relaxng::_xmlRelaxNGValidCtxt;
pub use crate::src::schematron::_xmlSchematron;
pub use crate::src::schematron::_xmlSchematronParserCtxt;
pub use crate::src::schematron::_xmlSchematronValidCtxt;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlreader::_xmlTextReader;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlsave::_xmlSaveCtxt;
pub use crate::src::xmlschemas::_xmlSchemaParserCtxt;
pub use crate::src::xmlschemas::_xmlSchemaValidCtxt;
pub use crate::src::xpath::_xmlXPathCompExpr;
pub use crate::src::error::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::src::error::__va_list_tag;
pub use crate::src::error::va_list;
pub use crate::src::HTMLparser::xmlChar;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::catalog::__dev_t;
pub use crate::src::catalog::__uid_t;
pub use crate::src::catalog::__gid_t;
pub use crate::src::catalog::__ino_t;
pub use crate::src::catalog::__mode_t;
pub use crate::src::catalog::__nlink_t;
pub use crate::src::HTMLtree::__off_t;
pub use crate::src::HTMLtree::__off64_t;
pub use crate::src::catalog::__time_t;
pub use crate::src::nanoftp::__suseconds_t;
pub use crate::src::catalog::__blksize_t;
pub use crate::src::catalog::__blkcnt_t;
pub use crate::src::catalog::__ssize_t;
pub use crate::src::catalog::__syscall_slong_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_IO_FILE;
pub use crate::src::HTMLtree::_IO_lock_t;
pub use crate::src::HTMLtree::FILE;
pub use crate::src::catalog::ssize_t;
// #[derive(Copy, Clone)]

pub use crate::src::nanoftp::timeval;
// #[derive(Copy, Clone)]

pub use crate::src::catalog::timespec;
// #[derive(Copy, Clone)]

pub use crate::src::catalog::stat;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::encoding::xmlStrdupFunc;
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

pub use crate::src::HTMLtree::_xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputCloseCallback;
pub use crate::src::HTMLtree::xmlOutputWriteCallback;
pub use crate::src::HTMLtree::xmlOutputBuffer;
pub use crate::src::HTMLtree::xmlOutputBufferPtr;
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
pub use crate::src::HTMLparser::xmlDtd;
pub use crate::src::HTMLparser::xmlDtdPtr;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
pub use crate::src::SAX2::xmlValidCtxtPtr;
pub use crate::src::python::libxml::xmlExternalEntityLoader;
pub use crate::src::HTMLparser::xmlCharEncoding;
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
pub type C2RustUnnamed = libc::c_uint;
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
pub use crate::src::parser::xmlFeature;
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
pub use crate::src::HTMLparser::xmlRegisterNodeFunc;
pub use crate::src::globals::xmlDeregisterNodeFunc;
pub use crate::src::HTMLparser::htmlParserCtxtPtr;
pub use crate::src::HTMLparser::htmlSAXHandlerPtr;
pub use crate::src::HTMLparser::htmlDocPtr;
pub type C2RustUnnamed_0 = libc::c_uint;
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
// #[derive(Copy, Clone)]

pub use crate::src::debugXML::_xmlXPathContext;
pub use crate::src::debugXML::xmlXPathFuncLookupFunc;
pub use crate::src::debugXML::xmlXPathFunction;
pub use crate::src::debugXML::xmlXPathParserContextPtr;
pub use crate::src::debugXML::xmlXPathParserContext;
// #[derive(Copy, Clone)]

pub use crate::src::debugXML::_xmlXPathParserContext;
pub use crate::src::debugXML::xmlXPathCompExprPtr;
pub use crate::src::debugXML::xmlXPathCompExpr;
pub use crate::src::debugXML::xmlXPathObjectPtr;
pub use crate::src::debugXML::xmlXPathObject;
// #[derive(Copy, Clone)]

pub use crate::src::debugXML::_xmlXPathObject;
pub use crate::src::c14n::xmlNodeSetPtr;
pub use crate::src::c14n::xmlNodeSet;
// #[derive(Copy, Clone)]

pub use crate::src::c14n::_xmlNodeSet;
pub use crate::src::debugXML::xmlXPathObjectType;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub use crate::src::debugXML::xmlXPathContextPtr;
pub use crate::src::debugXML::xmlXPathContext;
pub use crate::src::debugXML::xmlXPathVariableLookupFunc;
pub use crate::src::debugXML::xmlXPathAxisPtr;
pub use crate::src::debugXML::xmlXPathAxis;
// #[derive(Copy, Clone)]

pub use crate::src::debugXML::_xmlXPathAxis;
pub use crate::src::debugXML::xmlXPathAxisFunc;
pub use crate::src::debugXML::xmlXPathTypePtr;
pub use crate::src::debugXML::xmlXPathType;
// #[derive(Copy, Clone)]

pub use crate::src::debugXML::_xmlXPathType;
pub use crate::src::debugXML::xmlXPathConvertFunc;
pub use crate::src::debugXML::xmlShellReadlineFunc;
pub use crate::src::debugXML::xmlRelaxNG;
pub use crate::src::debugXML::xmlRelaxNGPtr;
pub use crate::src::debugXML::xmlRelaxNGValidityErrorFunc;
pub use crate::src::debugXML::xmlRelaxNGValidityWarningFunc;
pub use crate::src::debugXML::xmlRelaxNGParserCtxt;
pub use crate::src::debugXML::xmlRelaxNGParserCtxtPtr;
pub use crate::src::debugXML::xmlRelaxNGValidCtxt;
pub use crate::src::debugXML::xmlRelaxNGValidCtxtPtr;
pub use crate::src::python::libxml2_py::xmlSchema;
pub use crate::src::python::libxml2_py::xmlSchemaPtr;
pub use crate::src::python::libxml::xmlSchemaValidityErrorFunc;
pub use crate::src::python::libxml::xmlSchemaValidityWarningFunc;
pub use crate::src::python::libxml2_py::xmlSchemaParserCtxt;
pub use crate::src::python::libxml2_py::xmlSchemaParserCtxtPtr;
pub use crate::src::python::libxml::xmlSchemaValidCtxt;
pub use crate::src::python::libxml::xmlSchemaValidCtxtPtr;
pub type C2RustUnnamed_1 = libc::c_uint;
pub const XML_PARSER_SUBST_ENTITIES: C2RustUnnamed_1 = 4;
pub const XML_PARSER_VALIDATE: C2RustUnnamed_1 = 3;
pub const XML_PARSER_DEFAULTATTRS: C2RustUnnamed_1 = 2;
pub const XML_PARSER_LOADDTD: C2RustUnnamed_1 = 1;
pub type C2RustUnnamed_2 = libc::c_uint;
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
pub use crate::src::python::libxml::xmlTextReader;
pub use crate::src::python::libxml::xmlTextReaderPtr;
pub type C2RustUnnamed_3 = libc::c_uint;
pub const XML_SCHEMATRON_OUT_IO: C2RustUnnamed_3 = 1024;
pub const XML_SCHEMATRON_OUT_BUFFER: C2RustUnnamed_3 = 512;
pub const XML_SCHEMATRON_OUT_FILE: C2RustUnnamed_3 = 256;
pub const XML_SCHEMATRON_OUT_ERROR: C2RustUnnamed_3 = 8;
pub const XML_SCHEMATRON_OUT_XML: C2RustUnnamed_3 = 4;
pub const XML_SCHEMATRON_OUT_TEXT: C2RustUnnamed_3 = 2;
pub const XML_SCHEMATRON_OUT_QUIET: C2RustUnnamed_3 = 1;
pub use crate::src::schematron::xmlSchematron;
pub use crate::src::schematron::xmlSchematronPtr;
pub use crate::src::schematron::xmlSchematronParserCtxt;
pub use crate::src::schematron::xmlSchematronParserCtxtPtr;
pub use crate::src::schematron::xmlSchematronValidCtxt;
pub use crate::src::schematron::xmlSchematronValidCtxtPtr;
pub use crate::src::pattern::xmlPattern;
pub use crate::src::pattern::xmlPatternPtr;
pub use crate::src::pattern::xmlStreamCtxt;
pub use crate::src::pattern::xmlStreamCtxtPtr;
pub type C2RustUnnamed_4 = libc::c_uint;
pub const XML_C14N_1_1: C2RustUnnamed_4 = 2;
pub const XML_C14N_EXCLUSIVE_1_0: C2RustUnnamed_4 = 1;
pub const XML_C14N_1_0: C2RustUnnamed_4 = 0;
pub type C2RustUnnamed_5 = libc::c_uint;
pub const XML_SAVE_WSNONSIG: C2RustUnnamed_5 = 128;
pub const XML_SAVE_AS_HTML: C2RustUnnamed_5 = 64;
pub const XML_SAVE_AS_XML: C2RustUnnamed_5 = 32;
pub const XML_SAVE_XHTML: C2RustUnnamed_5 = 16;
pub const XML_SAVE_NO_XHTML: C2RustUnnamed_5 = 8;
pub const XML_SAVE_NO_EMPTY: C2RustUnnamed_5 = 4;
pub const XML_SAVE_NO_DECL: C2RustUnnamed_5 = 2;
pub const XML_SAVE_FORMAT: C2RustUnnamed_5 = 1;
pub use crate::src::python::libxml::xmlSaveCtxt;
pub use crate::src::python::libxml::xmlSaveCtxtPtr;
pub type xmllintReturnCode = libc::c_uint;
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
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as libc::c_int;
}
#[inline]
unsafe extern "C" fn stat(
    mut __path: *const libc::c_char,
    mut __statbuf: *mut stat,
) -> libc::c_int {
    return __xstat(1 as libc::c_int, __path, __statbuf);
}
static mut shell: libc::c_int = 0 as libc::c_int;
static mut debugent: libc::c_int = 0 as libc::c_int;
static mut debug: libc::c_int = 0 as libc::c_int;
static mut maxmem: libc::c_int = 0 as libc::c_int;
static mut copy: libc::c_int = 0 as libc::c_int;
static mut recovery: libc::c_int = 0 as libc::c_int;
static mut noent: libc::c_int = 0 as libc::c_int;
static mut noenc: libc::c_int = 0 as libc::c_int;
static mut noblanks: libc::c_int = 0 as libc::c_int;
static mut noout: libc::c_int = 0 as libc::c_int;
static mut nowrap: libc::c_int = 0 as libc::c_int;
static mut format: libc::c_int = 0 as libc::c_int;
static mut output: *const libc::c_char = 0 as *const libc::c_char;
static mut compress: libc::c_int = 0 as libc::c_int;
static mut oldout: libc::c_int = 0 as libc::c_int;
static mut valid: libc::c_int = 0 as libc::c_int;
static mut postvalid: libc::c_int = 0 as libc::c_int;
static mut dtdvalid: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut dtdvalidfpi: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
static mut relaxng: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut relaxngschemas: xmlRelaxNGPtr = 0 as *const xmlRelaxNG as xmlRelaxNGPtr;
static mut schema: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut wxschemas: xmlSchemaPtr = 0 as *const xmlSchema as xmlSchemaPtr;
static mut schematron: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut wxschematron: xmlSchematronPtr = 0 as *const xmlSchematron
    as xmlSchematronPtr;
static mut repeat: libc::c_int = 0 as libc::c_int;
static mut insert: libc::c_int = 0 as libc::c_int;
static mut html: libc::c_int = 0 as libc::c_int;
static mut xmlout: libc::c_int = 0 as libc::c_int;
static mut htmlout: libc::c_int = 0 as libc::c_int;
static mut nodefdtd: libc::c_int = 0 as libc::c_int;
static mut push: libc::c_int = 0 as libc::c_int;
static mut pushsize: libc::c_int = 4096 as libc::c_int;
static mut memory: libc::c_int = 0 as libc::c_int;
static mut testIO: libc::c_int = 0 as libc::c_int;
static mut encoding: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut xinclude: libc::c_int = 0 as libc::c_int;
static mut dtdattrs: libc::c_int = 0 as libc::c_int;
static mut loaddtd: libc::c_int = 0 as libc::c_int;
static mut progresult: xmllintReturnCode = XMLLINT_RETURN_OK;
static mut quiet: libc::c_int = 0 as libc::c_int;
static mut timing: libc::c_int = 0 as libc::c_int;
static mut generate: libc::c_int = 0 as libc::c_int;
static mut dropdtd: libc::c_int = 0 as libc::c_int;
static mut catalogs: libc::c_int = 0 as libc::c_int;
static mut nocatalogs: libc::c_int = 0 as libc::c_int;
static mut canonical: libc::c_int = 0 as libc::c_int;
static mut canonical_11: libc::c_int = 0 as libc::c_int;
static mut exc_canonical: libc::c_int = 0 as libc::c_int;
static mut stream: libc::c_int = 0 as libc::c_int;
static mut walker: libc::c_int = 0 as libc::c_int;
static mut pattern: *const libc::c_char = 0 as *const libc::c_char;
static mut patternc: xmlPatternPtr = 0 as *const xmlPattern as xmlPatternPtr;
static mut patstream: xmlStreamCtxtPtr = 0 as *const xmlStreamCtxt as xmlStreamCtxtPtr;
static mut chkregister: libc::c_int = 0 as libc::c_int;
static mut nbregister: libc::c_int = 0 as libc::c_int;
static mut sax1: libc::c_int = 0 as libc::c_int;
static mut xpathquery: *const libc::c_char = 0 as *const libc::c_char;
static mut options: libc::c_int = XML_PARSE_COMPACT as libc::c_int
    | XML_PARSE_BIG_LINES as libc::c_int;
static mut sax: libc::c_int = 0 as libc::c_int;
static mut oldxml10: libc::c_int = 0 as libc::c_int;
static mut paths: [*mut xmlChar; 65] = [0 as *const xmlChar as *mut xmlChar; 65];
static mut nbpaths: libc::c_int = 0 as libc::c_int;
static mut load_trace: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn parsePath(mut path: *const xmlChar) {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    if path.is_null() {
        return;
    }
    while *path as libc::c_int != 0 as libc::c_int {
        if nbpaths >= 64 as libc::c_int {
            fprintf(
                stderr,
                b"MAX_PATHS reached: too many paths\n\0" as *const u8
                    as *const libc::c_char,
            );
            return;
        }
        cur = path;
        while *cur as libc::c_int == ' ' as i32 || *cur as libc::c_int == ':' as i32 {
            cur = cur.offset(1);
        }
        path = cur;
        while *cur as libc::c_int != 0 as libc::c_int
            && *cur as libc::c_int != ' ' as i32 && *cur as libc::c_int != ':' as i32
        {
            cur = cur.offset(1);
        }
        if cur != path {
            paths[nbpaths
                as usize] = xmlStrndup(
                path,
                cur.offset_from(path) as libc::c_long as libc::c_int,
            );
            if !(paths[nbpaths as usize]).is_null() {
                nbpaths += 1;
            }
            path = cur;
        }
    }
}
static mut defaultEntityLoader: xmlExternalEntityLoader = None;
unsafe extern "C" fn xmllintExternalEntityLoader(
    mut URL: *const libc::c_char,
    mut ID: *const libc::c_char,
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    let mut ret: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut warning: warningSAXFunc = None;
    let mut err: errorSAXFunc = None;
    let mut i: libc::c_int = 0;
    let mut lastsegment: *const libc::c_char = URL;
    let mut iter: *const libc::c_char = URL;
    if nbpaths > 0 as libc::c_int && !iter.is_null() {
        while *iter as libc::c_int != 0 as libc::c_int {
            if *iter as libc::c_int == '/' as i32 {
                lastsegment = iter.offset(1 as libc::c_int as isize);
            }
            iter = iter.offset(1);
        }
    }
    if !ctxt.is_null() && !((*ctxt).sax).is_null() {
        warning = (*(*ctxt).sax).warning;
        err = (*(*ctxt).sax).error;
        let ref mut fresh0 = (*(*ctxt).sax).warning;
        *fresh0 = None;
        let ref mut fresh1 = (*(*ctxt).sax).error;
        *fresh1 = None;
    }
    if defaultEntityLoader.is_some() {
        ret = defaultEntityLoader.expect("non-null function pointer")(URL, ID, ctxt);
        if !ret.is_null() {
            if warning.is_some() {
                let ref mut fresh2 = (*(*ctxt).sax).warning;
                *fresh2 = warning;
            }
            if err.is_some() {
                let ref mut fresh3 = (*(*ctxt).sax).error;
                *fresh3 = err;
            }
            if load_trace != 0 {
                fprintf(
                    stderr,
                    b"Loaded URL=\"%s\" ID=\"%s\"\n\0" as *const u8
                        as *const libc::c_char,
                    if !URL.is_null() {
                        URL
                    } else {
                        b"(null)\0" as *const u8 as *const libc::c_char
                    },
                    if !ID.is_null() {
                        ID
                    } else {
                        b"(null)\0" as *const u8 as *const libc::c_char
                    },
                );
            }
            return ret;
        }
    }
    i = 0 as libc::c_int;
    while i < nbpaths {
        let mut newURL: *mut xmlChar = 0 as *mut xmlChar;
        newURL = xmlStrdup(paths[i as usize] as *const xmlChar);
        newURL = xmlStrcat(
            newURL,
            b"/\0" as *const u8 as *const libc::c_char as *const xmlChar,
        );
        newURL = xmlStrcat(newURL, lastsegment as *const xmlChar);
        if !newURL.is_null() {
            ret = defaultEntityLoader
                .expect(
                    "non-null function pointer",
                )(newURL as *const libc::c_char, ID, ctxt);
            if !ret.is_null() {
                if warning.is_some() {
                    let ref mut fresh4 = (*(*ctxt).sax).warning;
                    *fresh4 = warning;
                }
                if err.is_some() {
                    let ref mut fresh5 = (*(*ctxt).sax).error;
                    *fresh5 = err;
                }
                if load_trace != 0 {
                    fprintf(
                        stderr,
                        b"Loaded URL=\"%s\" ID=\"%s\"\n\0" as *const u8
                            as *const libc::c_char,
                        newURL,
                        if !ID.is_null() {
                            ID
                        } else {
                            b"(null)\0" as *const u8 as *const libc::c_char
                        },
                    );
                }
                xmlFree.expect("non-null function pointer")(newURL as *mut libc::c_void);
                return ret;
            }
            xmlFree.expect("non-null function pointer")(newURL as *mut libc::c_void);
        }
        i += 1;
    }
    if err.is_some() {
        let ref mut fresh6 = (*(*ctxt).sax).error;
        *fresh6 = err;
    }
    if warning.is_some() {
        let ref mut fresh7 = (*(*ctxt).sax).warning;
        *fresh7 = warning;
        if !URL.is_null() {
            warning
                .expect(
                    "non-null function pointer",
                )(
                ctxt as *mut libc::c_void,
                b"failed to load external entity \"%s\"\n\0" as *const u8
                    as *const libc::c_char,
                URL,
            );
        } else if !ID.is_null() {
            warning
                .expect(
                    "non-null function pointer",
                )(
                ctxt as *mut libc::c_void,
                b"failed to load external entity \"%s\"\n\0" as *const u8
                    as *const libc::c_char,
                ID,
            );
        }
    }
    return 0 as xmlParserInputPtr;
}
unsafe extern "C" fn OOM() {
    fprintf(
        stderr,
        b"Ran out of memory needs > %d bytes\n\0" as *const u8 as *const libc::c_char,
        maxmem,
    );
    progresult = XMLLINT_ERR_MEM;
}
unsafe extern "C" fn myFreeFunc(mut mem: *mut libc::c_void) {
    xmlMemFree(mem);
}
unsafe extern "C" fn myMallocFunc(mut size: size_t) -> *mut libc::c_void {
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    ret = xmlMemMalloc(size);
    if !ret.is_null() {
        if xmlMemUsed() > maxmem {
            OOM();
            xmlMemFree(ret);
            return 0 as *mut libc::c_void;
        }
    }
    return ret;
}
unsafe extern "C" fn myReallocFunc(
    mut mem: *mut libc::c_void,
    mut size: size_t,
) -> *mut libc::c_void {
    let mut ret: *mut libc::c_void = 0 as *mut libc::c_void;
    ret = xmlMemRealloc(mem, size);
    if !ret.is_null() {
        if xmlMemUsed() > maxmem {
            OOM();
            xmlMemFree(ret);
            return 0 as *mut libc::c_void;
        }
    }
    return ret;
}
unsafe extern "C" fn myStrdupFunc(mut str: *const libc::c_char) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    ret = xmlMemoryStrdup(str);
    if !ret.is_null() {
        if xmlMemUsed() > maxmem {
            OOM();
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
    }
    return ret;
}
static mut begin: timeval = timeval { tv_sec: 0, tv_usec: 0 };
static mut end: timeval = timeval { tv_sec: 0, tv_usec: 0 };
unsafe extern "C" fn startTimer() {
    gettimeofday(&mut begin, 0 as *mut libc::c_void);
}
unsafe extern "C" fn endTimer(mut fmt: *const libc::c_char, mut args: ...) {
    let mut msec: libc::c_long = 0;
    let mut ap: ::std::ffi::VaListImpl;
    gettimeofday(&mut end, 0 as *mut libc::c_void);
    msec = end.tv_sec - begin.tv_sec;
    msec *= 1000 as libc::c_int as libc::c_long;
    msec += (end.tv_usec - begin.tv_usec) / 1000 as libc::c_int as libc::c_long;
    ap = args.clone();
    vfprintf(stderr, fmt, ap.as_va_list());
    fprintf(stderr, b" took %ld ms\n\0" as *const u8 as *const libc::c_char, msec);
}
static mut buffer: [libc::c_char; 50000] = [0; 50000];
unsafe extern "C" fn xmlHTMLEncodeSend() {
    let mut result: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        &mut *buffer
            .as_mut_ptr()
            .offset(
                (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
                    .wrapping_sub(4 as libc::c_int as libc::c_ulong) as isize,
            ) as *mut libc::c_char as *mut libc::c_void,
        0 as libc::c_int,
        4 as libc::c_int as libc::c_ulong,
    );
    result = xmlEncodeEntitiesReentrant(
        0 as xmlDocPtr,
        buffer.as_mut_ptr() as *mut xmlChar,
    ) as *mut libc::c_char;
    if !result.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"%s\0" as *const u8 as *const libc::c_char,
            result,
        );
        xmlFree.expect("non-null function pointer")(result as *mut libc::c_void);
    }
    buffer[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
}
unsafe extern "C" fn xmlHTMLPrintFileInfo(mut input: xmlParserInputPtr) {
    let mut len: libc::c_int = 0;
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"<p>\0" as *const u8 as *const libc::c_char);
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    if !input.is_null() {
        if !((*input).filename).is_null() {
            snprintf(
                &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
                    .wrapping_sub(len as libc::c_ulong),
                b"%s:%d: \0" as *const u8 as *const libc::c_char,
                (*input).filename,
                (*input).line,
            );
        } else {
            snprintf(
                &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
                (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
                    .wrapping_sub(len as libc::c_ulong),
                b"Entity: line %d: \0" as *const u8 as *const libc::c_char,
                (*input).line,
            );
        }
    }
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlHTMLPrintFileContext(mut input: xmlParserInputPtr) {
    let mut cur: *const xmlChar = 0 as *const xmlChar;
    let mut base: *const xmlChar = 0 as *const xmlChar;
    let mut len: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    if input.is_null() {
        return;
    }
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"<pre>\n\0" as *const u8 as *const libc::c_char);
    cur = (*input).cur;
    base = (*input).base;
    while cur > base
        && (*cur as libc::c_int == '\n' as i32 || *cur as libc::c_int == '\r' as i32)
    {
        cur = cur.offset(-1);
    }
    n = 0 as libc::c_int;
    loop {
        let fresh8 = n;
        n = n + 1;
        if !(fresh8 < 80 as libc::c_int && cur > base
            && *cur as libc::c_int != '\n' as i32 && *cur as libc::c_int != '\r' as i32)
        {
            break;
        }
        cur = cur.offset(-1);
    }
    if *cur as libc::c_int == '\n' as i32 || *cur as libc::c_int == '\r' as i32 {
        cur = cur.offset(1);
    }
    base = cur;
    n = 0 as libc::c_int;
    while *cur as libc::c_int != 0 as libc::c_int && *cur as libc::c_int != '\n' as i32
        && *cur as libc::c_int != '\r' as i32 && n < 79 as libc::c_int
    {
        len = strlen(buffer.as_mut_ptr()) as libc::c_int;
        let fresh9 = cur;
        cur = cur.offset(1);
        snprintf(
            &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
                .wrapping_sub(len as libc::c_ulong),
            b"%c\0" as *const u8 as *const libc::c_char,
            *fresh9 as libc::c_int,
        );
        n += 1;
    }
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    snprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        b"\n\0" as *const u8 as *const libc::c_char,
    );
    cur = (*input).cur;
    while *cur as libc::c_int == '\n' as i32 || *cur as libc::c_int == '\r' as i32 {
        cur = cur.offset(-1);
    }
    n = 0 as libc::c_int;
    while cur != base
        && {
            let fresh10 = n;
            n = n + 1;
            fresh10 < 80 as libc::c_int
        }
    {
        len = strlen(buffer.as_mut_ptr()) as libc::c_int;
        snprintf(
            &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
            (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
                .wrapping_sub(len as libc::c_ulong),
            b" \0" as *const u8 as *const libc::c_char,
        );
        base = base.offset(1);
    }
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    snprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize) as *mut libc::c_char,
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        b"^\n\0" as *const u8 as *const libc::c_char,
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"</pre>\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn xmlHTMLError(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut len: libc::c_int = 0;
    buffer[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    input = (*ctxt).input;
    if !input.is_null() && ((*input).filename).is_null()
        && (*ctxt).inputNr > 1 as libc::c_int
    {
        input = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 2 as libc::c_int) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"<b>error</b>: \0" as *const u8 as *const libc::c_char,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"</p>\n\0" as *const u8 as *const libc::c_char);
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlHTMLWarning(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut len: libc::c_int = 0;
    buffer[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    input = (*ctxt).input;
    if !input.is_null() && ((*input).filename).is_null()
        && (*ctxt).inputNr > 1 as libc::c_int
    {
        input = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 2 as libc::c_int) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"<b>warning</b>: \0" as *const u8 as *const libc::c_char,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"</p>\n\0" as *const u8 as *const libc::c_char);
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlHTMLValidityError(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut len: libc::c_int = 0;
    buffer[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    input = (*ctxt).input;
    if ((*input).filename).is_null() && (*ctxt).inputNr > 1 as libc::c_int {
        input = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 2 as libc::c_int) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"<b>validity error</b>: \0" as *const u8 as *const libc::c_char,
    );
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    args_0 = args.clone();
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"</p>\n\0" as *const u8 as *const libc::c_char);
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
    progresult = XMLLINT_ERR_VALID;
}
unsafe extern "C" fn xmlHTMLValidityWarning(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ctxt: xmlParserCtxtPtr = ctx as xmlParserCtxtPtr;
    let mut input: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut len: libc::c_int = 0;
    buffer[0 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    input = (*ctxt).input;
    if ((*input).filename).is_null() && (*ctxt).inputNr > 1 as libc::c_int {
        input = *((*ctxt).inputTab)
            .offset(((*ctxt).inputNr - 2 as libc::c_int) as isize);
    }
    xmlHTMLPrintFileInfo(input);
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(
        *__xmlGenericErrorContext(),
        b"<b>validity warning</b>: \0" as *const u8 as *const libc::c_char,
    );
    args_0 = args.clone();
    len = strlen(buffer.as_mut_ptr()) as libc::c_int;
    vsnprintf(
        &mut *buffer.as_mut_ptr().offset(len as isize),
        (::std::mem::size_of::<[libc::c_char; 50000]>() as libc::c_ulong)
            .wrapping_sub(len as libc::c_ulong),
        msg,
        args_0.as_va_list(),
    );
    xmlHTMLEncodeSend();
    (*__xmlGenericError())
        .expect(
            "non-null function pointer",
        )(*__xmlGenericErrorContext(), b"</p>\n\0" as *const u8 as *const libc::c_char);
    xmlHTMLPrintFileContext(input);
    xmlHTMLEncodeSend();
}
unsafe extern "C" fn xmlShellReadline(
    mut prompt: *mut libc::c_char,
) -> *mut libc::c_char {
    let mut line_read: [libc::c_char; 501] = [0; 501];
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    if !prompt.is_null() {
        fprintf(stdout, b"%s\0" as *const u8 as *const libc::c_char, prompt);
    }
    fflush(stdout);
    if (fgets(line_read.as_mut_ptr(), 500 as libc::c_int, stdin)).is_null() {
        return 0 as *mut libc::c_char;
    }
    line_read[500 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    len = strlen(line_read.as_mut_ptr()) as libc::c_int;
    ret = malloc((len + 1 as libc::c_int) as libc::c_ulong) as *mut libc::c_char;
    if !ret.is_null() {
        memcpy(
            ret as *mut libc::c_void,
            line_read.as_mut_ptr() as *const libc::c_void,
            (len + 1 as libc::c_int) as libc::c_ulong,
        );
    }
    return ret;
}
unsafe extern "C" fn myRead(
    mut f: *mut libc::c_void,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    return fread(
        buf as *mut libc::c_void,
        1 as libc::c_int as libc::c_ulong,
        len as libc::c_ulong,
        f as *mut FILE,
    ) as libc::c_int;
}
unsafe extern "C" fn myClose(mut context: *mut libc::c_void) -> libc::c_int {
    let mut f: *mut FILE = context as *mut FILE;
    if f == stdin {
        return 0 as libc::c_int;
    }
    return fclose(f);
}
static mut emptySAXHandlerStruct: xmlSAXHandler = {
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
        initialized: 0xdeedbeaf as libc::c_uint,
        _private: 0 as *const libc::c_void as *mut libc::c_void,
        startElementNs: None,
        endElementNs: None,
        serror: None,
    };
    init
};
static mut emptySAXHandler: xmlSAXHandlerPtr = unsafe {
    &emptySAXHandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler
};
static mut callbacks: libc::c_int = 0;
unsafe extern "C" fn isStandaloneDebug(mut ctx: *mut libc::c_void) -> libc::c_int {
    callbacks += 1;
    if noout != 0 {
        return 0 as libc::c_int;
    }
    fprintf(stdout, b"SAX.isStandalone()\n\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
unsafe extern "C" fn hasInternalSubsetDebug(mut ctx: *mut libc::c_void) -> libc::c_int {
    callbacks += 1;
    if noout != 0 {
        return 0 as libc::c_int;
    }
    fprintf(stdout, b"SAX.hasInternalSubset()\n\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
unsafe extern "C" fn hasExternalSubsetDebug(mut ctx: *mut libc::c_void) -> libc::c_int {
    callbacks += 1;
    if noout != 0 {
        return 0 as libc::c_int;
    }
    fprintf(stdout, b"SAX.hasExternalSubset()\n\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
unsafe extern "C" fn internalSubsetDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.internalSubset(%s,\0" as *const u8 as *const libc::c_char,
        name,
    );
    if ExternalID.is_null() {
        fprintf(stdout, b" ,\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(stdout, b" %s,\0" as *const u8 as *const libc::c_char, ExternalID);
    }
    if SystemID.is_null() {
        fprintf(stdout, b" )\n\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(stdout, b" %s)\n\0" as *const u8 as *const libc::c_char, SystemID);
    };
}
unsafe extern "C" fn externalSubsetDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.externalSubset(%s,\0" as *const u8 as *const libc::c_char,
        name,
    );
    if ExternalID.is_null() {
        fprintf(stdout, b" ,\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(stdout, b" %s,\0" as *const u8 as *const libc::c_char, ExternalID);
    }
    if SystemID.is_null() {
        fprintf(stdout, b" )\n\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(stdout, b" %s)\n\0" as *const u8 as *const libc::c_char, SystemID);
    };
}
unsafe extern "C" fn resolveEntityDebug(
    mut ctx: *mut libc::c_void,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) -> xmlParserInputPtr {
    callbacks += 1;
    if noout != 0 {
        return 0 as xmlParserInputPtr;
    }
    fprintf(stdout, b"SAX.resolveEntity(\0" as *const u8 as *const libc::c_char);
    if !publicId.is_null() {
        fprintf(
            stdout,
            b"%s\0" as *const u8 as *const libc::c_char,
            publicId as *mut libc::c_char,
        );
    } else {
        fprintf(stdout, b" \0" as *const u8 as *const libc::c_char);
    }
    if !systemId.is_null() {
        fprintf(
            stdout,
            b", %s)\n\0" as *const u8 as *const libc::c_char,
            systemId as *mut libc::c_char,
        );
    } else {
        fprintf(stdout, b", )\n\0" as *const u8 as *const libc::c_char);
    }
    return 0 as xmlParserInputPtr;
}
unsafe extern "C" fn getEntityDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    callbacks += 1;
    if noout != 0 {
        return 0 as xmlEntityPtr;
    }
    fprintf(stdout, b"SAX.getEntity(%s)\n\0" as *const u8 as *const libc::c_char, name);
    return 0 as xmlEntityPtr;
}
unsafe extern "C" fn getParameterEntityDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) -> xmlEntityPtr {
    callbacks += 1;
    if noout != 0 {
        return 0 as xmlEntityPtr;
    }
    fprintf(
        stdout,
        b"SAX.getParameterEntity(%s)\n\0" as *const u8 as *const libc::c_char,
        name,
    );
    return 0 as xmlEntityPtr;
}
unsafe extern "C" fn entityDeclDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    let mut nullstr: *const xmlChar = b"(null)\0" as *const u8 as *const libc::c_char
        as *mut xmlChar;
    if publicId.is_null() {
        publicId = nullstr;
    }
    if systemId.is_null() {
        systemId = nullstr;
    }
    if content.is_null() {
        content = nullstr as *mut xmlChar;
    }
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.entityDecl(%s, %d, %s, %s, %s)\n\0" as *const u8 as *const libc::c_char,
        name,
        type_0,
        publicId,
        systemId,
        content,
    );
}
unsafe extern "C" fn attributeDeclDebug(
    mut ctx: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut def: libc::c_int,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    if defaultValue.is_null() {
        fprintf(
            stdout,
            b"SAX.attributeDecl(%s, %s, %d, %d, NULL, ...)\n\0" as *const u8
                as *const libc::c_char,
            elem,
            name,
            type_0,
            def,
        );
    } else {
        fprintf(
            stdout,
            b"SAX.attributeDecl(%s, %s, %d, %d, %s, ...)\n\0" as *const u8
                as *const libc::c_char,
            elem,
            name,
            type_0,
            def,
            defaultValue,
        );
    }
    xmlFreeEnumeration(tree);
}
unsafe extern "C" fn elementDeclDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut content: xmlElementContentPtr,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.elementDecl(%s, %d, ...)\n\0" as *const u8 as *const libc::c_char,
        name,
        type_0,
    );
}
unsafe extern "C" fn notationDeclDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.notationDecl(%s, %s, %s)\n\0" as *const u8 as *const libc::c_char,
        name as *mut libc::c_char,
        publicId as *mut libc::c_char,
        systemId as *mut libc::c_char,
    );
}
unsafe extern "C" fn unparsedEntityDeclDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    let mut nullstr: *const xmlChar = b"(null)\0" as *const u8 as *const libc::c_char
        as *mut xmlChar;
    if publicId.is_null() {
        publicId = nullstr;
    }
    if systemId.is_null() {
        systemId = nullstr;
    }
    if notationName.is_null() {
        notationName = nullstr;
    }
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.unparsedEntityDecl(%s, %s, %s, %s)\n\0" as *const u8
            as *const libc::c_char,
        name as *mut libc::c_char,
        publicId as *mut libc::c_char,
        systemId as *mut libc::c_char,
        notationName as *mut libc::c_char,
    );
}
unsafe extern "C" fn setDocumentLocatorDebug(
    mut ctx: *mut libc::c_void,
    mut loc: xmlSAXLocatorPtr,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(stdout, b"SAX.setDocumentLocator()\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn startDocumentDebug(mut ctx: *mut libc::c_void) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(stdout, b"SAX.startDocument()\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn endDocumentDebug(mut ctx: *mut libc::c_void) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(stdout, b"SAX.endDocument()\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn startElementDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
    mut atts: *mut *const xmlChar,
) {
    let mut i: libc::c_int = 0;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.startElement(%s\0" as *const u8 as *const libc::c_char,
        name as *mut libc::c_char,
    );
    if !atts.is_null() {
        i = 0 as libc::c_int;
        while !(*atts.offset(i as isize)).is_null() {
            let fresh11 = i;
            i = i + 1;
            fprintf(
                stdout,
                b", %s='\0" as *const u8 as *const libc::c_char,
                *atts.offset(fresh11 as isize),
            );
            if !(*atts.offset(i as isize)).is_null() {
                fprintf(
                    stdout,
                    b"%s'\0" as *const u8 as *const libc::c_char,
                    *atts.offset(i as isize),
                );
            }
            i += 1;
        }
    }
    fprintf(stdout, b")\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn endElementDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.endElement(%s)\n\0" as *const u8 as *const libc::c_char,
        name as *mut libc::c_char,
    );
}
unsafe extern "C" fn charactersDebug(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    let mut out: [libc::c_char; 40] = [0; 40];
    let mut i: libc::c_int = 0;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    i = 0 as libc::c_int;
    while i < len && i < 30 as libc::c_int {
        out[i as usize] = *ch.offset(i as isize) as libc::c_char;
        i += 1;
    }
    out[i as usize] = 0 as libc::c_int as libc::c_char;
    fprintf(
        stdout,
        b"SAX.characters(%s, %d)\n\0" as *const u8 as *const libc::c_char,
        out.as_mut_ptr(),
        len,
    );
}
unsafe extern "C" fn referenceDebug(
    mut ctx: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(stdout, b"SAX.reference(%s)\n\0" as *const u8 as *const libc::c_char, name);
}
unsafe extern "C" fn ignorableWhitespaceDebug(
    mut ctx: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    let mut out: [libc::c_char; 40] = [0; 40];
    let mut i: libc::c_int = 0;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    i = 0 as libc::c_int;
    while i < len && i < 30 as libc::c_int {
        out[i as usize] = *ch.offset(i as isize) as libc::c_char;
        i += 1;
    }
    out[i as usize] = 0 as libc::c_int as libc::c_char;
    fprintf(
        stdout,
        b"SAX.ignorableWhitespace(%s, %d)\n\0" as *const u8 as *const libc::c_char,
        out.as_mut_ptr(),
        len,
    );
}
unsafe extern "C" fn processingInstructionDebug(
    mut ctx: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    if !data.is_null() {
        fprintf(
            stdout,
            b"SAX.processingInstruction(%s, %s)\n\0" as *const u8 as *const libc::c_char,
            target as *mut libc::c_char,
            data as *mut libc::c_char,
        );
    } else {
        fprintf(
            stdout,
            b"SAX.processingInstruction(%s, NULL)\n\0" as *const u8
                as *const libc::c_char,
            target as *mut libc::c_char,
        );
    };
}
unsafe extern "C" fn cdataBlockDebug(
    mut ctx: *mut libc::c_void,
    mut value: *const xmlChar,
    mut len: libc::c_int,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.pcdata(%.20s, %d)\n\0" as *const u8 as *const libc::c_char,
        value as *mut libc::c_char,
        len,
    );
}
unsafe extern "C" fn commentDebug(
    mut ctx: *mut libc::c_void,
    mut value: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(stdout, b"SAX.comment(%s)\n\0" as *const u8 as *const libc::c_char, value);
}
unsafe extern "C" fn warningDebug(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut args_0: ::std::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.warning: \0" as *const u8 as *const libc::c_char);
    vfprintf(stdout, msg, args_0.as_va_list());
}
unsafe extern "C" fn errorDebug(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut args_0: ::std::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.error: \0" as *const u8 as *const libc::c_char);
    vfprintf(stdout, msg, args_0.as_va_list());
}
unsafe extern "C" fn fatalErrorDebug(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut args_0: ::std::ffi::VaListImpl;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    args_0 = args.clone();
    fprintf(stdout, b"SAX.fatalError: \0" as *const u8 as *const libc::c_char);
    vfprintf(stdout, msg, args_0.as_va_list());
}
static mut debugSAXHandlerStruct: xmlSAXHandler = unsafe {
    {
        let mut init = _xmlSAXHandler {
            internalSubset: Some(
                internalSubsetDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            isStandalone: Some(
                isStandaloneDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasInternalSubset: Some(
                hasInternalSubsetDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasExternalSubset: Some(
                hasExternalSubsetDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            resolveEntity: Some(
                resolveEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> xmlParserInputPtr,
            ),
            getEntity: Some(
                getEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            entityDecl: Some(
                entityDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                        *const xmlChar,
                        *const xmlChar,
                        *mut xmlChar,
                    ) -> (),
            ),
            notationDecl: Some(
                notationDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            attributeDecl: Some(
                attributeDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        libc::c_int,
                        libc::c_int,
                        *const xmlChar,
                        xmlEnumerationPtr,
                    ) -> (),
            ),
            elementDecl: Some(
                elementDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                        xmlElementContentPtr,
                    ) -> (),
            ),
            unparsedEntityDecl: Some(
                unparsedEntityDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            setDocumentLocator: Some(
                setDocumentLocatorDebug
                    as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
            ),
            startDocument: Some(
                startDocumentDebug as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            endDocument: Some(
                endDocumentDebug as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            startElement: Some(
                startElementDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                endElementDebug
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: Some(
                referenceDebug
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            characters: Some(
                charactersDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            ignorableWhitespace: Some(
                ignorableWhitespaceDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            processingInstruction: Some(
                processingInstructionDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            comment: Some(
                commentDebug
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                warningDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            error: Some(
                errorDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            fatalError: Some(
                fatalErrorDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            getParameterEntity: Some(
                getParameterEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                cdataBlockDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            externalSubset: Some(
                externalSubsetDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            initialized: 1 as libc::c_int as libc::c_uint,
            _private: 0 as *const libc::c_void as *mut libc::c_void,
            startElementNs: None,
            endElementNs: None,
            serror: None,
        };
        init
    }
};
#[no_mangle]
pub static mut debugSAXHandler: xmlSAXHandlerPtr = unsafe {
    &debugSAXHandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler
};
unsafe extern "C" fn startElementNsDebug(
    mut ctx: *mut libc::c_void,
    mut localname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
    mut nb_namespaces: libc::c_int,
    mut namespaces: *mut *const xmlChar,
    mut nb_attributes: libc::c_int,
    mut nb_defaulted: libc::c_int,
    mut attributes: *mut *const xmlChar,
) {
    let mut i: libc::c_int = 0;
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.startElementNs(%s\0" as *const u8 as *const libc::c_char,
        localname as *mut libc::c_char,
    );
    if prefix.is_null() {
        fprintf(stdout, b", NULL\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(
            stdout,
            b", %s\0" as *const u8 as *const libc::c_char,
            prefix as *mut libc::c_char,
        );
    }
    if URI.is_null() {
        fprintf(stdout, b", NULL\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(
            stdout,
            b", '%s'\0" as *const u8 as *const libc::c_char,
            URI as *mut libc::c_char,
        );
    }
    fprintf(stdout, b", %d\0" as *const u8 as *const libc::c_char, nb_namespaces);
    if !namespaces.is_null() {
        i = 0 as libc::c_int;
        while i < nb_namespaces * 2 as libc::c_int {
            fprintf(stdout, b", xmlns\0" as *const u8 as *const libc::c_char);
            if !(*namespaces.offset(i as isize)).is_null() {
                fprintf(
                    stdout,
                    b":%s\0" as *const u8 as *const libc::c_char,
                    *namespaces.offset(i as isize),
                );
            }
            i += 1;
            fprintf(
                stdout,
                b"='%s'\0" as *const u8 as *const libc::c_char,
                *namespaces.offset(i as isize),
            );
            i += 1;
        }
    }
    fprintf(
        stdout,
        b", %d, %d\0" as *const u8 as *const libc::c_char,
        nb_attributes,
        nb_defaulted,
    );
    if !attributes.is_null() {
        i = 0 as libc::c_int;
        while i < nb_attributes * 5 as libc::c_int {
            if !(*attributes.offset((i + 1 as libc::c_int) as isize)).is_null() {
                fprintf(
                    stdout,
                    b", %s:%s='\0" as *const u8 as *const libc::c_char,
                    *attributes.offset((i + 1 as libc::c_int) as isize),
                    *attributes.offset(i as isize),
                );
            } else {
                fprintf(
                    stdout,
                    b", %s='\0" as *const u8 as *const libc::c_char,
                    *attributes.offset(i as isize),
                );
            }
            fprintf(
                stdout,
                b"%.4s...', %d\0" as *const u8 as *const libc::c_char,
                *attributes.offset((i + 3 as libc::c_int) as isize),
                (*attributes.offset((i + 4 as libc::c_int) as isize))
                    .offset_from(*attributes.offset((i + 3 as libc::c_int) as isize))
                    as libc::c_long as libc::c_int,
            );
            i += 5 as libc::c_int;
        }
    }
    fprintf(stdout, b")\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn endElementNsDebug(
    mut ctx: *mut libc::c_void,
    mut localname: *const xmlChar,
    mut prefix: *const xmlChar,
    mut URI: *const xmlChar,
) {
    callbacks += 1;
    if noout != 0 {
        return;
    }
    fprintf(
        stdout,
        b"SAX.endElementNs(%s\0" as *const u8 as *const libc::c_char,
        localname as *mut libc::c_char,
    );
    if prefix.is_null() {
        fprintf(stdout, b", NULL\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(
            stdout,
            b", %s\0" as *const u8 as *const libc::c_char,
            prefix as *mut libc::c_char,
        );
    }
    if URI.is_null() {
        fprintf(stdout, b", NULL)\n\0" as *const u8 as *const libc::c_char);
    } else {
        fprintf(
            stdout,
            b", '%s')\n\0" as *const u8 as *const libc::c_char,
            URI as *mut libc::c_char,
        );
    };
}
static mut debugSAX2HandlerStruct: xmlSAXHandler = unsafe {
    {
        let mut init = _xmlSAXHandler {
            internalSubset: Some(
                internalSubsetDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            isStandalone: Some(
                isStandaloneDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasInternalSubset: Some(
                hasInternalSubsetDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            hasExternalSubset: Some(
                hasExternalSubsetDebug
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
            resolveEntity: Some(
                resolveEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> xmlParserInputPtr,
            ),
            getEntity: Some(
                getEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            entityDecl: Some(
                entityDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                        *const xmlChar,
                        *const xmlChar,
                        *mut xmlChar,
                    ) -> (),
            ),
            notationDecl: Some(
                notationDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            attributeDecl: Some(
                attributeDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        libc::c_int,
                        libc::c_int,
                        *const xmlChar,
                        xmlEnumerationPtr,
                    ) -> (),
            ),
            elementDecl: Some(
                elementDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                        xmlElementContentPtr,
                    ) -> (),
            ),
            unparsedEntityDecl: Some(
                unparsedEntityDeclDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            setDocumentLocator: Some(
                setDocumentLocatorDebug
                    as unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> (),
            ),
            startDocument: Some(
                startDocumentDebug as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            endDocument: Some(
                endDocumentDebug as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            startElement: None,
            endElement: None,
            reference: Some(
                referenceDebug
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            characters: Some(
                charactersDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            ignorableWhitespace: Some(
                ignorableWhitespaceDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            processingInstruction: Some(
                processingInstructionDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            comment: Some(
                commentDebug
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                warningDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            error: Some(
                errorDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            fatalError: Some(
                fatalErrorDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            getParameterEntity: Some(
                getParameterEntityDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                    ) -> xmlEntityPtr,
            ),
            cdataBlock: Some(
                cdataBlockDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            externalSubset: Some(
                externalSubsetDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            initialized: 0xdeedbeaf as libc::c_uint,
            _private: 0 as *const libc::c_void as *mut libc::c_void,
            startElementNs: Some(
                startElementNsDebug
                    as unsafe extern "C" fn(
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
            ),
            endElementNs: Some(
                endElementNsDebug
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            serror: None,
        };
        init
    }
};
static mut debugSAX2Handler: xmlSAXHandlerPtr = unsafe {
    &debugSAX2HandlerStruct as *const xmlSAXHandler as *mut xmlSAXHandler
};
unsafe extern "C" fn testSAX(mut filename: *const libc::c_char) {
    let mut handler: xmlSAXHandlerPtr = 0 as *mut xmlSAXHandler;
    let mut user_data: *const libc::c_char = b"user_data\0" as *const u8
        as *const libc::c_char;
    let mut buf: xmlParserInputBufferPtr = 0 as xmlParserInputBufferPtr;
    let mut inputStream: xmlParserInputPtr = 0 as *mut xmlParserInput;
    let mut ctxt: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
    let mut old_sax: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    callbacks = 0 as libc::c_int;
    if noout != 0 {
        handler = emptySAXHandler;
    } else if sax1 != 0 {
        handler = debugSAXHandler;
    } else {
        handler = debugSAX2Handler;
    }
    buf = xmlParserInputBufferCreateFilename(filename, XML_CHAR_ENCODING_NONE);
    if !buf.is_null() {
        if !wxschemas.is_null() {
            let mut ret: libc::c_int = 0;
            let mut vctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
            vctxt = xmlSchemaNewValidCtxt(wxschemas);
            if vctxt.is_null() {
                progresult = XMLLINT_ERR_MEM;
                xmlFreeParserInputBuffer(buf);
            } else {
                xmlSchemaSetValidErrors(
                    vctxt,
                    *__xmlGenericError(),
                    *__xmlGenericError(),
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
                if repeat == 0 as libc::c_int {
                    if ret == 0 as libc::c_int {
                        if quiet == 0 {
                            fprintf(
                                stderr,
                                b"%s validates\n\0" as *const u8 as *const libc::c_char,
                                filename,
                            );
                        }
                    } else if ret > 0 as libc::c_int {
                        fprintf(
                            stderr,
                            b"%s fails to validate\n\0" as *const u8
                                as *const libc::c_char,
                            filename,
                        );
                        progresult = XMLLINT_ERR_VALID;
                    } else {
                        fprintf(
                            stderr,
                            b"%s validation generated an internal error\n\0" as *const u8
                                as *const libc::c_char,
                            filename,
                        );
                        progresult = XMLLINT_ERR_VALID;
                    }
                }
                xmlSchemaFreeValidCtxt(vctxt);
            }
        } else {
            ctxt = xmlNewParserCtxt();
            if ctxt.is_null() {
                progresult = XMLLINT_ERR_MEM;
                xmlFreeParserInputBuffer(buf);
            } else {
                old_sax = (*ctxt).sax;
                let ref mut fresh12 = (*ctxt).sax;
                *fresh12 = handler;
                let ref mut fresh13 = (*ctxt).userData;
                *fresh13 = user_data as *mut libc::c_void;
                inputStream = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
                if inputStream.is_null() {
                    xmlFreeParserInputBuffer(buf);
                } else {
                    inputPush(ctxt, inputStream);
                    xmlParseDocument(ctxt);
                    if !((*ctxt).myDoc).is_null() {
                        fprintf(
                            stderr,
                            b"SAX generated a doc !\n\0" as *const u8
                                as *const libc::c_char,
                        );
                        xmlFreeDoc((*ctxt).myDoc);
                        let ref mut fresh14 = (*ctxt).myDoc;
                        *fresh14 = 0 as xmlDocPtr;
                    }
                }
            }
        }
    }
    if !ctxt.is_null() {
        let ref mut fresh15 = (*ctxt).sax;
        *fresh15 = old_sax;
        xmlFreeParserCtxt(ctxt);
    }
}
unsafe extern "C" fn processNode(mut reader: xmlTextReaderPtr) {
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut value: *const xmlChar = 0 as *const xmlChar;
    let mut type_0: libc::c_int = 0;
    let mut empty: libc::c_int = 0;
    type_0 = xmlTextReaderNodeType(reader);
    empty = xmlTextReaderIsEmptyElement(reader);
    if debug != 0 {
        name = xmlTextReaderConstName(reader);
        if name.is_null() {
            name = b"--\0" as *const u8 as *const libc::c_char as *mut xmlChar;
        }
        value = xmlTextReaderConstValue(reader);
        printf(
            b"%d %d %s %d %d\0" as *const u8 as *const libc::c_char,
            xmlTextReaderDepth(reader),
            type_0,
            name,
            empty,
            xmlTextReaderHasValue(reader),
        );
        if value.is_null() {
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b" %s\n\0" as *const u8 as *const libc::c_char, value);
        }
    }
    if !patternc.is_null() {
        let mut path: *mut xmlChar = 0 as *mut xmlChar;
        let mut match_0: libc::c_int = -(1 as libc::c_int);
        if type_0 == XML_READER_TYPE_ELEMENT as libc::c_int {
            match_0 = xmlPatternMatch(patternc, xmlTextReaderCurrentNode(reader));
            if match_0 != 0 {
                path = xmlGetNodePath(
                    xmlTextReaderCurrentNode(reader) as *const xmlNode,
                );
                printf(
                    b"Node %s matches pattern %s\n\0" as *const u8
                        as *const libc::c_char,
                    path,
                    pattern,
                );
            }
        }
        if !patstream.is_null() {
            let mut ret: libc::c_int = 0;
            if type_0 == XML_READER_TYPE_ELEMENT as libc::c_int {
                ret = xmlStreamPush(
                    patstream,
                    xmlTextReaderConstLocalName(reader),
                    xmlTextReaderConstNamespaceUri(reader),
                );
                if ret < 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"xmlStreamPush() failure\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    xmlFreeStreamCtxt(patstream);
                    patstream = 0 as xmlStreamCtxtPtr;
                } else if ret != match_0 {
                    if path.is_null() {
                        path = xmlGetNodePath(
                            xmlTextReaderCurrentNode(reader) as *const xmlNode,
                        );
                    }
                    fprintf(
                        stderr,
                        b"xmlPatternMatch and xmlStreamPush disagree\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    if !path.is_null() {
                        fprintf(
                            stderr,
                            b"  pattern %s node %s\n\0" as *const u8
                                as *const libc::c_char,
                            pattern,
                            path,
                        );
                    } else {
                        fprintf(
                            stderr,
                            b"  pattern %s node %s\n\0" as *const u8
                                as *const libc::c_char,
                            pattern,
                            xmlTextReaderConstName(reader),
                        );
                    }
                }
            }
            if type_0 == XML_READER_TYPE_END_ELEMENT as libc::c_int
                || type_0 == XML_READER_TYPE_ELEMENT as libc::c_int && empty != 0
            {
                ret = xmlStreamPop(patstream);
                if ret < 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"xmlStreamPop() failure\n\0" as *const u8 as *const libc::c_char,
                    );
                    xmlFreeStreamCtxt(patstream);
                    patstream = 0 as xmlStreamCtxtPtr;
                }
            }
        }
        if !path.is_null() {
            xmlFree.expect("non-null function pointer")(path as *mut libc::c_void);
        }
    }
}
unsafe extern "C" fn streamFile(mut filename: *mut libc::c_char) {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut ret: libc::c_int = 0;
    let mut fd: libc::c_int = -(1 as libc::c_int);
    let mut info: stat = stat {
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
        st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
        st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
        __glibc_reserved: [0; 3],
    };
    let mut base: *const libc::c_char = 0 as *const libc::c_char;
    let mut input: xmlParserInputBufferPtr = 0 as xmlParserInputBufferPtr;
    if memory != 0 {
        if stat(filename, &mut info) < 0 as libc::c_int {
            return;
        }
        fd = open(filename, 0 as libc::c_int);
        if fd < 0 as libc::c_int {
            return;
        }
        base = mmap(
            0 as *mut libc::c_void,
            info.st_size as size_t,
            0x1 as libc::c_int,
            0x1 as libc::c_int,
            fd,
            0 as libc::c_int as __off64_t,
        ) as *const libc::c_char;
        if base == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_char {
            close(fd);
            fprintf(
                stderr,
                b"mmap failure for file %s\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_RDFILE;
            return;
        }
        reader = xmlReaderForMemory(
            base,
            info.st_size as libc::c_int,
            filename,
            0 as *const libc::c_char,
            options,
        );
    } else {
        reader = xmlReaderForFile(filename, 0 as *const libc::c_char, options);
    }
    if !pattern.is_null() {
        patternc = xmlPatterncompile(
            pattern as *const xmlChar,
            0 as *mut xmlDict,
            0 as libc::c_int,
            0 as *mut *const xmlChar,
        );
        if patternc.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Pattern %s failed to compile\n\0" as *const u8 as *const libc::c_char,
                pattern,
            );
            progresult = XMLLINT_ERR_SCHEMAPAT;
            pattern = 0 as *const libc::c_char;
        }
    }
    if !patternc.is_null() {
        patstream = xmlPatternGetStreamCtxt(patternc);
        if !patstream.is_null() {
            ret = xmlStreamPush(patstream, 0 as *const xmlChar, 0 as *const xmlChar);
            if ret < 0 as libc::c_int {
                fprintf(
                    stderr,
                    b"xmlStreamPush() failure\n\0" as *const u8 as *const libc::c_char,
                );
                xmlFreeStreamCtxt(patstream);
                patstream = 0 as xmlStreamCtxtPtr;
            }
        }
    }
    if !reader.is_null() {
        if valid != 0 {
            xmlTextReaderSetParserProp(
                reader,
                XML_PARSER_VALIDATE as libc::c_int,
                1 as libc::c_int,
            );
        } else if loaddtd != 0 {
            xmlTextReaderSetParserProp(
                reader,
                XML_PARSER_LOADDTD as libc::c_int,
                1 as libc::c_int,
            );
        }
        if !relaxng.is_null() {
            if timing != 0 && repeat == 0 {
                startTimer();
            }
            ret = xmlTextReaderRelaxNGValidate(reader, relaxng);
            if ret < 0 as libc::c_int {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Relax-NG schema %s failed to compile\n\0" as *const u8
                        as *const libc::c_char,
                    relaxng,
                );
                progresult = XMLLINT_ERR_SCHEMACOMP;
                relaxng = 0 as *mut libc::c_char;
            }
            if timing != 0 && repeat == 0 {
                endTimer(b"Compiling the schemas\0" as *const u8 as *const libc::c_char);
            }
        }
        if !schema.is_null() {
            if timing != 0 && repeat == 0 {
                startTimer();
            }
            ret = xmlTextReaderSchemaValidate(reader, schema);
            if ret < 0 as libc::c_int {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"XSD schema %s failed to compile\n\0" as *const u8
                        as *const libc::c_char,
                    schema,
                );
                progresult = XMLLINT_ERR_SCHEMACOMP;
                schema = 0 as *mut libc::c_char;
            }
            if timing != 0 && repeat == 0 {
                endTimer(b"Compiling the schemas\0" as *const u8 as *const libc::c_char);
            }
        }
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        ret = xmlTextReaderRead(reader);
        while ret == 1 as libc::c_int {
            if debug != 0 || !patternc.is_null() {
                processNode(reader);
            }
            ret = xmlTextReaderRead(reader);
        }
        if timing != 0 && repeat == 0 {
            if !relaxng.is_null() {
                endTimer(
                    b"Parsing and validating\0" as *const u8 as *const libc::c_char,
                );
            } else if valid != 0 {
                endTimer(
                    b"Parsing and validating\0" as *const u8 as *const libc::c_char,
                );
            } else {
                endTimer(b"Parsing\0" as *const u8 as *const libc::c_char);
            }
        }
        if valid != 0 {
            if xmlTextReaderIsValid(reader) != 1 as libc::c_int {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Document %s does not validate\n\0" as *const u8
                        as *const libc::c_char,
                    filename,
                );
                progresult = XMLLINT_ERR_VALID;
            }
        }
        if !relaxng.is_null() || !schema.is_null() {
            if xmlTextReaderIsValid(reader) != 1 as libc::c_int {
                fprintf(
                    stderr,
                    b"%s fails to validate\n\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                progresult = XMLLINT_ERR_VALID;
            } else if quiet == 0 {
                fprintf(
                    stderr,
                    b"%s validates\n\0" as *const u8 as *const libc::c_char,
                    filename,
                );
            }
        }
        xmlFreeTextReader(reader);
        if ret != 0 as libc::c_int {
            fprintf(
                stderr,
                b"%s : failed to parse\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_UNCLASS;
        }
    } else {
        fprintf(
            stderr,
            b"Unable to open %s\n\0" as *const u8 as *const libc::c_char,
            filename,
        );
        progresult = XMLLINT_ERR_UNCLASS;
    }
    if !patstream.is_null() {
        xmlFreeStreamCtxt(patstream);
        patstream = 0 as xmlStreamCtxtPtr;
    }
    if memory != 0 {
        xmlFreeParserInputBuffer(input);
        munmap(base as *mut libc::c_char as *mut libc::c_void, info.st_size as size_t);
        close(fd);
    }
}
unsafe extern "C" fn walkDoc(mut doc: xmlDocPtr) {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut ret: libc::c_int = 0;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut namespaces: [*const xmlChar; 22] = [0 as *const xmlChar; 22];
    let mut i: libc::c_int = 0;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    root = xmlDocGetRootElement(doc as *const xmlDoc);
    if root.is_null() {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"Document does not have a root element\0" as *const u8
                as *const libc::c_char,
        );
        progresult = XMLLINT_ERR_UNCLASS;
        return;
    }
    ns = (*root).nsDef;
    i = 0 as libc::c_int;
    while !ns.is_null() && i < 20 as libc::c_int {
        let fresh16 = i;
        i = i + 1;
        namespaces[fresh16 as usize] = (*ns).href;
        let fresh17 = i;
        i = i + 1;
        namespaces[fresh17 as usize] = (*ns).prefix;
        ns = (*ns).next;
    }
    let fresh18 = i;
    i = i + 1;
    namespaces[fresh18 as usize] = 0 as *const xmlChar;
    namespaces[i as usize] = 0 as *const xmlChar;
    if !pattern.is_null() {
        patternc = xmlPatterncompile(
            pattern as *const xmlChar,
            (*doc).dict,
            0 as libc::c_int,
            &mut *namespaces.as_mut_ptr().offset(0 as libc::c_int as isize),
        );
        if patternc.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Pattern %s failed to compile\n\0" as *const u8 as *const libc::c_char,
                pattern,
            );
            progresult = XMLLINT_ERR_SCHEMAPAT;
            pattern = 0 as *const libc::c_char;
        }
    }
    if !patternc.is_null() {
        patstream = xmlPatternGetStreamCtxt(patternc);
        if !patstream.is_null() {
            ret = xmlStreamPush(patstream, 0 as *const xmlChar, 0 as *const xmlChar);
            if ret < 0 as libc::c_int {
                fprintf(
                    stderr,
                    b"xmlStreamPush() failure\n\0" as *const u8 as *const libc::c_char,
                );
                xmlFreeStreamCtxt(patstream);
                patstream = 0 as xmlStreamCtxtPtr;
            }
        }
    }
    reader = xmlReaderWalker(doc);
    if !reader.is_null() {
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        ret = xmlTextReaderRead(reader);
        while ret == 1 as libc::c_int {
            if debug != 0 || !patternc.is_null() {
                processNode(reader);
            }
            ret = xmlTextReaderRead(reader);
        }
        if timing != 0 && repeat == 0 {
            endTimer(b"walking through the doc\0" as *const u8 as *const libc::c_char);
        }
        xmlFreeTextReader(reader);
        if ret != 0 as libc::c_int {
            fprintf(
                stderr,
                b"failed to walk through the doc\n\0" as *const u8 as *const libc::c_char,
            );
            progresult = XMLLINT_ERR_UNCLASS;
        }
    } else {
        fprintf(
            stderr,
            b"Failed to crate a reader from the document\n\0" as *const u8
                as *const libc::c_char,
        );
        progresult = XMLLINT_ERR_UNCLASS;
    }
    if !patstream.is_null() {
        xmlFreeStreamCtxt(patstream);
        patstream = 0 as xmlStreamCtxtPtr;
    }
}
unsafe extern "C" fn doXPathDump(mut cur: xmlXPathObjectPtr) {
    match (*cur).type_0 as libc::c_uint {
        1 => {
            let mut i: libc::c_int = 0;
            let mut node: xmlNodePtr = 0 as *mut xmlNode;
            let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
            if ((*cur).nodesetval).is_null()
                || (*(*cur).nodesetval).nodeNr <= 0 as libc::c_int
            {
                fprintf(
                    stderr,
                    b"XPath set is empty\n\0" as *const u8 as *const libc::c_char,
                );
                progresult = XMLLINT_ERR_XPATH;
            } else {
                buf = xmlOutputBufferCreateFile(stdout, 0 as xmlCharEncodingHandlerPtr);
                if buf.is_null() {
                    fprintf(
                        stderr,
                        b"Out of memory for XPath\n\0" as *const u8
                            as *const libc::c_char,
                    );
                    progresult = XMLLINT_ERR_MEM;
                    return;
                }
                i = 0 as libc::c_int;
                while i < (*(*cur).nodesetval).nodeNr {
                    node = *((*(*cur).nodesetval).nodeTab).offset(i as isize);
                    xmlNodeDumpOutput(
                        buf,
                        0 as xmlDocPtr,
                        node,
                        0 as libc::c_int,
                        0 as libc::c_int,
                        0 as *const libc::c_char,
                    );
                    xmlOutputBufferWrite(
                        buf,
                        1 as libc::c_int,
                        b"\n\0" as *const u8 as *const libc::c_char,
                    );
                    i += 1;
                }
                xmlOutputBufferClose(buf);
            }
        }
        2 => {
            if (*cur).boolval != 0 {
                printf(b"true\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"false\n\0" as *const u8 as *const libc::c_char);
            }
        }
        3 => {
            match xmlXPathIsInf((*cur).floatval) {
                1 => {
                    printf(b"Infinity\n\0" as *const u8 as *const libc::c_char);
                }
                -1 => {
                    printf(b"-Infinity\n\0" as *const u8 as *const libc::c_char);
                }
                _ => {
                    if xmlXPathIsNaN((*cur).floatval) != 0 {
                        printf(b"NaN\n\0" as *const u8 as *const libc::c_char);
                    } else {
                        printf(
                            b"%0g\n\0" as *const u8 as *const libc::c_char,
                            (*cur).floatval,
                        );
                    }
                }
            }
        }
        4 => {
            printf(
                b"%s\n\0" as *const u8 as *const libc::c_char,
                (*cur).stringval as *const libc::c_char,
            );
        }
        0 => {
            fprintf(
                stderr,
                b"XPath Object is uninitialized\n\0" as *const u8 as *const libc::c_char,
            );
            progresult = XMLLINT_ERR_XPATH;
        }
        _ => {
            fprintf(
                stderr,
                b"XPath object of unexpected type\n\0" as *const u8
                    as *const libc::c_char,
            );
            progresult = XMLLINT_ERR_XPATH;
        }
    };
}
unsafe extern "C" fn doXPathQuery(mut doc: xmlDocPtr, mut query: *const libc::c_char) {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut res: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    ctxt = xmlXPathNewContext(doc);
    if ctxt.is_null() {
        fprintf(
            stderr,
            b"Out of memory for XPath\n\0" as *const u8 as *const libc::c_char,
        );
        progresult = XMLLINT_ERR_MEM;
        return;
    }
    let ref mut fresh19 = (*ctxt).node;
    *fresh19 = doc as xmlNodePtr;
    res = xmlXPathEval(query as *mut xmlChar, ctxt);
    xmlXPathFreeContext(ctxt);
    if res.is_null() {
        fprintf(
            stderr,
            b"XPath evaluation failure\n\0" as *const u8 as *const libc::c_char,
        );
        progresult = XMLLINT_ERR_XPATH;
        return;
    }
    doXPathDump(res);
    xmlXPathFreeObject(res);
}
unsafe extern "C" fn parseAndPrintFile(
    mut filename: *mut libc::c_char,
    mut rectxt: xmlParserCtxtPtr,
) {
    let mut doc: xmlDocPtr = 0 as xmlDocPtr;
    let mut tmp: xmlDocPtr = 0 as *mut xmlDoc;
    if timing != 0 && repeat == 0 {
        startTimer();
    }
    if filename.is_null() {
        if generate != 0 {
            let mut n: xmlNodePtr = 0 as *mut xmlNode;
            doc = xmlNewDoc(
                b"1.0\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            n = xmlNewDocNode(
                doc,
                0 as xmlNsPtr,
                b"info\0" as *const u8 as *const libc::c_char as *mut xmlChar,
                0 as *const xmlChar,
            );
            xmlNodeSetContent(
                n,
                b"abc\0" as *const u8 as *const libc::c_char as *mut xmlChar,
            );
            xmlDocSetRootElement(doc, n);
        }
    } else if html != 0 && push != 0 {
        let mut f: *mut FILE = 0 as *mut FILE;
        if *filename.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32
            && *filename.offset(1 as libc::c_int as isize) as libc::c_int
                == 0 as libc::c_int
        {
            f = stdin;
        } else {
            f = fopen(filename, b"rb\0" as *const u8 as *const libc::c_char);
        }
        if !f.is_null() {
            let mut res: libc::c_int = 0;
            let mut chars: [libc::c_char; 4096] = [0; 4096];
            let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
            res = fread(
                chars.as_mut_ptr() as *mut libc::c_void,
                1 as libc::c_int as libc::c_ulong,
                4 as libc::c_int as libc::c_ulong,
                f,
            ) as libc::c_int;
            if res > 0 as libc::c_int {
                ctxt = htmlCreatePushParserCtxt(
                    0 as htmlSAXHandlerPtr,
                    0 as *mut libc::c_void,
                    chars.as_mut_ptr(),
                    res,
                    filename,
                    XML_CHAR_ENCODING_NONE,
                );
                if ctxt.is_null() {
                    progresult = XMLLINT_ERR_MEM;
                    if f != stdin {
                        fclose(f);
                    }
                    return;
                }
                htmlCtxtUseOptions(ctxt, options);
                loop {
                    res = fread(
                        chars.as_mut_ptr() as *mut libc::c_void,
                        1 as libc::c_int as libc::c_ulong,
                        pushsize as libc::c_ulong,
                        f,
                    ) as libc::c_int;
                    if !(res > 0 as libc::c_int) {
                        break;
                    }
                    htmlParseChunk(ctxt, chars.as_mut_ptr(), res, 0 as libc::c_int);
                }
                htmlParseChunk(
                    ctxt,
                    chars.as_mut_ptr(),
                    0 as libc::c_int,
                    1 as libc::c_int,
                );
                doc = (*ctxt).myDoc;
                htmlFreeParserCtxt(ctxt);
            }
            if f != stdin {
                fclose(f);
            }
        }
    } else if html != 0 && memory != 0 {
        let mut fd: libc::c_int = 0;
        let mut info: stat = stat {
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
            st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
            __glibc_reserved: [0; 3],
        };
        let mut base: *const libc::c_char = 0 as *const libc::c_char;
        if stat(filename, &mut info) < 0 as libc::c_int {
            return;
        }
        fd = open(filename, 0 as libc::c_int);
        if fd < 0 as libc::c_int {
            return;
        }
        base = mmap(
            0 as *mut libc::c_void,
            info.st_size as size_t,
            0x1 as libc::c_int,
            0x1 as libc::c_int,
            fd,
            0 as libc::c_int as __off64_t,
        ) as *const libc::c_char;
        if base == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_char {
            close(fd);
            fprintf(
                stderr,
                b"mmap failure for file %s\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_RDFILE;
            return;
        }
        doc = htmlReadMemory(
            base as *mut libc::c_char,
            info.st_size as libc::c_int,
            filename,
            0 as *const libc::c_char,
            options,
        );
        munmap(base as *mut libc::c_char as *mut libc::c_void, info.st_size as size_t);
        close(fd);
    } else if html != 0 {
        doc = htmlReadFile(filename, 0 as *const libc::c_char, options);
    } else if push != 0 {
        let mut f_0: *mut FILE = 0 as *mut FILE;
        if *filename.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32
            && *filename.offset(1 as libc::c_int as isize) as libc::c_int
                == 0 as libc::c_int
        {
            f_0 = stdin;
        } else {
            f_0 = fopen(filename, b"rb\0" as *const u8 as *const libc::c_char);
        }
        if !f_0.is_null() {
            let mut ret: libc::c_int = 0;
            let mut res_0: libc::c_int = 0;
            let mut size: libc::c_int = 1024 as libc::c_int;
            let mut chars_0: [libc::c_char; 1024] = [0; 1024];
            let mut ctxt_0: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
            res_0 = fread(
                chars_0.as_mut_ptr() as *mut libc::c_void,
                1 as libc::c_int as libc::c_ulong,
                4 as libc::c_int as libc::c_ulong,
                f_0,
            ) as libc::c_int;
            if res_0 > 0 as libc::c_int {
                ctxt_0 = xmlCreatePushParserCtxt(
                    0 as xmlSAXHandlerPtr,
                    0 as *mut libc::c_void,
                    chars_0.as_mut_ptr(),
                    res_0,
                    filename,
                );
                if ctxt_0.is_null() {
                    progresult = XMLLINT_ERR_MEM;
                    if f_0 != stdin {
                        fclose(f_0);
                    }
                    return;
                }
                xmlCtxtUseOptions(ctxt_0, options);
                loop {
                    res_0 = fread(
                        chars_0.as_mut_ptr() as *mut libc::c_void,
                        1 as libc::c_int as libc::c_ulong,
                        size as libc::c_ulong,
                        f_0,
                    ) as libc::c_int;
                    if !(res_0 > 0 as libc::c_int) {
                        break;
                    }
                    xmlParseChunk(ctxt_0, chars_0.as_mut_ptr(), res_0, 0 as libc::c_int);
                }
                xmlParseChunk(
                    ctxt_0,
                    chars_0.as_mut_ptr(),
                    0 as libc::c_int,
                    1 as libc::c_int,
                );
                doc = (*ctxt_0).myDoc;
                ret = (*ctxt_0).wellFormed;
                xmlFreeParserCtxt(ctxt_0);
                if ret == 0 && recovery == 0 {
                    xmlFreeDoc(doc);
                    doc = 0 as xmlDocPtr;
                }
            }
            if f_0 != stdin {
                fclose(f_0);
            }
        }
    } else if testIO != 0 {
        if *filename.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32
            && *filename.offset(1 as libc::c_int as isize) as libc::c_int
                == 0 as libc::c_int
        {
            doc = xmlReadFd(
                0 as libc::c_int,
                0 as *const libc::c_char,
                0 as *const libc::c_char,
                options,
            );
        } else {
            let mut f_1: *mut FILE = 0 as *mut FILE;
            f_1 = fopen(filename, b"rb\0" as *const u8 as *const libc::c_char);
            if !f_1.is_null() {
                if rectxt.is_null() {
                    doc = xmlReadIO(
                        Some(
                            myRead
                                as unsafe extern "C" fn(
                                    *mut libc::c_void,
                                    *mut libc::c_char,
                                    libc::c_int,
                                ) -> libc::c_int,
                        ),
                        Some(
                            myClose
                                as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
                        ),
                        f_1 as *mut libc::c_void,
                        filename,
                        0 as *const libc::c_char,
                        options,
                    );
                } else {
                    doc = xmlCtxtReadIO(
                        rectxt,
                        Some(
                            myRead
                                as unsafe extern "C" fn(
                                    *mut libc::c_void,
                                    *mut libc::c_char,
                                    libc::c_int,
                                ) -> libc::c_int,
                        ),
                        Some(
                            myClose
                                as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
                        ),
                        f_1 as *mut libc::c_void,
                        filename,
                        0 as *const libc::c_char,
                        options,
                    );
                }
            } else {
                doc = 0 as xmlDocPtr;
            }
        }
    } else if htmlout != 0 {
        let mut ctxt_1: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
        if rectxt.is_null() {
            ctxt_1 = xmlNewParserCtxt();
            if ctxt_1.is_null() {
                progresult = XMLLINT_ERR_MEM;
                return;
            }
        } else {
            ctxt_1 = rectxt;
        }
        let ref mut fresh20 = (*(*ctxt_1).sax).error;
        *fresh20 = Some(
            xmlHTMLError
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh21 = (*(*ctxt_1).sax).warning;
        *fresh21 = Some(
            xmlHTMLWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh22 = (*ctxt_1).vctxt.error;
        *fresh22 = Some(
            xmlHTMLValidityError
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh23 = (*ctxt_1).vctxt.warning;
        *fresh23 = Some(
            xmlHTMLValidityWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        doc = xmlCtxtReadFile(ctxt_1, filename, 0 as *const libc::c_char, options);
        if rectxt.is_null() {
            xmlFreeParserCtxt(ctxt_1);
        }
    } else if memory != 0 {
        let mut fd_0: libc::c_int = 0;
        let mut info_0: stat = stat {
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
            st_atim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_mtim: timespec { tv_sec: 0, tv_nsec: 0 },
            st_ctim: timespec { tv_sec: 0, tv_nsec: 0 },
            __glibc_reserved: [0; 3],
        };
        let mut base_0: *const libc::c_char = 0 as *const libc::c_char;
        if stat(filename, &mut info_0) < 0 as libc::c_int {
            return;
        }
        fd_0 = open(filename, 0 as libc::c_int);
        if fd_0 < 0 as libc::c_int {
            return;
        }
        base_0 = mmap(
            0 as *mut libc::c_void,
            info_0.st_size as size_t,
            0x1 as libc::c_int,
            0x1 as libc::c_int,
            fd_0,
            0 as libc::c_int as __off64_t,
        ) as *const libc::c_char;
        if base_0 == -(1 as libc::c_int) as *mut libc::c_void as *const libc::c_char {
            close(fd_0);
            fprintf(
                stderr,
                b"mmap failure for file %s\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_RDFILE;
            return;
        }
        if rectxt.is_null() {
            doc = xmlReadMemory(
                base_0 as *mut libc::c_char,
                info_0.st_size as libc::c_int,
                filename,
                0 as *const libc::c_char,
                options,
            );
        } else {
            doc = xmlCtxtReadMemory(
                rectxt,
                base_0 as *mut libc::c_char,
                info_0.st_size as libc::c_int,
                filename,
                0 as *const libc::c_char,
                options,
            );
        }
        munmap(
            base_0 as *mut libc::c_char as *mut libc::c_void,
            info_0.st_size as size_t,
        );
        close(fd_0);
    } else if valid != 0 {
        let mut ctxt_2: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
        if rectxt.is_null() {
            ctxt_2 = xmlNewParserCtxt();
            if ctxt_2.is_null() {
                progresult = XMLLINT_ERR_MEM;
                return;
            }
        } else {
            ctxt_2 = rectxt;
        }
        doc = xmlCtxtReadFile(ctxt_2, filename, 0 as *const libc::c_char, options);
        if (*ctxt_2).valid == 0 as libc::c_int {
            progresult = XMLLINT_ERR_RDFILE;
        }
        if rectxt.is_null() {
            xmlFreeParserCtxt(ctxt_2);
        }
    } else if !rectxt.is_null() {
        doc = xmlCtxtReadFile(rectxt, filename, 0 as *const libc::c_char, options);
    } else if sax1 != 0 {
        doc = xmlParseFile(filename);
    } else {
        doc = xmlReadFile(filename, 0 as *const libc::c_char, options);
    }
    if doc.is_null() {
        progresult = XMLLINT_ERR_UNCLASS;
        return;
    }
    if timing != 0 && repeat == 0 {
        endTimer(b"Parsing\0" as *const u8 as *const libc::c_char);
    }
    if dropdtd != 0 {
        let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
        dtd = xmlGetIntSubset(doc as *const xmlDoc);
        if !dtd.is_null() {
            xmlUnlinkNode(dtd as xmlNodePtr);
            let ref mut fresh24 = (*doc).intSubset;
            *fresh24 = 0 as *mut _xmlDtd;
            xmlFreeDtd(dtd);
        }
    }
    if xinclude != 0 {
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        if xmlXIncludeProcessFlags(doc, options) < 0 as libc::c_int {
            progresult = XMLLINT_ERR_UNCLASS;
        }
        if timing != 0 && repeat == 0 {
            endTimer(b"Xinclude processing\0" as *const u8 as *const libc::c_char);
        }
    }
    if !xpathquery.is_null() {
        doXPathQuery(doc, xpathquery);
    }
    if shell != 0 {
        xmlXPathOrderDocElems(doc);
        xmlShell(
            doc,
            filename,
            Some(
                xmlShellReadline
                    as unsafe extern "C" fn(*mut libc::c_char) -> *mut libc::c_char,
            ),
            stdout,
        );
    }
    if copy != 0 {
        tmp = doc;
        if timing != 0 {
            startTimer();
        }
        doc = xmlCopyDoc(doc, 1 as libc::c_int);
        if timing != 0 {
            endTimer(b"Copying\0" as *const u8 as *const libc::c_char);
        }
        if timing != 0 {
            startTimer();
        }
        xmlFreeDoc(tmp);
        if timing != 0 {
            endTimer(b"Freeing original\0" as *const u8 as *const libc::c_char);
        }
    }
    if insert != 0 && html == 0 {
        let mut list: [*const xmlChar; 256] = [0 as *const xmlChar; 256];
        let mut nb: libc::c_int = 0;
        let mut i: libc::c_int = 0;
        let mut node: xmlNodePtr = 0 as *mut xmlNode;
        if !((*doc).children).is_null() {
            node = (*doc).children;
            while !node.is_null() && ((*node).last).is_null() {
                node = (*node).next;
            }
            if !node.is_null() {
                nb = xmlValidGetValidElements(
                    (*node).last,
                    0 as *mut xmlNode,
                    list.as_mut_ptr(),
                    256 as libc::c_int,
                );
                if nb < 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"could not get valid list of elements\n\0" as *const u8
                            as *const libc::c_char,
                    );
                } else if nb == 0 as libc::c_int {
                    fprintf(
                        stderr,
                        b"No element can be inserted under root\n\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    fprintf(
                        stderr,
                        b"%d element types can be inserted under root:\n\0" as *const u8
                            as *const libc::c_char,
                        nb,
                    );
                    i = 0 as libc::c_int;
                    while i < nb {
                        fprintf(
                            stderr,
                            b"%s\n\0" as *const u8 as *const libc::c_char,
                            list[i as usize] as *mut libc::c_char,
                        );
                        i += 1;
                    }
                }
            }
        }
    } else if walker != 0 {
        walkDoc(doc);
    }
    if noout == 0 as libc::c_int {
        let mut ret_0: libc::c_int = 0;
        if debug == 0 {
            if timing != 0 && repeat == 0 {
                startTimer();
            }
            if html != 0 && xmlout == 0 {
                if compress != 0 {
                    htmlSaveFile(
                        if !output.is_null() {
                            output
                        } else {
                            b"-\0" as *const u8 as *const libc::c_char
                        },
                        doc,
                    );
                } else if !encoding.is_null() {
                    if format == 1 as libc::c_int {
                        htmlSaveFileFormat(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                            doc,
                            encoding,
                            1 as libc::c_int,
                        );
                    } else {
                        htmlSaveFileFormat(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                            doc,
                            encoding,
                            0 as libc::c_int,
                        );
                    }
                } else if format == 1 as libc::c_int {
                    htmlSaveFileFormat(
                        if !output.is_null() {
                            output
                        } else {
                            b"-\0" as *const u8 as *const libc::c_char
                        },
                        doc,
                        0 as *const libc::c_char,
                        1 as libc::c_int,
                    );
                } else {
                    let mut out: *mut FILE = 0 as *mut FILE;
                    if output.is_null() {
                        out = stdout;
                    } else {
                        out = fopen(output, b"wb\0" as *const u8 as *const libc::c_char);
                    }
                    if !out.is_null() {
                        if htmlDocDump(out, doc) < 0 as libc::c_int {
                            progresult = XMLLINT_ERR_OUT;
                        }
                        if !output.is_null() {
                            fclose(out);
                        }
                    } else {
                        fprintf(
                            stderr,
                            b"failed to open %s\n\0" as *const u8 as *const libc::c_char,
                            output,
                        );
                        progresult = XMLLINT_ERR_OUT;
                    }
                }
                if timing != 0 && repeat == 0 {
                    endTimer(b"Saving\0" as *const u8 as *const libc::c_char);
                }
            } else if canonical != 0 {
                let mut result: *mut xmlChar = 0 as *mut xmlChar;
                let mut size_0: libc::c_int = 0;
                size_0 = xmlC14NDocDumpMemory(
                    doc,
                    0 as xmlNodeSetPtr,
                    XML_C14N_1_0 as libc::c_int,
                    0 as *mut *mut xmlChar,
                    1 as libc::c_int,
                    &mut result,
                );
                if size_0 >= 0 as libc::c_int {
                    if write(
                        1 as libc::c_int,
                        result as *const libc::c_void,
                        size_0 as size_t,
                    ) == -(1 as libc::c_int) as libc::c_long
                    {
                        fprintf(
                            stderr,
                            b"Can't write data\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(result as *mut libc::c_void);
                } else {
                    fprintf(
                        stderr,
                        b"Failed to canonicalize\n\0" as *const u8 as *const libc::c_char,
                    );
                    progresult = XMLLINT_ERR_OUT;
                }
            } else if canonical_11 != 0 {
                let mut result_0: *mut xmlChar = 0 as *mut xmlChar;
                let mut size_1: libc::c_int = 0;
                size_1 = xmlC14NDocDumpMemory(
                    doc,
                    0 as xmlNodeSetPtr,
                    XML_C14N_1_1 as libc::c_int,
                    0 as *mut *mut xmlChar,
                    1 as libc::c_int,
                    &mut result_0,
                );
                if size_1 >= 0 as libc::c_int {
                    if write(
                        1 as libc::c_int,
                        result_0 as *const libc::c_void,
                        size_1 as size_t,
                    ) == -(1 as libc::c_int) as libc::c_long
                    {
                        fprintf(
                            stderr,
                            b"Can't write data\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(result_0 as *mut libc::c_void);
                } else {
                    fprintf(
                        stderr,
                        b"Failed to canonicalize\n\0" as *const u8 as *const libc::c_char,
                    );
                    progresult = XMLLINT_ERR_OUT;
                }
            } else if exc_canonical != 0 {
                let mut result_1: *mut xmlChar = 0 as *mut xmlChar;
                let mut size_2: libc::c_int = 0;
                size_2 = xmlC14NDocDumpMemory(
                    doc,
                    0 as xmlNodeSetPtr,
                    XML_C14N_EXCLUSIVE_1_0 as libc::c_int,
                    0 as *mut *mut xmlChar,
                    1 as libc::c_int,
                    &mut result_1,
                );
                if size_2 >= 0 as libc::c_int {
                    if write(
                        1 as libc::c_int,
                        result_1 as *const libc::c_void,
                        size_2 as size_t,
                    ) == -(1 as libc::c_int) as libc::c_long
                    {
                        fprintf(
                            stderr,
                            b"Can't write data\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(result_1 as *mut libc::c_void);
                } else {
                    fprintf(
                        stderr,
                        b"Failed to canonicalize\n\0" as *const u8 as *const libc::c_char,
                    );
                    progresult = XMLLINT_ERR_OUT;
                }
            } else if memory != 0 {
                let mut result_2: *mut xmlChar = 0 as *mut xmlChar;
                let mut len: libc::c_int = 0;
                if !encoding.is_null() {
                    if format == 1 as libc::c_int {
                        xmlDocDumpFormatMemoryEnc(
                            doc,
                            &mut result_2,
                            &mut len,
                            encoding,
                            1 as libc::c_int,
                        );
                    } else {
                        xmlDocDumpMemoryEnc(doc, &mut result_2, &mut len, encoding);
                    }
                } else if format == 1 as libc::c_int {
                    xmlDocDumpFormatMemory(
                        doc,
                        &mut result_2,
                        &mut len,
                        1 as libc::c_int,
                    );
                } else {
                    xmlDocDumpMemory(doc, &mut result_2, &mut len);
                }
                if result_2.is_null() {
                    fprintf(
                        stderr,
                        b"Failed to save\n\0" as *const u8 as *const libc::c_char,
                    );
                    progresult = XMLLINT_ERR_OUT;
                } else {
                    if write(
                        1 as libc::c_int,
                        result_2 as *const libc::c_void,
                        len as size_t,
                    ) == -(1 as libc::c_int) as libc::c_long
                    {
                        fprintf(
                            stderr,
                            b"Can't write data\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(result_2 as *mut libc::c_void);
                }
            } else if compress != 0 {
                xmlSaveFile(
                    if !output.is_null() {
                        output
                    } else {
                        b"-\0" as *const u8 as *const libc::c_char
                    },
                    doc,
                );
            } else if oldout != 0 {
                if !encoding.is_null() {
                    if format == 1 as libc::c_int {
                        ret_0 = xmlSaveFormatFileEnc(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                            doc,
                            encoding,
                            1 as libc::c_int,
                        );
                    } else {
                        ret_0 = xmlSaveFileEnc(
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                            doc,
                            encoding,
                        );
                    }
                    if ret_0 < 0 as libc::c_int {
                        fprintf(
                            stderr,
                            b"failed save to %s\n\0" as *const u8 as *const libc::c_char,
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                        );
                        progresult = XMLLINT_ERR_OUT;
                    }
                } else if format == 1 as libc::c_int {
                    ret_0 = xmlSaveFormatFile(
                        if !output.is_null() {
                            output
                        } else {
                            b"-\0" as *const u8 as *const libc::c_char
                        },
                        doc,
                        1 as libc::c_int,
                    );
                    if ret_0 < 0 as libc::c_int {
                        fprintf(
                            stderr,
                            b"failed save to %s\n\0" as *const u8 as *const libc::c_char,
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                        );
                        progresult = XMLLINT_ERR_OUT;
                    }
                } else {
                    let mut out_0: *mut FILE = 0 as *mut FILE;
                    if output.is_null() {
                        out_0 = stdout;
                    } else {
                        out_0 = fopen(
                            output,
                            b"wb\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    if !out_0.is_null() {
                        if xmlDocDump(out_0, doc) < 0 as libc::c_int {
                            progresult = XMLLINT_ERR_OUT;
                        }
                        if !output.is_null() {
                            fclose(out_0);
                        }
                    } else {
                        fprintf(
                            stderr,
                            b"failed to open %s\n\0" as *const u8 as *const libc::c_char,
                            output,
                        );
                        progresult = XMLLINT_ERR_OUT;
                    }
                }
            } else {
                let mut ctxt_3: xmlSaveCtxtPtr = 0 as *mut xmlSaveCtxt;
                let mut saveOpts: libc::c_int = 0 as libc::c_int;
                if format == 1 as libc::c_int {
                    saveOpts |= XML_SAVE_FORMAT as libc::c_int;
                } else if format == 2 as libc::c_int {
                    saveOpts |= XML_SAVE_WSNONSIG as libc::c_int;
                }
                if xmlout != 0 {
                    saveOpts |= XML_SAVE_AS_XML as libc::c_int;
                }
                if output.is_null() {
                    ctxt_3 = xmlSaveToFd(1 as libc::c_int, encoding, saveOpts);
                } else {
                    ctxt_3 = xmlSaveToFilename(output, encoding, saveOpts);
                }
                if !ctxt_3.is_null() {
                    if xmlSaveDoc(ctxt_3, doc) < 0 as libc::c_int as libc::c_long {
                        fprintf(
                            stderr,
                            b"failed save to %s\n\0" as *const u8 as *const libc::c_char,
                            if !output.is_null() {
                                output
                            } else {
                                b"-\0" as *const u8 as *const libc::c_char
                            },
                        );
                        progresult = XMLLINT_ERR_OUT;
                    }
                    xmlSaveClose(ctxt_3);
                } else {
                    progresult = XMLLINT_ERR_OUT;
                }
            }
            if timing != 0 && repeat == 0 {
                endTimer(b"Saving\0" as *const u8 as *const libc::c_char);
            }
        } else {
            let mut out_1: *mut FILE = 0 as *mut FILE;
            if output.is_null() {
                out_1 = stdout;
            } else {
                out_1 = fopen(output, b"wb\0" as *const u8 as *const libc::c_char);
            }
            if !out_1.is_null() {
                xmlDebugDumpDocument(out_1, doc);
                if !output.is_null() {
                    fclose(out_1);
                }
            } else {
                fprintf(
                    stderr,
                    b"failed to open %s\n\0" as *const u8 as *const libc::c_char,
                    output,
                );
                progresult = XMLLINT_ERR_OUT;
            }
        }
    }
    if !dtdvalid.is_null() || !dtdvalidfpi.is_null() {
        let mut dtd_0: xmlDtdPtr = 0 as *mut xmlDtd;
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        if !dtdvalid.is_null() {
            dtd_0 = xmlParseDTD(0 as *const xmlChar, dtdvalid as *const xmlChar);
        } else {
            dtd_0 = xmlParseDTD(dtdvalidfpi as *const xmlChar, 0 as *const xmlChar);
        }
        if timing != 0 && repeat == 0 {
            endTimer(b"Parsing DTD\0" as *const u8 as *const libc::c_char);
        }
        if dtd_0.is_null() {
            if !dtdvalid.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Could not parse DTD %s\n\0" as *const u8 as *const libc::c_char,
                    dtdvalid,
                );
            } else {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Could not parse DTD %s\n\0" as *const u8 as *const libc::c_char,
                    dtdvalidfpi,
                );
            }
            progresult = XMLLINT_ERR_DTD;
        } else {
            let mut cvp: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
            cvp = xmlNewValidCtxt();
            if cvp.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Couldn't allocate validation context\n\0" as *const u8
                        as *const libc::c_char,
                );
                progresult = XMLLINT_ERR_MEM;
                xmlFreeDtd(dtd_0);
                return;
            }
            let ref mut fresh25 = (*cvp).userData;
            *fresh25 = 0 as *mut libc::c_void;
            let ref mut fresh26 = (*cvp).error;
            *fresh26 = *__xmlGenericError();
            let ref mut fresh27 = (*cvp).warning;
            *fresh27 = *__xmlGenericError();
            if timing != 0 && repeat == 0 {
                startTimer();
            }
            if xmlValidateDtd(cvp, doc, dtd_0) == 0 {
                if !dtdvalid.is_null() {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Document %s does not validate against %s\n\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        dtdvalid,
                    );
                } else {
                    (*__xmlGenericError())
                        .expect(
                            "non-null function pointer",
                        )(
                        *__xmlGenericErrorContext(),
                        b"Document %s does not validate against %s\n\0" as *const u8
                            as *const libc::c_char,
                        filename,
                        dtdvalidfpi,
                    );
                }
                progresult = XMLLINT_ERR_VALID;
            }
            if timing != 0 && repeat == 0 {
                endTimer(
                    b"Validating against DTD\0" as *const u8 as *const libc::c_char,
                );
            }
            xmlFreeValidCtxt(cvp);
            xmlFreeDtd(dtd_0);
        }
    } else if postvalid != 0 {
        let mut cvp_0: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
        cvp_0 = xmlNewValidCtxt();
        if cvp_0.is_null() {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Couldn't allocate validation context\n\0" as *const u8
                    as *const libc::c_char,
            );
            progresult = XMLLINT_ERR_MEM;
            xmlFreeDoc(doc);
            return;
        }
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        let ref mut fresh28 = (*cvp_0).userData;
        *fresh28 = 0 as *mut libc::c_void;
        let ref mut fresh29 = (*cvp_0).error;
        *fresh29 = *__xmlGenericError();
        let ref mut fresh30 = (*cvp_0).warning;
        *fresh30 = *__xmlGenericError();
        if xmlValidateDocument(cvp_0, doc) == 0 {
            (*__xmlGenericError())
                .expect(
                    "non-null function pointer",
                )(
                *__xmlGenericErrorContext(),
                b"Document %s does not validate\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        }
        if timing != 0 && repeat == 0 {
            endTimer(b"Validating\0" as *const u8 as *const libc::c_char);
        }
        xmlFreeValidCtxt(cvp_0);
    }
    if !wxschematron.is_null() {
        let mut ctxt_4: xmlSchematronValidCtxtPtr = 0 as *mut xmlSchematronValidCtxt;
        let mut ret_1: libc::c_int = 0;
        let mut flag: libc::c_int = 0;
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        if debug != 0 {
            flag = XML_SCHEMATRON_OUT_XML as libc::c_int;
        } else {
            flag = XML_SCHEMATRON_OUT_TEXT as libc::c_int;
        }
        if noout != 0 {
            flag |= XML_SCHEMATRON_OUT_QUIET as libc::c_int;
        }
        ctxt_4 = xmlSchematronNewValidCtxt(wxschematron, flag);
        if ctxt_4.is_null() {
            progresult = XMLLINT_ERR_MEM;
            xmlFreeDoc(doc);
            return;
        }
        ret_1 = xmlSchematronValidateDoc(ctxt_4, doc);
        if ret_1 == 0 as libc::c_int {
            if quiet == 0 {
                fprintf(
                    stderr,
                    b"%s validates\n\0" as *const u8 as *const libc::c_char,
                    filename,
                );
            }
        } else if ret_1 > 0 as libc::c_int {
            fprintf(
                stderr,
                b"%s fails to validate\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        } else {
            fprintf(
                stderr,
                b"%s validation generated an internal error\n\0" as *const u8
                    as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        }
        xmlSchematronFreeValidCtxt(ctxt_4);
        if timing != 0 && repeat == 0 {
            endTimer(b"Validating\0" as *const u8 as *const libc::c_char);
        }
    }
    if !relaxngschemas.is_null() {
        let mut ctxt_5: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
        let mut ret_2: libc::c_int = 0;
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        ctxt_5 = xmlRelaxNGNewValidCtxt(relaxngschemas);
        if ctxt_5.is_null() {
            progresult = XMLLINT_ERR_MEM;
            xmlFreeDoc(doc);
            return;
        }
        xmlRelaxNGSetValidErrors(
            ctxt_5,
            *__xmlGenericError(),
            *__xmlGenericError(),
            0 as *mut libc::c_void,
        );
        ret_2 = xmlRelaxNGValidateDoc(ctxt_5, doc);
        if ret_2 == 0 as libc::c_int {
            if quiet == 0 {
                fprintf(
                    stderr,
                    b"%s validates\n\0" as *const u8 as *const libc::c_char,
                    filename,
                );
            }
        } else if ret_2 > 0 as libc::c_int {
            fprintf(
                stderr,
                b"%s fails to validate\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        } else {
            fprintf(
                stderr,
                b"%s validation generated an internal error\n\0" as *const u8
                    as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        }
        xmlRelaxNGFreeValidCtxt(ctxt_5);
        if timing != 0 && repeat == 0 {
            endTimer(b"Validating\0" as *const u8 as *const libc::c_char);
        }
    } else if !wxschemas.is_null() {
        let mut ctxt_6: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
        let mut ret_3: libc::c_int = 0;
        if timing != 0 && repeat == 0 {
            startTimer();
        }
        ctxt_6 = xmlSchemaNewValidCtxt(wxschemas);
        if ctxt_6.is_null() {
            progresult = XMLLINT_ERR_MEM;
            xmlFreeDoc(doc);
            return;
        }
        xmlSchemaSetValidErrors(
            ctxt_6,
            *__xmlGenericError(),
            *__xmlGenericError(),
            0 as *mut libc::c_void,
        );
        ret_3 = xmlSchemaValidateDoc(ctxt_6, doc);
        if ret_3 == 0 as libc::c_int {
            if quiet == 0 {
                fprintf(
                    stderr,
                    b"%s validates\n\0" as *const u8 as *const libc::c_char,
                    filename,
                );
            }
        } else if ret_3 > 0 as libc::c_int {
            fprintf(
                stderr,
                b"%s fails to validate\n\0" as *const u8 as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        } else {
            fprintf(
                stderr,
                b"%s validation generated an internal error\n\0" as *const u8
                    as *const libc::c_char,
                filename,
            );
            progresult = XMLLINT_ERR_VALID;
        }
        xmlSchemaFreeValidCtxt(ctxt_6);
        if timing != 0 && repeat == 0 {
            endTimer(b"Validating\0" as *const u8 as *const libc::c_char);
        }
    }
    if debugent != 0 && html == 0 {
        xmlDebugDumpEntities(stderr, doc);
    }
    if timing != 0 && repeat == 0 {
        startTimer();
    }
    xmlFreeDoc(doc);
    if timing != 0 && repeat == 0 {
        endTimer(b"Freeing\0" as *const u8 as *const libc::c_char);
    }
}
unsafe extern "C" fn showVersion(mut name: *const libc::c_char) {
    fprintf(
        stderr,
        b"%s: using libxml version %s\n\0" as *const u8 as *const libc::c_char,
        name,
        *__xmlParserVersion(),
    );
    fprintf(stderr, b"   compiled with: \0" as *const u8 as *const libc::c_char);
    if xmlHasFeature(XML_WITH_THREAD) != 0 {
        fprintf(stderr, b"Threads \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_TREE) != 0 {
        fprintf(stderr, b"Tree \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_OUTPUT) != 0 {
        fprintf(stderr, b"Output \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_PUSH) != 0 {
        fprintf(stderr, b"Push \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_READER) != 0 {
        fprintf(stderr, b"Reader \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_PATTERN) != 0 {
        fprintf(stderr, b"Patterns \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_WRITER) != 0 {
        fprintf(stderr, b"Writer \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_SAX1) != 0 {
        fprintf(stderr, b"SAXv1 \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_FTP) != 0 {
        fprintf(stderr, b"FTP \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_HTTP) != 0 {
        fprintf(stderr, b"HTTP \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_VALID) != 0 {
        fprintf(stderr, b"DTDValid \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_HTML) != 0 {
        fprintf(stderr, b"HTML \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_LEGACY) != 0 {
        fprintf(stderr, b"Legacy \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_C14N) != 0 {
        fprintf(stderr, b"C14N \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_CATALOG) != 0 {
        fprintf(stderr, b"Catalog \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_XPATH) != 0 {
        fprintf(stderr, b"XPath \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_XPTR) != 0 {
        fprintf(stderr, b"XPointer \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_XINCLUDE) != 0 {
        fprintf(stderr, b"XInclude \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_ICONV) != 0 {
        fprintf(stderr, b"Iconv \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_ICU) != 0 {
        fprintf(stderr, b"ICU \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_ISO8859X) != 0 {
        fprintf(stderr, b"ISO8859X \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_UNICODE) != 0 {
        fprintf(stderr, b"Unicode \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_REGEXP) != 0 {
        fprintf(stderr, b"Regexps \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_AUTOMATA) != 0 {
        fprintf(stderr, b"Automata \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_EXPR) != 0 {
        fprintf(stderr, b"Expr \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_SCHEMAS) != 0 {
        fprintf(stderr, b"Schemas \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_SCHEMATRON) != 0 {
        fprintf(stderr, b"Schematron \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_MODULES) != 0 {
        fprintf(stderr, b"Modules \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_DEBUG) != 0 {
        fprintf(stderr, b"Debug \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_DEBUG_MEM) != 0 {
        fprintf(stderr, b"MemDebug \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_DEBUG_RUN) != 0 {
        fprintf(stderr, b"RunDebug \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_ZLIB) != 0 {
        fprintf(stderr, b"Zlib \0" as *const u8 as *const libc::c_char);
    }
    if xmlHasFeature(XML_WITH_LZMA) != 0 {
        fprintf(stderr, b"Lzma \0" as *const u8 as *const libc::c_char);
    }
    fprintf(stderr, b"\n\0" as *const u8 as *const libc::c_char);
}
unsafe extern "C" fn usage(mut f: *mut FILE, mut name: *const libc::c_char) {
    fprintf(
        f,
        b"Usage : %s [options] XMLfiles ...\n\0" as *const u8 as *const libc::c_char,
        name,
    );
    fprintf(
        f,
        b"\tParse the XML files and output the result of the parsing\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--version : display the version of the XML library used\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--debug : dump a debug tree of the in-memory document\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--shell : run a navigating shell\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--debugent : debug the entities defined in the document\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--copy : used to test the internal copy implementation\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--recover : output what was parsable on broken XML documents\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--huge : remove any internal arbitrary parser limits\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--noent : substitute entity references by their value\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--noenc : ignore any encoding specified inside the document\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--noout : don't output the result tree\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--path 'paths': provide a set of paths for resources\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--load-trace : print trace of all external entities loaded\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nonet : refuse to fetch DTDs or entities over network\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nocompact : do not generate compact text nodes\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--htmlout : output results as HTML\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nowrap : do not put HTML doc wrapper\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--valid : validate the document in addition to std well-formed check\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--postvalid : do a posteriori validation, i.e after parsing\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--dtdvalid URL : do a posteriori validation against a given DTD\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--dtdvalidfpi FPI : same but name the DTD with a Public Identifier\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--quiet : be quiet when succeeded\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--timing : print some timings\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--output file or -o file: save to a given file\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--repeat : repeat 100 times, for timing or profiling\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--insert : ad-hoc test for valid insertions\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--compress : turn on gzip compression of output\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--html : use the HTML parser\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--xmlout : force to use the XML serializer when using --html\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nodefdtd : do not default HTML doctype\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--push : use the push mode of the parser\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--pushsmall : use the push mode of the parser using tiny increments\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--memory : parse from memory\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--maxmem nbbytes : limits memory allocation to nbbytes bytes\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nowarning : do not emit warnings from parser/validator\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--noblanks : drop (ignorable?) blanks spaces\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nocdata : replace cdata section with text nodes\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--format : reformat/reindent the output\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--encode encoding : output in the given encoding\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--dropdtd : remove the DOCTYPE of the input docs\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--pretty STYLE : pretty-print in a particular style\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t                 0 Do not pretty print\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t                 1 Format the XML content, as --format\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t                 2 Add whitespace inside tags, preserving content\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--c14n : save in W3C canonical format v1.0 (with comments)\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--c14n11 : save in W3C canonical format v1.1 (with comments)\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--exc-c14n : save in W3C exclusive canonical format (with comments)\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nsclean : remove redundant namespace declarations\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--testIO : test user I/O support\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--catalogs : use SGML catalogs from $SGML_CATALOG_FILES\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t             otherwise XML Catalogs starting from \n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t         %s are activated by default\n\0" as *const u8
            as *const libc::c_char,
        b"file:///usr/local/etc/xml/catalog\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nocatalogs: deactivate all catalogs\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--auto : generate a small doc on the fly\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--xinclude : do XInclude processing\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--noxincludenode : same but do not generate XInclude nodes\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--nofixup-base-uris : do not fixup xml:base uris\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--loaddtd : fetch external DTD\n\0" as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--dtdattr : loaddtd + populate the tree with inherited attributes \n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--stream : use the streaming interface to process very large files\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--walker : create a reader and walk though the resulting doc\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--pattern pattern_value : test the pattern support\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--chkregister : verify the node registration code\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--relaxng schema : do RelaxNG validation against the schema\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--schema schema : do validation against the WXS schema\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--schematron schema : do validation against a schematron\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--sax1: use the old SAX1 interfaces for processing\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--sax: do not build a tree but work just at the SAX level\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--oldxml10: use XML-1.0 parsing rules before the 5th edition\n\0"
            as *const u8 as *const libc::c_char,
    );
    fprintf(
        f,
        b"\t--xpath expr: evaluate the XPath expression, imply --noout\n\0" as *const u8
            as *const libc::c_char,
    );
    fprintf(
        f,
        b"\nLibxml project home page: https://gitlab.gnome.org/GNOME/libxml2\n\0"
            as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn registerNode(mut node: xmlNodePtr) {
    let ref mut fresh31 = (*node)._private;
    *fresh31 = malloc(::std::mem::size_of::<libc::c_long>() as libc::c_ulong);
    if ((*node)._private).is_null() {
        fprintf(
            stderr,
            b"Out of memory in xmllint:registerNode()\n\0" as *const u8
                as *const libc::c_char,
        );
        exit(XMLLINT_ERR_MEM as libc::c_int);
    }
    *((*node)._private
        as *mut libc::c_long) = 0x81726354 as libc::c_uint as libc::c_long;
    nbregister += 1;
}
unsafe extern "C" fn deregisterNode(mut node: xmlNodePtr) {
    if !((*node)._private).is_null() {} else {
        __assert_fail(
            b"node->_private != NULL\0" as *const u8 as *const libc::c_char,
            b"xmllint.c\0" as *const u8 as *const libc::c_char,
            3103 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 32],
                &[libc::c_char; 32],
            >(b"void deregisterNode(xmlNodePtr)\0"))
                .as_ptr(),
        );
    }
    if *((*node)._private as *mut libc::c_long)
        == 0x81726354 as libc::c_uint as libc::c_long
    {} else {
        __assert_fail(
            b"*(long*)node->_private == (long) 0x81726354\0" as *const u8
                as *const libc::c_char,
            b"xmllint.c\0" as *const u8 as *const libc::c_char,
            3104 as libc::c_int as libc::c_uint,
            (*::std::mem::transmute::<
                &[u8; 32],
                &[libc::c_char; 32],
            >(b"void deregisterNode(xmlNodePtr)\0"))
                .as_ptr(),
        );
    }
    free((*node)._private);
    nbregister -= 1;
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: libc::c_int = 0;
    let mut acount: libc::c_int = 0;
    let mut files: libc::c_int = 0 as libc::c_int;
    let mut version: libc::c_int = 0 as libc::c_int;
    let mut indent: *const libc::c_char = 0 as *const libc::c_char;
    if argc <= 1 as libc::c_int {
        usage(stderr, *argv.offset(0 as libc::c_int as isize));
        return XMLLINT_ERR_UNCLASS as libc::c_int;
    }
    i = 1 as libc::c_int;
    while i < argc {
        if !(*(*argv.offset(i as isize)).offset(0 as libc::c_int as isize) as libc::c_int
            != '-' as i32)
        {
            if strcmp(
                *argv.offset(i as isize),
                b"-maxmem\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--maxmem\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
                i += 1;
                if i >= argc
                    || sscanf(
                        *argv.offset(i as isize),
                        b"%d\0" as *const u8 as *const libc::c_char,
                        &mut maxmem as *mut libc::c_int,
                    ) != 1 as libc::c_int
                {
                    maxmem = 0 as libc::c_int;
                }
            }
        }
        i += 1;
    }
    if maxmem != 0 as libc::c_int {
        xmlMemSetup(
            Some(myFreeFunc as unsafe extern "C" fn(*mut libc::c_void) -> ()),
            Some(myMallocFunc as unsafe extern "C" fn(size_t) -> *mut libc::c_void),
            Some(
                myReallocFunc
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        size_t,
                    ) -> *mut libc::c_void,
            ),
            Some(
                myStrdupFunc
                    as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_char,
            ),
        );
    }
    xmlCheckVersion(21000 as libc::c_int);
    i = 1 as libc::c_int;
    while i < argc {
        if !(*(*argv.offset(i as isize)).offset(0 as libc::c_int as isize) as libc::c_int
            != '-' as i32
            || *(*argv.offset(i as isize)).offset(1 as libc::c_int as isize)
                as libc::c_int == 0 as libc::c_int)
        {
            if strcmp(
                *argv.offset(i as isize),
                b"-debug\0" as *const u8 as *const libc::c_char,
            ) == 0
                || strcmp(
                    *argv.offset(i as isize),
                    b"--debug\0" as *const u8 as *const libc::c_char,
                ) == 0
            {
                debug += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-shell\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--shell\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                shell += 1;
                noout = 1 as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-copy\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--copy\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                copy += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-recover\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--recover\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                recovery += 1;
                options |= XML_PARSE_RECOVER as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-huge\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--huge\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options |= XML_PARSE_HUGE as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-noent\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--noent\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                noent += 1;
                options |= XML_PARSE_NOENT as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-noenc\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--noenc\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                noenc += 1;
                options |= XML_PARSE_IGNORE_ENC as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nsclean\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nsclean\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options |= XML_PARSE_NSCLEAN as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nocdata\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nocdata\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options |= XML_PARSE_NOCDATA as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nodict\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nodict\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options |= XML_PARSE_NODICT as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-version\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--version\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                showVersion(*argv.offset(0 as libc::c_int as isize));
                version = 1 as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-noout\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--noout\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                noout += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-o\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"-output\0" as *const u8 as *const libc::c_char,
                    ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--output\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                output = *argv.offset(i as isize);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-htmlout\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--htmlout\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                htmlout += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nowrap\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nowrap\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                nowrap += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-html\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--html\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                html += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-xmlout\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--xmlout\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                xmlout += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nodefdtd\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nodefdtd\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                nodefdtd += 1;
                options |= HTML_PARSE_NODEFDTD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-loaddtd\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--loaddtd\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                loaddtd += 1;
                options |= XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-dtdattr\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--dtdattr\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                loaddtd += 1;
                dtdattrs += 1;
                options |= XML_PARSE_DTDATTR as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-valid\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--valid\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                valid += 1;
                options |= XML_PARSE_DTDVALID as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-postvalid\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--postvalid\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                postvalid += 1;
                loaddtd += 1;
                options |= XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-dtdvalid\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--dtdvalid\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                dtdvalid = *argv.offset(i as isize);
                loaddtd += 1;
                options |= XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-dtdvalidfpi\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--dtdvalidfpi\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                dtdvalidfpi = *argv.offset(i as isize);
                loaddtd += 1;
                options |= XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-dropdtd\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--dropdtd\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                dropdtd += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-insert\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--insert\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                insert += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-quiet\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--quiet\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                quiet += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-timing\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--timing\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                timing += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-auto\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--auto\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                generate += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-repeat\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--repeat\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                if repeat != 0 {
                    repeat *= 10 as libc::c_int;
                } else {
                    repeat = 100 as libc::c_int;
                }
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-push\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--push\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                push += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-pushsmall\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--pushsmall\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                push += 1;
                pushsize = 10 as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-memory\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--memory\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                memory += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-testIO\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--testIO\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                testIO += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-xinclude\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--xinclude\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                xinclude += 1;
                options |= XML_PARSE_XINCLUDE as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-noxincludenode\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--noxincludenode\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                xinclude += 1;
                options |= XML_PARSE_XINCLUDE as libc::c_int;
                options |= XML_PARSE_NOXINCNODE as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nofixup-base-uris\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nofixup-base-uris\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                xinclude += 1;
                options |= XML_PARSE_XINCLUDE as libc::c_int;
                options |= XML_PARSE_NOBASEFIX as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-compress\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--compress\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                compress += 1;
                xmlSetCompressMode(9 as libc::c_int);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nowarning\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nowarning\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                *__xmlGetWarningsDefaultValue() = 0 as libc::c_int;
                xmlPedanticParserDefault(0 as libc::c_int);
                options |= XML_PARSE_NOWARNING as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-pedantic\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--pedantic\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                *__xmlGetWarningsDefaultValue() = 1 as libc::c_int;
                xmlPedanticParserDefault(1 as libc::c_int);
                options |= XML_PARSE_PEDANTIC as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-debugent\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--debugent\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                debugent += 1;
                *__xmlParserDebugEntities() = 1 as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-c14n\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--c14n\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                canonical += 1;
                options
                    |= XML_PARSE_NOENT as libc::c_int | XML_PARSE_DTDATTR as libc::c_int
                        | XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-c14n11\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--c14n11\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                canonical_11 += 1;
                options
                    |= XML_PARSE_NOENT as libc::c_int | XML_PARSE_DTDATTR as libc::c_int
                        | XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-exc-c14n\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--exc-c14n\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                exc_canonical += 1;
                options
                    |= XML_PARSE_NOENT as libc::c_int | XML_PARSE_DTDATTR as libc::c_int
                        | XML_PARSE_DTDLOAD as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-catalogs\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--catalogs\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                catalogs += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nocatalogs\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nocatalogs\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                nocatalogs += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-encode\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--encode\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                encoding = *argv.offset(i as isize);
                xmlAddEncodingAlias(
                    b"UTF-8\0" as *const u8 as *const libc::c_char,
                    b"DVEnc\0" as *const u8 as *const libc::c_char,
                );
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-noblanks\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--noblanks\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                noblanks += 1;
                xmlKeepBlanksDefault(0 as libc::c_int);
                options |= XML_PARSE_NOBLANKS as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-maxmem\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--maxmem\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-format\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--format\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                noblanks += 1;
                format = 1 as libc::c_int;
                xmlKeepBlanksDefault(0 as libc::c_int);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-pretty\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--pretty\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                if !(*argv.offset(i as isize)).is_null() {
                    format = atoi(*argv.offset(i as isize));
                    if format == 1 as libc::c_int {
                        noblanks += 1;
                        xmlKeepBlanksDefault(0 as libc::c_int);
                    }
                }
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-stream\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--stream\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                stream += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-walker\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--walker\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                walker += 1;
                noout += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-pattern\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--pattern\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                pattern = *argv.offset(i as isize);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-sax1\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--sax1\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                sax1 += 1;
                options |= XML_PARSE_SAX1 as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-sax\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--sax\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                sax += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-chkregister\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--chkregister\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                chkregister += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-relaxng\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--relaxng\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                relaxng = *argv.offset(i as isize);
                noent += 1;
                options |= XML_PARSE_NOENT as libc::c_int;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-schema\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--schema\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                schema = *argv.offset(i as isize);
                noent += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-schematron\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--schematron\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                schematron = *argv.offset(i as isize);
                noent += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nonet\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nonet\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options |= XML_PARSE_NONET as libc::c_int;
                xmlSetExternalEntityLoader(
                    Some(
                        xmlNoNetExternalEntityLoader
                            as unsafe extern "C" fn(
                                *const libc::c_char,
                                *const libc::c_char,
                                xmlParserCtxtPtr,
                            ) -> xmlParserInputPtr,
                    ),
                );
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-nocompact\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--nocompact\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                options &= !(XML_PARSE_COMPACT as libc::c_int);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-load-trace\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--load-trace\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                load_trace += 1;
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-path\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--path\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                parsePath(*argv.offset(i as isize) as *mut xmlChar);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-xpath\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--xpath\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                i += 1;
                noout += 1;
                xpathquery = *argv.offset(i as isize);
            } else if strcmp(
                    *argv.offset(i as isize),
                    b"-oldxml10\0" as *const u8 as *const libc::c_char,
                ) == 0
                    || strcmp(
                        *argv.offset(i as isize),
                        b"--oldxml10\0" as *const u8 as *const libc::c_char,
                    ) == 0
                {
                oldxml10 += 1;
                options |= XML_PARSE_OLD10 as libc::c_int;
            } else {
                fprintf(
                    stderr,
                    b"Unknown option %s\n\0" as *const u8 as *const libc::c_char,
                    *argv.offset(i as isize),
                );
                usage(stderr, *argv.offset(0 as libc::c_int as isize));
                return XMLLINT_ERR_UNCLASS as libc::c_int;
            }
        }
        i += 1;
    }
    if nocatalogs == 0 as libc::c_int {
        if catalogs != 0 {
            let mut catal: *const libc::c_char = 0 as *const libc::c_char;
            catal = getenv(b"SGML_CATALOG_FILES\0" as *const u8 as *const libc::c_char);
            if !catal.is_null() {
                xmlLoadCatalogs(catal);
            } else {
                fprintf(
                    stderr,
                    b"Variable $SGML_CATALOG_FILES not set\n\0" as *const u8
                        as *const libc::c_char,
                );
            }
        }
    }
    if sax1 != 0 {
        xmlSAXDefaultVersion(1 as libc::c_int);
    } else {
        xmlSAXDefaultVersion(2 as libc::c_int);
    }
    if chkregister != 0 {
        xmlRegisterNodeDefault(
            Some(registerNode as unsafe extern "C" fn(xmlNodePtr) -> ()),
        );
        xmlDeregisterNodeDefault(
            Some(deregisterNode as unsafe extern "C" fn(xmlNodePtr) -> ()),
        );
    }
    indent = getenv(b"XMLLINT_INDENT\0" as *const u8 as *const libc::c_char);
    if !indent.is_null() {
        let ref mut fresh32 = *__xmlTreeIndentString();
        *fresh32 = indent;
    }
    defaultEntityLoader = xmlGetExternalEntityLoader();
    xmlSetExternalEntityLoader(
        Some(
            xmllintExternalEntityLoader
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    *const libc::c_char,
                    xmlParserCtxtPtr,
                ) -> xmlParserInputPtr,
        ),
    );
    xmlLineNumbersDefault(1 as libc::c_int);
    if loaddtd != 0 as libc::c_int {
        *__xmlLoadExtDtdDefaultValue() |= 2 as libc::c_int;
    }
    if dtdattrs != 0 {
        *__xmlLoadExtDtdDefaultValue() |= 4 as libc::c_int;
    }
    if noent != 0 as libc::c_int {
        xmlSubstituteEntitiesDefault(1 as libc::c_int);
    }
    if valid != 0 as libc::c_int {
        *__xmlDoValidityCheckingDefaultValue() = 1 as libc::c_int;
    }
    if htmlout != 0 && nowrap == 0 {
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\"\n\0"
                as *const u8 as *const libc::c_char,
        );
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"\t\"http://www.w3.org/TR/REC-html40/loose.dtd\">\n\0" as *const u8
                as *const libc::c_char,
        );
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"<html><head><title>%s output</title></head>\n\0" as *const u8
                as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
        (*__xmlGenericError())
            .expect(
                "non-null function pointer",
            )(
            *__xmlGenericErrorContext(),
            b"<body bgcolor=\"#ffffff\"><h1 align=\"center\">%s output</h1>\n\0"
                as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
    }
    if !schematron.is_null() && sax == 0 as libc::c_int && stream == 0 as libc::c_int {
        let mut ctxt: xmlSchematronParserCtxtPtr = 0 as *mut xmlSchematronParserCtxt;
        *__xmlLoadExtDtdDefaultValue() |= 1 as libc::c_int;
        options |= XML_PARSE_DTDLOAD as libc::c_int;
        if timing != 0 {
            startTimer();
        }
        ctxt = xmlSchematronNewParserCtxt(schematron);
        if ctxt.is_null() {
            progresult = XMLLINT_ERR_MEM;
            current_block = 10779620755688928994;
        } else {
            wxschematron = xmlSchematronParse(ctxt);
            if wxschematron.is_null() {
                (*__xmlGenericError())
                    .expect(
                        "non-null function pointer",
                    )(
                    *__xmlGenericErrorContext(),
                    b"Schematron schema %s failed to compile\n\0" as *const u8
                        as *const libc::c_char,
                    schematron,
                );
                progresult = XMLLINT_ERR_SCHEMACOMP;
                schematron = 0 as *mut libc::c_char;
            }
            xmlSchematronFreeParserCtxt(ctxt);
            if timing != 0 {
                endTimer(b"Compiling the schemas\0" as *const u8 as *const libc::c_char);
            }
            current_block = 8158038653727582745;
        }
    } else {
        current_block = 8158038653727582745;
    }
    match current_block {
        8158038653727582745 => {
            if !relaxng.is_null() && sax == 0 as libc::c_int
                && stream == 0 as libc::c_int
            {
                let mut ctxt_0: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
                *__xmlLoadExtDtdDefaultValue() |= 1 as libc::c_int;
                options |= XML_PARSE_DTDLOAD as libc::c_int;
                if timing != 0 {
                    startTimer();
                }
                ctxt_0 = xmlRelaxNGNewParserCtxt(relaxng);
                if ctxt_0.is_null() {
                    progresult = XMLLINT_ERR_MEM;
                    current_block = 10779620755688928994;
                } else {
                    xmlRelaxNGSetParserErrors(
                        ctxt_0,
                        *__xmlGenericError(),
                        *__xmlGenericError(),
                        0 as *mut libc::c_void,
                    );
                    relaxngschemas = xmlRelaxNGParse(ctxt_0);
                    if relaxngschemas.is_null() {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"Relax-NG schema %s failed to compile\n\0" as *const u8
                                as *const libc::c_char,
                            relaxng,
                        );
                        progresult = XMLLINT_ERR_SCHEMACOMP;
                        relaxng = 0 as *mut libc::c_char;
                    }
                    xmlRelaxNGFreeParserCtxt(ctxt_0);
                    if timing != 0 {
                        endTimer(
                            b"Compiling the schemas\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    current_block = 12431460683607164915;
                }
            } else if !schema.is_null() && stream == 0 as libc::c_int {
                let mut ctxt_1: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
                if timing != 0 {
                    startTimer();
                }
                ctxt_1 = xmlSchemaNewParserCtxt(schema);
                if ctxt_1.is_null() {
                    progresult = XMLLINT_ERR_MEM;
                    current_block = 10779620755688928994;
                } else {
                    xmlSchemaSetParserErrors(
                        ctxt_1,
                        *__xmlGenericError(),
                        *__xmlGenericError(),
                        0 as *mut libc::c_void,
                    );
                    wxschemas = xmlSchemaParse(ctxt_1);
                    if wxschemas.is_null() {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"WXS schema %s failed to compile\n\0" as *const u8
                                as *const libc::c_char,
                            schema,
                        );
                        progresult = XMLLINT_ERR_SCHEMACOMP;
                        schema = 0 as *mut libc::c_char;
                    }
                    xmlSchemaFreeParserCtxt(ctxt_1);
                    if timing != 0 {
                        endTimer(
                            b"Compiling the schemas\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    current_block = 12431460683607164915;
                }
            } else {
                current_block = 12431460683607164915;
            }
            match current_block {
                10779620755688928994 => {}
                _ => {
                    if !pattern.is_null() && walker == 0 as libc::c_int {
                        patternc = xmlPatterncompile(
                            pattern as *const xmlChar,
                            0 as *mut xmlDict,
                            0 as libc::c_int,
                            0 as *mut *const xmlChar,
                        );
                        if patternc.is_null() {
                            (*__xmlGenericError())
                                .expect(
                                    "non-null function pointer",
                                )(
                                *__xmlGenericErrorContext(),
                                b"Pattern %s failed to compile\n\0" as *const u8
                                    as *const libc::c_char,
                                pattern,
                            );
                            progresult = XMLLINT_ERR_SCHEMAPAT;
                            pattern = 0 as *const libc::c_char;
                        }
                    }
                    i = 1 as libc::c_int;
                    while i < argc {
                        if strcmp(
                            *argv.offset(i as isize),
                            b"-encode\0" as *const u8 as *const libc::c_char,
                        ) == 0
                            || strcmp(
                                *argv.offset(i as isize),
                                b"--encode\0" as *const u8 as *const libc::c_char,
                            ) == 0
                        {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-o\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"-output\0" as *const u8 as *const libc::c_char,
                                ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--output\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-dtdvalid\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--dtdvalid\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-path\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--path\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-dtdvalidfpi\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--dtdvalidfpi\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-relaxng\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--relaxng\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-maxmem\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--maxmem\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-pretty\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--pretty\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-schema\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--schema\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-schematron\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--schematron\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-pattern\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--pattern\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else if strcmp(
                                *argv.offset(i as isize),
                                b"-xpath\0" as *const u8 as *const libc::c_char,
                            ) == 0
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"--xpath\0" as *const u8 as *const libc::c_char,
                                ) == 0
                            {
                            i += 1;
                        } else {
                            if timing != 0 && repeat != 0 {
                                startTimer();
                            }
                            if *(*argv.offset(i as isize))
                                .offset(0 as libc::c_int as isize) as libc::c_int
                                != '-' as i32
                                || strcmp(
                                    *argv.offset(i as isize),
                                    b"-\0" as *const u8 as *const libc::c_char,
                                ) == 0 as libc::c_int
                            {
                                if repeat != 0 {
                                    let mut ctxt_2: xmlParserCtxtPtr = 0 as xmlParserCtxtPtr;
                                    acount = 0 as libc::c_int;
                                    while acount < repeat {
                                        if stream != 0 as libc::c_int {
                                            streamFile(*argv.offset(i as isize));
                                        } else if sax != 0 {
                                            testSAX(*argv.offset(i as isize));
                                        } else {
                                            if ctxt_2.is_null() {
                                                ctxt_2 = xmlNewParserCtxt();
                                            }
                                            parseAndPrintFile(*argv.offset(i as isize), ctxt_2);
                                        }
                                        acount += 1;
                                    }
                                    if !ctxt_2.is_null() {
                                        xmlFreeParserCtxt(ctxt_2);
                                    }
                                } else {
                                    nbregister = 0 as libc::c_int;
                                    if stream != 0 as libc::c_int {
                                        streamFile(*argv.offset(i as isize));
                                    } else if sax != 0 {
                                        testSAX(*argv.offset(i as isize));
                                    } else {
                                        parseAndPrintFile(
                                            *argv.offset(i as isize),
                                            0 as xmlParserCtxtPtr,
                                        );
                                    }
                                    if chkregister != 0 && nbregister != 0 as libc::c_int {
                                        fprintf(
                                            stderr,
                                            b"Registration count off: %d\n\0" as *const u8
                                                as *const libc::c_char,
                                            nbregister,
                                        );
                                        progresult = XMLLINT_ERR_RDREGIS;
                                    }
                                }
                                files += 1;
                                if timing != 0 && repeat != 0 {
                                    endTimer(
                                        b"%d iterations\0" as *const u8 as *const libc::c_char,
                                        repeat,
                                    );
                                }
                            }
                        }
                        i += 1;
                    }
                    if generate != 0 {
                        parseAndPrintFile(0 as *mut libc::c_char, 0 as xmlParserCtxtPtr);
                    }
                    if htmlout != 0 && nowrap == 0 {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"</body></html>\n\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    if files == 0 as libc::c_int && generate == 0
                        && version == 0 as libc::c_int
                    {
                        usage(stderr, *argv.offset(0 as libc::c_int as isize));
                        progresult = XMLLINT_ERR_UNCLASS;
                    }
                    if !wxschematron.is_null() {
                        xmlSchematronFree(wxschematron);
                    }
                    if !relaxngschemas.is_null() {
                        xmlRelaxNGFree(relaxngschemas);
                    }
                    if !wxschemas.is_null() {
                        xmlSchemaFree(wxschemas);
                    }
                    if !patternc.is_null() {
                        xmlFreePattern(patternc);
                    }
                }
            }
        }
        _ => {}
    }
    xmlCleanupParser();
    xmlMemoryDump();
    return progresult as libc::c_int;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::std::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
