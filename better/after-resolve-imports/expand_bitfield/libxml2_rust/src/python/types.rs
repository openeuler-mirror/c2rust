use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn PyLong_FromLong(_: i64) -> *mut PyObject;
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> i32;
    fn PyObject_GetAttrString(_: *mut PyObject, _: *const i8) -> *mut PyObject;
    fn PyObject_HasAttrString(_: *mut PyObject, _: *const i8) -> i32;
    static mut _Py_NoneStruct: PyObject;
    fn PyUnicodeUCS4_AsUTF8String(unicode: *mut PyObject) -> *mut PyObject;
    fn PyInt_FromLong(_: i64) -> *mut PyObject;
    static mut PyBool_Type: PyTypeObject;
    static mut _Py_TrueStruct: PyIntObject;
    static mut PyFloat_Type: PyTypeObject;
    fn PyFloat_FromDouble(_: f64) -> *mut PyObject;
    fn PyString_FromString(_: *const i8) -> *mut PyObject;
    fn PyList_New(size: Py_ssize_t) -> *mut PyObject;
    fn PyList_Size(_: *mut PyObject) -> Py_ssize_t;
    fn PyList_GetItem(_: *mut PyObject, _: Py_ssize_t) -> *mut PyObject;
    fn PyList_SetItem(_: *mut PyObject, _: Py_ssize_t, _: *mut PyObject) -> i32;
    static mut PyCapsule_Type: PyTypeObject;
    fn PyCapsule_New(
        pointer: *mut libc::c_void,
        name: *const i8,
        destructor: PyCapsule_Destructor,
    ) -> *mut PyObject;
    fn PyCapsule_GetPointer(
        capsule: *mut PyObject,
        name: *const i8,
    ) -> *mut libc::c_void;
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xpath::xmlXPathFreeObject;
pub use crate::src::xpath::xmlXPathNewBoolean;
pub use crate::src::xpath::xmlXPathNewFloat;
pub use crate::src::xpath::xmlXPathNodeSetAdd;
pub use crate::src::xpath::xmlXPathNodeSetCreate;
pub use crate::src::xpath::xmlXPathNodeSetFreeNs;
pub use crate::src::xpath::xmlXPathWrapNodeSet;
pub use crate::src::xpath::xmlXPathWrapString;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::catalog::_xmlCatalog;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::python::libxml2_py::_xmlSchema;
pub use crate::src::globals::xmlFree;
pub use crate::src::parserInternals::_IO_wide_data;
pub use crate::src::python::libxml::PyMemberDef;
pub use crate::src::relaxng::_IO_codecvt;
pub use crate::src::uri::_IO_marker;
pub use crate::src::relaxng::_xmlRelaxNG;
pub use crate::src::relaxng::_xmlRelaxNGParserCtxt;
pub use crate::src::relaxng::_xmlRelaxNGValidCtxt;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlreader::_xmlTextReader;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlregexp::_xmlRegexp;
pub use crate::src::xmlschemas::_xmlSchemaParserCtxt;
pub use crate::src::xmlschemas::_xmlSchemaValidCtxt;
pub use crate::src::xpath::_xmlXPathCompExpr;
pub type size_t = crate::src::HTMLparser::size_t;
pub type __off_t = crate::src::HTMLtree::__off_t;
pub type __off64_t = crate::src::HTMLtree::__off64_t;
pub type __ssize_t = crate::src::catalog::__ssize_t;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::HTMLtree::_IO_FILE;
pub type _IO_lock_t = crate::src::HTMLtree::_IO_lock_t;
pub type FILE = crate::src::HTMLtree::FILE;
pub type ssize_t = crate::src::catalog::ssize_t;
pub type Py_ssize_t = crate::src::python::libxml::Py_ssize_t;
// #[derive(Copy, Clone)]

pub type _object = crate::src::python::libxml::_object;
// #[derive(Copy, Clone)]

pub type _typeobject = crate::src::python::libxml::_typeobject;
pub type destructor = crate::src::python::libxml::destructor;
pub type PyObject = crate::src::python::libxml::PyObject;
pub type inquiry = crate::src::python::libxml::inquiry;
pub type freefunc = crate::src::python::libxml::freefunc;
pub type newfunc = crate::src::python::libxml::newfunc;
pub type allocfunc = crate::src::python::libxml::allocfunc;
pub type initproc = crate::src::python::libxml::initproc;
pub type descrsetfunc = crate::src::python::libxml::descrsetfunc;
pub type descrgetfunc = crate::src::python::libxml::descrgetfunc;
// #[derive(Copy, Clone)]

pub type PyGetSetDef = crate::src::python::libxml::PyGetSetDef;
pub type setter = crate::src::python::libxml::setter;
pub type getter = crate::src::python::libxml::getter;
// #[derive(Copy, Clone)]

pub type PyMethodDef = crate::src::python::libxml::PyMethodDef;
pub type PyCFunction = crate::src::python::libxml::PyCFunction;
pub type iternextfunc = crate::src::python::libxml::iternextfunc;
pub type getiterfunc = crate::src::python::libxml::getiterfunc;
pub type richcmpfunc = crate::src::python::libxml::richcmpfunc;
pub type traverseproc = crate::src::python::libxml::traverseproc;
pub type visitproc = crate::src::python::libxml::visitproc;
// #[derive(Copy, Clone)]

pub type PyBufferProcs = crate::src::python::libxml::PyBufferProcs;
pub type releasebufferproc = crate::src::python::libxml::releasebufferproc;
pub type Py_buffer = crate::src::python::libxml::Py_buffer;
// #[derive(Copy, Clone)]

pub type bufferinfo = crate::src::python::libxml::bufferinfo;
pub type getbufferproc = crate::src::python::libxml::getbufferproc;
pub type charbufferproc = crate::src::python::libxml::charbufferproc;
pub type segcountproc = crate::src::python::libxml::segcountproc;
pub type writebufferproc = crate::src::python::libxml::writebufferproc;
pub type readbufferproc = crate::src::python::libxml::readbufferproc;
pub type setattrofunc = crate::src::python::libxml::setattrofunc;
pub type getattrofunc = crate::src::python::libxml::getattrofunc;
pub type reprfunc = crate::src::python::libxml::reprfunc;
pub type ternaryfunc = crate::src::python::libxml::ternaryfunc;
pub type hashfunc = crate::src::python::libxml::hashfunc;
// #[derive(Copy, Clone)]

pub type PyMappingMethods = crate::src::python::libxml::PyMappingMethods;
pub type objobjargproc = crate::src::python::libxml::objobjargproc;
pub type binaryfunc = crate::src::python::libxml::binaryfunc;
pub type lenfunc = crate::src::python::libxml::lenfunc;
// #[derive(Copy, Clone)]

pub type PySequenceMethods = crate::src::python::libxml::PySequenceMethods;
pub type ssizeargfunc = crate::src::python::libxml::ssizeargfunc;
pub type objobjproc = crate::src::python::libxml::objobjproc;
pub type ssizessizeobjargproc = crate::src::python::libxml::ssizessizeobjargproc;
pub type ssizeobjargproc = crate::src::python::libxml::ssizeobjargproc;
pub type ssizessizeargfunc = crate::src::python::libxml::ssizessizeargfunc;
// #[derive(Copy, Clone)]

pub type PyNumberMethods = crate::src::python::libxml::PyNumberMethods;
pub type unaryfunc = crate::src::python::libxml::unaryfunc;
pub type coercion = crate::src::python::libxml::coercion;
pub type cmpfunc = crate::src::python::libxml::cmpfunc;
pub type setattrfunc = crate::src::python::libxml::setattrfunc;
pub type getattrfunc = crate::src::python::libxml::getattrfunc;
pub type printfunc = crate::src::python::libxml::printfunc;
// #[derive(Copy, Clone)]

pub type PyVarObject = crate::src::python::libxml::PyVarObject;
pub type PyTypeObject = crate::src::python::libxml::PyTypeObject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyIntObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_ival: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyFloatObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_fval: f64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyStringObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
    pub ob_shash: i64,
    pub ob_sstate: i32,
    pub ob_sval: [i8; 1],
}
pub type PyCapsule_Destructor = Option::<unsafe extern "C" fn(*mut PyObject) -> ()>;
pub type xmlChar = crate::src::HTMLparser::xmlChar;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::HTMLparser::_xmlParserInputBuffer;
pub type xmlBufPtr = crate::src::HTMLparser::xmlBufPtr;
pub type xmlBuf = crate::src::HTMLparser::xmlBuf;
pub type xmlCharEncodingHandlerPtr = crate::src::HTMLparser::xmlCharEncodingHandlerPtr;
pub type xmlCharEncodingHandler = crate::src::HTMLparser::xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::HTMLparser::_xmlCharEncodingHandler;
pub type iconv_t = crate::src::HTMLparser::iconv_t;
pub type xmlCharEncodingOutputFunc = crate::src::HTMLparser::xmlCharEncodingOutputFunc;
pub type xmlCharEncodingInputFunc = crate::src::HTMLparser::xmlCharEncodingInputFunc;
pub type xmlInputCloseCallback = crate::src::HTMLparser::xmlInputCloseCallback;
pub type xmlInputReadCallback = crate::src::HTMLparser::xmlInputReadCallback;
pub type xmlParserInputBuffer = crate::src::HTMLparser::xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = crate::src::HTMLparser::xmlParserInputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlOutputBuffer = crate::src::HTMLtree::_xmlOutputBuffer;
pub type xmlOutputCloseCallback = crate::src::HTMLtree::xmlOutputCloseCallback;
pub type xmlOutputWriteCallback = crate::src::HTMLtree::xmlOutputWriteCallback;
pub type xmlOutputBuffer = crate::src::HTMLtree::xmlOutputBuffer;
pub type xmlOutputBufferPtr = crate::src::HTMLtree::xmlOutputBufferPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::HTMLparser::_xmlParserInput;
pub type xmlParserInputDeallocate = crate::src::HTMLparser::xmlParserInputDeallocate;
pub type xmlParserInput = crate::src::HTMLparser::xmlParserInput;
pub type xmlParserInputPtr = crate::src::HTMLparser::xmlParserInputPtr;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::HTMLparser::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::HTMLparser::xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::HTMLparser::_xmlParserNodeInfo;
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
pub type xmlParserMode = crate::src::HTMLparser::xmlParserMode;
pub const XML_PARSE_READER: xmlParserMode = 5;
pub const XML_PARSE_PUSH_SAX: xmlParserMode = 4;
pub const XML_PARSE_PUSH_DOM: xmlParserMode = 3;
pub const XML_PARSE_SAX: xmlParserMode = 2;
pub const XML_PARSE_DOM: xmlParserMode = 1;
pub const XML_PARSE_UNKNOWN: xmlParserMode = 0;
pub type xmlError = crate::src::HTMLparser::xmlError;
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::HTMLparser::_xmlError;
pub type xmlErrorLevel = crate::src::HTMLparser::xmlErrorLevel;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = crate::src::HTMLparser::xmlAttrPtr;
pub type xmlAttr = crate::src::HTMLparser::xmlAttr;
pub type xmlNodePtr = crate::src::HTMLparser::xmlNodePtr;
pub type xmlNode = crate::src::HTMLparser::xmlNode;
pub type xmlHashTablePtr = crate::src::HTMLparser::xmlHashTablePtr;
pub type xmlHashTable = crate::src::HTMLparser::xmlHashTable;
pub type xmlStartTag = crate::src::HTMLparser::xmlStartTag;
pub type xmlDictPtr = crate::src::HTMLparser::xmlDictPtr;
pub type xmlDict = crate::src::HTMLparser::xmlDict;
pub type xmlParserInputState = crate::src::HTMLparser::xmlParserInputState;
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
pub type xmlValidCtxt = crate::src::HTMLparser::xmlValidCtxt;
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::HTMLparser::_xmlValidCtxt;
pub type xmlAutomataStatePtr = crate::src::HTMLparser::xmlAutomataStatePtr;
pub type xmlAutomataState = crate::src::HTMLparser::xmlAutomataState;
pub type xmlAutomataPtr = crate::src::HTMLparser::xmlAutomataPtr;
pub type xmlAutomata = crate::src::HTMLparser::xmlAutomata;
pub type xmlValidState = crate::src::HTMLparser::xmlValidState;
pub type xmlDocPtr = crate::src::HTMLparser::xmlDocPtr;
pub type xmlDoc = crate::src::HTMLparser::xmlDoc;
pub type xmlValidityWarningFunc = crate::src::HTMLparser::xmlValidityWarningFunc;
pub type xmlValidityErrorFunc = crate::src::HTMLparser::xmlValidityErrorFunc;
pub type xmlParserNodeInfoSeq = crate::src::HTMLparser::xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::HTMLparser::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::HTMLparser::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = crate::src::HTMLparser::xmlStructuredErrorFunc;
pub type xmlErrorPtr = crate::src::HTMLparser::xmlErrorPtr;
pub type endElementNsSAX2Func = crate::src::HTMLparser::endElementNsSAX2Func;
pub type startElementNsSAX2Func = crate::src::HTMLparser::startElementNsSAX2Func;
pub type externalSubsetSAXFunc = crate::src::HTMLparser::externalSubsetSAXFunc;
pub type cdataBlockSAXFunc = crate::src::HTMLparser::cdataBlockSAXFunc;
pub type getParameterEntitySAXFunc = crate::src::HTMLparser::getParameterEntitySAXFunc;
pub type xmlEntityPtr = crate::src::HTMLparser::xmlEntityPtr;
pub type xmlEntity = crate::src::HTMLparser::xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::HTMLparser::_xmlEntity;
pub type xmlEntityType = crate::src::HTMLparser::xmlEntityType;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = crate::src::HTMLparser::fatalErrorSAXFunc;
pub type errorSAXFunc = crate::src::HTMLparser::errorSAXFunc;
pub type warningSAXFunc = crate::src::HTMLparser::warningSAXFunc;
pub type commentSAXFunc = crate::src::HTMLparser::commentSAXFunc;
pub type processingInstructionSAXFunc = crate::src::HTMLparser::processingInstructionSAXFunc;
pub type ignorableWhitespaceSAXFunc = crate::src::HTMLparser::ignorableWhitespaceSAXFunc;
pub type charactersSAXFunc = crate::src::HTMLparser::charactersSAXFunc;
pub type referenceSAXFunc = crate::src::HTMLparser::referenceSAXFunc;
pub type endElementSAXFunc = crate::src::HTMLparser::endElementSAXFunc;
pub type startElementSAXFunc = crate::src::HTMLparser::startElementSAXFunc;
pub type endDocumentSAXFunc = crate::src::HTMLparser::endDocumentSAXFunc;
pub type startDocumentSAXFunc = crate::src::HTMLparser::startDocumentSAXFunc;
pub type setDocumentLocatorSAXFunc = crate::src::HTMLparser::setDocumentLocatorSAXFunc;
pub type xmlSAXLocatorPtr = crate::src::HTMLparser::xmlSAXLocatorPtr;
pub type xmlSAXLocator = crate::src::HTMLparser::xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::HTMLparser::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = crate::src::HTMLparser::unparsedEntityDeclSAXFunc;
pub type elementDeclSAXFunc = crate::src::HTMLparser::elementDeclSAXFunc;
pub type xmlElementContentPtr = crate::src::HTMLparser::xmlElementContentPtr;
pub type xmlElementContent = crate::src::HTMLparser::xmlElementContent;
// #[derive(Copy, Clone)]

pub type _xmlElementContent = crate::src::HTMLparser::_xmlElementContent;
pub type xmlElementContentOccur = crate::src::HTMLparser::xmlElementContentOccur;
pub const XML_ELEMENT_CONTENT_PLUS: xmlElementContentOccur = 4;
pub const XML_ELEMENT_CONTENT_MULT: xmlElementContentOccur = 3;
pub const XML_ELEMENT_CONTENT_OPT: xmlElementContentOccur = 2;
pub const XML_ELEMENT_CONTENT_ONCE: xmlElementContentOccur = 1;
pub type xmlElementContentType = crate::src::HTMLparser::xmlElementContentType;
pub const XML_ELEMENT_CONTENT_OR: xmlElementContentType = 4;
pub const XML_ELEMENT_CONTENT_SEQ: xmlElementContentType = 3;
pub const XML_ELEMENT_CONTENT_ELEMENT: xmlElementContentType = 2;
pub const XML_ELEMENT_CONTENT_PCDATA: xmlElementContentType = 1;
pub type attributeDeclSAXFunc = crate::src::HTMLparser::attributeDeclSAXFunc;
pub type xmlEnumerationPtr = crate::src::HTMLparser::xmlEnumerationPtr;
pub type xmlEnumeration = crate::src::HTMLparser::xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::HTMLparser::_xmlEnumeration;
pub type notationDeclSAXFunc = crate::src::HTMLparser::notationDeclSAXFunc;
pub type entityDeclSAXFunc = crate::src::HTMLparser::entityDeclSAXFunc;
pub type getEntitySAXFunc = crate::src::HTMLparser::getEntitySAXFunc;
pub type resolveEntitySAXFunc = crate::src::HTMLparser::resolveEntitySAXFunc;
pub type hasExternalSubsetSAXFunc = crate::src::HTMLparser::hasExternalSubsetSAXFunc;
pub type hasInternalSubsetSAXFunc = crate::src::HTMLparser::hasInternalSubsetSAXFunc;
pub type isStandaloneSAXFunc = crate::src::HTMLparser::isStandaloneSAXFunc;
pub type internalSubsetSAXFunc = crate::src::HTMLparser::internalSubsetSAXFunc;
pub type xmlParserCtxt = crate::src::HTMLparser::xmlParserCtxt;
pub type xmlParserCtxtPtr = crate::src::HTMLparser::xmlParserCtxtPtr;
pub type xmlAttributeDefault = crate::src::SAX2::xmlAttributeDefault;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
// #[derive(Copy, Clone)]

pub type _xmlAttribute = crate::src::SAX2::_xmlAttribute;
pub type xmlAttribute = crate::src::SAX2::xmlAttribute;
pub type xmlAttributePtr = crate::src::SAX2::xmlAttributePtr;
pub type xmlElementTypeVal = crate::src::SAX2::xmlElementTypeVal;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = crate::src::SAX2::xmlRegexp;
pub type xmlRegexpPtr = crate::src::SAX2::xmlRegexpPtr;
// #[derive(Copy, Clone)]

pub type _xmlElement = crate::src::SAX2::_xmlElement;
pub type xmlElement = crate::src::SAX2::xmlElement;
pub type xmlElementPtr = crate::src::SAX2::xmlElementPtr;
pub type xmlNsPtr = crate::src::HTMLtree::xmlNsPtr;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlValidCtxtPtr = crate::src::SAX2::xmlValidCtxtPtr;
pub type xmlCatalog = crate::src::catalog::xmlCatalog;
pub type xmlCatalogPtr = crate::src::catalog::xmlCatalogPtr;
// #[derive(Copy, Clone)]

pub type _xmlURI = crate::src::SAX2::_xmlURI;
pub type xmlURI = crate::src::SAX2::xmlURI;
pub type xmlURIPtr = crate::src::SAX2::xmlURIPtr;
// #[derive(Copy, Clone)]

pub type _xmlXPathContext = crate::src::debugXML::_xmlXPathContext;
pub type xmlXPathFuncLookupFunc = crate::src::debugXML::xmlXPathFuncLookupFunc;
pub type xmlXPathFunction = crate::src::debugXML::xmlXPathFunction;
pub type xmlXPathParserContextPtr = crate::src::debugXML::xmlXPathParserContextPtr;
pub type xmlXPathParserContext = crate::src::debugXML::xmlXPathParserContext;
// #[derive(Copy, Clone)]

pub type _xmlXPathParserContext = crate::src::debugXML::_xmlXPathParserContext;
pub type xmlXPathCompExprPtr = crate::src::debugXML::xmlXPathCompExprPtr;
pub type xmlXPathCompExpr = crate::src::debugXML::xmlXPathCompExpr;
pub type xmlXPathObjectPtr = crate::src::debugXML::xmlXPathObjectPtr;
pub type xmlXPathObject = crate::src::debugXML::xmlXPathObject;
// #[derive(Copy, Clone)]

pub type _xmlXPathObject = crate::src::debugXML::_xmlXPathObject;
pub type xmlNodeSetPtr = crate::src::c14n::xmlNodeSetPtr;
pub type xmlNodeSet = crate::src::c14n::xmlNodeSet;
// #[derive(Copy, Clone)]

pub type _xmlNodeSet = crate::src::c14n::_xmlNodeSet;
pub type xmlXPathObjectType = crate::src::debugXML::xmlXPathObjectType;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = crate::src::debugXML::xmlXPathContextPtr;
pub type xmlXPathContext = crate::src::debugXML::xmlXPathContext;
pub type xmlXPathVariableLookupFunc = crate::src::debugXML::xmlXPathVariableLookupFunc;
pub type xmlXPathAxisPtr = crate::src::debugXML::xmlXPathAxisPtr;
pub type xmlXPathAxis = crate::src::debugXML::xmlXPathAxis;
// #[derive(Copy, Clone)]

pub type _xmlXPathAxis = crate::src::debugXML::_xmlXPathAxis;
pub type xmlXPathAxisFunc = crate::src::debugXML::xmlXPathAxisFunc;
pub type xmlXPathTypePtr = crate::src::debugXML::xmlXPathTypePtr;
pub type xmlXPathType = crate::src::debugXML::xmlXPathType;
// #[derive(Copy, Clone)]

pub type _xmlXPathType = crate::src::debugXML::_xmlXPathType;
pub type xmlXPathConvertFunc = crate::src::debugXML::xmlXPathConvertFunc;
pub type xmlRelaxNG = crate::src::debugXML::xmlRelaxNG;
pub type xmlRelaxNGPtr = crate::src::debugXML::xmlRelaxNGPtr;
pub type xmlRelaxNGParserCtxt = crate::src::debugXML::xmlRelaxNGParserCtxt;
pub type xmlRelaxNGParserCtxtPtr = crate::src::debugXML::xmlRelaxNGParserCtxtPtr;
pub type xmlRelaxNGValidCtxt = crate::src::debugXML::xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidCtxtPtr = crate::src::debugXML::xmlRelaxNGValidCtxtPtr;
pub type xmlSchema = crate::src::python::libxml2_py::xmlSchema;
pub type xmlSchemaPtr = crate::src::python::libxml2_py::xmlSchemaPtr;
pub type xmlSchemaParserCtxt = crate::src::python::libxml2_py::xmlSchemaParserCtxt;
pub type xmlSchemaParserCtxtPtr = crate::src::python::libxml2_py::xmlSchemaParserCtxtPtr;
pub type xmlSchemaValidCtxt = crate::src::python::libxml::xmlSchemaValidCtxt;
pub type xmlSchemaValidCtxtPtr = crate::src::python::libxml::xmlSchemaValidCtxtPtr;
pub type xmlTextReader = crate::src::python::libxml::xmlTextReader;
pub type xmlTextReaderPtr = crate::src::python::libxml::xmlTextReaderPtr;
pub type xmlTextReaderLocatorPtr = crate::src::python::libxml::xmlTextReaderLocatorPtr;
// #[derive(Copy, Clone)]

pub type PyxmlNode_Object = crate::src::python::libxml::PyxmlNode_Object;
#[no_mangle]
pub unsafe extern "C" fn libxml_intWrap(mut val: i32) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyInt_FromLong(val as i64);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_longWrap(mut val: i64) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyLong_FromLong(val);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_doubleWrap(mut val: f64) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyFloat_FromDouble(val);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_charPtrWrap(
    mut str: *mut i8,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh0 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh0 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str);
    xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_charPtrConstWrap(
    mut str: *const i8,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh1 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh1 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCharPtrWrap(mut str: *mut xmlChar) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh2 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh2 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut i8);
    xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCharPtrConstWrap(
    mut str: *const xmlChar,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh3 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh3 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut i8);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_constcharPtrWrap(
    mut str: *const i8,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh4 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh4 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_constxmlCharPtrWrap(
    mut str: *const xmlChar,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let fresh5 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh5 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut i8);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocPtrWrap(mut doc: xmlDocPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if doc.is_null() {
        let fresh6 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh6 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        doc as *mut libc::c_void,
        b"xmlDocPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodePtrWrap(mut node: xmlNodePtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if node.is_null() {
        let fresh7 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh7 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        node as *mut libc::c_void,
        b"xmlNodePtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIPtrWrap(mut uri: xmlURIPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if uri.is_null() {
        let fresh8 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh8 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        uri as *mut libc::c_void,
        b"xmlURIPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNsPtrWrap(mut ns: xmlNsPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ns.is_null() {
        let fresh9 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh9 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ns as *mut libc::c_void,
        b"xmlNsPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAttrPtrWrap(mut attr: xmlAttrPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if attr.is_null() {
        let fresh10 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh10 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        attr as *mut libc::c_void,
        b"xmlAttrPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAttributePtrWrap(
    mut attr: xmlAttributePtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if attr.is_null() {
        let fresh11 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh11 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        attr as *mut libc::c_void,
        b"xmlAttributePtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlElementPtrWrap(
    mut elem: xmlElementPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if elem.is_null() {
        let fresh12 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh12 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        elem as *mut libc::c_void,
        b"xmlElementPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathContextPtrWrap(
    mut ctxt: xmlXPathContextPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh13 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh13 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlXPathContextPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathParserContextPtrWrap(
    mut ctxt: xmlXPathParserContextPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh14 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh14 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlXPathParserContextPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserCtxtPtrWrap(
    mut ctxt: xmlParserCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh15 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh15 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlParserCtxtPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
unsafe extern "C" fn libxml_xmlXPathDestructNsNode(mut cap: *mut PyObject) {
    xmlXPathNodeSetFreeNs(
        PyCapsule_GetPointer(cap, b"xmlNsPtr\0" as *const u8 as *const i8)
            as xmlNsPtr,
    );
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathObjectPtrWrap(
    mut obj: xmlXPathObjectPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if obj.is_null() {
        let fresh16 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh16 += 1;
        return &mut _Py_NoneStruct;
    }
    match (*obj).type_0 as u32 {
        9 => {
            if ((*obj).nodesetval).is_null()
                || (*(*obj).nodesetval).nodeNr == 0 as i32
                || ((*(*obj).nodesetval).nodeTab).is_null()
            {
                ret = PyList_New(0 as i32 as Py_ssize_t);
            } else {
                let mut i: i32 = 0;
                let mut len: i32 = 0 as i32;
                let mut node: xmlNodePtr = 0 as *mut xmlNode;
                node = (**((*(*obj).nodesetval).nodeTab)
                    .offset(0 as i32 as isize))
                    .children;
                while !node.is_null() {
                    len += 1;
                    node = (*node).next;
                }
                ret = PyList_New(len as Py_ssize_t);
                node = (**((*(*obj).nodesetval).nodeTab)
                    .offset(0 as i32 as isize))
                    .children;
                i = 0 as i32;
                while i < len {
                    PyList_SetItem(ret, i as Py_ssize_t, libxml_xmlNodePtrWrap(node));
                    node = (*node).next;
                    i += 1;
                }
            }
            return ret;
        }
        1 => {
            if ((*obj).nodesetval).is_null()
                || (*(*obj).nodesetval).nodeNr == 0 as i32
            {
                ret = PyList_New(0 as i32 as Py_ssize_t);
            } else {
                let mut i_0: i32 = 0;
                let mut node_0: xmlNodePtr = 0 as *mut xmlNode;
                ret = PyList_New((*(*obj).nodesetval).nodeNr as Py_ssize_t);
                i_0 = 0 as i32;
                while i_0 < (*(*obj).nodesetval).nodeNr {
                    node_0 = *((*(*obj).nodesetval).nodeTab).offset(i_0 as isize);
                    if (*node_0).type_0 as u32
                        == XML_NAMESPACE_DECL as i32 as u32
                    {
                        let mut ns: *mut PyObject = PyCapsule_New(
                            node_0 as *mut libc::c_void,
                            b"xmlNsPtr\0" as *const u8 as *const i8
                                as *mut i8,
                            Some(
                                libxml_xmlXPathDestructNsNode
                                    as unsafe extern "C" fn(*mut PyObject) -> (),
                            ),
                        );
                        PyList_SetItem(ret, i_0 as Py_ssize_t, ns);
                        let fresh17 = &mut (*((*(*obj).nodesetval).nodeTab)
                            .offset(i_0 as isize));
                        *fresh17 = 0 as xmlNodePtr;
                    } else {
                        PyList_SetItem(
                            ret,
                            i_0 as Py_ssize_t,
                            libxml_xmlNodePtrWrap(node_0),
                        );
                    }
                    i_0 += 1;
                }
            }
        }
        2 => {
            ret = PyInt_FromLong((*obj).boolval as i64);
        }
        3 => {
            ret = PyFloat_FromDouble((*obj).floatval);
        }
        4 => {
            ret = PyString_FromString((*obj).stringval as *mut i8);
        }
        _ => {
            let fresh18 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
            *fresh18 += 1;
            ret = &mut _Py_NoneStruct;
        }
    }
    xmlXPathFreeObject(obj);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathObjectPtrConvert(
    mut obj: *mut PyObject,
) -> xmlXPathObjectPtr {
    let mut ret: xmlXPathObjectPtr = 0 as xmlXPathObjectPtr;
    if obj.is_null() {
        return 0 as xmlXPathObjectPtr;
    }
    if (*obj).ob_type == &mut PyFloat_Type as *mut PyTypeObject
        || PyType_IsSubtype((*obj).ob_type, &mut PyFloat_Type) != 0
    {
        ret = xmlXPathNewFloat((*(obj as *mut PyFloatObject)).ob_fval);
    } else if (*(*obj).ob_type).tp_flags & (1 as i64) << 24 as i32
            != 0 as i32 as i64
        {
        ret = xmlXPathNewFloat((*(obj as *mut PyIntObject)).ob_ival as f64);
    } else if (*obj).ob_type == &mut PyBool_Type as *mut PyTypeObject {
        if obj == &mut _Py_TrueStruct as *mut PyIntObject as *mut PyObject {
            ret = xmlXPathNewBoolean(1 as i32);
        } else {
            ret = xmlXPathNewBoolean(0 as i32);
        }
    } else if (*(*obj).ob_type).tp_flags & (1 as i64) << 27 as i32
            != 0 as i32 as i64
        {
        let mut str: *mut xmlChar = 0 as *mut xmlChar;
        str = xmlStrndup(
            ((*(obj as *mut PyStringObject)).ob_sval).as_mut_ptr() as *const xmlChar,
            (*(obj as *mut PyVarObject)).ob_size as i32,
        );
        ret = xmlXPathWrapString(str);
    } else if (*(*obj).ob_type).tp_flags & (1 as i64) << 28 as i32
            != 0 as i32 as i64
        {
        let mut str_0: *mut xmlChar = 0 as *mut xmlChar;
        let mut b: *mut PyObject = 0 as *mut PyObject;
        b = PyUnicodeUCS4_AsUTF8String(obj);
        if !b.is_null() {
            str_0 = xmlStrndup(
                ((*(b as *mut PyStringObject)).ob_sval).as_mut_ptr() as *const xmlChar,
                (*(b as *mut PyVarObject)).ob_size as i32,
            );
            let fresh19 = &mut ((*b).ob_refcnt);
            *fresh19 -= 1;
            if !(*fresh19 != 0 as i32 as i64) {
                (Some(((*(*b).ob_type).tp_dealloc).expect("non-null function pointer")))
                    .expect("non-null function pointer")(b);
            }
        }
        ret = xmlXPathWrapString(str_0);
    } else if (*(*obj).ob_type).tp_flags & (1 as i64) << 25 as i32
            != 0 as i32 as i64
        {
        let mut i: i32 = 0;
        let mut node: *mut PyObject = 0 as *mut PyObject;
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        let mut set: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
        set = xmlXPathNodeSetCreate(0 as xmlNodePtr);
        i = 0 as i32;
        while (i as i64) < PyList_Size(obj) {
            node = PyList_GetItem(obj, i as Py_ssize_t);
            if !(node.is_null() || ((*node).ob_type).is_null()) {
                cur = 0 as xmlNodePtr;
                if (*node).ob_type == &mut PyCapsule_Type as *mut PyTypeObject {
                    cur = if node == &mut _Py_NoneStruct as *mut PyObject {
                        0 as xmlNodePtr
                    } else {
                        (*(node as *mut PyxmlNode_Object)).obj
                    };
                } else if PyObject_HasAttrString(
                        node,
                        b"_o\0" as *const u8 as *const i8 as *mut i8,
                    ) != 0
                        && PyObject_HasAttrString(
                            node,
                            b"get_doc\0" as *const u8 as *const i8
                                as *mut i8,
                        ) != 0
                    {
                    let mut wrapper: *mut PyObject = 0 as *mut PyObject;
                    wrapper = PyObject_GetAttrString(
                        node,
                        b"_o\0" as *const u8 as *const i8 as *mut i8,
                    );
                    if !wrapper.is_null() {
                        cur = if wrapper == &mut _Py_NoneStruct as *mut PyObject {
                            0 as xmlNodePtr
                        } else {
                            (*(wrapper as *mut PyxmlNode_Object)).obj
                        };
                    }
                }
                if !cur.is_null() {
                    xmlXPathNodeSetAdd(set, cur);
                }
            }
            i += 1;
        }
        ret = xmlXPathWrapNodeSet(set);
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidCtxtPtrWrap(
    mut valid: xmlValidCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if valid.is_null() {
        let fresh20 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh20 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlValidCtxtPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogPtrWrap(
    mut catal: xmlCatalogPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if catal.is_null() {
        let fresh21 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh21 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        catal as *mut libc::c_void,
        b"xmlCatalogPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlOutputBufferPtrWrap(
    mut buffer: xmlOutputBufferPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if buffer.is_null() {
        let fresh22 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh22 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        buffer as *mut libc::c_void,
        b"xmlOutputBufferPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserInputBufferPtrWrap(
    mut buffer: xmlParserInputBufferPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if buffer.is_null() {
        let fresh23 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh23 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        buffer as *mut libc::c_void,
        b"xmlParserInputBufferPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegexpPtrWrap(
    mut regexp: xmlRegexpPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if regexp.is_null() {
        let fresh24 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh24 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        regexp as *mut libc::c_void,
        b"xmlRegexpPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderPtrWrap(
    mut reader: xmlTextReaderPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if reader.is_null() {
        let fresh25 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh25 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        reader as *mut libc::c_void,
        b"xmlTextReaderPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderLocatorPtrWrap(
    mut locator: xmlTextReaderLocatorPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if locator.is_null() {
        let fresh26 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh26 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        locator,
        b"xmlTextReaderLocatorPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGPtrWrap(
    mut ctxt: xmlRelaxNGPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh27 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh27 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlRelaxNGPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGParserCtxtPtrWrap(
    mut ctxt: xmlRelaxNGParserCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh28 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh28 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlRelaxNGParserCtxtPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidCtxtPtrWrap(
    mut valid: xmlRelaxNGValidCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if valid.is_null() {
        let fresh29 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh29 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlRelaxNGValidCtxtPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaPtrWrap(
    mut ctxt: xmlSchemaPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh30 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh30 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlSchemaPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaParserCtxtPtrWrap(
    mut ctxt: xmlSchemaParserCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ctxt.is_null() {
        let fresh31 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh31 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlSchemaParserCtxtPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidCtxtPtrWrap(
    mut valid: xmlSchemaValidCtxtPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if valid.is_null() {
        let fresh32 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh32 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlSchemaValidCtxtPtr\0" as *const u8 as *const i8
            as *mut i8,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorPtrWrap(
    mut error: xmlErrorPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if error.is_null() {
        let fresh33 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
        *fresh33 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        error as *mut libc::c_void,
        b"xmlErrorPtr\0" as *const u8 as *const i8 as *mut i8,
        None,
    );
    return ret;
}
