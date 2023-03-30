use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type PyMemberDef;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    fn PyLong_FromLong(_: libc::c_long) -> *mut PyObject;
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> libc::c_int;
    fn PyObject_GetAttrString(_: *mut PyObject, _: *const libc::c_char) -> *mut PyObject;
    fn PyObject_HasAttrString(_: *mut PyObject, _: *const libc::c_char) -> libc::c_int;
    static mut _Py_NoneStruct: PyObject;
    fn PyUnicodeUCS4_AsUTF8String(unicode: *mut PyObject) -> *mut PyObject;
    fn PyInt_FromLong(_: libc::c_long) -> *mut PyObject;
    static mut PyBool_Type: PyTypeObject;
    static mut _Py_TrueStruct: PyIntObject;
    static mut PyFloat_Type: PyTypeObject;
    fn PyFloat_FromDouble(_: libc::c_double) -> *mut PyObject;
    fn PyString_FromString(_: *const libc::c_char) -> *mut PyObject;
    fn PyList_New(size: Py_ssize_t) -> *mut PyObject;
    fn PyList_Size(_: *mut PyObject) -> Py_ssize_t;
    fn PyList_GetItem(_: *mut PyObject, _: Py_ssize_t) -> *mut PyObject;
    fn PyList_SetItem(_: *mut PyObject, _: Py_ssize_t, _: *mut PyObject) -> libc::c_int;
    static mut PyCapsule_Type: PyTypeObject;
    fn PyCapsule_New(
        pointer: *mut libc::c_void,
        name: *const libc::c_char,
        destructor: PyCapsule_Destructor,
    ) -> *mut PyObject;
    fn PyCapsule_GetPointer(
        capsule: *mut PyObject,
        name: *const libc::c_char,
    ) -> *mut libc::c_void;
    
    static mut xmlFree: xmlFreeFunc;
    
    
    
    
    
    
    
    
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
pub use crate::src::HTMLparser::size_t;
pub use crate::src::HTMLtree::__off_t;
pub use crate::src::HTMLtree::__off64_t;
pub use crate::src::catalog::__ssize_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_IO_FILE;
pub use crate::src::HTMLtree::_IO_lock_t;
pub use crate::src::HTMLtree::FILE;
pub use crate::src::catalog::ssize_t;
pub use crate::src::python::libxml::Py_ssize_t;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::_object;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::_typeobject;
pub use crate::src::python::libxml::destructor;
pub use crate::src::python::libxml::PyObject;
pub use crate::src::python::libxml::inquiry;
pub use crate::src::python::libxml::freefunc;
pub use crate::src::python::libxml::newfunc;
pub use crate::src::python::libxml::allocfunc;
pub use crate::src::python::libxml::initproc;
pub use crate::src::python::libxml::descrsetfunc;
pub use crate::src::python::libxml::descrgetfunc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyGetSetDef;
pub use crate::src::python::libxml::setter;
pub use crate::src::python::libxml::getter;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyMethodDef;
pub use crate::src::python::libxml::PyCFunction;
pub use crate::src::python::libxml::iternextfunc;
pub use crate::src::python::libxml::getiterfunc;
pub use crate::src::python::libxml::richcmpfunc;
pub use crate::src::python::libxml::traverseproc;
pub use crate::src::python::libxml::visitproc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyBufferProcs;
pub use crate::src::python::libxml::releasebufferproc;
pub use crate::src::python::libxml::Py_buffer;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::bufferinfo;
pub use crate::src::python::libxml::getbufferproc;
pub use crate::src::python::libxml::charbufferproc;
pub use crate::src::python::libxml::segcountproc;
pub use crate::src::python::libxml::writebufferproc;
pub use crate::src::python::libxml::readbufferproc;
pub use crate::src::python::libxml::setattrofunc;
pub use crate::src::python::libxml::getattrofunc;
pub use crate::src::python::libxml::reprfunc;
pub use crate::src::python::libxml::ternaryfunc;
pub use crate::src::python::libxml::hashfunc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyMappingMethods;
pub use crate::src::python::libxml::objobjargproc;
pub use crate::src::python::libxml::binaryfunc;
pub use crate::src::python::libxml::lenfunc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PySequenceMethods;
pub use crate::src::python::libxml::ssizeargfunc;
pub use crate::src::python::libxml::objobjproc;
pub use crate::src::python::libxml::ssizessizeobjargproc;
pub use crate::src::python::libxml::ssizeobjargproc;
pub use crate::src::python::libxml::ssizessizeargfunc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyNumberMethods;
pub use crate::src::python::libxml::unaryfunc;
pub use crate::src::python::libxml::coercion;
pub use crate::src::python::libxml::cmpfunc;
pub use crate::src::python::libxml::setattrfunc;
pub use crate::src::python::libxml::getattrfunc;
pub use crate::src::python::libxml::printfunc;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyVarObject;
pub use crate::src::python::libxml::PyTypeObject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyIntObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_ival: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyFloatObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_fval: libc::c_double,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyStringObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
    pub ob_shash: libc::c_long,
    pub ob_sstate: libc::c_int,
    pub ob_sval: [libc::c_char; 1],
}
pub type PyCapsule_Destructor = Option::<unsafe extern "C" fn(*mut PyObject) -> ()>;
pub use crate::src::HTMLparser::xmlChar;
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
pub use crate::src::SAX2::xmlAttributeDefault;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlAttribute;
pub use crate::src::SAX2::xmlAttribute;
pub use crate::src::SAX2::xmlAttributePtr;
pub use crate::src::SAX2::xmlElementTypeVal;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub use crate::src::SAX2::xmlRegexp;
pub use crate::src::SAX2::xmlRegexpPtr;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlElement;
pub use crate::src::SAX2::xmlElement;
pub use crate::src::SAX2::xmlElementPtr;
pub use crate::src::HTMLtree::xmlNsPtr;
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::SAX2::xmlValidCtxtPtr;
pub use crate::src::catalog::xmlCatalog;
pub use crate::src::catalog::xmlCatalogPtr;
// #[derive(Copy, Clone)]

pub use crate::src::SAX2::_xmlURI;
pub use crate::src::SAX2::xmlURI;
pub use crate::src::SAX2::xmlURIPtr;
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
pub use crate::src::debugXML::xmlRelaxNG;
pub use crate::src::debugXML::xmlRelaxNGPtr;
pub use crate::src::debugXML::xmlRelaxNGParserCtxt;
pub use crate::src::debugXML::xmlRelaxNGParserCtxtPtr;
pub use crate::src::debugXML::xmlRelaxNGValidCtxt;
pub use crate::src::debugXML::xmlRelaxNGValidCtxtPtr;
pub use crate::src::python::libxml2_py::xmlSchema;
pub use crate::src::python::libxml2_py::xmlSchemaPtr;
pub use crate::src::python::libxml2_py::xmlSchemaParserCtxt;
pub use crate::src::python::libxml2_py::xmlSchemaParserCtxtPtr;
pub use crate::src::python::libxml::xmlSchemaValidCtxt;
pub use crate::src::python::libxml::xmlSchemaValidCtxtPtr;
pub use crate::src::python::libxml::xmlTextReader;
pub use crate::src::python::libxml::xmlTextReaderPtr;
pub use crate::src::python::libxml::xmlTextReaderLocatorPtr;
// #[derive(Copy, Clone)]

pub use crate::src::python::libxml::PyxmlNode_Object;
#[no_mangle]
pub unsafe extern "C" fn libxml_intWrap(mut val: libc::c_int) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyInt_FromLong(val as libc::c_long);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_longWrap(mut val: libc::c_long) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyLong_FromLong(val);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_doubleWrap(mut val: libc::c_double) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = PyFloat_FromDouble(val);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_charPtrWrap(
    mut str: *mut libc::c_char,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let ref mut fresh0 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh0 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str);
    xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_charPtrConstWrap(
    mut str: *const libc::c_char,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let ref mut fresh1 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        let ref mut fresh2 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh2 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut libc::c_char);
    xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCharPtrConstWrap(
    mut str: *const xmlChar,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let ref mut fresh3 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh3 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut libc::c_char);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_constcharPtrWrap(
    mut str: *const libc::c_char,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if str.is_null() {
        let ref mut fresh4 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        let ref mut fresh5 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh5 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyString_FromString(str as *mut libc::c_char);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocPtrWrap(mut doc: xmlDocPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if doc.is_null() {
        let ref mut fresh6 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh6 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        doc as *mut libc::c_void,
        b"xmlDocPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodePtrWrap(mut node: xmlNodePtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if node.is_null() {
        let ref mut fresh7 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh7 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        node as *mut libc::c_void,
        b"xmlNodePtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIPtrWrap(mut uri: xmlURIPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if uri.is_null() {
        let ref mut fresh8 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh8 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        uri as *mut libc::c_void,
        b"xmlURIPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNsPtrWrap(mut ns: xmlNsPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if ns.is_null() {
        let ref mut fresh9 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh9 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ns as *mut libc::c_void,
        b"xmlNsPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAttrPtrWrap(mut attr: xmlAttrPtr) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if attr.is_null() {
        let ref mut fresh10 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh10 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        attr as *mut libc::c_void,
        b"xmlAttrPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh11 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh11 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        attr as *mut libc::c_void,
        b"xmlAttributePtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh12 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh12 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        elem as *mut libc::c_void,
        b"xmlElementPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh13 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh13 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlXPathContextPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh14 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh14 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlXPathParserContextPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh15 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh15 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlParserCtxtPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
unsafe extern "C" fn libxml_xmlXPathDestructNsNode(mut cap: *mut PyObject) {
    xmlXPathNodeSetFreeNs(
        PyCapsule_GetPointer(cap, b"xmlNsPtr\0" as *const u8 as *const libc::c_char)
            as xmlNsPtr,
    );
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathObjectPtrWrap(
    mut obj: xmlXPathObjectPtr,
) -> *mut PyObject {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    if obj.is_null() {
        let ref mut fresh16 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh16 += 1;
        return &mut _Py_NoneStruct;
    }
    match (*obj).type_0 as libc::c_uint {
        9 => {
            if ((*obj).nodesetval).is_null()
                || (*(*obj).nodesetval).nodeNr == 0 as libc::c_int
                || ((*(*obj).nodesetval).nodeTab).is_null()
            {
                ret = PyList_New(0 as libc::c_int as Py_ssize_t);
            } else {
                let mut i: libc::c_int = 0;
                let mut len: libc::c_int = 0 as libc::c_int;
                let mut node: xmlNodePtr = 0 as *mut xmlNode;
                node = (**((*(*obj).nodesetval).nodeTab)
                    .offset(0 as libc::c_int as isize))
                    .children;
                while !node.is_null() {
                    len += 1;
                    node = (*node).next;
                }
                ret = PyList_New(len as Py_ssize_t);
                node = (**((*(*obj).nodesetval).nodeTab)
                    .offset(0 as libc::c_int as isize))
                    .children;
                i = 0 as libc::c_int;
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
                || (*(*obj).nodesetval).nodeNr == 0 as libc::c_int
            {
                ret = PyList_New(0 as libc::c_int as Py_ssize_t);
            } else {
                let mut i_0: libc::c_int = 0;
                let mut node_0: xmlNodePtr = 0 as *mut xmlNode;
                ret = PyList_New((*(*obj).nodesetval).nodeNr as Py_ssize_t);
                i_0 = 0 as libc::c_int;
                while i_0 < (*(*obj).nodesetval).nodeNr {
                    node_0 = *((*(*obj).nodesetval).nodeTab).offset(i_0 as isize);
                    if (*node_0).type_0 as libc::c_uint
                        == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
                    {
                        let mut ns: *mut PyObject = PyCapsule_New(
                            node_0 as *mut libc::c_void,
                            b"xmlNsPtr\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char,
                            Some(
                                libxml_xmlXPathDestructNsNode
                                    as unsafe extern "C" fn(*mut PyObject) -> (),
                            ),
                        );
                        PyList_SetItem(ret, i_0 as Py_ssize_t, ns);
                        let ref mut fresh17 = *((*(*obj).nodesetval).nodeTab)
                            .offset(i_0 as isize);
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
            ret = PyInt_FromLong((*obj).boolval as libc::c_long);
        }
        3 => {
            ret = PyFloat_FromDouble((*obj).floatval);
        }
        4 => {
            ret = PyString_FromString((*obj).stringval as *mut libc::c_char);
        }
        _ => {
            let ref mut fresh18 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    } else if (*(*obj).ob_type).tp_flags & (1 as libc::c_long) << 24 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        ret = xmlXPathNewFloat((*(obj as *mut PyIntObject)).ob_ival as libc::c_double);
    } else if (*obj).ob_type == &mut PyBool_Type as *mut PyTypeObject {
        if obj == &mut _Py_TrueStruct as *mut PyIntObject as *mut PyObject {
            ret = xmlXPathNewBoolean(1 as libc::c_int);
        } else {
            ret = xmlXPathNewBoolean(0 as libc::c_int);
        }
    } else if (*(*obj).ob_type).tp_flags & (1 as libc::c_long) << 27 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        let mut str: *mut xmlChar = 0 as *mut xmlChar;
        str = xmlStrndup(
            ((*(obj as *mut PyStringObject)).ob_sval).as_mut_ptr() as *const xmlChar,
            (*(obj as *mut PyVarObject)).ob_size as libc::c_int,
        );
        ret = xmlXPathWrapString(str);
    } else if (*(*obj).ob_type).tp_flags & (1 as libc::c_long) << 28 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        let mut str_0: *mut xmlChar = 0 as *mut xmlChar;
        let mut b: *mut PyObject = 0 as *mut PyObject;
        b = PyUnicodeUCS4_AsUTF8String(obj);
        if !b.is_null() {
            str_0 = xmlStrndup(
                ((*(b as *mut PyStringObject)).ob_sval).as_mut_ptr() as *const xmlChar,
                (*(b as *mut PyVarObject)).ob_size as libc::c_int,
            );
            let ref mut fresh19 = (*b).ob_refcnt;
            *fresh19 -= 1;
            if !(*fresh19 != 0 as libc::c_int as libc::c_long) {
                (Some(((*(*b).ob_type).tp_dealloc).expect("non-null function pointer")))
                    .expect("non-null function pointer")(b);
            }
        }
        ret = xmlXPathWrapString(str_0);
    } else if (*(*obj).ob_type).tp_flags & (1 as libc::c_long) << 25 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        let mut i: libc::c_int = 0;
        let mut node: *mut PyObject = 0 as *mut PyObject;
        let mut cur: xmlNodePtr = 0 as *mut xmlNode;
        let mut set: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
        set = xmlXPathNodeSetCreate(0 as xmlNodePtr);
        i = 0 as libc::c_int;
        while (i as libc::c_long) < PyList_Size(obj) {
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
                        b"_o\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ) != 0
                        && PyObject_HasAttrString(
                            node,
                            b"get_doc\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char,
                        ) != 0
                    {
                    let mut wrapper: *mut PyObject = 0 as *mut PyObject;
                    wrapper = PyObject_GetAttrString(
                        node,
                        b"_o\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh20 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh20 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlValidCtxtPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh21 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh21 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        catal as *mut libc::c_void,
        b"xmlCatalogPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh22 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh22 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        buffer as *mut libc::c_void,
        b"xmlOutputBufferPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh23 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh23 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        buffer as *mut libc::c_void,
        b"xmlParserInputBufferPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh24 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh24 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        regexp as *mut libc::c_void,
        b"xmlRegexpPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh25 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh25 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        reader as *mut libc::c_void,
        b"xmlTextReaderPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh26 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh26 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        locator,
        b"xmlTextReaderLocatorPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh27 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh27 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlRelaxNGPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh28 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh28 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlRelaxNGParserCtxtPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh29 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh29 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlRelaxNGValidCtxtPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh30 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh30 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlSchemaPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        let ref mut fresh31 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh31 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        ctxt as *mut libc::c_void,
        b"xmlSchemaParserCtxtPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh32 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh32 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        valid as *mut libc::c_void,
        b"xmlSchemaValidCtxtPtr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        let ref mut fresh33 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh33 += 1;
        return &mut _Py_NoneStruct;
    }
    ret = PyCapsule_New(
        error as *mut libc::c_void,
        b"xmlErrorPtr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        None,
    );
    return ret;
}
