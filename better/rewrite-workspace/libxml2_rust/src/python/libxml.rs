use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type PyMemberDef;
    
    
    
    
    
    
    
    
    
    
    
    
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> libc::c_int;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn vfprintf(
        _: *mut FILE,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;
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
    fn PyUnicodeUCS4_AsUTF8String(unicode: *mut PyObject) -> *mut PyObject;
    fn PyLong_FromLong(_: libc::c_long) -> *mut PyObject;
    fn PyLong_AsLong(_: *mut PyObject) -> libc::c_long;
    fn PyLong_FromVoidPtr(_: *mut libc::c_void) -> *mut PyObject;
    fn PyString_FromStringAndSize(
        _: *const libc::c_char,
        _: Py_ssize_t,
    ) -> *mut PyObject;
    fn PyString_FromString(_: *const libc::c_char) -> *mut PyObject;
    fn PyString_Size(_: *mut PyObject) -> Py_ssize_t;
    fn PyString_AsString(_: *mut PyObject) -> *mut libc::c_char;
    fn PyTuple_New(size: Py_ssize_t) -> *mut PyObject;
    fn PyTuple_SetItem(_: *mut PyObject, _: Py_ssize_t, _: *mut PyObject) -> libc::c_int;
    fn PyList_New(size: Py_ssize_t) -> *mut PyObject;
    fn PyList_SetItem(_: *mut PyObject, _: Py_ssize_t, _: *mut PyObject) -> libc::c_int;
    fn PyDict_New() -> *mut PyObject;
    fn PyDict_SetItem(
        mp: *mut PyObject,
        key: *mut PyObject,
        item: *mut PyObject,
    ) -> libc::c_int;
    static mut PyFile_Type: PyTypeObject;
    fn PyFile_AsFile(_: *mut PyObject) -> *mut FILE;
    static mut PyCapsule_Type: PyTypeObject;
    fn PyCapsule_GetPointer(
        capsule: *mut PyObject,
        name: *const libc::c_char,
    ) -> *mut libc::c_void;
    fn PyCapsule_GetName(capsule: *mut PyObject) -> *const libc::c_char;
    fn PyErr_WarnEx(
        _: *mut PyObject,
        _: *const libc::c_char,
        _: Py_ssize_t,
    ) -> libc::c_int;
    fn PyErr_SetString(_: *mut PyObject, _: *const libc::c_char);
    fn PyErr_Occurred() -> *mut PyObject;
    static mut PyExc_Exception: *mut PyObject;
    static mut PyExc_AssertionError: *mut PyObject;
    static mut PyExc_IndexError: *mut PyObject;
    static mut PyExc_MemoryError: *mut PyObject;
    static mut PyExc_TypeError: *mut PyObject;
    static mut PyExc_ValueError: *mut PyObject;
    static mut PyExc_PendingDeprecationWarning: *mut PyObject;
    fn PyErr_NoMemory() -> *mut PyObject;
    fn _PyArg_ParseTuple_SizeT(
        _: *mut PyObject,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn _Py_BuildValue_SizeT(_: *const libc::c_char, _: ...) -> *mut PyObject;
    fn Py_InitModule4_64(
        name: *const libc::c_char,
        methods: *mut PyMethodDef,
        doc: *const libc::c_char,
        self_0: *mut PyObject,
        apiver: libc::c_int,
    ) -> *mut PyObject;
    fn PyErr_Print();
    fn PyEval_CallObjectWithKeywords(
        _: *mut PyObject,
        _: *mut PyObject,
        _: *mut PyObject,
    ) -> *mut PyObject;
    fn PyEval_CallMethod(
        obj: *mut PyObject,
        methodname: *const libc::c_char,
        format: *const libc::c_char,
        _: ...
    ) -> *mut PyObject;
    fn _PyObject_CallFunction_SizeT(
        callable_object: *mut PyObject,
        format: *mut libc::c_char,
        _: ...
    ) -> *mut PyObject;
    fn _PyObject_CallMethod_SizeT(
        o: *mut PyObject,
        m: *mut libc::c_char,
        format: *mut libc::c_char,
        _: ...
    ) -> *mut PyObject;
    fn PyObject_HasAttrString(_: *mut PyObject, _: *const libc::c_char) -> libc::c_int;
    fn PyCallable_Check(_: *mut PyObject) -> libc::c_int;
    static mut _Py_NoneStruct: PyObject;
    
    
    
    
    
    
    
    
    
    
    
    static mut xmlFree: xmlFreeFunc;
    static mut xmlRealloc: xmlReallocFunc;
    static mut xmlMalloc: xmlMallocFunc;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::HTMLparser::htmlCreatePushParserCtxt;
pub use crate::src::HTMLparser::htmlSAXParseFile;
pub use crate::src::HTMLtree::htmlDocContentDumpFormatOutput;
pub use crate::src::HTMLtree::htmlGetMetaEncoding;
pub use crate::src::HTMLtree::htmlNodeDumpFormatOutput;
pub use crate::src::c14n::xmlC14NDocDumpMemory;
pub use crate::src::c14n::xmlC14NDocSaveTo;
pub use crate::src::catalog::xmlCatalogAddLocal;
pub use crate::src::encoding::xmlFindCharEncodingHandler;
pub use crate::src::encoding::xmlParseCharEncoding;
pub use crate::src::error::xmlParserError;
pub use crate::src::error::xmlParserValidityError;
pub use crate::src::error::xmlParserValidityWarning;
pub use crate::src::error::xmlParserWarning;
pub use crate::src::error::xmlSetGenericErrorFunc;
pub use crate::src::globals::xmlThrDefSetGenericErrorFunc;
pub use crate::src::parser::xmlCleanupParser;
pub use crate::src::parser::xmlCreatePushParserCtxt;
pub use crate::src::parser::xmlInitParser;
pub use crate::src::parser::xmlSAXUserParseFile;
pub use crate::src::parserInternals::xmlFreeParserCtxt;
pub use crate::src::parserInternals::xmlNewIOInputStream;
pub use crate::src::python::libxml2_py::libxml_htmlAutoCloseTag;
pub use crate::src::python::libxml2_py::libxml_htmlCreateFileParserCtxt;
pub use crate::src::python::libxml2_py::libxml_htmlCreateMemoryParserCtxt;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtReadDoc;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtReadFd;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtReadFile;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtReadMemory;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtReset;
pub use crate::src::python::libxml2_py::libxml_htmlCtxtUseOptions;
pub use crate::src::python::libxml2_py::libxml_htmlDefaultSAXHandlerInit;
pub use crate::src::python::libxml2_py::libxml_htmlDocContentDumpFormatOutput;
pub use crate::src::python::libxml2_py::libxml_htmlDocContentDumpOutput;
pub use crate::src::python::libxml2_py::libxml_htmlDocDump;
pub use crate::src::python::libxml2_py::libxml_htmlFreeParserCtxt;
pub use crate::src::python::libxml2_py::libxml_htmlGetMetaEncoding;
pub use crate::src::python::libxml2_py::libxml_htmlHandleOmittedElem;
pub use crate::src::python::libxml2_py::libxml_htmlInitAutoClose;
pub use crate::src::python::libxml2_py::libxml_htmlIsAutoClosed;
pub use crate::src::python::libxml2_py::libxml_htmlIsBooleanAttr;
pub use crate::src::python::libxml2_py::libxml_htmlIsScriptAttribute;
pub use crate::src::python::libxml2_py::libxml_htmlNewDoc;
pub use crate::src::python::libxml2_py::libxml_htmlNewDocNoDtD;
pub use crate::src::python::libxml2_py::libxml_htmlNewParserCtxt;
pub use crate::src::python::libxml2_py::libxml_htmlNodeDumpFile;
pub use crate::src::python::libxml2_py::libxml_htmlNodeDumpFileFormat;
pub use crate::src::python::libxml2_py::libxml_htmlNodeDumpFormatOutput;
pub use crate::src::python::libxml2_py::libxml_htmlNodeDumpOutput;
pub use crate::src::python::libxml2_py::libxml_htmlParseCharRef;
pub use crate::src::python::libxml2_py::libxml_htmlParseChunk;
pub use crate::src::python::libxml2_py::libxml_htmlParseDoc;
pub use crate::src::python::libxml2_py::libxml_htmlParseDocument;
pub use crate::src::python::libxml2_py::libxml_htmlParseElement;
pub use crate::src::python::libxml2_py::libxml_htmlParseFile;
pub use crate::src::python::libxml2_py::libxml_htmlReadDoc;
pub use crate::src::python::libxml2_py::libxml_htmlReadFd;
pub use crate::src::python::libxml2_py::libxml_htmlReadFile;
pub use crate::src::python::libxml2_py::libxml_htmlReadMemory;
pub use crate::src::python::libxml2_py::libxml_htmlSaveFile;
pub use crate::src::python::libxml2_py::libxml_htmlSaveFileEnc;
pub use crate::src::python::libxml2_py::libxml_htmlSaveFileFormat;
pub use crate::src::python::libxml2_py::libxml_htmlSetMetaEncoding;
pub use crate::src::python::libxml2_py::libxml_namePop;
pub use crate::src::python::libxml2_py::libxml_namePush;
pub use crate::src::python::libxml2_py::libxml_nodePop;
pub use crate::src::python::libxml2_py::libxml_nodePush;
pub use crate::src::python::libxml2_py::libxml_valuePop;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogAdd;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogDump;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogRemove;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogResolve;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogResolvePublic;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogResolveSystem;
pub use crate::src::python::libxml2_py::libxml_xmlACatalogResolveURI;
pub use crate::src::python::libxml2_py::libxml_xmlAddChild;
pub use crate::src::python::libxml2_py::libxml_xmlAddChildList;
pub use crate::src::python::libxml2_py::libxml_xmlAddDocEntity;
pub use crate::src::python::libxml2_py::libxml_xmlAddDtdEntity;
pub use crate::src::python::libxml2_py::libxml_xmlAddEncodingAlias;
pub use crate::src::python::libxml2_py::libxml_xmlAddNextSibling;
pub use crate::src::python::libxml2_py::libxml_xmlAddPrevSibling;
pub use crate::src::python::libxml2_py::libxml_xmlAddSibling;
pub use crate::src::python::libxml2_py::libxml_xmlBoolToText;
pub use crate::src::python::libxml2_py::libxml_xmlBuildQName;
pub use crate::src::python::libxml2_py::libxml_xmlBuildRelativeURI;
pub use crate::src::python::libxml2_py::libxml_xmlBuildURI;
pub use crate::src::python::libxml2_py::libxml_xmlByteConsumed;
pub use crate::src::python::libxml2_py::libxml_xmlCanonicPath;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogAdd;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogConvert;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogDump;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogGetPublic;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogGetSystem;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogIsEmpty;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogRemove;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogResolve;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogResolvePublic;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogResolveSystem;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogResolveURI;
pub use crate::src::python::libxml2_py::libxml_xmlCatalogSetDebug;
pub use crate::src::python::libxml2_py::libxml_xmlCharStrdup;
pub use crate::src::python::libxml2_py::libxml_xmlCharStrndup;
pub use crate::src::python::libxml2_py::libxml_xmlCheckFilename;
pub use crate::src::python::libxml2_py::libxml_xmlCheckLanguageID;
pub use crate::src::python::libxml2_py::libxml_xmlCheckUTF8;
pub use crate::src::python::libxml2_py::libxml_xmlCheckVersion;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupCharEncodingHandlers;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupEncodingAliases;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupGlobals;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupInputCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupOutputCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlCleanupPredefinedEntities;
pub use crate::src::python::libxml2_py::libxml_xmlClearParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlConvertSGMLCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlCopyChar;
pub use crate::src::python::libxml2_py::libxml_xmlCopyCharMultiByte;
pub use crate::src::python::libxml2_py::libxml_xmlCopyDoc;
pub use crate::src::python::libxml2_py::libxml_xmlCopyDtd;
pub use crate::src::python::libxml2_py::libxml_xmlCopyError;
pub use crate::src::python::libxml2_py::libxml_xmlCopyNamespace;
pub use crate::src::python::libxml2_py::libxml_xmlCopyNamespaceList;
pub use crate::src::python::libxml2_py::libxml_xmlCopyNode;
pub use crate::src::python::libxml2_py::libxml_xmlCopyNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlCopyProp;
pub use crate::src::python::libxml2_py::libxml_xmlCopyPropList;
pub use crate::src::python::libxml2_py::libxml_xmlCreateDocParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlCreateEntityParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlCreateFileParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlCreateIntSubset;
pub use crate::src::python::libxml2_py::libxml_xmlCreateMemoryParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlCreateURI;
pub use crate::src::python::libxml2_py::libxml_xmlCreateURLParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtReadDoc;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtReadFd;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtReadFile;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtReadMemory;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtReset;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtResetPush;
pub use crate::src::python::libxml2_py::libxml_xmlCtxtUseOptions;
pub use crate::src::python::libxml2_py::libxml_xmlDebugCheckDocument;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpAttr;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpAttrList;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpDTD;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpDocument;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpDocumentHead;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpEntities;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpNode;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpOneNode;
pub use crate::src::python::libxml2_py::libxml_xmlDebugDumpString;
pub use crate::src::python::libxml2_py::libxml_xmlDecodeEntities;
pub use crate::src::python::libxml2_py::libxml_xmlDefaultSAXHandlerInit;
pub use crate::src::python::libxml2_py::libxml_xmlDelEncodingAlias;
pub use crate::src::python::libxml2_py::libxml_xmlDictCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlDocCopyNode;
pub use crate::src::python::libxml2_py::libxml_xmlDocCopyNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlDocDump;
pub use crate::src::python::libxml2_py::libxml_xmlDocFormatDump;
pub use crate::src::python::libxml2_py::libxml_xmlDocGetRootElement;
pub use crate::src::python::libxml2_py::libxml_xmlDocSetRootElement;
pub use crate::src::python::libxml2_py::libxml_xmlElemDump;
pub use crate::src::python::libxml2_py::libxml_xmlEncodeEntities;
pub use crate::src::python::libxml2_py::libxml_xmlEncodeEntitiesReentrant;
pub use crate::src::python::libxml2_py::libxml_xmlEncodeSpecialChars;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetCode;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetDomain;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetFile;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetLevel;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetLine;
pub use crate::src::python::libxml2_py::libxml_xmlErrorGetMessage;
pub use crate::src::python::libxml2_py::libxml_xmlFileMatch;
pub use crate::src::python::libxml2_py::libxml_xmlFirstElementChild;
pub use crate::src::python::libxml2_py::libxml_xmlFreeCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlFreeDoc;
pub use crate::src::python::libxml2_py::libxml_xmlFreeDtd;
pub use crate::src::python::libxml2_py::libxml_xmlFreeNode;
pub use crate::src::python::libxml2_py::libxml_xmlFreeNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlFreeNs;
pub use crate::src::python::libxml2_py::libxml_xmlFreeNsList;
pub use crate::src::python::libxml2_py::libxml_xmlFreeParserInputBuffer;
pub use crate::src::python::libxml2_py::libxml_xmlFreeProp;
pub use crate::src::python::libxml2_py::libxml_xmlFreePropList;
pub use crate::src::python::libxml2_py::libxml_xmlFreeURI;
pub use crate::src::python::libxml2_py::libxml_xmlGetCompressMode;
pub use crate::src::python::libxml2_py::libxml_xmlGetDocCompressMode;
pub use crate::src::python::libxml2_py::libxml_xmlGetDocEntity;
pub use crate::src::python::libxml2_py::libxml_xmlGetDtdAttrDesc;
pub use crate::src::python::libxml2_py::libxml_xmlGetDtdElementDesc;
pub use crate::src::python::libxml2_py::libxml_xmlGetDtdEntity;
pub use crate::src::python::libxml2_py::libxml_xmlGetDtdQAttrDesc;
pub use crate::src::python::libxml2_py::libxml_xmlGetDtdQElementDesc;
pub use crate::src::python::libxml2_py::libxml_xmlGetEncodingAlias;
pub use crate::src::python::libxml2_py::libxml_xmlGetID;
pub use crate::src::python::libxml2_py::libxml_xmlGetIntSubset;
pub use crate::src::python::libxml2_py::libxml_xmlGetLastChild;
pub use crate::src::python::libxml2_py::libxml_xmlGetLastError;
pub use crate::src::python::libxml2_py::libxml_xmlGetLineNo;
pub use crate::src::python::libxml2_py::libxml_xmlGetNoNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlGetNodePath;
pub use crate::src::python::libxml2_py::libxml_xmlGetNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlGetParameterEntity;
pub use crate::src::python::libxml2_py::libxml_xmlGetPredefinedEntity;
pub use crate::src::python::libxml2_py::libxml_xmlGetProp;
pub use crate::src::python::libxml2_py::libxml_xmlHandleEntity;
pub use crate::src::python::libxml2_py::libxml_xmlHasNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlHasProp;
pub use crate::src::python::libxml2_py::libxml_xmlIOFTPMatch;
pub use crate::src::python::libxml2_py::libxml_xmlIOHTTPMatch;
pub use crate::src::python::libxml2_py::libxml_xmlInitCharEncodingHandlers;
pub use crate::src::python::libxml2_py::libxml_xmlInitGlobals;
pub use crate::src::python::libxml2_py::libxml_xmlInitParser;
pub use crate::src::python::libxml2_py::libxml_xmlInitParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlInitializeCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlInitializeDict;
pub use crate::src::python::libxml2_py::libxml_xmlInitializePredefinedEntities;
pub use crate::src::python::libxml2_py::libxml_xmlIsBaseChar;
pub use crate::src::python::libxml2_py::libxml_xmlIsBlank;
pub use crate::src::python::libxml2_py::libxml_xmlIsBlankNode;
pub use crate::src::python::libxml2_py::libxml_xmlIsChar;
pub use crate::src::python::libxml2_py::libxml_xmlIsCombining;
pub use crate::src::python::libxml2_py::libxml_xmlIsDigit;
pub use crate::src::python::libxml2_py::libxml_xmlIsExtender;
pub use crate::src::python::libxml2_py::libxml_xmlIsID;
pub use crate::src::python::libxml2_py::libxml_xmlIsIdeographic;
pub use crate::src::python::libxml2_py::libxml_xmlIsLetter;
pub use crate::src::python::libxml2_py::libxml_xmlIsMixedElement;
pub use crate::src::python::libxml2_py::libxml_xmlIsPubidChar;
pub use crate::src::python::libxml2_py::libxml_xmlIsRef;
pub use crate::src::python::libxml2_py::libxml_xmlIsXHTML;
pub use crate::src::python::libxml2_py::libxml_xmlKeepBlanksDefault;
pub use crate::src::python::libxml2_py::libxml_xmlLastElementChild;
pub use crate::src::python::libxml2_py::libxml_xmlLineNumbersDefault;
pub use crate::src::python::libxml2_py::libxml_xmlLoadACatalog;
pub use crate::src::python::libxml2_py::libxml_xmlLoadCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlLoadCatalogs;
pub use crate::src::python::libxml2_py::libxml_xmlLoadSGMLSuperCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlLsCountNode;
pub use crate::src::python::libxml2_py::libxml_xmlLsOneNode;
pub use crate::src::python::libxml2_py::libxml_xmlNamespaceParseNCName;
pub use crate::src::python::libxml2_py::libxml_xmlNamespaceParseNSDef;
pub use crate::src::python::libxml2_py::libxml_xmlNanoFTPCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlNanoFTPInit;
pub use crate::src::python::libxml2_py::libxml_xmlNanoFTPProxy;
pub use crate::src::python::libxml2_py::libxml_xmlNanoFTPScanProxy;
pub use crate::src::python::libxml2_py::libxml_xmlNanoHTTPCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlNanoHTTPInit;
pub use crate::src::python::libxml2_py::libxml_xmlNanoHTTPScanProxy;
pub use crate::src::python::libxml2_py::libxml_xmlNewCDataBlock;
pub use crate::src::python::libxml2_py::libxml_xmlNewCatalog;
pub use crate::src::python::libxml2_py::libxml_xmlNewCharRef;
pub use crate::src::python::libxml2_py::libxml_xmlNewChild;
pub use crate::src::python::libxml2_py::libxml_xmlNewComment;
pub use crate::src::python::libxml2_py::libxml_xmlNewDoc;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocComment;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocFragment;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocNode;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocNodeEatName;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocPI;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocProp;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocRawNode;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocText;
pub use crate::src::python::libxml2_py::libxml_xmlNewDocTextLen;
pub use crate::src::python::libxml2_py::libxml_xmlNewDtd;
pub use crate::src::python::libxml2_py::libxml_xmlNewEntity;
pub use crate::src::python::libxml2_py::libxml_xmlNewGlobalNs;
pub use crate::src::python::libxml2_py::libxml_xmlNewNodeEatName;
pub use crate::src::python::libxml2_py::libxml_xmlNewNs;
pub use crate::src::python::libxml2_py::libxml_xmlNewNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlNewNsPropEatName;
pub use crate::src::python::libxml2_py::libxml_xmlNewPI;
pub use crate::src::python::libxml2_py::libxml_xmlNewParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlNewProp;
pub use crate::src::python::libxml2_py::libxml_xmlNewReference;
pub use crate::src::python::libxml2_py::libxml_xmlNewText;
pub use crate::src::python::libxml2_py::libxml_xmlNewTextChild;
pub use crate::src::python::libxml2_py::libxml_xmlNewTextLen;
pub use crate::src::python::libxml2_py::libxml_xmlNewTextReader;
pub use crate::src::python::libxml2_py::libxml_xmlNewTextReaderFilename;
pub use crate::src::python::libxml2_py::libxml_xmlNewValidCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlNextChar;
pub use crate::src::python::libxml2_py::libxml_xmlNextElementSibling;
pub use crate::src::python::libxml2_py::libxml_xmlNodeAddContent;
pub use crate::src::python::libxml2_py::libxml_xmlNodeAddContentLen;
pub use crate::src::python::libxml2_py::libxml_xmlNodeDumpOutput;
pub use crate::src::python::libxml2_py::libxml_xmlNodeGetBase;
pub use crate::src::python::libxml2_py::libxml_xmlNodeGetContent;
pub use crate::src::python::libxml2_py::libxml_xmlNodeGetLang;
pub use crate::src::python::libxml2_py::libxml_xmlNodeGetSpacePreserve;
pub use crate::src::python::libxml2_py::libxml_xmlNodeIsText;
pub use crate::src::python::libxml2_py::libxml_xmlNodeListGetRawString;
pub use crate::src::python::libxml2_py::libxml_xmlNodeListGetString;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetBase;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetContent;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetContentLen;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetLang;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetName;
pub use crate::src::python::libxml2_py::libxml_xmlNodeSetSpacePreserve;
pub use crate::src::python::libxml2_py::libxml_xmlNormalizeURIPath;
pub use crate::src::python::libxml2_py::libxml_xmlNormalizeWindowsPath;
pub use crate::src::python::libxml2_py::libxml_xmlOutputBufferGetContent;
pub use crate::src::python::libxml2_py::libxml_xmlOutputBufferWrite;
pub use crate::src::python::libxml2_py::libxml_xmlOutputBufferWriteString;
pub use crate::src::python::libxml2_py::libxml_xmlParseAttValue;
pub use crate::src::python::libxml2_py::libxml_xmlParseAttributeListDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseCDSect;
pub use crate::src::python::libxml2_py::libxml_xmlParseCatalogFile;
pub use crate::src::python::libxml2_py::libxml_xmlParseCharData;
pub use crate::src::python::libxml2_py::libxml_xmlParseCharRef;
pub use crate::src::python::libxml2_py::libxml_xmlParseChunk;
pub use crate::src::python::libxml2_py::libxml_xmlParseComment;
pub use crate::src::python::libxml2_py::libxml_xmlParseContent;
pub use crate::src::python::libxml2_py::libxml_xmlParseDTD;
pub use crate::src::python::libxml2_py::libxml_xmlParseDoc;
pub use crate::src::python::libxml2_py::libxml_xmlParseDocTypeDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseDocument;
pub use crate::src::python::libxml2_py::libxml_xmlParseElement;
pub use crate::src::python::libxml2_py::libxml_xmlParseElementDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseEncName;
pub use crate::src::python::libxml2_py::libxml_xmlParseEncodingDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseEndTag;
pub use crate::src::python::libxml2_py::libxml_xmlParseEntity;
pub use crate::src::python::libxml2_py::libxml_xmlParseEntityDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseEntityRef;
pub use crate::src::python::libxml2_py::libxml_xmlParseExtParsedEnt;
pub use crate::src::python::libxml2_py::libxml_xmlParseExternalSubset;
pub use crate::src::python::libxml2_py::libxml_xmlParseFile;
pub use crate::src::python::libxml2_py::libxml_xmlParseMarkupDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseMemory;
pub use crate::src::python::libxml2_py::libxml_xmlParseMisc;
pub use crate::src::python::libxml2_py::libxml_xmlParseName;
pub use crate::src::python::libxml2_py::libxml_xmlParseNamespace;
pub use crate::src::python::libxml2_py::libxml_xmlParseNmtoken;
pub use crate::src::python::libxml2_py::libxml_xmlParseNotationDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParsePEReference;
pub use crate::src::python::libxml2_py::libxml_xmlParsePI;
pub use crate::src::python::libxml2_py::libxml_xmlParsePITarget;
pub use crate::src::python::libxml2_py::libxml_xmlParsePubidLiteral;
pub use crate::src::python::libxml2_py::libxml_xmlParseQuotedString;
pub use crate::src::python::libxml2_py::libxml_xmlParseReference;
pub use crate::src::python::libxml2_py::libxml_xmlParseSDDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseStartTag;
pub use crate::src::python::libxml2_py::libxml_xmlParseSystemLiteral;
pub use crate::src::python::libxml2_py::libxml_xmlParseTextDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParseURI;
pub use crate::src::python::libxml2_py::libxml_xmlParseURIRaw;
pub use crate::src::python::libxml2_py::libxml_xmlParseURIReference;
pub use crate::src::python::libxml2_py::libxml_xmlParseVersionInfo;
pub use crate::src::python::libxml2_py::libxml_xmlParseVersionNum;
pub use crate::src::python::libxml2_py::libxml_xmlParseXMLDecl;
pub use crate::src::python::libxml2_py::libxml_xmlParserGetDirectory;
pub use crate::src::python::libxml2_py::libxml_xmlParserGetDoc;
pub use crate::src::python::libxml2_py::libxml_xmlParserGetIsValid;
pub use crate::src::python::libxml2_py::libxml_xmlParserGetWellFormed;
pub use crate::src::python::libxml2_py::libxml_xmlParserHandlePEReference;
pub use crate::src::python::libxml2_py::libxml_xmlParserHandleReference;
pub use crate::src::python::libxml2_py::libxml_xmlParserInputBufferGrow;
pub use crate::src::python::libxml2_py::libxml_xmlParserInputBufferPush;
pub use crate::src::python::libxml2_py::libxml_xmlParserInputBufferRead;
pub use crate::src::python::libxml2_py::libxml_xmlParserSetLineNumbers;
pub use crate::src::python::libxml2_py::libxml_xmlParserSetLoadSubset;
pub use crate::src::python::libxml2_py::libxml_xmlParserSetPedantic;
pub use crate::src::python::libxml2_py::libxml_xmlParserSetReplaceEntities;
pub use crate::src::python::libxml2_py::libxml_xmlParserSetValidate;
pub use crate::src::python::libxml2_py::libxml_xmlPathToURI;
pub use crate::src::python::libxml2_py::libxml_xmlPedanticParserDefault;
pub use crate::src::python::libxml2_py::libxml_xmlPopInput;
pub use crate::src::python::libxml2_py::libxml_xmlPopOutputCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlPreviousElementSibling;
pub use crate::src::python::libxml2_py::libxml_xmlPrintURI;
pub use crate::src::python::libxml2_py::libxml_xmlReadDoc;
pub use crate::src::python::libxml2_py::libxml_xmlReadFd;
pub use crate::src::python::libxml2_py::libxml_xmlReadFile;
pub use crate::src::python::libxml2_py::libxml_xmlReadMemory;
pub use crate::src::python::libxml2_py::libxml_xmlReaderForDoc;
pub use crate::src::python::libxml2_py::libxml_xmlReaderForFd;
pub use crate::src::python::libxml2_py::libxml_xmlReaderForFile;
pub use crate::src::python::libxml2_py::libxml_xmlReaderForMemory;
pub use crate::src::python::libxml2_py::libxml_xmlReaderNewDoc;
pub use crate::src::python::libxml2_py::libxml_xmlReaderNewFd;
pub use crate::src::python::libxml2_py::libxml_xmlReaderNewFile;
pub use crate::src::python::libxml2_py::libxml_xmlReaderNewMemory;
pub use crate::src::python::libxml2_py::libxml_xmlReaderNewWalker;
pub use crate::src::python::libxml2_py::libxml_xmlReaderWalker;
pub use crate::src::python::libxml2_py::libxml_xmlReconciliateNs;
pub use crate::src::python::libxml2_py::libxml_xmlRecoverDoc;
pub use crate::src::python::libxml2_py::libxml_xmlRecoverFile;
pub use crate::src::python::libxml2_py::libxml_xmlRecoverMemory;
pub use crate::src::python::libxml2_py::libxml_xmlRegFreeRegexp;
pub use crate::src::python::libxml2_py::libxml_xmlRegexpCompile;
pub use crate::src::python::libxml2_py::libxml_xmlRegexpExec;
pub use crate::src::python::libxml2_py::libxml_xmlRegexpIsDeterminist;
pub use crate::src::python::libxml2_py::libxml_xmlRegexpPrint;
pub use crate::src::python::libxml2_py::libxml_xmlRegisterDefaultInputCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlRegisterDefaultOutputCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlRegisterHTTPPostCallbacks;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGCleanupTypes;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGDump;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGDumpTree;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGFree;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGFreeParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGInitTypes;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGNewDocParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGNewMemParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGNewParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGNewValidCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGParse;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGValidateDoc;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGValidateFullElement;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGValidatePopElement;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGValidatePushCData;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxNGValidatePushElement;
pub use crate::src::python::libxml2_py::libxml_xmlRelaxParserSetFlag;
pub use crate::src::python::libxml2_py::libxml_xmlRemoveID;
pub use crate::src::python::libxml2_py::libxml_xmlRemoveProp;
pub use crate::src::python::libxml2_py::libxml_xmlRemoveRef;
pub use crate::src::python::libxml2_py::libxml_xmlReplaceNode;
pub use crate::src::python::libxml2_py::libxml_xmlResetError;
pub use crate::src::python::libxml2_py::libxml_xmlResetLastError;
pub use crate::src::python::libxml2_py::libxml_xmlSAXDefaultVersion;
pub use crate::src::python::libxml2_py::libxml_xmlSaveFile;
pub use crate::src::python::libxml2_py::libxml_xmlSaveFileEnc;
pub use crate::src::python::libxml2_py::libxml_xmlSaveFormatFile;
pub use crate::src::python::libxml2_py::libxml_xmlSaveFormatFileEnc;
pub use crate::src::python::libxml2_py::libxml_xmlSaveUri;
pub use crate::src::python::libxml2_py::libxml_xmlScanName;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaCleanupTypes;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaCollapseString;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaDump;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaFree;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaFreeParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaInitTypes;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaIsValid;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaNewDocParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaNewMemParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaNewParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaNewValidCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaParse;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaSetValidOptions;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidCtxtGetOptions;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidCtxtGetParserCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidateDoc;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidateFile;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidateOneElement;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaValidateSetFilename;
pub use crate::src::python::libxml2_py::libxml_xmlSchemaWhiteSpaceReplace;
pub use crate::src::python::libxml2_py::libxml_xmlSearchNs;
pub use crate::src::python::libxml2_py::libxml_xmlSearchNsByHref;
pub use crate::src::python::libxml2_py::libxml_xmlSetCompressMode;
pub use crate::src::python::libxml2_py::libxml_xmlSetDocCompressMode;
pub use crate::src::python::libxml2_py::libxml_xmlSetListDoc;
pub use crate::src::python::libxml2_py::libxml_xmlSetNs;
pub use crate::src::python::libxml2_py::libxml_xmlSetNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlSetProp;
pub use crate::src::python::libxml2_py::libxml_xmlSetTreeDoc;
pub use crate::src::python::libxml2_py::libxml_xmlSetupParserForBuffer;
pub use crate::src::python::libxml2_py::libxml_xmlShellPrintNode;
pub use crate::src::python::libxml2_py::libxml_xmlShellPrintXPathError;
pub use crate::src::python::libxml2_py::libxml_xmlSkipBlankChars;
pub use crate::src::python::libxml2_py::libxml_xmlStopParser;
pub use crate::src::python::libxml2_py::libxml_xmlStrEqual;
pub use crate::src::python::libxml2_py::libxml_xmlStrQEqual;
pub use crate::src::python::libxml2_py::libxml_xmlStrcasecmp;
pub use crate::src::python::libxml2_py::libxml_xmlStrcasestr;
pub use crate::src::python::libxml2_py::libxml_xmlStrcat;
pub use crate::src::python::libxml2_py::libxml_xmlStrchr;
pub use crate::src::python::libxml2_py::libxml_xmlStrcmp;
pub use crate::src::python::libxml2_py::libxml_xmlStrdup;
pub use crate::src::python::libxml2_py::libxml_xmlStringDecodeEntities;
pub use crate::src::python::libxml2_py::libxml_xmlStringGetNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlStringLenDecodeEntities;
pub use crate::src::python::libxml2_py::libxml_xmlStringLenGetNodeList;
pub use crate::src::python::libxml2_py::libxml_xmlStrlen;
pub use crate::src::python::libxml2_py::libxml_xmlStrncasecmp;
pub use crate::src::python::libxml2_py::libxml_xmlStrncat;
pub use crate::src::python::libxml2_py::libxml_xmlStrncatNew;
pub use crate::src::python::libxml2_py::libxml_xmlStrncmp;
pub use crate::src::python::libxml2_py::libxml_xmlStrndup;
pub use crate::src::python::libxml2_py::libxml_xmlStrstr;
pub use crate::src::python::libxml2_py::libxml_xmlStrsub;
pub use crate::src::python::libxml2_py::libxml_xmlSubstituteEntitiesDefault;
pub use crate::src::python::libxml2_py::libxml_xmlTextConcat;
pub use crate::src::python::libxml2_py::libxml_xmlTextMerge;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderAttributeCount;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderByteConsumed;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderClose;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstBaseUri;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstEncoding;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstLocalName;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstName;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstNamespaceUri;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstPrefix;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstString;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstValue;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstXmlLang;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderConstXmlVersion;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderCurrentDoc;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderCurrentNode;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderDepth;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderExpand;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetAttributeNo;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetAttributeNs;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetParserColumnNumber;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetParserLineNumber;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetParserProp;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderGetRemainder;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderHasAttributes;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderHasValue;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderIsDefault;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderIsEmptyElement;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderIsNamespaceDecl;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderIsValid;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderLocatorBaseURI;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderLocatorLineNumber;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderLookupNamespace;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToAttributeNo;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToAttributeNs;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToElement;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToFirstAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderMoveToNextAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderNext;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderNextSibling;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderNodeType;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderNormalization;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderPreserve;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderQuoteChar;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderRead;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderReadAttributeValue;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderReadInnerXml;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderReadOuterXml;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderReadState;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderReadString;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderRelaxNGSetSchema;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderRelaxNGValidate;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderRelaxNGValidateCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderSchemaValidate;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderSchemaValidateCtxt;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderSetParserProp;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderSetSchema;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderSetup;
pub use crate::src::python::libxml2_py::libxml_xmlTextReaderStandalone;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefDefaultBufferSize;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefDoValidityCheckingDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefGetWarningsDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefIndentTreeOutput;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefKeepBlanksDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefLineNumbersDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefLoadExtDtdDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefParserDebugEntities;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefPedanticParserDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefSaveNoEmptyTags;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefSubstituteEntitiesDefaultValue;
pub use crate::src::python::libxml2_py::libxml_xmlThrDefTreeIndentString;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsAegeanNumbers;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsAlphabeticPresentationForms;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsArabic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsArabicPresentationFormsA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsArabicPresentationFormsB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsArmenian;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsArrows;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBasicLatin;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBengali;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBlock;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBlockElements;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBopomofo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBopomofoExtended;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBoxDrawing;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBraillePatterns;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsBuhid;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsByzantineMusicalSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKCompatibility;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKCompatibilityForms;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKCompatibilityIdeographs;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKCompatibilityIdeographsSupplement;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKRadicalsSupplement;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKSymbolsandPunctuation;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKUnifiedIdeographs;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKUnifiedIdeographsExtensionA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCJKUnifiedIdeographsExtensionB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCat;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatC;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatCc;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatCf;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatCo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatCs;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatL;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatLl;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatLm;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatLo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatLt;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatLu;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatM;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatMc;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatMe;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatMn;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatN;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatNd;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatNl;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatNo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatP;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPc;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPd;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPe;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPf;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPi;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatPs;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatS;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatSc;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatSk;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatSm;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatSo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatZ;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatZl;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatZp;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCatZs;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCherokee;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCombiningDiacriticalMarks;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCombiningDiacriticalMarksforSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCombiningHalfMarks;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCombiningMarksforSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsControlPictures;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCurrencySymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCypriotSyllabary;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCyrillic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsCyrillicSupplement;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsDeseret;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsDevanagari;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsDingbats;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsEnclosedAlphanumerics;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsEnclosedCJKLettersandMonths;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsEthiopic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGeneralPunctuation;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGeometricShapes;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGeorgian;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGothic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGreek;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGreekExtended;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGreekandCoptic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGujarati;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsGurmukhi;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHalfwidthandFullwidthForms;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHangulCompatibilityJamo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHangulJamo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHangulSyllables;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHanunoo;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHebrew;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHighPrivateUseSurrogates;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHighSurrogates;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsHiragana;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsIPAExtensions;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsIdeographicDescriptionCharacters;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKanbun;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKangxiRadicals;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKannada;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKatakana;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKatakanaPhoneticExtensions;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKhmer;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsKhmerSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLao;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLatin1Supplement;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLatinExtendedA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLatinExtendedAdditional;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLatinExtendedB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLetterlikeSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLimbu;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLinearBIdeograms;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLinearBSyllabary;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsLowSurrogates;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMalayalam;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMathematicalAlphanumericSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMathematicalOperators;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMiscellaneousMathematicalSymbolsA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMiscellaneousMathematicalSymbolsB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMiscellaneousSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMiscellaneousSymbolsandArrows;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMiscellaneousTechnical;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMongolian;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMusicalSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsMyanmar;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsNumberForms;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsOgham;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsOldItalic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsOpticalCharacterRecognition;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsOriya;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsOsmanya;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsPhoneticExtensions;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsPrivateUse;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsPrivateUseArea;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsRunic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsShavian;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSinhala;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSmallFormVariants;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSpacingModifierLetters;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSpecials;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSuperscriptsandSubscripts;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSupplementalArrowsA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSupplementalArrowsB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSupplementalMathematicalOperators;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSupplementaryPrivateUseAreaA;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSupplementaryPrivateUseAreaB;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsSyriac;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTagalog;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTagbanwa;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTags;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTaiLe;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTaiXuanJingSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTamil;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTelugu;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsThaana;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsThai;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsTibetan;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsUgaritic;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsUnifiedCanadianAboriginalSyllabics;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsVariationSelectors;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsVariationSelectorsSupplement;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsYiRadicals;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsYiSyllables;
pub use crate::src::python::libxml2_py::libxml_xmlUCSIsYijingHexagramSymbols;
pub use crate::src::python::libxml2_py::libxml_xmlURIEscape;
pub use crate::src::python::libxml2_py::libxml_xmlURIEscapeStr;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetAuthority;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetFragment;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetOpaque;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetPath;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetPort;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetQuery;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetQueryRaw;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetScheme;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetServer;
pub use crate::src::python::libxml2_py::libxml_xmlURIGetUser;
pub use crate::src::python::libxml2_py::libxml_xmlURISetAuthority;
pub use crate::src::python::libxml2_py::libxml_xmlURISetFragment;
pub use crate::src::python::libxml2_py::libxml_xmlURISetOpaque;
pub use crate::src::python::libxml2_py::libxml_xmlURISetPath;
pub use crate::src::python::libxml2_py::libxml_xmlURISetPort;
pub use crate::src::python::libxml2_py::libxml_xmlURISetQuery;
pub use crate::src::python::libxml2_py::libxml_xmlURISetQueryRaw;
pub use crate::src::python::libxml2_py::libxml_xmlURISetScheme;
pub use crate::src::python::libxml2_py::libxml_xmlURISetServer;
pub use crate::src::python::libxml2_py::libxml_xmlURISetUser;
pub use crate::src::python::libxml2_py::libxml_xmlURIUnescapeString;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Charcmp;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Size;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strlen;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strloc;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strndup;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strpos;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strsize;
pub use crate::src::python::libxml2_py::libxml_xmlUTF8Strsub;
pub use crate::src::python::libxml2_py::libxml_xmlUnlinkNode;
pub use crate::src::python::libxml2_py::libxml_xmlUnsetNsProp;
pub use crate::src::python::libxml2_py::libxml_xmlUnsetProp;
pub use crate::src::python::libxml2_py::libxml_xmlValidCtxtNormalizeAttributeValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidNormalizeAttributeValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidateDocument;
pub use crate::src::python::libxml2_py::libxml_xmlValidateDocumentFinal;
pub use crate::src::python::libxml2_py::libxml_xmlValidateDtd;
pub use crate::src::python::libxml2_py::libxml_xmlValidateDtdFinal;
pub use crate::src::python::libxml2_py::libxml_xmlValidateElement;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNCName;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNMToken;
pub use crate::src::python::libxml2_py::libxml_xmlValidateName;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNameValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNamesValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNmtokenValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNmtokensValue;
pub use crate::src::python::libxml2_py::libxml_xmlValidateNotationUse;
pub use crate::src::python::libxml2_py::libxml_xmlValidateOneAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlValidateOneElement;
pub use crate::src::python::libxml2_py::libxml_xmlValidateOneNamespace;
pub use crate::src::python::libxml2_py::libxml_xmlValidatePopElement;
pub use crate::src::python::libxml2_py::libxml_xmlValidatePushCData;
pub use crate::src::python::libxml2_py::libxml_xmlValidatePushElement;
pub use crate::src::python::libxml2_py::libxml_xmlValidateQName;
pub use crate::src::python::libxml2_py::libxml_xmlValidateRoot;
pub use crate::src::python::libxml2_py::libxml_xmlXIncludeProcess;
pub use crate::src::python::libxml2_py::libxml_xmlXIncludeProcessFlags;
pub use crate::src::python::libxml2_py::libxml_xmlXIncludeProcessTree;
pub use crate::src::python::libxml2_py::libxml_xmlXIncludeProcessTreeFlags;
pub use crate::src::python::libxml2_py::libxml_xmlXPathAddValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathBooleanFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastBooleanToNumber;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastBooleanToString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastNodeToNumber;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastNodeToString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastNumberToBoolean;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastNumberToString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastStringToBoolean;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCastStringToNumber;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCeilingFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCmpNodes;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCompareValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathConcatFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathContainsFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathContextSetCache;
pub use crate::src::python::libxml2_py::libxml_xmlXPathCountFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathDivValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathEqualValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathErr;
pub use crate::src::python::libxml2_py::libxml_xmlXPathEval;
pub use crate::src::python::libxml2_py::libxml_xmlXPathEvalExpr;
pub use crate::src::python::libxml2_py::libxml_xmlXPathEvalExpression;
pub use crate::src::python::libxml2_py::libxml_xmlXPathFalseFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathFloorFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathFreeContext;
pub use crate::src::python::libxml2_py::libxml_xmlXPathFreeParserContext;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetContextDoc;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetContextNode;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetContextPosition;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetContextSize;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathGetFunctionURI;
pub use crate::src::python::libxml2_py::libxml_xmlXPathIdFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathInit;
pub use crate::src::python::libxml2_py::libxml_xmlXPathIsInf;
pub use crate::src::python::libxml2_py::libxml_xmlXPathIsNaN;
pub use crate::src::python::libxml2_py::libxml_xmlXPathIsNodeType;
pub use crate::src::python::libxml2_py::libxml_xmlXPathLangFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathLastFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathLocalNameFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathModValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathMultValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNamespaceURIFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewBoolean;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewCString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewContext;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewFloat;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewNodeSet;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewParserContext;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNewValueTree;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextAncestor;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextAncestorOrSelf;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextAttribute;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextChild;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextDescendant;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextDescendantOrSelf;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextFollowing;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextFollowingSibling;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextNamespace;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextParent;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextPreceding;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextPrecedingSibling;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNextSelf;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNodeEval;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNodeSetFreeNs;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNormalizeFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNotEqualValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNotFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNsLookup;
pub use crate::src::python::libxml2_py::libxml_xmlXPathNumberFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathOrderDocElems;
pub use crate::src::python::libxml2_py::libxml_xmlXPathParseNCName;
pub use crate::src::python::libxml2_py::libxml_xmlXPathParseName;
pub use crate::src::python::libxml2_py::libxml_xmlXPathParserGetContext;
pub use crate::src::python::libxml2_py::libxml_xmlXPathPopBoolean;
pub use crate::src::python::libxml2_py::libxml_xmlXPathPopNumber;
pub use crate::src::python::libxml2_py::libxml_xmlXPathPopString;
pub use crate::src::python::libxml2_py::libxml_xmlXPathPositionFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRegisterAllFunctions;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRegisterNs;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRegisteredFuncsCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRegisteredNsCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRegisteredVariablesCleanup;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRoot;
pub use crate::src::python::libxml2_py::libxml_xmlXPathRoundFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSetContextDoc;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSetContextNode;
pub use crate::src::python::libxml2_py::libxml_xmlXPathStartsWithFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathStringEvalNumber;
pub use crate::src::python::libxml2_py::libxml_xmlXPathStringFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathStringLengthFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSubValues;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSubstringAfterFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSubstringBeforeFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSubstringFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathSumFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathTranslateFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathTrueFunction;
pub use crate::src::python::libxml2_py::libxml_xmlXPathValueFlipSign;
pub use crate::src::python::libxml2_py::libxml_xmlXPathVariableLookup;
pub use crate::src::python::libxml2_py::libxml_xmlXPathVariableLookupNS;
pub use crate::src::python::libxml2_py::libxml_xmlXPatherror;
pub use crate::src::python::libxml2_py::libxml_xmlXPtrEval;
pub use crate::src::python::libxml2_py::libxml_xmlXPtrNewContext;
pub use crate::src::python::types::libxml_charPtrConstWrap;
pub use crate::src::python::types::libxml_charPtrWrap;
pub use crate::src::python::types::libxml_constxmlCharPtrWrap;
pub use crate::src::python::types::libxml_intWrap;
pub use crate::src::python::types::libxml_longWrap;
pub use crate::src::python::types::libxml_xmlAttrPtrWrap;
pub use crate::src::python::types::libxml_xmlDocPtrWrap;
pub use crate::src::python::types::libxml_xmlNodePtrWrap;
pub use crate::src::python::types::libxml_xmlNsPtrWrap;
pub use crate::src::python::types::libxml_xmlOutputBufferPtrWrap;
pub use crate::src::python::types::libxml_xmlParserCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlParserInputBufferPtrWrap;
pub use crate::src::python::types::libxml_xmlTextReaderLocatorPtrWrap;
pub use crate::src::python::types::libxml_xmlXPathObjectPtrConvert;
pub use crate::src::python::types::libxml_xmlXPathObjectPtrWrap;
pub use crate::src::python::types::libxml_xmlXPathParserContextPtrWrap;
pub use crate::src::relaxng::xmlRelaxNGFreeValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGGetValidErrors;
pub use crate::src::relaxng::xmlRelaxNGSetValidErrors;
pub use crate::src::tree::xmlBufferCreate;
pub use crate::src::tree::xmlBufferFree;
pub use crate::src::tree::xmlNewNode;
pub use crate::src::valid::xmlFreeValidCtxt;
pub use crate::src::xmlIO::xmlAllocOutputBuffer;
pub use crate::src::xmlIO::xmlAllocParserInputBuffer;
pub use crate::src::xmlIO::xmlGetExternalEntityLoader;
pub use crate::src::xmlIO::xmlOutputBufferClose;
pub use crate::src::xmlIO::xmlOutputBufferCreateFile;
pub use crate::src::xmlIO::xmlOutputBufferFlush;
pub use crate::src::xmlIO::xmlParserGetDirectory;
pub use crate::src::xmlIO::xmlPopInputCallbacks;
pub use crate::src::xmlIO::xmlRegisterInputCallbacks;
pub use crate::src::xmlIO::xmlSetExternalEntityLoader;
pub use crate::src::xmlmemory::xmlMemFree;
pub use crate::src::xmlmemory::xmlMemGet;
pub use crate::src::xmlmemory::xmlMemMalloc;
pub use crate::src::xmlmemory::xmlMemRealloc;
pub use crate::src::xmlmemory::xmlMemSetup;
pub use crate::src::xmlmemory::xmlMemUsed;
pub use crate::src::xmlmemory::xmlMemoryDump;
pub use crate::src::xmlmemory::xmlMemoryStrdup;
pub use crate::src::xmlreader::xmlFreeTextReader;
pub use crate::src::xmlreader::xmlTextReaderGetErrorHandler;
pub use crate::src::xmlreader::xmlTextReaderSetErrorHandler;
pub use crate::src::xmlsave::xmlNodeDumpOutput;
pub use crate::src::xmlsave::xmlSaveClose;
pub use crate::src::xmlsave::xmlSaveDoc;
pub use crate::src::xmlsave::xmlSaveFileTo;
pub use crate::src::xmlsave::xmlSaveFormatFileTo;
pub use crate::src::xmlsave::xmlSaveToBuffer;
pub use crate::src::xmlsave::xmlSaveTree;
pub use crate::src::xmlschemas::xmlSchemaFreeValidCtxt;
pub use crate::src::xmlschemas::xmlSchemaGetValidErrors;
pub use crate::src::xmlschemas::xmlSchemaSetValidErrors;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xpath::valuePop;
pub use crate::src::xpath::valuePush;
pub use crate::src::xpath::xmlXPathRegisterFuncLookup;
pub use crate::src::xpath::xmlXPathRegisterVariableNS;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
pub use crate::src::relaxng::_xmlRelaxNGValidCtxt;
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmlreader::_xmlTextReader;
pub use crate::src::xmlregexp::_xmlAutomata;
pub use crate::src::xmlregexp::_xmlAutomataState;
pub use crate::src::xmlsave::_xmlSaveCtxt;
pub use crate::src::xmlschemas::_xmlSchemaValidCtxt;
pub use crate::src::xpath::_xmlXPathCompExpr;
pub use crate::src::error::__builtin_va_list;
// #[derive(Copy, Clone)]

pub use crate::src::error::__va_list_tag;
pub use crate::src::HTMLparser::size_t;
pub use crate::src::error::va_list;
pub use crate::src::HTMLtree::__off_t;
pub use crate::src::HTMLtree::__off64_t;
pub use crate::src::catalog::__ssize_t;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_IO_FILE;
pub use crate::src::HTMLtree::_IO_lock_t;
pub use crate::src::HTMLtree::FILE;
pub use crate::src::catalog::ssize_t;
pub type Py_ssize_t = ssize_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _typeobject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
    pub tp_name: *const libc::c_char,
    pub tp_basicsize: Py_ssize_t,
    pub tp_itemsize: Py_ssize_t,
    pub tp_dealloc: destructor,
    pub tp_print: printfunc,
    pub tp_getattr: getattrfunc,
    pub tp_setattr: setattrfunc,
    pub tp_compare: cmpfunc,
    pub tp_repr: reprfunc,
    pub tp_as_number: *mut PyNumberMethods,
    pub tp_as_sequence: *mut PySequenceMethods,
    pub tp_as_mapping: *mut PyMappingMethods,
    pub tp_hash: hashfunc,
    pub tp_call: ternaryfunc,
    pub tp_str: reprfunc,
    pub tp_getattro: getattrofunc,
    pub tp_setattro: setattrofunc,
    pub tp_as_buffer: *mut PyBufferProcs,
    pub tp_flags: libc::c_long,
    pub tp_doc: *const libc::c_char,
    pub tp_traverse: traverseproc,
    pub tp_clear: inquiry,
    pub tp_richcompare: richcmpfunc,
    pub tp_weaklistoffset: Py_ssize_t,
    pub tp_iter: getiterfunc,
    pub tp_iternext: iternextfunc,
    pub tp_methods: *mut PyMethodDef,
    pub tp_members: *mut PyMemberDef,
    pub tp_getset: *mut PyGetSetDef,
    pub tp_base: *mut _typeobject,
    pub tp_dict: *mut PyObject,
    pub tp_descr_get: descrgetfunc,
    pub tp_descr_set: descrsetfunc,
    pub tp_dictoffset: Py_ssize_t,
    pub tp_init: initproc,
    pub tp_alloc: allocfunc,
    pub tp_new: newfunc,
    pub tp_free: freefunc,
    pub tp_is_gc: inquiry,
    pub tp_bases: *mut PyObject,
    pub tp_mro: *mut PyObject,
    pub tp_cache: *mut PyObject,
    pub tp_subclasses: *mut PyObject,
    pub tp_weaklist: *mut PyObject,
    pub tp_del: destructor,
    pub tp_version_tag: libc::c_uint,
}
pub type destructor = Option::<unsafe extern "C" fn(*mut PyObject) -> ()>;
pub type PyObject = _object;
pub type inquiry = Option::<unsafe extern "C" fn(*mut PyObject) -> libc::c_int>;
pub type freefunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type newfunc = Option::<
    unsafe extern "C" fn(*mut _typeobject, *mut PyObject, *mut PyObject) -> *mut PyObject,
>;
pub type allocfunc = Option::<
    unsafe extern "C" fn(*mut _typeobject, Py_ssize_t) -> *mut PyObject,
>;
pub type initproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type descrsetfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type descrgetfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyGetSetDef {
    pub name: *mut libc::c_char,
    pub get: getter,
    pub set: setter,
    pub doc: *mut libc::c_char,
    pub closure: *mut libc::c_void,
}
pub type setter = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut libc::c_void) -> libc::c_int,
>;
pub type getter = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut libc::c_void) -> *mut PyObject,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyMethodDef {
    pub ml_name: *const libc::c_char,
    pub ml_meth: PyCFunction,
    pub ml_flags: libc::c_int,
    pub ml_doc: *const libc::c_char,
}
pub type PyCFunction = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject,
>;
pub type iternextfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type getiterfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type richcmpfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, libc::c_int) -> *mut PyObject,
>;
pub type traverseproc = Option::<
    unsafe extern "C" fn(*mut PyObject, visitproc, *mut libc::c_void) -> libc::c_int,
>;
pub type visitproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut libc::c_void) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyBufferProcs {
    pub bf_getreadbuffer: readbufferproc,
    pub bf_getwritebuffer: writebufferproc,
    pub bf_getsegcount: segcountproc,
    pub bf_getcharbuffer: charbufferproc,
    pub bf_getbuffer: getbufferproc,
    pub bf_releasebuffer: releasebufferproc,
}
pub type releasebufferproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut Py_buffer) -> (),
>;
pub type Py_buffer = bufferinfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bufferinfo {
    pub buf: *mut libc::c_void,
    pub obj: *mut PyObject,
    pub len: Py_ssize_t,
    pub itemsize: Py_ssize_t,
    pub readonly: libc::c_int,
    pub ndim: libc::c_int,
    pub format: *mut libc::c_char,
    pub shape: *mut Py_ssize_t,
    pub strides: *mut Py_ssize_t,
    pub suboffsets: *mut Py_ssize_t,
    pub smalltable: [Py_ssize_t; 2],
    pub internal: *mut libc::c_void,
}
pub type getbufferproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut Py_buffer, libc::c_int) -> libc::c_int,
>;
pub type charbufferproc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut libc::c_char) -> Py_ssize_t,
>;
pub type segcountproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut Py_ssize_t) -> Py_ssize_t,
>;
pub type writebufferproc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut libc::c_void) -> Py_ssize_t,
>;
pub type readbufferproc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut libc::c_void) -> Py_ssize_t,
>;
pub type setattrofunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type getattrofunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject,
>;
pub type reprfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type ternaryfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject,
>;
pub type hashfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> libc::c_long>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyMappingMethods {
    pub mp_length: lenfunc,
    pub mp_subscript: binaryfunc,
    pub mp_ass_subscript: objobjargproc,
}
pub type objobjargproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type binaryfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject,
>;
pub type lenfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> Py_ssize_t>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PySequenceMethods {
    pub sq_length: lenfunc,
    pub sq_concat: binaryfunc,
    pub sq_repeat: ssizeargfunc,
    pub sq_item: ssizeargfunc,
    pub sq_slice: ssizessizeargfunc,
    pub sq_ass_item: ssizeobjargproc,
    pub sq_ass_slice: ssizessizeobjargproc,
    pub sq_contains: objobjproc,
    pub sq_inplace_concat: binaryfunc,
    pub sq_inplace_repeat: ssizeargfunc,
}
pub type ssizeargfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t) -> *mut PyObject,
>;
pub type objobjproc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type ssizessizeobjargproc = Option::<
    unsafe extern "C" fn(
        *mut PyObject,
        Py_ssize_t,
        Py_ssize_t,
        *mut PyObject,
    ) -> libc::c_int,
>;
pub type ssizeobjargproc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut PyObject) -> libc::c_int,
>;
pub type ssizessizeargfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, Py_ssize_t, Py_ssize_t) -> *mut PyObject,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyNumberMethods {
    pub nb_add: binaryfunc,
    pub nb_subtract: binaryfunc,
    pub nb_multiply: binaryfunc,
    pub nb_divide: binaryfunc,
    pub nb_remainder: binaryfunc,
    pub nb_divmod: binaryfunc,
    pub nb_power: ternaryfunc,
    pub nb_negative: unaryfunc,
    pub nb_positive: unaryfunc,
    pub nb_absolute: unaryfunc,
    pub nb_nonzero: inquiry,
    pub nb_invert: unaryfunc,
    pub nb_lshift: binaryfunc,
    pub nb_rshift: binaryfunc,
    pub nb_and: binaryfunc,
    pub nb_xor: binaryfunc,
    pub nb_or: binaryfunc,
    pub nb_coerce: coercion,
    pub nb_int: unaryfunc,
    pub nb_long: unaryfunc,
    pub nb_float: unaryfunc,
    pub nb_oct: unaryfunc,
    pub nb_hex: unaryfunc,
    pub nb_inplace_add: binaryfunc,
    pub nb_inplace_subtract: binaryfunc,
    pub nb_inplace_multiply: binaryfunc,
    pub nb_inplace_divide: binaryfunc,
    pub nb_inplace_remainder: binaryfunc,
    pub nb_inplace_power: ternaryfunc,
    pub nb_inplace_lshift: binaryfunc,
    pub nb_inplace_rshift: binaryfunc,
    pub nb_inplace_and: binaryfunc,
    pub nb_inplace_xor: binaryfunc,
    pub nb_inplace_or: binaryfunc,
    pub nb_floor_divide: binaryfunc,
    pub nb_true_divide: binaryfunc,
    pub nb_inplace_floor_divide: binaryfunc,
    pub nb_inplace_true_divide: binaryfunc,
    pub nb_index: unaryfunc,
}
pub type unaryfunc = Option::<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type coercion = Option::<
    unsafe extern "C" fn(*mut *mut PyObject, *mut *mut PyObject) -> libc::c_int,
>;
pub type cmpfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> libc::c_int,
>;
pub type setattrfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut libc::c_char, *mut PyObject) -> libc::c_int,
>;
pub type getattrfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut libc::c_char) -> *mut PyObject,
>;
pub type printfunc = Option::<
    unsafe extern "C" fn(*mut PyObject, *mut FILE, libc::c_int) -> libc::c_int,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyVarObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
}
pub type PyTypeObject = _typeobject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyTupleObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
    pub ob_item: [*mut PyObject; 1],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyListObject {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub ob_size: Py_ssize_t,
    pub ob_item: *mut *mut PyObject,
    pub allocated: Py_ssize_t,
}
pub use crate::src::HTMLparser::xmlFreeFunc;
pub use crate::src::HTMLparser::xmlMallocFunc;
pub use crate::src::HTMLparser::xmlReallocFunc;
pub use crate::src::encoding::xmlStrdupFunc;
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
pub use crate::src::HTMLparser::xmlSAXHandler;
pub use crate::src::HTMLparser::xmlSAXHandlerPtr;
pub use crate::src::HTMLtree::xmlBufferAllocationScheme;
pub const XML_BUFFER_ALLOC_BOUNDED: xmlBufferAllocationScheme = 5;
pub const XML_BUFFER_ALLOC_HYBRID: xmlBufferAllocationScheme = 4;
pub const XML_BUFFER_ALLOC_IO: xmlBufferAllocationScheme = 3;
pub const XML_BUFFER_ALLOC_IMMUTABLE: xmlBufferAllocationScheme = 2;
pub const XML_BUFFER_ALLOC_EXACT: xmlBufferAllocationScheme = 1;
pub const XML_BUFFER_ALLOC_DOUBLEIT: xmlBufferAllocationScheme = 0;
// #[derive(Copy, Clone)]

pub use crate::src::HTMLtree::_xmlBuffer;
pub use crate::src::HTMLtree::xmlBuffer;
pub use crate::src::HTMLtree::xmlBufferPtr;
pub use crate::src::HTMLtree::xmlNsPtr;
pub use crate::src::HTMLparser::xmlGenericErrorFunc;
pub use crate::src::SAX2::xmlValidCtxtPtr;
pub type xmlExternalEntityLoader = Option::<
    unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        xmlParserCtxtPtr,
    ) -> xmlParserInputPtr,
>;
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
pub type xmlInputMatchCallback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> libc::c_int,
>;
pub type xmlInputOpenCallback = Option::<
    unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void,
>;
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
pub use crate::src::debugXML::xmlRelaxNGValidityErrorFunc;
pub use crate::src::debugXML::xmlRelaxNGValidityWarningFunc;
pub use crate::src::debugXML::xmlRelaxNGValidCtxt;
pub use crate::src::debugXML::xmlRelaxNGValidCtxtPtr;
pub type xmlSchemaValidityErrorFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlSchemaValidityWarningFunc = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
>;
pub type xmlSchemaValidCtxt = _xmlSchemaValidCtxt;
pub type xmlSchemaValidCtxtPtr = *mut xmlSchemaValidCtxt;
pub type xmlParserSeverities = libc::c_uint;
pub const XML_PARSER_SEVERITY_ERROR: xmlParserSeverities = 4;
pub const XML_PARSER_SEVERITY_WARNING: xmlParserSeverities = 3;
pub const XML_PARSER_SEVERITY_VALIDITY_ERROR: xmlParserSeverities = 2;
pub const XML_PARSER_SEVERITY_VALIDITY_WARNING: xmlParserSeverities = 1;
pub type xmlTextReader = _xmlTextReader;
pub type xmlTextReaderPtr = *mut xmlTextReader;
pub type xmlTextReaderLocatorPtr = *mut libc::c_void;
pub type xmlTextReaderErrorFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        xmlParserSeverities,
        xmlTextReaderLocatorPtr,
    ) -> (),
>;
pub type C2RustUnnamed = libc::c_uint;
pub const XML_SAVE_WSNONSIG: C2RustUnnamed = 128;
pub const XML_SAVE_AS_HTML: C2RustUnnamed = 64;
pub const XML_SAVE_AS_XML: C2RustUnnamed = 32;
pub const XML_SAVE_XHTML: C2RustUnnamed = 16;
pub const XML_SAVE_NO_XHTML: C2RustUnnamed = 8;
pub const XML_SAVE_NO_EMPTY: C2RustUnnamed = 4;
pub const XML_SAVE_NO_DECL: C2RustUnnamed = 2;
pub const XML_SAVE_FORMAT: C2RustUnnamed = 1;
pub type xmlSaveCtxt = _xmlSaveCtxt;
pub type xmlSaveCtxtPtr = *mut xmlSaveCtxt;
pub use crate::src::HTMLparser::htmlParserCtxtPtr;
pub use crate::src::HTMLparser::htmlSAXHandlerPtr;
pub use crate::src::HTMLparser::htmlDocPtr;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlNode_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlNodePtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlXPathContext_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlXPathContextPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyparserCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlParserCtxtPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyValidCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlValidCtxtPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlTextReader_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlTextReaderPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyoutputBuffer_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlOutputBufferPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyrelaxNgValidCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlRelaxNGValidCtxtPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PySchemaValidCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlSchemaValidCtxtPtr,
}
pub type xmlSchemaValidCtxtPyCtxtPtr = *mut xmlSchemaValidCtxtPyCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlSchemaValidCtxtPyCtxt {
    pub warn: *mut PyObject,
    pub error: *mut PyObject,
    pub arg: *mut PyObject,
}
pub type libxml_xpathCallbackArray = [libxml_xpathCallback; 0];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct libxml_xpathCallback {
    pub ctx: xmlXPathContextPtr,
    pub name: *mut xmlChar,
    pub ns_uri: *mut xmlChar,
    pub function: *mut PyObject,
}
pub type xmlRelaxNGValidCtxtPyCtxtPtr = *mut xmlRelaxNGValidCtxtPyCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlRelaxNGValidCtxtPyCtxt {
    pub warn: *mut PyObject,
    pub error: *mut PyObject,
    pub arg: *mut PyObject,
}
pub type xmlTextReaderPyCtxtPtr = *mut xmlTextReaderPyCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlTextReaderPyCtxt {
    pub f: *mut PyObject,
    pub arg: *mut PyObject,
}
pub type xmlParserCtxtPyCtxtPtr = *mut xmlParserCtxtPyCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlParserCtxtPyCtxt {
    pub f: *mut PyObject,
    pub arg: *mut PyObject,
}
pub type xmlValidCtxtPyCtxtPtr = *mut xmlValidCtxtPyCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct xmlValidCtxtPyCtxt {
    pub warn: *mut PyObject,
    pub error: *mut PyObject,
    pub arg: *mut PyObject,
}
static mut libxml_xpathCallbacksInitialized: libc::c_int = 0 as libc::c_int;
static mut libxml_xpathCallbacksAllocd: libc::c_int = 10 as libc::c_int;
static mut libxml_xpathCallbacks: *mut libxml_xpathCallbackArray = 0
    as *const libxml_xpathCallbackArray as *mut libxml_xpathCallbackArray;
static mut libxml_xpathCallbacksNb: libc::c_int = 0 as libc::c_int;
static mut libxmlMemoryDebugActivated: libc::c_int = 0 as libc::c_int;
static mut libxmlMemoryAllocatedBase: libc::c_long = 0 as libc::c_int as libc::c_long;
static mut libxmlMemoryDebug: libc::c_int = 0 as libc::c_int;
static mut freeFunc: xmlFreeFunc = None;
static mut mallocFunc: xmlMallocFunc = None;
static mut reallocFunc: xmlReallocFunc = None;
static mut strdupFunc: xmlStrdupFunc = None;
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlMemoryUsed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ret: libc::c_long = 0;
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    ret = xmlMemUsed() as libc::c_long;
    py_retval = libxml_longWrap(ret);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut current_block: u64;
    let mut activate: libc::c_int = 0;
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut ret: libc::c_long = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlDebugMemory\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut activate as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if activate != 0 as libc::c_int {
        if libxmlMemoryDebug == 0 as libc::c_int {
            xmlMemGet(
                &mut freeFunc as *mut xmlFreeFunc,
                &mut mallocFunc as *mut xmlMallocFunc,
                &mut reallocFunc as *mut xmlReallocFunc,
                &mut strdupFunc as *mut xmlStrdupFunc,
            );
            if freeFunc
                == Some(xmlMemFree as unsafe extern "C" fn(*mut libc::c_void) -> ())
                && mallocFunc
                    == Some(
                        xmlMemMalloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
                    )
                && reallocFunc
                    == Some(
                        xmlMemRealloc
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                size_t,
                            ) -> *mut libc::c_void,
                    )
                && strdupFunc
                    == Some(
                        xmlMemoryStrdup
                            as unsafe extern "C" fn(
                                *const libc::c_char,
                            ) -> *mut libc::c_char,
                    )
            {
                libxmlMemoryAllocatedBase = xmlMemUsed() as libc::c_long;
                current_block = 10048703153582371463;
            } else {
                xmlCleanupParser();
                ret = xmlMemSetup(
                    Some(xmlMemFree as unsafe extern "C" fn(*mut libc::c_void) -> ()),
                    Some(
                        xmlMemMalloc as unsafe extern "C" fn(size_t) -> *mut libc::c_void,
                    ),
                    Some(
                        xmlMemRealloc
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                size_t,
                            ) -> *mut libc::c_void,
                    ),
                    Some(
                        xmlMemoryStrdup
                            as unsafe extern "C" fn(
                                *const libc::c_char,
                            ) -> *mut libc::c_char,
                    ),
                ) as libc::c_long;
                if ret < 0 as libc::c_int as libc::c_long {
                    current_block = 15224037586932921579;
                } else {
                    libxmlMemoryAllocatedBase = xmlMemUsed() as libc::c_long;
                    xmlInitParser();
                    libxml_xmlErrorInitialize();
                    current_block = 10048703153582371463;
                }
            }
            match current_block {
                15224037586932921579 => {}
                _ => {
                    ret = 0 as libc::c_int as libc::c_long;
                    current_block = 4495394744059808450;
                }
            }
        } else {
            if libxmlMemoryDebugActivated == 0 as libc::c_int {
                libxmlMemoryAllocatedBase = xmlMemUsed() as libc::c_long;
                ret = 0 as libc::c_int as libc::c_long;
            } else {
                ret = xmlMemUsed() as libc::c_long - libxmlMemoryAllocatedBase;
            }
            current_block = 4495394744059808450;
        }
        match current_block {
            15224037586932921579 => {}
            _ => {
                libxmlMemoryDebug = 1 as libc::c_int;
                libxmlMemoryDebugActivated = 1 as libc::c_int;
            }
        }
    } else {
        if libxmlMemoryDebugActivated == 1 as libc::c_int {
            ret = xmlMemUsed() as libc::c_long - libxmlMemoryAllocatedBase;
        } else {
            ret = 0 as libc::c_int as libc::c_long;
        }
        libxmlMemoryDebugActivated = 0 as libc::c_int;
    }
    py_retval = libxml_longWrap(ret);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPythonCleanupParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ix: libc::c_int = 0;
    let mut freed: libc::c_long = -(1 as libc::c_int) as libc::c_long;
    if libxmlMemoryDebug != 0 {
        freed = xmlMemUsed() as libc::c_long;
    }
    xmlCleanupParser();
    if !libxml_xpathCallbacks.is_null() {
        ix = 0 as libc::c_int;
        while ix < libxml_xpathCallbacksNb {
            if !((*(*libxml_xpathCallbacks).as_mut_ptr().offset(ix as isize)).name)
                .is_null()
            {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(
                    (*(*libxml_xpathCallbacks).as_mut_ptr().offset(ix as isize)).name
                        as *mut libc::c_void,
                );
            }
            if !((*(*libxml_xpathCallbacks).as_mut_ptr().offset(ix as isize)).ns_uri)
                .is_null()
            {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(
                    (*(*libxml_xpathCallbacks).as_mut_ptr().offset(ix as isize)).ns_uri
                        as *mut libc::c_void,
                );
            }
            ix += 1;
        }
        libxml_xpathCallbacksNb = 0 as libc::c_int;
        xmlFree
            .expect(
                "non-null function pointer",
            )(libxml_xpathCallbacks as *mut libc::c_void);
        libxml_xpathCallbacks = 0 as *mut libxml_xpathCallbackArray;
    }
    if libxmlMemoryDebug != 0 {
        freed -= xmlMemUsed() as libc::c_long;
        libxmlMemoryAllocatedBase -= freed;
        if libxmlMemoryAllocatedBase < 0 as libc::c_int as libc::c_long {
            libxmlMemoryAllocatedBase = 0 as libc::c_int as libc::c_long;
        }
    }
    let ref mut fresh0 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh0 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDumpMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxmlMemoryDebug != 0 as libc::c_int {
        xmlMemoryDump();
    }
    let ref mut fresh1 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh1 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn xmlPythonFileCloseRaw(
    mut context: *mut libc::c_void,
) -> libc::c_int {
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    file = context as *mut PyObject;
    if file.is_null() {
        return -(1 as libc::c_int);
    }
    ret = PyEval_CallMethod(
        file,
        b"close\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"()\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    if !ret.is_null() {
        let ref mut fresh2 = (*ret).ob_refcnt;
        *fresh2 -= 1;
        if !(*fresh2 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(ret);
        }
    }
    let ref mut fresh3 = (*file).ob_refcnt;
    *fresh3 -= 1;
    if !(*fresh3 != 0 as libc::c_int as libc::c_long) {
        (Some(((*(*file).ob_type).tp_dealloc).expect("non-null function pointer")))
            .expect("non-null function pointer")(file);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlPythonFileReadRaw(
    mut context: *mut libc::c_void,
    mut buffer: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    let mut lenread: libc::c_int = -(1 as libc::c_int);
    let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
    file = context as *mut PyObject;
    if file.is_null() {
        return -(1 as libc::c_int);
    }
    ret = PyEval_CallMethod(
        file,
        b"read\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"(i)\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        len,
    );
    if ret.is_null() {
        printf(
            b"xmlPythonFileReadRaw: result is NULL\n\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    } else {
        if (*(*ret).ob_type).tp_flags & (1 as libc::c_long) << 27 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
            lenread = PyString_Size(ret) as libc::c_int;
            data = PyString_AsString(ret);
        } else if (*(*ret).ob_type).tp_flags & (1 as libc::c_long) << 28 as libc::c_int
                != 0 as libc::c_int as libc::c_long
            {
            let mut b: *mut PyObject = 0 as *mut PyObject;
            b = PyUnicodeUCS4_AsUTF8String(ret);
            if b.is_null() {
                printf(
                    b"xmlPythonFileReadRaw: failed to convert to UTF-8\n\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            lenread = PyString_Size(b) as libc::c_int;
            data = PyString_AsString(b);
            let ref mut fresh4 = (*b).ob_refcnt;
            *fresh4 -= 1;
            if !(*fresh4 != 0 as libc::c_int as libc::c_long) {
                (Some(((*(*b).ob_type).tp_dealloc).expect("non-null function pointer")))
                    .expect("non-null function pointer")(b);
            }
        } else {
            printf(
                b"xmlPythonFileReadRaw: result is not a String\n\0" as *const u8
                    as *const libc::c_char,
            );
            let ref mut fresh5 = (*ret).ob_refcnt;
            *fresh5 -= 1;
            if !(*fresh5 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ret);
            }
            return -(1 as libc::c_int);
        }
    }
    if lenread > len {
        memcpy(
            buffer as *mut libc::c_void,
            data as *const libc::c_void,
            len as libc::c_ulong,
        );
    } else {
        memcpy(
            buffer as *mut libc::c_void,
            data as *const libc::c_void,
            lenread as libc::c_ulong,
        );
    }
    let ref mut fresh6 = (*ret).ob_refcnt;
    *fresh6 -= 1;
    if !(*fresh6 != 0 as libc::c_int as libc::c_long) {
        (Some(((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer")))
            .expect("non-null function pointer")(ret);
    }
    return lenread;
}
unsafe extern "C" fn xmlPythonFileRead(
    mut context: *mut libc::c_void,
    mut buffer: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    let mut lenread: libc::c_int = -(1 as libc::c_int);
    let mut data: *mut libc::c_char = 0 as *mut libc::c_char;
    file = context as *mut PyObject;
    if file.is_null() {
        return -(1 as libc::c_int);
    }
    ret = PyEval_CallMethod(
        file,
        b"io_read\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"(i)\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        len,
    );
    if ret.is_null() {
        printf(
            b"xmlPythonFileRead: result is NULL\n\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    } else {
        if (*(*ret).ob_type).tp_flags & (1 as libc::c_long) << 27 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
            lenread = PyString_Size(ret) as libc::c_int;
            data = PyString_AsString(ret);
        } else if (*(*ret).ob_type).tp_flags & (1 as libc::c_long) << 28 as libc::c_int
                != 0 as libc::c_int as libc::c_long
            {
            let mut b: *mut PyObject = 0 as *mut PyObject;
            b = PyUnicodeUCS4_AsUTF8String(ret);
            if b.is_null() {
                printf(
                    b"xmlPythonFileRead: failed to convert to UTF-8\n\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            lenread = PyString_Size(b) as libc::c_int;
            data = PyString_AsString(b);
            let ref mut fresh7 = (*b).ob_refcnt;
            *fresh7 -= 1;
            if !(*fresh7 != 0 as libc::c_int as libc::c_long) {
                (Some(((*(*b).ob_type).tp_dealloc).expect("non-null function pointer")))
                    .expect("non-null function pointer")(b);
            }
        } else {
            printf(
                b"xmlPythonFileRead: result is not a String\n\0" as *const u8
                    as *const libc::c_char,
            );
            let ref mut fresh8 = (*ret).ob_refcnt;
            *fresh8 -= 1;
            if !(*fresh8 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ret);
            }
            return -(1 as libc::c_int);
        }
    }
    if lenread > len {
        memcpy(
            buffer as *mut libc::c_void,
            data as *const libc::c_void,
            len as libc::c_ulong,
        );
    } else {
        memcpy(
            buffer as *mut libc::c_void,
            data as *const libc::c_void,
            lenread as libc::c_ulong,
        );
    }
    let ref mut fresh9 = (*ret).ob_refcnt;
    *fresh9 -= 1;
    if !(*fresh9 != 0 as libc::c_int as libc::c_long) {
        (Some(((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer")))
            .expect("non-null function pointer")(ret);
    }
    return lenread;
}
unsafe extern "C" fn xmlPythonFileWrite(
    mut context: *mut libc::c_void,
    mut buffer: *const libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut string: *mut PyObject = 0 as *mut PyObject;
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    let mut written: libc::c_int = -(1 as libc::c_int);
    file = context as *mut PyObject;
    if file.is_null() {
        return -(1 as libc::c_int);
    }
    string = PyString_FromStringAndSize(buffer, len as Py_ssize_t);
    if string.is_null() {
        return -(1 as libc::c_int);
    }
    if PyObject_HasAttrString(
        file,
        b"io_write\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        ret = PyEval_CallMethod(
            file,
            b"io_write\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"(O)\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            string,
        );
    } else if PyObject_HasAttrString(
            file,
            b"write\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        ret = PyEval_CallMethod(
            file,
            b"write\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"(O)\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            string,
        );
    }
    let ref mut fresh10 = (*string).ob_refcnt;
    *fresh10 -= 1;
    if !(*fresh10 != 0 as libc::c_int as libc::c_long) {
        (Some(((*(*string).ob_type).tp_dealloc).expect("non-null function pointer")))
            .expect("non-null function pointer")(string);
    }
    if ret.is_null() {
        printf(
            b"xmlPythonFileWrite: result is NULL\n\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    } else {
        if (*(*ret).ob_type).tp_flags & (1 as libc::c_long) << 24 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
            written = PyLong_AsLong(ret) as libc::c_int;
            let ref mut fresh11 = (*ret).ob_refcnt;
            *fresh11 -= 1;
            if !(*fresh11 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ret);
            }
        } else if ret == &mut _Py_NoneStruct as *mut PyObject {
            written = len;
            let ref mut fresh12 = (*ret).ob_refcnt;
            *fresh12 -= 1;
            if !(*fresh12 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ret);
            }
        } else {
            printf(
                b"xmlPythonFileWrite: result is not an Int nor None\n\0" as *const u8
                    as *const libc::c_char,
            );
            let ref mut fresh13 = (*ret).ob_refcnt;
            *fresh13 -= 1;
            if !(*fresh13 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ret);
            }
        }
    }
    return written;
}
unsafe extern "C" fn xmlPythonFileClose(mut context: *mut libc::c_void) -> libc::c_int {
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    file = context as *mut PyObject;
    if file.is_null() {
        return -(1 as libc::c_int);
    }
    if PyObject_HasAttrString(
        file,
        b"io_close\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        ret = PyEval_CallMethod(
            file,
            b"io_close\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"()\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
    } else if PyObject_HasAttrString(
            file,
            b"flush\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        ret = PyEval_CallMethod(
            file,
            b"flush\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"()\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
    }
    if !ret.is_null() {
        let ref mut fresh14 = (*ret).ob_refcnt;
        *fresh14 -= 1;
        if !(*fresh14 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*ret).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(ret);
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn xmlOutputBufferCreatePythonFile(
    mut file: *mut PyObject,
    mut encoder: xmlCharEncodingHandlerPtr,
) -> xmlOutputBufferPtr {
    let mut ret: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if file.is_null() {
        return 0 as xmlOutputBufferPtr;
    }
    ret = xmlAllocOutputBuffer(encoder);
    if !ret.is_null() {
        let ref mut fresh15 = (*ret).context;
        *fresh15 = file as *mut libc::c_void;
        let ref mut fresh16 = (*ret).writecallback;
        *fresh16 = Some(
            xmlPythonFileWrite
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    libc::c_int,
                ) -> libc::c_int,
        );
        let ref mut fresh17 = (*ret).closecallback;
        *fresh17 = Some(
            xmlPythonFileClose as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateOutputBuffer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    let mut handler: xmlCharEncodingHandlerPtr = 0 as xmlCharEncodingHandlerPtr;
    let mut buffer: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlOutputBufferCreate\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut file as *mut *mut PyObject,
        &mut encoding as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if !encoding.is_null()
        && *encoding.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
    {
        handler = xmlFindCharEncodingHandler(encoding as *const libc::c_char);
    }
    buffer = xmlOutputBufferCreatePythonFile(file, handler);
    if buffer.is_null() {
        printf(
            b"libxml_xmlCreateOutputBuffer: buffer == NULL\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    py_retval = libxml_xmlOutputBufferPtrWrap(buffer);
    return py_retval;
}
unsafe extern "C" fn libxml_outputBufferGetPythonFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buffer: *mut PyObject = 0 as *mut PyObject;
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut obj: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:outputBufferGetPythonFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    obj = if buffer == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(buffer as *mut PyoutputBuffer_Object)).obj
    };
    if obj.is_null() {
        fprintf(
            stderr,
            b"outputBufferGetPythonFile: obj == NULL\n\0" as *const u8
                as *const libc::c_char,
        );
        let ref mut fresh18 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh18 += 1;
        return &mut _Py_NoneStruct;
    }
    if (*obj).closecallback
        != Some(
            xmlPythonFileClose as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
        )
    {
        fprintf(
            stderr,
            b"outputBufferGetPythonFile: not a python file wrapper\n\0" as *const u8
                as *const libc::c_char,
        );
        let ref mut fresh19 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh19 += 1;
        return &mut _Py_NoneStruct;
    }
    file = (*obj).context as *mut PyObject;
    if file.is_null() {
        let ref mut fresh20 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh20 += 1;
        return &mut _Py_NoneStruct;
    }
    let ref mut fresh21 = (*file).ob_refcnt;
    *fresh21 += 1;
    return file;
}
unsafe extern "C" fn libxml_xmlOutputBufferClose(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlOutputBufferClose\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_out as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_out as *mut PyoutputBuffer_Object)).obj
    };
    if out.is_null() {
        let ref mut fresh22 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh22 += 1;
        return &mut _Py_NoneStruct;
    }
    c_retval = xmlOutputBufferClose(out);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlOutputBufferFlush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlOutputBufferFlush\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_out as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_out as *mut PyoutputBuffer_Object)).obj
    };
    c_retval = xmlOutputBufferFlush(out);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlSaveFileTo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlSaveFileTo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFileTo(buf, cur, encoding);
    let ref mut fresh23 = (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj;
    *fresh23 = 0 as xmlOutputBufferPtr;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlSaveFormatFileTo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzi:xmlSaveFormatFileTo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
        &mut format as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFormatFileTo(buf, cur, encoding, format);
    let ref mut fresh24 = (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj;
    *fresh24 = 0 as xmlOutputBufferPtr;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn xmlParserInputBufferCreatePythonFile(
    mut file: *mut PyObject,
    mut encoding: xmlCharEncoding,
) -> xmlParserInputBufferPtr {
    let mut ret: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if file.is_null() {
        return 0 as xmlParserInputBufferPtr;
    }
    ret = xmlAllocParserInputBuffer(encoding);
    if !ret.is_null() {
        let ref mut fresh25 = (*ret).context;
        *fresh25 = file as *mut libc::c_void;
        let ref mut fresh26 = (*ret).readcallback;
        *fresh26 = Some(
            xmlPythonFileRead
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_char,
                    libc::c_int,
                ) -> libc::c_int,
        );
        let ref mut fresh27 = (*ret).closecallback;
        *fresh27 = Some(
            xmlPythonFileClose as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
        );
    }
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateInputBuffer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut file: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    let mut enc: xmlCharEncoding = XML_CHAR_ENCODING_NONE;
    let mut buffer: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlParserInputBufferCreate\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut file as *mut *mut PyObject,
        &mut encoding as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if !encoding.is_null()
        && *encoding.offset(0 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
    {
        enc = xmlParseCharEncoding(encoding as *const libc::c_char);
    }
    buffer = xmlParserInputBufferCreatePythonFile(file, enc);
    if buffer.is_null() {
        printf(
            b"libxml_xmlParserInputBufferCreate: buffer == NULL\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    py_retval = libxml_xmlParserInputBufferPtrWrap(buffer);
    return py_retval;
}
static mut defaultExternalEntityLoader: xmlExternalEntityLoader = None;
static mut pythonExternalEntityLoaderObjext: *mut PyObject = 0 as *const PyObject
    as *mut PyObject;
unsafe extern "C" fn pythonExternalEntityLoader(
    mut URL: *const libc::c_char,
    mut ID: *const libc::c_char,
    mut ctxt: xmlParserCtxtPtr,
) -> xmlParserInputPtr {
    let mut result: xmlParserInputPtr = 0 as xmlParserInputPtr;
    if !pythonExternalEntityLoaderObjext.is_null() {
        let mut ret: *mut PyObject = 0 as *mut PyObject;
        let mut ctxtobj: *mut PyObject = 0 as *mut PyObject;
        ctxtobj = libxml_xmlParserCtxtPtrWrap(ctxt);
        ret = _PyObject_CallFunction_SizeT(
            pythonExternalEntityLoaderObjext,
            b"(ssO)\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            URL,
            ID,
            ctxtobj,
        );
        if !ctxtobj.is_null() {
            let ref mut fresh28 = (*ctxtobj).ob_refcnt;
            *fresh28 -= 1;
            if !(*fresh28 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*ctxtobj).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(ctxtobj);
            }
        }
        if !ret.is_null() {
            if PyObject_HasAttrString(
                ret,
                b"read\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            ) != 0
            {
                let mut buf: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
                buf = xmlAllocParserInputBuffer(XML_CHAR_ENCODING_NONE);
                if !buf.is_null() {
                    let ref mut fresh29 = (*buf).context;
                    *fresh29 = ret as *mut libc::c_void;
                    let ref mut fresh30 = (*buf).readcallback;
                    *fresh30 = Some(
                        xmlPythonFileReadRaw
                            as unsafe extern "C" fn(
                                *mut libc::c_void,
                                *mut libc::c_char,
                                libc::c_int,
                            ) -> libc::c_int,
                    );
                    let ref mut fresh31 = (*buf).closecallback;
                    *fresh31 = Some(
                        xmlPythonFileCloseRaw
                            as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
                    );
                    result = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
                }
            }
            if result.is_null() {
                let ref mut fresh32 = (*ret).ob_refcnt;
                *fresh32 -= 1;
                if !(*fresh32 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*ret).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")(ret);
                }
            } else if !URL.is_null() {
                let ref mut fresh33 = (*result).filename;
                *fresh33 = xmlStrdup(URL as *const xmlChar) as *mut libc::c_char;
                let ref mut fresh34 = (*result).directory;
                *fresh34 = xmlParserGetDirectory(URL);
            }
        }
    }
    if result.is_null() && defaultExternalEntityLoader.is_some() {
        result = defaultExternalEntityLoader
            .expect("non-null function pointer")(URL, ID, ctxt);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetEntityLoader(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut loader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:libxml_xmlSetEntityLoader\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut loader as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if PyCallable_Check(loader) == 0 {
        PyErr_SetString(
            PyExc_ValueError,
            b"entity loader is not callable\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    if defaultExternalEntityLoader.is_none() {
        defaultExternalEntityLoader = xmlGetExternalEntityLoader();
    }
    if !pythonExternalEntityLoaderObjext.is_null() {
        let ref mut fresh35 = (*pythonExternalEntityLoaderObjext).ob_refcnt;
        *fresh35 -= 1;
        if !(*fresh35 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*pythonExternalEntityLoaderObjext).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")(pythonExternalEntityLoaderObjext);
        }
    }
    pythonExternalEntityLoaderObjext = loader;
    if !pythonExternalEntityLoaderObjext.is_null() {
        let ref mut fresh36 = (*pythonExternalEntityLoaderObjext).ob_refcnt;
        *fresh36 += 1;
    }
    xmlSetExternalEntityLoader(
        Some(
            pythonExternalEntityLoader
                as unsafe extern "C" fn(
                    *const libc::c_char,
                    *const libc::c_char,
                    xmlParserCtxtPtr,
                ) -> xmlParserInputPtr,
        ),
    );
    py_retval = PyLong_FromLong(0 as libc::c_int as libc::c_long);
    return py_retval;
}
static mut pythonInputOpenCallbackObject: *mut PyObject = 0 as *const PyObject
    as *mut PyObject;
static mut pythonInputCallbackID: libc::c_int = -(1 as libc::c_int);
unsafe extern "C" fn pythonInputMatchCallback(
    mut URI: *const libc::c_char,
) -> libc::c_int {
    return 1 as libc::c_int;
}
unsafe extern "C" fn pythonInputOpenCallback(
    mut URI: *const libc::c_char,
) -> *mut libc::c_void {
    let mut ret: *mut PyObject = 0 as *mut PyObject;
    ret = _PyObject_CallFunction_SizeT(
        pythonInputOpenCallbackObject,
        b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        URI,
    );
    if ret == &mut _Py_NoneStruct as *mut PyObject {
        let ref mut fresh37 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh37 -= 1;
        if !(*fresh37 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(&mut _Py_NoneStruct as *mut PyObject)).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect(
                    "non-null function pointer",
                )(&mut _Py_NoneStruct as *mut PyObject);
        }
        return 0 as *mut libc::c_void;
    }
    return ret as *mut libc::c_void;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterInputCallback(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cb: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:libxml_xmlRegisterInputCallback\0" as *const u8 as *const libc::c_char,
        &mut cb as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if PyCallable_Check(cb) == 0 {
        PyErr_SetString(
            PyExc_ValueError,
            b"input callback is not callable\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    if pythonInputCallbackID == -(1 as libc::c_int) {
        pythonInputCallbackID = xmlRegisterInputCallbacks(
            Some(
                pythonInputMatchCallback
                    as unsafe extern "C" fn(*const libc::c_char) -> libc::c_int,
            ),
            Some(
                pythonInputOpenCallback
                    as unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void,
            ),
            Some(
                xmlPythonFileReadRaw
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            Some(
                xmlPythonFileCloseRaw
                    as unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
            ),
        );
        if pythonInputCallbackID == -(1 as libc::c_int) {
            return PyErr_NoMemory();
        }
        pythonInputOpenCallbackObject = cb;
        let ref mut fresh38 = (*pythonInputOpenCallbackObject).ob_refcnt;
        *fresh38 += 1;
    }
    let ref mut fresh39 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh39 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUnregisterInputCallback(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ret: libc::c_int = 0;
    ret = xmlPopInputCallbacks();
    if pythonInputCallbackID != -(1 as libc::c_int) {
        if pythonInputCallbackID == ret {
            pythonInputCallbackID = -(1 as libc::c_int);
            let ref mut fresh40 = (*pythonInputOpenCallbackObject).ob_refcnt;
            *fresh40 -= 1;
            if !(*fresh40 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*pythonInputOpenCallbackObject).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(pythonInputOpenCallbackObject);
            }
            pythonInputOpenCallbackObject = 0 as *mut PyObject;
        } else {
            PyErr_SetString(
                PyExc_AssertionError,
                b"popped non-python input callback\0" as *const u8 as *const libc::c_char,
            );
            return 0 as *mut PyObject;
        }
    } else if ret == -(1 as libc::c_int) {
        PyErr_SetString(
            PyExc_IndexError,
            b"no input callbacks to pop\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    let ref mut fresh41 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh41 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn pythonStartElement(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut attrs: *mut *const xmlChar,
) {
    let mut i: libc::c_int = 0;
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut dict: *mut PyObject = 0 as *mut PyObject;
    let mut attrname: *mut PyObject = 0 as *mut PyObject;
    let mut attrvalue: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: libc::c_int = 0 as libc::c_int;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"startElement\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        type_0 = 1 as libc::c_int;
    } else if PyObject_HasAttrString(
            handler,
            b"start\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        type_0 = 2 as libc::c_int;
    }
    if type_0 != 0 as libc::c_int {
        if attrs.is_null() && type_0 == 1 as libc::c_int {
            if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
                let ref mut fresh42 = (*(&mut _Py_NoneStruct as *mut PyObject))
                    .ob_refcnt;
                *fresh42 += 1;
            }
            dict = &mut _Py_NoneStruct;
        } else if attrs.is_null() {
            dict = PyDict_New();
        } else {
            dict = PyDict_New();
            i = 0 as libc::c_int;
            while !(*attrs.offset(i as isize)).is_null() {
                attrname = PyString_FromString(
                    *attrs.offset(i as isize) as *mut libc::c_char,
                );
                i += 1;
                if !(*attrs.offset(i as isize)).is_null() {
                    attrvalue = PyString_FromString(
                        *attrs.offset(i as isize) as *mut libc::c_char,
                    );
                } else {
                    if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
                        let ref mut fresh43 = (*(&mut _Py_NoneStruct as *mut PyObject))
                            .ob_refcnt;
                        *fresh43 += 1;
                    }
                    attrvalue = &mut _Py_NoneStruct;
                }
                PyDict_SetItem(dict, attrname, attrvalue);
                let ref mut fresh44 = (*attrname).ob_refcnt;
                *fresh44 -= 1;
                if !(*fresh44 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*attrname).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")(attrname);
                }
                let ref mut fresh45 = (*attrvalue).ob_refcnt;
                *fresh45 -= 1;
                if !(*fresh45 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*attrvalue).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")(attrvalue);
                }
                i += 1;
            }
        }
        if type_0 == 1 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"startElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                b"sO\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                name,
                dict,
            );
        } else if type_0 == 2 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"start\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"sO\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                name,
                dict,
            );
        }
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !dict.is_null() {
            let ref mut fresh46 = (*dict).ob_refcnt;
            *fresh46 -= 1;
            if !(*fresh46 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*dict).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(dict);
            }
        }
        if !result.is_null() {
            let ref mut fresh47 = (*result).ob_refcnt;
            *fresh47 -= 1;
            if !(*fresh47 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonStartDocument(mut user_data: *mut libc::c_void) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"startDocument\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"startDocument\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            0 as *mut libc::c_char,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh48 = (*result).ob_refcnt;
            *fresh48 -= 1;
            if !(*fresh48 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonEndDocument(mut user_data: *mut libc::c_void) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"endDocument\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"endDocument\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            0 as *mut libc::c_char,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh49 = (*result).ob_refcnt;
            *fresh49 -= 1;
            if !(*fresh49 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
    if !handler.is_null() {
        let ref mut fresh50 = (*handler).ob_refcnt;
        *fresh50 -= 1;
        if !(*fresh50 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*handler).ob_type).tp_dealloc).expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")(handler);
        }
    }
}
unsafe extern "C" fn pythonEndElement(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"endElement\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"endElement\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh51 = (*result).ob_refcnt;
            *fresh51 -= 1;
            if !(*fresh51 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    } else if PyObject_HasAttrString(
            handler,
            b"end\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"end\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh52 = (*result).ob_refcnt;
            *fresh52 -= 1;
            if !(*fresh52 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonReference(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"reference\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"reference\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh53 = (*result).ob_refcnt;
            *fresh53 -= 1;
            if !(*fresh53 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonCharacters(
    mut user_data: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: libc::c_int = 0 as libc::c_int;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"characters\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        type_0 = 1 as libc::c_int;
    } else if PyObject_HasAttrString(
            handler,
            b"data\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        type_0 = 2 as libc::c_int;
    }
    if type_0 != 0 as libc::c_int {
        if type_0 == 1 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"characters\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        } else if type_0 == 2 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"data\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        }
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh54 = (*result).ob_refcnt;
            *fresh54 -= 1;
            if !(*fresh54 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonIgnorableWhitespace(
    mut user_data: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: libc::c_int = 0 as libc::c_int;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"ignorableWhitespace\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        type_0 = 1 as libc::c_int;
    } else if PyObject_HasAttrString(
            handler,
            b"data\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        type_0 = 2 as libc::c_int;
    }
    if type_0 != 0 as libc::c_int {
        if type_0 == 1 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"ignorableWhitespace\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        } else if type_0 == 2 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"data\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        }
        if !result.is_null() {
            let ref mut fresh55 = (*result).ob_refcnt;
            *fresh55 -= 1;
            if !(*fresh55 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonProcessingInstruction(
    mut user_data: *mut libc::c_void,
    mut target: *const xmlChar,
    mut data: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"processingInstruction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"processingInstruction\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            b"ss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            target,
            data,
        );
        if !result.is_null() {
            let ref mut fresh56 = (*result).ob_refcnt;
            *fresh56 -= 1;
            if !(*fresh56 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonComment(
    mut user_data: *mut libc::c_void,
    mut value: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"comment\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"comment\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh57 = (*result).ob_refcnt;
            *fresh57 -= 1;
            if !(*fresh57 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonWarning(
    mut user_data: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"warning\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        args_0 = args.clone();
        vsnprintf(
            buf.as_mut_ptr(),
            1023 as libc::c_int as libc::c_ulong,
            msg,
            args_0.as_va_list(),
        );
        buf[1023 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"warning\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            buf.as_mut_ptr(),
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh58 = (*result).ob_refcnt;
            *fresh58 -= 1;
            if !(*fresh58 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonError(
    mut user_data: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"error\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        args_0 = args.clone();
        vsnprintf(
            buf.as_mut_ptr(),
            1023 as libc::c_int as libc::c_ulong,
            msg,
            args_0.as_va_list(),
        );
        buf[1023 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"error\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            buf.as_mut_ptr(),
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh59 = (*result).ob_refcnt;
            *fresh59 -= 1;
            if !(*fresh59 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonFatalError(
    mut user_data: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut args_0: ::std::ffi::VaListImpl;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"fatalError\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        args_0 = args.clone();
        vsnprintf(
            buf.as_mut_ptr(),
            1023 as libc::c_int as libc::c_ulong,
            msg,
            args_0.as_va_list(),
        );
        buf[1023 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"fatalError\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            buf.as_mut_ptr(),
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh60 = (*result).ob_refcnt;
            *fresh60 -= 1;
            if !(*fresh60 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonCdataBlock(
    mut user_data: *mut libc::c_void,
    mut ch: *const xmlChar,
    mut len: libc::c_int,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: libc::c_int = 0 as libc::c_int;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"cdataBlock\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        type_0 = 1 as libc::c_int;
    } else if PyObject_HasAttrString(
            handler,
            b"cdata\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ) != 0
        {
        type_0 = 2 as libc::c_int;
    }
    if type_0 != 0 as libc::c_int {
        if type_0 == 1 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"cdataBlock\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        } else if type_0 == 2 as libc::c_int {
            result = _PyObject_CallMethod_SizeT(
                handler,
                b"cdata\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                b"s#\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                ch,
                len as Py_ssize_t,
            );
        }
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh61 = (*result).ob_refcnt;
            *fresh61 -= 1;
            if !(*fresh61 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonExternalSubset(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut externalID: *const xmlChar,
    mut systemID: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"externalSubset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"externalSubset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"sss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            externalID,
            systemID,
        );
        if !result.is_null() {
            let ref mut fresh62 = (*result).ob_refcnt;
            *fresh62 -= 1;
            if !(*fresh62 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonEntityDecl(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut content: *mut xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"entityDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"entityDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"sisss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            type_0,
            publicId,
            systemId,
            content,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh63 = (*result).ob_refcnt;
            *fresh63 -= 1;
            if !(*fresh63 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonNotationDecl(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"notationDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"notationDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"sss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            publicId,
            systemId,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh64 = (*result).ob_refcnt;
            *fresh64 -= 1;
            if !(*fresh64 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonAttributeDecl(
    mut user_data: *mut libc::c_void,
    mut elem: *const xmlChar,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut def: libc::c_int,
    mut defaultValue: *const xmlChar,
    mut tree: xmlEnumerationPtr,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut nameList: *mut PyObject = 0 as *mut PyObject;
    let mut newName: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlEnumerationPtr = 0 as *mut xmlEnumeration;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut count: libc::c_int = 0;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"attributeDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        count = 0 as libc::c_int;
        node = tree;
        while !node.is_null() {
            count += 1;
            node = (*node).next;
        }
        nameList = PyList_New(count as Py_ssize_t);
        count = 0 as libc::c_int;
        node = tree;
        while !node.is_null() {
            newName = PyString_FromString((*node).name as *mut libc::c_char);
            PyList_SetItem(nameList, count as Py_ssize_t, newName);
            let ref mut fresh65 = (*newName).ob_refcnt;
            *fresh65 -= 1;
            if !(*fresh65 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*newName).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(newName);
            }
            count += 1;
            node = (*node).next;
        }
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"attributeDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"ssiisO\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            elem,
            name,
            type_0,
            def,
            defaultValue,
            nameList,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !nameList.is_null() {
            let ref mut fresh66 = (*nameList).ob_refcnt;
            *fresh66 -= 1;
            if !(*fresh66 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*nameList).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(nameList);
            }
        }
        if !result.is_null() {
            let ref mut fresh67 = (*result).ob_refcnt;
            *fresh67 -= 1;
            if !(*fresh67 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonElementDecl(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut type_0: libc::c_int,
    mut content: xmlElementContentPtr,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"elementDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        printf(
            b"pythonElementDecl: xmlElementContentPtr wrapper missing !\n\0" as *const u8
                as *const libc::c_char,
        );
        obj = &mut _Py_NoneStruct;
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"elementDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"siO\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            type_0,
            obj,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh68 = (*result).ob_refcnt;
            *fresh68 -= 1;
            if !(*fresh68 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonUnparsedEntityDecl(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut publicId: *const xmlChar,
    mut systemId: *const xmlChar,
    mut notationName: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"unparsedEntityDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"unparsedEntityDecl\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            b"ssss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            publicId,
            systemId,
            notationName,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh69 = (*result).ob_refcnt;
            *fresh69 -= 1;
            if !(*fresh69 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
unsafe extern "C" fn pythonInternalSubset(
    mut user_data: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ExternalID: *const xmlChar,
    mut SystemID: *const xmlChar,
) {
    let mut handler: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    handler = user_data as *mut PyObject;
    if PyObject_HasAttrString(
        handler,
        b"internalSubset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ) != 0
    {
        result = _PyObject_CallMethod_SizeT(
            handler,
            b"internalSubset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            b"sss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            name,
            ExternalID,
            SystemID,
        );
        if !(PyErr_Occurred()).is_null() {
            PyErr_Print();
        }
        if !result.is_null() {
            let ref mut fresh70 = (*result).ob_refcnt;
            *fresh70 -= 1;
            if !(*fresh70 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    }
}
static mut pythonSaxHandler: xmlSAXHandler = unsafe {
    {
        let mut init = _xmlSAXHandler {
            internalSubset: Some(
                pythonInternalSubset
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            isStandalone: None,
            hasInternalSubset: None,
            hasExternalSubset: None,
            resolveEntity: None,
            getEntity: None,
            entityDecl: Some(
                pythonEntityDecl
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
                pythonNotationDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            attributeDecl: Some(
                pythonAttributeDecl
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
                pythonElementDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                        xmlElementContentPtr,
                    ) -> (),
            ),
            unparsedEntityDecl: Some(
                pythonUnparsedEntityDecl
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            setDocumentLocator: None,
            startDocument: Some(
                pythonStartDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            endDocument: Some(
                pythonEndDocument as unsafe extern "C" fn(*mut libc::c_void) -> (),
            ),
            startElement: Some(
                pythonStartElement
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *mut *const xmlChar,
                    ) -> (),
            ),
            endElement: Some(
                pythonEndElement
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            reference: Some(
                pythonReference
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            characters: Some(
                pythonCharacters
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            ignorableWhitespace: Some(
                pythonIgnorableWhitespace
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            processingInstruction: Some(
                pythonProcessingInstruction
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        *const xmlChar,
                    ) -> (),
            ),
            comment: Some(
                pythonComment
                    as unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> (),
            ),
            warning: Some(
                pythonWarning
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            error: Some(
                pythonError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            fatalError: Some(
                pythonFatalError
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        ...
                    ) -> (),
            ),
            getParameterEntity: None,
            cdataBlock: Some(
                pythonCdataBlock
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const xmlChar,
                        libc::c_int,
                    ) -> (),
            ),
            externalSubset: Some(
                pythonExternalSubset
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
pub unsafe extern "C" fn libxml_xmlCreatePushParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut chunk: *const libc::c_char = 0 as *const libc::c_char;
    let mut size: libc::c_int = 0;
    let mut URI: *const libc::c_char = 0 as *const libc::c_char;
    let mut pyobj_SAX: *mut PyObject = 0 as *mut PyObject;
    let mut SAX: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut ret: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyret: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziz:xmlCreatePushParser\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_SAX as *mut *mut PyObject,
        &mut chunk as *mut *const libc::c_char,
        &mut size as *mut libc::c_int,
        &mut URI as *mut *const libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if pyobj_SAX != &mut _Py_NoneStruct as *mut PyObject {
        SAX = &mut pythonSaxHandler;
        let ref mut fresh71 = (*pyobj_SAX).ob_refcnt;
        *fresh71 += 1;
    }
    ret = xmlCreatePushParserCtxt(SAX, pyobj_SAX as *mut libc::c_void, chunk, size, URI);
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return pyret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCreatePushParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut chunk: *const libc::c_char = 0 as *const libc::c_char;
    let mut size: libc::c_int = 0;
    let mut URI: *const libc::c_char = 0 as *const libc::c_char;
    let mut pyobj_SAX: *mut PyObject = 0 as *mut PyObject;
    let mut SAX: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    let mut ret: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyret: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziz:htmlCreatePushParser\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_SAX as *mut *mut PyObject,
        &mut chunk as *mut *const libc::c_char,
        &mut size as *mut libc::c_int,
        &mut URI as *mut *const libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if pyobj_SAX != &mut _Py_NoneStruct as *mut PyObject {
        SAX = &mut pythonSaxHandler;
        let ref mut fresh72 = (*pyobj_SAX).ob_refcnt;
        *fresh72 += 1;
    }
    ret = htmlCreatePushParserCtxt(
        SAX,
        pyobj_SAX as *mut libc::c_void,
        chunk,
        size,
        URI,
        XML_CHAR_ENCODING_NONE,
    );
    pyret = libxml_xmlParserCtxtPtrWrap(ret);
    return pyret;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSAXParseFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut recover: libc::c_int = 0;
    let mut URI: *const libc::c_char = 0 as *const libc::c_char;
    let mut pyobj_SAX: *mut PyObject = 0 as *mut PyObject;
    let mut SAX: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Osi:xmlSAXParseFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_SAX as *mut *mut PyObject,
        &mut URI as *mut *const libc::c_char,
        &mut recover as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if pyobj_SAX == &mut _Py_NoneStruct as *mut PyObject {
        let ref mut fresh73 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh73 += 1;
        return &mut _Py_NoneStruct;
    }
    SAX = &mut pythonSaxHandler;
    let ref mut fresh74 = (*pyobj_SAX).ob_refcnt;
    *fresh74 += 1;
    xmlSAXUserParseFile(SAX, pyobj_SAX as *mut libc::c_void, URI);
    let ref mut fresh75 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh75 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlSAXParseFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: *const libc::c_char = 0 as *const libc::c_char;
    let mut encoding: *const libc::c_char = 0 as *const libc::c_char;
    let mut pyobj_SAX: *mut PyObject = 0 as *mut PyObject;
    let mut SAX: xmlSAXHandlerPtr = 0 as xmlSAXHandlerPtr;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Osz:htmlSAXParseFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_SAX as *mut *mut PyObject,
        &mut URI as *mut *const libc::c_char,
        &mut encoding as *mut *const libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if pyobj_SAX == &mut _Py_NoneStruct as *mut PyObject {
        let ref mut fresh76 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh76 += 1;
        return &mut _Py_NoneStruct;
    }
    SAX = &mut pythonSaxHandler;
    let ref mut fresh77 = (*pyobj_SAX).ob_refcnt;
    *fresh77 += 1;
    htmlSAXParseFile(URI, encoding, SAX, pyobj_SAX as *mut libc::c_void);
    let ref mut fresh78 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh78 += 1;
    return &mut _Py_NoneStruct;
}
static mut libxml_xmlPythonErrorFuncHandler: *mut PyObject = 0 as *const PyObject
    as *mut PyObject;
static mut libxml_xmlPythonErrorFuncCtxt: *mut PyObject = 0 as *const PyObject
    as *mut PyObject;
unsafe extern "C" fn libxml_buildMessage(
    mut msg: *const libc::c_char,
    mut ap: ::std::ffi::VaList,
) -> *mut libc::c_char {
    let mut chars: libc::c_int = 0;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    str = xmlMalloc.expect("non-null function pointer")(1000 as libc::c_int as size_t)
        as *mut libc::c_char;
    if str.is_null() {
        return 0 as *mut libc::c_char;
    }
    chars = vsnprintf(str, 999 as libc::c_int as libc::c_ulong, msg, ap.as_va_list());
    if chars >= 998 as libc::c_int {
        *str.offset(999 as libc::c_int as isize) = 0 as libc::c_int as libc::c_char;
    }
    return str;
}
unsafe extern "C" fn libxml_xmlErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut message: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut str: [libc::c_char; 1000] = [0; 1000];
    if libxml_xmlPythonErrorFuncHandler.is_null() {
        ap = args.clone();
        vfprintf(stderr, msg, ap.as_va_list());
    } else {
        ap = args.clone();
        if vsnprintf(
            str.as_mut_ptr(),
            999 as libc::c_int as libc::c_ulong,
            msg,
            ap.as_va_list(),
        ) >= 998 as libc::c_int
        {
            str[999 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
        }
        list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
        PyTuple_SetItem(
            list,
            0 as libc::c_int as Py_ssize_t,
            libxml_xmlPythonErrorFuncCtxt,
        );
        if !libxml_xmlPythonErrorFuncCtxt.is_null() {
            let ref mut fresh79 = (*libxml_xmlPythonErrorFuncCtxt).ob_refcnt;
            *fresh79 += 1;
        }
        message = libxml_charPtrConstWrap(str.as_mut_ptr());
        PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, message);
        result = PyEval_CallObjectWithKeywords(
            libxml_xmlPythonErrorFuncHandler,
            list,
            0 as *mut libc::c_void as *mut PyObject,
        );
        if !list.is_null() {
            let ref mut fresh80 = (*list).ob_refcnt;
            *fresh80 -= 1;
            if !(*fresh80 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*list).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(list);
            }
        }
        if !result.is_null() {
            let ref mut fresh81 = (*result).ob_refcnt;
            *fresh81 -= 1;
            if !(*fresh81 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*result).ob_type).tp_dealloc).expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(result);
            }
        }
    };
}
unsafe extern "C" fn libxml_xmlErrorInitialize() {
    xmlSetGenericErrorFunc(
        0 as *mut libc::c_void,
        Some(
            libxml_xmlErrorFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
    );
    xmlThrDefSetGenericErrorFunc(
        0 as *mut libc::c_void,
        Some(
            libxml_xmlErrorFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
    );
}
unsafe extern "C" fn libxml_xmlRegisterErrorHandler(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRegisterErrorHandler\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_ctx as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if !libxml_xmlPythonErrorFuncHandler.is_null() {
        if !libxml_xmlPythonErrorFuncHandler.is_null() {
            let ref mut fresh82 = (*libxml_xmlPythonErrorFuncHandler).ob_refcnt;
            *fresh82 -= 1;
            if !(*fresh82 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*libxml_xmlPythonErrorFuncHandler).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect(
                        "non-null function pointer",
                    )(libxml_xmlPythonErrorFuncHandler);
            }
        }
    }
    if !libxml_xmlPythonErrorFuncCtxt.is_null() {
        if !libxml_xmlPythonErrorFuncCtxt.is_null() {
            let ref mut fresh83 = (*libxml_xmlPythonErrorFuncCtxt).ob_refcnt;
            *fresh83 -= 1;
            if !(*fresh83 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*libxml_xmlPythonErrorFuncCtxt).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")(libxml_xmlPythonErrorFuncCtxt);
            }
        }
    }
    if !pyobj_ctx.is_null() {
        let ref mut fresh84 = (*pyobj_ctx).ob_refcnt;
        *fresh84 += 1;
    }
    if !pyobj_f.is_null() {
        let ref mut fresh85 = (*pyobj_f).ob_refcnt;
        *fresh85 += 1;
    }
    libxml_xmlPythonErrorFuncHandler = pyobj_f;
    libxml_xmlPythonErrorFuncCtxt = pyobj_ctx;
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlParserCtxtGenericErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut severity: libc::c_int,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyCtxt: xmlParserCtxtPyCtxtPtr = 0 as *mut xmlParserCtxtPyCtxt;
    ctxt = ctx as xmlParserCtxtPtr;
    pyCtxt = (*ctxt)._private as xmlParserCtxtPyCtxtPtr;
    list = PyTuple_New(4 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh86 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh86 += 1;
    }
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 2 as libc::c_int as Py_ssize_t, libxml_intWrap(severity));
    PyTuple_SetItem(list, 3 as libc::c_int as Py_ssize_t, &mut _Py_NoneStruct);
    let ref mut fresh87 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh87 += 1;
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).f,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh88 = (*list).ob_refcnt;
        *fresh88 -= 1;
        if !(*fresh88 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh89 = (*result).ob_refcnt;
        *fresh89 -= 1;
        if !(*fresh89 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlParserCtxtErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlParserCtxtGenericErrorFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_ERROR as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlParserCtxtWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlParserCtxtGenericErrorFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_WARNING as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlParserCtxtValidityErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlParserCtxtGenericErrorFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_VALIDITY_ERROR as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlParserCtxtValidityWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlParserCtxtGenericErrorFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_VALIDITY_WARNING as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlParserCtxtSetErrorHandler(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyCtxt: xmlParserCtxtPyCtxtPtr = 0 as *mut xmlParserCtxtPyCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_arg: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlParserCtxtSetErrorHandler\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_arg as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    if ((*ctxt)._private).is_null() {
        pyCtxt = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlParserCtxtPyCtxt>() as libc::c_ulong)
            as xmlParserCtxtPyCtxtPtr;
        if pyCtxt.is_null() {
            py_retval = libxml_intWrap(-(1 as libc::c_int));
            return py_retval;
        }
        memset(
            pyCtxt as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlParserCtxtPyCtxt>() as libc::c_ulong,
        );
        let ref mut fresh90 = (*ctxt)._private;
        *fresh90 = pyCtxt as *mut libc::c_void;
    } else {
        pyCtxt = (*ctxt)._private as xmlParserCtxtPyCtxtPtr;
    }
    if !((*pyCtxt).f).is_null() {
        let ref mut fresh91 = (*(*pyCtxt).f).ob_refcnt;
        *fresh91 -= 1;
        if !(*fresh91 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).f).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).f);
        }
    }
    if !pyobj_f.is_null() {
        let ref mut fresh92 = (*pyobj_f).ob_refcnt;
        *fresh92 += 1;
    }
    let ref mut fresh93 = (*pyCtxt).f;
    *fresh93 = pyobj_f;
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh94 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh94 -= 1;
        if !(*fresh94 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).arg);
        }
    }
    if !pyobj_arg.is_null() {
        let ref mut fresh95 = (*pyobj_arg).ob_refcnt;
        *fresh95 += 1;
    }
    let ref mut fresh96 = (*pyCtxt).arg;
    *fresh96 = pyobj_arg;
    if pyobj_f != &mut _Py_NoneStruct as *mut PyObject {
        let ref mut fresh97 = (*(*ctxt).sax).error;
        *fresh97 = Some(
            libxml_xmlParserCtxtErrorFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh98 = (*(*ctxt).sax).warning;
        *fresh98 = Some(
            libxml_xmlParserCtxtWarningFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh99 = (*ctxt).vctxt.error;
        *fresh99 = Some(
            libxml_xmlParserCtxtValidityErrorFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh100 = (*ctxt).vctxt.warning;
        *fresh100 = Some(
            libxml_xmlParserCtxtValidityWarningFuncHandler
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
    } else {
        let ref mut fresh101 = (*(*ctxt).sax).error;
        *fresh101 = Some(
            xmlParserError
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh102 = (*ctxt).vctxt.error;
        *fresh102 = Some(
            xmlParserValidityError
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh103 = (*(*ctxt).sax).warning;
        *fresh103 = Some(
            xmlParserWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
        let ref mut fresh104 = (*ctxt).vctxt.warning;
        *fresh104 = Some(
            xmlParserValidityWarning
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        );
    }
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlParserCtxtGetErrorHandler(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyCtxt: xmlParserCtxtPyCtxtPtr = 0 as *mut xmlParserCtxtPyCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserCtxtGetErrorHandler\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    py_retval = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    if !((*ctxt)._private).is_null() {
        pyCtxt = (*ctxt)._private as xmlParserCtxtPyCtxtPtr;
        PyTuple_SetItem(py_retval, 0 as libc::c_int as Py_ssize_t, (*pyCtxt).f);
        if !((*pyCtxt).f).is_null() {
            let ref mut fresh105 = (*(*pyCtxt).f).ob_refcnt;
            *fresh105 += 1;
        }
        PyTuple_SetItem(py_retval, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
        if !((*pyCtxt).arg).is_null() {
            let ref mut fresh106 = (*(*pyCtxt).arg).ob_refcnt;
            *fresh106 += 1;
        }
    } else {
        PyTuple_SetItem(py_retval, 0 as libc::c_int as Py_ssize_t, &mut _Py_NoneStruct);
        if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
            let ref mut fresh107 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
            *fresh107 += 1;
        }
        PyTuple_SetItem(py_retval, 1 as libc::c_int as Py_ssize_t, &mut _Py_NoneStruct);
        if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
            let ref mut fresh108 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
            *fresh108 += 1;
        }
    }
    return py_retval;
}
unsafe extern "C" fn libxml_xmlFreeParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlParserCtxtPyCtxtPtr = 0 as *mut xmlParserCtxtPyCtxt;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    if !ctxt.is_null() {
        pyCtxt = (*ctxt)._private as xmlParserCtxtPyCtxtPtr;
        if !pyCtxt.is_null() {
            if !((*pyCtxt).f).is_null() {
                let ref mut fresh109 = (*(*pyCtxt).f).ob_refcnt;
                *fresh109 -= 1;
                if !(*fresh109 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).f).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).f);
                }
            }
            if !((*pyCtxt).arg).is_null() {
                let ref mut fresh110 = (*(*pyCtxt).arg).ob_refcnt;
                *fresh110 -= 1;
                if !(*fresh110 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).arg);
                }
            }
            xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
        }
        xmlFreeParserCtxt(ctxt);
    }
    let ref mut fresh111 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh111 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn libxml_xmlValidCtxtGenericErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut severity: libc::c_int,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlValidCtxtPyCtxtPtr = 0 as *mut xmlValidCtxtPyCtxt;
    pyCtxt = ctx as xmlValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh112 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh112 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).error,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh113 = (*list).ob_refcnt;
        *fresh113 -= 1;
        if !(*fresh113 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh114 = (*result).ob_refcnt;
        *fresh114 -= 1;
        if !(*fresh114 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlValidCtxtGenericWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut severity: libc::c_int,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlValidCtxtPyCtxtPtr = 0 as *mut xmlValidCtxtPyCtxt;
    pyCtxt = ctx as xmlValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh115 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh115 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).warn,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh116 = (*list).ob_refcnt;
        *fresh116 -= 1;
        if !(*fresh116 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh117 = (*result).ob_refcnt;
        *fresh117 -= 1;
        if !(*fresh117 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlValidCtxtErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlValidCtxtGenericErrorFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_VALIDITY_ERROR as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlValidCtxtWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlValidCtxtGenericWarningFuncHandler(
        ctx,
        XML_PARSER_SEVERITY_VALIDITY_WARNING as libc::c_int,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlSetValidErrors(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_error: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_warn: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_arg: *mut PyObject = &mut _Py_NoneStruct;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyCtxt: xmlValidCtxtPyCtxtPtr = 0 as *mut xmlValidCtxtPyCtxt;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO|O:xmlSetValidErrors\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctx as *mut *mut PyObject,
        &mut pyobj_error as *mut *mut PyObject,
        &mut pyobj_warn as *mut *mut PyObject,
        &mut pyobj_arg as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctx as *mut PyValidCtxt_Object)).obj
    };
    pyCtxt = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlValidCtxtPyCtxt>() as libc::c_ulong)
        as xmlValidCtxtPyCtxtPtr;
    if pyCtxt.is_null() {
        py_retval = libxml_intWrap(-(1 as libc::c_int));
        return py_retval;
    }
    memset(
        pyCtxt as *mut libc::c_void,
        0 as libc::c_int,
        ::std::mem::size_of::<xmlValidCtxtPyCtxt>() as libc::c_ulong,
    );
    if !((*pyCtxt).error).is_null() {
        let ref mut fresh118 = (*(*pyCtxt).error).ob_refcnt;
        *fresh118 -= 1;
        if !(*fresh118 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).error);
        }
    }
    if !pyobj_error.is_null() {
        let ref mut fresh119 = (*pyobj_error).ob_refcnt;
        *fresh119 += 1;
    }
    let ref mut fresh120 = (*pyCtxt).error;
    *fresh120 = pyobj_error;
    if !((*pyCtxt).warn).is_null() {
        let ref mut fresh121 = (*(*pyCtxt).warn).ob_refcnt;
        *fresh121 -= 1;
        if !(*fresh121 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).warn);
        }
    }
    if !pyobj_warn.is_null() {
        let ref mut fresh122 = (*pyobj_warn).ob_refcnt;
        *fresh122 += 1;
    }
    let ref mut fresh123 = (*pyCtxt).warn;
    *fresh123 = pyobj_warn;
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh124 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh124 -= 1;
        if !(*fresh124 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).arg);
        }
    }
    if !pyobj_arg.is_null() {
        let ref mut fresh125 = (*pyobj_arg).ob_refcnt;
        *fresh125 += 1;
    }
    let ref mut fresh126 = (*pyCtxt).arg;
    *fresh126 = pyobj_arg;
    let ref mut fresh127 = (*ctxt).error;
    *fresh127 = Some(
        libxml_xmlValidCtxtErrorFuncHandler
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh128 = (*ctxt).warning;
    *fresh128 = Some(
        libxml_xmlValidCtxtWarningFuncHandler
            as unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char, ...) -> (),
    );
    let ref mut fresh129 = (*ctxt).userData;
    *fresh129 = pyCtxt as *mut libc::c_void;
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlFreeValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyCtxt: xmlValidCtxtPyCtxtPtr = 0 as *mut xmlValidCtxtPyCtxt;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeValidCtxt\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_cur as *mut PyValidCtxt_Object)).obj
    };
    pyCtxt = (*cur).userData as xmlValidCtxtPyCtxtPtr;
    if !pyCtxt.is_null() {
        if !((*pyCtxt).error).is_null() {
            let ref mut fresh130 = (*(*pyCtxt).error).ob_refcnt;
            *fresh130 -= 1;
            if !(*fresh130 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")((*pyCtxt).error);
            }
        }
        if !((*pyCtxt).warn).is_null() {
            let ref mut fresh131 = (*(*pyCtxt).warn).ob_refcnt;
            *fresh131 -= 1;
            if !(*fresh131 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")((*pyCtxt).warn);
            }
        }
        if !((*pyCtxt).arg).is_null() {
            let ref mut fresh132 = (*(*pyCtxt).arg).ob_refcnt;
            *fresh132 -= 1;
            if !(*fresh132 != 0 as libc::c_int as libc::c_long) {
                (Some(
                    ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                        .expect("non-null function pointer"),
                ))
                    .expect("non-null function pointer")((*pyCtxt).arg);
            }
        }
        xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
    }
    xmlFreeValidCtxt(cur);
    let ref mut fresh133 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh133 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn libxml_xmlTextReaderErrorCallback(
    mut arg: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut severity: libc::c_int,
    mut locator: xmlTextReaderLocatorPtr,
) {
    let mut pyCtxt: *mut xmlTextReaderPyCtxt = arg as *mut xmlTextReaderPyCtxt;
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    list = PyTuple_New(4 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh134 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh134 += 1;
    }
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, libxml_charPtrConstWrap(msg));
    PyTuple_SetItem(list, 2 as libc::c_int as Py_ssize_t, libxml_intWrap(severity));
    PyTuple_SetItem(
        list,
        3 as libc::c_int as Py_ssize_t,
        libxml_xmlTextReaderLocatorPtrWrap(locator),
    );
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).f,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh135 = (*list).ob_refcnt;
        *fresh135 -= 1;
        if !(*fresh135 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh136 = (*result).ob_refcnt;
        *fresh136 -= 1;
        if !(*fresh136 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlTextReaderSetErrorHandler(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyCtxt: xmlTextReaderPyCtxtPtr = 0 as *mut xmlTextReaderPyCtxt;
    let mut f: xmlTextReaderErrorFunc = None;
    let mut arg: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_arg: *mut PyObject = 0 as *mut PyObject;
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlTextReaderSetErrorHandler\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_arg as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    xmlTextReaderGetErrorHandler(reader, &mut f, &mut arg);
    if !arg.is_null() {
        if f
            == ::std::mem::transmute::<
                Option::<
                    unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        libc::c_int,
                        xmlTextReaderLocatorPtr,
                    ) -> (),
                >,
                xmlTextReaderErrorFunc,
            >(
                Some(
                    libxml_xmlTextReaderErrorCallback
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            libc::c_int,
                            xmlTextReaderLocatorPtr,
                        ) -> (),
                ),
            )
        {
            pyCtxt = arg as xmlTextReaderPyCtxtPtr;
            if !((*pyCtxt).f).is_null() {
                let ref mut fresh137 = (*(*pyCtxt).f).ob_refcnt;
                *fresh137 -= 1;
                if !(*fresh137 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).f).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).f);
                }
            }
            if !((*pyCtxt).arg).is_null() {
                let ref mut fresh138 = (*(*pyCtxt).arg).ob_refcnt;
                *fresh138 -= 1;
                if !(*fresh138 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).arg);
                }
            }
            xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
        } else {
            py_retval = libxml_intWrap(-(1 as libc::c_int));
            return py_retval;
        }
    }
    xmlTextReaderSetErrorHandler(reader, None, 0 as *mut libc::c_void);
    if pyobj_f != &mut _Py_NoneStruct as *mut PyObject {
        pyCtxt = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlTextReaderPyCtxt>() as libc::c_ulong)
            as xmlTextReaderPyCtxtPtr;
        if pyCtxt.is_null() {
            py_retval = libxml_intWrap(-(1 as libc::c_int));
            return py_retval;
        }
        if !pyobj_f.is_null() {
            let ref mut fresh139 = (*pyobj_f).ob_refcnt;
            *fresh139 += 1;
        }
        let ref mut fresh140 = (*pyCtxt).f;
        *fresh140 = pyobj_f;
        if !pyobj_arg.is_null() {
            let ref mut fresh141 = (*pyobj_arg).ob_refcnt;
            *fresh141 += 1;
        }
        let ref mut fresh142 = (*pyCtxt).arg;
        *fresh142 = pyobj_arg;
        xmlTextReaderSetErrorHandler(
            reader,
            ::std::mem::transmute::<
                Option::<
                    unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        libc::c_int,
                        xmlTextReaderLocatorPtr,
                    ) -> (),
                >,
                xmlTextReaderErrorFunc,
            >(
                Some(
                    libxml_xmlTextReaderErrorCallback
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            libc::c_int,
                            xmlTextReaderLocatorPtr,
                        ) -> (),
                ),
            ),
            pyCtxt as *mut libc::c_void,
        );
    }
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlTextReaderGetErrorHandler(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyCtxt: xmlTextReaderPyCtxtPtr = 0 as *mut xmlTextReaderPyCtxt;
    let mut f: xmlTextReaderErrorFunc = None;
    let mut arg: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderSetErrorHandler\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    xmlTextReaderGetErrorHandler(reader, &mut f, &mut arg);
    py_retval = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    if f
        == ::std::mem::transmute::<
            Option::<
                unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    libc::c_int,
                    xmlTextReaderLocatorPtr,
                ) -> (),
            >,
            xmlTextReaderErrorFunc,
        >(
            Some(
                libxml_xmlTextReaderErrorCallback
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        libc::c_int,
                        xmlTextReaderLocatorPtr,
                    ) -> (),
            ),
        )
    {
        pyCtxt = arg as xmlTextReaderPyCtxtPtr;
        PyTuple_SetItem(py_retval, 0 as libc::c_int as Py_ssize_t, (*pyCtxt).f);
        if !((*pyCtxt).f).is_null() {
            let ref mut fresh143 = (*(*pyCtxt).f).ob_refcnt;
            *fresh143 += 1;
        }
        PyTuple_SetItem(py_retval, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
        if !((*pyCtxt).arg).is_null() {
            let ref mut fresh144 = (*(*pyCtxt).arg).ob_refcnt;
            *fresh144 += 1;
        }
    } else {
        PyTuple_SetItem(py_retval, 0 as libc::c_int as Py_ssize_t, &mut _Py_NoneStruct);
        if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
            let ref mut fresh145 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
            *fresh145 += 1;
        }
        PyTuple_SetItem(py_retval, 1 as libc::c_int as Py_ssize_t, &mut _Py_NoneStruct);
        if !(&mut _Py_NoneStruct as *mut PyObject).is_null() {
            let ref mut fresh146 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
            *fresh146 += 1;
        }
    }
    return py_retval;
}
unsafe extern "C" fn libxml_xmlFreeTextReader(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlTextReaderPyCtxtPtr = 0 as *mut xmlTextReaderPyCtxt;
    let mut f: xmlTextReaderErrorFunc = None;
    let mut arg: *mut libc::c_void = 0 as *mut libc::c_void;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeTextReader\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    if !((*pyobj_reader).ob_type == &mut PyCapsule_Type as *mut PyTypeObject) {
        let ref mut fresh147 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh147 += 1;
        return &mut _Py_NoneStruct;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    if reader.is_null() {
        let ref mut fresh148 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh148 += 1;
        return &mut _Py_NoneStruct;
    }
    xmlTextReaderGetErrorHandler(reader, &mut f, &mut arg);
    if !arg.is_null() {
        if f
            == ::std::mem::transmute::<
                Option::<
                    unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const libc::c_char,
                        libc::c_int,
                        xmlTextReaderLocatorPtr,
                    ) -> (),
                >,
                xmlTextReaderErrorFunc,
            >(
                Some(
                    libxml_xmlTextReaderErrorCallback
                        as unsafe extern "C" fn(
                            *mut libc::c_void,
                            *const libc::c_char,
                            libc::c_int,
                            xmlTextReaderLocatorPtr,
                        ) -> (),
                ),
            )
        {
            pyCtxt = arg as xmlTextReaderPyCtxtPtr;
            if !((*pyCtxt).f).is_null() {
                let ref mut fresh149 = (*(*pyCtxt).f).ob_refcnt;
                *fresh149 -= 1;
                if !(*fresh149 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).f).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).f);
                }
            }
            if !((*pyCtxt).arg).is_null() {
                let ref mut fresh150 = (*(*pyCtxt).arg).ob_refcnt;
                *fresh150 -= 1;
                if !(*fresh150 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).arg);
                }
            }
            xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
        }
    }
    xmlFreeTextReader(reader);
    let ref mut fresh151 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh151 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn libxml_xmlXPathFuncCallback(
    mut ctxt: xmlXPathParserContextPtr,
    mut nargs: libc::c_int,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut obj: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut rctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut current_function: *mut PyObject = 0 as *mut PyObject;
    let mut name: *const xmlChar = 0 as *const xmlChar;
    let mut ns_uri: *const xmlChar = 0 as *const xmlChar;
    let mut i: libc::c_int = 0;
    if ctxt.is_null() {
        return;
    }
    rctxt = (*ctxt).context;
    if rctxt.is_null() {
        return;
    }
    name = (*rctxt).function;
    ns_uri = (*rctxt).functionURI;
    i = 0 as libc::c_int;
    while i < libxml_xpathCallbacksNb {
        if xmlStrEqual(
            name,
            (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).name,
        ) != 0
            && xmlStrEqual(
                ns_uri,
                (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).ns_uri,
            ) != 0
        {
            current_function = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .function;
        }
        i += 1;
    }
    if current_function.is_null() {
        printf(
            b"libxml_xmlXPathFuncCallback: internal error %s not found !\n\0"
                as *const u8 as *const libc::c_char,
            name,
        );
        return;
    }
    list = PyTuple_New((nargs + 1 as libc::c_int) as Py_ssize_t);
    PyTuple_SetItem(
        list,
        0 as libc::c_int as Py_ssize_t,
        libxml_xmlXPathParserContextPtrWrap(ctxt),
    );
    i = nargs - 1 as libc::c_int;
    while i >= 0 as libc::c_int {
        obj = valuePop(ctxt);
        cur = libxml_xmlXPathObjectPtrWrap(obj);
        PyTuple_SetItem(list, (i + 1 as libc::c_int) as Py_ssize_t, cur);
        i -= 1;
    }
    result = PyEval_CallObjectWithKeywords(
        current_function,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    let ref mut fresh152 = (*list).ob_refcnt;
    *fresh152 -= 1;
    if !(*fresh152 != 0 as libc::c_int as libc::c_long) {
        (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
            .expect("non-null function pointer")(list);
    }
    obj = libxml_xmlXPathObjectPtrConvert(result);
    valuePush(ctxt, obj);
}
unsafe extern "C" fn libxml_xmlXPathFuncLookupFunc(
    mut ctxt: *mut libc::c_void,
    mut name: *const xmlChar,
    mut ns_uri: *const xmlChar,
) -> xmlXPathFunction {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < libxml_xpathCallbacksNb {
        if ctxt
            == (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).ctx
                as *mut libc::c_void
            && xmlStrEqual(
                name,
                (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).name,
            ) != 0
            && xmlStrEqual(
                ns_uri,
                (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).ns_uri,
            ) != 0
        {
            return Some(
                libxml_xmlXPathFuncCallback
                    as unsafe extern "C" fn(xmlXPathParserContextPtr, libc::c_int) -> (),
            );
        }
        i += 1;
    }
    return None;
}
unsafe extern "C" fn libxml_xpathCallbacksInitialize() {
    let mut i: libc::c_int = 0;
    if libxml_xpathCallbacksInitialized != 0 as libc::c_int {
        return;
    }
    libxml_xpathCallbacks = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (libxml_xpathCallbacksAllocd as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<libxml_xpathCallback>() as libc::c_ulong),
    ) as *mut libxml_xpathCallbackArray;
    i = 0 as libc::c_int;
    while i < libxml_xpathCallbacksAllocd {
        let ref mut fresh153 = (*(*libxml_xpathCallbacks)
            .as_mut_ptr()
            .offset(i as isize))
            .ctx;
        *fresh153 = 0 as xmlXPathContextPtr;
        let ref mut fresh154 = (*(*libxml_xpathCallbacks)
            .as_mut_ptr()
            .offset(i as isize))
            .name;
        *fresh154 = 0 as *mut xmlChar;
        let ref mut fresh155 = (*(*libxml_xpathCallbacks)
            .as_mut_ptr()
            .offset(i as isize))
            .ns_uri;
        *fresh155 = 0 as *mut xmlChar;
        let ref mut fresh156 = (*(*libxml_xpathCallbacks)
            .as_mut_ptr()
            .offset(i as isize))
            .function;
        *fresh156 = 0 as *mut PyObject;
        i += 1;
    }
    libxml_xpathCallbacksInitialized = 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterXPathFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut current_block: u64;
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0 as libc::c_int;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut i: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OszO:registerXPathFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctx as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut ns_uri as *mut *mut xmlChar,
        &mut pyobj_f as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj
    };
    if libxml_xpathCallbacksInitialized == 0 as libc::c_int {
        libxml_xpathCallbacksInitialize();
    }
    xmlXPathRegisterFuncLookup(
        ctx,
        Some(
            libxml_xmlXPathFuncLookupFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const xmlChar,
                    *const xmlChar,
                ) -> xmlXPathFunction,
        ),
        ctx as *mut libc::c_void,
    );
    if pyobj_ctx.is_null() || name.is_null() || pyobj_f.is_null() {
        py_retval = libxml_intWrap(-(1 as libc::c_int));
        return py_retval;
    }
    i = 0 as libc::c_int;
    loop {
        if !(i < libxml_xpathCallbacksNb) {
            current_block = 18377268871191777778;
            break;
        }
        if ctx == (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).ctx
            && xmlStrEqual(
                name,
                (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).name,
            ) != 0
            && xmlStrEqual(
                ns_uri,
                (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).ns_uri,
            ) != 0
        {
            if !pyobj_f.is_null() {
                let ref mut fresh157 = (*pyobj_f).ob_refcnt;
                *fresh157 += 1;
            }
            if !((*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize)).function)
                .is_null()
            {
                let ref mut fresh158 = (*(*(*libxml_xpathCallbacks)
                    .as_mut_ptr()
                    .offset(i as isize))
                    .function)
                    .ob_refcnt;
                *fresh158 -= 1;
                if !(*fresh158 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize))
                            .function)
                            .ob_type)
                            .tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect(
                            "non-null function pointer",
                        )(
                        (*(*libxml_xpathCallbacks).as_mut_ptr().offset(i as isize))
                            .function,
                    );
                }
            }
            let ref mut fresh159 = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .function;
            *fresh159 = pyobj_f;
            c_retval = 1 as libc::c_int;
            current_block = 4356395540054036081;
            break;
        } else {
            i += 1;
        }
    }
    match current_block {
        18377268871191777778 => {
            if libxml_xpathCallbacksNb >= libxml_xpathCallbacksAllocd {
                libxml_xpathCallbacksAllocd += 10 as libc::c_int;
                libxml_xpathCallbacks = xmlRealloc
                    .expect(
                        "non-null function pointer",
                    )(
                    libxml_xpathCallbacks as *mut libc::c_void,
                    (libxml_xpathCallbacksAllocd as libc::c_ulong)
                        .wrapping_mul(
                            ::std::mem::size_of::<libxml_xpathCallback>()
                                as libc::c_ulong,
                        ),
                ) as *mut libxml_xpathCallbackArray;
            }
            let fresh160 = libxml_xpathCallbacksNb;
            libxml_xpathCallbacksNb = libxml_xpathCallbacksNb + 1;
            i = fresh160;
            if !pyobj_f.is_null() {
                let ref mut fresh161 = (*pyobj_f).ob_refcnt;
                *fresh161 += 1;
            }
            let ref mut fresh162 = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .ctx;
            *fresh162 = ctx;
            let ref mut fresh163 = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .name;
            *fresh163 = xmlStrdup(name);
            let ref mut fresh164 = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .ns_uri;
            *fresh164 = xmlStrdup(ns_uri);
            let ref mut fresh165 = (*(*libxml_xpathCallbacks)
                .as_mut_ptr()
                .offset(i as isize))
                .function;
            *fresh165 = pyobj_f;
            c_retval = 1 as libc::c_int;
        }
        _ => {}
    }
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisterVariable(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0 as libc::c_int;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut val: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_value: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OszO:xpathRegisterVariable\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctx as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut ns_uri as *mut *mut xmlChar,
        &mut pyobj_value as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj
    };
    val = libxml_xmlXPathObjectPtrConvert(pyobj_value);
    c_retval = xmlXPathRegisterVariableNS(ctx, name, ns_uri, val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn libxml_name(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: *const xmlChar = 0 as *const xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:name\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        9 | 13 => {
            let mut doc: xmlDocPtr = cur as xmlDocPtr;
            res = (*doc).URL;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).name;
        }
        18 => {
            let mut ns: xmlNsPtr = cur as xmlNsPtr;
            res = (*ns).prefix;
        }
        _ => {
            res = (*cur).name;
        }
    }
    resultobj = libxml_constxmlCharPtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_doc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlDocPtr = 0 as *mut xmlDoc;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:doc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        9 | 13 => {
            res = 0 as xmlDocPtr;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).doc;
        }
        18 => {
            res = 0 as xmlDocPtr;
        }
        _ => {
            res = (*cur).doc;
        }
    }
    resultobj = libxml_xmlDocPtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_properties(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlAttrPtr = 0 as *mut xmlAttr;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:properties\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    if !cur.is_null()
        && (*cur).type_0 as libc::c_uint
            == XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        res = (*cur).properties;
    } else {
        res = 0 as xmlAttrPtr;
    }
    resultobj = libxml_xmlAttrPtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_next(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:next\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        9 | 13 => {
            res = 0 as xmlNodePtr;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).next as xmlNodePtr;
        }
        18 => {
            let mut ns: xmlNsPtr = cur as xmlNsPtr;
            res = (*ns).next as xmlNodePtr;
        }
        _ => {
            res = (*cur).next;
        }
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_prev(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:prev\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        9 | 13 => {
            res = 0 as xmlNodePtr;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).prev as xmlNodePtr;
        }
        18 => {
            res = 0 as xmlNodePtr;
        }
        _ => {
            res = (*cur).prev;
        }
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_children(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:children\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        1 | 5 | 6 | 7 | 8 | 9 | 13 | 14 => {
            res = (*cur).children;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).children;
        }
        _ => {
            res = 0 as xmlNodePtr;
        }
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_last(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:last\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        1 | 5 | 6 | 7 | 8 | 9 | 13 | 14 => {
            res = (*cur).last;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).last;
        }
        _ => {
            res = 0 as xmlNodePtr;
        }
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_parent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:parent\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    match (*cur).type_0 as libc::c_uint {
        9 | 13 => {
            res = 0 as xmlNodePtr;
        }
        2 => {
            let mut attr: xmlAttrPtr = cur as xmlAttrPtr;
            res = (*attr).parent;
        }
        17 | 18 | 19 | 20 => {
            res = 0 as xmlNodePtr;
        }
        _ => {
            res = (*cur).parent;
        }
    }
    resultobj = libxml_xmlNodePtrWrap(res);
    return resultobj;
}
unsafe extern "C" fn libxml_type(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut resultobj: *mut PyObject = 0 as *mut PyObject;
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut res: *const xmlChar = 0 as *const xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:last\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if obj == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(obj as *mut PyxmlNode_Object)).obj
    };
    if cur.is_null() {
        let ref mut fresh166 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh166 += 1;
        return &mut _Py_NoneStruct;
    }
    match (*cur).type_0 as libc::c_uint {
        1 => {
            res = b"element\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        2 => {
            res = b"attribute\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        3 => {
            res = b"text\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        4 => {
            res = b"cdata\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        5 => {
            res = b"entity_ref\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        6 => {
            res = b"entity\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        7 => {
            res = b"pi\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        8 => {
            res = b"comment\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        9 => {
            res = b"document_xml\0" as *const u8 as *const libc::c_char
                as *const xmlChar;
        }
        10 => {
            res = b"doctype\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        11 => {
            res = b"fragment\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        12 => {
            res = b"notation\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        13 => {
            res = b"document_html\0" as *const u8 as *const libc::c_char
                as *const xmlChar;
        }
        14 => {
            res = b"dtd\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        15 => {
            res = b"elem_decl\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        16 => {
            res = b"attribute_decl\0" as *const u8 as *const libc::c_char
                as *const xmlChar;
        }
        17 => {
            res = b"entity_decl\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        18 => {
            res = b"namespace\0" as *const u8 as *const libc::c_char as *const xmlChar;
        }
        19 => {
            res = b"xinclude_start\0" as *const u8 as *const libc::c_char
                as *const xmlChar;
        }
        20 => {
            res = b"xinclude_end\0" as *const u8 as *const libc::c_char
                as *const xmlChar;
        }
        _ => {}
    }
    resultobj = libxml_constxmlCharPtrWrap(res);
    return resultobj;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetNsDefs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetNsDefs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        let ref mut fresh167 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh167 += 1;
        return &mut _Py_NoneStruct;
    }
    c_retval = (*node).nsDef;
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeRemoveNsDef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut prev: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeRemoveNsDef\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut href as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = 0 as xmlNsPtr;
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
    {
        let ref mut fresh168 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh168 += 1;
        return &mut _Py_NoneStruct;
    }
    if href.is_null() {
        ns = (*node).nsDef;
        let ref mut fresh169 = (*node).nsDef;
        *fresh169 = 0 as *mut xmlNs;
        c_retval = 0 as xmlNsPtr;
    } else {
        prev = 0 as xmlNsPtr;
        ns = (*node).nsDef;
        while !ns.is_null() {
            if xmlStrEqual((*ns).href, href) != 0 {
                if !prev.is_null() {
                    let ref mut fresh170 = (*prev).next;
                    *fresh170 = (*ns).next;
                } else {
                    let ref mut fresh171 = (*node).nsDef;
                    *fresh171 = (*ns).next;
                }
                let ref mut fresh172 = (*ns).next;
                *fresh172 = 0 as *mut _xmlNs;
                c_retval = 0 as xmlNsPtr;
                break;
            } else {
                prev = ns;
                ns = (*ns).next;
            }
        }
    }
    c_retval = ns;
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    if node.is_null()
        || (*node).type_0 as libc::c_uint
            != XML_ELEMENT_NODE as libc::c_int as libc::c_uint
            && (*node).type_0 as libc::c_uint
                != XML_ATTRIBUTE_NODE as libc::c_int as libc::c_uint
    {
        let ref mut fresh173 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh173 += 1;
        return &mut _Py_NoneStruct;
    }
    c_retval = (*node).ns;
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
unsafe extern "C" fn libxml_serializeNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut encoding: *const libc::c_char = 0 as *const libc::c_char;
    let mut format: libc::c_int = 0;
    let mut ctxt: xmlSaveCtxtPtr = 0 as *mut xmlSaveCtxt;
    let mut buf: xmlBufferPtr = 0 as *mut xmlBuffer;
    let mut options: libc::c_int = 0 as libc::c_int;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:serializeNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut encoding as *mut *const libc::c_char,
        &mut format as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    if node.is_null() {
        let ref mut fresh174 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh174 += 1;
        return &mut _Py_NoneStruct;
    }
    if (*node).type_0 as libc::c_uint == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        doc = node as xmlDocPtr;
        node = 0 as xmlNodePtr;
    } else if (*node).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        doc = node as xmlDocPtr;
        node = 0 as xmlNodePtr;
    } else {
        if (*node).type_0 as libc::c_uint
            == XML_NAMESPACE_DECL as libc::c_int as libc::c_uint
        {
            doc = 0 as xmlDocPtr;
        } else {
            doc = (*node).doc;
        }
        if !(doc.is_null()
            || (*doc).type_0 as libc::c_uint
                == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint)
        {
            if (*doc).type_0 as libc::c_uint
                == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
            {} else {
                let ref mut fresh175 = (*(&mut _Py_NoneStruct as *mut PyObject))
                    .ob_refcnt;
                *fresh175 += 1;
                return &mut _Py_NoneStruct;
            }
        }
    }
    buf = xmlBufferCreate();
    if buf.is_null() {
        let ref mut fresh176 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh176 += 1;
        return &mut _Py_NoneStruct;
    }
    if format != 0 {
        options |= XML_SAVE_FORMAT as libc::c_int;
    }
    ctxt = xmlSaveToBuffer(buf, encoding, options);
    if ctxt.is_null() {
        xmlBufferFree(buf);
        let ref mut fresh177 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh177 += 1;
        return &mut _Py_NoneStruct;
    }
    if node.is_null() {
        xmlSaveDoc(ctxt, doc);
    } else {
        xmlSaveTree(ctxt, node);
    }
    xmlSaveClose(ctxt);
    c_retval = (*buf).content;
    let ref mut fresh178 = (*buf).content;
    *fresh178 = 0 as *mut xmlChar;
    xmlBufferFree(buf);
    py_retval = libxml_charPtrWrap(c_retval as *mut libc::c_char);
    return py_retval;
}
unsafe extern "C" fn libxml_saveNodeTo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_file: *mut PyObject = 0 as *mut PyObject;
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut encoding: *const libc::c_char = 0 as *const libc::c_char;
    let mut format: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut handler: xmlCharEncodingHandlerPtr = 0 as xmlCharEncodingHandlerPtr;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzi:serializeNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut py_file as *mut *mut PyObject,
        &mut encoding as *mut *const libc::c_char,
        &mut format as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    if node.is_null() {
        return PyLong_FromLong(-(1 as libc::c_int) as libc::c_long);
    }
    output = if py_file == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*py_file).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*py_file).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(py_file)
    } else {
        stdout
    };
    if output.is_null() {
        return PyLong_FromLong(-(1 as libc::c_int) as libc::c_long);
    }
    if (*node).type_0 as libc::c_uint == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        doc = node as xmlDocPtr;
    } else if (*node).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        doc = node as xmlDocPtr;
    } else {
        doc = (*node).doc;
    }
    if (*doc).type_0 as libc::c_uint
        == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        if encoding.is_null() {
            encoding = htmlGetMetaEncoding(doc) as *const libc::c_char;
        }
    }
    if !encoding.is_null() {
        handler = xmlFindCharEncodingHandler(encoding);
        if handler.is_null() {
            return PyLong_FromLong(-(1 as libc::c_int) as libc::c_long);
        }
    }
    if (*doc).type_0 as libc::c_uint
        == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        if handler.is_null() {
            handler = xmlFindCharEncodingHandler(
                b"HTML\0" as *const u8 as *const libc::c_char,
            );
        }
        if handler.is_null() {
            handler = xmlFindCharEncodingHandler(
                b"ascii\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    buf = xmlOutputBufferCreateFile(output, handler);
    if (*node).type_0 as libc::c_uint == XML_DOCUMENT_NODE as libc::c_int as libc::c_uint
    {
        len = xmlSaveFormatFileTo(buf, doc, encoding, format);
    } else if (*node).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        htmlDocContentDumpFormatOutput(buf, doc, encoding, format);
        len = xmlOutputBufferClose(buf);
    } else if (*doc).type_0 as libc::c_uint
            == XML_HTML_DOCUMENT_NODE as libc::c_int as libc::c_uint
        {
        htmlNodeDumpFormatOutput(buf, doc, node, encoding, format);
        len = xmlOutputBufferClose(buf);
    } else {
        xmlNodeDumpOutput(buf, doc, node, 0 as libc::c_int, format, encoding);
        len = xmlOutputBufferClose(buf);
    }
    return PyLong_FromLong(len as libc::c_long);
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s:xmlNewNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = xmlNewNode(0 as xmlNsPtr, name);
    if node.is_null() {
        let ref mut fresh179 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
        *fresh179 += 1;
        return &mut _Py_NoneStruct;
    }
    py_retval = libxml_xmlNodePtrWrap(node);
    return py_retval;
}
unsafe extern "C" fn libxml_addLocalCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os:addLocalCatalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut URL as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    if !URL.is_null() {
        let ref mut fresh180 = (*ctxt).catalogs;
        *fresh180 = xmlCatalogAddLocal((*ctxt).catalogs, URL);
    }
    let ref mut fresh181 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh181 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn libxml_xmlRelaxNGValidityGenericErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlRelaxNGValidCtxtPyCtxtPtr = 0 as *mut xmlRelaxNGValidCtxtPyCtxt;
    pyCtxt = ctx as xmlRelaxNGValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh182 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh182 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).error,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh183 = (*list).ob_refcnt;
        *fresh183 -= 1;
        if !(*fresh183 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh184 = (*result).ob_refcnt;
        *fresh184 -= 1;
        if !(*fresh184 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlRelaxNGValidityGenericWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlRelaxNGValidCtxtPyCtxtPtr = 0 as *mut xmlRelaxNGValidCtxtPyCtxt;
    pyCtxt = ctx as xmlRelaxNGValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh185 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh185 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).warn,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh186 = (*list).ob_refcnt;
        *fresh186 -= 1;
        if !(*fresh186 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh187 = (*result).ob_refcnt;
        *fresh187 -= 1;
        if !(*fresh187 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlRelaxNGValidityErrorFunc(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlRelaxNGValidityGenericErrorFuncHandler(
        ctx,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlRelaxNGValidityWarningFunc(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlRelaxNGValidityGenericWarningFuncHandler(
        ctx,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlRelaxNGSetValidErrors(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_error: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_warn: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_arg: *mut PyObject = &mut _Py_NoneStruct;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyCtxt: xmlRelaxNGValidCtxtPyCtxtPtr = 0 as *mut xmlRelaxNGValidCtxtPyCtxt;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO|O:xmlRelaxNGSetValidErrors\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctx as *mut *mut PyObject,
        &mut pyobj_error as *mut *mut PyObject,
        &mut pyobj_warn as *mut *mut PyObject,
        &mut pyobj_arg as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctx as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    if xmlRelaxNGGetValidErrors(
        ctxt,
        0 as *mut xmlRelaxNGValidityErrorFunc,
        0 as *mut xmlRelaxNGValidityWarningFunc,
        &mut pyCtxt as *mut xmlRelaxNGValidCtxtPyCtxtPtr as *mut *mut libc::c_void,
    ) == -(1 as libc::c_int)
    {
        py_retval = libxml_intWrap(-(1 as libc::c_int));
        return py_retval;
    }
    if pyCtxt.is_null() {
        pyCtxt = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlRelaxNGValidCtxtPyCtxt>() as libc::c_ulong)
            as xmlRelaxNGValidCtxtPyCtxtPtr;
        if pyCtxt.is_null() {
            py_retval = libxml_intWrap(-(1 as libc::c_int));
            return py_retval;
        }
        memset(
            pyCtxt as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlRelaxNGValidCtxtPyCtxt>() as libc::c_ulong,
        );
    }
    if !((*pyCtxt).error).is_null() {
        let ref mut fresh188 = (*(*pyCtxt).error).ob_refcnt;
        *fresh188 -= 1;
        if !(*fresh188 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).error);
        }
    }
    if !pyobj_error.is_null() {
        let ref mut fresh189 = (*pyobj_error).ob_refcnt;
        *fresh189 += 1;
    }
    let ref mut fresh190 = (*pyCtxt).error;
    *fresh190 = pyobj_error;
    if !((*pyCtxt).warn).is_null() {
        let ref mut fresh191 = (*(*pyCtxt).warn).ob_refcnt;
        *fresh191 -= 1;
        if !(*fresh191 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).warn);
        }
    }
    if !pyobj_warn.is_null() {
        let ref mut fresh192 = (*pyobj_warn).ob_refcnt;
        *fresh192 += 1;
    }
    let ref mut fresh193 = (*pyCtxt).warn;
    *fresh193 = pyobj_warn;
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh194 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh194 -= 1;
        if !(*fresh194 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).arg);
        }
    }
    if !pyobj_arg.is_null() {
        let ref mut fresh195 = (*pyobj_arg).ob_refcnt;
        *fresh195 += 1;
    }
    let ref mut fresh196 = (*pyCtxt).arg;
    *fresh196 = pyobj_arg;
    xmlRelaxNGSetValidErrors(
        ctxt,
        Some(
            libxml_xmlRelaxNGValidityErrorFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
        Some(
            libxml_xmlRelaxNGValidityWarningFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
        pyCtxt as *mut libc::c_void,
    );
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlRelaxNGFreeValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyCtxt: xmlRelaxNGValidCtxtPyCtxtPtr = 0 as *mut xmlRelaxNGValidCtxtPyCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGFreeValidCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    if xmlRelaxNGGetValidErrors(
        ctxt,
        0 as *mut xmlRelaxNGValidityErrorFunc,
        0 as *mut xmlRelaxNGValidityWarningFunc,
        &mut pyCtxt as *mut xmlRelaxNGValidCtxtPyCtxtPtr as *mut *mut libc::c_void,
    ) == 0 as libc::c_int
    {
        if !pyCtxt.is_null() {
            if !((*pyCtxt).error).is_null() {
                let ref mut fresh197 = (*(*pyCtxt).error).ob_refcnt;
                *fresh197 -= 1;
                if !(*fresh197 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).error);
                }
            }
            if !((*pyCtxt).warn).is_null() {
                let ref mut fresh198 = (*(*pyCtxt).warn).ob_refcnt;
                *fresh198 -= 1;
                if !(*fresh198 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).warn);
                }
            }
            if !((*pyCtxt).arg).is_null() {
                let ref mut fresh199 = (*(*pyCtxt).arg).ob_refcnt;
                *fresh199 -= 1;
                if !(*fresh199 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).arg);
                }
            }
            xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
        }
    }
    xmlRelaxNGFreeValidCtxt(ctxt);
    let ref mut fresh200 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh200 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn libxml_xmlSchemaValidityGenericErrorFuncHandler(
    mut ctx: *mut libc::c_void,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlSchemaValidCtxtPyCtxtPtr = 0 as *mut xmlSchemaValidCtxtPyCtxt;
    pyCtxt = ctx as xmlSchemaValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh201 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh201 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).error,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh202 = (*list).ob_refcnt;
        *fresh202 -= 1;
        if !(*fresh202 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh203 = (*result).ob_refcnt;
        *fresh203 -= 1;
        if !(*fresh203 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlSchemaValidityGenericWarningFuncHandler(
    mut ctx: *mut libc::c_void,
    mut str: *mut libc::c_char,
) {
    let mut list: *mut PyObject = 0 as *mut PyObject;
    let mut result: *mut PyObject = 0 as *mut PyObject;
    let mut pyCtxt: xmlSchemaValidCtxtPyCtxtPtr = 0 as *mut xmlSchemaValidCtxtPyCtxt;
    pyCtxt = ctx as xmlSchemaValidCtxtPyCtxtPtr;
    list = PyTuple_New(2 as libc::c_int as Py_ssize_t);
    PyTuple_SetItem(list, 0 as libc::c_int as Py_ssize_t, libxml_charPtrWrap(str));
    PyTuple_SetItem(list, 1 as libc::c_int as Py_ssize_t, (*pyCtxt).arg);
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh204 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh204 += 1;
    }
    result = PyEval_CallObjectWithKeywords(
        (*pyCtxt).warn,
        list,
        0 as *mut libc::c_void as *mut PyObject,
    );
    if result.is_null() {
        PyErr_Print();
    }
    if !list.is_null() {
        let ref mut fresh205 = (*list).ob_refcnt;
        *fresh205 -= 1;
        if !(*fresh205 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*list).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(list);
        }
    }
    if !result.is_null() {
        let ref mut fresh206 = (*result).ob_refcnt;
        *fresh206 -= 1;
        if !(*fresh206 != 0 as libc::c_int as libc::c_long) {
            (Some(((*(*result).ob_type).tp_dealloc).expect("non-null function pointer")))
                .expect("non-null function pointer")(result);
        }
    }
}
unsafe extern "C" fn libxml_xmlSchemaValidityErrorFunc(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlSchemaValidityGenericErrorFuncHandler(
        ctx,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
unsafe extern "C" fn libxml_xmlSchemaValidityWarningFunc(
    mut ctx: *mut libc::c_void,
    mut msg: *const libc::c_char,
    mut args: ...
) {
    let mut ap: ::std::ffi::VaListImpl;
    ap = args.clone();
    libxml_xmlSchemaValidityGenericWarningFuncHandler(
        ctx,
        libxml_buildMessage(msg, ap.as_va_list()),
    );
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaSetValidErrors(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_error: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_warn: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_arg: *mut PyObject = &mut _Py_NoneStruct;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyCtxt: xmlSchemaValidCtxtPyCtxtPtr = 0 as *mut xmlSchemaValidCtxtPyCtxt;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO|O:xmlSchemaSetValidErrors\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctx as *mut *mut PyObject,
        &mut pyobj_error as *mut *mut PyObject,
        &mut pyobj_warn as *mut *mut PyObject,
        &mut pyobj_arg as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctx as *mut PySchemaValidCtxt_Object)).obj
    };
    if xmlSchemaGetValidErrors(
        ctxt,
        0 as *mut xmlSchemaValidityErrorFunc,
        0 as *mut xmlSchemaValidityWarningFunc,
        &mut pyCtxt as *mut xmlSchemaValidCtxtPyCtxtPtr as *mut *mut libc::c_void,
    ) == -(1 as libc::c_int)
    {
        py_retval = libxml_intWrap(-(1 as libc::c_int));
        return py_retval;
    }
    if pyCtxt.is_null() {
        pyCtxt = xmlMalloc
            .expect(
                "non-null function pointer",
            )(::std::mem::size_of::<xmlSchemaValidCtxtPyCtxt>() as libc::c_ulong)
            as xmlSchemaValidCtxtPyCtxtPtr;
        if pyCtxt.is_null() {
            py_retval = libxml_intWrap(-(1 as libc::c_int));
            return py_retval;
        }
        memset(
            pyCtxt as *mut libc::c_void,
            0 as libc::c_int,
            ::std::mem::size_of::<xmlSchemaValidCtxtPyCtxt>() as libc::c_ulong,
        );
    }
    if !((*pyCtxt).error).is_null() {
        let ref mut fresh207 = (*(*pyCtxt).error).ob_refcnt;
        *fresh207 -= 1;
        if !(*fresh207 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).error);
        }
    }
    if !pyobj_error.is_null() {
        let ref mut fresh208 = (*pyobj_error).ob_refcnt;
        *fresh208 += 1;
    }
    let ref mut fresh209 = (*pyCtxt).error;
    *fresh209 = pyobj_error;
    if !((*pyCtxt).warn).is_null() {
        let ref mut fresh210 = (*(*pyCtxt).warn).ob_refcnt;
        *fresh210 -= 1;
        if !(*fresh210 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).warn);
        }
    }
    if !pyobj_warn.is_null() {
        let ref mut fresh211 = (*pyobj_warn).ob_refcnt;
        *fresh211 += 1;
    }
    let ref mut fresh212 = (*pyCtxt).warn;
    *fresh212 = pyobj_warn;
    if !((*pyCtxt).arg).is_null() {
        let ref mut fresh213 = (*(*pyCtxt).arg).ob_refcnt;
        *fresh213 -= 1;
        if !(*fresh213 != 0 as libc::c_int as libc::c_long) {
            (Some(
                ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                    .expect("non-null function pointer"),
            ))
                .expect("non-null function pointer")((*pyCtxt).arg);
        }
    }
    if !pyobj_arg.is_null() {
        let ref mut fresh214 = (*pyobj_arg).ob_refcnt;
        *fresh214 += 1;
    }
    let ref mut fresh215 = (*pyCtxt).arg;
    *fresh215 = pyobj_arg;
    xmlSchemaSetValidErrors(
        ctxt,
        Some(
            libxml_xmlSchemaValidityErrorFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
        Some(
            libxml_xmlSchemaValidityWarningFunc
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *const libc::c_char,
                    ...
                ) -> (),
        ),
        pyCtxt as *mut libc::c_void,
    );
    py_retval = libxml_intWrap(1 as libc::c_int);
    return py_retval;
}
unsafe extern "C" fn libxml_xmlSchemaFreeValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyCtxt: xmlSchemaValidCtxtPyCtxtPtr = 0 as *mut xmlSchemaValidCtxtPyCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaFreeValidCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    if xmlSchemaGetValidErrors(
        ctxt,
        0 as *mut xmlSchemaValidityErrorFunc,
        0 as *mut xmlSchemaValidityWarningFunc,
        &mut pyCtxt as *mut xmlSchemaValidCtxtPyCtxtPtr as *mut *mut libc::c_void,
    ) == 0 as libc::c_int
    {
        if !pyCtxt.is_null() {
            if !((*pyCtxt).error).is_null() {
                let ref mut fresh216 = (*(*pyCtxt).error).ob_refcnt;
                *fresh216 -= 1;
                if !(*fresh216 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).error).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).error);
                }
            }
            if !((*pyCtxt).warn).is_null() {
                let ref mut fresh217 = (*(*pyCtxt).warn).ob_refcnt;
                *fresh217 -= 1;
                if !(*fresh217 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).warn).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).warn);
                }
            }
            if !((*pyCtxt).arg).is_null() {
                let ref mut fresh218 = (*(*pyCtxt).arg).ob_refcnt;
                *fresh218 -= 1;
                if !(*fresh218 != 0 as libc::c_int as libc::c_long) {
                    (Some(
                        ((*(*(*pyCtxt).arg).ob_type).tp_dealloc)
                            .expect("non-null function pointer"),
                    ))
                        .expect("non-null function pointer")((*pyCtxt).arg);
                }
            }
            xmlFree.expect("non-null function pointer")(pyCtxt as *mut libc::c_void);
        }
    }
    xmlSchemaFreeValidCtxt(ctxt);
    let ref mut fresh219 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh219 += 1;
    return &mut _Py_NoneStruct;
}
unsafe extern "C" fn PyxmlNodeSet_Convert(
    mut py_nodeset: *mut PyObject,
    mut result: *mut xmlNodeSetPtr,
) -> libc::c_int {
    let mut nodeSet: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut is_tuple: libc::c_int = 0 as libc::c_int;
    if (*(*py_nodeset).ob_type).tp_flags & (1 as libc::c_long) << 26 as libc::c_int
        != 0 as libc::c_int as libc::c_long
    {
        is_tuple = 1 as libc::c_int;
    } else if (*(*py_nodeset).ob_type).tp_flags
            & (1 as libc::c_long) << 25 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        is_tuple = 0 as libc::c_int;
    } else if py_nodeset == &mut _Py_NoneStruct as *mut PyObject {
        *result = 0 as xmlNodeSetPtr;
        return 0 as libc::c_int;
    } else {
        PyErr_SetString(
            PyExc_TypeError,
            b"must be a tuple or list of nodes.\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    nodeSet = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlNodeSet>() as libc::c_ulong) as xmlNodeSetPtr;
    if nodeSet.is_null() {
        PyErr_SetString(PyExc_MemoryError, b"\0" as *const u8 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    (*nodeSet).nodeNr = 0 as libc::c_int;
    (*nodeSet)
        .nodeMax = (if is_tuple != 0 {
        (*(py_nodeset as *mut PyVarObject)).ob_size
    } else {
        (*(py_nodeset as *mut PyVarObject)).ob_size
    }) as libc::c_int;
    let ref mut fresh220 = (*nodeSet).nodeTab;
    *fresh220 = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        ((*nodeSet).nodeMax as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as libc::c_ulong),
    ) as *mut xmlNodePtr;
    if ((*nodeSet).nodeTab).is_null() {
        xmlFree.expect("non-null function pointer")(nodeSet as *mut libc::c_void);
        PyErr_SetString(PyExc_MemoryError, b"\0" as *const u8 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    memset(
        (*nodeSet).nodeTab as *mut libc::c_void,
        0 as libc::c_int,
        ((*nodeSet).nodeMax as libc::c_ulong)
            .wrapping_mul(::std::mem::size_of::<xmlNodePtr>() as libc::c_ulong),
    );
    let mut idx: libc::c_int = 0;
    idx = 0 as libc::c_int;
    while idx < (*nodeSet).nodeMax {
        let mut pynode: xmlNodePtr = if (if is_tuple != 0 {
            *((*(py_nodeset as *mut PyTupleObject)).ob_item)
                .as_mut_ptr()
                .offset(idx as isize)
        } else {
            *((*(py_nodeset as *mut PyListObject)).ob_item).offset(idx as isize)
        }) == &mut _Py_NoneStruct as *mut PyObject
        {
            0 as xmlNodePtr
        } else {
            (*((if is_tuple != 0 {
                *((*(py_nodeset as *mut PyTupleObject)).ob_item)
                    .as_mut_ptr()
                    .offset(idx as isize)
            } else {
                *((*(py_nodeset as *mut PyListObject)).ob_item).offset(idx as isize)
            }) as *mut PyxmlNode_Object))
                .obj
        };
        if !pynode.is_null() {
            let ref mut fresh221 = (*nodeSet).nodeNr;
            let fresh222 = *fresh221;
            *fresh221 = *fresh221 + 1;
            let ref mut fresh223 = *((*nodeSet).nodeTab).offset(fresh222 as isize);
            *fresh223 = pynode;
        }
        idx += 1;
    }
    *result = nodeSet;
    return 0 as libc::c_int;
}
unsafe extern "C" fn PystringSet_Convert(
    mut py_strings: *mut PyObject,
    mut result: *mut *mut *mut xmlChar,
) -> libc::c_int {
    let mut strings: *mut *mut xmlChar = 0 as *mut *mut xmlChar;
    let mut is_tuple: libc::c_int = 0 as libc::c_int;
    let mut count: libc::c_int = 0;
    let mut init_index: libc::c_int = 0 as libc::c_int;
    if (*(*py_strings).ob_type).tp_flags & (1 as libc::c_long) << 26 as libc::c_int
        != 0 as libc::c_int as libc::c_long
    {
        is_tuple = 1 as libc::c_int;
    } else if (*(*py_strings).ob_type).tp_flags
            & (1 as libc::c_long) << 25 as libc::c_int
            != 0 as libc::c_int as libc::c_long
        {
        is_tuple = 0 as libc::c_int;
    } else if py_strings == &mut _Py_NoneStruct as *mut PyObject {
        *result = 0 as *mut *mut xmlChar;
        return 0 as libc::c_int;
    } else {
        PyErr_SetString(
            PyExc_TypeError,
            b"must be a tuple or list of strings.\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    count = (if is_tuple != 0 {
        (*(py_strings as *mut PyVarObject)).ob_size
    } else {
        (*(py_strings as *mut PyVarObject)).ob_size
    }) as libc::c_int;
    strings = xmlMalloc
        .expect(
            "non-null function pointer",
        )(
        (::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong)
            .wrapping_mul(count as libc::c_ulong),
    ) as *mut *mut xmlChar;
    if strings.is_null() {
        PyErr_SetString(PyExc_MemoryError, b"\0" as *const u8 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    memset(
        strings as *mut libc::c_void,
        0 as libc::c_int,
        (::std::mem::size_of::<*mut xmlChar>() as libc::c_ulong)
            .wrapping_mul(count as libc::c_ulong),
    );
    let mut idx: libc::c_int = 0;
    idx = 0 as libc::c_int;
    while idx < count {
        let mut s: *mut libc::c_char = PyString_AsString(
            if is_tuple != 0 {
                *((*(py_strings as *mut PyTupleObject)).ob_item)
                    .as_mut_ptr()
                    .offset(idx as isize)
            } else {
                *((*(py_strings as *mut PyListObject)).ob_item).offset(idx as isize)
            },
        );
        if !s.is_null() {
            let fresh224 = init_index;
            init_index = init_index + 1;
            let ref mut fresh225 = *strings.offset(fresh224 as isize);
            *fresh225 = s as *mut xmlChar;
        } else {
            xmlFree.expect("non-null function pointer")(strings as *mut libc::c_void);
            PyErr_SetString(
                PyExc_TypeError,
                b"must be a tuple or list of strings.\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        idx += 1;
    }
    *result = strings;
    return 0 as libc::c_int;
}
unsafe extern "C" fn libxml_C14NDocDumpMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_nodes: *mut PyObject = 0 as *mut PyObject;
    let mut exclusive: libc::c_int = 0;
    let mut pyobj_prefixes: *mut PyObject = 0 as *mut PyObject;
    let mut with_comments: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut nodes: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut prefixes: *mut *mut xmlChar = 0 as *mut *mut xmlChar;
    let mut doc_txt: *mut xmlChar = 0 as *mut xmlChar;
    let mut result: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOiOi:C14NDocDumpMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_nodes as *mut *mut PyObject,
        &mut exclusive as *mut libc::c_int,
        &mut pyobj_prefixes as *mut *mut PyObject,
        &mut with_comments as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    if doc.is_null() {
        PyErr_SetString(
            PyExc_TypeError,
            b"bad document.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    result = PyxmlNodeSet_Convert(pyobj_nodes, &mut nodes);
    if result < 0 as libc::c_int {
        return 0 as *mut PyObject;
    }
    if exclusive != 0 {
        result = PystringSet_Convert(pyobj_prefixes, &mut prefixes);
        if result < 0 as libc::c_int {
            if !nodes.is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*nodes).nodeTab as *mut libc::c_void);
                xmlFree.expect("non-null function pointer")(nodes as *mut libc::c_void);
            }
            return 0 as *mut PyObject;
        }
    }
    result = xmlC14NDocDumpMemory(
        doc,
        nodes,
        exclusive,
        prefixes,
        with_comments,
        &mut doc_txt,
    );
    if !nodes.is_null() {
        xmlFree
            .expect("non-null function pointer")((*nodes).nodeTab as *mut libc::c_void);
        xmlFree.expect("non-null function pointer")(nodes as *mut libc::c_void);
    }
    if !prefixes.is_null() {
        let mut idx: *mut *mut xmlChar = prefixes;
        while !(*idx).is_null() {
            let fresh226 = idx;
            idx = idx.offset(1);
            xmlFree.expect("non-null function pointer")(*fresh226 as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(prefixes as *mut libc::c_void);
    }
    if result < 0 as libc::c_int {
        PyErr_SetString(
            PyExc_Exception,
            b"libxml2 xmlC14NDocDumpMemory failure.\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    } else {
        py_retval = PyString_FromStringAndSize(
            doc_txt as *const libc::c_char,
            result as Py_ssize_t,
        );
        xmlFree.expect("non-null function pointer")(doc_txt as *mut libc::c_void);
        return py_retval;
    };
}
unsafe extern "C" fn libxml_C14NDocSaveTo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut py_file: *mut PyObject = 0 as *mut PyObject;
    let mut pyobj_nodes: *mut PyObject = 0 as *mut PyObject;
    let mut exclusive: libc::c_int = 0;
    let mut pyobj_prefixes: *mut PyObject = 0 as *mut PyObject;
    let mut with_comments: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut nodes: xmlNodeSetPtr = 0 as *mut xmlNodeSet;
    let mut prefixes: *mut *mut xmlChar = 0 as *mut *mut xmlChar;
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut result: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOiOiO:C14NDocSaveTo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_nodes as *mut *mut PyObject,
        &mut exclusive as *mut libc::c_int,
        &mut pyobj_prefixes as *mut *mut PyObject,
        &mut with_comments as *mut libc::c_int,
        &mut py_file as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    if doc.is_null() {
        PyErr_SetString(
            PyExc_TypeError,
            b"bad document.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    output = if py_file == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*py_file).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*py_file).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(py_file)
    } else {
        stdout
    };
    if output.is_null() {
        PyErr_SetString(
            PyExc_TypeError,
            b"bad file.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    }
    buf = xmlOutputBufferCreateFile(output, 0 as xmlCharEncodingHandlerPtr);
    result = PyxmlNodeSet_Convert(pyobj_nodes, &mut nodes);
    if result < 0 as libc::c_int {
        xmlOutputBufferClose(buf);
        return 0 as *mut PyObject;
    }
    if exclusive != 0 {
        result = PystringSet_Convert(pyobj_prefixes, &mut prefixes);
        if result < 0 as libc::c_int {
            if !nodes.is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*nodes).nodeTab as *mut libc::c_void);
                xmlFree.expect("non-null function pointer")(nodes as *mut libc::c_void);
            }
            xmlOutputBufferClose(buf);
            return 0 as *mut PyObject;
        }
    }
    result = xmlC14NDocSaveTo(doc, nodes, exclusive, prefixes, with_comments, buf);
    if !nodes.is_null() {
        xmlFree
            .expect("non-null function pointer")((*nodes).nodeTab as *mut libc::c_void);
        xmlFree.expect("non-null function pointer")(nodes as *mut libc::c_void);
    }
    if !prefixes.is_null() {
        let mut idx: *mut *mut xmlChar = prefixes;
        while !(*idx).is_null() {
            let fresh227 = idx;
            idx = idx.offset(1);
            xmlFree.expect("non-null function pointer")(*fresh227 as *mut libc::c_void);
        }
        xmlFree.expect("non-null function pointer")(prefixes as *mut libc::c_void);
    }
    len = xmlOutputBufferClose(buf);
    if result < 0 as libc::c_int {
        PyErr_SetString(
            PyExc_Exception,
            b"libxml2 xmlC14NDocSaveTo failure.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut PyObject;
    } else {
        return PyLong_FromLong(len as libc::c_long)
    };
}
unsafe extern "C" fn libxml_getObjDesc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut obj: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:getObjDesc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut obj as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    str = PyCapsule_GetPointer(obj, PyCapsule_GetName(obj)) as *mut libc::c_char;
    return _Py_BuildValue_SizeT(
        b"s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        str,
    );
}
unsafe extern "C" fn libxml_compareNodesEqual(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_node1: *mut PyObject = 0 as *mut PyObject;
    let mut py_node2: *mut PyObject = 0 as *mut PyObject;
    let mut node1: xmlNodePtr = 0 as *mut xmlNode;
    let mut node2: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:compareNodesEqual\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut py_node1 as *mut *mut PyObject,
        &mut py_node2 as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node1 = if py_node1 == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(py_node1 as *mut PyxmlNode_Object)).obj
    };
    node2 = if py_node2 == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(py_node2 as *mut PyxmlNode_Object)).obj
    };
    if node1 == node2 {
        return _Py_BuildValue_SizeT(
            b"i\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            1 as libc::c_int,
        )
    } else {
        return _Py_BuildValue_SizeT(
            b"i\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            0 as libc::c_int,
        )
    };
}
unsafe extern "C" fn libxml_nodeHash(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_node1: *mut PyObject = 0 as *mut PyObject;
    let mut node1: xmlNodePtr = 0 as *mut xmlNode;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:nodeHash\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut py_node1 as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node1 = if py_node1 == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(py_node1 as *mut PyxmlNode_Object)).obj
    };
    return PyLong_FromVoidPtr(node1 as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn libxml_deprecationWarning(
    mut func: *const libc::c_char,
) -> libc::c_int {
    return PyErr_WarnEx(
        PyExc_PendingDeprecationWarning,
        func,
        1 as libc::c_int as Py_ssize_t,
    );
}
static mut libxmlMethods: [PyMethodDef; 926] = unsafe {
    [
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlAutoCloseTag\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlAutoCloseTag
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCreateFileParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCreateFileParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCreateMemoryParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCreateMemoryParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCreatePushParser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCreatePushParser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtReadDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtReadDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtReadFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtReadFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtReadFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtReadFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtReadMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtReadMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtReset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtReset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlCtxtUseOptions\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlCtxtUseOptions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlDefaultSAXHandlerInit\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlDefaultSAXHandlerInit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlDocContentDumpFormatOutput\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlDocContentDumpFormatOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlDocContentDumpOutput\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlDocContentDumpOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlDocDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlDocDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlFreeParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlFreeParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlGetMetaEncoding\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlGetMetaEncoding
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlHandleOmittedElem\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlHandleOmittedElem
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlInitAutoClose\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlInitAutoClose
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlIsAutoClosed\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlIsAutoClosed
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlIsBooleanAttr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlIsBooleanAttr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlIsScriptAttribute\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlIsScriptAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNewDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNewDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNewDocNoDtD\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNewDocNoDtD
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNewParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNewParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNodeDumpFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNodeDumpFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNodeDumpFileFormat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNodeDumpFileFormat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNodeDumpFormatOutput\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNodeDumpFormatOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlNodeDumpOutput\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlNodeDumpOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseCharRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseCharRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseChunk\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseChunk
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseDocument\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseDocument
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlParseFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlParseFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlReadDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlReadDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlReadFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlReadFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlReadFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlReadFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlReadMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlReadMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlSAXParseFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlSAXParseFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlSaveFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlSaveFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlSaveFileEnc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlSaveFileEnc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlSaveFileFormat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlSaveFileFormat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"htmlSetMetaEncoding\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_htmlSetMetaEncoding
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"namePop\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_namePop
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"namePush\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_namePush
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"nodePop\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_nodePop
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"nodePush\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_nodePush
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"valuePop\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_valuePop
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogAdd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogAdd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogRemove\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogRemove
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogResolve\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogResolve
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogResolvePublic\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogResolvePublic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogResolveSystem\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogResolveSystem
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlACatalogResolveURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlACatalogResolveURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddChildList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddChildList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddDocEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddDocEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddDtdEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddDtdEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddEncodingAlias\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddEncodingAlias
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddNextSibling\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddNextSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddPrevSibling\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddPrevSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlAddSibling\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlAddSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlBoolToText\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlBoolToText
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlBuildQName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlBuildQName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlBuildRelativeURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlBuildRelativeURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlBuildURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlBuildURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlByteConsumed\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlByteConsumed
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCanonicPath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCanonicPath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogAdd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogAdd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogCleanup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogConvert\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogConvert
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogGetPublic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogGetPublic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogGetSystem\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogGetSystem
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogIsEmpty\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogIsEmpty
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogRemove\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogRemove
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogResolve\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogResolve
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogResolvePublic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogResolvePublic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogResolveSystem\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogResolveSystem
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogResolveURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogResolveURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCatalogSetDebug\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCatalogSetDebug
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCharStrdup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCharStrdup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCharStrndup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCharStrndup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCheckFilename\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCheckFilename
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCheckLanguageID\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCheckLanguageID
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCheckUTF8\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCheckUTF8
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCheckVersion\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCheckVersion
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupCharEncodingHandlers\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupCharEncodingHandlers
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupEncodingAliases\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupEncodingAliases
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupGlobals\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupGlobals
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupInputCallbacks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupInputCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupOutputCallbacks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupOutputCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCleanupPredefinedEntities\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCleanupPredefinedEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlClearParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlClearParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlConvertSGMLCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlConvertSGMLCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyCharMultiByte\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyCharMultiByte
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyDtd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyDtd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyError\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyError
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyNamespace\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyNamespace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyNamespaceList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyNamespaceList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCopyPropList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCopyPropList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateDocParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateDocParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateEntityParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateEntityParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateFileParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateFileParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateInputBuffer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateInputBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateIntSubset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateIntSubset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateMemoryParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateMemoryParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateOutputBuffer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateOutputBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreatePushParser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreatePushParser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCreateURLParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateURLParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtReadDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtReadDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtReadFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtReadFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtReadFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtReadFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtReadMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtReadMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtReset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtReset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtResetPush\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtResetPush
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlCtxtUseOptions\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCtxtUseOptions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugCheckDocument\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugCheckDocument
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpAttr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpAttr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpAttrList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpAttrList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpDTD\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpDTD
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpDocument\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpDocument
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpDocumentHead\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpDocumentHead
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpEntities\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpOneNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpOneNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugDumpString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugDumpString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDebugMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDebugMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDecodeEntities\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDecodeEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDefaultSAXHandlerInit\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDefaultSAXHandlerInit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDelEncodingAlias\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDelEncodingAlias
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDictCleanup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDictCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocCopyNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocCopyNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocCopyNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocCopyNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocFormatDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocFormatDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocGetRootElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocGetRootElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDocSetRootElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDocSetRootElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlDumpMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlDumpMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlElemDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlElemDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlEncodeEntities\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlEncodeEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlEncodeEntitiesReentrant\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlEncodeEntitiesReentrant
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlEncodeSpecialChars\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlEncodeSpecialChars
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetCode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetCode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetDomain\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetDomain
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetLevel\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetLevel
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetLine\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetLine
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlErrorGetMessage\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlErrorGetMessage
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFileMatch\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFileMatch
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFirstElementChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFirstElementChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeDtd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeDtd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeNsList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeNsList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeParserInputBuffer\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeParserInputBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreePropList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreePropList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetCompressMode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetCompressMode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDocCompressMode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDocCompressMode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDocEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDocEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDtdAttrDesc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDtdAttrDesc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDtdElementDesc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDtdElementDesc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDtdEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDtdEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDtdQAttrDesc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDtdQAttrDesc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetDtdQElementDesc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetDtdQElementDesc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetEncodingAlias\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetEncodingAlias
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetID\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetID
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetIntSubset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetIntSubset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetLastChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetLastChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetLastError\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetLastError
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetLineNo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetLineNo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetNoNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetNoNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetNodePath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetNodePath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetParameterEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetParameterEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetPredefinedEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetPredefinedEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlGetProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlGetProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlHandleEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlHandleEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlHasNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlHasNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlHasProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlHasProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIOFTPMatch\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIOFTPMatch
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIOHTTPMatch\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIOHTTPMatch
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitCharEncodingHandlers\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitCharEncodingHandlers
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitGlobals\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitGlobals
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitParser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitParser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitializeCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitializeCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitializeDict\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitializeDict
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlInitializePredefinedEntities\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlInitializePredefinedEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsBaseChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsBaseChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsBlank\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsBlank
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsBlankNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsBlankNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsCombining\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsCombining
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsDigit\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsDigit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsExtender\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsExtender
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsID\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsID
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsIdeographic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsIdeographic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsLetter\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsLetter
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsMixedElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsMixedElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsPubidChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsPubidChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlIsXHTML\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlIsXHTML
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlKeepBlanksDefault\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlKeepBlanksDefault
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLastElementChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLastElementChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLineNumbersDefault\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLineNumbersDefault
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLoadACatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLoadACatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLoadCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLoadCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLoadCatalogs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLoadCatalogs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLoadSGMLSuperCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLoadSGMLSuperCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLsCountNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLsCountNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlLsOneNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlLsOneNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlMemoryUsed\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlMemoryUsed
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNamespaceParseNCName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNamespaceParseNCName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNamespaceParseNSDef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNamespaceParseNSDef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoFTPCleanup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoFTPCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoFTPInit\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoFTPInit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoFTPProxy\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoFTPProxy
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoFTPScanProxy\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoFTPScanProxy
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoHTTPCleanup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoHTTPCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoHTTPInit\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoHTTPInit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNanoHTTPScanProxy\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNanoHTTPScanProxy
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewCDataBlock\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewCDataBlock
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewCharRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewCharRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewComment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewComment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocComment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocComment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocFragment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocFragment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocNodeEatName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocNodeEatName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocPI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocPI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocRawNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocRawNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocText\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocText
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDocTextLen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDocTextLen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewDtd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewDtd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewGlobalNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewGlobalNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNodeEatName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNodeEatName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNsPropEatName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNsPropEatName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewPI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewPI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewReference\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewText\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewText
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewTextChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewTextChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewTextLen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewTextLen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewTextReader\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewTextReader
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewTextReaderFilename\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewTextReaderFilename
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNextChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNextChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNextElementSibling\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNextElementSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeAddContent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeAddContent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeAddContentLen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeAddContentLen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeDumpOutput\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeDumpOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetBase\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetBase
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetContent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetContent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetLang\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetLang
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetNsDefs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetNsDefs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeGetSpacePreserve\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeGetSpacePreserve
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeIsText\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeIsText
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeListGetRawString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeListGetRawString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeListGetString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeListGetString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetBase\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetBase
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetContent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetContent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetContentLen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetContentLen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetLang\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetLang
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeSetSpacePreserve\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeSetSpacePreserve
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNormalizeURIPath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNormalizeURIPath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNormalizeWindowsPath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNormalizeWindowsPath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlOutputBufferGetContent\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlOutputBufferGetContent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlOutputBufferWrite\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlOutputBufferWrite
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlOutputBufferWriteString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlOutputBufferWriteString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseAttValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseAttValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseAttributeListDecl\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseAttributeListDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseCDSect\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseCDSect
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseCatalogFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseCatalogFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseCharData\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseCharData
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseCharRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseCharRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseChunk\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseChunk
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseComment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseComment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseContent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseContent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseDTD\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseDTD
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseDocTypeDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseDocTypeDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseDocument\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseDocument
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseElementDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseElementDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEncName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEncName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEncodingDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEncodingDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEndTag\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEndTag
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEntity\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEntity
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEntityDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEntityDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseEntityRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseEntityRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseExtParsedEnt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseExtParsedEnt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseExternalSubset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseExternalSubset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseMarkupDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseMarkupDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseMisc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseMisc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseNamespace\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseNamespace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseNmtoken\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseNmtoken
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseNotationDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseNotationDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParsePEReference\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParsePEReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParsePI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParsePI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParsePITarget\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParsePITarget
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParsePubidLiteral\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParsePubidLiteral
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseQuotedString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseQuotedString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseReference\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseSDDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseSDDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseStartTag\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseStartTag
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseSystemLiteral\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseSystemLiteral
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseTextDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseTextDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseURIRaw\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseURIRaw
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseURIReference\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseURIReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseVersionInfo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseVersionInfo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseVersionNum\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseVersionNum
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParseXMLDecl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParseXMLDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserGetDirectory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserGetDirectory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserGetDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserGetDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserGetIsValid\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserGetIsValid
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserGetWellFormed\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserGetWellFormed
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserHandlePEReference\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserHandlePEReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserHandleReference\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserHandleReference
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserInputBufferGrow\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserInputBufferGrow
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserInputBufferPush\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserInputBufferPush
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserInputBufferRead\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserInputBufferRead
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserSetLineNumbers\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserSetLineNumbers
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserSetLoadSubset\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserSetLoadSubset
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserSetPedantic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserSetPedantic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserSetReplaceEntities\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserSetReplaceEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserSetValidate\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserSetValidate
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPathToURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPathToURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPedanticParserDefault\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPedanticParserDefault
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPopInput\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPopInput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPopOutputCallbacks\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPopOutputCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPreviousElementSibling\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPreviousElementSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPrintURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPrintURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlPythonCleanupParser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlPythonCleanupParser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReadDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReadDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReadFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReadFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReadFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReadFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReadMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReadMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderForDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderForDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderForFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderForFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderForFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderForFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderForMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderForMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderNewDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderNewDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderNewFd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderNewFd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderNewFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderNewFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderNewMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderNewMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderNewWalker\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderNewWalker
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReaderWalker\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReaderWalker
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReconciliateNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReconciliateNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRecoverDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRecoverDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRecoverFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRecoverFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRecoverMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRecoverMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegFreeRegexp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegFreeRegexp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegexpCompile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegexpCompile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegexpExec\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegexpExec
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegexpIsDeterminist\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegexpIsDeterminist
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegexpPrint\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegexpPrint
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterDefaultInputCallbacks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterDefaultInputCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterDefaultOutputCallbacks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterDefaultOutputCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterHTTPPostCallbacks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterHTTPPostCallbacks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterXPathFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterXPathFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGCleanupTypes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGCleanupTypes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGDumpTree\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGDumpTree
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGFree\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGFree
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGFreeParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGFreeParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGInitTypes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGInitTypes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGNewDocParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGNewDocParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGNewMemParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGNewMemParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGNewParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGNewParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGNewValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGNewValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGParse\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGParse
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGValidateDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGValidateDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGValidateFullElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGValidateFullElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGValidatePopElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGValidatePopElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGValidatePushCData\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGValidatePushCData
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGValidatePushElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGValidatePushElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxParserSetFlag\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxParserSetFlag
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRemoveID\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRemoveID
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRemoveProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRemoveProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRemoveRef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRemoveRef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlReplaceNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlReplaceNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlResetError\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlResetError
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlResetLastError\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlResetLastError
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSAXDefaultVersion\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSAXDefaultVersion
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSAXParseFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSAXParseFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFileEnc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFileEnc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFormatFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFormatFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFormatFileEnc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFormatFileEnc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveUri\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveUri
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlScanName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlScanName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaCleanupTypes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaCleanupTypes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaCollapseString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaCollapseString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaDump\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaDump
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaFree\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaFree
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaFreeParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaFreeParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaInitTypes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaInitTypes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaIsValid\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaIsValid
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaNewDocParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaNewDocParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaNewMemParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaNewMemParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaNewParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaNewParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaNewValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaNewValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaParse\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaParse
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaSetValidOptions\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaSetValidOptions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidCtxtGetOptions\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidCtxtGetOptions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidCtxtGetParserCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidCtxtGetParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidateDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidateDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidateFile\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidateFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidateOneElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidateOneElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaValidateSetFilename\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaValidateSetFilename
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaWhiteSpaceReplace\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaWhiteSpaceReplace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSearchNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSearchNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSearchNsByHref\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSearchNsByHref
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetCompressMode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetCompressMode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetDocCompressMode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetDocCompressMode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetEntityLoader\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetEntityLoader
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetListDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetListDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetTreeDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetTreeDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetupParserForBuffer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetupParserForBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlShellPrintNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlShellPrintNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlShellPrintXPathError\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlShellPrintXPathError
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSkipBlankChars\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSkipBlankChars
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStopParser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStopParser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrEqual\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrEqual
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrQEqual\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrQEqual
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrcasecmp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrcasecmp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrcasestr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrcasestr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrcat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrcat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrchr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrchr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrcmp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrcmp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrdup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrdup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStringDecodeEntities\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStringDecodeEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStringGetNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStringGetNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStringLenDecodeEntities\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStringLenDecodeEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStringLenGetNodeList\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStringLenGetNodeList
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrlen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrlen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrncasecmp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrncasecmp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrncat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrncat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrncatNew\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrncatNew
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrncmp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrncmp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrndup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrndup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrstr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrstr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlStrsub\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlStrsub
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSubstituteEntitiesDefault\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSubstituteEntitiesDefault
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextConcat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextConcat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextMerge\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextMerge
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderAttributeCount\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderAttributeCount
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderByteConsumed\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderByteConsumed
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderClose\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderClose
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstBaseUri\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstBaseUri
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstEncoding\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstEncoding
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstLocalName\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstLocalName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstNamespaceUri\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstNamespaceUri
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstPrefix\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstPrefix
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstXmlLang\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstXmlLang
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderConstXmlVersion\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderConstXmlVersion
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderCurrentDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderCurrentDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderCurrentNode\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderCurrentNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderDepth\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderDepth
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderExpand\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderExpand
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetAttribute\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetAttributeNo\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetAttributeNo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetAttributeNs\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetAttributeNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetParserColumnNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetParserColumnNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetParserLineNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetParserLineNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetParserProp\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetParserProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetRemainder\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetRemainder
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderHasAttributes\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderHasAttributes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderHasValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderHasValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderIsDefault\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderIsDefault
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderIsEmptyElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderIsEmptyElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderIsNamespaceDecl\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderIsNamespaceDecl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderIsValid\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderIsValid
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderLocatorBaseURI\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderLocatorBaseURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderLocatorLineNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderLocatorLineNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderLookupNamespace\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderLookupNamespace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToAttribute\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToAttributeNo\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToAttributeNo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToAttributeNs\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToAttributeNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToElement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToFirstAttribute\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToFirstAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderMoveToNextAttribute\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderMoveToNextAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderNext\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderNext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderNextSibling\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderNextSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderNodeType\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderNodeType
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderNormalization\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderNormalization
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderPreserve\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderPreserve
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderQuoteChar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderQuoteChar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderRead\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderRead
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderReadAttributeValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderReadAttributeValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderReadInnerXml\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderReadInnerXml
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderReadOuterXml\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderReadOuterXml
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderReadState\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderReadState
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderReadString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderReadString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderRelaxNGSetSchema\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderRelaxNGSetSchema
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderRelaxNGValidate\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderRelaxNGValidate
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderRelaxNGValidateCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderRelaxNGValidateCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSchemaValidate\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSchemaValidate
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSchemaValidateCtxt\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSchemaValidateCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSetParserProp\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSetParserProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSetSchema\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSetSchema
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSetup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSetup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderStandalone\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderStandalone
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefDefaultBufferSize\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefDefaultBufferSize
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefDoValidityCheckingDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefDoValidityCheckingDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefGetWarningsDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefGetWarningsDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefIndentTreeOutput\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefIndentTreeOutput
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefKeepBlanksDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefKeepBlanksDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefLineNumbersDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefLineNumbersDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefLoadExtDtdDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefLoadExtDtdDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefParserDebugEntities\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefParserDebugEntities
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefPedanticParserDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefPedanticParserDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefSaveNoEmptyTags\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefSaveNoEmptyTags
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefSubstituteEntitiesDefaultValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefSubstituteEntitiesDefaultValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlThrDefTreeIndentString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlThrDefTreeIndentString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsAegeanNumbers\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsAegeanNumbers
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsAlphabeticPresentationForms\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsAlphabeticPresentationForms
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsArabic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsArabic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsArabicPresentationFormsA\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsArabicPresentationFormsA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsArabicPresentationFormsB\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsArabicPresentationFormsB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsArmenian\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsArmenian
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsArrows\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsArrows
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBasicLatin\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBasicLatin
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBengali\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBengali
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBlock\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBlock
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBlockElements\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBlockElements
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBopomofo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBopomofo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBopomofoExtended\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBopomofoExtended
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBoxDrawing\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBoxDrawing
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBraillePatterns\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBraillePatterns
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsBuhid\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsBuhid
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsByzantineMusicalSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsByzantineMusicalSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKCompatibility\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKCompatibility
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKCompatibilityForms\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKCompatibilityForms
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKCompatibilityIdeographs\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKCompatibilityIdeographs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKCompatibilityIdeographsSupplement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKCompatibilityIdeographsSupplement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKRadicalsSupplement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKRadicalsSupplement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKSymbolsandPunctuation\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKSymbolsandPunctuation
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKUnifiedIdeographs\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKUnifiedIdeographs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKUnifiedIdeographsExtensionA\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKUnifiedIdeographsExtensionA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCJKUnifiedIdeographsExtensionB\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCJKUnifiedIdeographsExtensionB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatC\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatC
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatCc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatCc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatCf\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatCf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatCo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatCo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatCs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatCs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatL\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatL
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatLl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatLl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatLm\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatLm
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatLo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatLo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatLt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatLt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatLu\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatLu
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatM\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatM
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatMc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatMc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatMe\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatMe
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatMn\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatMn
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatN\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatN
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatNd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatNd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatNl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatNl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatNo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatNo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatP\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatP
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPe\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPe
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPf\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPi\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPi
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatPs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatPs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatS\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatS
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatSc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatSc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatSk\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatSk
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatSm\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatSm
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatSo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatSo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatZ\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatZ
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatZl\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatZl
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatZp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatZp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCatZs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCatZs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCherokee\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCherokee
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCombiningDiacriticalMarks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCombiningDiacriticalMarks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCombiningDiacriticalMarksforSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCombiningDiacriticalMarksforSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCombiningHalfMarks\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCombiningHalfMarks
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCombiningMarksforSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCombiningMarksforSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsControlPictures\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsControlPictures
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCurrencySymbols\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCurrencySymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCypriotSyllabary\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCypriotSyllabary
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCyrillic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCyrillic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsCyrillicSupplement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsCyrillicSupplement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsDeseret\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsDeseret
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsDevanagari\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsDevanagari
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsDingbats\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsDingbats
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsEnclosedAlphanumerics\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsEnclosedAlphanumerics
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsEnclosedCJKLettersandMonths\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsEnclosedCJKLettersandMonths
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsEthiopic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsEthiopic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGeneralPunctuation\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGeneralPunctuation
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGeometricShapes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGeometricShapes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGeorgian\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGeorgian
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGothic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGothic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGreek\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGreek
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGreekExtended\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGreekExtended
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGreekandCoptic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGreekandCoptic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGujarati\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGujarati
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsGurmukhi\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsGurmukhi
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHalfwidthandFullwidthForms\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHalfwidthandFullwidthForms
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHangulCompatibilityJamo\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHangulCompatibilityJamo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHangulJamo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHangulJamo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHangulSyllables\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHangulSyllables
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHanunoo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHanunoo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHebrew\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHebrew
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHighPrivateUseSurrogates\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHighPrivateUseSurrogates
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHighSurrogates\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHighSurrogates
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsHiragana\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsHiragana
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsIPAExtensions\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsIPAExtensions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsIdeographicDescriptionCharacters\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsIdeographicDescriptionCharacters
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKanbun\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKanbun
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKangxiRadicals\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKangxiRadicals
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKannada\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKannada
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKatakana\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKatakana
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKatakanaPhoneticExtensions\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKatakanaPhoneticExtensions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKhmer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKhmer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsKhmerSymbols\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsKhmerSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLao\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLao
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLatin1Supplement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLatin1Supplement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLatinExtendedA\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLatinExtendedA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLatinExtendedAdditional\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLatinExtendedAdditional
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLatinExtendedB\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLatinExtendedB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLetterlikeSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLetterlikeSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLimbu\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLimbu
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLinearBIdeograms\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLinearBIdeograms
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLinearBSyllabary\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLinearBSyllabary
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsLowSurrogates\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsLowSurrogates
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMalayalam\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMalayalam
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMathematicalAlphanumericSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMathematicalAlphanumericSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMathematicalOperators\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMathematicalOperators
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMiscellaneousMathematicalSymbolsA\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMiscellaneousMathematicalSymbolsA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMiscellaneousMathematicalSymbolsB\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMiscellaneousMathematicalSymbolsB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMiscellaneousSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMiscellaneousSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMiscellaneousSymbolsandArrows\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMiscellaneousSymbolsandArrows
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMiscellaneousTechnical\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMiscellaneousTechnical
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMongolian\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMongolian
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMusicalSymbols\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMusicalSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsMyanmar\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsMyanmar
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsNumberForms\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsNumberForms
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsOgham\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsOgham
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsOldItalic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsOldItalic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsOpticalCharacterRecognition\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsOpticalCharacterRecognition
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsOriya\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsOriya
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsOsmanya\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsOsmanya
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsPhoneticExtensions\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsPhoneticExtensions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsPrivateUse\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsPrivateUse
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsPrivateUseArea\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsPrivateUseArea
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsRunic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsRunic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsShavian\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsShavian
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSinhala\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSinhala
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSmallFormVariants\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSmallFormVariants
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSpacingModifierLetters\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSpacingModifierLetters
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSpecials\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSpecials
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSuperscriptsandSubscripts\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSuperscriptsandSubscripts
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSupplementalArrowsA\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSupplementalArrowsA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSupplementalArrowsB\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSupplementalArrowsB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSupplementalMathematicalOperators\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSupplementalMathematicalOperators
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSupplementaryPrivateUseAreaA\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSupplementaryPrivateUseAreaA
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSupplementaryPrivateUseAreaB\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSupplementaryPrivateUseAreaB
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsSyriac\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsSyriac
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTagalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTagalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTagbanwa\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTagbanwa
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTags\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTags
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTaiLe\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTaiLe
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTaiXuanJingSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTaiXuanJingSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTamil\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTamil
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTelugu\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTelugu
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsThaana\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsThaana
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsThai\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsThai
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsTibetan\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsTibetan
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsUgaritic\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsUgaritic
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsUnifiedCanadianAboriginalSyllabics\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsUnifiedCanadianAboriginalSyllabics
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsVariationSelectors\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsVariationSelectors
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsVariationSelectorsSupplement\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsVariationSelectorsSupplement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsYiRadicals\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsYiRadicals
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsYiSyllables\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsYiSyllables
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUCSIsYijingHexagramSymbols\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUCSIsYijingHexagramSymbols
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIEscape\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIEscape
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIEscapeStr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIEscapeStr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetAuthority\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetAuthority
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetFragment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetFragment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetOpaque\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetOpaque
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetPath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetPath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetPort\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetPort
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetQuery\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetQuery
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetQueryRaw\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetQueryRaw
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetScheme\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetScheme
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetServer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetServer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIGetUser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIGetUser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetAuthority\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetAuthority
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetFragment\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetFragment
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetOpaque\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetOpaque
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetPath\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetPath
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetPort\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetPort
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetQuery\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetQuery
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetQueryRaw\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetQueryRaw
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetScheme\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetScheme
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetServer\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetServer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURISetUser\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURISetUser
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlURIUnescapeString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlURIUnescapeString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Charcmp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Charcmp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Size\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Size
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strlen\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strlen
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strloc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strloc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strndup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strndup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strpos\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strpos
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strsize\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strsize
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUTF8Strsub\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUTF8Strsub
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUnlinkNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUnlinkNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUnsetNsProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUnsetNsProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUnsetProp\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUnsetProp
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidCtxtNormalizeAttributeValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidCtxtNormalizeAttributeValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidNormalizeAttributeValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidNormalizeAttributeValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateDocument\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateDocument
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateDocumentFinal\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateDocumentFinal
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateDtd\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateDtd
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateDtdFinal\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateDtdFinal
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNCName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNCName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNMToken\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNMToken
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNameValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNameValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNamesValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNamesValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNmtokenValue\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNmtokenValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNmtokensValue\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNmtokensValue
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateNotationUse\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateNotationUse
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateOneAttribute\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateOneAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateOneElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateOneElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateOneNamespace\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateOneNamespace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidatePopElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidatePopElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidatePushCData\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidatePushCData
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidatePushElement\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidatePushElement
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateQName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateQName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlValidateRoot\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlValidateRoot
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXIncludeProcess\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXIncludeProcess
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXIncludeProcessFlags\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXIncludeProcessFlags
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXIncludeProcessTree\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXIncludeProcessTree
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXIncludeProcessTreeFlags\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXIncludeProcessTreeFlags
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathAddValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathAddValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathBooleanFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathBooleanFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastBooleanToNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastBooleanToNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastBooleanToString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastBooleanToString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastNodeToNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastNodeToNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastNodeToString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastNodeToString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastNumberToBoolean\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastNumberToBoolean
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastNumberToString\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastNumberToString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastStringToBoolean\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastStringToBoolean
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCastStringToNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCastStringToNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCeilingFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCeilingFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCmpNodes\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCmpNodes
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCompareValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCompareValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathConcatFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathConcatFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathContainsFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathContainsFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathContextSetCache\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathContextSetCache
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathCountFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathCountFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathDivValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathDivValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathEqualValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathEqualValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathErr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathErr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathEval\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathEval
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathEvalExpr\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathEvalExpr
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathEvalExpression\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathEvalExpression
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathFalseFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathFalseFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathFloorFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathFloorFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathFreeContext\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathFreeContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathFreeParserContext\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathFreeParserContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetContextDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetContextDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetContextNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetContextNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetContextPosition\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetContextPosition
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetContextSize\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetContextSize
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathGetFunctionURI\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathGetFunctionURI
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathIdFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathIdFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathInit\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathInit
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathIsInf\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathIsInf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathIsNaN\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathIsNaN
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathIsNodeType\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathIsNodeType
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathLangFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathLangFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathLastFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathLastFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathLocalNameFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathLocalNameFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathModValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathModValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathMultValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathMultValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNamespaceURIFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNamespaceURIFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewBoolean\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewBoolean
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewCString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewCString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewContext\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewFloat\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewFloat
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewNodeSet\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewNodeSet
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewParserContext\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewParserContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNewValueTree\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNewValueTree
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextAncestor\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextAncestor
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextAncestorOrSelf\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextAncestorOrSelf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextAttribute\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextAttribute
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextChild\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextChild
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextDescendant\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextDescendant
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextDescendantOrSelf\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextDescendantOrSelf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextFollowing\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextFollowing
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextFollowingSibling\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextFollowingSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextNamespace\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextNamespace
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextParent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextParent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextPreceding\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextPreceding
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextPrecedingSibling\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextPrecedingSibling
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNextSelf\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNextSelf
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNodeEval\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNodeEval
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNodeSetFreeNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNodeSetFreeNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNormalizeFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNormalizeFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNotEqualValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNotEqualValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNotFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNotFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNsLookup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNsLookup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathNumberFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathNumberFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathOrderDocElems\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathOrderDocElems
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathParseNCName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathParseNCName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathParseName\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathParseName
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathParserGetContext\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathParserGetContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathPopBoolean\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathPopBoolean
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathPopNumber\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathPopNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathPopString\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathPopString
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathPositionFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathPositionFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisterAllFunctions\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisterAllFunctions
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisterNs\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisterNs
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisterVariable\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisterVariable
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisteredFuncsCleanup\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisteredFuncsCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisteredNsCleanup\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisteredNsCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRegisteredVariablesCleanup\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRegisteredVariablesCleanup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRoot\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRoot
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathRoundFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathRoundFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSetContextDoc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSetContextDoc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSetContextNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSetContextNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathStartsWithFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathStartsWithFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathStringEvalNumber\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathStringEvalNumber
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathStringFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathStringFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathStringLengthFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathStringLengthFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSubValues\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSubValues
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSubstringAfterFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSubstringAfterFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSubstringBeforeFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSubstringBeforeFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSubstringFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSubstringFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathSumFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathSumFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathTranslateFunction\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathTranslateFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathTrueFunction\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathTrueFunction
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathValueFlipSign\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathValueFlipSign
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathVariableLookup\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathVariableLookup
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPathVariableLookupNS\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPathVariableLookupNS
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPatherror\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPatherror
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPtrEval\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPtrEval
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlXPtrNewContext\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlXPtrNewContext
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"name\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_name
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"children\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_children
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"properties\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_properties
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"last\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_last
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"prev\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_prev
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"next\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_next
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"parent\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_parent
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"type\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_type
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"doc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_doc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNewNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNewNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlNodeRemoveNsDef\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlNodeRemoveNsDef
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSetValidErrors\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetValidErrors
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"serializeNode\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_serializeNode
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"saveNodeTo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_saveNodeTo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"outputBufferCreate\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateOutputBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"outputBufferGetPythonFile\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_outputBufferGetPythonFile
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlOutputBufferClose\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlOutputBufferClose
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlOutputBufferFlush\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlOutputBufferFlush
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFileTo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFileTo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSaveFormatFileTo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSaveFormatFileTo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"inputBufferCreate\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlCreateInputBuffer
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"setEntityLoader\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSetEntityLoader
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterErrorHandler\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterErrorHandler
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserCtxtSetErrorHandler\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserCtxtSetErrorHandler
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlParserCtxtGetErrorHandler\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlParserCtxtGetErrorHandler
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeParserCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeParserCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderSetErrorHandler\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderSetErrorHandler
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlTextReaderGetErrorHandler\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlTextReaderGetErrorHandler
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlFreeTextReader\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlFreeTextReader
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"addLocalCatalog\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_addLocalCatalog
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGSetValidErrors\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGSetValidErrors
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRelaxNGFreeValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRelaxNGFreeValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaSetValidErrors\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaSetValidErrors
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlSchemaFreeValidCtxt\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlSchemaFreeValidCtxt
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlC14NDocDumpMemory\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_C14NDocDumpMemory
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlC14NDocSaveTo\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_C14NDocSaveTo
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"getObjDesc\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_getObjDesc
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"compareNodesEqual\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_compareNodesEqual
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"nodeHash\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char,
                ml_meth: Some(
                    libxml_nodeHash
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlRegisterInputCallback\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlRegisterInputCallback
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: b"xmlUnregisterInputCallback\0" as *const u8
                    as *const libc::c_char as *mut libc::c_char,
                ml_meth: Some(
                    libxml_xmlUnregisterInputCallback
                        as unsafe extern "C" fn(
                            *mut PyObject,
                            *mut PyObject,
                        ) -> *mut PyObject,
                ),
                ml_flags: 0x1 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
        {
            let mut init = PyMethodDef {
                ml_name: 0 as *const libc::c_char,
                ml_meth: None,
                ml_flags: 0 as libc::c_int,
                ml_doc: 0 as *const libc::c_char,
            };
            init
        },
    ]
};
#[no_mangle]
pub unsafe extern "C" fn initlibxml2mod() {
    let mut module: *mut PyObject = 0 as *mut PyObject;
    module = Py_InitModule4_64(
        b"libxml2mod\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        libxmlMethods.as_mut_ptr(),
        0 as *mut libc::c_void as *mut libc::c_char,
        0 as *mut libc::c_void as *mut PyObject,
        1013 as libc::c_int,
    );
    if module.is_null() {
        return;
    }
    xmlInitParser();
    libxml_xmlErrorInitialize();
}
