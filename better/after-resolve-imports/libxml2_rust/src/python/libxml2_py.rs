use ::libc;
extern "C" {
    
    
    
    pub type PyMemberDef;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    static mut stdout: *mut FILE;
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> i32;
    static mut _Py_NoneStruct: PyObject;
    static mut PyFile_Type: PyTypeObject;
    fn PyFile_AsFile(_: *mut PyObject) -> *mut FILE;
    fn _PyArg_ParseTuple_SizeT(
        _: *mut PyObject,
        _: *const i8,
        _: ...
    ) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::HTMLparser::htmlAutoCloseTag;
pub use crate::src::HTMLparser::htmlCreateFileParserCtxt;
pub use crate::src::HTMLparser::htmlCreateMemoryParserCtxt;
pub use crate::src::HTMLparser::htmlCtxtReadDoc;
pub use crate::src::HTMLparser::htmlCtxtReadFd;
pub use crate::src::HTMLparser::htmlCtxtReadFile;
pub use crate::src::HTMLparser::htmlCtxtReadMemory;
pub use crate::src::HTMLparser::htmlCtxtReset;
pub use crate::src::HTMLparser::htmlCtxtUseOptions;
pub use crate::src::HTMLparser::htmlFreeParserCtxt;
pub use crate::src::HTMLparser::htmlHandleOmittedElem;
pub use crate::src::HTMLparser::htmlInitAutoClose;
pub use crate::src::HTMLparser::htmlIsAutoClosed;
pub use crate::src::HTMLparser::htmlIsScriptAttribute;
pub use crate::src::HTMLparser::htmlNewDoc;
pub use crate::src::HTMLparser::htmlNewDocNoDtD;
pub use crate::src::HTMLparser::htmlNewParserCtxt;
pub use crate::src::HTMLparser::htmlParseCharRef;
pub use crate::src::HTMLparser::htmlParseChunk;
pub use crate::src::HTMLparser::htmlParseDoc;
pub use crate::src::HTMLparser::htmlParseDocument;
pub use crate::src::HTMLparser::htmlParseElement;
pub use crate::src::HTMLparser::htmlParseFile;
pub use crate::src::HTMLparser::htmlReadDoc;
pub use crate::src::HTMLparser::htmlReadFd;
pub use crate::src::HTMLparser::htmlReadFile;
pub use crate::src::HTMLparser::htmlReadMemory;
pub use crate::src::HTMLtree::htmlDocContentDumpFormatOutput;
pub use crate::src::HTMLtree::htmlDocContentDumpOutput;
pub use crate::src::HTMLtree::htmlDocDump;
pub use crate::src::HTMLtree::htmlGetMetaEncoding;
pub use crate::src::HTMLtree::htmlIsBooleanAttr;
pub use crate::src::HTMLtree::htmlNodeDumpFile;
pub use crate::src::HTMLtree::htmlNodeDumpFileFormat;
pub use crate::src::HTMLtree::htmlNodeDumpFormatOutput;
pub use crate::src::HTMLtree::htmlNodeDumpOutput;
pub use crate::src::HTMLtree::htmlSaveFile;
pub use crate::src::HTMLtree::htmlSaveFileEnc;
pub use crate::src::HTMLtree::htmlSaveFileFormat;
pub use crate::src::HTMLtree::htmlSetMetaEncoding;
pub use crate::src::SAX2::htmlDefaultSAXHandlerInit;
pub use crate::src::SAX2::xmlDefaultSAXHandlerInit;
pub use crate::src::SAX2::xmlSAXDefaultVersion;
pub use crate::src::catalog::xmlACatalogAdd;
pub use crate::src::catalog::xmlACatalogDump;
pub use crate::src::catalog::xmlACatalogRemove;
pub use crate::src::catalog::xmlACatalogResolve;
pub use crate::src::catalog::xmlACatalogResolvePublic;
pub use crate::src::catalog::xmlACatalogResolveSystem;
pub use crate::src::catalog::xmlACatalogResolveURI;
pub use crate::src::catalog::xmlCatalogAdd;
pub use crate::src::catalog::xmlCatalogCleanup;
pub use crate::src::catalog::xmlCatalogConvert;
pub use crate::src::catalog::xmlCatalogDump;
pub use crate::src::catalog::xmlCatalogGetPublic;
pub use crate::src::catalog::xmlCatalogGetSystem;
pub use crate::src::catalog::xmlCatalogIsEmpty;
pub use crate::src::catalog::xmlCatalogRemove;
pub use crate::src::catalog::xmlCatalogResolve;
pub use crate::src::catalog::xmlCatalogResolvePublic;
pub use crate::src::catalog::xmlCatalogResolveSystem;
pub use crate::src::catalog::xmlCatalogResolveURI;
pub use crate::src::catalog::xmlCatalogSetDebug;
pub use crate::src::catalog::xmlConvertSGMLCatalog;
pub use crate::src::catalog::xmlFreeCatalog;
pub use crate::src::catalog::xmlInitializeCatalog;
pub use crate::src::catalog::xmlLoadACatalog;
pub use crate::src::catalog::xmlLoadCatalog;
pub use crate::src::catalog::xmlLoadCatalogs;
pub use crate::src::catalog::xmlLoadSGMLSuperCatalog;
pub use crate::src::catalog::xmlNewCatalog;
pub use crate::src::catalog::xmlParseCatalogFile;
pub use crate::src::chvalid::xmlIsBaseChar;
pub use crate::src::chvalid::xmlIsBlank;
pub use crate::src::chvalid::xmlIsChar;
pub use crate::src::chvalid::xmlIsCombining;
pub use crate::src::chvalid::xmlIsDigit;
pub use crate::src::chvalid::xmlIsExtender;
pub use crate::src::chvalid::xmlIsIdeographic;
pub use crate::src::chvalid::xmlIsPubidChar;
pub use crate::src::debugXML::xmlBoolToText;
pub use crate::src::debugXML::xmlDebugCheckDocument;
pub use crate::src::debugXML::xmlDebugDumpAttr;
pub use crate::src::debugXML::xmlDebugDumpAttrList;
pub use crate::src::debugXML::xmlDebugDumpDTD;
pub use crate::src::debugXML::xmlDebugDumpDocument;
pub use crate::src::debugXML::xmlDebugDumpDocumentHead;
pub use crate::src::debugXML::xmlDebugDumpEntities;
pub use crate::src::debugXML::xmlDebugDumpNode;
pub use crate::src::debugXML::xmlDebugDumpNodeList;
pub use crate::src::debugXML::xmlDebugDumpOneNode;
pub use crate::src::debugXML::xmlDebugDumpString;
pub use crate::src::debugXML::xmlLsCountNode;
pub use crate::src::debugXML::xmlLsOneNode;
pub use crate::src::debugXML::xmlShellPrintNode;
pub use crate::src::debugXML::xmlShellPrintXPathError;
pub use crate::src::dict::xmlDictCleanup;
pub use crate::src::dict::xmlInitializeDict;
pub use crate::src::encoding::xmlAddEncodingAlias;
pub use crate::src::encoding::xmlByteConsumed;
pub use crate::src::encoding::xmlCleanupCharEncodingHandlers;
pub use crate::src::encoding::xmlCleanupEncodingAliases;
pub use crate::src::encoding::xmlDelEncodingAlias;
pub use crate::src::encoding::xmlGetEncodingAlias;
pub use crate::src::encoding::xmlInitCharEncodingHandlers;
pub use crate::src::entities::xmlAddDocEntity;
pub use crate::src::entities::xmlAddDtdEntity;
pub use crate::src::entities::xmlEncodeEntitiesReentrant;
pub use crate::src::entities::xmlEncodeSpecialChars;
pub use crate::src::entities::xmlGetDocEntity;
pub use crate::src::entities::xmlGetDtdEntity;
pub use crate::src::entities::xmlGetParameterEntity;
pub use crate::src::entities::xmlGetPredefinedEntity;
pub use crate::src::entities::xmlNewEntity;
pub use crate::src::error::xmlCopyError;
pub use crate::src::error::xmlGetLastError;
pub use crate::src::error::xmlResetError;
pub use crate::src::error::xmlResetLastError;
pub use crate::src::globals::xmlCleanupGlobals;
pub use crate::src::globals::xmlInitGlobals;
pub use crate::src::globals::xmlThrDefDefaultBufferSize;
pub use crate::src::globals::xmlThrDefDoValidityCheckingDefaultValue;
pub use crate::src::globals::xmlThrDefGetWarningsDefaultValue;
pub use crate::src::globals::xmlThrDefIndentTreeOutput;
pub use crate::src::globals::xmlThrDefKeepBlanksDefaultValue;
pub use crate::src::globals::xmlThrDefLineNumbersDefaultValue;
pub use crate::src::globals::xmlThrDefLoadExtDtdDefaultValue;
pub use crate::src::globals::xmlThrDefParserDebugEntities;
pub use crate::src::globals::xmlThrDefPedanticParserDefaultValue;
pub use crate::src::globals::xmlThrDefSaveNoEmptyTags;
pub use crate::src::globals::xmlThrDefSubstituteEntitiesDefaultValue;
pub use crate::src::globals::xmlThrDefTreeIndentString;
pub use crate::src::legacy::xmlCleanupPredefinedEntities;
pub use crate::src::legacy::xmlDecodeEntities;
pub use crate::src::legacy::xmlEncodeEntities;
pub use crate::src::legacy::xmlHandleEntity;
pub use crate::src::legacy::xmlInitializePredefinedEntities;
pub use crate::src::legacy::xmlNamespaceParseNCName;
pub use crate::src::legacy::xmlNamespaceParseNSDef;
pub use crate::src::legacy::xmlNewGlobalNs;
pub use crate::src::legacy::xmlParseNamespace;
pub use crate::src::legacy::xmlParseQuotedString;
pub use crate::src::legacy::xmlParserHandleReference;
pub use crate::src::legacy::xmlScanName;
pub use crate::src::nanoftp::xmlNanoFTPCleanup;
pub use crate::src::nanoftp::xmlNanoFTPInit;
pub use crate::src::nanoftp::xmlNanoFTPProxy;
pub use crate::src::nanoftp::xmlNanoFTPScanProxy;
pub use crate::src::nanohttp::xmlNanoHTTPCleanup;
pub use crate::src::nanohttp::xmlNanoHTTPInit;
pub use crate::src::nanohttp::xmlNanoHTTPScanProxy;
pub use crate::src::parser::namePop;
pub use crate::src::parser::namePush;
pub use crate::src::parser::nodePop;
pub use crate::src::parser::nodePush;
pub use crate::src::parser::xmlCheckLanguageID;
pub use crate::src::parser::xmlCreateDocParserCtxt;
pub use crate::src::parser::xmlCreateEntityParserCtxt;
pub use crate::src::parser::xmlCreateFileParserCtxt;
pub use crate::src::parser::xmlCreateMemoryParserCtxt;
pub use crate::src::parser::xmlCreateURLParserCtxt;
pub use crate::src::parser::xmlCtxtReadDoc;
pub use crate::src::parser::xmlCtxtReadFd;
pub use crate::src::parser::xmlCtxtReadFile;
pub use crate::src::parser::xmlCtxtReadMemory;
pub use crate::src::parser::xmlCtxtReset;
pub use crate::src::parser::xmlCtxtResetPush;
pub use crate::src::parser::xmlCtxtUseOptions;
pub use crate::src::parser::xmlInitParser;
pub use crate::src::parser::xmlParseAttValue;
pub use crate::src::parser::xmlParseAttributeListDecl;
pub use crate::src::parser::xmlParseCDSect;
pub use crate::src::parser::xmlParseCharData;
pub use crate::src::parser::xmlParseCharRef;
pub use crate::src::parser::xmlParseChunk;
pub use crate::src::parser::xmlParseComment;
pub use crate::src::parser::xmlParseContent;
pub use crate::src::parser::xmlParseDTD;
pub use crate::src::parser::xmlParseDoc;
pub use crate::src::parser::xmlParseDocTypeDecl;
pub use crate::src::parser::xmlParseDocument;
pub use crate::src::parser::xmlParseElement;
pub use crate::src::parser::xmlParseElementDecl;
pub use crate::src::parser::xmlParseEncName;
pub use crate::src::parser::xmlParseEncodingDecl;
pub use crate::src::parser::xmlParseEndTag;
pub use crate::src::parser::xmlParseEntity;
pub use crate::src::parser::xmlParseEntityDecl;
pub use crate::src::parser::xmlParseEntityRef;
pub use crate::src::parser::xmlParseExtParsedEnt;
pub use crate::src::parser::xmlParseExternalSubset;
pub use crate::src::parser::xmlParseFile;
pub use crate::src::parser::xmlParseMarkupDecl;
pub use crate::src::parser::xmlParseMemory;
pub use crate::src::parser::xmlParseMisc;
pub use crate::src::parser::xmlParseName;
pub use crate::src::parser::xmlParseNmtoken;
pub use crate::src::parser::xmlParseNotationDecl;
pub use crate::src::parser::xmlParsePEReference;
pub use crate::src::parser::xmlParsePI;
pub use crate::src::parser::xmlParsePITarget;
pub use crate::src::parser::xmlParsePubidLiteral;
pub use crate::src::parser::xmlParseReference;
pub use crate::src::parser::xmlParseSDDecl;
pub use crate::src::parser::xmlParseStartTag;
pub use crate::src::parser::xmlParseSystemLiteral;
pub use crate::src::parser::xmlParseTextDecl;
pub use crate::src::parser::xmlParseVersionInfo;
pub use crate::src::parser::xmlParseVersionNum;
pub use crate::src::parser::xmlParseXMLDecl;
pub use crate::src::parser::xmlParserHandlePEReference;
pub use crate::src::parser::xmlPopInput;
pub use crate::src::parser::xmlReadDoc;
pub use crate::src::parser::xmlReadFd;
pub use crate::src::parser::xmlReadFile;
pub use crate::src::parser::xmlReadMemory;
pub use crate::src::parser::xmlRecoverDoc;
pub use crate::src::parser::xmlRecoverFile;
pub use crate::src::parser::xmlRecoverMemory;
pub use crate::src::parser::xmlSetupParserForBuffer;
pub use crate::src::parser::xmlSkipBlankChars;
pub use crate::src::parser::xmlStopParser;
pub use crate::src::parser::xmlStringDecodeEntities;
pub use crate::src::parser::xmlStringLenDecodeEntities;
pub use crate::src::parserInternals::xmlCheckVersion;
pub use crate::src::parserInternals::xmlClearParserCtxt;
pub use crate::src::parserInternals::xmlCopyChar;
pub use crate::src::parserInternals::xmlCopyCharMultiByte;
pub use crate::src::parserInternals::xmlInitParserCtxt;
pub use crate::src::parserInternals::xmlIsLetter;
pub use crate::src::parserInternals::xmlKeepBlanksDefault;
pub use crate::src::parserInternals::xmlLineNumbersDefault;
pub use crate::src::parserInternals::xmlNewParserCtxt;
pub use crate::src::parserInternals::xmlNextChar;
pub use crate::src::parserInternals::xmlPedanticParserDefault;
pub use crate::src::parserInternals::xmlSubstituteEntitiesDefault;
pub use crate::src::python::libxml::libxml_deprecationWarning;
pub use crate::src::python::types::libxml_charPtrConstWrap;
pub use crate::src::python::types::libxml_charPtrWrap;
pub use crate::src::python::types::libxml_doubleWrap;
pub use crate::src::python::types::libxml_intWrap;
pub use crate::src::python::types::libxml_longWrap;
pub use crate::src::python::types::libxml_xmlAttributePtrWrap;
pub use crate::src::python::types::libxml_xmlCatalogPtrWrap;
pub use crate::src::python::types::libxml_xmlCharPtrConstWrap;
pub use crate::src::python::types::libxml_xmlCharPtrWrap;
pub use crate::src::python::types::libxml_xmlDocPtrWrap;
pub use crate::src::python::types::libxml_xmlElementPtrWrap;
pub use crate::src::python::types::libxml_xmlErrorPtrWrap;
pub use crate::src::python::types::libxml_xmlNodePtrWrap;
pub use crate::src::python::types::libxml_xmlNsPtrWrap;
pub use crate::src::python::types::libxml_xmlParserCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlParserInputBufferPtrWrap;
pub use crate::src::python::types::libxml_xmlRegexpPtrWrap;
pub use crate::src::python::types::libxml_xmlRelaxNGParserCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlRelaxNGPtrWrap;
pub use crate::src::python::types::libxml_xmlRelaxNGValidCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlSchemaParserCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlSchemaPtrWrap;
pub use crate::src::python::types::libxml_xmlSchemaValidCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlTextReaderPtrWrap;
pub use crate::src::python::types::libxml_xmlURIPtrWrap;
pub use crate::src::python::types::libxml_xmlValidCtxtPtrWrap;
pub use crate::src::python::types::libxml_xmlXPathContextPtrWrap;
pub use crate::src::python::types::libxml_xmlXPathObjectPtrWrap;
pub use crate::src::python::types::libxml_xmlXPathParserContextPtrWrap;
pub use crate::src::relaxng::xmlRelaxNGCleanupTypes;
pub use crate::src::relaxng::xmlRelaxNGDump;
pub use crate::src::relaxng::xmlRelaxNGDumpTree;
pub use crate::src::relaxng::xmlRelaxNGFree;
pub use crate::src::relaxng::xmlRelaxNGFreeParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGInitTypes;
pub use crate::src::relaxng::xmlRelaxNGNewDocParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewMemParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewParserCtxt;
pub use crate::src::relaxng::xmlRelaxNGNewValidCtxt;
pub use crate::src::relaxng::xmlRelaxNGParse;
pub use crate::src::relaxng::xmlRelaxNGValidateDoc;
pub use crate::src::relaxng::xmlRelaxNGValidateFullElement;
pub use crate::src::relaxng::xmlRelaxNGValidatePopElement;
pub use crate::src::relaxng::xmlRelaxNGValidatePushCData;
pub use crate::src::relaxng::xmlRelaxNGValidatePushElement;
pub use crate::src::relaxng::xmlRelaxParserSetFlag;
pub use crate::src::tree::xmlAddChild;
pub use crate::src::tree::xmlAddChildList;
pub use crate::src::tree::xmlAddNextSibling;
pub use crate::src::tree::xmlAddPrevSibling;
pub use crate::src::tree::xmlAddSibling;
pub use crate::src::tree::xmlBuildQName;
pub use crate::src::tree::xmlCopyDoc;
pub use crate::src::tree::xmlCopyDtd;
pub use crate::src::tree::xmlCopyNamespace;
pub use crate::src::tree::xmlCopyNamespaceList;
pub use crate::src::tree::xmlCopyNode;
pub use crate::src::tree::xmlCopyNodeList;
pub use crate::src::tree::xmlCopyProp;
pub use crate::src::tree::xmlCopyPropList;
pub use crate::src::tree::xmlCreateIntSubset;
pub use crate::src::tree::xmlDocCopyNode;
pub use crate::src::tree::xmlDocCopyNodeList;
pub use crate::src::tree::xmlDocGetRootElement;
pub use crate::src::tree::xmlDocSetRootElement;
pub use crate::src::tree::xmlFirstElementChild;
pub use crate::src::tree::xmlFreeDoc;
pub use crate::src::tree::xmlFreeDtd;
pub use crate::src::tree::xmlFreeNode;
pub use crate::src::tree::xmlFreeNodeList;
pub use crate::src::tree::xmlFreeNs;
pub use crate::src::tree::xmlFreeNsList;
pub use crate::src::tree::xmlFreeProp;
pub use crate::src::tree::xmlFreePropList;
pub use crate::src::tree::xmlGetCompressMode;
pub use crate::src::tree::xmlGetDocCompressMode;
pub use crate::src::tree::xmlGetIntSubset;
pub use crate::src::tree::xmlGetLastChild;
pub use crate::src::tree::xmlGetLineNo;
pub use crate::src::tree::xmlGetNoNsProp;
pub use crate::src::tree::xmlGetNodePath;
pub use crate::src::tree::xmlGetNsProp;
pub use crate::src::tree::xmlGetProp;
pub use crate::src::tree::xmlHasNsProp;
pub use crate::src::tree::xmlHasProp;
pub use crate::src::tree::xmlIsBlankNode;
pub use crate::src::tree::xmlLastElementChild;
pub use crate::src::tree::xmlNewCDataBlock;
pub use crate::src::tree::xmlNewCharRef;
pub use crate::src::tree::xmlNewChild;
pub use crate::src::tree::xmlNewComment;
pub use crate::src::tree::xmlNewDoc;
pub use crate::src::tree::xmlNewDocComment;
pub use crate::src::tree::xmlNewDocFragment;
pub use crate::src::tree::xmlNewDocNode;
pub use crate::src::tree::xmlNewDocNodeEatName;
pub use crate::src::tree::xmlNewDocPI;
pub use crate::src::tree::xmlNewDocProp;
pub use crate::src::tree::xmlNewDocRawNode;
pub use crate::src::tree::xmlNewDocText;
pub use crate::src::tree::xmlNewDocTextLen;
pub use crate::src::tree::xmlNewDtd;
pub use crate::src::tree::xmlNewNodeEatName;
pub use crate::src::tree::xmlNewNs;
pub use crate::src::tree::xmlNewNsProp;
pub use crate::src::tree::xmlNewNsPropEatName;
pub use crate::src::tree::xmlNewPI;
pub use crate::src::tree::xmlNewProp;
pub use crate::src::tree::xmlNewReference;
pub use crate::src::tree::xmlNewText;
pub use crate::src::tree::xmlNewTextChild;
pub use crate::src::tree::xmlNewTextLen;
pub use crate::src::tree::xmlNextElementSibling;
pub use crate::src::tree::xmlNodeAddContent;
pub use crate::src::tree::xmlNodeAddContentLen;
pub use crate::src::tree::xmlNodeGetBase;
pub use crate::src::tree::xmlNodeGetContent;
pub use crate::src::tree::xmlNodeGetLang;
pub use crate::src::tree::xmlNodeGetSpacePreserve;
pub use crate::src::tree::xmlNodeIsText;
pub use crate::src::tree::xmlNodeListGetRawString;
pub use crate::src::tree::xmlNodeListGetString;
pub use crate::src::tree::xmlNodeSetBase;
pub use crate::src::tree::xmlNodeSetContent;
pub use crate::src::tree::xmlNodeSetContentLen;
pub use crate::src::tree::xmlNodeSetLang;
pub use crate::src::tree::xmlNodeSetName;
pub use crate::src::tree::xmlNodeSetSpacePreserve;
pub use crate::src::tree::xmlPreviousElementSibling;
pub use crate::src::tree::xmlReconciliateNs;
pub use crate::src::tree::xmlRemoveProp;
pub use crate::src::tree::xmlReplaceNode;
pub use crate::src::tree::xmlSearchNs;
pub use crate::src::tree::xmlSearchNsByHref;
pub use crate::src::tree::xmlSetCompressMode;
pub use crate::src::tree::xmlSetDocCompressMode;
pub use crate::src::tree::xmlSetListDoc;
pub use crate::src::tree::xmlSetNs;
pub use crate::src::tree::xmlSetNsProp;
pub use crate::src::tree::xmlSetProp;
pub use crate::src::tree::xmlSetTreeDoc;
pub use crate::src::tree::xmlStringGetNodeList;
pub use crate::src::tree::xmlStringLenGetNodeList;
pub use crate::src::tree::xmlTextConcat;
pub use crate::src::tree::xmlTextMerge;
pub use crate::src::tree::xmlUnlinkNode;
pub use crate::src::tree::xmlUnsetNsProp;
pub use crate::src::tree::xmlUnsetProp;
pub use crate::src::tree::xmlValidateNCName;
pub use crate::src::tree::xmlValidateNMToken;
pub use crate::src::tree::xmlValidateName;
pub use crate::src::tree::xmlValidateQName;
pub use crate::src::uri::xmlBuildRelativeURI;
pub use crate::src::uri::xmlBuildURI;
pub use crate::src::uri::xmlCanonicPath;
pub use crate::src::uri::xmlCreateURI;
pub use crate::src::uri::xmlFreeURI;
pub use crate::src::uri::xmlNormalizeURIPath;
pub use crate::src::uri::xmlParseURI;
pub use crate::src::uri::xmlParseURIRaw;
pub use crate::src::uri::xmlParseURIReference;
pub use crate::src::uri::xmlPathToURI;
pub use crate::src::uri::xmlPrintURI;
pub use crate::src::uri::xmlSaveUri;
pub use crate::src::uri::xmlURIEscape;
pub use crate::src::uri::xmlURIEscapeStr;
pub use crate::src::uri::xmlURIUnescapeString;
pub use crate::src::valid::xmlGetDtdAttrDesc;
pub use crate::src::valid::xmlGetDtdElementDesc;
pub use crate::src::valid::xmlGetDtdQAttrDesc;
pub use crate::src::valid::xmlGetDtdQElementDesc;
pub use crate::src::valid::xmlGetID;
pub use crate::src::valid::xmlIsID;
pub use crate::src::valid::xmlIsMixedElement;
pub use crate::src::valid::xmlIsRef;
pub use crate::src::valid::xmlNewValidCtxt;
pub use crate::src::valid::xmlRemoveID;
pub use crate::src::valid::xmlRemoveRef;
pub use crate::src::valid::xmlValidCtxtNormalizeAttributeValue;
pub use crate::src::valid::xmlValidNormalizeAttributeValue;
pub use crate::src::valid::xmlValidateDocument;
pub use crate::src::valid::xmlValidateDocumentFinal;
pub use crate::src::valid::xmlValidateDtd;
pub use crate::src::valid::xmlValidateDtdFinal;
pub use crate::src::valid::xmlValidateElement;
pub use crate::src::valid::xmlValidateNameValue;
pub use crate::src::valid::xmlValidateNamesValue;
pub use crate::src::valid::xmlValidateNmtokenValue;
pub use crate::src::valid::xmlValidateNmtokensValue;
pub use crate::src::valid::xmlValidateNotationUse;
pub use crate::src::valid::xmlValidateOneAttribute;
pub use crate::src::valid::xmlValidateOneElement;
pub use crate::src::valid::xmlValidateOneNamespace;
pub use crate::src::valid::xmlValidatePopElement;
pub use crate::src::valid::xmlValidatePushCData;
pub use crate::src::valid::xmlValidatePushElement;
pub use crate::src::valid::xmlValidateRoot;
pub use crate::src::xinclude::xmlXIncludeProcess;
pub use crate::src::xinclude::xmlXIncludeProcessFlags;
pub use crate::src::xinclude::xmlXIncludeProcessTree;
pub use crate::src::xinclude::xmlXIncludeProcessTreeFlags;
pub use crate::src::xmlIO::xmlCheckFilename;
pub use crate::src::xmlIO::xmlCleanupInputCallbacks;
pub use crate::src::xmlIO::xmlCleanupOutputCallbacks;
pub use crate::src::xmlIO::xmlFileMatch;
pub use crate::src::xmlIO::xmlFreeParserInputBuffer;
pub use crate::src::xmlIO::xmlIOFTPMatch;
pub use crate::src::xmlIO::xmlIOHTTPMatch;
pub use crate::src::xmlIO::xmlNormalizeWindowsPath;
pub use crate::src::xmlIO::xmlOutputBufferGetContent;
pub use crate::src::xmlIO::xmlOutputBufferWrite;
pub use crate::src::xmlIO::xmlOutputBufferWriteString;
pub use crate::src::xmlIO::xmlParserGetDirectory;
pub use crate::src::xmlIO::xmlParserInputBufferGrow;
pub use crate::src::xmlIO::xmlParserInputBufferPush;
pub use crate::src::xmlIO::xmlParserInputBufferRead;
pub use crate::src::xmlIO::xmlPopOutputCallbacks;
pub use crate::src::xmlIO::xmlRegisterDefaultInputCallbacks;
pub use crate::src::xmlIO::xmlRegisterDefaultOutputCallbacks;
pub use crate::src::xmlIO::xmlRegisterHTTPPostCallbacks;
pub use crate::src::xmlreader::xmlNewTextReader;
pub use crate::src::xmlreader::xmlNewTextReaderFilename;
pub use crate::src::xmlreader::xmlReaderForDoc;
pub use crate::src::xmlreader::xmlReaderForFd;
pub use crate::src::xmlreader::xmlReaderForFile;
pub use crate::src::xmlreader::xmlReaderForMemory;
pub use crate::src::xmlreader::xmlReaderNewDoc;
pub use crate::src::xmlreader::xmlReaderNewFd;
pub use crate::src::xmlreader::xmlReaderNewFile;
pub use crate::src::xmlreader::xmlReaderNewMemory;
pub use crate::src::xmlreader::xmlReaderNewWalker;
pub use crate::src::xmlreader::xmlReaderWalker;
pub use crate::src::xmlreader::xmlTextReaderAttributeCount;
pub use crate::src::xmlreader::xmlTextReaderByteConsumed;
pub use crate::src::xmlreader::xmlTextReaderClose;
pub use crate::src::xmlreader::xmlTextReaderConstBaseUri;
pub use crate::src::xmlreader::xmlTextReaderConstEncoding;
pub use crate::src::xmlreader::xmlTextReaderConstLocalName;
pub use crate::src::xmlreader::xmlTextReaderConstName;
pub use crate::src::xmlreader::xmlTextReaderConstNamespaceUri;
pub use crate::src::xmlreader::xmlTextReaderConstPrefix;
pub use crate::src::xmlreader::xmlTextReaderConstString;
pub use crate::src::xmlreader::xmlTextReaderConstValue;
pub use crate::src::xmlreader::xmlTextReaderConstXmlLang;
pub use crate::src::xmlreader::xmlTextReaderConstXmlVersion;
pub use crate::src::xmlreader::xmlTextReaderCurrentDoc;
pub use crate::src::xmlreader::xmlTextReaderCurrentNode;
pub use crate::src::xmlreader::xmlTextReaderDepth;
pub use crate::src::xmlreader::xmlTextReaderExpand;
pub use crate::src::xmlreader::xmlTextReaderGetAttribute;
pub use crate::src::xmlreader::xmlTextReaderGetAttributeNo;
pub use crate::src::xmlreader::xmlTextReaderGetAttributeNs;
pub use crate::src::xmlreader::xmlTextReaderGetParserColumnNumber;
pub use crate::src::xmlreader::xmlTextReaderGetParserLineNumber;
pub use crate::src::xmlreader::xmlTextReaderGetParserProp;
pub use crate::src::xmlreader::xmlTextReaderGetRemainder;
pub use crate::src::xmlreader::xmlTextReaderHasAttributes;
pub use crate::src::xmlreader::xmlTextReaderHasValue;
pub use crate::src::xmlreader::xmlTextReaderIsDefault;
pub use crate::src::xmlreader::xmlTextReaderIsEmptyElement;
pub use crate::src::xmlreader::xmlTextReaderIsNamespaceDecl;
pub use crate::src::xmlreader::xmlTextReaderIsValid;
pub use crate::src::xmlreader::xmlTextReaderLocatorBaseURI;
pub use crate::src::xmlreader::xmlTextReaderLocatorLineNumber;
pub use crate::src::xmlreader::xmlTextReaderLookupNamespace;
pub use crate::src::xmlreader::xmlTextReaderMoveToAttribute;
pub use crate::src::xmlreader::xmlTextReaderMoveToAttributeNo;
pub use crate::src::xmlreader::xmlTextReaderMoveToAttributeNs;
pub use crate::src::xmlreader::xmlTextReaderMoveToElement;
pub use crate::src::xmlreader::xmlTextReaderMoveToFirstAttribute;
pub use crate::src::xmlreader::xmlTextReaderMoveToNextAttribute;
pub use crate::src::xmlreader::xmlTextReaderNext;
pub use crate::src::xmlreader::xmlTextReaderNextSibling;
pub use crate::src::xmlreader::xmlTextReaderNodeType;
pub use crate::src::xmlreader::xmlTextReaderNormalization;
pub use crate::src::xmlreader::xmlTextReaderPreserve;
pub use crate::src::xmlreader::xmlTextReaderQuoteChar;
pub use crate::src::xmlreader::xmlTextReaderRead;
pub use crate::src::xmlreader::xmlTextReaderReadAttributeValue;
pub use crate::src::xmlreader::xmlTextReaderReadInnerXml;
pub use crate::src::xmlreader::xmlTextReaderReadOuterXml;
pub use crate::src::xmlreader::xmlTextReaderReadState;
pub use crate::src::xmlreader::xmlTextReaderReadString;
pub use crate::src::xmlreader::xmlTextReaderRelaxNGSetSchema;
pub use crate::src::xmlreader::xmlTextReaderRelaxNGValidate;
pub use crate::src::xmlreader::xmlTextReaderRelaxNGValidateCtxt;
pub use crate::src::xmlreader::xmlTextReaderSchemaValidate;
pub use crate::src::xmlreader::xmlTextReaderSchemaValidateCtxt;
pub use crate::src::xmlreader::xmlTextReaderSetParserProp;
pub use crate::src::xmlreader::xmlTextReaderSetSchema;
pub use crate::src::xmlreader::xmlTextReaderSetup;
pub use crate::src::xmlreader::xmlTextReaderStandalone;
pub use crate::src::xmlregexp::xmlRegFreeRegexp;
pub use crate::src::xmlregexp::xmlRegexpCompile;
pub use crate::src::xmlregexp::xmlRegexpExec;
pub use crate::src::xmlregexp::xmlRegexpIsDeterminist;
pub use crate::src::xmlregexp::xmlRegexpPrint;
pub use crate::src::xmlsave::xmlDocDump;
pub use crate::src::xmlsave::xmlDocFormatDump;
pub use crate::src::xmlsave::xmlElemDump;
pub use crate::src::xmlsave::xmlIsXHTML;
pub use crate::src::xmlsave::xmlNodeDumpOutput;
pub use crate::src::xmlsave::xmlSaveFile;
pub use crate::src::xmlsave::xmlSaveFileEnc;
pub use crate::src::xmlsave::xmlSaveFormatFile;
pub use crate::src::xmlsave::xmlSaveFormatFileEnc;
pub use crate::src::xmlschemas::xmlSchemaDump;
pub use crate::src::xmlschemas::xmlSchemaFree;
pub use crate::src::xmlschemas::xmlSchemaFreeParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaIsValid;
pub use crate::src::xmlschemas::xmlSchemaNewDocParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaNewMemParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaNewParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaNewValidCtxt;
pub use crate::src::xmlschemas::xmlSchemaParse;
pub use crate::src::xmlschemas::xmlSchemaSetValidOptions;
pub use crate::src::xmlschemas::xmlSchemaValidCtxtGetOptions;
pub use crate::src::xmlschemas::xmlSchemaValidCtxtGetParserCtxt;
pub use crate::src::xmlschemas::xmlSchemaValidateDoc;
pub use crate::src::xmlschemas::xmlSchemaValidateFile;
pub use crate::src::xmlschemas::xmlSchemaValidateOneElement;
pub use crate::src::xmlschemas::xmlSchemaValidateSetFilename;
pub use crate::src::xmlschemastypes::xmlSchemaCleanupTypes;
pub use crate::src::xmlschemastypes::xmlSchemaCollapseString;
pub use crate::src::xmlschemastypes::xmlSchemaInitTypes;
pub use crate::src::xmlschemastypes::xmlSchemaWhiteSpaceReplace;
pub use crate::src::xmlstring::xmlCharStrdup;
pub use crate::src::xmlstring::xmlCharStrndup;
pub use crate::src::xmlstring::xmlCheckUTF8;
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrQEqual;
pub use crate::src::xmlstring::xmlStrcasecmp;
pub use crate::src::xmlstring::xmlStrcasestr;
pub use crate::src::xmlstring::xmlStrcat;
pub use crate::src::xmlstring::xmlStrchr;
pub use crate::src::xmlstring::xmlStrcmp;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrlen;
pub use crate::src::xmlstring::xmlStrncasecmp;
pub use crate::src::xmlstring::xmlStrncat;
pub use crate::src::xmlstring::xmlStrncatNew;
pub use crate::src::xmlstring::xmlStrncmp;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlstring::xmlStrstr;
pub use crate::src::xmlstring::xmlStrsub;
pub use crate::src::xmlstring::xmlUTF8Charcmp;
pub use crate::src::xmlstring::xmlUTF8Size;
pub use crate::src::xmlstring::xmlUTF8Strlen;
pub use crate::src::xmlstring::xmlUTF8Strloc;
pub use crate::src::xmlstring::xmlUTF8Strndup;
pub use crate::src::xmlstring::xmlUTF8Strpos;
pub use crate::src::xmlstring::xmlUTF8Strsize;
pub use crate::src::xmlstring::xmlUTF8Strsub;
pub use crate::src::xmlunicode::xmlUCSIsAegeanNumbers;
pub use crate::src::xmlunicode::xmlUCSIsAlphabeticPresentationForms;
pub use crate::src::xmlunicode::xmlUCSIsArabic;
pub use crate::src::xmlunicode::xmlUCSIsArabicPresentationFormsA;
pub use crate::src::xmlunicode::xmlUCSIsArabicPresentationFormsB;
pub use crate::src::xmlunicode::xmlUCSIsArmenian;
pub use crate::src::xmlunicode::xmlUCSIsArrows;
pub use crate::src::xmlunicode::xmlUCSIsBasicLatin;
pub use crate::src::xmlunicode::xmlUCSIsBengali;
pub use crate::src::xmlunicode::xmlUCSIsBlock;
pub use crate::src::xmlunicode::xmlUCSIsBlockElements;
pub use crate::src::xmlunicode::xmlUCSIsBopomofo;
pub use crate::src::xmlunicode::xmlUCSIsBopomofoExtended;
pub use crate::src::xmlunicode::xmlUCSIsBoxDrawing;
pub use crate::src::xmlunicode::xmlUCSIsBraillePatterns;
pub use crate::src::xmlunicode::xmlUCSIsBuhid;
pub use crate::src::xmlunicode::xmlUCSIsByzantineMusicalSymbols;
pub use crate::src::xmlunicode::xmlUCSIsCJKCompatibility;
pub use crate::src::xmlunicode::xmlUCSIsCJKCompatibilityForms;
pub use crate::src::xmlunicode::xmlUCSIsCJKCompatibilityIdeographs;
pub use crate::src::xmlunicode::xmlUCSIsCJKCompatibilityIdeographsSupplement;
pub use crate::src::xmlunicode::xmlUCSIsCJKRadicalsSupplement;
pub use crate::src::xmlunicode::xmlUCSIsCJKSymbolsandPunctuation;
pub use crate::src::xmlunicode::xmlUCSIsCJKUnifiedIdeographs;
pub use crate::src::xmlunicode::xmlUCSIsCJKUnifiedIdeographsExtensionA;
pub use crate::src::xmlunicode::xmlUCSIsCJKUnifiedIdeographsExtensionB;
pub use crate::src::xmlunicode::xmlUCSIsCat;
pub use crate::src::xmlunicode::xmlUCSIsCatC;
pub use crate::src::xmlunicode::xmlUCSIsCatCc;
pub use crate::src::xmlunicode::xmlUCSIsCatCf;
pub use crate::src::xmlunicode::xmlUCSIsCatCo;
pub use crate::src::xmlunicode::xmlUCSIsCatCs;
pub use crate::src::xmlunicode::xmlUCSIsCatL;
pub use crate::src::xmlunicode::xmlUCSIsCatLl;
pub use crate::src::xmlunicode::xmlUCSIsCatLm;
pub use crate::src::xmlunicode::xmlUCSIsCatLo;
pub use crate::src::xmlunicode::xmlUCSIsCatLt;
pub use crate::src::xmlunicode::xmlUCSIsCatLu;
pub use crate::src::xmlunicode::xmlUCSIsCatM;
pub use crate::src::xmlunicode::xmlUCSIsCatMc;
pub use crate::src::xmlunicode::xmlUCSIsCatMe;
pub use crate::src::xmlunicode::xmlUCSIsCatMn;
pub use crate::src::xmlunicode::xmlUCSIsCatN;
pub use crate::src::xmlunicode::xmlUCSIsCatNd;
pub use crate::src::xmlunicode::xmlUCSIsCatNl;
pub use crate::src::xmlunicode::xmlUCSIsCatNo;
pub use crate::src::xmlunicode::xmlUCSIsCatP;
pub use crate::src::xmlunicode::xmlUCSIsCatPc;
pub use crate::src::xmlunicode::xmlUCSIsCatPd;
pub use crate::src::xmlunicode::xmlUCSIsCatPe;
pub use crate::src::xmlunicode::xmlUCSIsCatPf;
pub use crate::src::xmlunicode::xmlUCSIsCatPi;
pub use crate::src::xmlunicode::xmlUCSIsCatPo;
pub use crate::src::xmlunicode::xmlUCSIsCatPs;
pub use crate::src::xmlunicode::xmlUCSIsCatS;
pub use crate::src::xmlunicode::xmlUCSIsCatSc;
pub use crate::src::xmlunicode::xmlUCSIsCatSk;
pub use crate::src::xmlunicode::xmlUCSIsCatSm;
pub use crate::src::xmlunicode::xmlUCSIsCatSo;
pub use crate::src::xmlunicode::xmlUCSIsCatZ;
pub use crate::src::xmlunicode::xmlUCSIsCatZl;
pub use crate::src::xmlunicode::xmlUCSIsCatZp;
pub use crate::src::xmlunicode::xmlUCSIsCatZs;
pub use crate::src::xmlunicode::xmlUCSIsCherokee;
pub use crate::src::xmlunicode::xmlUCSIsCombiningDiacriticalMarks;
pub use crate::src::xmlunicode::xmlUCSIsCombiningDiacriticalMarksforSymbols;
pub use crate::src::xmlunicode::xmlUCSIsCombiningHalfMarks;
pub use crate::src::xmlunicode::xmlUCSIsCombiningMarksforSymbols;
pub use crate::src::xmlunicode::xmlUCSIsControlPictures;
pub use crate::src::xmlunicode::xmlUCSIsCurrencySymbols;
pub use crate::src::xmlunicode::xmlUCSIsCypriotSyllabary;
pub use crate::src::xmlunicode::xmlUCSIsCyrillic;
pub use crate::src::xmlunicode::xmlUCSIsCyrillicSupplement;
pub use crate::src::xmlunicode::xmlUCSIsDeseret;
pub use crate::src::xmlunicode::xmlUCSIsDevanagari;
pub use crate::src::xmlunicode::xmlUCSIsDingbats;
pub use crate::src::xmlunicode::xmlUCSIsEnclosedAlphanumerics;
pub use crate::src::xmlunicode::xmlUCSIsEnclosedCJKLettersandMonths;
pub use crate::src::xmlunicode::xmlUCSIsEthiopic;
pub use crate::src::xmlunicode::xmlUCSIsGeneralPunctuation;
pub use crate::src::xmlunicode::xmlUCSIsGeometricShapes;
pub use crate::src::xmlunicode::xmlUCSIsGeorgian;
pub use crate::src::xmlunicode::xmlUCSIsGothic;
pub use crate::src::xmlunicode::xmlUCSIsGreek;
pub use crate::src::xmlunicode::xmlUCSIsGreekExtended;
pub use crate::src::xmlunicode::xmlUCSIsGreekandCoptic;
pub use crate::src::xmlunicode::xmlUCSIsGujarati;
pub use crate::src::xmlunicode::xmlUCSIsGurmukhi;
pub use crate::src::xmlunicode::xmlUCSIsHalfwidthandFullwidthForms;
pub use crate::src::xmlunicode::xmlUCSIsHangulCompatibilityJamo;
pub use crate::src::xmlunicode::xmlUCSIsHangulJamo;
pub use crate::src::xmlunicode::xmlUCSIsHangulSyllables;
pub use crate::src::xmlunicode::xmlUCSIsHanunoo;
pub use crate::src::xmlunicode::xmlUCSIsHebrew;
pub use crate::src::xmlunicode::xmlUCSIsHighPrivateUseSurrogates;
pub use crate::src::xmlunicode::xmlUCSIsHighSurrogates;
pub use crate::src::xmlunicode::xmlUCSIsHiragana;
pub use crate::src::xmlunicode::xmlUCSIsIPAExtensions;
pub use crate::src::xmlunicode::xmlUCSIsIdeographicDescriptionCharacters;
pub use crate::src::xmlunicode::xmlUCSIsKanbun;
pub use crate::src::xmlunicode::xmlUCSIsKangxiRadicals;
pub use crate::src::xmlunicode::xmlUCSIsKannada;
pub use crate::src::xmlunicode::xmlUCSIsKatakana;
pub use crate::src::xmlunicode::xmlUCSIsKatakanaPhoneticExtensions;
pub use crate::src::xmlunicode::xmlUCSIsKhmer;
pub use crate::src::xmlunicode::xmlUCSIsKhmerSymbols;
pub use crate::src::xmlunicode::xmlUCSIsLao;
pub use crate::src::xmlunicode::xmlUCSIsLatin1Supplement;
pub use crate::src::xmlunicode::xmlUCSIsLatinExtendedA;
pub use crate::src::xmlunicode::xmlUCSIsLatinExtendedAdditional;
pub use crate::src::xmlunicode::xmlUCSIsLatinExtendedB;
pub use crate::src::xmlunicode::xmlUCSIsLetterlikeSymbols;
pub use crate::src::xmlunicode::xmlUCSIsLimbu;
pub use crate::src::xmlunicode::xmlUCSIsLinearBIdeograms;
pub use crate::src::xmlunicode::xmlUCSIsLinearBSyllabary;
pub use crate::src::xmlunicode::xmlUCSIsLowSurrogates;
pub use crate::src::xmlunicode::xmlUCSIsMalayalam;
pub use crate::src::xmlunicode::xmlUCSIsMathematicalAlphanumericSymbols;
pub use crate::src::xmlunicode::xmlUCSIsMathematicalOperators;
pub use crate::src::xmlunicode::xmlUCSIsMiscellaneousMathematicalSymbolsA;
pub use crate::src::xmlunicode::xmlUCSIsMiscellaneousMathematicalSymbolsB;
pub use crate::src::xmlunicode::xmlUCSIsMiscellaneousSymbols;
pub use crate::src::xmlunicode::xmlUCSIsMiscellaneousSymbolsandArrows;
pub use crate::src::xmlunicode::xmlUCSIsMiscellaneousTechnical;
pub use crate::src::xmlunicode::xmlUCSIsMongolian;
pub use crate::src::xmlunicode::xmlUCSIsMusicalSymbols;
pub use crate::src::xmlunicode::xmlUCSIsMyanmar;
pub use crate::src::xmlunicode::xmlUCSIsNumberForms;
pub use crate::src::xmlunicode::xmlUCSIsOgham;
pub use crate::src::xmlunicode::xmlUCSIsOldItalic;
pub use crate::src::xmlunicode::xmlUCSIsOpticalCharacterRecognition;
pub use crate::src::xmlunicode::xmlUCSIsOriya;
pub use crate::src::xmlunicode::xmlUCSIsOsmanya;
pub use crate::src::xmlunicode::xmlUCSIsPhoneticExtensions;
pub use crate::src::xmlunicode::xmlUCSIsPrivateUse;
pub use crate::src::xmlunicode::xmlUCSIsPrivateUseArea;
pub use crate::src::xmlunicode::xmlUCSIsRunic;
pub use crate::src::xmlunicode::xmlUCSIsShavian;
pub use crate::src::xmlunicode::xmlUCSIsSinhala;
pub use crate::src::xmlunicode::xmlUCSIsSmallFormVariants;
pub use crate::src::xmlunicode::xmlUCSIsSpacingModifierLetters;
pub use crate::src::xmlunicode::xmlUCSIsSpecials;
pub use crate::src::xmlunicode::xmlUCSIsSuperscriptsandSubscripts;
pub use crate::src::xmlunicode::xmlUCSIsSupplementalArrowsA;
pub use crate::src::xmlunicode::xmlUCSIsSupplementalArrowsB;
pub use crate::src::xmlunicode::xmlUCSIsSupplementalMathematicalOperators;
pub use crate::src::xmlunicode::xmlUCSIsSupplementaryPrivateUseAreaA;
pub use crate::src::xmlunicode::xmlUCSIsSupplementaryPrivateUseAreaB;
pub use crate::src::xmlunicode::xmlUCSIsSyriac;
pub use crate::src::xmlunicode::xmlUCSIsTagalog;
pub use crate::src::xmlunicode::xmlUCSIsTagbanwa;
pub use crate::src::xmlunicode::xmlUCSIsTags;
pub use crate::src::xmlunicode::xmlUCSIsTaiLe;
pub use crate::src::xmlunicode::xmlUCSIsTaiXuanJingSymbols;
pub use crate::src::xmlunicode::xmlUCSIsTamil;
pub use crate::src::xmlunicode::xmlUCSIsTelugu;
pub use crate::src::xmlunicode::xmlUCSIsThaana;
pub use crate::src::xmlunicode::xmlUCSIsThai;
pub use crate::src::xmlunicode::xmlUCSIsTibetan;
pub use crate::src::xmlunicode::xmlUCSIsUgaritic;
pub use crate::src::xmlunicode::xmlUCSIsUnifiedCanadianAboriginalSyllabics;
pub use crate::src::xmlunicode::xmlUCSIsVariationSelectors;
pub use crate::src::xmlunicode::xmlUCSIsVariationSelectorsSupplement;
pub use crate::src::xmlunicode::xmlUCSIsYiRadicals;
pub use crate::src::xmlunicode::xmlUCSIsYiSyllables;
pub use crate::src::xmlunicode::xmlUCSIsYijingHexagramSymbols;
pub use crate::src::xpath::valuePop;
pub use crate::src::xpath::xmlXPathAddValues;
pub use crate::src::xpath::xmlXPathBooleanFunction;
pub use crate::src::xpath::xmlXPathCastBooleanToNumber;
pub use crate::src::xpath::xmlXPathCastBooleanToString;
pub use crate::src::xpath::xmlXPathCastNodeToNumber;
pub use crate::src::xpath::xmlXPathCastNodeToString;
pub use crate::src::xpath::xmlXPathCastNumberToBoolean;
pub use crate::src::xpath::xmlXPathCastNumberToString;
pub use crate::src::xpath::xmlXPathCastStringToBoolean;
pub use crate::src::xpath::xmlXPathCastStringToNumber;
pub use crate::src::xpath::xmlXPathCeilingFunction;
pub use crate::src::xpath::xmlXPathCmpNodes;
pub use crate::src::xpath::xmlXPathCompareValues;
pub use crate::src::xpath::xmlXPathConcatFunction;
pub use crate::src::xpath::xmlXPathContainsFunction;
pub use crate::src::xpath::xmlXPathContextSetCache;
pub use crate::src::xpath::xmlXPathCountFunction;
pub use crate::src::xpath::xmlXPathDivValues;
pub use crate::src::xpath::xmlXPathEqualValues;
pub use crate::src::xpath::xmlXPathErr;
pub use crate::src::xpath::xmlXPathEval;
pub use crate::src::xpath::xmlXPathEvalExpr;
pub use crate::src::xpath::xmlXPathEvalExpression;
pub use crate::src::xpath::xmlXPathFalseFunction;
pub use crate::src::xpath::xmlXPathFloorFunction;
pub use crate::src::xpath::xmlXPathFreeContext;
pub use crate::src::xpath::xmlXPathFreeParserContext;
pub use crate::src::xpath::xmlXPathIdFunction;
pub use crate::src::xpath::xmlXPathInit;
pub use crate::src::xpath::xmlXPathIsInf;
pub use crate::src::xpath::xmlXPathIsNaN;
pub use crate::src::xpath::xmlXPathIsNodeType;
pub use crate::src::xpath::xmlXPathLangFunction;
pub use crate::src::xpath::xmlXPathLastFunction;
pub use crate::src::xpath::xmlXPathLocalNameFunction;
pub use crate::src::xpath::xmlXPathModValues;
pub use crate::src::xpath::xmlXPathMultValues;
pub use crate::src::xpath::xmlXPathNamespaceURIFunction;
pub use crate::src::xpath::xmlXPathNewBoolean;
pub use crate::src::xpath::xmlXPathNewCString;
pub use crate::src::xpath::xmlXPathNewContext;
pub use crate::src::xpath::xmlXPathNewFloat;
pub use crate::src::xpath::xmlXPathNewNodeSet;
pub use crate::src::xpath::xmlXPathNewParserContext;
pub use crate::src::xpath::xmlXPathNewString;
pub use crate::src::xpath::xmlXPathNewValueTree;
pub use crate::src::xpath::xmlXPathNextAncestor;
pub use crate::src::xpath::xmlXPathNextAncestorOrSelf;
pub use crate::src::xpath::xmlXPathNextAttribute;
pub use crate::src::xpath::xmlXPathNextChild;
pub use crate::src::xpath::xmlXPathNextDescendant;
pub use crate::src::xpath::xmlXPathNextDescendantOrSelf;
pub use crate::src::xpath::xmlXPathNextFollowing;
pub use crate::src::xpath::xmlXPathNextFollowingSibling;
pub use crate::src::xpath::xmlXPathNextNamespace;
pub use crate::src::xpath::xmlXPathNextParent;
pub use crate::src::xpath::xmlXPathNextPreceding;
pub use crate::src::xpath::xmlXPathNextPrecedingSibling;
pub use crate::src::xpath::xmlXPathNextSelf;
pub use crate::src::xpath::xmlXPathNodeEval;
pub use crate::src::xpath::xmlXPathNodeSetFreeNs;
pub use crate::src::xpath::xmlXPathNormalizeFunction;
pub use crate::src::xpath::xmlXPathNotEqualValues;
pub use crate::src::xpath::xmlXPathNotFunction;
pub use crate::src::xpath::xmlXPathNsLookup;
pub use crate::src::xpath::xmlXPathNumberFunction;
pub use crate::src::xpath::xmlXPathOrderDocElems;
pub use crate::src::xpath::xmlXPathParseNCName;
pub use crate::src::xpath::xmlXPathParseName;
pub use crate::src::xpath::xmlXPathPopBoolean;
pub use crate::src::xpath::xmlXPathPopNumber;
pub use crate::src::xpath::xmlXPathPopString;
pub use crate::src::xpath::xmlXPathPositionFunction;
pub use crate::src::xpath::xmlXPathRegisterAllFunctions;
pub use crate::src::xpath::xmlXPathRegisterNs;
pub use crate::src::xpath::xmlXPathRegisteredFuncsCleanup;
pub use crate::src::xpath::xmlXPathRegisteredNsCleanup;
pub use crate::src::xpath::xmlXPathRegisteredVariablesCleanup;
pub use crate::src::xpath::xmlXPathRoot;
pub use crate::src::xpath::xmlXPathRoundFunction;
pub use crate::src::xpath::xmlXPathStartsWithFunction;
pub use crate::src::xpath::xmlXPathStringEvalNumber;
pub use crate::src::xpath::xmlXPathStringFunction;
pub use crate::src::xpath::xmlXPathStringLengthFunction;
pub use crate::src::xpath::xmlXPathSubValues;
pub use crate::src::xpath::xmlXPathSubstringAfterFunction;
pub use crate::src::xpath::xmlXPathSubstringBeforeFunction;
pub use crate::src::xpath::xmlXPathSubstringFunction;
pub use crate::src::xpath::xmlXPathSumFunction;
pub use crate::src::xpath::xmlXPathTranslateFunction;
pub use crate::src::xpath::xmlXPathTrueFunction;
pub use crate::src::xpath::xmlXPathValueFlipSign;
pub use crate::src::xpath::xmlXPathVariableLookup;
pub use crate::src::xpath::xmlXPathVariableLookupNS;
pub use crate::src::xpath::xmlXPatherror;
pub use crate::src::xpointer::xmlXPtrEval;
pub use crate::src::xpointer::xmlXPtrNewContext;
pub use crate::src::buf::_xmlBuf;
pub use crate::src::catalog::_xmlCatalog;
pub use crate::src::dict::_xmlDict;
pub use crate::src::hash::_xmlHashTable;
pub use crate::src::parser::_xmlStartTag;
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
pub use crate::src::HTMLtree::_IO_codecvt;
pub use crate::src::buf::_IO_marker;
pub use crate::src::globals::xmlFree;
pub use crate::src::python::types::_IO_wide_data;
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
pub type PyTypeObject = crate::src::python::libxml::PyTypeObject;
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
pub type xmlDtd = crate::src::HTMLparser::xmlDtd;
pub type xmlDtdPtr = crate::src::HTMLparser::xmlDtdPtr;
pub type xmlFreeFunc = crate::src::HTMLparser::xmlFreeFunc;
pub type xmlValidCtxtPtr = crate::src::SAX2::xmlValidCtxtPtr;
pub type xmlSchemaAnnotPtr = crate::src::relaxng::xmlSchemaAnnotPtr;
pub type xmlSchemaAnnot = crate::src::relaxng::xmlSchemaAnnot;
// #[derive(Copy, Clone)]

pub type _xmlSchemaAnnot = crate::src::relaxng::_xmlSchemaAnnot;
// #[derive(Copy, Clone)]

pub type _xmlSchema = crate::src::xmlschemas::_xmlSchema;
pub type xmlSchema = crate::src::xmllint::xmlSchema;
pub type xmlSchemaPtr = crate::src::xmllint::xmlSchemaPtr;
pub type xmlSchemaParserCtxt = crate::src::relaxng::xmlSchemaParserCtxt;
pub type xmlSchemaParserCtxtPtr = crate::src::relaxng::xmlSchemaParserCtxtPtr;
pub type xmlSchemaValidCtxt = crate::src::xmllint::xmlSchemaValidCtxt;
pub type xmlSchemaValidCtxtPtr = crate::src::xmllint::xmlSchemaValidCtxtPtr;
pub type htmlParserCtxtPtr = crate::src::HTMLparser::htmlParserCtxtPtr;
pub type htmlDocPtr = crate::src::HTMLparser::htmlDocPtr;
pub type htmlNodePtr = crate::src::HTMLparser::htmlNodePtr;
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
pub type xmlTextReader = crate::src::xmllint::xmlTextReader;
pub type xmlTextReaderPtr = crate::src::xmllint::xmlTextReaderPtr;
pub type xmlTextReaderLocatorPtr = crate::src::xmlreader::xmlTextReaderLocatorPtr;
// #[derive(Copy, Clone)]

pub type PyxmlNode_Object = crate::src::python::libxml::PyxmlNode_Object;
// #[derive(Copy, Clone)]

pub type PyxmlXPathContext_Object = crate::src::python::libxml::PyxmlXPathContext_Object;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlXPathParserContext_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlXPathParserContextPtr,
}
// #[derive(Copy, Clone)]

pub type PyparserCtxt_Object = crate::src::python::libxml::PyparserCtxt_Object;
// #[derive(Copy, Clone)]

pub type PyValidCtxt_Object = crate::src::python::libxml::PyValidCtxt_Object;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Pycatalog_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlCatalogPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlReg_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlRegexpPtr,
}
// #[derive(Copy, Clone)]

pub type PyxmlTextReader_Object = crate::src::python::libxml::PyxmlTextReader_Object;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlTextReaderLocator_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlTextReaderLocatorPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyError_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlErrorPtr,
}
// #[derive(Copy, Clone)]

pub type PyoutputBuffer_Object = crate::src::python::libxml::PyoutputBuffer_Object;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyinputBuffer_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlParserInputBufferPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyURI_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlURIPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyrelaxNgSchema_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlRelaxNGPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyrelaxNgParserCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlRelaxNGParserCtxtPtr,
}
// #[derive(Copy, Clone)]

pub type PyrelaxNgValidCtxt_Object = crate::src::python::libxml::PyrelaxNgValidCtxt_Object;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PySchema_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlSchemaPtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PySchemaParserCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlSchemaParserCtxtPtr,
}
// #[derive(Copy, Clone)]

pub type PySchemaValidCtxt_Object = crate::src::python::libxml::PySchemaValidCtxt_Object;
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlAutoCloseTag(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OzO:htmlAutoCloseTag\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as htmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = htmlAutoCloseTag(doc, name, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCreateFileParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlCreateFileParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlCreateFileParserCtxt(filename, encoding);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCreateMemoryParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:htmlCreateMemoryParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlCreateMemoryParserCtxt(buffer, size);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtReadDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:htmlCtxtReadDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlCtxtReadDoc(ctxt, cur, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtReadFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:htmlCtxtReadFd\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlCtxtReadFd(ctxt, fd, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtReadFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:htmlCtxtReadFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlCtxtReadFile(ctxt, filename, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtReadMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izzi:htmlCtxtReadMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlCtxtReadMemory(ctxt, buffer, size, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtReset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlCtxtReset\0" as *const u8 as *const i8 as *mut i8,
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
    htmlCtxtReset(ctxt);
    let fresh0 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh0 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtUseOptions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:htmlCtxtUseOptions\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlCtxtUseOptions(ctxt, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlDefaultSAXHandlerInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"htmlDefaultSAXHandlerInit\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    htmlDefaultSAXHandlerInit();
    let fresh1 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh1 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlDocContentDumpFormatOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzi:htmlDocContentDumpFormatOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
        &mut format as *mut i32,
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
    htmlDocContentDumpFormatOutput(buf, cur, encoding, format);
    let fresh2 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh2 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlDocContentDumpOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:htmlDocContentDumpOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
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
    htmlDocContentDumpOutput(buf, cur, encoding);
    let fresh3 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh3 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlDocDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:htmlDocDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_f).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_f)
    } else {
        stdout
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = htmlDocDump(f, cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlFreeParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlFreeParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
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
    htmlFreeParserCtxt(ctxt);
    let fresh4 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh4 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlGetMetaEncoding(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlGetMetaEncoding\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as htmlDocPtr;
    c_retval = htmlGetMetaEncoding(doc);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlHandleOmittedElem(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:htmlHandleOmittedElem\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlHandleOmittedElem(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlInitAutoClose(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"htmlInitAutoClose\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    htmlInitAutoClose();
    let fresh5 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh5 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlIsAutoClosed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:htmlIsAutoClosed\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as htmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = htmlIsAutoClosed(doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlIsBooleanAttr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:htmlIsBooleanAttr\0" as *const u8 as *const i8
            as *mut i8,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlIsBooleanAttr(name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlIsScriptAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:htmlIsScriptAttribute\0" as *const u8 as *const i8
            as *mut i8,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlIsScriptAttribute(name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNewDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlNewDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut URI as *mut *mut xmlChar,
        &mut ExternalID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlNewDoc(URI, ExternalID);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNewDocNoDtD(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlNewDocNoDtD\0" as *const u8 as *const i8 as *mut i8,
        &mut URI as *mut *mut xmlChar,
        &mut ExternalID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlNewDocNoDtD(URI, ExternalID);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNewParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    c_retval = htmlNewParserCtxt();
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNodeDumpFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:htmlNodeDumpFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_out as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_out).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_out)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    htmlNodeDumpFile(out, doc, cur);
    let fresh6 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh6 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNodeDumpFileFormat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzi:htmlNodeDumpFileFormat\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_out as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_out).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_out)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = htmlNodeDumpFileFormat(out, doc, cur, encoding, format);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNodeDumpFormatOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzi:htmlNodeDumpFormatOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    htmlNodeDumpFormatOutput(buf, doc, cur, encoding, format);
    let fresh7 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh7 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNodeDumpOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:htmlNodeDumpOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    htmlNodeDumpOutput(buf, doc, cur, encoding);
    let fresh8 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh8 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseCharRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlParseCharRef\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = htmlParseCharRef(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseChunk(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut terminate: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#ii:htmlParseChunk\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut terminate as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = htmlParseChunk(ctxt, chunk, size, terminate);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlParseDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlParseDoc(cur, encoding);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlParseDocument\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = htmlParseDocument(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlParseElement\0" as *const u8 as *const i8 as *mut i8,
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
    htmlParseElement(ctxt);
    let fresh9 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh9 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlParseFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlParseFile(filename, encoding);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlReadDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:htmlReadDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlReadDoc(cur, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlReadFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:htmlReadFd\0" as *const u8 as *const i8 as *mut i8,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlReadFd(fd, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlReadFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:htmlReadFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlReadFile(filename, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlReadMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#izzi:htmlReadMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = htmlReadMemory(buffer, size, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlSaveFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:htmlSaveFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = htmlSaveFile(filename, cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlSaveFileEnc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOz:htmlSaveFileEnc\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = htmlSaveFileEnc(filename, cur, encoding);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlSaveFileFormat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOzi:htmlSaveFileFormat\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = htmlSaveFileFormat(filename, cur, encoding, format);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlSetMetaEncoding(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:htmlSetMetaEncoding\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut encoding as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as htmlDocPtr;
    c_retval = htmlSetMetaEncoding(doc, encoding);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_namePop(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:namePop\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = namePop(ctxt);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_namePush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:namePush\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = namePush(ctxt, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_nodePop(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:nodePop\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = nodePop(ctxt);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_nodePush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_value: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:nodePush\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_value as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    value = if pyobj_value == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_value as *mut PyxmlNode_Object)).obj
    };
    c_retval = nodePush(ctxt, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_valuePop(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:valuePop\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = valuePop(ctxt);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogAdd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzz:xmlACatalogAdd\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut type_0 as *mut *mut xmlChar,
        &mut orig as *mut *mut xmlChar,
        &mut replace as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogAdd(catal, type_0, orig, replace);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlACatalogDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut pyobj_out as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_out).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_out)
    } else {
        stdout
    };
    xmlACatalogDump(catal, out);
    let fresh10 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh10 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogRemove(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlACatalogRemove\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogRemove(catal, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogResolve(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlACatalogResolve\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut pubID as *mut *mut xmlChar,
        &mut sysID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogResolve(catal, pubID, sysID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogResolvePublic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlACatalogResolvePublic\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut pubID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogResolvePublic(catal, pubID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogResolveSystem(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlACatalogResolveSystem\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut sysID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogResolveSystem(catal, sysID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogResolveURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlACatalogResolveURI\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
        &mut URI as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlACatalogResolveURI(catal, URI);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlAddChild\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlAddChild(parent, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddChildList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlAddChildList\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlAddChildList(parent, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddDocEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut type_0: i32 = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlAddDocEntity\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut i32,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlAddDocEntity(doc, name, type_0, ExternalID, SystemID, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddDtdEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut type_0: i32 = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlAddDtdEntity\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut i32,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlAddDtdEntity(doc, name, type_0, ExternalID, SystemID, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddEncodingAlias(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut i8 = 0 as *mut i8;
    let mut alias: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlAddEncodingAlias\0" as *const u8 as *const i8
            as *mut i8,
        &mut name as *mut *mut i8,
        &mut alias as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlAddEncodingAlias(name, alias);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddNextSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlAddNextSibling\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlAddNextSibling(cur, elem);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddPrevSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlAddPrevSibling\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlAddPrevSibling(cur, elem);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlAddSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlAddSibling\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlAddSibling(cur, elem);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlBoolToText(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut boolval: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlBoolToText\0" as *const u8 as *const i8 as *mut i8,
        &mut boolval as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlBoolToText(boolval);
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlBuildQName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ncname: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut memory: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlBuildQName\0" as *const u8 as *const i8 as *mut i8,
        &mut ncname as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
        &mut memory as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlBuildQName(ncname, prefix, memory, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlBuildRelativeURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlBuildRelativeURI\0" as *const u8 as *const i8
            as *mut i8,
        &mut URI as *mut *mut xmlChar,
        &mut base as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlBuildRelativeURI(URI, base);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlBuildURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlBuildURI\0" as *const u8 as *const i8 as *mut i8,
        &mut URI as *mut *mut xmlChar,
        &mut base as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlBuildURI(URI, base);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlByteConsumed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlByteConsumed\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlByteConsumed(ctxt);
    py_retval = libxml_longWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCanonicPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCanonicPath\0" as *const u8 as *const i8 as *mut i8,
        &mut path as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCanonicPath(path);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogAdd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzz:xmlCatalogAdd\0" as *const u8 as *const i8 as *mut i8,
        &mut type_0 as *mut *mut xmlChar,
        &mut orig as *mut *mut xmlChar,
        &mut replace as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogAdd(type_0, orig, replace);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCatalogCleanup();
    let fresh11 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh11 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogConvert(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = xmlCatalogConvert();
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCatalogDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_out as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_out).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_out)
    } else {
        stdout
    };
    xmlCatalogDump(out);
    let fresh12 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh12 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogGetPublic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogGetPublic\0" as *const u8 as *const i8
            as *mut i8,
        &mut pubID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogGetPublic(pubID);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogGetSystem(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogGetSystem\0" as *const u8 as *const i8
            as *mut i8,
        &mut sysID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogGetSystem(sysID);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogIsEmpty(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCatalogIsEmpty\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlCatalogIsEmpty(catal);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogRemove(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogRemove\0" as *const u8 as *const i8 as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogRemove(value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogResolve(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlCatalogResolve\0" as *const u8 as *const i8
            as *mut i8,
        &mut pubID as *mut *mut xmlChar,
        &mut sysID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogResolve(pubID, sysID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogResolvePublic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogResolvePublic\0" as *const u8 as *const i8
            as *mut i8,
        &mut pubID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogResolvePublic(pubID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogResolveSystem(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogResolveSystem\0" as *const u8 as *const i8
            as *mut i8,
        &mut sysID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogResolveSystem(sysID);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogResolveURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogResolveURI\0" as *const u8 as *const i8
            as *mut i8,
        &mut URI as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogResolveURI(URI);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogSetDebug(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut level: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlCatalogSetDebug\0" as *const u8 as *const i8
            as *mut i8,
        &mut level as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCatalogSetDebug(level);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCharStrdup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCharStrdup\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCharStrdup(cur);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCharStrndup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCharStrndup\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut i8,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCharStrndup(cur, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCheckFilename(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut path: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckFilename\0" as *const u8 as *const i8 as *mut i8,
        &mut path as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCheckFilename(path);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCheckLanguageID(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckLanguageID\0" as *const u8 as *const i8
            as *mut i8,
        &mut lang as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCheckLanguageID(lang);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCheckUTF8(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut u8 = 0 as *mut u8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckUTF8\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut u8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCheckUTF8(utf);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCheckVersion(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut version: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlCheckVersion\0" as *const u8 as *const i8 as *mut i8,
        &mut version as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlCheckVersion(version);
    let fresh13 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh13 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupCharEncodingHandlers(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlCleanupCharEncodingHandlers\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlCleanupCharEncodingHandlers();
    let fresh14 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh14 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupEncodingAliases(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupEncodingAliases();
    let fresh15 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh15 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupGlobals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlCleanupGlobals\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlCleanupGlobals();
    let fresh16 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh16 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupInputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupInputCallbacks();
    let fresh17 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh17 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupOutputCallbacks();
    let fresh18 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh18 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupPredefinedEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupPredefinedEntities();
    let fresh19 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh19 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlClearParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlClearParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlClearParserCtxt(ctxt);
    let fresh20 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh20 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlConvertSGMLCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlConvertSGMLCatalog\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    c_retval = xmlConvertSGMLCatalog(catal);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut len: i32 = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izi:xmlCopyChar\0" as *const u8 as *const i8 as *mut i8,
        &mut len as *mut i32,
        &mut out as *mut *mut xmlChar,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCopyChar(len, out, val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyCharMultiByte(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCopyCharMultiByte\0" as *const u8 as *const i8
            as *mut i8,
        &mut out as *mut *mut xmlChar,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCopyCharMultiByte(out, val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut recursive: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCopyDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut recursive as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlCopyDoc(doc, recursive);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyDtd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCopyDtd\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_dtd as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlCopyDtd(dtd);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut from: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_from: *mut PyObject = 0 as *mut PyObject;
    let mut to: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_to: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlCopyError\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_from as *mut *mut PyObject,
        &mut pyobj_to as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    from = if pyobj_from == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_from as *mut PyError_Object)).obj
    };
    to = if pyobj_to == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_to as *mut PyError_Object)).obj
    };
    c_retval = xmlCopyError(from, to);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyNamespace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCopyNamespace\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlCopyNamespace(cur);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyNamespaceList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCopyNamespaceList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlCopyNamespaceList(cur);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut extended: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCopyNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut extended as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlCopyNode(node, extended);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCopyNodeList\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlCopyNodeList(node);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut target: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_target: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlCopyProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_target as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    target = if pyobj_target == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_target as *mut PyxmlNode_Object)).obj
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlCopyProp(target, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCopyPropList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut target: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_target: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlCopyPropList\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_target as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    target = if pyobj_target == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_target as *mut PyxmlNode_Object)).obj
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlCopyPropList(target, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateDocParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCreateDocParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut cur as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCreateDocParserCtxt(cur);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateEntityParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzz:xmlCreateEntityParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut URL as *mut *mut xmlChar,
        &mut ID as *mut *mut xmlChar,
        &mut base as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCreateEntityParserCtxt(URL, ID, base);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateFileParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCreateFileParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCreateFileParserCtxt(filename);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateIntSubset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzz:xmlCreateIntSubset\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlCreateIntSubset(doc, name, ExternalID, SystemID);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateMemoryParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlCreateMemoryParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCreateMemoryParserCtxt(buffer, size);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    c_retval = xmlCreateURI();
    py_retval = libxml_xmlURIPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCreateURLParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCreateURLParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlCreateURLParserCtxt(filename, options);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtReadDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:xmlCtxtReadDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtReadDoc(ctxt, cur, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtReadFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:xmlCtxtReadFd\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtReadFd(ctxt, fd, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtReadFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:xmlCtxtReadFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtReadFile(ctxt, filename, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtReadMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izzi:xmlCtxtReadMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtReadMemory(ctxt, buffer, size, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtReset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCtxtReset\0" as *const u8 as *const i8 as *mut i8,
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
    xmlCtxtReset(ctxt);
    let fresh21 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh21 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtResetPush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izz:xmlCtxtResetPush\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtResetPush(ctxt, chunk, size, filename, encoding);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtUseOptions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCtxtUseOptions\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlCtxtUseOptions(ctxt, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugCheckDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugCheckDocument\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlDebugCheckDocument(output, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpAttr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpAttr\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
        &mut depth as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    xmlDebugDumpAttr(output, attr, depth);
    let fresh22 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh22 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpAttrList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpAttrList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
        &mut depth as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    xmlDebugDumpAttrList(output, attr, depth);
    let fresh23 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh23 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpDTD(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugDumpDTD\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_dtd as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    xmlDebugDumpDTD(output, dtd);
    let fresh24 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh24 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugDumpDocument\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlDebugDumpDocument(output, doc);
    let fresh25 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh25 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpDocumentHead(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugDumpDocumentHead\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlDebugDumpDocumentHead(output, doc);
    let fresh26 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh26 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugDumpEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlDebugDumpEntities(output, doc);
    let fresh27 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh27 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpNode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    xmlDebugDumpNode(output, node, depth);
    let fresh28 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh28 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpNodeList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    xmlDebugDumpNodeList(output, node, depth);
    let fresh29 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh29 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpOneNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpOneNode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    xmlDebugDumpOneNode(output, node, depth);
    let fresh30 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh30 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDebugDumpString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlDebugDumpString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    xmlDebugDumpString(output, str);
    let fresh31 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh31 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDecodeEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    let mut what: i32 = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if libxml_deprecationWarning(
        b"xmlDecodeEntities\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiiccc:xmlDecodeEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut len as *mut i32,
        &mut what as *mut i32,
        &mut end as *mut xmlChar,
        &mut end2 as *mut xmlChar,
        &mut end3 as *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlDecodeEntities(ctxt, len, what, end, end2, end3);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDefaultSAXHandlerInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlDefaultSAXHandlerInit\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlDefaultSAXHandlerInit();
    let fresh32 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh32 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDelEncodingAlias(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut alias: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlDelEncodingAlias\0" as *const u8 as *const i8
            as *mut i8,
        &mut alias as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlDelEncodingAlias(alias);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDictCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlDictCleanup\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlDictCleanup();
    let fresh33 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh33 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocCopyNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut extended: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDocCopyNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut extended as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlDocCopyNode(node, doc, extended);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocCopyNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDocCopyNodeList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlDocCopyNodeList(doc, node);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDocDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_f).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_f)
    } else {
        stdout
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlDocDump(f, cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocFormatDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDocFormatDump\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_f).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_f)
    } else {
        stdout
    };
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlDocFormatDump(f, cur, format);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocGetRootElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlDocGetRootElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlDocGetRootElement(doc);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDocSetRootElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_root: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDocSetRootElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_root as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    root = if pyobj_root == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_root as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlDocSetRootElement(doc, root);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlElemDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlElemDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_f).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_f)
    } else {
        stdout
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlElemDump(f, doc, cur);
    let fresh34 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh34 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlEncodeEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if libxml_deprecationWarning(
        b"xmlEncodeEntities\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlEncodeEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut input as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlEncodeEntities(doc, input);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlEncodeEntitiesReentrant(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlEncodeEntitiesReentrant\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut input as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlEncodeEntitiesReentrant(doc, input);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlEncodeSpecialChars(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlEncodeSpecialChars\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut input as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlEncodeSpecialChars(doc, input);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetCode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetCode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).code;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetDomain(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetDomain\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).domain;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetFile\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).file;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetLevel(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetLevel\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).level as i32;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetLine(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetLine\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).line;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetMessage(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetMessage\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_Error as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_Error as *mut PyError_Object)).obj
    };
    c_retval = (*Error).message;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFileMatch(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlFileMatch\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlFileMatch(filename);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFirstElementChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFirstElementChild\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlFirstElementChild(parent);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeCatalog\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_catal as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        (*(pyobj_catal as *mut Pycatalog_Object)).obj
    };
    xmlFreeCatalog(catal);
    let fresh35 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh35 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlFreeDoc(cur);
    let fresh36 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh36 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeDtd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeDtd\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    xmlFreeDtd(cur);
    let fresh37 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh37 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlFreeNode(cur);
    let fresh38 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh38 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeNodeList\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlFreeNodeList(cur);
    let fresh39 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh39 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeNs\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    xmlFreeNs(cur);
    let fresh40 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh40 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeNsList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeNsList\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    xmlFreeNsList(cur);
    let fresh41 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh41 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeParserInputBuffer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeParserInputBuffer\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_in as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_in as *mut PyinputBuffer_Object)).obj
    };
    xmlFreeParserInputBuffer(in_0);
    let fresh42 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh42 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    xmlFreeProp(cur);
    let fresh43 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh43 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreePropList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreePropList\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    xmlFreePropList(cur);
    let fresh44 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh44 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlFreeURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlFreeURI\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_uri as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_uri as *mut PyURI_Object)).obj
    };
    xmlFreeURI(uri);
    let fresh45 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh45 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetCompressMode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = xmlGetCompressMode();
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDocCompressMode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetDocCompressMode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlGetDocCompressMode(doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDocEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetDocEntity\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlGetDocEntity(doc, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDtdAttrDesc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut elem: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlGetDtdAttrDesc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_dtd as *mut *mut PyObject,
        &mut elem as *mut *mut xmlChar,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlGetDtdAttrDesc(dtd, elem, name);
    py_retval = libxml_xmlAttributePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDtdElementDesc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlElementPtr = 0 as *mut xmlElement;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetDtdElementDesc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_dtd as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlGetDtdElementDesc(dtd, name);
    py_retval = libxml_xmlElementPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDtdEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetDtdEntity\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlGetDtdEntity(doc, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDtdQAttrDesc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut elem: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzz:xmlGetDtdQAttrDesc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_dtd as *mut *mut PyObject,
        &mut elem as *mut *mut xmlChar,
        &mut name as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlGetDtdQAttrDesc(dtd, elem, name, prefix);
    py_retval = libxml_xmlAttributePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetDtdQElementDesc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlElementPtr = 0 as *mut xmlElement;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlGetDtdQElementDesc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_dtd as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlGetDtdQElementDesc(dtd, name, prefix);
    py_retval = libxml_xmlElementPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetEncodingAlias(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut alias: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlGetEncodingAlias\0" as *const u8 as *const i8
            as *mut i8,
        &mut alias as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlGetEncodingAlias(alias);
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetID(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetID\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut ID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlGetID(doc, ID);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetIntSubset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetIntSubset\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlGetIntSubset(doc);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetLastChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetLastChild\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlGetLastChild(parent);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetLastError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlErrorPtr = 0 as *mut xmlError;
    c_retval = xmlGetLastError();
    py_retval = libxml_xmlErrorPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetLineNo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetLineNo\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlGetLineNo(node);
    py_retval = libxml_longWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetNoNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetNoNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlGetNoNsProp(node, name);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetNodePath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetNodePath\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlGetNodePath(node);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlGetNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut nameSpace as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlGetNsProp(node, name, nameSpace);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetParameterEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetParameterEntity\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlGetParameterEntity(doc, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetPredefinedEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlGetPredefinedEntity\0" as *const u8 as *const i8
            as *mut i8,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlGetPredefinedEntity(name);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlGetProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlGetProp(node, name);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlHandleEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut entity: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut pyobj_entity: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlHandleEntity\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlHandleEntity\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_entity as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    entity = (if pyobj_entity == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_entity as *mut PyxmlNode_Object)).obj
    }) as xmlEntityPtr;
    xmlHandleEntity(ctxt, entity);
    let fresh46 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh46 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlHasNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlHasNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut nameSpace as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlHasNsProp(node, name, nameSpace);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlHasProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlHasProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlHasProp(node, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIOFTPMatch(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlIOFTPMatch\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIOFTPMatch(filename);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIOHTTPMatch(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlIOHTTPMatch\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIOHTTPMatch(filename);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitCharEncodingHandlers(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlInitCharEncodingHandlers\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlInitCharEncodingHandlers();
    let fresh47 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh47 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitGlobals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlInitGlobals\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlInitGlobals();
    let fresh48 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh48 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlInitParser();
    let fresh49 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh49 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlInitParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlInitParserCtxt(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitializeCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlInitializeCatalog();
    let fresh50 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh50 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitializeDict(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    if libxml_deprecationWarning(
        b"xmlInitializeDict\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlInitializeDict();
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitializePredefinedEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlInitializePredefinedEntities\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlInitializePredefinedEntities();
    let fresh51 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh51 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsBaseChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsBaseChar\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsBaseChar(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsBlank(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsBlank\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsBlank(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsBlankNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlIsBlankNode\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlIsBlankNode(node);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsChar\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsChar(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsCombining(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsCombining\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsCombining(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsDigit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsDigit\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsDigit(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsExtender(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsExtender\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsExtender(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsID(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlIsID\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlIsID(doc, elem, attr);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsIdeographic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsIdeographic\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsIdeographic(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsLetter(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut c: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsLetter\0" as *const u8 as *const i8 as *mut i8,
        &mut c as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsLetter(c);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsMixedElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlIsMixedElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlIsMixedElement(doc, name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsPubidChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsPubidChar\0" as *const u8 as *const i8 as *mut i8,
        &mut ch as *mut u32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsPubidChar(ch);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(b"xmlIsRef\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlIsRef\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlIsRef(doc, elem, attr);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsXHTML(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut systemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut publicID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlIsXHTML\0" as *const u8 as *const i8 as *mut i8,
        &mut systemID as *mut *mut xmlChar,
        &mut publicID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlIsXHTML(systemID, publicID);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlKeepBlanksDefault(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlKeepBlanksDefault\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlKeepBlanksDefault(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLastElementChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlLastElementChild\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlLastElementChild(parent);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLineNumbersDefault(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlLineNumbersDefault\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlLineNumbersDefault(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLoadACatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadACatalog\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlLoadACatalog(filename);
    py_retval = libxml_xmlCatalogPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLoadCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadCatalog\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlLoadCatalog(filename);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLoadCatalogs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut pathss: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadCatalogs\0" as *const u8 as *const i8 as *mut i8,
        &mut pathss as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlLoadCatalogs(pathss);
    let fresh52 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh52 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLoadSGMLSuperCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadSGMLSuperCatalog\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlLoadSGMLSuperCatalog(filename);
    py_retval = libxml_xmlCatalogPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLsCountNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlLsCountNode\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlLsCountNode(node);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlLsOneNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlLsOneNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    xmlLsOneNode(output, node);
    let fresh53 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh53 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNamespaceParseNCName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlNamespaceParseNCName\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNamespaceParseNCName\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlNamespaceParseNCName(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNamespaceParseNSDef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlNamespaceParseNSDef\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNamespaceParseNSDef\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlNamespaceParseNSDef(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlNanoFTPCleanup\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPCleanup();
    let fresh54 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh54 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlNanoFTPInit\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPInit();
    let fresh55 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh55 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut host: *mut i8 = 0 as *mut i8;
    let mut port: i32 = 0;
    let mut user: *mut i8 = 0 as *mut i8;
    let mut passwd: *mut i8 = 0 as *mut i8;
    let mut type_0: i32 = 0;
    if libxml_deprecationWarning(
        b"xmlNanoFTPProxy\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zizzi:xmlNanoFTPProxy\0" as *const u8 as *const i8
            as *mut i8,
        &mut host as *mut *mut i8,
        &mut port as *mut i32,
        &mut user as *mut *mut i8,
        &mut passwd as *mut *mut i8,
        &mut type_0 as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPProxy(host, port, user, passwd, type_0);
    let fresh56 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh56 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPScanProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut i8 = 0 as *mut i8;
    if libxml_deprecationWarning(
        b"xmlNanoFTPScanProxy\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNanoFTPScanProxy\0" as *const u8 as *const i8
            as *mut i8,
        &mut URL as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPScanProxy(URL);
    let fresh57 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh57 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlNanoHTTPCleanup();
    let fresh58 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh58 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlNanoHTTPInit();
    let fresh59 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh59 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPScanProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNanoHTTPScanProxy\0" as *const u8 as *const i8
            as *mut i8,
        &mut URL as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoHTTPScanProxy(URL);
    let fresh60 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh60 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewCDataBlock(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNewCDataBlock\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewCDataBlock(doc, content, len);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut sgml: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlNewCatalog\0" as *const u8 as *const i8 as *mut i8,
        &mut sgml as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewCatalog(sgml);
    py_retval = libxml_xmlCatalogPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewCharRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewCharRef\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewCharRef(doc, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewChild\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewChild(parent, ns, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewComment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNewComment\0" as *const u8 as *const i8 as *mut i8,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewComment(content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNewDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut version as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewDoc(version);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocComment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewDocComment\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDocComment(doc, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocFragment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNewDocFragment\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDocFragment(doc);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewDocNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewDocNode(doc, ns, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocNodeEatName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewDocNodeEatName\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewDocNodeEatName(doc, ns, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocPI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewDocPI\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDocPI(doc, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewDocProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDocProp(doc, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocRawNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewDocRawNode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewDocRawNode(doc, ns, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocText(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewDocText\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlNewDocText(doc, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDocTextLen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNewDocTextLen\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDocTextLen(doc, content, len);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewDtd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzz:xmlNewDtd\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewDtd(doc, name, ExternalID, SystemID);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut type_0: i32 = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlNewEntity\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut i32,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewEntity(doc, name, type_0, ExternalID, SystemID, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewGlobalNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if libxml_deprecationWarning(b"xmlNewGlobalNs\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewGlobalNs\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut href as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlNewGlobalNs(doc, href, prefix);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewNodeEatName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewNodeEatName\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewNodeEatName(ns, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewNs\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut href as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNewNs(node, href, prefix);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewNsProp(node, ns, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewNsPropEatName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewNsPropEatName\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewNsPropEatName(node, ns, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewPI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlNewPI\0" as *const u8 as *const i8 as *mut i8,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewPI(name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    c_retval = xmlNewParserCtxt();
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNewProp(node, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewReference\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlNewReference(doc, name);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewText(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNewText\0" as *const u8 as *const i8 as *mut i8,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewText(content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewTextChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlNewTextChild\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_parent as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_parent as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlNewTextChild(parent, ns, name, content);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewTextLen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlNewTextLen\0" as *const u8 as *const i8 as *mut i8,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewTextLen(content, len);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewTextReader(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_input: *mut PyObject = 0 as *mut PyObject;
    let mut URI: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewTextReader\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_input as *mut *mut PyObject,
        &mut URI as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    input = if pyobj_input == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_input as *mut PyinputBuffer_Object)).obj
    };
    c_retval = xmlNewTextReader(input, URI);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewTextReaderFilename(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut URI: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNewTextReaderFilename\0" as *const u8 as *const i8
            as *mut i8,
        &mut URI as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNewTextReaderFilename(URI);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNewValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    c_retval = xmlNewValidCtxt();
    py_retval = libxml_xmlValidCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNextChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNextChar\0" as *const u8 as *const i8 as *mut i8,
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
    xmlNextChar(ctxt);
    let fresh61 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh61 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNextElementSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNextElementSibling\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlNextElementSibling(node);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeAddContent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeAddContent\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeAddContent(cur, content);
    let fresh62 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh62 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeAddContentLen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNodeAddContentLen\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeAddContentLen(cur, content, len);
    let fresh63 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh63 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeDumpOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut level: i32 = 0;
    let mut format: i32 = 0;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOiiz:xmlNodeDumpOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut level as *mut i32,
        &mut format as *mut i32,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeDumpOutput(buf, doc, cur, level, format, encoding);
    let fresh64 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh64 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetBase(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlNodeGetBase\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeGetBase(doc, cur);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetContent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetContent\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeGetContent(cur);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetLang(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetLang\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeGetLang(cur);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeGetSpacePreserve(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetSpacePreserve\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeGetSpacePreserve(cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeIsText(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeIsText\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlNodeIsText(node);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeListGetRawString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut list: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut inLine: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlNodeListGetRawString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_list as *mut *mut PyObject,
        &mut inLine as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    list = if pyobj_list == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_list as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeListGetRawString(doc, list, inLine);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeListGetString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut list: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut inLine: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlNodeListGetString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_list as *mut *mut PyObject,
        &mut inLine as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    list = if pyobj_list == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_list as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlNodeListGetString(doc, list, inLine);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetBase(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut uri: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeSetBase\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut uri as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetBase(cur, uri);
    let fresh65 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh65 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetContent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeSetContent\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetContent(cur, content);
    let fresh66 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh66 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetContentLen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNodeSetContentLen\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetContentLen(cur, content, len);
    let fresh67 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh67 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetLang(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeSetLang\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut lang as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetLang(cur, lang);
    let fresh68 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh68 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNodeSetName\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetName(cur, name);
    let fresh69 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh69 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNodeSetSpacePreserve(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlNodeSetSpacePreserve\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlNodeSetSpacePreserve(cur, val);
    let fresh70 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh70 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNormalizeURIPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut path: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNormalizeURIPath\0" as *const u8 as *const i8
            as *mut i8,
        &mut path as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNormalizeURIPath(path);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNormalizeWindowsPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNormalizeWindowsPath\0" as *const u8 as *const i8
            as *mut i8,
        &mut path as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlNormalizeWindowsPath(path);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlOutputBufferGetContent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlOutputBufferGetContent\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlOutputBufferGetContent(out);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlOutputBufferWrite(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    let mut buf: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiz:xmlOutputBufferWrite\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_out as *mut *mut PyObject,
        &mut len as *mut i32,
        &mut buf as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_out as *mut PyoutputBuffer_Object)).obj
    };
    c_retval = xmlOutputBufferWrite(out, len, buf);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlOutputBufferWriteString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlOutputBufferWriteString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_out as *mut *mut PyObject,
        &mut str as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        (*(pyobj_out as *mut PyoutputBuffer_Object)).obj
    };
    c_retval = xmlOutputBufferWriteString(out, str);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseAttValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseAttValue\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseAttValue(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseAttributeListDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseAttributeListDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseAttributeListDecl(ctxt);
    let fresh71 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh71 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseCDSect(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseCDSect\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseCDSect(ctxt);
    let fresh72 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh72 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseCatalogFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseCatalogFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseCatalogFile(filename);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseCharData(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cdata: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParseCharData\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cdata as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    xmlParseCharData(ctxt, cdata);
    let fresh73 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh73 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseCharRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseCharRef\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseCharRef(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseChunk(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut terminate: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#ii:xmlParseChunk\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut terminate as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlParseChunk(ctxt, chunk, size, terminate);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseComment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseComment\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseComment(ctxt);
    let fresh74 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh74 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseContent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseContent\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseContent(ctxt);
    let fresh75 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh75 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseDTD(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlParseDTD\0" as *const u8 as *const i8 as *mut i8,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseDTD(ExternalID, SystemID);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseDoc(cur);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseDocTypeDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseDocTypeDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseDocTypeDecl(ctxt);
    let fresh76 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh76 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseDocument\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseDocument(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseElement\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseElement(ctxt);
    let fresh77 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh77 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseElementDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseElementDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseElementDecl(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEncName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseEncName\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseEncName(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEncodingDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseEncodingDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseEncodingDecl(ctxt);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEndTag(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseEndTag\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseEndTag(ctxt);
    let fresh78 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh78 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEntity(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseEntity\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseEntity(filename);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEntityDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseEntityDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseEntityDecl(ctxt);
    let fresh79 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh79 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseEntityRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseEntityRef\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseEntityRef(ctxt);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseExtParsedEnt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseExtParsedEnt\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseExtParsedEnt(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseExternalSubset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlParseExternalSubset\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut ExternalID as *mut *mut xmlChar,
        &mut SystemID as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    xmlParseExternalSubset(ctxt, ExternalID, SystemID);
    let fresh80 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh80 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseFile(filename);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseMarkupDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseMarkupDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseMarkupDecl(ctxt);
    let fresh81 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh81 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlParseMemory\0" as *const u8 as *const i8 as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseMemory(buffer, size);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseMisc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseMisc\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseMisc(ctxt);
    let fresh82 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh82 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseName\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseName(ctxt);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseNamespace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlParseNamespace\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseNamespace\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseNamespace(ctxt);
    let fresh83 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh83 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseNmtoken(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseNmtoken\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseNmtoken(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseNotationDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseNotationDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseNotationDecl(ctxt);
    let fresh84 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh84 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParsePEReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParsePEReference\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParsePEReference(ctxt);
    let fresh85 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh85 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParsePI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParsePI\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParsePI(ctxt);
    let fresh86 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh86 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParsePITarget(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParsePITarget\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParsePITarget(ctxt);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParsePubidLiteral(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParsePubidLiteral\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParsePubidLiteral(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseQuotedString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlParseQuotedString\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseQuotedString\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseQuotedString(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseReference\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParseReference(ctxt);
    let fresh87 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh87 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseSDDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseSDDecl\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseSDDecl(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseStartTag(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseStartTag\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlParseStartTag(ctxt);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseSystemLiteral(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseSystemLiteral\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseSystemLiteral(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseTextDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseTextDecl\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseTextDecl(ctxt);
    let fresh88 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh88 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    let mut str: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseURI\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseURI(str);
    py_retval = libxml_xmlURIPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseURIRaw(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut raw: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlParseURIRaw\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut i8,
        &mut raw as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParseURIRaw(str, raw);
    py_retval = libxml_xmlURIPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseURIReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlParseURIReference\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_uri as *mut *mut PyObject,
        &mut str as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_uri as *mut PyURI_Object)).obj
    };
    c_retval = xmlParseURIReference(uri, str);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseVersionInfo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseVersionInfo\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseVersionInfo(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseVersionNum(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseVersionNum\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlParseVersionNum(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseXMLDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseXMLDecl\0" as *const u8 as *const i8 as *mut i8,
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
    xmlParseXMLDecl(ctxt);
    let fresh89 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh89 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserGetDirectory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParserGetDirectory\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlParserGetDirectory(filename);
    py_retval = libxml_charPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserGetDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserGetDoc\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = (*ctxt).myDoc;
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserGetIsValid(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserGetIsValid\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = (*ctxt).valid;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserGetWellFormed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserGetWellFormed\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = (*ctxt).wellFormed;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserHandlePEReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserHandlePEReference\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParserHandlePEReference(ctxt);
    let fresh90 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh90 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserHandleReference(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(
        b"xmlParserHandleReference\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserHandleReference\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlParserHandleReference(ctxt);
    let fresh91 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh91 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserInputBufferGrow(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserInputBufferGrow\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_in as *mut PyinputBuffer_Object)).obj
    };
    c_retval = xmlParserInputBufferGrow(in_0, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserInputBufferPush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    let mut buf: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiz:xmlParserInputBufferPush\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut i32,
        &mut buf as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_in as *mut PyinputBuffer_Object)).obj
    };
    c_retval = xmlParserInputBufferPush(in_0, len, buf);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserInputBufferRead(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserInputBufferRead\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_in as *mut PyinputBuffer_Object)).obj
    };
    c_retval = xmlParserInputBufferRead(in_0, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserSetLineNumbers(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut linenumbers: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetLineNumbers\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut linenumbers as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    (*ctxt).linenumbers = linenumbers;
    let fresh92 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh92 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserSetLoadSubset(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut loadsubset: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetLoadSubset\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut loadsubset as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    (*ctxt).loadsubset = loadsubset;
    let fresh93 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh93 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserSetPedantic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut pedantic: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetPedantic\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pedantic as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    (*ctxt).pedantic = pedantic;
    let fresh94 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh94 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserSetReplaceEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut replaceEntities: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetReplaceEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut replaceEntities as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    (*ctxt).replaceEntities = replaceEntities;
    let fresh95 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh95 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserSetValidate(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut validate: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetValidate\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut validate as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    (*ctxt).validate = validate;
    let fresh96 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh96 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPathToURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlPathToURI\0" as *const u8 as *const i8 as *mut i8,
        &mut path as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlPathToURI(path);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPedanticParserDefault(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlPedanticParserDefault\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlPedanticParserDefault(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPopInput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlChar = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlPopInput\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlPopInput(ctxt);
    py_retval = libxml_intWrap(c_retval as i32);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPopOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = xmlPopOutputCallbacks();
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPreviousElementSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlPreviousElementSibling\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlPreviousElementSibling(node);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPrintURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut stream: *mut FILE = 0 as *mut FILE;
    let mut pyobj_stream: *mut PyObject = 0 as *mut PyObject;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlPrintURI\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_stream as *mut *mut PyObject,
        &mut pyobj_uri as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    stream = if pyobj_stream == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_stream).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_stream).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_stream)
    } else {
        stdout
    };
    uri = if pyobj_uri == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_uri as *mut PyURI_Object)).obj
    };
    xmlPrintURI(stream, uri);
    let fresh97 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh97 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReadDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlReadDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReadDoc(cur, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReadFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:xmlReadFd\0" as *const u8 as *const i8 as *mut i8,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReadFd(fd, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReadFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlReadFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReadFile(filename, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReadMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#izzi:xmlReadMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReadMemory(buffer, size, URL, encoding, options);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderForDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlReaderForDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReaderForDoc(cur, URL, encoding, options);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderForFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:xmlReaderForFd\0" as *const u8 as *const i8
            as *mut i8,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReaderForFd(fd, URL, encoding, options);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderForFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlReaderForFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReaderForFile(filename, encoding, options);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderForMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zizzi:xmlReaderForMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlReaderForMemory(buffer, size, URL, encoding, options);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderNewDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:xmlReaderNewDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlReaderNewDoc(reader, cur, URL, encoding, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderNewFd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:xmlReaderNewFd\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut fd as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlReaderNewFd(reader, fd, URL, encoding, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderNewFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:xmlReaderNewFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut filename as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlReaderNewFile(reader, filename, encoding, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderNewMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzi:xmlReaderNewMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut buffer as *mut *mut i8,
        &mut size as *mut i32,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlReaderNewMemory(reader, buffer, size, URL, encoding, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderNewWalker(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlReaderNewWalker\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlReaderNewWalker(reader, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReaderWalker(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlReaderWalker\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlReaderWalker(doc);
    py_retval = libxml_xmlTextReaderPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReconciliateNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlReconciliateNs\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_tree as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    tree = if pyobj_tree == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_tree as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlReconciliateNs(doc, tree);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRecoverDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRecoverDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRecoverDoc(cur);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRecoverFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRecoverFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRecoverFile(filename);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRecoverMemory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlRecoverMemory\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRecoverMemory(buffer, size);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegFreeRegexp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut regexp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_regexp: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRegFreeRegexp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_regexp as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    regexp = if pyobj_regexp == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        (*(pyobj_regexp as *mut PyxmlReg_Object)).obj
    };
    xmlRegFreeRegexp(regexp);
    let fresh98 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh98 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegexpCompile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut regexp: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRegexpCompile\0" as *const u8 as *const i8 as *mut i8,
        &mut regexp as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRegexpCompile(regexp);
    py_retval = libxml_xmlRegexpPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegexpExec(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlRegexpExec\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_comp as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    comp = if pyobj_comp == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        (*(pyobj_comp as *mut PyxmlReg_Object)).obj
    };
    c_retval = xmlRegexpExec(comp, content);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegexpIsDeterminist(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRegexpIsDeterminist\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_comp as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    comp = if pyobj_comp == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        (*(pyobj_comp as *mut PyxmlReg_Object)).obj
    };
    c_retval = xmlRegexpIsDeterminist(comp);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegexpPrint(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut regexp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_regexp: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRegexpPrint\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_regexp as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    regexp = if pyobj_regexp == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        (*(pyobj_regexp as *mut PyxmlReg_Object)).obj
    };
    xmlRegexpPrint(output, regexp);
    let fresh99 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh99 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterDefaultInputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterDefaultInputCallbacks();
    let fresh100 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh100 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterDefaultOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterDefaultOutputCallbacks();
    let fresh101 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh101 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterHTTPPostCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterHTTPPostCallbacks();
    let fresh102 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh102 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGCleanupTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlRelaxNGCleanupTypes\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlRelaxNGCleanupTypes();
    let fresh103 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh103 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRelaxNGDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj
    };
    xmlRelaxNGDump(output, schema);
    let fresh104 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh104 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGDumpTree(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRelaxNGDumpTree\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj
    };
    xmlRelaxNGDumpTree(output, schema);
    let fresh105 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh105 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGFree(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGFree\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj
    };
    xmlRelaxNGFree(schema);
    let fresh106 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh106 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGFreeParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGFreeParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj
    };
    xmlRelaxNGFreeParserCtxt(ctxt);
    let fresh107 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh107 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGInitTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    if libxml_deprecationWarning(
        b"xmlRelaxNGInitTypes\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRelaxNGInitTypes();
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGNewDocParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGNewDocParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlRelaxNGNewDocParserCtxt(doc);
    py_retval = libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGNewMemParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlRelaxNGNewMemParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRelaxNGNewMemParserCtxt(buffer, size);
    py_retval = libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGNewParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut URL: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRelaxNGNewParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut URL as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlRelaxNGNewParserCtxt(URL);
    py_retval = libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGNewValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGNewValidCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj
    };
    c_retval = xmlRelaxNGNewValidCtxt(schema);
    py_retval = libxml_xmlRelaxNGValidCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGParse(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRelaxNGParse\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj
    };
    c_retval = xmlRelaxNGParse(ctxt);
    py_retval = libxml_xmlRelaxNGPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidateDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRelaxNGValidateDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlRelaxNGValidateDoc(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidateFullElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidateFullElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlRelaxNGValidateFullElement(ctxt, doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidatePopElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidatePopElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlRelaxNGValidatePopElement(ctxt, doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidatePushCData(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlRelaxNGValidatePushCData\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut data as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    c_retval = xmlRelaxNGValidatePushCData(ctxt, data, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGValidatePushElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidatePushElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlRelaxNGValidatePushElement(ctxt, doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxParserSetFlag(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlRelaxParserSetFlag\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut flags as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj
    };
    c_retval = xmlRelaxParserSetFlag(ctxt, flags);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRemoveID(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRemoveID\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlRemoveID(doc, attr);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRemoveProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRemoveProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlRemoveProp(cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRemoveRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(b"xmlRemoveRef\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRemoveRef\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlRemoveRef(doc, attr);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlReplaceNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut old: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_old: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlReplaceNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_old as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    old = if pyobj_old == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_old as *mut PyxmlNode_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlReplaceNode(old, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlResetError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut err: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_err: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlResetError\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_err as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    err = if pyobj_err == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        (*(pyobj_err as *mut PyError_Object)).obj
    };
    xmlResetError(err);
    let fresh108 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh108 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlResetLastError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlResetLastError();
    let fresh109 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh109 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSAXDefaultVersion(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut version: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSAXDefaultVersion\0" as *const u8 as *const i8
            as *mut i8,
        &mut version as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSAXDefaultVersion(version);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSaveFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlSaveFile\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFile(filename, cur);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSaveFileEnc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOz:xmlSaveFileEnc\0" as *const u8 as *const i8 as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFileEnc(filename, cur, encoding);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSaveFormatFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOi:xmlSaveFormatFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFormatFile(filename, cur, format);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSaveFormatFileEnc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOzi:xmlSaveFormatFileEnc\0" as *const u8 as *const i8
            as *mut i8,
        &mut filename as *mut *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut i8,
        &mut format as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSaveFormatFileEnc(filename, cur, encoding, format);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSaveUri(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSaveUri\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_uri as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_uri as *mut PyURI_Object)).obj
    };
    c_retval = xmlSaveUri(uri);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlScanName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(b"xmlScanName\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlScanName\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlScanName(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaCleanupTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlSchemaCleanupTypes\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlSchemaCleanupTypes();
    let fresh110 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh110 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaCollapseString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlSchemaCollapseString\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSchemaCollapseString(value);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSchemaDump\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut FILE
    } else if (*pyobj_output).ob_type == &mut PyFile_Type as *mut PyTypeObject
            || PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) != 0
        {
        PyFile_AsFile(pyobj_output)
    } else {
        stdout
    };
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        (*(pyobj_schema as *mut PySchema_Object)).obj
    };
    xmlSchemaDump(output, schema);
    let fresh111 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh111 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaFree(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaFree\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        (*(pyobj_schema as *mut PySchema_Object)).obj
    };
    xmlSchemaFree(schema);
    let fresh112 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh112 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaFreeParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaFreeParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaParserCtxt_Object)).obj
    };
    xmlSchemaFreeParserCtxt(ctxt);
    let fresh113 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh113 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaInitTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlSchemaInitTypes\0" as *const u8 as *const i8,
    ) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlSchemaInitTypes();
    let fresh114 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh114 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaIsValid(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaIsValid\0" as *const u8 as *const i8 as *mut i8,
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
    c_retval = xmlSchemaIsValid(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaNewDocParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaNewDocParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSchemaNewDocParserCtxt(doc);
    py_retval = libxml_xmlSchemaParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaNewMemParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlSchemaNewMemParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut buffer as *mut *mut i8,
        &mut size as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSchemaNewMemParserCtxt(buffer, size);
    py_retval = libxml_xmlSchemaParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaNewParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut URL: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlSchemaNewParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut URL as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSchemaNewParserCtxt(URL);
    py_retval = libxml_xmlSchemaParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaNewValidCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaNewValidCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        (*(pyobj_schema as *mut PySchema_Object)).obj
    };
    c_retval = xmlSchemaNewValidCtxt(schema);
    py_retval = libxml_xmlSchemaValidCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaParse(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut ctxt: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaParse\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaParserCtxt_Object)).obj
    };
    c_retval = xmlSchemaParse(ctxt);
    py_retval = libxml_xmlSchemaPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaSetValidOptions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlSchemaSetValidOptions\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    c_retval = xmlSchemaSetValidOptions(ctxt, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidCtxtGetOptions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaValidCtxtGetOptions\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlSchemaValidCtxtGetOptions(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidCtxtGetParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaValidCtxtGetParserCtxt\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlSchemaValidCtxtGetParserCtxt(ctxt);
    py_retval = libxml_xmlParserCtxtPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidateDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSchemaValidateDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlSchemaValidateDoc(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidateFile(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlSchemaValidateFile\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    c_retval = xmlSchemaValidateFile(ctxt, filename, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidateOneElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSchemaValidateOneElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlSchemaValidateOneElement(ctxt, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaValidateSetFilename(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut vctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_vctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlSchemaValidateSetFilename\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_vctxt as *mut *mut PyObject,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    vctxt = if pyobj_vctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_vctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    xmlSchemaValidateSetFilename(vctxt, filename);
    let fresh115 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh115 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaWhiteSpaceReplace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlSchemaWhiteSpaceReplace\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSchemaWhiteSpaceReplace(value);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSearchNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlSearchNs\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut nameSpace as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlSearchNs(doc, node, nameSpace);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSearchNsByHref(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlSearchNsByHref\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut href as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlSearchNsByHref(doc, node, href);
    py_retval = libxml_xmlNsPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetCompressMode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut mode: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSetCompressMode\0" as *const u8 as *const i8
            as *mut i8,
        &mut mode as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlSetCompressMode(mode);
    let fresh116 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh116 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetDocCompressMode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut mode: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlSetDocCompressMode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut mode as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlSetDocCompressMode(doc, mode);
    let fresh117 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh117 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetListDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut list: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSetListDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_list as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    list = if pyobj_list == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_list as *mut PyxmlNode_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlSetListDoc(list, doc);
    let fresh118 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh118 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSetNs\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    xmlSetNs(node, ns);
    let fresh119 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh119 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlSetNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlSetNsProp(node, ns, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlSetProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlSetProp(node, name, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval as xmlNodePtr);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetTreeDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSetTreeDoc\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_tree as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_tree as *mut PyxmlNode_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    xmlSetTreeDoc(tree, doc);
    let fresh120 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh120 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSetupParserForBuffer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut filename: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlSetupParserForBuffer\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut xmlChar,
        &mut filename as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    xmlSetupParserForBuffer(ctxt, buffer, filename);
    let fresh121 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh121 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlShellPrintNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlShellPrintNode\0" as *const u8 as *const i8
            as *mut i8,
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
    xmlShellPrintNode(node);
    let fresh122 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh122 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlShellPrintXPathError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut errorType: i32 = 0;
    let mut arg: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlShellPrintXPathError\0" as *const u8 as *const i8
            as *mut i8,
        &mut errorType as *mut i32,
        &mut arg as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlShellPrintXPathError(errorType, arg);
    let fresh123 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh123 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSkipBlankChars(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSkipBlankChars\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlSkipBlankChars(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStopParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlStopParser\0" as *const u8 as *const i8 as *mut i8,
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
    xmlStopParser(ctxt);
    let fresh124 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh124 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrEqual(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrEqual\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrEqual(str1, str2);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrQEqual(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut pref: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzz:xmlStrQEqual\0" as *const u8 as *const i8 as *mut i8,
        &mut pref as *mut *mut xmlChar,
        &mut name as *mut *mut xmlChar,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrQEqual(pref, name, str);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrcasecmp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcasecmp\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrcasecmp(str1, str2);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrcasestr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcasestr\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut val as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrcasestr(str, val);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrcat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut add: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcat\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut add as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrcat(cur, add);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrchr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: xmlChar = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zc:xmlStrchr\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut val as *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrchr(str, val);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrcmp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcmp\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrcmp(str1, str2);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrdup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlStrdup\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrdup(cur);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStringDecodeEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut what: i32 = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziccc:xmlStringDecodeEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
        &mut what as *mut i32,
        &mut end as *mut xmlChar,
        &mut end2 as *mut xmlChar,
        &mut end3 as *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlStringDecodeEntities(ctxt, str, what, end, end2, end3);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStringGetNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlStringGetNodeList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlStringGetNodeList(doc, value);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStringLenDecodeEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    let mut what: i32 = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziiccc:xmlStringLenDecodeEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
        &mut len as *mut i32,
        &mut what as *mut i32,
        &mut end as *mut xmlChar,
        &mut end2 as *mut xmlChar,
        &mut end3 as *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj
    };
    c_retval = xmlStringLenDecodeEntities(ctxt, str, len, what, end, end2, end3);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStringLenGetNodeList(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlStringLenGetNodeList\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as *mut xmlDoc;
    c_retval = xmlStringLenGetNodeList(doc, value, len);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrlen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlStrlen\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrlen(str);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrncasecmp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncasecmp\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrncasecmp(str1, str2, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrncat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut add: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncat\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut add as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrncat(cur, add, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrncatNew(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncatNew\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrncatNew(str1, str2, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrncmp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncmp\0" as *const u8 as *const i8 as *mut i8,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrncmp(str1, str2, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrndup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlStrndup\0" as *const u8 as *const i8 as *mut i8,
        &mut cur as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrndup(cur, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrstr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrstr\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut val as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrstr(str, val);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrsub(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut start: i32 = 0;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zii:xmlStrsub\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut start as *mut i32,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlStrsub(str, start, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSubstituteEntitiesDefault(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSubstituteEntitiesDefault\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlSubstituteEntitiesDefault(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextConcat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlTextConcat\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlTextConcat(node, content, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextMerge(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut first: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_first: *mut PyObject = 0 as *mut PyObject;
    let mut second: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_second: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlTextMerge\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_first as *mut *mut PyObject,
        &mut pyobj_second as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    first = if pyobj_first == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_first as *mut PyxmlNode_Object)).obj
    };
    second = if pyobj_second == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_second as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlTextMerge(first, second);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderAttributeCount(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderAttributeCount\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderAttributeCount(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderByteConsumed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderByteConsumed\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderByteConsumed(reader);
    py_retval = libxml_longWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderClose(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderClose\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderClose(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstBaseUri(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstBaseUri\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstBaseUri(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstEncoding(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstEncoding\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstEncoding(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstLocalName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstLocalName\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstLocalName(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstName\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstName(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstNamespaceUri(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstNamespaceUri\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstNamespaceUri(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstPrefix(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstPrefix\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstPrefix(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderConstString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderConstString(reader, str);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstValue\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstValue(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstXmlLang(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstXmlLang\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstXmlLang(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderConstXmlVersion(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderConstXmlVersion\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderConstXmlVersion(reader);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderCurrentDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderCurrentDoc\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderCurrentDoc(reader);
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderCurrentNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderCurrentNode\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderCurrentNode(reader);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderDepth(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderDepth\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderDepth(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderExpand(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderExpand\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderExpand(reader);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderGetAttribute\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderGetAttribute(reader, name);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetAttributeNo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut no: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderGetAttributeNo\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut no as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderGetAttributeNo(reader, no);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetAttributeNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut localName: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlTextReaderGetAttributeNs\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut localName as *mut *mut xmlChar,
        &mut namespaceURI as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderGetAttributeNs(reader, localName, namespaceURI);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetParserColumnNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderGetParserColumnNumber\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderGetParserColumnNumber(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetParserLineNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderGetParserLineNumber\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderGetParserLineNumber(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetParserProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderGetParserProp\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut prop as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderGetParserProp(reader, prop);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderGetRemainder(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderGetRemainder\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderGetRemainder(reader);
    py_retval = libxml_xmlParserInputBufferPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderHasAttributes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderHasAttributes\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderHasAttributes(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderHasValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderHasValue\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderHasValue(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderIsDefault(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsDefault\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderIsDefault(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderIsEmptyElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsEmptyElement\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderIsEmptyElement(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderIsNamespaceDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsNamespaceDecl\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderIsNamespaceDecl(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderIsValid(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsValid\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderIsValid(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderLocatorBaseURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut locator: xmlTextReaderLocatorPtr = 0 as *mut libc::c_void;
    let mut pyobj_locator: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderLocatorBaseURI\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_locator as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    locator = if pyobj_locator == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut libc::c_void
    } else {
        (*(pyobj_locator as *mut PyxmlTextReaderLocator_Object)).obj
    };
    c_retval = xmlTextReaderLocatorBaseURI(locator);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderLocatorLineNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut locator: xmlTextReaderLocatorPtr = 0 as *mut libc::c_void;
    let mut pyobj_locator: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderLocatorLineNumber\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_locator as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    locator = if pyobj_locator == &mut _Py_NoneStruct as *mut PyObject {
        0 as *mut libc::c_void
    } else {
        (*(pyobj_locator as *mut PyxmlTextReaderLocator_Object)).obj
    };
    c_retval = xmlTextReaderLocatorLineNumber(locator);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderLookupNamespace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderLookupNamespace\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderLookupNamespace(reader, prefix);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderMoveToAttribute\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderMoveToAttribute(reader, name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToAttributeNo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut no: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderMoveToAttributeNo\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut no as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderMoveToAttributeNo(reader, no);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToAttributeNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut localName: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlTextReaderMoveToAttributeNs\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut localName as *mut *mut xmlChar,
        &mut namespaceURI as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderMoveToAttributeNs(reader, localName, namespaceURI);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToElement\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderMoveToElement(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToFirstAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToFirstAttribute\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderMoveToFirstAttribute(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderMoveToNextAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToNextAttribute\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderMoveToNextAttribute(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderNext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNext\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderNext(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderNextSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNextSibling\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderNextSibling(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderNodeType(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNodeType\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderNodeType(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderNormalization(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNormalization\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderNormalization(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderPreserve(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderPreserve\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderPreserve(reader);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderQuoteChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderQuoteChar\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderQuoteChar(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderRead(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderRead\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderRead(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderReadAttributeValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadAttributeValue\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderReadAttributeValue(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderReadInnerXml(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadInnerXml\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderReadInnerXml(reader);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderReadOuterXml(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadOuterXml\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderReadOuterXml(reader);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderReadState(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadState\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderReadState(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderReadString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadString\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderReadString(reader);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderRelaxNGSetSchema(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlTextReaderRelaxNGSetSchema\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj
    };
    c_retval = xmlTextReaderRelaxNGSetSchema(reader, schema);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderRelaxNGValidate(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut rng: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderRelaxNGValidate\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut rng as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderRelaxNGValidate(reader, rng);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderRelaxNGValidateCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlTextReaderRelaxNGValidateCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj
    };
    c_retval = xmlTextReaderRelaxNGValidateCtxt(reader, ctxt, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderSchemaValidate(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut xsd: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderSchemaValidate\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut xsd as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderSchemaValidate(reader, xsd);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderSchemaValidateCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlTextReaderSchemaValidateCtxt\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj
    };
    c_retval = xmlTextReaderSchemaValidateCtxt(reader, ctxt, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderSetParserProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: i32 = 0;
    let mut value: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oii:xmlTextReaderSetParserProp\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut prop as *mut i32,
        &mut value as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    c_retval = xmlTextReaderSetParserProp(reader, prop, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderSetSchema(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlTextReaderSetSchema\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_schema as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    schema = if pyobj_schema == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        (*(pyobj_schema as *mut PySchema_Object)).obj
    };
    c_retval = xmlTextReaderSetSchema(reader, schema);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderSetup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_input: *mut PyObject = 0 as *mut PyObject;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzzi:xmlTextReaderSetup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_input as *mut *mut PyObject,
        &mut URL as *mut *mut i8,
        &mut encoding as *mut *mut i8,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj
    };
    input = if pyobj_input == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        (*(pyobj_input as *mut PyinputBuffer_Object)).obj
    };
    c_retval = xmlTextReaderSetup(reader, input, URL, encoding, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlTextReaderStandalone(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderStandalone\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlTextReaderStandalone(reader);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefDefaultBufferSize(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefDefaultBufferSize\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefDefaultBufferSize(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefDoValidityCheckingDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefDoValidityCheckingDefaultValue\0" as *const u8
            as *const i8 as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefDoValidityCheckingDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefGetWarningsDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefGetWarningsDefaultValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefGetWarningsDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefIndentTreeOutput(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefIndentTreeOutput\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefIndentTreeOutput(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefKeepBlanksDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefKeepBlanksDefaultValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefKeepBlanksDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefLineNumbersDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefLineNumbersDefaultValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefLineNumbersDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefLoadExtDtdDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefLoadExtDtdDefaultValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefLoadExtDtdDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefParserDebugEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefParserDebugEntities\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefParserDebugEntities(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefPedanticParserDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefPedanticParserDefaultValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefPedanticParserDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefSaveNoEmptyTags(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefSaveNoEmptyTags\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefSaveNoEmptyTags(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefSubstituteEntitiesDefaultValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefSubstituteEntitiesDefaultValue\0" as *const u8
            as *const i8 as *mut i8,
        &mut v as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefSubstituteEntitiesDefaultValue(v);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlThrDefTreeIndentString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut v: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlThrDefTreeIndentString\0" as *const u8 as *const i8
            as *mut i8,
        &mut v as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlThrDefTreeIndentString(v);
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsAegeanNumbers(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsAegeanNumbers\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsAegeanNumbers(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsAlphabeticPresentationForms(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsAlphabeticPresentationForms\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsAlphabeticPresentationForms(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsArabic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsArabic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsArabicPresentationFormsA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabicPresentationFormsA\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsArabicPresentationFormsA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsArabicPresentationFormsB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabicPresentationFormsB\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsArabicPresentationFormsB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsArmenian(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArmenian\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsArmenian(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsArrows(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArrows\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsArrows(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBasicLatin(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBasicLatin\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBasicLatin(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBengali(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBengali\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBengali(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBlock(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    let mut block: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlUCSIsBlock\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
        &mut block as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBlock(code, block);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBlockElements(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBlockElements\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBlockElements(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBopomofo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBopomofo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBopomofo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBopomofoExtended(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBopomofoExtended\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBopomofoExtended(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBoxDrawing(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBoxDrawing\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBoxDrawing(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBraillePatterns(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBraillePatterns\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBraillePatterns(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsBuhid(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBuhid\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsBuhid(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsByzantineMusicalSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsByzantineMusicalSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsByzantineMusicalSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKCompatibility(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibility\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKCompatibility(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKCompatibilityForms(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityForms\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKCompatibilityForms(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKCompatibilityIdeographs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityIdeographs\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKCompatibilityIdeographs(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKCompatibilityIdeographsSupplement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityIdeographsSupplement\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKCompatibilityIdeographsSupplement(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKRadicalsSupplement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKRadicalsSupplement\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKRadicalsSupplement(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKSymbolsandPunctuation(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKSymbolsandPunctuation\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKSymbolsandPunctuation(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographs\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKUnifiedIdeographs(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographsExtensionA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographsExtensionA\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKUnifiedIdeographsExtensionA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographsExtensionB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographsExtensionB\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCJKUnifiedIdeographsExtensionB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    let mut cat: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlUCSIsCat\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
        &mut cat as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCat(code, cat);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatC(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatC\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatC(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatCc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCc\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatCc(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatCf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCf\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatCf(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatCo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatCo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatCs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCs\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatCs(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatL(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatL\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatL(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatLl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLl\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatLl(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatLm(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLm\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatLm(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatLo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatLo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatLt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLt\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatLt(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatLu(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLu\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatLu(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatM(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatM\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatM(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatMc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMc\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatMc(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatMe(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMe\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatMe(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatMn(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMn\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatMn(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatN(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatN\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatN(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatNd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNd\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatNd(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatNl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNl\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatNl(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatNo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatNo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatP(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatP\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatP(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPc\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPc(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPd\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPd(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPe(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPe\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPe(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPf\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPf(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPi(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPi\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPi(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatPs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPs\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatPs(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatS(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatS\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatS(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatSc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSc\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatSc(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatSk(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSk\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatSk(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatSm(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSm\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatSm(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatSo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatSo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatZ(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZ\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatZ(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatZl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZl\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatZl(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatZp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZp\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatZp(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCatZs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZs\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCatZs(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCherokee(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCherokee\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCherokee(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCombiningDiacriticalMarks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningDiacriticalMarks\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCombiningDiacriticalMarks(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCombiningDiacriticalMarksforSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningDiacriticalMarksforSymbols\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCombiningDiacriticalMarksforSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCombiningHalfMarks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningHalfMarks\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCombiningHalfMarks(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCombiningMarksforSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningMarksforSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCombiningMarksforSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsControlPictures(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsControlPictures\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsControlPictures(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCurrencySymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCurrencySymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCurrencySymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCypriotSyllabary(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCypriotSyllabary\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCypriotSyllabary(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCyrillic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCyrillic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCyrillic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsCyrillicSupplement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCyrillicSupplement\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsCyrillicSupplement(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsDeseret(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDeseret\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsDeseret(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsDevanagari(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDevanagari\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsDevanagari(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsDingbats(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDingbats\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsDingbats(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsEnclosedAlphanumerics(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEnclosedAlphanumerics\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsEnclosedAlphanumerics(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsEnclosedCJKLettersandMonths(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEnclosedCJKLettersandMonths\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsEnclosedCJKLettersandMonths(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsEthiopic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEthiopic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsEthiopic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGeneralPunctuation(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeneralPunctuation\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGeneralPunctuation(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGeometricShapes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeometricShapes\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGeometricShapes(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGeorgian(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeorgian\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGeorgian(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGothic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGothic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGothic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGreek(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreek\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGreek(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGreekExtended(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreekExtended\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGreekExtended(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGreekandCoptic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreekandCoptic\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGreekandCoptic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGujarati(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGujarati\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGujarati(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsGurmukhi(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGurmukhi\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsGurmukhi(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHalfwidthandFullwidthForms(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHalfwidthandFullwidthForms\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHalfwidthandFullwidthForms(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHangulCompatibilityJamo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulCompatibilityJamo\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHangulCompatibilityJamo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHangulJamo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulJamo\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHangulJamo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHangulSyllables(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulSyllables\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHangulSyllables(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHanunoo(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHanunoo\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHanunoo(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHebrew(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHebrew\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHebrew(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHighPrivateUseSurrogates(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHighPrivateUseSurrogates\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHighPrivateUseSurrogates(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHighSurrogates(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHighSurrogates\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHighSurrogates(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsHiragana(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHiragana\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsHiragana(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsIPAExtensions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsIPAExtensions\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsIPAExtensions(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsIdeographicDescriptionCharacters(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsIdeographicDescriptionCharacters\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsIdeographicDescriptionCharacters(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKanbun(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKanbun\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKanbun(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKangxiRadicals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKangxiRadicals\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKangxiRadicals(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKannada(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKannada\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKannada(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKatakana(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKatakana\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKatakana(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKatakanaPhoneticExtensions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKatakanaPhoneticExtensions\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKatakanaPhoneticExtensions(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKhmer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKhmer\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKhmer(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsKhmerSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKhmerSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsKhmerSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLao(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLao\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLao(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLatin1Supplement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatin1Supplement\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLatin1Supplement(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLatinExtendedA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedA\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLatinExtendedA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLatinExtendedAdditional(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedAdditional\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLatinExtendedAdditional(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLatinExtendedB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedB\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLatinExtendedB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLetterlikeSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLetterlikeSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLetterlikeSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLimbu(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLimbu\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLimbu(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLinearBIdeograms(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLinearBIdeograms\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLinearBIdeograms(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLinearBSyllabary(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLinearBSyllabary\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLinearBSyllabary(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsLowSurrogates(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLowSurrogates\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsLowSurrogates(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMalayalam(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMalayalam\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMalayalam(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMathematicalAlphanumericSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMathematicalAlphanumericSymbols\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMathematicalAlphanumericSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMathematicalOperators(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMathematicalOperators\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMathematicalOperators(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMiscellaneousMathematicalSymbolsA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousMathematicalSymbolsA\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMiscellaneousMathematicalSymbolsA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMiscellaneousMathematicalSymbolsB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousMathematicalSymbolsB\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMiscellaneousMathematicalSymbolsB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMiscellaneousSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMiscellaneousSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMiscellaneousSymbolsandArrows(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousSymbolsandArrows\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMiscellaneousSymbolsandArrows(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMiscellaneousTechnical(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousTechnical\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMiscellaneousTechnical(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMongolian(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMongolian\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMongolian(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMusicalSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMusicalSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMusicalSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsMyanmar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMyanmar\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsMyanmar(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsNumberForms(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsNumberForms\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsNumberForms(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsOgham(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOgham\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsOgham(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsOldItalic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOldItalic\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsOldItalic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsOpticalCharacterRecognition(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOpticalCharacterRecognition\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsOpticalCharacterRecognition(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsOriya(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOriya\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsOriya(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsOsmanya(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOsmanya\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsOsmanya(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsPhoneticExtensions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPhoneticExtensions\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsPhoneticExtensions(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsPrivateUse(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPrivateUse\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsPrivateUse(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsPrivateUseArea(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPrivateUseArea\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsPrivateUseArea(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsRunic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsRunic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsRunic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsShavian(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsShavian\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsShavian(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSinhala(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSinhala\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSinhala(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSmallFormVariants(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSmallFormVariants\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSmallFormVariants(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSpacingModifierLetters(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSpacingModifierLetters\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSpacingModifierLetters(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSpecials(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSpecials\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSpecials(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSuperscriptsandSubscripts(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSuperscriptsandSubscripts\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSuperscriptsandSubscripts(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSupplementalArrowsA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalArrowsA\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSupplementalArrowsA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSupplementalArrowsB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalArrowsB\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSupplementalArrowsB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSupplementalMathematicalOperators(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalMathematicalOperators\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSupplementalMathematicalOperators(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSupplementaryPrivateUseAreaA(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementaryPrivateUseAreaA\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSupplementaryPrivateUseAreaA(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSupplementaryPrivateUseAreaB(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementaryPrivateUseAreaB\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSupplementaryPrivateUseAreaB(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsSyriac(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSyriac\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsSyriac(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTagalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTagalog\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTagalog(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTagbanwa(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTagbanwa\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTagbanwa(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTags(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTags\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTags(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTaiLe(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTaiLe\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTaiLe(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTaiXuanJingSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTaiXuanJingSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTaiXuanJingSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTamil(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTamil\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTamil(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTelugu(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTelugu\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTelugu(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsThaana(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsThaana\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsThaana(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsThai(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsThai\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsThai(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsTibetan(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTibetan\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsTibetan(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsUgaritic(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsUgaritic\0" as *const u8 as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsUgaritic(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsUnifiedCanadianAboriginalSyllabics(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsUnifiedCanadianAboriginalSyllabics\0" as *const u8
            as *const i8 as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsUnifiedCanadianAboriginalSyllabics(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsVariationSelectors(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsVariationSelectors\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsVariationSelectors(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsVariationSelectorsSupplement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsVariationSelectorsSupplement\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsVariationSelectorsSupplement(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsYiRadicals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYiRadicals\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsYiRadicals(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsYiSyllables(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYiSyllables\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsYiSyllables(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUCSIsYijingHexagramSymbols(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYijingHexagramSymbols\0" as *const u8 as *const i8
            as *mut i8,
        &mut code as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUCSIsYijingHexagramSymbols(code);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIEscape(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlURIEscape\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlURIEscape(str);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIEscapeStr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut list: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlURIEscapeStr\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut list as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlURIEscapeStr(str, list);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetAuthority(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetAuthority\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).authority;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetFragment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetFragment\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).fragment;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetOpaque(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetOpaque\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).opaque;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetPath\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).path;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetPort(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetPort\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).port;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetQuery(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetQuery\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).query;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetQueryRaw(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetQueryRaw\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).query_raw;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetScheme(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetScheme\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).scheme;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetServer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetServer\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).server;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIGetUser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetUser\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    c_retval = (*URI).user;
    py_retval = libxml_charPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetAuthority(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut authority: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetAuthority\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut authority as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).authority).is_null() {
        xmlFree
            .expect("non-null function pointer")((*URI).authority as *mut libc::c_void);
    }
    let fresh125 = &mut ((*URI).authority);
    *fresh125 = xmlStrdup(authority as *const xmlChar) as *mut i8;
    let fresh126 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh126 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetFragment(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut fragment: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetFragment\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut fragment as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).fragment).is_null() {
        xmlFree
            .expect("non-null function pointer")((*URI).fragment as *mut libc::c_void);
    }
    let fresh127 = &mut ((*URI).fragment);
    *fresh127 = xmlStrdup(fragment as *const xmlChar) as *mut i8;
    let fresh128 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh128 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetOpaque(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut opaque: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetOpaque\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut opaque as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).opaque).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).opaque as *mut libc::c_void);
    }
    let fresh129 = &mut ((*URI).opaque);
    *fresh129 = xmlStrdup(opaque as *const xmlChar) as *mut i8;
    let fresh130 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh130 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut path: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetPath\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut path as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).path).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).path as *mut libc::c_void);
    }
    let fresh131 = &mut ((*URI).path);
    *fresh131 = xmlStrdup(path as *const xmlChar) as *mut i8;
    let fresh132 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh132 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetPort(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut port: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlURISetPort\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut port as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    (*URI).port = port;
    let fresh133 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh133 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetQuery(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut query: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetQuery\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut query as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).query).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).query as *mut libc::c_void);
    }
    let fresh134 = &mut ((*URI).query);
    *fresh134 = xmlStrdup(query as *const xmlChar) as *mut i8;
    let fresh135 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh135 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetQueryRaw(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut query_raw: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetQueryRaw\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut query_raw as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).query_raw).is_null() {
        xmlFree
            .expect("non-null function pointer")((*URI).query_raw as *mut libc::c_void);
    }
    let fresh136 = &mut ((*URI).query_raw);
    *fresh136 = xmlStrdup(query_raw as *const xmlChar) as *mut i8;
    let fresh137 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh137 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetScheme(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut scheme: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetScheme\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut scheme as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).scheme).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).scheme as *mut libc::c_void);
    }
    let fresh138 = &mut ((*URI).scheme);
    *fresh138 = xmlStrdup(scheme as *const xmlChar) as *mut i8;
    let fresh139 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh139 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetServer(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut server: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetServer\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut server as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).server).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).server as *mut libc::c_void);
    }
    let fresh140 = &mut ((*URI).server);
    *fresh140 = xmlStrdup(server as *const xmlChar) as *mut i8;
    let fresh141 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh141 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURISetUser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut user: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetUser\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut user as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlURIPtr
    } else {
        (*(pyobj_URI as *mut PyURI_Object)).obj
    };
    if !((*URI).user).is_null() {
        xmlFree.expect("non-null function pointer")((*URI).user as *mut libc::c_void);
    }
    let fresh142 = &mut ((*URI).user);
    *fresh142 = xmlStrdup(user as *const xmlChar) as *mut i8;
    let fresh143 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh143 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIUnescapeString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut i8 = 0 as *mut i8;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    let mut target: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"ziz:xmlURIUnescapeString\0" as *const u8 as *const i8
            as *mut i8,
        &mut str as *mut *mut i8,
        &mut len as *mut i32,
        &mut target as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlURIUnescapeString(str, len, target);
    py_retval = libxml_charPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Charcmp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf1: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlUTF8Charcmp\0" as *const u8 as *const i8 as *mut i8,
        &mut utf1 as *mut *mut xmlChar,
        &mut utf2 as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Charcmp(utf1, utf2);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Size(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlUTF8Size\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Size(utf);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strlen(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlUTF8Strlen\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strlen(utf);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strloc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut utfchar: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlUTF8Strloc\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
        &mut utfchar as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strloc(utf, utfchar);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strndup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strndup\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strndup(utf, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strpos(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut pos: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strpos\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
        &mut pos as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strpos(utf, pos);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strsize(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strsize\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strsize(utf, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUTF8Strsub(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut start: i32 = 0;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zii:xmlUTF8Strsub\0" as *const u8 as *const i8 as *mut i8,
        &mut utf as *mut *mut xmlChar,
        &mut start as *mut i32,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlUTF8Strsub(utf, start, len);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUnlinkNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlUnlinkNode\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    xmlUnlinkNode(cur);
    let fresh144 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh144 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUnsetNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlUnsetNsProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlUnsetNsProp(node, ns, name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUnsetProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlUnsetProp\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlUnsetProp(node, name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidCtxtNormalizeAttributeValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzz:xmlValidCtxtNormalizeAttributeValue\0" as *const u8
            as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidCtxtNormalizeAttributeValue(ctxt, doc, elem, name, value);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidNormalizeAttributeValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzz:xmlValidNormalizeAttributeValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidNormalizeAttributeValue(doc, elem, name, value);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDocument\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlValidateDocument(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateDocumentFinal(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDocumentFinal\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlValidateDocumentFinal(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateDtd(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateDtd\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_dtd as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    dtd = (if pyobj_dtd == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_dtd as *mut PyxmlNode_Object)).obj
    }) as xmlDtdPtr;
    c_retval = xmlValidateDtd(ctxt, doc, dtd);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateDtdFinal(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDtdFinal\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlValidateDtdFinal(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidateElement(ctxt, doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNCName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateNCName\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNCName(value, space);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNMToken(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateNMToken\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNMToken(value, space);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateName\0" as *const u8 as *const i8 as *mut i8,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateName(value, space);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNameValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNameValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNameValue(value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNamesValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNamesValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNamesValue(value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNmtokenValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNmtokenValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNmtokenValue(value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNmtokensValue(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNmtokensValue\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateNmtokensValue(value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateNotationUse(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut notationName: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlValidateNotationUse\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut notationName as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlValidateNotationUse(ctxt, doc, notationName);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateOneAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOOz:xmlValidateOneAttribute\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    attr = (if pyobj_attr == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_attr as *mut PyxmlNode_Object)).obj
    }) as xmlAttrPtr;
    c_retval = xmlValidateOneAttribute(ctxt, doc, elem, attr, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateOneElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateOneElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidateOneElement(ctxt, doc, elem);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateOneNamespace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzOz:xmlValidateOneNamespace\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut prefix as *mut *mut xmlChar,
        &mut pyobj_ns as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    c_retval = xmlValidateOneNamespace(ctxt, doc, elem, prefix, ns, value);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidatePopElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut qname: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:xmlValidatePopElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut qname as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidatePopElement(ctxt, doc, elem, qname);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidatePushCData(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlValidatePushCData\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut data as *mut *mut xmlChar,
        &mut len as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    c_retval = xmlValidatePushCData(ctxt, data, len);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidatePushElement(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut qname: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:xmlValidatePushElement\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_elem as *mut *mut PyObject,
        &mut qname as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    elem = if pyobj_elem == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_elem as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlValidatePushElement(ctxt, doc, elem, qname);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateQName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateQName\0" as *const u8 as *const i8
            as *mut i8,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlValidateQName(value, space);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlValidateRoot(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateRoot\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlValidateRoot(ctxt, doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXIncludeProcess(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXIncludeProcess\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlXIncludeProcess(doc);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXIncludeProcessFlags(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXIncludeProcessFlags\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut flags as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlXIncludeProcessFlags(doc, flags);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXIncludeProcessTree(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXIncludeProcessTree\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_tree as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_tree as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXIncludeProcessTree(tree);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXIncludeProcessTreeFlags(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXIncludeProcessTreeFlags\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_tree as *mut *mut PyObject,
        &mut flags as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_tree as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXIncludeProcessTreeFlags(tree, flags);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathAddValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathAddValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathAddValues(ctxt);
    let fresh145 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh145 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathBooleanFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathBooleanFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathBooleanFunction(ctxt, nargs);
    let fresh146 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh146 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastBooleanToNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathCastBooleanToNumber\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastBooleanToNumber(val);
    py_retval = libxml_doubleWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastBooleanToString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathCastBooleanToString\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastBooleanToString(val);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastNodeToNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathCastNodeToNumber\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlXPathCastNodeToNumber(node);
    py_retval = libxml_doubleWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastNodeToString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathCastNodeToString\0" as *const u8 as *const i8
            as *mut i8,
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
    c_retval = xmlXPathCastNodeToString(node);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastNumberToBoolean(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathCastNumberToBoolean\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut f64,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastNumberToBoolean(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastNumberToString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: f64 = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathCastNumberToString\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut f64,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastNumberToString(val);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastStringToBoolean(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathCastStringToBoolean\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastStringToBoolean(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastStringToNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathCastStringToNumber\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathCastStringToNumber(val);
    py_retval = libxml_doubleWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCeilingFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathCeilingFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathCeilingFunction(ctxt, nargs);
    let fresh147 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh147 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCmpNodes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node1: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node1: *mut PyObject = 0 as *mut PyObject;
    let mut node2: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node2: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathCmpNodes\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_node1 as *mut *mut PyObject,
        &mut pyobj_node2 as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node1 = if pyobj_node1 == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node1 as *mut PyxmlNode_Object)).obj
    };
    node2 = if pyobj_node2 == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node2 as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathCmpNodes(node1, node2);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCompareValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut inf: i32 = 0;
    let mut strict: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oii:xmlXPathCompareValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut inf as *mut i32,
        &mut strict as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathCompareValues(ctxt, inf, strict);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathConcatFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathConcatFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathConcatFunction(ctxt, nargs);
    let fresh148 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh148 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathContainsFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathContainsFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathContainsFunction(ctxt, nargs);
    let fresh149 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh149 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathContextSetCache(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut active: i32 = 0;
    let mut value: i32 = 0;
    let mut options: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiii:xmlXPathContextSetCache\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut active as *mut i32,
        &mut value as *mut i32,
        &mut options as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathContextSetCache(ctxt, active, value, options);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCountFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathCountFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathCountFunction(ctxt, nargs);
    let fresh150 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh150 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathDivValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathDivValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathDivValues(ctxt);
    let fresh151 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh151 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathEqualValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathEqualValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathEqualValues(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathErr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut error: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathErr\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut error as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathErr(ctxt, error);
    let fresh152 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh152 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathEval(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlXPathEval\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut pyobj_ctx as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathEval(str, ctx);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathEvalExpr(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathEvalExpr\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathEvalExpr(ctxt);
    let fresh153 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh153 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathEvalExpression(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlXPathEvalExpression\0" as *const u8 as *const i8
            as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathEvalExpression(str, ctxt);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathFalseFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathFalseFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathFalseFunction(ctxt, nargs);
    let fresh154 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh154 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathFloorFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathFloorFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathFloorFunction(ctxt, nargs);
    let fresh155 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh155 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathFreeContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathFreeContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    xmlXPathFreeContext(ctxt);
    let fresh156 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh156 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathFreeParserContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathFreeParserContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathFreeParserContext(ctxt);
    let fresh157 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh157 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetContextDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).doc;
    py_retval = libxml_xmlDocPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetContextNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextNode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).node;
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetContextPosition(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextPosition\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).proximityPosition;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetContextSize(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextSize\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).contextSize;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).function;
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathGetFunctionURI(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetFunctionURI\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = (*ctxt).functionURI;
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathIdFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathIdFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathIdFunction(ctxt, nargs);
    let fresh158 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh158 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlXPathInit\0" as *const u8 as *const i8)
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    xmlXPathInit();
    let fresh159 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh159 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathIsInf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathIsInf\0" as *const u8 as *const i8 as *mut i8,
        &mut val as *mut f64,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathIsInf(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathIsNaN(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathIsNaN\0" as *const u8 as *const i8 as *mut i8,
        &mut val as *mut f64,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathIsNaN(val);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathIsNodeType(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathIsNodeType\0" as *const u8 as *const i8
            as *mut i8,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathIsNodeType(name);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathLangFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLangFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathLangFunction(ctxt, nargs);
    let fresh160 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh160 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathLastFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLastFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathLastFunction(ctxt, nargs);
    let fresh161 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh161 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathLocalNameFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLocalNameFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathLocalNameFunction(ctxt, nargs);
    let fresh162 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh162 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathModValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathModValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathModValues(ctxt);
    let fresh163 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh163 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathMultValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathMultValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathMultValues(ctxt);
    let fresh164 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh164 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNamespaceURIFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNamespaceURIFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathNamespaceURIFunction(ctxt, nargs);
    let fresh165 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh165 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewBoolean(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathNewBoolean\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathNewBoolean(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewCString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: *mut i8 = 0 as *mut i8;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathNewCString\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut *mut i8,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathNewCString(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNewContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlXPathNewContext(doc);
    py_retval = libxml_xmlXPathContextPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewFloat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathNewFloat\0" as *const u8 as *const i8 as *mut i8,
        &mut val as *mut f64,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathNewFloat(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewNodeSet(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_val: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNewNodeSet\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_val as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    val = if pyobj_val == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_val as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNewNodeSet(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewParserContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlXPathNewParserContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathNewParserContext(str, ctxt);
    py_retval = libxml_xmlXPathParserContextPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathNewString\0" as *const u8 as *const i8
            as *mut i8,
        &mut val as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathNewString(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNewValueTree(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_val: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNewValueTree\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_val as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    val = if pyobj_val == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_val as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNewValueTree(val);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextAncestor(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextAncestor\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextAncestor(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextAncestorOrSelf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextAncestorOrSelf\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextAncestorOrSelf(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextAttribute(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextAttribute\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextAttribute(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextChild(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextChild\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextChild(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextDescendant(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextDescendant\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextDescendant(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextDescendantOrSelf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextDescendantOrSelf\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextDescendantOrSelf(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextFollowing(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextFollowing\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextFollowing(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextFollowingSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextFollowingSibling\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextFollowingSibling(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextNamespace(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextNamespace\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextNamespace(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextParent(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextParent\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextParent(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextPreceding(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextPreceding\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextPreceding(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextPrecedingSibling(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextPrecedingSibling\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextPrecedingSibling(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNextSelf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathNextSelf\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    cur = if pyobj_cur == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_cur as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPathNextSelf(ctxt, cur);
    py_retval = libxml_xmlNodePtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNodeEval(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OzO:xmlXPathNodeEval\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_node as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
        &mut pyobj_ctx as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    ctx = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathNodeEval(node, str, ctx);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNodeSetFreeNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNodeSetFreeNs\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ns as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ns = (if pyobj_ns == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_ns as *mut PyxmlNode_Object)).obj
    }) as xmlNsPtr;
    xmlXPathNodeSetFreeNs(ns);
    let fresh166 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh166 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNormalizeFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNormalizeFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathNormalizeFunction(ctxt, nargs);
    let fresh167 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh167 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNotEqualValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNotEqualValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathNotEqualValues(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNotFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNotFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathNotFunction(ctxt, nargs);
    let fresh168 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh168 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNsLookup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlXPathNsLookup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut prefix as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathNsLookup(ctxt, prefix);
    py_retval = libxml_xmlCharPtrConstWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNumberFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNumberFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathNumberFunction(ctxt, nargs);
    let fresh169 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh169 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathOrderDocElems(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathOrderDocElems\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    c_retval = xmlXPathOrderDocElems(doc);
    py_retval = libxml_longWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathParseNCName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathParseNCName\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathParseNCName(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathParseName(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathParseName\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathParseName(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathParserGetContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathParserGetContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = (*ctxt).context;
    py_retval = libxml_xmlXPathContextPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathPopBoolean(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathPopBoolean\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathPopBoolean(ctxt);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathPopNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathPopNumber\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathPopNumber(ctxt);
    py_retval = libxml_doubleWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathPopString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathPopString\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    c_retval = xmlXPathPopString(ctxt);
    py_retval = libxml_xmlCharPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathPositionFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathPositionFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathPositionFunction(ctxt, nargs);
    let fresh170 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh170 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisterAllFunctions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathRegisterAllFunctions\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    xmlXPathRegisterAllFunctions(ctxt);
    let fresh171 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh171 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisterNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlXPathRegisterNs\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut prefix as *mut *mut xmlChar,
        &mut ns_uri as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathRegisterNs(ctxt, prefix, ns_uri);
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisteredFuncsCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathRegisteredFuncsCleanup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    xmlXPathRegisteredFuncsCleanup(ctxt);
    let fresh172 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh172 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisteredNsCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathRegisteredNsCleanup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    xmlXPathRegisteredNsCleanup(ctxt);
    let fresh173 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh173 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisteredVariablesCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathRegisteredVariablesCleanup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    xmlXPathRegisteredVariablesCleanup(ctxt);
    let fresh174 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh174 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRoot(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathRoot\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathRoot(ctxt);
    let fresh175 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh175 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRoundFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathRoundFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathRoundFunction(ctxt, nargs);
    let fresh176 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh176 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSetContextDoc(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathSetContextDoc\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    let fresh177 = &mut ((*ctxt).doc);
    *fresh177 = doc;
    let fresh178 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh178 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSetContextNode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathSetContextNode\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    node = if pyobj_node == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_node as *mut PyxmlNode_Object)).obj
    };
    let fresh179 = &mut ((*ctxt).node);
    *fresh179 = node;
    let fresh180 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh180 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathStartsWithFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStartsWithFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathStartsWithFunction(ctxt, nargs);
    let fresh181 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh181 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathStringEvalNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathStringEvalNumber\0" as *const u8 as *const i8
            as *mut i8,
        &mut str as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = xmlXPathStringEvalNumber(str);
    py_retval = libxml_doubleWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathStringFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStringFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathStringFunction(ctxt, nargs);
    let fresh182 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh182 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathStringLengthFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStringLengthFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathStringLengthFunction(ctxt, nargs);
    let fresh183 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh183 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSubValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathSubValues\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathSubValues(ctxt);
    let fresh184 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh184 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSubstringAfterFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringAfterFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathSubstringAfterFunction(ctxt, nargs);
    let fresh185 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh185 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSubstringBeforeFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringBeforeFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathSubstringBeforeFunction(ctxt, nargs);
    let fresh186 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh186 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSubstringFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathSubstringFunction(ctxt, nargs);
    let fresh187 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh187 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathSumFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSumFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathSumFunction(ctxt, nargs);
    let fresh188 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh188 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathTranslateFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathTranslateFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathTranslateFunction(ctxt, nargs);
    let fresh189 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh189 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathTrueFunction(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathTrueFunction\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathTrueFunction(ctxt, nargs);
    let fresh190 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh190 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathValueFlipSign(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathValueFlipSign\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPathValueFlipSign(ctxt);
    let fresh191 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh191 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathVariableLookup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlXPathVariableLookup\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathVariableLookup(ctxt, name);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathVariableLookupNS(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlXPathVariableLookupNS\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut ns_uri as *mut *mut xmlChar,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPathVariableLookupNS(ctxt, name, ns_uri);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPatherror(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut file: *mut i8 = 0 as *mut i8;
    let mut line: i32 = 0;
    let mut no: i32 = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozii:xmlXPatherror\0" as *const u8 as *const i8 as *mut i8,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut file as *mut *mut i8,
        &mut line as *mut i32,
        &mut no as *mut i32,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj
    };
    xmlXPatherror(ctxt, file, line, no);
    let fresh192 = &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt);
    *fresh192 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPtrEval(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlXPtrEval\0" as *const u8 as *const i8 as *mut i8,
        &mut str as *mut *mut xmlChar,
        &mut pyobj_ctx as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj
    };
    c_retval = xmlXPtrEval(str, ctx);
    py_retval = libxml_xmlXPathObjectPtrWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPtrNewContext(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut here: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_here: *mut PyObject = 0 as *mut PyObject;
    let mut origin: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_origin: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlXPtrNewContext\0" as *const u8 as *const i8
            as *mut i8,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_here as *mut *mut PyObject,
        &mut pyobj_origin as *mut *mut PyObject,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_doc as *mut PyxmlNode_Object)).obj
    }) as xmlDocPtr;
    here = if pyobj_here == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_here as *mut PyxmlNode_Object)).obj
    };
    origin = if pyobj_origin == &mut _Py_NoneStruct as *mut PyObject {
        0 as xmlNodePtr
    } else {
        (*(pyobj_origin as *mut PyxmlNode_Object)).obj
    };
    c_retval = xmlXPtrNewContext(doc, here, origin);
    py_retval = libxml_xmlXPathContextPtrWrap(c_retval);
    return py_retval;
}
