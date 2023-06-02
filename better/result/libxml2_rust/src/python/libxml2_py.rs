use :: libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type PyMemberDef;
    pub type _xmlBuf;
    pub type _xmlDict;
    pub type _xmlHashTable;
    pub type _xmlStartTag;
    pub type _xmlAutomataState;
    pub type _xmlAutomata;
    pub type _xmlValidState;
    pub type _xmlRegexp;
    pub type _xmlSchemaParserCtxt;
    pub type _xmlSchemaValidCtxt;
    pub type _xmlCatalog;
    pub type _xmlXPathCompExpr;
    pub type _xmlRelaxNG;
    pub type _xmlRelaxNGParserCtxt;
    pub type _xmlRelaxNGValidCtxt;
    pub type _xmlTextReader;
    static mut stdout: *mut FILE;
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> i32;
    static mut _Py_NoneStruct: PyObject;
    static mut PyFile_Type: PyTypeObject;
    fn PyFile_AsFile(_: *mut PyObject) -> *mut FILE;
    fn _PyArg_ParseTuple_SizeT(_: *mut PyObject, _: *const i8, _: ...) -> i32;
    fn xmlCheckVersion(version: i32);
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlCharStrndup(cur: *const i8, len: i32) -> *mut xmlChar;
    fn xmlCharStrdup(cur: *const i8) -> *mut xmlChar;
    fn xmlStrsub(str: *const xmlChar, start: i32, len: i32) -> *mut xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrstr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrcasestr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrncmp(str1: *const xmlChar, str2: *const xmlChar, len: i32) -> i32;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrncasecmp(str1: *const xmlChar, str2: *const xmlChar, len: i32) -> i32;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> i32;
    fn xmlStrQEqual(pref: *const xmlChar, name: *const xmlChar, str: *const xmlChar) -> i32;
    fn xmlStrlen(str: *const xmlChar) -> i32;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrncat(cur: *mut xmlChar, add: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlStrncatNew(str1: *const xmlChar, str2: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlCheckUTF8(utf: *const u8) -> i32;
    fn xmlUTF8Strsize(utf: *const xmlChar, len: i32) -> i32;
    fn xmlUTF8Strndup(utf: *const xmlChar, len: i32) -> *mut xmlChar;
    fn xmlUTF8Strpos(utf: *const xmlChar, pos: i32) -> *const xmlChar;
    fn xmlUTF8Strloc(utf: *const xmlChar, utfchar: *const xmlChar) -> i32;
    fn xmlUTF8Strsub(utf: *const xmlChar, start: i32, len: i32) -> *mut xmlChar;
    fn xmlValidateDocument(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlInitializeDict() -> i32;
    fn xmlDictCleanup();
    fn xmlRegexpCompile(regexp: *const xmlChar) -> xmlRegexpPtr;
    fn xmlRegFreeRegexp(regexp: xmlRegexpPtr);
    fn xmlRegexpExec(comp: xmlRegexpPtr, value: *const xmlChar) -> i32;
    fn xmlRegexpPrint(output: *mut FILE, regexp: xmlRegexpPtr);
    fn xmlRegexpIsDeterminist(comp: xmlRegexpPtr) -> i32;
    fn xmlValidateNCName(value: *const xmlChar, space: i32) -> i32;
    fn xmlValidateQName(value: *const xmlChar, space: i32) -> i32;
    fn xmlValidateName(value: *const xmlChar, space: i32) -> i32;
    fn xmlValidateNMToken(value: *const xmlChar, space: i32) -> i32;
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: i32,
    ) -> *mut xmlChar;
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
    fn xmlGetIntSubset(doc: *const xmlDoc) -> xmlDtdPtr;
    fn xmlFreeDtd(cur: xmlDtdPtr);
    fn xmlNewGlobalNs(doc: xmlDocPtr, href: *const xmlChar, prefix: *const xmlChar) -> xmlNsPtr;
    fn xmlNewNs(node: xmlNodePtr, href: *const xmlChar, prefix: *const xmlChar) -> xmlNsPtr;
    fn xmlFreeNs(cur: xmlNsPtr);
    fn xmlFreeNsList(cur: xmlNsPtr);
    fn xmlNewDoc(version: *const xmlChar) -> xmlDocPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlNewDocProp(doc: xmlDocPtr, name: *const xmlChar, value: *const xmlChar) -> xmlAttrPtr;
    fn xmlNewProp(node: xmlNodePtr, name: *const xmlChar, value: *const xmlChar) -> xmlAttrPtr;
    fn xmlNewNsProp(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlNewNsPropEatName(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *mut xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlFreePropList(cur: xmlAttrPtr);
    fn xmlFreeProp(cur: xmlAttrPtr);
    fn xmlCopyProp(target: xmlNodePtr, cur: xmlAttrPtr) -> xmlAttrPtr;
    fn xmlCopyPropList(target: xmlNodePtr, cur: xmlAttrPtr) -> xmlAttrPtr;
    fn xmlCopyDtd(dtd: xmlDtdPtr) -> xmlDtdPtr;
    fn xmlCopyDoc(doc: xmlDocPtr, recursive: i32) -> xmlDocPtr;
    fn xmlNewDocNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocNodeEatName(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *mut xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewNodeEatName(ns: xmlNsPtr, name: *mut xmlChar) -> xmlNodePtr;
    fn xmlNewChild(
        parent: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocText(doc: *const xmlDoc, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewText(content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewDocPI(doc: xmlDocPtr, name: *const xmlChar, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewPI(name: *const xmlChar, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewDocTextLen(doc: xmlDocPtr, content: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlNewTextLen(content: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlNewDocComment(doc: xmlDocPtr, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewComment(content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewCDataBlock(doc: xmlDocPtr, content: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlNewCharRef(doc: xmlDocPtr, name: *const xmlChar) -> xmlNodePtr;
    fn xmlNewReference(doc: *const xmlDoc, name: *const xmlChar) -> xmlNodePtr;
    fn xmlCopyNode(node: xmlNodePtr, recursive: i32) -> xmlNodePtr;
    fn xmlDocCopyNode(node: xmlNodePtr, doc: xmlDocPtr, recursive: i32) -> xmlNodePtr;
    fn xmlDocCopyNodeList(doc: xmlDocPtr, node: xmlNodePtr) -> xmlNodePtr;
    fn xmlCopyNodeList(node: xmlNodePtr) -> xmlNodePtr;
    fn xmlNewTextChild(
        parent: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocRawNode(
        doc: xmlDocPtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewDocFragment(doc: xmlDocPtr) -> xmlNodePtr;
    fn xmlGetLineNo(node: *const xmlNode) -> i64;
    fn xmlGetNodePath(node: *const xmlNode) -> *mut xmlChar;
    fn xmlDocGetRootElement(doc: *const xmlDoc) -> xmlNodePtr;
    fn xmlGetLastChild(parent: *const xmlNode) -> xmlNodePtr;
    fn xmlNodeIsText(node: *const xmlNode) -> i32;
    fn xmlIsBlankNode(node: *const xmlNode) -> i32;
    fn xmlDocSetRootElement(doc: xmlDocPtr, root: xmlNodePtr) -> xmlNodePtr;
    fn xmlNodeSetName(cur: xmlNodePtr, name: *const xmlChar);
    fn xmlAddChild(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddChildList(parent: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlReplaceNode(old: xmlNodePtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddPrevSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlAddNextSibling(cur: xmlNodePtr, elem: xmlNodePtr) -> xmlNodePtr;
    fn xmlUnlinkNode(cur: xmlNodePtr);
    fn xmlTextMerge(first: xmlNodePtr, second: xmlNodePtr) -> xmlNodePtr;
    fn xmlTextConcat(node: xmlNodePtr, content: *const xmlChar, len: i32) -> i32;
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSetTreeDoc(tree: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSetListDoc(list: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSearchNs(doc: xmlDocPtr, node: xmlNodePtr, nameSpace: *const xmlChar) -> xmlNsPtr;
    fn xmlSearchNsByHref(doc: xmlDocPtr, node: xmlNodePtr, href: *const xmlChar) -> xmlNsPtr;
    fn xmlSetNs(node: xmlNodePtr, ns: xmlNsPtr);
    fn xmlCopyNamespace(cur: xmlNsPtr) -> xmlNsPtr;
    fn xmlCopyNamespaceList(cur: xmlNsPtr) -> xmlNsPtr;
    fn xmlSetProp(node: xmlNodePtr, name: *const xmlChar, value: *const xmlChar) -> xmlAttrPtr;
    fn xmlSetNsProp(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlGetNoNsProp(node: *const xmlNode, name: *const xmlChar) -> *mut xmlChar;
    fn xmlGetProp(node: *const xmlNode, name: *const xmlChar) -> *mut xmlChar;
    fn xmlHasProp(node: *const xmlNode, name: *const xmlChar) -> xmlAttrPtr;
    fn xmlHasNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        nameSpace: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlGetNsProp(
        node: *const xmlNode,
        name: *const xmlChar,
        nameSpace: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlStringGetNodeList(doc: *const xmlDoc, value: *const xmlChar) -> xmlNodePtr;
    fn xmlStringLenGetNodeList(doc: *const xmlDoc, value: *const xmlChar, len: i32) -> xmlNodePtr;
    fn xmlNodeListGetString(doc: xmlDocPtr, list: *const xmlNode, inLine: i32) -> *mut xmlChar;
    fn xmlNodeListGetRawString(
        doc: *const xmlDoc,
        list: *const xmlNode,
        inLine: i32,
    ) -> *mut xmlChar;
    fn xmlNodeSetContent(cur: xmlNodePtr, content: *const xmlChar);
    fn xmlNodeSetContentLen(cur: xmlNodePtr, content: *const xmlChar, len: i32);
    fn xmlNodeAddContent(cur: xmlNodePtr, content: *const xmlChar);
    fn xmlNodeAddContentLen(cur: xmlNodePtr, content: *const xmlChar, len: i32);
    fn xmlNodeGetContent(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetLang(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetSpacePreserve(cur: *const xmlNode) -> i32;
    fn xmlNodeSetLang(cur: xmlNodePtr, lang: *const xmlChar);
    fn xmlNodeSetSpacePreserve(cur: xmlNodePtr, val: i32);
    fn xmlNodeGetBase(doc: *const xmlDoc, cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeSetBase(cur: xmlNodePtr, uri: *const xmlChar);
    fn xmlRemoveProp(cur: xmlAttrPtr) -> i32;
    fn xmlUnsetNsProp(node: xmlNodePtr, ns: xmlNsPtr, name: *const xmlChar) -> i32;
    fn xmlUnsetProp(node: xmlNodePtr, name: *const xmlChar) -> i32;
    fn xmlReconciliateNs(doc: xmlDocPtr, tree: xmlNodePtr) -> i32;
    fn xmlDocFormatDump(f: *mut FILE, cur: xmlDocPtr, format: i32) -> i32;
    fn xmlDocDump(f: *mut FILE, cur: xmlDocPtr) -> i32;
    fn xmlElemDump(f: *mut FILE, doc: xmlDocPtr, cur: xmlNodePtr);
    fn xmlSaveFile(filename: *const i8, cur: xmlDocPtr) -> i32;
    fn xmlSaveFormatFile(filename: *const i8, cur: xmlDocPtr, format: i32) -> i32;
    fn xmlNodeDumpOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        level: i32,
        format: i32,
        encoding: *const i8,
    );
    fn xmlSaveFormatFileEnc(
        filename: *const i8,
        cur: xmlDocPtr,
        encoding: *const i8,
        format: i32,
    ) -> i32;
    fn xmlSaveFileEnc(filename: *const i8, cur: xmlDocPtr, encoding: *const i8) -> i32;
    fn xmlIsXHTML(systemID: *const xmlChar, publicID: *const xmlChar) -> i32;
    fn xmlGetDocCompressMode(doc: *const xmlDoc) -> i32;
    fn xmlSetDocCompressMode(doc: xmlDocPtr, mode: i32);
    fn xmlGetCompressMode() -> i32;
    fn xmlSetCompressMode(mode: i32);
    fn xmlNextElementSibling(node: xmlNodePtr) -> xmlNodePtr;
    fn xmlFirstElementChild(parent: xmlNodePtr) -> xmlNodePtr;
    fn xmlLastElementChild(parent: xmlNodePtr) -> xmlNodePtr;
    fn xmlPreviousElementSibling(node: xmlNodePtr) -> xmlNodePtr;
    fn xmlGetLastError() -> xmlErrorPtr;
    fn xmlResetLastError();
    fn xmlResetError(err: xmlErrorPtr);
    fn xmlCopyError(from: xmlErrorPtr, to: xmlErrorPtr) -> i32;
    fn xmlGetID(doc: xmlDocPtr, ID: *const xmlChar) -> xmlAttrPtr;
    fn xmlIsID(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> i32;
    fn xmlRemoveID(doc: xmlDocPtr, attr: xmlAttrPtr) -> i32;
    fn xmlIsRef(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> i32;
    fn xmlRemoveRef(doc: xmlDocPtr, attr: xmlAttrPtr) -> i32;
    fn xmlNewValidCtxt() -> xmlValidCtxtPtr;
    fn xmlValidateRoot(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlValidNormalizeAttributeValue(
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlValidCtxtNormalizeAttributeValue(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlValidateDtd(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, dtd: xmlDtdPtr) -> i32;
    fn xmlValidateDtdFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlUTF8Strlen(utf: *const xmlChar) -> i32;
    fn xmlUTF8Charcmp(utf1: *const xmlChar, utf2: *const xmlChar) -> i32;
    fn xmlUTF8Size(utf: *const xmlChar) -> i32;
    fn xmlInitializePredefinedEntities();
    fn xmlNewEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlAddDocEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlAddDtdEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: i32,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlGetPredefinedEntity(name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetDocEntity(doc: *const xmlDoc, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetDtdEntity(doc: xmlDocPtr, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlGetParameterEntity(doc: xmlDocPtr, name: *const xmlChar) -> xmlEntityPtr;
    fn xmlEncodeEntities(doc: xmlDocPtr, input: *const xmlChar) -> *const xmlChar;
    fn xmlEncodeEntitiesReentrant(doc: xmlDocPtr, input: *const xmlChar) -> *mut xmlChar;
    fn xmlEncodeSpecialChars(doc: *const xmlDoc, input: *const xmlChar) -> *mut xmlChar;
    fn xmlCleanupPredefinedEntities();
    fn xmlInitCharEncodingHandlers();
    fn xmlCleanupCharEncodingHandlers();
    fn xmlAddEncodingAlias(name: *const i8, alias: *const i8) -> i32;
    fn xmlDelEncodingAlias(alias: *const i8) -> i32;
    fn xmlGetEncodingAlias(alias: *const i8) -> *const i8;
    fn xmlCleanupEncodingAliases();
    fn xmlCleanupInputCallbacks();
    fn xmlRegisterDefaultInputCallbacks();
    fn xmlParserInputBufferRead(in_0: xmlParserInputBufferPtr, len: i32) -> i32;
    fn xmlParserInputBufferGrow(in_0: xmlParserInputBufferPtr, len: i32) -> i32;
    fn xmlParserInputBufferPush(in_0: xmlParserInputBufferPtr, len: i32, buf: *const i8) -> i32;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const i8) -> *mut i8;
    fn xmlCleanupOutputCallbacks();
    fn xmlPopOutputCallbacks() -> i32;
    fn xmlRegisterDefaultOutputCallbacks();
    fn xmlOutputBufferGetContent(out: xmlOutputBufferPtr) -> *const xmlChar;
    fn xmlOutputBufferWrite(out: xmlOutputBufferPtr, len: i32, buf: *const i8) -> i32;
    fn xmlOutputBufferWriteString(out: xmlOutputBufferPtr, str: *const i8) -> i32;
    fn xmlRegisterHTTPPostCallbacks();
    fn xmlNormalizeWindowsPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlCheckFilename(path: *const i8) -> i32;
    fn xmlFileMatch(filename: *const i8) -> i32;
    fn xmlIOHTTPMatch(filename: *const i8) -> i32;
    fn xmlIOFTPMatch(filename: *const i8) -> i32;
    fn xmlInitParser();
    fn xmlParseDoc(cur: *const xmlChar) -> xmlDocPtr;
    fn xmlParseFile(filename: *const i8) -> xmlDocPtr;
    fn xmlParseMemory(buffer: *const i8, size: i32) -> xmlDocPtr;
    fn xmlSubstituteEntitiesDefault(val: i32) -> i32;
    fn xmlKeepBlanksDefault(val: i32) -> i32;
    fn xmlStopParser(ctxt: xmlParserCtxtPtr);
    fn xmlPedanticParserDefault(val: i32) -> i32;
    fn xmlLineNumbersDefault(val: i32) -> i32;
    fn xmlRecoverDoc(cur: *const xmlChar) -> xmlDocPtr;
    fn xmlRecoverMemory(buffer: *const i8, size: i32) -> xmlDocPtr;
    fn xmlRecoverFile(filename: *const i8) -> xmlDocPtr;
    fn xmlParseDocument(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParseExtParsedEnt(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParseEntity(filename: *const i8) -> xmlDocPtr;
    fn xmlParseDTD(ExternalID: *const xmlChar, SystemID: *const xmlChar) -> xmlDtdPtr;
    fn xmlNewParserCtxt() -> xmlParserCtxtPtr;
    fn xmlInitParserCtxt(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlClearParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlSetupParserForBuffer(ctxt: xmlParserCtxtPtr, buffer: *const xmlChar, filename: *const i8);
    fn xmlCreateDocParserCtxt(cur: *const xmlChar) -> xmlParserCtxtPtr;
    fn xmlParseChunk(ctxt: xmlParserCtxtPtr, chunk: *const i8, size: i32, terminate: i32) -> i32;
    fn xmlByteConsumed(ctxt: xmlParserCtxtPtr) -> i64;
    fn xmlCtxtReset(ctxt: xmlParserCtxtPtr);
    fn xmlCtxtResetPush(
        ctxt: xmlParserCtxtPtr,
        chunk: *const i8,
        size: i32,
        filename: *const i8,
        encoding: *const i8,
    ) -> i32;
    fn xmlCtxtUseOptions(ctxt: xmlParserCtxtPtr, options: i32) -> i32;
    fn xmlReadDoc(
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlReadFile(URL: *const i8, encoding: *const i8, options: i32) -> xmlDocPtr;
    fn xmlReadMemory(
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlReadFd(fd: i32, URL: *const i8, encoding: *const i8, options: i32) -> xmlDocPtr;
    fn xmlCtxtReadDoc(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlCtxtReadFile(
        ctxt: xmlParserCtxtPtr,
        filename: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlCtxtReadMemory(
        ctxt: xmlParserCtxtPtr,
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlCtxtReadFd(
        ctxt: xmlParserCtxtPtr,
        fd: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlDocPtr;
    fn xmlSAXDefaultVersion(version: i32) -> i32;
    fn htmlDefaultSAXHandlerInit();
    fn xmlDefaultSAXHandlerInit();
    fn xmlInitGlobals();
    fn xmlCleanupGlobals();
    static mut xmlFree: xmlFreeFunc;
    fn xmlThrDefDefaultBufferSize(v: i32) -> i32;
    fn xmlThrDefDoValidityCheckingDefaultValue(v: i32) -> i32;
    fn xmlThrDefGetWarningsDefaultValue(v: i32) -> i32;
    fn xmlThrDefIndentTreeOutput(v: i32) -> i32;
    fn xmlThrDefTreeIndentString(v: *const i8) -> *const i8;
    fn xmlThrDefKeepBlanksDefaultValue(v: i32) -> i32;
    fn xmlThrDefLineNumbersDefaultValue(v: i32) -> i32;
    fn xmlThrDefLoadExtDtdDefaultValue(v: i32) -> i32;
    fn xmlThrDefParserDebugEntities(v: i32) -> i32;
    fn xmlThrDefPedanticParserDefaultValue(v: i32) -> i32;
    fn xmlThrDefSaveNoEmptyTags(v: i32) -> i32;
    fn xmlThrDefSubstituteEntitiesDefaultValue(v: i32) -> i32;
    fn xmlGetDtdElementDesc(dtd: xmlDtdPtr, name: *const xmlChar) -> xmlElementPtr;
    fn xmlIsMixedElement(doc: xmlDocPtr, name: *const xmlChar) -> i32;
    fn xmlValidateNotationUse(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        notationName: *const xmlChar,
    ) -> i32;
    fn xmlValidateDocumentFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlValidateOneNamespace(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        prefix: *const xmlChar,
        ns: xmlNsPtr,
        value: *const xmlChar,
    ) -> i32;
    fn xmlValidateOneAttribute(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        attr: xmlAttrPtr,
        value: *const xmlChar,
    ) -> i32;
    fn xmlValidateOneElement(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, elem: xmlNodePtr) -> i32;
    fn xmlValidateElement(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr, elem: xmlNodePtr) -> i32;
    fn xmlGetDtdAttrDesc(
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
    ) -> xmlAttributePtr;
    fn xmlGetDtdQAttrDesc(
        dtd: xmlDtdPtr,
        elem: *const xmlChar,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlAttributePtr;
    fn xmlGetDtdQElementDesc(
        dtd: xmlDtdPtr,
        name: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlElementPtr;
    fn xmlValidateNameValue(value: *const xmlChar) -> i32;
    fn xmlValidateNamesValue(value: *const xmlChar) -> i32;
    fn xmlValidateNmtokenValue(value: *const xmlChar) -> i32;
    fn xmlValidateNmtokensValue(value: *const xmlChar) -> i32;
    fn xmlValidatePushElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> i32;
    fn xmlValidatePushCData(ctxt: xmlValidCtxtPtr, data: *const xmlChar, len: i32) -> i32;
    fn xmlValidatePopElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> i32;
    fn xmlSchemaValidCtxtGetParserCtxt(ctxt: xmlSchemaValidCtxtPtr) -> xmlParserCtxtPtr;
    fn xmlSchemaNewParserCtxt(URL: *const i8) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaNewMemParserCtxt(buffer: *const i8, size: i32) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaNewDocParserCtxt(doc: xmlDocPtr) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaFreeParserCtxt(ctxt: xmlSchemaParserCtxtPtr);
    fn xmlSchemaIsValid(ctxt: xmlSchemaValidCtxtPtr) -> i32;
    fn xmlSchemaParse(ctxt: xmlSchemaParserCtxtPtr) -> xmlSchemaPtr;
    fn xmlSchemaFree(schema: xmlSchemaPtr);
    fn xmlSchemaDump(output: *mut FILE, schema: xmlSchemaPtr);
    fn xmlSchemaSetValidOptions(ctxt: xmlSchemaValidCtxtPtr, options: i32) -> i32;
    fn xmlSchemaValidateSetFilename(vctxt: xmlSchemaValidCtxtPtr, filename: *const i8);
    fn xmlSchemaValidCtxtGetOptions(ctxt: xmlSchemaValidCtxtPtr) -> i32;
    fn xmlSchemaNewValidCtxt(schema: xmlSchemaPtr) -> xmlSchemaValidCtxtPtr;
    fn xmlSchemaValidateDoc(ctxt: xmlSchemaValidCtxtPtr, instance: xmlDocPtr) -> i32;
    fn xmlSchemaValidateOneElement(ctxt: xmlSchemaValidCtxtPtr, elem: xmlNodePtr) -> i32;
    fn xmlSchemaValidateFile(ctxt: xmlSchemaValidCtxtPtr, filename: *const i8, options: i32)
        -> i32;
    fn xmlSchemaInitTypes();
    fn xmlSchemaCleanupTypes();
    fn xmlSchemaCollapseString(value: *const xmlChar) -> *mut xmlChar;
    fn xmlSchemaWhiteSpaceReplace(value: *const xmlChar) -> *mut xmlChar;
    fn xmlNewTextReader(input: xmlParserInputBufferPtr, URI: *const i8) -> xmlTextReaderPtr;
    fn xmlNewTextReaderFilename(URI: *const i8) -> xmlTextReaderPtr;
    fn xmlTextReaderSetup(
        reader: xmlTextReaderPtr,
        input: xmlParserInputBufferPtr,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> i32;
    fn xmlTextReaderRead(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderReadInnerXml(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadOuterXml(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadString(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadAttributeValue(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderAttributeCount(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderDepth(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderHasAttributes(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderHasValue(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderIsDefault(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderIsEmptyElement(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderNodeType(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderQuoteChar(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderReadState(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderIsNamespaceDecl(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderConstBaseUri(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstLocalName(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstName(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstNamespaceUri(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstPrefix(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstXmlLang(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstString(reader: xmlTextReaderPtr, str: *const xmlChar) -> *const xmlChar;
    fn xmlTextReaderConstValue(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderClose(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderGetAttributeNo(reader: xmlTextReaderPtr, no: i32) -> *mut xmlChar;
    fn xmlTextReaderGetAttribute(reader: xmlTextReaderPtr, name: *const xmlChar) -> *mut xmlChar;
    fn xmlTextReaderGetAttributeNs(
        reader: xmlTextReaderPtr,
        localName: *const xmlChar,
        namespaceURI: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlTextReaderGetRemainder(reader: xmlTextReaderPtr) -> xmlParserInputBufferPtr;
    fn xmlTextReaderLookupNamespace(
        reader: xmlTextReaderPtr,
        prefix: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlTextReaderMoveToAttributeNo(reader: xmlTextReaderPtr, no: i32) -> i32;
    fn xmlTextReaderMoveToAttribute(reader: xmlTextReaderPtr, name: *const xmlChar) -> i32;
    fn xmlTextReaderMoveToAttributeNs(
        reader: xmlTextReaderPtr,
        localName: *const xmlChar,
        namespaceURI: *const xmlChar,
    ) -> i32;
    fn xmlTextReaderMoveToFirstAttribute(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderMoveToNextAttribute(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderMoveToElement(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderNormalization(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderConstEncoding(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderSetParserProp(reader: xmlTextReaderPtr, prop: i32, value: i32) -> i32;
    fn xmlTextReaderGetParserProp(reader: xmlTextReaderPtr, prop: i32) -> i32;
    fn xmlTextReaderCurrentNode(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderGetParserLineNumber(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderGetParserColumnNumber(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderPreserve(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderCurrentDoc(reader: xmlTextReaderPtr) -> xmlDocPtr;
    fn xmlTextReaderExpand(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderNext(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderNextSibling(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderIsValid(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderRelaxNGValidate(reader: xmlTextReaderPtr, rng: *const i8) -> i32;
    fn xmlTextReaderRelaxNGValidateCtxt(
        reader: xmlTextReaderPtr,
        ctxt: xmlRelaxNGValidCtxtPtr,
        options: i32,
    ) -> i32;
    fn xmlTextReaderRelaxNGSetSchema(reader: xmlTextReaderPtr, schema: xmlRelaxNGPtr) -> i32;
    fn xmlTextReaderSchemaValidate(reader: xmlTextReaderPtr, xsd: *const i8) -> i32;
    fn xmlTextReaderSchemaValidateCtxt(
        reader: xmlTextReaderPtr,
        ctxt: xmlSchemaValidCtxtPtr,
        options: i32,
    ) -> i32;
    fn xmlTextReaderSetSchema(reader: xmlTextReaderPtr, schema: xmlSchemaPtr) -> i32;
    fn xmlTextReaderConstXmlVersion(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderStandalone(reader: xmlTextReaderPtr) -> i32;
    fn xmlTextReaderByteConsumed(reader: xmlTextReaderPtr) -> i64;
    fn xmlUCSIsLinearBSyllabary(code: i32) -> i32;
    fn xmlIsLetter(c: i32) -> i32;
    fn xmlCreateFileParserCtxt(filename: *const i8) -> xmlParserCtxtPtr;
    fn xmlCreateURLParserCtxt(filename: *const i8, options: i32) -> xmlParserCtxtPtr;
    fn xmlCreateMemoryParserCtxt(buffer: *const i8, size: i32) -> xmlParserCtxtPtr;
    fn xmlCreateEntityParserCtxt(
        URL: *const xmlChar,
        ID: *const xmlChar,
        base: *const xmlChar,
    ) -> xmlParserCtxtPtr;
    fn xmlPopInput(ctxt: xmlParserCtxtPtr) -> xmlChar;
    fn xmlParseName(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn xmlParseNmtoken(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseAttValue(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseSystemLiteral(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParsePubidLiteral(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseCharData(ctxt: xmlParserCtxtPtr, cdata: i32);
    fn xmlParseComment(ctxt: xmlParserCtxtPtr);
    fn xmlParsePITarget(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn xmlParsePI(ctxt: xmlParserCtxtPtr);
    fn xmlParseNotationDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseEntityDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseAttributeListDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseElementDecl(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParseMarkupDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseCharRef(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParseEntityRef(ctxt: xmlParserCtxtPtr) -> xmlEntityPtr;
    fn xmlParseReference(ctxt: xmlParserCtxtPtr);
    fn xmlParsePEReference(ctxt: xmlParserCtxtPtr);
    fn xmlParseDocTypeDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseStartTag(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn xmlParseEndTag(ctxt: xmlParserCtxtPtr);
    fn xmlParseCDSect(ctxt: xmlParserCtxtPtr);
    fn xmlParseContent(ctxt: xmlParserCtxtPtr);
    fn xmlParseElement(ctxt: xmlParserCtxtPtr);
    fn xmlParseVersionNum(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseVersionInfo(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseEncName(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseEncodingDecl(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn xmlParseSDDecl(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParseXMLDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseTextDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseMisc(ctxt: xmlParserCtxtPtr);
    fn xmlParseExternalSubset(
        ctxt: xmlParserCtxtPtr,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
    );
    fn xmlStringDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        str: *const xmlChar,
        what: i32,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn xmlStringLenDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        str: *const xmlChar,
        len: i32,
        what: i32,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn nodePush(ctxt: xmlParserCtxtPtr, value: xmlNodePtr) -> i32;
    fn nodePop(ctxt: xmlParserCtxtPtr) -> xmlNodePtr;
    fn namePop(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn namePush(ctxt: xmlParserCtxtPtr, value: *const xmlChar) -> i32;
    fn xmlSkipBlankChars(ctxt: xmlParserCtxtPtr) -> i32;
    fn xmlParserHandlePEReference(ctxt: xmlParserCtxtPtr);
    fn xmlCheckLanguageID(lang: *const xmlChar) -> i32;
    fn xmlCopyCharMultiByte(out: *mut xmlChar, val: i32) -> i32;
    fn xmlCopyChar(len: i32, out: *mut xmlChar, val: i32) -> i32;
    fn xmlNextChar(ctxt: xmlParserCtxtPtr);
    fn htmlInitAutoClose();
    fn htmlCreateFileParserCtxt(filename: *const i8, encoding: *const i8) -> htmlParserCtxtPtr;
    fn xmlParseQuotedString(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseNamespace(ctxt: xmlParserCtxtPtr);
    fn xmlNamespaceParseNSDef(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlScanName(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlNamespaceParseNCName(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParserHandleReference(ctxt: xmlParserCtxtPtr);
    fn xmlDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        len: i32,
        what: i32,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn xmlHandleEntity(ctxt: xmlParserCtxtPtr, entity: xmlEntityPtr);
    fn xmlNewCatalog(sgml: i32) -> xmlCatalogPtr;
    fn xmlLoadACatalog(filename: *const i8) -> xmlCatalogPtr;
    fn xmlLoadSGMLSuperCatalog(filename: *const i8) -> xmlCatalogPtr;
    fn xmlConvertSGMLCatalog(catal: xmlCatalogPtr) -> i32;
    fn xmlACatalogAdd(
        catal: xmlCatalogPtr,
        type_0: *const xmlChar,
        orig: *const xmlChar,
        replace: *const xmlChar,
    ) -> i32;
    fn xmlACatalogRemove(catal: xmlCatalogPtr, value: *const xmlChar) -> i32;
    fn xmlACatalogResolve(
        catal: xmlCatalogPtr,
        pubID: *const xmlChar,
        sysID: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlACatalogResolveSystem(catal: xmlCatalogPtr, sysID: *const xmlChar) -> *mut xmlChar;
    fn xmlACatalogResolvePublic(catal: xmlCatalogPtr, pubID: *const xmlChar) -> *mut xmlChar;
    fn xmlACatalogResolveURI(catal: xmlCatalogPtr, URI: *const xmlChar) -> *mut xmlChar;
    fn xmlACatalogDump(catal: xmlCatalogPtr, out: *mut FILE);
    fn xmlFreeCatalog(catal: xmlCatalogPtr);
    fn xmlCatalogIsEmpty(catal: xmlCatalogPtr) -> i32;
    fn xmlInitializeCatalog();
    fn xmlLoadCatalog(filename: *const i8) -> i32;
    fn xmlLoadCatalogs(paths: *const i8);
    fn xmlCatalogCleanup();
    fn xmlCatalogDump(out: *mut FILE);
    fn xmlCatalogResolve(pubID: *const xmlChar, sysID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolveSystem(sysID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolvePublic(pubID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolveURI(URI: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogAdd(type_0: *const xmlChar, orig: *const xmlChar, replace: *const xmlChar) -> i32;
    fn xmlCatalogRemove(value: *const xmlChar) -> i32;
    fn xmlParseCatalogFile(filename: *const i8) -> xmlDocPtr;
    fn xmlCatalogConvert() -> i32;
    fn xmlCatalogSetDebug(level: i32) -> i32;
    fn xmlCatalogGetSystem(sysID: *const xmlChar) -> *const xmlChar;
    fn xmlCatalogGetPublic(pubID: *const xmlChar) -> *const xmlChar;
    fn xmlNanoFTPInit();
    fn xmlNanoFTPCleanup();
    fn xmlNanoFTPScanProxy(URL: *const i8);
    fn xmlNanoFTPProxy(host: *const i8, port: i32, user: *const i8, passwd: *const i8, type_0: i32);
    fn xmlNanoHTTPInit();
    fn xmlNanoHTTPCleanup();
    fn xmlNanoHTTPScanProxy(URL: *const i8);
    fn xmlCreateURI() -> xmlURIPtr;
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlBuildRelativeURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const i8) -> xmlURIPtr;
    fn xmlParseURIRaw(str: *const i8, raw: i32) -> xmlURIPtr;
    fn xmlParseURIReference(uri: xmlURIPtr, str: *const i8) -> i32;
    fn xmlSaveUri(uri: xmlURIPtr) -> *mut xmlChar;
    fn xmlPrintURI(stream: *mut FILE, uri: xmlURIPtr);
    fn xmlURIEscapeStr(str: *const xmlChar, list: *const xmlChar) -> *mut xmlChar;
    fn xmlURIUnescapeString(str: *const i8, len: i32, target: *mut i8) -> *mut i8;
    fn xmlNormalizeURIPath(path: *mut i8) -> i32;
    fn xmlURIEscape(str: *const xmlChar) -> *mut xmlChar;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlPathToURI(path: *const xmlChar) -> *mut xmlChar;
    fn xmlXPathCmpNodes(node1: xmlNodePtr, node2: xmlNodePtr) -> i32;
    fn xmlXPathCastNumberToBoolean(val: f64) -> i32;
    fn xmlXPathCastStringToBoolean(val: *const xmlChar) -> i32;
    fn xmlXPathCastBooleanToNumber(val: i32) -> f64;
    fn xmlXPathCastStringToNumber(val: *const xmlChar) -> f64;
    fn xmlXPathCastNodeToNumber(node: xmlNodePtr) -> f64;
    fn xmlXPathCastBooleanToString(val: i32) -> *mut xmlChar;
    fn xmlXPathCastNumberToString(val: f64) -> *mut xmlChar;
    fn xmlXPathCastNodeToString(node: xmlNodePtr) -> *mut xmlChar;
    fn xmlXPathNewContext(doc: xmlDocPtr) -> xmlXPathContextPtr;
    fn xmlXPathFreeContext(ctxt: xmlXPathContextPtr);
    fn xmlXPathContextSetCache(
        ctxt: xmlXPathContextPtr,
        active: i32,
        value: i32,
        options: i32,
    ) -> i32;
    fn xmlXPathOrderDocElems(doc: xmlDocPtr) -> i64;
    fn xmlXPathNodeEval(
        node: xmlNodePtr,
        str: *const xmlChar,
        ctx: xmlXPathContextPtr,
    ) -> xmlXPathObjectPtr;
    fn xmlXPathEval(str: *const xmlChar, ctx: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlXPathEvalExpression(str: *const xmlChar, ctxt: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlXPathInit();
    fn xmlXPathIsNaN(val: f64) -> i32;
    fn xmlXPathIsInf(val: f64) -> i32;
    fn xmlXPathPopBoolean(ctxt: xmlXPathParserContextPtr) -> i32;
    fn xmlXPathPopNumber(ctxt: xmlXPathParserContextPtr) -> f64;
    fn xmlXPathPopString(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPatherror(ctxt: xmlXPathParserContextPtr, file: *const i8, line: i32, no: i32);
    fn xmlXPathErr(ctxt: xmlXPathParserContextPtr, error: i32);
    fn xmlXPathRegisterNs(
        ctxt: xmlXPathContextPtr,
        prefix: *const xmlChar,
        ns_uri: *const xmlChar,
    ) -> i32;
    fn xmlXPathNsLookup(ctxt: xmlXPathContextPtr, prefix: *const xmlChar) -> *const xmlChar;
    fn xmlXPathRegisteredNsCleanup(ctxt: xmlXPathContextPtr);
    fn xmlXPathRegisteredFuncsCleanup(ctxt: xmlXPathContextPtr);
    fn xmlXPathVariableLookup(ctxt: xmlXPathContextPtr, name: *const xmlChar) -> xmlXPathObjectPtr;
    fn xmlXPathVariableLookupNS(
        ctxt: xmlXPathContextPtr,
        name: *const xmlChar,
        ns_uri: *const xmlChar,
    ) -> xmlXPathObjectPtr;
    fn xmlXPathRegisteredVariablesCleanup(ctxt: xmlXPathContextPtr);
    fn xmlXPathNewParserContext(
        str: *const xmlChar,
        ctxt: xmlXPathContextPtr,
    ) -> xmlXPathParserContextPtr;
    fn xmlXPathFreeParserContext(ctxt: xmlXPathParserContextPtr);
    fn valuePop(ctxt: xmlXPathParserContextPtr) -> xmlXPathObjectPtr;
    fn xmlXPathNewString(val: *const xmlChar) -> xmlXPathObjectPtr;
    fn xmlXPathNewCString(val: *const i8) -> xmlXPathObjectPtr;
    fn xmlXPathNewFloat(val: f64) -> xmlXPathObjectPtr;
    fn xmlXPathNewBoolean(val: i32) -> xmlXPathObjectPtr;
    fn xmlXPathNewNodeSet(val: xmlNodePtr) -> xmlXPathObjectPtr;
    fn xmlXPathNewValueTree(val: xmlNodePtr) -> xmlXPathObjectPtr;
    fn xmlXPathRoot(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathEvalExpr(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathParseName(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPathParseNCName(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPathStringEvalNumber(str: *const xmlChar) -> f64;
    fn xmlXPathRegisterAllFunctions(ctxt: xmlXPathContextPtr);
    fn xmlXPathEqualValues(ctxt: xmlXPathParserContextPtr) -> i32;
    fn xmlXPathNotEqualValues(ctxt: xmlXPathParserContextPtr) -> i32;
    fn xmlXPathCompareValues(ctxt: xmlXPathParserContextPtr, inf: i32, strict: i32) -> i32;
    fn xmlXPathValueFlipSign(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathAddValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathSubValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathMultValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathDivValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathModValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathIsNodeType(name: *const xmlChar) -> i32;
    fn xmlXPathNextSelf(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextChild(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextDescendant(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextDescendantOrSelf(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextParent(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextAncestorOrSelf(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextFollowingSibling(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextFollowing(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextNamespace(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextAttribute(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextPreceding(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextAncestor(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextPrecedingSibling(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathLastFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathPositionFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathCountFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathIdFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathLocalNameFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathNamespaceURIFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathStringFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathStringLengthFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathConcatFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathContainsFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathStartsWithFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathSubstringFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathSubstringBeforeFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathSubstringAfterFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathNormalizeFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathTranslateFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathNotFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathTrueFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathFalseFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathLangFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathNumberFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathSumFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathFloorFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathCeilingFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathRoundFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathBooleanFunction(ctxt: xmlXPathParserContextPtr, nargs: i32);
    fn xmlXPathNodeSetFreeNs(ns: xmlNsPtr);
    fn xmlDebugDumpString(output: *mut FILE, str: *const xmlChar);
    fn xmlDebugDumpAttr(output: *mut FILE, attr: xmlAttrPtr, depth: i32);
    fn xmlDebugDumpAttrList(output: *mut FILE, attr: xmlAttrPtr, depth: i32);
    fn xmlDebugDumpOneNode(output: *mut FILE, node: xmlNodePtr, depth: i32);
    fn xmlDebugDumpNode(output: *mut FILE, node: xmlNodePtr, depth: i32);
    fn xmlDebugDumpNodeList(output: *mut FILE, node: xmlNodePtr, depth: i32);
    fn xmlDebugDumpDocumentHead(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugDumpDocument(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugDumpDTD(output: *mut FILE, dtd: xmlDtdPtr);
    fn xmlDebugDumpEntities(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugCheckDocument(output: *mut FILE, doc: xmlDocPtr) -> i32;
    fn xmlLsOneNode(output: *mut FILE, node: xmlNodePtr);
    fn xmlLsCountNode(node: xmlNodePtr) -> i32;
    fn xmlBoolToText(boolval: i32) -> *const i8;
    fn xmlShellPrintXPathError(errorType: i32, arg: *const i8);
    fn xmlShellPrintNode(node: xmlNodePtr);
    fn htmlNewDoc(URI: *const xmlChar, ExternalID: *const xmlChar) -> htmlDocPtr;
    fn htmlNewDocNoDtD(URI: *const xmlChar, ExternalID: *const xmlChar) -> htmlDocPtr;
    fn htmlGetMetaEncoding(doc: htmlDocPtr) -> *const xmlChar;
    fn htmlSetMetaEncoding(doc: htmlDocPtr, encoding: *const xmlChar) -> i32;
    fn htmlDocDump(f: *mut FILE, cur: xmlDocPtr) -> i32;
    fn htmlSaveFile(filename: *const i8, cur: xmlDocPtr) -> i32;
    fn htmlNodeDumpFile(out: *mut FILE, doc: xmlDocPtr, cur: xmlNodePtr);
    fn htmlNodeDumpFileFormat(
        out: *mut FILE,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const i8,
        format: i32,
    ) -> i32;
    fn htmlSaveFileEnc(filename: *const i8, cur: xmlDocPtr, encoding: *const i8) -> i32;
    fn htmlSaveFileFormat(
        filename: *const i8,
        cur: xmlDocPtr,
        encoding: *const i8,
        format: i32,
    ) -> i32;
    fn htmlNodeDumpFormatOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const i8,
        format: i32,
    );
    fn htmlDocContentDumpOutput(buf: xmlOutputBufferPtr, cur: xmlDocPtr, encoding: *const i8);
    fn htmlDocContentDumpFormatOutput(
        buf: xmlOutputBufferPtr,
        cur: xmlDocPtr,
        encoding: *const i8,
        format: i32,
    );
    fn htmlNodeDumpOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const i8,
    );
    fn htmlIsBooleanAttr(name: *const xmlChar) -> i32;
    fn xmlXIncludeProcess(doc: xmlDocPtr) -> i32;
    fn xmlXIncludeProcessFlags(doc: xmlDocPtr, flags: i32) -> i32;
    fn xmlXIncludeProcessTree(tree: xmlNodePtr) -> i32;
    fn xmlXIncludeProcessTreeFlags(tree: xmlNodePtr, flags: i32) -> i32;
    fn xmlXPtrNewContext(
        doc: xmlDocPtr,
        here: xmlNodePtr,
        origin: xmlNodePtr,
    ) -> xmlXPathContextPtr;
    fn xmlXPtrEval(str: *const xmlChar, ctx: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlUCSIsAegeanNumbers(code: i32) -> i32;
    fn xmlUCSIsAlphabeticPresentationForms(code: i32) -> i32;
    fn xmlUCSIsArabic(code: i32) -> i32;
    fn xmlUCSIsArabicPresentationFormsA(code: i32) -> i32;
    fn xmlUCSIsArabicPresentationFormsB(code: i32) -> i32;
    fn xmlUCSIsArmenian(code: i32) -> i32;
    fn xmlUCSIsArrows(code: i32) -> i32;
    fn xmlUCSIsBasicLatin(code: i32) -> i32;
    fn xmlUCSIsBengali(code: i32) -> i32;
    fn xmlUCSIsBlockElements(code: i32) -> i32;
    fn xmlUCSIsBopomofo(code: i32) -> i32;
    fn xmlUCSIsBopomofoExtended(code: i32) -> i32;
    fn xmlUCSIsBoxDrawing(code: i32) -> i32;
    fn xmlUCSIsBraillePatterns(code: i32) -> i32;
    fn xmlUCSIsBuhid(code: i32) -> i32;
    fn xmlUCSIsByzantineMusicalSymbols(code: i32) -> i32;
    fn xmlUCSIsCJKCompatibility(code: i32) -> i32;
    fn xmlUCSIsCJKCompatibilityForms(code: i32) -> i32;
    fn xmlUCSIsCJKCompatibilityIdeographs(code: i32) -> i32;
    fn xmlUCSIsCJKCompatibilityIdeographsSupplement(code: i32) -> i32;
    fn xmlUCSIsCJKRadicalsSupplement(code: i32) -> i32;
    fn xmlUCSIsCJKSymbolsandPunctuation(code: i32) -> i32;
    fn xmlUCSIsCJKUnifiedIdeographs(code: i32) -> i32;
    fn xmlUCSIsCJKUnifiedIdeographsExtensionA(code: i32) -> i32;
    fn xmlUCSIsCJKUnifiedIdeographsExtensionB(code: i32) -> i32;
    fn xmlUCSIsCherokee(code: i32) -> i32;
    fn xmlUCSIsCombiningDiacriticalMarks(code: i32) -> i32;
    fn xmlUCSIsCombiningDiacriticalMarksforSymbols(code: i32) -> i32;
    fn xmlUCSIsCombiningHalfMarks(code: i32) -> i32;
    fn xmlUCSIsCombiningMarksforSymbols(code: i32) -> i32;
    fn xmlUCSIsControlPictures(code: i32) -> i32;
    fn xmlUCSIsCurrencySymbols(code: i32) -> i32;
    fn xmlUCSIsCypriotSyllabary(code: i32) -> i32;
    fn xmlUCSIsCyrillic(code: i32) -> i32;
    fn xmlUCSIsCyrillicSupplement(code: i32) -> i32;
    fn xmlUCSIsDeseret(code: i32) -> i32;
    fn xmlUCSIsDevanagari(code: i32) -> i32;
    fn xmlUCSIsDingbats(code: i32) -> i32;
    fn xmlUCSIsEnclosedAlphanumerics(code: i32) -> i32;
    fn xmlUCSIsEnclosedCJKLettersandMonths(code: i32) -> i32;
    fn xmlUCSIsEthiopic(code: i32) -> i32;
    fn xmlUCSIsGeneralPunctuation(code: i32) -> i32;
    fn xmlUCSIsGeometricShapes(code: i32) -> i32;
    fn xmlUCSIsGeorgian(code: i32) -> i32;
    fn xmlUCSIsGothic(code: i32) -> i32;
    fn xmlUCSIsGreek(code: i32) -> i32;
    fn xmlUCSIsGreekExtended(code: i32) -> i32;
    fn xmlUCSIsGreekandCoptic(code: i32) -> i32;
    fn xmlUCSIsGujarati(code: i32) -> i32;
    fn xmlUCSIsGurmukhi(code: i32) -> i32;
    fn xmlUCSIsHalfwidthandFullwidthForms(code: i32) -> i32;
    fn xmlUCSIsHangulCompatibilityJamo(code: i32) -> i32;
    fn xmlUCSIsHangulJamo(code: i32) -> i32;
    fn xmlUCSIsHangulSyllables(code: i32) -> i32;
    fn xmlUCSIsHanunoo(code: i32) -> i32;
    fn xmlUCSIsHebrew(code: i32) -> i32;
    fn xmlUCSIsHighPrivateUseSurrogates(code: i32) -> i32;
    fn xmlUCSIsHighSurrogates(code: i32) -> i32;
    fn xmlUCSIsHiragana(code: i32) -> i32;
    fn xmlUCSIsIPAExtensions(code: i32) -> i32;
    fn xmlUCSIsIdeographicDescriptionCharacters(code: i32) -> i32;
    fn xmlUCSIsKanbun(code: i32) -> i32;
    fn xmlUCSIsKangxiRadicals(code: i32) -> i32;
    fn xmlUCSIsKannada(code: i32) -> i32;
    fn xmlUCSIsKatakana(code: i32) -> i32;
    fn xmlUCSIsKatakanaPhoneticExtensions(code: i32) -> i32;
    fn xmlUCSIsKhmer(code: i32) -> i32;
    fn xmlUCSIsKhmerSymbols(code: i32) -> i32;
    fn xmlUCSIsLao(code: i32) -> i32;
    fn xmlUCSIsLatin1Supplement(code: i32) -> i32;
    fn xmlUCSIsLatinExtendedA(code: i32) -> i32;
    fn xmlUCSIsLatinExtendedB(code: i32) -> i32;
    fn xmlUCSIsLatinExtendedAdditional(code: i32) -> i32;
    fn xmlUCSIsLetterlikeSymbols(code: i32) -> i32;
    fn xmlUCSIsLimbu(code: i32) -> i32;
    fn xmlUCSIsLinearBIdeograms(code: i32) -> i32;
    fn xmlIsPubidChar(ch: u32) -> i32;
    fn libxml_deprecationWarning(func: *const i8) -> i32;
    fn libxml_xmlErrorPtrWrap(error: xmlErrorPtr) -> *mut PyObject;
    fn libxml_xmlSchemaValidCtxtPtrWrap(valid: xmlSchemaValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlSchemaParserCtxtPtrWrap(ctxt: xmlSchemaParserCtxtPtr) -> *mut PyObject;
    fn libxml_xmlSchemaPtrWrap(ctxt: xmlSchemaPtr) -> *mut PyObject;
    fn libxml_xmlRelaxNGValidCtxtPtrWrap(valid: xmlRelaxNGValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlRelaxNGParserCtxtPtrWrap(ctxt: xmlRelaxNGParserCtxtPtr) -> *mut PyObject;
    fn libxml_xmlRelaxNGPtrWrap(ctxt: xmlRelaxNGPtr) -> *mut PyObject;
    fn libxml_xmlTextReaderPtrWrap(reader: xmlTextReaderPtr) -> *mut PyObject;
    fn libxml_xmlRegexpPtrWrap(regexp: xmlRegexpPtr) -> *mut PyObject;
    fn libxml_xmlParserInputBufferPtrWrap(buffer: xmlParserInputBufferPtr) -> *mut PyObject;
    fn libxml_xmlURIPtrWrap(uri: xmlURIPtr) -> *mut PyObject;
    fn libxml_xmlCatalogPtrWrap(obj: xmlCatalogPtr) -> *mut PyObject;
    fn libxml_xmlValidCtxtPtrWrap(valid: xmlValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlXPathObjectPtrWrap(obj: xmlXPathObjectPtr) -> *mut PyObject;
    fn libxml_xmlXPathParserContextPtrWrap(ctxt: xmlXPathParserContextPtr) -> *mut PyObject;
    fn libxml_xmlParserCtxtPtrWrap(ctxt: xmlParserCtxtPtr) -> *mut PyObject;
    fn libxml_xmlXPathContextPtrWrap(ctxt: xmlXPathContextPtr) -> *mut PyObject;
    fn libxml_doubleWrap(val: f64) -> *mut PyObject;
    fn libxml_xmlElementPtrWrap(ns: xmlElementPtr) -> *mut PyObject;
    fn libxml_xmlAttributePtrWrap(ns: xmlAttributePtr) -> *mut PyObject;
    fn libxml_xmlNsPtrWrap(ns: xmlNsPtr) -> *mut PyObject;
    fn libxml_xmlNodePtrWrap(node: xmlNodePtr) -> *mut PyObject;
    fn libxml_xmlDocPtrWrap(doc: xmlDocPtr) -> *mut PyObject;
    fn libxml_xmlCharPtrConstWrap(str: *const xmlChar) -> *mut PyObject;
    fn libxml_charPtrConstWrap(str: *const i8) -> *mut PyObject;
    fn libxml_charPtrWrap(str: *mut i8) -> *mut PyObject;
    fn libxml_xmlCharPtrWrap(str: *mut xmlChar) -> *mut PyObject;
    fn libxml_longWrap(val: i64) -> *mut PyObject;
    fn libxml_intWrap(val: i32) -> *mut PyObject;
    fn xmlRelaxNGInitTypes() -> i32;
    fn xmlRelaxNGCleanupTypes();
    fn xmlRelaxNGNewParserCtxt(URL: *const i8) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxNGNewMemParserCtxt(buffer: *const i8, size: i32) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxNGNewDocParserCtxt(doc: xmlDocPtr) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxParserSetFlag(ctxt: xmlRelaxNGParserCtxtPtr, flag: i32) -> i32;
    fn xmlRelaxNGFreeParserCtxt(ctxt: xmlRelaxNGParserCtxtPtr);
    fn xmlRelaxNGParse(ctxt: xmlRelaxNGParserCtxtPtr) -> xmlRelaxNGPtr;
    fn xmlRelaxNGFree(schema: xmlRelaxNGPtr);
    fn xmlRelaxNGDump(output: *mut FILE, schema: xmlRelaxNGPtr);
    fn xmlRelaxNGDumpTree(output: *mut FILE, schema: xmlRelaxNGPtr);
    fn xmlRelaxNGNewValidCtxt(schema: xmlRelaxNGPtr) -> xmlRelaxNGValidCtxtPtr;
    fn xmlRelaxNGValidateDoc(ctxt: xmlRelaxNGValidCtxtPtr, doc: xmlDocPtr) -> i32;
    fn xmlRelaxNGValidatePushElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlRelaxNGValidatePushCData(
        ctxt: xmlRelaxNGValidCtxtPtr,
        data: *const xmlChar,
        len: i32,
    ) -> i32;
    fn xmlRelaxNGValidatePopElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlRelaxNGValidateFullElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> i32;
    fn xmlIsIdeographic(ch: u32) -> i32;
    fn xmlIsExtender(ch: u32) -> i32;
    fn xmlIsDigit(ch: u32) -> i32;
    fn xmlIsCombining(ch: u32) -> i32;
    fn xmlIsChar(ch: u32) -> i32;
    fn xmlIsBlank(ch: u32) -> i32;
    fn xmlIsBaseChar(ch: u32) -> i32;
    fn htmlCtxtReadFd(
        ctxt: xmlParserCtxtPtr,
        fd: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlCtxtReadMemory(
        ctxt: xmlParserCtxtPtr,
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlCtxtReadFile(
        ctxt: xmlParserCtxtPtr,
        filename: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlCtxtReadDoc(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlReadFd(fd: i32, URL: *const i8, encoding: *const i8, options: i32) -> htmlDocPtr;
    fn htmlReadMemory(
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlReadFile(URL: *const i8, encoding: *const i8, options: i32) -> htmlDocPtr;
    fn htmlReadDoc(
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> htmlDocPtr;
    fn htmlCtxtUseOptions(ctxt: htmlParserCtxtPtr, options: i32) -> i32;
    fn htmlCtxtReset(ctxt: htmlParserCtxtPtr);
    fn htmlFreeParserCtxt(ctxt: htmlParserCtxtPtr);
    fn htmlParseChunk(ctxt: htmlParserCtxtPtr, chunk: *const i8, size: i32, terminate: i32) -> i32;
    fn htmlHandleOmittedElem(val: i32) -> i32;
    fn htmlIsScriptAttribute(name: *const xmlChar) -> i32;
    fn htmlParseFile(filename: *const i8, encoding: *const i8) -> htmlDocPtr;
    fn htmlParseDoc(cur: *const xmlChar, encoding: *const i8) -> htmlDocPtr;
    fn htmlParseDocument(ctxt: htmlParserCtxtPtr) -> i32;
    fn htmlCreateMemoryParserCtxt(buffer: *const i8, size: i32) -> htmlParserCtxtPtr;
    fn htmlNewParserCtxt() -> htmlParserCtxtPtr;
    fn htmlParseElement(ctxt: htmlParserCtxtPtr);
    fn htmlParseCharRef(ctxt: htmlParserCtxtPtr) -> i32;
    fn htmlAutoCloseTag(doc: htmlDocPtr, name: *const xmlChar, elem: htmlNodePtr) -> i32;
    fn htmlIsAutoClosed(doc: htmlDocPtr, elem: htmlNodePtr) -> i32;
    fn xmlReaderWalker(doc: xmlDocPtr) -> xmlTextReaderPtr;
    fn xmlReaderForDoc(
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlTextReaderPtr;
    fn xmlReaderForFile(filename: *const i8, encoding: *const i8, options: i32)
        -> xmlTextReaderPtr;
    fn xmlReaderForMemory(
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlTextReaderPtr;
    fn xmlReaderForFd(
        fd: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> xmlTextReaderPtr;
    fn xmlReaderNewWalker(reader: xmlTextReaderPtr, doc: xmlDocPtr) -> i32;
    fn xmlReaderNewDoc(
        reader: xmlTextReaderPtr,
        cur: *const xmlChar,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> i32;
    fn xmlReaderNewFile(
        reader: xmlTextReaderPtr,
        filename: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> i32;
    fn xmlReaderNewMemory(
        reader: xmlTextReaderPtr,
        buffer: *const i8,
        size: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> i32;
    fn xmlReaderNewFd(
        reader: xmlTextReaderPtr,
        fd: i32,
        URL: *const i8,
        encoding: *const i8,
        options: i32,
    ) -> i32;
    fn xmlTextReaderLocatorLineNumber(locator: xmlTextReaderLocatorPtr) -> i32;
    fn xmlTextReaderLocatorBaseURI(locator: xmlTextReaderLocatorPtr) -> *mut xmlChar;
    fn xmlUCSIsCatLl(code: i32) -> i32;
    fn xmlUCSIsMalayalam(code: i32) -> i32;
    fn xmlUCSIsMathematicalAlphanumericSymbols(code: i32) -> i32;
    fn xmlUCSIsMathematicalOperators(code: i32) -> i32;
    fn xmlUCSIsMiscellaneousMathematicalSymbolsA(code: i32) -> i32;
    fn xmlUCSIsMiscellaneousMathematicalSymbolsB(code: i32) -> i32;
    fn xmlUCSIsMiscellaneousSymbols(code: i32) -> i32;
    fn xmlUCSIsMiscellaneousSymbolsandArrows(code: i32) -> i32;
    fn xmlUCSIsMiscellaneousTechnical(code: i32) -> i32;
    fn xmlUCSIsMongolian(code: i32) -> i32;
    fn xmlUCSIsMusicalSymbols(code: i32) -> i32;
    fn xmlUCSIsMyanmar(code: i32) -> i32;
    fn xmlUCSIsNumberForms(code: i32) -> i32;
    fn xmlUCSIsOgham(code: i32) -> i32;
    fn xmlUCSIsOldItalic(code: i32) -> i32;
    fn xmlUCSIsLowSurrogates(code: i32) -> i32;
    fn xmlUCSIsCatL(code: i32) -> i32;
    fn xmlUCSIsCatCs(code: i32) -> i32;
    fn xmlUCSIsCatCo(code: i32) -> i32;
    fn xmlUCSIsCatCf(code: i32) -> i32;
    fn xmlUCSIsCatCc(code: i32) -> i32;
    fn xmlUCSIsCatC(code: i32) -> i32;
    fn xmlUCSIsBlock(code: i32, block: *const i8) -> i32;
    fn xmlUCSIsYijingHexagramSymbols(code: i32) -> i32;
    fn xmlUCSIsYiSyllables(code: i32) -> i32;
    fn xmlUCSIsYiRadicals(code: i32) -> i32;
    fn xmlUCSIsVariationSelectorsSupplement(code: i32) -> i32;
    fn xmlUCSIsVariationSelectors(code: i32) -> i32;
    fn xmlUCSIsUnifiedCanadianAboriginalSyllabics(code: i32) -> i32;
    fn xmlUCSIsUgaritic(code: i32) -> i32;
    fn xmlUCSIsTibetan(code: i32) -> i32;
    fn xmlUCSIsThai(code: i32) -> i32;
    fn xmlUCSIsThaana(code: i32) -> i32;
    fn xmlUCSIsTelugu(code: i32) -> i32;
    fn xmlUCSIsTamil(code: i32) -> i32;
    fn xmlUCSIsTaiXuanJingSymbols(code: i32) -> i32;
    fn xmlUCSIsTaiLe(code: i32) -> i32;
    fn xmlUCSIsTags(code: i32) -> i32;
    fn xmlUCSIsTagbanwa(code: i32) -> i32;
    fn xmlUCSIsTagalog(code: i32) -> i32;
    fn xmlUCSIsSyriac(code: i32) -> i32;
    fn xmlUCSIsSupplementaryPrivateUseAreaB(code: i32) -> i32;
    fn xmlUCSIsSupplementaryPrivateUseAreaA(code: i32) -> i32;
    fn xmlUCSIsSupplementalMathematicalOperators(code: i32) -> i32;
    fn xmlUCSIsSupplementalArrowsB(code: i32) -> i32;
    fn xmlUCSIsSupplementalArrowsA(code: i32) -> i32;
    fn xmlUCSIsSuperscriptsandSubscripts(code: i32) -> i32;
    fn xmlUCSIsOpticalCharacterRecognition(code: i32) -> i32;
    fn xmlUCSIsOriya(code: i32) -> i32;
    fn xmlUCSIsOsmanya(code: i32) -> i32;
    fn xmlUCSIsPhoneticExtensions(code: i32) -> i32;
    fn xmlUCSIsSpecials(code: i32) -> i32;
    fn xmlUCSIsSpacingModifierLetters(code: i32) -> i32;
    fn xmlUCSIsPrivateUse(code: i32) -> i32;
    fn xmlUCSIsSmallFormVariants(code: i32) -> i32;
    fn xmlUCSIsSinhala(code: i32) -> i32;
    fn xmlUCSIsShavian(code: i32) -> i32;
    fn xmlUCSIsRunic(code: i32) -> i32;
    fn xmlUCSIsPrivateUseArea(code: i32) -> i32;
    fn xmlUCSIsCatPc(code: i32) -> i32;
    fn xmlUCSIsCatLm(code: i32) -> i32;
    fn xmlUCSIsCatLo(code: i32) -> i32;
    fn xmlUCSIsCatLt(code: i32) -> i32;
    fn xmlUCSIsCatLu(code: i32) -> i32;
    fn xmlUCSIsCatM(code: i32) -> i32;
    fn xmlUCSIsCatMc(code: i32) -> i32;
    fn xmlUCSIsCatMe(code: i32) -> i32;
    fn xmlUCSIsCatMn(code: i32) -> i32;
    fn xmlUCSIsCatN(code: i32) -> i32;
    fn xmlUCSIsCatNd(code: i32) -> i32;
    fn xmlUCSIsCatNl(code: i32) -> i32;
    fn xmlUCSIsCatNo(code: i32) -> i32;
    fn xmlUCSIsCatP(code: i32) -> i32;
    fn xmlUCSIsCatSo(code: i32) -> i32;
    fn xmlUCSIsCatPf(code: i32) -> i32;
    fn xmlUCSIsCatPe(code: i32) -> i32;
    fn xmlUCSIsCatPd(code: i32) -> i32;
    fn xmlUCSIsCatPi(code: i32) -> i32;
    fn xmlUCSIsCatPo(code: i32) -> i32;
    fn xmlUCSIsCatPs(code: i32) -> i32;
    fn xmlUCSIsCatS(code: i32) -> i32;
    fn xmlUCSIsCatSc(code: i32) -> i32;
    fn xmlUCSIsCatSm(code: i32) -> i32;
    fn xmlUCSIsCatSk(code: i32) -> i32;
    fn xmlUCSIsCatZ(code: i32) -> i32;
    fn xmlUCSIsCatZl(code: i32) -> i32;
    fn xmlUCSIsCatZp(code: i32) -> i32;
    fn xmlUCSIsCatZs(code: i32) -> i32;
    fn xmlUCSIsCat(code: i32, cat: *const i8) -> i32;
}
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
pub type __ssize_t = i64;
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
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: __off_t,
    pub _cur_column: u16,
    pub _vtable_offset: i8,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type ssize_t = __ssize_t;
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
    pub tp_name: *const i8,
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
    pub tp_flags: i64,
    pub tp_doc: *const i8,
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
    pub tp_version_tag: u32,
}
pub type destructor = Option<unsafe extern "C" fn(*mut PyObject) -> ()>;
pub type PyObject = _object;
pub type inquiry = Option<unsafe extern "C" fn(*mut PyObject) -> i32>;
pub type freefunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type newfunc =
    Option<unsafe extern "C" fn(*mut _typeobject, *mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type allocfunc = Option<unsafe extern "C" fn(*mut _typeobject, Py_ssize_t) -> *mut PyObject>;
pub type initproc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> i32>;
pub type descrsetfunc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> i32>;
pub type descrgetfunc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyGetSetDef {
    pub name: *mut i8,
    pub get: getter,
    pub set: setter,
    pub doc: *mut i8,
    pub closure: *mut libc::c_void,
}
pub type setter =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut libc::c_void) -> i32>;
pub type getter = Option<unsafe extern "C" fn(*mut PyObject, *mut libc::c_void) -> *mut PyObject>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyMethodDef {
    pub ml_name: *const i8,
    pub ml_meth: PyCFunction,
    pub ml_flags: i32,
    pub ml_doc: *const i8,
}
pub type PyCFunction = Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type iternextfunc = Option<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type getiterfunc = Option<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type richcmpfunc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, i32) -> *mut PyObject>;
pub type traverseproc =
    Option<unsafe extern "C" fn(*mut PyObject, visitproc, *mut libc::c_void) -> i32>;
pub type visitproc = Option<unsafe extern "C" fn(*mut PyObject, *mut libc::c_void) -> i32>;
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
pub type releasebufferproc = Option<unsafe extern "C" fn(*mut PyObject, *mut Py_buffer) -> ()>;
pub type Py_buffer = bufferinfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bufferinfo {
    pub buf: *mut libc::c_void,
    pub obj: *mut PyObject,
    pub len: Py_ssize_t,
    pub itemsize: Py_ssize_t,
    pub readonly: i32,
    pub ndim: i32,
    pub format: *mut i8,
    pub shape: *mut Py_ssize_t,
    pub strides: *mut Py_ssize_t,
    pub suboffsets: *mut Py_ssize_t,
    pub smalltable: [Py_ssize_t; 2],
    pub internal: *mut libc::c_void,
}
pub type getbufferproc = Option<unsafe extern "C" fn(*mut PyObject, *mut Py_buffer, i32) -> i32>;
pub type charbufferproc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut i8) -> Py_ssize_t>;
pub type segcountproc = Option<unsafe extern "C" fn(*mut PyObject, *mut Py_ssize_t) -> Py_ssize_t>;
pub type writebufferproc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut libc::c_void) -> Py_ssize_t>;
pub type readbufferproc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut *mut libc::c_void) -> Py_ssize_t>;
pub type setattrofunc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> i32>;
pub type getattrofunc = Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type reprfunc = Option<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type ternaryfunc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type hashfunc = Option<unsafe extern "C" fn(*mut PyObject) -> i64>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyMappingMethods {
    pub mp_length: lenfunc,
    pub mp_subscript: binaryfunc,
    pub mp_ass_subscript: objobjargproc,
}
pub type objobjargproc =
    Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject, *mut PyObject) -> i32>;
pub type binaryfunc = Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> *mut PyObject>;
pub type lenfunc = Option<unsafe extern "C" fn(*mut PyObject) -> Py_ssize_t>;
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
pub type ssizeargfunc = Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t) -> *mut PyObject>;
pub type objobjproc = Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> i32>;
pub type ssizessizeobjargproc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, Py_ssize_t, *mut PyObject) -> i32>;
pub type ssizeobjargproc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, *mut PyObject) -> i32>;
pub type ssizessizeargfunc =
    Option<unsafe extern "C" fn(*mut PyObject, Py_ssize_t, Py_ssize_t) -> *mut PyObject>;
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
pub type unaryfunc = Option<unsafe extern "C" fn(*mut PyObject) -> *mut PyObject>;
pub type coercion = Option<unsafe extern "C" fn(*mut *mut PyObject, *mut *mut PyObject) -> i32>;
pub type cmpfunc = Option<unsafe extern "C" fn(*mut PyObject, *mut PyObject) -> i32>;
pub type setattrfunc = Option<unsafe extern "C" fn(*mut PyObject, *mut i8, *mut PyObject) -> i32>;
pub type getattrfunc = Option<unsafe extern "C" fn(*mut PyObject, *mut i8) -> *mut PyObject>;
pub type printfunc = Option<unsafe extern "C" fn(*mut PyObject, *mut FILE, i32) -> i32>;
pub type PyTypeObject = _typeobject;
pub type xmlChar = u8;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInputBuffer {
    pub context: *mut libc::c_void,
    pub readcallback: xmlInputReadCallback,
    pub closecallback: xmlInputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub raw: xmlBufPtr,
    pub compressed: i32,
    pub error: i32,
    pub rawconsumed: u64,
}
pub type xmlBufPtr = *mut xmlBuf;
pub type xmlBuf = _xmlBuf;
pub type xmlCharEncodingHandlerPtr = *mut xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = _xmlCharEncodingHandler;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlCharEncodingHandler {
    pub name: *mut i8,
    pub input: xmlCharEncodingInputFunc,
    pub output: xmlCharEncodingOutputFunc,
    pub iconv_in: iconv_t,
    pub iconv_out: iconv_t,
}
pub type iconv_t = *mut libc::c_void;
pub type xmlCharEncodingOutputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlCharEncodingInputFunc =
    Option<unsafe extern "C" fn(*mut u8, *mut i32, *const u8, *mut i32) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlInputReadCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *mut i8, i32) -> i32>;
pub type xmlParserInputBuffer = _xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = *mut xmlParserInputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlOutputBuffer {
    pub context: *mut libc::c_void,
    pub writecallback: xmlOutputWriteCallback,
    pub closecallback: xmlOutputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub conv: xmlBufPtr,
    pub written: i32,
    pub error: i32,
}
pub type xmlOutputCloseCallback = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type xmlOutputWriteCallback =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, i32) -> i32>;
pub type xmlOutputBuffer = _xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut xmlOutputBuffer;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserInput {
    pub buf: xmlParserInputBufferPtr,
    pub filename: *const i8,
    pub directory: *const i8,
    pub base: *const xmlChar,
    pub cur: *const xmlChar,
    pub end: *const xmlChar,
    pub length: i32,
    pub line: i32,
    pub col: i32,
    pub consumed: u64,
    pub free: xmlParserInputDeallocate,
    pub encoding: *const xmlChar,
    pub version: *const xmlChar,
    pub standalone: i32,
    pub id: i32,
}
pub type xmlParserInputDeallocate = Option<unsafe extern "C" fn(*mut xmlChar) -> ()>;
pub type xmlParserInput = _xmlParserInput;
pub type xmlParserInputPtr = *mut xmlParserInput;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserCtxt {
    pub sax: *mut _xmlSAXHandler,
    pub userData: *mut libc::c_void,
    pub myDoc: xmlDocPtr,
    pub wellFormed: i32,
    pub replaceEntities: i32,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub standalone: i32,
    pub html: i32,
    pub input: xmlParserInputPtr,
    pub inputNr: i32,
    pub inputMax: i32,
    pub inputTab: *mut xmlParserInputPtr,
    pub node: xmlNodePtr,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
    pub record_info: i32,
    pub node_seq: xmlParserNodeInfoSeq,
    pub errNo: i32,
    pub hasExternalSubset: i32,
    pub hasPErefs: i32,
    pub external: i32,
    pub valid: i32,
    pub validate: i32,
    pub vctxt: xmlValidCtxt,
    pub instate: xmlParserInputState,
    pub token: i32,
    pub directory: *mut i8,
    pub name: *const xmlChar,
    pub nameNr: i32,
    pub nameMax: i32,
    pub nameTab: *mut *const xmlChar,
    pub nbChars: i64,
    pub checkIndex: i64,
    pub keepBlanks: i32,
    pub disableSAX: i32,
    pub inSubset: i32,
    pub intSubName: *const xmlChar,
    pub extSubURI: *mut xmlChar,
    pub extSubSystem: *mut xmlChar,
    pub space: *mut i32,
    pub spaceNr: i32,
    pub spaceMax: i32,
    pub spaceTab: *mut i32,
    pub depth: i32,
    pub entity: xmlParserInputPtr,
    pub charset: i32,
    pub nodelen: i32,
    pub nodemem: i32,
    pub pedantic: i32,
    pub _private: *mut libc::c_void,
    pub loadsubset: i32,
    pub linenumbers: i32,
    pub catalogs: *mut libc::c_void,
    pub recovery: i32,
    pub progressive: i32,
    pub dict: xmlDictPtr,
    pub atts: *mut *const xmlChar,
    pub maxatts: i32,
    pub docdict: i32,
    pub str_xml: *const xmlChar,
    pub str_xmlns: *const xmlChar,
    pub str_xml_ns: *const xmlChar,
    pub sax2: i32,
    pub nsNr: i32,
    pub nsMax: i32,
    pub nsTab: *mut *const xmlChar,
    pub attallocs: *mut i32,
    pub pushTab: *mut xmlStartTag,
    pub attsDefault: xmlHashTablePtr,
    pub attsSpecial: xmlHashTablePtr,
    pub nsWellFormed: i32,
    pub options: i32,
    pub dictNames: i32,
    pub freeElemsNr: i32,
    pub freeElems: xmlNodePtr,
    pub freeAttrsNr: i32,
    pub freeAttrs: xmlAttrPtr,
    pub lastError: xmlError,
    pub parseMode: xmlParserMode,
    pub nbentities: u64,
    pub sizeentities: u64,
    pub nodeInfo: *mut xmlParserNodeInfo,
    pub nodeInfoNr: i32,
    pub nodeInfoMax: i32,
    pub nodeInfoTab: *mut xmlParserNodeInfo,
    pub input_id: i32,
    pub sizeentcopy: u64,
}
pub type xmlParserNodeInfo = _xmlParserNodeInfo;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfo {
    pub node: *const _xmlNode,
    pub begin_pos: u64,
    pub begin_line: u64,
    pub end_pos: u64,
    pub end_line: u64,
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
    pub line: u16,
    pub extra: u16,
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
    pub name: *mut i8,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlNode,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub compression: i32,
    pub standalone: i32,
    pub intSubset: *mut _xmlDtd,
    pub extSubset: *mut _xmlDtd,
    pub oldNs: *mut _xmlNs,
    pub version: *const xmlChar,
    pub encoding: *const xmlChar,
    pub ids: *mut libc::c_void,
    pub refs: *mut libc::c_void,
    pub URL: *const xmlChar,
    pub charset: i32,
    pub dict: *mut _xmlDict,
    pub psvi: *mut libc::c_void,
    pub parseFlags: i32,
    pub properties: i32,
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
pub type xmlError = _xmlError;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlError {
    pub domain: i32,
    pub code: i32,
    pub message: *mut i8,
    pub level: xmlErrorLevel,
    pub file: *mut i8,
    pub line: i32,
    pub str1: *mut i8,
    pub str2: *mut i8,
    pub str3: *mut i8,
    pub int1: i32,
    pub int2: i32,
    pub ctxt: *mut libc::c_void,
    pub node: *mut libc::c_void,
}
pub type xmlErrorLevel = u32;
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
pub type xmlDictPtr = *mut xmlDict;
pub type xmlDict = _xmlDict;
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
pub type xmlValidCtxt = _xmlValidCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlValidCtxt {
    pub userData: *mut libc::c_void,
    pub error: xmlValidityErrorFunc,
    pub warning: xmlValidityWarningFunc,
    pub node: xmlNodePtr,
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
    pub flags: u32,
    pub doc: xmlDocPtr,
    pub valid: i32,
    pub vstate: *mut xmlValidState,
    pub vstateNr: i32,
    pub vstateMax: i32,
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
pub type xmlValidityWarningFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlValidityErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type xmlParserNodeInfoSeq = _xmlParserNodeInfoSeq;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlParserNodeInfoSeq {
    pub maximum: u64,
    pub length: u64,
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
    pub initialized: u32,
    pub _private: *mut libc::c_void,
    pub startElementNs: startElementNsSAX2Func,
    pub endElementNs: endElementNsSAX2Func,
    pub serror: xmlStructuredErrorFunc,
}
pub type xmlStructuredErrorFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlErrorPtr) -> ()>;
pub type xmlErrorPtr = *mut xmlError;
pub type endElementNsSAX2Func = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type startElementNsSAX2Func = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        i32,
        *mut *const xmlChar,
        i32,
        i32,
        *mut *const xmlChar,
    ) -> (),
>;
pub type externalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type cdataBlockSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type getParameterEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
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
    pub length: i32,
    pub etype: xmlEntityType,
    pub ExternalID: *const xmlChar,
    pub SystemID: *const xmlChar,
    pub nexte: *mut _xmlEntity,
    pub URI: *const xmlChar,
    pub owner: i32,
    pub checked: i32,
}
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const i8, ...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type processingInstructionSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> ()>;
pub type ignorableWhitespaceSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type charactersSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> ()>;
pub type startElementSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *mut *const xmlChar) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type setDocumentLocatorSAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, xmlSAXLocatorPtr) -> ()>;
pub type xmlSAXLocatorPtr = *mut xmlSAXLocator;
pub type xmlSAXLocator = _xmlSAXLocator;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSAXLocator {
    pub getPublicId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getSystemId: Option<unsafe extern "C" fn(*mut libc::c_void) -> *const xmlChar>,
    pub getLineNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
    pub getColumnNumber: Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>,
}
pub type unparsedEntityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
        *const xmlChar,
    ) -> (),
>;
pub type elementDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, i32, xmlElementContentPtr) -> (),
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
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
        i32,
        i32,
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
pub type notationDeclSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type entityDeclSAXFunc = Option<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        i32,
        *const xmlChar,
        *const xmlChar,
        *mut xmlChar,
    ) -> (),
>;
pub type getEntitySAXFunc =
    Option<unsafe extern "C" fn(*mut libc::c_void, *const xmlChar) -> xmlEntityPtr>;
pub type resolveEntitySAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlParserInputPtr,
>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> i32>;
pub type internalSubsetSAXFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar, *const xmlChar) -> (),
>;
pub type xmlParserCtxt = _xmlParserCtxt;
pub type xmlParserCtxtPtr = *mut xmlParserCtxt;
pub type xmlAttributeDefault = u32;
pub const XML_ATTRIBUTE_FIXED: xmlAttributeDefault = 4;
pub const XML_ATTRIBUTE_IMPLIED: xmlAttributeDefault = 3;
pub const XML_ATTRIBUTE_REQUIRED: xmlAttributeDefault = 2;
pub const XML_ATTRIBUTE_NONE: xmlAttributeDefault = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAttribute {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub nexth: *mut _xmlAttribute,
    pub atype: xmlAttributeType,
    pub def: xmlAttributeDefault,
    pub defaultValue: *const xmlChar,
    pub tree: xmlEnumerationPtr,
    pub prefix: *const xmlChar,
    pub elem: *const xmlChar,
}
pub type xmlAttribute = _xmlAttribute;
pub type xmlAttributePtr = *mut xmlAttribute;
pub type xmlElementTypeVal = u32;
pub const XML_ELEMENT_TYPE_ELEMENT: xmlElementTypeVal = 4;
pub const XML_ELEMENT_TYPE_MIXED: xmlElementTypeVal = 3;
pub const XML_ELEMENT_TYPE_ANY: xmlElementTypeVal = 2;
pub const XML_ELEMENT_TYPE_EMPTY: xmlElementTypeVal = 1;
pub const XML_ELEMENT_TYPE_UNDEFINED: xmlElementTypeVal = 0;
pub type xmlRegexp = _xmlRegexp;
pub type xmlRegexpPtr = *mut xmlRegexp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlElement {
    pub _private: *mut libc::c_void,
    pub type_0: xmlElementType,
    pub name: *const xmlChar,
    pub children: *mut _xmlNode,
    pub last: *mut _xmlNode,
    pub parent: *mut _xmlDtd,
    pub next: *mut _xmlNode,
    pub prev: *mut _xmlNode,
    pub doc: *mut _xmlDoc,
    pub etype: xmlElementTypeVal,
    pub content: xmlElementContentPtr,
    pub attributes: xmlAttributePtr,
    pub prefix: *const xmlChar,
    pub contModel: xmlRegexpPtr,
}
pub type xmlElement = _xmlElement;
pub type xmlElementPtr = *mut xmlElement;
pub type xmlNsPtr = *mut xmlNs;
pub type xmlDtd = _xmlDtd;
pub type xmlDtdPtr = *mut xmlDtd;
pub type xmlFreeFunc = Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
pub type xmlValidCtxtPtr = *mut xmlValidCtxt;
pub type xmlSchemaAnnotPtr = *mut xmlSchemaAnnot;
pub type xmlSchemaAnnot = _xmlSchemaAnnot;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchemaAnnot {
    pub next: *mut _xmlSchemaAnnot,
    pub content: xmlNodePtr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlSchema {
    pub name: *const xmlChar,
    pub targetNamespace: *const xmlChar,
    pub version: *const xmlChar,
    pub id: *const xmlChar,
    pub doc: xmlDocPtr,
    pub annot: xmlSchemaAnnotPtr,
    pub flags: i32,
    pub typeDecl: xmlHashTablePtr,
    pub attrDecl: xmlHashTablePtr,
    pub attrgrpDecl: xmlHashTablePtr,
    pub elemDecl: xmlHashTablePtr,
    pub notaDecl: xmlHashTablePtr,
    pub schemasImports: xmlHashTablePtr,
    pub _private: *mut libc::c_void,
    pub groupDecl: xmlHashTablePtr,
    pub dict: xmlDictPtr,
    pub includes: *mut libc::c_void,
    pub preserve: i32,
    pub counter: i32,
    pub idcDef: xmlHashTablePtr,
    pub volatiles: *mut libc::c_void,
}
pub type xmlSchema = _xmlSchema;
pub type xmlSchemaPtr = *mut xmlSchema;
pub type xmlSchemaParserCtxt = _xmlSchemaParserCtxt;
pub type xmlSchemaParserCtxtPtr = *mut xmlSchemaParserCtxt;
pub type xmlSchemaValidCtxt = _xmlSchemaValidCtxt;
pub type xmlSchemaValidCtxtPtr = *mut xmlSchemaValidCtxt;
pub type htmlParserCtxtPtr = xmlParserCtxtPtr;
pub type htmlDocPtr = xmlDocPtr;
pub type htmlNodePtr = xmlNodePtr;
pub type xmlCatalog = _xmlCatalog;
pub type xmlCatalogPtr = *mut xmlCatalog;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlURI {
    pub scheme: *mut i8,
    pub opaque: *mut i8,
    pub authority: *mut i8,
    pub server: *mut i8,
    pub user: *mut i8,
    pub port: i32,
    pub path: *mut i8,
    pub query: *mut i8,
    pub fragment: *mut i8,
    pub cleanup: i32,
    pub query_raw: *mut i8,
}
pub type xmlURI = _xmlURI;
pub type xmlURIPtr = *mut xmlURI;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathContext {
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub nb_variables_unused: i32,
    pub max_variables_unused: i32,
    pub varHash: xmlHashTablePtr,
    pub nb_types: i32,
    pub max_types: i32,
    pub types: xmlXPathTypePtr,
    pub nb_funcs_unused: i32,
    pub max_funcs_unused: i32,
    pub funcHash: xmlHashTablePtr,
    pub nb_axis: i32,
    pub max_axis: i32,
    pub axis: xmlXPathAxisPtr,
    pub namespaces: *mut xmlNsPtr,
    pub nsNr: i32,
    pub user: *mut libc::c_void,
    pub contextSize: i32,
    pub proximityPosition: i32,
    pub xptr: i32,
    pub here: xmlNodePtr,
    pub origin: xmlNodePtr,
    pub nsHash: xmlHashTablePtr,
    pub varLookupFunc: xmlXPathVariableLookupFunc,
    pub varLookupData: *mut libc::c_void,
    pub extra: *mut libc::c_void,
    pub function: *const xmlChar,
    pub functionURI: *const xmlChar,
    pub funcLookupFunc: xmlXPathFuncLookupFunc,
    pub funcLookupData: *mut libc::c_void,
    pub tmpNsList: *mut xmlNsPtr,
    pub tmpNsNr: i32,
    pub userData: *mut libc::c_void,
    pub error: xmlStructuredErrorFunc,
    pub lastError: xmlError,
    pub debugNode: xmlNodePtr,
    pub dict: xmlDictPtr,
    pub flags: i32,
    pub cache: *mut libc::c_void,
    pub opLimit: u64,
    pub opCount: u64,
    pub depth: i32,
}
pub type xmlXPathFuncLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathFunction,
>;
pub type xmlXPathFunction = Option<unsafe extern "C" fn(xmlXPathParserContextPtr, i32) -> ()>;
pub type xmlXPathParserContextPtr = *mut xmlXPathParserContext;
pub type xmlXPathParserContext = _xmlXPathParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: i32,
    pub context: xmlXPathContextPtr,
    pub value: xmlXPathObjectPtr,
    pub valueNr: i32,
    pub valueMax: i32,
    pub valueTab: *mut xmlXPathObjectPtr,
    pub comp: xmlXPathCompExprPtr,
    pub xptr: i32,
    pub ancestor: xmlNodePtr,
    pub valueFrame: i32,
}
pub type xmlXPathCompExprPtr = *mut xmlXPathCompExpr;
pub type xmlXPathCompExpr = _xmlXPathCompExpr;
pub type xmlXPathObjectPtr = *mut xmlXPathObject;
pub type xmlXPathObject = _xmlXPathObject;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathObject {
    pub type_0: xmlXPathObjectType,
    pub nodesetval: xmlNodeSetPtr,
    pub boolval: i32,
    pub floatval: f64,
    pub stringval: *mut xmlChar,
    pub user: *mut libc::c_void,
    pub index: i32,
    pub user2: *mut libc::c_void,
    pub index2: i32,
}
pub type xmlNodeSetPtr = *mut xmlNodeSet;
pub type xmlNodeSet = _xmlNodeSet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNodeSet {
    pub nodeNr: i32,
    pub nodeMax: i32,
    pub nodeTab: *mut xmlNodePtr,
}
pub type xmlXPathObjectType = u32;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = *mut xmlXPathContext;
pub type xmlXPathContext = _xmlXPathContext;
pub type xmlXPathVariableLookupFunc = Option<
    unsafe extern "C" fn(*mut libc::c_void, *const xmlChar, *const xmlChar) -> xmlXPathObjectPtr,
>;
pub type xmlXPathAxisPtr = *mut xmlXPathAxis;
pub type xmlXPathAxis = _xmlXPathAxis;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathAxis {
    pub name: *const xmlChar,
    pub func: xmlXPathAxisFunc,
}
pub type xmlXPathAxisFunc =
    Option<unsafe extern "C" fn(xmlXPathParserContextPtr, xmlXPathObjectPtr) -> xmlXPathObjectPtr>;
pub type xmlXPathTypePtr = *mut xmlXPathType;
pub type xmlXPathType = _xmlXPathType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathType {
    pub name: *const xmlChar,
    pub func: xmlXPathConvertFunc,
}
pub type xmlXPathConvertFunc = Option<unsafe extern "C" fn(xmlXPathObjectPtr, i32) -> i32>;
pub type xmlRelaxNG = _xmlRelaxNG;
pub type xmlRelaxNGPtr = *mut xmlRelaxNG;
pub type xmlRelaxNGParserCtxt = _xmlRelaxNGParserCtxt;
pub type xmlRelaxNGParserCtxtPtr = *mut xmlRelaxNGParserCtxt;
pub type xmlRelaxNGValidCtxt = _xmlRelaxNGValidCtxt;
pub type xmlRelaxNGValidCtxtPtr = *mut xmlRelaxNGValidCtxt;
pub type xmlTextReader = _xmlTextReader;
pub type xmlTextReaderPtr = *mut xmlTextReader;
pub type xmlTextReaderLocatorPtr = *mut libc::c_void;
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
pub struct PyxmlXPathParserContext_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlXPathParserContextPtr,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyxmlTextReader_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlTextReaderPtr,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyoutputBuffer_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlOutputBufferPtr,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyrelaxNgValidCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlRelaxNGValidCtxtPtr,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PySchemaValidCtxt_Object {
    pub ob_refcnt: Py_ssize_t,
    pub ob_type: *mut _typeobject,
    pub obj: xmlSchemaValidCtxtPtr,
}
#[no_mangle]
pub extern "C" fn libxml_htmlAutoCloseTag(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OzO:htmlAutoCloseTag\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as htmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { htmlAutoCloseTag(doc, name, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCreateFileParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:htmlCreateFileParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlCreateFileParserCtxt(filename, encoding) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCreateMemoryParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#i:htmlCreateMemoryParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlCreateMemoryParserCtxt(buffer, size) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtReadDoc(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzzi:htmlCtxtReadDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlCtxtReadDoc(ctxt, cur, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtReadFd(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oizzi:htmlCtxtReadFd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlCtxtReadFd(ctxt, fd, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtReadFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzi:htmlCtxtReadFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlCtxtReadFile(ctxt, filename, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtReadMemory(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Os#izzi:htmlCtxtReadMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlCtxtReadMemory(ctxt, buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtReset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlCtxtReset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { htmlCtxtReset(ctxt) });
    let fresh0 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh0 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlCtxtUseOptions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:htmlCtxtUseOptions\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlCtxtUseOptions(ctxt, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlDefaultSAXHandlerInit(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe {
        libxml_deprecationWarning(b"htmlDefaultSAXHandlerInit\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { htmlDefaultSAXHandlerInit() });
    let fresh1 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh1 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlDocContentDumpFormatOutput(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzi:htmlDocContentDumpFormatOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_buf as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { htmlDocContentDumpFormatOutput(buf, cur, encoding, format) });
    let fresh2 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh2 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlDocContentDumpOutput(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOz:htmlDocContentDumpOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_buf as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { htmlDocContentDumpOutput(buf, cur, encoding) });
    let fresh3 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh3 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlDocDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:htmlDocDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_f as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_f).ob_type }) == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_f) }
    } else {
        unsafe { stdout }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { htmlDocDump(f, cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlFreeParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlFreeParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { htmlFreeParserCtxt(ctxt) });
    let fresh4 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh4 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlGetMetaEncoding(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlGetMetaEncoding\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as htmlDocPtr;
    c_retval = unsafe { htmlGetMetaEncoding(doc) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlHandleOmittedElem(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:htmlHandleOmittedElem\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlHandleOmittedElem(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlInitAutoClose(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"htmlInitAutoClose\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { htmlInitAutoClose() });
    let fresh5 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh5 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlIsAutoClosed(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:htmlIsAutoClosed\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as htmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { htmlIsAutoClosed(doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlIsBooleanAttr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:htmlIsBooleanAttr\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlIsBooleanAttr(name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlIsScriptAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:htmlIsScriptAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlIsScriptAttribute(name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlNewDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:htmlNewDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut xmlChar,
            &mut ExternalID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlNewDoc(URI, ExternalID) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlNewDocNoDtD(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:htmlNewDocNoDtD\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut xmlChar,
            &mut ExternalID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlNewDocNoDtD(URI, ExternalID) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlNewParserCtxt(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    c_retval = unsafe { htmlNewParserCtxt() };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlNodeDumpFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:htmlNodeDumpFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_out).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_out) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { htmlNodeDumpFile(out, doc, cur) });
    let fresh6 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh6 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlNodeDumpFileFormat(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOzi:htmlNodeDumpFileFormat\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_out).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_out) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { htmlNodeDumpFileFormat(out, doc, cur, encoding, format) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlNodeDumpFormatOutput(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOzi:htmlNodeDumpFormatOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_buf as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { htmlNodeDumpFormatOutput(buf, doc, cur, encoding, format) });
    let fresh7 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh7 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlNodeDumpOutput(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut buf: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_buf: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOz:htmlNodeDumpOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_buf as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { htmlNodeDumpOutput(buf, doc, cur, encoding) });
    let fresh8 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh8 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseCharRef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlParseCharRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlParseCharRef(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseChunk(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Os#ii:htmlParseChunk\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut chunk as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut terminate as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlParseChunk(ctxt, chunk, size, terminate) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:htmlParseDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlParseDoc(cur, encoding) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseDocument(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlParseDocument\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { htmlParseDocument(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:htmlParseElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { htmlParseElement(ctxt) });
    let fresh9 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh9 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_htmlParseFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:htmlParseFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlParseFile(filename, encoding) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlReadDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzzi:htmlReadDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlReadDoc(cur, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlReadFd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"izzi:htmlReadFd\0" as *const u8 as *const i8 as *mut i8,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlReadFd(fd, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlReadFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: htmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:htmlReadFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlReadFile(filename, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlReadMemory(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#izzi:htmlReadMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { htmlReadMemory(buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlSaveFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:htmlSaveFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { htmlSaveFile(filename, cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlSaveFileEnc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zOz:htmlSaveFileEnc\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { htmlSaveFileEnc(filename, cur, encoding) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlSaveFileFormat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zOzi:htmlSaveFileFormat\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { htmlSaveFileFormat(filename, cur, encoding, format) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_htmlSetMetaEncoding(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:htmlSetMetaEncoding\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut encoding as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as htmlDocPtr;
    c_retval = unsafe { htmlSetMetaEncoding(doc, encoding) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_namePop(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:namePop\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { namePop(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_namePush(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:namePush\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { namePush(ctxt, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_nodePop(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:nodePop\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { nodePop(ctxt) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_nodePush(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_value: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:nodePush\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_value as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    value = if pyobj_value == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_value as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { nodePush(ctxt, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_valuePop(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:valuePop\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { valuePop(ctxt) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogAdd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzz:xmlACatalogAdd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut type_0 as *mut *mut xmlChar,
            &mut orig as *mut *mut xmlChar,
            &mut replace as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogAdd(catal, type_0, orig, replace) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlACatalogDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut pyobj_out as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_out).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_out) }
    } else {
        unsafe { stdout }
    };
    (unsafe { xmlACatalogDump(catal, out) });
    let fresh10 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh10 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogRemove(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlACatalogRemove\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogRemove(catal, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogResolve(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlACatalogResolve\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut pubID as *mut *mut xmlChar,
            &mut sysID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogResolve(catal, pubID, sysID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogResolvePublic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlACatalogResolvePublic\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut pubID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogResolvePublic(catal, pubID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogResolveSystem(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlACatalogResolveSystem\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut sysID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogResolveSystem(catal, sysID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlACatalogResolveURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlACatalogResolveURI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
            &mut URI as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlACatalogResolveURI(catal, URI) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddChild(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlAddChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlAddChild(parent, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddChildList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlAddChildList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlAddChildList(parent, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddDocEntity(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozizzz:xmlAddDocEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut type_0 as *mut i32,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlAddDocEntity(doc, name, type_0, ExternalID, SystemID, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddDtdEntity(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozizzz:xmlAddDtdEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut type_0 as *mut i32,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlAddDtdEntity(doc, name, type_0, ExternalID, SystemID, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddEncodingAlias(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut i8 = 0 as *mut i8;
    let mut alias: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlAddEncodingAlias\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut i8,
            &mut alias as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlAddEncodingAlias(name, alias) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddNextSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlAddNextSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlAddNextSibling(cur, elem) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddPrevSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlAddPrevSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlAddPrevSibling(cur, elem) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlAddSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlAddSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlAddSibling(cur, elem) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlBoolToText(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut boolval: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlBoolToText\0" as *const u8 as *const i8 as *mut i8,
            &mut boolval as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlBoolToText(boolval) };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlBuildQName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ncname: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut memory: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzzi:xmlBuildQName\0" as *const u8 as *const i8 as *mut i8,
            &mut ncname as *mut *mut xmlChar,
            &mut prefix as *mut *mut xmlChar,
            &mut memory as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlBuildQName(ncname, prefix, memory, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlBuildRelativeURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlBuildRelativeURI\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut xmlChar,
            &mut base as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlBuildRelativeURI(URI, base) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlBuildURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlBuildURI\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut xmlChar,
            &mut base as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlBuildURI(URI, base) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlByteConsumed(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlByteConsumed\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlByteConsumed(ctxt) };
    py_retval = unsafe { libxml_longWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCanonicPath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCanonicPath\0" as *const u8 as *const i8 as *mut i8,
            &mut path as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCanonicPath(path) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogAdd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzz:xmlCatalogAdd\0" as *const u8 as *const i8 as *mut i8,
            &mut type_0 as *mut *mut xmlChar,
            &mut orig as *mut *mut xmlChar,
            &mut replace as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogAdd(type_0, orig, replace) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogCleanup(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlCatalogCleanup() });
    let fresh11 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh11 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogConvert(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = unsafe { xmlCatalogConvert() };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCatalogDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_out).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_out).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_out) }
    } else {
        unsafe { stdout }
    };
    (unsafe { xmlCatalogDump(out) });
    let fresh12 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh12 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogGetPublic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogGetPublic\0" as *const u8 as *const i8 as *mut i8,
            &mut pubID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogGetPublic(pubID) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogGetSystem(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogGetSystem\0" as *const u8 as *const i8 as *mut i8,
            &mut sysID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogGetSystem(sysID) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogIsEmpty(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCatalogIsEmpty\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlCatalogIsEmpty(catal) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogRemove(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogRemove\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogRemove(value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogResolve(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlCatalogResolve\0" as *const u8 as *const i8 as *mut i8,
            &mut pubID as *mut *mut xmlChar,
            &mut sysID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogResolve(pubID, sysID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogResolvePublic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut pubID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogResolvePublic\0" as *const u8 as *const i8 as *mut i8,
            &mut pubID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogResolvePublic(pubID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogResolveSystem(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut sysID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogResolveSystem\0" as *const u8 as *const i8 as *mut i8,
            &mut sysID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogResolveSystem(sysID) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogResolveURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut URI: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCatalogResolveURI\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogResolveURI(URI) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCatalogSetDebug(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut level: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlCatalogSetDebug\0" as *const u8 as *const i8 as *mut i8,
            &mut level as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCatalogSetDebug(level) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCharStrdup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCharStrdup\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCharStrdup(cur) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCharStrndup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlCharStrndup\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut i8,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCharStrndup(cur, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCheckFilename(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut path: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCheckFilename\0" as *const u8 as *const i8 as *mut i8,
            &mut path as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCheckFilename(path) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCheckLanguageID(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCheckLanguageID\0" as *const u8 as *const i8 as *mut i8,
            &mut lang as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCheckLanguageID(lang) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCheckUTF8(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut u8 = 0 as *mut u8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCheckUTF8\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut u8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCheckUTF8(utf) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCheckVersion(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut version: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlCheckVersion\0" as *const u8 as *const i8 as *mut i8,
            &mut version as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlCheckVersion(version) });
    let fresh13 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh13 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupCharEncodingHandlers(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe {
        libxml_deprecationWarning(b"xmlCleanupCharEncodingHandlers\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlCleanupCharEncodingHandlers() });
    let fresh14 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh14 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupEncodingAliases(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlCleanupEncodingAliases() });
    let fresh15 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh15 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupGlobals(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlCleanupGlobals\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlCleanupGlobals() });
    let fresh16 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh16 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupInputCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlCleanupInputCallbacks() });
    let fresh17 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh17 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupOutputCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlCleanupOutputCallbacks() });
    let fresh18 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh18 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCleanupPredefinedEntities(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlCleanupPredefinedEntities() });
    let fresh19 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh19 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlClearParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlClearParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlClearParserCtxt(ctxt) });
    let fresh20 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh20 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlConvertSGMLCatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlConvertSGMLCatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    c_retval = unsafe { xmlConvertSGMLCatalog(catal) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut len: i32 = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"izi:xmlCopyChar\0" as *const u8 as *const i8 as *mut i8,
            &mut len as *mut i32,
            &mut out as *mut *mut xmlChar,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCopyChar(len, out, val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyCharMultiByte(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlCopyCharMultiByte\0" as *const u8 as *const i8 as *mut i8,
            &mut out as *mut *mut xmlChar,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCopyCharMultiByte(out, val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut recursive: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlCopyDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut recursive as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlCopyDoc(doc, recursive) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyDtd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCopyDtd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_dtd as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlCopyDtd(dtd) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyError(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut from: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_from: *mut PyObject = 0 as *mut PyObject;
    let mut to: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_to: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlCopyError\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_from as *mut *mut PyObject,
            &mut pyobj_to as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    from = if pyobj_from == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_from as *mut PyError_Object)).obj }
    };
    to = if pyobj_to == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_to as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { xmlCopyError(from, to) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyNamespace(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCopyNamespace\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlCopyNamespace(cur) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyNamespaceList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCopyNamespaceList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlCopyNamespaceList(cur) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut extended: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlCopyNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut extended as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlCopyNode(node, extended) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCopyNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlCopyNodeList(node) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut target: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_target: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlCopyProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_target as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    target = if pyobj_target == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_target as *mut PyxmlNode_Object)).obj }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlCopyProp(target, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCopyPropList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut target: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_target: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlCopyPropList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_target as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    target = if pyobj_target == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_target as *mut PyxmlNode_Object)).obj }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlCopyPropList(target, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateDocParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCreateDocParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCreateDocParserCtxt(cur) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateEntityParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut URL: *mut xmlChar = 0 as *mut xmlChar;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    let mut base: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzz:xmlCreateEntityParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut URL as *mut *mut xmlChar,
            &mut ID as *mut *mut xmlChar,
            &mut base as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCreateEntityParserCtxt(URL, ID, base) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateFileParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlCreateFileParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCreateFileParserCtxt(filename) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateIntSubset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzz:xmlCreateIntSubset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlCreateIntSubset(doc, name, ExternalID, SystemID) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateMemoryParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#i:xmlCreateMemoryParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCreateMemoryParserCtxt(buffer, size) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateURI(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    c_retval = unsafe { xmlCreateURI() };
    py_retval = unsafe { libxml_xmlURIPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCreateURLParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlCreateURLParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlCreateURLParserCtxt(filename, options) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtReadDoc(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzzi:xmlCtxtReadDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtReadDoc(ctxt, cur, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtReadFd(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oizzi:xmlCtxtReadFd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtReadFd(ctxt, fd, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtReadFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzi:xmlCtxtReadFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtReadFile(ctxt, filename, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtReadMemory(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Os#izzi:xmlCtxtReadMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtReadMemory(ctxt, buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtReset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlCtxtReset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlCtxtReset(ctxt) });
    let fresh21 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh21 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtResetPush(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Os#izz:xmlCtxtResetPush\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut chunk as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtResetPush(ctxt, chunk, size, filename, encoding) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlCtxtUseOptions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlCtxtUseOptions\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlCtxtUseOptions(ctxt, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugCheckDocument(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDebugCheckDocument\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlDebugCheckDocument(output, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpAttr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDebugDumpAttr\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
            &mut depth as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    (unsafe { xmlDebugDumpAttr(output, attr, depth) });
    let fresh22 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh22 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpAttrList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDebugDumpAttrList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
            &mut depth as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    (unsafe { xmlDebugDumpAttrList(output, attr, depth) });
    let fresh23 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh23 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpDTD(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDebugDumpDTD\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_dtd as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    (unsafe { xmlDebugDumpDTD(output, dtd) });
    let fresh24 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh24 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpDocument(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDebugDumpDocument\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlDebugDumpDocument(output, doc) });
    let fresh25 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh25 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpDocumentHead(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDebugDumpDocumentHead\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlDebugDumpDocumentHead(output, doc) });
    let fresh26 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh26 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpEntities(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDebugDumpEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlDebugDumpEntities(output, doc) });
    let fresh27 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh27 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDebugDumpNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
            &mut depth as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlDebugDumpNode(output, node, depth) });
    let fresh28 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh28 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDebugDumpNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
            &mut depth as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlDebugDumpNodeList(output, node, depth) });
    let fresh29 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh29 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpOneNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut depth: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDebugDumpOneNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
            &mut depth as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlDebugDumpOneNode(output, node, depth) });
    let fresh30 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh30 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDebugDumpString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlDebugDumpString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    (unsafe { xmlDebugDumpString(output, str) });
    let fresh31 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh31 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDecodeEntities(
    mut _self_0: *mut PyObject,
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
    if (unsafe { libxml_deprecationWarning(b"xmlDecodeEntities\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oiiccc:xmlDecodeEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut len as *mut i32,
            &mut what as *mut i32,
            &mut end as *mut xmlChar,
            &mut end2 as *mut xmlChar,
            &mut end3 as *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlDecodeEntities(ctxt, len, what, end, end2, end3) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDefaultSAXHandlerInit(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe {
        libxml_deprecationWarning(b"xmlDefaultSAXHandlerInit\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlDefaultSAXHandlerInit() });
    let fresh32 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh32 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDelEncodingAlias(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut alias: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlDelEncodingAlias\0" as *const u8 as *const i8 as *mut i8,
            &mut alias as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlDelEncodingAlias(alias) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDictCleanup(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlDictCleanup\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlDictCleanup() });
    let fresh33 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh33 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocCopyNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut extended: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDocCopyNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut extended as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlDocCopyNode(node, doc, extended) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocCopyNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDocCopyNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlDocCopyNodeList(doc, node) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDocDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_f as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_f).ob_type }) == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_f) }
    } else {
        unsafe { stdout }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlDocDump(f, cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocFormatDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlDocFormatDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_f as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_f).ob_type }) == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_f) }
    } else {
        unsafe { stdout }
    };
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlDocFormatDump(f, cur, format) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocGetRootElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlDocGetRootElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlDocGetRootElement(doc) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlDocSetRootElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut root: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_root: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlDocSetRootElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_root as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    root = if pyobj_root == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_root as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlDocSetRootElement(doc, root) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlElemDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlElemDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_f as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    f = if pyobj_f == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_f).ob_type }) == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_f).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_f) }
    } else {
        unsafe { stdout }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlElemDump(f, doc, cur) });
    let fresh34 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh34 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlEncodeEntities(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { libxml_deprecationWarning(b"xmlEncodeEntities\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlEncodeEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut input as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlEncodeEntities(doc, input) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlEncodeEntitiesReentrant(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlEncodeEntitiesReentrant\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut input as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlEncodeEntitiesReentrant(doc, input) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlEncodeSpecialChars(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut input: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlEncodeSpecialChars\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut input as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlEncodeSpecialChars(doc, input) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetCode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetCode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { (*Error).code };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetDomain(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetDomain\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { (*Error).domain };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { (*Error).file };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetLevel(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetLevel\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = (unsafe { (*Error).level }) as i32;
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetLine(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetLine\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { (*Error).line };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlErrorGetMessage(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlErrorGetMessage\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_Error as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    Error = if pyobj_Error == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_Error as *mut PyError_Object)).obj }
    };
    c_retval = unsafe { (*Error).message };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlFileMatch(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlFileMatch\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlFileMatch(filename) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlFirstElementChild(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFirstElementChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlFirstElementChild(parent) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeCatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeCatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_catal as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    catal = if pyobj_catal == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlCatalogPtr
    } else {
        unsafe { (*(pyobj_catal as *mut Pycatalog_Object)).obj }
    };
    (unsafe { xmlFreeCatalog(catal) });
    let fresh35 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh35 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlFreeDoc(cur) });
    let fresh36 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh36 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeDtd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeDtd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    (unsafe { xmlFreeDtd(cur) });
    let fresh37 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh37 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlFreeNode(cur) });
    let fresh38 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh38 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlFreeNodeList(cur) });
    let fresh39 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh39 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    (unsafe { xmlFreeNs(cur) });
    let fresh40 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh40 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeNsList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeNsList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    (unsafe { xmlFreeNsList(cur) });
    let fresh41 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh41 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeParserInputBuffer(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeParserInputBuffer\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_in as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_in as *mut PyinputBuffer_Object)).obj }
    };
    (unsafe { xmlFreeParserInputBuffer(in_0) });
    let fresh42 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh42 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    (unsafe { xmlFreeProp(cur) });
    let fresh43 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh43 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreePropList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreePropList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    (unsafe { xmlFreePropList(cur) });
    let fresh44 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh44 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlFreeURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlFreeURI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_uri as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_uri as *mut PyURI_Object)).obj }
    };
    (unsafe { xmlFreeURI(uri) });
    let fresh45 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh45 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetCompressMode(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = unsafe { xmlGetCompressMode() };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDocCompressMode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlGetDocCompressMode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlGetDocCompressMode(doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDocEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetDocEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlGetDocEntity(doc, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDtdAttrDesc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut elem: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlGetDtdAttrDesc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_dtd as *mut *mut PyObject,
            &mut elem as *mut *mut xmlChar,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlGetDtdAttrDesc(dtd, elem, name) };
    py_retval = unsafe { libxml_xmlAttributePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDtdElementDesc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlElementPtr = 0 as *mut xmlElement;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetDtdElementDesc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_dtd as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlGetDtdElementDesc(dtd, name) };
    py_retval = unsafe { libxml_xmlElementPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDtdEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetDtdEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlGetDtdEntity(doc, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDtdQAttrDesc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttributePtr = 0 as *mut xmlAttribute;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut elem: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzz:xmlGetDtdQAttrDesc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_dtd as *mut *mut PyObject,
            &mut elem as *mut *mut xmlChar,
            &mut name as *mut *mut xmlChar,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlGetDtdQAttrDesc(dtd, elem, name, prefix) };
    py_retval = unsafe { libxml_xmlAttributePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetDtdQElementDesc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlElementPtr = 0 as *mut xmlElement;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlGetDtdQElementDesc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_dtd as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlGetDtdQElementDesc(dtd, name, prefix) };
    py_retval = unsafe { libxml_xmlElementPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetEncodingAlias(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut alias: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlGetEncodingAlias\0" as *const u8 as *const i8 as *mut i8,
            &mut alias as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlGetEncodingAlias(alias) };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetID(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut ID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetID\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut ID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlGetID(doc, ID) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetIntSubset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlGetIntSubset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlGetIntSubset(doc) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetLastChild(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlGetLastChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetLastChild(parent) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetLastError(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlErrorPtr = 0 as *mut xmlError;
    c_retval = unsafe { xmlGetLastError() };
    py_retval = unsafe { libxml_xmlErrorPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetLineNo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlGetLineNo\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetLineNo(node) };
    py_retval = unsafe { libxml_longWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetNoNsProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetNoNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetNoNsProp(node, name) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetNodePath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlGetNodePath\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetNodePath(node) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetNsProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlGetNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut nameSpace as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetNsProp(node, name, nameSpace) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetParameterEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetParameterEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlGetParameterEntity(doc, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetPredefinedEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlGetPredefinedEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlGetPredefinedEntity(name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlGetProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlGetProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlGetProp(node, name) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlHandleEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut entity: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut pyobj_entity: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlHandleEntity\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlHandleEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_entity as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    entity = (if pyobj_entity == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_entity as *mut PyxmlNode_Object)).obj }
    }) as xmlEntityPtr;
    (unsafe { xmlHandleEntity(ctxt, entity) });
    let fresh46 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh46 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlHasNsProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlHasNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut nameSpace as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlHasNsProp(node, name, nameSpace) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlHasProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlHasProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlHasProp(node, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIOFTPMatch(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlIOFTPMatch\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIOFTPMatch(filename) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIOHTTPMatch(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlIOHTTPMatch\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIOHTTPMatch(filename) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitCharEncodingHandlers(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe {
        libxml_deprecationWarning(b"xmlInitCharEncodingHandlers\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlInitCharEncodingHandlers() });
    let fresh47 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh47 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitGlobals(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlInitGlobals\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlInitGlobals() });
    let fresh48 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh48 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitParser(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlInitParser() });
    let fresh49 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh49 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlInitParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlInitParserCtxt(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitializeCatalog(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlInitializeCatalog() });
    let fresh50 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh50 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitializeDict(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    if (unsafe { libxml_deprecationWarning(b"xmlInitializeDict\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlInitializeDict() };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlInitializePredefinedEntities(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe {
        libxml_deprecationWarning(b"xmlInitializePredefinedEntities\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlInitializePredefinedEntities() });
    let fresh51 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh51 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsBaseChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsBaseChar\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsBaseChar(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsBlank(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsBlank\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsBlank(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsBlankNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlIsBlankNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlIsBlankNode(node) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsChar\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsChar(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsCombining(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsCombining\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsCombining(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsDigit(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsDigit\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsDigit(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsExtender(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsExtender\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsExtender(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsID(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlIsID\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlIsID(doc, elem, attr) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsIdeographic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsIdeographic\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsIdeographic(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsLetter(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut c: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsLetter\0" as *const u8 as *const i8 as *mut i8,
            &mut c as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsLetter(c) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsMixedElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlIsMixedElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlIsMixedElement(doc, name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsPubidChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ch: u32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlIsPubidChar\0" as *const u8 as *const i8 as *mut i8,
            &mut ch as *mut u32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsPubidChar(ch) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsRef(
    mut _self_0: *mut PyObject,
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
    if (unsafe { libxml_deprecationWarning(b"xmlIsRef\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlIsRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlIsRef(doc, elem, attr) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlIsXHTML(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut systemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut publicID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlIsXHTML\0" as *const u8 as *const i8 as *mut i8,
            &mut systemID as *mut *mut xmlChar,
            &mut publicID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlIsXHTML(systemID, publicID) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlKeepBlanksDefault(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlKeepBlanksDefault\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlKeepBlanksDefault(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLastElementChild(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut parent: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_parent: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlLastElementChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlLastElementChild(parent) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLineNumbersDefault(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlLineNumbersDefault\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlLineNumbersDefault(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLoadACatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlLoadACatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlLoadACatalog(filename) };
    py_retval = unsafe { libxml_xmlCatalogPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLoadCatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlLoadCatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlLoadCatalog(filename) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLoadCatalogs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut pathss: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlLoadCatalogs\0" as *const u8 as *const i8 as *mut i8,
            &mut pathss as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlLoadCatalogs(pathss) });
    let fresh52 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh52 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlLoadSGMLSuperCatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlLoadSGMLSuperCatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlLoadSGMLSuperCatalog(filename) };
    py_retval = unsafe { libxml_xmlCatalogPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLsCountNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlLsCountNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlLsCountNode(node) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlLsOneNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlLsOneNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlLsOneNode(output, node) });
    let fresh53 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh53 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNamespaceParseNCName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        libxml_deprecationWarning(b"xmlNamespaceParseNCName\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNamespaceParseNCName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlNamespaceParseNCName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNamespaceParseNSDef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlNamespaceParseNSDef\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNamespaceParseNSDef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlNamespaceParseNSDef(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoFTPCleanup(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlNanoFTPCleanup\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlNanoFTPCleanup() });
    let fresh54 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh54 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoFTPInit(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlNanoFTPInit\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlNanoFTPInit() });
    let fresh55 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh55 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoFTPProxy(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut host: *mut i8 = 0 as *mut i8;
    let mut port: i32 = 0;
    let mut user: *mut i8 = 0 as *mut i8;
    let mut passwd: *mut i8 = 0 as *mut i8;
    let mut type_0: i32 = 0;
    if (unsafe { libxml_deprecationWarning(b"xmlNanoFTPProxy\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zizzi:xmlNanoFTPProxy\0" as *const u8 as *const i8 as *mut i8,
            &mut host as *mut *mut i8,
            &mut port as *mut i32,
            &mut user as *mut *mut i8,
            &mut passwd as *mut *mut i8,
            &mut type_0 as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlNanoFTPProxy(host, port, user, passwd, type_0) });
    let fresh56 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh56 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoFTPScanProxy(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut i8 = 0 as *mut i8;
    if (unsafe { libxml_deprecationWarning(b"xmlNanoFTPScanProxy\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNanoFTPScanProxy\0" as *const u8 as *const i8 as *mut i8,
            &mut URL as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlNanoFTPScanProxy(URL) });
    let fresh57 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh57 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoHTTPCleanup(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlNanoHTTPCleanup() });
    let fresh58 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh58 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoHTTPInit(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlNanoHTTPInit() });
    let fresh59 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh59 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNanoHTTPScanProxy(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNanoHTTPScanProxy\0" as *const u8 as *const i8 as *mut i8,
            &mut URL as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlNanoHTTPScanProxy(URL) });
    let fresh60 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh60 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewCDataBlock(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlNewCDataBlock\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewCDataBlock(doc, content, len) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewCatalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut sgml: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlNewCatalog\0" as *const u8 as *const i8 as *mut i8,
            &mut sgml as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewCatalog(sgml) };
    py_retval = unsafe { libxml_xmlCatalogPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewCharRef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewCharRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewCharRef(doc, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewChild(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewChild(parent, ns, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewComment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNewComment\0" as *const u8 as *const i8 as *mut i8,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewComment(content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut version: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNewDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut version as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewDoc(version) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocComment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewDocComment\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDocComment(doc, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocFragment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNewDocFragment\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDocFragment(doc) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocNode(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewDocNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewDocNode(doc, ns, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocNodeEatName(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewDocNodeEatName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewDocNodeEatName(doc, ns, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocPI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlNewDocPI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDocPI(doc, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlNewDocProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDocProp(doc, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocRawNode(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewDocRawNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewDocRawNode(doc, ns, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocText(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewDocText\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlNewDocText(doc, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDocTextLen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlNewDocTextLen\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDocTextLen(doc, content, len) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewDtd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzz:xmlNewDtd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewDtd(doc, name, ExternalID, SystemID) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewEntity(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozizzz:xmlNewEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut type_0 as *mut i32,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewEntity(doc, name, type_0, ExternalID, SystemID, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewGlobalNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe { libxml_deprecationWarning(b"xmlNewGlobalNs\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlNewGlobalNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut href as *mut *mut xmlChar,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlNewGlobalNs(doc, href, prefix) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewNodeEatName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewNodeEatName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewNodeEatName(ns, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlNewNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut href as *mut *mut xmlChar,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNewNs(node, href, prefix) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewNsProp(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewNsProp(node, ns, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewNsPropEatName(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewNsPropEatName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewNsPropEatName(node, ns, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewPI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlNewPI\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewPI(name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewParserCtxt(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    c_retval = unsafe { xmlNewParserCtxt() };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlNewProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNewProp(node, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlNewReference(doc, name) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewText(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNewText\0" as *const u8 as *const i8 as *mut i8,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewText(content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewTextChild(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlNewTextChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_parent as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    parent = if pyobj_parent == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_parent as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlNewTextChild(parent, ns, name, content) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewTextLen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlNewTextLen\0" as *const u8 as *const i8 as *mut i8,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewTextLen(content, len) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewTextReader(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_input: *mut PyObject = 0 as *mut PyObject;
    let mut URI: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNewTextReader\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_input as *mut *mut PyObject,
            &mut URI as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    input = if pyobj_input == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_input as *mut PyinputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlNewTextReader(input, URI) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewTextReaderFilename(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut URI: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNewTextReaderFilename\0" as *const u8 as *const i8 as *mut i8,
            &mut URI as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNewTextReaderFilename(URI) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNewValidCtxt(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    c_retval = unsafe { xmlNewValidCtxt() };
    py_retval = unsafe { libxml_xmlValidCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNextChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNextChar\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlNextChar(ctxt) });
    let fresh61 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh61 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNextElementSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNextElementSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNextElementSibling(node) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeAddContent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNodeAddContent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeAddContent(cur, content) });
    let fresh62 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh62 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeAddContentLen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlNodeAddContentLen\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeAddContentLen(cur, content, len) });
    let fresh63 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh63 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeDumpOutput(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOiiz:xmlNodeDumpOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_buf as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut level as *mut i32,
            &mut format as *mut i32,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    buf = if pyobj_buf == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_buf as *mut PyoutputBuffer_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeDumpOutput(buf, doc, cur, level, format, encoding) });
    let fresh64 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh64 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeGetBase(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlNodeGetBase\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeGetBase(doc, cur) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeGetContent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNodeGetContent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeGetContent(cur) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeGetLang(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNodeGetLang\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeGetLang(cur) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeGetSpacePreserve(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNodeGetSpacePreserve\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeGetSpacePreserve(cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeIsText(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlNodeIsText\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeIsText(node) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeListGetRawString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut list: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut inLine: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlNodeListGetRawString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_list as *mut *mut PyObject,
            &mut inLine as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    list = if pyobj_list == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_list as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeListGetRawString(doc, list, inLine) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeListGetString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut list: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut inLine: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlNodeListGetString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_list as *mut *mut PyObject,
            &mut inLine as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    list = if pyobj_list == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_list as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlNodeListGetString(doc, list, inLine) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetBase(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut uri: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNodeSetBase\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut uri as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetBase(cur, uri) });
    let fresh65 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh65 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetContent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNodeSetContent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetContent(cur, content) });
    let fresh66 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh66 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetContentLen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlNodeSetContentLen\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetContentLen(cur, content, len) });
    let fresh67 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh67 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetLang(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNodeSetLang\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut lang as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetLang(cur, lang) });
    let fresh68 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh68 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlNodeSetName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetName(cur, name) });
    let fresh69 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh69 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNodeSetSpacePreserve(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlNodeSetSpacePreserve\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlNodeSetSpacePreserve(cur, val) });
    let fresh70 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh70 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlNormalizeURIPath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut path: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNormalizeURIPath\0" as *const u8 as *const i8 as *mut i8,
            &mut path as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNormalizeURIPath(path) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlNormalizeWindowsPath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlNormalizeWindowsPath\0" as *const u8 as *const i8 as *mut i8,
            &mut path as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlNormalizeWindowsPath(path) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlOutputBufferGetContent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlOutputBufferGetContent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_out as *mut PyoutputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlOutputBufferGetContent(out) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlOutputBufferWrite(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    let mut buf: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oiz:xmlOutputBufferWrite\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
            &mut len as *mut i32,
            &mut buf as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_out as *mut PyoutputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlOutputBufferWrite(out, len, buf) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlOutputBufferWriteString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlOutputBufferWriteString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_out as *mut *mut PyObject,
            &mut str as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    out = if pyobj_out == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlOutputBufferPtr
    } else {
        unsafe { (*(pyobj_out as *mut PyoutputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlOutputBufferWriteString(out, str) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseAttValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseAttValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseAttValue(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseAttributeListDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseAttributeListDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseAttributeListDecl(ctxt) });
    let fresh71 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh71 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseCDSect(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseCDSect\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseCDSect(ctxt) });
    let fresh72 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh72 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseCatalogFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParseCatalogFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseCatalogFile(filename) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseCharData(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cdata: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParseCharData\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut cdata as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseCharData(ctxt, cdata) });
    let fresh73 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh73 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseCharRef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseCharRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseCharRef(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseChunk(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Os#ii:xmlParseChunk\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut chunk as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut terminate as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseChunk(ctxt, chunk, size, terminate) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseComment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseComment\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseComment(ctxt) });
    let fresh74 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh74 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseContent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseContent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseContent(ctxt) });
    let fresh75 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh75 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseDTD(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlParseDTD\0" as *const u8 as *const i8 as *mut i8,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseDTD(ExternalID, SystemID) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParseDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseDoc(cur) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseDocTypeDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseDocTypeDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseDocTypeDecl(ctxt) });
    let fresh76 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh76 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseDocument(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseDocument\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseDocument(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseElement(ctxt) });
    let fresh77 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh77 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseElementDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseElementDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseElementDecl(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEncName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseEncName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseEncName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEncodingDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseEncodingDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseEncodingDecl(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEndTag(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseEndTag\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseEndTag(ctxt) });
    let fresh78 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh78 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEntity(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParseEntity\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseEntity(filename) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEntityDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseEntityDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseEntityDecl(ctxt) });
    let fresh79 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh79 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseEntityRef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlEntityPtr = 0 as *mut xmlEntity;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseEntityRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseEntityRef(ctxt) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseExtParsedEnt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseExtParsedEnt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseExtParsedEnt(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseExternalSubset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlParseExternalSubset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut ExternalID as *mut *mut xmlChar,
            &mut SystemID as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseExternalSubset(ctxt, ExternalID, SystemID) });
    let fresh80 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh80 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParseFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseFile(filename) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseMarkupDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseMarkupDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseMarkupDecl(ctxt) });
    let fresh81 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh81 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseMemory(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#i:xmlParseMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseMemory(buffer, size) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseMisc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseMisc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseMisc(ctxt) });
    let fresh82 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh82 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseNamespace(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlParseNamespace\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseNamespace\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseNamespace(ctxt) });
    let fresh83 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh83 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseNmtoken(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseNmtoken\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseNmtoken(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseNotationDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseNotationDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseNotationDecl(ctxt) });
    let fresh84 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh84 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParsePEReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParsePEReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParsePEReference(ctxt) });
    let fresh85 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh85 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParsePI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParsePI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParsePI(ctxt) });
    let fresh86 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh86 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParsePITarget(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParsePITarget\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParsePITarget(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParsePubidLiteral(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParsePubidLiteral\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParsePubidLiteral(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseQuotedString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlParseQuotedString\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseQuotedString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseQuotedString(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseReference(ctxt) });
    let fresh87 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh87 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseSDDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseSDDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseSDDecl(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseStartTag(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseStartTag\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseStartTag(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseSystemLiteral(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseSystemLiteral\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseSystemLiteral(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseTextDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseTextDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseTextDecl(ctxt) });
    let fresh88 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh88 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    let mut str: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParseURI\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseURI(str) };
    py_retval = unsafe { libxml_xmlURIPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseURIRaw(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlURIPtr = 0 as *mut xmlURI;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut raw: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlParseURIRaw\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut i8,
            &mut raw as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParseURIRaw(str, raw) };
    py_retval = unsafe { libxml_xmlURIPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseURIReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlParseURIReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_uri as *mut *mut PyObject,
            &mut str as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_uri as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { xmlParseURIReference(uri, str) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseVersionInfo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseVersionInfo\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseVersionInfo(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseVersionNum(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseVersionNum\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlParseVersionNum(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParseXMLDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParseXMLDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParseXMLDecl(ctxt) });
    let fresh89 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh89 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserGetDirectory(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut i8 = 0 as *mut i8;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlParserGetDirectory\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlParserGetDirectory(filename) };
    py_retval = unsafe { libxml_charPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserGetDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParserGetDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).myDoc };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserGetIsValid(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParserGetIsValid\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).valid };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserGetWellFormed(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParserGetWellFormed\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).wellFormed };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserHandlePEReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParserHandlePEReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParserHandlePEReference(ctxt) });
    let fresh90 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh90 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserHandleReference(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        libxml_deprecationWarning(b"xmlParserHandleReference\0" as *const u8 as *const i8)
    }) == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlParserHandleReference\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlParserHandleReference(ctxt) });
    let fresh91 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh91 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserInputBufferGrow(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserInputBufferGrow\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_in as *mut *mut PyObject,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_in as *mut PyinputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlParserInputBufferGrow(in_0, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserInputBufferPush(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    let mut buf: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oiz:xmlParserInputBufferPush\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_in as *mut *mut PyObject,
            &mut len as *mut i32,
            &mut buf as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_in as *mut PyinputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlParserInputBufferPush(in_0, len, buf) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserInputBufferRead(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserInputBufferRead\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_in as *mut *mut PyObject,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    in_0 = if pyobj_in == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_in as *mut PyinputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlParserInputBufferRead(in_0, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserSetLineNumbers(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut linenumbers: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserSetLineNumbers\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut linenumbers as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { (*ctxt).linenumbers = linenumbers });
    let fresh92 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh92 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserSetLoadSubset(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut loadsubset: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserSetLoadSubset\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut loadsubset as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { (*ctxt).loadsubset = loadsubset });
    let fresh93 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh93 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserSetPedantic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut pedantic: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserSetPedantic\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pedantic as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { (*ctxt).pedantic = pedantic });
    let fresh94 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh94 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserSetReplaceEntities(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut replaceEntities: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserSetReplaceEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut replaceEntities as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { (*ctxt).replaceEntities = replaceEntities });
    let fresh95 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh95 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlParserSetValidate(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut validate: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlParserSetValidate\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut validate as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { (*ctxt).validate = validate });
    let fresh96 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh96 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlPathToURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut path: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlPathToURI\0" as *const u8 as *const i8 as *mut i8,
            &mut path as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlPathToURI(path) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlPedanticParserDefault(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlPedanticParserDefault\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlPedanticParserDefault(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlPopInput(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlChar = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlPopInput\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlPopInput(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval as i32) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlPopOutputCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    c_retval = unsafe { xmlPopOutputCallbacks() };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlPreviousElementSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlPreviousElementSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlPreviousElementSibling(node) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlPrintURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut stream: *mut FILE = 0 as *mut FILE;
    let mut pyobj_stream: *mut PyObject = 0 as *mut PyObject;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlPrintURI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_stream as *mut *mut PyObject,
            &mut pyobj_uri as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    stream = if pyobj_stream == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_stream).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_stream).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_stream) }
    } else {
        unsafe { stdout }
    };
    uri = if pyobj_uri == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_uri as *mut PyURI_Object)).obj }
    };
    (unsafe { xmlPrintURI(stream, uri) });
    let fresh97 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh97 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlReadDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzzi:xmlReadDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReadDoc(cur, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReadFd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"izzi:xmlReadFd\0" as *const u8 as *const i8 as *mut i8,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReadFd(fd, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReadFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlReadFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReadFile(filename, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReadMemory(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#izzi:xmlReadMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReadMemory(buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderForDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzzi:xmlReaderForDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReaderForDoc(cur, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderForFd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut fd: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"izzi:xmlReaderForFd\0" as *const u8 as *const i8 as *mut i8,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReaderForFd(fd, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderForFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlReaderForFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReaderForFile(filename, encoding, options) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderForMemory(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    let mut URL: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zizzi:xmlReaderForMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlReaderForMemory(buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderNewDoc(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzzi:xmlReaderNewDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut cur as *mut *mut xmlChar,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlReaderNewDoc(reader, cur, URL, encoding, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderNewFd(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oizzi:xmlReaderNewFd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut fd as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlReaderNewFd(reader, fd, URL, encoding, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderNewFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozzi:xmlReaderNewFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut filename as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlReaderNewFile(reader, filename, encoding, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderNewMemory(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozizzi:xmlReaderNewMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut buffer as *mut *mut i8,
            &mut size as *mut i32,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlReaderNewMemory(reader, buffer, size, URL, encoding, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderNewWalker(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlReaderNewWalker\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlReaderNewWalker(reader, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReaderWalker(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlReaderWalker\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlReaderWalker(doc) };
    py_retval = unsafe { libxml_xmlTextReaderPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReconciliateNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlReconciliateNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_tree as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    tree = if pyobj_tree == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_tree as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlReconciliateNs(doc, tree) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRecoverDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlRecoverDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRecoverDoc(cur) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRecoverFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlRecoverFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRecoverFile(filename) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRecoverMemory(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"s#i:xmlRecoverMemory\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut py_buffsize0 as *mut Py_ssize_t,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRecoverMemory(buffer, size) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegFreeRegexp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut regexp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_regexp: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRegFreeRegexp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_regexp as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    regexp = if pyobj_regexp == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        unsafe { (*(pyobj_regexp as *mut PyxmlReg_Object)).obj }
    };
    (unsafe { xmlRegFreeRegexp(regexp) });
    let fresh98 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh98 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegexpCompile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut regexp: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlRegexpCompile\0" as *const u8 as *const i8 as *mut i8,
            &mut regexp as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRegexpCompile(regexp) };
    py_retval = unsafe { libxml_xmlRegexpPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegexpExec(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlRegexpExec\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_comp as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    comp = if pyobj_comp == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        unsafe { (*(pyobj_comp as *mut PyxmlReg_Object)).obj }
    };
    c_retval = unsafe { xmlRegexpExec(comp, content) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegexpIsDeterminist(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRegexpIsDeterminist\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_comp as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    comp = if pyobj_comp == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        unsafe { (*(pyobj_comp as *mut PyxmlReg_Object)).obj }
    };
    c_retval = unsafe { xmlRegexpIsDeterminist(comp) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegexpPrint(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut regexp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_regexp: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRegexpPrint\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_regexp as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    regexp = if pyobj_regexp == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRegexpPtr
    } else {
        unsafe { (*(pyobj_regexp as *mut PyxmlReg_Object)).obj }
    };
    (unsafe { xmlRegexpPrint(output, regexp) });
    let fresh99 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh99 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegisterDefaultInputCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlRegisterDefaultInputCallbacks() });
    let fresh100 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh100 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegisterDefaultOutputCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlRegisterDefaultOutputCallbacks() });
    let fresh101 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh101 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRegisterHTTPPostCallbacks(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlRegisterHTTPPostCallbacks() });
    let fresh102 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh102 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGCleanupTypes(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlRelaxNGCleanupTypes\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlRelaxNGCleanupTypes() });
    let fresh103 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh103 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRelaxNGDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj }
    };
    (unsafe { xmlRelaxNGDump(output, schema) });
    let fresh104 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh104 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGDumpTree(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRelaxNGDumpTree\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj }
    };
    (unsafe { xmlRelaxNGDumpTree(output, schema) });
    let fresh105 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh105 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGFree(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRelaxNGFree\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj }
    };
    (unsafe { xmlRelaxNGFree(schema) });
    let fresh106 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh106 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGFreeParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRelaxNGFreeParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj }
    };
    (unsafe { xmlRelaxNGFreeParserCtxt(ctxt) });
    let fresh107 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh107 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGInitTypes(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    if (unsafe { libxml_deprecationWarning(b"xmlRelaxNGInitTypes\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRelaxNGInitTypes() };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGNewDocParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRelaxNGNewDocParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlRelaxNGNewDocParserCtxt(doc) };
    py_retval = unsafe { libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGNewMemParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlRelaxNGNewMemParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRelaxNGNewMemParserCtxt(buffer, size) };
    py_retval = unsafe { libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGNewParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut URL: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlRelaxNGNewParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut URL as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlRelaxNGNewParserCtxt(URL) };
    py_retval = unsafe { libxml_xmlRelaxNGParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGNewValidCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRelaxNGNewValidCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGNewValidCtxt(schema) };
    py_retval = unsafe { libxml_xmlRelaxNGValidCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGParse(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRelaxNGParse\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGParse(ctxt) };
    py_retval = unsafe { libxml_xmlRelaxNGPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGValidateDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRelaxNGValidateDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlRelaxNGValidateDoc(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGValidateFullElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlRelaxNGValidateFullElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGValidateFullElement(ctxt, doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGValidatePopElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlRelaxNGValidatePopElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGValidatePopElement(ctxt, doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGValidatePushCData(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlRelaxNGValidatePushCData\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut data as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGValidatePushCData(ctxt, data, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxNGValidatePushElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlRelaxNGValidatePushElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxNGValidatePushElement(ctxt, doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRelaxParserSetFlag(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlRelaxParserSetFlag\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut flags as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgParserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlRelaxParserSetFlag(ctxt, flags) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRemoveID(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRemoveID\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlRemoveID(doc, attr) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRemoveProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlRemoveProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlRemoveProp(cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlRemoveRef(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlRemoveRef\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlRemoveRef\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlRemoveRef(doc, attr) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlReplaceNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut old: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_old: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlReplaceNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_old as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    old = if pyobj_old == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_old as *mut PyxmlNode_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlReplaceNode(old, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlResetError(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut err: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_err: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlResetError\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_err as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    err = if pyobj_err == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlErrorPtr
    } else {
        unsafe { (*(pyobj_err as *mut PyError_Object)).obj }
    };
    (unsafe { xmlResetError(err) });
    let fresh108 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh108 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlResetLastError(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    (unsafe { xmlResetLastError() });
    let fresh109 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh109 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSAXDefaultVersion(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut version: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlSAXDefaultVersion\0" as *const u8 as *const i8 as *mut i8,
            &mut version as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSAXDefaultVersion(version) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSaveFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:xmlSaveFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSaveFile(filename, cur) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSaveFileEnc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zOz:xmlSaveFileEnc\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSaveFileEnc(filename, cur, encoding) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSaveFormatFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zOi:xmlSaveFormatFile\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSaveFormatFile(filename, cur, format) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSaveFormatFileEnc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut i8 = 0 as *mut i8;
    let mut format: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zOzi:xmlSaveFormatFileEnc\0" as *const u8 as *const i8 as *mut i8,
            &mut filename as *mut *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
            &mut encoding as *mut *mut i8,
            &mut format as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = (if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSaveFormatFileEnc(filename, cur, encoding, format) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSaveUri(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSaveUri\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_uri as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    uri = if pyobj_uri == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_uri as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { xmlSaveUri(uri) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlScanName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe { libxml_deprecationWarning(b"xmlScanName\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlScanName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlScanName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaCleanupTypes(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlSchemaCleanupTypes\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlSchemaCleanupTypes() });
    let fresh110 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh110 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaCollapseString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlSchemaCollapseString\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSchemaCollapseString(value) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaDump(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSchemaDump\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_output as *mut *mut PyObject,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    output = if pyobj_output == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut FILE
    } else if (unsafe { (*pyobj_output).ob_type })
        == (unsafe { &mut PyFile_Type }) as *mut PyTypeObject
        || (unsafe { PyType_IsSubtype((*pyobj_output).ob_type, &mut PyFile_Type) }) != 0
    {
        unsafe { PyFile_AsFile(pyobj_output) }
    } else {
        unsafe { stdout }
    };
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PySchema_Object)).obj }
    };
    (unsafe { xmlSchemaDump(output, schema) });
    let fresh111 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh111 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaFree(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaFree\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PySchema_Object)).obj }
    };
    (unsafe { xmlSchemaFree(schema) });
    let fresh112 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh112 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaFreeParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaFreeParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaParserCtxt_Object)).obj }
    };
    (unsafe { xmlSchemaFreeParserCtxt(ctxt) });
    let fresh113 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh113 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaInitTypes(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlSchemaInitTypes\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlSchemaInitTypes() });
    let fresh114 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh114 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaIsValid(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaIsValid\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaIsValid(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaNewDocParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaNewDocParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSchemaNewDocParserCtxt(doc) };
    py_retval = unsafe { libxml_xmlSchemaParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaNewMemParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut buffer: *mut i8 = 0 as *mut i8;
    let mut size: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlSchemaNewMemParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut buffer as *mut *mut i8,
            &mut size as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSchemaNewMemParserCtxt(buffer, size) };
    py_retval = unsafe { libxml_xmlSchemaParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaNewParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut URL: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlSchemaNewParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut URL as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSchemaNewParserCtxt(URL) };
    py_retval = unsafe { libxml_xmlSchemaParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaNewValidCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaNewValidCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PySchema_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaNewValidCtxt(schema) };
    py_retval = unsafe { libxml_xmlSchemaValidCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaParse(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut ctxt: xmlSchemaParserCtxtPtr = 0 as *mut xmlSchemaParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaParse\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaParserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaParse(ctxt) };
    py_retval = unsafe { libxml_xmlSchemaPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaSetValidOptions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlSchemaSetValidOptions\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaSetValidOptions(ctxt, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidCtxtGetOptions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaValidCtxtGetOptions\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaValidCtxtGetOptions(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidCtxtGetParserCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSchemaValidCtxtGetParserCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaValidCtxtGetParserCtxt(ctxt) };
    py_retval = unsafe { libxml_xmlParserCtxtPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidateDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSchemaValidateDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlSchemaValidateDoc(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidateFile(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlSchemaValidateFile\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut filename as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaValidateFile(ctxt, filename, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidateOneElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSchemaValidateOneElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlSchemaValidateOneElement(ctxt, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaValidateSetFilename(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut vctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_vctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlSchemaValidateSetFilename\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_vctxt as *mut *mut PyObject,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    vctxt = if pyobj_vctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_vctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    (unsafe { xmlSchemaValidateSetFilename(vctxt, filename) });
    let fresh115 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh115 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSchemaWhiteSpaceReplace(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlSchemaWhiteSpaceReplace\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSchemaWhiteSpaceReplace(value) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSearchNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut nameSpace: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOz:xmlSearchNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
            &mut nameSpace as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlSearchNs(doc, node, nameSpace) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSearchNsByHref(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNsPtr = 0 as *mut xmlNs;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut href: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOz:xmlSearchNsByHref\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
            &mut href as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlSearchNsByHref(doc, node, href) };
    py_retval = unsafe { libxml_xmlNsPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetCompressMode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut mode: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlSetCompressMode\0" as *const u8 as *const i8 as *mut i8,
            &mut mode as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlSetCompressMode(mode) });
    let fresh116 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh116 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetDocCompressMode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut mode: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlSetDocCompressMode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut mode as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlSetDocCompressMode(doc, mode) });
    let fresh117 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh117 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetListDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut list: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_list: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSetListDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_list as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    list = if pyobj_list == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_list as *mut PyxmlNode_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlSetListDoc(list, doc) });
    let fresh118 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh118 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSetNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    (unsafe { xmlSetNs(node, ns) });
    let fresh119 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh119 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetNsProp(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlSetNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlSetNsProp(node, ns, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlSetProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlSetProp(node, name, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval as xmlNodePtr) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetTreeDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlSetTreeDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_tree as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_tree as *mut PyxmlNode_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    (unsafe { xmlSetTreeDoc(tree, doc) });
    let fresh120 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh120 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSetupParserForBuffer(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut xmlChar = 0 as *mut xmlChar;
    let mut filename: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlSetupParserForBuffer\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut buffer as *mut *mut xmlChar,
            &mut filename as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlSetupParserForBuffer(ctxt, buffer, filename) });
    let fresh121 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh121 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlShellPrintNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlShellPrintNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlShellPrintNode(node) });
    let fresh122 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh122 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlShellPrintXPathError(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut errorType: i32 = 0;
    let mut arg: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"iz:xmlShellPrintXPathError\0" as *const u8 as *const i8 as *mut i8,
            &mut errorType as *mut i32,
            &mut arg as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlShellPrintXPathError(errorType, arg) });
    let fresh123 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh123 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlSkipBlankChars(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlSkipBlankChars\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlSkipBlankChars(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStopParser(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlStopParser\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    (unsafe { xmlStopParser(ctxt) });
    let fresh124 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh124 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrEqual(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrEqual\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrEqual(str1, str2) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrQEqual(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut pref: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzz:xmlStrQEqual\0" as *const u8 as *const i8 as *mut i8,
            &mut pref as *mut *mut xmlChar,
            &mut name as *mut *mut xmlChar,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrQEqual(pref, name, str) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrcasecmp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrcasecmp\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrcasecmp(str1, str2) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrcasestr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrcasestr\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut val as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrcasestr(str, val) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrcat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut add: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrcat\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut add as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrcat(cur, add) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrchr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: xmlChar = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zc:xmlStrchr\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut val as *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrchr(str, val) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrcmp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrcmp\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrcmp(str1, str2) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrdup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlStrdup\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrdup(cur) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStringDecodeEntities(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oziccc:xmlStringDecodeEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut str as *mut *mut xmlChar,
            &mut what as *mut i32,
            &mut end as *mut xmlChar,
            &mut end2 as *mut xmlChar,
            &mut end3 as *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlStringDecodeEntities(ctxt, str, what, end, end2, end3) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStringGetNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlStringGetNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlStringGetNodeList(doc, value) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStringLenDecodeEntities(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oziiccc:xmlStringLenDecodeEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut str as *mut *mut xmlChar,
            &mut len as *mut i32,
            &mut what as *mut i32,
            &mut end as *mut xmlChar,
            &mut end2 as *mut xmlChar,
            &mut end3 as *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyparserCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlStringLenDecodeEntities(ctxt, str, len, what, end, end2, end3) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStringLenGetNodeList(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlStringLenGetNodeList\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as *mut xmlDoc;
    c_retval = unsafe { xmlStringLenGetNodeList(doc, value, len) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrlen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlStrlen\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrlen(str) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrncasecmp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlStrncasecmp\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrncasecmp(str1, str2, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrncat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut add: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlStrncat\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut add as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrncat(cur, add, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrncatNew(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlStrncatNew\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrncatNew(str1, str2, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrncmp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zzi:xmlStrncmp\0" as *const u8 as *const i8 as *mut i8,
            &mut str1 as *mut *mut xmlChar,
            &mut str2 as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrncmp(str1, str2, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrndup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlStrndup\0" as *const u8 as *const i8 as *mut i8,
            &mut cur as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrndup(cur, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrstr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlStrstr\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut val as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrstr(str, val) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlStrsub(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut start: i32 = 0;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zii:xmlStrsub\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut start as *mut i32,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlStrsub(str, start, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlSubstituteEntitiesDefault(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlSubstituteEntitiesDefault\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlSubstituteEntitiesDefault(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextConcat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlTextConcat\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut content as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlTextConcat(node, content, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextMerge(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut first: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_first: *mut PyObject = 0 as *mut PyObject;
    let mut second: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_second: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlTextMerge\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_first as *mut *mut PyObject,
            &mut pyobj_second as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    first = if pyobj_first == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_first as *mut PyxmlNode_Object)).obj }
    };
    second = if pyobj_second == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_second as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlTextMerge(first, second) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderAttributeCount(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderAttributeCount\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderAttributeCount(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderByteConsumed(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderByteConsumed\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderByteConsumed(reader) };
    py_retval = unsafe { libxml_longWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderClose(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderClose\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderClose(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstBaseUri(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstBaseUri\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstBaseUri(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstEncoding(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstEncoding\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstEncoding(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstLocalName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstLocalName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstLocalName(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstName(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstNamespaceUri(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstNamespaceUri\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstNamespaceUri(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstPrefix(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstPrefix\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstPrefix(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderConstString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstString(reader, str) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstValue(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstXmlLang(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstXmlLang\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstXmlLang(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderConstXmlVersion(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderConstXmlVersion\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderConstXmlVersion(reader) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderCurrentDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderCurrentDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderCurrentDoc(reader) };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderCurrentNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderCurrentNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderCurrentNode(reader) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderDepth(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderDepth\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderDepth(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderExpand(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderExpand\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderExpand(reader) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderGetAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetAttribute(reader, name) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetAttributeNo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut no: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlTextReaderGetAttributeNo\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut no as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetAttributeNo(reader, no) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetAttributeNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut localName: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlTextReaderGetAttributeNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut localName as *mut *mut xmlChar,
            &mut namespaceURI as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetAttributeNs(reader, localName, namespaceURI) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetParserColumnNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderGetParserColumnNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetParserColumnNumber(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetParserLineNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderGetParserLineNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetParserLineNumber(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetParserProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlTextReaderGetParserProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut prop as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetParserProp(reader, prop) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderGetRemainder(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderGetRemainder\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderGetRemainder(reader) };
    py_retval = unsafe { libxml_xmlParserInputBufferPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderHasAttributes(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderHasAttributes\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderHasAttributes(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderHasValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderHasValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderHasValue(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderIsDefault(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderIsDefault\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderIsDefault(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderIsEmptyElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderIsEmptyElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderIsEmptyElement(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderIsNamespaceDecl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderIsNamespaceDecl\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderIsNamespaceDecl(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderIsValid(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderIsValid\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderIsValid(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderLocatorBaseURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut locator: xmlTextReaderLocatorPtr = 0 as *mut libc::c_void;
    let mut pyobj_locator: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderLocatorBaseURI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_locator as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    locator = if pyobj_locator == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut libc::c_void
    } else {
        unsafe { (*(pyobj_locator as *mut PyxmlTextReaderLocator_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderLocatorBaseURI(locator) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderLocatorLineNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut locator: xmlTextReaderLocatorPtr = 0 as *mut libc::c_void;
    let mut pyobj_locator: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderLocatorLineNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_locator as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    locator = if pyobj_locator == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as *mut libc::c_void
    } else {
        unsafe { (*(pyobj_locator as *mut PyxmlTextReaderLocator_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderLocatorLineNumber(locator) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderLookupNamespace(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderLookupNamespace\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderLookupNamespace(reader, prefix) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderMoveToAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToAttribute(reader, name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToAttributeNo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut no: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlTextReaderMoveToAttributeNo\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut no as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToAttributeNo(reader, no) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToAttributeNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut localName: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlTextReaderMoveToAttributeNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut localName as *mut *mut xmlChar,
            &mut namespaceURI as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToAttributeNs(reader, localName, namespaceURI) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToElement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderMoveToElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToElement(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToFirstAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderMoveToFirstAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToFirstAttribute(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderMoveToNextAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderMoveToNextAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderMoveToNextAttribute(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderNext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderNext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderNext(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderNextSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderNextSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderNextSibling(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderNodeType(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderNodeType\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderNodeType(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderNormalization(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderNormalization\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderNormalization(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderPreserve(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderPreserve\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderPreserve(reader) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderQuoteChar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderQuoteChar\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderQuoteChar(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderRead(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderRead\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderRead(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderReadAttributeValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderReadAttributeValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderReadAttributeValue(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderReadInnerXml(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderReadInnerXml\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderReadInnerXml(reader) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderReadOuterXml(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderReadOuterXml\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderReadOuterXml(reader) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderReadState(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderReadState\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderReadState(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderReadString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderReadString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderReadString(reader) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderRelaxNGSetSchema(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlTextReaderRelaxNGSetSchema\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PyrelaxNgSchema_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderRelaxNGSetSchema(reader, schema) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderRelaxNGValidate(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut rng: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderRelaxNGValidate\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut rng as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderRelaxNGValidate(reader, rng) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderRelaxNGValidateCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlTextReaderRelaxNGValidateCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlRelaxNGValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyrelaxNgValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderRelaxNGValidateCtxt(reader, ctxt, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderSchemaValidate(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut xsd: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlTextReaderSchemaValidate\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut xsd as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderSchemaValidate(reader, xsd) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderSchemaValidateCtxt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOi:xmlTextReaderSchemaValidateCtxt\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PySchemaValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderSchemaValidateCtxt(reader, ctxt, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderSetParserProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: i32 = 0;
    let mut value: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oii:xmlTextReaderSetParserProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut prop as *mut i32,
            &mut value as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderSetParserProp(reader, prop, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderSetSchema(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlTextReaderSetSchema\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_schema as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    schema = if pyobj_schema == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlSchemaPtr
    } else {
        unsafe { (*(pyobj_schema as *mut PySchema_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderSetSchema(reader, schema) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderSetup(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzzi:xmlTextReaderSetup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
            &mut pyobj_input as *mut *mut PyObject,
            &mut URL as *mut *mut i8,
            &mut encoding as *mut *mut i8,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    input = if pyobj_input == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlParserInputBufferPtr
    } else {
        unsafe { (*(pyobj_input as *mut PyinputBuffer_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderSetup(reader, input, URL, encoding, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlTextReaderStandalone(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlTextReaderStandalone\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_reader as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    reader = if pyobj_reader == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlTextReaderPtr
    } else {
        unsafe { (*(pyobj_reader as *mut PyxmlTextReader_Object)).obj }
    };
    c_retval = unsafe { xmlTextReaderStandalone(reader) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefDefaultBufferSize(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefDefaultBufferSize\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefDefaultBufferSize(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefDoValidityCheckingDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefDoValidityCheckingDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefDoValidityCheckingDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefGetWarningsDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefGetWarningsDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefGetWarningsDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefIndentTreeOutput(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefIndentTreeOutput\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefIndentTreeOutput(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefKeepBlanksDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefKeepBlanksDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefKeepBlanksDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefLineNumbersDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefLineNumbersDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefLineNumbersDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefLoadExtDtdDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefLoadExtDtdDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefLoadExtDtdDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefParserDebugEntities(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefParserDebugEntities\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefParserDebugEntities(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefPedanticParserDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefPedanticParserDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefPedanticParserDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefSaveNoEmptyTags(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefSaveNoEmptyTags\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefSaveNoEmptyTags(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefSubstituteEntitiesDefaultValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut v: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlThrDefSubstituteEntitiesDefaultValue\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefSubstituteEntitiesDefaultValue(v) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlThrDefTreeIndentString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut v: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlThrDefTreeIndentString\0" as *const u8 as *const i8 as *mut i8,
            &mut v as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlThrDefTreeIndentString(v) };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsAegeanNumbers(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsAegeanNumbers\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsAegeanNumbers(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsAlphabeticPresentationForms(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsAlphabeticPresentationForms\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsAlphabeticPresentationForms(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsArabic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsArabic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsArabic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsArabicPresentationFormsA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsArabicPresentationFormsA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsArabicPresentationFormsA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsArabicPresentationFormsB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsArabicPresentationFormsB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsArabicPresentationFormsB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsArmenian(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsArmenian\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsArmenian(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsArrows(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsArrows\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsArrows(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBasicLatin(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBasicLatin\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBasicLatin(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBengali(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBengali\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBengali(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBlock(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    let mut block: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"iz:xmlUCSIsBlock\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
            &mut block as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBlock(code, block) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBlockElements(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBlockElements\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBlockElements(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBopomofo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBopomofo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBopomofo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBopomofoExtended(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBopomofoExtended\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBopomofoExtended(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBoxDrawing(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBoxDrawing\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBoxDrawing(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBraillePatterns(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBraillePatterns\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBraillePatterns(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsBuhid(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsBuhid\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsBuhid(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsByzantineMusicalSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsByzantineMusicalSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsByzantineMusicalSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKCompatibility(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKCompatibility\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKCompatibility(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKCompatibilityForms(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKCompatibilityForms\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKCompatibilityForms(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKCompatibilityIdeographs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKCompatibilityIdeographs\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKCompatibilityIdeographs(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKCompatibilityIdeographsSupplement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKCompatibilityIdeographsSupplement\0" as *const u8 as *const i8
                as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKCompatibilityIdeographsSupplement(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKRadicalsSupplement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKRadicalsSupplement\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKRadicalsSupplement(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKSymbolsandPunctuation(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKSymbolsandPunctuation\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKSymbolsandPunctuation(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKUnifiedIdeographs\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKUnifiedIdeographs(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographsExtensionA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKUnifiedIdeographsExtensionA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKUnifiedIdeographsExtensionA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCJKUnifiedIdeographsExtensionB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCJKUnifiedIdeographsExtensionB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCJKUnifiedIdeographsExtensionB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    let mut cat: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"iz:xmlUCSIsCat\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
            &mut cat as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCat(code, cat) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatC(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatC\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatC(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatCc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatCc\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatCc(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatCf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatCf\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatCf(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatCo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatCo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatCo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatCs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatCs\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatCs(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatL(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatL\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatL(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatLl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatLl\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatLl(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatLm(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatLm\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatLm(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatLo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatLo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatLo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatLt(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatLt\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatLt(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatLu(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatLu\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatLu(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatM(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatM\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatM(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatMc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatMc\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatMc(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatMe(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatMe\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatMe(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatMn(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatMn\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatMn(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatN(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatN\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatN(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatNd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatNd\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatNd(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatNl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatNl\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatNl(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatNo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatNo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatNo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatP(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatP\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatP(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPc\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPc(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPd(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPd\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPd(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPe(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPe\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPe(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPf\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPf(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPi(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPi\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPi(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatPs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatPs\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatPs(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatS(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatS\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatS(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatSc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatSc\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatSc(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatSk(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatSk\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatSk(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatSm(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatSm\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatSm(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatSo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatSo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatSo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatZ(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatZ\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatZ(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatZl(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatZl\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatZl(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatZp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatZp\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatZp(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCatZs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCatZs\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCatZs(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCherokee(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCherokee\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCherokee(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCombiningDiacriticalMarks(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCombiningDiacriticalMarks\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCombiningDiacriticalMarks(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCombiningDiacriticalMarksforSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCombiningDiacriticalMarksforSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCombiningDiacriticalMarksforSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCombiningHalfMarks(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCombiningHalfMarks\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCombiningHalfMarks(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCombiningMarksforSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCombiningMarksforSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCombiningMarksforSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsControlPictures(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsControlPictures\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsControlPictures(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCurrencySymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCurrencySymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCurrencySymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCypriotSyllabary(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCypriotSyllabary\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCypriotSyllabary(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCyrillic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCyrillic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCyrillic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsCyrillicSupplement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsCyrillicSupplement\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsCyrillicSupplement(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsDeseret(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsDeseret\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsDeseret(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsDevanagari(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsDevanagari\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsDevanagari(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsDingbats(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsDingbats\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsDingbats(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsEnclosedAlphanumerics(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsEnclosedAlphanumerics\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsEnclosedAlphanumerics(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsEnclosedCJKLettersandMonths(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsEnclosedCJKLettersandMonths\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsEnclosedCJKLettersandMonths(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsEthiopic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsEthiopic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsEthiopic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGeneralPunctuation(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGeneralPunctuation\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGeneralPunctuation(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGeometricShapes(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGeometricShapes\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGeometricShapes(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGeorgian(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGeorgian\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGeorgian(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGothic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGothic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGothic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGreek(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGreek\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGreek(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGreekExtended(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGreekExtended\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGreekExtended(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGreekandCoptic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGreekandCoptic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGreekandCoptic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGujarati(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGujarati\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGujarati(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsGurmukhi(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsGurmukhi\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsGurmukhi(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHalfwidthandFullwidthForms(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHalfwidthandFullwidthForms\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHalfwidthandFullwidthForms(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHangulCompatibilityJamo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHangulCompatibilityJamo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHangulCompatibilityJamo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHangulJamo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHangulJamo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHangulJamo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHangulSyllables(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHangulSyllables\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHangulSyllables(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHanunoo(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHanunoo\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHanunoo(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHebrew(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHebrew\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHebrew(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHighPrivateUseSurrogates(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHighPrivateUseSurrogates\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHighPrivateUseSurrogates(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHighSurrogates(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHighSurrogates\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHighSurrogates(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsHiragana(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsHiragana\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsHiragana(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsIPAExtensions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsIPAExtensions\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsIPAExtensions(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsIdeographicDescriptionCharacters(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsIdeographicDescriptionCharacters\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsIdeographicDescriptionCharacters(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKanbun(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKanbun\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKanbun(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKangxiRadicals(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKangxiRadicals\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKangxiRadicals(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKannada(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKannada\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKannada(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKatakana(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKatakana\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKatakana(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKatakanaPhoneticExtensions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKatakanaPhoneticExtensions\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKatakanaPhoneticExtensions(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKhmer(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKhmer\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKhmer(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsKhmerSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsKhmerSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsKhmerSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLao(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLao\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLao(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLatin1Supplement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLatin1Supplement\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLatin1Supplement(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLatinExtendedA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLatinExtendedA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLatinExtendedA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLatinExtendedAdditional(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLatinExtendedAdditional\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLatinExtendedAdditional(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLatinExtendedB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLatinExtendedB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLatinExtendedB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLetterlikeSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLetterlikeSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLetterlikeSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLimbu(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLimbu\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLimbu(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLinearBIdeograms(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLinearBIdeograms\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLinearBIdeograms(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLinearBSyllabary(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLinearBSyllabary\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLinearBSyllabary(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsLowSurrogates(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsLowSurrogates\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsLowSurrogates(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMalayalam(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMalayalam\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMalayalam(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMathematicalAlphanumericSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMathematicalAlphanumericSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMathematicalAlphanumericSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMathematicalOperators(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMathematicalOperators\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMathematicalOperators(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMiscellaneousMathematicalSymbolsA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMiscellaneousMathematicalSymbolsA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMiscellaneousMathematicalSymbolsA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMiscellaneousMathematicalSymbolsB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMiscellaneousMathematicalSymbolsB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMiscellaneousMathematicalSymbolsB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMiscellaneousSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMiscellaneousSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMiscellaneousSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMiscellaneousSymbolsandArrows(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMiscellaneousSymbolsandArrows\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMiscellaneousSymbolsandArrows(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMiscellaneousTechnical(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMiscellaneousTechnical\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMiscellaneousTechnical(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMongolian(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMongolian\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMongolian(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMusicalSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMusicalSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMusicalSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsMyanmar(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsMyanmar\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsMyanmar(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsNumberForms(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsNumberForms\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsNumberForms(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsOgham(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsOgham\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsOgham(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsOldItalic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsOldItalic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsOldItalic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsOpticalCharacterRecognition(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsOpticalCharacterRecognition\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsOpticalCharacterRecognition(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsOriya(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsOriya\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsOriya(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsOsmanya(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsOsmanya\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsOsmanya(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsPhoneticExtensions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsPhoneticExtensions\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsPhoneticExtensions(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsPrivateUse(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsPrivateUse\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsPrivateUse(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsPrivateUseArea(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsPrivateUseArea\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsPrivateUseArea(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsRunic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsRunic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsRunic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsShavian(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsShavian\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsShavian(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSinhala(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSinhala\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSinhala(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSmallFormVariants(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSmallFormVariants\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSmallFormVariants(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSpacingModifierLetters(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSpacingModifierLetters\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSpacingModifierLetters(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSpecials(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSpecials\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSpecials(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSuperscriptsandSubscripts(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSuperscriptsandSubscripts\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSuperscriptsandSubscripts(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSupplementalArrowsA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSupplementalArrowsA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSupplementalArrowsA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSupplementalArrowsB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSupplementalArrowsB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSupplementalArrowsB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSupplementalMathematicalOperators(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSupplementalMathematicalOperators\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSupplementalMathematicalOperators(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSupplementaryPrivateUseAreaA(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSupplementaryPrivateUseAreaA\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSupplementaryPrivateUseAreaA(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSupplementaryPrivateUseAreaB(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSupplementaryPrivateUseAreaB\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSupplementaryPrivateUseAreaB(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsSyriac(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsSyriac\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsSyriac(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTagalog(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTagalog\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTagalog(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTagbanwa(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTagbanwa\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTagbanwa(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTags(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTags\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTags(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTaiLe(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTaiLe\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTaiLe(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTaiXuanJingSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTaiXuanJingSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTaiXuanJingSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTamil(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTamil\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTamil(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTelugu(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTelugu\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTelugu(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsThaana(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsThaana\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsThaana(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsThai(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsThai\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsThai(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsTibetan(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsTibetan\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsTibetan(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsUgaritic(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsUgaritic\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsUgaritic(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsUnifiedCanadianAboriginalSyllabics(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsUnifiedCanadianAboriginalSyllabics\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsUnifiedCanadianAboriginalSyllabics(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsVariationSelectors(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsVariationSelectors\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsVariationSelectors(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsVariationSelectorsSupplement(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsVariationSelectorsSupplement\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsVariationSelectorsSupplement(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsYiRadicals(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsYiRadicals\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsYiRadicals(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsYiSyllables(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsYiSyllables\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsYiSyllables(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUCSIsYijingHexagramSymbols(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut code: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlUCSIsYijingHexagramSymbols\0" as *const u8 as *const i8 as *mut i8,
            &mut code as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUCSIsYijingHexagramSymbols(code) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIEscape(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlURIEscape\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlURIEscape(str) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIEscapeStr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut list: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlURIEscapeStr\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut list as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlURIEscapeStr(str, list) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetAuthority(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetAuthority\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).authority };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetFragment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetFragment\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).fragment };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetOpaque(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetOpaque\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).opaque };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetPath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetPath\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).path };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetPort(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetPort\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).port };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetQuery(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetQuery\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).query };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetQueryRaw(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetQueryRaw\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).query_raw };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetScheme(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetScheme\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).scheme };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetServer(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetServer\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).server };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIGetUser(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const i8 = 0 as *const i8;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlURIGetUser\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    c_retval = unsafe { (*URI).user };
    py_retval = unsafe { libxml_charPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetAuthority(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut authority: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetAuthority\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut authority as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).authority }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).authority as *mut libc::c_void)
        });
    }
    let fresh125 = unsafe { &mut ((*URI).authority) };
    *fresh125 = (unsafe { xmlStrdup(authority as *const xmlChar) }) as *mut i8;
    let fresh126 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh126 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetFragment(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut fragment: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetFragment\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut fragment as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).fragment }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).fragment as *mut libc::c_void)
        });
    }
    let fresh127 = unsafe { &mut ((*URI).fragment) };
    *fresh127 = (unsafe { xmlStrdup(fragment as *const xmlChar) }) as *mut i8;
    let fresh128 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh128 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetOpaque(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut opaque: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetOpaque\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut opaque as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).opaque }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).opaque as *mut libc::c_void)
        });
    }
    let fresh129 = unsafe { &mut ((*URI).opaque) };
    *fresh129 = (unsafe { xmlStrdup(opaque as *const xmlChar) }) as *mut i8;
    let fresh130 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh130 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetPath(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut path: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetPath\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut path as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).path }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*URI).path as *mut libc::c_void) });
    }
    let fresh131 = unsafe { &mut ((*URI).path) };
    *fresh131 = (unsafe { xmlStrdup(path as *const xmlChar) }) as *mut i8;
    let fresh132 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh132 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetPort(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut port: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlURISetPort\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut port as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    (unsafe { (*URI).port = port });
    let fresh133 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh133 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetQuery(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut query: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetQuery\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut query as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).query }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*URI).query as *mut libc::c_void) });
    }
    let fresh134 = unsafe { &mut ((*URI).query) };
    *fresh134 = (unsafe { xmlStrdup(query as *const xmlChar) }) as *mut i8;
    let fresh135 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh135 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetQueryRaw(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut query_raw: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetQueryRaw\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut query_raw as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).query_raw }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).query_raw as *mut libc::c_void)
        });
    }
    let fresh136 = unsafe { &mut ((*URI).query_raw) };
    *fresh136 = (unsafe { xmlStrdup(query_raw as *const xmlChar) }) as *mut i8;
    let fresh137 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh137 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetScheme(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut scheme: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetScheme\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut scheme as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).scheme }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).scheme as *mut libc::c_void)
        });
    }
    let fresh138 = unsafe { &mut ((*URI).scheme) };
    *fresh138 = (unsafe { xmlStrdup(scheme as *const xmlChar) }) as *mut i8;
    let fresh139 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh139 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetServer(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut server: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetServer\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut server as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).server }).is_null() {
        (unsafe {
            xmlFree.expect("non-null function pointer")((*URI).server as *mut libc::c_void)
        });
    }
    let fresh140 = unsafe { &mut ((*URI).server) };
    *fresh140 = (unsafe { xmlStrdup(server as *const xmlChar) }) as *mut i8;
    let fresh141 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh141 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURISetUser(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    let mut user: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlURISetUser\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_URI as *mut *mut PyObject,
            &mut user as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    URI = if pyobj_URI == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlURIPtr
    } else {
        unsafe { (*(pyobj_URI as *mut PyURI_Object)).obj }
    };
    if !(unsafe { (*URI).user }).is_null() {
        (unsafe { xmlFree.expect("non-null function pointer")((*URI).user as *mut libc::c_void) });
    }
    let fresh142 = unsafe { &mut ((*URI).user) };
    *fresh142 = (unsafe { xmlStrdup(user as *const xmlChar) }) as *mut i8;
    let fresh143 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh143 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlURIUnescapeString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut i8 = 0 as *mut i8;
    let mut str: *mut i8 = 0 as *mut i8;
    let mut len: i32 = 0;
    let mut target: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"ziz:xmlURIUnescapeString\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut i8,
            &mut len as *mut i32,
            &mut target as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlURIUnescapeString(str, len, target) };
    py_retval = unsafe { libxml_charPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Charcmp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf1: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf2: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlUTF8Charcmp\0" as *const u8 as *const i8 as *mut i8,
            &mut utf1 as *mut *mut xmlChar,
            &mut utf2 as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Charcmp(utf1, utf2) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Size(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlUTF8Size\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Size(utf) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strlen(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlUTF8Strlen\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strlen(utf) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strloc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut utfchar: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zz:xmlUTF8Strloc\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
            &mut utfchar as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strloc(utf, utfchar) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strndup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlUTF8Strndup\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strndup(utf, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strpos(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut pos: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlUTF8Strpos\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
            &mut pos as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strpos(utf, pos) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strsize(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlUTF8Strsize\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strsize(utf, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUTF8Strsub(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut start: i32 = 0;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zii:xmlUTF8Strsub\0" as *const u8 as *const i8 as *mut i8,
            &mut utf as *mut *mut xmlChar,
            &mut start as *mut i32,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlUTF8Strsub(utf, start, len) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUnlinkNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlUnlinkNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    (unsafe { xmlUnlinkNode(cur) });
    let fresh144 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh144 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlUnsetNsProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOz:xmlUnsetNsProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlUnsetNsProp(node, ns, name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlUnsetProp(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlUnsetProp\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlUnsetProp(node, name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidCtxtNormalizeAttributeValue(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOzz:xmlValidCtxtNormalizeAttributeValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidCtxtNormalizeAttributeValue(ctxt, doc, elem, name, value) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidNormalizeAttributeValue(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOzz:xmlValidNormalizeAttributeValue\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidNormalizeAttributeValue(doc, elem, name, value) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateDocument(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlValidateDocument\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlValidateDocument(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateDocumentFinal(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlValidateDocumentFinal\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlValidateDocumentFinal(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateDtd(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlValidateDtd\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_dtd as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    dtd = (if pyobj_dtd == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_dtd as *mut PyxmlNode_Object)).obj }
    }) as xmlDtdPtr;
    c_retval = unsafe { xmlValidateDtd(ctxt, doc, dtd) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateDtdFinal(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlValidateDtdFinal\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlValidateDtdFinal(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlValidateElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidateElement(ctxt, doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNCName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlValidateNCName\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
            &mut space as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNCName(value, space) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNMToken(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlValidateNMToken\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
            &mut space as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNMToken(value, space) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlValidateName\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
            &mut space as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateName(value, space) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNameValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlValidateNameValue\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNameValue(value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNamesValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlValidateNamesValue\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNamesValue(value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNmtokenValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlValidateNmtokenValue\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNmtokenValue(value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNmtokensValue(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlValidateNmtokensValue\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateNmtokensValue(value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateNotationUse(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut notationName: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOz:xmlValidateNotationUse\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut notationName as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlValidateNotationUse(ctxt, doc, notationName) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateOneAttribute(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOOz:xmlValidateOneAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut pyobj_attr as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    attr = (if pyobj_attr == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_attr as *mut PyxmlNode_Object)).obj }
    }) as xmlAttrPtr;
    c_retval = unsafe { xmlValidateOneAttribute(ctxt, doc, elem, attr, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateOneElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlValidateOneElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidateOneElement(ctxt, doc, elem) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateOneNamespace(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOzOz:xmlValidateOneNamespace\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut prefix as *mut *mut xmlChar,
            &mut pyobj_ns as *mut *mut PyObject,
            &mut value as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    c_retval = unsafe { xmlValidateOneNamespace(ctxt, doc, elem, prefix, ns, value) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidatePopElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOz:xmlValidatePopElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut qname as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidatePopElement(ctxt, doc, elem, qname) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidatePushCData(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozi:xmlValidatePushCData\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut data as *mut *mut xmlChar,
            &mut len as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    c_retval = unsafe { xmlValidatePushCData(ctxt, data, len) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidatePushElement(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOOz:xmlValidatePushElement\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_elem as *mut *mut PyObject,
            &mut qname as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    elem = if pyobj_elem == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_elem as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlValidatePushElement(ctxt, doc, elem, qname) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateQName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zi:xmlValidateQName\0" as *const u8 as *const i8 as *mut i8,
            &mut value as *mut *mut xmlChar,
            &mut space as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlValidateQName(value, space) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlValidateRoot(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlValidateRoot\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlValidCtxtPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyValidCtxt_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlValidateRoot(ctxt, doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXIncludeProcess(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXIncludeProcess\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlXIncludeProcess(doc) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXIncludeProcessFlags(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXIncludeProcessFlags\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut flags as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlXIncludeProcessFlags(doc, flags) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXIncludeProcessTree(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXIncludeProcessTree\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_tree as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_tree as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXIncludeProcessTree(tree) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXIncludeProcessTreeFlags(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    let mut flags: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXIncludeProcessTreeFlags\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_tree as *mut *mut PyObject,
            &mut flags as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    tree = if pyobj_tree == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_tree as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXIncludeProcessTreeFlags(tree, flags) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathAddValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathAddValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathAddValues(ctxt) });
    let fresh145 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh145 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathBooleanFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathBooleanFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathBooleanFunction(ctxt, nargs) });
    let fresh146 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh146 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastBooleanToNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlXPathCastBooleanToNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastBooleanToNumber(val) };
    py_retval = unsafe { libxml_doubleWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastBooleanToString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlXPathCastBooleanToString\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastBooleanToString(val) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastNodeToNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathCastNodeToNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathCastNodeToNumber(node) };
    py_retval = unsafe { libxml_doubleWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastNodeToString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathCastNodeToString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathCastNodeToString(node) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastNumberToBoolean(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"d:xmlXPathCastNumberToBoolean\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut f64,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastNumberToBoolean(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastNumberToString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: f64 = 0.;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"d:xmlXPathCastNumberToString\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut f64,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastNumberToString(val) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastStringToBoolean(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathCastStringToBoolean\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastStringToBoolean(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCastStringToNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathCastStringToNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathCastStringToNumber(val) };
    py_retval = unsafe { libxml_doubleWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCeilingFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathCeilingFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathCeilingFunction(ctxt, nargs) });
    let fresh147 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh147 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCmpNodes(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut node1: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node1: *mut PyObject = 0 as *mut PyObject;
    let mut node2: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node2: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathCmpNodes\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node1 as *mut *mut PyObject,
            &mut pyobj_node2 as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node1 = if pyobj_node1 == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node1 as *mut PyxmlNode_Object)).obj }
    };
    node2 = if pyobj_node2 == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node2 as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathCmpNodes(node1, node2) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCompareValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut inf: i32 = 0;
    let mut strict: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oii:xmlXPathCompareValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut inf as *mut i32,
            &mut strict as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathCompareValues(ctxt, inf, strict) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathConcatFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathConcatFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathConcatFunction(ctxt, nargs) });
    let fresh148 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh148 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathContainsFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathContainsFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathContainsFunction(ctxt, nargs) });
    let fresh149 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh149 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathContextSetCache(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut active: i32 = 0;
    let mut value: i32 = 0;
    let mut options: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oiii:xmlXPathContextSetCache\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut active as *mut i32,
            &mut value as *mut i32,
            &mut options as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathContextSetCache(ctxt, active, value, options) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathCountFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathCountFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathCountFunction(ctxt, nargs) });
    let fresh150 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh150 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathDivValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathDivValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathDivValues(ctxt) });
    let fresh151 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh151 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathEqualValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathEqualValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathEqualValues(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathErr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut error: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathErr\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut error as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathErr(ctxt, error) });
    let fresh152 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh152 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathEval(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:xmlXPathEval\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut pyobj_ctx as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathEval(str, ctx) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathEvalExpr(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathEvalExpr\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathEvalExpr(ctxt) });
    let fresh153 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh153 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathEvalExpression(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:xmlXPathEvalExpression\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathEvalExpression(str, ctxt) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathFalseFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathFalseFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathFalseFunction(ctxt, nargs) });
    let fresh154 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh154 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathFloorFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathFloorFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathFloorFunction(ctxt, nargs) });
    let fresh155 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh155 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathFreeContext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathFreeContext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    (unsafe { xmlXPathFreeContext(ctxt) });
    let fresh156 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh156 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathFreeParserContext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathFreeParserContext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathFreeParserContext(ctxt) });
    let fresh157 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh157 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetContextDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlDocPtr = 0 as *mut xmlDoc;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetContextDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).doc };
    py_retval = unsafe { libxml_xmlDocPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetContextNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetContextNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).node };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetContextPosition(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetContextPosition\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).proximityPosition };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetContextSize(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetContextSize\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).contextSize };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).function };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathGetFunctionURI(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathGetFunctionURI\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).functionURI };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathIdFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathIdFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathIdFunction(ctxt, nargs) });
    let fresh158 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh158 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathInit(
    mut _self_0: *mut PyObject,
    mut _args: *mut PyObject,
) -> *mut PyObject {
    if (unsafe { libxml_deprecationWarning(b"xmlXPathInit\0" as *const u8 as *const i8) })
        == -(1 as i32)
    {
        return 0 as *mut PyObject;
    }
    (unsafe { xmlXPathInit() });
    let fresh159 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh159 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathIsInf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"d:xmlXPathIsInf\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut f64,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathIsInf(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathIsNaN(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut val: f64 = 0.;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"d:xmlXPathIsNaN\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut f64,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathIsNaN(val) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathIsNodeType(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathIsNodeType\0" as *const u8 as *const i8 as *mut i8,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathIsNodeType(name) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathLangFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathLangFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathLangFunction(ctxt, nargs) });
    let fresh160 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh160 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathLastFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathLastFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathLastFunction(ctxt, nargs) });
    let fresh161 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh161 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathLocalNameFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathLocalNameFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathLocalNameFunction(ctxt, nargs) });
    let fresh162 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh162 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathModValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathModValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathModValues(ctxt) });
    let fresh163 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh163 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathMultValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathMultValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathMultValues(ctxt) });
    let fresh164 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh164 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNamespaceURIFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathNamespaceURIFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathNamespaceURIFunction(ctxt, nargs) });
    let fresh165 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh165 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewBoolean(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"i:xmlXPathNewBoolean\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathNewBoolean(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewCString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: *mut i8 = 0 as *mut i8;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathNewCString\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut *mut i8,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathNewCString(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewContext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathNewContext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlXPathNewContext(doc) };
    py_retval = unsafe { libxml_xmlXPathContextPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewFloat(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: f64 = 0.;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"d:xmlXPathNewFloat\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut f64,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathNewFloat(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewNodeSet(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_val: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathNewNodeSet\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_val as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    val = if pyobj_val == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_val as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNewNodeSet(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewParserContext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:xmlXPathNewParserContext\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNewParserContext(str, ctxt) };
    py_retval = unsafe { libxml_xmlXPathParserContextPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathNewString\0" as *const u8 as *const i8 as *mut i8,
            &mut val as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathNewString(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNewValueTree(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut val: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_val: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathNewValueTree\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_val as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    val = if pyobj_val == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_val as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNewValueTree(val) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextAncestor(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextAncestor\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextAncestor(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextAncestorOrSelf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextAncestorOrSelf\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextAncestorOrSelf(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextAttribute(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextAttribute\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextAttribute(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextChild(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextChild\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextChild(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextDescendant(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextDescendant\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextDescendant(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextDescendantOrSelf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextDescendantOrSelf\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextDescendantOrSelf(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextFollowing(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextFollowing\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextFollowing(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextFollowingSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextFollowingSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextFollowingSibling(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextNamespace(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextNamespace\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextNamespace(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextParent(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextParent\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextParent(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextPreceding(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextPreceding\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextPreceding(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextPrecedingSibling(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextPrecedingSibling\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextPrecedingSibling(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNextSelf(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlNodePtr = 0 as *mut xmlNode;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathNextSelf\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_cur as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    cur = if pyobj_cur == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_cur as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNextSelf(ctxt, cur) };
    py_retval = unsafe { libxml_xmlNodePtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNodeEval(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OzO:xmlXPathNodeEval\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_node as *mut *mut PyObject,
            &mut str as *mut *mut xmlChar,
            &mut pyobj_ctx as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    ctx = if pyobj_ctx == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNodeEval(node, str, ctx) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNodeSetFreeNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathNodeSetFreeNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ns as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ns = (if pyobj_ns == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_ns as *mut PyxmlNode_Object)).obj }
    }) as xmlNsPtr;
    (unsafe { xmlXPathNodeSetFreeNs(ns) });
    let fresh166 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh166 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNormalizeFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathNormalizeFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathNormalizeFunction(ctxt, nargs) });
    let fresh167 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh167 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNotEqualValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathNotEqualValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNotEqualValues(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNotFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathNotFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathNotFunction(ctxt, nargs) });
    let fresh168 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh168 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNsLookup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *const xmlChar = 0 as *const xmlChar;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlXPathNsLookup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut prefix as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathNsLookup(ctxt, prefix) };
    py_retval = unsafe { libxml_xmlCharPtrConstWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathNumberFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathNumberFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathNumberFunction(ctxt, nargs) });
    let fresh169 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh169 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathOrderDocElems(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i64 = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathOrderDocElems\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    c_retval = unsafe { xmlXPathOrderDocElems(doc) };
    py_retval = unsafe { libxml_longWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathParseNCName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathParseNCName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathParseNCName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathParseName(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathParseName\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathParseName(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathParserGetContext(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathParserGetContext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { (*ctxt).context };
    py_retval = unsafe { libxml_xmlXPathContextPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathPopBoolean(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathPopBoolean\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathPopBoolean(ctxt) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathPopNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathPopNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathPopNumber(ctxt) };
    py_retval = unsafe { libxml_doubleWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathPopString(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathPopString\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathPopString(ctxt) };
    py_retval = unsafe { libxml_xmlCharPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathPositionFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathPositionFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathPositionFunction(ctxt, nargs) });
    let fresh170 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh170 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRegisterAllFunctions(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathRegisterAllFunctions\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    (unsafe { xmlXPathRegisterAllFunctions(ctxt) });
    let fresh171 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh171 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRegisterNs(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: i32 = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlXPathRegisterNs\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut prefix as *mut *mut xmlChar,
            &mut ns_uri as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathRegisterNs(ctxt, prefix, ns_uri) };
    py_retval = unsafe { libxml_intWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRegisteredFuncsCleanup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathRegisteredFuncsCleanup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    (unsafe { xmlXPathRegisteredFuncsCleanup(ctxt) });
    let fresh172 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh172 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRegisteredNsCleanup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathRegisteredNsCleanup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    (unsafe { xmlXPathRegisteredNsCleanup(ctxt) });
    let fresh173 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh173 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRegisteredVariablesCleanup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathRegisteredVariablesCleanup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    (unsafe { xmlXPathRegisteredVariablesCleanup(ctxt) });
    let fresh174 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh174 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRoot(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathRoot\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathRoot(ctxt) });
    let fresh175 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh175 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathRoundFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathRoundFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathRoundFunction(ctxt, nargs) });
    let fresh176 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh176 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSetContextDoc(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathSetContextDoc\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_doc as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    let fresh177 = unsafe { &mut ((*ctxt).doc) };
    *fresh177 = doc;
    let fresh178 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh178 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSetContextNode(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OO:xmlXPathSetContextNode\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut pyobj_node as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    node = if pyobj_node == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_node as *mut PyxmlNode_Object)).obj }
    };
    let fresh179 = unsafe { &mut ((*ctxt).node) };
    *fresh179 = node;
    let fresh180 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh180 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathStartsWithFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathStartsWithFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathStartsWithFunction(ctxt, nargs) });
    let fresh181 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh181 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathStringEvalNumber(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: f64 = 0.;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"z:xmlXPathStringEvalNumber\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    c_retval = unsafe { xmlXPathStringEvalNumber(str) };
    py_retval = unsafe { libxml_doubleWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathStringFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathStringFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathStringFunction(ctxt, nargs) });
    let fresh182 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh182 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathStringLengthFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathStringLengthFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathStringLengthFunction(ctxt, nargs) });
    let fresh183 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh183 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSubValues(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathSubValues\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathSubValues(ctxt) });
    let fresh184 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh184 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSubstringAfterFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathSubstringAfterFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathSubstringAfterFunction(ctxt, nargs) });
    let fresh185 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh185 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSubstringBeforeFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathSubstringBeforeFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathSubstringBeforeFunction(ctxt, nargs) });
    let fresh186 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh186 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSubstringFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathSubstringFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathSubstringFunction(ctxt, nargs) });
    let fresh187 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh187 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathSumFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathSumFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathSumFunction(ctxt, nargs) });
    let fresh188 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh188 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathTranslateFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathTranslateFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathTranslateFunction(ctxt, nargs) });
    let fresh189 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh189 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathTrueFunction(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut nargs: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oi:xmlXPathTrueFunction\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut nargs as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathTrueFunction(ctxt, nargs) });
    let fresh190 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh190 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathValueFlipSign(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"O:xmlXPathValueFlipSign\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPathValueFlipSign(ctxt) });
    let fresh191 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh191 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathVariableLookup(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Oz:xmlXPathVariableLookup\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathVariableLookup(ctxt, name) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPathVariableLookupNS(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozz:xmlXPathVariableLookupNS\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut name as *mut *mut xmlChar,
            &mut ns_uri as *mut *mut xmlChar,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPathVariableLookupNS(ctxt, name, ns_uri) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPatherror(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut file: *mut i8 = 0 as *mut i8;
    let mut line: i32 = 0;
    let mut no: i32 = 0;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"Ozii:xmlXPatherror\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_ctxt as *mut *mut PyObject,
            &mut file as *mut *mut i8,
            &mut line as *mut i32,
            &mut no as *mut i32,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctxt = if pyobj_ctxt == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathParserContextPtr
    } else {
        unsafe { (*(pyobj_ctxt as *mut PyxmlXPathParserContext_Object)).obj }
    };
    (unsafe { xmlXPatherror(ctxt, file, line, no) });
    let fresh192 = unsafe { &mut ((*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt) };
    *fresh192 += 1;
    return unsafe { &mut _Py_NoneStruct };
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPtrEval(
    mut _self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: xmlXPathObjectPtr = 0 as *mut xmlXPathObject;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    let mut ctx: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctx: *mut PyObject = 0 as *mut PyObject;
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"zO:xmlXPtrEval\0" as *const u8 as *const i8 as *mut i8,
            &mut str as *mut *mut xmlChar,
            &mut pyobj_ctx as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    ctx = if pyobj_ctx == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlXPathContextPtr
    } else {
        unsafe { (*(pyobj_ctx as *mut PyxmlXPathContext_Object)).obj }
    };
    c_retval = unsafe { xmlXPtrEval(str, ctx) };
    py_retval = unsafe { libxml_xmlXPathObjectPtrWrap(c_retval) };
    return py_retval;
}
#[no_mangle]
pub extern "C" fn libxml_xmlXPtrNewContext(
    mut _self_0: *mut PyObject,
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
    if (unsafe {
        _PyArg_ParseTuple_SizeT(
            args,
            b"OOO:xmlXPtrNewContext\0" as *const u8 as *const i8 as *mut i8,
            &mut pyobj_doc as *mut *mut PyObject,
            &mut pyobj_here as *mut *mut PyObject,
            &mut pyobj_origin as *mut *mut PyObject,
        )
    }) == 0
    {
        return 0 as *mut PyObject;
    }
    doc = (if pyobj_doc == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_doc as *mut PyxmlNode_Object)).obj }
    }) as xmlDocPtr;
    here = if pyobj_here == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_here as *mut PyxmlNode_Object)).obj }
    };
    origin = if pyobj_origin == (unsafe { &mut _Py_NoneStruct }) as *mut PyObject {
        0 as xmlNodePtr
    } else {
        unsafe { (*(pyobj_origin as *mut PyxmlNode_Object)).obj }
    };
    c_retval = unsafe { xmlXPtrNewContext(doc, here, origin) };
    py_retval = unsafe { libxml_xmlXPathContextPtrWrap(c_retval) };
    return py_retval;
}
