use ::libc;
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
    fn PyType_IsSubtype(_: *mut PyTypeObject, _: *mut PyTypeObject) -> libc::c_int;
    static mut _Py_NoneStruct: PyObject;
    static mut PyFile_Type: PyTypeObject;
    fn PyFile_AsFile(_: *mut PyObject) -> *mut FILE;
    fn _PyArg_ParseTuple_SizeT(
        _: *mut PyObject,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn xmlCheckVersion(version: libc::c_int);
    fn xmlStrdup(cur: *const xmlChar) -> *mut xmlChar;
    fn xmlStrndup(cur: *const xmlChar, len: libc::c_int) -> *mut xmlChar;
    fn xmlCharStrndup(cur: *const libc::c_char, len: libc::c_int) -> *mut xmlChar;
    fn xmlCharStrdup(cur: *const libc::c_char) -> *mut xmlChar;
    fn xmlStrsub(
        str: *const xmlChar,
        start: libc::c_int,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlStrchr(str: *const xmlChar, val: xmlChar) -> *const xmlChar;
    fn xmlStrstr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrcasestr(str: *const xmlChar, val: *const xmlChar) -> *const xmlChar;
    fn xmlStrcmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrncmp(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlStrcasecmp(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrncasecmp(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlStrEqual(str1: *const xmlChar, str2: *const xmlChar) -> libc::c_int;
    fn xmlStrQEqual(
        pref: *const xmlChar,
        name: *const xmlChar,
        str: *const xmlChar,
    ) -> libc::c_int;
    fn xmlStrlen(str: *const xmlChar) -> libc::c_int;
    fn xmlStrcat(cur: *mut xmlChar, add: *const xmlChar) -> *mut xmlChar;
    fn xmlStrncat(
        cur: *mut xmlChar,
        add: *const xmlChar,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlStrncatNew(
        str1: *const xmlChar,
        str2: *const xmlChar,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlCheckUTF8(utf: *const libc::c_uchar) -> libc::c_int;
    fn xmlUTF8Strsize(utf: *const xmlChar, len: libc::c_int) -> libc::c_int;
    fn xmlUTF8Strndup(utf: *const xmlChar, len: libc::c_int) -> *mut xmlChar;
    fn xmlUTF8Strpos(utf: *const xmlChar, pos: libc::c_int) -> *const xmlChar;
    fn xmlUTF8Strloc(utf: *const xmlChar, utfchar: *const xmlChar) -> libc::c_int;
    fn xmlUTF8Strsub(
        utf: *const xmlChar,
        start: libc::c_int,
        len: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlValidateDocument(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> libc::c_int;
    fn xmlInitializeDict() -> libc::c_int;
    fn xmlDictCleanup();
    fn xmlRegexpCompile(regexp: *const xmlChar) -> xmlRegexpPtr;
    fn xmlRegFreeRegexp(regexp: xmlRegexpPtr);
    fn xmlRegexpExec(comp: xmlRegexpPtr, value: *const xmlChar) -> libc::c_int;
    fn xmlRegexpPrint(output: *mut FILE, regexp: xmlRegexpPtr);
    fn xmlRegexpIsDeterminist(comp: xmlRegexpPtr) -> libc::c_int;
    fn xmlValidateNCName(value: *const xmlChar, space: libc::c_int) -> libc::c_int;
    fn xmlValidateQName(value: *const xmlChar, space: libc::c_int) -> libc::c_int;
    fn xmlValidateName(value: *const xmlChar, space: libc::c_int) -> libc::c_int;
    fn xmlValidateNMToken(value: *const xmlChar, space: libc::c_int) -> libc::c_int;
    fn xmlBuildQName(
        ncname: *const xmlChar,
        prefix: *const xmlChar,
        memory: *mut xmlChar,
        len: libc::c_int,
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
    fn xmlNewGlobalNs(
        doc: xmlDocPtr,
        href: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlNewNs(
        node: xmlNodePtr,
        href: *const xmlChar,
        prefix: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlFreeNs(cur: xmlNsPtr);
    fn xmlFreeNsList(cur: xmlNsPtr);
    fn xmlNewDoc(version: *const xmlChar) -> xmlDocPtr;
    fn xmlFreeDoc(cur: xmlDocPtr);
    fn xmlNewDocProp(
        doc: xmlDocPtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
    fn xmlNewProp(
        node: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
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
    fn xmlCopyDoc(doc: xmlDocPtr, recursive: libc::c_int) -> xmlDocPtr;
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
    fn xmlNewDocPI(
        doc: xmlDocPtr,
        name: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlNodePtr;
    fn xmlNewPI(name: *const xmlChar, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewDocTextLen(
        doc: xmlDocPtr,
        content: *const xmlChar,
        len: libc::c_int,
    ) -> xmlNodePtr;
    fn xmlNewTextLen(content: *const xmlChar, len: libc::c_int) -> xmlNodePtr;
    fn xmlNewDocComment(doc: xmlDocPtr, content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewComment(content: *const xmlChar) -> xmlNodePtr;
    fn xmlNewCDataBlock(
        doc: xmlDocPtr,
        content: *const xmlChar,
        len: libc::c_int,
    ) -> xmlNodePtr;
    fn xmlNewCharRef(doc: xmlDocPtr, name: *const xmlChar) -> xmlNodePtr;
    fn xmlNewReference(doc: *const xmlDoc, name: *const xmlChar) -> xmlNodePtr;
    fn xmlCopyNode(node: xmlNodePtr, recursive: libc::c_int) -> xmlNodePtr;
    fn xmlDocCopyNode(
        node: xmlNodePtr,
        doc: xmlDocPtr,
        recursive: libc::c_int,
    ) -> xmlNodePtr;
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
    fn xmlGetLineNo(node: *const xmlNode) -> libc::c_long;
    fn xmlGetNodePath(node: *const xmlNode) -> *mut xmlChar;
    fn xmlDocGetRootElement(doc: *const xmlDoc) -> xmlNodePtr;
    fn xmlGetLastChild(parent: *const xmlNode) -> xmlNodePtr;
    fn xmlNodeIsText(node: *const xmlNode) -> libc::c_int;
    fn xmlIsBlankNode(node: *const xmlNode) -> libc::c_int;
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
    fn xmlTextConcat(
        node: xmlNodePtr,
        content: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlFreeNodeList(cur: xmlNodePtr);
    fn xmlFreeNode(cur: xmlNodePtr);
    fn xmlSetTreeDoc(tree: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSetListDoc(list: xmlNodePtr, doc: xmlDocPtr);
    fn xmlSearchNs(
        doc: xmlDocPtr,
        node: xmlNodePtr,
        nameSpace: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlSearchNsByHref(
        doc: xmlDocPtr,
        node: xmlNodePtr,
        href: *const xmlChar,
    ) -> xmlNsPtr;
    fn xmlSetNs(node: xmlNodePtr, ns: xmlNsPtr);
    fn xmlCopyNamespace(cur: xmlNsPtr) -> xmlNsPtr;
    fn xmlCopyNamespaceList(cur: xmlNsPtr) -> xmlNsPtr;
    fn xmlSetProp(
        node: xmlNodePtr,
        name: *const xmlChar,
        value: *const xmlChar,
    ) -> xmlAttrPtr;
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
    fn xmlStringLenGetNodeList(
        doc: *const xmlDoc,
        value: *const xmlChar,
        len: libc::c_int,
    ) -> xmlNodePtr;
    fn xmlNodeListGetString(
        doc: xmlDocPtr,
        list: *const xmlNode,
        inLine: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlNodeListGetRawString(
        doc: *const xmlDoc,
        list: *const xmlNode,
        inLine: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlNodeSetContent(cur: xmlNodePtr, content: *const xmlChar);
    fn xmlNodeSetContentLen(cur: xmlNodePtr, content: *const xmlChar, len: libc::c_int);
    fn xmlNodeAddContent(cur: xmlNodePtr, content: *const xmlChar);
    fn xmlNodeAddContentLen(cur: xmlNodePtr, content: *const xmlChar, len: libc::c_int);
    fn xmlNodeGetContent(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetLang(cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeGetSpacePreserve(cur: *const xmlNode) -> libc::c_int;
    fn xmlNodeSetLang(cur: xmlNodePtr, lang: *const xmlChar);
    fn xmlNodeSetSpacePreserve(cur: xmlNodePtr, val: libc::c_int);
    fn xmlNodeGetBase(doc: *const xmlDoc, cur: *const xmlNode) -> *mut xmlChar;
    fn xmlNodeSetBase(cur: xmlNodePtr, uri: *const xmlChar);
    fn xmlRemoveProp(cur: xmlAttrPtr) -> libc::c_int;
    fn xmlUnsetNsProp(
        node: xmlNodePtr,
        ns: xmlNsPtr,
        name: *const xmlChar,
    ) -> libc::c_int;
    fn xmlUnsetProp(node: xmlNodePtr, name: *const xmlChar) -> libc::c_int;
    fn xmlReconciliateNs(doc: xmlDocPtr, tree: xmlNodePtr) -> libc::c_int;
    fn xmlDocFormatDump(
        f: *mut FILE,
        cur: xmlDocPtr,
        format: libc::c_int,
    ) -> libc::c_int;
    fn xmlDocDump(f: *mut FILE, cur: xmlDocPtr) -> libc::c_int;
    fn xmlElemDump(f: *mut FILE, doc: xmlDocPtr, cur: xmlNodePtr);
    fn xmlSaveFile(filename: *const libc::c_char, cur: xmlDocPtr) -> libc::c_int;
    fn xmlSaveFormatFile(
        filename: *const libc::c_char,
        cur: xmlDocPtr,
        format: libc::c_int,
    ) -> libc::c_int;
    fn xmlNodeDumpOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        level: libc::c_int,
        format: libc::c_int,
        encoding: *const libc::c_char,
    );
    fn xmlSaveFormatFileEnc(
        filename: *const libc::c_char,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
        format: libc::c_int,
    ) -> libc::c_int;
    fn xmlSaveFileEnc(
        filename: *const libc::c_char,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlIsXHTML(systemID: *const xmlChar, publicID: *const xmlChar) -> libc::c_int;
    fn xmlGetDocCompressMode(doc: *const xmlDoc) -> libc::c_int;
    fn xmlSetDocCompressMode(doc: xmlDocPtr, mode: libc::c_int);
    fn xmlGetCompressMode() -> libc::c_int;
    fn xmlSetCompressMode(mode: libc::c_int);
    fn xmlNextElementSibling(node: xmlNodePtr) -> xmlNodePtr;
    fn xmlFirstElementChild(parent: xmlNodePtr) -> xmlNodePtr;
    fn xmlLastElementChild(parent: xmlNodePtr) -> xmlNodePtr;
    fn xmlPreviousElementSibling(node: xmlNodePtr) -> xmlNodePtr;
    fn xmlGetLastError() -> xmlErrorPtr;
    fn xmlResetLastError();
    fn xmlResetError(err: xmlErrorPtr);
    fn xmlCopyError(from: xmlErrorPtr, to: xmlErrorPtr) -> libc::c_int;
    fn xmlGetID(doc: xmlDocPtr, ID: *const xmlChar) -> xmlAttrPtr;
    fn xmlIsID(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlRemoveID(doc: xmlDocPtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlIsRef(doc: xmlDocPtr, elem: xmlNodePtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlRemoveRef(doc: xmlDocPtr, attr: xmlAttrPtr) -> libc::c_int;
    fn xmlNewValidCtxt() -> xmlValidCtxtPtr;
    fn xmlValidateRoot(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> libc::c_int;
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
    fn xmlValidateDtd(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        dtd: xmlDtdPtr,
    ) -> libc::c_int;
    fn xmlValidateDtdFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> libc::c_int;
    fn xmlUTF8Strlen(utf: *const xmlChar) -> libc::c_int;
    fn xmlUTF8Charcmp(utf1: *const xmlChar, utf2: *const xmlChar) -> libc::c_int;
    fn xmlUTF8Size(utf: *const xmlChar) -> libc::c_int;
    fn xmlInitializePredefinedEntities();
    fn xmlNewEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: libc::c_int,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlAddDocEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: libc::c_int,
        ExternalID: *const xmlChar,
        SystemID: *const xmlChar,
        content: *const xmlChar,
    ) -> xmlEntityPtr;
    fn xmlAddDtdEntity(
        doc: xmlDocPtr,
        name: *const xmlChar,
        type_0: libc::c_int,
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
    fn xmlAddEncodingAlias(
        name: *const libc::c_char,
        alias: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlDelEncodingAlias(alias: *const libc::c_char) -> libc::c_int;
    fn xmlGetEncodingAlias(alias: *const libc::c_char) -> *const libc::c_char;
    fn xmlCleanupEncodingAliases();
    fn xmlCleanupInputCallbacks();
    fn xmlRegisterDefaultInputCallbacks();
    fn xmlParserInputBufferRead(
        in_0: xmlParserInputBufferPtr,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlParserInputBufferGrow(
        in_0: xmlParserInputBufferPtr,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlParserInputBufferPush(
        in_0: xmlParserInputBufferPtr,
        len: libc::c_int,
        buf: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlFreeParserInputBuffer(in_0: xmlParserInputBufferPtr);
    fn xmlParserGetDirectory(filename: *const libc::c_char) -> *mut libc::c_char;
    fn xmlCleanupOutputCallbacks();
    fn xmlPopOutputCallbacks() -> libc::c_int;
    fn xmlRegisterDefaultOutputCallbacks();
    fn xmlOutputBufferGetContent(out: xmlOutputBufferPtr) -> *const xmlChar;
    fn xmlOutputBufferWrite(
        out: xmlOutputBufferPtr,
        len: libc::c_int,
        buf: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlOutputBufferWriteString(
        out: xmlOutputBufferPtr,
        str: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlRegisterHTTPPostCallbacks();
    fn xmlNormalizeWindowsPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlCheckFilename(path: *const libc::c_char) -> libc::c_int;
    fn xmlFileMatch(filename: *const libc::c_char) -> libc::c_int;
    fn xmlIOHTTPMatch(filename: *const libc::c_char) -> libc::c_int;
    fn xmlIOFTPMatch(filename: *const libc::c_char) -> libc::c_int;
    fn xmlInitParser();
    fn xmlParseDoc(cur: *const xmlChar) -> xmlDocPtr;
    fn xmlParseFile(filename: *const libc::c_char) -> xmlDocPtr;
    fn xmlParseMemory(buffer: *const libc::c_char, size: libc::c_int) -> xmlDocPtr;
    fn xmlSubstituteEntitiesDefault(val: libc::c_int) -> libc::c_int;
    fn xmlKeepBlanksDefault(val: libc::c_int) -> libc::c_int;
    fn xmlStopParser(ctxt: xmlParserCtxtPtr);
    fn xmlPedanticParserDefault(val: libc::c_int) -> libc::c_int;
    fn xmlLineNumbersDefault(val: libc::c_int) -> libc::c_int;
    fn xmlRecoverDoc(cur: *const xmlChar) -> xmlDocPtr;
    fn xmlRecoverMemory(buffer: *const libc::c_char, size: libc::c_int) -> xmlDocPtr;
    fn xmlRecoverFile(filename: *const libc::c_char) -> xmlDocPtr;
    fn xmlParseDocument(ctxt: xmlParserCtxtPtr) -> libc::c_int;
    fn xmlParseExtParsedEnt(ctxt: xmlParserCtxtPtr) -> libc::c_int;
    fn xmlParseEntity(filename: *const libc::c_char) -> xmlDocPtr;
    fn xmlParseDTD(ExternalID: *const xmlChar, SystemID: *const xmlChar) -> xmlDtdPtr;
    fn xmlNewParserCtxt() -> xmlParserCtxtPtr;
    fn xmlInitParserCtxt(ctxt: xmlParserCtxtPtr) -> libc::c_int;
    fn xmlClearParserCtxt(ctxt: xmlParserCtxtPtr);
    fn xmlSetupParserForBuffer(
        ctxt: xmlParserCtxtPtr,
        buffer: *const xmlChar,
        filename: *const libc::c_char,
    );
    fn xmlCreateDocParserCtxt(cur: *const xmlChar) -> xmlParserCtxtPtr;
    fn xmlParseChunk(
        ctxt: xmlParserCtxtPtr,
        chunk: *const libc::c_char,
        size: libc::c_int,
        terminate: libc::c_int,
    ) -> libc::c_int;
    fn xmlByteConsumed(ctxt: xmlParserCtxtPtr) -> libc::c_long;
    fn xmlCtxtReset(ctxt: xmlParserCtxtPtr);
    fn xmlCtxtResetPush(
        ctxt: xmlParserCtxtPtr,
        chunk: *const libc::c_char,
        size: libc::c_int,
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlCtxtUseOptions(ctxt: xmlParserCtxtPtr, options: libc::c_int) -> libc::c_int;
    fn xmlReadDoc(
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlReadFile(
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlReadMemory(
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlReadFd(
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlCtxtReadDoc(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlCtxtReadFile(
        ctxt: xmlParserCtxtPtr,
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlCtxtReadMemory(
        ctxt: xmlParserCtxtPtr,
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlCtxtReadFd(
        ctxt: xmlParserCtxtPtr,
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlDocPtr;
    fn xmlSAXDefaultVersion(version: libc::c_int) -> libc::c_int;
    fn htmlDefaultSAXHandlerInit();
    fn xmlDefaultSAXHandlerInit();
    fn xmlInitGlobals();
    fn xmlCleanupGlobals();
    static mut xmlFree: xmlFreeFunc;
    fn xmlThrDefDefaultBufferSize(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefDoValidityCheckingDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefGetWarningsDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefIndentTreeOutput(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefTreeIndentString(v: *const libc::c_char) -> *const libc::c_char;
    fn xmlThrDefKeepBlanksDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefLineNumbersDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefLoadExtDtdDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefParserDebugEntities(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefPedanticParserDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefSaveNoEmptyTags(v: libc::c_int) -> libc::c_int;
    fn xmlThrDefSubstituteEntitiesDefaultValue(v: libc::c_int) -> libc::c_int;
    fn xmlGetDtdElementDesc(dtd: xmlDtdPtr, name: *const xmlChar) -> xmlElementPtr;
    fn xmlIsMixedElement(doc: xmlDocPtr, name: *const xmlChar) -> libc::c_int;
    fn xmlValidateNotationUse(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        notationName: *const xmlChar,
    ) -> libc::c_int;
    fn xmlValidateDocumentFinal(ctxt: xmlValidCtxtPtr, doc: xmlDocPtr) -> libc::c_int;
    fn xmlValidateOneNamespace(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        prefix: *const xmlChar,
        ns: xmlNsPtr,
        value: *const xmlChar,
    ) -> libc::c_int;
    fn xmlValidateOneAttribute(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        attr: xmlAttrPtr,
        value: *const xmlChar,
    ) -> libc::c_int;
    fn xmlValidateOneElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlValidateElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
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
    fn xmlValidateNameValue(value: *const xmlChar) -> libc::c_int;
    fn xmlValidateNamesValue(value: *const xmlChar) -> libc::c_int;
    fn xmlValidateNmtokenValue(value: *const xmlChar) -> libc::c_int;
    fn xmlValidateNmtokensValue(value: *const xmlChar) -> libc::c_int;
    fn xmlValidatePushElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> libc::c_int;
    fn xmlValidatePushCData(
        ctxt: xmlValidCtxtPtr,
        data: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlValidatePopElement(
        ctxt: xmlValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
        qname: *const xmlChar,
    ) -> libc::c_int;
    fn xmlSchemaValidCtxtGetParserCtxt(ctxt: xmlSchemaValidCtxtPtr) -> xmlParserCtxtPtr;
    fn xmlSchemaNewParserCtxt(URL: *const libc::c_char) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaNewMemParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaNewDocParserCtxt(doc: xmlDocPtr) -> xmlSchemaParserCtxtPtr;
    fn xmlSchemaFreeParserCtxt(ctxt: xmlSchemaParserCtxtPtr);
    fn xmlSchemaIsValid(ctxt: xmlSchemaValidCtxtPtr) -> libc::c_int;
    fn xmlSchemaParse(ctxt: xmlSchemaParserCtxtPtr) -> xmlSchemaPtr;
    fn xmlSchemaFree(schema: xmlSchemaPtr);
    fn xmlSchemaDump(output: *mut FILE, schema: xmlSchemaPtr);
    fn xmlSchemaSetValidOptions(
        ctxt: xmlSchemaValidCtxtPtr,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlSchemaValidateSetFilename(
        vctxt: xmlSchemaValidCtxtPtr,
        filename: *const libc::c_char,
    );
    fn xmlSchemaValidCtxtGetOptions(ctxt: xmlSchemaValidCtxtPtr) -> libc::c_int;
    fn xmlSchemaNewValidCtxt(schema: xmlSchemaPtr) -> xmlSchemaValidCtxtPtr;
    fn xmlSchemaValidateDoc(
        ctxt: xmlSchemaValidCtxtPtr,
        instance: xmlDocPtr,
    ) -> libc::c_int;
    fn xmlSchemaValidateOneElement(
        ctxt: xmlSchemaValidCtxtPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlSchemaValidateFile(
        ctxt: xmlSchemaValidCtxtPtr,
        filename: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlSchemaInitTypes();
    fn xmlSchemaCleanupTypes();
    fn xmlSchemaCollapseString(value: *const xmlChar) -> *mut xmlChar;
    fn xmlSchemaWhiteSpaceReplace(value: *const xmlChar) -> *mut xmlChar;
    fn xmlNewTextReader(
        input: xmlParserInputBufferPtr,
        URI: *const libc::c_char,
    ) -> xmlTextReaderPtr;
    fn xmlNewTextReaderFilename(URI: *const libc::c_char) -> xmlTextReaderPtr;
    fn xmlTextReaderSetup(
        reader: xmlTextReaderPtr,
        input: xmlParserInputBufferPtr,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderRead(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderReadInnerXml(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadOuterXml(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadString(reader: xmlTextReaderPtr) -> *mut xmlChar;
    fn xmlTextReaderReadAttributeValue(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderAttributeCount(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderDepth(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderHasAttributes(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderHasValue(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderIsDefault(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderIsEmptyElement(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderNodeType(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderQuoteChar(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderReadState(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderIsNamespaceDecl(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderConstBaseUri(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstLocalName(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstName(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstNamespaceUri(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstPrefix(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstXmlLang(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderConstString(
        reader: xmlTextReaderPtr,
        str: *const xmlChar,
    ) -> *const xmlChar;
    fn xmlTextReaderConstValue(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderClose(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderGetAttributeNo(
        reader: xmlTextReaderPtr,
        no: libc::c_int,
    ) -> *mut xmlChar;
    fn xmlTextReaderGetAttribute(
        reader: xmlTextReaderPtr,
        name: *const xmlChar,
    ) -> *mut xmlChar;
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
    fn xmlTextReaderMoveToAttributeNo(
        reader: xmlTextReaderPtr,
        no: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderMoveToAttribute(
        reader: xmlTextReaderPtr,
        name: *const xmlChar,
    ) -> libc::c_int;
    fn xmlTextReaderMoveToAttributeNs(
        reader: xmlTextReaderPtr,
        localName: *const xmlChar,
        namespaceURI: *const xmlChar,
    ) -> libc::c_int;
    fn xmlTextReaderMoveToFirstAttribute(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderMoveToNextAttribute(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderMoveToElement(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderNormalization(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderConstEncoding(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderSetParserProp(
        reader: xmlTextReaderPtr,
        prop: libc::c_int,
        value: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderGetParserProp(
        reader: xmlTextReaderPtr,
        prop: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderCurrentNode(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderGetParserLineNumber(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderGetParserColumnNumber(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderPreserve(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderCurrentDoc(reader: xmlTextReaderPtr) -> xmlDocPtr;
    fn xmlTextReaderExpand(reader: xmlTextReaderPtr) -> xmlNodePtr;
    fn xmlTextReaderNext(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderNextSibling(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderIsValid(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderRelaxNGValidate(
        reader: xmlTextReaderPtr,
        rng: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlTextReaderRelaxNGValidateCtxt(
        reader: xmlTextReaderPtr,
        ctxt: xmlRelaxNGValidCtxtPtr,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderRelaxNGSetSchema(
        reader: xmlTextReaderPtr,
        schema: xmlRelaxNGPtr,
    ) -> libc::c_int;
    fn xmlTextReaderSchemaValidate(
        reader: xmlTextReaderPtr,
        xsd: *const libc::c_char,
    ) -> libc::c_int;
    fn xmlTextReaderSchemaValidateCtxt(
        reader: xmlTextReaderPtr,
        ctxt: xmlSchemaValidCtxtPtr,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderSetSchema(
        reader: xmlTextReaderPtr,
        schema: xmlSchemaPtr,
    ) -> libc::c_int;
    fn xmlTextReaderConstXmlVersion(reader: xmlTextReaderPtr) -> *const xmlChar;
    fn xmlTextReaderStandalone(reader: xmlTextReaderPtr) -> libc::c_int;
    fn xmlTextReaderByteConsumed(reader: xmlTextReaderPtr) -> libc::c_long;
    fn xmlUCSIsLinearBSyllabary(code: libc::c_int) -> libc::c_int;
    fn xmlIsLetter(c: libc::c_int) -> libc::c_int;
    fn xmlCreateFileParserCtxt(filename: *const libc::c_char) -> xmlParserCtxtPtr;
    fn xmlCreateURLParserCtxt(
        filename: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlParserCtxtPtr;
    fn xmlCreateMemoryParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> xmlParserCtxtPtr;
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
    fn xmlParseCharData(ctxt: xmlParserCtxtPtr, cdata: libc::c_int);
    fn xmlParseComment(ctxt: xmlParserCtxtPtr);
    fn xmlParsePITarget(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn xmlParsePI(ctxt: xmlParserCtxtPtr);
    fn xmlParseNotationDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseEntityDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseAttributeListDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseElementDecl(ctxt: xmlParserCtxtPtr) -> libc::c_int;
    fn xmlParseMarkupDecl(ctxt: xmlParserCtxtPtr);
    fn xmlParseCharRef(ctxt: xmlParserCtxtPtr) -> libc::c_int;
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
    fn xmlParseSDDecl(ctxt: xmlParserCtxtPtr) -> libc::c_int;
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
        what: libc::c_int,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn xmlStringLenDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        str: *const xmlChar,
        len: libc::c_int,
        what: libc::c_int,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn nodePush(ctxt: xmlParserCtxtPtr, value: xmlNodePtr) -> libc::c_int;
    fn nodePop(ctxt: xmlParserCtxtPtr) -> xmlNodePtr;
    fn namePop(ctxt: xmlParserCtxtPtr) -> *const xmlChar;
    fn namePush(ctxt: xmlParserCtxtPtr, value: *const xmlChar) -> libc::c_int;
    fn xmlSkipBlankChars(ctxt: xmlParserCtxtPtr) -> libc::c_int;
    fn xmlParserHandlePEReference(ctxt: xmlParserCtxtPtr);
    fn xmlCheckLanguageID(lang: *const xmlChar) -> libc::c_int;
    fn xmlCopyCharMultiByte(out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    fn xmlCopyChar(len: libc::c_int, out: *mut xmlChar, val: libc::c_int) -> libc::c_int;
    fn xmlNextChar(ctxt: xmlParserCtxtPtr);
    fn htmlInitAutoClose();
    fn htmlCreateFileParserCtxt(
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
    ) -> htmlParserCtxtPtr;
    fn xmlParseQuotedString(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParseNamespace(ctxt: xmlParserCtxtPtr);
    fn xmlNamespaceParseNSDef(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlScanName(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlNamespaceParseNCName(ctxt: xmlParserCtxtPtr) -> *mut xmlChar;
    fn xmlParserHandleReference(ctxt: xmlParserCtxtPtr);
    fn xmlDecodeEntities(
        ctxt: xmlParserCtxtPtr,
        len: libc::c_int,
        what: libc::c_int,
        end: xmlChar,
        end2: xmlChar,
        end3: xmlChar,
    ) -> *mut xmlChar;
    fn xmlHandleEntity(ctxt: xmlParserCtxtPtr, entity: xmlEntityPtr);
    fn xmlNewCatalog(sgml: libc::c_int) -> xmlCatalogPtr;
    fn xmlLoadACatalog(filename: *const libc::c_char) -> xmlCatalogPtr;
    fn xmlLoadSGMLSuperCatalog(filename: *const libc::c_char) -> xmlCatalogPtr;
    fn xmlConvertSGMLCatalog(catal: xmlCatalogPtr) -> libc::c_int;
    fn xmlACatalogAdd(
        catal: xmlCatalogPtr,
        type_0: *const xmlChar,
        orig: *const xmlChar,
        replace: *const xmlChar,
    ) -> libc::c_int;
    fn xmlACatalogRemove(catal: xmlCatalogPtr, value: *const xmlChar) -> libc::c_int;
    fn xmlACatalogResolve(
        catal: xmlCatalogPtr,
        pubID: *const xmlChar,
        sysID: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlACatalogResolveSystem(
        catal: xmlCatalogPtr,
        sysID: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlACatalogResolvePublic(
        catal: xmlCatalogPtr,
        pubID: *const xmlChar,
    ) -> *mut xmlChar;
    fn xmlACatalogResolveURI(catal: xmlCatalogPtr, URI: *const xmlChar) -> *mut xmlChar;
    fn xmlACatalogDump(catal: xmlCatalogPtr, out: *mut FILE);
    fn xmlFreeCatalog(catal: xmlCatalogPtr);
    fn xmlCatalogIsEmpty(catal: xmlCatalogPtr) -> libc::c_int;
    fn xmlInitializeCatalog();
    fn xmlLoadCatalog(filename: *const libc::c_char) -> libc::c_int;
    fn xmlLoadCatalogs(paths: *const libc::c_char);
    fn xmlCatalogCleanup();
    fn xmlCatalogDump(out: *mut FILE);
    fn xmlCatalogResolve(pubID: *const xmlChar, sysID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolveSystem(sysID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolvePublic(pubID: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogResolveURI(URI: *const xmlChar) -> *mut xmlChar;
    fn xmlCatalogAdd(
        type_0: *const xmlChar,
        orig: *const xmlChar,
        replace: *const xmlChar,
    ) -> libc::c_int;
    fn xmlCatalogRemove(value: *const xmlChar) -> libc::c_int;
    fn xmlParseCatalogFile(filename: *const libc::c_char) -> xmlDocPtr;
    fn xmlCatalogConvert() -> libc::c_int;
    fn xmlCatalogSetDebug(level: libc::c_int) -> libc::c_int;
    fn xmlCatalogGetSystem(sysID: *const xmlChar) -> *const xmlChar;
    fn xmlCatalogGetPublic(pubID: *const xmlChar) -> *const xmlChar;
    fn xmlNanoFTPInit();
    fn xmlNanoFTPCleanup();
    fn xmlNanoFTPScanProxy(URL: *const libc::c_char);
    fn xmlNanoFTPProxy(
        host: *const libc::c_char,
        port: libc::c_int,
        user: *const libc::c_char,
        passwd: *const libc::c_char,
        type_0: libc::c_int,
    );
    fn xmlNanoHTTPInit();
    fn xmlNanoHTTPCleanup();
    fn xmlNanoHTTPScanProxy(URL: *const libc::c_char);
    fn xmlCreateURI() -> xmlURIPtr;
    fn xmlBuildURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlBuildRelativeURI(URI: *const xmlChar, base: *const xmlChar) -> *mut xmlChar;
    fn xmlParseURI(str: *const libc::c_char) -> xmlURIPtr;
    fn xmlParseURIRaw(str: *const libc::c_char, raw: libc::c_int) -> xmlURIPtr;
    fn xmlParseURIReference(uri: xmlURIPtr, str: *const libc::c_char) -> libc::c_int;
    fn xmlSaveUri(uri: xmlURIPtr) -> *mut xmlChar;
    fn xmlPrintURI(stream: *mut FILE, uri: xmlURIPtr);
    fn xmlURIEscapeStr(str: *const xmlChar, list: *const xmlChar) -> *mut xmlChar;
    fn xmlURIUnescapeString(
        str: *const libc::c_char,
        len: libc::c_int,
        target: *mut libc::c_char,
    ) -> *mut libc::c_char;
    fn xmlNormalizeURIPath(path: *mut libc::c_char) -> libc::c_int;
    fn xmlURIEscape(str: *const xmlChar) -> *mut xmlChar;
    fn xmlFreeURI(uri: xmlURIPtr);
    fn xmlCanonicPath(path: *const xmlChar) -> *mut xmlChar;
    fn xmlPathToURI(path: *const xmlChar) -> *mut xmlChar;
    fn xmlXPathCmpNodes(node1: xmlNodePtr, node2: xmlNodePtr) -> libc::c_int;
    fn xmlXPathCastNumberToBoolean(val: libc::c_double) -> libc::c_int;
    fn xmlXPathCastStringToBoolean(val: *const xmlChar) -> libc::c_int;
    fn xmlXPathCastBooleanToNumber(val: libc::c_int) -> libc::c_double;
    fn xmlXPathCastStringToNumber(val: *const xmlChar) -> libc::c_double;
    fn xmlXPathCastNodeToNumber(node: xmlNodePtr) -> libc::c_double;
    fn xmlXPathCastBooleanToString(val: libc::c_int) -> *mut xmlChar;
    fn xmlXPathCastNumberToString(val: libc::c_double) -> *mut xmlChar;
    fn xmlXPathCastNodeToString(node: xmlNodePtr) -> *mut xmlChar;
    fn xmlXPathNewContext(doc: xmlDocPtr) -> xmlXPathContextPtr;
    fn xmlXPathFreeContext(ctxt: xmlXPathContextPtr);
    fn xmlXPathContextSetCache(
        ctxt: xmlXPathContextPtr,
        active: libc::c_int,
        value: libc::c_int,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlXPathOrderDocElems(doc: xmlDocPtr) -> libc::c_long;
    fn xmlXPathNodeEval(
        node: xmlNodePtr,
        str: *const xmlChar,
        ctx: xmlXPathContextPtr,
    ) -> xmlXPathObjectPtr;
    fn xmlXPathEval(str: *const xmlChar, ctx: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlXPathEvalExpression(
        str: *const xmlChar,
        ctxt: xmlXPathContextPtr,
    ) -> xmlXPathObjectPtr;
    fn xmlXPathInit();
    fn xmlXPathIsNaN(val: libc::c_double) -> libc::c_int;
    fn xmlXPathIsInf(val: libc::c_double) -> libc::c_int;
    fn xmlXPathPopBoolean(ctxt: xmlXPathParserContextPtr) -> libc::c_int;
    fn xmlXPathPopNumber(ctxt: xmlXPathParserContextPtr) -> libc::c_double;
    fn xmlXPathPopString(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPatherror(
        ctxt: xmlXPathParserContextPtr,
        file: *const libc::c_char,
        line: libc::c_int,
        no: libc::c_int,
    );
    fn xmlXPathErr(ctxt: xmlXPathParserContextPtr, error: libc::c_int);
    fn xmlXPathRegisterNs(
        ctxt: xmlXPathContextPtr,
        prefix: *const xmlChar,
        ns_uri: *const xmlChar,
    ) -> libc::c_int;
    fn xmlXPathNsLookup(
        ctxt: xmlXPathContextPtr,
        prefix: *const xmlChar,
    ) -> *const xmlChar;
    fn xmlXPathRegisteredNsCleanup(ctxt: xmlXPathContextPtr);
    fn xmlXPathRegisteredFuncsCleanup(ctxt: xmlXPathContextPtr);
    fn xmlXPathVariableLookup(
        ctxt: xmlXPathContextPtr,
        name: *const xmlChar,
    ) -> xmlXPathObjectPtr;
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
    fn xmlXPathNewCString(val: *const libc::c_char) -> xmlXPathObjectPtr;
    fn xmlXPathNewFloat(val: libc::c_double) -> xmlXPathObjectPtr;
    fn xmlXPathNewBoolean(val: libc::c_int) -> xmlXPathObjectPtr;
    fn xmlXPathNewNodeSet(val: xmlNodePtr) -> xmlXPathObjectPtr;
    fn xmlXPathNewValueTree(val: xmlNodePtr) -> xmlXPathObjectPtr;
    fn xmlXPathRoot(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathEvalExpr(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathParseName(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPathParseNCName(ctxt: xmlXPathParserContextPtr) -> *mut xmlChar;
    fn xmlXPathStringEvalNumber(str: *const xmlChar) -> libc::c_double;
    fn xmlXPathRegisterAllFunctions(ctxt: xmlXPathContextPtr);
    fn xmlXPathEqualValues(ctxt: xmlXPathParserContextPtr) -> libc::c_int;
    fn xmlXPathNotEqualValues(ctxt: xmlXPathParserContextPtr) -> libc::c_int;
    fn xmlXPathCompareValues(
        ctxt: xmlXPathParserContextPtr,
        inf: libc::c_int,
        strict: libc::c_int,
    ) -> libc::c_int;
    fn xmlXPathValueFlipSign(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathAddValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathSubValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathMultValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathDivValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathModValues(ctxt: xmlXPathParserContextPtr);
    fn xmlXPathIsNodeType(name: *const xmlChar) -> libc::c_int;
    fn xmlXPathNextSelf(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextChild(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextDescendant(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextDescendantOrSelf(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextParent(ctxt: xmlXPathParserContextPtr, cur: xmlNodePtr) -> xmlNodePtr;
    fn xmlXPathNextAncestorOrSelf(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextFollowingSibling(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextFollowing(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextNamespace(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextAttribute(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextPreceding(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextAncestor(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathNextPrecedingSibling(
        ctxt: xmlXPathParserContextPtr,
        cur: xmlNodePtr,
    ) -> xmlNodePtr;
    fn xmlXPathLastFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathPositionFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathCountFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathIdFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathLocalNameFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathNamespaceURIFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathStringFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathStringLengthFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathConcatFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathContainsFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathStartsWithFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathSubstringFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathSubstringBeforeFunction(
        ctxt: xmlXPathParserContextPtr,
        nargs: libc::c_int,
    );
    fn xmlXPathSubstringAfterFunction(
        ctxt: xmlXPathParserContextPtr,
        nargs: libc::c_int,
    );
    fn xmlXPathNormalizeFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathTranslateFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathNotFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathTrueFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathFalseFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathLangFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathNumberFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathSumFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathFloorFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathCeilingFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathRoundFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathBooleanFunction(ctxt: xmlXPathParserContextPtr, nargs: libc::c_int);
    fn xmlXPathNodeSetFreeNs(ns: xmlNsPtr);
    fn xmlDebugDumpString(output: *mut FILE, str: *const xmlChar);
    fn xmlDebugDumpAttr(output: *mut FILE, attr: xmlAttrPtr, depth: libc::c_int);
    fn xmlDebugDumpAttrList(output: *mut FILE, attr: xmlAttrPtr, depth: libc::c_int);
    fn xmlDebugDumpOneNode(output: *mut FILE, node: xmlNodePtr, depth: libc::c_int);
    fn xmlDebugDumpNode(output: *mut FILE, node: xmlNodePtr, depth: libc::c_int);
    fn xmlDebugDumpNodeList(output: *mut FILE, node: xmlNodePtr, depth: libc::c_int);
    fn xmlDebugDumpDocumentHead(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugDumpDocument(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugDumpDTD(output: *mut FILE, dtd: xmlDtdPtr);
    fn xmlDebugDumpEntities(output: *mut FILE, doc: xmlDocPtr);
    fn xmlDebugCheckDocument(output: *mut FILE, doc: xmlDocPtr) -> libc::c_int;
    fn xmlLsOneNode(output: *mut FILE, node: xmlNodePtr);
    fn xmlLsCountNode(node: xmlNodePtr) -> libc::c_int;
    fn xmlBoolToText(boolval: libc::c_int) -> *const libc::c_char;
    fn xmlShellPrintXPathError(errorType: libc::c_int, arg: *const libc::c_char);
    fn xmlShellPrintNode(node: xmlNodePtr);
    fn htmlNewDoc(URI: *const xmlChar, ExternalID: *const xmlChar) -> htmlDocPtr;
    fn htmlNewDocNoDtD(URI: *const xmlChar, ExternalID: *const xmlChar) -> htmlDocPtr;
    fn htmlGetMetaEncoding(doc: htmlDocPtr) -> *const xmlChar;
    fn htmlSetMetaEncoding(doc: htmlDocPtr, encoding: *const xmlChar) -> libc::c_int;
    fn htmlDocDump(f: *mut FILE, cur: xmlDocPtr) -> libc::c_int;
    fn htmlSaveFile(filename: *const libc::c_char, cur: xmlDocPtr) -> libc::c_int;
    fn htmlNodeDumpFile(out: *mut FILE, doc: xmlDocPtr, cur: xmlNodePtr);
    fn htmlNodeDumpFileFormat(
        out: *mut FILE,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const libc::c_char,
        format: libc::c_int,
    ) -> libc::c_int;
    fn htmlSaveFileEnc(
        filename: *const libc::c_char,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
    ) -> libc::c_int;
    fn htmlSaveFileFormat(
        filename: *const libc::c_char,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
        format: libc::c_int,
    ) -> libc::c_int;
    fn htmlNodeDumpFormatOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const libc::c_char,
        format: libc::c_int,
    );
    fn htmlDocContentDumpOutput(
        buf: xmlOutputBufferPtr,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
    );
    fn htmlDocContentDumpFormatOutput(
        buf: xmlOutputBufferPtr,
        cur: xmlDocPtr,
        encoding: *const libc::c_char,
        format: libc::c_int,
    );
    fn htmlNodeDumpOutput(
        buf: xmlOutputBufferPtr,
        doc: xmlDocPtr,
        cur: xmlNodePtr,
        encoding: *const libc::c_char,
    );
    fn htmlIsBooleanAttr(name: *const xmlChar) -> libc::c_int;
    fn xmlXIncludeProcess(doc: xmlDocPtr) -> libc::c_int;
    fn xmlXIncludeProcessFlags(doc: xmlDocPtr, flags: libc::c_int) -> libc::c_int;
    fn xmlXIncludeProcessTree(tree: xmlNodePtr) -> libc::c_int;
    fn xmlXIncludeProcessTreeFlags(tree: xmlNodePtr, flags: libc::c_int) -> libc::c_int;
    fn xmlXPtrNewContext(
        doc: xmlDocPtr,
        here: xmlNodePtr,
        origin: xmlNodePtr,
    ) -> xmlXPathContextPtr;
    fn xmlXPtrEval(str: *const xmlChar, ctx: xmlXPathContextPtr) -> xmlXPathObjectPtr;
    fn xmlUCSIsAegeanNumbers(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsAlphabeticPresentationForms(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsArabic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsArabicPresentationFormsA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsArabicPresentationFormsB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsArmenian(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsArrows(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBasicLatin(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBengali(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBlockElements(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBopomofo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBopomofoExtended(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBoxDrawing(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBraillePatterns(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBuhid(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsByzantineMusicalSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKCompatibility(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKCompatibilityForms(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKCompatibilityIdeographs(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKCompatibilityIdeographsSupplement(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKRadicalsSupplement(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKSymbolsandPunctuation(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKUnifiedIdeographs(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKUnifiedIdeographsExtensionA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCJKUnifiedIdeographsExtensionB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCherokee(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCombiningDiacriticalMarks(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCombiningDiacriticalMarksforSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCombiningHalfMarks(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCombiningMarksforSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsControlPictures(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCurrencySymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCypriotSyllabary(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCyrillic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCyrillicSupplement(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsDeseret(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsDevanagari(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsDingbats(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsEnclosedAlphanumerics(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsEnclosedCJKLettersandMonths(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsEthiopic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGeneralPunctuation(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGeometricShapes(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGeorgian(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGothic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGreek(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGreekExtended(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGreekandCoptic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGujarati(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsGurmukhi(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHalfwidthandFullwidthForms(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHangulCompatibilityJamo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHangulJamo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHangulSyllables(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHanunoo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHebrew(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHighPrivateUseSurrogates(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHighSurrogates(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsHiragana(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsIPAExtensions(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsIdeographicDescriptionCharacters(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKanbun(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKangxiRadicals(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKannada(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKatakana(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKatakanaPhoneticExtensions(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKhmer(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsKhmerSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLao(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLatin1Supplement(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLatinExtendedA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLatinExtendedB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLatinExtendedAdditional(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLetterlikeSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLimbu(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLinearBIdeograms(code: libc::c_int) -> libc::c_int;
    fn xmlIsPubidChar(ch: libc::c_uint) -> libc::c_int;
    fn libxml_deprecationWarning(func: *const libc::c_char) -> libc::c_int;
    fn libxml_xmlErrorPtrWrap(error: xmlErrorPtr) -> *mut PyObject;
    fn libxml_xmlSchemaValidCtxtPtrWrap(valid: xmlSchemaValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlSchemaParserCtxtPtrWrap(ctxt: xmlSchemaParserCtxtPtr) -> *mut PyObject;
    fn libxml_xmlSchemaPtrWrap(ctxt: xmlSchemaPtr) -> *mut PyObject;
    fn libxml_xmlRelaxNGValidCtxtPtrWrap(valid: xmlRelaxNGValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlRelaxNGParserCtxtPtrWrap(
        ctxt: xmlRelaxNGParserCtxtPtr,
    ) -> *mut PyObject;
    fn libxml_xmlRelaxNGPtrWrap(ctxt: xmlRelaxNGPtr) -> *mut PyObject;
    fn libxml_xmlTextReaderPtrWrap(reader: xmlTextReaderPtr) -> *mut PyObject;
    fn libxml_xmlRegexpPtrWrap(regexp: xmlRegexpPtr) -> *mut PyObject;
    fn libxml_xmlParserInputBufferPtrWrap(
        buffer: xmlParserInputBufferPtr,
    ) -> *mut PyObject;
    fn libxml_xmlURIPtrWrap(uri: xmlURIPtr) -> *mut PyObject;
    fn libxml_xmlCatalogPtrWrap(obj: xmlCatalogPtr) -> *mut PyObject;
    fn libxml_xmlValidCtxtPtrWrap(valid: xmlValidCtxtPtr) -> *mut PyObject;
    fn libxml_xmlXPathObjectPtrWrap(obj: xmlXPathObjectPtr) -> *mut PyObject;
    fn libxml_xmlXPathParserContextPtrWrap(
        ctxt: xmlXPathParserContextPtr,
    ) -> *mut PyObject;
    fn libxml_xmlParserCtxtPtrWrap(ctxt: xmlParserCtxtPtr) -> *mut PyObject;
    fn libxml_xmlXPathContextPtrWrap(ctxt: xmlXPathContextPtr) -> *mut PyObject;
    fn libxml_doubleWrap(val: libc::c_double) -> *mut PyObject;
    fn libxml_xmlElementPtrWrap(ns: xmlElementPtr) -> *mut PyObject;
    fn libxml_xmlAttributePtrWrap(ns: xmlAttributePtr) -> *mut PyObject;
    fn libxml_xmlNsPtrWrap(ns: xmlNsPtr) -> *mut PyObject;
    fn libxml_xmlNodePtrWrap(node: xmlNodePtr) -> *mut PyObject;
    fn libxml_xmlDocPtrWrap(doc: xmlDocPtr) -> *mut PyObject;
    fn libxml_xmlCharPtrConstWrap(str: *const xmlChar) -> *mut PyObject;
    fn libxml_charPtrConstWrap(str: *const libc::c_char) -> *mut PyObject;
    fn libxml_charPtrWrap(str: *mut libc::c_char) -> *mut PyObject;
    fn libxml_xmlCharPtrWrap(str: *mut xmlChar) -> *mut PyObject;
    fn libxml_longWrap(val: libc::c_long) -> *mut PyObject;
    fn libxml_intWrap(val: libc::c_int) -> *mut PyObject;
    fn xmlRelaxNGInitTypes() -> libc::c_int;
    fn xmlRelaxNGCleanupTypes();
    fn xmlRelaxNGNewParserCtxt(URL: *const libc::c_char) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxNGNewMemParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxNGNewDocParserCtxt(doc: xmlDocPtr) -> xmlRelaxNGParserCtxtPtr;
    fn xmlRelaxParserSetFlag(
        ctxt: xmlRelaxNGParserCtxtPtr,
        flag: libc::c_int,
    ) -> libc::c_int;
    fn xmlRelaxNGFreeParserCtxt(ctxt: xmlRelaxNGParserCtxtPtr);
    fn xmlRelaxNGParse(ctxt: xmlRelaxNGParserCtxtPtr) -> xmlRelaxNGPtr;
    fn xmlRelaxNGFree(schema: xmlRelaxNGPtr);
    fn xmlRelaxNGDump(output: *mut FILE, schema: xmlRelaxNGPtr);
    fn xmlRelaxNGDumpTree(output: *mut FILE, schema: xmlRelaxNGPtr);
    fn xmlRelaxNGNewValidCtxt(schema: xmlRelaxNGPtr) -> xmlRelaxNGValidCtxtPtr;
    fn xmlRelaxNGValidateDoc(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
    ) -> libc::c_int;
    fn xmlRelaxNGValidatePushElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlRelaxNGValidatePushCData(
        ctxt: xmlRelaxNGValidCtxtPtr,
        data: *const xmlChar,
        len: libc::c_int,
    ) -> libc::c_int;
    fn xmlRelaxNGValidatePopElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlRelaxNGValidateFullElement(
        ctxt: xmlRelaxNGValidCtxtPtr,
        doc: xmlDocPtr,
        elem: xmlNodePtr,
    ) -> libc::c_int;
    fn xmlIsIdeographic(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsExtender(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsDigit(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsCombining(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsChar(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsBlank(ch: libc::c_uint) -> libc::c_int;
    fn xmlIsBaseChar(ch: libc::c_uint) -> libc::c_int;
    fn htmlCtxtReadFd(
        ctxt: xmlParserCtxtPtr,
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlCtxtReadMemory(
        ctxt: xmlParserCtxtPtr,
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlCtxtReadFile(
        ctxt: xmlParserCtxtPtr,
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlCtxtReadDoc(
        ctxt: xmlParserCtxtPtr,
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlReadFd(
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlReadMemory(
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlReadFile(
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlReadDoc(
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> htmlDocPtr;
    fn htmlCtxtUseOptions(ctxt: htmlParserCtxtPtr, options: libc::c_int) -> libc::c_int;
    fn htmlCtxtReset(ctxt: htmlParserCtxtPtr);
    fn htmlFreeParserCtxt(ctxt: htmlParserCtxtPtr);
    fn htmlParseChunk(
        ctxt: htmlParserCtxtPtr,
        chunk: *const libc::c_char,
        size: libc::c_int,
        terminate: libc::c_int,
    ) -> libc::c_int;
    fn htmlHandleOmittedElem(val: libc::c_int) -> libc::c_int;
    fn htmlIsScriptAttribute(name: *const xmlChar) -> libc::c_int;
    fn htmlParseFile(
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
    ) -> htmlDocPtr;
    fn htmlParseDoc(cur: *const xmlChar, encoding: *const libc::c_char) -> htmlDocPtr;
    fn htmlParseDocument(ctxt: htmlParserCtxtPtr) -> libc::c_int;
    fn htmlCreateMemoryParserCtxt(
        buffer: *const libc::c_char,
        size: libc::c_int,
    ) -> htmlParserCtxtPtr;
    fn htmlNewParserCtxt() -> htmlParserCtxtPtr;
    fn htmlParseElement(ctxt: htmlParserCtxtPtr);
    fn htmlParseCharRef(ctxt: htmlParserCtxtPtr) -> libc::c_int;
    fn htmlAutoCloseTag(
        doc: htmlDocPtr,
        name: *const xmlChar,
        elem: htmlNodePtr,
    ) -> libc::c_int;
    fn htmlIsAutoClosed(doc: htmlDocPtr, elem: htmlNodePtr) -> libc::c_int;
    fn xmlReaderWalker(doc: xmlDocPtr) -> xmlTextReaderPtr;
    fn xmlReaderForDoc(
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlTextReaderPtr;
    fn xmlReaderForFile(
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlTextReaderPtr;
    fn xmlReaderForMemory(
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlTextReaderPtr;
    fn xmlReaderForFd(
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> xmlTextReaderPtr;
    fn xmlReaderNewWalker(reader: xmlTextReaderPtr, doc: xmlDocPtr) -> libc::c_int;
    fn xmlReaderNewDoc(
        reader: xmlTextReaderPtr,
        cur: *const xmlChar,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlReaderNewFile(
        reader: xmlTextReaderPtr,
        filename: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlReaderNewMemory(
        reader: xmlTextReaderPtr,
        buffer: *const libc::c_char,
        size: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlReaderNewFd(
        reader: xmlTextReaderPtr,
        fd: libc::c_int,
        URL: *const libc::c_char,
        encoding: *const libc::c_char,
        options: libc::c_int,
    ) -> libc::c_int;
    fn xmlTextReaderLocatorLineNumber(locator: xmlTextReaderLocatorPtr) -> libc::c_int;
    fn xmlTextReaderLocatorBaseURI(locator: xmlTextReaderLocatorPtr) -> *mut xmlChar;
    fn xmlUCSIsCatLl(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMalayalam(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMathematicalAlphanumericSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMathematicalOperators(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMiscellaneousMathematicalSymbolsA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMiscellaneousMathematicalSymbolsB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMiscellaneousSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMiscellaneousSymbolsandArrows(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMiscellaneousTechnical(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMongolian(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMusicalSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsMyanmar(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsNumberForms(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsOgham(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsOldItalic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsLowSurrogates(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatL(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatCs(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatCo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatCf(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatCc(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatC(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsBlock(code: libc::c_int, block: *const libc::c_char) -> libc::c_int;
    fn xmlUCSIsYijingHexagramSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsYiSyllables(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsYiRadicals(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsVariationSelectorsSupplement(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsVariationSelectors(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsUnifiedCanadianAboriginalSyllabics(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsUgaritic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTibetan(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsThai(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsThaana(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTelugu(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTamil(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTaiXuanJingSymbols(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTaiLe(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTags(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTagbanwa(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsTagalog(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSyriac(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSupplementaryPrivateUseAreaB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSupplementaryPrivateUseAreaA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSupplementalMathematicalOperators(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSupplementalArrowsB(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSupplementalArrowsA(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSuperscriptsandSubscripts(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsOpticalCharacterRecognition(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsOriya(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsOsmanya(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsPhoneticExtensions(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSpecials(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSpacingModifierLetters(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsPrivateUse(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSmallFormVariants(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsSinhala(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsShavian(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsRunic(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsPrivateUseArea(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPc(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatLm(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatLo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatLt(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatLu(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatM(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatMc(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatMe(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatMn(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatN(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatNd(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatNl(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatNo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatP(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatSo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPf(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPe(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPd(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPi(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPo(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatPs(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatS(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatSc(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatSm(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatSk(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatZ(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatZl(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatZp(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCatZs(code: libc::c_int) -> libc::c_int;
    fn xmlUCSIsCat(code: libc::c_int, cat: *const libc::c_char) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
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
pub type PyTypeObject = _typeobject;
pub type xmlChar = libc::c_uchar;
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
pub struct _xmlOutputBuffer {
    pub context: *mut libc::c_void,
    pub writecallback: xmlOutputWriteCallback,
    pub closecallback: xmlOutputCloseCallback,
    pub encoder: xmlCharEncodingHandlerPtr,
    pub buffer: xmlBufPtr,
    pub conv: xmlBufPtr,
    pub written: libc::c_int,
    pub error: libc::c_int,
}
pub type xmlOutputCloseCallback = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int,
>;
pub type xmlOutputWriteCallback = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const libc::c_char,
        libc::c_int,
    ) -> libc::c_int,
>;
pub type xmlOutputBuffer = _xmlOutputBuffer;
pub type xmlOutputBufferPtr = *mut xmlOutputBuffer;
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
pub type xmlAttributeDefault = libc::c_uint;
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
pub type xmlElementTypeVal = libc::c_uint;
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
pub type xmlFreeFunc = Option::<unsafe extern "C" fn(*mut libc::c_void) -> ()>;
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
    pub flags: libc::c_int,
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
    pub preserve: libc::c_int,
    pub counter: libc::c_int,
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
pub type xmlURI = _xmlURI;
pub type xmlURIPtr = *mut xmlURI;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathContext {
    pub doc: xmlDocPtr,
    pub node: xmlNodePtr,
    pub nb_variables_unused: libc::c_int,
    pub max_variables_unused: libc::c_int,
    pub varHash: xmlHashTablePtr,
    pub nb_types: libc::c_int,
    pub max_types: libc::c_int,
    pub types: xmlXPathTypePtr,
    pub nb_funcs_unused: libc::c_int,
    pub max_funcs_unused: libc::c_int,
    pub funcHash: xmlHashTablePtr,
    pub nb_axis: libc::c_int,
    pub max_axis: libc::c_int,
    pub axis: xmlXPathAxisPtr,
    pub namespaces: *mut xmlNsPtr,
    pub nsNr: libc::c_int,
    pub user: *mut libc::c_void,
    pub contextSize: libc::c_int,
    pub proximityPosition: libc::c_int,
    pub xptr: libc::c_int,
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
    pub tmpNsNr: libc::c_int,
    pub userData: *mut libc::c_void,
    pub error: xmlStructuredErrorFunc,
    pub lastError: xmlError,
    pub debugNode: xmlNodePtr,
    pub dict: xmlDictPtr,
    pub flags: libc::c_int,
    pub cache: *mut libc::c_void,
    pub opLimit: libc::c_ulong,
    pub opCount: libc::c_ulong,
    pub depth: libc::c_int,
}
pub type xmlXPathFuncLookupFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlXPathFunction,
>;
pub type xmlXPathFunction = Option::<
    unsafe extern "C" fn(xmlXPathParserContextPtr, libc::c_int) -> (),
>;
pub type xmlXPathParserContextPtr = *mut xmlXPathParserContext;
pub type xmlXPathParserContext = _xmlXPathParserContext;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathParserContext {
    pub cur: *const xmlChar,
    pub base: *const xmlChar,
    pub error: libc::c_int,
    pub context: xmlXPathContextPtr,
    pub value: xmlXPathObjectPtr,
    pub valueNr: libc::c_int,
    pub valueMax: libc::c_int,
    pub valueTab: *mut xmlXPathObjectPtr,
    pub comp: xmlXPathCompExprPtr,
    pub xptr: libc::c_int,
    pub ancestor: xmlNodePtr,
    pub valueFrame: libc::c_int,
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
    pub boolval: libc::c_int,
    pub floatval: libc::c_double,
    pub stringval: *mut xmlChar,
    pub user: *mut libc::c_void,
    pub index: libc::c_int,
    pub user2: *mut libc::c_void,
    pub index2: libc::c_int,
}
pub type xmlNodeSetPtr = *mut xmlNodeSet;
pub type xmlNodeSet = _xmlNodeSet;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlNodeSet {
    pub nodeNr: libc::c_int,
    pub nodeMax: libc::c_int,
    pub nodeTab: *mut xmlNodePtr,
}
pub type xmlXPathObjectType = libc::c_uint;
pub const XPATH_XSLT_TREE: xmlXPathObjectType = 9;
pub const XPATH_USERS: xmlXPathObjectType = 8;
pub const XPATH_STRING: xmlXPathObjectType = 4;
pub const XPATH_NUMBER: xmlXPathObjectType = 3;
pub const XPATH_BOOLEAN: xmlXPathObjectType = 2;
pub const XPATH_NODESET: xmlXPathObjectType = 1;
pub const XPATH_UNDEFINED: xmlXPathObjectType = 0;
pub type xmlXPathContextPtr = *mut xmlXPathContext;
pub type xmlXPathContext = _xmlXPathContext;
pub type xmlXPathVariableLookupFunc = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const xmlChar,
        *const xmlChar,
    ) -> xmlXPathObjectPtr,
>;
pub type xmlXPathAxisPtr = *mut xmlXPathAxis;
pub type xmlXPathAxis = _xmlXPathAxis;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathAxis {
    pub name: *const xmlChar,
    pub func: xmlXPathAxisFunc,
}
pub type xmlXPathAxisFunc = Option::<
    unsafe extern "C" fn(
        xmlXPathParserContextPtr,
        xmlXPathObjectPtr,
    ) -> xmlXPathObjectPtr,
>;
pub type xmlXPathTypePtr = *mut xmlXPathType;
pub type xmlXPathType = _xmlXPathType;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlXPathType {
    pub name: *const xmlChar,
    pub func: xmlXPathConvertFunc,
}
pub type xmlXPathConvertFunc = Option::<
    unsafe extern "C" fn(xmlXPathObjectPtr, libc::c_int) -> libc::c_int,
>;
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
pub unsafe extern "C" fn libxml_htmlAutoCloseTag(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OzO:htmlAutoCloseTag\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlCreateFileParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:htmlCreateMemoryParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:htmlCtxtReadDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:htmlCtxtReadFd\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:htmlCtxtReadFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izzi:htmlCtxtReadMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
        b"O:htmlCtxtReset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh0 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh0 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlCtxtUseOptions(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:htmlCtxtUseOptions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut libc::c_int,
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
        b"htmlDefaultSAXHandlerInit\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    htmlDefaultSAXHandlerInit();
    let ref mut fresh1 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzi:htmlDocContentDumpFormatOutput\0" as *const u8 as *const libc::c_char
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
    htmlDocContentDumpFormatOutput(buf, cur, encoding, format);
    let ref mut fresh2 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:htmlDocContentDumpOutput\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    htmlDocContentDumpOutput(buf, cur, encoding);
    let ref mut fresh3 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh3 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlDocDump(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:htmlDocDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:htmlFreeParserCtxt\0" as *const u8 as *const libc::c_char
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
    htmlFreeParserCtxt(ctxt);
    let ref mut fresh4 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:htmlGetMetaEncoding\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:htmlHandleOmittedElem\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
        b"htmlInitAutoClose\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    htmlInitAutoClose();
    let ref mut fresh5 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh5 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlIsAutoClosed(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: htmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:htmlIsAutoClosed\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:htmlIsBooleanAttr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:htmlIsScriptAttribute\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"zz:htmlNewDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zz:htmlNewDocNoDtD\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOO:htmlNodeDumpFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh6 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh6 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlNodeDumpFileFormat(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut out: *mut FILE = 0 as *mut FILE;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzi:htmlNodeDumpFileFormat\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_out as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
        &mut format as *mut libc::c_int,
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
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOzi:htmlNodeDumpFormatOutput\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
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
    let ref mut fresh7 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:htmlNodeDumpOutput\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
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
    let ref mut fresh8 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh8 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_htmlParseCharRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlParseCharRef\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut terminate: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#ii:htmlParseChunk\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut terminate as *mut libc::c_int,
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
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlParseDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: htmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:htmlParseDocument\0" as *const u8 as *const libc::c_char
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
        b"O:htmlParseElement\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh9 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:htmlParseFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:htmlReadDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:htmlReadFd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:htmlReadFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#izzi:htmlReadMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:htmlSaveFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOz:htmlSaveFileEnc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOzi:htmlSaveFileFormat\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
        &mut format as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: htmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:htmlSetMetaEncoding\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:namePop\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:namePush\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:nodePop\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut value: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_value: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:nodePush\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:valuePop\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzz:xmlACatalogAdd\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlACatalogDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh10 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh10 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlACatalogRemove(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlACatalogRemove\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Ozz:xmlACatalogResolve\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlACatalogResolvePublic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlACatalogResolveSystem\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlACatalogResolveURI\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlAddChild\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlAddChildList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut type_0: libc::c_int = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlAddDocEntity\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut libc::c_int,
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
    let mut type_0: libc::c_int = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlAddDtdEntity\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alias: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlAddEncodingAlias\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut name as *mut *mut libc::c_char,
        &mut alias as *mut *mut libc::c_char,
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
        b"OO:xmlAddNextSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlAddPrevSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlAddSibling\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut boolval: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlBoolToText\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut boolval as *mut libc::c_int,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlBuildQName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ncname as *mut *mut xmlChar,
        &mut prefix as *mut *mut xmlChar,
        &mut memory as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
        b"zz:xmlBuildRelativeURI\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"zz:xmlBuildURI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_long = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlByteConsumed\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlCanonicPath\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut type_0: *mut xmlChar = 0 as *mut xmlChar;
    let mut orig: *mut xmlChar = 0 as *mut xmlChar;
    let mut replace: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzz:xmlCatalogAdd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh11 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh11 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCatalogConvert(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
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
        b"O:xmlCatalogDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh12 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"z:xmlCatalogGetPublic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlCatalogGetSystem\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlCatalogIsEmpty\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCatalogRemove\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zz:xmlCatalogResolve\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlCatalogResolvePublic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlCatalogResolveSystem\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlCatalogResolveURI\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut level: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlCatalogSetDebug\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut level as *mut libc::c_int,
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
    let mut cur: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCharStrdup\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut libc::c_char,
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
    let mut cur: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCharStrndup\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut libc::c_char,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckFilename\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut path as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut lang: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckLanguageID\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCheckUTF8\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut utf as *mut *mut libc::c_uchar,
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
    let mut version: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlCheckVersion\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut version as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlCheckVersion(version);
    let ref mut fresh13 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh13 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupCharEncodingHandlers(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlCleanupCharEncodingHandlers\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlCleanupCharEncodingHandlers();
    let ref mut fresh14 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh14 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupEncodingAliases(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupEncodingAliases();
    let ref mut fresh15 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh15 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupGlobals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlCleanupGlobals\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlCleanupGlobals();
    let ref mut fresh16 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh16 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupInputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupInputCallbacks();
    let ref mut fresh17 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh17 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupOutputCallbacks();
    let ref mut fresh18 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh18 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCleanupPredefinedEntities(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlCleanupPredefinedEntities();
    let ref mut fresh19 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlClearParserCtxt\0" as *const u8 as *const libc::c_char
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
    xmlClearParserCtxt(ctxt);
    let ref mut fresh20 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh20 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlConvertSGMLCatalog(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut catal: xmlCatalogPtr = 0 as *mut xmlCatalog;
    let mut pyobj_catal: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlConvertSGMLCatalog\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izi:xmlCopyChar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut len as *mut libc::c_int,
        &mut out as *mut *mut xmlChar,
        &mut val as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut out: *mut xmlChar = 0 as *mut xmlChar;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCopyCharMultiByte\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut out as *mut *mut xmlChar,
        &mut val as *mut libc::c_int,
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
    let mut recursive: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCopyDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut recursive as *mut libc::c_int,
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
        b"O:xmlCopyDtd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut from: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_from: *mut PyObject = 0 as *mut PyObject;
    let mut to: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_to: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlCopyError\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlCopyNamespace\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlCopyNamespaceList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut extended: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCopyNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut extended as *mut libc::c_int,
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
        b"O:xmlCopyNodeList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlCopyProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlCopyPropList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlCreateDocParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"zzz:xmlCreateEntityParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlCreateFileParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"Ozzz:xmlCreateIntSubset\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlCreateMemoryParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlCreateURLParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:xmlCtxtReadDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:xmlCtxtReadFd\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:xmlCtxtReadFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izzi:xmlCtxtReadMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
        b"O:xmlCtxtReset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh21 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh21 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlCtxtResetPush(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#izz:xmlCtxtResetPush\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlCtxtUseOptions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut output: *mut FILE = 0 as *mut FILE;
    let mut pyobj_output: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDebugCheckDocument\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut depth: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpAttr\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
        &mut depth as *mut libc::c_int,
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
    let ref mut fresh22 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut depth: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpAttrList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_attr as *mut *mut PyObject,
        &mut depth as *mut libc::c_int,
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
    let ref mut fresh23 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlDebugDumpDTD\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh24 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlDebugDumpDocument\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh25 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlDebugDumpDocumentHead\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh26 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlDebugDumpEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh27 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut depth: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut libc::c_int,
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
    let ref mut fresh28 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut depth: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpNodeList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut libc::c_int,
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
    let ref mut fresh29 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut depth: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDebugDumpOneNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_output as *mut *mut PyObject,
        &mut pyobj_node as *mut *mut PyObject,
        &mut depth as *mut libc::c_int,
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
    let ref mut fresh30 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlDebugDumpString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh31 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut len: libc::c_int = 0;
    let mut what: libc::c_int = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if libxml_deprecationWarning(
        b"xmlDecodeEntities\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiiccc:xmlDecodeEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut len as *mut libc::c_int,
        &mut what as *mut libc::c_int,
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
        b"xmlDefaultSAXHandlerInit\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlDefaultSAXHandlerInit();
    let ref mut fresh32 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh32 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlDelEncodingAlias(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut alias: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlDelEncodingAlias\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut alias as *mut *mut libc::c_char,
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
    if libxml_deprecationWarning(b"xmlDictCleanup\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlDictCleanup();
    let ref mut fresh33 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut extended: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDocCopyNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut extended as *mut libc::c_int,
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
        b"OO:xmlDocCopyNodeList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlDocDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut pyobj_f: *mut PyObject = 0 as *mut PyObject;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlDocFormatDump\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_f as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut format as *mut libc::c_int,
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
        b"O:xmlDocGetRootElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlDocSetRootElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OOO:xmlElemDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh34 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"xmlEncodeEntities\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlEncodeEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlEncodeEntitiesReentrant\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlEncodeSpecialChars\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetCode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetDomain\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetLevel\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    c_retval = (*Error).level as libc::c_int;
    py_retval = libxml_intWrap(c_retval);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlErrorGetLine(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetLine\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut Error: xmlErrorPtr = 0 as *mut xmlError;
    let mut pyobj_Error: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlErrorGetMessage\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlFileMatch\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"O:xmlFirstElementChild\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlFreeCatalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh35 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh36 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeDtd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh37 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh38 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeNodeList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh39 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh40 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeNsList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh41 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeParserInputBuffer\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh42 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh43 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreePropList\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh44 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlFreeURI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh45 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh45 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlGetCompressMode(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: *mut xmlDoc = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetDocCompressMode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlGetDocEntity\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozz:xmlGetDtdAttrDesc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlGetDtdElementDesc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlGetDtdEntity\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozzz:xmlGetDtdQAttrDesc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Ozz:xmlGetDtdQElementDesc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut alias: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlGetEncodingAlias\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut alias as *mut *mut libc::c_char,
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
        b"Oz:xmlGetID\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlGetIntSubset\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlGetLastChild\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_long = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlGetLineNo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlGetNoNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlGetNodePath\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozz:xmlGetNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlGetParameterEntity\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlGetPredefinedEntity\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlGetProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"xmlHandleEntity\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlHandleEntity\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh46 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Ozz:xmlHasNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlHasProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlIOFTPMatch\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlIOHTTPMatch\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"xmlInitCharEncodingHandlers\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlInitCharEncodingHandlers();
    let ref mut fresh47 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh47 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitGlobals(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlInitGlobals\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlInitGlobals();
    let ref mut fresh48 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh48 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitParser(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlInitParser();
    let ref mut fresh49 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh49 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitParserCtxt(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlInitParserCtxt\0" as *const u8 as *const libc::c_char
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
    let ref mut fresh50 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh50 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlInitializeDict(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    if libxml_deprecationWarning(
        b"xmlInitializeDict\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
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
        b"xmlInitializePredefinedEntities\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlInitializePredefinedEntities();
    let ref mut fresh51 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh51 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlIsBaseChar(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsBaseChar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsBlank\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlIsBlankNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsChar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsCombining\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsDigit\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsExtender\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlIsID\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsIdeographic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut c: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsLetter\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut c as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlIsMixedElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ch: libc::c_uint = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlIsPubidChar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut ch as *mut libc::c_uint,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(b"xmlIsRef\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlIsRef\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut systemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut publicID: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlIsXHTML\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlKeepBlanksDefault\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
        b"O:xmlLastElementChild\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlLineNumbersDefault\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadACatalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadCatalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut pathss: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadCatalogs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pathss as *mut *mut libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlLoadCatalogs(pathss);
    let ref mut fresh52 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlLoadSGMLSuperCatalog\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlLsCountNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlLsOneNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh53 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"xmlNamespaceParseNCName\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNamespaceParseNCName\0" as *const u8 as *const libc::c_char
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
        b"xmlNamespaceParseNSDef\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNamespaceParseNSDef\0" as *const u8 as *const libc::c_char
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
        b"xmlNanoFTPCleanup\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPCleanup();
    let ref mut fresh54 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh54 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlNanoFTPInit\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPInit();
    let ref mut fresh55 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh55 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = 0;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut passwd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: libc::c_int = 0;
    if libxml_deprecationWarning(
        b"xmlNanoFTPProxy\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zizzi:xmlNanoFTPProxy\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut host as *mut *mut libc::c_char,
        &mut port as *mut libc::c_int,
        &mut user as *mut *mut libc::c_char,
        &mut passwd as *mut *mut libc::c_char,
        &mut type_0 as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPProxy(host, port, user, passwd, type_0);
    let ref mut fresh56 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh56 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoFTPScanProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    if libxml_deprecationWarning(
        b"xmlNanoFTPScanProxy\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNanoFTPScanProxy\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut URL as *mut *mut libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoFTPScanProxy(URL);
    let ref mut fresh57 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh57 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPCleanup(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlNanoHTTPCleanup();
    let ref mut fresh58 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh58 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlNanoHTTPInit();
    let ref mut fresh59 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh59 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNanoHTTPScanProxy(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNanoHTTPScanProxy\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut URL as *mut *mut libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlNanoHTTPScanProxy(URL);
    let ref mut fresh60 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNewCDataBlock\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut sgml: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlNewCatalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut sgml as *mut libc::c_int,
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
        b"Oz:xmlNewCharRef\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewChild\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlNewComment\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlNewDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlNewDocComment\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlNewDocFragment\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OOzz:xmlNewDocNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewDocNodeEatName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Ozz:xmlNewDocPI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozz:xmlNewDocProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewDocRawNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlNewDocText\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNewDocTextLen\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
        b"Ozzz:xmlNewDtd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut type_0: libc::c_int = 0;
    let mut ExternalID: *mut xmlChar = 0 as *mut xmlChar;
    let mut SystemID: *mut xmlChar = 0 as *mut xmlChar;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzz:xmlNewEntity\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut name as *mut *mut xmlChar,
        &mut type_0 as *mut libc::c_int,
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
    if libxml_deprecationWarning(b"xmlNewGlobalNs\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlNewGlobalNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlNewNodeEatName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Ozz:xmlNewNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewNsPropEatName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"zz:xmlNewPI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozz:xmlNewProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Oz:xmlNewReference\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlNewText\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlNewTextChild\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlNewTextLen\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut URI: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlNewTextReader\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_input as *mut *mut PyObject,
        &mut URI as *mut *mut libc::c_char,
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
    let mut URI: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNewTextReaderFilename\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut URI as *mut *mut libc::c_char,
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
        b"O:xmlNextChar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh61 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlNextElementSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlNodeAddContent\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh62 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNodeAddContentLen\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let ref mut fresh63 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut level: libc::c_int = 0;
    let mut format: libc::c_int = 0;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOiiz:xmlNodeDumpOutput\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_buf as *mut *mut PyObject,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut level as *mut libc::c_int,
        &mut format as *mut libc::c_int,
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
    let ref mut fresh64 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlNodeGetBase\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlNodeGetContent\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlNodeGetLang\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut cur: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeGetSpacePreserve\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut node: *mut xmlNode = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlNodeIsText\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut inLine: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlNodeListGetRawString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_list as *mut *mut PyObject,
        &mut inLine as *mut libc::c_int,
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
    let mut inLine: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlNodeListGetString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut pyobj_list as *mut *mut PyObject,
        &mut inLine as *mut libc::c_int,
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
        b"Oz:xmlNodeSetBase\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh65 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlNodeSetContent\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh66 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlNodeSetContentLen\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let ref mut fresh67 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlNodeSetLang\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh68 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlNodeSetName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh69 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlNodeSetSpacePreserve\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut val as *mut libc::c_int,
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
    let ref mut fresh70 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh70 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlNormalizeURIPath(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlNormalizeURIPath\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut path as *mut *mut libc::c_char,
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
        b"z:xmlNormalizeWindowsPath\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlOutputBufferGetContent\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut len: libc::c_int = 0;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiz:xmlOutputBufferWrite\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_out as *mut *mut PyObject,
        &mut len as *mut libc::c_int,
        &mut buf as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut out: xmlOutputBufferPtr = 0 as *mut xmlOutputBuffer;
    let mut pyobj_out: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlOutputBufferWriteString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_out as *mut *mut PyObject,
        &mut str as *mut *mut libc::c_char,
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
        b"O:xmlParseAttValue\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseAttributeListDecl\0" as *const u8 as *const libc::c_char
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
    xmlParseAttributeListDecl(ctxt);
    let ref mut fresh71 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParseCDSect\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh72 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseCatalogFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut cdata: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParseCharData\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut cdata as *mut libc::c_int,
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
    let ref mut fresh73 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh73 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseCharRef(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseCharRef\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut chunk: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut terminate: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Os#ii:xmlParseChunk\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut chunk as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut terminate as *mut libc::c_int,
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
        b"O:xmlParseComment\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh74 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParseContent\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh75 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"zz:xmlParseDTD\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlParseDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseDocTypeDecl\0" as *const u8 as *const libc::c_char
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
    xmlParseDocTypeDecl(ctxt);
    let ref mut fresh76 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh76 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseDocument(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseDocument\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseElement\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh77 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh77 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseElementDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseElementDecl\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseEncName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseEncodingDecl\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseEndTag\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh78 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseEntity\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"O:xmlParseEntityDecl\0" as *const u8 as *const libc::c_char
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
    xmlParseEntityDecl(ctxt);
    let ref mut fresh79 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParseEntityRef\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseExtParsedEnt\0" as *const u8 as *const libc::c_char
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
        b"Ozz:xmlParseExternalSubset\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh80 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"O:xmlParseMarkupDecl\0" as *const u8 as *const libc::c_char
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
    xmlParseMarkupDecl(ctxt);
    let ref mut fresh81 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlParseMemory\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
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
        b"O:xmlParseMisc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh82 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParseName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"xmlParseNamespace\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseNamespace\0" as *const u8 as *const libc::c_char
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
    xmlParseNamespace(ctxt);
    let ref mut fresh83 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParseNmtoken\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseNotationDecl\0" as *const u8 as *const libc::c_char
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
    xmlParseNotationDecl(ctxt);
    let ref mut fresh84 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParsePEReference\0" as *const u8 as *const libc::c_char
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
    xmlParsePEReference(ctxt);
    let ref mut fresh85 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParsePI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh86 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlParsePITarget\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParsePubidLiteral\0" as *const u8 as *const libc::c_char
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
        b"xmlParseQuotedString\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseQuotedString\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseReference\0" as *const u8 as *const libc::c_char
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
    xmlParseReference(ctxt);
    let ref mut fresh87 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh87 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParseSDDecl(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParseSDDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseStartTag\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlParseSystemLiteral\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseTextDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh88 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParseURI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str as *mut *mut libc::c_char,
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
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut raw: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlParseURIRaw\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str as *mut *mut libc::c_char,
        &mut raw as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut uri: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_uri: *mut PyObject = 0 as *mut PyObject;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlParseURIReference\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_uri as *mut *mut PyObject,
        &mut str as *mut *mut libc::c_char,
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
        b"O:xmlParseVersionInfo\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseVersionNum\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParseXMLDecl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh89 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh89 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserGetDirectory(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlParserGetDirectory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
        b"O:xmlParserGetDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserGetIsValid\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserGetWellFormed\0" as *const u8 as *const libc::c_char
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
        b"O:xmlParserHandlePEReference\0" as *const u8 as *const libc::c_char
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
    xmlParserHandlePEReference(ctxt);
    let ref mut fresh90 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"xmlParserHandleReference\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlParserHandleReference\0" as *const u8 as *const libc::c_char
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
    xmlParserHandleReference(ctxt);
    let ref mut fresh91 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh91 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlParserInputBufferGrow(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserInputBufferGrow\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: libc::c_int = 0;
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiz:xmlParserInputBufferPush\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut libc::c_int,
        &mut buf as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut in_0: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_in: *mut PyObject = 0 as *mut PyObject;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserInputBufferRead\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_in as *mut *mut PyObject,
        &mut len as *mut libc::c_int,
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
    let mut linenumbers: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetLineNumbers\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut linenumbers as *mut libc::c_int,
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
    let ref mut fresh92 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut loadsubset: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetLoadSubset\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut loadsubset as *mut libc::c_int,
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
    let ref mut fresh93 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut pedantic: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetPedantic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut pedantic as *mut libc::c_int,
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
    let ref mut fresh94 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut replaceEntities: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetReplaceEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut replaceEntities as *mut libc::c_int,
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
    let ref mut fresh95 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut validate: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlParserSetValidate\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut validate as *mut libc::c_int,
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
    let ref mut fresh96 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"z:xmlPathToURI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlPedanticParserDefault\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
        b"O:xmlPopInput\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    py_retval = libxml_intWrap(c_retval as libc::c_int);
    return py_retval;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlPopOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
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
        b"O:xmlPreviousElementSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlPrintURI\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh97 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlReadDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:xmlReadFd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlReadFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#izzi:xmlReadMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzzi:xmlReaderForDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"izzi:xmlReaderForFd\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlReaderForFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zizzi:xmlReaderForMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut cur: *mut xmlChar = 0 as *mut xmlChar;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzzi:xmlReaderNewDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut cur as *mut *mut xmlChar,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut fd: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oizzi:xmlReaderNewFd\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut fd as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozzi:xmlReaderNewFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut filename as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozizzi:xmlReaderNewMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut buffer as *mut *mut libc::c_char,
        &mut size as *mut libc::c_int,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlReaderNewWalker\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlReaderWalker\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlReconciliateNs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlRecoverDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRecoverFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut py_buffsize0: Py_ssize_t = 0;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"s#i:xmlRecoverMemory\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut py_buffsize0 as *mut Py_ssize_t,
        &mut size as *mut libc::c_int,
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
        b"O:xmlRegFreeRegexp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh98 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"z:xmlRegexpCompile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlRegexpExec\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut comp: xmlRegexpPtr = 0 as *mut xmlRegexp;
    let mut pyobj_comp: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRegexpIsDeterminist\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlRegexpPrint\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh99 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh99 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterDefaultInputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterDefaultInputCallbacks();
    let ref mut fresh100 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh100 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterDefaultOutputCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterDefaultOutputCallbacks();
    let ref mut fresh101 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh101 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRegisterHTTPPostCallbacks(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlRegisterHTTPPostCallbacks();
    let ref mut fresh102 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh102 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGCleanupTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlRelaxNGCleanupTypes\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlRelaxNGCleanupTypes();
    let ref mut fresh103 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlRelaxNGDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh104 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlRelaxNGDumpTree\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh105 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlRelaxNGFree\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh106 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlRelaxNGFreeParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh107 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh107 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlRelaxNGInitTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    if libxml_deprecationWarning(
        b"xmlRelaxNGInitTypes\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
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
        b"O:xmlRelaxNGNewDocParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlRelaxNGNewMemParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut size as *mut libc::c_int,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlRelaxNGNewParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut URL as *mut *mut libc::c_char,
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
        b"O:xmlRelaxNGNewValidCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlRelaxNGParse\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRelaxNGValidateDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidateFullElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidatePopElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlRelaxNGValidatePushCData\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut data as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlRelaxNGValidatePushElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlRelaxNGParserCtxtPtr = 0 as *mut xmlRelaxNGParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut flags: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlRelaxParserSetFlag\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut flags as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRemoveID\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut cur: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlRemoveProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut attr: xmlAttrPtr = 0 as *mut xmlAttr;
    let mut pyobj_attr: *mut PyObject = 0 as *mut PyObject;
    if libxml_deprecationWarning(b"xmlRemoveRef\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlRemoveRef\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlReplaceNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlResetError\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh108 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh108 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlResetLastError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    xmlResetLastError();
    let ref mut fresh109 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh109 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSAXDefaultVersion(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut version: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSAXDefaultVersion\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut version as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zO:xmlSaveFile\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOz:xmlSaveFileEnc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOi:xmlSaveFormatFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut format as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cur: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_cur: *mut PyObject = 0 as *mut PyObject;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut format: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zOzi:xmlSaveFormatFileEnc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut filename as *mut *mut libc::c_char,
        &mut pyobj_cur as *mut *mut PyObject,
        &mut encoding as *mut *mut libc::c_char,
        &mut format as *mut libc::c_int,
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
        b"O:xmlSaveUri\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    if libxml_deprecationWarning(b"xmlScanName\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlScanName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"xmlSchemaCleanupTypes\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlSchemaCleanupTypes();
    let ref mut fresh110 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"z:xmlSchemaCollapseString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlSchemaDump\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh111 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlSchemaFree\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh112 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlSchemaFreeParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh113 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh113 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaInitTypes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(
        b"xmlSchemaInitTypes\0" as *const u8 as *const libc::c_char,
    ) == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlSchemaInitTypes();
    let ref mut fresh114 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh114 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSchemaIsValid(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaIsValid\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlSchemaNewDocParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut buffer: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut size: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlSchemaNewMemParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut buffer as *mut *mut libc::c_char,
        &mut size as *mut libc::c_int,
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
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlSchemaNewParserCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut URL as *mut *mut libc::c_char,
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
        b"O:xmlSchemaNewValidCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlSchemaParse\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlSchemaSetValidOptions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSchemaValidCtxtGetOptions\0" as *const u8 as *const libc::c_char
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
        b"O:xmlSchemaValidCtxtGetParserCtxt\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSchemaValidateDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlSchemaValidateFile\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut filename as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlSchemaValidateOneElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlSchemaValidateSetFilename\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_vctxt as *mut *mut PyObject,
        &mut filename as *mut *mut libc::c_char,
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
    let ref mut fresh115 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"z:xmlSchemaWhiteSpaceReplace\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OOz:xmlSearchNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOz:xmlSearchNsByHref\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut mode: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSetCompressMode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut mode as *mut libc::c_int,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlSetCompressMode(mode);
    let ref mut fresh116 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut mode: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlSetDocCompressMode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut mode as *mut libc::c_int,
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
    let ref mut fresh117 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlSetListDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh118 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlSetNs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh119 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OOzz:xmlSetNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"Ozz:xmlSetProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OO:xmlSetTreeDoc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh120 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlSetupParserForBuffer\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut buffer as *mut *mut xmlChar,
        &mut filename as *mut *mut libc::c_char,
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
    let ref mut fresh121 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlShellPrintNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh122 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh122 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlShellPrintXPathError(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut errorType: libc::c_int = 0;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlShellPrintXPathError\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut errorType as *mut libc::c_int,
        &mut arg as *mut *mut libc::c_char,
    ) == 0
    {
        return 0 as *mut PyObject;
    }
    xmlShellPrintXPathError(errorType, arg);
    let ref mut fresh123 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh123 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlSkipBlankChars(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlParserCtxtPtr = 0 as *mut xmlParserCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlSkipBlankChars\0" as *const u8 as *const libc::c_char
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
        b"O:xmlStopParser\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh124 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh124 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlStrEqual(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrEqual\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut pref: *mut xmlChar = 0 as *mut xmlChar;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzz:xmlStrQEqual\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcasecmp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zz:xmlStrcasestr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zz:xmlStrcat\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zc:xmlStrchr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlStrcmp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"z:xmlStrdup\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut what: libc::c_int = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziccc:xmlStringDecodeEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
        &mut what as *mut libc::c_int,
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
        b"Oz:xmlStringGetNodeList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut len: libc::c_int = 0;
    let mut what: libc::c_int = 0;
    let mut end: xmlChar = 0;
    let mut end2: xmlChar = 0;
    let mut end3: xmlChar = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oziiccc:xmlStringLenDecodeEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut str as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
        &mut what as *mut libc::c_int,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlStringLenGetNodeList\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut value as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlStrlen\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncasecmp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncat\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut add as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncatNew\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut str1: *mut xmlChar = 0 as *mut xmlChar;
    let mut str2: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zzi:xmlStrncmp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str1 as *mut *mut xmlChar,
        &mut str2 as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlStrndup\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut cur as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
        b"zz:xmlStrstr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut start: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zii:xmlStrsub\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut str as *mut *mut xmlChar,
        &mut start as *mut libc::c_int,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlSubstituteEntitiesDefault\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut content: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlTextConcat\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_node as *mut *mut PyObject,
        &mut content as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
        b"OO:xmlTextMerge\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderAttributeCount\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_long = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderByteConsumed\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderClose\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstBaseUri\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstEncoding\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstLocalName\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstName\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstNamespaceUri\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstPrefix\0" as *const u8 as *const libc::c_char
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
        b"Oz:xmlTextReaderConstString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlTextReaderConstValue\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstXmlLang\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderConstXmlVersion\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderCurrentDoc\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderCurrentNode\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderDepth\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderExpand\0" as *const u8 as *const libc::c_char
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
        b"Oz:xmlTextReaderGetAttribute\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut no: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderGetAttributeNo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut no as *mut libc::c_int,
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
        b"Ozz:xmlTextReaderGetAttributeNs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderGetParserColumnNumber\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderGetParserLineNumber\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderGetParserProp\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut prop as *mut libc::c_int,
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
        b"O:xmlTextReaderGetRemainder\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderHasAttributes\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderHasValue\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsDefault\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsEmptyElement\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsNamespaceDecl\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderIsValid\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderLocatorBaseURI\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut locator: xmlTextReaderLocatorPtr = 0 as *mut libc::c_void;
    let mut pyobj_locator: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderLocatorLineNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Oz:xmlTextReaderLookupNamespace\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderMoveToAttribute\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut no: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlTextReaderMoveToAttributeNo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut no as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut localName: *mut xmlChar = 0 as *mut xmlChar;
    let mut namespaceURI: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlTextReaderMoveToAttributeNs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToElement\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToFirstAttribute\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderMoveToNextAttribute\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNext\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNextSibling\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNodeType\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderNormalization\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderPreserve\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderQuoteChar\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderRead\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadAttributeValue\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderReadInnerXml\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderReadOuterXml\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderReadState\0" as *const u8 as *const libc::c_char
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
        b"O:xmlTextReaderReadString\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlRelaxNGPtr = 0 as *mut xmlRelaxNG;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlTextReaderRelaxNGSetSchema\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut rng: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderRelaxNGValidate\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut rng as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlRelaxNGValidCtxtPtr = 0 as *mut xmlRelaxNGValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlTextReaderRelaxNGValidateCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut xsd: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlTextReaderSchemaValidate\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut xsd as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut ctxt: xmlSchemaValidCtxtPtr = 0 as *mut xmlSchemaValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOi:xmlTextReaderSchemaValidateCtxt\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut prop: libc::c_int = 0;
    let mut value: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oii:xmlTextReaderSetParserProp\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut prop as *mut libc::c_int,
        &mut value as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut schema: xmlSchemaPtr = 0 as *mut xmlSchema;
    let mut pyobj_schema: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlTextReaderSetSchema\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    let mut input: xmlParserInputBufferPtr = 0 as *mut xmlParserInputBuffer;
    let mut pyobj_input: *mut PyObject = 0 as *mut PyObject;
    let mut URL: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut encoding: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOzzi:xmlTextReaderSetup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_reader as *mut *mut PyObject,
        &mut pyobj_input as *mut *mut PyObject,
        &mut URL as *mut *mut libc::c_char,
        &mut encoding as *mut *mut libc::c_char,
        &mut options as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut reader: xmlTextReaderPtr = 0 as *mut xmlTextReader;
    let mut pyobj_reader: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlTextReaderStandalone\0" as *const u8 as *const libc::c_char
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefDefaultBufferSize\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefDoValidityCheckingDefaultValue\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefGetWarningsDefaultValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefIndentTreeOutput\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefKeepBlanksDefaultValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefLineNumbersDefaultValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefLoadExtDtdDefaultValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefParserDebugEntities\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefPedanticParserDefaultValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefSaveNoEmptyTags\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut v: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlThrDefSubstituteEntitiesDefaultValue\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut v as *mut libc::c_int,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut v: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlThrDefTreeIndentString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut v as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsAegeanNumbers\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsAlphabeticPresentationForms\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabicPresentationFormsA\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArabicPresentationFormsB\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArmenian\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsArrows\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBasicLatin\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBengali\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    let mut block: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlUCSIsBlock\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
        &mut block as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBlockElements\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBopomofo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBopomofoExtended\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBoxDrawing\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBraillePatterns\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsBuhid\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsByzantineMusicalSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibility\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityForms\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityIdeographs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKCompatibilityIdeographsSupplement\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKRadicalsSupplement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKSymbolsandPunctuation\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographsExtensionA\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCJKUnifiedIdeographsExtensionB\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    let mut cat: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"iz:xmlUCSIsCat\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
        &mut cat as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatC\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCf\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatCs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatL\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLm\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLt\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatLu\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatM\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMe\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatMn\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatN\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatNo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatP\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPe\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPf\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPi\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatPs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatS\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSk\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSm\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatSo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZ\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZl\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCatZs\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCherokee\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningDiacriticalMarks\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningDiacriticalMarksforSymbols\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningHalfMarks\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCombiningMarksforSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsControlPictures\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCurrencySymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCypriotSyllabary\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCyrillic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsCyrillicSupplement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDeseret\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDevanagari\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsDingbats\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEnclosedAlphanumerics\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEnclosedCJKLettersandMonths\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsEthiopic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeneralPunctuation\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeometricShapes\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGeorgian\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGothic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreek\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreekExtended\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGreekandCoptic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGujarati\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsGurmukhi\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHalfwidthandFullwidthForms\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulCompatibilityJamo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulJamo\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHangulSyllables\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHanunoo\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHebrew\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHighPrivateUseSurrogates\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHighSurrogates\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsHiragana\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsIPAExtensions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsIdeographicDescriptionCharacters\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKanbun\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKangxiRadicals\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKannada\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKatakana\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKatakanaPhoneticExtensions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKhmer\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsKhmerSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLao\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatin1Supplement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedA\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedAdditional\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLatinExtendedB\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLetterlikeSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLimbu\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLinearBIdeograms\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLinearBSyllabary\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsLowSurrogates\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMalayalam\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMathematicalAlphanumericSymbols\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMathematicalOperators\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousMathematicalSymbolsA\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousMathematicalSymbolsB\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousSymbolsandArrows\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMiscellaneousTechnical\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMongolian\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMusicalSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsMyanmar\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsNumberForms\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOgham\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOldItalic\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOpticalCharacterRecognition\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOriya\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsOsmanya\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPhoneticExtensions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPrivateUse\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsPrivateUseArea\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsRunic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsShavian\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSinhala\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSmallFormVariants\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSpacingModifierLetters\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSpecials\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSuperscriptsandSubscripts\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalArrowsA\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalArrowsB\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementalMathematicalOperators\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementaryPrivateUseAreaA\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSupplementaryPrivateUseAreaB\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsSyriac\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTagalog\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTagbanwa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTags\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTaiLe\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTaiXuanJingSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTamil\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTelugu\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsThaana\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsThai\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsTibetan\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsUgaritic\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsUnifiedCanadianAboriginalSyllabics\0" as *const u8
            as *const libc::c_char as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsVariationSelectors\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsVariationSelectorsSupplement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYiRadicals\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYiSyllables\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut code: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlUCSIsYijingHexagramSymbols\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut code as *mut libc::c_int,
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
        b"z:xmlURIEscape\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"zz:xmlURIEscapeStr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetAuthority\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetFragment\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetOpaque\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetPath\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetPort\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetQuery\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetQueryRaw\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetScheme\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetServer\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: *const libc::c_char = 0 as *const libc::c_char;
    let mut URI: xmlURIPtr = 0 as *mut xmlURI;
    let mut pyobj_URI: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlURIGetUser\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut authority: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetAuthority\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut authority as *mut *mut libc::c_char,
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
    let ref mut fresh125 = (*URI).authority;
    *fresh125 = xmlStrdup(authority as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh126 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut fragment: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetFragment\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut fragment as *mut *mut libc::c_char,
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
    let ref mut fresh127 = (*URI).fragment;
    *fresh127 = xmlStrdup(fragment as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh128 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut opaque: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetOpaque\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut opaque as *mut *mut libc::c_char,
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
    let ref mut fresh129 = (*URI).opaque;
    *fresh129 = xmlStrdup(opaque as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh130 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetPath\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut path as *mut *mut libc::c_char,
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
    let ref mut fresh131 = (*URI).path;
    *fresh131 = xmlStrdup(path as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh132 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut port: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlURISetPort\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut port as *mut libc::c_int,
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
    let ref mut fresh133 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut query: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetQuery\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut query as *mut *mut libc::c_char,
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
    let ref mut fresh134 = (*URI).query;
    *fresh134 = xmlStrdup(query as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh135 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut query_raw: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetQueryRaw\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut query_raw as *mut *mut libc::c_char,
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
    let ref mut fresh136 = (*URI).query_raw;
    *fresh136 = xmlStrdup(query_raw as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh137 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut scheme: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetScheme\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut scheme as *mut *mut libc::c_char,
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
    let ref mut fresh138 = (*URI).scheme;
    *fresh138 = xmlStrdup(scheme as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh139 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut server: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetServer\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut server as *mut *mut libc::c_char,
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
    let ref mut fresh140 = (*URI).server;
    *fresh140 = xmlStrdup(server as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh141 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlURISetUser\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_URI as *mut *mut PyObject,
        &mut user as *mut *mut libc::c_char,
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
    let ref mut fresh142 = (*URI).user;
    *fresh142 = xmlStrdup(user as *const xmlChar) as *mut libc::c_char;
    let ref mut fresh143 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh143 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlURIUnescapeString(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut str: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: libc::c_int = 0;
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"ziz:xmlURIUnescapeString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut str as *mut *mut libc::c_char,
        &mut len as *mut libc::c_int,
        &mut target as *mut *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf1: *mut xmlChar = 0 as *mut xmlChar;
    let mut utf2: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlUTF8Charcmp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlUTF8Size\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlUTF8Strlen\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut utfchar: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zz:xmlUTF8Strloc\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strndup\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut utf as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut pos: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strpos\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut utf as *mut *mut xmlChar,
        &mut pos as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut utf: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlUTF8Strsize\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut utf as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut start: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zii:xmlUTF8Strsub\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut utf as *mut *mut xmlChar,
        &mut start as *mut libc::c_int,
        &mut len as *mut libc::c_int,
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
        b"O:xmlUnlinkNode\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh144 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh144 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlUnsetNsProp(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut ns: xmlNsPtr = 0 as *mut xmlNs;
    let mut pyobj_ns: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlUnsetNsProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oz:xmlUnsetProp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
            as *const libc::c_char as *mut libc::c_char,
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
        b"OOzz:xmlValidNormalizeAttributeValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDocument\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDocumentFinal\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut dtd: xmlDtdPtr = 0 as *mut xmlDtd;
    let mut pyobj_dtd: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateDtd\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateDtdFinal\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateNCName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateNMToken\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateName\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNameValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNamesValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNmtokenValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlValidateNmtokensValue\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut notationName: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOz:xmlValidateNotationUse\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
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
        b"OOOOz:xmlValidateOneAttribute\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOO:xmlValidateOneElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
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
        b"OOOzOz:xmlValidateOneNamespace\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut qname: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:xmlValidatePopElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut data: *mut xmlChar = 0 as *mut xmlChar;
    let mut len: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozi:xmlValidatePushCData\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut data as *mut *mut xmlChar,
        &mut len as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut elem: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_elem: *mut PyObject = 0 as *mut PyObject;
    let mut qname: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OOOz:xmlValidatePushElement\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut value: *mut xmlChar = 0 as *mut xmlChar;
    let mut space: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"zi:xmlValidateQName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut value as *mut *mut xmlChar,
        &mut space as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlValidCtxtPtr = 0 as *mut xmlValidCtxt;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlValidateRoot\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXIncludeProcess\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    let mut flags: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXIncludeProcessFlags\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_doc as *mut *mut PyObject,
        &mut flags as *mut libc::c_int,
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
    let mut c_retval: libc::c_int = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXIncludeProcessTree\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut tree: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_tree: *mut PyObject = 0 as *mut PyObject;
    let mut flags: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXIncludeProcessTreeFlags\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_tree as *mut *mut PyObject,
        &mut flags as *mut libc::c_int,
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
        b"O:xmlXPathAddValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh145 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathBooleanFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh146 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh146 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCastBooleanToNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_double = 0.;
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathCastBooleanToNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathCastBooleanToString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
    let mut c_retval: libc::c_double = 0.;
    let mut node: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathCastNodeToNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathCastNodeToString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_double = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathCastNumberToBoolean\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_double,
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
    let mut val: libc::c_double = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathCastNumberToString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_double,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathCastStringToBoolean\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_double = 0.;
    let mut val: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathCastStringToNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathCeilingFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh147 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh147 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathCmpNodes(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut node1: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node1: *mut PyObject = 0 as *mut PyObject;
    let mut node2: xmlNodePtr = 0 as *mut xmlNode;
    let mut pyobj_node2: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"OO:xmlXPathCmpNodes\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut inf: libc::c_int = 0;
    let mut strict: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oii:xmlXPathCompareValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut inf as *mut libc::c_int,
        &mut strict as *mut libc::c_int,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathConcatFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh148 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathContainsFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh149 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh149 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathContextSetCache(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut active: libc::c_int = 0;
    let mut value: libc::c_int = 0;
    let mut options: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oiii:xmlXPathContextSetCache\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut active as *mut libc::c_int,
        &mut value as *mut libc::c_int,
        &mut options as *mut libc::c_int,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathCountFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh150 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathDivValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh151 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh151 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathEqualValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathEqualValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut error: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathErr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut error as *mut libc::c_int,
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
    let ref mut fresh152 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"zO:xmlXPathEval\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"O:xmlXPathEvalExpr\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh153 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"zO:xmlXPathEvalExpression\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathFalseFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh154 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathFloorFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh155 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathFreeContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh156 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathFreeParserContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh157 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathGetContextDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathGetContextNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextPosition\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathGetContextSize\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathGetFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathGetFunctionURI\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathIdFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh158 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh158 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathInit(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    if libxml_deprecationWarning(b"xmlXPathInit\0" as *const u8 as *const libc::c_char)
        == -(1 as libc::c_int)
    {
        return 0 as *mut PyObject;
    }
    xmlXPathInit();
    let ref mut fresh159 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh159 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathIsInf(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_double = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathIsInf\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut val as *mut libc::c_double,
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
    let mut c_retval: libc::c_int = 0;
    let mut val: libc::c_double = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathIsNaN\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut val as *mut libc::c_double,
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
    let mut c_retval: libc::c_int = 0;
    let mut name: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathIsNodeType\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLangFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh160 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLastFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh161 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathLocalNameFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh162 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathModValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh163 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathMultValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh164 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNamespaceURIFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh165 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut val: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"i:xmlXPathNewBoolean\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut libc::c_int,
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
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathNewCString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut val as *mut *mut libc::c_char,
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
        b"O:xmlXPathNewContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut val: libc::c_double = 0.;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"d:xmlXPathNewFloat\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut val as *mut libc::c_double,
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
        b"O:xmlXPathNewNodeSet\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"zO:xmlXPathNewParserContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"z:xmlXPathNewString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathNewValueTree\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextAncestor\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextAncestorOrSelf\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextAttribute\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextChild\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextDescendant\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextDescendantOrSelf\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextFollowing\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextFollowingSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextNamespace\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextParent\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextPreceding\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextPrecedingSibling\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OO:xmlXPathNextSelf\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"OzO:xmlXPathNodeEval\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathNodeSetFreeNs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh166 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNormalizeFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh167 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh167 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathNotEqualValues(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathNotEqualValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNotFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh168 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlXPathNsLookup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathNumberFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh169 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh169 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathOrderDocElems(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_long = 0;
    let mut doc: xmlDocPtr = 0 as *mut xmlDoc;
    let mut pyobj_doc: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathOrderDocElems\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathParseNCName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathParseName\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathParserGetContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathPopBoolean\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut c_retval: libc::c_double = 0.;
    let mut ctxt: xmlXPathParserContextPtr = 0 as *mut xmlXPathParserContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"O:xmlXPathPopNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathPopString\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathPositionFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh170 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathRegisterAllFunctions\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh171 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh171 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathRegisterNs(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_int = 0;
    let mut ctxt: xmlXPathContextPtr = 0 as *mut xmlXPathContext;
    let mut pyobj_ctxt: *mut PyObject = 0 as *mut PyObject;
    let mut prefix: *mut xmlChar = 0 as *mut xmlChar;
    let mut ns_uri: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozz:xmlXPathRegisterNs\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"O:xmlXPathRegisteredFuncsCleanup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh172 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathRegisteredNsCleanup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh173 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathRegisteredVariablesCleanup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh174 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathRoot\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
    let ref mut fresh175 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathRoundFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh176 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlXPathSetContextDoc\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh177 = (*ctxt).doc;
    *fresh177 = doc;
    let ref mut fresh178 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"OO:xmlXPathSetContextNode\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh179 = (*ctxt).node;
    *fresh179 = node;
    let ref mut fresh180 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStartsWithFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh181 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
    *fresh181 += 1;
    return &mut _Py_NoneStruct;
}
#[no_mangle]
pub unsafe extern "C" fn libxml_xmlXPathStringEvalNumber(
    mut self_0: *mut PyObject,
    mut args: *mut PyObject,
) -> *mut PyObject {
    let mut py_retval: *mut PyObject = 0 as *mut PyObject;
    let mut c_retval: libc::c_double = 0.;
    let mut str: *mut xmlChar = 0 as *mut xmlChar;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"z:xmlXPathStringEvalNumber\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStringFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh182 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathStringLengthFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh183 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathSubValues\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh184 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringAfterFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh185 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringBeforeFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh186 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSubstringFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh187 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathSumFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh188 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathTranslateFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh189 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
    let mut nargs: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Oi:xmlXPathTrueFunction\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut nargs as *mut libc::c_int,
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
    let ref mut fresh190 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"O:xmlXPathValueFlipSign\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let ref mut fresh191 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"Oz:xmlXPathVariableLookup\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
        b"Ozz:xmlXPathVariableLookupNS\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
    let mut file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: libc::c_int = 0;
    let mut no: libc::c_int = 0;
    if _PyArg_ParseTuple_SizeT(
        args,
        b"Ozii:xmlXPatherror\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        &mut pyobj_ctxt as *mut *mut PyObject,
        &mut file as *mut *mut libc::c_char,
        &mut line as *mut libc::c_int,
        &mut no as *mut libc::c_int,
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
    let ref mut fresh192 = (*(&mut _Py_NoneStruct as *mut PyObject)).ob_refcnt;
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
        b"zO:xmlXPtrEval\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
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
        b"OOO:xmlXPtrNewContext\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
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
