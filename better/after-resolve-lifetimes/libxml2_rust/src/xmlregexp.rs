use ::libc;
extern "C" {
    
    
    
    
    
    
    
    
    static mut stderr: * mut crate::src::tree::_IO_FILE;
    fn fprintf(_: * mut crate::src::tree::_IO_FILE, _: * const i8, _: ...) -> i32;
    fn printf(_: * const i8, _: ...) -> i32;
    fn snprintf(
        _: * mut i8,
        _: u64,
        _: * const i8,
        _: ...
    ) -> i32;
    
    
    
    
    fn memcpy(
        _: * mut core::ffi::c_void,
        _: * const core::ffi::c_void,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn memset(
        _: * mut core::ffi::c_void,
        _: i32,
        _: u64,
    ) -> * mut core::ffi::c_void;
    fn strlen(_: * const i8) -> u64;
    static mut xmlFree: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
    fn __xmlRaiseError(
        schannel: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::threads::_xmlError,) -> ()>,
        channel: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>,
        data: * mut core::ffi::c_void,
        ctx: * mut core::ffi::c_void,
        node: * mut core::ffi::c_void,
        domain: i32,
        code: i32,
        level: u32,
        file: * const i8,
        line: i32,
        str1: * const i8,
        str2: * const i8,
        str3: * const i8,
        int1: i32,
        col: i32,
        msg: * const i8,
        _: ...
    );
    static mut xmlMalloc: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
    static mut xmlRealloc: Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
    static mut xmlMallocAtomic: Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
    fn __xmlGenericErrorContext() -> * mut * mut core::ffi::c_void;
    fn __xmlGenericError() -> * mut Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
    fn xmlCharInRange(val: u32, group: * const crate::src::tree::_xmlChRangeGroup) -> i32;
    static xmlIsBaseCharGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsCombiningGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsDigitGroup: crate::src::tree::_xmlChRangeGroup;
    static xmlIsExtenderGroup: crate::src::tree::_xmlChRangeGroup;
    fn xmlStringCurrentChar(
        ctxt: * mut crate::src::tree::_xmlParserCtxt,
        cur: * const u8,
        len: * mut i32,
    ) -> i32;
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
}
pub use crate::src::xmlstring::xmlStrEqual;
pub use crate::src::xmlstring::xmlStrchr;
pub use crate::src::xmlstring::xmlStrdup;
pub use crate::src::xmlstring::xmlStrndup;
pub use crate::src::xmlunicode::xmlUCSIsBlock;
pub use crate::src::xmlunicode::xmlUCSIsCatC;
pub use crate::src::xmlunicode::xmlUCSIsCatCc;
pub use crate::src::xmlunicode::xmlUCSIsCatCf;
pub use crate::src::xmlunicode::xmlUCSIsCatCo;
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
pub use crate::src::valid::_xmlValidState;
pub use crate::src::xmllint::_IO_marker;
pub use crate::src::xmlmemory::_IO_wide_data;
pub use crate::src::xmlsave::_IO_codecvt;
pub use crate::src::xmlsave::_xmlHashTable;
pub use crate::src::xmlstring::_xmlBuf;
pub use crate::src::xmlstring::_xmlStartTag;
pub use crate::src::xpointer::_xmlDict;
pub type xmlChar = u8;
pub type size_t = u64;
pub type __off_t = i64;
pub type __off64_t = i64;
// #[derive(Copy, Clone)]

pub type _IO_FILE = crate::src::tree::_IO_FILE;
pub type _IO_lock_t = ();
pub type FILE = crate::src::tree::_IO_FILE;
// #[derive(Copy, Clone)]

pub type _xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlBufPtr = * mut crate::src::xmlstring::_xmlBuf;
pub type xmlBuf = crate::src::xmlstring::_xmlBuf;
pub type xmlCharEncodingHandlerPtr = * mut crate::src::threads::_xmlCharEncodingHandler;
pub type xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
// #[derive(Copy, Clone)]

pub type _xmlCharEncodingHandler = crate::src::threads::_xmlCharEncodingHandler;
pub type iconv_t = * mut core::ffi::c_void;
pub type xmlCharEncodingOutputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlCharEncodingInputFunc = Option<unsafe extern "C"  fn(_: * mut u8,_: * mut i32,_: * const u8,_: * mut i32,) -> i32>;
pub type xmlInputCloseCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type xmlInputReadCallback = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut i8,_: i32,) -> i32>;
pub type xmlParserInputBuffer = crate::src::threads::_xmlParserInputBuffer;
pub type xmlParserInputBufferPtr = * mut crate::src::threads::_xmlParserInputBuffer;
// #[derive(Copy, Clone)]

pub type _xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputDeallocate = Option<unsafe extern "C"  fn(_: * mut u8,) -> ()>;
pub type xmlParserInput = crate::src::threads::_xmlParserInput;
pub type xmlParserInputPtr = * mut crate::src::threads::_xmlParserInput;
// #[derive(Copy, Clone)]

pub type _xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfo = crate::src::tree::_xmlParserNodeInfo;
// #[derive(Copy, Clone)]

pub type _xmlNode = crate::src::threads::_xmlNode;
pub type xmlNs = crate::src::threads::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlNs = crate::src::threads::_xmlNs;
// #[derive(Copy, Clone)]

pub type _xmlDoc = crate::src::threads::_xmlDoc;
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

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
// #[derive(Copy, Clone)]

pub type _xmlError = crate::src::threads::_xmlError;
pub type xmlErrorLevel = u32;
pub const XML_ERR_FATAL: xmlErrorLevel = 3;
pub const XML_ERR_ERROR: xmlErrorLevel = 2;
pub const XML_ERR_WARNING: xmlErrorLevel = 1;
pub const XML_ERR_NONE: xmlErrorLevel = 0;
pub type xmlAttrPtr = * mut crate::src::threads::_xmlAttr;
pub type xmlAttr = crate::src::threads::_xmlAttr;
pub type xmlNodePtr = * mut crate::src::threads::_xmlNode;
pub type xmlNode = crate::src::threads::_xmlNode;
pub type xmlHashTablePtr = * mut crate::src::xmlsave::_xmlHashTable;
pub type xmlHashTable = crate::src::xmlsave::_xmlHashTable;
pub type xmlStartTag = crate::src::xmlstring::_xmlStartTag;
pub type xmlDictPtr = * mut crate::src::xpointer::_xmlDict;
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
// #[derive(Copy, Clone)]

pub type _xmlValidCtxt = crate::src::tree::_xmlValidCtxt;
pub type xmlAutomataStatePtr = * mut crate::src::xmlregexp::_xmlAutomataState;
pub type xmlAutomataState = crate::src::xmlregexp::_xmlAutomataState;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAutomataState {
    pub type_0: u32,
    pub mark: u32,
    pub markd: u32,
    pub reached: u32,
    pub no: i32,
    pub maxTrans: i32,
    pub nbTrans: i32,
    pub trans: * mut crate::src::xmlregexp::_xmlRegTrans,
    pub maxTransTo: i32,
    pub nbTransTo: i32,
    pub transTo: * mut i32,
}
impl _xmlAutomataState {
    pub const fn new() -> Self {
        _xmlAutomataState {
        type_0: 0,
        mark: 0,
        markd: 0,
        reached: 0,
        no: 0,
        maxTrans: 0,
        nbTrans: 0,
        trans: (0 as * mut crate::src::xmlregexp::_xmlRegTrans),
        maxTransTo: 0,
        nbTransTo: 0,
        transTo: (0 as * mut i32)
        }
    }
}

impl std::default::Default for _xmlAutomataState {
    fn default() -> Self { _xmlAutomataState::new() }
}

pub type xmlRegTrans = crate::src::xmlregexp::_xmlRegTrans;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegTrans {
    pub atom: * mut crate::src::xmlregexp::_xmlRegAtom,
    pub to: i32,
    pub counter: i32,
    pub count: i32,
    pub nd: i32,
}
impl _xmlRegTrans {
    pub const fn new() -> Self {
        _xmlRegTrans {
        atom: (0 as * mut crate::src::xmlregexp::_xmlRegAtom),
        to: 0,
        counter: 0,
        count: 0,
        nd: 0
        }
    }
}

impl std::default::Default for _xmlRegTrans {
    fn default() -> Self { _xmlRegTrans::new() }
}

pub type xmlRegAtomPtr = * mut crate::src::xmlregexp::_xmlRegAtom;
pub type xmlRegAtom = crate::src::xmlregexp::_xmlRegAtom;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegAtom {
    pub no: i32,
    pub type_0: u32,
    pub quant: u32,
    pub min: i32,
    pub max: i32,
    pub valuep: * mut core::ffi::c_void,
    pub valuep2: * mut core::ffi::c_void,
    pub neg: i32,
    pub codepoint: i32,
    pub start: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub start0: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub stop: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub maxRanges: i32,
    pub nbRanges: i32,
    pub ranges: * mut * mut crate::src::xmlregexp::_xmlRegRange,
    pub data: * mut core::ffi::c_void,
}
impl _xmlRegAtom {
    pub const fn new() -> Self {
        _xmlRegAtom {
        no: 0,
        type_0: 0,
        quant: 0,
        min: 0,
        max: 0,
        valuep: (0 as * mut core::ffi::c_void),
        valuep2: (0 as * mut core::ffi::c_void),
        neg: 0,
        codepoint: 0,
        start: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        start0: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        stop: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        maxRanges: 0,
        nbRanges: 0,
        ranges: (0 as * mut * mut crate::src::xmlregexp::_xmlRegRange),
        data: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for _xmlRegAtom {
    fn default() -> Self { _xmlRegAtom::new() }
}

pub type xmlRegRangePtr = * mut crate::src::xmlregexp::_xmlRegRange;
pub type xmlRegRange = crate::src::xmlregexp::_xmlRegRange;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegRange {
    pub neg: i32,
    pub type_0: u32,
    pub start: i32,
    pub end: i32,
    pub blockName: * mut u8,
}
impl _xmlRegRange {
    pub const fn new() -> Self {
        _xmlRegRange {
        neg: 0,
        type_0: 0,
        start: 0,
        end: 0,
        blockName: (0 as * mut u8)
        }
    }
}

impl std::default::Default for _xmlRegRange {
    fn default() -> Self { _xmlRegRange::new() }
}

pub type xmlRegAtomType = u32;
pub const XML_REGEXP_BLOCK_NAME: xmlRegAtomType = 136;
pub const XML_REGEXP_OTHER_NA: xmlRegAtomType = 135;
pub const XML_REGEXP_OTHER_PRIVATE: xmlRegAtomType = 134;
pub const XML_REGEXP_OTHER_FORMAT: xmlRegAtomType = 133;
pub const XML_REGEXP_OTHER_CONTROL: xmlRegAtomType = 132;
pub const XML_REGEXP_OTHER: xmlRegAtomType = 131;
pub const XML_REGEXP_SYMBOL_OTHERS: xmlRegAtomType = 130;
pub const XML_REGEXP_SYMBOL_MODIFIER: xmlRegAtomType = 129;
pub const XML_REGEXP_SYMBOL_CURRENCY: xmlRegAtomType = 128;
pub const XML_REGEXP_SYMBOL_MATH: xmlRegAtomType = 127;
pub const XML_REGEXP_SYMBOL: xmlRegAtomType = 126;
pub const XML_REGEXP_SEPAR_PARA: xmlRegAtomType = 125;
pub const XML_REGEXP_SEPAR_LINE: xmlRegAtomType = 124;
pub const XML_REGEXP_SEPAR_SPACE: xmlRegAtomType = 123;
pub const XML_REGEXP_SEPAR: xmlRegAtomType = 122;
pub const XML_REGEXP_PUNCT_OTHERS: xmlRegAtomType = 121;
pub const XML_REGEXP_PUNCT_FINQUOTE: xmlRegAtomType = 120;
pub const XML_REGEXP_PUNCT_INITQUOTE: xmlRegAtomType = 119;
pub const XML_REGEXP_PUNCT_CLOSE: xmlRegAtomType = 118;
pub const XML_REGEXP_PUNCT_OPEN: xmlRegAtomType = 117;
pub const XML_REGEXP_PUNCT_DASH: xmlRegAtomType = 116;
pub const XML_REGEXP_PUNCT_CONNECTOR: xmlRegAtomType = 115;
pub const XML_REGEXP_PUNCT: xmlRegAtomType = 114;
pub const XML_REGEXP_NUMBER_OTHERS: xmlRegAtomType = 113;
pub const XML_REGEXP_NUMBER_LETTER: xmlRegAtomType = 112;
pub const XML_REGEXP_NUMBER_DECIMAL: xmlRegAtomType = 111;
pub const XML_REGEXP_NUMBER: xmlRegAtomType = 110;
pub const XML_REGEXP_MARK_ENCLOSING: xmlRegAtomType = 109;
pub const XML_REGEXP_MARK_SPACECOMBINING: xmlRegAtomType = 108;
pub const XML_REGEXP_MARK_NONSPACING: xmlRegAtomType = 107;
pub const XML_REGEXP_MARK: xmlRegAtomType = 106;
pub const XML_REGEXP_LETTER_OTHERS: xmlRegAtomType = 105;
pub const XML_REGEXP_LETTER_MODIFIER: xmlRegAtomType = 104;
pub const XML_REGEXP_LETTER_TITLECASE: xmlRegAtomType = 103;
pub const XML_REGEXP_LETTER_LOWERCASE: xmlRegAtomType = 102;
pub const XML_REGEXP_LETTER_UPPERCASE: xmlRegAtomType = 101;
pub const XML_REGEXP_LETTER: xmlRegAtomType = 100;
pub const XML_REGEXP_NOTREALCHAR: xmlRegAtomType = 16;
pub const XML_REGEXP_REALCHAR: xmlRegAtomType = 15;
pub const XML_REGEXP_NOTDECIMAL: xmlRegAtomType = 14;
pub const XML_REGEXP_DECIMAL: xmlRegAtomType = 13;
pub const XML_REGEXP_NOTNAMECHAR: xmlRegAtomType = 12;
pub const XML_REGEXP_NAMECHAR: xmlRegAtomType = 11;
pub const XML_REGEXP_NOTINITNAME: xmlRegAtomType = 10;
pub const XML_REGEXP_INITNAME: xmlRegAtomType = 9;
pub const XML_REGEXP_NOTSPACE: xmlRegAtomType = 8;
pub const XML_REGEXP_ANYSPACE: xmlRegAtomType = 7;
pub const XML_REGEXP_ANYCHAR: xmlRegAtomType = 6;
pub const XML_REGEXP_STRING: xmlRegAtomType = 5;
pub const XML_REGEXP_SUBREG: xmlRegAtomType = 4;
pub const XML_REGEXP_RANGES: xmlRegAtomType = 3;
pub const XML_REGEXP_CHARVAL: xmlRegAtomType = 2;
pub const XML_REGEXP_EPSILON: xmlRegAtomType = 1;
pub type xmlRegStatePtr = * mut crate::src::xmlregexp::_xmlAutomataState;
pub type xmlRegState = crate::src::xmlregexp::_xmlAutomataState;
pub type xmlRegQuantType = u32;
pub const XML_REGEXP_QUANT_RANGE: xmlRegQuantType = 8;
pub const XML_REGEXP_QUANT_ALL: xmlRegQuantType = 7;
pub const XML_REGEXP_QUANT_ONCEONLY: xmlRegQuantType = 6;
pub const XML_REGEXP_QUANT_PLUS: xmlRegQuantType = 5;
pub const XML_REGEXP_QUANT_MULT: xmlRegQuantType = 4;
pub const XML_REGEXP_QUANT_OPT: xmlRegQuantType = 3;
pub const XML_REGEXP_QUANT_ONCE: xmlRegQuantType = 2;
pub const XML_REGEXP_QUANT_EPSILON: xmlRegQuantType = 1;
pub type xmlRegMarkedType = u32;
pub const XML_REGEXP_MARK_VISITED: xmlRegMarkedType = 2;
pub const XML_REGEXP_MARK_START: xmlRegMarkedType = 1;
pub const XML_REGEXP_MARK_NORMAL: xmlRegMarkedType = 0;
pub type xmlRegStateType = u32;
pub const XML_REGEXP_UNREACH_STATE: xmlRegStateType = 5;
pub const XML_REGEXP_SINK_STATE: xmlRegStateType = 4;
pub const XML_REGEXP_TRANS_STATE: xmlRegStateType = 3;
pub const XML_REGEXP_FINAL_STATE: xmlRegStateType = 2;
pub const XML_REGEXP_START_STATE: xmlRegStateType = 1;
pub type xmlAutomataPtr = * mut crate::src::xmlregexp::_xmlAutomata;
pub type xmlAutomata = crate::src::xmlregexp::_xmlAutomata;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlAutomata {
    pub string: * mut u8,
    pub cur: * mut u8,
    pub error: i32,
    pub neg: i32,
    pub start: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub end: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub state: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub atom: * mut crate::src::xmlregexp::_xmlRegAtom,
    pub maxAtoms: i32,
    pub nbAtoms: i32,
    pub atoms: * mut * mut crate::src::xmlregexp::_xmlRegAtom,
    pub maxStates: i32,
    pub nbStates: i32,
    pub states: * mut * mut crate::src::xmlregexp::_xmlAutomataState,
    pub maxCounters: i32,
    pub nbCounters: i32,
    pub counters: * mut crate::src::xmlregexp::_xmlRegCounter,
    pub determinist: i32,
    pub negs: i32,
    pub flags: i32,
    pub depth: i32,
}
impl _xmlAutomata {
    pub const fn new() -> Self {
        _xmlAutomata {
        string: (0 as * mut u8),
        cur: (0 as * mut u8),
        error: 0,
        neg: 0,
        start: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        end: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        state: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        atom: (0 as * mut crate::src::xmlregexp::_xmlRegAtom),
        maxAtoms: 0,
        nbAtoms: 0,
        atoms: (0 as * mut * mut crate::src::xmlregexp::_xmlRegAtom),
        maxStates: 0,
        nbStates: 0,
        states: (0 as * mut * mut crate::src::xmlregexp::_xmlAutomataState),
        maxCounters: 0,
        nbCounters: 0,
        counters: (0 as * mut crate::src::xmlregexp::_xmlRegCounter),
        determinist: 0,
        negs: 0,
        flags: 0,
        depth: 0
        }
    }
}

impl std::default::Default for _xmlAutomata {
    fn default() -> Self { _xmlAutomata::new() }
}

pub type xmlRegCounter = crate::src::xmlregexp::_xmlRegCounter;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegCounter {
    pub min: i32,
    pub max: i32,
}
impl _xmlRegCounter {
    pub const fn new() -> Self {
        _xmlRegCounter {
        min: 0,
        max: 0
        }
    }
}

impl std::default::Default for _xmlRegCounter {
    fn default() -> Self { _xmlRegCounter::new() }
}

pub type xmlValidState = crate::src::valid::_xmlValidState;
pub type xmlDocPtr = * mut crate::src::threads::_xmlDoc;
pub type xmlDoc = crate::src::threads::_xmlDoc;
pub type xmlValidityWarningFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlValidityErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlParserNodeInfoSeq = crate::src::tree::_xmlParserNodeInfoSeq;
// #[derive(Copy, Clone)]

pub type _xmlSAXHandler = crate::src::tree::_xmlSAXHandler;
pub type xmlStructuredErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::threads::_xmlError,) -> ()>;
pub type xmlErrorPtr = * mut crate::src::threads::_xmlError;
pub type endElementNsSAX2Func = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type startElementNsSAX2Func = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,_: i32,_: * mut * const u8,_: i32,_: i32,_: * mut * const u8,) -> ()>;
pub type externalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type cdataBlockSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type getParameterEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::threads::_xmlEntity>;
pub type xmlEntityPtr = * mut crate::src::threads::_xmlEntity;
pub type xmlEntity = crate::src::threads::_xmlEntity;
// #[derive(Copy, Clone)]

pub type _xmlEntity = crate::src::threads::_xmlEntity;
pub type xmlEntityType = u32;
pub const XML_INTERNAL_PREDEFINED_ENTITY: xmlEntityType = 6;
pub const XML_EXTERNAL_PARAMETER_ENTITY: xmlEntityType = 5;
pub const XML_INTERNAL_PARAMETER_ENTITY: xmlEntityType = 4;
pub const XML_EXTERNAL_GENERAL_UNPARSED_ENTITY: xmlEntityType = 3;
pub const XML_EXTERNAL_GENERAL_PARSED_ENTITY: xmlEntityType = 2;
pub const XML_INTERNAL_GENERAL_ENTITY: xmlEntityType = 1;
pub type fatalErrorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type errorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type warningSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type commentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type processingInstructionSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> ()>;
pub type ignorableWhitespaceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type charactersSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,) -> ()>;
pub type referenceSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type endElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> ()>;
pub type startElementSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * mut * const u8,) -> ()>;
pub type endDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type startDocumentSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type setDocumentLocatorSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * mut crate::src::threads::_xmlSAXLocator,) -> ()>;
pub type xmlSAXLocatorPtr = * mut crate::src::threads::_xmlSAXLocator;
pub type xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
// #[derive(Copy, Clone)]

pub type _xmlSAXLocator = crate::src::threads::_xmlSAXLocator;
pub type unparsedEntityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type elementDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * mut crate::src::threads::_xmlElementContent,) -> ()>;
pub type xmlElementContentPtr = * mut crate::src::threads::_xmlElementContent;
pub type xmlElementContent = crate::src::threads::_xmlElementContent;
// #[derive(Copy, Clone)]

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
pub type attributeDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: i32,_: i32,_: * const u8,_: * mut crate::src::threads::_xmlEnumeration,) -> ()>;
pub type xmlEnumerationPtr = * mut crate::src::threads::_xmlEnumeration;
pub type xmlEnumeration = crate::src::threads::_xmlEnumeration;
// #[derive(Copy, Clone)]

pub type _xmlEnumeration = crate::src::threads::_xmlEnumeration;
pub type notationDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type entityDeclSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: i32,_: * const u8,_: * const u8,_: * mut u8,) -> ()>;
pub type getEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,) -> * mut crate::src::threads::_xmlEntity>;
pub type resolveEntitySAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,) -> * mut crate::src::threads::_xmlParserInput>;
pub type hasExternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type hasInternalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type isStandaloneSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> i32>;
pub type internalSubsetSAXFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const u8,_: * const u8,_: * const u8,) -> ()>;
pub type xmlParserCtxt = crate::src::tree::_xmlParserCtxt;
pub type xmlParserCtxtPtr = * mut crate::src::tree::_xmlParserCtxt;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegexp {
    pub string: * mut u8,
    pub nbStates: i32,
    pub states: * mut * mut crate::src::xmlregexp::_xmlAutomataState,
    pub nbAtoms: i32,
    pub atoms: * mut * mut crate::src::xmlregexp::_xmlRegAtom,
    pub nbCounters: i32,
    pub counters: * mut crate::src::xmlregexp::_xmlRegCounter,
    pub determinist: i32,
    pub flags: i32,
    pub nbstates: i32,
    pub compact: * mut i32,
    pub transdata: * mut * mut core::ffi::c_void,
    pub nbstrings: i32,
    pub stringMap: * mut * mut u8,
}
impl _xmlRegexp {
    pub const fn new() -> Self {
        _xmlRegexp {
        string: (0 as * mut u8),
        nbStates: 0,
        states: (0 as * mut * mut crate::src::xmlregexp::_xmlAutomataState),
        nbAtoms: 0,
        atoms: (0 as * mut * mut crate::src::xmlregexp::_xmlRegAtom),
        nbCounters: 0,
        counters: (0 as * mut crate::src::xmlregexp::_xmlRegCounter),
        determinist: 0,
        flags: 0,
        nbstates: 0,
        compact: (0 as * mut i32),
        transdata: (0 as * mut * mut core::ffi::c_void),
        nbstrings: 0,
        stringMap: (0 as * mut * mut u8)
        }
    }
}

impl std::default::Default for _xmlRegexp {
    fn default() -> Self { _xmlRegexp::new() }
}

pub type xmlRegexp = crate::src::xmlregexp::_xmlRegexp;
pub type xmlRegexpPtr = * mut crate::src::xmlregexp::_xmlRegexp;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegExecCtxt {
    pub status: i32,
    pub determinist: i32,
    pub comp: * mut crate::src::xmlregexp::_xmlRegexp,
    pub callback: Option<unsafe extern "C"  fn(_: * mut crate::src::xmlregexp::_xmlRegExecCtxt,_: * const u8,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>,
    pub data: * mut core::ffi::c_void,
    pub state: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub transno: i32,
    pub transcount: i32,
    pub maxRollbacks: i32,
    pub nbRollbacks: i32,
    pub rollbacks: * mut crate::src::xmlregexp::_xmlRegExecRollback,
    pub counts: * mut i32,
    pub inputStackMax: i32,
    pub inputStackNr: i32,
    pub index: i32,
    pub charStack: * mut i32,
    pub inputString: * const u8,
    pub inputStack: * mut crate::src::xmlregexp::_xmlRegInputToken,
    pub errStateNo: i32,
    pub errState: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub errString: * mut u8,
    pub errCounts: * mut i32,
    pub nbPush: i32,
}
impl _xmlRegExecCtxt {
    pub const fn new() -> Self {
        _xmlRegExecCtxt {
        status: 0,
        determinist: 0,
        comp: (0 as * mut crate::src::xmlregexp::_xmlRegexp),
        callback: None,
        data: (0 as * mut core::ffi::c_void),
        state: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        transno: 0,
        transcount: 0,
        maxRollbacks: 0,
        nbRollbacks: 0,
        rollbacks: (0 as * mut crate::src::xmlregexp::_xmlRegExecRollback),
        counts: (0 as * mut i32),
        inputStackMax: 0,
        inputStackNr: 0,
        index: 0,
        charStack: (0 as * mut i32),
        inputString: (0 as * const u8),
        inputStack: (0 as * mut crate::src::xmlregexp::_xmlRegInputToken),
        errStateNo: 0,
        errState: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        errString: (0 as * mut u8),
        errCounts: (0 as * mut i32),
        nbPush: 0
        }
    }
}

impl std::default::Default for _xmlRegExecCtxt {
    fn default() -> Self { _xmlRegExecCtxt::new() }
}

pub type xmlRegInputTokenPtr = * mut crate::src::xmlregexp::_xmlRegInputToken;
pub type xmlRegInputToken = crate::src::xmlregexp::_xmlRegInputToken;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegInputToken {
    pub value: * mut u8,
    pub data: * mut core::ffi::c_void,
}
impl _xmlRegInputToken {
    pub const fn new() -> Self {
        _xmlRegInputToken {
        value: (0 as * mut u8),
        data: (0 as * mut core::ffi::c_void)
        }
    }
}

impl std::default::Default for _xmlRegInputToken {
    fn default() -> Self { _xmlRegInputToken::new() }
}

pub type xmlRegExecRollback = crate::src::xmlregexp::_xmlRegExecRollback;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _xmlRegExecRollback {
    pub state: * mut crate::src::xmlregexp::_xmlAutomataState,
    pub index: i32,
    pub nextbranch: i32,
    pub counts: * mut i32,
}
impl _xmlRegExecRollback {
    pub const fn new() -> Self {
        _xmlRegExecRollback {
        state: (0 as * mut crate::src::xmlregexp::_xmlAutomataState),
        index: 0,
        nextbranch: 0,
        counts: (0 as * mut i32)
        }
    }
}

impl std::default::Default for _xmlRegExecRollback {
    fn default() -> Self { _xmlRegExecRollback::new() }
}

pub type xmlRegExecCallbacks = Option<unsafe extern "C"  fn(_: * mut crate::src::xmlregexp::_xmlRegExecCtxt,_: * const u8,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>;
pub type xmlRegExecCtxtPtr = * mut crate::src::xmlregexp::_xmlRegExecCtxt;
pub type xmlRegExecCtxt = crate::src::xmlregexp::_xmlRegExecCtxt;
pub type xmlRegParserCtxtPtr = * mut crate::src::xmlregexp::_xmlAutomata;
pub type xmlRegParserCtxt = crate::src::xmlregexp::_xmlAutomata;
pub type xmlFreeFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,) -> ()>;
pub type xmlRegTransPtr = * mut crate::src::xmlregexp::_xmlRegTrans;
pub const XML_ERR_NO_MEMORY: C2RustUnnamed_0 = 2;
pub const XML_FROM_REGEXP: C2RustUnnamed = 14;
pub type xmlGenericErrorFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: * const i8,...) -> ()>;
pub type xmlMallocFunc = Option<unsafe extern "C"  fn(_: u64,) -> * mut core::ffi::c_void>;
pub type xmlChRangeGroup = crate::src::tree::_xmlChRangeGroup;
// #[derive(Copy, Clone)]

pub type _xmlChRangeGroup = crate::src::tree::_xmlChRangeGroup;
pub type xmlChLRange = crate::src::tree::_xmlChLRange;
// #[derive(Copy, Clone)]

pub type _xmlChLRange = crate::src::tree::_xmlChLRange;
pub type xmlChSRange = crate::src::tree::_xmlChSRange;
// #[derive(Copy, Clone)]

pub type _xmlChSRange = crate::src::tree::_xmlChSRange;
pub type xmlReallocFunc = Option<unsafe extern "C"  fn(_: * mut core::ffi::c_void,_: u64,) -> * mut core::ffi::c_void>;
pub const XML_REGEXP_COMPILE_ERROR: C2RustUnnamed_0 = 1450;
pub type xmlRegCounterPtr = * mut crate::src::xmlregexp::_xmlRegCounter;
pub type C2RustUnnamed = u32;
pub const XML_FROM_URI: C2RustUnnamed = 30;
pub const XML_FROM_BUFFER: C2RustUnnamed = 29;
pub const XML_FROM_SCHEMATRONV: C2RustUnnamed = 28;
pub const XML_FROM_I18N: C2RustUnnamed = 27;
pub const XML_FROM_MODULE: C2RustUnnamed = 26;
pub const XML_FROM_WRITER: C2RustUnnamed = 25;
pub const XML_FROM_CHECK: C2RustUnnamed = 24;
pub const XML_FROM_VALID: C2RustUnnamed = 23;
pub const XML_FROM_XSLT: C2RustUnnamed = 22;
pub const XML_FROM_C14N: C2RustUnnamed = 21;
pub const XML_FROM_CATALOG: C2RustUnnamed = 20;
pub const XML_FROM_RELAXNGV: C2RustUnnamed = 19;
pub const XML_FROM_RELAXNGP: C2RustUnnamed = 18;
pub const XML_FROM_SCHEMASV: C2RustUnnamed = 17;
pub const XML_FROM_SCHEMASP: C2RustUnnamed = 16;
pub const XML_FROM_DATATYPE: C2RustUnnamed = 15;
pub const XML_FROM_XPOINTER: C2RustUnnamed = 13;
pub const XML_FROM_XPATH: C2RustUnnamed = 12;
pub const XML_FROM_XINCLUDE: C2RustUnnamed = 11;
pub const XML_FROM_HTTP: C2RustUnnamed = 10;
pub const XML_FROM_FTP: C2RustUnnamed = 9;
pub const XML_FROM_IO: C2RustUnnamed = 8;
pub const XML_FROM_OUTPUT: C2RustUnnamed = 7;
pub const XML_FROM_MEMORY: C2RustUnnamed = 6;
pub const XML_FROM_HTML: C2RustUnnamed = 5;
pub const XML_FROM_DTD: C2RustUnnamed = 4;
pub const XML_FROM_NAMESPACE: C2RustUnnamed = 3;
pub const XML_FROM_TREE: C2RustUnnamed = 2;
pub const XML_FROM_PARSER: C2RustUnnamed = 1;
pub const XML_FROM_NONE: C2RustUnnamed = 0;
pub type C2RustUnnamed_0 = u32;
pub const XML_BUF_OVERFLOW: C2RustUnnamed_0 = 7000;
pub const XML_I18N_NO_OUTPUT: C2RustUnnamed_0 = 6004;
pub const XML_I18N_CONV_FAILED: C2RustUnnamed_0 = 6003;
pub const XML_I18N_EXCESS_HANDLER: C2RustUnnamed_0 = 6002;
pub const XML_I18N_NO_HANDLER: C2RustUnnamed_0 = 6001;
pub const XML_I18N_NO_NAME: C2RustUnnamed_0 = 6000;
pub const XML_CHECK_NAME_NOT_NULL: C2RustUnnamed_0 = 5037;
pub const XML_CHECK_WRONG_NAME: C2RustUnnamed_0 = 5036;
pub const XML_CHECK_OUTSIDE_DICT: C2RustUnnamed_0 = 5035;
pub const XML_CHECK_NOT_NCNAME: C2RustUnnamed_0 = 5034;
pub const XML_CHECK_NO_DICT: C2RustUnnamed_0 = 5033;
pub const XML_CHECK_NOT_UTF8: C2RustUnnamed_0 = 5032;
pub const XML_CHECK_NS_ANCESTOR: C2RustUnnamed_0 = 5031;
pub const XML_CHECK_NS_SCOPE: C2RustUnnamed_0 = 5030;
pub const XML_CHECK_WRONG_PARENT: C2RustUnnamed_0 = 5029;
pub const XML_CHECK_NO_HREF: C2RustUnnamed_0 = 5028;
pub const XML_CHECK_NOT_NS_DECL: C2RustUnnamed_0 = 5027;
pub const XML_CHECK_NOT_ENTITY_DECL: C2RustUnnamed_0 = 5026;
pub const XML_CHECK_NOT_ELEM_DECL: C2RustUnnamed_0 = 5025;
pub const XML_CHECK_NOT_ATTR_DECL: C2RustUnnamed_0 = 5024;
pub const XML_CHECK_NOT_ATTR: C2RustUnnamed_0 = 5023;
pub const XML_CHECK_NOT_DTD: C2RustUnnamed_0 = 5022;
pub const XML_CHECK_WRONG_NEXT: C2RustUnnamed_0 = 5021;
pub const XML_CHECK_NO_NEXT: C2RustUnnamed_0 = 5020;
pub const XML_CHECK_WRONG_PREV: C2RustUnnamed_0 = 5019;
pub const XML_CHECK_NO_PREV: C2RustUnnamed_0 = 5018;
pub const XML_CHECK_WRONG_DOC: C2RustUnnamed_0 = 5017;
pub const XML_CHECK_NO_ELEM: C2RustUnnamed_0 = 5016;
pub const XML_CHECK_NO_NAME: C2RustUnnamed_0 = 5015;
pub const XML_CHECK_NO_DOC: C2RustUnnamed_0 = 5014;
pub const XML_CHECK_NO_PARENT: C2RustUnnamed_0 = 5013;
pub const XML_CHECK_ENTITY_TYPE: C2RustUnnamed_0 = 5012;
pub const XML_CHECK_UNKNOWN_NODE: C2RustUnnamed_0 = 5011;
pub const XML_CHECK_FOUND_NOTATION: C2RustUnnamed_0 = 5010;
pub const XML_CHECK_FOUND_FRAGMENT: C2RustUnnamed_0 = 5009;
pub const XML_CHECK_FOUND_DOCTYPE: C2RustUnnamed_0 = 5008;
pub const XML_CHECK_FOUND_COMMENT: C2RustUnnamed_0 = 5007;
pub const XML_CHECK_FOUND_PI: C2RustUnnamed_0 = 5006;
pub const XML_CHECK_FOUND_ENTITY: C2RustUnnamed_0 = 5005;
pub const XML_CHECK_FOUND_ENTITYREF: C2RustUnnamed_0 = 5004;
pub const XML_CHECK_FOUND_CDATA: C2RustUnnamed_0 = 5003;
pub const XML_CHECK_FOUND_TEXT: C2RustUnnamed_0 = 5002;
pub const XML_CHECK_FOUND_ATTRIBUTE: C2RustUnnamed_0 = 5001;
pub const XML_CHECK_FOUND_ELEMENT: C2RustUnnamed_0 = 5000;
pub const XML_MODULE_CLOSE: C2RustUnnamed_0 = 4901;
pub const XML_MODULE_OPEN: C2RustUnnamed_0 = 4900;
pub const XML_SCHEMATRONV_REPORT: C2RustUnnamed_0 = 4001;
pub const XML_SCHEMATRONV_ASSERT: C2RustUnnamed_0 = 4000;
pub const XML_SCHEMAP_COS_ALL_LIMITED: C2RustUnnamed_0 = 3091;
pub const XML_SCHEMAP_A_PROPS_CORRECT_3: C2RustUnnamed_0 = 3090;
pub const XML_SCHEMAP_AU_PROPS_CORRECT: C2RustUnnamed_0 = 3089;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_2: C2RustUnnamed_0 = 3088;
pub const XML_SCHEMAP_AG_PROPS_CORRECT: C2RustUnnamed_0 = 3087;
pub const XML_SCHEMAP_WARN_ATTR_POINTLESS_PROH: C2RustUnnamed_0 = 3086;
pub const XML_SCHEMAP_WARN_ATTR_REDECL_PROH: C2RustUnnamed_0 = 3085;
pub const XML_SCHEMAP_WARN_UNLOCATED_SCHEMA: C2RustUnnamed_0 = 3084;
pub const XML_SCHEMAP_WARN_SKIP_SCHEMA: C2RustUnnamed_0 = 3083;
pub const XML_SCHEMAP_SRC_IMPORT: C2RustUnnamed_0 = 3082;
pub const XML_SCHEMAP_SRC_REDEFINE: C2RustUnnamed_0 = 3081;
pub const XML_SCHEMAP_C_PROPS_CORRECT: C2RustUnnamed_0 = 3080;
pub const XML_SCHEMAP_A_PROPS_CORRECT_2: C2RustUnnamed_0 = 3079;
pub const XML_SCHEMAP_AU_PROPS_CORRECT_2: C2RustUnnamed_0 = 3078;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_3: C2RustUnnamed_0 = 3077;
pub const XML_SCHEMAP_SRC_CT_1: C2RustUnnamed_0 = 3076;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_2: C2RustUnnamed_0 = 3075;
pub const XML_SCHEMAP_MG_PROPS_CORRECT_1: C2RustUnnamed_0 = 3074;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_3: C2RustUnnamed_0 = 3073;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_2: C2RustUnnamed_0 = 3072;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_GROUP_1: C2RustUnnamed_0 = 3071;
pub const XML_SCHEMAP_NOT_DETERMINISTIC: C2RustUnnamed_0 = 3070;
pub const XML_SCHEMAP_INTERNAL: C2RustUnnamed_0 = 3069;
pub const XML_SCHEMAP_SRC_IMPORT_2_2: C2RustUnnamed_0 = 3068;
pub const XML_SCHEMAP_SRC_IMPORT_2_1: C2RustUnnamed_0 = 3067;
pub const XML_SCHEMAP_SRC_IMPORT_2: C2RustUnnamed_0 = 3066;
pub const XML_SCHEMAP_SRC_IMPORT_1_2: C2RustUnnamed_0 = 3065;
pub const XML_SCHEMAP_SRC_IMPORT_1_1: C2RustUnnamed_0 = 3064;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_1: C2RustUnnamed_0 = 3063;
pub const XML_SCHEMAP_CVC_SIMPLE_TYPE: C2RustUnnamed_0 = 3062;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_2: C2RustUnnamed_0 = 3061;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_2_1: C2RustUnnamed_0 = 3060;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_2_1: C2RustUnnamed_0 = 3059;
pub const XML_SCHEMAP_COS_VALID_DEFAULT_1: C2RustUnnamed_0 = 3058;
pub const XML_SCHEMAP_NO_XSI: C2RustUnnamed_0 = 3057;
pub const XML_SCHEMAP_NO_XMLNS: C2RustUnnamed_0 = 3056;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_4: C2RustUnnamed_0 = 3055;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_2: C2RustUnnamed_0 = 3054;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_3_1: C2RustUnnamed_0 = 3053;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_2: C2RustUnnamed_0 = 3052;
pub const XML_SCHEMAP_SRC_ATTRIBUTE_1: C2RustUnnamed_0 = 3051;
pub const XML_SCHEMAP_SRC_INCLUDE: C2RustUnnamed_0 = 3050;
pub const XML_SCHEMAP_E_PROPS_CORRECT_6: C2RustUnnamed_0 = 3049;
pub const XML_SCHEMAP_E_PROPS_CORRECT_5: C2RustUnnamed_0 = 3048;
pub const XML_SCHEMAP_E_PROPS_CORRECT_4: C2RustUnnamed_0 = 3047;
pub const XML_SCHEMAP_E_PROPS_CORRECT_3: C2RustUnnamed_0 = 3046;
pub const XML_SCHEMAP_E_PROPS_CORRECT_2: C2RustUnnamed_0 = 3045;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_2: C2RustUnnamed_0 = 3044;
pub const XML_SCHEMAP_P_PROPS_CORRECT_2_1: C2RustUnnamed_0 = 3043;
pub const XML_SCHEMAP_P_PROPS_CORRECT_1: C2RustUnnamed_0 = 3042;
pub const XML_SCHEMAP_SRC_ELEMENT_3: C2RustUnnamed_0 = 3041;
pub const XML_SCHEMAP_SRC_ELEMENT_2_2: C2RustUnnamed_0 = 3040;
pub const XML_SCHEMAP_SRC_ELEMENT_2_1: C2RustUnnamed_0 = 3039;
pub const XML_SCHEMAP_SRC_ELEMENT_1: C2RustUnnamed_0 = 3038;
pub const XML_SCHEMAP_S4S_ATTR_INVALID_VALUE: C2RustUnnamed_0 = 3037;
pub const XML_SCHEMAP_S4S_ATTR_MISSING: C2RustUnnamed_0 = 3036;
pub const XML_SCHEMAP_S4S_ATTR_NOT_ALLOWED: C2RustUnnamed_0 = 3035;
pub const XML_SCHEMAP_S4S_ELEM_MISSING: C2RustUnnamed_0 = 3034;
pub const XML_SCHEMAP_S4S_ELEM_NOT_ALLOWED: C2RustUnnamed_0 = 3033;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_2: C2RustUnnamed_0 = 3032;
pub const XML_SCHEMAP_COS_ST_DERIVED_OK_2_1: C2RustUnnamed_0 = 3031;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_5: C2RustUnnamed_0 = 3030;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_4: C2RustUnnamed_0 = 3029;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_3: C2RustUnnamed_0 = 3028;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_1: C2RustUnnamed_0 = 3027;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_2_2: C2RustUnnamed_0 = 3026;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1_2: C2RustUnnamed_0 = 3025;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_3_1: C2RustUnnamed_0 = 3024;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_3_1: C2RustUnnamed_0 = 3023;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_5: C2RustUnnamed_0 = 3022;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_4: C2RustUnnamed_0 = 3021;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_3: C2RustUnnamed_0 = 3020;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_2: C2RustUnnamed_0 = 3019;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_2_1: C2RustUnnamed_0 = 3018;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_2: C2RustUnnamed_0 = 3017;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_3_1_1: C2RustUnnamed_0 = 3016;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_2_1: C2RustUnnamed_0 = 3015;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_2: C2RustUnnamed_0 = 3014;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_3_1: C2RustUnnamed_0 = 3013;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_2: C2RustUnnamed_0 = 3012;
pub const XML_SCHEMAP_COS_ST_RESTRICTS_1_1: C2RustUnnamed_0 = 3011;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_3: C2RustUnnamed_0 = 3010;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_2: C2RustUnnamed_0 = 3009;
pub const XML_SCHEMAP_ST_PROPS_CORRECT_1: C2RustUnnamed_0 = 3008;
pub const XML_SCHEMAP_SRC_UNION_MEMBERTYPES_OR_SIMPLETYPES: C2RustUnnamed_0 = 3007;
pub const XML_SCHEMAP_SRC_LIST_ITEMTYPE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3006;
pub const XML_SCHEMAP_SRC_RESTRICTION_BASE_OR_SIMPLETYPE: C2RustUnnamed_0 = 3005;
pub const XML_SCHEMAP_SRC_RESOLVE: C2RustUnnamed_0 = 3004;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_4: C2RustUnnamed_0 = 3003;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_3: C2RustUnnamed_0 = 3002;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_2: C2RustUnnamed_0 = 3001;
pub const XML_SCHEMAP_SRC_SIMPLE_TYPE_1: C2RustUnnamed_0 = 3000;
pub const XML_HTTP_UNKNOWN_HOST: C2RustUnnamed_0 = 2022;
pub const XML_HTTP_USE_IP: C2RustUnnamed_0 = 2021;
pub const XML_HTTP_URL_SYNTAX: C2RustUnnamed_0 = 2020;
pub const XML_FTP_URL_SYNTAX: C2RustUnnamed_0 = 2003;
pub const XML_FTP_ACCNT: C2RustUnnamed_0 = 2002;
pub const XML_FTP_EPSV_ANSWER: C2RustUnnamed_0 = 2001;
pub const XML_FTP_PASV_ANSWER: C2RustUnnamed_0 = 2000;
pub const XML_C14N_RELATIVE_NAMESPACE: C2RustUnnamed_0 = 1955;
pub const XML_C14N_UNKNOW_NODE: C2RustUnnamed_0 = 1954;
pub const XML_C14N_INVALID_NODE: C2RustUnnamed_0 = 1953;
pub const XML_C14N_CREATE_STACK: C2RustUnnamed_0 = 1952;
pub const XML_C14N_REQUIRES_UTF8: C2RustUnnamed_0 = 1951;
pub const XML_C14N_CREATE_CTXT: C2RustUnnamed_0 = 1950;
pub const XML_XPTR_EXTRA_OBJECTS: C2RustUnnamed_0 = 1903;
pub const XML_XPTR_EVAL_FAILED: C2RustUnnamed_0 = 1902;
pub const XML_XPTR_CHILDSEQ_START: C2RustUnnamed_0 = 1901;
pub const XML_XPTR_UNKNOWN_SCHEME: C2RustUnnamed_0 = 1900;
pub const XML_SCHEMAV_MISC: C2RustUnnamed_0 = 1879;
pub const XML_SCHEMAV_CVC_WILDCARD: C2RustUnnamed_0 = 1878;
pub const XML_SCHEMAV_CVC_IDC: C2RustUnnamed_0 = 1877;
pub const XML_SCHEMAV_CVC_TYPE_2: C2RustUnnamed_0 = 1876;
pub const XML_SCHEMAV_CVC_TYPE_1: C2RustUnnamed_0 = 1875;
pub const XML_SCHEMAV_CVC_AU: C2RustUnnamed_0 = 1874;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_1: C2RustUnnamed_0 = 1873;
pub const XML_SCHEMAV_DOCUMENT_ELEMENT_MISSING: C2RustUnnamed_0 = 1872;
pub const XML_SCHEMAV_ELEMENT_CONTENT: C2RustUnnamed_0 = 1871;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_2: C2RustUnnamed_0 = 1870;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_5_1: C2RustUnnamed_0 = 1869;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_4: C2RustUnnamed_0 = 1868;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_2: C2RustUnnamed_0 = 1867;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_2_1: C2RustUnnamed_0 = 1866;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_3_1: C2RustUnnamed_0 = 1865;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_4: C2RustUnnamed_0 = 1864;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_3: C2RustUnnamed_0 = 1863;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_2: C2RustUnnamed_0 = 1862;
pub const XML_SCHEMAV_CVC_ATTRIBUTE_1: C2RustUnnamed_0 = 1861;
pub const XML_SCHEMAV_CVC_ELT_7: C2RustUnnamed_0 = 1860;
pub const XML_SCHEMAV_CVC_ELT_6: C2RustUnnamed_0 = 1859;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_2: C2RustUnnamed_0 = 1858;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_2_1: C2RustUnnamed_0 = 1857;
pub const XML_SCHEMAV_CVC_ELT_5_2_2_1: C2RustUnnamed_0 = 1856;
pub const XML_SCHEMAV_CVC_ELT_5_2_1: C2RustUnnamed_0 = 1855;
pub const XML_SCHEMAV_CVC_ELT_5_1_2: C2RustUnnamed_0 = 1854;
pub const XML_SCHEMAV_CVC_ELT_5_1_1: C2RustUnnamed_0 = 1853;
pub const XML_SCHEMAV_CVC_ELT_4_3: C2RustUnnamed_0 = 1852;
pub const XML_SCHEMAV_CVC_ELT_4_2: C2RustUnnamed_0 = 1851;
pub const XML_SCHEMAV_CVC_ELT_4_1: C2RustUnnamed_0 = 1850;
pub const XML_SCHEMAV_CVC_ELT_3_2_2: C2RustUnnamed_0 = 1849;
pub const XML_SCHEMAV_CVC_ELT_3_2_1: C2RustUnnamed_0 = 1848;
pub const XML_SCHEMAV_CVC_ELT_3_1: C2RustUnnamed_0 = 1847;
pub const XML_SCHEMAV_CVC_ELT_2: C2RustUnnamed_0 = 1846;
pub const XML_SCHEMAV_CVC_ELT_1: C2RustUnnamed_0 = 1845;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_4: C2RustUnnamed_0 = 1844;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_3: C2RustUnnamed_0 = 1843;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_2: C2RustUnnamed_0 = 1842;
pub const XML_SCHEMAV_CVC_COMPLEX_TYPE_2_1: C2RustUnnamed_0 = 1841;
pub const XML_SCHEMAV_CVC_ENUMERATION_VALID: C2RustUnnamed_0 = 1840;
pub const XML_SCHEMAV_CVC_PATTERN_VALID: C2RustUnnamed_0 = 1839;
pub const XML_SCHEMAV_CVC_FRACTIONDIGITS_VALID: C2RustUnnamed_0 = 1838;
pub const XML_SCHEMAV_CVC_TOTALDIGITS_VALID: C2RustUnnamed_0 = 1837;
pub const XML_SCHEMAV_CVC_MAXEXCLUSIVE_VALID: C2RustUnnamed_0 = 1836;
pub const XML_SCHEMAV_CVC_MINEXCLUSIVE_VALID: C2RustUnnamed_0 = 1835;
pub const XML_SCHEMAV_CVC_MAXINCLUSIVE_VALID: C2RustUnnamed_0 = 1834;
pub const XML_SCHEMAV_CVC_MININCLUSIVE_VALID: C2RustUnnamed_0 = 1833;
pub const XML_SCHEMAV_CVC_MAXLENGTH_VALID: C2RustUnnamed_0 = 1832;
pub const XML_SCHEMAV_CVC_MINLENGTH_VALID: C2RustUnnamed_0 = 1831;
pub const XML_SCHEMAV_CVC_LENGTH_VALID: C2RustUnnamed_0 = 1830;
pub const XML_SCHEMAV_CVC_FACET_VALID: C2RustUnnamed_0 = 1829;
pub const XML_SCHEMAV_CVC_TYPE_3_1_2: C2RustUnnamed_0 = 1828;
pub const XML_SCHEMAV_CVC_TYPE_3_1_1: C2RustUnnamed_0 = 1827;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_3: C2RustUnnamed_0 = 1826;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_2: C2RustUnnamed_0 = 1825;
pub const XML_SCHEMAV_CVC_DATATYPE_VALID_1_2_1: C2RustUnnamed_0 = 1824;
pub const XML_SCHEMAV_FACET: C2RustUnnamed_0 = 1823;
pub const XML_SCHEMAV_VALUE: C2RustUnnamed_0 = 1822;
pub const XML_SCHEMAV_ATTRINVALID: C2RustUnnamed_0 = 1821;
pub const XML_SCHEMAV_ATTRUNKNOWN: C2RustUnnamed_0 = 1820;
pub const XML_SCHEMAV_NOTSIMPLE: C2RustUnnamed_0 = 1819;
pub const XML_SCHEMAV_INTERNAL: C2RustUnnamed_0 = 1818;
pub const XML_SCHEMAV_CONSTRUCT: C2RustUnnamed_0 = 1817;
pub const XML_SCHEMAV_NOTDETERMINIST: C2RustUnnamed_0 = 1816;
pub const XML_SCHEMAV_INVALIDELEM: C2RustUnnamed_0 = 1815;
pub const XML_SCHEMAV_INVALIDATTR: C2RustUnnamed_0 = 1814;
pub const XML_SCHEMAV_EXTRACONTENT: C2RustUnnamed_0 = 1813;
pub const XML_SCHEMAV_NOTNILLABLE: C2RustUnnamed_0 = 1812;
pub const XML_SCHEMAV_HAVEDEFAULT: C2RustUnnamed_0 = 1811;
pub const XML_SCHEMAV_ELEMCONT: C2RustUnnamed_0 = 1810;
pub const XML_SCHEMAV_NOTEMPTY: C2RustUnnamed_0 = 1809;
pub const XML_SCHEMAV_ISABSTRACT: C2RustUnnamed_0 = 1808;
pub const XML_SCHEMAV_NOROLLBACK: C2RustUnnamed_0 = 1807;
pub const XML_SCHEMAV_NOTYPE: C2RustUnnamed_0 = 1806;
pub const XML_SCHEMAV_WRONGELEM: C2RustUnnamed_0 = 1805;
pub const XML_SCHEMAV_MISSING: C2RustUnnamed_0 = 1804;
pub const XML_SCHEMAV_NOTTOPLEVEL: C2RustUnnamed_0 = 1803;
pub const XML_SCHEMAV_UNDECLAREDELEM: C2RustUnnamed_0 = 1802;
pub const XML_SCHEMAV_NOROOT: C2RustUnnamed_0 = 1801;
pub const XML_SCHEMAP_COS_CT_EXTENDS_1_3: C2RustUnnamed_0 = 1800;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_3: C2RustUnnamed_0 = 1799;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_2: C2RustUnnamed_0 = 1798;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_4_1: C2RustUnnamed_0 = 1797;
pub const XML_SCHEMAP_SRC_IMPORT_3_2: C2RustUnnamed_0 = 1796;
pub const XML_SCHEMAP_SRC_IMPORT_3_1: C2RustUnnamed_0 = 1795;
pub const XML_SCHEMAP_UNION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1794;
pub const XML_SCHEMAP_INTERSECTION_NOT_EXPRESSIBLE: C2RustUnnamed_0 = 1793;
pub const XML_SCHEMAP_WILDCARD_INVALID_NS_MEMBER: C2RustUnnamed_0 = 1792;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_3: C2RustUnnamed_0 = 1791;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_2: C2RustUnnamed_0 = 1790;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_2: C2RustUnnamed_0 = 1789;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_2_1_1: C2RustUnnamed_0 = 1788;
pub const XML_SCHEMAP_DERIVATION_OK_RESTRICTION_1: C2RustUnnamed_0 = 1787;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_5: C2RustUnnamed_0 = 1786;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_4: C2RustUnnamed_0 = 1785;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_3: C2RustUnnamed_0 = 1784;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_2: C2RustUnnamed_0 = 1783;
pub const XML_SCHEMAP_CT_PROPS_CORRECT_1: C2RustUnnamed_0 = 1782;
pub const XML_SCHEMAP_REF_AND_CONTENT: C2RustUnnamed_0 = 1781;
pub const XML_SCHEMAP_INVALID_ATTR_NAME: C2RustUnnamed_0 = 1780;
pub const XML_SCHEMAP_MISSING_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1779;
pub const XML_SCHEMAP_INVALID_ATTR_INLINE_COMBINATION: C2RustUnnamed_0 = 1778;
pub const XML_SCHEMAP_INVALID_ATTR_COMBINATION: C2RustUnnamed_0 = 1777;
pub const XML_SCHEMAP_SUPERNUMEROUS_LIST_ITEM_TYPE: C2RustUnnamed_0 = 1776;
pub const XML_SCHEMAP_RECURSIVE: C2RustUnnamed_0 = 1775;
pub const XML_SCHEMAP_INVALID_ATTR_USE: C2RustUnnamed_0 = 1774;
pub const XML_SCHEMAP_UNKNOWN_MEMBER_TYPE: C2RustUnnamed_0 = 1773;
pub const XML_SCHEMAP_NOT_SCHEMA: C2RustUnnamed_0 = 1772;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NO_URI: C2RustUnnamed_0 = 1771;
pub const XML_SCHEMAP_INCLUDE_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1770;
pub const XML_SCHEMAP_UNKNOWN_INCLUDE_CHILD: C2RustUnnamed_0 = 1769;
pub const XML_SCHEMAP_DEF_AND_PREFIX: C2RustUnnamed_0 = 1768;
pub const XML_SCHEMAP_UNKNOWN_PREFIX: C2RustUnnamed_0 = 1767;
pub const XML_SCHEMAP_FAILED_PARSE: C2RustUnnamed_0 = 1766;
pub const XML_SCHEMAP_REDEFINED_NOTATION: C2RustUnnamed_0 = 1765;
pub const XML_SCHEMAP_REDEFINED_ATTR: C2RustUnnamed_0 = 1764;
pub const XML_SCHEMAP_REDEFINED_ATTRGROUP: C2RustUnnamed_0 = 1763;
pub const XML_SCHEMAP_REDEFINED_ELEMENT: C2RustUnnamed_0 = 1762;
pub const XML_SCHEMAP_REDEFINED_TYPE: C2RustUnnamed_0 = 1761;
pub const XML_SCHEMAP_REDEFINED_GROUP: C2RustUnnamed_0 = 1760;
pub const XML_SCHEMAP_NOROOT: C2RustUnnamed_0 = 1759;
pub const XML_SCHEMAP_NOTHING_TO_PARSE: C2RustUnnamed_0 = 1758;
pub const XML_SCHEMAP_FAILED_LOAD: C2RustUnnamed_0 = 1757;
pub const XML_SCHEMAP_REGEXP_INVALID: C2RustUnnamed_0 = 1756;
pub const XML_SCHEMAP_ELEM_DEFAULT_FIXED: C2RustUnnamed_0 = 1755;
pub const XML_SCHEMAP_UNKNOWN_UNION_CHILD: C2RustUnnamed_0 = 1754;
pub const XML_SCHEMAP_UNKNOWN_TYPE: C2RustUnnamed_0 = 1753;
pub const XML_SCHEMAP_UNKNOWN_SIMPLETYPE_CHILD: C2RustUnnamed_0 = 1752;
pub const XML_SCHEMAP_UNKNOWN_SIMPLECONTENT_CHILD: C2RustUnnamed_0 = 1751;
pub const XML_SCHEMAP_UNKNOWN_SEQUENCE_CHILD: C2RustUnnamed_0 = 1750;
pub const XML_SCHEMAP_UNKNOWN_SCHEMAS_CHILD: C2RustUnnamed_0 = 1749;
pub const XML_SCHEMAP_UNKNOWN_RESTRICTION_CHILD: C2RustUnnamed_0 = 1748;
pub const XML_SCHEMAP_UNKNOWN_REF: C2RustUnnamed_0 = 1747;
pub const XML_SCHEMAP_UNKNOWN_PROCESSCONTENT_CHILD: C2RustUnnamed_0 = 1746;
pub const XML_SCHEMAP_UNKNOWN_NOTATION_CHILD: C2RustUnnamed_0 = 1745;
pub const XML_SCHEMAP_UNKNOWN_LIST_CHILD: C2RustUnnamed_0 = 1744;
pub const XML_SCHEMAP_UNKNOWN_IMPORT_CHILD: C2RustUnnamed_0 = 1743;
pub const XML_SCHEMAP_UNKNOWN_GROUP_CHILD: C2RustUnnamed_0 = 1742;
pub const XML_SCHEMAP_UNKNOWN_FACET_TYPE: C2RustUnnamed_0 = 1741;
pub const XML_SCHEMAP_UNKNOWN_FACET_CHILD: C2RustUnnamed_0 = 1740;
pub const XML_SCHEMAP_UNKNOWN_EXTENSION_CHILD: C2RustUnnamed_0 = 1739;
pub const XML_SCHEMAP_UNKNOWN_ELEM_CHILD: C2RustUnnamed_0 = 1738;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXTYPE_CHILD: C2RustUnnamed_0 = 1737;
pub const XML_SCHEMAP_UNKNOWN_COMPLEXCONTENT_CHILD: C2RustUnnamed_0 = 1736;
pub const XML_SCHEMAP_UNKNOWN_CHOICE_CHILD: C2RustUnnamed_0 = 1735;
pub const XML_SCHEMAP_UNKNOWN_BASE_TYPE: C2RustUnnamed_0 = 1734;
pub const XML_SCHEMAP_UNKNOWN_ATTRIBUTE_GROUP: C2RustUnnamed_0 = 1733;
pub const XML_SCHEMAP_UNKNOWN_ATTRGRP_CHILD: C2RustUnnamed_0 = 1732;
pub const XML_SCHEMAP_UNKNOWN_ATTR_CHILD: C2RustUnnamed_0 = 1731;
pub const XML_SCHEMAP_UNKNOWN_ANYATTRIBUTE_CHILD: C2RustUnnamed_0 = 1730;
pub const XML_SCHEMAP_UNKNOWN_ALL_CHILD: C2RustUnnamed_0 = 1729;
pub const XML_SCHEMAP_TYPE_AND_SUBTYPE: C2RustUnnamed_0 = 1728;
pub const XML_SCHEMAP_SIMPLETYPE_NONAME: C2RustUnnamed_0 = 1727;
pub const XML_SCHEMAP_RESTRICTION_NONAME_NOREF: C2RustUnnamed_0 = 1726;
pub const XML_SCHEMAP_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1725;
pub const XML_SCHEMAP_NOTYPE_NOREF: C2RustUnnamed_0 = 1724;
pub const XML_SCHEMAP_NOTATION_NO_NAME: C2RustUnnamed_0 = 1723;
pub const XML_SCHEMAP_NOATTR_NOREF: C2RustUnnamed_0 = 1722;
pub const XML_SCHEMAP_INVALID_WHITE_SPACE: C2RustUnnamed_0 = 1721;
pub const XML_SCHEMAP_INVALID_REF_AND_SUBTYPE: C2RustUnnamed_0 = 1720;
pub const XML_SCHEMAP_INVALID_MINOCCURS: C2RustUnnamed_0 = 1719;
pub const XML_SCHEMAP_INVALID_MAXOCCURS: C2RustUnnamed_0 = 1718;
pub const XML_SCHEMAP_INVALID_FACET_VALUE: C2RustUnnamed_0 = 1717;
pub const XML_SCHEMAP_INVALID_FACET: C2RustUnnamed_0 = 1716;
pub const XML_SCHEMAP_INVALID_ENUM: C2RustUnnamed_0 = 1715;
pub const XML_SCHEMAP_INVALID_BOOLEAN: C2RustUnnamed_0 = 1714;
pub const XML_SCHEMAP_IMPORT_SCHEMA_NOT_URI: C2RustUnnamed_0 = 1713;
pub const XML_SCHEMAP_IMPORT_REDEFINE_NSNAME: C2RustUnnamed_0 = 1712;
pub const XML_SCHEMAP_IMPORT_NAMESPACE_NOT_URI: C2RustUnnamed_0 = 1711;
pub const XML_SCHEMAP_GROUP_NONAME_NOREF: C2RustUnnamed_0 = 1710;
pub const XML_SCHEMAP_FAILED_BUILD_IMPORT: C2RustUnnamed_0 = 1709;
pub const XML_SCHEMAP_FACET_NO_VALUE: C2RustUnnamed_0 = 1708;
pub const XML_SCHEMAP_EXTENSION_NO_BASE: C2RustUnnamed_0 = 1707;
pub const XML_SCHEMAP_ELEM_NONAME_NOREF: C2RustUnnamed_0 = 1706;
pub const XML_SCHEMAP_ELEMFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1705;
pub const XML_SCHEMAP_COMPLEXTYPE_NONAME_NOREF: C2RustUnnamed_0 = 1704;
pub const XML_SCHEMAP_ATTR_NONAME_NOREF: C2RustUnnamed_0 = 1703;
pub const XML_SCHEMAP_ATTRGRP_NONAME_NOREF: C2RustUnnamed_0 = 1702;
pub const XML_SCHEMAP_ATTRFORMDEFAULT_VALUE: C2RustUnnamed_0 = 1701;
pub const XML_SCHEMAP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1700;
pub const XML_CATALOG_RECURSION: C2RustUnnamed_0 = 1654;
pub const XML_CATALOG_NOT_CATALOG: C2RustUnnamed_0 = 1653;
pub const XML_CATALOG_PREFER_VALUE: C2RustUnnamed_0 = 1652;
pub const XML_CATALOG_ENTRY_BROKEN: C2RustUnnamed_0 = 1651;
pub const XML_CATALOG_MISSING_ATTR: C2RustUnnamed_0 = 1650;
pub const XML_XINCLUDE_FRAGMENT_ID: C2RustUnnamed_0 = 1618;
pub const XML_XINCLUDE_DEPRECATED_NS: C2RustUnnamed_0 = 1617;
pub const XML_XINCLUDE_FALLBACK_NOT_IN_INCLUDE: C2RustUnnamed_0 = 1616;
pub const XML_XINCLUDE_FALLBACKS_IN_INCLUDE: C2RustUnnamed_0 = 1615;
pub const XML_XINCLUDE_INCLUDE_IN_INCLUDE: C2RustUnnamed_0 = 1614;
pub const XML_XINCLUDE_XPTR_RESULT: C2RustUnnamed_0 = 1613;
pub const XML_XINCLUDE_XPTR_FAILED: C2RustUnnamed_0 = 1612;
pub const XML_XINCLUDE_MULTIPLE_ROOT: C2RustUnnamed_0 = 1611;
pub const XML_XINCLUDE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1610;
pub const XML_XINCLUDE_BUILD_FAILED: C2RustUnnamed_0 = 1609;
pub const XML_XINCLUDE_INVALID_CHAR: C2RustUnnamed_0 = 1608;
pub const XML_XINCLUDE_TEXT_DOCUMENT: C2RustUnnamed_0 = 1607;
pub const XML_XINCLUDE_TEXT_FRAGMENT: C2RustUnnamed_0 = 1606;
pub const XML_XINCLUDE_HREF_URI: C2RustUnnamed_0 = 1605;
pub const XML_XINCLUDE_NO_FALLBACK: C2RustUnnamed_0 = 1604;
pub const XML_XINCLUDE_NO_HREF: C2RustUnnamed_0 = 1603;
pub const XML_XINCLUDE_ENTITY_DEF_MISMATCH: C2RustUnnamed_0 = 1602;
pub const XML_XINCLUDE_PARSE_VALUE: C2RustUnnamed_0 = 1601;
pub const XML_XINCLUDE_RECURSION: C2RustUnnamed_0 = 1600;
pub const XML_IO_EAFNOSUPPORT: C2RustUnnamed_0 = 1556;
pub const XML_IO_EALREADY: C2RustUnnamed_0 = 1555;
pub const XML_IO_EADDRINUSE: C2RustUnnamed_0 = 1554;
pub const XML_IO_ENETUNREACH: C2RustUnnamed_0 = 1553;
pub const XML_IO_ECONNREFUSED: C2RustUnnamed_0 = 1552;
pub const XML_IO_EISCONN: C2RustUnnamed_0 = 1551;
pub const XML_IO_ENOTSOCK: C2RustUnnamed_0 = 1550;
pub const XML_IO_LOAD_ERROR: C2RustUnnamed_0 = 1549;
pub const XML_IO_BUFFER_FULL: C2RustUnnamed_0 = 1548;
pub const XML_IO_NO_INPUT: C2RustUnnamed_0 = 1547;
pub const XML_IO_WRITE: C2RustUnnamed_0 = 1546;
pub const XML_IO_FLUSH: C2RustUnnamed_0 = 1545;
pub const XML_IO_ENCODER: C2RustUnnamed_0 = 1544;
pub const XML_IO_NETWORK_ATTEMPT: C2RustUnnamed_0 = 1543;
pub const XML_IO_EXDEV: C2RustUnnamed_0 = 1542;
pub const XML_IO_ETIMEDOUT: C2RustUnnamed_0 = 1541;
pub const XML_IO_ESRCH: C2RustUnnamed_0 = 1540;
pub const XML_IO_ESPIPE: C2RustUnnamed_0 = 1539;
pub const XML_IO_EROFS: C2RustUnnamed_0 = 1538;
pub const XML_IO_ERANGE: C2RustUnnamed_0 = 1537;
pub const XML_IO_EPIPE: C2RustUnnamed_0 = 1536;
pub const XML_IO_EPERM: C2RustUnnamed_0 = 1535;
pub const XML_IO_ENXIO: C2RustUnnamed_0 = 1534;
pub const XML_IO_ENOTTY: C2RustUnnamed_0 = 1533;
pub const XML_IO_ENOTSUP: C2RustUnnamed_0 = 1532;
pub const XML_IO_ENOTEMPTY: C2RustUnnamed_0 = 1531;
pub const XML_IO_ENOTDIR: C2RustUnnamed_0 = 1530;
pub const XML_IO_ENOSYS: C2RustUnnamed_0 = 1529;
pub const XML_IO_ENOSPC: C2RustUnnamed_0 = 1528;
pub const XML_IO_ENOMEM: C2RustUnnamed_0 = 1527;
pub const XML_IO_ENOLCK: C2RustUnnamed_0 = 1526;
pub const XML_IO_ENOEXEC: C2RustUnnamed_0 = 1525;
pub const XML_IO_ENOENT: C2RustUnnamed_0 = 1524;
pub const XML_IO_ENODEV: C2RustUnnamed_0 = 1523;
pub const XML_IO_ENFILE: C2RustUnnamed_0 = 1522;
pub const XML_IO_ENAMETOOLONG: C2RustUnnamed_0 = 1521;
pub const XML_IO_EMSGSIZE: C2RustUnnamed_0 = 1520;
pub const XML_IO_EMLINK: C2RustUnnamed_0 = 1519;
pub const XML_IO_EMFILE: C2RustUnnamed_0 = 1518;
pub const XML_IO_EISDIR: C2RustUnnamed_0 = 1517;
pub const XML_IO_EIO: C2RustUnnamed_0 = 1516;
pub const XML_IO_EINVAL: C2RustUnnamed_0 = 1515;
pub const XML_IO_EINTR: C2RustUnnamed_0 = 1514;
pub const XML_IO_EINPROGRESS: C2RustUnnamed_0 = 1513;
pub const XML_IO_EFBIG: C2RustUnnamed_0 = 1512;
pub const XML_IO_EFAULT: C2RustUnnamed_0 = 1511;
pub const XML_IO_EEXIST: C2RustUnnamed_0 = 1510;
pub const XML_IO_EDOM: C2RustUnnamed_0 = 1509;
pub const XML_IO_EDEADLK: C2RustUnnamed_0 = 1508;
pub const XML_IO_ECHILD: C2RustUnnamed_0 = 1507;
pub const XML_IO_ECANCELED: C2RustUnnamed_0 = 1506;
pub const XML_IO_EBUSY: C2RustUnnamed_0 = 1505;
pub const XML_IO_EBADMSG: C2RustUnnamed_0 = 1504;
pub const XML_IO_EBADF: C2RustUnnamed_0 = 1503;
pub const XML_IO_EAGAIN: C2RustUnnamed_0 = 1502;
pub const XML_IO_EACCES: C2RustUnnamed_0 = 1501;
pub const XML_IO_UNKNOWN: C2RustUnnamed_0 = 1500;
pub const XML_SAVE_UNKNOWN_ENCODING: C2RustUnnamed_0 = 1403;
pub const XML_SAVE_NO_DOCTYPE: C2RustUnnamed_0 = 1402;
pub const XML_SAVE_CHAR_INVALID: C2RustUnnamed_0 = 1401;
pub const XML_SAVE_NOT_UTF8: C2RustUnnamed_0 = 1400;
pub const XML_TREE_NOT_UTF8: C2RustUnnamed_0 = 1303;
pub const XML_TREE_UNTERMINATED_ENTITY: C2RustUnnamed_0 = 1302;
pub const XML_TREE_INVALID_DEC: C2RustUnnamed_0 = 1301;
pub const XML_TREE_INVALID_HEX: C2RustUnnamed_0 = 1300;
pub const XML_XPATH_INVALID_CHAR_ERROR: C2RustUnnamed_0 = 1221;
pub const XML_XPATH_ENCODING_ERROR: C2RustUnnamed_0 = 1220;
pub const XML_XPATH_UNDEF_PREFIX_ERROR: C2RustUnnamed_0 = 1219;
pub const XML_XPTR_SUB_RESOURCE_ERROR: C2RustUnnamed_0 = 1218;
pub const XML_XPTR_RESOURCE_ERROR: C2RustUnnamed_0 = 1217;
pub const XML_XPTR_SYNTAX_ERROR: C2RustUnnamed_0 = 1216;
pub const XML_XPATH_MEMORY_ERROR: C2RustUnnamed_0 = 1215;
pub const XML_XPATH_INVALID_CTXT_POSITION: C2RustUnnamed_0 = 1214;
pub const XML_XPATH_INVALID_CTXT_SIZE: C2RustUnnamed_0 = 1213;
pub const XML_XPATH_INVALID_ARITY: C2RustUnnamed_0 = 1212;
pub const XML_XPATH_INVALID_TYPE: C2RustUnnamed_0 = 1211;
pub const XML_XPATH_INVALID_OPERAND: C2RustUnnamed_0 = 1210;
pub const XML_XPATH_UNKNOWN_FUNC_ERROR: C2RustUnnamed_0 = 1209;
pub const XML_XPATH_UNCLOSED_ERROR: C2RustUnnamed_0 = 1208;
pub const XML_XPATH_EXPR_ERROR: C2RustUnnamed_0 = 1207;
pub const XML_XPATH_INVALID_PREDICATE_ERROR: C2RustUnnamed_0 = 1206;
pub const XML_XPATH_UNDEF_VARIABLE_ERROR: C2RustUnnamed_0 = 1205;
pub const XML_XPATH_VARIABLE_REF_ERROR: C2RustUnnamed_0 = 1204;
pub const XML_XPATH_START_LITERAL_ERROR: C2RustUnnamed_0 = 1203;
pub const XML_XPATH_UNFINISHED_LITERAL_ERROR: C2RustUnnamed_0 = 1202;
pub const XML_XPATH_NUMBER_ERROR: C2RustUnnamed_0 = 1201;
pub const XML_XPATH_EXPRESSION_OK: C2RustUnnamed_0 = 1200;
pub const XML_RNGP_XML_NS: C2RustUnnamed_0 = 1122;
pub const XML_RNGP_XMLNS_NAME: C2RustUnnamed_0 = 1121;
pub const XML_RNGP_VALUE_NO_CONTENT: C2RustUnnamed_0 = 1120;
pub const XML_RNGP_VALUE_EMPTY: C2RustUnnamed_0 = 1119;
pub const XML_RNGP_URI_NOT_ABSOLUTE: C2RustUnnamed_0 = 1118;
pub const XML_RNGP_URI_FRAGMENT: C2RustUnnamed_0 = 1117;
pub const XML_RNGP_UNKNOWN_TYPE_LIB: C2RustUnnamed_0 = 1116;
pub const XML_RNGP_UNKNOWN_CONSTRUCT: C2RustUnnamed_0 = 1115;
pub const XML_RNGP_UNKNOWN_COMBINE: C2RustUnnamed_0 = 1114;
pub const XML_RNGP_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 1113;
pub const XML_RNGP_TYPE_VALUE: C2RustUnnamed_0 = 1112;
pub const XML_RNGP_TYPE_NOT_FOUND: C2RustUnnamed_0 = 1111;
pub const XML_RNGP_TYPE_MISSING: C2RustUnnamed_0 = 1110;
pub const XML_RNGP_TEXT_HAS_CHILD: C2RustUnnamed_0 = 1109;
pub const XML_RNGP_TEXT_EXPECTED: C2RustUnnamed_0 = 1108;
pub const XML_RNGP_START_MISSING: C2RustUnnamed_0 = 1107;
pub const XML_RNGP_START_EMPTY: C2RustUnnamed_0 = 1106;
pub const XML_RNGP_START_CONTENT: C2RustUnnamed_0 = 1105;
pub const XML_RNGP_START_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1104;
pub const XML_RNGP_REF_NOT_EMPTY: C2RustUnnamed_0 = 1103;
pub const XML_RNGP_REF_NO_NAME: C2RustUnnamed_0 = 1102;
pub const XML_RNGP_REF_NO_DEF: C2RustUnnamed_0 = 1101;
pub const XML_RNGP_REF_NAME_INVALID: C2RustUnnamed_0 = 1100;
pub const XML_RNGP_REF_CYCLE: C2RustUnnamed_0 = 1099;
pub const XML_RNGP_REF_CREATE_FAILED: C2RustUnnamed_0 = 1098;
pub const XML_RNGP_PREFIX_UNDEFINED: C2RustUnnamed_0 = 1097;
pub const XML_RNGP_PAT_START_VALUE: C2RustUnnamed_0 = 1096;
pub const XML_RNGP_PAT_START_TEXT: C2RustUnnamed_0 = 1095;
pub const XML_RNGP_PAT_START_ONEMORE: C2RustUnnamed_0 = 1094;
pub const XML_RNGP_PAT_START_LIST: C2RustUnnamed_0 = 1093;
pub const XML_RNGP_PAT_START_INTERLEAVE: C2RustUnnamed_0 = 1092;
pub const XML_RNGP_PAT_START_GROUP: C2RustUnnamed_0 = 1091;
pub const XML_RNGP_PAT_START_EMPTY: C2RustUnnamed_0 = 1090;
pub const XML_RNGP_PAT_START_DATA: C2RustUnnamed_0 = 1089;
pub const XML_RNGP_PAT_START_ATTR: C2RustUnnamed_0 = 1088;
pub const XML_RNGP_PAT_ONEMORE_INTERLEAVE_ATTR: C2RustUnnamed_0 = 1087;
pub const XML_RNGP_PAT_ONEMORE_GROUP_ATTR: C2RustUnnamed_0 = 1086;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_NSNAME: C2RustUnnamed_0 = 1085;
pub const XML_RNGP_PAT_NSNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1084;
pub const XML_RNGP_PAT_LIST_TEXT: C2RustUnnamed_0 = 1083;
pub const XML_RNGP_PAT_LIST_REF: C2RustUnnamed_0 = 1082;
pub const XML_RNGP_PAT_LIST_LIST: C2RustUnnamed_0 = 1081;
pub const XML_RNGP_PAT_LIST_INTERLEAVE: C2RustUnnamed_0 = 1080;
pub const XML_RNGP_PAT_LIST_ELEM: C2RustUnnamed_0 = 1079;
pub const XML_RNGP_PAT_LIST_ATTR: C2RustUnnamed_0 = 1078;
pub const XML_RNGP_PAT_DATA_EXCEPT_TEXT: C2RustUnnamed_0 = 1077;
pub const XML_RNGP_PAT_DATA_EXCEPT_REF: C2RustUnnamed_0 = 1076;
pub const XML_RNGP_PAT_DATA_EXCEPT_ONEMORE: C2RustUnnamed_0 = 1075;
pub const XML_RNGP_PAT_DATA_EXCEPT_LIST: C2RustUnnamed_0 = 1074;
pub const XML_RNGP_PAT_DATA_EXCEPT_INTERLEAVE: C2RustUnnamed_0 = 1073;
pub const XML_RNGP_PAT_DATA_EXCEPT_GROUP: C2RustUnnamed_0 = 1072;
pub const XML_RNGP_PAT_DATA_EXCEPT_EMPTY: C2RustUnnamed_0 = 1071;
pub const XML_RNGP_PAT_DATA_EXCEPT_ELEM: C2RustUnnamed_0 = 1070;
pub const XML_RNGP_PAT_DATA_EXCEPT_ATTR: C2RustUnnamed_0 = 1069;
pub const XML_RNGP_PAT_ATTR_ELEM: C2RustUnnamed_0 = 1068;
pub const XML_RNGP_PAT_ATTR_ATTR: C2RustUnnamed_0 = 1067;
pub const XML_RNGP_PAT_ANYNAME_EXCEPT_ANYNAME: C2RustUnnamed_0 = 1066;
pub const XML_RNGP_PARSE_ERROR: C2RustUnnamed_0 = 1065;
pub const XML_RNGP_PARENTREF_NOT_EMPTY: C2RustUnnamed_0 = 1064;
pub const XML_RNGP_PARENTREF_NO_PARENT: C2RustUnnamed_0 = 1063;
pub const XML_RNGP_PARENTREF_NO_NAME: C2RustUnnamed_0 = 1062;
pub const XML_RNGP_PARENTREF_NAME_INVALID: C2RustUnnamed_0 = 1061;
pub const XML_RNGP_PARENTREF_CREATE_FAILED: C2RustUnnamed_0 = 1060;
pub const XML_RNGP_PARAM_NAME_MISSING: C2RustUnnamed_0 = 1059;
pub const XML_RNGP_PARAM_FORBIDDEN: C2RustUnnamed_0 = 1058;
pub const XML_RNGP_NSNAME_NO_NS: C2RustUnnamed_0 = 1057;
pub const XML_RNGP_NSNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1056;
pub const XML_RNGP_NOTALLOWED_NOT_EMPTY: C2RustUnnamed_0 = 1055;
pub const XML_RNGP_NEED_COMBINE: C2RustUnnamed_0 = 1054;
pub const XML_RNGP_NAME_MISSING: C2RustUnnamed_0 = 1053;
pub const XML_RNGP_MISSING_HREF: C2RustUnnamed_0 = 1052;
pub const XML_RNGP_INVALID_VALUE: C2RustUnnamed_0 = 1051;
pub const XML_RNGP_INVALID_URI: C2RustUnnamed_0 = 1050;
pub const XML_RNGP_INVALID_DEFINE_NAME: C2RustUnnamed_0 = 1049;
pub const XML_RNGP_INTERLEAVE_NO_CONTENT: C2RustUnnamed_0 = 1048;
pub const XML_RNGP_INTERLEAVE_EMPTY: C2RustUnnamed_0 = 1047;
pub const XML_RNGP_INTERLEAVE_CREATE_FAILED: C2RustUnnamed_0 = 1046;
pub const XML_RNGP_INTERLEAVE_ADD: C2RustUnnamed_0 = 1045;
pub const XML_RNGP_INCLUDE_RECURSE: C2RustUnnamed_0 = 1044;
pub const XML_RNGP_INCLUDE_FAILURE: C2RustUnnamed_0 = 1043;
pub const XML_RNGP_INCLUDE_EMPTY: C2RustUnnamed_0 = 1042;
pub const XML_RNGP_HREF_ERROR: C2RustUnnamed_0 = 1041;
pub const XML_RNGP_GROUP_ATTR_CONFLICT: C2RustUnnamed_0 = 1040;
pub const XML_RNGP_GRAMMAR_NO_START: C2RustUnnamed_0 = 1039;
pub const XML_RNGP_GRAMMAR_MISSING: C2RustUnnamed_0 = 1038;
pub const XML_RNGP_GRAMMAR_EMPTY: C2RustUnnamed_0 = 1037;
pub const XML_RNGP_GRAMMAR_CONTENT: C2RustUnnamed_0 = 1036;
pub const XML_RNGP_FOREIGN_ELEMENT: C2RustUnnamed_0 = 1035;
pub const XML_RNGP_FORBIDDEN_ATTRIBUTE: C2RustUnnamed_0 = 1034;
pub const XML_RNGP_EXTERNALREF_RECURSE: C2RustUnnamed_0 = 1033;
pub const XML_RNGP_EXTERNAL_REF_FAILURE: C2RustUnnamed_0 = 1032;
pub const XML_RNGP_EXTERNALREF_EMTPY: C2RustUnnamed_0 = 1031;
pub const XML_RNGP_EXCEPT_NO_CONTENT: C2RustUnnamed_0 = 1030;
pub const XML_RNGP_EXCEPT_MULTIPLE: C2RustUnnamed_0 = 1029;
pub const XML_RNGP_EXCEPT_MISSING: C2RustUnnamed_0 = 1028;
pub const XML_RNGP_EXCEPT_EMPTY: C2RustUnnamed_0 = 1027;
pub const XML_RNGP_ERROR_TYPE_LIB: C2RustUnnamed_0 = 1026;
pub const XML_RNGP_EMPTY_NOT_EMPTY: C2RustUnnamed_0 = 1025;
pub const XML_RNGP_EMPTY_CONTENT: C2RustUnnamed_0 = 1024;
pub const XML_RNGP_EMPTY_CONSTRUCT: C2RustUnnamed_0 = 1023;
pub const XML_RNGP_EMPTY: C2RustUnnamed_0 = 1022;
pub const XML_RNGP_ELEM_TEXT_CONFLICT: C2RustUnnamed_0 = 1021;
pub const XML_RNGP_ELEMENT_NO_CONTENT: C2RustUnnamed_0 = 1020;
pub const XML_RNGP_ELEMENT_NAME: C2RustUnnamed_0 = 1019;
pub const XML_RNGP_ELEMENT_CONTENT: C2RustUnnamed_0 = 1018;
pub const XML_RNGP_ELEMENT_EMPTY: C2RustUnnamed_0 = 1017;
pub const XML_RNGP_ELEM_CONTENT_ERROR: C2RustUnnamed_0 = 1016;
pub const XML_RNGP_ELEM_CONTENT_EMPTY: C2RustUnnamed_0 = 1015;
pub const XML_RNGP_DEFINE_NAME_MISSING: C2RustUnnamed_0 = 1014;
pub const XML_RNGP_DEFINE_MISSING: C2RustUnnamed_0 = 1013;
pub const XML_RNGP_DEFINE_EMPTY: C2RustUnnamed_0 = 1012;
pub const XML_RNGP_DEFINE_CREATE_FAILED: C2RustUnnamed_0 = 1011;
pub const XML_RNGP_DEF_CHOICE_AND_INTERLEAVE: C2RustUnnamed_0 = 1010;
pub const XML_RNGP_DATA_CONTENT: C2RustUnnamed_0 = 1009;
pub const XML_RNGP_CREATE_FAILURE: C2RustUnnamed_0 = 1008;
pub const XML_RNGP_CHOICE_EMPTY: C2RustUnnamed_0 = 1007;
pub const XML_RNGP_CHOICE_CONTENT: C2RustUnnamed_0 = 1006;
pub const XML_RNGP_ATTRIBUTE_NOOP: C2RustUnnamed_0 = 1005;
pub const XML_RNGP_ATTRIBUTE_EMPTY: C2RustUnnamed_0 = 1004;
pub const XML_RNGP_ATTRIBUTE_CONTENT: C2RustUnnamed_0 = 1003;
pub const XML_RNGP_ATTRIBUTE_CHILDREN: C2RustUnnamed_0 = 1002;
pub const XML_RNGP_ATTR_CONFLICT: C2RustUnnamed_0 = 1001;
pub const XML_RNGP_ANYNAME_ATTR_ANCESTOR: C2RustUnnamed_0 = 1000;
pub const XML_HTML_INCORRECTLY_OPENED_COMMENT: C2RustUnnamed_0 = 802;
pub const XML_HTML_UNKNOWN_TAG: C2RustUnnamed_0 = 801;
pub const XML_HTML_STRUCURE_ERROR: C2RustUnnamed_0 = 800;
pub const XML_DTD_DUP_TOKEN: C2RustUnnamed_0 = 541;
pub const XML_DTD_XMLID_TYPE: C2RustUnnamed_0 = 540;
pub const XML_DTD_XMLID_VALUE: C2RustUnnamed_0 = 539;
pub const XML_DTD_STANDALONE_DEFAULTED: C2RustUnnamed_0 = 538;
pub const XML_DTD_UNKNOWN_NOTATION: C2RustUnnamed_0 = 537;
pub const XML_DTD_UNKNOWN_ID: C2RustUnnamed_0 = 536;
pub const XML_DTD_UNKNOWN_ENTITY: C2RustUnnamed_0 = 535;
pub const XML_DTD_UNKNOWN_ELEM: C2RustUnnamed_0 = 534;
pub const XML_DTD_UNKNOWN_ATTRIBUTE: C2RustUnnamed_0 = 533;
pub const XML_DTD_STANDALONE_WHITE_SPACE: C2RustUnnamed_0 = 532;
pub const XML_DTD_ROOT_NAME: C2RustUnnamed_0 = 531;
pub const XML_DTD_NOT_STANDALONE: C2RustUnnamed_0 = 530;
pub const XML_DTD_NOT_PCDATA: C2RustUnnamed_0 = 529;
pub const XML_DTD_NOT_EMPTY: C2RustUnnamed_0 = 528;
pub const XML_DTD_NOTATION_VALUE: C2RustUnnamed_0 = 527;
pub const XML_DTD_NOTATION_REDEFINED: C2RustUnnamed_0 = 526;
pub const XML_DTD_NO_ROOT: C2RustUnnamed_0 = 525;
pub const XML_DTD_NO_PREFIX: C2RustUnnamed_0 = 524;
pub const XML_DTD_NO_ELEM_NAME: C2RustUnnamed_0 = 523;
pub const XML_DTD_NO_DTD: C2RustUnnamed_0 = 522;
pub const XML_DTD_NO_DOC: C2RustUnnamed_0 = 521;
pub const XML_DTD_MULTIPLE_ID: C2RustUnnamed_0 = 520;
pub const XML_DTD_MIXED_CORRUPT: C2RustUnnamed_0 = 519;
pub const XML_DTD_MISSING_ATTRIBUTE: C2RustUnnamed_0 = 518;
pub const XML_DTD_LOAD_ERROR: C2RustUnnamed_0 = 517;
pub const XML_DTD_INVALID_DEFAULT: C2RustUnnamed_0 = 516;
pub const XML_DTD_INVALID_CHILD: C2RustUnnamed_0 = 515;
pub const XML_DTD_ID_SUBSET: C2RustUnnamed_0 = 514;
pub const XML_DTD_ID_REDEFINED: C2RustUnnamed_0 = 513;
pub const XML_DTD_ID_FIXED: C2RustUnnamed_0 = 512;
pub const XML_DTD_ENTITY_TYPE: C2RustUnnamed_0 = 511;
pub const XML_DTD_EMPTY_NOTATION: C2RustUnnamed_0 = 510;
pub const XML_DTD_ELEM_REDEFINED: C2RustUnnamed_0 = 509;
pub const XML_DTD_ELEM_NAMESPACE: C2RustUnnamed_0 = 508;
pub const XML_DTD_ELEM_DEFAULT_NAMESPACE: C2RustUnnamed_0 = 507;
pub const XML_DTD_DIFFERENT_PREFIX: C2RustUnnamed_0 = 506;
pub const XML_DTD_CONTENT_NOT_DETERMINIST: C2RustUnnamed_0 = 505;
pub const XML_DTD_CONTENT_MODEL: C2RustUnnamed_0 = 504;
pub const XML_DTD_CONTENT_ERROR: C2RustUnnamed_0 = 503;
pub const XML_DTD_ATTRIBUTE_VALUE: C2RustUnnamed_0 = 502;
pub const XML_DTD_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 501;
pub const XML_DTD_ATTRIBUTE_DEFAULT: C2RustUnnamed_0 = 500;
pub const XML_NS_ERR_COLON: C2RustUnnamed_0 = 205;
pub const XML_NS_ERR_EMPTY: C2RustUnnamed_0 = 204;
pub const XML_NS_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 203;
pub const XML_NS_ERR_QNAME: C2RustUnnamed_0 = 202;
pub const XML_NS_ERR_UNDEFINED_NAMESPACE: C2RustUnnamed_0 = 201;
pub const XML_NS_ERR_XML_NAMESPACE: C2RustUnnamed_0 = 200;
pub const XML_ERR_COMMENT_ABRUPTLY_ENDED: C2RustUnnamed_0 = 112;
pub const XML_ERR_USER_STOP: C2RustUnnamed_0 = 111;
pub const XML_ERR_NAME_TOO_LONG: C2RustUnnamed_0 = 110;
pub const XML_ERR_VERSION_MISMATCH: C2RustUnnamed_0 = 109;
pub const XML_ERR_UNKNOWN_VERSION: C2RustUnnamed_0 = 108;
pub const XML_WAR_ENTITY_REDEFINED: C2RustUnnamed_0 = 107;
pub const XML_WAR_NS_COLUMN: C2RustUnnamed_0 = 106;
pub const XML_ERR_NOTATION_PROCESSING: C2RustUnnamed_0 = 105;
pub const XML_ERR_ENTITY_PROCESSING: C2RustUnnamed_0 = 104;
pub const XML_ERR_NOT_STANDALONE: C2RustUnnamed_0 = 103;
pub const XML_WAR_SPACE_VALUE: C2RustUnnamed_0 = 102;
pub const XML_ERR_MISSING_ENCODING: C2RustUnnamed_0 = 101;
pub const XML_WAR_NS_URI_RELATIVE: C2RustUnnamed_0 = 100;
pub const XML_WAR_NS_URI: C2RustUnnamed_0 = 99;
pub const XML_WAR_LANG_VALUE: C2RustUnnamed_0 = 98;
pub const XML_WAR_UNKNOWN_VERSION: C2RustUnnamed_0 = 97;
pub const XML_ERR_VERSION_MISSING: C2RustUnnamed_0 = 96;
pub const XML_ERR_CONDSEC_INVALID_KEYWORD: C2RustUnnamed_0 = 95;
pub const XML_ERR_NO_DTD: C2RustUnnamed_0 = 94;
pub const XML_WAR_CATALOG_PI: C2RustUnnamed_0 = 93;
pub const XML_ERR_URI_FRAGMENT: C2RustUnnamed_0 = 92;
pub const XML_ERR_INVALID_URI: C2RustUnnamed_0 = 91;
pub const XML_ERR_ENTITY_BOUNDARY: C2RustUnnamed_0 = 90;
pub const XML_ERR_ENTITY_LOOP: C2RustUnnamed_0 = 89;
pub const XML_ERR_ENTITY_PE_INTERNAL: C2RustUnnamed_0 = 88;
pub const XML_ERR_ENTITY_CHAR_ERROR: C2RustUnnamed_0 = 87;
pub const XML_ERR_EXTRA_CONTENT: C2RustUnnamed_0 = 86;
pub const XML_ERR_NOT_WELL_BALANCED: C2RustUnnamed_0 = 85;
pub const XML_ERR_VALUE_REQUIRED: C2RustUnnamed_0 = 84;
pub const XML_ERR_CONDSEC_INVALID: C2RustUnnamed_0 = 83;
pub const XML_ERR_EXT_ENTITY_STANDALONE: C2RustUnnamed_0 = 82;
pub const XML_ERR_INVALID_ENCODING: C2RustUnnamed_0 = 81;
pub const XML_ERR_HYPHEN_IN_COMMENT: C2RustUnnamed_0 = 80;
pub const XML_ERR_ENCODING_NAME: C2RustUnnamed_0 = 79;
pub const XML_ERR_STANDALONE_VALUE: C2RustUnnamed_0 = 78;
pub const XML_ERR_TAG_NOT_FINISHED: C2RustUnnamed_0 = 77;
pub const XML_ERR_TAG_NAME_MISMATCH: C2RustUnnamed_0 = 76;
pub const XML_ERR_EQUAL_REQUIRED: C2RustUnnamed_0 = 75;
pub const XML_ERR_LTSLASH_REQUIRED: C2RustUnnamed_0 = 74;
pub const XML_ERR_GT_REQUIRED: C2RustUnnamed_0 = 73;
pub const XML_ERR_LT_REQUIRED: C2RustUnnamed_0 = 72;
pub const XML_ERR_PUBID_REQUIRED: C2RustUnnamed_0 = 71;
pub const XML_ERR_URI_REQUIRED: C2RustUnnamed_0 = 70;
pub const XML_ERR_PCDATA_REQUIRED: C2RustUnnamed_0 = 69;
pub const XML_ERR_NAME_REQUIRED: C2RustUnnamed_0 = 68;
pub const XML_ERR_NMTOKEN_REQUIRED: C2RustUnnamed_0 = 67;
pub const XML_ERR_SEPARATOR_REQUIRED: C2RustUnnamed_0 = 66;
pub const XML_ERR_SPACE_REQUIRED: C2RustUnnamed_0 = 65;
pub const XML_ERR_RESERVED_XML_NAME: C2RustUnnamed_0 = 64;
pub const XML_ERR_CDATA_NOT_FINISHED: C2RustUnnamed_0 = 63;
pub const XML_ERR_MISPLACED_CDATA_END: C2RustUnnamed_0 = 62;
pub const XML_ERR_DOCTYPE_NOT_FINISHED: C2RustUnnamed_0 = 61;
pub const XML_ERR_EXT_SUBSET_NOT_FINISHED: C2RustUnnamed_0 = 60;
pub const XML_ERR_CONDSEC_NOT_FINISHED: C2RustUnnamed_0 = 59;
pub const XML_ERR_CONDSEC_NOT_STARTED: C2RustUnnamed_0 = 58;
pub const XML_ERR_XMLDECL_NOT_FINISHED: C2RustUnnamed_0 = 57;
pub const XML_ERR_XMLDECL_NOT_STARTED: C2RustUnnamed_0 = 56;
pub const XML_ERR_ELEMCONTENT_NOT_FINISHED: C2RustUnnamed_0 = 55;
pub const XML_ERR_ELEMCONTENT_NOT_STARTED: C2RustUnnamed_0 = 54;
pub const XML_ERR_MIXED_NOT_FINISHED: C2RustUnnamed_0 = 53;
pub const XML_ERR_MIXED_NOT_STARTED: C2RustUnnamed_0 = 52;
pub const XML_ERR_ATTLIST_NOT_FINISHED: C2RustUnnamed_0 = 51;
pub const XML_ERR_ATTLIST_NOT_STARTED: C2RustUnnamed_0 = 50;
pub const XML_ERR_NOTATION_NOT_FINISHED: C2RustUnnamed_0 = 49;
pub const XML_ERR_NOTATION_NOT_STARTED: C2RustUnnamed_0 = 48;
pub const XML_ERR_PI_NOT_FINISHED: C2RustUnnamed_0 = 47;
pub const XML_ERR_PI_NOT_STARTED: C2RustUnnamed_0 = 46;
pub const XML_ERR_COMMENT_NOT_FINISHED: C2RustUnnamed_0 = 45;
pub const XML_ERR_LITERAL_NOT_FINISHED: C2RustUnnamed_0 = 44;
pub const XML_ERR_LITERAL_NOT_STARTED: C2RustUnnamed_0 = 43;
pub const XML_ERR_ATTRIBUTE_REDEFINED: C2RustUnnamed_0 = 42;
pub const XML_ERR_ATTRIBUTE_WITHOUT_VALUE: C2RustUnnamed_0 = 41;
pub const XML_ERR_ATTRIBUTE_NOT_FINISHED: C2RustUnnamed_0 = 40;
pub const XML_ERR_ATTRIBUTE_NOT_STARTED: C2RustUnnamed_0 = 39;
pub const XML_ERR_LT_IN_ATTRIBUTE: C2RustUnnamed_0 = 38;
pub const XML_ERR_ENTITY_NOT_FINISHED: C2RustUnnamed_0 = 37;
pub const XML_ERR_ENTITY_NOT_STARTED: C2RustUnnamed_0 = 36;
pub const XML_ERR_NS_DECL_ERROR: C2RustUnnamed_0 = 35;
pub const XML_ERR_STRING_NOT_CLOSED: C2RustUnnamed_0 = 34;
pub const XML_ERR_STRING_NOT_STARTED: C2RustUnnamed_0 = 33;
pub const XML_ERR_UNSUPPORTED_ENCODING: C2RustUnnamed_0 = 32;
pub const XML_ERR_UNKNOWN_ENCODING: C2RustUnnamed_0 = 31;
pub const XML_ERR_ENTITY_IS_PARAMETER: C2RustUnnamed_0 = 30;
pub const XML_ERR_ENTITY_IS_EXTERNAL: C2RustUnnamed_0 = 29;
pub const XML_ERR_UNPARSED_ENTITY: C2RustUnnamed_0 = 28;
pub const XML_WAR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 27;
pub const XML_ERR_UNDECLARED_ENTITY: C2RustUnnamed_0 = 26;
pub const XML_ERR_PEREF_SEMICOL_MISSING: C2RustUnnamed_0 = 25;
pub const XML_ERR_PEREF_NO_NAME: C2RustUnnamed_0 = 24;
pub const XML_ERR_ENTITYREF_SEMICOL_MISSING: C2RustUnnamed_0 = 23;
pub const XML_ERR_ENTITYREF_NO_NAME: C2RustUnnamed_0 = 22;
pub const XML_ERR_PEREF_IN_INT_SUBSET: C2RustUnnamed_0 = 21;
pub const XML_ERR_PEREF_IN_EPILOG: C2RustUnnamed_0 = 20;
pub const XML_ERR_PEREF_IN_PROLOG: C2RustUnnamed_0 = 19;
pub const XML_ERR_PEREF_AT_EOF: C2RustUnnamed_0 = 18;
pub const XML_ERR_ENTITYREF_IN_DTD: C2RustUnnamed_0 = 17;
pub const XML_ERR_ENTITYREF_IN_EPILOG: C2RustUnnamed_0 = 16;
pub const XML_ERR_ENTITYREF_IN_PROLOG: C2RustUnnamed_0 = 15;
pub const XML_ERR_ENTITYREF_AT_EOF: C2RustUnnamed_0 = 14;
pub const XML_ERR_CHARREF_IN_DTD: C2RustUnnamed_0 = 13;
pub const XML_ERR_CHARREF_IN_EPILOG: C2RustUnnamed_0 = 12;
pub const XML_ERR_CHARREF_IN_PROLOG: C2RustUnnamed_0 = 11;
pub const XML_ERR_CHARREF_AT_EOF: C2RustUnnamed_0 = 10;
pub const XML_ERR_INVALID_CHAR: C2RustUnnamed_0 = 9;
pub const XML_ERR_INVALID_CHARREF: C2RustUnnamed_0 = 8;
pub const XML_ERR_INVALID_DEC_CHARREF: C2RustUnnamed_0 = 7;
pub const XML_ERR_INVALID_HEX_CHARREF: C2RustUnnamed_0 = 6;
pub const XML_ERR_DOCUMENT_END: C2RustUnnamed_0 = 5;
pub const XML_ERR_DOCUMENT_EMPTY: C2RustUnnamed_0 = 4;
pub const XML_ERR_DOCUMENT_START: C2RustUnnamed_0 = 3;
pub const XML_ERR_INTERNAL_ERROR: C2RustUnnamed_0 = 1;
pub const XML_ERR_OK: C2RustUnnamed_0 = 0;
unsafe extern "C" fn xmlRegexpErrMemory(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut extra: * const i8,
) {
    let mut regexp: * const i8 = 0 as *const i8;
    if !ctxt.is_null() {
        regexp = (*ctxt).string as *const i8;
        (*ctxt).error = XML_ERR_NO_MEMORY as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_REGEXP as i32,
        XML_ERR_NO_MEMORY as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        extra,
        regexp,
        0 as *const i8,
        0 as i32,
        0 as i32,
        b"Memory allocation failed : %s\n\0" as *const u8 as *const i8,
        extra,
    );
}
unsafe extern "C" fn xmlRegexpErrCompile(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut extra: * const i8,
) {
    let mut regexp: * const i8 = 0 as *const i8;
    let mut idx: i32 = 0 as i32;
    if !ctxt.is_null() {
        regexp = (*ctxt).string as *const i8;
        idx = ((*ctxt).cur).offset_from((*ctxt).string) as i64 as i32;
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
    }
    __xmlRaiseError(
        None,
        None,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        0 as *mut libc::c_void,
        XML_FROM_REGEXP as i32,
        XML_REGEXP_COMPILE_ERROR as i32,
        XML_ERR_FATAL,
        0 as *const i8,
        0 as i32,
        extra,
        regexp,
        0 as *const i8,
        idx,
        0 as i32,
        b"failed to compile: %s\n\0" as *const u8 as *const i8,
        extra,
    );
}
unsafe extern "C" fn xmlRegCalloc2(
    mut dim1: u64,
    mut dim2: u64,
    mut elemSize: u64,
) -> * mut core::ffi::c_void {
    let mut totalSize: u64 = 0;
    let mut ret: * mut core::ffi::c_void = 0 as *mut libc::c_void;
    if dim1 > (-(1 as i32) as size_t).wrapping_div(dim2).wrapping_div(elemSize) {
        return 0 as *mut libc::c_void;
    }
    totalSize = dim1.wrapping_mul(dim2).wrapping_mul(elemSize);
    ret = xmlMalloc.expect("non-null function pointer")(totalSize);
    if !ret.is_null() {
        memset(ret, 0 as i32, totalSize);
    }
    return ret;
}
unsafe extern "C" fn xmlRegEpxFromParse(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> * mut crate::src::xmlregexp::_xmlRegexp {
    let mut current_block: u64;
    let mut ret: * mut crate::src::xmlregexp::_xmlRegexp = 0 as *mut xmlRegexp;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegexp>() as u64) as xmlRegexpPtr;
    if ret.is_null() {
        xmlRegexpErrMemory(
            ctxt,
            b"compiling regexp\0" as *const u8 as *const i8,
        );
        return 0 as xmlRegexpPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegexp>() as u64,
    );
    let fresh0 = &mut ((*ret).string);
    *fresh0 = (*ctxt).string;
    (*ret).nbStates = (*ctxt).nbStates;
    let fresh1 = &mut ((*ret).states);
    *fresh1 = (*ctxt).states;
    (*ret).nbAtoms = (*ctxt).nbAtoms;
    let fresh2 = &mut ((*ret).atoms);
    *fresh2 = (*ctxt).atoms;
    (*ret).nbCounters = (*ctxt).nbCounters;
    let fresh3 = &mut ((*ret).counters);
    *fresh3 = (*ctxt).counters;
    (*ret).determinist = (*ctxt).determinist;
    (*ret).flags = (*ctxt).flags;
    if (*ret).determinist == -(1 as i32) {
        xmlRegexpIsDeterminist(ret);
    }
    if (*ret).determinist != 0 as i32 && (*ret).nbCounters == 0 as i32
        && (*ctxt).negs == 0 as i32 && !((*ret).atoms).is_null()
        && !(*((*ret).atoms).offset(0 as i32 as isize)).is_null()
        && (**((*ret).atoms).offset(0 as i32 as isize)).type_0 as u32
            == XML_REGEXP_STRING as i32 as u32
    {
        let mut i: i32 = 0;
        let mut j: i32 = 0;
        let mut nbstates: i32 = 0 as i32;
        let mut nbatoms: i32 = 0 as i32;
        let mut stateRemap: * mut i32 = 0 as *mut i32;
        let mut stringRemap: * mut i32 = 0 as *mut i32;
        let mut transitions: * mut i32 = 0 as *mut i32;
        let mut transdata: * mut * mut core::ffi::c_void = 0 as *mut *mut libc::c_void;
        let mut stringMap: * mut * mut u8 = 0 as *mut *mut xmlChar;
        let mut value: * mut u8 = 0 as *mut xmlChar;
        stateRemap = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ret).nbStates as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if stateRemap.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"compiling regexp\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlRegexpPtr;
        }
        i = 0 as i32;
        while i < (*ret).nbStates {
            if !(*((*ret).states).offset(i as isize)).is_null() {
                *stateRemap.offset(i as isize) = nbstates;
                nbstates += 1;
            } else {
                *stateRemap.offset(i as isize) = -(1 as i32);
            }
            i += 1;
        }
        stringMap = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ret).nbAtoms as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<*mut i8>() as u64,
                ),
        ) as *mut *mut xmlChar;
        if stringMap.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"compiling regexp\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(stateRemap as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlRegexpPtr;
        }
        stringRemap = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ret).nbAtoms as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if stringRemap.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"compiling regexp\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(stringMap as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(stateRemap as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlRegexpPtr;
        }
        i = 0 as i32;
        while i < (*ret).nbAtoms {
            if (**((*ret).atoms).offset(i as isize)).type_0 as u32
                == XML_REGEXP_STRING as i32 as u32
                && (**((*ret).atoms).offset(i as isize)).quant as u32
                    == XML_REGEXP_QUANT_ONCE as i32 as u32
            {
                value = (**((*ret).atoms).offset(i as isize)).valuep as *mut xmlChar;
                j = 0 as i32;
                while j < nbatoms {
                    if xmlStrEqual(*stringMap.offset(j as isize), value) != 0 {
                        *stringRemap.offset(i as isize) = j;
                        break;
                    } else {
                        j += 1;
                    }
                }
                if j >= nbatoms {
                    *stringRemap.offset(i as isize) = nbatoms;
                    let fresh4 = &mut (*stringMap.offset(nbatoms as isize));
                    *fresh4 = xmlStrdup(value);
                    if (*stringMap.offset(nbatoms as isize)).is_null() {
                        i = 0 as i32;
                        while i < nbatoms {
                            xmlFree
                                .expect(
                                    "non-null function pointer",
                                )(*stringMap.offset(i as isize) as *mut libc::c_void);
                            i += 1;
                        }
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(stringRemap as *mut libc::c_void);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(stringMap as *mut libc::c_void);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(stateRemap as *mut libc::c_void);
                        xmlFree
                            .expect(
                                "non-null function pointer",
                            )(ret as *mut libc::c_void);
                        return 0 as xmlRegexpPtr;
                    }
                    nbatoms += 1;
                }
            } else {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(stateRemap as *mut libc::c_void);
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(stringRemap as *mut libc::c_void);
                i = 0 as i32;
                while i < nbatoms {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(*stringMap.offset(i as isize) as *mut libc::c_void);
                    i += 1;
                }
                xmlFree
                    .expect("non-null function pointer")(stringMap as *mut libc::c_void);
                xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
                return 0 as xmlRegexpPtr;
            }
            i += 1;
        }
        transitions = xmlRegCalloc2(
            (nbstates + 1 as i32) as size_t,
            (nbatoms + 1 as i32) as size_t,
            ::std::mem::size_of::<i32>() as u64,
        ) as *mut i32;
        if transitions.is_null() {
            xmlFree.expect("non-null function pointer")(stateRemap as *mut libc::c_void);
            xmlFree
                .expect("non-null function pointer")(stringRemap as *mut libc::c_void);
            i = 0 as i32;
            while i < nbatoms {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(*stringMap.offset(i as isize) as *mut libc::c_void);
                i += 1;
            }
            xmlFree.expect("non-null function pointer")(stringMap as *mut libc::c_void);
            xmlFree.expect("non-null function pointer")(ret as *mut libc::c_void);
            return 0 as xmlRegexpPtr;
        }
        transdata = 0 as *mut *mut libc::c_void;
        i = 0 as i32;
        's_444: loop {
            if !(i < (*ret).nbStates) {
                current_block = 2627991079881472758;
                break;
            }
            let mut stateno: i32 = 0;
            let mut atomno: i32 = 0;
            let mut targetno: i32 = 0;
            let mut prev: i32 = 0;
            let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
            let mut trans: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegTrans>::None;
            stateno = *stateRemap.offset(i as isize);
            if !(stateno == -(1 as i32)) {
                state = *((*ret).states).offset(i as isize);
                *transitions
                    .offset(
                        (stateno * (nbatoms + 1 as i32)) as isize,
                    ) = (*state).type_0 as i32;
                j = 0 as i32;
                while j < (*state).nbTrans {
                    trans = Some(&mut *((*state).trans).offset(j as isize));
                    if !((*(borrow(& trans)).unwrap()).to == -(1 as i32) || ((*(borrow(& trans)).unwrap()).atom).is_null())
                    {
                        atomno = *stringRemap.offset((*(*(borrow(& trans)).unwrap()).atom).no as isize);
                        if !((*(*(borrow_mut(&mut trans)).unwrap()).atom).data).is_null() && transdata.is_null() {
                            transdata = xmlRegCalloc2(
                                nbstates as size_t,
                                nbatoms as size_t,
                                ::std::mem::size_of::<*mut libc::c_void>() as u64,
                            ) as *mut *mut libc::c_void;
                            if transdata.is_null() {
                                xmlRegexpErrMemory(
                                    ctxt,
                                    b"compiling regexp\0" as *const u8 as *const i8,
                                );
                                break;
                            }
                        }
                        targetno = *stateRemap.offset((*(borrow(& trans)).unwrap()).to as isize);
                        prev = *transitions
                            .offset(
                                (stateno * (nbatoms + 1 as i32) + atomno
                                    + 1 as i32) as isize,
                            );
                        if prev != 0 as i32 {
                            if prev != targetno + 1 as i32 {
                                (*ret).determinist = 0 as i32;
                                if !transdata.is_null() {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(transdata as *mut libc::c_void);
                                }
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(transitions as *mut libc::c_void);
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(stateRemap as *mut libc::c_void);
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(stringRemap as *mut libc::c_void);
                                i = 0 as i32;
                                while i < nbatoms {
                                    xmlFree
                                        .expect(
                                            "non-null function pointer",
                                        )(*stringMap.offset(i as isize) as *mut libc::c_void);
                                    i += 1;
                                }
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )(stringMap as *mut libc::c_void);
                                current_block = 13635467803606088781;
                                break 's_444;
                            }
                        } else {
                            *transitions
                                .offset(
                                    (stateno * (nbatoms + 1 as i32) + atomno
                                        + 1 as i32) as isize,
                                ) = targetno + 1 as i32;
                            if !transdata.is_null() {
                                let fresh5 = &mut (*transdata
                                    .offset((stateno * nbatoms + atomno) as isize));
                                *fresh5 = (*(*(borrow_mut(&mut trans)).unwrap()).atom).data;
                            }
                        }
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        match current_block {
            13635467803606088781 => {}
            _ => {
                (*ret).determinist = 1 as i32;
                if !((*ret).states).is_null() {
                    i = 0 as i32;
                    while i < (*ret).nbStates {
                        xmlRegFreeState(*((*ret).states).offset(i as isize));
                        i += 1;
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*ret).states as *mut libc::c_void);
                }
                let fresh6 = &mut ((*ret).states);
                *fresh6 = 0 as *mut xmlRegStatePtr;
                (*ret).nbStates = 0 as i32;
                if !((*ret).atoms).is_null() {
                    i = 0 as i32;
                    while i < (*ret).nbAtoms {
                        xmlRegFreeAtom(*((*ret).atoms).offset(i as isize));
                        i += 1;
                    }
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )((*ret).atoms as *mut libc::c_void);
                }
                let fresh7 = &mut ((*ret).atoms);
                *fresh7 = 0 as *mut xmlRegAtomPtr;
                (*ret).nbAtoms = 0 as i32;
                let fresh8 = &mut ((*ret).compact);
                *fresh8 = transitions;
                let fresh9 = &mut ((*ret).transdata);
                *fresh9 = transdata;
                let fresh10 = &mut ((*ret).stringMap);
                *fresh10 = stringMap;
                (*ret).nbstrings = nbatoms;
                (*ret).nbstates = nbstates;
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(stateRemap as *mut libc::c_void);
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(stringRemap as *mut libc::c_void);
            }
        }
    }
    let fresh11 = &mut ((*ctxt).string);
    *fresh11 = 0 as *mut xmlChar;
    (*ctxt).nbStates = 0 as i32;
    let fresh12 = &mut ((*ctxt).states);
    *fresh12 = 0 as *mut xmlRegStatePtr;
    (*ctxt).nbAtoms = 0 as i32;
    let fresh13 = &mut ((*ctxt).atoms);
    *fresh13 = 0 as *mut xmlRegAtomPtr;
    (*ctxt).nbCounters = 0 as i32;
    let fresh14 = &mut ((*ctxt).counters);
    *fresh14 = 0 as *mut xmlRegCounter;
    return ret;
}
unsafe extern "C" fn xmlRegNewParserCtxt(
    mut string: * const u8,
) -> * mut crate::src::xmlregexp::_xmlAutomata {
    let mut ret: * mut crate::src::xmlregexp::_xmlAutomata = 0 as *mut xmlRegParserCtxt;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegParserCtxt>() as u64)
        as xmlRegParserCtxtPtr;
    if ret.is_null() {
        return 0 as xmlRegParserCtxtPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegParserCtxt>() as u64,
    );
    if !string.is_null() {
        let fresh15 = &mut ((*ret).string);
        *fresh15 = xmlStrdup(string);
    }
    let fresh16 = &mut ((*ret).cur);
    *fresh16 = (*ret).string;
    (*ret).neg = 0 as i32;
    (*ret).negs = 0 as i32;
    (*ret).error = 0 as i32;
    (*ret).determinist = -(1 as i32);
    return ret;
}
unsafe extern "C" fn xmlRegNewRange(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut neg: i32,
    mut type_0: u32,
    mut start: i32,
    mut end: i32,
) -> * mut crate::src::xmlregexp::_xmlRegRange {
    let mut ret: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegRange>() as u64) as xmlRegRangePtr;
    if ret.is_null() {
        xmlRegexpErrMemory(
            ctxt,
            b"allocating range\0" as *const u8 as *const i8,
        );
        return 0 as xmlRegRangePtr;
    }
    (*ret).neg = neg;
    (*ret).type_0 = type_0;
    (*ret).start = start;
    (*ret).end = end;
    return ret;
}
unsafe extern "C" fn xmlRegFreeRange(mut range: * mut crate::src::xmlregexp::_xmlRegRange) {
    if range.is_null() {
        return;
    }
    if !((*range).blockName).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*range).blockName as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(range as *mut libc::c_void);
}
unsafe extern "C" fn xmlRegCopyRange(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut range: * mut crate::src::xmlregexp::_xmlRegRange,
) -> * mut crate::src::xmlregexp::_xmlRegRange {
    let mut ret: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
    if range.is_null() {
        return 0 as xmlRegRangePtr;
    }
    ret = xmlRegNewRange(
        ctxt,
        (*range).neg,
        (*range).type_0,
        (*range).start,
        (*range).end,
    );
    if ret.is_null() {
        return 0 as xmlRegRangePtr;
    }
    if !((*range).blockName).is_null() {
        let fresh17 = &mut ((*ret).blockName);
        *fresh17 = xmlStrdup((*range).blockName);
        if ((*ret).blockName).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"allocating range\0" as *const u8 as *const i8,
            );
            xmlRegFreeRange(ret);
            return 0 as xmlRegRangePtr;
        }
    }
    return ret;
}
unsafe extern "C" fn xmlRegNewAtom(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut type_0: u32,
) -> * mut crate::src::xmlregexp::_xmlRegAtom {
    let mut ret: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegAtom>() as u64) as xmlRegAtomPtr;
    if ret.is_null() {
        xmlRegexpErrMemory(
            ctxt,
            b"allocating atom\0" as *const u8 as *const i8,
        );
        return 0 as xmlRegAtomPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegAtom>() as u64,
    );
    (*ret).type_0 = type_0;
    (*ret).quant = XML_REGEXP_QUANT_ONCE;
    (*ret).min = 0 as i32;
    (*ret).max = 0 as i32;
    return ret;
}
unsafe extern "C" fn xmlRegFreeAtom(mut atom: * mut crate::src::xmlregexp::_xmlRegAtom) {
    let mut i: i32 = 0;
    if atom.is_null() {
        return;
    }
    i = 0 as i32;
    while i < (*atom).nbRanges {
        xmlRegFreeRange(*((*atom).ranges).offset(i as isize));
        i += 1;
    }
    if !((*atom).ranges).is_null() {
        xmlFree.expect("non-null function pointer")((*atom).ranges as *mut libc::c_void);
    }
    if (*atom).type_0 as u32 == XML_REGEXP_STRING as i32 as u32
        && !((*atom).valuep).is_null()
    {
        xmlFree.expect("non-null function pointer")((*atom).valuep);
    }
    if (*atom).type_0 as u32 == XML_REGEXP_STRING as i32 as u32
        && !((*atom).valuep2).is_null()
    {
        xmlFree.expect("non-null function pointer")((*atom).valuep2);
    }
    if (*atom).type_0 as u32
        == XML_REGEXP_BLOCK_NAME as i32 as u32
        && !((*atom).valuep).is_null()
    {
        xmlFree.expect("non-null function pointer")((*atom).valuep);
    }
    xmlFree.expect("non-null function pointer")(atom as *mut libc::c_void);
}
unsafe extern "C" fn xmlRegCopyAtom(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
) -> * mut crate::src::xmlregexp::_xmlRegAtom {
    let mut current_block: u64;
    let mut ret: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegAtom>() as u64) as xmlRegAtomPtr;
    if ret.is_null() {
        xmlRegexpErrMemory(ctxt, b"copying atom\0" as *const u8 as *const i8);
        return 0 as xmlRegAtomPtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegAtom>() as u64,
    );
    (*ret).type_0 = (*atom).type_0;
    (*ret).quant = (*atom).quant;
    (*ret).min = (*atom).min;
    (*ret).max = (*atom).max;
    if (*atom).nbRanges > 0 as i32 {
        let mut i: i32 = 0;
        let fresh18 = &mut ((*ret).ranges);
        *fresh18 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            (::std::mem::size_of::<xmlRegRangePtr>() as u64)
                .wrapping_mul((*atom).nbRanges as u64),
        ) as *mut xmlRegRangePtr;
        if ((*ret).ranges).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"copying atom\0" as *const u8 as *const i8,
            );
            current_block = 16366640603525550618;
        } else {
            i = 0 as i32;
            loop {
                if !(i < (*atom).nbRanges) {
                    current_block = 12124785117276362961;
                    break;
                }
                let fresh19 = &mut (*((*ret).ranges).offset(i as isize));
                *fresh19 = xmlRegCopyRange(ctxt, *((*atom).ranges).offset(i as isize));
                if (*((*ret).ranges).offset(i as isize)).is_null() {
                    current_block = 16366640603525550618;
                    break;
                }
                (*ret).nbRanges = i + 1 as i32;
                i += 1;
            }
        }
        match current_block {
            12124785117276362961 => {}
            _ => {
                xmlRegFreeAtom(ret);
                return 0 as xmlRegAtomPtr;
            }
        }
    }
    return ret;
}
unsafe extern "C" fn xmlRegNewState(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut ret: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    ret = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegState>() as u64) as xmlRegStatePtr;
    if ret.is_null() {
        xmlRegexpErrMemory(
            ctxt,
            b"allocating state\0" as *const u8 as *const i8,
        );
        return 0 as xmlRegStatePtr;
    }
    memset(
        ret as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegState>() as u64,
    );
    (*ret).type_0 = XML_REGEXP_TRANS_STATE;
    (*ret).mark = XML_REGEXP_MARK_NORMAL;
    return ret;
}
unsafe extern "C" fn xmlRegFreeState(mut state: * mut crate::src::xmlregexp::_xmlAutomataState) {
    if state.is_null() {
        return;
    }
    if !((*state).trans).is_null() {
        xmlFree.expect("non-null function pointer")((*state).trans as *mut libc::c_void);
    }
    if !((*state).transTo).is_null() {
        xmlFree
            .expect("non-null function pointer")((*state).transTo as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(state as *mut libc::c_void);
}
unsafe extern "C" fn xmlRegFreeParserCtxt(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut i: i32 = 0;
    if ctxt.is_null() {
        return;
    }
    if !((*ctxt).string).is_null() {
        xmlFree.expect("non-null function pointer")((*ctxt).string as *mut libc::c_void);
    }
    if !((*ctxt).states).is_null() {
        i = 0 as i32;
        while i < (*ctxt).nbStates {
            xmlRegFreeState(*((*ctxt).states).offset(i as isize));
            i += 1;
        }
        xmlFree.expect("non-null function pointer")((*ctxt).states as *mut libc::c_void);
    }
    if !((*ctxt).atoms).is_null() {
        i = 0 as i32;
        while i < (*ctxt).nbAtoms {
            xmlRegFreeAtom(*((*ctxt).atoms).offset(i as isize));
            i += 1;
        }
        xmlFree.expect("non-null function pointer")((*ctxt).atoms as *mut libc::c_void);
    }
    if !((*ctxt).counters).is_null() {
        xmlFree
            .expect("non-null function pointer")((*ctxt).counters as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(ctxt as *mut libc::c_void);
}
unsafe extern "C" fn xmlRegPrintAtomType(
    mut output: * mut crate::src::tree::_IO_FILE,
    mut type_0: u32,
) {
    match type_0 as u32 {
        1 => {
            fprintf(output, b"epsilon \0" as *const u8 as *const i8);
        }
        2 => {
            fprintf(output, b"charval \0" as *const u8 as *const i8);
        }
        3 => {
            fprintf(output, b"ranges \0" as *const u8 as *const i8);
        }
        4 => {
            fprintf(output, b"subexpr \0" as *const u8 as *const i8);
        }
        5 => {
            fprintf(output, b"string \0" as *const u8 as *const i8);
        }
        6 => {
            fprintf(output, b"anychar \0" as *const u8 as *const i8);
        }
        7 => {
            fprintf(output, b"anyspace \0" as *const u8 as *const i8);
        }
        8 => {
            fprintf(output, b"notspace \0" as *const u8 as *const i8);
        }
        9 => {
            fprintf(output, b"initname \0" as *const u8 as *const i8);
        }
        10 => {
            fprintf(output, b"notinitname \0" as *const u8 as *const i8);
        }
        11 => {
            fprintf(output, b"namechar \0" as *const u8 as *const i8);
        }
        12 => {
            fprintf(output, b"notnamechar \0" as *const u8 as *const i8);
        }
        13 => {
            fprintf(output, b"decimal \0" as *const u8 as *const i8);
        }
        14 => {
            fprintf(output, b"notdecimal \0" as *const u8 as *const i8);
        }
        15 => {
            fprintf(output, b"realchar \0" as *const u8 as *const i8);
        }
        16 => {
            fprintf(output, b"notrealchar \0" as *const u8 as *const i8);
        }
        100 => {
            fprintf(output, b"LETTER \0" as *const u8 as *const i8);
        }
        101 => {
            fprintf(output, b"LETTER_UPPERCASE \0" as *const u8 as *const i8);
        }
        102 => {
            fprintf(output, b"LETTER_LOWERCASE \0" as *const u8 as *const i8);
        }
        103 => {
            fprintf(output, b"LETTER_TITLECASE \0" as *const u8 as *const i8);
        }
        104 => {
            fprintf(output, b"LETTER_MODIFIER \0" as *const u8 as *const i8);
        }
        105 => {
            fprintf(output, b"LETTER_OTHERS \0" as *const u8 as *const i8);
        }
        106 => {
            fprintf(output, b"MARK \0" as *const u8 as *const i8);
        }
        107 => {
            fprintf(output, b"MARK_NONSPACING \0" as *const u8 as *const i8);
        }
        108 => {
            fprintf(
                output,
                b"MARK_SPACECOMBINING \0" as *const u8 as *const i8,
            );
        }
        109 => {
            fprintf(output, b"MARK_ENCLOSING \0" as *const u8 as *const i8);
        }
        110 => {
            fprintf(output, b"NUMBER \0" as *const u8 as *const i8);
        }
        111 => {
            fprintf(output, b"NUMBER_DECIMAL \0" as *const u8 as *const i8);
        }
        112 => {
            fprintf(output, b"NUMBER_LETTER \0" as *const u8 as *const i8);
        }
        113 => {
            fprintf(output, b"NUMBER_OTHERS \0" as *const u8 as *const i8);
        }
        114 => {
            fprintf(output, b"PUNCT \0" as *const u8 as *const i8);
        }
        115 => {
            fprintf(output, b"PUNCT_CONNECTOR \0" as *const u8 as *const i8);
        }
        116 => {
            fprintf(output, b"PUNCT_DASH \0" as *const u8 as *const i8);
        }
        117 => {
            fprintf(output, b"PUNCT_OPEN \0" as *const u8 as *const i8);
        }
        118 => {
            fprintf(output, b"PUNCT_CLOSE \0" as *const u8 as *const i8);
        }
        119 => {
            fprintf(output, b"PUNCT_INITQUOTE \0" as *const u8 as *const i8);
        }
        120 => {
            fprintf(output, b"PUNCT_FINQUOTE \0" as *const u8 as *const i8);
        }
        121 => {
            fprintf(output, b"PUNCT_OTHERS \0" as *const u8 as *const i8);
        }
        122 => {
            fprintf(output, b"SEPAR \0" as *const u8 as *const i8);
        }
        123 => {
            fprintf(output, b"SEPAR_SPACE \0" as *const u8 as *const i8);
        }
        124 => {
            fprintf(output, b"SEPAR_LINE \0" as *const u8 as *const i8);
        }
        125 => {
            fprintf(output, b"SEPAR_PARA \0" as *const u8 as *const i8);
        }
        126 => {
            fprintf(output, b"SYMBOL \0" as *const u8 as *const i8);
        }
        127 => {
            fprintf(output, b"SYMBOL_MATH \0" as *const u8 as *const i8);
        }
        128 => {
            fprintf(output, b"SYMBOL_CURRENCY \0" as *const u8 as *const i8);
        }
        129 => {
            fprintf(output, b"SYMBOL_MODIFIER \0" as *const u8 as *const i8);
        }
        130 => {
            fprintf(output, b"SYMBOL_OTHERS \0" as *const u8 as *const i8);
        }
        131 => {
            fprintf(output, b"OTHER \0" as *const u8 as *const i8);
        }
        132 => {
            fprintf(output, b"OTHER_CONTROL \0" as *const u8 as *const i8);
        }
        133 => {
            fprintf(output, b"OTHER_FORMAT \0" as *const u8 as *const i8);
        }
        134 => {
            fprintf(output, b"OTHER_PRIVATE \0" as *const u8 as *const i8);
        }
        135 => {
            fprintf(output, b"OTHER_NA \0" as *const u8 as *const i8);
        }
        136 => {
            fprintf(output, b"BLOCK \0" as *const u8 as *const i8);
        }
        _ => {}
    };
}
unsafe extern "C" fn xmlRegPrintQuantType(
    mut output: * mut crate::src::tree::_IO_FILE,
    mut type_0: u32,
) {
    match type_0 as u32 {
        1 => {
            fprintf(output, b"epsilon \0" as *const u8 as *const i8);
        }
        2 => {
            fprintf(output, b"once \0" as *const u8 as *const i8);
        }
        3 => {
            fprintf(output, b"? \0" as *const u8 as *const i8);
        }
        4 => {
            fprintf(output, b"* \0" as *const u8 as *const i8);
        }
        5 => {
            fprintf(output, b"+ \0" as *const u8 as *const i8);
        }
        8 => {
            fprintf(output, b"range \0" as *const u8 as *const i8);
        }
        6 => {
            fprintf(output, b"onceonly \0" as *const u8 as *const i8);
        }
        7 => {
            fprintf(output, b"all \0" as *const u8 as *const i8);
        }
        _ => {}
    };
}
unsafe extern "C" fn xmlRegPrintRange(mut output: * mut crate::src::tree::_IO_FILE, mut range: * mut crate::src::xmlregexp::_xmlRegRange) {
    fprintf(output, b"  range: \0" as *const u8 as *const i8);
    if (*range).neg != 0 {
        fprintf(output, b"negative \0" as *const u8 as *const i8);
    }
    xmlRegPrintAtomType(output, (*range).type_0);
    fprintf(
        output,
        b"%c - %c\n\0" as *const u8 as *const i8,
        (*range).start,
        (*range).end,
    );
}
unsafe extern "C" fn xmlRegPrintAtom(mut output: * mut crate::src::tree::_IO_FILE, mut atom: * mut crate::src::xmlregexp::_xmlRegAtom) {
    fprintf(output, b" atom: \0" as *const u8 as *const i8);
    if atom.is_null() {
        fprintf(output, b"NULL\n\0" as *const u8 as *const i8);
        return;
    }
    if (*atom).neg != 0 {
        fprintf(output, b"not \0" as *const u8 as *const i8);
    }
    xmlRegPrintAtomType(output, (*atom).type_0);
    xmlRegPrintQuantType(output, (*atom).quant);
    if (*atom).quant as u32
        == XML_REGEXP_QUANT_RANGE as i32 as u32
    {
        fprintf(
            output,
            b"%d-%d \0" as *const u8 as *const i8,
            (*atom).min,
            (*atom).max,
        );
    }
    if (*atom).type_0 as u32 == XML_REGEXP_STRING as i32 as u32
    {
        fprintf(
            output,
            b"'%s' \0" as *const u8 as *const i8,
            (*atom).valuep as *mut i8,
        );
    }
    if (*atom).type_0 as u32
        == XML_REGEXP_CHARVAL as i32 as u32
    {
        fprintf(
            output,
            b"char %c\n\0" as *const u8 as *const i8,
            (*atom).codepoint,
        );
    } else if (*atom).type_0 as u32
            == XML_REGEXP_RANGES as i32 as u32
        {
        let mut i: i32 = 0;
        fprintf(
            output,
            b"%d entries\n\0" as *const u8 as *const i8,
            (*atom).nbRanges,
        );
        i = 0 as i32;
        while i < (*atom).nbRanges {
            xmlRegPrintRange(output, *((*atom).ranges).offset(i as isize));
            i += 1;
        }
    } else if (*atom).type_0 as u32
            == XML_REGEXP_SUBREG as i32 as u32
        {
        fprintf(
            output,
            b"start %d end %d\n\0" as *const u8 as *const i8,
            (*(*atom).start).no,
            (*(*atom).stop).no,
        );
    } else {
        fprintf(output, b"\n\0" as *const u8 as *const i8);
    };
}
unsafe extern "C" fn xmlRegPrintTrans<'a1>(mut output: * mut crate::src::tree::_IO_FILE, mut trans: Option<&'a1 mut crate::src::xmlregexp::_xmlRegTrans>) {
    fprintf(output, b"  trans: \0" as *const u8 as *const i8);
    if borrow(& trans).is_none() {
        fprintf(output, b"NULL\n\0" as *const u8 as *const i8);
        return;
    }
    if (*(borrow(& trans)).unwrap()).to < 0 as i32 {
        fprintf(output, b"removed\n\0" as *const u8 as *const i8);
        return;
    }
    if (*(borrow(& trans)).unwrap()).nd != 0 as i32 {
        if (*(borrow(& trans)).unwrap()).nd == 2 as i32 {
            fprintf(
                output,
                b"last not determinist, \0" as *const u8 as *const i8,
            );
        } else {
            fprintf(output, b"not determinist, \0" as *const u8 as *const i8);
        }
    }
    if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
        fprintf(
            output,
            b"counted %d, \0" as *const u8 as *const i8,
            (*(borrow(& trans)).unwrap()).counter,
        );
    }
    if (*(borrow(& trans)).unwrap()).count == 0x123456 as i32 {
        fprintf(output, b"all transition, \0" as *const u8 as *const i8);
    } else if (*(borrow(& trans)).unwrap()).count >= 0 as i32 {
        fprintf(
            output,
            b"count based %d, \0" as *const u8 as *const i8,
            (*(borrow(& trans)).unwrap()).count,
        );
    }
    if ((*(borrow_mut(&mut trans)).unwrap()).atom).is_null() {
        fprintf(
            output,
            b"epsilon to %d\n\0" as *const u8 as *const i8,
            (*(borrow(& trans)).unwrap()).to,
        );
        return;
    }
    if (*(*(borrow(& trans)).unwrap()).atom).type_0 as u32
        == XML_REGEXP_CHARVAL as i32 as u32
    {
        fprintf(
            output,
            b"char %c \0" as *const u8 as *const i8,
            (*(*(borrow(& trans)).unwrap()).atom).codepoint,
        );
    }
    fprintf(
        output,
        b"atom %d, to %d\n\0" as *const u8 as *const i8,
        (*(*(borrow(& trans)).unwrap()).atom).no,
        (*(borrow(& trans)).unwrap()).to,
    );
}
unsafe extern "C" fn xmlRegPrintState(mut output: * mut crate::src::tree::_IO_FILE, mut state: * mut crate::src::xmlregexp::_xmlAutomataState) {
    let mut i: i32 = 0;
    fprintf(output, b" state: \0" as *const u8 as *const i8);
    if state.is_null() {
        fprintf(output, b"NULL\n\0" as *const u8 as *const i8);
        return;
    }
    if (*state).type_0 as u32
        == XML_REGEXP_START_STATE as i32 as u32
    {
        fprintf(output, b"START \0" as *const u8 as *const i8);
    }
    if (*state).type_0 as u32
        == XML_REGEXP_FINAL_STATE as i32 as u32
    {
        fprintf(output, b"FINAL \0" as *const u8 as *const i8);
    }
    fprintf(
        output,
        b"%d, %d transitions:\n\0" as *const u8 as *const i8,
        (*state).no,
        (*state).nbTrans,
    );
    i = 0 as i32;
    while i < (*state).nbTrans {
        xmlRegPrintTrans(output, Some(&mut *((*state).trans).offset(i as isize)));
        i += 1;
    }
}
unsafe extern "C" fn xmlRegAtomAddRange(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut neg: i32,
    mut type_0: u32,
    mut start: i32,
    mut end: i32,
    mut blockName: * mut u8,
) {
    let mut range: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
    if atom.is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"add range: atom is NULL\0" as *const u8 as *const i8,
        );
        return;
    }
    if (*atom).type_0 as u32 != XML_REGEXP_RANGES as i32 as u32
    {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"add range: atom is not ranges\0" as *const u8 as *const i8,
        );
        return;
    }
    if (*atom).maxRanges == 0 as i32 {
        (*atom).maxRanges = 4 as i32;
        let fresh20 = &mut ((*atom).ranges);
        *fresh20 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*atom).maxRanges as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegRangePtr>() as u64),
        ) as *mut xmlRegRangePtr;
        if ((*atom).ranges).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding ranges\0" as *const u8 as *const i8,
            );
            (*atom).maxRanges = 0 as i32;
            return;
        }
    } else if (*atom).nbRanges >= (*atom).maxRanges {
        let mut tmp: * mut * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRangePtr;
        (*atom).maxRanges *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*atom).ranges as *mut libc::c_void,
            ((*atom).maxRanges as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegRangePtr>() as u64),
        ) as *mut xmlRegRangePtr;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding ranges\0" as *const u8 as *const i8,
            );
            (*atom).maxRanges /= 2 as i32;
            return;
        }
        let fresh21 = &mut ((*atom).ranges);
        *fresh21 = tmp;
    }
    range = xmlRegNewRange(ctxt, neg, type_0, start, end);
    if range.is_null() {
        return;
    }
    let fresh22 = &mut ((*range).blockName);
    *fresh22 = blockName;
    let fresh23 = &mut ((*atom).nbRanges);
    let mut fresh24 = *fresh23;
    *fresh23 = *fresh23 + 1;
    let fresh25 = &mut (*((*atom).ranges).offset(fresh24 as isize));
    *fresh25 = range;
}
unsafe extern "C" fn xmlRegGetCounter(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    if (*ctxt).maxCounters == 0 as i32 {
        (*ctxt).maxCounters = 4 as i32;
        let fresh26 = &mut ((*ctxt).counters);
        *fresh26 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).maxCounters as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegCounter>() as u64),
        ) as *mut xmlRegCounter;
        if ((*ctxt).counters).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"allocating counter\0" as *const u8 as *const i8,
            );
            (*ctxt).maxCounters = 0 as i32;
            return -(1 as i32);
        }
    } else if (*ctxt).nbCounters >= (*ctxt).maxCounters {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegCounter = 0 as *mut xmlRegCounter;
        (*ctxt).maxCounters *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).counters as *mut libc::c_void,
            ((*ctxt).maxCounters as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegCounter>() as u64),
        ) as *mut xmlRegCounter;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"allocating counter\0" as *const u8 as *const i8,
            );
            (*ctxt).maxCounters /= 2 as i32;
            return -(1 as i32);
        }
        let fresh27 = &mut ((*ctxt).counters);
        *fresh27 = tmp;
    }
    (*((*ctxt).counters).offset((*ctxt).nbCounters as isize)).min = -(1 as i32);
    (*((*ctxt).counters).offset((*ctxt).nbCounters as isize)).max = -(1 as i32);
    let fresh28 = &mut ((*ctxt).nbCounters);
    let mut fresh29 = *fresh28;
    *fresh28 = *fresh28 + 1;
    return fresh29;
}
unsafe extern "C" fn xmlRegAtomPush(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
) -> i32 {
    if atom.is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"atom push: atom is NULL\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if (*ctxt).maxAtoms == 0 as i32 {
        (*ctxt).maxAtoms = 4 as i32;
        let fresh30 = &mut ((*ctxt).atoms);
        *fresh30 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).maxAtoms as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegAtomPtr>() as u64),
        ) as *mut xmlRegAtomPtr;
        if ((*ctxt).atoms).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"pushing atom\0" as *const u8 as *const i8,
            );
            (*ctxt).maxAtoms = 0 as i32;
            return -(1 as i32);
        }
    } else if (*ctxt).nbAtoms >= (*ctxt).maxAtoms {
        let mut tmp: * mut * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtomPtr;
        (*ctxt).maxAtoms *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).atoms as *mut libc::c_void,
            ((*ctxt).maxAtoms as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegAtomPtr>() as u64),
        ) as *mut xmlRegAtomPtr;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"allocating counter\0" as *const u8 as *const i8,
            );
            (*ctxt).maxAtoms /= 2 as i32;
            return -(1 as i32);
        }
        let fresh31 = &mut ((*ctxt).atoms);
        *fresh31 = tmp;
    }
    (*atom).no = (*ctxt).nbAtoms;
    let fresh32 = &mut ((*ctxt).nbAtoms);
    let mut fresh33 = *fresh32;
    *fresh32 = *fresh32 + 1;
    let fresh34 = &mut (*((*ctxt).atoms).offset(fresh33 as isize));
    *fresh34 = atom;
    return 0 as i32;
}
unsafe extern "C" fn xmlRegStateAddTransTo(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut target: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut from: i32,
) {
    if (*target).maxTransTo == 0 as i32 {
        (*target).maxTransTo = 8 as i32;
        let fresh35 = &mut ((*target).transTo);
        *fresh35 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*target).maxTransTo as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if ((*target).transTo).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding transition\0" as *const u8 as *const i8,
            );
            (*target).maxTransTo = 0 as i32;
            return;
        }
    } else if (*target).nbTransTo >= (*target).maxTransTo {
        let mut tmp: * mut i32 = 0 as *mut i32;
        (*target).maxTransTo *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*target).transTo as *mut libc::c_void,
            ((*target).maxTransTo as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding transition\0" as *const u8 as *const i8,
            );
            (*target).maxTransTo /= 2 as i32;
            return;
        }
        let fresh36 = &mut ((*target).transTo);
        *fresh36 = tmp;
    }
    *((*target).transTo).offset((*target).nbTransTo as isize) = from;
    let fresh37 = &mut ((*target).nbTransTo);
    *fresh37 += 1;
}
unsafe extern "C" fn xmlRegStateAddTrans(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut state: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut target: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut counter: i32,
    mut count: i32,
) {
    let mut nrtrans: i32 = 0;
    if state.is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"add state: state is NULL\0" as *const u8 as *const i8,
        );
        return;
    }
    if target.is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"add state: target is NULL\0" as *const u8 as *const i8,
        );
        return;
    }
    nrtrans = (*state).nbTrans - 1 as i32;
    while nrtrans >= 0 as i32 {
        let mut trans: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Some(&mut *((*state).trans).offset(nrtrans as isize));
        if (*(borrow(& trans)).unwrap()).atom == atom && (*(borrow(& trans)).unwrap()).to == (*target).no
            && (*(borrow(& trans)).unwrap()).counter == counter && (*(borrow(& trans)).unwrap()).count == count
        {
            return;
        }
        nrtrans -= 1;
    }
    if (*state).maxTrans == 0 as i32 {
        (*state).maxTrans = 8 as i32;
        let fresh38 = &mut ((*state).trans);
        *fresh38 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*state).maxTrans as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegTrans>() as u64),
        ) as *mut xmlRegTrans;
        if ((*state).trans).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding transition\0" as *const u8 as *const i8,
            );
            (*state).maxTrans = 0 as i32;
            return;
        }
    } else if (*state).nbTrans >= (*state).maxTrans {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegTrans = 0 as *mut xmlRegTrans;
        (*state).maxTrans *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*state).trans as *mut libc::c_void,
            ((*state).maxTrans as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegTrans>() as u64),
        ) as *mut xmlRegTrans;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding transition\0" as *const u8 as *const i8,
            );
            (*state).maxTrans /= 2 as i32;
            return;
        }
        let fresh39 = &mut ((*state).trans);
        *fresh39 = tmp;
    }
    let fresh40 = &mut ((*((*state).trans).offset((*state).nbTrans as isize)).atom);
    *fresh40 = atom;
    (*((*state).trans).offset((*state).nbTrans as isize)).to = (*target).no;
    (*((*state).trans).offset((*state).nbTrans as isize)).counter = counter;
    (*((*state).trans).offset((*state).nbTrans as isize)).count = count;
    (*((*state).trans).offset((*state).nbTrans as isize)).nd = 0 as i32;
    let fresh41 = &mut ((*state).nbTrans);
    *fresh41 += 1;
    xmlRegStateAddTransTo(ctxt, target, (*state).no);
}
unsafe extern "C" fn xmlRegStatePush(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut state: * mut crate::src::xmlregexp::_xmlAutomataState,
) -> i32 {
    if state.is_null() {
        return -(1 as i32);
    }
    if (*ctxt).maxStates == 0 as i32 {
        (*ctxt).maxStates = 4 as i32;
        let fresh42 = &mut ((*ctxt).states);
        *fresh42 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*ctxt).maxStates as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegStatePtr>() as u64),
        ) as *mut xmlRegStatePtr;
        if ((*ctxt).states).is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding state\0" as *const u8 as *const i8,
            );
            (*ctxt).maxStates = 0 as i32;
            return -(1 as i32);
        }
    } else if (*ctxt).nbStates >= (*ctxt).maxStates {
        let mut tmp: * mut * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegStatePtr;
        (*ctxt).maxStates *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*ctxt).states as *mut libc::c_void,
            ((*ctxt).maxStates as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegStatePtr>() as u64),
        ) as *mut xmlRegStatePtr;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                ctxt,
                b"adding state\0" as *const u8 as *const i8,
            );
            (*ctxt).maxStates /= 2 as i32;
            return -(1 as i32);
        }
        let fresh43 = &mut ((*ctxt).states);
        *fresh43 = tmp;
    }
    (*state).no = (*ctxt).nbStates;
    let fresh44 = &mut ((*ctxt).nbStates);
    let mut fresh45 = *fresh44;
    *fresh44 = *fresh44 + 1;
    let fresh46 = &mut (*((*ctxt).states).offset(fresh45 as isize));
    *fresh46 = state;
    return 0 as i32;
}
unsafe extern "C" fn xmlFAGenerateAllTransition(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut lax: i32,
) {
    if to.is_null() {
        to = xmlRegNewState(ctxt);
        xmlRegStatePush(ctxt, to);
        let fresh47 = &mut ((*ctxt).state);
        *fresh47 = to;
    }
    if lax != 0 {
        xmlRegStateAddTrans(
            ctxt,
            from,
            0 as xmlRegAtomPtr,
            to,
            -(1 as i32),
            0x123457 as i32,
        );
    } else {
        xmlRegStateAddTrans(
            ctxt,
            from,
            0 as xmlRegAtomPtr,
            to,
            -(1 as i32),
            0x123456 as i32,
        );
    };
}
unsafe extern "C" fn xmlFAGenerateEpsilonTransition(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
) {
    if to.is_null() {
        to = xmlRegNewState(ctxt);
        xmlRegStatePush(ctxt, to);
        let fresh48 = &mut ((*ctxt).state);
        *fresh48 = to;
    }
    xmlRegStateAddTrans(
        ctxt,
        from,
        0 as xmlRegAtomPtr,
        to,
        -(1 as i32),
        -(1 as i32),
    );
}
unsafe extern "C" fn xmlFAGenerateCountedEpsilonTransition(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut counter: i32,
) {
    if to.is_null() {
        to = xmlRegNewState(ctxt);
        xmlRegStatePush(ctxt, to);
        let fresh49 = &mut ((*ctxt).state);
        *fresh49 = to;
    }
    xmlRegStateAddTrans(
        ctxt,
        from,
        0 as xmlRegAtomPtr,
        to,
        counter,
        -(1 as i32),
    );
}
unsafe extern "C" fn xmlFAGenerateCountedTransition(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut counter: i32,
) {
    if to.is_null() {
        to = xmlRegNewState(ctxt);
        xmlRegStatePush(ctxt, to);
        let fresh50 = &mut ((*ctxt).state);
        *fresh50 = to;
    }
    xmlRegStateAddTrans(
        ctxt,
        from,
        0 as xmlRegAtomPtr,
        to,
        -(1 as i32),
        counter,
    );
}
unsafe extern "C" fn xmlFAGenerateTransitions(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
) -> i32 {
    let mut end: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut nullable: i32 = 0 as i32;
    if atom.is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"generate transition: atom == NULL\0" as *const u8 as *const i8,
        );
        return -(1 as i32);
    }
    if (*atom).type_0 as u32 == XML_REGEXP_SUBREG as i32 as u32
    {
        if xmlRegAtomPush(ctxt, atom) < 0 as i32 {
            return -(1 as i32);
        }
        if !to.is_null() && (*atom).stop != to
            && (*atom).quant as u32
                != XML_REGEXP_QUANT_RANGE as i32 as u32
        {
            xmlFAGenerateEpsilonTransition(ctxt, (*atom).stop, to);
        }
        match (*atom).quant as u32 {
            3 => {
                (*atom).quant = XML_REGEXP_QUANT_ONCE;
                if to.is_null() {
                    xmlFAGenerateEpsilonTransition(
                        ctxt,
                        (*atom).start,
                        0 as xmlRegStatePtr,
                    );
                    xmlFAGenerateEpsilonTransition(ctxt, (*atom).stop, (*ctxt).state);
                } else {
                    xmlFAGenerateEpsilonTransition(ctxt, (*atom).start, to);
                }
            }
            4 => {
                (*atom).quant = XML_REGEXP_QUANT_ONCE;
                xmlFAGenerateEpsilonTransition(ctxt, (*atom).start, (*atom).stop);
                xmlFAGenerateEpsilonTransition(ctxt, (*atom).stop, (*atom).start);
            }
            5 => {
                (*atom).quant = XML_REGEXP_QUANT_ONCE;
                xmlFAGenerateEpsilonTransition(ctxt, (*atom).stop, (*atom).start);
            }
            8 => {
                let mut counter: i32 = 0;
                let mut inter: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
                let mut newstate: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
                if !to.is_null() {
                    newstate = to;
                } else {
                    newstate = xmlRegNewState(ctxt);
                    xmlRegStatePush(ctxt, newstate);
                }
                if (*atom).min == 0 as i32 && ((*atom).start0).is_null() {
                    let mut copy: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
                    copy = xmlRegCopyAtom(ctxt, atom);
                    if copy.is_null() {
                        return -(1 as i32);
                    }
                    (*copy).quant = XML_REGEXP_QUANT_ONCE;
                    (*copy).min = 0 as i32;
                    (*copy).max = 0 as i32;
                    if xmlFAGenerateTransitions(
                        ctxt,
                        (*atom).start,
                        0 as xmlRegStatePtr,
                        copy,
                    ) < 0 as i32
                    {
                        return -(1 as i32);
                    }
                    inter = (*ctxt).state;
                    counter = xmlRegGetCounter(ctxt);
                    (*((*ctxt).counters).offset(counter as isize))
                        .min = (*atom).min - 1 as i32;
                    (*((*ctxt).counters).offset(counter as isize))
                        .max = (*atom).max - 1 as i32;
                    xmlFAGenerateCountedEpsilonTransition(
                        ctxt,
                        inter,
                        (*atom).stop,
                        counter,
                    );
                    xmlFAGenerateCountedTransition(ctxt, inter, newstate, counter);
                    xmlFAGenerateEpsilonTransition(ctxt, (*atom).start, newstate);
                } else {
                    counter = xmlRegGetCounter(ctxt);
                    (*((*ctxt).counters).offset(counter as isize))
                        .min = (*atom).min - 1 as i32;
                    (*((*ctxt).counters).offset(counter as isize))
                        .max = (*atom).max - 1 as i32;
                    xmlFAGenerateCountedTransition(
                        ctxt,
                        (*atom).stop,
                        newstate,
                        counter,
                    );
                    xmlFAGenerateCountedEpsilonTransition(
                        ctxt,
                        (*atom).stop,
                        (*atom).start,
                        counter,
                    );
                    if (*atom).min == 0 as i32 {
                        xmlFAGenerateEpsilonTransition(ctxt, (*atom).start0, newstate);
                    }
                }
                (*atom).min = 0 as i32;
                (*atom).max = 0 as i32;
                (*atom).quant = XML_REGEXP_QUANT_ONCE;
                let fresh51 = &mut ((*ctxt).state);
                *fresh51 = newstate;
            }
            _ => {}
        }
        return 0 as i32;
    }
    if (*atom).min == 0 as i32 && (*atom).max == 0 as i32
        && (*atom).quant as u32
            == XML_REGEXP_QUANT_RANGE as i32 as u32
    {
        if to.is_null() {
            to = xmlRegNewState(ctxt);
            if !to.is_null() {
                xmlRegStatePush(ctxt, to);
            } else {
                return -(1 as i32)
            }
        }
        xmlFAGenerateEpsilonTransition(ctxt, from, to);
        let fresh52 = &mut ((*ctxt).state);
        *fresh52 = to;
        xmlRegFreeAtom(atom);
        return 0 as i32;
    }
    if to.is_null() {
        to = xmlRegNewState(ctxt);
        if !to.is_null() {
            xmlRegStatePush(ctxt, to);
        } else {
            return -(1 as i32)
        }
    }
    end = to;
    if (*atom).quant as u32
        == XML_REGEXP_QUANT_MULT as i32 as u32
        || (*atom).quant as u32
            == XML_REGEXP_QUANT_PLUS as i32 as u32
    {
        let mut tmp: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
        tmp = xmlRegNewState(ctxt);
        if !tmp.is_null() {
            xmlRegStatePush(ctxt, tmp);
        } else {
            return -(1 as i32)
        }
        xmlFAGenerateEpsilonTransition(ctxt, tmp, to);
        to = tmp;
    }
    if xmlRegAtomPush(ctxt, atom) < 0 as i32 {
        return -(1 as i32);
    }
    if (*atom).quant as u32
        == XML_REGEXP_QUANT_RANGE as i32 as u32
        && (*atom).min == 0 as i32 && (*atom).max > 0 as i32
    {
        nullable = 1 as i32;
        (*atom).min = 1 as i32;
        if (*atom).max == 1 as i32 {
            (*atom).quant = XML_REGEXP_QUANT_OPT;
        }
    }
    xmlRegStateAddTrans(ctxt, from, atom, to, -(1 as i32), -(1 as i32));
    let fresh53 = &mut ((*ctxt).state);
    *fresh53 = end;
    match (*atom).quant as u32 {
        3 => {
            (*atom).quant = XML_REGEXP_QUANT_ONCE;
            xmlFAGenerateEpsilonTransition(ctxt, from, to);
        }
        4 => {
            (*atom).quant = XML_REGEXP_QUANT_ONCE;
            xmlFAGenerateEpsilonTransition(ctxt, from, to);
            xmlRegStateAddTrans(
                ctxt,
                to,
                atom,
                to,
                -(1 as i32),
                -(1 as i32),
            );
        }
        5 => {
            (*atom).quant = XML_REGEXP_QUANT_ONCE;
            xmlRegStateAddTrans(
                ctxt,
                to,
                atom,
                to,
                -(1 as i32),
                -(1 as i32),
            );
        }
        8 => {
            if nullable != 0 {
                xmlFAGenerateEpsilonTransition(ctxt, from, to);
            }
        }
        _ => {}
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlFAReduceEpsilonTransitions(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut fromnr: i32,
    mut tonr: i32,
    mut counter: i32,
) {
    let mut transnr: i32 = 0;
    let mut from: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut to: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    from = *((*ctxt).states).offset(fromnr as isize);
    if from.is_null() {
        return;
    }
    to = *((*ctxt).states).offset(tonr as isize);
    if to.is_null() {
        return;
    }
    if (*to).mark as u32 == XML_REGEXP_MARK_START as i32 as u32
        || (*to).mark as u32
            == XML_REGEXP_MARK_VISITED as i32 as u32
    {
        return;
    }
    (*to).mark = XML_REGEXP_MARK_VISITED;
    if (*to).type_0 as u32
        == XML_REGEXP_FINAL_STATE as i32 as u32
    {
        (*from).type_0 = XML_REGEXP_FINAL_STATE;
    }
    transnr = 0 as i32;
    while transnr < (*to).nbTrans {
        if !((*((*to).trans).offset(transnr as isize)).to < 0 as i32) {
            if ((*((*to).trans).offset(transnr as isize)).atom).is_null() {
                if (*((*to).trans).offset(transnr as isize)).to != fromnr {
                    if (*((*to).trans).offset(transnr as isize)).count
                        >= 0 as i32
                    {
                        let mut newto: i32 = (*((*to).trans)
                            .offset(transnr as isize))
                            .to;
                        xmlRegStateAddTrans(
                            ctxt,
                            from,
                            0 as xmlRegAtomPtr,
                            *((*ctxt).states).offset(newto as isize),
                            -(1 as i32),
                            (*((*to).trans).offset(transnr as isize)).count,
                        );
                    } else if (*((*to).trans).offset(transnr as isize)).counter
                            >= 0 as i32
                        {
                        xmlFAReduceEpsilonTransitions(
                            ctxt,
                            fromnr,
                            (*((*to).trans).offset(transnr as isize)).to,
                            (*((*to).trans).offset(transnr as isize)).counter,
                        );
                    } else {
                        xmlFAReduceEpsilonTransitions(
                            ctxt,
                            fromnr,
                            (*((*to).trans).offset(transnr as isize)).to,
                            counter,
                        );
                    }
                }
            } else {
                let mut newto_0: i32 = (*((*to).trans).offset(transnr as isize))
                    .to;
                if (*((*to).trans).offset(transnr as isize)).counter >= 0 as i32
                {
                    xmlRegStateAddTrans(
                        ctxt,
                        from,
                        (*((*to).trans).offset(transnr as isize)).atom,
                        *((*ctxt).states).offset(newto_0 as isize),
                        (*((*to).trans).offset(transnr as isize)).counter,
                        -(1 as i32),
                    );
                } else {
                    xmlRegStateAddTrans(
                        ctxt,
                        from,
                        (*((*to).trans).offset(transnr as isize)).atom,
                        *((*ctxt).states).offset(newto_0 as isize),
                        counter,
                        -(1 as i32),
                    );
                }
            }
        }
        transnr += 1;
    }
    (*to).mark = XML_REGEXP_MARK_NORMAL;
}
unsafe extern "C" fn xmlFAEliminateSimpleEpsilonTransitions(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
) {
    let mut statenr: i32 = 0;
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut newto: i32 = 0;
    let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut tmp: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null() {
            if !((*state).nbTrans != 1 as i32) {
                if !((*state).type_0 as u32
                    == XML_REGEXP_UNREACH_STATE as i32 as u32
                    || (*state).type_0 as u32
                        == XML_REGEXP_FINAL_STATE as i32 as u32)
                {
                    if ((*((*state).trans).offset(0 as i32 as isize)).atom)
                        .is_null()
                        && (*((*state).trans).offset(0 as i32 as isize)).to
                            >= 0 as i32
                        && (*((*state).trans).offset(0 as i32 as isize)).to
                            != statenr
                        && (*((*state).trans).offset(0 as i32 as isize)).counter
                            < 0 as i32
                        && (*((*state).trans).offset(0 as i32 as isize)).count
                            < 0 as i32
                    {
                        newto = (*((*state).trans).offset(0 as i32 as isize)).to;
                        if !((*state).type_0 as u32
                            == XML_REGEXP_START_STATE as i32 as u32)
                        {
                            i = 0 as i32;
                            while i < (*state).nbTransTo {
                                tmp = *((*ctxt).states)
                                    .offset(*((*state).transTo).offset(i as isize) as isize);
                                j = 0 as i32;
                                while j < (*tmp).nbTrans {
                                    if (*((*tmp).trans).offset(j as isize)).to == statenr {
                                        (*((*tmp).trans).offset(j as isize))
                                            .to = -(1 as i32);
                                        xmlRegStateAddTrans(
                                            ctxt,
                                            tmp,
                                            (*((*tmp).trans).offset(j as isize)).atom,
                                            *((*ctxt).states).offset(newto as isize),
                                            (*((*tmp).trans).offset(j as isize)).counter,
                                            (*((*tmp).trans).offset(j as isize)).count,
                                        );
                                    }
                                    j += 1;
                                }
                                i += 1;
                            }
                            if (*state).type_0 as u32
                                == XML_REGEXP_FINAL_STATE as i32 as u32
                            {
                                (**((*ctxt).states).offset(newto as isize))
                                    .type_0 = XML_REGEXP_FINAL_STATE;
                            }
                            (*state).nbTrans = 0 as i32;
                            (*state).type_0 = XML_REGEXP_UNREACH_STATE;
                        }
                    }
                }
            }
        }
        statenr += 1;
    }
}
unsafe extern "C" fn xmlFAEliminateEpsilonTransitions(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut statenr: i32 = 0;
    let mut transnr: i32 = 0;
    let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut has_epsilon: i32 = 0;
    if ((*ctxt).states).is_null() {
        return;
    }
    xmlFAEliminateSimpleEpsilonTransitions(ctxt);
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null()
            && (*state).type_0 as u32
                == XML_REGEXP_UNREACH_STATE as i32 as u32
        {
            xmlRegFreeState(state);
            let fresh54 = &mut (*((*ctxt).states).offset(statenr as isize));
            *fresh54 = 0 as xmlRegStatePtr;
        }
        statenr += 1;
    }
    has_epsilon = 0 as i32;
    statenr = (*ctxt).nbStates - 1 as i32;
    while statenr >= 0 as i32 {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null() {
            if (*state).nbTrans == 0 as i32
                && (*state).type_0 as u32
                    != XML_REGEXP_FINAL_STATE as i32 as u32
            {
                (*state).type_0 = XML_REGEXP_SINK_STATE;
            }
            transnr = 0 as i32;
            while transnr < (*state).nbTrans {
                if ((*((*state).trans).offset(transnr as isize)).atom).is_null()
                    && (*((*state).trans).offset(transnr as isize)).to
                        >= 0 as i32
                {
                    if (*((*state).trans).offset(transnr as isize)).to == statenr {
                        (*((*state).trans).offset(transnr as isize))
                            .to = -(1 as i32);
                    } else if (*((*state).trans).offset(transnr as isize)).count
                            < 0 as i32
                        {
                        let mut newto: i32 = (*((*state).trans)
                            .offset(transnr as isize))
                            .to;
                        has_epsilon = 1 as i32;
                        (*((*state).trans).offset(transnr as isize))
                            .to = -(2 as i32);
                        (*state).mark = XML_REGEXP_MARK_START;
                        xmlFAReduceEpsilonTransitions(
                            ctxt,
                            statenr,
                            newto,
                            (*((*state).trans).offset(transnr as isize)).counter,
                        );
                        (*state).mark = XML_REGEXP_MARK_NORMAL;
                    }
                }
                transnr += 1;
            }
        }
        statenr -= 1;
    }
    if has_epsilon != 0 {
        statenr = 0 as i32;
        while statenr < (*ctxt).nbStates {
            state = *((*ctxt).states).offset(statenr as isize);
            if !state.is_null() {
                transnr = 0 as i32;
                while transnr < (*state).nbTrans {
                    let mut trans: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Some(&mut *((*state).trans)
                        .offset(transnr as isize));
                    if ((*(borrow(& trans)).unwrap()).atom).is_null() && (*(borrow(& trans)).unwrap()).count < 0 as i32
                        && (*(borrow(& trans)).unwrap()).to >= 0 as i32
                    {
                        (*(borrow_mut(&mut trans)).unwrap()).to = -(1 as i32);
                    }
                    transnr += 1;
                }
            }
            statenr += 1;
        }
    }
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null() {
            (*state).reached = XML_REGEXP_MARK_NORMAL;
        }
        statenr += 1;
    }
    state = *((*ctxt).states).offset(0 as i32 as isize);
    if !state.is_null() {
        (*state).reached = XML_REGEXP_MARK_START;
    }
    while !state.is_null() {
        let mut target: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as xmlRegStatePtr;
        (*state).reached = XML_REGEXP_MARK_VISITED;
        transnr = 0 as i32;
        while transnr < (*state).nbTrans {
            if (*((*state).trans).offset(transnr as isize)).to >= 0 as i32
                && (!((*((*state).trans).offset(transnr as isize)).atom).is_null()
                    || (*((*state).trans).offset(transnr as isize)).count
                        >= 0 as i32)
            {
                let mut newto_0: i32 = (*((*state).trans)
                    .offset(transnr as isize))
                    .to;
                if !(*((*ctxt).states).offset(newto_0 as isize)).is_null() {
                    if (**((*ctxt).states).offset(newto_0 as isize)).reached
                        as u32
                        == XML_REGEXP_MARK_NORMAL as i32 as u32
                    {
                        (**((*ctxt).states).offset(newto_0 as isize))
                            .reached = XML_REGEXP_MARK_START;
                        target = *((*ctxt).states).offset(newto_0 as isize);
                    }
                }
            }
            transnr += 1;
        }
        if target.is_null() {
            statenr = 1 as i32;
            while statenr < (*ctxt).nbStates {
                state = *((*ctxt).states).offset(statenr as isize);
                if !state.is_null()
                    && (*state).reached as u32
                        == XML_REGEXP_MARK_START as i32 as u32
                {
                    target = state;
                    break;
                } else {
                    statenr += 1;
                }
            }
        }
        state = target;
    }
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null()
            && (*state).reached as u32
                == XML_REGEXP_MARK_NORMAL as i32 as u32
        {
            xmlRegFreeState(state);
            let fresh55 = &mut (*((*ctxt).states).offset(statenr as isize));
            *fresh55 = 0 as xmlRegStatePtr;
        }
        statenr += 1;
    }
}
unsafe extern "C" fn xmlFACompareRanges(
    mut range1: * mut crate::src::xmlregexp::_xmlRegRange,
    mut range2: * mut crate::src::xmlregexp::_xmlRegRange,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    if (*range1).type_0 as u32
        == XML_REGEXP_RANGES as i32 as u32
        || (*range2).type_0 as u32
            == XML_REGEXP_RANGES as i32 as u32
        || (*range2).type_0 as u32
            == XML_REGEXP_SUBREG as i32 as u32
        || (*range1).type_0 as u32
            == XML_REGEXP_SUBREG as i32 as u32
        || (*range1).type_0 as u32
            == XML_REGEXP_STRING as i32 as u32
        || (*range2).type_0 as u32
            == XML_REGEXP_STRING as i32 as u32
    {
        return -(1 as i32);
    }
    if (*range1).type_0 as u32 > (*range2).type_0 as u32 {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
        tmp = range1;
        range1 = range2;
        range2 = tmp;
    }
    if (*range1).type_0 as u32
        == XML_REGEXP_ANYCHAR as i32 as u32
        || (*range2).type_0 as u32
            == XML_REGEXP_ANYCHAR as i32 as u32
    {
        ret = 1 as i32;
    } else if (*range1).type_0 as u32
            == XML_REGEXP_EPSILON as i32 as u32
            || (*range2).type_0 as u32
                == XML_REGEXP_EPSILON as i32 as u32
        {
        return 0 as i32
    } else {
        if (*range1).type_0 as u32 == (*range2).type_0 as u32 {
            if (*range1).type_0 as u32
                != XML_REGEXP_CHARVAL as i32 as u32
            {
                ret = 1 as i32;
            } else if (*range1).end < (*range2).start || (*range2).end < (*range1).start
                {
                ret = 0 as i32;
            } else {
                ret = 1 as i32;
            }
        } else if (*range1).type_0 as u32
                == XML_REGEXP_CHARVAL as i32 as u32
            {
            let mut codepoint: i32 = 0;
            let mut neg: i32 = 0 as i32;
            if (*range1).neg == 0 as i32 && (*range2).neg != 0 as i32
                || (*range1).neg != 0 as i32 && (*range2).neg == 0 as i32
            {
                neg = 1 as i32;
            }
            codepoint = (*range1).start;
            while codepoint <= (*range1).end {
                ret = xmlRegCheckCharacterRange(
                    (*range2).type_0,
                    codepoint,
                    0 as i32,
                    (*range2).start,
                    (*range2).end,
                    (*range2).blockName,
                );
                if ret < 0 as i32 {
                    return -(1 as i32);
                }
                if neg == 1 as i32 && ret == 0 as i32
                    || neg == 0 as i32 && ret == 1 as i32
                {
                    return 1 as i32;
                }
                codepoint += 1;
            }
            return 0 as i32;
        } else {
            if (*range1).type_0 as u32
                == XML_REGEXP_BLOCK_NAME as i32 as u32
                || (*range2).type_0 as u32
                    == XML_REGEXP_BLOCK_NAME as i32 as u32
            {
                if (*range1).type_0 as u32 == (*range2).type_0 as u32 {
                    ret = xmlStrEqual((*range1).blockName, (*range2).blockName);
                } else {
                    return 1 as i32
                }
            } else if ((*range1).type_0 as u32)
                    < XML_REGEXP_LETTER as i32 as u32
                    || ((*range2).type_0 as u32)
                        < XML_REGEXP_LETTER as i32 as u32
                {
                if (*range1).type_0 as u32
                    == XML_REGEXP_ANYSPACE as i32 as u32
                    && (*range2).type_0 as u32
                        == XML_REGEXP_NOTSPACE as i32 as u32
                {
                    ret = 0 as i32;
                } else if (*range1).type_0 as u32
                        == XML_REGEXP_INITNAME as i32 as u32
                        && (*range2).type_0 as u32
                            == XML_REGEXP_NOTINITNAME as i32 as u32
                    {
                    ret = 0 as i32;
                } else if (*range1).type_0 as u32
                        == XML_REGEXP_NAMECHAR as i32 as u32
                        && (*range2).type_0 as u32
                            == XML_REGEXP_NOTNAMECHAR as i32 as u32
                    {
                    ret = 0 as i32;
                } else if (*range1).type_0 as u32
                        == XML_REGEXP_DECIMAL as i32 as u32
                        && (*range2).type_0 as u32
                            == XML_REGEXP_NOTDECIMAL as i32 as u32
                    {
                    ret = 0 as i32;
                } else if (*range1).type_0 as u32
                        == XML_REGEXP_REALCHAR as i32 as u32
                        && (*range2).type_0 as u32
                            == XML_REGEXP_NOTREALCHAR as i32 as u32
                    {
                    ret = 0 as i32;
                } else {
                    return 1 as i32
                }
            } else {
                ret = 0 as i32;
                match (*range1).type_0 as u32 {
                    100 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_LETTER_UPPERCASE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_LETTER_LOWERCASE as i32
                                    as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_LETTER_TITLECASE as i32
                                    as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_LETTER_MODIFIER as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_LETTER_OTHERS as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    106 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_MARK_NONSPACING as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_MARK_SPACECOMBINING as i32
                                    as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_MARK_ENCLOSING as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    110 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_NUMBER_DECIMAL as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_NUMBER_LETTER as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_NUMBER_OTHERS as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    114 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_PUNCT_CONNECTOR as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_DASH as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_OPEN as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_CLOSE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_INITQUOTE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_FINQUOTE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_PUNCT_OTHERS as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    122 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_SEPAR_SPACE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_SEPAR_LINE as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_SEPAR_PARA as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    126 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_SYMBOL_MATH as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_SYMBOL_CURRENCY as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_SYMBOL_MODIFIER as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_SYMBOL_OTHERS as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    131 => {
                        if (*range2).type_0 as u32
                            == XML_REGEXP_OTHER_CONTROL as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_OTHER_FORMAT as i32 as u32
                            || (*range2).type_0 as u32
                                == XML_REGEXP_OTHER_PRIVATE as i32 as u32
                        {
                            ret = 1 as i32;
                        }
                    }
                    _ => {
                        if (*range2).type_0 as u32
                            >= XML_REGEXP_LETTER as i32 as u32
                            && ((*range2).type_0 as u32)
                                < XML_REGEXP_BLOCK_NAME as i32 as u32
                        {
                            ret = 0 as i32;
                        } else {
                            return 1 as i32
                        }
                    }
                }
            }
        }
    }
    if (*range1).neg == 0 as i32 && (*range2).neg != 0 as i32
        || (*range1).neg != 0 as i32 && (*range2).neg == 0 as i32
    {
        ret = (ret == 0) as i32;
    }
    return ret;
}
 extern "C" fn xmlFACompareAtomTypes(
    mut type1: u32,
    mut type2: u32,
) -> i32 {
    if type1 as u32 == XML_REGEXP_EPSILON as i32 as u32
        || type1 as u32 == XML_REGEXP_CHARVAL as i32 as u32
        || type1 as u32 == XML_REGEXP_RANGES as i32 as u32
        || type1 as u32 == XML_REGEXP_SUBREG as i32 as u32
        || type1 as u32 == XML_REGEXP_STRING as i32 as u32
        || type1 as u32 == XML_REGEXP_ANYCHAR as i32 as u32
    {
        return 1 as i32;
    }
    if type2 as u32 == XML_REGEXP_EPSILON as i32 as u32
        || type2 as u32 == XML_REGEXP_CHARVAL as i32 as u32
        || type2 as u32 == XML_REGEXP_RANGES as i32 as u32
        || type2 as u32 == XML_REGEXP_SUBREG as i32 as u32
        || type2 as u32 == XML_REGEXP_STRING as i32 as u32
        || type2 as u32 == XML_REGEXP_ANYCHAR as i32 as u32
    {
        return 1 as i32;
    }
    if type1 as u32 == type2 as u32 {
        return 1 as i32;
    }
    if type1 as u32 > type2 as u32 {
        let mut tmp: u32 = type1;
        type1 = type2;
        type2 = tmp;
    }
    match type1 as u32 {
        7 => {
            if type2 as u32
                == XML_REGEXP_NOTSPACE as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_LETTER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_LETTER_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_NUMBER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_NUMBER_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_MARK as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_PUNCT as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SYMBOL as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
            {
                return 0 as i32;
            }
        }
        8 => {}
        9 => {
            if type2 as u32
                == XML_REGEXP_NOTINITNAME as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_NUMBER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_NUMBER_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_MARK as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SEPAR as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SEPAR_PARA as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_PUNCT as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SYMBOL as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_OTHER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_OTHER_NA as i32 as u32
            {
                return 0 as i32;
            }
        }
        10 => {}
        11 => {
            if type2 as u32
                == XML_REGEXP_NOTNAMECHAR as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_MARK as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_PUNCT as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SEPAR as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SEPAR_PARA as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SYMBOL as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_OTHER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_OTHER_NA as i32 as u32
            {
                return 0 as i32;
            }
        }
        12 => {}
        13 => {
            if type2 as u32
                == XML_REGEXP_NOTDECIMAL as i32 as u32
                || type2 as u32
                    == XML_REGEXP_REALCHAR as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_LETTER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_LETTER_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_MARK as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_PUNCT as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SEPAR as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SEPAR_PARA as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SYMBOL as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_OTHER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_OTHER_NA as i32 as u32
            {
                return 0 as i32;
            }
        }
        14 => {}
        15 => {
            if type2 as u32
                == XML_REGEXP_NOTDECIMAL as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_MARK as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_PUNCT as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SEPAR as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SEPAR_PARA as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_SYMBOL as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
                || type2 as u32
                    >= XML_REGEXP_OTHER as i32 as u32
                    && type2 as u32
                        <= XML_REGEXP_OTHER_NA as i32 as u32
            {
                return 0 as i32;
            }
        }
        100 => {
            if type2 as u32
                <= XML_REGEXP_LETTER_OTHERS as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        101 | 102 | 103 | 104 | 105 => return 0 as i32,
        106 => {
            if type2 as u32
                <= XML_REGEXP_MARK_ENCLOSING as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        107 | 108 | 109 => return 0 as i32,
        110 => {
            if type2 as u32
                <= XML_REGEXP_NUMBER_OTHERS as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        111 | 112 | 113 => return 0 as i32,
        114 => {
            if type2 as u32
                <= XML_REGEXP_PUNCT_OTHERS as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        115 | 116 | 117 | 118 | 119 | 120 | 121 => return 0 as i32,
        122 => {
            if type2 as u32
                <= XML_REGEXP_SEPAR_PARA as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        123 | 124 | 125 => return 0 as i32,
        126 => {
            if type2 as u32
                <= XML_REGEXP_SYMBOL_OTHERS as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        127 | 128 | 129 | 130 => return 0 as i32,
        131 => {
            if type2 as u32
                <= XML_REGEXP_OTHER_NA as i32 as u32
            {
                return 1 as i32;
            }
            return 0 as i32;
        }
        132 | 133 | 134 | 135 => return 0 as i32,
        16 | _ => {}
    }
    return 1 as i32;
}
unsafe extern "C" fn xmlFAEqualAtoms(
    mut atom1: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut atom2: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut deep: i32,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    if atom1 == atom2 {
        return 1 as i32;
    }
    if atom1.is_null() || atom2.is_null() {
        return 0 as i32;
    }
    if (*atom1).type_0 as u32 != (*atom2).type_0 as u32 {
        return 0 as i32;
    }
    match (*atom1).type_0 as u32 {
        1 => {
            ret = 0 as i32;
        }
        5 => {
            if deep == 0 {
                ret = ((*atom1).valuep == (*atom2).valuep) as i32;
            } else {
                ret = xmlStrEqual(
                    (*atom1).valuep as *mut xmlChar,
                    (*atom2).valuep as *mut xmlChar,
                );
            }
        }
        2 => {
            ret = ((*atom1).codepoint == (*atom2).codepoint) as i32;
        }
        3 => {
            ret = 0 as i32;
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn xmlFACompareAtoms(
    mut atom1: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut atom2: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut deep: i32,
) -> i32 {
    let mut current_block: u64;
    let mut ret: i32 = 1 as i32;
    if atom1 == atom2 {
        return 1 as i32;
    }
    if atom1.is_null() || atom2.is_null() {
        return 0 as i32;
    }
    if (*atom1).type_0 as u32
        == XML_REGEXP_ANYCHAR as i32 as u32
        || (*atom2).type_0 as u32
            == XML_REGEXP_ANYCHAR as i32 as u32
    {
        return 1 as i32;
    }
    if (*atom1).type_0 as u32 > (*atom2).type_0 as u32 {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
        tmp = atom1;
        atom1 = atom2;
        atom2 = tmp;
    }
    if (*atom1).type_0 as u32 != (*atom2).type_0 as u32 {
        ret = xmlFACompareAtomTypes((*atom1).type_0, (*atom2).type_0);
        if ret == 0 as i32 {
            return 0 as i32;
        }
    }
    match (*atom1).type_0 as u32 {
        5 => {
            if deep == 0 {
                ret = ((*atom1).valuep != (*atom2).valuep) as i32;
            } else {
                let mut val1: * mut u8 = (*atom1).valuep as *mut xmlChar;
                let mut val2: * mut u8 = (*atom2).valuep as *mut xmlChar;
                let mut compound1: i32 = (xmlStrchr(val1, '|' as i32 as xmlChar)
                    != 0 as *mut libc::c_void as *const xmlChar) as i32;
                let mut compound2: i32 = (xmlStrchr(val2, '|' as i32 as xmlChar)
                    != 0 as *mut libc::c_void as *const xmlChar) as i32;
                if compound1 != compound2 {
                    return 0 as i32;
                }
                ret = xmlRegStrEqualWildcard(val1, val2);
            }
            current_block = 3686881736565329710;
        }
        2 => {
            if (*atom2).type_0 as u32
                == XML_REGEXP_CHARVAL as i32 as u32
            {
                ret = ((*atom1).codepoint == (*atom2).codepoint) as i32;
            } else {
                ret = xmlRegCheckCharacter(atom2, (*atom1).codepoint);
                if ret < 0 as i32 {
                    ret = 1 as i32;
                }
            }
            current_block = 3686881736565329710;
        }
        3 => {
            if (*atom2).type_0 as u32
                == XML_REGEXP_RANGES as i32 as u32
            {
                let mut i: i32 = 0;
                let mut j: i32 = 0;
                let mut res: i32 = 0;
                let mut r1: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
                let mut r2: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
                i = 0 as i32;
                's_172: loop {
                    if !(i < (*atom1).nbRanges) {
                        current_block = 3938820862080741272;
                        break;
                    }
                    j = 0 as i32;
                    while j < (*atom2).nbRanges {
                        r1 = *((*atom1).ranges).offset(i as isize);
                        r2 = *((*atom2).ranges).offset(j as isize);
                        res = xmlFACompareRanges(r1, r2);
                        if res == 1 as i32 {
                            ret = 1 as i32;
                            current_block = 3686881736565329710;
                            break 's_172;
                        } else {
                            j += 1;
                        }
                    }
                    i += 1;
                }
                match current_block {
                    3686881736565329710 => {}
                    _ => {
                        ret = 0 as i32;
                        current_block = 3686881736565329710;
                    }
                }
            } else {
                current_block = 3686881736565329710;
            }
        }
        1 | _ => {
            current_block = 10156241871818535325;
        }
    }
    match current_block {
        3686881736565329710 => {
            if (*atom1).neg != (*atom2).neg {
                ret = (ret == 0) as i32;
            }
            if ret == 0 as i32 {
                return 0 as i32;
            }
        }
        _ => {}
    }
    return 1 as i32;
}
unsafe extern "C" fn xmlFARecurseDeterminism(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut state: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: i32,
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
) -> i32 {
    let mut ret: i32 = 1 as i32;
    let mut res: i32 = 0;
    let mut transnr: i32 = 0;
    let mut nbTrans: i32 = 0;
    let mut t1: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegTrans>::None;
    let mut deep: i32 = 1 as i32;
    if state.is_null() {
        return ret;
    }
    if (*state).markd as u32
        == XML_REGEXP_MARK_VISITED as i32 as u32
    {
        return ret;
    }
    if (*ctxt).flags & 1 as i32 != 0 {
        deep = 0 as i32;
    }
    nbTrans = (*state).nbTrans;
    transnr = 0 as i32;
    while transnr < nbTrans {
        t1 = Some(&mut *((*state).trans).offset(transnr as isize));
        if ((*(borrow(& t1)).unwrap()).atom).is_null() {
            if !((*(borrow(& t1)).unwrap()).to < 0 as i32) {
                (*state).markd = XML_REGEXP_MARK_VISITED;
                res = xmlFARecurseDeterminism(
                    ctxt,
                    *((*ctxt).states).offset((*(borrow(& t1)).unwrap()).to as isize),
                    to,
                    atom,
                );
                if res == 0 as i32 {
                    ret = 0 as i32;
                }
            }
        } else if !((*(borrow(& t1)).unwrap()).to != to) {
            if xmlFACompareAtoms((*(borrow_mut(&mut t1)).unwrap()).atom, atom, deep) != 0 {
                ret = 0 as i32;
                (*(borrow_mut(&mut t1)).unwrap()).nd = 1 as i32;
            }
        }
        transnr += 1;
    }
    return ret;
}
unsafe extern "C" fn xmlFAFinishRecurseDeterminism(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut state: * mut crate::src::xmlregexp::_xmlAutomataState,
) {
    let mut transnr: i32 = 0;
    let mut nbTrans: i32 = 0;
    if state.is_null() {
        return;
    }
    if (*state).markd as u32
        != XML_REGEXP_MARK_VISITED as i32 as u32
    {
        return;
    }
    (*state).markd = XML_REGEXP_MARK_NORMAL;
    nbTrans = (*state).nbTrans;
    transnr = 0 as i32;
    while transnr < nbTrans {
        let mut t1: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Some(&mut *((*state).trans).offset(transnr as isize));
        if ((*(borrow(& t1)).unwrap()).atom).is_null() && (*(borrow(& t1)).unwrap()).to >= 0 as i32 {
            xmlFAFinishRecurseDeterminism(
                ctxt,
                *((*ctxt).states).offset((*(borrow(& t1)).unwrap()).to as isize),
            );
        }
        transnr += 1;
    }
}
unsafe extern "C" fn xmlFAComputesDeterminism(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
) -> i32 {
    let mut statenr: i32 = 0;
    let mut transnr: i32 = 0;
    let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut t1: * mut crate::src::xmlregexp::_xmlRegTrans = (0 as * mut crate::src::xmlregexp::_xmlRegTrans);
    let mut t2: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegTrans>::None;
    let mut last: * mut crate::src::xmlregexp::_xmlRegTrans = (0 as * mut crate::src::xmlregexp::_xmlRegTrans);
    let mut i: i32 = 0;
    let mut ret: i32 = 1 as i32;
    let mut deep: i32 = 1 as i32;
    if (*ctxt).determinist != -(1 as i32) {
        return (*ctxt).determinist;
    }
    if (*ctxt).flags & 1 as i32 != 0 {
        deep = 0 as i32;
    }
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null() {
            if !((*state).nbTrans < 2 as i32) {
                transnr = 0 as i32;
                while transnr < (*state).nbTrans {
                    t1 = &mut *((*state).trans).offset(transnr as isize)
                        as *mut xmlRegTrans;
                    if !((*t1).atom).is_null() {
                        if !((*t1).to == -(1 as i32)) {
                            i = 0 as i32;
                            while i < transnr {
                                t2 = Some(&mut *((*state).trans).offset(i as isize));
                                if !((*(borrow(& t2)).unwrap()).to == -(1 as i32)) {
                                    if !((*(borrow(& t2)).unwrap()).atom).is_null() {
                                        if (*t1).to == (*(borrow(& t2)).unwrap()).to {
                                            if xmlFAEqualAtoms((*t1).atom, (*(borrow_mut(&mut t2)).unwrap()).atom, deep) != 0
                                                && (*t1).counter == (*(borrow(& t2)).unwrap()).counter
                                                && (*t1).count == (*(borrow(& t2)).unwrap()).count
                                            {
                                                (*(borrow_mut(&mut t2)).unwrap()).to = -(1 as i32);
                                            }
                                        }
                                    }
                                }
                                i += 1;
                            }
                        }
                    }
                    transnr += 1;
                }
            }
        }
        statenr += 1;
    }
    statenr = 0 as i32;
    while statenr < (*ctxt).nbStates {
        state = *((*ctxt).states).offset(statenr as isize);
        if !state.is_null() {
            if !((*state).nbTrans < 2 as i32) {
                last = (0 as * mut crate::src::xmlregexp::_xmlRegTrans);
                transnr = 0 as i32;
                while transnr < (*state).nbTrans {
                    t1 = &mut *((*state).trans).offset(transnr as isize)
                        as *mut xmlRegTrans;
                    if !((*t1).atom).is_null() {
                        if !((*t1).to == -(1 as i32)) {
                            i = 0 as i32;
                            while i < transnr {
                                t2 = Some(&mut *((*state).trans).offset(i as isize));
                                if !((*(borrow(& t2)).unwrap()).to == -(1 as i32)) {
                                    if !((*(borrow(& t2)).unwrap()).atom).is_null() {
                                        if xmlFACompareAtoms(
                                            (*t1).atom,
                                            (*(borrow_mut(&mut t2)).unwrap()).atom,
                                            1 as i32,
                                        ) != 0
                                        {
                                            ret = 0 as i32;
                                            (*t1).nd = 1 as i32;
                                            (*(borrow_mut(&mut t2)).unwrap()).nd = 1 as i32;
                                            last = t1;
                                        }
                                    } else if (*t1).to != -(1 as i32) {
                                        ret = xmlFARecurseDeterminism(
                                            ctxt,
                                            *((*ctxt).states).offset((*t1).to as isize),
                                            (*(borrow_mut(&mut t2)).unwrap()).to,
                                            (*(borrow_mut(&mut t2)).unwrap()).atom,
                                        );
                                        xmlFAFinishRecurseDeterminism(
                                            ctxt,
                                            *((*ctxt).states).offset((*t1).to as isize),
                                        );
                                        if ret == 0 as i32 {
                                            (*t1).nd = 1 as i32;
                                            last = t1;
                                        }
                                    }
                                }
                                i += 1;
                            }
                        }
                    }
                    transnr += 1;
                }
                if !last.is_null() {
                    (*last).nd = 2 as i32;
                }
            }
        }
        statenr += 1;
    }
    (*ctxt).determinist = ret;
    return ret;
}
unsafe extern "C" fn xmlRegCheckCharacterRange(
    mut type_0: u32,
    mut codepoint: i32,
    mut neg: i32,
    mut start: i32,
    mut end: i32,
    mut blockName: * const u8,
) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut current_block_53: u64;
    match type_0 as u32 {
        5 | 4 | 3 | 1 => return -(1 as i32),
        6 => {
            ret = (codepoint != '\n' as i32 && codepoint != '\r' as i32) as i32;
            current_block_53 = 3879520548144599102;
        }
        2 => {
            ret = (codepoint >= start && codepoint <= end) as i32;
            current_block_53 = 3879520548144599102;
        }
        8 => {
            neg = (neg == 0) as i32;
            current_block_53 = 1336241090893225463;
        }
        7 => {
            current_block_53 = 1336241090893225463;
        }
        10 => {
            neg = (neg == 0) as i32;
            current_block_53 = 465810355216019241;
        }
        9 => {
            current_block_53 = 465810355216019241;
        }
        12 => {
            neg = (neg == 0) as i32;
            current_block_53 = 10310224489676203593;
        }
        11 => {
            current_block_53 = 10310224489676203593;
        }
        14 => {
            neg = (neg == 0) as i32;
            current_block_53 = 7867894563361037860;
        }
        13 => {
            current_block_53 = 7867894563361037860;
        }
        15 => {
            neg = (neg == 0) as i32;
            current_block_53 = 4570984857387965468;
        }
        16 => {
            current_block_53 = 4570984857387965468;
        }
        100 => {
            ret = xmlUCSIsCatL(codepoint);
            current_block_53 = 3879520548144599102;
        }
        101 => {
            ret = xmlUCSIsCatLu(codepoint);
            current_block_53 = 3879520548144599102;
        }
        102 => {
            ret = xmlUCSIsCatLl(codepoint);
            current_block_53 = 3879520548144599102;
        }
        103 => {
            ret = xmlUCSIsCatLt(codepoint);
            current_block_53 = 3879520548144599102;
        }
        104 => {
            ret = xmlUCSIsCatLm(codepoint);
            current_block_53 = 3879520548144599102;
        }
        105 => {
            ret = xmlUCSIsCatLo(codepoint);
            current_block_53 = 3879520548144599102;
        }
        106 => {
            ret = xmlUCSIsCatM(codepoint);
            current_block_53 = 3879520548144599102;
        }
        107 => {
            ret = xmlUCSIsCatMn(codepoint);
            current_block_53 = 3879520548144599102;
        }
        108 => {
            ret = xmlUCSIsCatMc(codepoint);
            current_block_53 = 3879520548144599102;
        }
        109 => {
            ret = xmlUCSIsCatMe(codepoint);
            current_block_53 = 3879520548144599102;
        }
        110 => {
            ret = xmlUCSIsCatN(codepoint);
            current_block_53 = 3879520548144599102;
        }
        111 => {
            ret = xmlUCSIsCatNd(codepoint);
            current_block_53 = 3879520548144599102;
        }
        112 => {
            ret = xmlUCSIsCatNl(codepoint);
            current_block_53 = 3879520548144599102;
        }
        113 => {
            ret = xmlUCSIsCatNo(codepoint);
            current_block_53 = 3879520548144599102;
        }
        114 => {
            ret = xmlUCSIsCatP(codepoint);
            current_block_53 = 3879520548144599102;
        }
        115 => {
            ret = xmlUCSIsCatPc(codepoint);
            current_block_53 = 3879520548144599102;
        }
        116 => {
            ret = xmlUCSIsCatPd(codepoint);
            current_block_53 = 3879520548144599102;
        }
        117 => {
            ret = xmlUCSIsCatPs(codepoint);
            current_block_53 = 3879520548144599102;
        }
        118 => {
            ret = xmlUCSIsCatPe(codepoint);
            current_block_53 = 3879520548144599102;
        }
        119 => {
            ret = xmlUCSIsCatPi(codepoint);
            current_block_53 = 3879520548144599102;
        }
        120 => {
            ret = xmlUCSIsCatPf(codepoint);
            current_block_53 = 3879520548144599102;
        }
        121 => {
            ret = xmlUCSIsCatPo(codepoint);
            current_block_53 = 3879520548144599102;
        }
        122 => {
            ret = xmlUCSIsCatZ(codepoint);
            current_block_53 = 3879520548144599102;
        }
        123 => {
            ret = xmlUCSIsCatZs(codepoint);
            current_block_53 = 3879520548144599102;
        }
        124 => {
            ret = xmlUCSIsCatZl(codepoint);
            current_block_53 = 3879520548144599102;
        }
        125 => {
            ret = xmlUCSIsCatZp(codepoint);
            current_block_53 = 3879520548144599102;
        }
        126 => {
            ret = xmlUCSIsCatS(codepoint);
            current_block_53 = 3879520548144599102;
        }
        127 => {
            ret = xmlUCSIsCatSm(codepoint);
            current_block_53 = 3879520548144599102;
        }
        128 => {
            ret = xmlUCSIsCatSc(codepoint);
            current_block_53 = 3879520548144599102;
        }
        129 => {
            ret = xmlUCSIsCatSk(codepoint);
            current_block_53 = 3879520548144599102;
        }
        130 => {
            ret = xmlUCSIsCatSo(codepoint);
            current_block_53 = 3879520548144599102;
        }
        131 => {
            ret = xmlUCSIsCatC(codepoint);
            current_block_53 = 3879520548144599102;
        }
        132 => {
            ret = xmlUCSIsCatCc(codepoint);
            current_block_53 = 3879520548144599102;
        }
        133 => {
            ret = xmlUCSIsCatCf(codepoint);
            current_block_53 = 3879520548144599102;
        }
        134 => {
            ret = xmlUCSIsCatCo(codepoint);
            current_block_53 = 3879520548144599102;
        }
        135 => {
            ret = 0 as i32;
            current_block_53 = 3879520548144599102;
        }
        136 => {
            ret = xmlUCSIsBlock(codepoint, blockName as *const i8);
            current_block_53 = 3879520548144599102;
        }
        _ => {
            current_block_53 = 3879520548144599102;
        }
    }
    match current_block_53 {
        4570984857387965468 => {
            ret = xmlUCSIsCatP(codepoint);
            if ret == 0 as i32 {
                ret = xmlUCSIsCatZ(codepoint);
            }
            if ret == 0 as i32 {
                ret = xmlUCSIsCatC(codepoint);
            }
        }
        1336241090893225463 => {
            ret = (codepoint == '\n' as i32 || codepoint == '\r' as i32
                || codepoint == '\t' as i32 || codepoint == ' ' as i32) as i32;
        }
        465810355216019241 => {
            ret = ((if codepoint < 0x100 as i32 {
                (0x41 as i32 <= codepoint && codepoint <= 0x5a as i32
                    || 0x61 as i32 <= codepoint
                        && codepoint <= 0x7a as i32
                    || 0xc0 as i32 <= codepoint
                        && codepoint <= 0xd6 as i32
                    || 0xd8 as i32 <= codepoint
                        && codepoint <= 0xf6 as i32
                    || 0xf8 as i32 <= codepoint) as i32
            } else {
                xmlCharInRange(codepoint as u32, &xmlIsBaseCharGroup)
            }) != 0
                || (if codepoint < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= codepoint
                        && codepoint <= 0x9fa5 as i32
                        || codepoint == 0x3007 as i32
                        || 0x3021 as i32 <= codepoint
                            && codepoint <= 0x3029 as i32) as i32
                }) != 0 || codepoint == '_' as i32 || codepoint == ':' as i32)
                as i32;
        }
        10310224489676203593 => {
            ret = ((if codepoint < 0x100 as i32 {
                (0x41 as i32 <= codepoint && codepoint <= 0x5a as i32
                    || 0x61 as i32 <= codepoint
                        && codepoint <= 0x7a as i32
                    || 0xc0 as i32 <= codepoint
                        && codepoint <= 0xd6 as i32
                    || 0xd8 as i32 <= codepoint
                        && codepoint <= 0xf6 as i32
                    || 0xf8 as i32 <= codepoint) as i32
            } else {
                xmlCharInRange(codepoint as u32, &xmlIsBaseCharGroup)
            }) != 0
                || (if codepoint < 0x100 as i32 {
                    0 as i32
                } else {
                    (0x4e00 as i32 <= codepoint
                        && codepoint <= 0x9fa5 as i32
                        || codepoint == 0x3007 as i32
                        || 0x3021 as i32 <= codepoint
                            && codepoint <= 0x3029 as i32) as i32
                }) != 0
                || (if codepoint < 0x100 as i32 {
                    (0x30 as i32 <= codepoint
                        && codepoint <= 0x39 as i32) as i32
                } else {
                    xmlCharInRange(codepoint as u32, &xmlIsDigitGroup)
                }) != 0 || codepoint == '.' as i32 || codepoint == '-' as i32
                || codepoint == '_' as i32 || codepoint == ':' as i32
                || (if codepoint < 0x100 as i32 {
                    0 as i32
                } else {
                    xmlCharInRange(codepoint as u32, &xmlIsCombiningGroup)
                }) != 0
                || (if codepoint < 0x100 as i32 {
                    (codepoint == 0xb7 as i32) as i32
                } else {
                    xmlCharInRange(codepoint as u32, &xmlIsExtenderGroup)
                }) != 0) as i32;
        }
        7867894563361037860 => {
            ret = xmlUCSIsCatNd(codepoint);
        }
        _ => {}
    }
    if neg != 0 {
        return (ret == 0) as i32;
    }
    return ret;
}
unsafe extern "C" fn xmlRegCheckCharacter(
    mut atom: * mut crate::src::xmlregexp::_xmlRegAtom,
    mut codepoint: i32,
) -> i32 {
    let mut i: i32 = 0;
    let mut ret: i32 = 0 as i32;
    let mut range: * mut crate::src::xmlregexp::_xmlRegRange = 0 as *mut xmlRegRange;
    if atom.is_null()
        || (if codepoint < 0x100 as i32 {
            (0x9 as i32 <= codepoint && codepoint <= 0xa as i32
                || codepoint == 0xd as i32 || 0x20 as i32 <= codepoint)
                as i32
        } else {
            (0x100 as i32 <= codepoint && codepoint <= 0xd7ff as i32
                || 0xe000 as i32 <= codepoint
                    && codepoint <= 0xfffd as i32
                || 0x10000 as i32 <= codepoint
                    && codepoint <= 0x10ffff as i32) as i32
        }) == 0
    {
        return -(1 as i32);
    }
    match (*atom).type_0 as u32 {
        4 | 1 => return -(1 as i32),
        2 => return (codepoint == (*atom).codepoint) as i32,
        3 => {
            let mut accept: i32 = 0 as i32;
            i = 0 as i32;
            while i < (*atom).nbRanges {
                range = *((*atom).ranges).offset(i as isize);
                if (*range).neg == 2 as i32 {
                    ret = xmlRegCheckCharacterRange(
                        (*range).type_0,
                        codepoint,
                        0 as i32,
                        (*range).start,
                        (*range).end,
                        (*range).blockName,
                    );
                    if ret != 0 as i32 {
                        return 0 as i32;
                    }
                } else if (*range).neg != 0 {
                    ret = xmlRegCheckCharacterRange(
                        (*range).type_0,
                        codepoint,
                        0 as i32,
                        (*range).start,
                        (*range).end,
                        (*range).blockName,
                    );
                    if ret == 0 as i32 {
                        accept = 1 as i32;
                    } else {
                        return 0 as i32
                    }
                } else {
                    ret = xmlRegCheckCharacterRange(
                        (*range).type_0,
                        codepoint,
                        0 as i32,
                        (*range).start,
                        (*range).end,
                        (*range).blockName,
                    );
                    if ret != 0 as i32 {
                        accept = 1 as i32;
                    }
                }
                i += 1;
            }
            return accept;
        }
        5 => {
            printf(b"TODO: XML_REGEXP_STRING\n\0" as *const u8 as *const i8);
            return -(1 as i32);
        }
        6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 100 | 101 | 102 | 103 | 104
        | 105 | 106 | 107 | 108 | 109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117
        | 118 | 119 | 120 | 121 | 122 | 123 | 124 | 125 | 126 | 127 | 128 | 129 | 130
        | 131 | 132 | 133 | 134 | 135 | 136 => {
            ret = xmlRegCheckCharacterRange(
                (*atom).type_0,
                codepoint,
                0 as i32,
                0 as i32,
                0 as i32,
                (*atom).valuep as *const xmlChar,
            );
            if (*atom).neg != 0 {
                ret = (ret == 0) as i32;
            }
        }
        _ => {}
    }
    return ret;
}
unsafe extern "C" fn xmlFARegExecSave(mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt) {
    if (*exec).nbPush > 10000000 as i32 {
        return;
    }
    let fresh56 = &mut ((*exec).nbPush);
    *fresh56 += 1;
    if (*exec).maxRollbacks == 0 as i32 {
        (*exec).maxRollbacks = 4 as i32;
        let fresh57 = &mut ((*exec).rollbacks);
        *fresh57 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*exec).maxRollbacks as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlRegExecRollback>() as u64,
                ),
        ) as *mut xmlRegExecRollback;
        if ((*exec).rollbacks).is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"saving regexp\0" as *const u8 as *const i8,
            );
            (*exec).maxRollbacks = 0 as i32;
            return;
        }
        memset(
            (*exec).rollbacks as *mut libc::c_void,
            0 as i32,
            ((*exec).maxRollbacks as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlRegExecRollback>() as u64,
                ),
        );
    } else if (*exec).nbRollbacks >= (*exec).maxRollbacks {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegExecRollback = 0 as *mut xmlRegExecRollback;
        let mut len: i32 = (*exec).maxRollbacks;
        (*exec).maxRollbacks *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*exec).rollbacks as *mut libc::c_void,
            ((*exec).maxRollbacks as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlRegExecRollback>() as u64,
                ),
        ) as *mut xmlRegExecRollback;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"saving regexp\0" as *const u8 as *const i8,
            );
            (*exec).maxRollbacks /= 2 as i32;
            return;
        }
        let fresh58 = &mut ((*exec).rollbacks);
        *fresh58 = tmp;
        tmp = &mut *((*exec).rollbacks).offset(len as isize) as *mut xmlRegExecRollback;
        memset(
            tmp as *mut libc::c_void,
            0 as i32,
            (((*exec).maxRollbacks - len) as u64)
                .wrapping_mul(
                    ::std::mem::size_of::<xmlRegExecRollback>() as u64,
                ),
        );
    }
    let fresh59 = &mut ((*((*exec).rollbacks).offset((*exec).nbRollbacks as isize))
        .state);
    *fresh59 = (*exec).state;
    (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).index = (*exec).index;
    (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize))
        .nextbranch = (*exec).transno + 1 as i32;
    if (*(*exec).comp).nbCounters > 0 as i32 {
        if ((*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).counts).is_null()
        {
            let fresh60 = &mut ((*((*exec).rollbacks)
                .offset((*exec).nbRollbacks as isize))
                .counts);
            *fresh60 = xmlMalloc
                .expect(
                    "non-null function pointer",
                )(
                ((*(*exec).comp).nbCounters as u64)
                    .wrapping_mul(::std::mem::size_of::<i32>() as u64),
            ) as *mut i32;
            if ((*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).counts)
                .is_null()
            {
                xmlRegexpErrMemory(
                    0 as xmlRegParserCtxtPtr,
                    b"saving regexp\0" as *const u8 as *const i8,
                );
                (*exec).status = -(5 as i32);
                return;
            }
        }
        memcpy(
            (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).counts
                as *mut libc::c_void,
            (*exec).counts as *const libc::c_void,
            ((*(*exec).comp).nbCounters as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        );
    }
    let fresh61 = &mut ((*exec).nbRollbacks);
    *fresh61 += 1;
}
unsafe extern "C" fn xmlFARegExecRollBack(mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt) {
    if (*exec).nbRollbacks <= 0 as i32 {
        (*exec).status = -(1 as i32);
        return;
    }
    let fresh62 = &mut ((*exec).nbRollbacks);
    *fresh62 -= 1;
    let fresh63 = &mut ((*exec).state);
    *fresh63 = (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).state;
    (*exec).index = (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).index;
    (*exec)
        .transno = (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize))
        .nextbranch;
    if (*(*exec).comp).nbCounters > 0 as i32 {
        if ((*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).counts).is_null()
        {
            fprintf(
                stderr,
                b"exec save: allocation failed\0" as *const u8 as *const i8,
            );
            (*exec).status = -(6 as i32);
            return;
        }
        if !((*exec).counts).is_null() {
            memcpy(
                (*exec).counts as *mut libc::c_void,
                (*((*exec).rollbacks).offset((*exec).nbRollbacks as isize)).counts
                    as *const libc::c_void,
                ((*(*exec).comp).nbCounters as u64)
                    .wrapping_mul(::std::mem::size_of::<i32>() as u64),
            );
        }
    }
}
unsafe extern "C" fn xmlFARegExec(
    mut comp: * mut crate::src::xmlregexp::_xmlRegexp,
    mut content: * const u8,
) -> i32 {
    let mut current_block: u64;
    let mut execval: crate::src::xmlregexp::_xmlRegExecCtxt = xmlRegExecCtxt {
        status: 0,
        determinist: 0,
        comp: 0 as *mut xmlRegexp,
        callback: None,
        data: 0 as *mut libc::c_void,
        state: 0 as *mut xmlRegState,
        transno: 0,
        transcount: 0,
        maxRollbacks: 0,
        nbRollbacks: 0,
        rollbacks: 0 as *mut xmlRegExecRollback,
        counts: 0 as *mut i32,
        inputStackMax: 0,
        inputStackNr: 0,
        index: 0,
        charStack: 0 as *mut i32,
        inputString: 0 as *const xmlChar,
        inputStack: 0 as *mut xmlRegInputToken,
        errStateNo: 0,
        errState: 0 as *mut xmlRegState,
        errString: 0 as *mut xmlChar,
        errCounts: 0 as *mut i32,
        nbPush: 0,
    };
    let mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt = &mut execval;
    let mut ret: i32 = 0;
    let mut codepoint: i32 = 0 as i32;
    let mut len: i32 = 0;
    let mut deter: i32 = 0;
    let fresh64 = &mut ((*exec).inputString);
    *fresh64 = content;
    (*exec).index = 0 as i32;
    (*exec).nbPush = 0 as i32;
    (*exec).determinist = 1 as i32;
    (*exec).maxRollbacks = 0 as i32;
    (*exec).nbRollbacks = 0 as i32;
    let fresh65 = &mut ((*exec).rollbacks);
    *fresh65 = 0 as *mut xmlRegExecRollback;
    (*exec).status = 0 as i32;
    let fresh66 = &mut ((*exec).comp);
    *fresh66 = comp;
    let fresh67 = &mut ((*exec).state);
    *fresh67 = *((*comp).states).offset(0 as i32 as isize);
    (*exec).transno = 0 as i32;
    (*exec).transcount = 0 as i32;
    let fresh68 = &mut ((*exec).inputStack);
    *fresh68 = 0 as xmlRegInputTokenPtr;
    (*exec).inputStackMax = 0 as i32;
    if (*comp).nbCounters > 0 as i32 {
        let fresh69 = &mut ((*exec).counts);
        *fresh69 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*comp).nbCounters as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        ) as *mut i32;
        if ((*exec).counts).is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"running regexp\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        memset(
            (*exec).counts as *mut libc::c_void,
            0 as i32,
            ((*comp).nbCounters as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64),
        );
    } else {
        let fresh70 = &mut ((*exec).counts);
        *fresh70 = 0 as *mut i32;
    }
    's_105: while (*exec).status == 0 as i32 && !((*exec).state).is_null()
        && (*((*exec).inputString).offset((*exec).index as isize) as i32
            != 0 as i32
            || !((*exec).state).is_null()
                && (*(*exec).state).type_0 as u32
                    != XML_REGEXP_FINAL_STATE as i32 as u32)
    {
        let mut trans: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegTrans>::None;
        let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
        len = 1 as i32;
        if *((*exec).inputString).offset((*exec).index as isize) as i32
            == 0 as i32 && ((*exec).counts).is_null()
        {
            if (*exec).transno < (*(*exec).state).nbTrans {
                trans = Some(&mut *((*(*exec).state).trans).offset((*exec).transno as isize));
                if (*(borrow(& trans)).unwrap()).to >= 0 as i32 {
                    atom = (*(borrow_mut(&mut trans)).unwrap()).atom;
                    if !((*atom).min == 0 as i32
                        && (*atom).max > 0 as i32)
                    {
                        current_block = 17840493588698777309;
                    } else {
                        current_block = 17281240262373992796;
                    }
                } else {
                    current_block = 17281240262373992796;
                }
            } else {
                current_block = 17840493588698777309;
            }
        } else {
            current_block = 17281240262373992796;
        }
        match current_block {
            17281240262373992796 => {
                (*exec).transcount = 0 as i32;
                loop {
                    if !((*exec).transno < (*(*exec).state).nbTrans) {
                        current_block = 2872334340672008580;
                        break;
                    }
                    trans = Some(&mut *((*(*exec).state).trans)
                        .offset((*exec).transno as isize));
                    if !((*(borrow(& trans)).unwrap()).to < 0 as i32) {
                        atom = (*(borrow_mut(&mut trans)).unwrap()).atom;
                        ret = 0 as i32;
                        deter = 1 as i32;
                        if (*(borrow(& trans)).unwrap()).count >= 0 as i32 {
                            let mut count: i32 = 0;
                            let mut counter: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                            if ((*exec).counts).is_null() {
                                (*exec).status = -(1 as i32);
                                break 's_105;
                            } else {
                                count = *((*exec).counts).offset((*(borrow(& trans)).unwrap()).count as isize);
                                counter = Some(&mut *((*(*exec).comp).counters)
                                    .offset((*(borrow(& trans)).unwrap()).count as isize));
                                ret = (count >= (*(borrow(& counter)).unwrap()).min && count <= (*(borrow(& counter)).unwrap()).max)
                                    as i32;
                                if ret != 0 && (*(borrow(& counter)).unwrap()).min != (*(borrow(& counter)).unwrap()).max {
                                    deter = 0 as i32;
                                }
                            }
                            current_block = 14155412868135599428;
                        } else if atom.is_null() {
                            fprintf(
                                stderr,
                                b"epsilon transition left at runtime\n\0" as *const u8
                                    as *const i8,
                            );
                            (*exec).status = -(2 as i32);
                            current_block = 2872334340672008580;
                            break;
                        } else if *((*exec).inputString).offset((*exec).index as isize)
                                as i32 != 0 as i32
                            {
                            codepoint = xmlStringCurrentChar(
                                0 as xmlParserCtxtPtr,
                                &*((*exec).inputString).offset((*exec).index as isize),
                                &mut len,
                            );
                            ret = xmlRegCheckCharacter(atom, codepoint);
                            if ret == 1 as i32 && (*atom).min >= 0 as i32
                                && (*atom).max > 0 as i32
                            {
                                let mut to: * mut crate::src::xmlregexp::_xmlAutomataState = *((*comp).states)
                                    .offset((*(borrow(& trans)).unwrap()).to as isize);
                                if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
                                    let mut counter_0: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                                    if ((*exec).counts).is_null() || ((*exec).comp).is_null()
                                        || ((*(*exec).comp).counters).is_null()
                                    {
                                        (*exec).status = -(1 as i32);
                                        break 's_105;
                                    } else {
                                        counter_0 = Some(&mut *((*(*exec).comp).counters)
                                            .offset((*(borrow(& trans)).unwrap()).counter as isize));
                                        if *((*exec).counts).offset((*(borrow(& trans)).unwrap()).counter as isize)
                                            >= (*(borrow(& counter_0)).unwrap()).max
                                        {
                                            current_block = 17500079516916021833;
                                        } else {
                                            current_block = 3546145585875536353;
                                        }
                                    }
                                } else {
                                    current_block = 3546145585875536353;
                                }
                                match current_block {
                                    17500079516916021833 => {}
                                    _ => {
                                        if (*(*exec).state).nbTrans
                                            > (*exec).transno + 1 as i32
                                        {
                                            xmlFARegExecSave(exec);
                                        }
                                        if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
                                            let fresh71 = &mut (*((*exec).counts)
                                                .offset((*(borrow(& trans)).unwrap()).counter as isize));
                                            *fresh71 += 1;
                                        }
                                        (*exec).transcount = 1 as i32;
                                        while !((*exec).transcount == (*atom).max) {
                                            (*exec).index += len;
                                            if *((*exec).inputString).offset((*exec).index as isize)
                                                as i32 == 0 as i32
                                            {
                                                (*exec).index -= len;
                                                break;
                                            } else {
                                                if (*exec).transcount >= (*atom).min {
                                                    let mut transno: i32 = (*exec).transno;
                                                    let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = (*exec).state;
                                                    (*exec).transno = -(1 as i32);
                                                    let fresh72 = &mut ((*exec).state);
                                                    *fresh72 = to;
                                                    xmlFARegExecSave(exec);
                                                    (*exec).transno = transno;
                                                    let fresh73 = &mut ((*exec).state);
                                                    *fresh73 = state;
                                                }
                                                codepoint = xmlStringCurrentChar(
                                                    0 as xmlParserCtxtPtr,
                                                    &*((*exec).inputString).offset((*exec).index as isize),
                                                    &mut len,
                                                );
                                                ret = xmlRegCheckCharacter(atom, codepoint);
                                                let fresh74 = &mut ((*exec).transcount);
                                                *fresh74 += 1;
                                                if !(ret == 1 as i32) {
                                                    break;
                                                }
                                            }
                                        }
                                        if (*exec).transcount < (*atom).min {
                                            ret = 0 as i32;
                                        }
                                        if ret < 0 as i32 {
                                            ret = 0 as i32;
                                        }
                                        if ret == 0 as i32 {
                                            current_block = 17840493588698777309;
                                            break;
                                        }
                                        if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
                                            if ((*exec).counts).is_null() {
                                                (*exec).status = -(1 as i32);
                                                break 's_105;
                                            } else {
                                                let fresh75 = &mut (*((*exec).counts)
                                                    .offset((*(borrow(& trans)).unwrap()).counter as isize));
                                                *fresh75 -= 1;
                                            }
                                            current_block = 14155412868135599428;
                                        } else {
                                            current_block = 14155412868135599428;
                                        }
                                    }
                                }
                            } else {
                                if ret == 0 as i32
                                    && (*atom).min == 0 as i32
                                    && (*atom).max > 0 as i32
                                {
                                    (*exec).transcount = 1 as i32;
                                    len = 0 as i32;
                                    ret = 1 as i32;
                                }
                                current_block = 14155412868135599428;
                            }
                        } else {
                            if (*atom).min == 0 as i32
                                && (*atom).max > 0 as i32
                            {
                                (*exec).transcount = 1 as i32;
                                len = 0 as i32;
                                ret = 1 as i32;
                            }
                            current_block = 14155412868135599428;
                        }
                        match current_block {
                            17500079516916021833 => {}
                            _ => {
                                if ret == 1 as i32 {
                                    if (*(borrow(& trans)).unwrap()).nd == 1 as i32
                                        || (*(borrow(& trans)).unwrap()).count >= 0 as i32
                                            && deter == 0 as i32
                                            && (*(*exec).state).nbTrans
                                                > (*exec).transno + 1 as i32
                                    {
                                        xmlFARegExecSave(exec);
                                    }
                                    if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
                                        let mut counter_1: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                                        if ((*exec).counts).is_null() || ((*exec).comp).is_null()
                                            || ((*(*exec).comp).counters).is_null()
                                        {
                                            (*exec).status = -(1 as i32);
                                            break 's_105;
                                        } else {
                                            counter_1 = Some(&mut *((*(*exec).comp).counters)
                                                .offset((*(borrow(& trans)).unwrap()).counter as isize));
                                            if *((*exec).counts).offset((*(borrow(& trans)).unwrap()).counter as isize)
                                                >= (*(borrow(& counter_1)).unwrap()).max
                                            {
                                                current_block = 17500079516916021833;
                                            } else {
                                                let fresh76 = &mut (*((*exec).counts)
                                                    .offset((*(borrow(& trans)).unwrap()).counter as isize));
                                                *fresh76 += 1;
                                                current_block = 11718254377427810743;
                                            }
                                        }
                                    } else {
                                        current_block = 11718254377427810743;
                                    }
                                    match current_block {
                                        17500079516916021833 => {}
                                        _ => {
                                            if (*(borrow(& trans)).unwrap()).count >= 0 as i32
                                                && (*(borrow(& trans)).unwrap()).count < 0x123456 as i32
                                            {
                                                if ((*exec).counts).is_null() {
                                                    (*exec).status = -(1 as i32);
                                                    break 's_105;
                                                } else {
                                                    *((*exec).counts)
                                                        .offset((*(borrow(& trans)).unwrap()).count as isize) = 0 as i32;
                                                }
                                            }
                                            let fresh77 = &mut ((*exec).state);
                                            *fresh77 = *((*comp).states).offset((*(borrow(& trans)).unwrap()).to as isize);
                                            (*exec).transno = 0 as i32;
                                            if !((*(borrow_mut(&mut trans)).unwrap()).atom).is_null() {
                                                (*exec).index += len;
                                            }
                                            continue 's_105;
                                        }
                                    }
                                } else if ret < 0 as i32 {
                                    (*exec).status = -(4 as i32);
                                    current_block = 2872334340672008580;
                                    break;
                                }
                            }
                        }
                    }
                    let fresh78 = &mut ((*exec).transno);
                    *fresh78 += 1;
                }
                match current_block {
                    17840493588698777309 => {}
                    _ => {
                        if !((*exec).transno != 0 as i32
                            || (*(*exec).state).nbTrans == 0 as i32)
                        {
                            continue;
                        }
                    }
                }
            }
            _ => {}
        }
        (*exec).determinist = 0 as i32;
        xmlFARegExecRollBack(exec);
    }
    if !((*exec).rollbacks).is_null() {
        if !((*exec).counts).is_null() {
            let mut i: i32 = 0;
            i = 0 as i32;
            while i < (*exec).maxRollbacks {
                if !((*((*exec).rollbacks).offset(i as isize)).counts).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(
                        (*((*exec).rollbacks).offset(i as isize)).counts
                            as *mut libc::c_void,
                    );
                }
                i += 1;
            }
        }
        xmlFree
            .expect("non-null function pointer")((*exec).rollbacks as *mut libc::c_void);
    }
    if ((*exec).state).is_null() {
        return -(1 as i32);
    }
    if !((*exec).counts).is_null() {
        xmlFree.expect("non-null function pointer")((*exec).counts as *mut libc::c_void);
    }
    if (*exec).status == 0 as i32 {
        return 1 as i32;
    }
    if (*exec).status == -(1 as i32) {
        if (*exec).nbPush > 10000000 as i32 {
            return -(1 as i32);
        }
        return 0 as i32;
    }
    return (*exec).status;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegNewExecCtxt(
    mut comp: * mut crate::src::xmlregexp::_xmlRegexp,
    mut callback: Option<unsafe extern "C"  fn(_: * mut crate::src::xmlregexp::_xmlRegExecCtxt,_: * const u8,_: * mut core::ffi::c_void,_: * mut core::ffi::c_void,) -> ()>,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlRegExecCtxt {
    let mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt = 0 as *mut xmlRegExecCtxt;
    if comp.is_null() {
        return 0 as xmlRegExecCtxtPtr;
    }
    if ((*comp).compact).is_null() && ((*comp).states).is_null() {
        return 0 as xmlRegExecCtxtPtr;
    }
    exec = xmlMalloc
        .expect(
            "non-null function pointer",
        )(::std::mem::size_of::<xmlRegExecCtxt>() as u64) as xmlRegExecCtxtPtr;
    if exec.is_null() {
        xmlRegexpErrMemory(
            0 as xmlRegParserCtxtPtr,
            b"creating execution context\0" as *const u8 as *const i8,
        );
        return 0 as xmlRegExecCtxtPtr;
    }
    memset(
        exec as *mut libc::c_void,
        0 as i32,
        ::std::mem::size_of::<xmlRegExecCtxt>() as u64,
    );
    let fresh79 = &mut ((*exec).inputString);
    *fresh79 = 0 as *const xmlChar;
    (*exec).index = 0 as i32;
    (*exec).determinist = 1 as i32;
    (*exec).maxRollbacks = 0 as i32;
    (*exec).nbRollbacks = 0 as i32;
    let fresh80 = &mut ((*exec).rollbacks);
    *fresh80 = 0 as *mut xmlRegExecRollback;
    (*exec).status = 0 as i32;
    let fresh81 = &mut ((*exec).comp);
    *fresh81 = comp;
    if ((*comp).compact).is_null() {
        let fresh82 = &mut ((*exec).state);
        *fresh82 = *((*comp).states).offset(0 as i32 as isize);
    }
    (*exec).transno = 0 as i32;
    (*exec).transcount = 0 as i32;
    let fresh83 = &mut ((*exec).callback);
    *fresh83 = callback;
    let fresh84 = &mut ((*exec).data);
    *fresh84 = data;
    if (*comp).nbCounters > 0 as i32 {
        let fresh85 = &mut ((*exec).counts);
        *fresh85 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*comp).nbCounters as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64)
                .wrapping_mul(2 as i32 as u64),
        ) as *mut i32;
        if ((*exec).counts).is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"creating execution context\0" as *const u8 as *const i8,
            );
            xmlFree.expect("non-null function pointer")(exec as *mut libc::c_void);
            return 0 as xmlRegExecCtxtPtr;
        }
        memset(
            (*exec).counts as *mut libc::c_void,
            0 as i32,
            ((*comp).nbCounters as u64)
                .wrapping_mul(::std::mem::size_of::<i32>() as u64)
                .wrapping_mul(2 as i32 as u64),
        );
        let fresh86 = &mut ((*exec).errCounts);
        *fresh86 = &mut *((*exec).counts).offset((*comp).nbCounters as isize)
            as *mut i32;
    } else {
        let fresh87 = &mut ((*exec).counts);
        *fresh87 = 0 as *mut i32;
        let fresh88 = &mut ((*exec).errCounts);
        *fresh88 = 0 as *mut i32;
    }
    (*exec).inputStackMax = 0 as i32;
    (*exec).inputStackNr = 0 as i32;
    let fresh89 = &mut ((*exec).inputStack);
    *fresh89 = 0 as xmlRegInputTokenPtr;
    (*exec).errStateNo = -(1 as i32);
    let fresh90 = &mut ((*exec).errString);
    *fresh90 = 0 as *mut xmlChar;
    (*exec).nbPush = 0 as i32;
    return exec;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegFreeExecCtxt(mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt) {
    if exec.is_null() {
        return;
    }
    if !((*exec).rollbacks).is_null() {
        if !((*exec).counts).is_null() {
            let mut i: i32 = 0;
            i = 0 as i32;
            while i < (*exec).maxRollbacks {
                if !((*((*exec).rollbacks).offset(i as isize)).counts).is_null() {
                    xmlFree
                        .expect(
                            "non-null function pointer",
                        )(
                        (*((*exec).rollbacks).offset(i as isize)).counts
                            as *mut libc::c_void,
                    );
                }
                i += 1;
            }
        }
        xmlFree
            .expect("non-null function pointer")((*exec).rollbacks as *mut libc::c_void);
    }
    if !((*exec).counts).is_null() {
        xmlFree.expect("non-null function pointer")((*exec).counts as *mut libc::c_void);
    }
    if !((*exec).inputStack).is_null() {
        let mut i_0: i32 = 0;
        i_0 = 0 as i32;
        while i_0 < (*exec).inputStackNr {
            if !((*((*exec).inputStack).offset(i_0 as isize)).value).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )(
                    (*((*exec).inputStack).offset(i_0 as isize)).value
                        as *mut libc::c_void,
                );
            }
            i_0 += 1;
        }
        xmlFree
            .expect(
                "non-null function pointer",
            )((*exec).inputStack as *mut libc::c_void);
    }
    if !((*exec).errString).is_null() {
        xmlFree
            .expect("non-null function pointer")((*exec).errString as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(exec as *mut libc::c_void);
}
unsafe extern "C" fn xmlFARegExecSaveInputString(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut value: * const u8,
    mut data: * mut core::ffi::c_void,
) {
    if (*exec).inputStackMax == 0 as i32 {
        (*exec).inputStackMax = 4 as i32;
        let fresh91 = &mut ((*exec).inputStack);
        *fresh91 = xmlMalloc
            .expect(
                "non-null function pointer",
            )(
            ((*exec).inputStackMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegInputToken>() as u64),
        ) as xmlRegInputTokenPtr;
        if ((*exec).inputStack).is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"pushing input string\0" as *const u8 as *const i8,
            );
            (*exec).inputStackMax = 0 as i32;
            return;
        }
    } else if (*exec).inputStackNr + 1 as i32 >= (*exec).inputStackMax {
        let mut tmp: * mut crate::src::xmlregexp::_xmlRegInputToken = 0 as *mut xmlRegInputToken;
        (*exec).inputStackMax *= 2 as i32;
        tmp = xmlRealloc
            .expect(
                "non-null function pointer",
            )(
            (*exec).inputStack as *mut libc::c_void,
            ((*exec).inputStackMax as u64)
                .wrapping_mul(::std::mem::size_of::<xmlRegInputToken>() as u64),
        ) as xmlRegInputTokenPtr;
        if tmp.is_null() {
            xmlRegexpErrMemory(
                0 as xmlRegParserCtxtPtr,
                b"pushing input string\0" as *const u8 as *const i8,
            );
            (*exec).inputStackMax /= 2 as i32;
            return;
        }
        let fresh92 = &mut ((*exec).inputStack);
        *fresh92 = tmp;
    }
    let fresh93 = &mut ((*((*exec).inputStack).offset((*exec).inputStackNr as isize))
        .value);
    *fresh93 = xmlStrdup(value);
    let fresh94 = &mut ((*((*exec).inputStack).offset((*exec).inputStackNr as isize))
        .data);
    *fresh94 = data;
    let fresh95 = &mut ((*exec).inputStackNr);
    *fresh95 += 1;
    let fresh96 = &mut ((*((*exec).inputStack).offset((*exec).inputStackNr as isize))
        .value);
    *fresh96 = 0 as *mut xmlChar;
    let fresh97 = &mut ((*((*exec).inputStack).offset((*exec).inputStackNr as isize))
        .data);
    *fresh97 = 0 as *mut libc::c_void;
}
unsafe extern "C" fn xmlRegStrEqualWildcard(
    mut expStr: * const u8,
    mut valStr: * const u8,
) -> i32 {
    if expStr == valStr {
        return 1 as i32;
    }
    if expStr.is_null() {
        return 0 as i32;
    }
    if valStr.is_null() {
        return 0 as i32;
    }
    loop {
        if *expStr as i32 != *valStr as i32 {
            if *valStr as i32 == '*' as i32 {
                let mut tmp: * const u8 = 0 as *const xmlChar;
                tmp = valStr;
                valStr = expStr;
                expStr = tmp;
            }
            if *valStr as i32 != 0 as i32
                && *expStr as i32 != 0 as i32
                && {
                    let mut fresh98 = expStr;
                    expStr = expStr.offset(1);
                    *fresh98 as i32 == '*' as i32
                }
            {
                while !(*valStr as i32 == '|' as i32) {
                    valStr = valStr.offset(1);
                    if !(*valStr as i32 != 0 as i32) {
                        break;
                    }
                }
            } else {
                return 0 as i32
            }
        } else {
            expStr = expStr.offset(1);
            valStr = valStr.offset(1);
        }
        if !(*valStr as i32 != 0 as i32) {
            break;
        }
    }
    if *expStr as i32 != 0 as i32 {
        return 0 as i32
    } else {
        return 1 as i32
    };
}
unsafe extern "C" fn xmlRegCompactPushString(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut comp: * mut crate::src::xmlregexp::_xmlRegexp,
    mut value: * const u8,
    mut data: * mut core::ffi::c_void,
) -> i32 {
    let mut state: i32 = (*exec).index;
    let mut i: i32 = 0;
    let mut target: i32 = 0;
    if comp.is_null() || ((*comp).compact).is_null() || ((*comp).stringMap).is_null() {
        return -(1 as i32);
    }
    if value.is_null() {
        if *((*comp).compact)
            .offset((state * ((*comp).nbstrings + 1 as i32)) as isize)
            == XML_REGEXP_FINAL_STATE as i32
        {
            return 1 as i32;
        }
        return 0 as i32;
    }
    i = 0 as i32;
    while i < (*comp).nbstrings {
        target = *((*comp).compact)
            .offset(
                (state * ((*comp).nbstrings + 1 as i32) + i + 1 as i32)
                    as isize,
            );
        if target > 0 as i32 && target <= (*comp).nbstates {
            target -= 1;
            if xmlRegStrEqualWildcard(*((*comp).stringMap).offset(i as isize), value)
                != 0
            {
                (*exec).index = target;
                if ((*exec).callback).is_some() && !((*comp).transdata).is_null() {
                    ((*exec).callback)
                        .expect(
                            "non-null function pointer",
                        )(
                        (*exec).data as xmlRegExecCtxtPtr,
                        value,
                        *((*comp).transdata)
                            .offset((state * (*comp).nbstrings + i) as isize),
                        data,
                    );
                }
                if *((*comp).compact)
                    .offset((target * ((*comp).nbstrings + 1 as i32)) as isize)
                    == XML_REGEXP_SINK_STATE as i32
                {
                    break;
                }
                if *((*comp).compact)
                    .offset((target * ((*comp).nbstrings + 1 as i32)) as isize)
                    == XML_REGEXP_FINAL_STATE as i32
                {
                    return 1 as i32;
                }
                return 0 as i32;
            }
        }
        i += 1;
    }
    if !((*exec).errString).is_null() {
        xmlFree
            .expect("non-null function pointer")((*exec).errString as *mut libc::c_void);
    }
    let fresh99 = &mut ((*exec).errString);
    *fresh99 = xmlStrdup(value);
    (*exec).errStateNo = state;
    (*exec).status = -(1 as i32);
    return -(1 as i32);
}
unsafe extern "C" fn xmlRegExecPushStringInternal(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut value: * const u8,
    mut data: * mut core::ffi::c_void,
    mut compound: i32,
) -> i32 {
    let mut current_block: u64;
    let mut trans: * mut crate::src::xmlregexp::_xmlRegTrans = 0 as *mut xmlRegTrans;
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut ret: i32 = 0;
    let mut final_0: i32 = 0 as i32;
    let mut progress: i32 = 1 as i32;
    if exec.is_null() {
        return -(1 as i32);
    }
    if ((*exec).comp).is_null() {
        return -(1 as i32);
    }
    if (*exec).status != 0 as i32 {
        return (*exec).status;
    }
    if !((*(*exec).comp).compact).is_null() {
        return xmlRegCompactPushString(exec, (*exec).comp, value, data);
    }
    if value.is_null() {
        if (*(*exec).state).type_0 as u32
            == XML_REGEXP_FINAL_STATE as i32 as u32
        {
            return 1 as i32;
        }
        final_0 = 1 as i32;
    }
    if !value.is_null() && (*exec).inputStackNr > 0 as i32 {
        xmlFARegExecSaveInputString(exec, value, data);
        value = (*((*exec).inputStack).offset((*exec).index as isize)).value;
        data = (*((*exec).inputStack).offset((*exec).index as isize)).data;
    }
    while (*exec).status == 0 as i32
        && (!value.is_null()
            || final_0 == 1 as i32
                && (*(*exec).state).type_0 as u32
                    != XML_REGEXP_FINAL_STATE as i32 as u32)
    {
        if !(value.is_null() && ((*exec).counts).is_null()) {
            (*exec).transcount = 0 as i32;
            loop {
                if !((*exec).transno < (*(*exec).state).nbTrans) {
                    current_block = 5511877782510663281;
                    break;
                }
                trans = &mut *((*(*exec).state).trans).offset((*exec).transno as isize)
                    as *mut xmlRegTrans;
                if !((*trans).to < 0 as i32) {
                    atom = (*trans).atom;
                    ret = 0 as i32;
                    if (*trans).count == 0x123457 as i32 {
                        let mut i: i32 = 0;
                        let mut count: i32 = 0;
                        let mut t: * mut crate::src::xmlregexp::_xmlRegTrans = 0 as *mut xmlRegTrans;
                        let mut counter: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                        ret = 0 as i32;
                        if value.is_null() && final_0 != 0 {
                            ret = 1 as i32;
                        } else if !value.is_null() {
                            i = 0 as i32;
                            while i < (*(*exec).state).nbTrans {
                                t = &mut *((*(*exec).state).trans).offset(i as isize)
                                    as *mut xmlRegTrans;
                                if !((*t).counter < 0 as i32 || t == trans) {
                                    counter = Some(&mut *((*(*exec).comp).counters)
                                        .offset((*t).counter as isize));
                                    count = *((*exec).counts).offset((*t).counter as isize);
                                    if count < (*(borrow(& counter)).unwrap()).max && !((*t).atom).is_null()
                                        && xmlStrEqual(value, (*(*t).atom).valuep as *const xmlChar)
                                            != 0
                                    {
                                        ret = 0 as i32;
                                        break;
                                    } else if count >= (*(borrow(& counter)).unwrap()).min && count < (*(borrow(& counter)).unwrap()).max
                                            && !((*t).atom).is_null()
                                            && xmlStrEqual(value, (*(*t).atom).valuep as *const xmlChar)
                                                != 0
                                        {
                                        ret = 1 as i32;
                                        break;
                                    }
                                }
                                i += 1;
                            }
                        }
                    } else if (*trans).count == 0x123456 as i32 {
                        let mut i_0: i32 = 0;
                        let mut count_0: i32 = 0;
                        let mut t_0: * mut crate::src::xmlregexp::_xmlRegTrans = 0 as *mut xmlRegTrans;
                        let mut counter_0: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                        ret = 1 as i32;
                        i_0 = 0 as i32;
                        while i_0 < (*(*exec).state).nbTrans {
                            t_0 = &mut *((*(*exec).state).trans).offset(i_0 as isize)
                                as *mut xmlRegTrans;
                            if !((*t_0).counter < 0 as i32 || t_0 == trans) {
                                counter_0 = Some(&mut *((*(*exec).comp).counters)
                                    .offset((*t_0).counter as isize));
                                count_0 = *((*exec).counts).offset((*t_0).counter as isize);
                                if count_0 < (*(borrow(& counter_0)).unwrap()).min || count_0 > (*(borrow(& counter_0)).unwrap()).max
                                {
                                    ret = 0 as i32;
                                    break;
                                }
                            }
                            i_0 += 1;
                        }
                    } else if (*trans).count >= 0 as i32 {
                        let mut count_1: i32 = 0;
                        let mut counter_1: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                        count_1 = *((*exec).counts).offset((*trans).count as isize);
                        counter_1 = Some(&mut *((*(*exec).comp).counters)
                            .offset((*trans).count as isize));
                        ret = (count_1 >= (*(borrow(& counter_1)).unwrap()).min
                            && count_1 <= (*(borrow(& counter_1)).unwrap()).max) as i32;
                    } else if atom.is_null() {
                        fprintf(
                            stderr,
                            b"epsilon transition left at runtime\n\0" as *const u8
                                as *const i8,
                        );
                        (*exec).status = -(2 as i32);
                        current_block = 5511877782510663281;
                        break;
                    } else if !value.is_null() {
                        ret = xmlRegStrEqualWildcard(
                            (*atom).valuep as *const xmlChar,
                            value,
                        );
                        if (*atom).neg != 0 {
                            ret = (ret == 0) as i32;
                            if compound == 0 {
                                ret = 0 as i32;
                            }
                        }
                        if ret == 1 as i32
                            && (*trans).counter >= 0 as i32
                        {
                            let mut counter_2: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                            let mut count_2: i32 = 0;
                            count_2 = *((*exec).counts)
                                .offset((*trans).counter as isize);
                            counter_2 = Some(&mut *((*(*exec).comp).counters)
                                .offset((*trans).counter as isize));
                            if count_2 >= (*(borrow(& counter_2)).unwrap()).max {
                                ret = 0 as i32;
                            }
                        }
                        if ret == 1 as i32 && (*atom).min > 0 as i32
                            && (*atom).max > 0 as i32
                        {
                            let mut to: * mut crate::src::xmlregexp::_xmlAutomataState = *((*(*exec).comp).states)
                                .offset((*trans).to as isize);
                            if (*(*exec).state).nbTrans
                                > (*exec).transno + 1 as i32
                            {
                                if (*exec).inputStackNr <= 0 as i32 {
                                    xmlFARegExecSaveInputString(exec, value, data);
                                }
                                xmlFARegExecSave(exec);
                            }
                            (*exec).transcount = 1 as i32;
                            while !((*exec).transcount == (*atom).max) {
                                let fresh100 = &mut ((*exec).index);
                                *fresh100 += 1;
                                value = (*((*exec).inputStack)
                                    .offset((*exec).index as isize))
                                    .value;
                                data = (*((*exec).inputStack)
                                    .offset((*exec).index as isize))
                                    .data;
                                if value.is_null() {
                                    let fresh101 = &mut ((*exec).index);
                                    *fresh101 -= 1;
                                    break;
                                } else {
                                    if (*exec).transcount >= (*atom).min {
                                        let mut transno: i32 = (*exec).transno;
                                        let mut state: * mut crate::src::xmlregexp::_xmlAutomataState = (*exec).state;
                                        (*exec).transno = -(1 as i32);
                                        let fresh102 = &mut ((*exec).state);
                                        *fresh102 = to;
                                        if (*exec).inputStackNr <= 0 as i32 {
                                            xmlFARegExecSaveInputString(exec, value, data);
                                        }
                                        xmlFARegExecSave(exec);
                                        (*exec).transno = transno;
                                        let fresh103 = &mut ((*exec).state);
                                        *fresh103 = state;
                                    }
                                    ret = xmlStrEqual(value, (*atom).valuep as *const xmlChar);
                                    let fresh104 = &mut ((*exec).transcount);
                                    *fresh104 += 1;
                                    if !(ret == 1 as i32) {
                                        break;
                                    }
                                }
                            }
                            if (*exec).transcount < (*atom).min {
                                ret = 0 as i32;
                            }
                            if ret < 0 as i32 {
                                ret = 0 as i32;
                            }
                            if ret == 0 as i32 {
                                current_block = 10868385912253950213;
                                break;
                            }
                        }
                    }
                    if ret == 1 as i32 {
                        if ((*exec).callback).is_some() && !atom.is_null()
                            && !data.is_null()
                        {
                            ((*exec).callback)
                                .expect(
                                    "non-null function pointer",
                                )(
                                (*exec).data as xmlRegExecCtxtPtr,
                                (*atom).valuep as *const xmlChar,
                                (*atom).data,
                                data,
                            );
                        }
                        if (*(*exec).state).nbTrans > (*exec).transno + 1 as i32
                        {
                            if (*exec).inputStackNr <= 0 as i32 {
                                xmlFARegExecSaveInputString(exec, value, data);
                            }
                            xmlFARegExecSave(exec);
                        }
                        if (*trans).counter >= 0 as i32 {
                            let fresh105 = &mut (*((*exec).counts)
                                .offset((*trans).counter as isize));
                            *fresh105 += 1;
                        }
                        if (*trans).count >= 0 as i32
                            && (*trans).count < 0x123456 as i32
                        {
                            *((*exec).counts)
                                .offset((*trans).count as isize) = 0 as i32;
                        }
                        if !(*((*(*exec).comp).states).offset((*trans).to as isize))
                            .is_null()
                            && (**((*(*exec).comp).states).offset((*trans).to as isize))
                                .type_0 as u32
                                == XML_REGEXP_SINK_STATE as i32 as u32
                        {
                            if !((*exec).errString).is_null() {
                                xmlFree
                                    .expect(
                                        "non-null function pointer",
                                    )((*exec).errString as *mut libc::c_void);
                            }
                            let fresh106 = &mut ((*exec).errString);
                            *fresh106 = xmlStrdup(value);
                            let fresh107 = &mut ((*exec).errState);
                            *fresh107 = (*exec).state;
                            memcpy(
                                (*exec).errCounts as *mut libc::c_void,
                                (*exec).counts as *const libc::c_void,
                                ((*(*exec).comp).nbCounters as u64)
                                    .wrapping_mul(
                                        ::std::mem::size_of::<i32>() as u64,
                                    ),
                            );
                        }
                        let fresh108 = &mut ((*exec).state);
                        *fresh108 = *((*(*exec).comp).states)
                            .offset((*trans).to as isize);
                        (*exec).transno = 0 as i32;
                        if !((*trans).atom).is_null() {
                            if !((*exec).inputStack).is_null() {
                                let fresh109 = &mut ((*exec).index);
                                *fresh109 += 1;
                                if (*exec).index < (*exec).inputStackNr {
                                    value = (*((*exec).inputStack)
                                        .offset((*exec).index as isize))
                                        .value;
                                    data = (*((*exec).inputStack)
                                        .offset((*exec).index as isize))
                                        .data;
                                } else {
                                    value = 0 as *const xmlChar;
                                    data = 0 as *mut libc::c_void;
                                }
                            } else {
                                value = 0 as *const xmlChar;
                                data = 0 as *mut libc::c_void;
                            }
                        }
                        current_block = 8483073061411596610;
                        break;
                    } else if ret < 0 as i32 {
                        (*exec).status = -(4 as i32);
                        current_block = 5511877782510663281;
                        break;
                    }
                }
                let fresh110 = &mut ((*exec).transno);
                *fresh110 += 1;
            }
            match current_block {
                10868385912253950213 => {}
                _ => {
                    match current_block {
                        8483073061411596610 => {
                            progress = 1 as i32;
                            continue;
                        }
                        _ => {
                            if !((*exec).transno != 0 as i32
                                || (*(*exec).state).nbTrans == 0 as i32)
                            {
                                continue;
                            }
                        }
                    }
                }
            }
        }
        if progress != 0 && !((*exec).state).is_null()
            && (*(*exec).state).type_0 as u32
                != XML_REGEXP_SINK_STATE as i32 as u32
        {
            progress = 0 as i32;
            if !((*exec).errString).is_null() {
                xmlFree
                    .expect(
                        "non-null function pointer",
                    )((*exec).errString as *mut libc::c_void);
            }
            let fresh111 = &mut ((*exec).errString);
            *fresh111 = xmlStrdup(value);
            let fresh112 = &mut ((*exec).errState);
            *fresh112 = (*exec).state;
            if (*(*exec).comp).nbCounters != 0 {
                memcpy(
                    (*exec).errCounts as *mut libc::c_void,
                    (*exec).counts as *const libc::c_void,
                    ((*(*exec).comp).nbCounters as u64)
                        .wrapping_mul(
                            ::std::mem::size_of::<i32>() as u64,
                        ),
                );
            }
        }
        (*exec).determinist = 0 as i32;
        xmlFARegExecRollBack(exec);
        if !((*exec).inputStack).is_null() && (*exec).status == 0 as i32 {
            value = (*((*exec).inputStack).offset((*exec).index as isize)).value;
            data = (*((*exec).inputStack).offset((*exec).index as isize)).data;
        }
    }
    if (*exec).status == 0 as i32 {
        return ((*(*exec).state).type_0 as u32
            == XML_REGEXP_FINAL_STATE as i32 as u32) as i32;
    }
    return (*exec).status;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegExecPushString(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut value: * const u8,
    mut data: * mut core::ffi::c_void,
) -> i32 {
    return xmlRegExecPushStringInternal(exec, value, data, 0 as i32);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegExecPushString2(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut value: * const u8,
    mut value2: * const u8,
    mut data: * mut core::ffi::c_void,
) -> i32 {
    let mut buf: [u8; 150] = [0; 150];
    let mut lenn: i32 = 0;
    let mut lenp: i32 = 0;
    let mut ret: i32 = 0;
    let mut str: * mut u8 = 0 as *mut xmlChar;
    if exec.is_null() {
        return -(1 as i32);
    }
    if ((*exec).comp).is_null() {
        return -(1 as i32);
    }
    if (*exec).status != 0 as i32 {
        return (*exec).status;
    }
    if value2.is_null() {
        return xmlRegExecPushString(exec, value, data);
    }
    lenn = strlen(value2 as *mut i8) as i32;
    lenp = strlen(value as *mut i8) as i32;
    if (150 as i32) < lenn + lenp + 2 as i32 {
        str = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as i32) as size_t) as *mut xmlChar;
        if str.is_null() {
            (*exec).status = -(1 as i32);
            return -(1 as i32);
        }
    } else {
        str = buf.as_mut_ptr();
    }
    memcpy(
        &mut *str.offset(0 as i32 as isize) as *mut xmlChar as *mut libc::c_void,
        value as *const libc::c_void,
        lenp as u64,
    );
    *str.offset(lenp as isize) = '|' as i32 as xmlChar;
    memcpy(
        &mut *str.offset((lenp + 1 as i32) as isize) as *mut xmlChar
            as *mut libc::c_void,
        value2 as *const libc::c_void,
        lenn as u64,
    );
    *str.offset((lenn + lenp + 1 as i32) as isize) = 0 as i32 as xmlChar;
    if !((*(*exec).comp).compact).is_null() {
        ret = xmlRegCompactPushString(exec, (*exec).comp, str, data);
    } else {
        ret = xmlRegExecPushStringInternal(exec, str, data, 1 as i32);
    }
    if str != buf.as_mut_ptr() {
        xmlFree.expect("non-null function pointer")(str as *mut libc::c_void);
    }
    return ret;
}
unsafe extern "C" fn xmlRegExecGetValues<'a1, 'a2, 'a3>(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut err: i32,
    mut nbval: Option<&'a1 mut i32>,
    mut nbneg: Option<&'a2 mut i32>,
    mut values: * mut * mut u8,
    mut terminal: Option<&'a3 mut i32>,
) -> i32 {
    let mut maxval: i32 = 0;
    let mut nb: i32 = 0 as i32;
    if exec.is_null() || borrow(& nbval).is_none() || borrow(& nbneg).is_none() || values.is_null()
        || *(borrow(& nbval)).unwrap() <= 0 as i32
    {
        return -(1 as i32);
    }
    maxval = *(borrow_mut(&mut nbval)).unwrap();
    *(borrow_mut(&mut nbval)).unwrap() = 0 as i32;
    *(borrow_mut(&mut nbneg)).unwrap() = 0 as i32;
    if !((*exec).comp).is_null() && !((*(*exec).comp).compact).is_null() {
        let mut comp: * mut crate::src::xmlregexp::_xmlRegexp = 0 as *mut xmlRegexp;
        let mut target: i32 = 0;
        let mut i: i32 = 0;
        let mut state: i32 = 0;
        comp = (*exec).comp;
        if err != 0 {
            if (*exec).errStateNo == -(1 as i32) {
                return -(1 as i32);
            }
            state = (*exec).errStateNo;
        } else {
            state = (*exec).index;
        }
        if !borrow(& terminal).is_none() {
            if *((*comp).compact)
                .offset((state * ((*comp).nbstrings + 1 as i32)) as isize)
                == XML_REGEXP_FINAL_STATE as i32
            {
                *(borrow_mut(&mut terminal)).unwrap() = 1 as i32;
            } else {
                *(borrow_mut(&mut terminal)).unwrap() = 0 as i32;
            }
        }
        i = 0 as i32;
        while i < (*comp).nbstrings && nb < maxval {
            target = *((*comp).compact)
                .offset(
                    (state * ((*comp).nbstrings + 1 as i32) + i
                        + 1 as i32) as isize,
                );
            if target > 0 as i32 && target <= (*comp).nbstates
                && *((*comp).compact)
                    .offset(
                        ((target - 1 as i32)
                            * ((*comp).nbstrings + 1 as i32)) as isize,
                    ) != XML_REGEXP_SINK_STATE as i32
            {
                let mut fresh113 = nb;
                nb = nb + 1;
                let fresh114 = &mut (*values.offset(fresh113 as isize));
                *fresh114 = *((*comp).stringMap).offset(i as isize);
                *(borrow_mut(&mut nbval)).unwrap() += 1;
            }
            i += 1;
        }
        i = 0 as i32;
        while i < (*comp).nbstrings && nb < maxval {
            target = *((*comp).compact)
                .offset(
                    (state * ((*comp).nbstrings + 1 as i32) + i
                        + 1 as i32) as isize,
                );
            if target > 0 as i32 && target <= (*comp).nbstates
                && *((*comp).compact)
                    .offset(
                        ((target - 1 as i32)
                            * ((*comp).nbstrings + 1 as i32)) as isize,
                    ) == XML_REGEXP_SINK_STATE as i32
            {
                let mut fresh115 = nb;
                nb = nb + 1;
                let fresh116 = &mut (*values.offset(fresh115 as isize));
                *fresh116 = *((*comp).stringMap).offset(i as isize);
                *(borrow_mut(&mut nbneg)).unwrap() += 1;
            }
            i += 1;
        }
    } else {
        let mut transno: i32 = 0;
        let mut trans: Option<&'_ mut crate::src::xmlregexp::_xmlRegTrans> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegTrans>::None;
        let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
        let mut state_0: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
        if !borrow(& terminal).is_none() {
            if (*(*exec).state).type_0 as u32
                == XML_REGEXP_FINAL_STATE as i32 as u32
            {
                *(borrow_mut(&mut terminal)).unwrap() = 1 as i32;
            } else {
                *(borrow_mut(&mut terminal)).unwrap() = 0 as i32;
            }
        }
        if err != 0 {
            if ((*exec).errState).is_null() {
                return -(1 as i32);
            }
            state_0 = (*exec).errState;
        } else {
            if ((*exec).state).is_null() {
                return -(1 as i32);
            }
            state_0 = (*exec).state;
        }
        transno = 0 as i32;
        while transno < (*state_0).nbTrans && nb < maxval {
            trans = Some(&mut *((*state_0).trans).offset(transno as isize));
            if !((*(borrow(& trans)).unwrap()).to < 0 as i32) {
                atom = (*(borrow_mut(&mut trans)).unwrap()).atom;
                if !(atom.is_null() || ((*atom).valuep).is_null()) {
                    if (*(borrow(& trans)).unwrap()).count == 0x123457 as i32 {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"Unimplemented block at %s:%d\n\0" as *const u8
                                as *const i8,
                            b"xmlregexp.c\0" as *const u8 as *const i8,
                            4365 as i32,
                        );
                    } else if (*(borrow(& trans)).unwrap()).count == 0x123456 as i32 {
                        (*__xmlGenericError())
                            .expect(
                                "non-null function pointer",
                            )(
                            *__xmlGenericErrorContext(),
                            b"Unimplemented block at %s:%d\n\0" as *const u8
                                as *const i8,
                            b"xmlregexp.c\0" as *const u8 as *const i8,
                            4368 as i32,
                        );
                    } else if (*(borrow(& trans)).unwrap()).counter >= 0 as i32 {
                        let mut counter: Option<&'_ mut crate::src::xmlregexp::_xmlRegCounter> = Option::<&'_ mut crate::src::xmlregexp::_xmlRegCounter>::None;
                        let mut count: i32 = 0;
                        if err != 0 {
                            count = *((*exec).errCounts)
                                .offset((*(borrow(& trans)).unwrap()).counter as isize);
                        } else {
                            count = *((*exec).counts).offset((*(borrow(& trans)).unwrap()).counter as isize);
                        }
                        if !((*exec).comp).is_null() {
                            counter = Some(&mut *((*(*exec).comp).counters)
                                .offset((*(borrow(& trans)).unwrap()).counter as isize));
                        }
                        if borrow(& counter).is_none() || count < (*(borrow(& counter)).unwrap()).max {
                            if (*atom).neg != 0 {
                                let mut fresh117 = nb;
                                nb = nb + 1;
                                let fresh118 = &mut (*values.offset(fresh117 as isize));
                                *fresh118 = (*atom).valuep2 as *mut xmlChar;
                            } else {
                                let mut fresh119 = nb;
                                nb = nb + 1;
                                let fresh120 = &mut (*values.offset(fresh119 as isize));
                                *fresh120 = (*atom).valuep as *mut xmlChar;
                            }
                            *(borrow_mut(&mut nbval)).unwrap() += 1;
                        }
                    } else if !((*exec).comp).is_null()
                            && !(*((*(*exec).comp).states).offset((*(borrow(& trans)).unwrap()).to as isize))
                                .is_null()
                            && (**((*(*exec).comp).states).offset((*(borrow(& trans)).unwrap()).to as isize))
                                .type_0 as u32
                                != XML_REGEXP_SINK_STATE as i32 as u32
                        {
                        if (*atom).neg != 0 {
                            let mut fresh121 = nb;
                            nb = nb + 1;
                            let fresh122 = &mut (*values.offset(fresh121 as isize));
                            *fresh122 = (*atom).valuep2 as *mut xmlChar;
                        } else {
                            let mut fresh123 = nb;
                            nb = nb + 1;
                            let fresh124 = &mut (*values.offset(fresh123 as isize));
                            *fresh124 = (*atom).valuep as *mut xmlChar;
                        }
                        *(borrow_mut(&mut nbval)).unwrap() += 1;
                    }
                }
            }
            transno += 1;
        }
        transno = 0 as i32;
        while transno < (*state_0).nbTrans && nb < maxval {
            trans = Some(&mut *((*state_0).trans).offset(transno as isize));
            if !((*(borrow(& trans)).unwrap()).to < 0 as i32) {
                atom = (*(borrow_mut(&mut trans)).unwrap()).atom;
                if !(atom.is_null() || ((*atom).valuep).is_null()) {
                    if !((*(borrow(& trans)).unwrap()).count == 0x123457 as i32) {
                        if !((*(borrow(& trans)).unwrap()).count == 0x123456 as i32) {
                            if !((*(borrow(& trans)).unwrap()).counter >= 0 as i32) {
                                if !(*((*(*exec).comp).states).offset((*(borrow(& trans)).unwrap()).to as isize))
                                    .is_null()
                                    && (**((*(*exec).comp).states).offset((*(borrow(& trans)).unwrap()).to as isize))
                                        .type_0 as u32
                                        == XML_REGEXP_SINK_STATE as i32 as u32
                                {
                                    if (*atom).neg != 0 {
                                        let mut fresh125 = nb;
                                        nb = nb + 1;
                                        let fresh126 = &mut (*values.offset(fresh125 as isize));
                                        *fresh126 = (*atom).valuep2 as *mut xmlChar;
                                    } else {
                                        let mut fresh127 = nb;
                                        nb = nb + 1;
                                        let fresh128 = &mut (*values.offset(fresh127 as isize));
                                        *fresh128 = (*atom).valuep as *mut xmlChar;
                                    }
                                    *(borrow_mut(&mut nbneg)).unwrap() += 1;
                                }
                            }
                        }
                    }
                }
            }
            transno += 1;
        }
    }
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegExecNextValues<'a1, 'a2, 'a3>(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut nbval: Option<&'a1 mut i32>,
    mut nbneg: Option<&'a2 mut i32>,
    mut values: * mut * mut u8,
    mut terminal: Option<&'a3 mut i32>,
) -> i32 {
    return xmlRegExecGetValues(exec, 0 as i32, borrow_mut(&mut nbval), borrow_mut(&mut nbneg), values, borrow_mut(&mut terminal));
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegExecErrInfo<'a1, 'a2, 'a3, 'a4>(
    mut exec: * mut crate::src::xmlregexp::_xmlRegExecCtxt,
    mut string: Option<&'a1 mut * const u8>,
    mut nbval: Option<&'a2 mut i32>,
    mut nbneg: Option<&'a3 mut i32>,
    mut values: * mut * mut u8,
    mut terminal: Option<&'a4 mut i32>,
) -> i32 {
    if exec.is_null() {
        return -(1 as i32);
    }
    if !borrow(& string).is_none() {
        if (*exec).status != 0 as i32 {
            *(borrow_mut(&mut string)).unwrap() = (*exec).errString;
        } else {
            *(borrow_mut(&mut string)).unwrap() = 0 as *const xmlChar;
        }
    }
    return xmlRegExecGetValues(exec, 1 as i32, borrow_mut(&mut nbval), borrow_mut(&mut nbneg), values, borrow_mut(&mut terminal));
}
unsafe extern "C" fn xmlFAIsChar(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    let mut cur: i32 = 0;
    let mut len: i32 = 0;
    cur = xmlStringCurrentChar(0 as xmlParserCtxtPtr, (*ctxt).cur, &mut len);
    if cur == '.' as i32 || cur == '\\' as i32 || cur == '?' as i32 || cur == '*' as i32
        || cur == '+' as i32 || cur == '(' as i32 || cur == ')' as i32
        || cur == '|' as i32 || cur == 0x5b as i32 || cur == 0x5d as i32
        || cur == 0 as i32
    {
        return -(1 as i32);
    }
    return cur;
}
unsafe extern "C" fn xmlFAParseCharProp(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut cur: i32 = 0;
    let mut type_0: u32 = 0 as xmlRegAtomType;
    let mut blockName: * mut u8 = 0 as *mut xmlChar;
    cur = *(*ctxt).cur as i32;
    if cur == 'L' as i32 {
        let fresh129 = &mut ((*ctxt).cur);
        *fresh129 = (*fresh129).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'u' as i32 {
            let fresh130 = &mut ((*ctxt).cur);
            *fresh130 = (*fresh130).offset(1);
            type_0 = XML_REGEXP_LETTER_UPPERCASE;
        } else if cur == 'l' as i32 {
            let fresh131 = &mut ((*ctxt).cur);
            *fresh131 = (*fresh131).offset(1);
            type_0 = XML_REGEXP_LETTER_LOWERCASE;
        } else if cur == 't' as i32 {
            let fresh132 = &mut ((*ctxt).cur);
            *fresh132 = (*fresh132).offset(1);
            type_0 = XML_REGEXP_LETTER_TITLECASE;
        } else if cur == 'm' as i32 {
            let fresh133 = &mut ((*ctxt).cur);
            *fresh133 = (*fresh133).offset(1);
            type_0 = XML_REGEXP_LETTER_MODIFIER;
        } else if cur == 'o' as i32 {
            let fresh134 = &mut ((*ctxt).cur);
            *fresh134 = (*fresh134).offset(1);
            type_0 = XML_REGEXP_LETTER_OTHERS;
        } else {
            type_0 = XML_REGEXP_LETTER;
        }
    } else if cur == 'M' as i32 {
        let fresh135 = &mut ((*ctxt).cur);
        *fresh135 = (*fresh135).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'n' as i32 {
            let fresh136 = &mut ((*ctxt).cur);
            *fresh136 = (*fresh136).offset(1);
            type_0 = XML_REGEXP_MARK_NONSPACING;
        } else if cur == 'c' as i32 {
            let fresh137 = &mut ((*ctxt).cur);
            *fresh137 = (*fresh137).offset(1);
            type_0 = XML_REGEXP_MARK_SPACECOMBINING;
        } else if cur == 'e' as i32 {
            let fresh138 = &mut ((*ctxt).cur);
            *fresh138 = (*fresh138).offset(1);
            type_0 = XML_REGEXP_MARK_ENCLOSING;
        } else {
            type_0 = XML_REGEXP_MARK;
        }
    } else if cur == 'N' as i32 {
        let fresh139 = &mut ((*ctxt).cur);
        *fresh139 = (*fresh139).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'd' as i32 {
            let fresh140 = &mut ((*ctxt).cur);
            *fresh140 = (*fresh140).offset(1);
            type_0 = XML_REGEXP_NUMBER_DECIMAL;
        } else if cur == 'l' as i32 {
            let fresh141 = &mut ((*ctxt).cur);
            *fresh141 = (*fresh141).offset(1);
            type_0 = XML_REGEXP_NUMBER_LETTER;
        } else if cur == 'o' as i32 {
            let fresh142 = &mut ((*ctxt).cur);
            *fresh142 = (*fresh142).offset(1);
            type_0 = XML_REGEXP_NUMBER_OTHERS;
        } else {
            type_0 = XML_REGEXP_NUMBER;
        }
    } else if cur == 'P' as i32 {
        let fresh143 = &mut ((*ctxt).cur);
        *fresh143 = (*fresh143).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'c' as i32 {
            let fresh144 = &mut ((*ctxt).cur);
            *fresh144 = (*fresh144).offset(1);
            type_0 = XML_REGEXP_PUNCT_CONNECTOR;
        } else if cur == 'd' as i32 {
            let fresh145 = &mut ((*ctxt).cur);
            *fresh145 = (*fresh145).offset(1);
            type_0 = XML_REGEXP_PUNCT_DASH;
        } else if cur == 's' as i32 {
            let fresh146 = &mut ((*ctxt).cur);
            *fresh146 = (*fresh146).offset(1);
            type_0 = XML_REGEXP_PUNCT_OPEN;
        } else if cur == 'e' as i32 {
            let fresh147 = &mut ((*ctxt).cur);
            *fresh147 = (*fresh147).offset(1);
            type_0 = XML_REGEXP_PUNCT_CLOSE;
        } else if cur == 'i' as i32 {
            let fresh148 = &mut ((*ctxt).cur);
            *fresh148 = (*fresh148).offset(1);
            type_0 = XML_REGEXP_PUNCT_INITQUOTE;
        } else if cur == 'f' as i32 {
            let fresh149 = &mut ((*ctxt).cur);
            *fresh149 = (*fresh149).offset(1);
            type_0 = XML_REGEXP_PUNCT_FINQUOTE;
        } else if cur == 'o' as i32 {
            let fresh150 = &mut ((*ctxt).cur);
            *fresh150 = (*fresh150).offset(1);
            type_0 = XML_REGEXP_PUNCT_OTHERS;
        } else {
            type_0 = XML_REGEXP_PUNCT;
        }
    } else if cur == 'Z' as i32 {
        let fresh151 = &mut ((*ctxt).cur);
        *fresh151 = (*fresh151).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 's' as i32 {
            let fresh152 = &mut ((*ctxt).cur);
            *fresh152 = (*fresh152).offset(1);
            type_0 = XML_REGEXP_SEPAR_SPACE;
        } else if cur == 'l' as i32 {
            let fresh153 = &mut ((*ctxt).cur);
            *fresh153 = (*fresh153).offset(1);
            type_0 = XML_REGEXP_SEPAR_LINE;
        } else if cur == 'p' as i32 {
            let fresh154 = &mut ((*ctxt).cur);
            *fresh154 = (*fresh154).offset(1);
            type_0 = XML_REGEXP_SEPAR_PARA;
        } else {
            type_0 = XML_REGEXP_SEPAR;
        }
    } else if cur == 'S' as i32 {
        let fresh155 = &mut ((*ctxt).cur);
        *fresh155 = (*fresh155).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'm' as i32 {
            let fresh156 = &mut ((*ctxt).cur);
            *fresh156 = (*fresh156).offset(1);
            type_0 = XML_REGEXP_SYMBOL_MATH;
        } else if cur == 'c' as i32 {
            let fresh157 = &mut ((*ctxt).cur);
            *fresh157 = (*fresh157).offset(1);
            type_0 = XML_REGEXP_SYMBOL_CURRENCY;
        } else if cur == 'k' as i32 {
            let fresh158 = &mut ((*ctxt).cur);
            *fresh158 = (*fresh158).offset(1);
            type_0 = XML_REGEXP_SYMBOL_MODIFIER;
        } else if cur == 'o' as i32 {
            let fresh159 = &mut ((*ctxt).cur);
            *fresh159 = (*fresh159).offset(1);
            type_0 = XML_REGEXP_SYMBOL_OTHERS;
        } else {
            type_0 = XML_REGEXP_SYMBOL;
        }
    } else if cur == 'C' as i32 {
        let fresh160 = &mut ((*ctxt).cur);
        *fresh160 = (*fresh160).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur == 'c' as i32 {
            let fresh161 = &mut ((*ctxt).cur);
            *fresh161 = (*fresh161).offset(1);
            type_0 = XML_REGEXP_OTHER_CONTROL;
        } else if cur == 'f' as i32 {
            let fresh162 = &mut ((*ctxt).cur);
            *fresh162 = (*fresh162).offset(1);
            type_0 = XML_REGEXP_OTHER_FORMAT;
        } else if cur == 'o' as i32 {
            let fresh163 = &mut ((*ctxt).cur);
            *fresh163 = (*fresh163).offset(1);
            type_0 = XML_REGEXP_OTHER_PRIVATE;
        } else if cur == 'n' as i32 {
            let fresh164 = &mut ((*ctxt).cur);
            *fresh164 = (*fresh164).offset(1);
            type_0 = XML_REGEXP_OTHER_NA;
        } else {
            type_0 = XML_REGEXP_OTHER;
        }
    } else if cur == 'I' as i32 {
        let mut start: * const u8 = 0 as *const xmlChar;
        let fresh165 = &mut ((*ctxt).cur);
        *fresh165 = (*fresh165).offset(1);
        cur = *(*ctxt).cur as i32;
        if cur != 's' as i32 {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"IsXXXX expected\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh166 = &mut ((*ctxt).cur);
        *fresh166 = (*fresh166).offset(1);
        start = (*ctxt).cur;
        cur = *(*ctxt).cur as i32;
        if cur >= 'a' as i32 && cur <= 'z' as i32
            || cur >= 'A' as i32 && cur <= 'Z' as i32
            || cur >= '0' as i32 && cur <= '9' as i32 || cur == 0x2d as i32
        {
            let fresh167 = &mut ((*ctxt).cur);
            *fresh167 = (*fresh167).offset(1);
            cur = *(*ctxt).cur as i32;
            while cur >= 'a' as i32 && cur <= 'z' as i32
                || cur >= 'A' as i32 && cur <= 'Z' as i32
                || cur >= '0' as i32 && cur <= '9' as i32 || cur == 0x2d as i32
            {
                let fresh168 = &mut ((*ctxt).cur);
                *fresh168 = (*fresh168).offset(1);
                cur = *(*ctxt).cur as i32;
            }
        }
        type_0 = XML_REGEXP_BLOCK_NAME;
        blockName = xmlStrndup(
            start,
            ((*ctxt).cur).offset_from(start) as i64 as i32,
        );
    } else {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Unknown char property\0" as *const u8 as *const i8,
        );
        return;
    }
    if ((*ctxt).atom).is_null() {
        let fresh169 = &mut ((*ctxt).atom);
        *fresh169 = xmlRegNewAtom(ctxt, type_0);
        if !((*ctxt).atom).is_null() {
            let fresh170 = &mut ((*(*ctxt).atom).valuep);
            *fresh170 = blockName as *mut libc::c_void;
        }
    } else if (*(*ctxt).atom).type_0 as u32
            == XML_REGEXP_RANGES as i32 as u32
        {
        xmlRegAtomAddRange(
            ctxt,
            (*ctxt).atom,
            (*ctxt).neg,
            type_0,
            0 as i32,
            0 as i32,
            blockName,
        );
    }
}
unsafe extern "C" fn parse_escaped_codeunit(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
) -> i32 {
    let mut val: i32 = 0 as i32;
    let mut i: i32 = 0;
    let mut cur: i32 = 0;
    i = 0 as i32;
    while i < 4 as i32 {
        let fresh171 = &mut ((*ctxt).cur);
        *fresh171 = (*fresh171).offset(1);
        val *= 16 as i32;
        cur = *(*ctxt).cur as i32;
        if cur >= '0' as i32 && cur <= '9' as i32 {
            val += cur - '0' as i32;
        } else if cur >= 'A' as i32 && cur <= 'F' as i32 {
            val += cur - 'A' as i32 + 10 as i32;
        } else if cur >= 'a' as i32 && cur <= 'f' as i32 {
            val += cur - 'a' as i32 + 10 as i32;
        } else {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Expecting hex digit\0" as *const u8 as *const i8,
            );
            return -(1 as i32);
        }
        i += 1;
    }
    return val;
}
unsafe extern "C" fn parse_escaped_codepoint(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
) -> i32 {
    let mut val: i32 = parse_escaped_codeunit(ctxt);
    if 0xd800 as i32 <= val && val <= 0xdbff as i32 {
        let fresh172 = &mut ((*ctxt).cur);
        *fresh172 = (*fresh172).offset(1);
        if *(*ctxt).cur as i32 == '\\' as i32 {
            let fresh173 = &mut ((*ctxt).cur);
            *fresh173 = (*fresh173).offset(1);
            if *(*ctxt).cur as i32 == 'u' as i32 {
                let mut low: i32 = parse_escaped_codeunit(ctxt);
                if 0xdc00 as i32 <= low && low <= 0xdfff as i32 {
                    return (val - 0xd800 as i32) * 0x400 as i32
                        + (low - 0xdc00 as i32) + 0x10000 as i32;
                }
            }
        }
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Invalid low surrogate pair code unit\0" as *const u8 as *const i8,
        );
        val = -(1 as i32);
    }
    return val;
}
unsafe extern "C" fn xmlFAParseCharClassEsc(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut cur: i32 = 0;
    if *(*ctxt).cur as i32 == '.' as i32 {
        if ((*ctxt).atom).is_null() {
            let fresh174 = &mut ((*ctxt).atom);
            *fresh174 = xmlRegNewAtom(ctxt, XML_REGEXP_ANYCHAR);
        } else if (*(*ctxt).atom).type_0 as u32
                == XML_REGEXP_RANGES as i32 as u32
            {
            xmlRegAtomAddRange(
                ctxt,
                (*ctxt).atom,
                (*ctxt).neg,
                XML_REGEXP_ANYCHAR,
                0 as i32,
                0 as i32,
                0 as *mut xmlChar,
            );
        }
        let fresh175 = &mut ((*ctxt).cur);
        *fresh175 = (*fresh175).offset(1);
        return;
    }
    if *(*ctxt).cur as i32 != '\\' as i32 {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Escaped sequence: expecting \\\0" as *const u8 as *const i8,
        );
        return;
    }
    let fresh176 = &mut ((*ctxt).cur);
    *fresh176 = (*fresh176).offset(1);
    cur = *(*ctxt).cur as i32;
    if cur == 'p' as i32 {
        let fresh177 = &mut ((*ctxt).cur);
        *fresh177 = (*fresh177).offset(1);
        if *(*ctxt).cur as i32 != '{' as i32 {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Expecting '{'\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh178 = &mut ((*ctxt).cur);
        *fresh178 = (*fresh178).offset(1);
        xmlFAParseCharProp(ctxt);
        if *(*ctxt).cur as i32 != '}' as i32 {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Expecting '}'\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh179 = &mut ((*ctxt).cur);
        *fresh179 = (*fresh179).offset(1);
    } else if cur == 'P' as i32 {
        let fresh180 = &mut ((*ctxt).cur);
        *fresh180 = (*fresh180).offset(1);
        if *(*ctxt).cur as i32 != '{' as i32 {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Expecting '{'\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh181 = &mut ((*ctxt).cur);
        *fresh181 = (*fresh181).offset(1);
        xmlFAParseCharProp(ctxt);
        if !((*ctxt).atom).is_null() {
            (*(*ctxt).atom).neg = 1 as i32;
        }
        if *(*ctxt).cur as i32 != '}' as i32 {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Expecting '}'\0" as *const u8 as *const i8,
            );
            return;
        }
        let fresh182 = &mut ((*ctxt).cur);
        *fresh182 = (*fresh182).offset(1);
    } else if cur == 'n' as i32 || cur == 'r' as i32 || cur == 't' as i32
            || cur == '\\' as i32 || cur == '|' as i32 || cur == '.' as i32
            || cur == '?' as i32 || cur == '*' as i32 || cur == '+' as i32
            || cur == '(' as i32 || cur == ')' as i32 || cur == '{' as i32
            || cur == '}' as i32 || cur == 0x2d as i32
            || cur == 0x5b as i32 || cur == 0x5d as i32
            || cur == 0x5e as i32 || cur == '!' as i32 || cur == '"' as i32
            || cur == '#' as i32 || cur == '$' as i32 || cur == '%' as i32
            || cur == ',' as i32 || cur == '/' as i32 || cur == ':' as i32
            || cur == ';' as i32 || cur == '=' as i32 || cur == '>' as i32
            || cur == '@' as i32 || cur == '`' as i32 || cur == '~' as i32
            || cur == 'u' as i32
        {
        if ((*ctxt).atom).is_null() {
            let fresh183 = &mut ((*ctxt).atom);
            *fresh183 = xmlRegNewAtom(ctxt, XML_REGEXP_CHARVAL);
            if !((*ctxt).atom).is_null() {
                match cur {
                    110 => {
                        (*(*ctxt).atom).codepoint = '\n' as i32;
                    }
                    114 => {
                        (*(*ctxt).atom).codepoint = '\r' as i32;
                    }
                    116 => {
                        (*(*ctxt).atom).codepoint = '\t' as i32;
                    }
                    117 => {
                        cur = parse_escaped_codepoint(ctxt);
                        if cur < 0 as i32 {
                            return;
                        }
                        (*(*ctxt).atom).codepoint = cur;
                    }
                    _ => {
                        (*(*ctxt).atom).codepoint = cur;
                    }
                }
            }
        } else if (*(*ctxt).atom).type_0 as u32
                == XML_REGEXP_RANGES as i32 as u32
            {
            match cur {
                110 => {
                    cur = '\n' as i32;
                }
                114 => {
                    cur = '\r' as i32;
                }
                116 => {
                    cur = '\t' as i32;
                }
                _ => {}
            }
            xmlRegAtomAddRange(
                ctxt,
                (*ctxt).atom,
                (*ctxt).neg,
                XML_REGEXP_CHARVAL,
                cur,
                cur,
                0 as *mut xmlChar,
            );
        }
        let fresh184 = &mut ((*ctxt).cur);
        *fresh184 = (*fresh184).offset(1);
    } else if cur == 's' as i32 || cur == 'S' as i32 || cur == 'i' as i32
            || cur == 'I' as i32 || cur == 'c' as i32 || cur == 'C' as i32
            || cur == 'd' as i32 || cur == 'D' as i32 || cur == 'w' as i32
            || cur == 'W' as i32
        {
        let mut type_0: u32 = XML_REGEXP_ANYSPACE;
        match cur {
            115 => {
                type_0 = XML_REGEXP_ANYSPACE;
            }
            83 => {
                type_0 = XML_REGEXP_NOTSPACE;
            }
            105 => {
                type_0 = XML_REGEXP_INITNAME;
            }
            73 => {
                type_0 = XML_REGEXP_NOTINITNAME;
            }
            99 => {
                type_0 = XML_REGEXP_NAMECHAR;
            }
            67 => {
                type_0 = XML_REGEXP_NOTNAMECHAR;
            }
            100 => {
                type_0 = XML_REGEXP_DECIMAL;
            }
            68 => {
                type_0 = XML_REGEXP_NOTDECIMAL;
            }
            119 => {
                type_0 = XML_REGEXP_REALCHAR;
            }
            87 => {
                type_0 = XML_REGEXP_NOTREALCHAR;
            }
            _ => {}
        }
        let fresh185 = &mut ((*ctxt).cur);
        *fresh185 = (*fresh185).offset(1);
        if ((*ctxt).atom).is_null() {
            let fresh186 = &mut ((*ctxt).atom);
            *fresh186 = xmlRegNewAtom(ctxt, type_0);
        } else if (*(*ctxt).atom).type_0 as u32
                == XML_REGEXP_RANGES as i32 as u32
            {
            xmlRegAtomAddRange(
                ctxt,
                (*ctxt).atom,
                (*ctxt).neg,
                type_0,
                0 as i32,
                0 as i32,
                0 as *mut xmlChar,
            );
        }
    } else {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Wrong escape sequence, misuse of character '\\'\0" as *const u8
                as *const i8,
        );
    };
}
unsafe extern "C" fn xmlFAParseCharRange(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut cur: i32 = 0;
    let mut len: i32 = 0;
    let mut start: i32 = -(1 as i32);
    let mut end: i32 = -(1 as i32);
    if *(*ctxt).cur as i32 == '\u{0}' as i32 {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Expecting ']'\0" as *const u8 as *const i8,
        );
        return;
    }
    cur = *(*ctxt).cur as i32;
    if cur == '\\' as i32 {
        let fresh187 = &mut ((*ctxt).cur);
        *fresh187 = (*fresh187).offset(1);
        cur = *(*ctxt).cur as i32;
        match cur {
            110 => {
                start = 0xa as i32;
            }
            114 => {
                start = 0xd as i32;
            }
            116 => {
                start = 0x9 as i32;
            }
            92 | 124 | 46 | 45 | 94 | 63 | 42 | 43 | 123 | 125 | 40 | 41 | 91 | 93 => {
                start = cur;
            }
            _ => {
                (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                xmlRegexpErrCompile(
                    ctxt,
                    b"Invalid escape value\0" as *const u8 as *const i8,
                );
                return;
            }
        }
        end = start;
        len = 1 as i32;
    } else if cur != 0x5b as i32 && cur != 0x5d as i32 {
        start = xmlStringCurrentChar(0 as xmlParserCtxtPtr, (*ctxt).cur, &mut len);
        end = start;
    } else {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Expecting a char range\0" as *const u8 as *const i8,
        );
        return;
    }
    if start == '-' as i32
        && *((*ctxt).cur).offset(1 as i32 as isize) as i32 != ']' as i32
        && *((*ctxt).cur).offset(-(1 as i32) as isize) as i32
            != '[' as i32
        && *((*ctxt).cur).offset(-(1 as i32) as isize) as i32
            != '^' as i32
    {
        let fresh188 = &mut ((*ctxt).cur);
        *fresh188 = (*fresh188).offset(len as isize);
        return;
    }
    let fresh189 = &mut ((*ctxt).cur);
    *fresh189 = (*fresh189).offset(len as isize);
    cur = *(*ctxt).cur as i32;
    if cur != '-' as i32
        || *((*ctxt).cur).offset(1 as i32 as isize) as i32 == '[' as i32
        || *((*ctxt).cur).offset(1 as i32 as isize) as i32 == ']' as i32
    {
        xmlRegAtomAddRange(
            ctxt,
            (*ctxt).atom,
            (*ctxt).neg,
            XML_REGEXP_CHARVAL,
            start,
            end,
            0 as *mut xmlChar,
        );
        return;
    }
    let fresh190 = &mut ((*ctxt).cur);
    *fresh190 = (*fresh190).offset(1);
    cur = *(*ctxt).cur as i32;
    if cur == '\\' as i32 {
        let fresh191 = &mut ((*ctxt).cur);
        *fresh191 = (*fresh191).offset(1);
        cur = *(*ctxt).cur as i32;
        match cur {
            110 => {
                end = 0xa as i32;
            }
            114 => {
                end = 0xd as i32;
            }
            116 => {
                end = 0x9 as i32;
            }
            92 | 124 | 46 | 45 | 94 | 63 | 42 | 43 | 123 | 125 | 40 | 41 | 91 | 93 => {
                end = cur;
            }
            _ => {
                (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                xmlRegexpErrCompile(
                    ctxt,
                    b"Invalid escape value\0" as *const u8 as *const i8,
                );
                return;
            }
        }
        len = 1 as i32;
    } else if cur != '\u{0}' as i32 && cur != 0x5b as i32
            && cur != 0x5d as i32
        {
        end = xmlStringCurrentChar(0 as xmlParserCtxtPtr, (*ctxt).cur, &mut len);
    } else {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"Expecting the end of a char range\0" as *const u8 as *const i8,
        );
        return;
    }
    if end < start {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"End of range is before start of range\0" as *const u8
                as *const i8,
        );
    } else {
        let fresh192 = &mut ((*ctxt).cur);
        *fresh192 = (*fresh192).offset(len as isize);
        xmlRegAtomAddRange(
            ctxt,
            (*ctxt).atom,
            (*ctxt).neg,
            XML_REGEXP_CHARVAL,
            start,
            end,
            0 as *mut xmlChar,
        );
    };
}
unsafe extern "C" fn xmlFAParsePosCharGroup(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    loop {
        if *(*ctxt).cur as i32 == '\\' as i32 {
            xmlFAParseCharClassEsc(ctxt);
        } else {
            xmlFAParseCharRange(ctxt);
        }
        if !(*(*ctxt).cur as i32 != ']' as i32
            && *(*ctxt).cur as i32 != '-' as i32
            && *(*ctxt).cur as i32 != 0 as i32
            && (*ctxt).error == 0 as i32)
        {
            break;
        }
    };
}
unsafe extern "C" fn xmlFAParseCharGroup(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    let mut neg: i32 = (*ctxt).neg;
    if *(*ctxt).cur as i32 == '^' as i32 {
        let fresh193 = &mut ((*ctxt).cur);
        *fresh193 = (*fresh193).offset(1);
        (*ctxt).neg = ((*ctxt).neg == 0) as i32;
        xmlFAParsePosCharGroup(ctxt);
        (*ctxt).neg = neg;
    }
    while *(*ctxt).cur as i32 != ']' as i32 && (*ctxt).error == 0 as i32
    {
        if *(*ctxt).cur as i32 == '-' as i32
            && *((*ctxt).cur).offset(1 as i32 as isize) as i32
                == '[' as i32
        {
            let fresh194 = &mut ((*ctxt).cur);
            *fresh194 = (*fresh194).offset(1);
            let fresh195 = &mut ((*ctxt).cur);
            *fresh195 = (*fresh195).offset(1);
            (*ctxt).neg = 2 as i32;
            xmlFAParseCharGroup(ctxt);
            (*ctxt).neg = neg;
            if *(*ctxt).cur as i32 == ']' as i32 {
                let fresh196 = &mut ((*ctxt).cur);
                *fresh196 = (*fresh196).offset(1);
            } else {
                (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                xmlRegexpErrCompile(
                    ctxt,
                    b"charClassExpr: ']' expected\0" as *const u8 as *const i8,
                );
            }
            break;
        } else {
            xmlFAParsePosCharGroup(ctxt);
        }
    }
}
unsafe extern "C" fn xmlFAParseCharClass(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) {
    if *(*ctxt).cur as i32 == '[' as i32 {
        let fresh197 = &mut ((*ctxt).cur);
        *fresh197 = (*fresh197).offset(1);
        let fresh198 = &mut ((*ctxt).atom);
        *fresh198 = xmlRegNewAtom(ctxt, XML_REGEXP_RANGES);
        if ((*ctxt).atom).is_null() {
            return;
        }
        xmlFAParseCharGroup(ctxt);
        if *(*ctxt).cur as i32 == ']' as i32 {
            let fresh199 = &mut ((*ctxt).cur);
            *fresh199 = (*fresh199).offset(1);
        } else {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"xmlFAParseCharClass: ']' expected\0" as *const u8
                    as *const i8,
            );
        }
    } else {
        xmlFAParseCharClassEsc(ctxt);
    };
}
unsafe extern "C" fn xmlFAParseQuantExact(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    let mut ret: i32 = 0 as i32;
    let mut ok: i32 = 0 as i32;
    let mut overflow: i32 = 0 as i32;
    while *(*ctxt).cur as i32 >= '0' as i32
        && *(*ctxt).cur as i32 <= '9' as i32
    {
        if ret > 2147483647 as i32 / 10 as i32 {
            overflow = 1 as i32;
        } else {
            let mut digit: i32 = *(*ctxt).cur as i32 - '0' as i32;
            ret *= 10 as i32;
            if ret > 2147483647 as i32 - digit {
                overflow = 1 as i32;
            } else {
                ret += digit;
            }
        }
        ok = 1 as i32;
        let fresh200 = &mut ((*ctxt).cur);
        *fresh200 = (*fresh200).offset(1);
    }
    if ok != 1 as i32 || overflow == 1 as i32 {
        return -(1 as i32);
    }
    return ret;
}
unsafe extern "C" fn xmlFAParseQuantifier(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    let mut cur: i32 = 0;
    cur = *(*ctxt).cur as i32;
    if cur == '?' as i32 || cur == '*' as i32 || cur == '+' as i32 {
        if !((*ctxt).atom).is_null() {
            if cur == '?' as i32 {
                (*(*ctxt).atom).quant = XML_REGEXP_QUANT_OPT;
            } else if cur == '*' as i32 {
                (*(*ctxt).atom).quant = XML_REGEXP_QUANT_MULT;
            } else if cur == '+' as i32 {
                (*(*ctxt).atom).quant = XML_REGEXP_QUANT_PLUS;
            }
        }
        let fresh201 = &mut ((*ctxt).cur);
        *fresh201 = (*fresh201).offset(1);
        return 1 as i32;
    }
    if cur == '{' as i32 {
        let mut min: i32 = 0 as i32;
        let mut max: i32 = 0 as i32;
        let fresh202 = &mut ((*ctxt).cur);
        *fresh202 = (*fresh202).offset(1);
        cur = xmlFAParseQuantExact(ctxt);
        if cur >= 0 as i32 {
            min = cur;
        } else {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Improper quantifier\0" as *const u8 as *const i8,
            );
        }
        if *(*ctxt).cur as i32 == ',' as i32 {
            let fresh203 = &mut ((*ctxt).cur);
            *fresh203 = (*fresh203).offset(1);
            if *(*ctxt).cur as i32 == '}' as i32 {
                max = 2147483647 as i32;
            } else {
                cur = xmlFAParseQuantExact(ctxt);
                if cur >= 0 as i32 {
                    max = cur;
                } else {
                    (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                    xmlRegexpErrCompile(
                        ctxt,
                        b"Improper quantifier\0" as *const u8 as *const i8,
                    );
                }
            }
        }
        if *(*ctxt).cur as i32 == '}' as i32 {
            let fresh204 = &mut ((*ctxt).cur);
            *fresh204 = (*fresh204).offset(1);
        } else {
            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
            xmlRegexpErrCompile(
                ctxt,
                b"Unterminated quantifier\0" as *const u8 as *const i8,
            );
        }
        if max == 0 as i32 {
            max = min;
        }
        if !((*ctxt).atom).is_null() {
            (*(*ctxt).atom).quant = XML_REGEXP_QUANT_RANGE;
            (*(*ctxt).atom).min = min;
            (*(*ctxt).atom).max = max;
        }
        return 1 as i32;
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlFAParseAtom(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    let mut codepoint: i32 = 0;
    let mut len: i32 = 0;
    codepoint = xmlFAIsChar(ctxt);
    if codepoint > 0 as i32 {
        let fresh205 = &mut ((*ctxt).atom);
        *fresh205 = xmlRegNewAtom(ctxt, XML_REGEXP_CHARVAL);
        if ((*ctxt).atom).is_null() {
            return -(1 as i32);
        }
        codepoint = xmlStringCurrentChar(0 as xmlParserCtxtPtr, (*ctxt).cur, &mut len);
        (*(*ctxt).atom).codepoint = codepoint;
        let fresh206 = &mut ((*ctxt).cur);
        *fresh206 = (*fresh206).offset(len as isize);
        return 1 as i32;
    } else {
        if *(*ctxt).cur as i32 == '|' as i32 {
            return 0 as i32
        } else {
            if *(*ctxt).cur as i32 == 0 as i32 {
                return 0 as i32
            } else {
                if *(*ctxt).cur as i32 == ')' as i32 {
                    return 0 as i32
                } else {
                    if *(*ctxt).cur as i32 == '(' as i32 {
                        let mut start: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
                        let mut oldend: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
                        let mut start0: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
                        let fresh207 = &mut ((*ctxt).cur);
                        *fresh207 = (*fresh207).offset(1);
                        if (*ctxt).depth >= 50 as i32 {
                            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                            xmlRegexpErrCompile(
                                ctxt,
                                b"xmlFAParseAtom: maximum nesting depth exceeded\0"
                                    as *const u8 as *const i8,
                            );
                            return -(1 as i32);
                        }
                        xmlFAGenerateEpsilonTransition(
                            ctxt,
                            (*ctxt).state,
                            0 as xmlRegStatePtr,
                        );
                        start0 = (*ctxt).state;
                        xmlFAGenerateEpsilonTransition(
                            ctxt,
                            (*ctxt).state,
                            0 as xmlRegStatePtr,
                        );
                        start = (*ctxt).state;
                        oldend = (*ctxt).end;
                        let fresh208 = &mut ((*ctxt).end);
                        *fresh208 = 0 as xmlRegStatePtr;
                        let fresh209 = &mut ((*ctxt).atom);
                        *fresh209 = 0 as xmlRegAtomPtr;
                        let fresh210 = &mut ((*ctxt).depth);
                        *fresh210 += 1;
                        xmlFAParseRegExp(ctxt, 0 as i32);
                        let fresh211 = &mut ((*ctxt).depth);
                        *fresh211 -= 1;
                        if *(*ctxt).cur as i32 == ')' as i32 {
                            let fresh212 = &mut ((*ctxt).cur);
                            *fresh212 = (*fresh212).offset(1);
                        } else {
                            (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
                            xmlRegexpErrCompile(
                                ctxt,
                                b"xmlFAParseAtom: expecting ')'\0" as *const u8
                                    as *const i8,
                            );
                        }
                        let fresh213 = &mut ((*ctxt).atom);
                        *fresh213 = xmlRegNewAtom(ctxt, XML_REGEXP_SUBREG);
                        if ((*ctxt).atom).is_null() {
                            return -(1 as i32);
                        }
                        let fresh214 = &mut ((*(*ctxt).atom).start);
                        *fresh214 = start;
                        let fresh215 = &mut ((*(*ctxt).atom).start0);
                        *fresh215 = start0;
                        let fresh216 = &mut ((*(*ctxt).atom).stop);
                        *fresh216 = (*ctxt).state;
                        let fresh217 = &mut ((*ctxt).end);
                        *fresh217 = oldend;
                        return 1 as i32;
                    } else {
                        if *(*ctxt).cur as i32 == '[' as i32
                            || *(*ctxt).cur as i32 == '\\' as i32
                            || *(*ctxt).cur as i32 == '.' as i32
                        {
                            xmlFAParseCharClass(ctxt);
                            return 1 as i32;
                        }
                    }
                }
            }
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlFAParsePiece(mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata) -> i32 {
    let mut ret: i32 = 0;
    let fresh218 = &mut ((*ctxt).atom);
    *fresh218 = 0 as xmlRegAtomPtr;
    ret = xmlFAParseAtom(ctxt);
    if ret == 0 as i32 {
        return 0 as i32;
    }
    if ((*ctxt).atom).is_null() {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"internal: no atom generated\0" as *const u8 as *const i8,
        );
    }
    xmlFAParseQuantifier(ctxt);
    return 1 as i32;
}
unsafe extern "C" fn xmlFAParseBranch(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
) -> i32 {
    let mut previous: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut ret: i32 = 0;
    previous = (*ctxt).state;
    ret = xmlFAParsePiece(ctxt);
    if ret == 0 as i32 {
        xmlFAGenerateEpsilonTransition(ctxt, previous, to);
    } else {
        if xmlFAGenerateTransitions(
            ctxt,
            previous,
            (if *(*ctxt).cur as i32 == '|' as i32
                || *(*ctxt).cur as i32 == ')' as i32
                || *(*ctxt).cur as i32 == 0 as i32
            {
                to
            } else {
                0 as xmlRegStatePtr
            }),
            (*ctxt).atom,
        ) < 0 as i32
        {
            return -(1 as i32);
        }
        previous = (*ctxt).state;
        let fresh219 = &mut ((*ctxt).atom);
        *fresh219 = 0 as xmlRegAtomPtr;
    }
    while ret != 0 as i32 && (*ctxt).error == 0 as i32 {
        ret = xmlFAParsePiece(ctxt);
        if ret != 0 as i32 {
            if xmlFAGenerateTransitions(
                ctxt,
                previous,
                (if *(*ctxt).cur as i32 == '|' as i32
                    || *(*ctxt).cur as i32 == ')' as i32
                    || *(*ctxt).cur as i32 == 0 as i32
                {
                    to
                } else {
                    0 as xmlRegStatePtr
                }),
                (*ctxt).atom,
            ) < 0 as i32
            {
                return -(1 as i32);
            }
            previous = (*ctxt).state;
            let fresh220 = &mut ((*ctxt).atom);
            *fresh220 = 0 as xmlRegAtomPtr;
        }
    }
    return 0 as i32;
}
unsafe extern "C" fn xmlFAParseRegExp(
    mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata,
    mut top: i32,
) {
    let mut start: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    let mut end: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlRegState;
    start = (*ctxt).state;
    let fresh221 = &mut ((*ctxt).end);
    *fresh221 = 0 as xmlRegStatePtr;
    xmlFAParseBranch(ctxt, 0 as xmlRegStatePtr);
    if top != 0 {
        (*(*ctxt).state).type_0 = XML_REGEXP_FINAL_STATE;
    }
    if *(*ctxt).cur as i32 != '|' as i32 {
        let fresh222 = &mut ((*ctxt).end);
        *fresh222 = (*ctxt).state;
        return;
    }
    end = (*ctxt).state;
    while *(*ctxt).cur as i32 == '|' as i32 && (*ctxt).error == 0 as i32
    {
        let fresh223 = &mut ((*ctxt).cur);
        *fresh223 = (*fresh223).offset(1);
        let fresh224 = &mut ((*ctxt).state);
        *fresh224 = start;
        let fresh225 = &mut ((*ctxt).end);
        *fresh225 = 0 as xmlRegStatePtr;
        xmlFAParseBranch(ctxt, end);
    }
    if top == 0 {
        let fresh226 = &mut ((*ctxt).state);
        *fresh226 = end;
        let fresh227 = &mut ((*ctxt).end);
        *fresh227 = end;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegexpPrint<'a1>(
    mut output: * mut crate::src::tree::_IO_FILE,
    mut regexp: Option<&'a1 mut crate::src::xmlregexp::_xmlRegexp>,
) {
    let mut i: i32 = 0;
    if output.is_null() {
        return;
    }
    fprintf(output, b" regexp: \0" as *const u8 as *const i8);
    if borrow(& regexp).is_none() {
        fprintf(output, b"NULL\n\0" as *const u8 as *const i8);
        return;
    }
    fprintf(output, b"'%s' \0" as *const u8 as *const i8, (*(borrow(& regexp)).unwrap()).string);
    fprintf(output, b"\n\0" as *const u8 as *const i8);
    fprintf(
        output,
        b"%d atoms:\n\0" as *const u8 as *const i8,
        (*(borrow(& regexp)).unwrap()).nbAtoms,
    );
    i = 0 as i32;
    while i < (*(borrow(& regexp)).unwrap()).nbAtoms {
        fprintf(output, b" %02d \0" as *const u8 as *const i8, i);
        xmlRegPrintAtom(output, *((*(borrow(& regexp)).unwrap()).atoms).offset(i as isize));
        i += 1;
    }
    fprintf(
        output,
        b"%d states:\0" as *const u8 as *const i8,
        (*(borrow(& regexp)).unwrap()).nbStates,
    );
    fprintf(output, b"\n\0" as *const u8 as *const i8);
    i = 0 as i32;
    while i < (*(borrow(& regexp)).unwrap()).nbStates {
        xmlRegPrintState(output, *((*(borrow(& regexp)).unwrap()).states).offset(i as isize));
        i += 1;
    }
    fprintf(
        output,
        b"%d counters:\n\0" as *const u8 as *const i8,
        (*(borrow(& regexp)).unwrap()).nbCounters,
    );
    i = 0 as i32;
    while i < (*(borrow(& regexp)).unwrap()).nbCounters {
        fprintf(
            output,
            b" %d: min %d max %d\n\0" as *const u8 as *const i8,
            i,
            (*((*(borrow(& regexp)).unwrap()).counters).offset(i as isize)).min,
            (*((*(borrow(& regexp)).unwrap()).counters).offset(i as isize)).max,
        );
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegexpCompile(mut regexp: * const u8) -> * mut crate::src::xmlregexp::_xmlRegexp {
    let mut ret: * mut crate::src::xmlregexp::_xmlRegexp = 0 as *mut xmlRegexp;
    let mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata = 0 as *mut xmlRegParserCtxt;
    ctxt = xmlRegNewParserCtxt(regexp);
    if ctxt.is_null() {
        return 0 as xmlRegexpPtr;
    }
    let fresh228 = &mut ((*ctxt).end);
    *fresh228 = 0 as xmlRegStatePtr;
    let fresh229 = &mut ((*ctxt).state);
    *fresh229 = xmlRegNewState(ctxt);
    let fresh230 = &mut ((*ctxt).start);
    *fresh230 = *fresh229;
    xmlRegStatePush(ctxt, (*ctxt).start);
    xmlFAParseRegExp(ctxt, 1 as i32);
    if *(*ctxt).cur as i32 != 0 as i32 {
        (*ctxt).error = XML_REGEXP_COMPILE_ERROR as i32;
        xmlRegexpErrCompile(
            ctxt,
            b"xmlFAParseRegExp: extra characters\0" as *const u8 as *const i8,
        );
    }
    if (*ctxt).error != 0 as i32 {
        xmlRegFreeParserCtxt(ctxt);
        return 0 as xmlRegexpPtr;
    }
    let fresh231 = &mut ((*ctxt).end);
    *fresh231 = (*ctxt).state;
    (*(*ctxt).start).type_0 = XML_REGEXP_START_STATE;
    (*(*ctxt).end).type_0 = XML_REGEXP_FINAL_STATE;
    xmlFAEliminateEpsilonTransitions(ctxt);
    if (*ctxt).error != 0 as i32 {
        xmlRegFreeParserCtxt(ctxt);
        return 0 as xmlRegexpPtr;
    }
    ret = xmlRegEpxFromParse(ctxt);
    xmlRegFreeParserCtxt(ctxt);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegexpExec(
    mut comp: * mut crate::src::xmlregexp::_xmlRegexp,
    mut content: * const u8,
) -> i32 {
    if comp.is_null() || content.is_null() {
        return -(1 as i32);
    }
    return xmlFARegExec(comp, content);
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegexpIsDeterminist(mut comp: * mut crate::src::xmlregexp::_xmlRegexp) -> i32 {
    let mut am: * mut crate::src::xmlregexp::_xmlAutomata = 0 as *mut xmlAutomata;
    let mut ret: i32 = 0;
    if comp.is_null() {
        return -(1 as i32);
    }
    if (*comp).determinist != -(1 as i32) {
        return (*comp).determinist;
    }
    am = xmlNewAutomata();
    if am.is_null() {
        return -(1 as i32);
    }
    if !((*am).states).is_null() {
        let mut i: i32 = 0;
        i = 0 as i32;
        while i < (*am).nbStates {
            xmlRegFreeState(*((*am).states).offset(i as isize));
            i += 1;
        }
        xmlFree.expect("non-null function pointer")((*am).states as *mut libc::c_void);
    }
    (*am).nbAtoms = (*comp).nbAtoms;
    let fresh232 = &mut ((*am).atoms);
    *fresh232 = (*comp).atoms;
    (*am).nbStates = (*comp).nbStates;
    let fresh233 = &mut ((*am).states);
    *fresh233 = (*comp).states;
    (*am).determinist = -(1 as i32);
    (*am).flags = (*comp).flags;
    ret = xmlFAComputesDeterminism(am);
    let fresh234 = &mut ((*am).atoms);
    *fresh234 = 0 as *mut xmlRegAtomPtr;
    let fresh235 = &mut ((*am).states);
    *fresh235 = 0 as *mut xmlRegStatePtr;
    xmlFreeAutomata(am);
    (*comp).determinist = ret;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlRegFreeRegexp(mut regexp: * mut crate::src::xmlregexp::_xmlRegexp) {
    let mut i: i32 = 0;
    if regexp.is_null() {
        return;
    }
    if !((*regexp).string).is_null() {
        xmlFree
            .expect("non-null function pointer")((*regexp).string as *mut libc::c_void);
    }
    if !((*regexp).states).is_null() {
        i = 0 as i32;
        while i < (*regexp).nbStates {
            xmlRegFreeState(*((*regexp).states).offset(i as isize));
            i += 1;
        }
        xmlFree
            .expect("non-null function pointer")((*regexp).states as *mut libc::c_void);
    }
    if !((*regexp).atoms).is_null() {
        i = 0 as i32;
        while i < (*regexp).nbAtoms {
            xmlRegFreeAtom(*((*regexp).atoms).offset(i as isize));
            i += 1;
        }
        xmlFree
            .expect("non-null function pointer")((*regexp).atoms as *mut libc::c_void);
    }
    if !((*regexp).counters).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*regexp).counters as *mut libc::c_void);
    }
    if !((*regexp).compact).is_null() {
        xmlFree
            .expect("non-null function pointer")((*regexp).compact as *mut libc::c_void);
    }
    if !((*regexp).transdata).is_null() {
        xmlFree
            .expect(
                "non-null function pointer",
            )((*regexp).transdata as *mut libc::c_void);
    }
    if !((*regexp).stringMap).is_null() {
        i = 0 as i32;
        while i < (*regexp).nbstrings {
            xmlFree
                .expect(
                    "non-null function pointer",
                )(*((*regexp).stringMap).offset(i as isize) as *mut libc::c_void);
            i += 1;
        }
        xmlFree
            .expect(
                "non-null function pointer",
            )((*regexp).stringMap as *mut libc::c_void);
    }
    xmlFree.expect("non-null function pointer")(regexp as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn xmlNewAutomata() -> * mut crate::src::xmlregexp::_xmlAutomata {
    let mut ctxt: * mut crate::src::xmlregexp::_xmlAutomata = 0 as *mut xmlAutomata;
    ctxt = xmlRegNewParserCtxt(0 as *const xmlChar);
    if ctxt.is_null() {
        return 0 as xmlAutomataPtr;
    }
    let fresh236 = &mut ((*ctxt).end);
    *fresh236 = 0 as xmlRegStatePtr;
    let fresh237 = &mut ((*ctxt).state);
    *fresh237 = xmlRegNewState(ctxt);
    let fresh238 = &mut ((*ctxt).start);
    *fresh238 = *fresh237;
    if ((*ctxt).start).is_null() {
        xmlFreeAutomata(ctxt);
        return 0 as xmlAutomataPtr;
    }
    (*(*ctxt).start).type_0 = XML_REGEXP_START_STATE;
    if xmlRegStatePush(ctxt, (*ctxt).start) < 0 as i32 {
        xmlRegFreeState((*ctxt).start);
        xmlFreeAutomata(ctxt);
        return 0 as xmlAutomataPtr;
    }
    (*ctxt).flags = 0 as i32;
    return ctxt;
}
#[no_mangle]
pub unsafe extern "C" fn xmlFreeAutomata(mut am: * mut crate::src::xmlregexp::_xmlAutomata) {
    if am.is_null() {
        return;
    }
    xmlRegFreeParserCtxt(am);
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataSetFlags<'a1>(
    mut am: Option<&'a1 mut crate::src::xmlregexp::_xmlAutomata>,
    mut flags: i32,
) {
    if borrow(& am).is_none() {
        return;
    }
    (*(borrow_mut(&mut am)).unwrap()).flags |= flags;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataGetInitState(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    if am.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    return (*am).start;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataSetFinalState(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut state: * mut crate::src::xmlregexp::_xmlAutomataState,
) -> i32 {
    if am.is_null() || state.is_null() {
        return -(1 as i32);
    }
    (*state).type_0 = XML_REGEXP_FINAL_STATE;
    return 0 as i32;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewTransition(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    let fresh239 = &mut ((*atom).data);
    *fresh239 = data;
    let fresh240 = &mut ((*atom).valuep);
    *fresh240 = xmlStrdup(token) as *mut libc::c_void;
    if xmlFAGenerateTransitions(am, from, to, atom) < 0 as i32 {
        xmlRegFreeAtom(atom);
        return 0 as xmlAutomataStatePtr;
    }
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewTransition2(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut token2: * const u8,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    let fresh241 = &mut ((*atom).data);
    *fresh241 = data;
    if token2.is_null() || *token2 as i32 == 0 as i32 {
        let fresh242 = &mut ((*atom).valuep);
        *fresh242 = xmlStrdup(token) as *mut libc::c_void;
    } else {
        let mut lenn: i32 = 0;
        let mut lenp: i32 = 0;
        let mut str: * mut u8 = 0 as *mut xmlChar;
        lenn = strlen(token2 as *mut i8) as i32;
        lenp = strlen(token as *mut i8) as i32;
        str = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as i32) as size_t) as *mut xmlChar;
        if str.is_null() {
            xmlRegFreeAtom(atom);
            return 0 as xmlAutomataStatePtr;
        }
        memcpy(
            &mut *str.offset(0 as i32 as isize) as *mut xmlChar
                as *mut libc::c_void,
            token as *const libc::c_void,
            lenp as u64,
        );
        *str.offset(lenp as isize) = '|' as i32 as xmlChar;
        memcpy(
            &mut *str.offset((lenp + 1 as i32) as isize) as *mut xmlChar
                as *mut libc::c_void,
            token2 as *const libc::c_void,
            lenn as u64,
        );
        *str
            .offset(
                (lenn + lenp + 1 as i32) as isize,
            ) = 0 as i32 as xmlChar;
        let fresh243 = &mut ((*atom).valuep);
        *fresh243 = str as *mut libc::c_void;
    }
    if xmlFAGenerateTransitions(am, from, to, atom) < 0 as i32 {
        xmlRegFreeAtom(atom);
        return 0 as xmlAutomataStatePtr;
    }
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewNegTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut token2: * const u8,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut err_msg: [u8; 200] = [0; 200];
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    let fresh244 = &mut ((*atom).data);
    *fresh244 = data;
    (*atom).neg = 1 as i32;
    if token2.is_null() || *token2 as i32 == 0 as i32 {
        let fresh245 = &mut ((*atom).valuep);
        *fresh245 = xmlStrdup(token) as *mut libc::c_void;
    } else {
        let mut lenn: i32 = 0;
        let mut lenp: i32 = 0;
        let mut str: * mut u8 = 0 as *mut xmlChar;
        lenn = strlen(token2 as *mut i8) as i32;
        lenp = strlen(token as *mut i8) as i32;
        str = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as i32) as size_t) as *mut xmlChar;
        if str.is_null() {
            xmlRegFreeAtom(atom);
            return 0 as xmlAutomataStatePtr;
        }
        memcpy(
            &mut *str.offset(0 as i32 as isize) as *mut xmlChar
                as *mut libc::c_void,
            token as *const libc::c_void,
            lenp as u64,
        );
        *str.offset(lenp as isize) = '|' as i32 as xmlChar;
        memcpy(
            &mut *str.offset((lenp + 1 as i32) as isize) as *mut xmlChar
                as *mut libc::c_void,
            token2 as *const libc::c_void,
            lenn as u64,
        );
        *str
            .offset(
                (lenn + lenp + 1 as i32) as isize,
            ) = 0 as i32 as xmlChar;
        let fresh246 = &mut ((*atom).valuep);
        *fresh246 = str as *mut libc::c_void;
    }
    snprintf(
        err_msg.as_mut_ptr() as *mut i8,
        199 as i32 as u64,
        b"not %s\0" as *const u8 as *const i8,
        (*atom).valuep as *const i8,
    );
    err_msg[199 as i32 as usize] = 0 as i32 as xmlChar;
    let fresh247 = &mut ((*atom).valuep2);
    *fresh247 = xmlStrdup(err_msg.as_mut_ptr()) as *mut libc::c_void;
    if xmlFAGenerateTransitions(am, from, to, atom) < 0 as i32 {
        xmlRegFreeAtom(atom);
        return 0 as xmlAutomataStatePtr;
    }
    let fresh248 = &mut ((*am).negs);
    *fresh248 += 1;
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewCountTrans2(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut token2: * const u8,
    mut min: i32,
    mut max: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut counter: i32 = 0;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min < 0 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    if max < min || max < 1 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if token2.is_null() || *token2 as i32 == 0 as i32 {
        let fresh249 = &mut ((*atom).valuep);
        *fresh249 = xmlStrdup(token) as *mut libc::c_void;
    } else {
        let mut lenn: i32 = 0;
        let mut lenp: i32 = 0;
        let mut str: * mut u8 = 0 as *mut xmlChar;
        lenn = strlen(token2 as *mut i8) as i32;
        lenp = strlen(token as *mut i8) as i32;
        str = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as i32) as size_t) as *mut xmlChar;
        if str.is_null() {
            xmlRegFreeAtom(atom);
            return 0 as xmlAutomataStatePtr;
        }
        memcpy(
            &mut *str.offset(0 as i32 as isize) as *mut xmlChar
                as *mut libc::c_void,
            token as *const libc::c_void,
            lenp as u64,
        );
        *str.offset(lenp as isize) = '|' as i32 as xmlChar;
        memcpy(
            &mut *str.offset((lenp + 1 as i32) as isize) as *mut xmlChar
                as *mut libc::c_void,
            token2 as *const libc::c_void,
            lenn as u64,
        );
        *str
            .offset(
                (lenn + lenp + 1 as i32) as isize,
            ) = 0 as i32 as xmlChar;
        let fresh250 = &mut ((*atom).valuep);
        *fresh250 = str as *mut libc::c_void;
    }
    let fresh251 = &mut ((*atom).data);
    *fresh251 = data;
    if min == 0 as i32 {
        (*atom).min = 1 as i32;
    } else {
        (*atom).min = min;
    }
    (*atom).max = max;
    counter = xmlRegGetCounter(am);
    (*((*am).counters).offset(counter as isize)).min = min;
    (*((*am).counters).offset(counter as isize)).max = max;
    if to.is_null() {
        to = xmlRegNewState(am);
        xmlRegStatePush(am, to);
    }
    xmlRegStateAddTrans(am, from, atom, to, counter, -(1 as i32));
    xmlRegAtomPush(am, atom);
    let fresh252 = &mut ((*am).state);
    *fresh252 = to;
    if to.is_null() {
        to = (*am).state;
    }
    if to.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min == 0 as i32 {
        xmlFAGenerateEpsilonTransition(am, from, to);
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewCountTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut min: i32,
    mut max: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut counter: i32 = 0;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min < 0 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    if max < min || max < 1 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    let fresh253 = &mut ((*atom).valuep);
    *fresh253 = xmlStrdup(token) as *mut libc::c_void;
    let fresh254 = &mut ((*atom).data);
    *fresh254 = data;
    if min == 0 as i32 {
        (*atom).min = 1 as i32;
    } else {
        (*atom).min = min;
    }
    (*atom).max = max;
    counter = xmlRegGetCounter(am);
    (*((*am).counters).offset(counter as isize)).min = min;
    (*((*am).counters).offset(counter as isize)).max = max;
    if to.is_null() {
        to = xmlRegNewState(am);
        xmlRegStatePush(am, to);
    }
    xmlRegStateAddTrans(am, from, atom, to, counter, -(1 as i32));
    xmlRegAtomPush(am, atom);
    let fresh255 = &mut ((*am).state);
    *fresh255 = to;
    if to.is_null() {
        to = (*am).state;
    }
    if to.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min == 0 as i32 {
        xmlFAGenerateEpsilonTransition(am, from, to);
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewOnceTrans2(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut token2: * const u8,
    mut min: i32,
    mut max: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut counter: i32 = 0;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min < 1 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    if max < min {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if token2.is_null() || *token2 as i32 == 0 as i32 {
        let fresh256 = &mut ((*atom).valuep);
        *fresh256 = xmlStrdup(token) as *mut libc::c_void;
    } else {
        let mut lenn: i32 = 0;
        let mut lenp: i32 = 0;
        let mut str: * mut u8 = 0 as *mut xmlChar;
        lenn = strlen(token2 as *mut i8) as i32;
        lenp = strlen(token as *mut i8) as i32;
        str = xmlMallocAtomic
            .expect(
                "non-null function pointer",
            )((lenn + lenp + 2 as i32) as size_t) as *mut xmlChar;
        if str.is_null() {
            xmlRegFreeAtom(atom);
            return 0 as xmlAutomataStatePtr;
        }
        memcpy(
            &mut *str.offset(0 as i32 as isize) as *mut xmlChar
                as *mut libc::c_void,
            token as *const libc::c_void,
            lenp as u64,
        );
        *str.offset(lenp as isize) = '|' as i32 as xmlChar;
        memcpy(
            &mut *str.offset((lenp + 1 as i32) as isize) as *mut xmlChar
                as *mut libc::c_void,
            token2 as *const libc::c_void,
            lenn as u64,
        );
        *str
            .offset(
                (lenn + lenp + 1 as i32) as isize,
            ) = 0 as i32 as xmlChar;
        let fresh257 = &mut ((*atom).valuep);
        *fresh257 = str as *mut libc::c_void;
    }
    let fresh258 = &mut ((*atom).data);
    *fresh258 = data;
    (*atom).quant = XML_REGEXP_QUANT_ONCEONLY;
    (*atom).min = min;
    (*atom).max = max;
    counter = xmlRegGetCounter(am);
    (*((*am).counters).offset(counter as isize)).min = 1 as i32;
    (*((*am).counters).offset(counter as isize)).max = 1 as i32;
    if to.is_null() {
        to = xmlRegNewState(am);
        xmlRegStatePush(am, to);
    }
    xmlRegStateAddTrans(am, from, atom, to, counter, -(1 as i32));
    xmlRegAtomPush(am, atom);
    let fresh259 = &mut ((*am).state);
    *fresh259 = to;
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewOnceTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut token: * const u8,
    mut min: i32,
    mut max: i32,
    mut data: * mut core::ffi::c_void,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut atom: * mut crate::src::xmlregexp::_xmlRegAtom = 0 as *mut xmlRegAtom;
    let mut counter: i32 = 0;
    if am.is_null() || from.is_null() || token.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    if min < 1 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    if max < min {
        return 0 as xmlAutomataStatePtr;
    }
    atom = xmlRegNewAtom(am, XML_REGEXP_STRING);
    if atom.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    let fresh260 = &mut ((*atom).valuep);
    *fresh260 = xmlStrdup(token) as *mut libc::c_void;
    let fresh261 = &mut ((*atom).data);
    *fresh261 = data;
    (*atom).quant = XML_REGEXP_QUANT_ONCEONLY;
    (*atom).min = min;
    (*atom).max = max;
    counter = xmlRegGetCounter(am);
    (*((*am).counters).offset(counter as isize)).min = 1 as i32;
    (*((*am).counters).offset(counter as isize)).max = 1 as i32;
    if to.is_null() {
        to = xmlRegNewState(am);
        xmlRegStatePush(am, to);
    }
    xmlRegStateAddTrans(am, from, atom, to, counter, -(1 as i32));
    xmlRegAtomPush(am, atom);
    let fresh262 = &mut ((*am).state);
    *fresh262 = to;
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewState(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    let mut to: * mut crate::src::xmlregexp::_xmlAutomataState = 0 as *mut xmlAutomataState;
    if am.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    to = xmlRegNewState(am);
    xmlRegStatePush(am, to);
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewEpsilon(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    if am.is_null() || from.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    xmlFAGenerateEpsilonTransition(am, from, to);
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewAllTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut lax: i32,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    if am.is_null() || from.is_null() {
        return 0 as xmlAutomataStatePtr;
    }
    xmlFAGenerateAllTransition(am, from, to, lax);
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewCounter(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut min: i32,
    mut max: i32,
) -> i32 {
    let mut ret: i32 = 0;
    if am.is_null() {
        return -(1 as i32);
    }
    ret = xmlRegGetCounter(am);
    if ret < 0 as i32 {
        return -(1 as i32);
    }
    (*((*am).counters).offset(ret as isize)).min = min;
    (*((*am).counters).offset(ret as isize)).max = max;
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewCountedTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut counter: i32,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    if am.is_null() || from.is_null() || counter < 0 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    xmlFAGenerateCountedEpsilonTransition(am, from, to, counter);
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataNewCounterTrans(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
    mut from: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut to: * mut crate::src::xmlregexp::_xmlAutomataState,
    mut counter: i32,
) -> * mut crate::src::xmlregexp::_xmlAutomataState {
    if am.is_null() || from.is_null() || counter < 0 as i32 {
        return 0 as xmlAutomataStatePtr;
    }
    xmlFAGenerateCountedTransition(am, from, to, counter);
    if to.is_null() {
        return (*am).state;
    }
    return to;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataCompile(mut am: * mut crate::src::xmlregexp::_xmlAutomata) -> * mut crate::src::xmlregexp::_xmlRegexp {
    let mut ret: * mut crate::src::xmlregexp::_xmlRegexp = 0 as *mut xmlRegexp;
    if am.is_null() || (*am).error != 0 as i32 {
        return 0 as xmlRegexpPtr;
    }
    xmlFAEliminateEpsilonTransitions(am);
    ret = xmlRegEpxFromParse(am);
    return ret;
}
#[no_mangle]
pub unsafe extern "C" fn xmlAutomataIsDeterminist(
    mut am: * mut crate::src::xmlregexp::_xmlAutomata,
) -> i32 {
    let mut ret: i32 = 0;
    if am.is_null() {
        return -(1 as i32);
    }
    ret = xmlFAComputesDeterminism(am);
    return ret;
}
use crate::laertes_rt::*;
